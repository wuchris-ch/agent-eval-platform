"""Run records: the results.json schema and the SQLite store for cross-run queries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Mapping
from contextlib import closing, suppress
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .assessments import Assessment, expected_assessment_id
from .assurance import AssuranceResult
from .evaluators.tests import TestResults
from .governance import GovernanceEvidence, LegacyGovernanceEvidenceV1
from .limits import MAX_RESULTS_JSON_BYTES
from .outcome import RunOutcome
from .paths import (
    UnsafeStatePathError,
    ensure_private_directory,
    ensure_private_file,
    ensure_run_directory,
    get_state_dir,
    secure_run_tree,
    validate_no_symlink_components,
)

RUNS_ROOT = get_state_dir()
SQLITE_TIMEOUT_SECONDS = 30.0
_SAFE_STATE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SCANNER_EXECUTABLE_NAMES = (
    "uv",
    "python",
    "ruff",
    "semgrep",
    "gitleaks",
    "trivy",
)
SCANNER_REQUIRED_VERSIONS = {
    "ruff": "0.15.20",
    "semgrep": "1.176.0",
    "gitleaks": "8.30.1",
    "trivy": "0.72.0",
}
_SCANNER_ASSURANCE_MATERIAL_FIELDS = (
    "schema_version",
    "runtime_bundle_sha256",
    "runtime_project_sha256",
    "runtime_lock_sha256",
    "runtime_environment_sha256",
    "semgrep_ruleset_sha256",
    "gitleaks_config_sha256",
    "scanner_executable_sha256",
    "trivy_db",
)


def scanner_assurance_material_sha256(value: Mapping[str, object]) -> str:
    """Hash only the canonical scanner supply-chain identity material."""

    material = {name: value[name] for name in _SCANNER_ASSURANCE_MATERIAL_FIELDS}
    trivy_db = material["trivy_db"]
    if isinstance(trivy_db, BaseModel):
        material["trivy_db"] = trivy_db.model_dump(mode="json")
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AgentMetrics(BaseModel):
    """Efficiency metrics parsed from the coding agent's transcript."""

    model_config = ConfigDict(validate_assignment=True)

    wall_time_s: float | None = Field(
        default=None, ge=0, allow_inf_nan=False, strict=True
    )
    tokens_in: int | None = Field(default=None, ge=0, strict=True)
    tokens_out: int | None = Field(default=None, ge=0, strict=True)
    cost_usd: float | None = Field(default=None, ge=0, allow_inf_nan=False, strict=True)
    turns: int | None = Field(default=None, ge=0, strict=True)
    tool_calls: int | None = Field(default=None, ge=0, strict=True)
    model: str | None = Field(default=None, max_length=256)
    requested_model: str | None = Field(default=None, max_length=256)
    agent_exit_code: int | None = Field(default=None, strict=True)
    timed_out: bool = False
    infra_error: str | None = None
    runtime_image_digest: str | None = None


class DiffStats(BaseModel):
    lines_added: int = 0
    lines_removed: int = 0
    files_changed: int = 0
    complete: bool = True
    error_code: Literal["output_limit", "timeout", "git_error"] | None = None


class TrivyDatabaseIdentity(BaseModel):
    """Bounded Trivy database metadata plus an exact local content digest."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1, strict=True)
    updated_at: str = Field(min_length=1, max_length=128)
    next_update: str = Field(min_length=1, max_length=128)
    downloaded_at: str = Field(min_length=1, max_length=128)
    content_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )


class ScannerAssuranceIdentity(BaseModel):
    """Exact scanner supply-chain inputs and promotion readiness."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2"] = "2"
    runtime_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_project_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_lock_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_environment_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    semgrep_ruleset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    gitleaks_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scanner_executable_sha256: dict[str, str | None]
    trivy_db: TrivyDatabaseIdentity | None = None
    identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    promotion_ready: bool
    promotion_blockers: list[str] = Field(default_factory=list)

    @field_validator("scanner_executable_sha256")
    @classmethod
    def _exact_executable_identity(
        cls, value: dict[str, str | None]
    ) -> dict[str, str | None]:
        expected = set(SCANNER_EXECUTABLE_NAMES)
        if set(value) != expected:
            raise ValueError(
                "scanner executable identity must contain exactly "
                + ", ".join(SCANNER_EXECUTABLE_NAMES)
            )
        for name, digest in value.items():
            if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError(f"scanner executable digest for {name} is invalid")
        return value

    @model_validator(mode="after")
    def _canonical_identity(self) -> ScannerAssuranceIdentity:
        expected_identity = scanner_assurance_material_sha256(
            self.model_dump(mode="python")
        )
        if self.identity_sha256 != expected_identity:
            raise ValueError(
                "scanner assurance identity_sha256 does not match its material"
            )
        canonical_blockers = sorted(set(self.promotion_blockers))
        if self.promotion_blockers != canonical_blockers:
            raise ValueError("scanner promotion blockers must be sorted and unique")
        if self.promotion_ready != (not self.promotion_blockers):
            raise ValueError(
                "scanner promotion readiness contradicts its promotion blockers"
            )
        return self


class ScanResults(BaseModel):
    lint_errors: int | None = None
    sec_findings_high: int | None = None
    sec_findings_medium: int | None = None
    sec_findings_low: int | None = None
    secrets_found: int | None = None
    vulns: int | None = None
    scanner_status: dict[str, str] = Field(default_factory=dict)
    scanner_versions: dict[str, str | None] = Field(default_factory=dict)
    scanner_configs: dict[str, str] = Field(default_factory=dict)
    scanner_runtime_lock_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    scanner_runtime_environment_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    scanner_executable_sha256: dict[str, str | None] = Field(
        default_factory=dict
    )
    trivy_db: TrivyDatabaseIdentity | None = None
    scanner_assurance: ScannerAssuranceIdentity | None = None
    findings: list[dict] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent_scanner_assurance(self) -> ScanResults:
        assurance = self.scanner_assurance
        if assurance is None:
            return self
        if self.scanner_runtime_lock_sha256 != assurance.runtime_lock_sha256:
            raise ValueError(
                "scanner runtime lock evidence does not match scanner assurance"
            )
        if (
            self.scanner_runtime_environment_sha256
            != assurance.runtime_environment_sha256
        ):
            raise ValueError(
                "scanner runtime environment evidence does not match scanner assurance"
            )
        if self.scanner_executable_sha256 != assurance.scanner_executable_sha256:
            raise ValueError(
                "scanner executable evidence does not match scanner assurance"
            )
        if self.trivy_db != assurance.trivy_db:
            raise ValueError(
                "Trivy database evidence does not match scanner assurance"
            )
        expected_blockers = scanner_promotion_blockers(self)
        if assurance.promotion_blockers != expected_blockers:
            raise ValueError(
                "scanner promotion evidence does not match observed scanner results"
            )
        return self


def scanner_promotion_blockers(results: ScanResults) -> list[str]:
    """Return the canonical reasons scanner evidence is not promotable."""

    blockers: list[str] = []
    if results.scanner_runtime_lock_sha256 is None:
        blockers.append("scanner:runtime:lock-sha256-missing")
    if results.scanner_runtime_environment_sha256 is None:
        blockers.append("scanner:runtime:environment-sha256-missing")
    for scanner, required_version in SCANNER_REQUIRED_VERSIONS.items():
        status = results.scanner_status.get(scanner)
        allowed = {"ok", "not_applicable"} if scanner == "ruff" else {"ok"}
        if status not in allowed:
            blockers.append(f"scanner:{scanner}:status:{status or 'missing'}")
        observed_version = results.scanner_versions.get(scanner)
        if not observed_version:
            blockers.append(f"scanner:{scanner}:version-missing")
        elif observed_version != required_version:
            blockers.append(f"scanner:{scanner}:version-mismatch")
    for scanner in SCANNER_EXECUTABLE_NAMES:
        if results.scanner_executable_sha256.get(scanner) is None:
            blockers.append(f"scanner:{scanner}:executable-sha256-missing")
    if results.trivy_db is None:
        blockers.append("scanner:trivy:database-identity-missing")
    elif results.trivy_db.content_sha256 is None:
        blockers.append("scanner:trivy:database-content-sha256-missing")
    return sorted(set(blockers))


class JudgeResult(BaseModel):
    scores: dict[str, int] = Field(default_factory=dict)  # dimension -> 1..5
    weighted_score: float | None = None
    rationale: dict[str, str] = Field(default_factory=dict)
    backend: str | None = Field(default=None, max_length=256)
    model: str | None = Field(default=None, max_length=256)


class RunProvenance(BaseModel):
    """Non-secret execution identity persisted with a trial."""

    image_tag: str | None = None
    image_digest: str | None = None
    local_image_digest: str | None = None
    task_tree_sha256: str | None = None
    evaluation_spec_digest: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    harness_version: str | None = None
    harness_commit: str | None = None
    harness_dirty: bool | None = None
    harness_worktree_sha256: str | None = None
    agent_image_digest: str | None = None
    eval_image_digest: str | None = None
    submission_image_digest: str | None = None
    credential_source: str | None = None
    credential_mode: str | None = None
    credential_expires_at: str | None = None
    audit_trace_id: str | None = None
    audit_final_hash: str | None = None
    audit_event_count: int | None = None
    audit_error: str | None = None
    attestation_error: str | None = None
    tool_versions: dict[str, str | None] = Field(default_factory=dict)


class RunRecord(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    schema_version: Literal["agent-eval.run/v2"] = "agent-eval.run/v2"
    run_id: str = Field(strict=True, min_length=1, max_length=128)
    task_id: str = Field(strict=True, min_length=1, max_length=128)
    agent: str = Field(strict=True, min_length=1, max_length=128)
    trial: int = Field(default=1, gt=0, strict=True)
    experiment_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    correctness: TestResults = Field(default_factory=TestResults)
    efficiency: AgentMetrics = Field(default_factory=AgentMetrics)
    diff: DiffStats = Field(default_factory=DiffStats)
    scans: ScanResults = Field(default_factory=ScanResults)
    judge: JudgeResult = Field(default_factory=JudgeResult)
    assurance: AssuranceResult | None = None
    outcome: RunOutcome | None = None
    governance: GovernanceEvidence | LegacyGovernanceEvidenceV1 | None = None
    provenance: RunProvenance = Field(default_factory=RunProvenance)
    assessments: list[Assessment] = Field(default_factory=list)

    @field_validator("run_id", "task_id", "agent")
    @classmethod
    def _path_safe_identifier(cls, value: str) -> str:
        if _SAFE_STATE_ID.fullmatch(value) is None:
            raise ValueError(
                "run_id, task_id, and agent must be portable path-safe identifiers"
            )
        return value

    @model_validator(mode="after")
    def _assessment_integrity(self) -> RunRecord:
        assessment_ids: set[str] = set()
        assessment_names: set[str] = set()
        for assessment in self.assessments:
            if assessment.run_id != self.run_id:
                raise ValueError("every assessment must belong to the record run_id")
            if assessment.assessment_id != expected_assessment_id(assessment):
                raise ValueError("assessment_id must match its deterministic identity")
            if assessment.assessment_id in assessment_ids:
                raise ValueError("assessment_id values must be unique within a run")
            if assessment.name in assessment_names:
                raise ValueError("assessment names must be unique within a run")
            assessment_ids.add(assessment.assessment_id)
            assessment_names.add(assessment.name)
        return self

    @property
    def run_dir(self) -> Path:
        return RUNS_ROOT / self.run_id


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


_RUNS_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    trial INTEGER NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    resolved INTEGER,
    tests_passed INTEGER,
    tests_total INTEGER,
    coverage REAL,
    wall_time_s REAL,
    tokens_in INTEGER,
    tokens_out INTEGER,
    cost_usd REAL,
    turns INTEGER,
    tool_calls INTEGER,
    lint_errors INTEGER,
    sec_findings INTEGER,
    secrets_found INTEGER,
    vulns INTEGER,
    diff_added INTEGER,
    diff_removed INTEGER,
    files_changed INTEGER,
    judge_score REAL,
    experiment_id TEXT,
    outcome_status TEXT,
    image_digest TEXT,
    results_json TEXT NOT NULL
)
"""

_MIGRATIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL
)
"""

_ASSESSMENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    value_type TEXT,
    numeric_value REAL,
    boolean_value INTEGER,
    categorical_value TEXT,
    text_value TEXT,
    direction TEXT NOT NULL,
    range_min REAL,
    range_max REAL,
    threshold REAL,
    evaluator_name TEXT NOT NULL,
    evaluator_version TEXT,
    evaluator_model TEXT,
    config_digest TEXT,
    prompt_digest TEXT,
    rubric_digest TEXT,
    dataset_id TEXT,
    dataset_revision TEXT,
    dataset_item_id TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    error_type TEXT,
    error_code TEXT,
    assessment_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
)
"""

# The v2 ledger was briefly capable of creating this exact layout before
# dataset_id became part of the normalized projection. Keep the historical DDL
# explicit so migration can distinguish that supported predecessor from an
# arbitrary lookalike table.
_ASSESSMENTS_V2_SCHEMA = _ASSESSMENTS_SCHEMA.replace("    dataset_id TEXT,\n", "")

_SCHEMA_MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, "initial-runs-schema"),
    (2, "normalized-assessments"),
    (3, "assessment-dataset-identity"),
)

_REQUIRED_INDEXES: dict[str, tuple[str, ...]] = {
    "assessments_run_name_idx": ("run_id", "name"),
    "assessments_source_status_idx": ("source_kind", "status"),
    "assessments_evaluator_idx": ("evaluator_name",),
    "assessments_dataset_idx": (
        "dataset_id",
        "dataset_revision",
        "dataset_item_id",
    ),
}
_INDEX_SCHEMAS = {
    "assessments_run_name_idx": (
        "CREATE INDEX assessments_run_name_idx ON assessments(run_id, name)"
    ),
    "assessments_source_status_idx": (
        "CREATE INDEX assessments_source_status_idx "
        "ON assessments(source_kind, status)"
    ),
    "assessments_evaluator_idx": (
        "CREATE INDEX assessments_evaluator_idx ON assessments(evaluator_name)"
    ),
    "assessments_dataset_idx": (
        "CREATE INDEX assessments_dataset_idx "
        "ON assessments(dataset_id, dataset_revision, dataset_item_id)"
    ),
}


def _migration_rows(conn: sqlite3.Connection) -> list[tuple[int, str]]:
    table = conn.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if table is None:
        return []
    try:
        rows = conn.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        ).fetchall()
    except sqlite3.Error as exc:
        raise ValueError("schema_migrations has an invalid schema") from exc
    result: list[tuple[int, str]] = []
    for row in rows:
        version, name = row[0], row[1]
        if type(version) is not int or not isinstance(name, str):
            raise ValueError("schema_migrations contains invalid values")
        result.append((version, name))
    return result


def _validate_migration_ledger(conn: sqlite3.Connection) -> None:
    rows = _migration_rows(conn)
    expected_prefix = list(_SCHEMA_MIGRATIONS[: len(rows)])
    if rows != expected_prefix:
        if any(version > len(_SCHEMA_MIGRATIONS) for version, _ in rows):
            raise ValueError("metrics.db uses a newer unsupported schema version")
        raise ValueError("schema_migrations is inconsistent or has unexpected names")


def _column_signature(
    conn: sqlite3.Connection, table: str
) -> dict[str, tuple[str, int, str | None, int, int]]:
    return {
        str(row[1]): (
            str(row[2]).upper(),
            int(row[3]),
            None if row[4] is None else str(row[4]),
            int(row[5]),
            int(row[6]),
        )
        for row in conn.execute(f"PRAGMA table_xinfo({table})").fetchall()
    }


@lru_cache(maxsize=1)
def _canonical_column_signatures() -> dict[
    str, dict[str, tuple[str, int, str | None, int, int]]
]:
    with closing(sqlite3.connect(":memory:")) as expected:
        expected.execute(_MIGRATIONS_SCHEMA)
        expected.execute(_RUNS_SCHEMA)
        expected.execute(_ASSESSMENTS_SCHEMA)
        return {
            table: _column_signature(expected, table)
            for table in ("schema_migrations", "runs", "assessments")
        }


@lru_cache(maxsize=1)
def _canonical_schema_sql() -> dict[tuple[str, str, str], str]:
    with closing(sqlite3.connect(":memory:")) as expected:
        expected.execute(_MIGRATIONS_SCHEMA)
        expected.execute(_RUNS_SCHEMA)
        expected.execute(_ASSESSMENTS_SCHEMA)
        for statement in _INDEX_SCHEMAS.values():
            expected.execute(statement)
        return {
            (str(row[0]), str(row[1]), str(row[2])): str(row[3])
            for row in expected.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "WHERE sql IS NOT NULL"
            ).fetchall()
        }


def _canonicalize_legacy_runs_table(conn: sqlite3.Connection) -> None:
    """Rebuild a pre-ledger runs table before adding dependent schema."""

    actual_sql = conn.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'runs'"
    ).fetchone()
    expected_sql = _canonical_schema_sql()[("table", "runs", "runs")]
    if actual_sql is not None and actual_sql[0] == expected_sql:
        return
    expected_columns = _canonical_column_signatures()["runs"]
    if _column_signature(conn, "runs") != expected_columns:
        raise ValueError("legacy runs table cannot be canonicalized safely")
    allowed_objects = {
        ("table", "runs", "runs"),
        ("index", "sqlite_autoindex_runs_1", "runs"),
        ("table", "schema_migrations", "schema_migrations"),
        (
            "index",
            "sqlite_autoindex_schema_migrations_1",
            "schema_migrations",
        ),
    }
    actual_objects = {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in conn.execute(
            "SELECT type, name, tbl_name FROM sqlite_schema"
        ).fetchall()
    }
    if actual_objects != allowed_objects:
        raise ValueError("legacy runs database has unexpected schema objects")
    columns = ", ".join(expected_columns)
    conn.execute("ALTER TABLE runs RENAME TO _agent_eval_legacy_runs")
    conn.execute(_RUNS_SCHEMA)
    conn.execute(
        f"INSERT INTO runs ({columns}) SELECT {columns} "
        "FROM _agent_eval_legacy_runs"
    )
    conn.execute("DROP TABLE _agent_eval_legacy_runs")


def _rebuild_v2_assessments_table(conn: sqlite3.Connection) -> None:
    """Rebuild the exact v2 projection into canonical v3 column order."""

    with closing(sqlite3.connect(":memory:")) as expected:
        expected.execute(_ASSESSMENTS_V2_SCHEMA)
        expected_sql = expected.execute(
            "SELECT sql FROM sqlite_schema "
            "WHERE type = 'table' AND name = 'assessments'"
        ).fetchone()[0]
        expected_columns = _column_signature(expected, "assessments")
    actual_sql = conn.execute(
        "SELECT sql FROM sqlite_schema "
        "WHERE type = 'table' AND name = 'assessments'"
    ).fetchone()
    if (
        actual_sql is None
        or actual_sql[0] != expected_sql
        or _column_signature(conn, "assessments") != expected_columns
    ):
        raise ValueError("schema v2 assessments table cannot be migrated safely")

    allowed_objects = {
        ("table", "schema_migrations", "schema_migrations"),
        ("table", "runs", "runs"),
        ("table", "assessments", "assessments"),
        ("index", "sqlite_autoindex_schema_migrations_1", "schema_migrations"),
        ("index", "sqlite_autoindex_runs_1", "runs"),
        ("index", "sqlite_autoindex_assessments_1", "assessments"),
        *(
            ("index", name, "assessments")
            for name in (
                "assessments_run_name_idx",
                "assessments_source_status_idx",
                "assessments_evaluator_idx",
            )
        ),
    }
    actual_objects = {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in conn.execute(
            "SELECT type, name, tbl_name FROM sqlite_schema"
        ).fetchall()
    }
    if actual_objects != allowed_objects:
        raise ValueError("schema v2 database has unexpected schema objects")

    for name in (
        "assessments_run_name_idx",
        "assessments_source_status_idx",
        "assessments_evaluator_idx",
    ):
        conn.execute(f"DROP INDEX {name}")
    conn.execute("ALTER TABLE assessments RENAME TO _agent_eval_v2_assessments")
    conn.execute(_ASSESSMENTS_SCHEMA)
    conn.execute("DROP TABLE _agent_eval_v2_assessments")
    for name in (
        "assessments_run_name_idx",
        "assessments_source_status_idx",
        "assessments_evaluator_idx",
    ):
        conn.execute(_INDEX_SCHEMAS[name])

def _validate_current_schema(conn: sqlite3.Connection) -> None:
    """Require the exact supported ledger and all durable schema invariants."""

    integrity = conn.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or integrity[0] != "ok":
        raise ValueError("metrics.db failed SQLite integrity_check")
    rows = _migration_rows(conn)
    if rows != list(_SCHEMA_MIGRATIONS):
        if any(version > len(_SCHEMA_MIGRATIONS) for version, _ in rows):
            raise ValueError("metrics.db uses a newer unsupported schema version")
        raise ValueError("metrics.db does not have the exact current schema ledger")

    allowed_objects = {
        ("table", "schema_migrations", "schema_migrations"),
        ("table", "runs", "runs"),
        ("table", "assessments", "assessments"),
        ("index", "sqlite_autoindex_schema_migrations_1", "schema_migrations"),
        ("index", "sqlite_autoindex_runs_1", "runs"),
        ("index", "sqlite_autoindex_assessments_1", "assessments"),
        *(("index", name, "assessments") for name in _REQUIRED_INDEXES),
    }
    actual_objects = {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in conn.execute(
            "SELECT type, name, tbl_name FROM sqlite_schema"
        ).fetchall()
    }
    if actual_objects != allowed_objects:
        raise ValueError("metrics.db contains unexpected or missing schema objects")

    actual_sql = {
        (str(row[0]), str(row[1]), str(row[2])): str(row[3])
        for row in conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE sql IS NOT NULL"
        ).fetchall()
    }
    if actual_sql != _canonical_schema_sql():
        raise ValueError("metrics.db schema SQL is not the exact canonical schema")

    expected_columns = _canonical_column_signatures()
    for table, expected in expected_columns.items():
        actual = _column_signature(conn, table)
        if actual != expected:
            raise ValueError(f"metrics.db has an invalid {table} table schema")

    for index_name, expected_columns_for_index in _REQUIRED_INDEXES.items():
        index = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?",
            (index_name,),
        ).fetchone()
        actual_columns = tuple(
            str(row[2])
            for row in conn.execute(f"PRAGMA index_info({index_name})").fetchall()
        )
        index_list = {
            str(row[1]): (int(row[2]), str(row[3]), int(row[4]))
            for row in conn.execute("PRAGMA index_list(assessments)").fetchall()
        }
        if (
            index is None
            or actual_columns != expected_columns_for_index
            or index_list.get(index_name) != (0, "c", 0)
        ):
            raise ValueError(f"metrics.db has an invalid {index_name} index")

    foreign_keys = conn.execute("PRAGMA foreign_key_list(assessments)").fetchall()
    if len(foreign_keys) != 1:
        raise ValueError("metrics.db has an invalid assessments foreign key")
    foreign_key = foreign_keys[0]
    if (
        foreign_key[2],
        foreign_key[3],
        foreign_key[4],
        str(foreign_key[6]).upper(),
    ) != ("runs", "run_id", "run_id", "CASCADE"):
        raise ValueError("metrics.db has an invalid assessments foreign key")
    if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ValueError("metrics.db failed SQLite foreign_key_check")


def _apply_schema_migrations(conn: sqlite3.Connection) -> None:
    conn.execute(_MIGRATIONS_SCHEMA)
    _validate_migration_ledger(conn)
    applied = {
        row["version"]
        for row in conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    }
    migration_performed = False
    if 1 not in applied:
        migration_performed = True
        conn.execute(_RUNS_SCHEMA)
        existing = {
            row["name"] for row in conn.execute("PRAGMA table_info(runs)").fetchall()
        }
        for name in ("experiment_id", "outcome_status", "image_digest"):
            if name not in existing:
                conn.execute(f"ALTER TABLE runs ADD COLUMN {name} TEXT")
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) "
            "VALUES (?, ?, ?)",
            (1, "initial-runs-schema", now_iso()),
        )
        _canonicalize_legacy_runs_table(conn)
    if 2 not in applied:
        migration_performed = True
        conn.execute(_ASSESSMENTS_SCHEMA)
        for name in (
            "assessments_run_name_idx",
            "assessments_source_status_idx",
            "assessments_evaluator_idx",
        ):
            conn.execute(_INDEX_SCHEMAS[name].replace("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) "
            "VALUES (?, ?, ?)",
            (2, "normalized-assessments", now_iso()),
        )
    if 3 not in applied:
        migration_performed = True
        assessment_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(assessments)").fetchall()
        }
        if "dataset_id" not in assessment_columns:
            _rebuild_v2_assessments_table(conn)
        conn.execute(
            _INDEX_SCHEMAS["assessments_dataset_idx"].replace(
                "CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1
            )
        )
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) "
            "VALUES (?, ?, ?)",
            (3, "assessment-dataset-identity", now_iso()),
        )
    if migration_performed:
        # results_json is the authoritative record. Every supported migration
        # rebuilds scalar and normalized query projections from that envelope,
        # avoiding invented legacy defaults and canonicalizing new columns.
        records = [
            RunRecord.model_validate_json(row[0], extra="forbid")
            for row in conn.execute("SELECT results_json FROM runs").fetchall()
        ]
        for record in records:
            _write_record_rows(conn, record, record.model_dump_json())
    _validate_current_schema(conn)


def _sqlite_paths() -> tuple[Path, Path, Path]:
    database = RUNS_ROOT / "metrics.db"
    return (
        database,
        database.with_name(f"{database.name}-wal"),
        database.with_name(f"{database.name}-shm"),
    )


def _secure_sqlite_files(*, create_database: bool) -> None:
    database, *sidecars = _sqlite_paths()
    ensure_private_file(database, create=create_database)
    for sidecar in sidecars:
        if sidecar.exists() or sidecar.is_symlink():
            ensure_private_file(sidecar, create=False)


def _state_database_exists() -> bool:
    root = validate_no_symlink_components(RUNS_ROOT)
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeStatePathError(f"state directory must be a directory: {root}")
    ensure_private_directory(root, create=False)
    database = root / "metrics.db"
    try:
        database_metadata = database.lstat()
    except FileNotFoundError:
        with os.scandir(root) as entries:
            content = list(entries)
        if not content:
            return False
        if len(content) == 1 and content[0].name == "admissions":
            metadata = content[0].stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                secure_run_tree(root / "admissions")
                return False
        # The missing database is the condition being reported, not an
        # unexpected failure, so the lookup error is not chained.
        raise ValueError(
            "state directory has content but no metrics.db"
        ) from None
    if stat.S_ISLNK(database_metadata.st_mode):
        raise UnsafeStatePathError(f"state file must not be a symlink: {database}")
    if not stat.S_ISREG(database_metadata.st_mode):
        raise UnsafeStatePathError(
            f"state file must be a regular file: {database}"
        )
    _secure_sqlite_files(create_database=False)
    return True


def _connect(*, create_database: bool = True) -> sqlite3.Connection:
    ensure_private_directory(
        RUNS_ROOT,
        create=create_database,
        parents=create_database,
    )
    _secure_sqlite_files(create_database=create_database)
    database = RUNS_ROOT / "metrics.db"
    target: str | Path = database
    uri = False
    if not create_database:
        target = f"file:{quote(str(database), safe='/:')}?mode=rw"
        uri = True
    conn = sqlite3.connect(
        target,
        timeout=SQLITE_TIMEOUT_SECONDS,
        uri=uri,
    )
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {int(SQLITE_TIMEOUT_SECONDS * 1000)}")
        journal_mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if journal_mode.lower() != "wal":
            raise RuntimeError("SQLite refused WAL journal mode")
        conn.execute("PRAGMA synchronous = FULL")
        with conn:
            _apply_schema_migrations(conn)
        _secure_sqlite_files(create_database=False)
        return conn
    except BaseException:
        conn.close()
        raise


def prepare_run_dir(record: RunRecord, *, exist_ok: bool = True) -> Path:
    """Create or validate a record's owner-only run directory."""

    return ensure_run_directory(
        RUNS_ROOT,
        record.run_dir,
        exist_ok=exist_ok,
    )


_RUN_PROJECTION_COLUMNS = (
    "run_id",
    "task_id",
    "agent",
    "trial",
    "started_at",
    "finished_at",
    "resolved",
    "tests_passed",
    "tests_total",
    "coverage",
    "wall_time_s",
    "tokens_in",
    "tokens_out",
    "cost_usd",
    "turns",
    "tool_calls",
    "lint_errors",
    "sec_findings",
    "secrets_found",
    "vulns",
    "diff_added",
    "diff_removed",
    "files_changed",
    "judge_score",
    "experiment_id",
    "outcome_status",
    "image_digest",
)


def _expected_run_projection(record: RunRecord) -> dict[str, object]:
    """Return the canonical scalar query projection for one results record."""

    correctness = record.correctness
    scans = record.scans
    security_total = (
        sum(
            value
            for value in (
                scans.sec_findings_high,
                scans.sec_findings_medium,
                scans.sec_findings_low,
            )
            if value is not None
        )
        if scans.sec_findings_high is not None
        else None
    )
    return {
        "run_id": record.run_id,
        "task_id": record.task_id,
        "agent": record.agent,
        "trial": record.trial,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "resolved": int(correctness.resolved),
        "tests_passed": correctness.passed,
        "tests_total": correctness.total,
        "coverage": correctness.coverage_percent,
        "wall_time_s": record.efficiency.wall_time_s,
        "tokens_in": record.efficiency.tokens_in,
        "tokens_out": record.efficiency.tokens_out,
        "cost_usd": record.efficiency.cost_usd,
        "turns": record.efficiency.turns,
        "tool_calls": record.efficiency.tool_calls,
        "lint_errors": scans.lint_errors,
        "sec_findings": security_total,
        "secrets_found": scans.secrets_found,
        "vulns": scans.vulns,
        "diff_added": record.diff.lines_added,
        "diff_removed": record.diff.lines_removed,
        "files_changed": record.diff.files_changed,
        "judge_score": record.judge.weighted_score,
        "experiment_id": record.experiment_id,
        "outcome_status": record.outcome.status if record.outcome else None,
        "image_digest": record.provenance.image_digest,
    }


def _validate_run_projection(record: RunRecord, row: Mapping[str, object]) -> None:
    try:
        actual = {column: row[column] for column in _RUN_PROJECTION_COLUMNS}
    except (IndexError, KeyError) as exc:
        raise ValueError("metrics.db run projection is incomplete") from exc
    if actual != _expected_run_projection(record):
        raise ValueError(
            f"metrics.db run projection differs from results_json for {record.run_id!r}"
        )


def _write_record_rows(
    conn: sqlite3.Connection,
    record: RunRecord,
    results_json: str,
) -> None:
    projection = _expected_run_projection(record)
    conn.execute(
        """INSERT OR REPLACE INTO runs (
           run_id, task_id, agent, trial, started_at, finished_at,
           resolved, tests_passed, tests_total, coverage, wall_time_s,
           tokens_in, tokens_out, cost_usd, turns, tool_calls, lint_errors,
           sec_findings, secrets_found, vulns, diff_added, diff_removed,
           files_changed, judge_score, experiment_id, outcome_status,
           image_digest, results_json
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (*tuple(projection[column] for column in _RUN_PROJECTION_COLUMNS), results_json),
    )
    conn.execute("DELETE FROM assessments WHERE run_id = ?", (record.run_id,))
    for assessment in record.assessments:
        value = assessment.value
        error = assessment.error
        conn.execute(
            """INSERT INTO assessments (
               assessment_id, run_id, name, source_kind, status, value_type,
               numeric_value, boolean_value, categorical_value, text_value,
               direction, range_min, range_max, threshold, evaluator_name,
               evaluator_version, evaluator_model, config_digest,
               prompt_digest, rubric_digest, dataset_id, dataset_revision,
               dataset_item_id, started_at, finished_at, observed_at,
               error_type, error_code, assessment_json
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                assessment.assessment_id,
                record.run_id,
                assessment.name,
                assessment.source_kind,
                assessment.status,
                value.type if value is not None else None,
                value.numeric if value is not None else None,
                (
                    int(value.boolean)
                    if value is not None and value.boolean is not None
                    else None
                ),
                value.categorical if value is not None else None,
                value.text if value is not None else None,
                assessment.direction,
                assessment.range_min,
                assessment.range_max,
                assessment.threshold,
                assessment.evaluator.name,
                assessment.evaluator.version,
                assessment.evaluator.model,
                assessment.evaluator.config_digest,
                assessment.evaluator.prompt_digest,
                assessment.evaluator.rubric_digest,
                assessment.dataset_id,
                assessment.dataset_revision,
                assessment.dataset_item_id,
                assessment.started_at.isoformat(),
                assessment.finished_at.isoformat(),
                assessment.observed_at.isoformat(),
                error.type if error is not None else None,
                error.code if error is not None else None,
                assessment.model_dump_json(),
            ),
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _commit_connection(conn: sqlite3.Connection) -> None:
    """Small failure-injection seam for durable save tests."""

    conn.commit()


def save_run(record: RunRecord) -> None:
    # Lists are mutable even with validate_assignment. Persist only a freshly
    # validated snapshot so post-construction mutation cannot partially write.
    record = RunRecord.model_validate(record.model_dump(mode="python"))
    results_json = record.model_dump_json()
    results_file = record.model_dump_json(indent=2).encode("utf-8")
    if len(results_json.encode("utf-8")) > MAX_RESULTS_JSON_BYTES:
        raise ValueError("compact results JSON exceeds the 16 MiB state limit")
    if len(results_file) > MAX_RESULTS_JSON_BYTES:
        raise ValueError("formatted results JSON exceeds the 16 MiB state limit")
    prepare_run_dir(record)
    secure_run_tree(record.run_dir)
    results = record.run_dir / "results.json"
    descriptor, staged_name = tempfile.mkstemp(
        prefix=".results.json.stage-", dir=record.run_dir
    )
    staged = Path(staged_name)
    backup: Path | None = None
    published = False
    committed = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(results_file)
            stream.flush()
            os.fsync(stream.fileno())

        with closing(_connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                _write_record_rows(conn, record, results_json)
                if results.exists():
                    backup_descriptor, backup_name = tempfile.mkstemp(
                        prefix=".results.json.backup-", dir=record.run_dir
                    )
                    os.close(backup_descriptor)
                    backup = Path(backup_name)
                    backup.unlink()
                    os.replace(results, backup)
                os.replace(staged, results)
                published = True
                _fsync_directory(record.run_dir)
                _commit_connection(conn)
                committed = True
            except BaseException:
                if conn.in_transaction:
                    conn.rollback()
                raise
        if backup is not None:
            try:
                backup.unlink()
                _fsync_directory(record.run_dir)
            except OSError:
                # The committed database and canonical results file agree. A
                # private backup is safe to remove on a later secure tree pass.
                pass
            backup = None
    except BaseException:
        if not committed:
            if backup is not None and backup.exists():
                os.replace(backup, results)
                backup = None
            elif published:
                with suppress(FileNotFoundError):
                    results.unlink()
            _fsync_directory(record.run_dir)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        cleanup = (staged, backup) if committed else (staged,)
        for temporary in cleanup:
            if temporary is not None:
                with suppress(FileNotFoundError):
                    temporary.unlink()
    _secure_sqlite_files(create_database=False)


def load_runs(task_id: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
    if not _state_database_exists():
        return []
    with closing(_connect(create_database=False)) as conn:
        if task_id:
            cur = conn.execute(
                "SELECT * FROM runs WHERE task_id = ? ORDER BY started_at DESC LIMIT ?",
                (task_id, limit))
        else:
            cur = conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        for row in rows:
            record = RunRecord.model_validate_json(
                row["results_json"],
                extra="forbid",
            )
            _validate_run_projection(record, row)
        return rows


def load_run(
    run_id: str,
    *,
    forbid_extra: bool = False,
    validate_assessments: bool = False,
) -> RunRecord | None:
    """Load one run, optionally reconciling its normalized query projection."""

    if not _state_database_exists():
        return None
    with closing(_connect(create_database=False)) as conn:
        # Keep results_json and its normalized assessment projection on one
        # SQLite read snapshot. Verification must not accept contradictory
        # evidence from two independently observed database states.
        conn.execute("BEGIN")
        row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        record = RunRecord.model_validate_json(
            row["results_json"],
            extra="forbid" if forbid_extra else None,
        )
        _validate_run_projection(record, row)
        if validate_assessments:
            assessment_rows = tuple(
                dict(assessment_row)
                for assessment_row in conn.execute(
                    "SELECT * FROM assessments WHERE run_id = ? "
                    "ORDER BY assessment_id",
                    (run_id,),
                ).fetchall()
            )
            # State migration and live verification share one canonical row
            # projection so neither path can silently normalize a mismatch.
            from .state import _validate_assessment_rows

            _validate_assessment_rows({run_id: record}, assessment_rows)
        return record


def load_assessments(
    run_id: str | None = None,
    *,
    dataset_id: str | None = None,
    dataset_revision: str | None = None,
    dataset_item_id: str | None = None,
    source_kind: str | None = None,
    status: str | None = None,
    limit: int = 500,
) -> list[sqlite3.Row]:
    """Query normalized assessment rows without parsing results JSON."""

    if type(limit) is not int or not 1 <= limit <= 10_000:
        raise ValueError("assessment query limit must be between 1 and 10000")
    clauses: list[str] = []
    parameters: list[object] = []
    for column, value in (
        ("run_id", run_id),
        ("dataset_id", dataset_id),
        ("dataset_revision", dataset_revision),
        ("dataset_item_id", dataset_item_id),
        ("source_kind", source_kind),
        ("status", status),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    if not _state_database_exists():
        return []
    with closing(_connect(create_database=False)) as conn:
        return conn.execute(
            "SELECT * FROM assessments"
            + where
            + " ORDER BY observed_at DESC, assessment_id LIMIT ?",
            (*parameters, limit),
        ).fetchall()
