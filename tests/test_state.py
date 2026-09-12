from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from agent_eval import metrics, paths
from agent_eval import cli as cli_module
from agent_eval import state as state_module
from agent_eval.assessments import (
    Assessment,
    AssessmentValue,
    EvaluatorIdentity,
    expected_assessment_id,
)
from agent_eval.governance import LegacyGovernanceEvidenceV1
from agent_eval.metrics import RunRecord
from agent_eval.paths import UnsafeStatePathError, get_state_dir
from agent_eval.state import inspect_legacy_state, migrate_legacy_state
from agent_eval.task import list_tasks, load_task
from typer.testing import CliRunner


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _record() -> RunRecord:
    return RunRecord(run_id="safe-run", task_id="safe-task", agent="test-agent")


def _assessment(
    run_id: str = "safe-run",
    name: str = "tests.resolved",
    evaluator_name: str = "tests",
) -> Assessment:
    timestamp = datetime(2026, 7, 14, tzinfo=UTC)
    draft = Assessment(
        assessment_id="0" * 64,
        run_id=run_id,
        name=name,
        source_kind="test",
        status="passed",
        value=AssessmentValue(type="boolean", boolean=True),
        direction="higher_is_better",
        evaluator=EvaluatorIdentity(name=evaluator_name),
        started_at=timestamp,
        finished_at=timestamp,
        observed_at=timestamp,
    )
    return draft.model_copy(
        update={"assessment_id": expected_assessment_id(draft)}
    )


def _write_task(root, task_id: str) -> None:
    task_dir = root / task_id
    task_dir.mkdir(parents=True)
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        f"id: {task_id}\n"
        "prompt: Test configured discovery\n"
        "test_command: pytest\n",
        encoding="utf-8",
    )


def test_state_directory_honors_explicit_environment(monkeypatch, tmp_path):
    configured = tmp_path / "configured-state"
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(configured))

    assert get_state_dir() == configured.resolve()


def test_configured_state_symlink_is_preserved_then_rejected(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    configured = tmp_path / "configured-state"
    configured.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(configured))
    monkeypatch.setattr(metrics, "RUNS_ROOT", get_state_dir())

    assert get_state_dir() == configured
    with pytest.raises(UnsafeStatePathError, match="symlink component"):
        metrics.load_runs()


def test_state_rejects_symlinked_ancestor(monkeypatch, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    ancestor = tmp_path / "ancestor"
    ancestor.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(metrics, "RUNS_ROOT", ancestor / "state")

    with pytest.raises(UnsafeStatePathError, match="symlink component"):
        metrics.save_run(_record())

    assert not (outside / "state").exists()


def test_private_state_parent_chain_is_owner_only_under_permissive_umask(tmp_path):
    destination = tmp_path / "missing-parent" / "missing-child" / "state"
    previous = os.umask(0)
    try:
        created = paths.ensure_private_directory(destination, parents=True)
    finally:
        os.umask(previous)

    assert created == destination
    for directory in (
        tmp_path / "missing-parent",
        tmp_path / "missing-parent" / "missing-child",
        destination,
    ):
        assert _mode(directory) == 0o700


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACL semantics")
def test_private_state_rejects_an_extended_acl_on_an_ancestor(tmp_path):
    ancestor = tmp_path / "acl-parent"
    ancestor.mkdir(mode=0o700)
    subprocess.run(
        [
            "/bin/chmod",
            "+a",
            (
                "everyone allow list,search,add_file,add_subdirectory,"
                "delete_child,file_inherit,directory_inherit"
            ),
            str(ancestor),
        ],
        check=True,
    )
    try:
        with pytest.raises(UnsafeStatePathError, match="extended allow ACL"):
            paths.ensure_private_directory(ancestor / "state", parents=True)
    finally:
        subprocess.run(["/bin/chmod", "-N", str(ancestor)], check=True)

    assert not (ancestor / "state").exists()


def test_state_directory_uses_native_macos_location(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_EVAL_STATE_DIR", raising=False)
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    monkeypatch.setattr(paths.Path, "home", classmethod(lambda _cls: tmp_path))

    assert get_state_dir() == (
        tmp_path / "Library" / "Application Support" / "agent-eval"
    )


def test_state_directory_uses_xdg_state_home(monkeypatch, tmp_path):
    xdg = tmp_path / "xdg-state"
    monkeypatch.delenv("AGENT_EVAL_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(xdg))
    monkeypatch.setattr(paths.sys, "platform", "linux")

    assert get_state_dir() == xdg / "agent-eval"


def test_task_discovery_uses_configured_tasks_and_keeps_bundled_fallback(
    monkeypatch, tmp_path
):
    configured = tmp_path / "configured-tasks"
    _write_task(configured, "custom-task")
    monkeypatch.setenv("AGENT_EVAL_TASKS_DIR", str(configured))

    custom = load_task("custom-task")
    bundled = load_task("example-todo-api")
    discovered = {task.id for task in list_tasks()}

    assert custom.path == configured / "custom-task"
    assert bundled.path.name == "example-todo-api"
    assert {"custom-task", "example-todo-api", "owasp-agentic-safety"} <= discovered


def test_save_run_is_private_atomic_and_migrated(monkeypatch, tmp_path):
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "state")
    record = _record()
    metrics.prepare_run_dir(record)
    nested = record.run_dir / "artifacts"
    nested.mkdir(mode=0o755)
    log = nested / "agent.log"
    log.write_text("private\n", encoding="utf-8")
    log.chmod(0o644)

    metrics.save_run(record)
    first_results = (record.run_dir / "results.json").stat().st_ino
    record.finished_at = "2026-07-14T12:00:00+00:00"
    metrics.save_run(record)
    results = record.run_dir / "results.json"

    assert results.stat().st_ino != first_results
    assert _mode(metrics.RUNS_ROOT) == 0o700
    assert _mode(record.run_dir) == 0o700
    assert _mode(nested) == 0o700
    assert _mode(log) == 0o600
    assert _mode(results) == 0o600
    assert _mode(metrics.RUNS_ROOT / "metrics.db") == 0o600

    with closing(metrics._connect()) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30_000
        migrations = {
            tuple(row)
            for row in conn.execute(
                "SELECT version, name FROM schema_migrations"
            ).fetchall()
        }
        assert (1, "initial-runs-schema") in migrations


def test_save_run_rejects_oversized_evidence_before_mutating_state(
    monkeypatch, tmp_path
):
    root = tmp_path / "state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)
    monkeypatch.setattr(metrics, "MAX_RESULTS_JSON_BYTES", 512)
    record = _record()
    record.scans.findings = [{"payload": "x" * 512}]

    with pytest.raises(ValueError, match="results JSON exceeds"):
        metrics.save_run(record)

    assert not root.exists()


@pytest.mark.parametrize("field", ["model", "requested_model"])
def test_agent_model_identity_is_bounded(field):
    with pytest.raises(ValidationError, match="at most 256"):
        metrics.AgentMetrics(**{field: "x" * 257})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "../escape"),
        ("run_id", "nested/run"),
        ("task_id", "nested\\task"),
        ("agent", "agent:tag"),
        ("agent", "agent name"),
    ],
)
def test_run_record_rejects_nonportable_identifiers(field, value):
    values = {"run_id": "run", "task_id": "task", "agent": "agent"}
    values[field] = value

    with pytest.raises(ValidationError, match="portable path-safe identifiers"):
        RunRecord(**values)


def test_run_record_revalidates_identifier_assignment():
    record = _record()

    with pytest.raises(ValidationError, match="portable path-safe identifiers"):
        record.run_id = "../../escape"

    assert record.run_id == "safe-run"


def test_save_run_rejects_symlink_state_root(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    state_link = tmp_path / "state-link"
    state_link.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(metrics, "RUNS_ROOT", state_link)

    with pytest.raises(UnsafeStatePathError, match="must not be a symlink"):
        metrics.save_run(_record())


def test_save_run_rejects_symlink_run_directory(monkeypatch, tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "safe-run").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)

    with pytest.raises(UnsafeStatePathError, match="must not be a symlink"):
        metrics.save_run(_record())


@pytest.mark.parametrize("name", ["results.json", "nested"])
def test_save_run_rejects_symlink_files_and_nested_directories(
    monkeypatch, tmp_path, name
):
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "state")
    record = _record()
    metrics.prepare_run_dir(record)
    outside = tmp_path / "outside"
    if name == "results.json":
        outside.write_text("do not overwrite\n", encoding="utf-8")
    else:
        outside.mkdir()
    (record.run_dir / name).symlink_to(
        outside,
        target_is_directory=name == "nested",
    )

    with pytest.raises(UnsafeStatePathError, match="must not contain symlinks"):
        metrics.save_run(record)


def test_sqlite_database_must_not_be_a_symlink(monkeypatch, tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    outside = tmp_path / "outside.db"
    with sqlite3.connect(outside):
        pass
    (root / "metrics.db").symlink_to(outside)
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)

    with pytest.raises(UnsafeStatePathError, match="must not be a symlink"):
        metrics.load_runs()


def test_metrics_runs_root_remains_monkeypatchable(monkeypatch, tmp_path):
    replacement = tmp_path / "replacement"
    monkeypatch.setattr(metrics, "RUNS_ROOT", replacement)
    record = _record()

    metrics.save_run(record)

    assert record.run_dir == replacement / record.run_id
    assert (replacement / "metrics.db").is_file()
    assert metrics.load_run(record.run_id) == record


def _write_legacy_state(root) -> RunRecord:
    root.mkdir()
    record = _record()
    run_dir = root / record.run_id
    run_dir.mkdir()
    (run_dir / "results.json").write_text(
        record.model_dump_json(indent=2), encoding="utf-8"
    )
    with sqlite3.connect(root / "metrics.db") as connection:
        connection.execute(metrics._RUNS_SCHEMA)
        connection.execute(
            "INSERT INTO runs (run_id, task_id, agent, trial, results_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                record.run_id,
                record.task_id,
                record.agent,
                record.trial,
                record.model_dump_json(),
            ),
        )
    return record


def test_state_migration_dry_runs_then_applies_atomically(monkeypatch, tmp_path):
    source = tmp_path / "legacy-runs"
    target = tmp_path / "native-state"
    record = _write_legacy_state(source)
    monkeypatch.setattr(metrics, "RUNS_ROOT", target)

    inventory = inspect_legacy_state(source)
    assert inventory.run_count == 1
    dry_run = CliRunner().invoke(
        cli_module.app, ["state", "migrate", "--from", str(source)]
    )

    assert dry_run.exit_code == 0
    assert "re-run with --apply" in dry_run.output
    assert not target.exists()

    applied = CliRunner().invoke(
        cli_module.app,
        ["state", "migrate", "--from", str(source), "--apply"],
    )

    assert applied.exit_code == 0, applied.exception
    assert "state migrated" in applied.output
    assert metrics.load_run(record.run_id) == record
    assert _mode(target) == 0o700
    assert _mode(target / "metrics.db") == 0o600
    assert _mode(target / record.run_id / "results.json") == 0o600
    with closing(metrics._connect()) as connection:
        migrations = {
            row[0] for row in connection.execute("SELECT version FROM schema_migrations")
        }
    assert {1, 2, 3} <= migrations


def test_state_migration_rejects_symlinked_legacy_content(tmp_path):
    source = tmp_path / "legacy-runs"
    _write_legacy_state(source)
    outside = tmp_path / "outside"
    outside.write_text("do not copy", encoding="utf-8")
    (source / "escape").symlink_to(outside)

    with pytest.raises(UnsafeStatePathError, match="must not contain symlinks"):
        inspect_legacy_state(source)


def test_read_apis_do_not_create_missing_state(monkeypatch, tmp_path):
    root = tmp_path / "missing-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)

    assert metrics.load_runs() == []
    assert metrics.load_run("missing") is None
    assert metrics.load_assessments() == []
    assert not root.exists()


def test_read_apis_allow_admissions_only_state(monkeypatch, tmp_path):
    root = tmp_path / "admissions-only"
    admission = root / "admissions" / "decision-1"
    admission.mkdir(parents=True)
    (admission / "request.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)

    assert metrics.load_runs() == []
    assert metrics.load_run("missing") is None
    assert metrics.load_assessments() == []
    assert not (root / "metrics.db").exists()
    assert _mode(root / "admissions") == 0o700
    assert _mode(admission / "request.json") == 0o600


def test_state_migration_requires_preexisting_compatible_database(tmp_path):
    source = tmp_path / "not-state"
    source.mkdir()
    (source / "note.txt").write_text("not state\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no metrics.db"):
        inspect_legacy_state(source)

    assert not (source / "metrics.db").exists()


@pytest.mark.parametrize("failure", ["missing", "mismatch", "orphan", "unknown"])
def test_state_migration_reconciles_database_and_run_tree(tmp_path, failure):
    source = tmp_path / "legacy-runs"
    record = _write_legacy_state(source)
    if failure == "missing":
        (source / record.run_id).rename(source / "moved-run")
    elif failure == "mismatch":
        changed = record.model_copy(update={"finished_at": "changed"})
        (source / record.run_id / "results.json").write_text(
            changed.model_dump_json(), encoding="utf-8"
        )
    elif failure == "orphan":
        (source / "orphan").mkdir()
    else:
        (source / "unknown.txt").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(ValueError, match="legacy (state|run)"):
        inspect_legacy_state(source)


def test_state_migration_rejects_nonfinite_and_duplicate_results_json(tmp_path):
    for label, suffix in (
        ("nonfinite", ', "unexpected": NaN}'),
        ("duplicate", ', "run_id": "safe-run"}'),
    ):
        source = tmp_path / label
        record = _write_legacy_state(source)
        payload = record.model_dump_json()[:-1] + suffix
        (source / record.run_id / "results.json").write_text(
            payload, encoding="utf-8"
        )
        with sqlite3.connect(source / "metrics.db") as connection:
            connection.execute(
                "UPDATE runs SET results_json = ? WHERE run_id = ?",
                (payload, record.run_id),
            )

        with pytest.raises(ValueError, match="not strict JSON"):
            inspect_legacy_state(source)


def test_state_migration_rejects_unknown_results_fields(tmp_path):
    source = tmp_path / "legacy-runs"
    record = _write_legacy_state(source)
    payload = record.model_dump(mode="json")
    payload["unexpected"] = "not part of the evidence schema"
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    (source / record.run_id / "results.json").write_text(
        encoded, encoding="utf-8"
    )
    with sqlite3.connect(source / "metrics.db") as connection:
        connection.execute(
            "UPDATE runs SET results_json = ? WHERE run_id = ?",
            (encoded, record.run_id),
        )

    with pytest.raises(ValueError, match="invalid results record"):
        inspect_legacy_state(source)


def test_state_migration_rejects_future_or_inconsistent_schema_ledgers(tmp_path):
    for label, version, name in (
        ("future", 99, "future"),
        ("inconsistent", 1, "wrong-name"),
    ):
        source = tmp_path / label
        _write_legacy_state(source)
        with sqlite3.connect(source / "metrics.db") as connection:
            connection.execute(metrics._MIGRATIONS_SCHEMA)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) "
                "VALUES (?, ?, ?)",
                (version, name, "2026-07-14T00:00:00+00:00"),
            )

        with pytest.raises(ValueError, match="schema"):
            inspect_legacy_state(source)


def test_state_migration_validates_current_indexes(monkeypatch, tmp_path):
    source = tmp_path / "current-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", source)
    metrics.save_run(_record())
    with sqlite3.connect(source / "metrics.db") as connection:
        connection.execute("DROP INDEX assessments_run_name_idx")

    with pytest.raises(ValueError, match="schema objects"):
        inspect_legacy_state(source)


def test_state_migration_rejects_executable_or_unknown_schema_objects(
    monkeypatch, tmp_path
):
    source = tmp_path / "current-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", source)
    metrics.save_run(_record())
    with sqlite3.connect(source / "metrics.db") as connection:
        connection.execute(
            "CREATE TRIGGER corrupt_run AFTER INSERT ON runs BEGIN "
            "UPDATE runs SET results_json = '{}' WHERE run_id = NEW.run_id; END"
        )

    with pytest.raises(ValueError, match="schema objects"):
        inspect_legacy_state(source)


def test_current_schema_rejects_hidden_generated_columns(monkeypatch, tmp_path):
    source = tmp_path / "current-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", source)
    metrics.save_run(_record())
    with sqlite3.connect(source / "metrics.db") as connection:
        connection.execute(
            "ALTER TABLE runs ADD COLUMN payload TEXT "
            "GENERATED ALWAYS AS (hex(zeroblob(1000000))) VIRTUAL"
        )

    with pytest.raises(ValueError, match="canonical schema"):
        inspect_legacy_state(source)


def test_current_schema_rejects_noncanonical_table_constraints(
    monkeypatch, tmp_path
):
    source = tmp_path / "current-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", source)
    metrics.save_run(_record())
    with sqlite3.connect(source / "metrics.db") as connection:
        sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'runs'"
        ).fetchone()[0]
        modified = sql.replace(
            "run_id TEXT PRIMARY KEY,",
            "run_id TEXT PRIMARY KEY CHECK (run_id != 'blocked'),",
        )
        version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_schema SET sql = ? "
            "WHERE type = 'table' AND name = 'runs'",
            (modified,),
        )
        connection.execute("PRAGMA writable_schema = OFF")
        connection.execute(f"PRAGMA schema_version = {version + 1}")

    with pytest.raises(ValueError, match="canonical schema"):
        inspect_legacy_state(source)


def test_state_migration_reconciles_normalized_assessments(monkeypatch, tmp_path):
    source = tmp_path / "current-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", source)
    record = _record()
    record.assessments = [_assessment()]
    metrics.save_run(record)
    with sqlite3.connect(source / "metrics.db") as connection:
        connection.execute(
            "UPDATE assessments SET status = 'failed' WHERE run_id = ?",
            (record.run_id,),
        )

    with pytest.raises(ValueError, match="normalized assessments differ"):
        inspect_legacy_state(source)


def test_read_apis_and_state_inspection_reject_run_projection_drift(
    monkeypatch,
    tmp_path,
):
    root = tmp_path / "projection-drift"
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)
    record = _record()
    metrics.save_run(record)
    with sqlite3.connect(root / "metrics.db") as connection:
        connection.execute(
            "UPDATE runs SET tests_passed = 999, tests_total = 999, cost_usd = 0 "
            "WHERE run_id = ?",
            (record.run_id,),
        )

    with pytest.raises(ValueError, match="run projection differs"):
        metrics.load_run(record.run_id)
    with pytest.raises(ValueError, match="run projection differs"):
        metrics.load_runs()
    with pytest.raises(ValueError, match="run projection differs"):
        inspect_legacy_state(root)


def test_schema_v2_assessments_rebuilds_to_canonical_v3_order(
    monkeypatch,
    tmp_path,
):
    root = tmp_path / "schema-v2-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)
    record = _record()
    record.assessments = [_assessment()]
    metrics.save_run(record)

    with sqlite3.connect(root / "metrics.db") as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP INDEX assessments_dataset_idx")
        for name in (
            "assessments_run_name_idx",
            "assessments_source_status_idx",
            "assessments_evaluator_idx",
        ):
            connection.execute(f"DROP INDEX {name}")
        connection.execute("ALTER TABLE assessments RENAME TO old_assessments")
        connection.execute(metrics._ASSESSMENTS_V2_SCHEMA)
        columns = [
            str(row[1])
            for row in connection.execute("PRAGMA table_info(assessments)")
        ]
        names = ", ".join(columns)
        connection.execute(
            f"INSERT INTO assessments ({names}) "
            f"SELECT {names} FROM old_assessments"
        )
        connection.execute("DROP TABLE old_assessments")
        for name in (
            "assessments_run_name_idx",
            "assessments_source_status_idx",
            "assessments_evaluator_idx",
        ):
            connection.execute(metrics._INDEX_SCHEMAS[name])
        connection.execute("DELETE FROM schema_migrations WHERE version = 3")

    with closing(metrics._connect()) as connection:
        columns = [
            str(row[1])
            for row in connection.execute("PRAGMA table_info(assessments)")
        ]
    assert columns.index("dataset_id") < columns.index("dataset_revision")
    assert metrics.load_run(record.run_id, validate_assessments=True) == record


def test_migration_requires_absent_destination_for_single_rename_cutover(
    monkeypatch, tmp_path
):
    source = tmp_path / "legacy-runs"
    record = _write_legacy_state(source)
    target = tmp_path / "native-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", target)
    with closing(metrics._connect()):
        pass

    with pytest.raises(FileExistsError, match="must not exist"):
        migrate_legacy_state(source, target)

    assert metrics.load_run(record.run_id) is None
    assert (source / record.run_id / "results.json").is_file()


def test_migration_atomic_cutover_never_replaces_racing_destination(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "legacy-runs"
    _write_legacy_state(source)
    target = tmp_path / "native-state"
    real_install = state_module._install_state

    def create_destination_before_cutover(temporary, destination):
        destination.mkdir()
        (destination / "concurrent-owner").write_text("preserve\n")
        real_install(temporary, destination)

    monkeypatch.setattr(
        state_module,
        "_install_state",
        create_destination_before_cutover,
    )

    with pytest.raises(FileExistsError, match="refusing replacement"):
        migrate_legacy_state(source, target)

    assert (target / "concurrent-owner").read_text() == "preserve\n"
    assert (source / "safe-run" / "results.json").is_file()
    assert not list(tmp_path.glob(".native-state.migrate-*"))


def test_migration_rejects_same_size_rewrite_with_restored_mtime(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "legacy-runs"
    _write_legacy_state(source)
    target = tmp_path / "native-state"
    result_path = source / "safe-run" / "results.json"
    copy_file = state_module._copy_file
    attacked = False

    def rewrite_before_copy(root_fd, destination, entry):
        nonlocal attacked
        if entry.relative == Path("safe-run/results.json") and not attacked:
            attacked = True
            before = result_path.stat()
            original = result_path.read_text(encoding="utf-8")
            changed = original.replace("safe-task", "evil-task")
            assert len(changed.encode()) == len(original.encode())
            result_path.write_text(changed, encoding="utf-8")
            os.utime(
                result_path,
                ns=(before.st_atime_ns, before.st_mtime_ns),
                follow_symlinks=False,
            )
            after = result_path.stat()
            assert after.st_size == before.st_size
            assert after.st_mtime_ns == before.st_mtime_ns
            assert after.st_ctime_ns != before.st_ctime_ns
        copy_file(root_fd, destination, entry)

    monkeypatch.setattr(state_module, "_copy_file", rewrite_before_copy)

    with pytest.raises(RuntimeError, match="changed during access"):
        migrate_legacy_state(source, target)

    assert attacked
    assert not target.exists()


def test_migration_rejects_racing_symlinked_source_ancestor(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "legacy-runs"
    _write_legacy_state(source)
    target = tmp_path / "native-state"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "results.json").write_text("outside\n", encoding="utf-8")
    copy_file = state_module._copy_file
    attacked = False

    def swap_ancestor_before_copy(root_fd, destination, entry):
        nonlocal attacked
        if entry.relative == Path("safe-run/results.json") and not attacked:
            attacked = True
            (source / "safe-run").rename(source / "original-run")
            (source / "safe-run").symlink_to(outside, target_is_directory=True)
        copy_file(root_fd, destination, entry)

    monkeypatch.setattr(state_module, "_copy_file", swap_ancestor_before_copy)

    with pytest.raises(UnsafeStatePathError, match="path changed"):
        migrate_legacy_state(source, target)

    assert attacked
    assert not target.exists()
    assert (outside / "results.json").read_text(encoding="utf-8") == "outside\n"


def test_migration_fsync_failure_leaves_only_the_complete_renamed_tree(
    monkeypatch, tmp_path
):
    source = tmp_path / "legacy-runs"
    _write_legacy_state(source)
    target = tmp_path / "native-state"
    monkeypatch.setattr(metrics, "RUNS_ROOT", target)
    fsync = state_module._fsync_directory
    calls = 0

    def fail_first_fsync(path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected cutover fsync failure")
        fsync(path)

    monkeypatch.setattr(state_module, "_fsync_directory", fail_first_fsync)
    with pytest.raises(OSError, match="injected"):
        migrate_legacy_state(source, target)

    assert metrics.load_run("safe-run") is not None
    assert (source / "safe-run" / "results.json").is_file()


def test_migration_refuses_nonempty_or_uninitialized_destination(
    monkeypatch, tmp_path
):
    source = tmp_path / "legacy-runs"
    _write_legacy_state(source)
    target = tmp_path / "target"
    monkeypatch.setattr(metrics, "RUNS_ROOT", target)
    metrics.save_run(RunRecord(run_id="existing", task_id="task", agent="agent"))

    with pytest.raises(FileExistsError, match="must not exist"):
        migrate_legacy_state(source, target)

    empty_directory = tmp_path / "uninitialized"
    empty_directory.mkdir()
    with pytest.raises(FileExistsError, match="must not exist"):
        migrate_legacy_state(source, empty_directory)


def test_migration_rejects_symlinked_source_and_destination_ancestors(tmp_path):
    real_source_parent = tmp_path / "real-source"
    real_source_parent.mkdir()
    source = real_source_parent / "runs"
    _write_legacy_state(source)
    source_link = tmp_path / "source-link"
    source_link.symlink_to(real_source_parent, target_is_directory=True)

    with pytest.raises(UnsafeStatePathError, match="symlink component"):
        inspect_legacy_state(source_link / "runs")

    destination_parent = tmp_path / "destination-real"
    destination_parent.mkdir()
    destination_link = tmp_path / "destination-link"
    destination_link.symlink_to(destination_parent, target_is_directory=True)
    with pytest.raises(UnsafeStatePathError, match="symlink component"):
        migrate_legacy_state(source, destination_link / "state")


def test_migration_secures_writable_destination_parent_before_staging(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "legacy-runs"
    _write_legacy_state(source)
    destination_parent = tmp_path / "replaceable-parent"
    destination_parent.mkdir(mode=0o700)
    destination_parent.chmod(0o777)
    target = destination_parent / "state"
    make_temporary = state_module.tempfile.mkdtemp
    staged = False

    def assert_private_parent(*args, **kwargs):
        nonlocal staged
        directory = kwargs.get("dir", args[2] if len(args) > 2 else None)
        if directory is not None and Path(directory) == destination_parent:
            staged = True
            assert stat.S_IMODE(destination_parent.stat().st_mode) == 0o700
        return make_temporary(*args, **kwargs)

    monkeypatch.setattr(state_module.tempfile, "mkdtemp", assert_private_parent)

    migrated = migrate_legacy_state(source, target)

    assert migrated.run_count == 1
    assert staged
    assert stat.S_IMODE(destination_parent.stat().st_mode) == 0o700
    assert (target / "safe-run" / "results.json").is_file()


def test_run_record_requires_assessment_ownership_identity_and_uniqueness(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "state")
    record = _record()
    record.assessments.append(_assessment(run_id="another-run"))
    with pytest.raises(ValidationError, match="belong to the record"):
        metrics.save_run(record)
    assert not metrics.RUNS_ROOT.exists()

    record = _record()
    forged = _assessment().model_copy(update={"name": "tests.forged"})
    record.assessments.append(forged)
    with pytest.raises(ValidationError, match="deterministic identity"):
        metrics.save_run(record)
    assert not metrics.RUNS_ROOT.exists()

    record = _record()
    assessment = _assessment()
    record.assessments.extend([assessment, assessment])
    with pytest.raises(ValidationError, match="assessment_id values must be unique"):
        metrics.save_run(record)

    record = _record()
    record.assessments.extend(
        [assessment, _assessment(evaluator_name="alternate-tests")]
    )
    with pytest.raises(ValidationError, match="assessment names must be unique"):
        metrics.save_run(record)


def test_save_run_restores_file_and_database_when_commit_fails(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "state")
    original = _record()
    metrics.save_run(original)
    results = original.run_dir / "results.json"
    original_file = results.read_bytes()
    changed = original.model_copy(update={"finished_at": "changed"})

    def fail_commit(_connection):
        raise sqlite3.OperationalError("injected commit failure")

    monkeypatch.setattr(metrics, "_commit_connection", fail_commit)
    with pytest.raises(sqlite3.OperationalError, match="injected"):
        metrics.save_run(changed)

    assert results.read_bytes() == original_file
    assert metrics.load_run(original.run_id) == original


def test_save_run_restores_existing_file_when_publication_fails(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "state")
    original = _record()
    metrics.save_run(original)
    results = original.run_dir / "results.json"
    original_file = results.read_bytes()
    changed = original.model_copy(update={"finished_at": "changed"})
    replace = os.replace

    def fail_staged_replace(source, destination):
        if Path(source).name.startswith(".results.json.stage-"):
            raise OSError("injected publication failure")
        replace(source, destination)

    monkeypatch.setattr(metrics.os, "replace", fail_staged_replace)
    with pytest.raises(OSError, match="injected"):
        metrics.save_run(changed)

    assert results.read_bytes() == original_file
    assert metrics.load_run(original.run_id) == original


def test_strict_legacy_governance_evidence_remains_persistable(
    monkeypatch, tmp_path
):
    legacy = LegacyGovernanceEvidenceV1.model_validate(
        {
            "schema_version": "agent-eval.governance-evidence/v1",
            "decision_stage": "execution",
            "preflight_decision_id": UUID(
                "12345678-1234-5678-9234-567812345671"
            ),
            "preflight_decision_digest": "a" * 64,
            "decision_id": UUID("12345678-1234-5678-9234-567812345672"),
            "trace_id": "b" * 32,
            "decided_at": datetime(2026, 7, 14, tzinfo=UTC),
            "allowed": True,
            "request_id": UUID("12345678-1234-5678-9234-567812345673"),
            "idempotency_key": "legacy:run",
            "tenant_id": "tenant",
            "project_id": "project",
            "asserted_actor": "user:operator",
            "identity_assurance": "asserted-unverified",
            "data_classification": "internal",
            "retention_class": "standard",
            "request_digest": "c" * 64,
            "policy_id": "policy",
            "policy_revision": "v1",
            "policy_digest": "d" * 64,
            "registry_id": "models",
            "registry_revision": "v1",
            "registry_digest": "e" * 64,
            "task_tree_sha256": "f" * 64,
            "execution_spec_digest": "1" * 64,
            "task_image_digest": "sha256:" + "2" * 64,
            "task_image_ref": "agent-eval/task:governed-" + "3" * 64,
            "task_image_platform": "linux/amd64",
            "run_scans": True,
            "run_judge": False,
            "judge_backend": None,
            "judge_model": None,
            "reason_codes": ["admitted"],
            "effective_limits": {
                "max_trials": 1,
                "max_agent_seconds": 60,
                "max_eval_seconds": 60,
                "max_total_tokens": 1000,
                "max_cost_usd": 1.0,
            },
            "matched_model": None,
            "matched_judge": None,
        }
    )
    record = _record()
    record.governance = legacy
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "state")

    metrics.save_run(record)
    loaded = metrics.load_run(record.run_id, forbid_extra=True)

    assert loaded is not None
    assert loaded.governance == legacy
    assert loaded.governance.schema_version == "agent-eval.governance-evidence/v1"


def test_permission_checks_do_not_invalidate_a_concurrent_evidence_read(
    tmp_path, monkeypatch
):
    from agent_eval import limits
    from agent_eval.paths import (
        ensure_private_directory,
        ensure_private_file,
        secure_run_tree,
    )

    root = ensure_private_directory(tmp_path / "private")
    evidence = ensure_private_file(root / "evidence.json")
    evidence.write_bytes(b'{"observed":true}')
    original_read = limits.os.read
    checked = False

    def read_after_permission_check(descriptor, size):
        nonlocal checked
        if not checked:
            checked = True
            ensure_private_file(evidence, create=False)
            secure_run_tree(root)
        return original_read(descriptor, size)

    monkeypatch.setattr(limits.os, "read", read_after_permission_check)
    assert (
        limits.read_stable_bounded_file(evidence, maximum_bytes=100)
        == b'{"observed":true}'
    )
    assert checked
