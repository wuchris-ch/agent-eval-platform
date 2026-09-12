"""Single-writer SQLite journal, sealed observations and reconstructible reports.

The journal and receipts are canonical. report.json is a disposable projection.
An exclusive OS lock spans execution; SQLite transactions never span agent calls.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from statistics import median

from ..blackbox.models import Report, Result, digest, json_bytes, parse_json
from ..limits import MAX_RESULTS_JSON_BYTES, read_stable_bounded_file
from ..paths import (
    atomic_write_private,
    ensure_private_directory,
    ensure_private_file,
    get_state_dir,
)
from .models import ExperimentStatus, Plan, Receipt, TrialStatus

SCHEMA_VERSION = 2


class JournalError(RuntimeError):
    """A safe, content-free state failure suitable for the CLI."""


class ExperimentBusy(JournalError):
    pass


def directory(experiment_id: str) -> Path:
    # Canonical UUID validation prevents path traversal and duplicate spellings.
    try:
        if str(uuid.UUID(experiment_id)) != experiment_id:
            raise ValueError
    except ValueError:
        raise JournalError("invalid experiment ID") from None
    return get_state_dir() / "experiments" / experiment_id


def read_json(path: Path):
    ensure_private_file(path, create=False)
    return parse_json(
        read_stable_bounded_file(path, maximum_bytes=MAX_RESULTS_JSON_BYTES)
    )


def immutable_json(path: Path, value: object) -> None:
    data = json_bytes(value)
    if len(data) >= MAX_RESULTS_JSON_BYTES:
        raise JournalError("artifact exceeds the size limit")
    if path.exists() or path.is_symlink():
        if json_bytes(read_json(path)) != data:
            raise JournalError("immutable artifact conflict")
    else:
        atomic_write_private(path, data + b"\n")


class Journal:
    def __init__(
        self, root: Path, connection: sqlite3.Connection, plan: Plan, *, write: bool
    ):
        self.root = root
        self.connection = connection
        self.plan = plan
        self.plan_sha256 = digest(plan.model_dump(mode="json"))
        self.write = write

    @classmethod
    def create(cls, plan: Plan, environment_key: bytes) -> str:
        root = directory(plan.experiment_id)
        ensure_private_directory(root.parent, parents=True)
        ensure_private_directory(root, exist_ok=False)
        for name in ("artifacts", "receipts"):
            ensure_private_directory(root / name)
        immutable_json(root / "plan.json", plan.model_dump(mode="json"))
        immutable_json(root / "suite.json", plan.suite.model_dump(mode="json"))
        atomic_write_private(root / "environment.key", environment_key)
        ensure_private_file(root / "writer.lock")
        database = ensure_private_file(root / "journal.db")
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript("""
                CREATE TABLE metadata (plan_sha256 TEXT NOT NULL);
                CREATE TABLE trials (
                    ordinal INTEGER PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL CHECK(state IN
                        ('queued','running','observed','completed','reconciliation_required','cancelled')),
                    observation_sha256 TEXT, result_sha256 TEXT,
                    CHECK ((state IN ('queued','running','reconciliation_required','cancelled')
                              AND observation_sha256 IS NULL AND result_sha256 IS NULL)
                        OR (state = 'observed' AND observation_sha256 IS NOT NULL AND result_sha256 IS NULL)
                        OR (state = 'completed' AND observation_sha256 IS NOT NULL AND result_sha256 IS NOT NULL))
                );
            """)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO metadata VALUES (?)",
                (digest(plan.model_dump(mode="json")),),
            )
            connection.executemany(
                "INSERT INTO trials VALUES (?, ?, 'queued', NULL, NULL)",
                [
                    (index, str(uuid.uuid4()))
                    for index in range(plan.trials * len(plan.suite.cases))
                ],
            )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.commit()
        # SQLite fsyncs its data; persist the directory entry before any dispatch.
        descriptor = os.open(root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return plan.experiment_id

    @classmethod
    @contextmanager
    def open(cls, experiment_id: str, *, write: bool = False):
        root = ensure_private_directory(directory(experiment_id), create=False)
        lock_fd = None
        connection = None
        try:
            if write:
                lock_path = ensure_private_file(root / "writer.lock", create=False)
                lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ExperimentBusy(
                        "experiment already has an active worker"
                    ) from None
            for name in ("artifacts", "receipts"):
                ensure_private_directory(root / name, create=False)
            database = ensure_private_file(root / "journal.db", create=False)
            # Never let SQLite follow a pre-existing sidecar symlink.
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = Path(str(database) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    ensure_private_file(sidecar, create=False)
            connection = sqlite3.connect(
                database.as_uri() + "?mode=rw", uri=True, timeout=5
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 1 and write:
                backup = ensure_private_file(root / "journal.v1.backup.db")
                with closing(sqlite3.connect(backup)) as saved:
                    connection.backup(saved)
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    original = connection.execute(
                        "SELECT sql FROM sqlite_master WHERE name='trials'"
                    ).fetchone()[0]
                    connection.execute("ALTER TABLE trials RENAME TO trials_v1")
                    revised = original.replace(
                        "'reconciliation_required'",
                        "'reconciliation_required','cancelled'",
                    )
                    connection.execute(revised)
                    connection.execute("INSERT INTO trials SELECT * FROM trials_v1")
                    connection.execute("DROP TABLE trials_v1")
                    connection.execute("PRAGMA user_version=2")
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (
                {1, SCHEMA_VERSION} if not write else {SCHEMA_VERSION}
            ):
                raise JournalError("unsupported or uninitialized journal schema")
            if connection.execute("PRAGMA quick_check").fetchall()[0][0] != "ok":
                raise JournalError("journal integrity check failed")
            if not write:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
            else:
                connection.execute("PRAGMA synchronous=FULL")
            plan = Plan.model_validate(read_json(root / "plan.json"))
            if plan.experiment_id != experiment_id:
                raise JournalError("experiment identity mismatch")
            journal = cls(root, connection, plan, write=write)
            identities = connection.execute(
                "SELECT plan_sha256 FROM metadata"
            ).fetchall()
            if len(identities) != 1 or identities[0][0] != journal.plan_sha256:
                raise JournalError("plan digest mismatch")
            if read_json(root / "suite.json") != plan.suite.model_dump(mode="json"):
                raise JournalError("suite snapshot mismatch")
            journal.rows()  # Verify the full planned matrix before any side effect.
            yield journal
        finally:
            if connection is not None:
                connection.close()
            if lock_fd is not None:
                os.close(lock_fd)

    def rows(self):
        rows = self.connection.execute(
            "SELECT * FROM trials ORDER BY ordinal"
        ).fetchall()
        count = self.plan.trials * len(self.plan.suite.cases)
        if [row["ordinal"] for row in rows] != list(range(count)):
            raise JournalError("trial matrix does not match the plan")
        for row in rows:
            TrialStatus(
                ordinal=row["ordinal"],
                attempt_id=row["attempt_id"],
                case_sha256=digest(self.plan.case_trial(row["ordinal"])[0].id),
                trial=self.plan.case_trial(row["ordinal"])[1],
                state=row["state"],
            )
        return rows

    def row(self, ordinal: int):
        self.plan.case_trial(ordinal)
        row = self.connection.execute(
            "SELECT * FROM trials WHERE ordinal=?", (ordinal,)
        ).fetchone()
        if row is None:
            raise JournalError("missing planned trial")
        return row

    def _transition(
        self, ordinal: int, previous: str, state: str, *, observation=None, result=None
    ):
        if not self.write:
            raise JournalError("a writer lock is required")
        with self.connection:
            changed = self.connection.execute(
                "UPDATE trials SET state=?, observation_sha256=?, result_sha256=? WHERE ordinal=? AND state=?",
                (state, observation, result, ordinal, previous),
            ).rowcount
            if changed != 1:
                raise JournalError("invalid trial transition")

    def cancel_requested(self):
        path = self.root / "cancel.json"
        if not path.exists() and not path.is_symlink():
            return False
        if read_json(path) != {"plan_sha256": self.plan_sha256}:
            raise JournalError("invalid cancellation binding")
        return True

    def cancel_queued(self):
        for row in self.rows():
            if row["state"] == "queued":
                self._transition(row["ordinal"], "queued", "cancelled")

    def claim(self, ordinal: int):
        self._transition(ordinal, "queued", "running")

    def blob(self, value: object) -> str:
        if not self.write:
            raise JournalError("a writer lock is required")
        sha = digest(value)
        immutable_json(self.root / "artifacts" / f"{sha}.json", value)
        return sha

    def load_blob(self, sha: str):
        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or any(c not in "0123456789abcdef" for c in sha)
        ):
            raise JournalError("invalid artifact digest")
        value = read_json(self.root / "artifacts" / f"{sha}.json")
        if digest(value) != sha:
            raise JournalError("artifact digest mismatch")
        return value

    def _receipt_path(self, row):
        return self.root / "receipts" / f"{row['attempt_id']}.json"

    def receipt(self, row) -> tuple[Receipt, str]:
        pointer = read_json(self._receipt_path(row))
        if not isinstance(pointer, dict) or set(pointer) != {"sha256"}:
            raise JournalError("invalid receipt pointer")
        sha = pointer["sha256"]
        receipt = Receipt.model_validate(self.load_blob(sha))
        if (receipt.plan_sha256, receipt.attempt_id, receipt.ordinal) != (
            self.plan_sha256,
            row["attempt_id"],
            row["ordinal"],
        ):
            raise JournalError("receipt identity mismatch")
        if row["observation_sha256"] is not None and row["observation_sha256"] != sha:
            raise JournalError("observation pointer mismatch")
        case, trial = self.plan.case_trial(row["ordinal"])
        if receipt.observation is not None:
            observation = receipt.observation
            if (observation.case_id, observation.trial, observation.input_sha256) != (
                case.id,
                trial,
                digest(case.input),
            ):
                raise JournalError("observation binding mismatch")
        return receipt, sha

    def observe(self, row, receipt: Receipt):
        # A durable named receipt survives a crash before the database update.
        sha = self.blob(receipt.model_dump(mode="json"))
        immutable_json(self._receipt_path(row), {"sha256": sha})
        self.receipt(row)
        self._transition(row["ordinal"], "running", "observed", observation=sha)

    def recover(self):
        """Only the exclusive writer can declare an abandoned dispatch ambiguous."""
        for row in self.rows():
            if row["state"] in {"running", "reconciliation_required"}:
                path = self._receipt_path(row)
                if path.exists() or path.is_symlink():
                    _, sha = self.receipt(row)
                    self._transition(
                        row["ordinal"], row["state"], "observed", observation=sha
                    )
                elif row["state"] == "running":
                    self._transition(
                        row["ordinal"], "running", "reconciliation_required"
                    )

    def complete(self, row, result: Result):
        receipt, sha = self.receipt(row)
        case, trial = self.plan.case_trial(row["ordinal"])
        if (result.case_id, result.trial, result.input_sha256, result.observation) != (
            case.id,
            trial,
            digest(case.input),
            receipt.observation,
        ):
            raise JournalError("result binding mismatch")
        value = {
            "plan_sha256": self.plan_sha256,
            "attempt_id": row["attempt_id"],
            "result": result.model_dump(mode="json"),
        }
        result_sha = self.blob(value)
        current = self.row(row["ordinal"])
        if current["state"] == "completed":
            if current["result_sha256"] != result_sha:
                raise JournalError("conflicting finalization")
            return
        self._transition(
            row["ordinal"], "observed", "completed", observation=sha, result=result_sha
        )

    def result(self, row) -> Result:
        receipt, _ = self.receipt(row)
        value = self.load_blob(row["result_sha256"])
        if not isinstance(value, dict) or set(value) != {
            "plan_sha256",
            "attempt_id",
            "result",
        }:
            raise JournalError("invalid result artifact")
        if (value["plan_sha256"], value["attempt_id"]) != (
            self.plan_sha256,
            row["attempt_id"],
        ):
            raise JournalError("result identity mismatch")
        result = Result.model_validate(value["result"])
        case, trial = self.plan.case_trial(row["ordinal"])
        if (result.case_id, result.trial, result.input_sha256, result.observation) != (
            case.id,
            trial,
            digest(case.input),
            receipt.observation,
        ) or result.error != receipt.error:
            # This executor only supports deterministic graders, which cannot
            # introduce a new judge error after a valid observation.
            raise JournalError("result does not match the observation")
        return result

    def status(self) -> ExperimentStatus:
        rows = self.rows()
        results = []
        trials = []
        for row in rows:
            if row["state"] == "completed":
                results.append(self.result(row))
            elif row["state"] == "observed":
                self.receipt(row)
            elif row["state"] == "queued" and self._receipt_path(row).exists():
                raise JournalError("queued trial has an unexpected receipt")
            case, trial = self.plan.case_trial(row["ordinal"])
            trials.append(
                TrialStatus(
                    ordinal=row["ordinal"],
                    attempt_id=row["attempt_id"],
                    case_sha256=digest(case.id),
                    trial=trial,
                    state=row["state"],
                )
            )
        all_complete = len(results) == len(rows)
        states = {row["state"] for row in rows}
        return ExperimentStatus(
            experiment_id=self.plan.experiment_id,
            state="completed"
            if all_complete
            else (
                "reconciliation_required"
                if "reconciliation_required" in states
                else "cancelled"
                if "cancelled" in states
                else "queued"
                if states == {"queued"}
                else "in_progress"
            ),
            planned=len(rows),
            completed=len(results),
            accepted=sum(r.outcome == "accepted" for r in results),
            rejected=sum(r.outcome == "rejected" for r in results),
            infra_errors=sum(r.outcome == "infra_error" for r in results),
            passed=all(r.outcome == "accepted" for r in results)
            if all_complete
            else None,
            trials=trials,
        )

    def export_report(self) -> Path:
        if not self.write:
            raise JournalError("a writer lock is required")
        if self.status().state != "completed":
            raise JournalError("incomplete experiments cannot export a passing report")
        results = [self.result(row) for row in self.rows()]
        latencies = [
            r.observation.latency_ms
            for r in results
            if r.observation and r.observation.latency_ms is not None
        ]
        report = Report(
            run_id=self.plan.experiment_id,
            created_at=self.plan.created_at,
            suite_id=self.plan.suite.id,
            suite_version=self.plan.suite.version,
            suite_sha256=self.plan.suite_sha256,
            agent=self.plan.agent,
            target_sha256=self.plan.target_sha256,
            mode="command",
            trials=self.plan.trials,
            evaluations=len(results),
            accepted=sum(r.outcome == "accepted" for r in results),
            rejected=sum(r.outcome == "rejected" for r in results),
            infra_errors=sum(r.outcome == "infra_error" for r in results),
            average_score=sum(r.score or 0 for r in results) / len(results),
            median_latency_ms=median(latencies) if latencies else None,
            passed=all(r.outcome == "accepted" for r in results),
            results=results,
        )
        payload = report.model_dump_json(indent=2).encode() + b"\n"
        if len(payload) > MAX_RESULTS_JSON_BYTES:
            raise JournalError(
                "report exceeds the export limit; per-trial artifacts remain available"
            )
        path = self.root / "report.json"
        # This file is a projection. Rebuild missing/corrupt exports from the journal.
        atomic_write_private(path, payload)
        return path


def request_cancel(experiment_id: str):
    with Journal.open(experiment_id) as journal:
        immutable_json(
            journal.root / "cancel.json", {"plan_sha256": journal.plan_sha256}
        )
