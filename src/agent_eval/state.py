"""Validated, explicit migration of legacy checkout-local run state."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from pydantic import ValidationError

from .limits import MAX_RESULTS_JSON_BYTES
from .paths import (
    UnsafeStatePathError,
    ensure_private_directory,
    secure_run_tree,
    validate_no_symlink_components,
)

_DATABASE_NAMES = frozenset(
    {"metrics.db", "metrics.db-journal", "metrics.db-shm", "metrics.db-wal"}
)


@dataclass(frozen=True)
class LegacyStateInventory:
    source: Path
    run_count: int
    file_count: int
    directory_count: int
    total_bytes: int


@dataclass(frozen=True)
class _Entry:
    relative: Path
    is_directory: bool
    fingerprint: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class _RunRow:
    run_id: str
    task_id: str
    agent: str
    trial: int
    results: dict[str, Any]


class _DuplicateJSONKey(ValueError):
    pass


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _fingerprint(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _unsafe_directory_open(path: Path, exc: OSError) -> UnsafeStatePathError:
    return UnsafeStatePathError(
        f"legacy state path changed or contains a non-directory link: {path}"
    )


def _open_directory_chain(path: Path) -> int:
    """Open every absolute path component without following a symlink."""

    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, _DIRECTORY_OPEN_FLAGS)
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            try:
                child = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _unsafe_directory_open(current, exc) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_relative_directory(root_fd: int, relative: Path) -> int:
    """Open a source directory beneath an already pinned root descriptor."""

    descriptor = os.open(".", _DIRECTORY_OPEN_FLAGS, dir_fd=root_fd)
    current = Path()
    try:
        for component in relative.parts:
            current /= component
            try:
                child = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _unsafe_directory_open(current, exc) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_source_file(root_fd: int, entry: _Entry) -> int:
    if entry.is_directory:
        raise ValueError(f"expected a regular file: {entry.relative}")
    parent_fd = _open_relative_directory(root_fd, entry.relative.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(entry.relative.name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise UnsafeStatePathError(
                f"legacy state file changed or became unsafe: {entry.relative}"
            ) from exc
    finally:
        os.close(parent_fd)
    if _fingerprint(os.fstat(descriptor)) != entry.fingerprint:
        os.close(descriptor)
        raise RuntimeError(f"legacy state changed during access: {entry.relative}")
    return descriptor


def _source_root(source: Path | str) -> Path:
    candidate = validate_no_symlink_components(Path(source).expanduser())
    try:
        metadata = candidate.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"legacy state directory does not exist: {candidate}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeStatePathError(
            f"legacy state must be a non-symlink directory: {candidate}"
        )
    return candidate


def _scan_source(root_fd: int) -> tuple[_Entry, ...]:
    """Inventory one descriptor-pinned tree without following any link."""

    entries: list[_Entry] = []
    pending: list[tuple[Path, tuple[int, int, int, int, int, int, int] | None]] = [
        (Path(), None)
    ]
    while pending:
        relative_directory, expected_fingerprint = pending.pop()
        directory_fd = _open_relative_directory(root_fd, relative_directory)
        try:
            if (
                expected_fingerprint is not None
                and _fingerprint(os.fstat(directory_fd)) != expected_fingerprint
            ):
                raise RuntimeError(
                    "legacy state changed during directory traversal: "
                    f"{relative_directory}"
                )
            ordered = sorted(os.listdir(directory_fd), key=os.fsencode)
            for name in ordered:
                relative = relative_directory / name
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise UnsafeStatePathError(
                        f"legacy state must not contain symlinks: {relative}"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    fingerprint = _fingerprint(metadata)
                    entries.append(_Entry(relative, True, fingerprint))
                    pending.append((relative, fingerprint))
                elif stat.S_ISREG(metadata.st_mode):
                    entries.append(_Entry(relative, False, _fingerprint(metadata)))
                else:
                    raise UnsafeStatePathError(
                        f"legacy state contains a special file: {relative}"
                    )
        finally:
            os.close(directory_fd)
    return tuple(sorted(entries, key=lambda item: os.fsencode(item.relative)))


def _copy_file(root_fd: int, destination: Path, expected: _Entry) -> None:
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_fd = _open_source_file(root_fd, expected)
    try:
        if _fingerprint(os.fstat(source_fd)) != expected.fingerprint:
            raise RuntimeError(
                f"legacy state changed during migration: {expected.relative}"
            )
        destination_fd = os.open(destination, write_flags, 0o600)
        try:
            with (
                os.fdopen(source_fd, "rb", closefd=False) as source_stream,
                os.fdopen(destination_fd, "wb", closefd=False) as destination_stream,
            ):
                shutil.copyfileobj(
                    source_stream, destination_stream, length=1024 * 1024
                )
                destination_stream.flush()
                os.fsync(destination_fd)
            if _fingerprint(os.fstat(source_fd)) != expected.fingerprint:
                raise RuntimeError(
                    f"legacy state changed during migration: {expected.relative}"
                )
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def _read_file_stable(root_fd: int, entry: _Entry) -> bytes:
    if entry.is_directory:
        raise ValueError(f"expected a regular file: {entry.relative}")
    if entry.fingerprint[3] > MAX_RESULTS_JSON_BYTES:
        raise ValueError(
            f"results.json exceeds the migration size limit: {entry.relative}"
        )
    descriptor = _open_source_file(root_fd, entry)
    try:
        if _fingerprint(os.fstat(descriptor)) != entry.fingerprint:
            raise RuntimeError(
                f"legacy state changed during inspection: {entry.relative}"
            )
        chunks: list[bytes] = []
        remaining = MAX_RESULTS_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > MAX_RESULTS_JSON_BYTES:
            raise ValueError(
                f"results.json exceeds the migration size limit: {entry.relative}"
            )
        if _fingerprint(os.fstat(descriptor)) != entry.fingerprint:
            raise RuntimeError(
                f"legacy state changed during inspection: {entry.relative}"
            )
        return content
    finally:
        os.close(descriptor)


def _database_entries(entries: tuple[_Entry, ...]) -> tuple[_Entry, ...]:
    selected = tuple(
        entry
        for entry in entries
        if not entry.is_directory
        and len(entry.relative.parts) == 1
        and entry.relative.name in _DATABASE_NAMES
    )
    if not any(entry.relative.name == "metrics.db" for entry in selected):
        raise ValueError("legacy state has no metrics.db")
    return selected


def _copy_database_snapshot(
    root_fd: int, entries: tuple[_Entry, ...], destination: Path
) -> None:
    for entry in _database_entries(entries):
        _copy_file(root_fd, destination / entry.relative, entry)


def _json_object(value: str | bytes, *, location: str) -> dict[str, Any]:
    if isinstance(value, bytes):
        encoded = value
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        raise ValueError(f"{location} must contain JSON text")
    if len(encoded) > MAX_RESULTS_JSON_BYTES:
        raise ValueError(f"{location} exceeds the migration size limit")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise _DuplicateJSONKey(f"duplicate JSON key {key!r}")
            result[key] = item
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    try:
        parsed = json.loads(
            encoded,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(
            f"{location} is not strict JSON: {type(exc).__name__}"
        ) from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{location} must contain a JSON object")
    return parsed


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _read_run_rows(root: Path) -> tuple[_RunRow, ...]:
    database = root / "metrics.db"
    uri = f"file:{quote(str(database), safe='/:')}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                raise ValueError("legacy metrics.db failed SQLite integrity_check")
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(runs)").fetchall()
            }
            required = {"run_id", "task_id", "agent", "trial", "results_json"}
            if not required <= columns:
                raise ValueError("legacy metrics.db has no compatible runs table")
            rows = connection.execute(
                "SELECT run_id, task_id, agent, trial, results_json "
                "FROM runs ORDER BY run_id"
            ).fetchall()
    except sqlite3.Error as exc:
        raise ValueError(f"legacy metrics.db is invalid: {type(exc).__name__}") from exc

    result: list[_RunRow] = []
    for row in rows:
        run_id, task_id, agent, trial, results_json = row
        if (
            not isinstance(run_id, str)
            or not isinstance(task_id, str)
            or not isinstance(agent, str)
            or type(trial) is not int
        ):
            raise ValueError("legacy metrics.db has invalid run identity values")
        result.append(
            _RunRow(
                run_id=run_id,
                task_id=task_id,
                agent=agent,
                trial=trial,
                results=_json_object(
                    results_json,
                    location=f"metrics.db results_json for run {run_id!r}",
                ),
            )
        )
    return tuple(result)


def _upgrade_database(root: Path) -> None:
    """Apply current additive migrations to a private copy before cutover."""

    from .metrics import _apply_schema_migrations

    database = root / "metrics.db"
    try:
        with closing(sqlite3.connect(database, timeout=5.0)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            with connection:
                _apply_schema_migrations(connection)
    except ValidationError as exc:
        raise ValueError(
            "legacy metrics.db contains an invalid results record"
        ) from exc
    except sqlite3.Error as exc:
        raise ValueError(
            f"legacy metrics.db cannot migrate: {type(exc).__name__}"
        ) from exc


def _validate_current_database(root: Path) -> tuple[int, int]:
    from .metrics import RunRecord, _validate_current_schema, _validate_run_projection

    database = root / "metrics.db"
    uri = f"file:{quote(str(database), safe='/:')}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            _validate_current_schema(connection)
            for row in connection.execute("SELECT * FROM runs").fetchall():
                try:
                    record = RunRecord.model_validate_json(
                        row["results_json"],
                        extra="forbid",
                    )
                except ValidationError as exc:
                    raise ValueError(
                        "metrics.db contains an invalid current results record"
                    ) from exc
                _validate_run_projection(record, row)
            run_count = int(
                connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            )
            assessment_count = int(
                connection.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
            )
            return run_count, assessment_count
    except sqlite3.Error as exc:
        raise ValueError(
            f"metrics.db current schema validation failed: {type(exc).__name__}"
        ) from exc


def _read_assessment_rows(root: Path) -> tuple[dict[str, Any], ...]:
    database = root / "metrics.db"
    uri = f"file:{quote(str(database), safe='/:')}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT * FROM assessments ORDER BY assessment_id"
            ).fetchall()
            return tuple(dict(row) for row in rows)
    except sqlite3.Error as exc:
        raise ValueError(
            f"metrics.db assessment validation failed: {type(exc).__name__}"
        ) from exc


def _snapshot_run_rows(
    root_fd: int,
    entries: tuple[_Entry, ...],
    *,
    prove_migratable: bool = False,
    require_current: bool = False,
) -> tuple[tuple[_RunRow, ...], tuple[dict[str, Any], ...]]:
    with tempfile.TemporaryDirectory(prefix="agent-eval-state-inspect-") as temporary:
        snapshot = Path(temporary)
        _copy_database_snapshot(root_fd, entries, snapshot)
        # Prove the source already has a readable runs table before any migration
        # can create or alter a schema in the private snapshot.
        rows = _read_run_rows(snapshot)
        if prove_migratable:
            _upgrade_database(snapshot)
            _validate_current_database(snapshot)
        elif require_current:
            _validate_current_database(snapshot)
        return rows, _read_assessment_rows(snapshot)


def _expected_assessment_row(assessment: Any, run_id: str) -> dict[str, Any]:
    value = assessment.value
    error = assessment.error
    return {
        "assessment_id": assessment.assessment_id,
        "run_id": run_id,
        "name": assessment.name,
        "source_kind": assessment.source_kind,
        "status": assessment.status,
        "value_type": value.type if value is not None else None,
        "numeric_value": value.numeric if value is not None else None,
        "boolean_value": (
            int(value.boolean)
            if value is not None and value.boolean is not None
            else None
        ),
        "categorical_value": value.categorical if value is not None else None,
        "text_value": value.text if value is not None else None,
        "direction": assessment.direction,
        "range_min": assessment.range_min,
        "range_max": assessment.range_max,
        "threshold": assessment.threshold,
        "evaluator_name": assessment.evaluator.name,
        "evaluator_version": assessment.evaluator.version,
        "evaluator_model": assessment.evaluator.model,
        "config_digest": assessment.evaluator.config_digest,
        "prompt_digest": assessment.evaluator.prompt_digest,
        "rubric_digest": assessment.evaluator.rubric_digest,
        "dataset_id": assessment.dataset_id,
        "dataset_revision": assessment.dataset_revision,
        "dataset_item_id": assessment.dataset_item_id,
        "started_at": assessment.started_at.isoformat(),
        "finished_at": assessment.finished_at.isoformat(),
        "observed_at": assessment.observed_at.isoformat(),
        "error_type": error.type if error is not None else None,
        "error_code": error.code if error is not None else None,
        "assessment_json": assessment.model_dump(mode="json"),
    }


def _validate_assessment_rows(
    records: dict[str, Any], rows: tuple[dict[str, Any], ...]
) -> None:
    expected = sorted(
        (
            _expected_assessment_row(assessment, record.run_id)
            for record in records.values()
            for assessment in record.assessments
        ),
        key=lambda row: row["assessment_id"],
    )
    actual: list[dict[str, Any]] = []
    for row in rows:
        normalized = dict(row)
        normalized["assessment_json"] = _json_object(
            normalized["assessment_json"],
            location=(
                "metrics.db assessment_json for assessment "
                f"{normalized['assessment_id']!r}"
            ),
        )
        actual.append(normalized)
    actual.sort(key=lambda row: str(row["assessment_id"]))
    if _canonical_json(actual) != _canonical_json(expected):
        raise ValueError(
            "metrics.db normalized assessments differ from results.json records"
        )


def _validate_run_tree(
    root_fd: int,
    entries: tuple[_Entry, ...],
    rows: tuple[_RunRow, ...],
) -> dict[str, Any]:
    from .metrics import RunRecord

    entry_by_path = {entry.relative: entry for entry in entries}
    direct_files = {
        entry.relative.name
        for entry in entries
        if not entry.is_directory and len(entry.relative.parts) == 1
    }
    unknown_files = direct_files - _DATABASE_NAMES
    if unknown_files:
        raise ValueError(
            "legacy state has unknown top-level files: "
            + ", ".join(sorted(unknown_files))
        )

    run_ids = {row.run_id for row in rows}
    if len(run_ids) != len(rows):
        raise ValueError("legacy metrics.db has duplicate run identities")
    if "admissions" in run_ids:
        raise ValueError("legacy run_id 'admissions' conflicts with reserved state")
    direct_directories = {
        entry.relative.name
        for entry in entries
        if entry.is_directory and len(entry.relative.parts) == 1
    }
    allowed_directories = run_ids | (
        {"admissions"} if "admissions" in direct_directories else set()
    )
    if direct_directories != allowed_directories:
        unknown = sorted(direct_directories - allowed_directories)
        missing = sorted(run_ids - direct_directories)
        detail = []
        if unknown:
            detail.append("orphan directories: " + ", ".join(unknown))
        if missing:
            detail.append("missing run directories: " + ", ".join(missing))
        raise ValueError(
            "legacy state does not match metrics.db (" + "; ".join(detail) + ")"
        )

    records: dict[str, Any] = {}
    for row in rows:
        result_path = Path(row.run_id) / "results.json"
        entry = entry_by_path.get(result_path)
        if entry is None or entry.is_directory:
            raise ValueError(f"legacy run {row.run_id!r} has no regular results.json")
        file_results = _json_object(
            _read_file_stable(root_fd, entry),
            location=str(result_path),
        )
        if _canonical_json(file_results) != _canonical_json(row.results):
            raise ValueError(
                f"legacy run {row.run_id!r} results.json differs from metrics.db"
            )
        try:
            record = RunRecord.model_validate_json(
                _canonical_json(row.results), extra="forbid"
            )
        except ValidationError as exc:
            raise ValueError(
                f"legacy run {row.run_id!r} has an invalid results record"
            ) from exc
        if (
            record.run_id != row.run_id
            or record.task_id != row.task_id
            or record.agent != row.agent
            or record.trial != row.trial
        ):
            raise ValueError(
                f"legacy run {row.run_id!r} identity differs from metrics.db"
            )
        records[row.run_id] = record
    return records


def _validated_entries(
    root_fd: int,
    *,
    prove_migratable: bool = False,
    require_current: bool = False,
) -> tuple[tuple[_Entry, ...], tuple[_RunRow, ...]]:
    root_fingerprint = _fingerprint(os.fstat(root_fd))
    entries = _scan_source(root_fd)
    rows, assessment_rows = _snapshot_run_rows(
        root_fd,
        entries,
        prove_migratable=prove_migratable,
        require_current=require_current,
    )
    records = _validate_run_tree(root_fd, entries, rows)
    _validate_assessment_rows(records, assessment_rows)
    if (
        _fingerprint(os.fstat(root_fd)) != root_fingerprint
        or _scan_source(root_fd) != entries
    ):
        raise RuntimeError("legacy state changed during inspection")
    return entries, rows


def _legacy_inventory(
    root: Path,
    entries: tuple[_Entry, ...],
    rows: tuple[_RunRow, ...],
) -> LegacyStateInventory:
    return LegacyStateInventory(
        source=root,
        run_count=len(rows),
        file_count=sum(not entry.is_directory for entry in entries),
        directory_count=sum(entry.is_directory for entry in entries),
        total_bytes=sum(
            entry.fingerprint[3] for entry in entries if not entry.is_directory
        ),
    )


def inspect_legacy_state(source: Path | str) -> LegacyStateInventory:
    """Validate a legacy state tree without modifying it or the destination."""

    root = _source_root(source)
    root_fd = _open_directory_chain(root)
    try:
        entries, rows = _validated_entries(root_fd, prove_migratable=True)
        return _legacy_inventory(root, entries, rows)
    finally:
        os.close(root_fd)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _install_state(temporary: Path, target: Path) -> None:
    """Atomically publish one tree without replacing a concurrent destination."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(temporary)
    target_bytes = os.fsencode(target)
    if sys.platform == "darwin":
        rename_exclusive = getattr(libc, "renamex_np", None)
        if rename_exclusive is None:
            raise OSError(errno.ENOTSUP, "exclusive rename is unavailable")
        rename_exclusive.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename_exclusive.restype = ctypes.c_int
        result = rename_exclusive(source_bytes, target_bytes, 0x00000004)
    elif sys.platform.startswith("linux"):
        rename_noreplace = getattr(libc, "renameat2", None)
        if rename_noreplace is None:
            raise OSError(errno.ENOTSUP, "no-replace rename is unavailable")
        rename_noreplace.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_noreplace.restype = ctypes.c_int
        result = rename_noreplace(-100, source_bytes, -100, target_bytes, 0x00000001)
    else:
        raise OSError(errno.ENOTSUP, "atomic no-replace state cutover is unsupported")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(
                error_number,
                "destination appeared during state migration; refusing replacement",
                target,
            )
        raise OSError(error_number, os.strerror(error_number), target)
    _fsync_directory(target.parent)


def migrate_legacy_state(
    source: Path | str,
    destination: Path | str,
) -> LegacyStateInventory:
    """Atomically copy one stable legacy tree to an absent private state root."""

    root = _source_root(source)
    target = validate_no_symlink_components(Path(destination).expanduser())
    if root == target or root in target.parents or target in root.parents:
        raise ValueError("legacy source and destination must be separate trees")

    try:
        target_metadata = target.lstat()
    except FileNotFoundError:
        target_metadata = None
    if target_metadata is not None:
        raise FileExistsError(
            "destination state must not exist; refusing to replace any existing "
            f"path: {target}"
        )

    ensure_private_directory(target.parent, parents=True)
    root_fd = _open_directory_chain(root)
    temporary: Path | None = None
    try:
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{target.name}.migrate-", dir=target.parent)
        )
        os.chmod(temporary, 0o700)
        entries, rows = _validated_entries(root_fd, prove_migratable=True)
        inventory = _legacy_inventory(root, entries, rows)
        for entry in entries:
            destination_path = temporary / entry.relative
            if entry.is_directory:
                destination_path.mkdir(mode=0o700)
            else:
                _copy_file(root_fd, destination_path, entry)
        if _scan_source(root_fd) != entries:
            raise RuntimeError("legacy state changed during migration")
        _upgrade_database(temporary)
        secure_run_tree(temporary)
        temporary_fd = _open_directory_chain(temporary)
        try:
            _post_entries, post_rows = _validated_entries(
                temporary_fd,
                require_current=True,
            )
        finally:
            os.close(temporary_fd)
        if len(post_rows) != inventory.run_count:
            raise RuntimeError("run count changed while migrating state")
        _install_state(temporary, target)
        return inventory
    except BaseException:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    finally:
        os.close(root_fd)
