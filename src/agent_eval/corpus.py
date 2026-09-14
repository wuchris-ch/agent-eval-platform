"""Validation for versioned, executable pull-request review corpora."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .paths import validate_no_symlink_components
from .review_benchmark import BenchmarkManifest, parse_manifest_bytes
from .yaml_utils import load_unique_yaml

CORPUS_SCHEMA_VERSION = "1.0"
REPRODUCER_TIMEOUT_SECONDS = 60
REPRODUCER_OUTPUT_LIMIT_BYTES = 1024 * 1024
REPRODUCER_DETAIL_LIMIT_BYTES = 500
TREE_DIFF_TIMEOUT_SECONDS = 30
TREE_DIFF_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024
MAX_CORPUS_FILES = 4096
MAX_CORPUS_FILE_BYTES = 32 * 1024 * 1024
MAX_CORPUS_TOTAL_BYTES = 256 * 1024 * 1024
_REPRODUCER_ENV_ALLOWLIST = (
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ValueError("must be a safe relative path")
    return value


def _resolve(root: Path, value: str) -> Path:
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"path escapes corpus root: {value}") from exc
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


FileFingerprint = tuple[int, int, int, int, int, int]
CorpusInventory = dict[str, tuple[str, FileFingerprint]]


def _fingerprint(metadata: os.stat_result) -> FileFingerprint:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _scan_corpus_tree(root: Path) -> CorpusInventory:
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("corpus root must be a non-symlink directory")
    inventory: CorpusInventory = {}
    pending = [root]
    file_count = 0
    total_bytes = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                item_metadata = entry.stat(follow_symlinks=False)
                relative = Path(entry.path).relative_to(root).as_posix()
                if stat.S_ISLNK(item_metadata.st_mode):
                    raise ValueError(f"symlink is not allowed: {relative}")
                if stat.S_ISDIR(item_metadata.st_mode):
                    inventory[relative] = ("directory", _fingerprint(item_metadata))
                    pending.append(Path(entry.path))
                    continue
                if not stat.S_ISREG(item_metadata.st_mode):
                    raise ValueError(f"corpus contains a special file: {relative}")
                file_count += 1
                total_bytes += item_metadata.st_size
                if file_count > MAX_CORPUS_FILES:
                    raise ValueError("corpus exceeds the safe file-count limit")
                if item_metadata.st_size > MAX_CORPUS_FILE_BYTES:
                    raise ValueError(
                        f"corpus file exceeds the safe size limit: {relative}"
                    )
                if total_bytes > MAX_CORPUS_TOTAL_BYTES:
                    raise ValueError("corpus exceeds the safe total-byte limit")
                inventory[relative] = ("file", _fingerprint(item_metadata))
    return inventory


def _read_corpus_file_stable(path: Path, expected: FileFingerprint) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if _fingerprint(before) != expected or not stat.S_ISREG(before.st_mode):
            raise ValueError("corpus changed while its snapshot was created")
        output = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            output.extend(chunk)
            if len(output) > MAX_CORPUS_FILE_BYTES:
                raise ValueError("corpus file exceeds the safe size limit")
        after = os.fstat(descriptor)
        if _fingerprint(after) != expected or len(output) != after.st_size:
            raise ValueError("corpus changed while its snapshot was created")
        return bytes(output)
    finally:
        os.close(descriptor)


def _snapshot_corpus(path: Path | str, destination: Path) -> Path:
    source_manifest = validate_no_symlink_components(
        Path(os.path.abspath(Path(path).expanduser()))
    )
    source_root = source_manifest.parent
    inventory = _scan_corpus_tree(source_root)
    manifest_relative = source_manifest.relative_to(source_root).as_posix()
    manifest_entry = inventory.get(manifest_relative)
    if manifest_entry is None or manifest_entry[0] != "file":
        raise ValueError("corpus manifest must be a regular file")

    destination.mkdir(mode=0o700)
    for relative, (kind, fingerprint) in sorted(
        inventory.items(), key=lambda item: (item[0].count("/"), item[0])
    ):
        target = destination / relative
        if kind == "directory":
            target.mkdir(mode=0o700)
            continue
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = _read_corpus_file_stable(source_root / relative, fingerprint)
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        source_mode = stat.S_IMODE((source_root / relative).lstat().st_mode)
        private_mode = 0o600 | (0o100 if source_mode & 0o111 else 0)
        os.chmod(target, private_mode)

    if _scan_corpus_tree(source_root) != inventory:
        raise ValueError("corpus changed while its snapshot was created")
    return destination / manifest_relative


class Reproducer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: list[str]
    base_cwd: str
    head_cwd: str
    expected_base_exit: int = 0
    expected_head_exit: int

    @field_validator("command")
    @classmethod
    def _command_is_argv(cls, value: list[str]) -> list[str]:
        if not value or any(not item or "\x00" in item for item in value):
            raise ValueError("reproducer command must be a non-empty argv list")
        return value

    @field_validator("base_cwd", "head_cwd")
    @classmethod
    def _safe_paths(cls, value: str) -> str:
        return _safe_relative(value)


class CorpusCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["faulty", "clean"]
    diff: str
    reproducer: Reproducer
    artifact_sha256: dict[str, str]

    @field_validator("id")
    @classmethod
    def _safe_id(cls, value: str) -> str:
        if not _CASE_ID.fullmatch(value):
            raise ValueError("case id must be a safe path segment")
        return value

    @field_validator("diff")
    @classmethod
    def _safe_diff(cls, value: str) -> str:
        return _safe_relative(value)

    @field_validator("artifact_sha256")
    @classmethod
    def _valid_artifact_hashes(cls, value: dict[str, str]) -> dict[str, str]:
        if not value:
            raise ValueError("artifact_sha256 must bind at least one file")
        for path, digest in value.items():
            _safe_relative(path)
            if not _SHA256.fullmatch(digest):
                raise ValueError(f"invalid SHA-256 digest for {path}")
        return value

    @model_validator(mode="after")
    def _case_paths_and_polarity_are_bound(self) -> CorpusCase:
        prefix = ("cases", self.id)
        if PurePosixPath(self.diff).parts[:2] != prefix:
            raise ValueError(f"diff must stay beneath the case subtree cases/{self.id}")

        base_parts = PurePosixPath(self.reproducer.base_cwd).parts
        head_parts = PurePosixPath(self.reproducer.head_cwd).parts
        base_prefix = (*prefix, "base")
        head_prefix = (*prefix, "head")
        if base_parts[:3] != base_prefix:
            raise ValueError(
                f"reproducer base_cwd must stay beneath cases/{self.id}/base"
            )
        if head_parts[:3] != head_prefix:
            raise ValueError(
                f"reproducer head_cwd must stay beneath cases/{self.id}/head"
            )
        if base_parts[3:] != head_parts[3:]:
            raise ValueError(
                "reproducer base_cwd and head_cwd must use the same relative suffix"
            )

        if self.reproducer.expected_base_exit != 0:
            raise ValueError("reproducer expected_base_exit must be zero")
        if self.kind == "faulty" and self.reproducer.expected_head_exit == 0:
            raise ValueError("faulty case expected_head_exit must be nonzero")
        if self.kind == "clean" and self.reproducer.expected_head_exit != 0:
            raise ValueError("clean case expected_head_exit must be zero")
        return self


class CorpusManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    corpus_id: str
    version: str
    benchmark_manifest: str
    benchmark_sha256: str
    cases: list[CorpusCase]

    @field_validator("benchmark_manifest")
    @classmethod
    def _safe_benchmark(cls, value: str) -> str:
        return _safe_relative(value)

    @field_validator("benchmark_sha256")
    @classmethod
    def _valid_benchmark_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("benchmark_sha256 must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def _unique_cases(self) -> CorpusManifest:
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("corpus contains duplicate case ids")
        return self


class ReproducerResult(BaseModel):
    case_id: str
    base_exit: int | None
    head_exit: int | None
    passed: bool
    detail: str = ""


class CorpusValidation(BaseModel):
    corpus_id: str
    version: str
    valid: bool
    errors: list[str] = Field(default_factory=list)
    reproducers: list[ReproducerResult] = Field(default_factory=list)


def load_corpus(path: Path | str) -> tuple[CorpusManifest, Path]:
    manifest_path = Path(path).resolve()
    raw = load_unique_yaml(manifest_path.read_text(encoding="utf-8")) or {}
    return CorpusManifest.model_validate(raw), manifest_path.parent


def _added_lines(diff: str) -> set[tuple[str, int]]:
    locations: set[tuple[str, int]] = set()
    current_path: str | None = None
    head_line: int | None = None
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current_path = None
            head_line = None
            in_hunk = False
        elif not in_hunk and line.startswith("+++ "):
            raw = line[4:].strip()
            current_path = raw[2:] if raw.startswith("b/") else raw
            if raw == "/dev/null":
                current_path = None
        elif match := _HUNK.match(line):
            head_line = int(match.group("start")) if current_path else None
            in_hunk = True
        elif current_path is not None and head_line is not None:
            if line.startswith("+"):
                locations.add((current_path, head_line))
                head_line += 1
            elif line.startswith("-"):
                continue
            elif not line.startswith("\\ No newline"):
                head_line += 1
    return locations


def _changed_nonblank_lines(diff: str) -> int:
    """Count nonblank added source lines for the benchmark KLoC denominator."""

    count = 0
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
        elif _HUNK.match(line):
            in_hunk = True
        elif in_hunk and line.startswith("+") and line[1:].strip():
            count += 1
    return count


def _reproducer_environment() -> dict[str, str]:
    """Build a minimal environment without forwarding host credentials."""

    environment = {
        key: value
        for key in _REPRODUCER_ENV_ALLOWLIST
        if (value := os.environ.get(key)) is not None
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _git_diff_environment() -> dict[str, str]:
    environment = _reproducer_environment()
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    )
    return environment


def _terminate_reproducer(process: subprocess.Popen[bytes]) -> None:
    # Descendants can outlive a group leader while retaining captured pipes.
    # Always address the dedicated process group, even after the leader exits.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
    process.wait()


def _append_tail(tail: bytearray, chunk: bytes) -> None:
    tail.extend(chunk)
    overflow = len(tail) - REPRODUCER_DETAIL_LIMIT_BYTES
    if overflow > 0:
        del tail[:overflow]


def _run_reproducer_command(
    command: list[str], cwd: Path
) -> tuple[int | None, str, str | None]:
    """Run a trusted command with bounded output, duration, and environment."""

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=_reproducer_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        return None, "", type(exc).__name__

    assert process.stdout is not None
    assert process.stderr is not None
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    totals = dict.fromkeys(streams, 0)
    tails = {name: bytearray() for name in streams}
    selector = selectors.DefaultSelector()
    for name, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, data=name)

    deadline = time.monotonic() + REPRODUCER_TIMEOUT_SECONDS
    failure: str | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"timed out after {REPRODUCER_TIMEOUT_SECONDS:g} second(s)"
                break

            for key, _ in selector.select(timeout=min(remaining, 0.1)):
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue

                name = key.data
                totals[name] += len(chunk)
                _append_tail(tails[name], chunk)
                if totals[name] > REPRODUCER_OUTPUT_LIMIT_BYTES:
                    failure = (
                        f"{name} exceeded the "
                        f"{REPRODUCER_OUTPUT_LIMIT_BYTES}-byte limit"
                    )
                    break
            if failure is not None:
                break
    finally:
        selector.close()
        for stream in streams.values():
            if not stream.closed:
                stream.close()
        # A successful group leader may leave redirected background children
        # that no longer hold the captured pipes. Always tear down the group.
        _terminate_reproducer(process)

    output = b"\n".join(tails[name] for name in ("stdout", "stderr") if tails[name])
    detail = output[-REPRODUCER_DETAIL_LIMIT_BYTES:].decode("utf-8", errors="replace")
    if failure is not None:
        return None, detail, failure
    return process.wait(), detail, None


def _normalize_git_tree_diff(value: bytes) -> bytes:
    normalized: list[bytes] = []
    metadata_prefixes = (
        b"diff --git ",
        b"--- ",
        b"+++ ",
        b"Binary files ",
    )
    in_hunk = False
    for line in value.splitlines(keepends=True):
        if line.startswith(b"diff --git "):
            in_hunk = False
        elif line.startswith(b"@@ "):
            in_hunk = True
        if line.startswith(b"index "):
            continue
        if not in_hunk and line.startswith(metadata_prefixes):
            for source, destination in (
                (b"a/base/", b"a/"),
                (b"a/head/", b"a/"),
                (b"b/base/", b"b/"),
                (b"b/head/", b"b/"),
            ):
                line = line.replace(source, destination)
        normalized.append(line)
    return b"".join(normalized)


def _canonical_tree_diff(case_root: Path) -> tuple[bytes | None, str | None]:
    """Produce a bounded, configuration-independent base-to-head Git diff."""

    command = [
        "git",
        "-c",
        "diff.algorithm=myers",
        "-c",
        "core.autocrlf=false",
        "diff",
        "--no-index",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--binary",
        "--no-color",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--",
        "base",
        "head",
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=case_root,
            env={
                **_git_diff_environment(),
                "GIT_CEILING_DIRECTORIES": str(case_root),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        return None, f"canonical diff could not start: {type(exc).__name__}"

    assert process.stdout is not None
    assert process.stderr is not None
    streams = {process.stdout: "stdout", process.stderr: "stderr"}
    selector = selectors.DefaultSelector()
    output = bytearray()
    error_tail = bytearray()
    for stream, label in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, data=label)

    deadline = time.monotonic() + TREE_DIFF_TIMEOUT_SECONDS
    failure: str | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "canonical diff timed out"
                break
            for key, _ in selector.select(timeout=min(remaining, 0.1)):
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if key.data == "stdout":
                    output.extend(chunk)
                    if len(output) > TREE_DIFF_OUTPUT_LIMIT_BYTES:
                        failure = "canonical diff exceeded the output limit"
                        break
                else:
                    _append_tail(error_tail, chunk)
            if failure is not None:
                break
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
        _terminate_reproducer(process)

    if failure is not None:
        return None, failure
    if process.returncode not in (0, 1):
        return None, "canonical diff failed"
    return _normalize_git_tree_diff(bytes(output)), None


def _run_reproducer(
    root: Path,
    case: CorpusCase,
    expected_inventory: CorpusInventory | None = None,
) -> ReproducerResult:
    expected_inventory = expected_inventory or _scan_corpus_tree(root)
    exits: list[int | None] = []
    details: list[str] = []
    for label, cwd_value in (
        ("base", case.reproducer.base_cwd),
        ("head", case.reproducer.head_cwd),
    ):
        if _scan_corpus_tree(root) != expected_inventory:
            exits.extend([None] * (2 - len(exits)))
            details.append(f"{label}: corpus snapshot changed before execution")
            return ReproducerResult(
                case_id=case.id,
                base_exit=exits[0],
                head_exit=exits[1],
                passed=False,
                detail="; ".join(details),
            )
        cwd = _resolve(root, cwd_value)
        returncode, output, error = _run_reproducer_command(
            case.reproducer.command, cwd
        )
        exits.append(returncode)
        if error is not None:
            details.append(f"{label}: {error}")
        elif returncode:
            details.append(f"{label}: {output}")
        if _scan_corpus_tree(root) != expected_inventory:
            exits.extend([None] * (2 - len(exits)))
            details.append(f"{label}: reproducer mutated the corpus snapshot")
            return ReproducerResult(
                case_id=case.id,
                base_exit=exits[0],
                head_exit=exits[1],
                passed=False,
                detail="; ".join(details),
            )
    base_exit, head_exit = exits
    passed = (
        base_exit == case.reproducer.expected_base_exit
        and head_exit == case.reproducer.expected_head_exit
    )
    return ReproducerResult(
        case_id=case.id,
        base_exit=base_exit,
        head_exit=head_exit,
        passed=passed,
        detail="; ".join(details),
    )


def _case_artifacts(root: Path, case: CorpusCase) -> tuple[set[str], list[str]]:
    """Inventory regular files without following symlinks."""

    cases_root = root / "cases"
    case_root = cases_root / case.id
    if cases_root.is_symlink():
        return set(), [f"{case.id}: symlink is not allowed: cases"]
    if case_root.is_symlink():
        return set(), [f"{case.id}: symlink is not allowed: cases/{case.id}"]
    if not case_root.is_dir():
        return set(), [f"{case.id}: case artifact subtree is missing"]

    regular_files: set[str] = set()
    errors: list[str] = []
    for artifact in case_root.rglob("*"):
        relative = artifact.relative_to(root).as_posix()
        if artifact.is_symlink():
            errors.append(f"{case.id}: symlink is not allowed: {relative}")
        elif artifact.is_file():
            regular_files.add(relative)
        elif not artifact.is_dir():
            errors.append(f"{case.id}: special file is not allowed: {relative}")
    return regular_files, errors


def _validate_case_artifacts(root: Path, case: CorpusCase) -> list[str]:
    actual, errors = _case_artifacts(root, case)
    prefix = ("cases", case.id)
    declared = set(case.artifact_sha256)
    declared_in_case = {
        relative for relative in declared if PurePosixPath(relative).parts[:2] == prefix
    }

    for relative in sorted(declared - declared_in_case):
        errors.append(f"{case.id}: artifact is outside its case subtree: {relative}")
    if case.diff not in declared_in_case:
        errors.append(f"{case.id}: diff artifact is not hash-bound: {case.diff}")
    for relative in sorted(actual - declared_in_case):
        errors.append(f"{case.id}: unlisted artifact: {relative}")
    for relative in sorted(declared_in_case - actual):
        errors.append(f"{case.id}: artifact missing or not a regular file: {relative}")

    for relative in sorted(actual & declared_in_case):
        artifact = root / relative
        if _sha256(artifact) != case.artifact_sha256[relative]:
            errors.append(f"{case.id}: artifact hash mismatch: {relative}")
    return errors


def _validate_corpus_snapshot(
    path: Path | str, *, execute: bool = False
) -> CorpusValidation:
    manifest, root = load_corpus(path)
    benchmark_path = _resolve(root, manifest.benchmark_manifest)
    errors: list[str] = []
    benchmark_bytes = _read_corpus_file_stable(
        benchmark_path,
        _fingerprint(benchmark_path.lstat()),
    )
    if hashlib.sha256(benchmark_bytes).hexdigest() != manifest.benchmark_sha256:
        errors.append("benchmark manifest hash mismatch")
    benchmark: BenchmarkManifest = parse_manifest_bytes(benchmark_bytes)
    benchmark_by_id = {case.id: case for case in benchmark.cases}
    corpus_by_id = {case.id: case for case in manifest.cases}
    if set(benchmark_by_id) != set(corpus_by_id):
        errors.append("corpus and benchmark case ids differ")

    reproducers = []
    for case in manifest.cases:
        benchmark_case = benchmark_by_id.get(case.id)
        if benchmark_case is None:
            continue
        if case.kind == "clean" and benchmark_case.expected_findings:
            errors.append(f"{case.id}: clean case has expected findings")
        if case.kind == "faulty" and not benchmark_case.expected_findings:
            errors.append(f"{case.id}: faulty case has no expected findings")

        diff_path = _resolve(root, case.diff)
        if not diff_path.is_file():
            errors.append(f"{case.id}: diff artifact is missing")
            added = set()
        else:
            added = _added_lines(diff_path.read_text(encoding="utf-8"))
        for finding in benchmark_case.expected_findings:
            if not any(
                path == finding.file and finding.line_start <= line <= finding.line_end
                for path, line in added
            ):
                errors.append(
                    f"{case.id}: finding {finding.id} is not on an added diff line"
                )

        for label, cwd_value in (
            ("base", case.reproducer.base_cwd),
            ("head", case.reproducer.head_cwd),
        ):
            cwd = _resolve(root, cwd_value)
            if not cwd.is_dir():
                errors.append(f"{case.id}: {label} reproducer cwd is missing")

        artifact_errors = _validate_case_artifacts(root, case)
        errors.extend(artifact_errors)
        if not artifact_errors and diff_path.is_file():
            generated_diff, generation_error = _canonical_tree_diff(
                root / "cases" / case.id
            )
            if generation_error is not None:
                errors.append(f"{case.id}: {generation_error}")
            else:
                declared_diff = diff_path.read_bytes()
                if generated_diff != declared_diff:
                    errors.append(
                        f"{case.id}: diff artifact does not match the base/head trees"
                    )
                derived_changed_lines = _changed_nonblank_lines(
                    generated_diff.decode("utf-8", errors="surrogateescape")
                )
                if benchmark_case.changed_lines != derived_changed_lines:
                    errors.append(
                        f"{case.id}: benchmark changed_lines does not match "
                        "the verified diff"
                    )

    if execute and not errors:
        execution_inventory = _scan_corpus_tree(root)
        for case in manifest.cases:
            result = _run_reproducer(root, case, execution_inventory)
            reproducers.append(result)
            if not result.passed:
                errors.append(f"{case.id}: reproducer did not distinguish base/head")

    return CorpusValidation(
        corpus_id=manifest.corpus_id,
        version=manifest.version,
        valid=not errors,
        errors=errors,
        reproducers=reproducers,
    )


def validate_corpus(path: Path | str, *, execute: bool = False) -> CorpusValidation:
    """Validate an immutable private snapshot of a corpus and its reproducers."""

    with tempfile.TemporaryDirectory(prefix="agent-eval-corpus-snapshot-") as temporary:
        try:
            snapshot_manifest = _snapshot_corpus(
                path,
                Path(temporary) / "corpus",
            )
        except (OSError, ValueError) as exc:
            return CorpusValidation(
                corpus_id="unavailable",
                version="unavailable",
                valid=False,
                errors=[str(exc)],
            )
        return _validate_corpus_snapshot(snapshot_manifest, execute=execute)
