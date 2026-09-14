"""Unsigned, locally verifiable provenance for agent-eval artifacts.

The format deliberately separates integrity from authenticity.  The statement
and its SHA-256 sidecar can detect accidental or uncoordinated changes, but
neither is signed and neither proves who produced an artifact.

Statements use the in-toto Statement v1 envelope with an agent-eval-specific
predicate.  Artifact names are always relative to an explicit root.  During
verification they are treated as hostile input: absolute paths, traversal,
ambiguous separators, and symlinked path components are rejected before any
artifact is opened.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .yaml_utils import load_unique_yaml

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/wuchris-ch/agent-eval-k3s/attestation/v1"
PREDICATE_SCHEMA_VERSION = 1
TREE_ALGORITHM = "agent-eval-tree-sha256-v1"
GIT_WORKTREE_ALGORITHM = "agent-eval-git-worktree-sha256-v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DRIVE_OR_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_CHUNK_SIZE = 1024 * 1024
MAX_ATTESTATION_STATEMENT_BYTES = 16 * 1024 * 1024
MAX_ATTESTATION_SUBJECTS = 10_000
MAX_ARTIFACT_FILES = 50_000
MAX_JSON_DEPTH = 100
MAX_SIDECAR_BYTES = 1024


class AttestationError(ValueError):
    """Raised when provenance inputs cannot be represented safely."""


class GitState(BaseModel):
    """Git state bound into the provenance predicate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sha: str
    dirty: bool
    worktree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AttestationBundle(BaseModel):
    """Paths and digest returned after writing an attestation bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    statement_path: Path
    sidecar_path: Path
    statement_sha256: str
    subject_count: int = Field(ge=0)


class VerificationFailure(BaseModel):
    """One machine-readable reason a local verification did not succeed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    path: str | None = None
    expected: str | None = None
    actual: str | None = None


class VerificationResult(BaseModel):
    """Complete local verification result.

    ``ok`` means the unsigned statement, sidecar, and requested local evidence
    agree.  It is an integrity result, not an authenticity result.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    failures: list[VerificationFailure] = Field(default_factory=list)
    statement_sha256: str | None = None
    sidecar_verified: bool = False
    subjects_declared: int = 0
    subjects_checked: int = 0
    task_checked: bool = False
    harness_checked: bool = False
    predicate: dict[str, Any] | None = None
    subject_digests: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True)
class _TreeScan:
    files: frozenset[str]
    unsafe: tuple[tuple[str, str], ...]


def _json_value(value: Any, *, location: str = "value", depth: int = 0) -> Any:
    """Return a deterministic JSON-compatible copy or raise AttestationError."""

    if depth > MAX_JSON_DEPTH:
        raise AttestationError(f"{location} exceeds the maximum JSON depth")

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    elif isinstance(value, Enum):
        value = value.value
    elif isinstance(value, Path):
        value = str(value)
    elif isinstance(value, (datetime, date)):
        value = value.isoformat()

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AttestationError(f"{location} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AttestationError(f"{location} contains a non-string key")
            normalized[key] = _json_value(
                item,
                location=f"{location}.{key}",
                depth=depth + 1,
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _json_value(
                item,
                location=f"{location}[{index}]",
                depth=depth + 1,
            )
            for index, item in enumerate(value)
        ]
    raise AttestationError(
        f"{location} contains unsupported value type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a JSON value deterministically, without a trailing newline."""

    normalized = _json_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_statement_bytes(statement: Mapping[str, Any]) -> bytes:
    """Return the exact canonical bytes written for a statement."""

    return canonical_json_bytes(statement) + b"\n"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _worktree_digest(
    staged_diff: bytes,
    unstaged_diff: bytes,
    untracked_records: Iterable[Mapping[str, Any]],
) -> str:
    """Hash canonical Git worktree evidence with unambiguous boundaries."""

    digest = hashlib.sha256()
    digest.update(GIT_WORKTREE_ALGORITHM.encode("ascii") + b"\x00")
    for label, data in (
        (b"staged-diff", staged_diff),
        (b"unstaged-diff", unstaged_diff),
    ):
        digest.update(label + b"\x00")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    for record in untracked_records:
        data = canonical_json_bytes(record)
        digest.update(b"untracked\x00")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


CLEAN_WORKTREE_SHA256 = _worktree_digest(b"", b"", ())


def _hash_open_file(fd: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(fd, _CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: str | Path) -> str:
    """Hash one regular file without following a final symlink."""

    target = os.fspath(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AttestationError(f"not a regular file: {path}")
        return _hash_open_file(fd)
    finally:
        os.close(fd)


def _read_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_ATTESTATION_STATEMENT_BYTES,
) -> bytes:
    """Read one stable regular file without following its final symlink."""

    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode):
        raise AttestationError(f"{label} must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise AttestationError(f"{label} must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise AttestationError(f"{label} must be a regular file")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise AttestationError(f"{label} changed while it was opened")
        if opened.st_size > max_bytes:
            raise AttestationError(f"{label} exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(fd, min(_CHUNK_SIZE, max_bytes - size + 1)):
            size += len(chunk)
            if size > max_bytes:
                raise AttestationError(f"{label} exceeds {max_bytes} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_regular_file(
    path: str | Path,
    *,
    label: str = "file",
    max_bytes: int = MAX_ATTESTATION_STATEMENT_BYTES,
) -> bytes:
    """Return a no-follow snapshot of one stable regular file."""

    return _read_regular_file(Path(path), label=label, max_bytes=max_bytes)


def _directory_root(path: str | Path, *, label: str) -> Path:
    try:
        root = Path(path).expanduser().resolve(strict=True)
    except OSError as exc:
        raise AttestationError(f"{label} does not exist: {path}") from exc
    if not root.is_dir():
        raise AttestationError(f"{label} is not a directory: {path}")
    return root


def _safe_relative_name(value: Any) -> str:
    if not isinstance(value, str):
        raise AttestationError("artifact name must be a string")
    if not value or value != value.strip():
        raise AttestationError("artifact name must be non-empty and unpadded")
    if "\x00" in value or "\\" in value:
        raise AttestationError("artifact name contains an unsafe separator")
    if value.startswith(("/", "~")) or _DRIVE_OR_URI_RE.match(value):
        raise AttestationError("artifact name must be repository-relative")
    raw_parts = value.split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        raise AttestationError("artifact name contains traversal or ambiguity")
    path = PurePosixPath(value)
    if path.is_absolute() or tuple(path.parts) != tuple(raw_parts):
        raise AttestationError("artifact name is not a canonical relative path")
    return path.as_posix()


def _relative_input_name(root: Path, value: str | Path) -> str:
    path = Path(value)
    if path.is_absolute():
        try:
            relative = Path(os.path.abspath(path)).relative_to(root)
        except ValueError as exc:
            raise AttestationError(f"artifact is outside its root: {value}") from exc
        return _safe_relative_name(relative.as_posix())
    return _safe_relative_name(path.as_posix())


def _open_regular_beneath(root: Path, name: str) -> int:
    """Open a regular file beneath root without following any symlink."""

    safe_name = _safe_relative_name(name)
    parts = PurePosixPath(safe_name).parts
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(root, directory_flags)
    current_fd = root_fd
    opened_directories: list[int] = []
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                directory_flags | nofollow,
                dir_fd=current_fd,
            )
            opened_directories.append(next_fd)
            current_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=current_fd)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            os.close(file_fd)
            raise AttestationError(f"artifact is not a regular file: {safe_name}")
        return file_fd
    finally:
        for directory_fd in reversed(opened_directories):
            os.close(directory_fd)
        os.close(root_fd)


def _read_regular_beneath(
    root: Path,
    name: str,
    *,
    max_bytes: int = MAX_ATTESTATION_STATEMENT_BYTES,
) -> bytes:
    fd = _open_regular_beneath(root, name)
    try:
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(_CHUNK_SIZE, max_bytes + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise AttestationError(f"artifact exceeds {max_bytes} bytes: {name}")
    finally:
        os.close(fd)


def _hash_regular_beneath(root: Path, name: str) -> str:
    fd = _open_regular_beneath(root, name)
    try:
        return _hash_open_file(fd)
    finally:
        os.close(fd)


def _tree_records(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    visited_entries = 0

    def visit(
        directory: Path,
        prefix: PurePosixPath | None = None,
        depth: int = 0,
    ) -> None:
        nonlocal visited_entries
        if depth > MAX_JSON_DEPTH:
            raise AttestationError("task tree exceeds the maximum depth")
        with os.scandir(directory) as entries:
            ordered = []
            for entry in entries:
                visited_entries += 1
                if visited_entries > MAX_ARTIFACT_FILES:
                    raise AttestationError(
                        f"task tree exceeds {MAX_ARTIFACT_FILES} entries"
                    )
                ordered.append(entry)
            ordered.sort(key=lambda entry: os.fsencode(entry.name))
        for entry in ordered:
            relative = (
                PurePosixPath(entry.name) if prefix is None else prefix / entry.name
            )
            name = _safe_relative_name(relative.as_posix())
            metadata = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                records.append(
                    {
                        "mode": mode,
                        "path": name,
                        "target": os.readlink(entry.path),
                        "type": "symlink",
                    }
                )
            elif stat.S_ISDIR(metadata.st_mode):
                records.append({"mode": mode, "path": name, "type": "directory"})
                visit(Path(entry.path), relative, depth + 1)
            elif stat.S_ISREG(metadata.st_mode):
                records.append(
                    {
                        "digest": {"sha256": sha256_file(entry.path)},
                        "mode": mode,
                        "path": name,
                        "size": metadata.st_size,
                        "type": "file",
                    }
                )
            else:
                raise AttestationError(f"task tree contains special file: {name}")

    visit(root)
    return records


def hash_tree(root: str | Path) -> str:
    """Hash names, types, modes, links, and file contents in a directory tree."""

    directory = _directory_root(root, label="task root")
    digest = hashlib.sha256()
    digest.update(TREE_ALGORITHM.encode("ascii") + b"\x00")
    for record in _tree_records(directory):
        digest.update(canonical_json_bytes(record) + b"\n")
    return digest.hexdigest()


def _untracked_record(root_fd: int, raw_path: bytes) -> dict[str, Any]:
    """Describe one untracked path without following any symlink component."""

    parts = raw_path.split(b"/")
    if (
        not raw_path
        or raw_path.startswith(b"/")
        or any(part in (b"", b".", b"..") for part in parts)
    ):
        raise AttestationError(f"Git returned an unsafe untracked path: {raw_path!r}")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                directory_flags | nofollow,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd

        name = parts[-1]
        metadata = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        base: dict[str, Any] = {
            "mode": stat.S_IMODE(metadata.st_mode),
            "pathBytes": raw_path.hex(),
        }
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(name, dir_fd=current_fd)
            target_bytes = target if isinstance(target, bytes) else os.fsencode(target)
            return {
                **base,
                "targetBytes": target_bytes.hex(),
                "type": "symlink",
            }
        if not stat.S_ISREG(metadata.st_mode):
            raise AttestationError(
                f"untracked path is not a regular file or symlink: {raw_path!r}"
            )

        file_fd = os.open(name, os.O_RDONLY | nofollow, dir_fd=current_fd)
        try:
            opened = os.fstat(file_fd)
            if not stat.S_ISREG(opened.st_mode):
                raise AttestationError(
                    f"untracked path changed type while hashing: {raw_path!r}"
                )
            return {
                "digest": {"sha256": _hash_open_file(file_fd)},
                "mode": stat.S_IMODE(opened.st_mode),
                "pathBytes": raw_path.hex(),
                "size": opened.st_size,
                "type": "file",
            }
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise AttestationError(
            f"could not hash untracked path {raw_path!r}: {exc}"
        ) from exc
    finally:
        os.close(current_fd)


def capture_git_state(repo: str | Path) -> GitState:
    """Capture HEAD and exact tracked/untracked dirty worktree evidence."""

    requested_root = _directory_root(repo, label="harness repository")

    def git_at(cwd: Path, *args: str) -> bytes:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            timeout=30,
            env={**os.environ, "GIT_PAGER": "cat", "LC_ALL": "C"},
        )
        if proc.returncode != 0:
            error = proc.stderr.decode("utf-8", errors="replace").strip()[:500]
            raise AttestationError(f"git {' '.join(args)} failed: {error}")
        return proc.stdout

    top_level_raw = git_at(requested_root, "rev-parse", "--show-toplevel").rstrip(
        b"\r\n"
    )
    try:
        root = _directory_root(
            os.fsdecode(top_level_raw), label="harness repository root"
        )
    except (UnicodeError, ValueError) as exc:
        raise AttestationError("Git returned an invalid repository root") from exc

    sha = (
        git_at(root, "rev-parse", "--verify", "HEAD")
        .decode("ascii", errors="strict")
        .strip()
        .lower()
    )
    if not _GIT_SHA_RE.fullmatch(sha):
        raise AttestationError(f"unsupported Git object id: {sha!r}")

    diff_options = (
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--ignore-submodules=none",
        "--src-prefix=a/",
        "--dst-prefix=b/",
    )
    staged_diff = git_at(root, "diff", *diff_options, "--cached", "HEAD", "--")
    unstaged_diff = git_at(root, "diff", *diff_options, "--")
    raw_untracked = git_at(root, "ls-files", "--others", "--exclude-standard", "-z")
    untracked_paths = raw_untracked.split(b"\x00")
    if untracked_paths and untracked_paths[-1] == b"":
        untracked_paths.pop()
    if len(untracked_paths) != len(set(untracked_paths)):
        raise AttestationError("Git returned duplicate untracked paths")

    root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        untracked_records = [
            _untracked_record(root_fd, path) for path in sorted(untracked_paths)
        ]
    finally:
        os.close(root_fd)

    dirty = bool(staged_diff or unstaged_diff or untracked_records)
    return GitState(
        sha=sha,
        dirty=dirty,
        worktree_sha256=_worktree_digest(
            staged_diff,
            unstaged_diff,
            untracked_records,
        ),
    )


def _version_map(
    value: Mapping[str, str | None] | None, *, label: str
) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for key, version in (value or {}).items():
        if not isinstance(key, str) or not key.strip() or key != key.strip():
            raise AttestationError(f"{label} names must be non-empty strings")
        if version is not None and (
            not isinstance(version, str)
            or not version.strip()
            or version != version.strip()
        ):
            raise AttestationError(f"{label} version for {key!r} must be text or null")
        result[key] = version
    return dict(sorted(result.items()))


def _image_digest(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise AttestationError("image digest must use the sha256:<hex> form")
    digest = value.removeprefix("sha256:").lower()
    if not _SHA256_RE.fullmatch(digest):
        raise AttestationError("image digest must contain exactly 64 hex characters")
    return digest


def _task_identity(task_root: Path, task_id: str | None) -> str:
    try:
        raw = load_unique_yaml(_read_regular_beneath(task_root, "task.yaml"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise AttestationError(f"could not read task.yaml: {exc}") from exc
    manifest_id = raw.get("id") if isinstance(raw, dict) else None
    if not isinstance(manifest_id, str) or not manifest_id.strip():
        raise AttestationError("task.yaml must contain a non-empty string id")
    if task_id is not None and task_id != manifest_id:
        raise AttestationError(
            f"task id {task_id!r} does not match task.yaml id {manifest_id!r}"
        )
    return manifest_id


def _subject_entries(
    artifact_root: Path,
    artifacts: Iterable[str | Path],
) -> list[dict[str, Any]]:
    names = [_relative_input_name(artifact_root, artifact) for artifact in artifacts]
    if len(names) != len(set(names)):
        raise AttestationError("artifact list contains duplicate paths")
    return [
        {"name": name, "digest": {"sha256": _hash_regular_beneath(artifact_root, name)}}
        for name in sorted(names)
    ]


def build_statement(
    *,
    artifact_root: str | Path,
    artifacts: Iterable[str | Path],
    task_root: str | Path,
    image_tag: str,
    image_digest: str,
    harness_git_sha: str,
    harness_git_dirty: bool,
    harness_git_worktree_sha256: str | None = None,
    task_id: str | None = None,
    models: Mapping[str, str | None] | None = None,
    tool_versions: Mapping[str, str | None] | None = None,
    outcome: Mapping[str, Any] | None = None,
    governance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an in-toto Statement v1-shaped unsigned provenance document."""

    artifact_directory = _directory_root(artifact_root, label="artifact root")
    task_directory = _directory_root(task_root, label="task root")
    git_sha = str(harness_git_sha).lower()
    if not _GIT_SHA_RE.fullmatch(git_sha):
        raise AttestationError("harness_git_sha must be a 40 or 64 digit hex id")
    if type(harness_git_dirty) is not bool:
        raise AttestationError("harness_git_dirty must be a boolean")
    if harness_git_worktree_sha256 is None:
        if harness_git_dirty:
            raise AttestationError(
                "dirty harness Git state requires harness_git_worktree_sha256"
            )
        harness_git_worktree_sha256 = CLEAN_WORKTREE_SHA256
    if not isinstance(harness_git_worktree_sha256, str) or not _SHA256_RE.fullmatch(
        harness_git_worktree_sha256
    ):
        raise AttestationError(
            "harness_git_worktree_sha256 must be a lowercase SHA-256 digest"
        )
    if harness_git_dirty is False and (
        harness_git_worktree_sha256 != CLEAN_WORKTREE_SHA256
    ):
        raise AttestationError(
            "clean harness Git state must use the deterministic clean worktree digest"
        )
    if harness_git_dirty is True and (
        harness_git_worktree_sha256 == CLEAN_WORKTREE_SHA256
    ):
        raise AttestationError(
            "dirty harness Git state cannot use the clean worktree digest"
        )
    if not isinstance(image_tag, str) or not image_tag.strip():
        raise AttestationError("image_tag must be non-empty")
    if image_tag != image_tag.strip():
        raise AttestationError("image_tag must not contain surrounding whitespace")
    normalized_outcome = _json_value(outcome or {}, location="outcome")
    if not isinstance(normalized_outcome, dict):
        raise AttestationError("outcome must be a JSON object")
    normalized_governance = _json_value(governance or {}, location="governance")
    if not isinstance(normalized_governance, dict):
        raise AttestationError("governance must be a JSON object")

    resolved_task_id = _task_identity(task_directory, task_id)
    manifest_digest = _hash_regular_beneath(task_directory, "task.yaml")
    tree_digest = hash_tree(task_directory)
    image_sha256 = _image_digest(image_digest)

    return {
        "_type": STATEMENT_TYPE,
        "subject": _subject_entries(artifact_directory, artifacts),
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "schemaVersion": PREDICATE_SCHEMA_VERSION,
            "integrity": {
                "mode": "unsigned-local",
                "authenticityClaimed": False,
            },
            "harness": {
                "git": {
                    "sha": git_sha,
                    "dirty": harness_git_dirty,
                    "worktree_sha256": harness_git_worktree_sha256,
                },
            },
            "task": {
                "id": resolved_task_id,
                "manifest": {
                    "path": "task.yaml",
                    "digest": {"sha256": manifest_digest},
                },
                "tree": {
                    "algorithm": TREE_ALGORITHM,
                    "digest": {"sha256": tree_digest},
                },
            },
            "image": {
                "tag": image_tag,
                "digest": {"sha256": image_sha256},
            },
            "models": _version_map(models, label="model"),
            "tools": _version_map(tool_versions, label="tool"),
            "outcome": normalized_outcome,
            "governance": normalized_governance,
        },
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def default_sidecar_path(statement_path: str | Path) -> Path:
    path = Path(statement_path)
    return path.with_name(f"{path.name}.sha256")


def write_attestation(
    statement: Mapping[str, Any],
    statement_path: str | Path,
    *,
    sidecar_path: str | Path | None = None,
) -> AttestationBundle:
    """Write canonical statement bytes and their unsigned SHA-256 sidecar."""

    output = Path(statement_path)
    sidecar = Path(sidecar_path) if sidecar_path else default_sidecar_path(output)
    if os.path.abspath(output) == os.path.abspath(sidecar):
        raise AttestationError("statement and sidecar paths must differ")
    data = canonical_statement_bytes(statement)
    digest = _sha256_bytes(data)
    _atomic_write(output, data)
    _atomic_write(sidecar, f"{digest}\n".encode("ascii"))
    subjects = statement.get("subject")
    subject_count = len(subjects) if isinstance(subjects, list) else 0
    return AttestationBundle(
        statement_path=output,
        sidecar_path=sidecar,
        statement_sha256=digest,
        subject_count=subject_count,
    )


def _lexical_relative(root: Path, path: Path) -> str | None:
    try:
        return Path(os.path.abspath(path)).relative_to(root).as_posix()
    except ValueError:
        return None


def _scan_artifact_tree(root: Path, excluded: set[str]) -> _TreeScan:
    files: set[str] = set()
    unsafe: list[tuple[str, str]] = []
    visited_entries = 0
    stopped = False

    def visit(
        directory: Path,
        prefix: PurePosixPath | None = None,
        depth: int = 0,
    ) -> None:
        nonlocal stopped, visited_entries
        if stopped:
            return
        if depth > MAX_JSON_DEPTH:
            relative = prefix.as_posix() if prefix else "."
            unsafe.append((relative, "artifact tree exceeds the maximum depth"))
            stopped = True
            return
        try:
            with os.scandir(directory) as entries:
                ordered = []
                for entry in entries:
                    visited_entries += 1
                    if visited_entries > MAX_ARTIFACT_FILES:
                        unsafe.append(
                            (".", f"artifact tree exceeds {MAX_ARTIFACT_FILES} entries")
                        )
                        stopped = True
                        return
                    ordered.append(entry)
                ordered.sort(key=lambda entry: os.fsencode(entry.name))
        except OSError as exc:
            relative = prefix.as_posix() if prefix else "."
            unsafe.append((relative, f"directory could not be read: {exc}"))
            return
        for entry in ordered:
            relative = (
                PurePosixPath(entry.name) if prefix is None else prefix / entry.name
            )
            name = relative.as_posix()
            try:
                safe_name = _safe_relative_name(name)
                metadata = entry.stat(follow_symlinks=False)
            except (AttestationError, OSError) as exc:
                unsafe.append((name, str(exc)))
                continue
            if safe_name in excluded:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                unsafe.append((safe_name, "symlinks are not attestable run artifacts"))
            elif stat.S_ISDIR(metadata.st_mode):
                visit(Path(entry.path), relative, depth + 1)
            elif stat.S_ISREG(metadata.st_mode):
                files.add(safe_name)
            else:
                unsafe.append((safe_name, "special files are not attestable"))

    visit(root)
    return _TreeScan(files=frozenset(files), unsafe=tuple(unsafe))


def create_attestation(
    *,
    statement_path: str | Path,
    artifact_root: str | Path,
    task_root: str | Path,
    image_tag: str,
    image_digest: str,
    artifact_paths: Iterable[str | Path] | None = None,
    task_id: str | None = None,
    harness_repo: str | Path | None = None,
    harness_git_sha: str | None = None,
    harness_git_dirty: bool | None = None,
    harness_git_worktree_sha256: str | None = None,
    models: Mapping[str, str | None] | None = None,
    tool_versions: Mapping[str, str | None] | None = None,
    outcome: Mapping[str, Any] | None = None,
    governance: Mapping[str, Any] | None = None,
    sidecar_path: str | Path | None = None,
) -> AttestationBundle:
    """Build and write an unsigned local provenance bundle.

    When ``artifact_paths`` is omitted, every regular file under
    ``artifact_root`` is included except the output statement and sidecar.
    Symlinks and special files are rejected.  Git evidence can be captured
    from ``harness_repo`` or passed explicitly as SHA, dirty state, and exact
    worktree digest. Clean explicit state receives the deterministic clean
    digest automatically.
    """

    root = _directory_root(artifact_root, label="artifact root")
    output = Path(statement_path)
    sidecar = Path(sidecar_path) if sidecar_path else default_sidecar_path(output)
    excluded = {
        name
        for candidate in (output, sidecar)
        if (name := _lexical_relative(root, candidate)) is not None
    }

    if artifact_paths is None:
        scan = _scan_artifact_tree(root, excluded)
        if scan.unsafe:
            path, reason = scan.unsafe[0]
            raise AttestationError(f"unsafe artifact {path}: {reason}")
        artifacts: list[str | Path] = sorted(scan.files)
    else:
        artifacts = list(artifact_paths)
        selected_names = {
            _relative_input_name(root, artifact) for artifact in artifacts
        }
        overlap = selected_names & excluded
        if overlap:
            raise AttestationError(
                f"attestation output cannot be its own subject: {sorted(overlap)[0]}"
            )

    if harness_repo is not None:
        captured = capture_git_state(harness_repo)
        if harness_git_sha is not None and captured.sha != harness_git_sha.lower():
            raise AttestationError("captured harness SHA disagrees with supplied SHA")
        if harness_git_dirty is not None and captured.dirty is not harness_git_dirty:
            raise AttestationError(
                "captured harness dirty state disagrees with supplied state"
            )
        if (
            harness_git_worktree_sha256 is not None
            and captured.worktree_sha256 != harness_git_worktree_sha256
        ):
            raise AttestationError(
                "captured harness worktree digest disagrees with supplied digest"
            )
        harness_git_sha = captured.sha
        harness_git_dirty = captured.dirty
        harness_git_worktree_sha256 = captured.worktree_sha256
    if harness_git_sha is None or harness_git_dirty is None:
        raise AttestationError(
            "provide harness_repo or both harness_git_sha and harness_git_dirty"
        )

    statement = build_statement(
        artifact_root=root,
        artifacts=artifacts,
        task_root=task_root,
        task_id=task_id,
        image_tag=image_tag,
        image_digest=image_digest,
        harness_git_sha=harness_git_sha,
        harness_git_dirty=harness_git_dirty,
        harness_git_worktree_sha256=harness_git_worktree_sha256,
        models=models,
        tool_versions=tool_versions,
        outcome=outcome,
        governance=governance,
    )
    return write_attestation(statement, output, sidecar_path=sidecar)


def _failure(
    failures: list[VerificationFailure],
    code: str,
    message: str,
    *,
    path: str | None = None,
    expected: Any = None,
    actual: Any = None,
) -> None:
    failures.append(
        VerificationFailure(
            code=code,
            message=message,
            path=path,
            expected=None if expected is None else str(expected),
            actual=None if actual is None else str(actual),
        )
    )


def _digest_member(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    digest = value.get("sha256")
    return digest if isinstance(digest, str) and _SHA256_RE.fullmatch(digest) else None


def _verify_sidecar(
    statement_data: bytes,
    sidecar: Path,
    failures: list[VerificationFailure],
) -> tuple[str, bool]:
    actual = _sha256_bytes(statement_data)
    try:
        raw = _read_regular_file(
            sidecar,
            label="statement digest sidecar",
            max_bytes=MAX_SIDECAR_BYTES,
        )
    except FileNotFoundError:
        _failure(
            failures,
            "sidecar_missing",
            "statement digest sidecar is missing",
            path=str(sidecar),
        )
        return actual, False
    except AttestationError as exc:
        _failure(
            failures,
            "sidecar_unsafe",
            str(exc),
            path=str(sidecar),
        )
        return actual, False
    except OSError as exc:
        _failure(
            failures,
            "sidecar_unreadable",
            f"statement digest sidecar could not be read: {exc}",
            path=str(sidecar),
        )
        return actual, False
    try:
        expected = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        expected = ""
    if not _SHA256_RE.fullmatch(expected):
        _failure(
            failures,
            "sidecar_invalid",
            "sidecar must contain one lowercase SHA-256 digest",
            path=str(sidecar),
        )
        return actual, False
    if expected != actual:
        _failure(
            failures,
            "sidecar_digest_mismatch",
            "statement bytes do not match their sidecar digest",
            path=str(sidecar),
            expected=expected,
            actual=actual,
        )
        return actual, False
    return actual, True


def _verify_predicate_shape(
    predicate: Any,
    failures: list[VerificationFailure],
) -> Mapping[str, Any] | None:
    if not isinstance(predicate, Mapping):
        _failure(
            failures,
            "predicate_invalid",
            "statement predicate must be an object",
        )
        return None
    if predicate.get("schemaVersion") != PREDICATE_SCHEMA_VERSION:
        _failure(
            failures,
            "predicate_version_unsupported",
            "predicate schema version is not supported",
            expected=PREDICATE_SCHEMA_VERSION,
            actual=predicate.get("schemaVersion"),
        )
    integrity = predicate.get("integrity")
    if not isinstance(integrity, Mapping) or (
        integrity.get("mode") != "unsigned-local"
        or integrity.get("authenticityClaimed") is not False
    ):
        _failure(
            failures,
            "integrity_mode_invalid",
            "predicate must explicitly describe unsigned local integrity",
        )
    for name in ("models", "tools"):
        versions = predicate.get(name)
        if not isinstance(versions, Mapping) or any(
            not isinstance(key, str)
            or (version is not None and not isinstance(version, str))
            for key, version in versions.items()
        ):
            _failure(
                failures,
                f"{name}_invalid",
                f"predicate {name} must map names to text or null",
            )
    try:
        normalized_outcome = _json_value(predicate.get("outcome"), location="outcome")
        if not isinstance(normalized_outcome, dict):
            raise AttestationError("outcome must be an object")
    except AttestationError as exc:
        _failure(failures, "outcome_invalid", str(exc))
    governance = predicate.get("governance")
    if governance is not None:
        try:
            normalized_governance = _json_value(governance, location="governance")
            if not isinstance(normalized_governance, dict):
                raise AttestationError("governance must be an object")
        except AttestationError as exc:
            _failure(failures, "governance_invalid", str(exc))
    image = predicate.get("image")
    if not isinstance(image, Mapping) or not isinstance(image.get("tag"), str):
        _failure(failures, "image_invalid", "image tag and digest are required")
    elif _digest_member(image.get("digest")) is None:
        _failure(
            failures,
            "image_digest_invalid",
            "image digest must be a SHA-256 digest",
        )
    return predicate


def _verify_subjects(
    subjects: Any,
    root: Path,
    failures: list[VerificationFailure],
) -> tuple[set[str], int, int, dict[str, str]]:
    if not isinstance(subjects, list):
        _failure(
            failures,
            "subjects_invalid",
            "statement subject must be an array",
        )
        return set(), 0, 0, {}
    if len(subjects) > MAX_ATTESTATION_SUBJECTS:
        _failure(
            failures,
            "subjects_too_many",
            f"statement exceeds {MAX_ATTESTATION_SUBJECTS} subjects",
        )
        return set(), len(subjects), 0, {}
    names: set[str] = set()
    subject_digests: dict[str, str] = {}
    checked = 0
    for index, subject in enumerate(subjects):
        if not isinstance(subject, Mapping):
            _failure(
                failures,
                "subject_invalid",
                "subject entry must be an object",
                path=f"subject[{index}]",
            )
            continue
        raw_name = subject.get("name")
        try:
            name = _safe_relative_name(raw_name)
        except AttestationError as exc:
            _failure(
                failures,
                "unsafe_subject_path",
                str(exc),
                path=str(raw_name),
            )
            continue
        if name in names:
            _failure(
                failures,
                "duplicate_subject",
                "statement contains a duplicate subject name",
                path=name,
            )
            continue
        names.add(name)
        expected = _digest_member(subject.get("digest"))
        if expected is None:
            _failure(
                failures,
                "subject_digest_invalid",
                "subject is missing a lowercase SHA-256 digest",
                path=name,
            )
            continue
        subject_digests[name] = expected
        try:
            actual = _hash_regular_beneath(root, name)
        except FileNotFoundError:
            _failure(
                failures,
                "artifact_missing",
                "attested artifact is missing",
                path=name,
                expected=expected,
            )
            continue
        except (AttestationError, OSError) as exc:
            _failure(
                failures,
                "unsafe_artifact_path",
                f"attested artifact could not be opened safely: {exc}",
                path=name,
            )
            continue
        checked += 1
        if actual != expected:
            _failure(
                failures,
                "artifact_digest_mismatch",
                "artifact content does not match the statement",
                path=name,
                expected=expected,
                actual=actual,
            )
    return names, len(subjects), checked, subject_digests


def _verify_task(
    predicate: Mapping[str, Any],
    task_root: Path,
    failures: list[VerificationFailure],
) -> bool:
    task = predicate.get("task")
    if not isinstance(task, Mapping):
        _failure(failures, "task_invalid", "predicate task must be an object")
        return False
    task_id = task.get("id")
    if not isinstance(task_id, str) or not task_id.strip():
        _failure(failures, "task_id_invalid", "predicate task id is invalid")

    manifest = task.get("manifest")
    manifest_expected = None
    if not isinstance(manifest, Mapping) or manifest.get("path") != "task.yaml":
        _failure(
            failures,
            "task_manifest_invalid",
            "task manifest must identify task.yaml",
        )
    else:
        manifest_expected = _digest_member(manifest.get("digest"))
        if manifest_expected is None:
            _failure(
                failures,
                "task_manifest_digest_invalid",
                "task manifest digest is invalid",
            )

    manifest_data: bytes | None = None
    try:
        manifest_data = _read_regular_beneath(task_root, "task.yaml")
    except (AttestationError, OSError) as exc:
        _failure(
            failures,
            "task_manifest_unreadable",
            f"task.yaml could not be opened safely: {exc}",
            path="task.yaml",
        )
    if manifest_data is not None and manifest_expected is not None:
        manifest_actual = _sha256_bytes(manifest_data)
        if manifest_actual != manifest_expected:
            _failure(
                failures,
                "task_manifest_digest_mismatch",
                "task.yaml content does not match the statement",
                path="task.yaml",
                expected=manifest_expected,
                actual=manifest_actual,
            )
        try:
            raw = load_unique_yaml(manifest_data)
            manifest_id = raw.get("id") if isinstance(raw, dict) else None
        except (ValueError, yaml.YAMLError) as exc:
            _failure(
                failures,
                "task_manifest_parse_error",
                f"task.yaml could not be parsed: {exc}",
                path="task.yaml",
            )
        else:
            if manifest_id != task_id:
                _failure(
                    failures,
                    "task_id_mismatch",
                    "task.yaml id does not match the predicate",
                    path="task.yaml",
                    expected=task_id,
                    actual=manifest_id,
                )

    tree = task.get("tree")
    tree_expected = None
    if not isinstance(tree, Mapping) or tree.get("algorithm") != TREE_ALGORITHM:
        _failure(
            failures,
            "task_tree_invalid",
            "task tree algorithm is missing or unsupported",
        )
    else:
        tree_expected = _digest_member(tree.get("digest"))
        if tree_expected is None:
            _failure(
                failures,
                "task_tree_digest_invalid",
                "task tree digest is invalid",
            )
    if tree_expected is not None:
        try:
            tree_actual = hash_tree(task_root)
        except (AttestationError, OSError) as exc:
            _failure(
                failures,
                "task_tree_unreadable",
                f"task tree could not be hashed safely: {exc}",
            )
        else:
            if tree_actual != tree_expected:
                _failure(
                    failures,
                    "task_tree_digest_mismatch",
                    "task tree does not match the statement",
                    expected=tree_expected,
                    actual=tree_actual,
                )
    return manifest_data is not None and tree_expected is not None


def _verify_harness(
    predicate: Mapping[str, Any],
    harness_repo: str | Path | None,
    failures: list[VerificationFailure],
) -> bool:
    harness = predicate.get("harness")
    git = harness.get("git") if isinstance(harness, Mapping) else None
    if not isinstance(git, Mapping):
        _failure(
            failures,
            "harness_git_invalid",
            "predicate harness Git evidence is missing",
        )
        return False
    expected_sha = git.get("sha")
    expected_dirty = git.get("dirty")
    expected_worktree = git.get("worktree_sha256")
    if not isinstance(expected_sha, str) or not _GIT_SHA_RE.fullmatch(expected_sha):
        _failure(
            failures,
            "harness_git_sha_invalid",
            "harness Git SHA is invalid",
        )
    if type(expected_dirty) is not bool:
        _failure(
            failures,
            "harness_git_dirty_invalid",
            "harness Git dirty state must be boolean",
        )
    if not isinstance(expected_worktree, str) or not _SHA256_RE.fullmatch(
        expected_worktree
    ):
        _failure(
            failures,
            "harness_git_worktree_sha256_invalid",
            "harness Git worktree digest must be a lowercase SHA-256 digest",
        )
    elif expected_dirty is False and expected_worktree != CLEAN_WORKTREE_SHA256:
        _failure(
            failures,
            "harness_git_worktree_state_inconsistent",
            "clean harness Git state does not use the clean worktree digest",
            expected=CLEAN_WORKTREE_SHA256,
            actual=expected_worktree,
        )
    elif expected_dirty is True and expected_worktree == CLEAN_WORKTREE_SHA256:
        _failure(
            failures,
            "harness_git_worktree_state_inconsistent",
            "dirty harness Git state uses the clean worktree digest",
        )
    if harness_repo is None:
        return False
    try:
        actual = capture_git_state(harness_repo)
    except (AttestationError, OSError) as exc:
        _failure(
            failures,
            "harness_git_unreadable",
            f"harness repository could not be inspected: {exc}",
        )
        return False
    if actual.sha != expected_sha:
        _failure(
            failures,
            "harness_git_sha_mismatch",
            "current harness commit does not match the statement",
            expected=expected_sha,
            actual=actual.sha,
        )
    if actual.dirty is not expected_dirty:
        _failure(
            failures,
            "harness_git_dirty_mismatch",
            "current harness dirty state does not match the statement",
            expected=expected_dirty,
            actual=actual.dirty,
        )
    if actual.worktree_sha256 != expected_worktree:
        _failure(
            failures,
            "harness_git_worktree_sha256_mismatch",
            "current harness worktree does not match the statement",
            expected=expected_worktree,
            actual=actual.worktree_sha256,
        )
    return True


def _verify_attestation(
    statement_path: str | Path,
    *,
    artifact_root: str | Path,
    task_root: str | Path,
    harness_repo: str | Path | None = None,
    sidecar_path: str | Path | None = None,
    require_complete_artifact_set: bool = True,
) -> VerificationResult:
    """Recompute local evidence and return all structured verification failures."""

    failures: list[VerificationFailure] = []
    statement_file = Path(statement_path)
    sidecar = (
        Path(sidecar_path)
        if sidecar_path is not None
        else default_sidecar_path(statement_file)
    )
    try:
        statement_data = _read_regular_file(
            statement_file, label="attestation statement"
        )
    except AttestationError as exc:
        _failure(
            failures,
            "statement_unsafe",
            str(exc),
            path=str(statement_file),
        )
        return VerificationResult(ok=False, failures=failures)
    except OSError as exc:
        _failure(
            failures,
            "statement_unreadable",
            f"statement could not be read: {exc}",
            path=str(statement_file),
        )
        return VerificationResult(ok=False, failures=failures)

    statement_digest, sidecar_verified = _verify_sidecar(
        statement_data, sidecar, failures
    )
    try:
        statement = json.loads(statement_data)
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        RecursionError,
        MemoryError,
    ) as exc:
        _failure(
            failures,
            "statement_json_invalid",
            f"statement is not valid UTF-8 JSON: {exc}",
            path=str(statement_file),
        )
        return VerificationResult(
            ok=False,
            failures=failures,
            statement_sha256=statement_digest,
            sidecar_verified=sidecar_verified,
        )
    if not isinstance(statement, Mapping):
        _failure(
            failures,
            "statement_invalid",
            "statement root must be an object",
        )
        return VerificationResult(
            ok=False,
            failures=failures,
            statement_sha256=statement_digest,
            sidecar_verified=sidecar_verified,
        )
    try:
        canonical = canonical_statement_bytes(statement)
    except AttestationError as exc:
        _failure(failures, "statement_value_invalid", str(exc))
        canonical = b""
    if canonical != statement_data:
        _failure(
            failures,
            "statement_not_canonical",
            "statement bytes are not in canonical JSON form",
            path=str(statement_file),
        )
    if statement.get("_type") != STATEMENT_TYPE:
        _failure(
            failures,
            "statement_type_invalid",
            "statement does not use the in-toto Statement v1 type",
            expected=STATEMENT_TYPE,
            actual=statement.get("_type"),
        )
    if statement.get("predicateType") != PREDICATE_TYPE:
        _failure(
            failures,
            "predicate_type_invalid",
            "statement predicate type is not agent-eval attestation v1",
            expected=PREDICATE_TYPE,
            actual=statement.get("predicateType"),
        )

    try:
        artifact_directory = _directory_root(artifact_root, label="artifact root")
    except AttestationError as exc:
        _failure(failures, "artifact_root_invalid", str(exc))
        artifact_directory = None
    try:
        task_directory = _directory_root(task_root, label="task root")
    except AttestationError as exc:
        _failure(failures, "task_root_invalid", str(exc))
        task_directory = None

    names: set[str] = set()
    subject_digests: dict[str, str] = {}
    declared = checked = 0
    if artifact_directory is not None:
        names, declared, checked, subject_digests = _verify_subjects(
            statement.get("subject"), artifact_directory, failures
        )

        if require_complete_artifact_set:
            excluded = {
                name
                for candidate in (statement_file, sidecar)
                if (name := _lexical_relative(artifact_directory, candidate))
                is not None
            }
            scan = _scan_artifact_tree(artifact_directory, excluded)
            for path, reason in scan.unsafe:
                _failure(
                    failures,
                    "unsafe_artifact_tree",
                    reason,
                    path=path,
                )
            for path in sorted(scan.files - names):
                _failure(
                    failures,
                    "unattested_artifact",
                    "artifact exists locally but is absent from the statement",
                    path=path,
                )

    predicate = _verify_predicate_shape(statement.get("predicate"), failures)
    task_checked = False
    harness_checked = False
    if predicate is not None:
        if task_directory is not None:
            task_checked = _verify_task(predicate, task_directory, failures)
        harness_checked = _verify_harness(predicate, harness_repo, failures)

    return VerificationResult(
        ok=not failures,
        failures=failures,
        statement_sha256=statement_digest,
        sidecar_verified=sidecar_verified,
        subjects_declared=declared,
        subjects_checked=checked,
        task_checked=task_checked,
        harness_checked=harness_checked,
        predicate=dict(predicate) if predicate is not None else None,
        subject_digests=subject_digests,
    )


def verify_attestation(
    statement_path: str | Path,
    *,
    artifact_root: str | Path,
    task_root: str | Path,
    harness_repo: str | Path | None = None,
    sidecar_path: str | Path | None = None,
    require_complete_artifact_set: bool = True,
) -> VerificationResult:
    """Verify local evidence behind a resource-safe structured boundary."""

    try:
        return _verify_attestation(
            statement_path,
            artifact_root=artifact_root,
            task_root=task_root,
            harness_repo=harness_repo,
            sidecar_path=sidecar_path,
            require_complete_artifact_set=require_complete_artifact_set,
        )
    except (RecursionError, MemoryError) as exc:
        return VerificationResult(
            ok=False,
            failures=[
                VerificationFailure(
                    code="verification_resource_limit",
                    message=(
                        "attestation verification exceeded a safe resource limit: "
                        f"{type(exc).__name__}"
                    ),
                    path=str(statement_path),
                )
            ],
        )
