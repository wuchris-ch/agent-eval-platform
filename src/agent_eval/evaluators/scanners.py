"""Host-side static analysis of the produced workspace. Every scanner degrades
gracefully: a missing tool records None for its metrics rather than failing
the run. Scanner artifacts are kept under the configured state root at
<run-id>/scans/; secret reports retain only redacted location metadata."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

from rich.console import Console

from ..metrics import (
    SCANNER_EXECUTABLE_NAMES,
    SCANNER_REQUIRED_VERSIONS,
    ScannerAssuranceIdentity,
    ScanResults,
    TrivyDatabaseIdentity,
    scanner_assurance_material_sha256,
    scanner_promotion_blockers,
)
from ..paths import ensure_private_directory, get_state_dir
from ..scanner_runtime import (
    SCANNER_RUNTIME_EMPTY_IGNORE_POLICY,
    SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256,
    SCANNER_RUNTIME_GITLEAKS_CONFIG,
    SCANNER_RUNTIME_PROJECT,
    SCANNER_RUNTIME_RULESET,
    scanner_runtime_digest,
    scanner_runtime_environment_digest,
    scanner_runtime_gitleaks_config_digest,
    scanner_runtime_invocation_policy,
    scanner_runtime_invocation_policy_digest,
    scanner_runtime_lock_digest,
    scanner_runtime_project_digest,
    scanner_runtime_ruleset_digest,
)

console = Console()
SCAN_TIMEOUT = 600
_VERSION_TIMEOUT = 60
_PREPARE_TIMEOUT = 900
_TERMINATION_GRACE_SECONDS = 2.0
_STREAM_JOIN_SECONDS = 2.0
_PROCESS_POLL_SECONDS = 0.05
_STREAM_CHUNK_BYTES = 64 * 1024
_MAX_STREAM_BYTES = 16 * 1024 * 1024
_MAX_RETAINED_FINDINGS = 1_000
_MAX_RULE_CHARS = 256
_MAX_PATH_CHARS = 1_024
_MAX_SEVERITY_CHARS = 32
_MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_CACHE_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_CACHE_FILES = 128
_MAX_SOURCE_CACHE_LINES = 250_000
_MAX_SOURCE_LINES = 100_000
_MAX_SECRET_TOKEN_CHARS = 4_096
_MAX_REDACTION_SEGMENTS_PER_FILE = 128
_MAX_REDACTION_PATTERN_CHARS = 64 * 1024
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_MAX_SCANNER_ENVIRONMENT_BYTES = 4 * 1024 * 1024 * 1024
_MAX_SCANNER_ENVIRONMENT_ENTRIES = 200_000
_MAX_TRIVY_DB_BYTES = 2 * 1024 * 1024 * 1024
_MAX_TRIVY_DB_FILES = 256
_MAX_GITLEAKS_STAGE_BYTES = 512 * 1024 * 1024
_MAX_GITLEAKS_STAGE_ENTRIES = 100_000
_MAX_GITLEAKS_STAGE_PATH_BYTES = 4_096
_MAX_GITLEAKS_STAGE_DEPTH = 128
_MAX_SCANNER_BATCH_ARGUMENT_BYTES = 64 * 1024
_PYTHON_SOURCE_SUFFIXES = frozenset({".py", ".pyi", ".pyw", ".ipynb"})
_KNOWN_NON_PYTHON_SUFFIXES = frozenset(
    {
        ".7z",
        ".cfg",
        ".class",
        ".css",
        ".csv",
        ".diff",
        ".gif",
        ".go",
        ".gz",
        ".html",
        ".ico",
        ".ini",
        ".jar",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".lock",
        ".md",
        ".pdf",
        ".png",
        ".properties",
        ".proto",
        ".rs",
        ".sh",
        ".sql",
        ".svg",
        ".tar",
        ".toml",
        ".ts",
        ".tsx",
        ".wasm",
        ".xml",
        ".yaml",
        ".yml",
        ".zip",
    }
)
_EVALUATOR_SCREENING_FILES = frozenset(
    {
        ".agent-eval-model-context.txt",
        ".agent-eval-workspace.diff",
        "agent-eval-change.diff",
        "agent-eval-review-metadata.txt",
    }
)
_GITLEAKS_TARGET_IGNORE_NAME = ".gitleaksignore"
_GITLEAKS_STAGED_IGNORE_NAME = ".agent-eval-target-gitleaksignore"
_GITLEAKS_TARGET_GIT_NAME = ".git"
_GITLEAKS_STAGED_GIT_NAME = ".agent-eval-target-git"
_TARGET_NODE_MODULES_NAME = "node_modules"
_STAGED_NODE_MODULES_NAME = ".agent-eval-target-node-modules"
_EXTERNAL_SCANNER_CONTROL_RENAMES = {
    _GITLEAKS_TARGET_GIT_NAME: _GITLEAKS_STAGED_GIT_NAME,
    _GITLEAKS_TARGET_IGNORE_NAME: _GITLEAKS_STAGED_IGNORE_NAME,
    _TARGET_NODE_MODULES_NAME: _STAGED_NODE_MODULES_NAME,
}
_REDACTED_SECRET = "<REDACTED_SECRET>"
_SEMGREP_CONFIG = SCANNER_RUNTIME_RULESET
_SCANNER_ENV_PASSTHROUGH = (
    "ALL_PROXY",
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "PATH",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
)


def _scanner_runtime_state_root() -> Path:
    state_root = get_state_dir()
    return state_root.with_name(f"{state_root.name}-scanner-runtime")


def _scanner_identity_root() -> Path:
    runtime_root = ensure_private_directory(
        _scanner_runtime_state_root(), parents=True
    )
    return ensure_private_directory(
        runtime_root / scanner_runtime_environment_digest()
    )


def _scanner_subprocess_environment() -> dict[str, str]:
    """Build a credential-minimized environment with private scanner state."""

    identity_root = _scanner_identity_root()
    private_directories = {
        name: ensure_private_directory(identity_root / name)
        for name in (
            "cache",
            "config",
            "data",
            "home",
            "state",
            "tmp",
        )
    }
    environment: dict[str, str] = {}
    for name in _SCANNER_ENV_PASSTHROUGH:
        value = os.environ.get(name)
        if value is None:
            continue
        if "proxy" in name.lower():
            try:
                parsed = urlsplit(value)
            except ValueError:
                continue
            if parsed.username is not None or parsed.password is not None:
                continue
        environment[name] = value
    environment.setdefault("PATH", os.defpath)
    environment.update(
        {
            "HOME": str(private_directories["home"]),
            "TMPDIR": str(private_directories["tmp"]),
            "TMP": str(private_directories["tmp"]),
            "TEMP": str(private_directories["tmp"]),
            "PYTHONDONTWRITEBYTECODE": "1",
            "UV_CACHE_DIR": str(private_directories["cache"]),
            "UV_NO_CONFIG": "1",
            "UV_NO_ENV_FILE": "1",
            "UV_PROJECT_ENVIRONMENT": str(identity_root / "environment"),
            "XDG_CACHE_HOME": str(private_directories["cache"]),
            "XDG_CONFIG_HOME": str(private_directories["config"]),
            "XDG_DATA_HOME": str(private_directories["data"]),
            "XDG_STATE_HOME": str(private_directories["state"]),
        }
    )
    return environment


def _resolved_executable(name: str) -> str | None:
    located = shutil.which(name)
    if located is None:
        return None
    try:
        resolved = Path(located).resolve(strict=True)
        if resolved.is_file():
            return str(resolved)
    except (OSError, RuntimeError):
        pass
    return located


def _executable_sha256(path: str) -> str | None:
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_EXECUTABLE_BYTES
        ):
            return None
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, _STREAM_CHUNK_BYTES)
            if not chunk:
                return digest.hexdigest()
            total += len(chunk)
            if total > _MAX_EXECUTABLE_BYTES:
                return None
            digest.update(chunk)
    finally:
        os.close(descriptor)


def _verified_empty_ignore_policy_sha256() -> str | None:
    """Verify the evaluator-owned no-suppression policy as a regular file."""

    path = SCANNER_RUNTIME_EMPTY_IGNORE_POLICY
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or opened.st_size != metadata.st_size
            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(metadata.st_mode)
        ):
            return None
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, _STREAM_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        closed = os.fstat(descriptor)
        if (
            (closed.st_dev, closed.st_ino) != (opened.st_dev, opened.st_ino)
            or closed.st_size != opened.st_size
            or closed.st_mtime_ns != opened.st_mtime_ns
            or closed.st_ctime_ns != opened.st_ctime_ns
        ):
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)
    actual = digest.hexdigest()
    return (
        actual
        if actual == SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256
        else None
    )


def _external_scanner_policy_arguments(name: str) -> list[str] | None:
    """Resolve the exact bound invocation arguments for an external scanner."""

    try:
        raw_arguments = scanner_runtime_invocation_policy()[name]["arguments"]
    except (KeyError, RuntimeError, TypeError):
        return None
    if not isinstance(raw_arguments, list) or not all(
        isinstance(argument, str) for argument in raw_arguments
    ):
        return None
    return [
        str(SCANNER_RUNTIME_EMPTY_IGNORE_POLICY)
        if argument == "{empty_ignore_policy}"
        else argument
        for argument in raw_arguments
    ]


def _stage_gitleaks_workspace(
    workspace: Path, destination: Path
) -> dict[str, str]:
    """Create a private bounded snapshot with scanner skip names neutralized."""

    entry_count = 0
    total_bytes = 0
    renamed_controls: dict[str, str] = {}
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    def copy_directory(
        source_descriptor: int,
        target_directory: Path,
        relative_directory: Path,
    ) -> None:
        nonlocal entry_count, total_bytes
        if len(relative_directory.parts) > _MAX_GITLEAKS_STAGE_DEPTH:
            raise ValueError("Gitleaks staging depth limit exceeded")
        opened_directory = os.fstat(source_descriptor)
        if not stat.S_ISDIR(opened_directory.st_mode):
            raise ValueError("Gitleaks staging input is not a directory")
        with os.scandir(source_descriptor) as scanned_entries:
            entries = sorted(
                scanned_entries, key=lambda entry: os.fsencode(entry.name)
            )
        directory_names = {entry.name for entry in entries}
        if any(
            staged in directory_names
            for staged in _EXTERNAL_SCANNER_CONTROL_RENAMES.values()
        ):
            raise ValueError("external scanner staging control name collides")
        for entry in entries:
            relative = relative_directory / entry.name
            staged_name = _EXTERNAL_SCANNER_CONTROL_RENAMES.get(
                entry.name, entry.name
            )
            if staged_name != entry.name:
                renamed_controls[staged_name] = entry.name
            staged_relative = relative_directory / staged_name
            if (
                len(os.fsencode(relative.as_posix()))
                > _MAX_GITLEAKS_STAGE_PATH_BYTES
                or len(os.fsencode(staged_relative.as_posix()))
                > _MAX_GITLEAKS_STAGE_PATH_BYTES
            ):
                raise ValueError("Gitleaks staging path is too long")
            entry_count += 1
            if entry_count > _MAX_GITLEAKS_STAGE_ENTRIES:
                raise ValueError("Gitleaks staging entry limit exceeded")
            metadata = entry.stat(follow_symlinks=False)
            target = target_directory / staged_name
            if stat.S_ISDIR(metadata.st_mode):
                target.mkdir(mode=0o700)
                child_descriptor = os.open(
                    entry.name, directory_flags, dir_fd=source_descriptor
                )
                try:
                    child = os.fstat(child_descriptor)
                    if (
                        not stat.S_ISDIR(child.st_mode)
                        or (child.st_dev, child.st_ino)
                        != (metadata.st_dev, metadata.st_ino)
                        or stat.S_IMODE(child.st_mode)
                        != stat.S_IMODE(metadata.st_mode)
                    ):
                        raise ValueError("Gitleaks staging input changed")
                    copy_directory(child_descriptor, target, relative)
                finally:
                    os.close(child_descriptor)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Gitleaks staging rejects non-regular input")
            total_bytes += metadata.st_size
            if total_bytes > _MAX_GITLEAKS_STAGE_BYTES:
                raise ValueError("Gitleaks staging byte limit exceeded")

            source_file = os.open(
                entry.name, read_flags, dir_fd=source_descriptor
            )
            target_file = None
            try:
                opened = os.fstat(source_file)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                    or opened.st_size != metadata.st_size
                    or stat.S_IMODE(opened.st_mode)
                    != stat.S_IMODE(metadata.st_mode)
                ):
                    raise ValueError("Gitleaks staging input changed")
                target_file = os.open(target, write_flags, 0o600)
                copied = 0
                while True:
                    chunk = os.read(source_file, _STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > metadata.st_size:
                        raise ValueError("Gitleaks staging input grew")
                    remaining = memoryview(chunk)
                    while remaining:
                        written = os.write(target_file, remaining)
                        if written <= 0:
                            raise OSError("short Gitleaks staging write")
                        remaining = remaining[written:]
                closed = os.fstat(source_file)
                staged = os.fstat(target_file)
                if (
                    copied != metadata.st_size
                    or staged.st_size != metadata.st_size
                    or (closed.st_dev, closed.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or closed.st_size != opened.st_size
                    or closed.st_mtime_ns != opened.st_mtime_ns
                    or closed.st_ctime_ns != opened.st_ctime_ns
                ):
                    raise ValueError("Gitleaks staging input changed")
            finally:
                if target_file is not None:
                    os.close(target_file)
                os.close(source_file)
        closed_directory = os.fstat(source_descriptor)
        if (
            (closed_directory.st_dev, closed_directory.st_ino)
            != (opened_directory.st_dev, opened_directory.st_ino)
            or closed_directory.st_mtime_ns != opened_directory.st_mtime_ns
            or closed_directory.st_ctime_ns != opened_directory.st_ctime_ns
        ):
            raise ValueError("Gitleaks staging directory changed")

    try:
        workspace_metadata = workspace.lstat()
        if (
            not stat.S_ISDIR(workspace_metadata.st_mode)
            or stat.S_ISLNK(workspace_metadata.st_mode)
        ):
            raise ValueError("Gitleaks workspace must be a regular directory")
        destination.mkdir(mode=0o700)
        workspace_descriptor = os.open(workspace, directory_flags)
        try:
            opened_workspace = os.fstat(workspace_descriptor)
            if (
                (opened_workspace.st_dev, opened_workspace.st_ino)
                != (workspace_metadata.st_dev, workspace_metadata.st_ino)
                or stat.S_IMODE(opened_workspace.st_mode)
                != stat.S_IMODE(workspace_metadata.st_mode)
            ):
                raise ValueError("Gitleaks workspace changed")
            copy_directory(workspace_descriptor, destination, Path())
        finally:
            os.close(workspace_descriptor)
    except OSError as exc:
        raise ValueError("Gitleaks staging failed") from exc
    return renamed_controls


def _normalize_staged_gitleaks_findings(
    findings: list[dict],
    staged_workspace: Path,
    *,
    renamed_controls: dict[str, str],
) -> bool:
    """Map verified staging locations back to workspace-relative paths."""

    staged_root = staged_workspace.absolute()
    for finding in findings:
        raw_path = finding.get("File")
        if not isinstance(raw_path, str) or not raw_path:
            return False
        candidate = Path(raw_path)
        candidate = candidate if candidate.is_absolute() else staged_root / candidate
        try:
            relative = candidate.relative_to(staged_root)
        except ValueError:
            return False
        if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
            return False
        relative = Path(
            *(renamed_controls.get(part, part) for part in relative.parts)
        )
        finding["File"] = relative.as_posix()
    return True


def _normalize_staged_report_path(
    raw_path: object,
    staged_workspace: Path,
    *,
    renamed_controls: dict[str, str],
) -> str | None:
    """Return one verified workspace-relative path from a staged report."""

    if not isinstance(raw_path, str) or not raw_path:
        return None
    staged_root = staged_workspace.absolute()
    candidate = Path(raw_path)
    candidate = candidate if candidate.is_absolute() else staged_root / candidate
    try:
        relative = candidate.relative_to(staged_root)
    except ValueError:
        return None
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        return None
    return Path(
        *(renamed_controls.get(part, part) for part in relative.parts)
    ).as_posix()


def _scanner_environment_content_digest() -> str | None:
    """Hash all prepared environment entries without following symbolic links."""

    root = _scanner_identity_root() / "environment"
    try:
        root_metadata = root.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(
        root_metadata.st_mode
    ):
        return None

    digest = hashlib.sha256()
    digest.update(b"agent-eval-scanner-installed-environment-v1\0")
    pending = [(root, Path())]
    entry_count = 0
    total_bytes = 0
    try:
        while pending:
            path, relative = pending.pop()
            metadata = path.lstat()
            encoded_name = relative.as_posix().encode("utf-8")
            if len(encoded_name) > 4096:
                return None
            entry_count += 1
            if entry_count > _MAX_SCANNER_ENVIRONMENT_ENTRIES:
                return None
            digest.update(len(encoded_name).to_bytes(4, "big"))
            digest.update(encoded_name)
            digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
            if stat.S_ISDIR(metadata.st_mode):
                digest.update(b"d")
                with os.scandir(path) as entries:
                    children = sorted(
                        (Path(entry.path), relative / entry.name)
                        for entry in entries
                    )
                pending.extend(reversed(children))
                continue
            if stat.S_ISLNK(metadata.st_mode):
                target = os.fsencode(os.readlink(path))
                if len(target) > 4096:
                    return None
                digest.update(b"l")
                digest.update(len(target).to_bytes(4, "big"))
                digest.update(target)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                return None
            total_bytes += metadata.st_size
            if total_bytes > _MAX_SCANNER_ENVIRONMENT_BYTES:
                return None
            digest.update(b"f")
            digest.update(metadata.st_size.to_bytes(8, "big"))
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
                os, "O_NOFOLLOW", 0
            )
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                    or opened.st_size != metadata.st_size
                    or stat.S_IMODE(opened.st_mode)
                    != stat.S_IMODE(metadata.st_mode)
                ):
                    return None
                while True:
                    chunk = os.read(descriptor, _STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    digest.update(chunk)
            finally:
                os.close(descriptor)
    except (OSError, UnicodeError, ValueError):
        return None
    return digest.hexdigest()


def _scanner_runtime_command(executable: str, *arguments: str) -> list[str] | None:
    uv = _resolved_executable("uv")
    if uv is None:
        return None
    return [
        uv,
        "run",
        "--project",
        str(SCANNER_RUNTIME_PROJECT.parent),
        "--frozen",
        "--offline",
        "--no-sync",
        "--python",
        "3.12",
        "--no-dev",
        "--",
        executable,
        *arguments,
    ]


def _scanner_environment_executable(name: str) -> str | None:
    candidate = _scanner_identity_root() / "environment" / "bin" / name
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    return str(resolved) if resolved.is_file() else None
@dataclass
class _BoundedBuffer:
    limit: int
    overflow: threading.Event
    content: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    error: bool = False

    def consume(self, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(_STREAM_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = self.limit - len(self.content)
                if remaining > 0:
                    self.content.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True
                    self.overflow.set()
        except OSError:
            self.error = True
        finally:
            with contextlib.suppress(OSError):
                stream.close()


def _terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        with contextlib.suppress(OSError, ProcessLookupError):
            proc.terminate()
    try:
        proc.wait(timeout=_TERMINATION_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        with contextlib.suppress(OSError, ProcessLookupError):
            proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=_TERMINATION_GRACE_SECONDS)


def _execute_bounded(
    cmd: list[str], *, timeout: float
) -> tuple[subprocess.CompletedProcess[str] | None, str, bytes]:
    try:
        environment = _scanner_subprocess_environment()
        proc = subprocess.Popen(
            cmd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, RuntimeError, ValueError):
        return None, "error", b""
    assert proc.stdout is not None
    assert proc.stderr is not None
    overflow = threading.Event()
    stdout = _BoundedBuffer(_MAX_STREAM_BYTES, overflow)
    stderr = _BoundedBuffer(_MAX_STREAM_BYTES, overflow)
    threads = (
        threading.Thread(target=stdout.consume, args=(proc.stdout,), daemon=True),
        threading.Thread(target=stderr.consume, args=(proc.stderr,), daemon=True),
    )
    for thread in threads:
        thread.start()
    timed_out = False
    output_limited = False
    deadline = time.monotonic() + timeout
    while True:
        returncode = proc.poll()
        if returncode is not None:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            _terminate_process_group(proc)
            returncode = proc.poll()
            break
        if overflow.wait(timeout=min(_PROCESS_POLL_SECONDS, remaining)):
            output_limited = True
            _terminate_process_group(proc)
            returncode = proc.poll()
            break
    for thread in threads:
        thread.join(timeout=_STREAM_JOIN_SECONDS)
    if any(thread.is_alive() for thread in threads):
        _terminate_process_group(proc)
        for stream in (proc.stdout, proc.stderr):
            with contextlib.suppress(OSError):
                stream.close()
        for thread in threads:
            thread.join(timeout=_STREAM_JOIN_SECONDS)
    if timed_out:
        return None, "timeout", b""
    output = bytes(stdout.content or stderr.content)
    completed = subprocess.CompletedProcess(
        cmd,
        returncode if returncode is not None else -1,
        stdout.content.decode("utf-8", errors="replace"),
        stderr.content.decode("utf-8", errors="replace"),
    )
    if (
        stdout.truncated
        or stderr.truncated
        or output_limited
        or stdout.error
        or stderr.error
        or any(thread.is_alive() for thread in threads)
    ):
        return completed, "truncated", output
    return completed, "ok", output


def _installed_version(command: list[str]) -> str | None:
    proc, status, _output = _execute_bounded(
        command, timeout=_VERSION_TIMEOUT
    )
    if proc is None or status != "ok":
        return None
    output = (proc.stdout or proc.stderr).strip().splitlines()
    return output[0][:200] if proc.returncode == 0 and output else None


def _workspace_source_path(workspace: Path, raw_path: object) -> Path | None:
    source = Path(str(raw_path or ""))
    candidate = source if source.is_absolute() else workspace / source
    try:
        root = workspace.resolve(strict=True)
        candidate = candidate.resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate


def _read_regular_file_bounded(
    path: Path, *, maximum: int
) -> tuple[bytes | None, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, "error"
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, "error"
        if metadata.st_size > maximum:
            return None, "truncated"
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(_STREAM_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > maximum:
            return None, "truncated"
        return content, "ok"
    finally:
        os.close(descriptor)


def _read_source_lines_bounded(path: Path) -> tuple[list[str] | None, str, int]:
    content, status = _read_regular_file_bounded(
        path, maximum=_MAX_SOURCE_FILE_BYTES
    )
    if content is None:
        return None, status, 0
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None, "error", 0
    if len(lines) > _MAX_SOURCE_LINES:
        return None, "truncated", len(content)
    return lines, "ok", len(content)


def _workspace_regular_files(workspace: Path) -> tuple[Path, ...]:
    """Inventory a bounded no-follow workspace for explicit scanner coverage."""

    try:
        root_metadata = workspace.lstat()
        root = workspace.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("scanner workspace is unavailable") from exc
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or not root.is_dir()
    ):
        raise ValueError("scanner workspace must be a regular directory")

    files: list[Path] = []
    entry_count = 0
    total_bytes = 0
    pending = [root]
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda entry: os.fsencode(entry.name))
            child_directories: list[Path] = []
            for entry in ordered:
                entry_count += 1
                if entry_count > _MAX_GITLEAKS_STAGE_ENTRIES:
                    raise ValueError("scanner workspace entry limit exceeded")
                path = Path(entry.path)
                relative = path.relative_to(root)
                if (
                    len(os.fsencode(relative.as_posix()))
                    > _MAX_GITLEAKS_STAGE_PATH_BYTES
                ):
                    raise ValueError("scanner workspace path is too long")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    child_directories.append(path)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("scanner workspace rejects non-regular input")
                total_bytes += metadata.st_size
                if total_bytes > _MAX_GITLEAKS_STAGE_BYTES:
                    raise ValueError("scanner workspace byte limit exceeded")
                files.append(path)
            pending.extend(reversed(child_directories))
    except OSError as exc:
        raise ValueError("scanner workspace inventory failed") from exc
    return tuple(files)


def _looks_like_python_source(path: Path) -> bool:
    """Classify unknown text conservatively so extensions cannot hide Python."""

    if path.suffix.casefold() in _PYTHON_SOURCE_SUFFIXES:
        return True
    if path.suffix.casefold() in _KNOWN_NON_PYTHON_SUFFIXES:
        return False
    if path.name in _EVALUATOR_SCREENING_FILES:
        return False
    content, status = _read_regular_file_bounded(
        path, maximum=_MAX_SOURCE_FILE_BYTES
    )
    if status == "truncated":
        raise ValueError(
            f"unknown scanner source exceeds classification limit: {path.name}"
        )
    if content is None or not content or b"\0" in content:
        return False
    try:
        parsed = ast.parse(content, filename=str(path))
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return False
    strong_python_nodes = (
        ast.AsyncFunctionDef,
        ast.Await,
        ast.Call,
        ast.ClassDef,
        ast.FunctionDef,
        ast.Global,
        ast.Import,
        ast.ImportFrom,
        ast.Lambda,
        ast.Match,
        ast.Nonlocal,
        ast.Raise,
        ast.Try,
        ast.With,
        ast.Yield,
        ast.YieldFrom,
    )
    if any(isinstance(node, strong_python_nodes) for node in ast.walk(parsed)):
        return True
    meaningful_statements = (
        statement
        for statement in parsed.body
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, (ast.Constant, ast.Name))
        )
    )
    return (
        any(meaningful_statements)
        and not path.name.startswith(".")
        and ".git" not in path.parts
    )


def _python_scan_targets(workspace: Path) -> tuple[Path, ...]:
    return tuple(
        path for path in _workspace_regular_files(workspace)
        if _looks_like_python_source(path)
    )


def _scanner_target_batches(
    targets: tuple[Path, ...],
) -> tuple[tuple[str, ...], ...]:
    """Bound argv size while preserving an explicit target for every source."""

    batches: list[tuple[str, ...]] = []
    current: list[str] = []
    current_bytes = 0
    for target in targets:
        encoded_bytes = len(os.fsencode(str(target))) + 1
        if encoded_bytes > _MAX_SCANNER_BATCH_ARGUMENT_BYTES:
            raise ValueError("scanner target path exceeds argument limit")
        if current and (
            current_bytes + encoded_bytes > _MAX_SCANNER_BATCH_ARGUMENT_BYTES
        ):
            batches.append(tuple(current))
            current = []
            current_bytes = 0
        current.append(str(target))
        current_bytes += encoded_bytes
    if current:
        batches.append(tuple(current))
    return tuple(batches)


def _observed_runtime_version(name: str) -> str | None:
    command = _scanner_runtime_command(name, "--version")
    if command is None:
        return None
    observed = _installed_version(command)
    if name == "ruff" and observed is not None:
        return observed.removeprefix("ruff ")
    return observed


def _write_json_artifact(path: Path, value: object) -> bool:
    try:
        encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        if len(encoded) > _MAX_STREAM_BYTES:
            return False
        path.write_bytes(encoded)
    except (OSError, TypeError, ValueError):
        return False
    return True


@dataclass
class _SourceLineCache:
    lines: dict[Path, list[str] | None] = field(default_factory=dict)
    total_bytes: int = 0
    total_lines: int = 0
    truncated: bool = False

    def get(self, candidate: Path) -> list[str] | None:
        if candidate not in self.lines:
            if len(self.lines) >= _MAX_SOURCE_CACHE_FILES:
                self.truncated = True
                return None
            lines, status, size = _read_source_lines_bounded(candidate)
            if status == "truncated":
                self.truncated = True
            if lines is None:
                self.lines[candidate] = None
                return None
            if self.total_bytes + size > _MAX_SOURCE_CACHE_BYTES:
                self.truncated = True
                self.lines[candidate] = None
                return None
            if self.total_lines + len(lines) > _MAX_SOURCE_CACHE_LINES:
                self.truncated = True
                self.lines[candidate] = None
                return None
            self.total_bytes += size
            self.total_lines += len(lines)
            self.lines[candidate] = lines
        return self.lines[candidate]


@dataclass
class _SourceIdentityCache:
    workspace: Path
    sources: _SourceLineCache = field(default_factory=_SourceLineCache)
    identities: dict[Path, tuple[tuple[str, str], ...] | None] = field(
        default_factory=dict
    )

    @property
    def truncated(self) -> bool:
        return self.sources.truncated

    def get(self, raw_path: object, line: object) -> tuple[str, str] | None:
        if isinstance(line, bool) or not isinstance(line, int) or line <= 0:
            return None
        candidate = _workspace_source_path(self.workspace, raw_path)
        if candidate is None:
            return None
        if candidate not in self.identities:
            lines = self.sources.get(candidate)
            if lines is None:
                self.identities[candidate] = None
                return None
            self.identities[candidate] = _all_line_identities(lines)
        cached = self.identities[candidate]
        if cached is None or line > len(cached):
            return None
        return cached[line - 1]


def _bounded_string(value: object, maximum: int) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if not isinstance(value, str):
        return None, False
    prefix = value[:maximum]
    sanitized = "".join(
        character if character.isprintable() else "?" for character in prefix
    )
    changed = sanitized != value
    if len(value) <= maximum:
        return sanitized, changed
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    suffix = f"...sha256:{digest}"
    return sanitized[: maximum - len(suffix)] + suffix, True


def _bounded_line(value: object) -> tuple[int | None, bool]:
    if value is None:
        return None, False
    if type(value) is int and 0 < value <= 2_147_483_647:
        return value, False
    return None, True


def _line_identity(lines: list[str], line: object) -> tuple[str, str] | None:
    if isinstance(line, bool) or not isinstance(line, int) or line <= 0:
        return None
    if line > len(lines):
        return None
    source_line = lines[line - 1].strip()
    occurrence = sum(
        candidate_line.strip() == source_line for candidate_line in lines[:line]
    )
    digest = hashlib.sha256(source_line.encode("utf-8")).hexdigest()
    return f"{digest[:16]}:{occurrence}", f"{digest}:{occurrence}"


def _all_line_identities(lines: list[str]) -> tuple[tuple[str, str], ...]:
    occurrences: dict[str, int] = {}
    identities: list[tuple[str, str]] = []
    for source_line in lines:
        normalized = source_line.strip()
        occurrence = occurrences.get(normalized, 0) + 1
        occurrences[normalized] = occurrence
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        identities.append(
            (f"{digest[:16]}:{occurrence}", f"{digest}:{occurrence}")
        )
    return tuple(identities)


def _line_fingerprint(lines: list[str], line: object) -> str | None:
    identity = _line_identity(lines, line)
    return identity[0] if identity else None


def _source_line_identity(
    workspace: Path, raw_path: object, line: object
) -> tuple[str, str] | None:
    candidate = _workspace_source_path(workspace, raw_path)
    if candidate is None:
        return None
    lines, _status, _size = _read_source_lines_bounded(candidate)
    if lines is None:
        return None
    return _line_identity(lines, line)


def _source_line_fingerprint(
    workspace: Path, raw_path: object, line: object
) -> str | None:
    identity = _source_line_identity(workspace, raw_path, line)
    return identity[0] if identity else None


def _redacted_gitleaks_identities_bounded(
    workspace: Path, findings: list[object]
) -> tuple[dict[int, tuple[str, str]], bool]:
    grouped: dict[Path, list[tuple[int, dict]]] = {}
    truncated = False
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        raw_path = finding.get("File")
        if isinstance(raw_path, str) and len(raw_path) > _MAX_PATH_CHARS:
            truncated = True
            continue
        source = _workspace_source_path(workspace, raw_path)
        if source is not None:
            grouped.setdefault(source, []).append((index, finding))

    identities: dict[int, tuple[str, str]] = {}
    source_cache = _SourceLineCache()
    for source, source_findings in grouped.items():
        source_lines = source_cache.get(source)
        if source_lines is None:
            continue
        redacted_lines = list(source_lines)

        tokens: dict[int, tuple[str, ...]] = {}
        segment_count = 0
        for index, finding in source_findings:
            secret = finding.get("Secret")
            match = finding.get("Match")
            token = secret if isinstance(secret, str) and secret else match
            if not isinstance(token, str) or not token:
                continue
            if len(token) > _MAX_SECRET_TOKEN_CHARS:
                truncated = True
                continue
            segments = tuple(segment for segment in token.splitlines() if segment)
            if segment_count + len(segments) > _MAX_REDACTION_SEGMENTS_PER_FILE:
                truncated = True
                continue
            if segments:
                segment_count += len(segments)
                tokens[index] = segments

        selected_segments: list[str] = []
        pattern_chars = 0
        for segment in sorted(
            {segment for segments in tokens.values() for segment in segments},
            key=len,
            reverse=True,
        ):
            escaped_length = len(re.escape(segment)) + 1
            if (
                len(selected_segments) >= _MAX_REDACTION_SEGMENTS_PER_FILE
                or pattern_chars + escaped_length > _MAX_REDACTION_PATTERN_CHARS
            ):
                truncated = True
                continue
            selected_segments.append(segment)
            pattern_chars += escaped_length

        redacted_segments: set[str] = set()
        if selected_segments:
            pattern = re.compile(
                "|".join(re.escape(segment) for segment in selected_segments)
            )

            # Bind the per-file accumulator at definition time so the closure
            # can never observe a later loop iteration's set.
            def redact(
                match: re.Match[str],
                sink: set[str] = redacted_segments,
            ) -> str:
                sink.add(match.group(0))
                return _REDACTED_SECRET

            redacted_lines = [pattern.sub(redact, line) for line in source_lines]

        line_identities = _all_line_identities(redacted_lines)
        for index, finding in source_findings:
            finding_tokens = tokens.get(index)
            if not finding_tokens or not all(
                segment in redacted_segments for segment in finding_tokens
            ):
                continue
            line = finding.get("StartLine")
            if (
                isinstance(line, bool)
                or not isinstance(line, int)
                or line <= 0
                or line > len(source_lines)
                or source_lines[line - 1] == redacted_lines[line - 1]
            ):
                continue
            identities[index] = line_identities[line - 1]
    return identities, truncated or source_cache.truncated


def _redacted_gitleaks_identities(
    workspace: Path, findings: list[object]
) -> dict[int, tuple[str, str]]:
    return _redacted_gitleaks_identities_bounded(workspace, findings)[0]


def _redacted_gitleaks_fingerprints(
    workspace: Path, findings: list[object]
) -> dict[int, str]:
    return {
        index: identity[0]
        for index, identity in _redacted_gitleaks_identities(
            workspace, findings
        ).items()
    }


def _canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _trivy_version_identity(
    executable: str, cache_dir: Path
) -> tuple[str | None, TrivyDatabaseIdentity | None]:
    proc, status, _output = _execute_bounded(
        [
            executable,
            "version",
            "--format",
            "json",
            "--cache-dir",
            str(cache_dir),
        ],
        timeout=_VERSION_TIMEOUT,
    )
    if proc is None or status != "ok" or proc.returncode != 0:
        return None, None
    try:
        report = json.loads(proc.stdout)
    except (TypeError, UnicodeDecodeError, ValueError):
        return None, None
    if not isinstance(report, dict):
        return None, None
    version, version_truncated = _bounded_string(report.get("Version"), 200)
    raw_database = report.get("VulnerabilityDB")
    if version_truncated or not version or not isinstance(raw_database, dict):
        return version, None
    database_version = raw_database.get("Version")
    timestamps = {
        "updated_at": raw_database.get("UpdatedAt"),
        "next_update": raw_database.get("NextUpdate"),
        "downloaded_at": raw_database.get("DownloadedAt"),
    }
    if (
        isinstance(database_version, bool)
        or not isinstance(database_version, int)
        or database_version < 1
        or not all(
            isinstance(value, str) and 0 < len(value) <= 128
            for value in timestamps.values()
        )
    ):
        return version, None
    return version, TrivyDatabaseIdentity(
        version=database_version,
        **timestamps,
    )


def _trivy_database_content_digest(cache_dir: Path) -> str | None:
    """Hash the exact local Trivy vulnerability database without following links."""

    root = cache_dir / "db"
    try:
        metadata = root.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return None

    digest = hashlib.sha256()
    digest.update(b"agent-eval-trivy-db-v1\0")
    total_bytes = 0
    file_count = 0
    pending = [(root, Path())]
    try:
        while pending:
            directory, relative_directory = pending.pop()
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda entry: os.fsencode(entry.name))
            for entry in ordered:
                relative = relative_directory / entry.name
                encoded_name = relative.as_posix().encode("utf-8")
                if len(encoded_name) > 4096:
                    return None
                entry_metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(entry_metadata.st_mode):
                    pending.append((Path(entry.path), relative))
                    continue
                if not stat.S_ISREG(entry_metadata.st_mode):
                    return None
                file_count += 1
                total_bytes += entry_metadata.st_size
                if (
                    file_count > _MAX_TRIVY_DB_FILES
                    or total_bytes > _MAX_TRIVY_DB_BYTES
                ):
                    return None
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
                    os, "O_NOFOLLOW", 0
                )
                descriptor = os.open(entry.path, flags)
                try:
                    opened = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or (opened.st_dev, opened.st_ino)
                        != (entry_metadata.st_dev, entry_metadata.st_ino)
                        or opened.st_size != entry_metadata.st_size
                    ):
                        return None
                    digest.update(len(encoded_name).to_bytes(4, "big"))
                    digest.update(encoded_name)
                    digest.update(opened.st_size.to_bytes(8, "big"))
                    while True:
                        chunk = os.read(descriptor, _STREAM_CHUNK_BYTES)
                        if not chunk:
                            break
                        digest.update(chunk)
                finally:
                    os.close(descriptor)
    except (OSError, UnicodeError):
        return None
    return digest.hexdigest() if file_count else None


def scanner_assurance_identity(
    results: ScanResults,
) -> ScannerAssuranceIdentity:
    """Create one canonical identity and explicit promotion readiness result."""

    executable_hashes = {
        name: results.scanner_executable_sha256.get(name)
        for name in SCANNER_EXECUTABLE_NAMES
    }
    material = {
        "schema_version": "2",
        "runtime_bundle_sha256": scanner_runtime_digest(),
        "runtime_project_sha256": scanner_runtime_project_digest(),
        "runtime_lock_sha256": scanner_runtime_lock_digest(),
        "runtime_environment_sha256": (
            results.scanner_runtime_environment_sha256
        ),
        "semgrep_ruleset_sha256": scanner_runtime_ruleset_digest(),
        "gitleaks_config_sha256": scanner_runtime_gitleaks_config_digest(),
        "scanner_executable_sha256": executable_hashes,
        "trivy_db": (
            results.trivy_db.model_dump(mode="json")
            if results.trivy_db is not None
            else None
        ),
    }
    blockers = scanner_promotion_blockers(results)
    return ScannerAssuranceIdentity(
        **material,
        identity_sha256=scanner_assurance_material_sha256(material),
        promotion_ready=not blockers,
        promotion_blockers=blockers,
    )


def scanner_preflight_assurance_identity() -> ScannerAssuranceIdentity:
    """Inspect the exact local scanner materials without scanning a workspace."""

    runtime_versions = {
        name: _observed_runtime_version(name) for name in ("ruff", "semgrep")
    }
    results = ScanResults(
        scanner_runtime_lock_sha256=scanner_runtime_lock_digest(),
        scanner_runtime_environment_sha256=(
            _scanner_environment_content_digest()
        ),
        scanner_status={
            name: (
                "ok"
                if observed == SCANNER_REQUIRED_VERSIONS[name]
                else "error"
            )
            for name, observed in runtime_versions.items()
        },
        scanner_versions=runtime_versions,
    )
    uv_executable = _resolved_executable("uv")
    results.scanner_executable_sha256["uv"] = (
        _executable_sha256(uv_executable) if uv_executable is not None else None
    )
    for name in ("python", "ruff", "semgrep"):
        executable = _scanner_environment_executable(name)
        results.scanner_executable_sha256[name] = (
            _executable_sha256(executable) if executable is not None else None
        )

    gitleaks = _resolved_executable("gitleaks")
    if gitleaks is None:
        results.scanner_status["gitleaks"] = "unavailable"
    else:
        before = _executable_sha256(gitleaks)
        version = _installed_version([gitleaks, "version"])
        after = _executable_sha256(gitleaks)
        stable = before is not None and before == after
        results.scanner_executable_sha256["gitleaks"] = before if stable else None
        results.scanner_versions["gitleaks"] = version
        results.scanner_status["gitleaks"] = (
            "ok"
            if stable and version == SCANNER_REQUIRED_VERSIONS["gitleaks"]
            else "error"
        )

    trivy = _resolved_executable("trivy")
    if trivy is None:
        results.scanner_status["trivy"] = "unavailable"
    else:
        before = _executable_sha256(trivy)
        try:
            cache_dir = ensure_private_directory(
                _scanner_identity_root() / "trivy-cache"
            )
            version, database = _trivy_version_identity(trivy, cache_dir)
            if database is not None:
                database = database.model_copy(
                    update={
                        "content_sha256": _trivy_database_content_digest(cache_dir)
                    }
                )
        except (OSError, RuntimeError, ValueError):
            version, database = None, None
        after = _executable_sha256(trivy)
        stable = before is not None and before == after
        results.scanner_executable_sha256["trivy"] = before if stable else None
        results.scanner_versions["trivy"] = version
        results.trivy_db = database
        results.scanner_status["trivy"] = (
            "ok"
            if stable
            and version == SCANNER_REQUIRED_VERSIONS["trivy"]
            and database is not None
            and database.content_sha256 is not None
            else "error"
        )
    return scanner_assurance_identity(results)


def prepare_scanner_runtime() -> ScannerAssuranceIdentity:
    """Hydrate locked scanners and the Trivy DB before offline evaluation."""

    uv = _resolved_executable("uv")
    if uv is None:
        raise RuntimeError("uv is required to prepare the scanner runtime")
    uv_before = _executable_sha256(uv)
    if uv_before is None:
        raise RuntimeError("uv executable identity could not be verified")
    proc, status, _output = _execute_bounded(
        [
            uv,
            "sync",
            "--project",
            str(SCANNER_RUNTIME_PROJECT.parent),
            "--frozen",
            "--python",
            "3.12",
            "--no-dev",
            "--no-install-project",
        ],
        timeout=_PREPARE_TIMEOUT,
    )
    if proc is None or status != "ok" or proc.returncode != 0:
        raise RuntimeError(f"locked scanner runtime preparation failed: {status}")
    if _executable_sha256(uv) != uv_before:
        raise RuntimeError("uv executable changed during scanner preparation")

    trivy = _resolved_executable("trivy")
    if trivy is not None:
        trivy_before = _executable_sha256(trivy)
        cache_dir = ensure_private_directory(_scanner_identity_root() / "trivy-cache")
        proc, status, _output = _execute_bounded(
            [
                trivy,
                "image",
                "--cache-dir",
                str(cache_dir),
                "--download-db-only",
                "--no-progress",
            ],
            timeout=_PREPARE_TIMEOUT,
        )
        if proc is None or status != "ok" or proc.returncode != 0:
            raise RuntimeError(f"Trivy database preparation failed: {status}")
        if trivy_before is None or _executable_sha256(trivy) != trivy_before:
            raise RuntimeError("Trivy executable changed during database preparation")

    return scanner_preflight_assurance_identity()


def _run(
    cmd: list[str], out_file: Path
) -> tuple[subprocess.CompletedProcess | None, str]:
    proc, status, output = _execute_bounded(cmd, timeout=SCAN_TIMEOUT)
    try:
        out_file.write_bytes(output)
    except OSError as exc:
        console.print(
            f"[yellow]scanner {cmd[0]} output failed: {type(exc).__name__}[/yellow]"
        )
        return None, "error"
    if status != "ok":
        console.print(f"[yellow]scanner {cmd[0]} failed: {status}[/yellow]")
    return proc, status


def run_scanners(workspace: Path, run_dir: Path,
                 language: str | None = "python") -> ScanResults:
    results = ScanResults(
        scanner_runtime_lock_sha256=scanner_runtime_lock_digest()
    )
    scans_dir = run_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)

    uv_executable = _resolved_executable("uv")
    uv_before = (
        _executable_sha256(uv_executable) if uv_executable is not None else None
    )
    environment_digest_before = _scanner_environment_content_digest()
    environment_executables_before = {
        name: _scanner_environment_executable(name)
        for name in ("python", "ruff", "semgrep")
    }
    environment_hashes_before = {
        name: _executable_sha256(executable) if executable is not None else None
        for name, executable in environment_executables_before.items()
    }
    try:
        python_targets = _python_scan_targets(workspace)
    except (OSError, RuntimeError, ValueError):
        python_targets = None
    _lint(
        language,
        workspace,
        scans_dir,
        results,
        targets=python_targets,
    )
    _semgrep(
        workspace,
        scans_dir,
        results,
        targets=python_targets,
    )
    _gitleaks(workspace, scans_dir, results)
    _trivy(workspace, scans_dir, results)
    uv_after = (
        _executable_sha256(uv_executable) if uv_executable is not None else None
    )
    results.scanner_executable_sha256["uv"] = (
        uv_before if uv_before is not None and uv_before == uv_after else None
    )
    environment_digest_after = _scanner_environment_content_digest()
    results.scanner_runtime_environment_sha256 = (
        environment_digest_before
        if environment_digest_before is not None
        and environment_digest_before == environment_digest_after
        else None
    )
    for name, before_executable in environment_executables_before.items():
        after_executable = _scanner_environment_executable(name)
        after_hash = (
            _executable_sha256(after_executable)
            if after_executable is not None
            else None
        )
        before_hash = environment_hashes_before[name]
        results.scanner_executable_sha256[name] = (
            before_hash
            if before_executable == after_executable
            and before_hash is not None
            and before_hash == after_hash
            else None
        )
    results.scanner_assurance = scanner_assurance_identity(results)
    return results


def _lint(
    language: str | None,
    workspace: Path,
    scans_dir: Path,
    results: ScanResults,
    *,
    targets: tuple[Path, ...] | None = None,
) -> None:
    observed_version = _observed_runtime_version("ruff")
    results.scanner_versions["ruff"] = observed_version
    results.scanner_configs["ruff"] = (
        "packaged-runtime; isolated; "
        f"lock-sha256={scanner_runtime_lock_digest()}; "
        f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
    )
    if language != "python":
        results.scanner_status["ruff"] = "not_applicable"
        return  # eslint etc. can be added per-language later
    if observed_version != SCANNER_REQUIRED_VERSIONS["ruff"]:
        results.scanner_status["ruff"] = "error"
        return
    if targets is None:
        try:
            targets = _python_scan_targets(workspace)
        except (OSError, RuntimeError, ValueError):
            results.scanner_status["ruff"] = "error"
            return
    try:
        policy_arguments = scanner_runtime_invocation_policy()["ruff"][
            "arguments"
        ]
    except (KeyError, RuntimeError, TypeError):
        results.scanner_status["ruff"] = "error"
        return
    try:
        batches = _scanner_target_batches(targets)
    except ValueError:
        results.scanner_status["ruff"] = "error"
        return
    findings: list[object] = []
    captured_bytes = 0
    for batch in batches:
        command = _scanner_runtime_command(
            "ruff",
            "check",
            "--output-format",
            "json",
            "--exit-zero",
            "--isolated",
            *policy_arguments,
            *batch,
        )
        if command is None:
            results.scanner_status["ruff"] = "unavailable"
            return
        proc, status = _run(command, scans_dir / "ruff.json")
        results.scanner_status["ruff"] = status
        if proc is None or status != "ok" or proc.returncode != 0:
            if proc is not None and status == "ok":
                results.scanner_status["ruff"] = "error"
            return
        captured_bytes += len(proc.stdout.encode("utf-8"))
        if captured_bytes > _MAX_STREAM_BYTES:
            results.scanner_status["ruff"] = "truncated"
            return
        try:
            batch_findings = json.loads(proc.stdout)
        except ValueError:
            results.scanner_status["ruff"] = "error"
            return
        if not isinstance(batch_findings, list):
            results.scanner_status["ruff"] = "error"
            return
        findings.extend(batch_findings)
    if not _write_json_artifact(scans_dir / "ruff.json", findings):
        results.scanner_status["ruff"] = "truncated"
        return
    results.scanner_status["ruff"] = "ok"
    results.lint_errors = len(findings)


def _semgrep(
    workspace: Path,
    scans_dir: Path,
    results: ScanResults,
    *,
    targets: tuple[Path, ...] | None = None,
) -> None:
    observed_version = _observed_runtime_version("semgrep")
    results.scanner_versions["semgrep"] = observed_version
    results.scanner_configs["semgrep"] = (
        "packaged:semgrep.yml; "
        f"sha256={scanner_runtime_ruleset_digest()}; "
        f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
    )
    if observed_version != SCANNER_REQUIRED_VERSIONS["semgrep"]:
        results.scanner_status["semgrep"] = "error"
        return
    if targets is None:
        try:
            targets = _python_scan_targets(workspace)
        except (OSError, RuntimeError, ValueError):
            results.scanner_status["semgrep"] = "error"
            return
    try:
        policy_arguments = scanner_runtime_invocation_policy()["semgrep"][
            "arguments"
        ]
    except (KeyError, RuntimeError, TypeError):
        results.scanner_status["semgrep"] = "error"
        return
    try:
        batches = _scanner_target_batches(targets)
    except ValueError:
        results.scanner_status["semgrep"] = "error"
        return
    findings: list[object] = []
    scanned_sources: set[Path] = set()
    captured_bytes = 0
    for batch in batches:
        command = _scanner_runtime_command(
            "semgrep",
            "scan",
            "--config",
            str(_SEMGREP_CONFIG),
            "--no-rewrite-rule-ids",
            "--disable-version-check",
            "--metrics",
            "off",
            *policy_arguments,
            "--json",
            "--quiet",
            *batch,
        )
        if command is None:
            results.scanner_status["semgrep"] = "unavailable"
            return
        proc, status = _run(command, scans_dir / "semgrep.json")
        results.scanner_status["semgrep"] = status
        if proc is None or status != "ok" or proc.returncode not in (0, 1):
            if proc is not None and status == "ok":
                results.scanner_status["semgrep"] = "error"
            return
        captured_bytes += len(proc.stdout.encode("utf-8"))
        if captured_bytes > _MAX_STREAM_BYTES:
            results.scanner_status["semgrep"] = "truncated"
            return
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            results.scanner_status["semgrep"] = "error"
            return
        if not isinstance(report, dict):
            results.scanner_status["semgrep"] = "error"
            return
        errors = report.get("errors")
        skipped_rules = report.get("skipped_rules")
        paths = report.get("paths")
        scanned_paths = paths.get("scanned") if isinstance(paths, dict) else None
        skipped_paths = paths.get("skipped", []) if isinstance(paths, dict) else None
        if (
            report.get("version") != SCANNER_REQUIRED_VERSIONS["semgrep"]
            or not isinstance(errors, list)
            or errors
            or not isinstance(skipped_rules, list)
            or skipped_rules
            or not isinstance(scanned_paths, list)
            or not all(isinstance(path, str) for path in scanned_paths)
            or not isinstance(skipped_paths, list)
            or skipped_paths
        ):
            results.scanner_status["semgrep"] = "error"
            return
        batch_findings = report.get("results")
        if not isinstance(batch_findings, list):
            results.scanner_status["semgrep"] = "error"
            return
        findings.extend(batch_findings)
        for raw_path in scanned_paths:
            candidate = _workspace_source_path(workspace, raw_path)
            if candidate is None:
                results.scanner_status["semgrep"] = "error"
                return
            scanned_sources.add(candidate)
    try:
        expected_sources = {target.resolve(strict=True) for target in targets}
    except (OSError, RuntimeError):
        results.scanner_status["semgrep"] = "error"
        return
    if scanned_sources != expected_sources:
        results.scanner_status["semgrep"] = "error"
        return
    if not isinstance(findings, list) or not all(
        isinstance(finding, dict)
        and isinstance(finding.get("extra", {}), dict)
        and isinstance(finding.get("extra", {}).get("severity", "INFO"), str)
        and (
            finding.get("start") is None
            or isinstance(finding.get("start"), dict)
        )
        for finding in findings
    ):
        results.scanner_status["semgrep"] = "error"
        return
    consolidated_report = {
        "version": SCANNER_REQUIRED_VERSIONS["semgrep"],
        "results": findings,
        "errors": [],
        "paths": {"scanned": sorted(str(path) for path in scanned_sources)},
        "skipped_rules": [],
    }
    if not _write_json_artifact(scans_dir / "semgrep.json", consolidated_report):
        results.scanner_status["semgrep"] = "truncated"
        return
    results.scanner_status["semgrep"] = "ok"
    sev = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    available = max(0, _MAX_RETAINED_FINDINGS - len(results.findings))
    retained_truncated = len(findings) > available
    source_cache = _SourceIdentityCache(workspace)
    for f in findings:
        raw_severity = f.get("extra", {}).get("severity", "INFO")
        sev[raw_severity] = sev.get(raw_severity, 0) + 1
    for f in findings[:available]:
        rule, rule_truncated = _bounded_string(f.get("check_id"), _MAX_RULE_CHARS)
        severity, severity_truncated = _bounded_string(
            f.get("extra", {}).get("severity"), _MAX_SEVERITY_CHARS
        )
        path, path_truncated = _bounded_string(f.get("path"), _MAX_PATH_CHARS)
        line, line_truncated = _bounded_line((f.get("start") or {}).get("line"))
        retained_truncated = retained_truncated or any(
            (
                rule_truncated,
                severity_truncated,
                path_truncated,
                line_truncated,
            )
        )
        finding = {
            "tool": "semgrep",
            "rule": rule,
            "severity": severity,
            "path": path,
            "line": line,
        }
        line_identity = source_cache.get(finding["path"], finding["line"])
        if line_identity:
            finding["primary_location_line_hash"] = line_identity[0]
            finding["semantic_location_hash"] = line_identity[1]
        results.findings.append(finding)
    results.sec_findings_high = sev["ERROR"]
    results.sec_findings_medium = sev["WARNING"]
    results.sec_findings_low = sev["INFO"]
    if retained_truncated or source_cache.truncated:
        results.scanner_status["semgrep"] = "truncated"


def _gitleaks(workspace: Path, scans_dir: Path, results: ScanResults) -> None:
    executable = _resolved_executable("gitleaks")
    if executable is None:
        results.scanner_status["gitleaks"] = "unavailable"
        return
    ignore_policy_before = _verified_empty_ignore_policy_sha256()
    policy_arguments = _external_scanner_policy_arguments("gitleaks")
    if ignore_policy_before is None or policy_arguments is None:
        results.scanner_status["gitleaks"] = "error"
        return
    executable_before = _executable_sha256(executable)
    results.scanner_versions["gitleaks"] = _installed_version(
        [executable, "version"]
    )
    staged_workspace = None
    renamed_controls: dict[str, str] = {}
    try:
        private_tmp = ensure_private_directory(_scanner_identity_root() / "tmp")
        with tempfile.TemporaryDirectory(
            prefix="gitleaks-input-", dir=private_tmp
        ) as temporary:
            os.chmod(temporary, 0o700, follow_symlinks=False)
            staged_workspace = Path(temporary) / "workspace"
            renamed_controls = _stage_gitleaks_workspace(
                workspace, staged_workspace
            )
            proc, status = _run(
                [
                    executable,
                    "dir",
                    str(staged_workspace),
                    "--report-format",
                    "json",
                    "--report-path",
                    "-",
                    "--config",
                    str(SCANNER_RUNTIME_GITLEAKS_CONFIG),
                    "--no-banner",
                    *policy_arguments,
                ],
                Path(os.devnull),
            )
    except (OSError, RuntimeError, ValueError):
        proc, status = None, "error"
    ignore_policy_after = _verified_empty_ignore_policy_sha256()
    executable_after = _executable_sha256(executable)
    executable_stable = executable_before == executable_after
    results.scanner_executable_sha256["gitleaks"] = (
        executable_before if executable_stable else None
    )
    results.scanner_configs["gitleaks"] = (
        (
            "packaged-default; config-sha256="
            f"{scanner_runtime_gitleaks_config_digest()}; "
            f"empty-ignore-policy-sha256={ignore_policy_before}; "
            "target-suppressions=disabled; "
            f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
        )
        if executable_before is None
        else (
            "packaged-default; config-sha256="
            f"{scanner_runtime_gitleaks_config_digest()}; "
            f"empty-ignore-policy-sha256={ignore_policy_before}; "
            "target-suppressions=disabled; "
            f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}; "
            f"executable-sha256={executable_before}"
        )
    )
    results.scanner_status["gitleaks"] = status
    if (
        not executable_stable
        or ignore_policy_after != ignore_policy_before
        or results.scanner_versions.get("gitleaks")
        != SCANNER_REQUIRED_VERSIONS["gitleaks"]
    ):
        results.scanner_status["gitleaks"] = "error"
        return
    if proc is None or status != "ok":
        return
    if proc.returncode not in (0, 1):
        results.scanner_status["gitleaks"] = "error"
        return
    try:
        raw_findings = json.loads(proc.stdout)
    except (TypeError, UnicodeDecodeError, ValueError):
        results.scanner_status["gitleaks"] = "error"
        return
    if not isinstance(raw_findings, list):
        results.scanner_status["gitleaks"] = "error"
        return
    if not all(isinstance(finding, dict) for finding in raw_findings):
        results.scanner_status["gitleaks"] = "error"
        return
    if staged_workspace is None or not _normalize_staged_gitleaks_findings(
        raw_findings,
        staged_workspace,
        renamed_controls=renamed_controls,
    ):
        results.scanner_status["gitleaks"] = "error"
        return

    results.secrets_found = len(raw_findings)
    available = max(0, _MAX_RETAINED_FINDINGS - len(results.findings))
    retained_raw_findings = raw_findings[:available]
    retained_truncated = len(raw_findings) > len(retained_raw_findings)
    identities, identity_truncated = _redacted_gitleaks_identities_bounded(
        workspace, retained_raw_findings
    )
    retained_truncated = retained_truncated or identity_truncated
    retained_findings = []
    for index, raw_finding in enumerate(retained_raw_findings):
        rule, rule_truncated = _bounded_string(
            raw_finding.get("RuleID") or "secret", _MAX_RULE_CHARS
        )
        path, path_truncated = _bounded_string(
            raw_finding.get("File"), _MAX_PATH_CHARS
        )
        line, line_truncated = _bounded_line(raw_finding.get("StartLine"))
        retained_truncated = (
            retained_truncated
            or rule_truncated
            or path_truncated
            or line_truncated
        )
        finding = {
            "tool": "gitleaks",
            "rule": rule,
            "severity": "ERROR",
            "path": path,
            "line": line,
        }
        identity = identities.get(index)
        if identity:
            finding["primary_location_line_hash"] = identity[0]
            finding["semantic_location_hash"] = identity[1]
        results.findings.append(finding)
        retained_findings.append(finding)
    try:
        (scans_dir / "gitleaks.json").write_text(
            json.dumps(retained_findings, indent=2) + "\n"
        )
        (scans_dir / "gitleaks.log").write_text(
            f"exit_code={proc.returncode} "
            f"redacted_findings={len(retained_findings)}\n"
        )
    except OSError:
        results.scanner_status["gitleaks"] = "error"
        return
    if retained_truncated:
        results.scanner_status["gitleaks"] = "truncated"


def _trivy(workspace: Path, scans_dir: Path, results: ScanResults) -> None:
    executable = _resolved_executable("trivy")
    if executable is None:
        results.scanner_status["trivy"] = "unavailable"
        return
    ignore_policy_before = _verified_empty_ignore_policy_sha256()
    policy_arguments = _external_scanner_policy_arguments("trivy")
    if ignore_policy_before is None or policy_arguments is None:
        results.scanner_status["trivy"] = "error"
        return
    executable_before = _executable_sha256(executable)
    try:
        cache_dir = ensure_private_directory(
            _scanner_identity_root() / "trivy-cache"
        )
    except (OSError, RuntimeError, ValueError):
        results.scanner_status["trivy"] = "error"
        return
    version_before, database_before = _trivy_version_identity(
        executable, cache_dir
    )
    if database_before is not None:
        database_before = database_before.model_copy(
            update={
                "content_sha256": _trivy_database_content_digest(cache_dir)
            }
        )
    results.scanner_versions["trivy"] = version_before
    results.trivy_db = database_before
    if (
        version_before != SCANNER_REQUIRED_VERSIONS["trivy"]
        or database_before is None
        or database_before.content_sha256 is None
    ):
        results.scanner_status["trivy"] = "error"
        return

    staged_workspace = None
    renamed_controls: dict[str, str] = {}
    try:
        private_tmp = ensure_private_directory(_scanner_identity_root() / "tmp")
        with tempfile.TemporaryDirectory(
            prefix="trivy-input-", dir=private_tmp
        ) as temporary:
            os.chmod(temporary, 0o700, follow_symlinks=False)
            staged_workspace = Path(temporary) / "workspace"
            renamed_controls = _stage_gitleaks_workspace(
                workspace, staged_workspace
            )
            proc, status = _run(
                [
                    executable,
                    "fs",
                    "--cache-dir",
                    str(cache_dir),
                    *policy_arguments,
                    "--format",
                    "json",
                    str(staged_workspace),
                ],
                Path(os.devnull),
            )
    except (OSError, RuntimeError, ValueError):
        proc, status = None, "error"
    version_after, database_after = _trivy_version_identity(executable, cache_dir)
    if database_after is not None:
        database_after = database_after.model_copy(
            update={
                "content_sha256": _trivy_database_content_digest(cache_dir)
            }
        )
    executable_after = _executable_sha256(executable)
    ignore_policy_after = _verified_empty_ignore_policy_sha256()
    executable_stable = executable_before == executable_after
    results.scanner_executable_sha256["trivy"] = (
        executable_before if executable_stable else None
    )
    results.scanner_versions["trivy"] = version_after
    results.trivy_db = database_after
    results.scanner_configs["trivy"] = (
        "filesystem-vulnerability-db; "
        f"empty-ignore-policy-sha256={ignore_policy_before}; "
        "target-suppressions=disabled; "
        f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
    )
    if database_after is not None and executable_before is not None:
        database_digest = _canonical_json_sha256(
            database_after.model_dump(mode="json")
        )
        results.scanner_configs["trivy"] = (
            "filesystem-vulnerability-db; "
            f"empty-ignore-policy-sha256={ignore_policy_before}; "
            "target-suppressions=disabled; "
            f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}; "
            f"metadata-sha256={database_digest}; "
            f"executable-sha256={executable_before}"
        )
    results.scanner_status["trivy"] = status
    if (
        not executable_stable
        or ignore_policy_after != ignore_policy_before
        or version_after != SCANNER_REQUIRED_VERSIONS["trivy"]
        or database_after != database_before
    ):
        results.scanner_status["trivy"] = "error"
        return
    if proc is None or status != "ok" or proc.returncode != 0:
        if proc is not None and status == "ok":
            results.scanner_status["trivy"] = "error"
        return
    try:
        data = json.loads(proc.stdout)
        reports = data.get("Results") if isinstance(data, dict) else None
        if reports is None:
            reports = []
        if not isinstance(reports, list) or not all(
            isinstance(report, dict)
            and (
                report.get("Vulnerabilities") is None
                or isinstance(report.get("Vulnerabilities"), list)
            )
            for report in reports
        ):
            raise ValueError("invalid Trivy report shape")
        if staged_workspace is None:
            raise ValueError("missing Trivy staging identity")
        for report in reports:
            normalized_target = _normalize_staged_report_path(
                report.get("Target"),
                staged_workspace,
                renamed_controls=renamed_controls,
            )
            if normalized_target is None:
                raise ValueError("invalid Trivy report target")
            report["Target"] = normalized_target
        data["Results"] = reports
        if not _write_json_artifact(scans_dir / "trivy.json", data):
            results.scanner_status["trivy"] = "truncated"
            return
        results.vulns = sum(
            len(report.get("Vulnerabilities") or []) for report in reports
        )
    except ValueError:
        results.scanner_status["trivy"] = "error"
