"""Portable configuration and hardened local-state filesystem helpers."""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

STATE_DIR_ENV = "AGENT_EVAL_STATE_DIR"
TASKS_DIR_ENV = "AGENT_EVAL_TASKS_DIR"
BUNDLED_TASKS_DIR = Path(__file__).resolve().parents[2] / "tasks"


class UnsafeStatePathError(ValueError):
    """A state path is a symlink, special file, or outside its expected root."""


def _configured_directory(variable: str) -> Path | None:
    raw = os.environ.get(variable)
    if raw is None:
        return None
    if not raw.strip():
        raise ValueError(f"{variable} must not be empty")
    # Preserve the lexical path so later no-follow validation can detect a
    # configured symlink instead of silently accepting its resolved target.
    return Path(os.path.abspath(Path(raw).expanduser()))


def get_state_dir() -> Path:
    """Return the configured or OS-native application state directory."""

    configured = _configured_directory(STATE_DIR_ENV)
    if configured is not None:
        return configured

    home = Path.home()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support"
    elif os.name == "nt" or sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = (
            Path(local_app_data).expanduser()
            if local_app_data and local_app_data.strip()
            else home / "AppData" / "Local"
        )
    else:
        xdg_state_home = os.environ.get("XDG_STATE_HOME")
        base = (
            Path(xdg_state_home).expanduser()
            if xdg_state_home and xdg_state_home.strip()
            else home / ".local" / "state"
        )
    return Path(os.path.abspath(base / "agent-eval"))


def task_search_paths() -> tuple[Path, ...]:
    """Return configured tasks first, followed by source-checkout tasks."""

    configured = _configured_directory(TASKS_DIR_ENV)
    candidates = (
        (configured, BUNDLED_TASKS_DIR)
        if configured is not None
        else (BUNDLED_TASKS_DIR,)
    )
    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.abspath(candidate))
        if normalized not in seen:
            seen.add(normalized)
            result.append(candidate)
    return tuple(result)


def _metadata(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _macos_acl_entries(path: Path) -> tuple[str, ...]:
    if sys.platform != "darwin":
        return ()
    process = subprocess.run(
        ["/bin/ls", "-lde", os.fspath(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if process.returncode != 0 or not process.stdout:
        raise UnsafeStatePathError(f"private path ACL could not be inspected: {path}")
    entries: list[str] = []
    for line in process.stdout.splitlines()[1:]:
        index, separator, _entry = line.lstrip().partition(":")
        if separator and index.isdigit():
            entries.append(_entry.strip())
    return tuple(entries)


def _macos_has_extended_acl(path: Path) -> bool:
    return bool(_macos_acl_entries(path))


def _macos_has_allow_acl(path: Path) -> bool:
    return any(" allow " in f" {entry} " for entry in _macos_acl_entries(path))


def _strip_private_acl(path: Path) -> None:
    if sys.platform != "darwin" or not _macos_has_extended_acl(path):
        return
    process = subprocess.run(
        ["/bin/chmod", "-N", os.fspath(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if process.returncode != 0 or _macos_has_extended_acl(path):
        raise UnsafeStatePathError(
            f"private path extended ACL could not be removed: {path}"
        )


def validate_no_symlink_components(path: Path | str) -> Path:
    """Reject every existing symlink component in an absolute path."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        metadata = _metadata(current)
        if metadata is None:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise UnsafeStatePathError(
                "private path must not be a symlink or contain a symlink "
                f"component: {current}"
            )
    return absolute


def _validate_existing_ancestor_permissions(path: Path) -> None:
    """Reject replaceable ancestors while allowing sticky system temp roots."""

    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        metadata = _metadata(current)
        if metadata is None:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise UnsafeStatePathError(
                f"private path ancestor must be a directory: {current}"
            )
        if _macos_has_allow_acl(current):
            raise UnsafeStatePathError(
                f"private path ancestor has an extended allow ACL: {current}"
            )
        writable_by_others = metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        get_effective_uid = getattr(os, "geteuid", None)
        effective_uid = get_effective_uid() if get_effective_uid is not None else None
        trusted_sticky_owner = (
            bool(metadata.st_mode & stat.S_ISVTX)
            and effective_uid is not None
            and metadata.st_uid in {0, effective_uid}
        )
        if writable_by_others and not trusted_sticky_owner:
            raise UnsafeStatePathError(
                f"private path has a replaceable writable ancestor: {current}"
            )


def _validate_private_directory_metadata(
    directory: Path, metadata: os.stat_result
) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeStatePathError(
            f"state directory must be a non-symlink directory: {directory}"
        )
    get_effective_uid = getattr(os, "geteuid", None)
    if get_effective_uid is not None and metadata.st_uid != get_effective_uid():
        raise UnsafeStatePathError(
            f"state directory must be owned by the current user: {directory}"
        )


def _create_private_directory_chain(directory: Path) -> None:
    missing: list[Path] = []
    candidate = directory
    while _metadata(candidate) is None:
        missing.append(candidate)
        if candidate == candidate.parent:
            break
        candidate = candidate.parent
    for target in reversed(missing):
        try:
            target.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise UnsafeStatePathError(
                f"private directory creation raced with another writer: {target}"
            ) from exc
        metadata = target.lstat()
        _validate_private_directory_metadata(target, metadata)
        os.chmod(target, 0o700, follow_symlinks=False)
        _strip_private_acl(target)


def ensure_private_directory(
    path: Path | str,
    *,
    create: bool = True,
    parents: bool = False,
    exist_ok: bool = True,
) -> Path:
    """Create or validate a real owner-only directory without following it."""

    directory = Path(os.path.abspath(path))
    validate_no_symlink_components(directory)
    _validate_existing_ancestor_permissions(directory)
    metadata = _metadata(directory)
    if metadata is not None:
        _validate_private_directory_metadata(directory, metadata)
        if not exist_ok:
            raise FileExistsError(directory)
    elif not create:
        raise FileNotFoundError(directory)
    else:
        if parents:
            _create_private_directory_chain(directory)
        else:
            directory.mkdir(mode=0o700, exist_ok=False)
        metadata = directory.lstat()
        _validate_private_directory_metadata(directory, metadata)

    validate_no_symlink_components(directory)
    if stat.S_IMODE(directory.lstat().st_mode) != 0o700:
        os.chmod(directory, 0o700, follow_symlinks=False)
    _strip_private_acl(directory)
    return directory


def ensure_run_directory(
    state_root: Path | str,
    run_directory: Path | str,
    *,
    exist_ok: bool,
) -> Path:
    """Create one direct child run directory beneath a non-symlink state root."""

    root = ensure_private_directory(state_root, parents=True)
    run_dir = Path(run_directory)
    if Path(os.path.abspath(run_dir)).parent != Path(os.path.abspath(root)):
        raise UnsafeStatePathError(
            f"run directory must be a direct child of the state root: {run_dir}"
        )
    return ensure_private_directory(run_dir, exist_ok=exist_ok)


def _secure_tree(directory: Path) -> None:
    with os.scandir(directory) as entries:
        for entry in entries:
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise UnsafeStatePathError(
                    f"run state must not contain symlinks: {path}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o700:
                    os.chmod(path, 0o700)
                _strip_private_acl(path)
                _secure_tree(path)
            elif stat.S_ISREG(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o600:
                    os.chmod(path, 0o600)
                _strip_private_acl(path)
            else:
                raise UnsafeStatePathError(
                    f"run state must contain only directories and regular files: {path}"
                )


def secure_run_tree(run_directory: Path | str) -> None:
    """Reject links and special files, then normalize private permissions."""

    run_dir = ensure_private_directory(run_directory, create=False)
    _secure_tree(run_dir)


def ensure_private_file(path: Path | str, *, create: bool = True) -> Path:
    """Create or validate an owner-only regular file without following links."""

    target = Path(path)
    validate_no_symlink_components(target.parent)
    metadata = _metadata(target)
    if metadata is not None:
        if stat.S_ISLNK(metadata.st_mode):
            raise UnsafeStatePathError(f"state file must not be a symlink: {target}")
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafeStatePathError(f"state file must be a regular file: {target}")
    elif not create:
        raise FileNotFoundError(target)

    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        raise UnsafeStatePathError(
            f"could not open state file safely: {target}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeStatePathError(f"state file must be a regular file: {target}")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    _strip_private_acl(target)
    return target


def ensure_private_sqlite_sidecar(path: Path | str) -> None:
    """Validate an optional SQLite file that another connection may unlink."""
    target = Path(path)
    validate_no_symlink_components(target.parent)
    try:
        ensure_private_file(target, create=False)
    except FileNotFoundError:
        pass
    except UnsafeStatePathError:
        # SQLite removes rollback journals on commit. A file that still exists,
        # including a dangling symlink, must continue to fail closed.
        if _metadata(target) is not None:
            raise


def atomic_write_private(path: Path | str, data: bytes) -> None:
    """Durably replace a regular state file with owner-only permissions."""

    if not isinstance(data, bytes):
        raise TypeError("atomic state writes require bytes")
    destination = Path(path)
    validate_no_symlink_components(destination.parent)
    ensure_private_directory(destination.parent, create=False)
    existing = _metadata(destination)
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
    ):
        raise UnsafeStatePathError(
            f"state file must be a non-symlink regular file: {destination}"
        )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _strip_private_acl(temporary)
        os.replace(temporary, destination)
        # The published inode already has private mode and no ACL. Touching its
        # metadata after rename races readers verifying the immutable evidence.
        try:
            directory_descriptor = os.open(destination.parent, os.O_RDONLY)
        except OSError:
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise
