"""Snapshot selected repository text without importing or executing agent code."""

from __future__ import annotations

import hashlib
import os
from fnmatch import fnmatchcase
from functools import cache
from pathlib import Path, PurePosixPath

from ..limits import read_stable_bounded_file
from ..paths import validate_no_symlink_components
from .inspection_models import SourceFile, SourceSelection, SourceSnapshot
from .models import digest

MAX_SOURCE_BYTES = 512 * 1024
MAX_SOURCE_FILES = 100
MAX_SOURCE_ENTRIES = 20_000
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".ssh",
    ".aws",
    ".codex",
}
EXCLUDED_FILES = {
    ".env",
    "credentials",
    "credentials.json",
    "auth.json",
    "id_rsa",
    "id_ed25519",
}


def _matches(path: str, pattern: str) -> bool:
    # PurePath.match treats ** like a single directory on Python 3.12. Match
    # root-relative components explicitly so ** includes zero or more levels.
    parts = PurePosixPath(path).parts
    patterns = PurePosixPath(pattern).parts

    @cache
    def match(path_index: int, pattern_index: int) -> bool:
        if pattern_index == len(patterns):
            return path_index == len(parts)
        current = patterns[pattern_index]
        if current == "**":
            return match(path_index, pattern_index + 1) or (
                path_index < len(parts) and match(path_index + 1, pattern_index)
            )
        return (
            path_index < len(parts)
            and fnmatchcase(parts[path_index], current)
            and match(path_index + 1, pattern_index + 1)
        )

    return match(0, 0)


def collect_source(root: Path, selection: SourceSelection) -> SourceSnapshot:
    root = validate_no_symlink_components(root)
    if not root.is_dir():
        raise ValueError("source root must be a directory")
    files = []
    consumed = 0
    entries = 0

    def on_error(_error):
        raise ValueError("source tree could not be enumerated")

    for directory, directories, names in os.walk(
        root, followlinks=False, onerror=on_error
    ):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() not in EXCLUDED_DIRS
            and not (Path(directory) / name).is_symlink()
        )
        entries += len(directories) + len(names)
        if entries > MAX_SOURCE_ENTRIES:
            raise ValueError("source tree exceeds the enumeration limit")
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if (
                name.casefold() in EXCLUDED_FILES
                or name.casefold().startswith(".env.")
                or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}
                or any(_matches(relative, pattern) for pattern in selection.exclude)
                or not any(_matches(relative, pattern) for pattern in selection.include)
            ):
                continue
            if len(files) >= MAX_SOURCE_FILES:
                raise ValueError("source selection exceeds the file limit")
            validate_no_symlink_components(path)
            raw = read_stable_bounded_file(
                path, maximum_bytes=MAX_SOURCE_BYTES - consumed
            )
            consumed += len(raw)
            content = raw.decode("utf-8")
            if "\x00" in content:
                raise ValueError("source selection contains binary content")
            files.append(
                SourceFile(
                    path=relative,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    content=content,
                )
            )
    if not files:
        raise ValueError("source selection matched no readable files")
    files.sort(key=lambda file: file.path)
    return SourceSnapshot(
        files=files,
        sha256=digest([{"path": file.path, "sha256": file.sha256} for file in files]),
    )
