"""Shared resource ceilings and readers for untrusted evaluation evidence."""

from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_RESULTS_JSON_BYTES = 16 * 1024 * 1024


def _file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_stable_bounded_file(
    path: Path | str,
    *,
    maximum_bytes: int,
) -> bytes:
    """Read one no-follow regular file from a single stable inode."""

    if maximum_bytes < 0:
        raise ValueError("maximum_bytes must be nonnegative")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input must be a regular file")
        if before.st_size > maximum_bytes:
            raise ValueError("input exceeds the safe byte limit")
        output = bytearray()
        chunk_size = min(1024 * 1024, maximum_bytes + 1)
        while chunk := os.read(descriptor, chunk_size):
            output.extend(chunk)
            if len(output) > maximum_bytes:
                raise ValueError("input exceeds the safe byte limit")
        after = os.fstat(descriptor)
        if (
            _file_identity(before) != _file_identity(after)
            or len(output) != after.st_size
        ):
            raise ValueError("input changed while it was being read")
        return bytes(output)
    finally:
        os.close(descriptor)
