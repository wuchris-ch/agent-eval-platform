#!/usr/bin/env python3
"""Standalone candidate/v1 exporter. Uses only Python and Git, no evaluator imports."""

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def export(repository, replacement, destination):
    def git(root, *args):
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=root,
            stderr=subprocess.DEVNULL,
        )

    base = git(repository, "rev-parse", "HEAD").decode().strip()
    with tempfile.TemporaryDirectory(prefix="candidate-export-") as temporary:
        workspace = Path(temporary) / "candidate"
        subprocess.run(
            ["git", "clone", "-q", "--no-hardlinks", str(repository), str(workspace)],
            check=True,
        )
        if replacement is not None:
            (workspace / "server.py").write_bytes(Path(replacement).read_bytes())
        files = {}
        for raw in git(workspace, "ls-files", "-z").split(b"\0"):
            if raw:
                name = raw.decode()
                path = workspace / name
                files[name] = {
                    "data": base64.b64encode(path.read_bytes()).decode(),
                    "mode": 493 if path.stat().st_mode & 0o111 else 420,
                }
        patch = git(workspace, "diff", "--binary", "--no-ext-diff", "--no-textconv")
        manifest = {
            "schema_version": "candidate/v1",
            "base_revision": base,
            "tree_sha256": sha(canonical(files)),
            "files": files,
            "changed_paths": sorted(
                git(workspace, "diff", "--name-only").decode().splitlines()
            ),
            "patch_sha256": sha(patch),
        }
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "candidate.json").write_bytes(canonical(manifest))
        (destination / "candidate.patch").write_bytes(patch)
        return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--replacement", type=Path)
    args = parser.parse_args()
    export(args.repository, args.replacement, args.destination)
