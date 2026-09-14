"""Idle-state backup, bounded restore, and explicit experiment retention."""

from __future__ import annotations

import hashlib
import shutil
import zipfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

from ..blackbox.models import json_bytes, parse_json
from ..experiments.journal import Journal, JournalError, directory
from ..paths import (
    atomic_write_private,
    ensure_private_directory,
    ensure_private_file,
    get_state_dir,
    secure_run_tree,
    validate_no_symlink_components,
)

MAX_BACKUP = 1024 * 1024 * 1024


def backup(store, destination: Path):
    root = ensure_private_directory(get_state_dir(), create=False)
    if (
        destination.exists()
        or destination.is_symlink()
        or destination.absolute().is_relative_to(root)
    ):
        raise ValueError("backup must be a new file outside state")
    ensure_private_directory(destination.parent, create=False)
    manifest = {}
    with ExitStack() as stack:
        stack.enter_context(store.db())
        experiments = root / "experiments"
        if experiments.exists():
            for item in sorted(experiments.iterdir()):
                journal = stack.enter_context(Journal.open(item.name, write=True))
                journal.status()
        secure_run_tree(root)
        files = [
            p
            for p in root.rglob("*")
            if p.is_file() and not p.name.endswith(("-journal", "-wal", "-shm"))
        ]
        if sum(p.stat().st_size for p in files) > MAX_BACKUP:
            raise ValueError("backup exceeds size limit")
        ensure_private_file(destination)
        try:
            with zipfile.ZipFile(
                destination, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for path in files:
                    data = path.read_bytes()
                    name = path.relative_to(root).as_posix()
                    manifest[name] = {
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data),
                    }
                    archive.writestr(name, data)
                archive.writestr(
                    "backup-manifest.json",
                    json_bytes({"schema_version": 1, "files": manifest}),
                )
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    return {
        "files": len(files),
        "manifest_sha256": hashlib.sha256(json_bytes(manifest)).hexdigest(),
    }


def restore(source: Path, destination: Path):
    validate_no_symlink_components(source)
    if destination.exists() or destination.is_symlink():
        raise ValueError("restore requires a new empty destination")
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        if (
            len(names) > 100000
            or len(names) != len(set(names))
            or sum(i.file_size for i in infos) > MAX_BACKUP
        ):
            raise ValueError("invalid archive bounds")
        for item in infos:
            path = PurePosixPath(item.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in item.filename
                or str(path) != item.filename
                or item.is_dir()
            ):
                raise ValueError("unsafe archive path")
        manifest = parse_json(archive.read("backup-manifest.json"))
        if manifest.get("schema_version") != 1 or set(names) != set(
            manifest["files"]
        ) | {"backup-manifest.json"}:
            raise ValueError("invalid backup manifest")
        for name, expected in manifest["files"].items():
            data = archive.read(name)
            if (
                len(data) != expected["bytes"]
                or hashlib.sha256(data).hexdigest() != expected["sha256"]
            ):
                raise JournalError("backup digest mismatch")
        ensure_private_directory(destination, parents=True, exist_ok=False)
        for name in manifest["files"]:
            target = destination / name
            ensure_private_directory(target.parent, parents=True)
            atomic_write_private(target, archive.read(name))
    return {"files": len(manifest["files"]), "destination": str(destination)}


def expire(store, project, experiment, *, actor, reason, execute=False):
    store.get(project, "experiment", experiment)
    if not reason.strip():
        raise ValueError("retention reason required")
    root = directory(experiment)
    if not root.exists():
        store.get(project, "tombstone", experiment)
        return {"deleted": True, "experiment": experiment}
    with Journal.open(experiment, write=True) as journal:
        if any(
            row["state"] in ("running", "reconciliation_required")
            for row in journal.rows()
        ):
            raise JournalError("unconfirmed work prevents retention deletion")
        files = list(root.rglob("*"))
        secure_run_tree(root)
        result = {
            "experiment": experiment,
            "files": sum(p.is_file() for p in files),
            "deleted": False,
        }
        if not execute:
            return result
        store.put(
            project,
            "tombstone",
            {"experiment": experiment, "actor": actor, "reason": reason},
            actor=actor,
            object_id=experiment,
        )
        with store.db() as db:
            db.execute(
                "DELETE FROM annotations WHERE project=? AND experiment=?",
                (project, experiment),
            )
            db.execute(
                "DELETE FROM records WHERE project=? AND kind='inspection' AND id=?",
                (project, experiment),
            )
            for row in db.execute(
                "SELECT kind,id,body FROM records WHERE project=? AND kind IN ('assessment-set','external-report')",
                (project,),
            ).fetchall():
                value = parse_json(row["body"])
                original = value.get("original", {})
                if (
                    value.get("experiment") == experiment
                    or original.get("run_id") == experiment
                    or original.get("parent_run_id") == experiment
                ):
                    db.execute(
                        "DELETE FROM records WHERE project=? AND kind=? AND id=?",
                        (project, row["kind"], row["id"]),
                    )
            store.audit(
                db, project, actor, "retention:purge-derived-content", experiment
            )
        # Keep the locked inode alive during deletion. This is an idle, explicitly
        # selected experiment; keys and observations are removed together.
        shutil.rmtree(root)
        result["deleted"] = True
        return result
