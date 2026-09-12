"""Operator-issued identities and runner-only artifact intake."""

from __future__ import annotations

import base64
import hashlib
import os
import platform
import stat
import subprocess
import tempfile
from pathlib import Path

from pydantic import TypeAdapter

from ..blackbox.models import digest, json_bytes
from ..experiments.journal import immutable_json, read_json
from ..experiments.models import Sha256
from ..limits import read_stable_bounded_file
from ..paths import atomic_write_private, ensure_private_directory, get_state_dir
from .contracts import (
    AcceptancePolicy,
    ArtifactEnvelope,
    CandidateManifest,
    ExecutionContract,
    Recipe,
    Submission,
    TrialTicket,
    safe_path,
)


def identity():
    root = Path(__file__).parent
    return digest(
        {
            "python": platform.python_version(),
            "files": {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(root.glob("*.py"))
            },
        }
    )


def artifact_root(project):
    return ensure_private_directory(
        get_state_dir() / "producer-artifacts" / digest(project), parents=True
    )


def upload(store, project, envelope: ArtifactEnvelope, actor):
    value = envelope.model_dump(mode="json")
    key = digest(value)
    immutable_json(artifact_root(project) / (key + ".json"), value)
    store.put(
        project,
        "producer-blob",
        {"storage_key": key},
        object_id=envelope.content_sha256,
        actor=actor,
    )
    return {"storage_key": key, "sha256": envelope.content_sha256}


def read_artifact(store, project, raw_sha, key=None):
    TypeAdapter(Sha256).validate_python(raw_sha)
    registered = store.get(project, "producer-blob", raw_sha)["storage_key"]
    if key is not None and key != registered:
        raise ValueError("artifact key mismatch")
    value = read_json(artifact_root(project) / (registered + ".json"))
    if digest(value) != registered:
        raise ValueError("artifact envelope mismatch")
    envelope = ArtifactEnvelope.model_validate(value)
    if envelope.content_sha256 != raw_sha:
        raise ValueError("artifact content mismatch")
    return envelope.content()


def git(root, *args, data=None):
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=root,
        input=data,
        capture_output=True,
        timeout=30,
        check=True,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        },
    ).stdout


def git_snapshot(repository: Path, revision: str):
    # Require an actual commit object; tree objects and invented identifiers fail here.
    resolved = (
        git(repository, "rev-parse", "--verify", revision + "^{commit}")
        .decode()
        .strip()
    )
    if revision != resolved:
        raise ValueError("an exact Git commit is required")
    entries = git(repository, "ls-tree", "-rz", "--full-tree", resolved).split(b"\0")
    files = {}
    for entry in entries:
        if not entry:
            continue
        meta, name = entry.split(b"\t", 1)
        mode, kind, sha = meta.decode().split()
        name = safe_path(name.decode())
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("unsupported Git entry")
        content = git(repository, "cat-file", "blob", sha)
        files[name] = {
            "mode": int(mode, 8) & 0o777,
            "data": base64.b64encode(content).decode(),
        }
    # Reuse the same path, size, mode and canonical tree validation as intake.
    CandidateManifest(
        base_revision=resolved,
        tree_sha256=digest(files),
        files=files,
        changed_paths=[],
        patch_sha256=hashlib.sha256(b"").hexdigest(),
    )
    return files


def register_revision(store, project, repository: Path, revision: str, actor="local"):
    files = git_snapshot(repository, revision)
    envelope = ArtifactEnvelope.wrap(json_bytes(files))
    upload(store, project, envelope, actor)
    store.put(
        project,
        "verified-revision",
        {"tree_sha256": digest(files), "files_sha256": envelope.content_sha256},
        object_id=revision,
        actor=actor,
    )
    return revision


def materialize(root: Path, files):
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, file in files.items():
        safe_path(name)
        path = root / name
        atomic_write_private(path, base64.b64decode(file["data"], validate=True))
        path.chmod(file["mode"])


def verify_patch(base, candidate, patch):
    """Apply the producer patch to independently captured base bytes, then compare trees."""
    with tempfile.TemporaryDirectory(prefix="candidate-patch-") as temporary:
        root = Path(temporary).resolve() / "tree"
        materialize(root, base)
        git(root, "init", "-q", "--template=")
        git(root, "add", "-f", "--all")
        if patch:
            git(
                root,
                "apply",
                "--index",
                "--binary",
                "--whitespace=nowarn",
                "-",
                data=patch,
            )
        actual = {}
        for raw in git(root, "ls-files", "-z").split(b"\0"):
            if not raw:
                continue
            name = safe_path(raw.decode())
            path = root / name
            meta = path.lstat()
            if not stat.S_ISREG(meta.st_mode):
                raise ValueError("patch introduced a nonregular file")
            content = read_stable_bounded_file(path, maximum_bytes=8 * 1024 * 1024)
            actual[name] = {
                "data": base64.b64encode(content).decode(),
                "mode": 493 if meta.st_mode & 0o111 else 420,
            }
        if actual != candidate:
            raise ValueError("patch does not reconstruct the candidate tree")


def manifest_for(store, project, candidate):
    manifest = CandidateManifest.from_bytes(
        read_artifact(store, project, candidate.candidate_manifest_sha256)
    )
    if (
        manifest.base_revision != candidate.base_revision
        or manifest.tree_sha256 != candidate.candidate_tree_sha256
    ):
        raise ValueError("candidate identity mismatch")
    base_record = store.get(project, "verified-revision", candidate.base_revision)
    from ..blackbox.models import parse_json

    base = parse_json(read_artifact(store, project, base_record["files_sha256"]))
    if digest(base) != base_record["tree_sha256"]:
        raise ValueError("base snapshot mismatch")
    files = {k: v.model_dump() for k, v in manifest.files.items()}
    changed = sorted(k for k in set(base) | set(files) if base.get(k) != files.get(k))
    if changed != sorted(manifest.changed_paths):
        raise ValueError("declared changed paths differ from the base")
    if candidate.candidate_revision is not None:
        revision = store.get(project, "verified-revision", candidate.candidate_revision)
        if revision["tree_sha256"] != manifest.tree_sha256:
            raise ValueError("candidate commit differs from submitted tree")
    verify_patch(base, files, read_artifact(store, project, manifest.patch_sha256))
    return manifest


def reserve(store, project, contract: TrialTicket, actor):
    if contract.evaluator_sha256 != identity():
        raise ValueError("evaluator identity changed")
    store.get(project, "verified-revision", contract.base_revision)
    recipe = Recipe.model_validate(
        store.get(project, "candidate-recipe", contract.recipe_sha256)
    )
    policy = AcceptancePolicy.model_validate(
        store.get(project, "candidate-policy", contract.policy_sha256)
    )
    from .oracles import BehaviorSuite

    suite = BehaviorSuite.model_validate(
        store.get(project, "candidate-suite", contract.suite_sha256)
    )
    trial = contract.trial_identity
    if (trial.task_id, trial.family, trial.split) != (
        suite.task_id,
        suite.family,
        suite.split,
    ):
        raise ValueError("trial differs from registered task family/split")
    if set(policy.required_checks) != {c.id for c in suite.checks}:
        raise ValueError("policy must include every independent behavioral check")
    if trial.parent_execution_id:
        parent = ExecutionContract.model_validate(
            store.get(project, "execution-v2", trial.parent_execution_id)
        )
        p = parent.trial_identity.model_dump()
        t = trial.model_dump()
        for name in ("attempt_kind", "parent_execution_id"):
            p.pop(name)
            t.pop(name)
        if (
            p != t
            or parent.suite_sha256 != contract.suite_sha256
            or parent.base_revision != contract.base_revision
        ):
            raise ValueError("repair parent identity mismatch")
        if not recipe.budget.max_repairs:
            raise ValueError("recipe does not permit repair")
    with store.db() as db:
        # A task family cannot be silently moved between splits within a project.
        store.put(
            project,
            "candidate-family-split",
            {"split": trial.split},
            object_id=digest(trial.family),
            db=db,
            actor=actor,
        )
        store.put(
            project,
            "reserved-trial",
            {"execution_id": contract.execution_id},
            object_id=digest(contract.trial_identity.model_dump(mode="json")),
            db=db,
            actor=actor,
        )
        store.put(
            project,
            "trial-ticket-v2",
            contract.model_dump(mode="json"),
            object_id=contract.execution_id,
            db=db,
            actor=actor,
        )
    return {
        "trial_ticket": contract.model_dump(mode="json"),
        "trial_ticket_sha256": digest(contract.model_dump(mode="json")),
    }


def issue(store, project, contract: ExecutionContract, actor):
    ticket = TrialTicket.model_validate(
        store.get(project, "trial-ticket-v2", contract.execution_id)
    )
    if contract.trial_ticket_sha256 != digest(ticket.model_dump(mode="json")):
        raise ValueError("stale trial ticket")
    for field in (
        "base_revision",
        "trial_identity",
        "recipe_sha256",
        "suite_sha256",
        "policy_sha256",
        "evaluator_sha256",
    ):
        if getattr(contract, field) != getattr(ticket, field):
            raise ValueError("execution differs from reserved trial")
    if contract.evaluator_sha256 != identity():
        raise ValueError("evaluator identity changed")
    manifest_for(store, project, contract)
    store.put(
        project,
        "execution-v2",
        contract.model_dump(mode="json"),
        object_id=contract.execution_id,
        actor=actor,
    )
    return {
        "execution_contract": contract.model_dump(mode="json"),
        "execution_contract_sha256": digest(contract.model_dump(mode="json")),
    }


def ingest(store, project, submission: Submission, actor):
    if submission.usage.provenance == "independently_observed":
        raise ValueError("producer cannot claim independently observed usage")
    contract = ExecutionContract.model_validate(
        store.get(project, "execution-v2", submission.execution_id)
    )
    if digest(contract.model_dump(mode="json")) != submission.execution_contract_sha256:
        raise ValueError("stale execution contract")
    for field in (
        "trial_ticket_sha256",
        "base_revision",
        "candidate_revision",
        "candidate_tree_sha256",
        "candidate_manifest_sha256",
        "recipe_sha256",
        "suite_sha256",
        "policy_sha256",
        "evaluator_sha256",
    ):
        if getattr(submission, field) != getattr(contract, field):
            raise ValueError("submission differs from issued execution identity")
    if contract.evaluator_sha256 != identity():
        raise ValueError("evaluator identity changed")
    manifest = manifest_for(store, project, submission)
    keys = set()
    roles = {}
    for ref in submission.artifacts:
        if ref.storage_key in keys or ref.role in roles:
            raise ValueError("duplicate submission artifact or role")
        keys.add(ref.storage_key)
        roles[ref.role] = ref.sha256
        read_artifact(store, project, ref.sha256, ref.storage_key)
    if (
        roles.get("candidate") != submission.candidate_manifest_sha256
        or roles.get("patch") != manifest.patch_sha256
    ):
        raise ValueError("candidate and patch artifact roles must bind submitted bytes")
    value = submission.model_dump(mode="json")
    store.put(
        project, "submission-v2", value, object_id=submission.execution_id, actor=actor
    )
    return {
        "execution_id": submission.execution_id,
        "submission_sha256": digest(value),
        "status": "awaiting_independent_evaluation",
    }
