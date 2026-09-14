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
    from .. import limits, paths
    from ..experiments import journal, service
    from ..workbench import api, store

    return digest(
        {
            "python": platform.python_version(),
            "experiment_evaluator": service.evaluator_identity(),
            "storage": {
                module.__name__: hashlib.sha256(
                    Path(module.__file__).read_bytes()
                ).hexdigest()
                for module in (journal, store, paths, limits, api)
            },
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
    if len(entries) > 2001:
        raise ValueError("too many source files")
    files = {}
    total = 0
    for entry in entries:
        if not entry:
            continue
        meta, name = entry.split(b"\t", 1)
        mode, kind, sha = meta.decode().split()
        name = safe_path(name.decode())
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("unsupported Git entry")
        total += int(git(repository, "cat-file", "-s", sha))
        if total > 8 * 1024 * 1024:
            raise ValueError("source snapshot exceeds size limit")
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
        assessment = store.get(project, "assessment-v2", trial.parent_execution_id)
        if assessment["outcome"] not in ("fail", "inconclusive"):
            raise ValueError("repair requires a completed unsuccessful assessment")
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
        count = 1
        ancestor = parent
        seen = {contract.execution_id}
        while True:
            if ancestor.execution_id in seen:
                raise ValueError("repair ancestry cycle")
            seen.add(ancestor.execution_id)
            previous = ancestor.trial_identity.parent_execution_id
            if previous is None:
                break
            count += 1
            ancestor = ExecutionContract.model_validate(
                store.get(project, "execution-v2", previous)
            )
        original_recipe = Recipe.model_validate(
            store.get(project, "candidate-recipe", ancestor.recipe_sha256)
        )
        allowed_repairs = min(
            recipe.budget.max_repairs, original_recipe.budget.max_repairs
        )
        try:
            study = store.get(project, "candidate-study", trial.cohort_id)
        except KeyError:
            pass
        else:
            # Study-assisted executions have a separate, predeclared budget and selection.
            # A producer's internal repair allowance can remain zero for first-candidate trials.
            allowed_repairs = int(study["max_assisted_executions"] > 0)
        if count > allowed_repairs:
            raise ValueError("repair limit exhausted")
        if parent.policy_sha256 != contract.policy_sha256:
            raise ValueError("repair cannot change the acceptance policy")
    with store.db() as db:
        if trial.parent_execution_id:
            reserve_repair_budget(store, project, contract, recipe, db)
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


def reserve_repair_budget(store, project, ticket, recipe, db):
    from ..blackbox.models import parse_json

    cohort = ticket.trial_identity.cohort_id
    try:
        plan = store.get(project, "candidate-study", cohort, db=db)
    except KeyError:
        return
    schedule = store.get(project, "candidate-schedule", cohort, db=db)["executions"]
    eligible = []
    for key in schedule:
        try:
            assessment = store.get(project, "assessment-v2", key, db=db)
        except KeyError:
            try:
                store.get(project, "production-failure-v2", key, db=db)
            except KeyError:
                raise ValueError(
                    "complete the initial cohort before assisted correction"
                ) from None
        else:
            if assessment["outcome"] in ("fail", "inconclusive"):
                eligible.append(key)
    if (
        ticket.trial_identity.parent_execution_id
        not in eligible[: plan["max_assisted_executions"]]
    ):
        raise ValueError("repair is outside predeclared failure selection")
    reserved = [
        parse_json(row[0])
        for row in db.execute(
            "SELECT body FROM records WHERE project=? AND kind='trial-ticket-v2'",
            (project,),
        )
    ]
    repairs = [
        r
        for r in reserved
        if r["trial_identity"]["cohort_id"] == cohort
        and r["trial_identity"]["attempt_kind"] == "assisted_correction"
        and r["execution_id"] != ticket.execution_id
    ]
    budgets = [
        Recipe.model_validate(
            store.get(project, "candidate-recipe", r["recipe_sha256"], db=db)
        ).budget
        for r in repairs
    ] + [recipe.budget]
    if (
        len(budgets) > plan["max_assisted_executions"]
        or sum(b.max_model_requests for b in budgets)
        > plan["max_assisted_model_requests"]
        or sum(b.max_total_tokens for b in budgets) > plan["max_assisted_total_tokens"]
    ):
        raise ValueError("assisted cohort budget exhausted")


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
    with store.db() as db:
        try:
            store.get(project, "production-failure-v2", contract.execution_id, db=db)
        except KeyError:
            pass
        else:
            raise ValueError("production failure already sealed for this ticket")
        store.put(
            project,
            "execution-v2",
            contract.model_dump(mode="json"),
            object_id=contract.execution_id,
            actor=actor,
            db=db,
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


def record_failure(store, project, failure, actor):
    from .contracts import ProductionFailure

    failure = ProductionFailure.model_validate(failure)
    if failure.usage.provenance == "independently_observed":
        raise ValueError("producer cannot claim independently observed usage")
    with store.db() as db:
        ticket = store.get(project, "trial-ticket-v2", failure.execution_id, db=db)
        if digest(ticket) != failure.trial_ticket_sha256:
            raise ValueError("failure differs from reserved ticket")
        try:
            store.get(project, "execution-v2", failure.execution_id, db=db)
        except KeyError:
            pass
        else:
            raise ValueError("candidate already bound; submit its actual outcome")
        return store.put(
            project,
            "production-failure-v2",
            failure.model_dump(mode="json"),
            object_id=failure.execution_id,
            actor=actor,
            db=db,
        )
