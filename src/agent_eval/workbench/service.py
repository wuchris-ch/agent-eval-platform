"""Workbench workflows, all backed by immutable experiment records."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

from ..blackbox.models import Case, Metric, Suite, digest
from ..experiments.executor import execute
from ..experiments.journal import Journal, JournalError, immutable_json, read_json
from ..experiments.models import CommandSpec
from ..experiments.service import create_experiment
from ..environments.world import World, assess
from .analysis import Policy, compare, decide
from .datasets import Dataset, register_dataset
from .models import Launch, TargetProfile
from .store import Conflict


def preview(store, project, launch: Launch):
    if launch.parent_experiment:
        store.get(project, "experiment", launch.parent_experiment)
    profile = TargetProfile.model_validate(store.get(project, "target", launch.target))
    dataset = Dataset.model_validate(store.get(project, "dataset", launch.dataset))
    if dataset.split == "held_out":
        raise ValueError("held-out packs require a protected remote evaluator")
    count = launch.trials * len(dataset.suite.cases)
    if count > profile.max_invocations:
        raise ValueError("profile invocation limit exceeded")
    return {
        "agent": profile.name,
        "dataset": dataset.suite.id,
        "split": dataset.split,
        "invocations": count,
        "identity_provenance": profile.identity_provenance,
        "isolation": "cooperative local process",
        "world": profile.world,
        "model_calls": profile.model_calls,
        "cost_usd": None,
        "budget": "invocation limit enforced; provider dollar cap unavailable",
        "judging": "deterministic",
        "launch": launch.model_dump(),
    }


def launch_experiment(store, project, request: Launch, *, actor, key):
    preview(store, project, request)
    profile = TargetProfile.model_validate(store.get(project, "target", request.target))
    dataset = Dataset.model_validate(store.get(project, "dataset", request.dataset))
    if profile.model_calls != "none" and not request.budget_acknowledged:
        raise ValueError("live profile requires explicit budget acknowledgement")
    if not isinstance(key, str) or not 1 <= len(key) <= 200:
        raise ValueError("idempotency key required")
    sha = digest(request.model_dump())
    with store.db() as db:
        old = db.execute(
            "SELECT sha,object_id FROM requests WHERE project=? AND key=?",
            (project, key),
        ).fetchone()
        if old:
            if old[0] != sha:
                raise Conflict("idempotency key reused with different request")
            return old[1]
        identity = create_experiment(
            dataset.suite,
            agent=profile.name,
            command=profile.command,
            trials=request.trials,
            identity_files=[Path(p) for p in profile.identity_files],
        )
        metadata = {
            "target": request.target,
            "dataset": request.dataset,
            "profile": profile.model_dump(mode="json"),
            "launch": request.model_dump(),
            "actor": actor,
        }
        store.put(
            project, "experiment", metadata, actor=actor, object_id=identity, db=db
        )
        db.execute(
            "INSERT INTO requests VALUES(?,?,?,?)", (project, key, sha, identity)
        )
    return identity


def state_evidence(journal):
    items = []
    for row in journal.rows():
        if row["state"] != "completed":
            continue
        path = journal.root / "receipts" / f"{row['attempt_id']}.state.json"
        if not path.exists():
            raise JournalError("required independent state receipt unavailable")
        pointer = read_json(path)
        value = journal.load_blob(pointer["sha256"])
        if (
            value["plan_sha256"] != journal.plan_sha256
            or value["attempt_id"] != row["attempt_id"]
        ):
            raise JournalError("state receipt binding mismatch")
        receipt, _ = journal.receipt(row)
        if value["output_sha256"] != digest(
            receipt.observation.actual_output if receipt.observation else None
        ):
            raise JournalError("state receipt output mismatch")
        if value["assessment"] != assess(
            value["before"],
            value["after"],
            kind=value["kind"],
            output=receipt.observation.actual_output if receipt.observation else None,
        ):
            raise JournalError("independent state assessment mismatch")
        items.append(value)
    return items


def run(store, project, experiment, *, max_new_trials=None, end_ordinal=None):
    metadata = store.get(project, "experiment", experiment)
    profile = TargetProfile.model_validate(metadata["profile"])
    world = (
        World(kind=profile.world, faults=profile.faults).start()
        if profile.world
        else None
    )

    def observer(journal, row, target, public_input):
        before = world.reset(profile.seed + row["ordinal"])
        if not world.health():
            raise JournalError("environment reset failed")
        payload = copy.deepcopy(public_input)
        if not isinstance(payload, dict):
            raise JournalError("world requires structured public input")
        payload["environment"] = world.handle()
        output = target.invoke(payload)
        after = world.snapshot()
        value = {
            "plan_sha256": journal.plan_sha256,
            "attempt_id": row["attempt_id"],
            "kind": profile.world,
            "before": before,
            "after": after,
            "output_sha256": digest(output),
            "assessment": assess(before, after, kind=profile.world, output=output),
        }
        sha = journal.blob(value)
        immutable_json(
            journal.root / "receipts" / f"{row['attempt_id']}.state.json",
            {"sha256": sha},
        )
        return output

    try:
        result = execute(
            experiment,
            observer=observer if world else None,
            max_new_trials=max_new_trials,
            end_ordinal=end_ordinal,
        )
    finally:
        if world:
            world.cleanup()
    with store.db() as db:
        store.audit(db, project, "worker", "execution:" + result.state, experiment)
    return detail(store, project, experiment)


def detail(store, project, experiment):
    metadata = store.get(project, "experiment", experiment)
    with Journal.open(experiment) as journal:
        status = journal.status().model_dump(mode="json")
        status.update(
            {
                "agent": journal.plan.agent,
                "attempt_kind": metadata.get("launch", {}).get(
                    "attempt_kind", "initial"
                ),
                "dataset": metadata["dataset"],
                "created_at": journal.plan.created_at,
                "cancel_requested": journal.cancel_requested(),
                "state_assessments": [],
            }
        )
        if metadata["profile"]["world"]:
            evidence = state_evidence(journal)
            status["state_assessments"] = [v["assessment"] for v in evidence]
            status["overall_passed"] = status["passed"] and all(
                v["assessment"]["status"] == "accepted" for v in evidence
            )
        else:
            status["overall_passed"] = status["passed"]
        try:
            inspection = store.get(project, "inspection", experiment)["inspection"]
        except KeyError:
            inspection = None
        status["inspection"] = inspection
        if inspection and inspection["required"] and inspection["status"] != "accepted":
            status["overall_passed"] = False if status["passed"] is not None else None
        return status


def trial_detail(store, project, experiment, ordinal):
    metadata = store.get(project, "experiment", experiment)
    with Journal.open(experiment) as journal:
        row = journal.row(ordinal)
        case, trial = journal.plan.case_trial(ordinal)
        result = (
            journal.result(row).model_dump(mode="json")
            if row["state"] == "completed"
            else None
        )
        state = (
            next(
                (
                    v
                    for v in state_evidence(journal)
                    if v["attempt_id"] == row["attempt_id"]
                ),
                None,
            )
            if metadata["profile"]["world"]
            else None
        )
        return {
            "case": case.model_dump(mode="json"),
            "trial": trial,
            "state": row["state"],
            "result": result,
            "state_evidence": state,
            "trace_url": metadata["profile"]["trace_url"],
            "annotations": store.annotations(project, experiment, ordinal),
        }


def comparison(store, project, baseline, candidate, *, policy=None):
    detail(store, project, baseline)
    detail(store, project, candidate)
    a = store.get(project, "experiment", baseline)
    b = store.get(project, "experiment", candidate)
    dataset = Dataset.model_validate(store.get(project, "dataset", a["dataset"]))
    result = compare(
        baseline,
        candidate,
        families=dataset.families,
        seed=policy.seed if policy else 0,
        samples=policy.bootstrap_samples if policy else 2000,
    )
    kinds = [arm.get("launch", {}).get("attempt_kind", "initial") for arm in (a, b)]
    result["attempt_kind"] = kinds[0] if kinds[0] == kinds[1] else "mixed"
    if kinds[0] != kinds[1]:
        result["reasons"].append(
            "initial, recovery and assisted attempts cannot be pooled"
        )
    for arm in (a, b):
        if arm["profile"]["model_calls"] != "none" and not {
            "model",
            "environment",
            "retry_policy",
        }.issubset(arm["profile"]["conditions"]):
            result["reasons"].append("live target condition identity incomplete")
    for field in ("conditions", "world", "faults", "seed"):
        if a["profile"][field] != b["profile"][field]:
            result["reasons"].append(f"incompatible {field}; partition the cohort")
    return result


def gate(store, project, baseline, candidate, policy_id, artifact, actor):
    policy = Policy.model_validate(store.get(project, "policy", policy_id))
    data = comparison(store, project, baseline, candidate, policy=policy)
    if data["attempt_kind"] != "initial":
        data["reasons"].append("release policy requires initial invocations")
    candidate_detail = detail(store, project, candidate)
    states = candidate_detail["state_assessments"]
    state = (
        ("accepted" if all(v["status"] == "accepted" for v in states) else "rejected")
        if states and len(states) == candidate_detail["planned"]
        else None
    )
    inspection = candidate_detail.get("inspection")
    if any(value["status"] == "invalid" for value in states):
        state = None
    if (
        inspection
        and inspection["required"]
        and inspection["status"] not in ("accepted", "rejected")
    ):
        data["reasons"].append("required attached inspection unavailable")
    decision = decide(
        data,
        policy,
        artifact,
        state=state,
        inspection=inspection["status"] if inspection else None,
    )
    identity = store.put(project, "decision", decision, actor=actor)
    return {"id": identity, **decision}


def demo(store, project="local"):
    metric = Metric(name="answer", kind="json_subset")
    suite = Suite(
        schema_version="1.0",
        id="offline-support",
        version="1",
        metrics=[metric],
        cases=[
            Case(id=q, input={"question": q}, expected_output={"answer": q})
            for q in ("shipping", "returns", "hours")
        ],
    )
    dataset = Dataset(
        suite=suite,
        split="regression",
        origin="bundled synthetic controls",
        license="Apache-2.0",
        reviewed_by="fixture assertions",
        families={c.id: c.id for c in suite.cases},
    )
    dataset_id = register_dataset(store, project, dataset, "local")
    output = {}
    for mode in ("good", "regression"):
        profile = TargetProfile(
            name="Offline " + mode,
            command=CommandSpec(
                argv=[sys.executable, "-m", "agent_eval.workbench.adapter", mode],
                response_format="json",
            ),
            identity_files=[str(Path(__file__).with_name("adapter.py"))],
            model_calls="none",
        )
        target_id = store.put(project, "target", profile.model_dump(mode="json"))
        identity = launch_experiment(
            store,
            project,
            Launch(target=target_id, dataset=dataset_id, trials=3),
            actor="local",
            key="demo:" + mode + ":" + target_id + ":" + dataset_id,
        )
        run(store, project, identity)
        output[mode] = identity
    return output


def paired_run(
    store, project, baseline_request, candidate_request, *, seed, key, actor
):
    """Freeze and execute one randomized arm order per case/replicate block."""
    import random

    if (
        baseline_request.dataset != candidate_request.dataset
        or baseline_request.trials != candidate_request.trials
    ):
        raise ValueError("paired arms require the same dataset and replicate count")
    baseline = launch_experiment(
        store, project, baseline_request, actor=actor, key=key + ":baseline"
    )
    candidate = launch_experiment(
        store, project, candidate_request, actor=actor, key=key + ":candidate"
    )
    planned = detail(store, project, baseline)["planned"]
    rng = random.Random(seed)
    schedule = []
    for ordinal in range(planned):
        arms = [baseline, candidate]
        rng.shuffle(arms)
        schedule.extend({"experiment": arm, "ordinal": ordinal} for arm in arms)
    design = {
        "baseline": baseline,
        "candidate": candidate,
        "seed": seed,
        "schedule": schedule,
        "stopping_rule": "fixed planned count",
        "attempt_kind": "initial",
    }
    design_id = store.put(
        project,
        "comparison-design",
        design,
        actor=actor,
        object_id=digest({"key": key}),
    )
    for slot in schedule:
        with Journal.open(slot["experiment"]) as journal:
            row = journal.row(slot["ordinal"])
            if row["state"] == "completed":
                continue
            if row["state"] not in ("queued", "observed"):
                raise JournalError(
                    "paired run requires reconciliation before continuation"
                )
        result = run(
            store,
            project,
            slot["experiment"],
            max_new_trials=1,
            end_ordinal=slot["ordinal"],
        )
        if result["state"] in ("cancelled", "reconciliation_required"):
            break
    return {"design": design_id, "baseline": baseline, "candidate": candidate}
