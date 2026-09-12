"""Journal-backed independent assessment and evidence-bound policy decisions."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from ..blackbox.models import Case, Metric, Observation, Suite, digest
from ..experiments.executor import execute as execute_journal
from ..experiments.journal import Journal, JournalError
from ..experiments.models import CommandSpec, Receipt
from ..experiments.service import create_experiment
from . import authority, boundary
from .contracts import (
    AcceptancePolicy,
    Assessment,
    ExecutionContract,
    Submission,
    Usage,
    validate_assessment,
)
from .oracles import BehaviorSuite, grade


def policy_decision(checks, policy, usage, *, completed=True):
    known = {c.id: c.passed for c in checks}
    missing = [name for name in policy.required_checks if name not in known]
    failed = [name for name in policy.required_checks if known.get(name) is False]
    reasons = ["missing check: " + name for name in missing]
    if not completed:
        reasons.append("producer did not complete")
    for metric, maximum in [
        ("latency_ms", policy.max_latency_ms),
        ("total_tokens", policy.max_total_tokens),
        ("cost_usd", policy.max_cost_usd),
    ]:
        if maximum is not None:
            value = getattr(usage, metric)
            if value is None or usage.provenance != "independently_observed":
                reasons.append(metric + " measurement unavailable")
            elif value > maximum:
                failed.append(metric + " exceeds policy")
    verdict = "fail" if failed else "inconclusive" if reasons else "pass"
    return verdict, ["failed check: " + item for item in failed] + reasons


def assessment_inputs(store, project, execution):
    contract = ExecutionContract.model_validate(
        store.get(project, "execution-v2", execution)
    )
    submission = Submission.model_validate(
        store.get(project, "submission-v2", execution)
    )
    if contract.evaluator_sha256 != authority.identity():
        raise JournalError("assessment requires the issued evaluator implementation")
    authority.ingest(store, project, submission, "evaluator")
    suite = BehaviorSuite.model_validate(
        store.get(project, "candidate-suite", contract.suite_sha256)
    )
    return contract, submission, suite


def plan(store, project, contract, suite):
    with store.db() as db:
        try:
            return store.get(
                project, "candidate-experiment", contract.execution_id, db=db
            )["experiment"]
        except KeyError:
            pass
        experiment = create_experiment(
            Suite(
                schema_version="1.0",
                id="candidate-" + suite.task_id,
                version="2",
                metrics=[Metric(name="independent_checks", kind="json_subset")],
                cases=[
                    Case(
                        id=suite.task_id,
                        input={
                            "execution_id": contract.execution_id,
                            "requests_sha256": digest(suite.requests),
                        },
                        expected_output={"checks": {c.id: True for c in suite.checks}},
                    )
                ],
            ),
            agent="candidate/" + contract.trial_identity.arm,
            command=CommandSpec(
                argv=[
                    sys.executable,
                    "-c",
                    'raise SystemExit("operator observer required")',
                ],
                response_format="json",
                timeout=180,
            ),
            identity_files=list(Path(__file__).parent.glob("*.py")),
        )
        store.put(
            project,
            "candidate-experiment",
            {"experiment": experiment},
            object_id=contract.execution_id,
            db=db,
        )
        return experiment


def evaluate(store, project, execution):
    contract, submission, suite = assessment_inputs(store, project, execution)
    try:
        previous = Assessment.model_validate(
            store.get(project, "assessment-v2", execution)
        )
        validate_assessment(previous, submission)
        return previous.model_dump(mode="json")
    except KeyError:
        pass
    manifest = authority.manifest_for(store, project, contract)
    experiment = plan(store, project, contract, suite)

    def observe(*_args):
        raw = boundary.execute(project, contract, manifest, suite)
        return {
            "checks": {c.id: c.passed for c in grade(suite, raw)},
            "observation_sha256": digest(raw),
        }

    # Reconcile from our owned container or sealed receipt, never producer-supplied verdicts.
    with Journal.open(experiment, write=True) as journal:
        journal.recover()
        row = journal.row(0)
        if row["state"] == "reconciliation_required":
            actual = observe()
            raw = boundary.execute(project, contract, manifest, suite)
            case, trial = journal.plan.case_trial(0)
            observation = Observation(
                case_id=case.id,
                trial=trial,
                input_sha256=digest(case.input),
                actual_output=actual,
                latency_ms=elapsed(raw),
            )
            journal.reconcile_observation(
                row,
                Receipt(
                    plan_sha256=journal.plan_sha256,
                    attempt_id=row["attempt_id"],
                    ordinal=0,
                    observation=observation,
                ),
            )
    snapshot = execute_journal(experiment, observer=observe)
    if snapshot.state != "completed":
        return {
            "execution_id": execution,
            "status": snapshot.state,
            "experiment_id": experiment,
        }
    with Journal.open(experiment) as journal:
        result = journal.result(journal.row(0))
        if result.observation is None:
            return {
                "execution_id": execution,
                "status": "evaluation_unavailable",
                "experiment_id": experiment,
            }
    raw = boundary.execute(project, contract, manifest, suite)
    checks = grade(suite, raw)
    if result.observation.actual_output != {
        "checks": {c.id: c.passed for c in checks},
        "observation_sha256": digest(raw),
    }:
        raise JournalError(
            "journal differs from independently collected candidate evidence"
        )
    policy = AcceptancePolicy.model_validate(
        store.get(project, "candidate-policy", contract.policy_sha256)
    )
    usage = submission.usage
    try:
        usage = Usage.model_validate(store.get(project, "candidate-usage", execution))
    except KeyError:
        pass
    verdict, reasons = policy_decision(
        checks, policy, usage, completed=submission.producer_status == "completed"
    )
    fields = {
        k: getattr(submission, k)
        for k in (
            "execution_id",
            "execution_contract_sha256",
            "trial_ticket_sha256",
            "base_revision",
            "candidate_revision",
            "candidate_tree_sha256",
            "candidate_manifest_sha256",
            "recipe_sha256",
            "suite_sha256",
            "policy_sha256",
            "evaluator_sha256",
        )
    }
    assessment = Assessment(
        **fields,
        submission_sha256=digest(submission.model_dump(mode="json")),
        observation_sha256=digest(raw),
        checks=checks,
        outcome=verdict,
        reasons=reasons,
        usage=usage,
        evaluation_latency_ms=elapsed(raw),
    )
    store.put(
        project,
        "assessment-v2",
        assessment.model_dump(mode="json"),
        object_id=execution,
        actor="evaluator",
    )
    boundary.cleanup(project, execution)
    return assessment.model_dump(mode="json")


def elapsed(raw):
    return max(
        0,
        (
            datetime.fromisoformat(raw["finished_at"].replace("Z", "+00:00"))
            - datetime.fromisoformat(raw["started_at"].replace("Z", "+00:00"))
        ).total_seconds()
        * 1000,
    )
