"""Operator-only inspection of sealed candidate state and individual checks."""

from ..blackbox.models import digest
from ..experiments.journal import read_json
from ..paths import get_state_dir
from .contracts import Assessment, ExecutionContract
from .oracles import BehaviorSuite, grade
from .studies import validate_recorded_assessment


def investigate(store, project, execution):
    ticket = store.get(project, "trial-ticket-v2", execution)
    contract = ExecutionContract.model_validate(
        store.get(project, "execution-v2", execution)
    )
    assessment = Assessment.model_validate(
        store.get(project, "assessment-v2", execution)
    )
    validate_recorded_assessment(
        store, project, ticket, assessment.model_dump(mode="json")
    )
    suite = BehaviorSuite.model_validate(
        store.get(project, "candidate-suite", contract.suite_sha256)
    )
    receipt = read_json(
        get_state_dir()
        / "candidate-executions"
        / digest(project)
        / execution
        / "observation.json"
    )
    raw = receipt["observation"]
    if (
        receipt["contract_sha256"] != digest(contract.model_dump(mode="json"))
        or digest(raw) != assessment.observation_sha256
    ):
        raise ValueError("independent observation binding mismatch")
    if grade(suite, raw) != assessment.checks:
        raise ValueError("independent checks do not replay")
    return {
        "ticket": ticket,
        "assessment": assessment.model_dump(mode="json"),
        "observation": raw,
        "checks": [
            {
                **check.model_dump(mode="json"),
                "oracle": oracle.model_dump(mode="json"),
                "requests": [suite.requests[i] for i in oracle.response_indices],
            }
            for check, oracle in zip(assessment.checks, suite.checks, strict=True)
        ],
        "trace": [
            {"stage": "reserved", "sha256": digest(ticket)},
            {
                "stage": "candidate_bound",
                "sha256": digest(contract.model_dump(mode="json")),
            },
            {"stage": "submitted", "sha256": assessment.submission_sha256},
            {
                "stage": "independently_observed",
                "sha256": assessment.observation_sha256,
            },
            {"stage": "assessed", "sha256": digest(assessment.model_dump(mode="json"))},
        ],
    }
