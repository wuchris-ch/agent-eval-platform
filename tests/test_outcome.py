from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_eval.evaluators.tests import TestResults as EvalTestResults
from agent_eval.metrics import AgentMetrics, JudgeResult, ScanResults
from agent_eval.outcome import AcceptancePolicy, evaluate_outcome


def _record(**overrides):
    values = {
        "correctness": EvalTestResults(
            total=2,
            passed=2,
            command_exit_code=0,
            coverage_percent=92,
        ),
        "efficiency": AgentMetrics(
            wall_time_s=10,
            tokens_in=100,
            tokens_out=20,
            cost_usd=0.04,
        ),
        "scans": ScanResults(
            lint_errors=0,
            sec_findings_high=0,
            secrets_found=0,
            vulns=0,
            scanner_status={"ruff": "ok", "gitleaks": "ok"},
        ),
        "judge": JudgeResult(weighted_score=4.2),
        "assurance": SimpleNamespace(passed=True),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_acceptance_policy_accepts_complete_evidence():
    policy = AcceptancePolicy(
        min_coverage_percent=90,
        min_judge_score=4,
        required_scanners=["ruff", "gitleaks"],
        max_lint_errors=0,
        max_security_findings_high=0,
        max_secrets=0,
        max_vulnerabilities=0,
        max_wall_time_s=20,
        max_total_tokens=150,
        max_cost_usd=0.05,
        require_challenges_passed=True,
    )

    outcome = evaluate_outcome(_record(), policy)

    assert outcome.status == "accepted"
    assert outcome.reasons == []
    assert all(check.passed for check in outcome.checks)


def test_configured_missing_evidence_fails_closed():
    record = _record(
        scans=ScanResults(scanner_status={"ruff": "unavailable"}),
        judge=JudgeResult(),
    )
    policy = AcceptancePolicy(
        min_judge_score=3,
        required_scanners=["ruff", "gitleaks"],
        max_secrets=0,
    )

    outcome = evaluate_outcome(record, policy)

    assert outcome.status == "rejected"
    assert any("scanner ruff" in reason for reason in outcome.reasons)
    assert any("scanner gitleaks" in reason for reason in outcome.reasons)
    assert any("judge score" in reason for reason in outcome.reasons)
    assert any("secrets" in reason for reason in outcome.reasons)


def test_infrastructure_failure_is_distinct_from_rejection():
    correctness = EvalTestResults(infra_error="eval pod OOMKilled")

    outcome = evaluate_outcome(_record(correctness=correctness), AcceptancePolicy())

    assert outcome.status == "infra_error"
    assert outcome.reasons == ["eval pod OOMKilled"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wall_time_s", -0.1),
        ("wall_time_s", float("nan")),
        ("wall_time_s", float("inf")),
        ("tokens_in", -1),
        ("tokens_out", -1),
        ("cost_usd", -0.01),
        ("cost_usd", float("nan")),
        ("cost_usd", float("inf")),
        ("turns", -1),
        ("tool_calls", -1),
        ("tokens_in", "1"),
        ("cost_usd", "0.01"),
    ],
)
def test_agent_metrics_reject_invalid_accounting_at_construction(field, value):
    with pytest.raises(ValidationError):
        AgentMetrics(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wall_time_s", float("nan")),
        ("tokens_in", -1),
        ("cost_usd", -0.01),
        ("turns", -1),
        ("tool_calls", -1),
    ],
)
def test_agent_metrics_validate_accounting_assignment(field, value):
    metrics = AgentMetrics()

    with pytest.raises(ValidationError):
        setattr(metrics, field, value)

    assert getattr(metrics, field) is None


def test_agent_metrics_allow_negative_subprocess_exit_codes():
    metrics = AgentMetrics(agent_exit_code=-9)
    metrics.agent_exit_code = -15

    assert metrics.agent_exit_code == -15
    outcome = evaluate_outcome(_record(efficiency=metrics), AcceptancePolicy())
    assert outcome.status == "rejected"
    assert any("exit -15" in reason for reason in outcome.reasons)


@pytest.mark.parametrize(
    ("field", "value", "expected_check"),
    [
        ("wall_time_s", -1.0, "wall time accounting"),
        ("wall_time_s", float("nan"), "wall time accounting"),
        ("tokens_in", -100, "input token accounting"),
        ("tokens_out", -100, "output token accounting"),
        ("cost_usd", -1.0, "cost accounting"),
        ("cost_usd", float("inf"), "cost accounting"),
        ("turns", -1, "turn accounting"),
        ("tool_calls", -1, "tool-call accounting"),
    ],
)
def test_outcome_rejects_invalid_accounting_if_validation_is_bypassed(
    field, value, expected_check
):
    metrics = AgentMetrics.model_construct(**{field: value})

    outcome = evaluate_outcome(_record(efficiency=metrics), AcceptancePolicy())

    assert outcome.status == "rejected"
    assert any(
        check.name == expected_check and not check.passed for check in outcome.checks
    )
