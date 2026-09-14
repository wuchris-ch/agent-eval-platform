import hashlib
from datetime import UTC, datetime

import pytest

from agent_eval.agent_comparison import compare_agents
from agent_eval.assessments import (
    Assessment,
    AssessmentValue,
    EvaluatorIdentity,
    expected_assessment_id,
)
from agent_eval.evaluators.tests import TestResults as EvalTestResults
from agent_eval.metrics import AgentMetrics, RunProvenance, RunRecord
from agent_eval.outcome import RunOutcome


def _run(
    agent,
    model,
    trial,
    resolved,
    *,
    experiment="exp-1",
    time=10,
    tokens=100,
    run_id=None,
):
    run_id = run_id or f"{agent}-{trial}"
    timestamp = datetime(2026, 7, 14, tzinfo=UTC)
    assessment = Assessment(
        assessment_id="0" * 64,
        run_id=run_id,
        name="tests.resolved",
        source_kind="test",
        status="passed" if resolved else "failed",
        value=AssessmentValue(type="boolean", boolean=resolved),
        direction="higher_is_better",
        evaluator=EvaluatorIdentity(
            name="hidden-tests", version="0.3.0", config_digest="c" * 64
        ),
        started_at=timestamp,
        finished_at=timestamp,
        observed_at=timestamp,
    )
    assessment = assessment.model_copy(
        update={"assessment_id": expected_assessment_id(assessment)}
    )
    return RunRecord(
        run_id=run_id,
        task_id="task",
        agent=agent,
        trial=trial,
        experiment_id=experiment,
        correctness=EvalTestResults(
            total=1,
            passed=int(resolved),
            failed=int(not resolved),
            command_exit_code=0 if resolved else 1,
        ),
        efficiency=AgentMetrics(
            model=model,
            wall_time_s=time,
            tokens_in=tokens - 10,
            tokens_out=10,
            tool_calls=2,
        ),
        provenance=RunProvenance(
            evaluation_spec_digest="c" * 64,
            task_tree_sha256="a" * 64,
            image_digest="sha256:" + "b" * 64,
            harness_version="0.3.0",
            harness_commit="d" * 40,
            harness_dirty=False,
            harness_worktree_sha256="e" * 64,
            tool_versions={
                "agent-adapter-distribution": f"test-{agent}",
                "agent-adapter-version": "1.0.0",
                "agent-adapter-sha256": "f" * 64,
            },
        ),
        assessments=[assessment],
    )


def test_comparison_has_denominators_intervals_and_paired_deltas():
    records = [
        _run("alpha", "a1", 1, False, time=12, tokens=100),
        _run("alpha", "a1", 2, True, time=10, tokens=120),
        _run("beta", "b1", 1, True, time=8, tokens=90),
        _run("beta", "b1", 2, True, time=9, tokens=100),
    ]

    result = compare_agents(records)

    alpha = result.summaries[0]
    assert alpha.sample_size == 2
    assert alpha.correctness_evidence_count == 2
    assert alpha.legacy_incomplete_count == 0
    assert alpha.resolved_rate == 0.5
    assert 0 <= alpha.resolved_wilson_95.lower < alpha.resolved_wilson_95.upper <= 1
    assert alpha.total_tokens.observed == 2
    assert alpha.total_tokens.median == 110
    assert alpha.cost_usd.completeness == 0
    assert alpha.sample_label == "small sample"

    paired = result.paired[0]
    assert paired.cohort.binding == "bound"
    assert paired.expected_pairs == 2
    assert paired.pairs == 2
    assert paired.unavailable_pairs == 0
    assert paired.excluded_pairs == 0
    assert paired.candidate_wins == 1
    assert paired.ties == 1
    assert paired.candidate_losses == 0
    assert paired.resolved_rate_delta == 0.5
    assert paired.wall_time_median_delta_s == -2.5


def test_unpaired_historical_runs_are_not_presented_as_paired():
    records = [
        _run("alpha", "a1", 1, True, experiment=None),
        _run("beta", "b1", 1, False, experiment=None),
    ]

    result = compare_agents(records)

    assert len(result.summaries) == 2
    assert result.paired == []


def test_distinct_experiments_are_not_inferred_to_be_missing_pairs():
    records = [
        _run("alpha", "a1", 1, True, experiment="experiment-alpha"),
        _run("beta", "b1", 1, False, experiment="experiment-beta"),
    ]

    result = compare_agents(records)

    assert len(result.summaries) == 2
    assert result.paired == []


def test_legacy_records_without_command_exit_are_not_misreported_as_failures():
    legacy = _run("alpha", "a1", 1, True)
    legacy.correctness.command_exit_code = None

    summary = compare_agents([legacy]).summaries[0]

    assert summary.correctness_evidence_count == 0
    assert summary.legacy_incomplete_count == 1
    assert summary.resolved_rate is None
    assert summary.resolved_wilson_95 is None


def test_infrastructure_failures_do_not_enter_correctness_denominator():
    record = _run("alpha", "a1", 1, False)
    record.correctness = EvalTestResults(infra_error="pod failed")

    summary = compare_agents([record]).summaries[0]

    assert summary.correctness_evidence_count == 0
    assert summary.resolved_rate is None
    assert summary.infrastructure_failures == 1
    assert summary.infrastructure_failure_rate == 1.0


def test_infrastructure_failures_are_not_paired_as_correctness_results():
    baseline = _run("alpha", "a1", 1, True)
    candidate = _run("beta", "b1", 1, False)
    candidate.correctness = EvalTestResults(infra_error="pod failed")

    paired = compare_agents([baseline, candidate]).paired[0]

    assert paired.expected_pairs == 1
    assert paired.pairs == 0
    assert paired.unavailable_pairs == 1
    assert paired.excluded_pairs == 0
    assert paired.unavailable_pair_reasons == {"candidate_correctness_unavailable": 1}
    assert (paired.candidate_wins, paired.ties, paired.candidate_losses) == (
        0,
        0,
        0,
    )
    assert paired.resolved_rate_delta is None


def test_post_test_infrastructure_failure_excludes_observed_command_result():
    baseline = _run("alpha", "a1", 1, True)
    candidate = _run("beta", "b1", 1, True)
    candidate.correctness.infra_error = "cleanup failed"
    candidate.outcome = RunOutcome(status="infra_error")

    result = compare_agents([baseline, candidate])
    candidate_summary = next(item for item in result.summaries if item.agent == "beta")

    assert candidate_summary.correctness_evidence_count == 0
    assert candidate_summary.resolved_rate is None
    assert candidate_summary.infrastructure_failures == 1
    paired = result.paired[0]
    assert paired.expected_pairs == 1
    assert paired.pairs == 0
    assert paired.unavailable_pairs == 1
    assert paired.unavailable_pair_reasons == {"candidate_correctness_unavailable": 1}


def test_infrastructure_outcome_does_not_enter_acceptance_denominator():
    record = _run("alpha", "a1", 1, False)
    record.correctness = EvalTestResults(infra_error="pod failed")
    record.outcome = RunOutcome(status="infra_error")

    summary = compare_agents([record]).summaries[0]

    assert summary.accepted is None
    assert summary.accepted_evidence_count == 0
    assert summary.accepted_rate is None


def test_pairing_requires_identical_task_and_image_identity():
    alpha = _run("alpha", "a1", 1, True)
    beta = _run("beta", "b1", 1, True)
    beta.provenance.task_tree_sha256 = "c" * 64

    assert compare_agents([alpha, beta]).paired == []


def test_different_evaluation_specs_are_not_aggregated_or_scored_as_pairs():
    alpha = _run("alpha", "a1", 1, True)
    beta = _run("beta", "b1", 1, False)
    alpha_other_recipe = _run("alpha", "a1", 2, False)
    beta.provenance.evaluation_spec_digest = "d" * 64
    alpha_other_recipe.provenance.evaluation_spec_digest = "d" * 64

    result = compare_agents([alpha, beta, alpha_other_recipe])

    assert len(result.summaries) == 3
    assert all(summary.sample_size == 1 for summary in result.summaries)
    assert len({summary.cohort.cohort_id for summary in result.summaries}) == 2
    assert len(result.paired) == 1
    paired = result.paired[0]
    assert paired.expected_pairs == 2
    assert paired.pairs == 0
    assert paired.unavailable_pairs == 2
    assert paired.unavailable_pair_reasons == {
        "missing_baseline": 1,
        "missing_candidate": 1,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_tree_sha256", "d" * 64),
        ("image_digest", "sha256:" + "e" * 64),
    ],
)
def test_different_task_or_image_identity_is_not_aggregated(field, value):
    first = _run("alpha", "a1", 1, True)
    second = _run("alpha", "a1", 2, False)
    setattr(second.provenance, field, value)

    result = compare_agents([first, second])

    assert len(result.summaries) == 2
    assert all(summary.sample_size == 1 for summary in result.summaries)


def test_harness_identity_splits_but_observed_evaluator_identity_does_not():
    baseline = _run("alpha", "a1", 1, True)
    different_harness = _run("alpha", "a1", 2, True)
    different_evaluator = _run("alpha", "a1", 3, True)
    different_harness.provenance.harness_version = "0.3.1"
    assessment = different_evaluator.assessments[0].model_copy(
        update={
            "evaluator": different_evaluator.assessments[0].evaluator.model_copy(
                update={"version": "0.3.1"}
            )
        }
    )
    different_evaluator.assessments[0] = assessment.model_copy(
        update={"assessment_id": expected_assessment_id(assessment)}
    )

    result = compare_agents([baseline, different_harness, different_evaluator])

    assert len(result.summaries) == 2
    assert sorted(summary.sample_size for summary in result.summaries) == [1, 2]
    assert len({summary.cohort.cohort_id for summary in result.summaries}) == 2


def test_observed_assessment_presence_does_not_change_configured_cohort():
    first = _run("alpha", "a1", 1, True)
    second = _run("alpha", "a1", 2, False)
    extra = second.assessments[0].model_copy(
        update={
            "assessment_id": "0" * 64,
            "name": "judge.score",
            "source_kind": "judge",
            "value": AssessmentValue(type="numeric", numeric=0.7),
        }
    )
    second.assessments.append(
        extra.model_copy(update={"assessment_id": expected_assessment_id(extra)})
    )

    result = compare_agents([first, second])

    assert len(result.summaries) == 1
    assert result.summaries[0].sample_size == 2
    assert result.summaries[0].cohort.binding == "bound"


@pytest.mark.parametrize(
    "identity",
    [
        "registry:auto (mutable)",
        "registry:auto (mutable; network-fetched)",
        "filesystem-vulnerability-db",
    ],
)
def test_observed_scanner_configuration_does_not_change_configured_cohort(identity):
    record = _run("alpha", "a1", 1, True)
    assessment = record.assessments[0].model_copy(
        update={
            "evaluator": record.assessments[0].evaluator.model_copy(
                update={
                    "config_digest": hashlib.sha256(
                        identity.encode("utf-8")
                    ).hexdigest()
                }
            )
        }
    )
    record.assessments[0] = assessment.model_copy(
        update={"assessment_id": expected_assessment_id(assessment)}
    )

    cohort = compare_agents([record]).summaries[0].cohort

    assert cohort.binding == "bound"
    assert cohort.evaluation_recipe_digest == record.provenance.evaluation_spec_digest


def test_legacy_unbound_records_are_each_isolated():
    alpha = _run("alpha", "a1", 1, True)
    alpha_retry = _run("alpha", "a1", 2, False)
    beta = _run("beta", "b1", 1, True)
    for record in (alpha, alpha_retry, beta):
        record.provenance.evaluation_spec_digest = None

    result = compare_agents([alpha, alpha_retry, beta])

    assert result.paired == []
    assert len(result.summaries) == 3
    assert all(summary.sample_size == 1 for summary in result.summaries)
    assert all(
        summary.cohort.binding == "legacy-unbound" for summary in result.summaries
    )
    assert all(
        "evaluation_spec_digest" in summary.cohort.missing_fields
        for summary in result.summaries
    )


def test_missing_harness_git_identity_is_legacy_unbound():
    record = _run("alpha", "a1", 1, True)
    record.provenance.harness_commit = None
    record.provenance.harness_dirty = None
    record.provenance.harness_worktree_sha256 = None

    cohort = compare_agents([record]).summaries[0].cohort

    assert cohort.binding == "legacy-unbound"
    assert {
        "harness_commit",
        "harness_dirty",
        "harness_worktree_sha256",
    } <= set(cohort.missing_fields)


def test_plugin_adapter_without_artifact_identity_is_never_aggregated():
    first = _run("third-party", "m1", 1, True)
    second = _run("third-party", "m1", 2, False)
    for record in (first, second):
        record.provenance.tool_versions.clear()

    result = compare_agents([first, second])

    assert len(result.summaries) == 2
    assert all(item.cohort.binding == "legacy-unbound" for item in result.summaries)
    assert result.paired == []


def test_external_workspaces_without_producer_identity_are_never_aggregated():
    first = _run("external", None, 1, True)
    second = _run("external", None, 2, False)
    for record in (first, second):
        record.provenance.tool_versions.clear()

    result = compare_agents([first, second])

    assert len(result.summaries) == 2
    assert all(item.cohort.binding == "legacy-unbound" for item in result.summaries)


def test_plugin_adapter_versions_are_distinct_agent_implementations():
    first = _run("third-party", "m1", 1, True)
    second = _run("third-party", "m1", 2, False)
    second.provenance.tool_versions["agent-adapter-version"] = "2.0.0"

    result = compare_agents([first, second])

    assert len(result.summaries) == 2
    assert all(item.cohort.binding == "bound" for item in result.summaries)


def test_duplicate_retries_are_excluded_from_pairing():
    records = [
        _run("alpha", "a1", 1, False),
        _run("alpha", "a1", 1, True, run_id="alpha-retry"),
        _run("beta", "b1", 1, True),
        _run("alpha", "a1", 2, True),
        _run("beta", "b1", 2, True),
    ]
    paired = compare_agents(records).paired[0]

    assert paired.expected_pairs == 2
    assert paired.pairs == 1
    assert paired.unavailable_pairs == 0
    assert paired.excluded_pairs == 1
    assert paired.excluded_pair_reasons == {"duplicate_baseline": 1}
    assert paired.duplicate_keys_excluded == 1


def test_missing_declared_counterpart_is_reported_as_unavailable():
    records = [
        _run("alpha", "a1", 1, False),
        _run("beta", "b1", 1, True),
        _run("alpha", "a1", 2, True),
    ]

    paired = compare_agents(records).paired[0]

    assert paired.expected_pairs == 2
    assert paired.pairs == 1
    assert paired.unavailable_pairs == 1
    assert paired.excluded_pairs == 0
    assert paired.unavailable_pair_reasons == {"missing_candidate": 1}
    assert (paired.candidate_wins, paired.ties, paired.candidate_losses) == (
        1,
        0,
        0,
    )


def test_infrastructure_trial_is_reported_but_excluded_from_win_loss_counts():
    baseline_one = _run("alpha", "a1", 1, False)
    candidate_one = _run("beta", "b1", 1, True)
    baseline_two = _run("alpha", "a1", 2, True)
    candidate_two = _run("beta", "b1", 2, False)
    candidate_two.correctness = EvalTestResults(infra_error="pod failed")

    paired = compare_agents(
        [baseline_one, candidate_one, baseline_two, candidate_two]
    ).paired[0]

    assert paired.expected_pairs == 2
    assert paired.pairs == 1
    assert paired.unavailable_pairs == 1
    assert paired.excluded_pairs == 0
    assert paired.unavailable_pair_reasons == {"candidate_correctness_unavailable": 1}
    assert (paired.candidate_wins, paired.ties, paired.candidate_losses) == (
        1,
        0,
        0,
    )


def test_requested_model_is_not_collapsed_into_unknown():
    run = _run("alpha", None, 1, True)
    run.efficiency.requested_model = "requested-model"

    summary = compare_agents([run]).summaries[0]

    assert summary.model == "requested-model (requested, unobserved)"
