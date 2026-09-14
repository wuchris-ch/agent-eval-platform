"""Cross-run coding-agent summaries with explicit denominators and pairing."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, Field

from .metrics import RunRecord
from .report import pass_at_k

_Z_95 = 1.959963984540054
_HARNESS_BOUND_ADAPTERS = frozenset({"claude-code", "codex", "oracle"})


class Interval(BaseModel):
    lower: float
    upper: float
    confidence: float = 0.95


class Distribution(BaseModel):
    observed: int
    total: int
    completeness: float
    median: float | None = None
    p95: float | None = None
    mean: float | None = None


class EvaluationCohort(BaseModel):
    """Exact evaluation identity shared by records that may be aggregated."""

    cohort_id: str
    binding: Literal["bound", "legacy-unbound"]
    task_id: str
    evaluation_spec_digest: str | None = None
    task_tree_sha256: str | None = None
    image_digest: str | None = None
    harness_version: str | None = None
    harness_commit: str | None = None
    harness_dirty: bool | None = None
    harness_worktree_sha256: str | None = None
    evaluation_recipe_digest: str | None = None
    missing_fields: list[str] = Field(default_factory=list)


class AgentSummary(BaseModel):
    cohort: EvaluationCohort
    agent: str
    model: str
    sample_size: int
    sample_label: str
    correctness_evidence_count: int
    legacy_incomplete_count: int
    resolved: int
    resolved_rate: float | None
    resolved_wilson_95: Interval | None
    accepted: int | None = None
    accepted_evidence_count: int = 0
    accepted_rate: float | None = None
    infrastructure_failures: int = 0
    infrastructure_failure_rate: float = 0.0
    pass_at_k: dict[str, float] = Field(default_factory=dict)
    wall_time_s: Distribution
    total_tokens: Distribution
    cost_usd: Distribution
    tool_calls: Distribution
    judge_score: Distribution
    changed_lines: Distribution


class PairedDelta(BaseModel):
    cohort: EvaluationCohort
    baseline: str
    candidate: str
    expected_pairs: int
    pairs: int
    unavailable_pairs: int = 0
    excluded_pairs: int = 0
    unavailable_pair_reasons: dict[str, int] = Field(default_factory=dict)
    excluded_pair_reasons: dict[str, int] = Field(default_factory=dict)
    candidate_wins: int
    ties: int
    candidate_losses: int
    duplicate_keys_excluded: int = 0
    resolved_rate_delta: float | None
    wall_time_median_delta_s: float | None
    token_median_delta: float | None
    cost_median_delta_usd: float | None


class AgentComparison(BaseModel):
    summaries: list[AgentSummary]
    paired: list[PairedDelta] = Field(default_factory=list)


def _wilson(successes: int, total: int) -> Interval:
    if total <= 0:
        return Interval(lower=0.0, upper=0.0)
    proportion = successes / total
    z2 = _Z_95**2
    denominator = 1 + z2 / total
    center = (proportion + z2 / (2 * total)) / denominator
    margin = _Z_95 * math.sqrt(
        proportion * (1 - proportion) / total + z2 / (4 * total**2)
    ) / denominator
    return Interval(
        lower=max(0.0, center - margin),
        upper=min(1.0, center + margin),
    )


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def _distribution(records: list[RunRecord], getter: Callable[[RunRecord], float | int | None]) -> Distribution:
    values = [float(value) for record in records if (value := getter(record)) is not None]
    total = len(records)
    return Distribution(
        observed=len(values),
        total=total,
        completeness=len(values) / total if total else 0.0,
        median=statistics.median(values) if values else None,
        p95=_percentile(values, 0.95),
        mean=statistics.fmean(values) if values else None,
    )


def _model(record: RunRecord) -> str:
    observed = record.efficiency.model
    requested = record.efficiency.requested_model
    if observed and requested and observed != requested:
        return f"{observed} (requested {requested})"
    if observed:
        return observed
    if requested:
        return f"{requested} (requested, unobserved)"
    return "unknown"


def _agent_key(record: RunRecord) -> str:
    identity = _agent_implementation_identity(record)
    if identity is None:
        identity = f"unbound:{record.run_id}"
    return f"{record.agent}/{_model(record)}/{identity}"


def _agent_implementation_identity(record: RunRecord) -> str | None:
    """Return an exact adapter identity or None when aggregation is unsafe."""

    if record.agent in _HARNESS_BOUND_ADAPTERS:
        return f"harness-bound:{record.agent}"
    distribution = record.provenance.tool_versions.get(
        "agent-adapter-distribution"
    )
    version = record.provenance.tool_versions.get("agent-adapter-version")
    digest = record.provenance.tool_versions.get("agent-adapter-sha256")
    if (
        not distribution
        or not version
        or not digest
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        return None
    return f"plugin:{distribution}:{version}:sha256:{digest}"


def _evaluation_recipe_digest(record: RunRecord) -> str | None:
    """Return the configured evaluator and dataset recipe identity.

    The execution-specification digest is computed before evaluation and binds
    the task manifest, including dataset metadata and evaluator configuration,
    plus the enabled grader recipe. Assessment rows are observed outputs: their
    presence varies when a judge, scanner, or evaluator is unavailable and must
    never decide which denominator a run enters.
    """

    return record.provenance.evaluation_spec_digest


def _cohort(record: RunRecord) -> EvaluationCohort:
    provenance = record.provenance
    values = {
        "evaluation_spec_digest": provenance.evaluation_spec_digest,
        "task_tree_sha256": provenance.task_tree_sha256,
        "image_digest": provenance.image_digest,
        "harness_version": provenance.harness_version,
        "evaluation_recipe_digest": _evaluation_recipe_digest(record),
    }
    missing = sorted(name for name, value in values.items() if not value)
    if _agent_implementation_identity(record) is None:
        missing.append("agent_adapter_identity")
    git_values = {
        "harness_commit": provenance.harness_commit,
        "harness_dirty": provenance.harness_dirty,
        "harness_worktree_sha256": provenance.harness_worktree_sha256,
    }
    missing.extend(name for name, value in git_values.items() if value is None)
    missing = sorted(set(missing))
    if missing:
        identity = f"legacy-unbound\0{record.run_id}".encode()
        binding: Literal["bound", "legacy-unbound"] = "legacy-unbound"
    else:
        identity = json.dumps(
            {
                "task_id": record.task_id,
                **values,
                **git_values,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        binding = "bound"
    return EvaluationCohort(
        cohort_id=hashlib.sha256(identity).hexdigest(),
        binding=binding,
        task_id=record.task_id,
        evaluation_spec_digest=values["evaluation_spec_digest"],
        task_tree_sha256=values["task_tree_sha256"],
        image_digest=values["image_digest"],
        harness_version=values["harness_version"],
        harness_commit=git_values["harness_commit"],
        harness_dirty=git_values["harness_dirty"],
        harness_worktree_sha256=git_values["harness_worktree_sha256"],
        evaluation_recipe_digest=values["evaluation_recipe_digest"],
        missing_fields=missing,
    )


def _total_tokens(record: RunRecord) -> int | None:
    if record.efficiency.tokens_in is None or record.efficiency.tokens_out is None:
        return None
    return record.efficiency.tokens_in + record.efficiency.tokens_out


def _accepted(record: RunRecord) -> bool | None:
    outcome = getattr(record, "outcome", None)
    if outcome is None or outcome.status == "infra_error":
        return None
    return outcome.status == "accepted"


def _has_correctness_evidence(record: RunRecord) -> bool:
    outcome = getattr(record, "outcome", None)
    return (
        record.correctness.command_exit_code is not None
        and record.correctness.infra_error is None
        and record.efficiency.infra_error is None
        and (outcome is None or outcome.status != "infra_error")
    )


def _summarize(records: list[RunRecord], cohort: EvaluationCohort) -> AgentSummary:
    first = records[0]
    total = len(records)
    evaluable = [
        record for record in records
        if _has_correctness_evidence(record)
    ]
    resolved = sum(record.correctness.resolved for record in evaluable)
    accepted_values = [_accepted(record) for record in records]
    accepted_observed = [value for value in accepted_values if value is not None]
    infra = sum(
        bool(record.correctness.infra_error or record.efficiency.infra_error)
        for record in records
    )
    return AgentSummary(
        cohort=cohort,
        agent=first.agent,
        model=_model(first),
        sample_size=total,
        sample_label="small sample" if total < 10 else "established sample",
        correctness_evidence_count=len(evaluable),
        legacy_incomplete_count=total - len(evaluable),
        resolved=resolved,
        resolved_rate=resolved / len(evaluable) if evaluable else None,
        resolved_wilson_95=(
            _wilson(resolved, len(evaluable)) if evaluable else None
        ),
        accepted=(sum(accepted_observed) if accepted_observed else None),
        accepted_evidence_count=len(accepted_observed),
        accepted_rate=(
            sum(accepted_observed) / len(accepted_observed)
            if accepted_observed else None
        ),
        infrastructure_failures=infra,
        infrastructure_failure_rate=infra / total,
        pass_at_k={
            f"pass@{k}": pass_at_k(len(evaluable), resolved, k)
            for k in (1, 3, 5)
            if k <= len(evaluable)
        },
        wall_time_s=_distribution(records, lambda r: r.efficiency.wall_time_s),
        total_tokens=_distribution(records, _total_tokens),
        cost_usd=_distribution(records, lambda r: r.efficiency.cost_usd),
        tool_calls=_distribution(records, lambda r: r.efficiency.tool_calls),
        judge_score=_distribution(records, lambda r: r.judge.weighted_score),
        changed_lines=_distribution(
            records, lambda r: r.diff.lines_added + r.diff.lines_removed
        ),
    )


def _pair_key(record: RunRecord) -> tuple[str, str, int, str] | None:
    experiment_id = getattr(record, "experiment_id", None)
    cohort = _cohort(record)
    if not experiment_id or cohort.binding != "bound":
        return None
    return (
        experiment_id,
        record.task_id,
        record.trial,
        cohort.cohort_id,
    )


def _median_delta(
    pairs: list[tuple[RunRecord, RunRecord]],
    getter: Callable[[RunRecord], float | int | None],
) -> float | None:
    deltas = []
    for baseline, candidate in pairs:
        left = getter(baseline)
        right = getter(candidate)
        if left is not None and right is not None:
            deltas.append(float(right) - float(left))
    return statistics.median(deltas) if deltas else None


def _paired(
    grouped: dict[str, list[RunRecord]],
    baseline: str,
    candidate: str,
    cohort: EvaluationCohort,
) -> PairedDelta | None:
    shared_experiments = {
        record.experiment_id
        for record in grouped.get(baseline, [])
        if record.experiment_id
    } & {
        record.experiment_id
        for record in grouped.get(candidate, [])
        if record.experiment_id
    }
    if not shared_experiments:
        return None

    by_key: dict[str, dict[tuple[str, str, int, str], RunRecord]] = {}
    duplicate_keys: dict[str, set[tuple[str, str, int, str]]] = {}
    for name in (baseline, candidate):
        records = grouped.get(name, [])
        candidates: dict[tuple[str, str, int, str], list[RunRecord]] = defaultdict(
            list
        )
        for record in records:
            if (
                record.experiment_id in shared_experiments
                and (key := _pair_key(record)) is not None
            ):
                candidates[key].append(record)
        duplicate_keys[name] = {
            key for key, matches in candidates.items() if len(matches) > 1
        }
        indexed = {
            key: matches[0]
            for key, matches in candidates.items()
            if len(matches) == 1
        }
        by_key[name] = indexed
    keys = sorted(
        set(by_key[baseline])
        | set(by_key[candidate])
        | duplicate_keys[baseline]
        | duplicate_keys[candidate]
    )
    if not keys:
        return None
    pairs: list[tuple[RunRecord, RunRecord]] = []
    unavailable_reasons: Counter[str] = Counter()
    excluded_reasons: Counter[str] = Counter()
    unavailable_pairs = 0
    excluded_pairs = 0
    for key in keys:
        baseline_duplicate = key in duplicate_keys[baseline]
        candidate_duplicate = key in duplicate_keys[candidate]
        if baseline_duplicate or candidate_duplicate:
            excluded_pairs += 1
            reason = (
                "duplicate_baseline_and_candidate"
                if baseline_duplicate and candidate_duplicate
                else "duplicate_baseline"
                if baseline_duplicate
                else "duplicate_candidate"
            )
            excluded_reasons[reason] += 1
            continue
        left = by_key[baseline].get(key)
        right = by_key[candidate].get(key)
        if left is None or right is None:
            unavailable_pairs += 1
            unavailable_reasons[
                "missing_baseline" if left is None else "missing_candidate"
            ] += 1
            continue
        left_available = _has_correctness_evidence(left)
        right_available = _has_correctness_evidence(right)
        if not left_available or not right_available:
            unavailable_pairs += 1
            reason = (
                "baseline_and_candidate_correctness_unavailable"
                if not left_available and not right_available
                else "baseline_correctness_unavailable"
                if not left_available
                else "candidate_correctness_unavailable"
            )
            unavailable_reasons[reason] += 1
            continue
        pairs.append((left, right))
    wins = ties = losses = 0
    deltas = []
    for left, right in pairs:
        delta = int(right.correctness.resolved) - int(left.correctness.resolved)
        deltas.append(delta)
        if delta > 0:
            wins += 1
        elif delta < 0:
            losses += 1
        else:
            ties += 1
    return PairedDelta(
        cohort=cohort,
        baseline=baseline,
        candidate=candidate,
        expected_pairs=len(keys),
        pairs=len(pairs),
        unavailable_pairs=unavailable_pairs,
        excluded_pairs=excluded_pairs,
        unavailable_pair_reasons=dict(sorted(unavailable_reasons.items())),
        excluded_pair_reasons=dict(sorted(excluded_reasons.items())),
        candidate_wins=wins,
        ties=ties,
        candidate_losses=losses,
        duplicate_keys_excluded=len(
            duplicate_keys[baseline] | duplicate_keys[candidate]
        ),
        resolved_rate_delta=statistics.fmean(deltas) if deltas else None,
        wall_time_median_delta_s=_median_delta(
            pairs, lambda r: r.efficiency.wall_time_s
        ),
        token_median_delta=_median_delta(pairs, _total_tokens),
        cost_median_delta_usd=_median_delta(
            pairs, lambda r: r.efficiency.cost_usd
        ),
    )


def compare_agents(records: list[RunRecord]) -> AgentComparison:
    """Summarize records and produce only defensibly paired comparisons."""

    cohorts: dict[str, tuple[EvaluationCohort, dict[str, list[RunRecord]]]] = {}
    for record in records:
        cohort = _cohort(record)
        if cohort.cohort_id not in cohorts:
            cohorts[cohort.cohort_id] = (cohort, defaultdict(list))
        cohorts[cohort.cohort_id][1][_agent_key(record)].append(record)

    summaries = []
    paired = []
    for cohort_id in sorted(cohorts):
        cohort, groups = cohorts[cohort_id]
        summaries.extend(
            _summarize(groups[name], cohort) for name in sorted(groups)
        )
        if cohort.binding != "bound":
            continue
        names = sorted(groups)
        for index, baseline in enumerate(names):
            for candidate in names[index + 1 :]:
                comparison = _paired(groups, baseline, candidate, cohort)
                if comparison is not None:
                    paired.append(comparison)
    return AgentComparison(summaries=summaries, paired=paired)
