"""Repeated, budget-aware experiments for pull-request review systems.

The experiment layer is intentionally separate from reviewer execution.  It
consumes versioned, vendor-neutral output directories, delegates correctness
scoring to :mod:`agent_eval.review_benchmark`, and adds the experiment design
needed to compare single reviewers and deterministic reviewer panels.

Experiment paths are relative to the experiment YAML file.  A single-reviewer
trial directory contains ``<case-id>.json`` files.  A panel trial directory
contains ``<member-id>/<case-id>.json`` files.  Generic output files use this
shape (native ``review.json`` files remain supported by the benchmark loader)::

    {
      "findings": [...],
      "metrics": {"latency_s": 2.4, "tokens": 1800, "cost_usd": 0.03}
    }

Panel members run in parallel: panel latency is the maximum member latency,
while tokens and cost are summed.  A member gets at most one vote for an exact
normalized ``(file, category, line)`` identity.  Quorum findings use severity
plurality with a conservative severity tie-break.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from collections import Counter
from itertools import combinations
from math import isfinite
from pathlib import Path, PurePosixPath
from statistics import fmean, stdev
from tempfile import TemporaryDirectory
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

from .limits import read_stable_bounded_file
from .review_benchmark import (
    BenchmarkManifest,
    BenchmarkResult,
    CaseResult,
    PredictedFinding,
    _DuplicateJsonKeyError,
    _normalize_file,
    _predictions_from_raw,
    _reject_json_constant,
    _unique_json_object,
    _UniqueKeySafeLoader,
    parse_manifest_bytes,
    score_benchmark,
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_URI_OR_DRIVE_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_SEVERITY_RANK = {"info": 1, "minor": 2, "major": 3, "blocker": 4}
MAX_BENCHMARK_BYTES = 16 * 1024 * 1024
MAX_EXPERIMENT_BYTES = 4 * 1024 * 1024
MAX_REVIEW_OUTPUT_BYTES = 16 * 1024 * 1024


def _validate_id(value: str) -> str:
    value = value.strip()
    if not _SAFE_ID.fullmatch(value):
        raise ValueError(
            "must contain only letters, digits, dots, underscores, and hyphens"
        )
    return value


def _safe_relative_path(value: str) -> str:
    """Return a normalized relative POSIX path, rejecting escape syntax."""

    candidate = value.strip().replace("\\", "/")
    if not candidate or "\x00" in candidate or _URI_OR_DRIVE_PREFIX.match(candidate):
        raise ValueError("must be a safe relative path")
    path = PurePosixPath(candidate)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        raise ValueError("must be a safe relative path")
    return path.as_posix()


def _resolve_inside(root: Path, relative: str) -> Path:
    """Resolve a declared path and ensure symlinks cannot leave ``root``."""

    resolved_root = root.resolve()
    resolved = (resolved_root / relative).resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(
            f"path {relative!r} resolves outside the experiment root"
        ) from exc
    return resolved


def _stable_file_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one bounded regular file from a single stable inode."""

    return read_stable_bounded_file(
        path,
        maximum_bytes=maximum_bytes,
    )


_OwnershipKey = tuple[str, str] | tuple[str, int, int]


def _ownership_keys(path: Path, root: Path) -> tuple[_OwnershipKey, ...]:
    """Return conservative planned identity plus inode identity when available."""

    relative = path.relative_to(root.resolve()).as_posix()
    planned = unicodedata.normalize("NFC", relative).casefold()
    keys: list[_OwnershipKey] = [("planned", planned)]
    try:
        metadata = path.stat()
    except (FileNotFoundError, NotADirectoryError):
        return tuple(keys)
    keys.append(("inode", metadata.st_dev, metadata.st_ino))
    return tuple(keys)


def _resolved_output_roots(
    spec: ExperimentSpec,
    root: Path,
    manifest: BenchmarkManifest,
) -> dict[tuple[str, str], Path]:
    """Resolve roots and reject any concrete source-output reuse."""

    resolved_by_trial: dict[tuple[str, str], Path] = {}
    owners: dict[_OwnershipKey, tuple[str, str]] = {}
    source_owners: dict[_OwnershipKey, tuple[str, str, str, str]] = {}
    for system in spec.systems:
        for trial in system.trials:
            owner = (system.id, trial.id)
            resolved_output = _resolve_inside(root, trial.outputs)
            root_keys = _ownership_keys(resolved_output, root)
            for key in root_keys:
                if previous := owners.get(key):
                    previous_system, previous_trial = previous
                    raise ValueError(
                        "experiment reuses a resolved trial output directory across "
                        "systems or trials: "
                        f"{previous_system}/{previous_trial} and "
                        f"{system.id}/{trial.id}"
                    )
            for key in root_keys:
                owners[key] = owner
            resolved_by_trial[owner] = resolved_output
            source_roots = (
                [("single", resolved_output)]
                if system.mode == "single"
                else [
                    (member, _resolve_inside(resolved_output, member))
                    for member in system.members
                ]
            )
            for source_id, source_root in source_roots:
                for case in manifest.cases:
                    source_path = _resolve_inside(
                        root,
                        (source_root / f"{case.id}.json")
                        .relative_to(root.resolve())
                        .as_posix(),
                    )
                    source_keys = _ownership_keys(source_path, root)
                    for key in source_keys:
                        if previous := source_owners.get(key):
                            (
                                previous_system,
                                previous_trial,
                                previous_source,
                                previous_case,
                            ) = previous
                            raise ValueError(
                                "experiment reuses a concrete source output across "
                                "systems, trials, or cases: "
                                f"{previous_system}/{previous_trial}/"
                                f"{previous_source}/{previous_case} and "
                                f"{system.id}/{trial.id}/{source_id}/{case.id}"
                            )
                    for key in source_keys:
                        source_owners[key] = (
                            system.id,
                            trial.id,
                            source_id,
                            case.id,
                        )
    return resolved_by_trial


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TrialSpec(_StrictModel):
    """One repeated run. Outputs are paired across systems by trial id."""

    id: str
    outputs: str

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("outputs")
    @classmethod
    def _valid_outputs(cls, value: str) -> str:
        return _safe_relative_path(value)


class SingleSystemSpec(_StrictModel):
    id: str
    mode: Literal["single"]
    trials: list[TrialSpec] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        return _validate_id(value)

    @model_validator(mode="after")
    def _unique_trials(self) -> SingleSystemSpec:
        _validate_trial_set(self.id, self.trials)
        return self


class PanelSystemSpec(_StrictModel):
    id: str
    mode: Literal["panel"]
    members: list[str] = Field(min_length=2)
    quorum: int = Field(ge=1, strict=True)
    trials: list[TrialSpec] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("members")
    @classmethod
    def _valid_members(cls, members: list[str]) -> list[str]:
        normalized = [_validate_id(member) for member in members]
        if len(normalized) != len(set(normalized)):
            raise ValueError("panel member ids must be unique")
        return normalized

    @model_validator(mode="after")
    def _valid_panel(self) -> PanelSystemSpec:
        if self.quorum > len(self.members):
            raise ValueError("panel quorum must not exceed its member count")
        _validate_trial_set(self.id, self.trials)
        return self


def _validate_trial_set(system_id: str, trials: list[TrialSpec]) -> None:
    ids = [trial.id for trial in trials]
    if len(ids) != len(set(ids)):
        raise ValueError(f"system {system_id!r} contains duplicate trial ids")
    paths = [trial.outputs for trial in trials]
    if len(paths) != len(set(paths)):
        raise ValueError(f"system {system_id!r} reuses a trial output directory")


SystemSpec = Annotated[
    SingleSystemSpec | PanelSystemSpec,
    Field(discriminator="mode"),
]


class BudgetSpec(_StrictModel):
    """Mean per-case operating budgets used to mark system eligibility."""

    max_fp_per_case: float | None = Field(default=None, ge=0, strict=True)
    max_latency_s: float | None = Field(default=None, ge=0, strict=True)
    max_tokens: int | None = Field(default=None, ge=0, strict=True)
    max_cost_usd: float | None = Field(default=None, ge=0, strict=True)

    @field_validator("max_fp_per_case", "max_latency_s", "max_tokens", "max_cost_usd")
    @classmethod
    def _finite(cls, value: float | None) -> float | None:
        if value is not None and not isfinite(value):
            raise ValueError("must be finite")
        return value


class ExperimentSpec(_StrictModel):
    """Strict schema for a digest-bound version 2 reviewer experiment."""

    version: Literal[2]
    benchmark: str
    benchmark_sha256: str
    baseline: str
    budgets: BudgetSpec = Field(default_factory=BudgetSpec)
    systems: list[SystemSpec] = Field(min_length=1)
    _source_path: Path | None = PrivateAttr(default=None)

    @field_validator("benchmark")
    @classmethod
    def _valid_benchmark(cls, value: str) -> str:
        return _safe_relative_path(value)

    @field_validator("benchmark_sha256")
    @classmethod
    def _valid_benchmark_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("must be a lowercase SHA-256 digest")
        return value

    @field_validator("baseline")
    @classmethod
    def _valid_baseline(cls, value: str) -> str:
        return _validate_id(value)

    @model_validator(mode="after")
    def _consistent_design(self) -> ExperimentSpec:
        system_ids = [system.id for system in self.systems]
        if len(system_ids) != len(set(system_ids)):
            raise ValueError("experiment contains duplicate system ids")
        if self.baseline not in system_ids:
            raise ValueError("baseline must name one of the declared systems")

        expected_trials = {trial.id for trial in self.systems[0].trials}
        for system in self.systems[1:]:
            actual = {trial.id for trial in system.trials}
            if actual != expected_trials:
                raise ValueError(
                    "every system must declare the same trial ids for paired analysis"
                )
        return self


class OutputMetrics(_StrictModel):
    """Optional operational metadata for one reviewer invocation."""

    latency_s: float | None = Field(default=None, ge=0, strict=True)
    tokens: int | None = Field(default=None, ge=0, strict=True)
    cost_usd: float | None = Field(default=None, ge=0, strict=True)

    @field_validator("latency_s", "cost_usd")
    @classmethod
    def _finite(cls, value: float | None) -> float | None:
        if value is not None and not isfinite(value):
            raise ValueError("must be finite")
        return value


class SummaryStatistic(_StrictModel):
    """Mean and sample standard deviation with an explicit denominator."""

    count: int
    expected_count: int
    completeness: float
    mean: float | None = None
    sample_stdev: float | None = None


class TrialEfficiency(_StrictModel):
    latency_s: SummaryStatistic
    tokens: SummaryStatistic
    cost_usd: SummaryStatistic


class CaseTrialOutput(_StrictModel):
    case_id: str
    findings: list[PredictedFinding] = Field(default_factory=list)
    metrics: OutputMetrics = Field(default_factory=OutputMetrics)
    complete: bool
    expected_source_outputs: int
    complete_source_outputs: int
    issues: list[str] = Field(default_factory=list)


class ExperimentTrialResult(_StrictModel):
    id: str
    output_directory: str
    benchmark: BenchmarkResult
    cases: list[CaseTrialOutput]
    efficiency: TrialEfficiency


class SystemCompleteness(_StrictModel):
    expected_case_trials: int
    complete_case_trials: int
    case_trial_rate: float
    expected_source_outputs: int
    complete_source_outputs: int
    source_output_rate: float
    latency_outputs: int
    latency_rate: float
    token_outputs: int
    token_rate: float
    cost_outputs: int
    cost_rate: float


class StabilitySummary(_StrictModel):
    expected_pair_count: int
    compared_pair_count: int
    completeness: float
    mean_jaccard: float | None = None
    sample_stdev: float | None = None


class SystemStatistics(_StrictModel):
    precision: SummaryStatistic
    recall: SummaryStatistic
    f1: SummaryStatistic
    blocker_major_recall: SummaryStatistic
    severity_accuracy: SummaryStatistic
    false_positives_per_case: SummaryStatistic
    false_positives_per_kloc: SummaryStatistic
    clean_case_accuracy: SummaryStatistic
    latency_s: SummaryStatistic
    tokens: SummaryStatistic
    cost_usd: SummaryStatistic


class BudgetEligibility(_StrictModel):
    eligible: bool
    failures: list[str] = Field(default_factory=list)


class SystemExperimentResult(_StrictModel):
    system_id: str
    mode: Literal["single", "panel"]
    trials: list[ExperimentTrialResult]
    statistics: SystemStatistics
    completeness: SystemCompleteness
    finding_stability: StabilitySummary
    budget: BudgetEligibility


PairOutcome = Literal["win", "tie", "loss", "unavailable"]


class PairedCaseDelta(_StrictModel):
    trial_id: str
    case_id: str
    outcome: PairOutcome
    baseline_f1: float | None = None
    candidate_f1: float | None = None
    delta_f1: float | None = None
    delta_true_positives: int | None = None
    delta_false_positives: int | None = None
    delta_false_negatives: int | None = None
    delta_latency_s: float | None = None
    delta_tokens: float | None = None
    delta_cost_usd: float | None = None


class PairedComparison(_StrictModel):
    baseline_system_id: str
    candidate_system_id: str
    expected_pairs: int
    compared_pairs: int
    unavailable_pairs: int
    wins: int
    ties: int
    losses: int
    f1_delta: SummaryStatistic
    latency_delta_s: SummaryStatistic
    token_delta: SummaryStatistic
    cost_delta_usd: SummaryStatistic
    pairs: list[PairedCaseDelta]


class EfficiencyFrontierPoint(_StrictModel):
    system_id: str
    f1: float
    false_positives_per_case: float
    latency_s: float
    tokens: float
    cost_usd: float
    budget_eligible: bool


class ReviewExperimentResult(_StrictModel):
    version: Literal[2]
    benchmark: str
    benchmark_sha256: str
    baseline: str
    systems: list[SystemExperimentResult]
    paired_comparisons: list[PairedComparison]
    efficiency_frontier: list[EfficiencyFrontierPoint]


class _LoadedOutput(BaseModel):
    predictions: list[PredictedFinding] = Field(default_factory=list)
    metrics: OutputMetrics = Field(default_factory=OutputMetrics)
    complete: bool = False
    issue: str | None = None
    metric_issue: str | None = None


def load_experiment(path: str | Path) -> ExperimentSpec:
    """Load and validate a strict version 2 experiment YAML file."""

    experiment_path = Path(os.path.abspath(Path(path).expanduser()))
    encoded = _stable_file_bytes(
        experiment_path,
        maximum_bytes=MAX_EXPERIMENT_BYTES,
    )
    try:
        experiment_text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("experiment must be valid UTF-8") from exc
    raw = yaml.load(experiment_text, Loader=_UniqueKeySafeLoader)
    if raw is None:
        raw = {}
    spec = ExperimentSpec.model_validate(raw)
    root = experiment_path.parent
    benchmark = _resolve_inside(root, spec.benchmark)
    if not benchmark.is_file():
        raise ValueError(f"benchmark file not found: {spec.benchmark}")
    benchmark_bytes = _stable_file_bytes(
        benchmark, maximum_bytes=MAX_BENCHMARK_BYTES
    )
    if hashlib.sha256(benchmark_bytes).hexdigest() != spec.benchmark_sha256:
        raise ValueError("benchmark SHA-256 does not match the experiment spec")
    manifest = parse_manifest_bytes(benchmark_bytes)
    _resolved_output_roots(spec, root, manifest)
    spec._source_path = experiment_path
    return spec


def _load_output(path: Path) -> _LoadedOutput:
    try:
        encoded = _stable_file_bytes(path, maximum_bytes=MAX_REVIEW_OUTPUT_BYTES)
    except FileNotFoundError:
        return _LoadedOutput(issue="output file not found")
    except (OSError, ValueError) as exc:
        return _LoadedOutput(issue=f"could not read output: {type(exc).__name__}")
    try:
        raw = json.loads(
            encoded,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        predictions, incomplete_reason = _predictions_from_raw(raw, path)
    except (json.JSONDecodeError, _DuplicateJsonKeyError, ValueError) as exc:
        return _LoadedOutput(issue=str(exc).replace(str(path), path.name))
    if incomplete_reason is None:
        try:
            # Revalidate defaults as explicit values.  The benchmark model
            # intentionally has permissive defaults for compatibility, but an
            # empty default file cannot form a safe panel identity.
            predictions = [
                PredictedFinding.model_validate(prediction.model_dump())
                for prediction in predictions
            ]
        except ValueError as exc:
            predictions = []
            incomplete_reason = f"finding identity is incomplete: {exc}"

    metrics = OutputMetrics()
    metric_issue = None
    try:
        if not isinstance(raw, dict):
            raise ValueError("output must contain a JSON object")
        metrics_raw = raw.get("metrics")
        if metrics_raw is not None:
            metrics = OutputMetrics.model_validate(metrics_raw)
    except ValueError as exc:
        metric_issue = f"invalid metrics: {exc}"

    return _LoadedOutput(
        predictions=predictions,
        metrics=metrics,
        complete=incomplete_reason is None,
        issue=incomplete_reason,
        metric_issue=metric_issue,
    )


def _severity_key(severity: str) -> tuple[int, str]:
    normalized = severity.strip().casefold()
    return _SEVERITY_RANK.get(normalized, 0), normalized


def _identity(finding: PredictedFinding) -> tuple[str, str, int | None]:
    return (_normalize_file(finding.file), finding.category, finding.line)


def _identity_sort_key(
    identity: tuple[str, str, int | None],
) -> tuple[str, str, bool, int]:
    file, category, line = identity
    return file, category, line is None, line if line is not None else -1


def _member_votes(
    findings: list[PredictedFinding],
) -> dict[tuple[str, str, int | None], PredictedFinding]:
    """Deduplicate one member so it cannot cast repeated votes."""

    votes: dict[tuple[str, str, int | None], PredictedFinding] = {}
    for finding in findings:
        identity = _identity(finding)
        existing = votes.get(identity)
        if existing is None or (_severity_key(finding.severity), finding.confidence) > (
            _severity_key(existing.severity),
            existing.confidence,
        ):
            votes[identity] = finding
    return votes


def _panel_findings(
    member_findings: list[list[PredictedFinding]], quorum: int
) -> list[PredictedFinding]:
    votes_by_identity: dict[tuple[str, str, int | None], list[PredictedFinding]] = {}
    for findings in member_findings:
        for identity, finding in _member_votes(findings).items():
            votes_by_identity.setdefault(identity, []).append(finding)

    panel: list[PredictedFinding] = []
    for identity in sorted(votes_by_identity, key=_identity_sort_key):
        votes = votes_by_identity[identity]
        if len(votes) < quorum:
            continue
        severity_counts = Counter(vote.severity.strip().casefold() for vote in votes)
        severity = max(
            severity_counts,
            key=lambda candidate: (
                severity_counts[candidate],
                _severity_key(candidate),
            ),
        )
        file, category, line = identity
        panel.append(
            PredictedFinding(
                severity=severity,
                category=category,
                file=file,
                line=line,
                confidence=fmean(vote.confidence for vote in votes),
            )
        )
    return panel


def _combine_panel_metrics(outputs: list[_LoadedOutput]) -> OutputMetrics:
    latencies = [output.metrics.latency_s for output in outputs]
    tokens = [output.metrics.tokens for output in outputs]
    costs = [output.metrics.cost_usd for output in outputs]
    return OutputMetrics(
        latency_s=(
            max(value for value in latencies if value is not None)
            if all(value is not None for value in latencies)
            else None
        ),
        tokens=(
            sum(value for value in tokens if value is not None)
            if all(value is not None for value in tokens)
            else None
        ),
        cost_usd=(
            sum(value for value in costs if value is not None)
            if all(value is not None for value in costs)
            else None
        ),
    )


def _summary(values: list[float | int], expected_count: int) -> SummaryStatistic:
    numeric = [float(value) for value in values]
    return SummaryStatistic(
        count=len(numeric),
        expected_count=expected_count,
        completeness=(len(numeric) / expected_count if expected_count else 1.0),
        mean=fmean(numeric) if numeric else None,
        sample_stdev=stdev(numeric) if len(numeric) >= 2 else None,
    )


def _trial_efficiency(cases: list[CaseTrialOutput]) -> TrialEfficiency:
    expected = len(cases)
    return TrialEfficiency(
        latency_s=_summary(
            [
                case.metrics.latency_s
                for case in cases
                if case.metrics.latency_s is not None
            ],
            expected,
        ),
        tokens=_summary(
            [case.metrics.tokens for case in cases if case.metrics.tokens is not None],
            expected,
        ),
        cost_usd=_summary(
            [
                case.metrics.cost_usd
                for case in cases
                if case.metrics.cost_usd is not None
            ],
            expected,
        ),
    )


def _write_normalized_output(
    directory: Path,
    case_id: str,
    findings: list[PredictedFinding] | None,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "findings": (
            [finding.model_dump(mode="json") for finding in findings]
            if findings is not None
            else None
        )
    }
    (directory / f"{case_id}.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )


def _single_trial(
    manifest: BenchmarkManifest,
    trial: TrialSpec,
    outputs_root: Path,
    normalized_dir: Path,
) -> ExperimentTrialResult:
    case_outputs: list[CaseTrialOutput] = []
    for case in manifest.cases:
        source_path = _resolve_inside(outputs_root, f"{case.id}.json")
        loaded = _load_output(source_path)
        issues = [issue for issue in (loaded.issue, loaded.metric_issue) if issue]
        case_outputs.append(
            CaseTrialOutput(
                case_id=case.id,
                findings=loaded.predictions,
                metrics=loaded.metrics,
                complete=loaded.complete,
                expected_source_outputs=1,
                complete_source_outputs=int(loaded.complete),
                issues=issues,
            )
        )
        if loaded.complete:
            _write_normalized_output(normalized_dir, case.id, loaded.predictions)
        elif source_path.is_file():
            _write_normalized_output(normalized_dir, case.id, None)

    benchmark = score_benchmark(manifest, normalized_dir)
    _rewrite_prediction_paths(benchmark, trial.outputs)
    return ExperimentTrialResult(
        id=trial.id,
        output_directory=trial.outputs,
        benchmark=benchmark,
        cases=case_outputs,
        efficiency=_trial_efficiency(case_outputs),
    )


def _panel_trial(
    manifest: BenchmarkManifest,
    system: PanelSystemSpec,
    trial: TrialSpec,
    outputs_root: Path,
    normalized_dir: Path,
) -> ExperimentTrialResult:
    case_outputs: list[CaseTrialOutput] = []
    for case in manifest.cases:
        member_outputs = [
            _load_output(_resolve_inside(outputs_root, f"{member}/{case.id}.json"))
            for member in system.members
        ]
        findings = _panel_findings(
            [output.predictions for output in member_outputs if output.complete],
            system.quorum,
        )
        issues = []
        for member, output in zip(system.members, member_outputs, strict=True):
            if output.issue:
                issues.append(f"{member}: {output.issue}")
            if output.metric_issue:
                issues.append(f"{member}: {output.metric_issue}")
        complete_count = sum(output.complete for output in member_outputs)
        case_outputs.append(
            CaseTrialOutput(
                case_id=case.id,
                findings=findings,
                metrics=_combine_panel_metrics(member_outputs),
                complete=complete_count == len(system.members),
                expected_source_outputs=len(system.members),
                complete_source_outputs=complete_count,
                issues=issues,
            )
        )
        _write_normalized_output(
            normalized_dir,
            case.id,
            findings if complete_count == len(system.members) else None,
        )

    benchmark = score_benchmark(manifest, normalized_dir)
    _rewrite_prediction_paths(benchmark, trial.outputs)
    return ExperimentTrialResult(
        id=trial.id,
        output_directory=trial.outputs,
        benchmark=benchmark,
        cases=case_outputs,
        efficiency=_trial_efficiency(case_outputs),
    )


def _rewrite_prediction_paths(result: BenchmarkResult, logical_root: str) -> None:
    for case in result.cases:
        case.prediction_file = f"{logical_root}/{case.case_id}.json"


def _quality_values(trials: list[ExperimentTrialResult], attribute: str) -> list[float]:
    values = []
    for trial in trials:
        if any(not case.complete for case in trial.cases):
            continue
        value = getattr(trial.benchmark.metrics, attribute)
        if value is not None:
            values.append(value)
    return values


def _system_statistics(trials: list[ExperimentTrialResult]) -> SystemStatistics:
    expected_trials = len(trials)
    case_outputs = [case for trial in trials for case in trial.cases]
    expected_outputs = len(case_outputs)
    return SystemStatistics(
        precision=_summary(_quality_values(trials, "precision"), expected_trials),
        recall=_summary(_quality_values(trials, "recall"), expected_trials),
        f1=_summary(_quality_values(trials, "f1"), expected_trials),
        blocker_major_recall=_summary(
            _quality_values(trials, "blocker_major_recall"), expected_trials
        ),
        severity_accuracy=_summary(
            _quality_values(trials, "severity_accuracy"), expected_trials
        ),
        false_positives_per_case=_summary(
            _quality_values(trials, "false_positives_per_case"), expected_trials
        ),
        false_positives_per_kloc=_summary(
            _quality_values(trials, "false_positives_per_kloc"), expected_trials
        ),
        clean_case_accuracy=_summary(
            _quality_values(trials, "clean_case_accuracy"), expected_trials
        ),
        latency_s=_summary(
            [
                case.metrics.latency_s
                for case in case_outputs
                if case.metrics.latency_s is not None
            ],
            expected_outputs,
        ),
        tokens=_summary(
            [
                case.metrics.tokens
                for case in case_outputs
                if case.metrics.tokens is not None
            ],
            expected_outputs,
        ),
        cost_usd=_summary(
            [
                case.metrics.cost_usd
                for case in case_outputs
                if case.metrics.cost_usd is not None
            ],
            expected_outputs,
        ),
    )


def _system_completeness(
    trials: list[ExperimentTrialResult],
) -> SystemCompleteness:
    cases = [case for trial in trials for case in trial.cases]
    expected_case_trials = len(cases)
    expected_sources = sum(case.expected_source_outputs for case in cases)
    complete_sources = sum(case.complete_source_outputs for case in cases)
    complete_cases = sum(case.complete for case in cases)
    latency_count = sum(case.metrics.latency_s is not None for case in cases)
    token_count = sum(case.metrics.tokens is not None for case in cases)
    cost_count = sum(case.metrics.cost_usd is not None for case in cases)

    def rate(count: int, total: int) -> float:
        return count / total if total else 1.0

    return SystemCompleteness(
        expected_case_trials=expected_case_trials,
        complete_case_trials=complete_cases,
        case_trial_rate=rate(complete_cases, expected_case_trials),
        expected_source_outputs=expected_sources,
        complete_source_outputs=complete_sources,
        source_output_rate=rate(complete_sources, expected_sources),
        latency_outputs=latency_count,
        latency_rate=rate(latency_count, expected_case_trials),
        token_outputs=token_count,
        token_rate=rate(token_count, expected_case_trials),
        cost_outputs=cost_count,
        cost_rate=rate(cost_count, expected_case_trials),
    )


def _jaccard(
    left: set[tuple[str, str, int | None]],
    right: set[tuple[str, str, int | None]],
) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _finding_stability(
    manifest: BenchmarkManifest, trials: list[ExperimentTrialResult]
) -> StabilitySummary:
    expected = len(manifest.cases) * (len(trials) * (len(trials) - 1) // 2)
    by_trial = {
        trial.id: {case.case_id: case for case in trial.cases} for trial in trials
    }
    values: list[float] = []
    for case in manifest.cases:
        for left, right in combinations(trials, 2):
            left_case = by_trial[left.id][case.id]
            right_case = by_trial[right.id][case.id]
            if not left_case.complete or not right_case.complete:
                continue
            left_set = {_identity(finding) for finding in left_case.findings}
            right_set = {_identity(finding) for finding in right_case.findings}
            values.append(_jaccard(left_set, right_set))
    return StabilitySummary(
        expected_pair_count=expected,
        compared_pair_count=len(values),
        completeness=len(values) / expected if expected else 1.0,
        mean_jaccard=fmean(values) if values else None,
        sample_stdev=stdev(values) if len(values) >= 2 else None,
    )


def _budget_eligibility(
    budgets: BudgetSpec,
    statistics: SystemStatistics,
    completeness: SystemCompleteness,
) -> BudgetEligibility:
    failures: list[str] = []
    if completeness.source_output_rate < 1 or completeness.case_trial_rate < 1:
        failures.append("review outputs are incomplete")

    checks = (
        (
            "false positives per case",
            statistics.false_positives_per_case,
            budgets.max_fp_per_case,
        ),
        ("latency_s", statistics.latency_s, budgets.max_latency_s),
        ("tokens", statistics.tokens, budgets.max_tokens),
        ("cost_usd", statistics.cost_usd, budgets.max_cost_usd),
    )
    for name, statistic, limit in checks:
        if limit is None:
            continue
        if statistic.completeness < 1 or statistic.mean is None:
            failures.append(f"{name} is incomplete")
        elif statistic.mean > limit:
            failures.append(f"{name} {statistic.mean:g} exceeds {limit:g}")
    return BudgetEligibility(eligible=not failures, failures=failures)


def _case_f1(case: CaseResult) -> float:
    denominator = 2 * case.tp + case.fp + case.fn
    return 2 * case.tp / denominator if denominator else 1.0


def _optional_delta(
    left: float | int | None, right: float | int | None
) -> float | None:
    if left is None or right is None:
        return None
    return float(left) - float(right)


def _paired_comparison(
    baseline: SystemExperimentResult,
    candidate: SystemExperimentResult,
) -> PairedComparison:
    baseline_trials = {trial.id: trial for trial in baseline.trials}
    pairs: list[PairedCaseDelta] = []
    for candidate_trial in candidate.trials:
        baseline_trial = baseline_trials[candidate_trial.id]
        baseline_scores = {
            case.case_id: case for case in baseline_trial.benchmark.cases
        }
        candidate_scores = {
            case.case_id: case for case in candidate_trial.benchmark.cases
        }
        baseline_outputs = {case.case_id: case for case in baseline_trial.cases}
        for case_output in candidate_trial.cases:
            case_id = case_output.case_id
            baseline_output = baseline_outputs[case_id]
            if not baseline_output.complete or not case_output.complete:
                pairs.append(
                    PairedCaseDelta(
                        trial_id=candidate_trial.id,
                        case_id=case_id,
                        outcome="unavailable",
                    )
                )
                continue

            baseline_case = baseline_scores[case_id]
            candidate_case = candidate_scores[case_id]
            baseline_f1 = _case_f1(baseline_case)
            candidate_f1 = _case_f1(candidate_case)
            delta_f1 = candidate_f1 - baseline_f1
            if delta_f1 > 1e-12:
                outcome: PairOutcome = "win"
            elif delta_f1 < -1e-12:
                outcome = "loss"
            else:
                outcome = "tie"
            pairs.append(
                PairedCaseDelta(
                    trial_id=candidate_trial.id,
                    case_id=case_id,
                    outcome=outcome,
                    baseline_f1=baseline_f1,
                    candidate_f1=candidate_f1,
                    delta_f1=delta_f1,
                    delta_true_positives=candidate_case.tp - baseline_case.tp,
                    delta_false_positives=candidate_case.fp - baseline_case.fp,
                    delta_false_negatives=candidate_case.fn - baseline_case.fn,
                    delta_latency_s=_optional_delta(
                        case_output.metrics.latency_s,
                        baseline_output.metrics.latency_s,
                    ),
                    delta_tokens=_optional_delta(
                        case_output.metrics.tokens, baseline_output.metrics.tokens
                    ),
                    delta_cost_usd=_optional_delta(
                        case_output.metrics.cost_usd,
                        baseline_output.metrics.cost_usd,
                    ),
                )
            )

    expected = len(pairs)
    compared = [pair for pair in pairs if pair.outcome != "unavailable"]
    return PairedComparison(
        baseline_system_id=baseline.system_id,
        candidate_system_id=candidate.system_id,
        expected_pairs=expected,
        compared_pairs=len(compared),
        unavailable_pairs=expected - len(compared),
        wins=sum(pair.outcome == "win" for pair in compared),
        ties=sum(pair.outcome == "tie" for pair in compared),
        losses=sum(pair.outcome == "loss" for pair in compared),
        f1_delta=_summary(
            [pair.delta_f1 for pair in pairs if pair.delta_f1 is not None], expected
        ),
        latency_delta_s=_summary(
            [
                pair.delta_latency_s
                for pair in pairs
                if pair.delta_latency_s is not None
            ],
            expected,
        ),
        token_delta=_summary(
            [pair.delta_tokens for pair in pairs if pair.delta_tokens is not None],
            expected,
        ),
        cost_delta_usd=_summary(
            [pair.delta_cost_usd for pair in pairs if pair.delta_cost_usd is not None],
            expected,
        ),
        pairs=pairs,
    )


def _dominates(left: EfficiencyFrontierPoint, right: EfficiencyFrontierPoint) -> bool:
    no_worse = (
        left.f1 >= right.f1
        and left.false_positives_per_case <= right.false_positives_per_case
        and left.latency_s <= right.latency_s
        and left.tokens <= right.tokens
        and left.cost_usd <= right.cost_usd
    )
    strictly_better = (
        left.f1 > right.f1
        or left.false_positives_per_case < right.false_positives_per_case
        or left.latency_s < right.latency_s
        or left.tokens < right.tokens
        or left.cost_usd < right.cost_usd
    )
    return no_worse and strictly_better


def _efficiency_frontier(
    systems: list[SystemExperimentResult],
) -> list[EfficiencyFrontierPoint]:
    points: list[EfficiencyFrontierPoint] = []
    for system in systems:
        if not system.budget.eligible:
            continue
        statistics = system.statistics
        values = (
            statistics.f1.mean,
            statistics.false_positives_per_case.mean,
            statistics.latency_s.mean,
            statistics.tokens.mean,
            statistics.cost_usd.mean,
        )
        if (
            any(value is None for value in values)
            or system.completeness.case_trial_rate < 1
            or system.completeness.source_output_rate < 1
        ):
            continue
        f1, fp, latency, tokens, cost = values
        assert all(value is not None for value in values)
        points.append(
            EfficiencyFrontierPoint(
                system_id=system.system_id,
                f1=f1,
                false_positives_per_case=fp,
                latency_s=latency,
                tokens=tokens,
                cost_usd=cost,
                budget_eligible=system.budget.eligible,
            )
        )
    return [
        point
        for point in points
        if not any(
            _dominates(other, point)
            for other in points
            if other.system_id != point.system_id
        )
    ]


def run_experiment(
    experiment: ExperimentSpec | str | Path,
    *,
    base_dir: str | Path | None = None,
) -> ReviewExperimentResult:
    """Score every trial and return deterministic experiment analytics.

    Pass a YAML path, an object returned by :func:`load_experiment`, or a
    manually constructed :class:`ExperimentSpec` together with ``base_dir``.
    """

    if isinstance(experiment, (str, Path)):
        spec = load_experiment(experiment)
    else:
        spec = experiment

    if base_dir is not None:
        root = Path(base_dir).resolve()
    elif spec._source_path is not None:
        root = spec._source_path.parent
    else:
        raise ValueError(
            "base_dir is required for an ExperimentSpec not loaded from YAML"
        )

    benchmark_path = _resolve_inside(root, spec.benchmark)
    benchmark_bytes = _stable_file_bytes(
        benchmark_path, maximum_bytes=MAX_BENCHMARK_BYTES
    )
    if hashlib.sha256(benchmark_bytes).hexdigest() != spec.benchmark_sha256:
        raise ValueError("benchmark changed after experiment validation")
    manifest = parse_manifest_bytes(benchmark_bytes)
    output_roots = _resolved_output_roots(spec, root, manifest)
    system_results: list[SystemExperimentResult] = []

    with TemporaryDirectory(prefix="agent-eval-review-experiment-") as temp:
        temp_root = Path(temp)
        for system_index, system in enumerate(spec.systems):
            trial_results: list[ExperimentTrialResult] = []
            for trial_index, trial in enumerate(system.trials):
                outputs_root = output_roots[(system.id, trial.id)]
                normalized_dir = temp_root / str(system_index) / str(trial_index)
                if system.mode == "single":
                    result = _single_trial(
                        manifest, trial, outputs_root, normalized_dir
                    )
                else:
                    result = _panel_trial(
                        manifest, system, trial, outputs_root, normalized_dir
                    )
                trial_results.append(result)

            statistics = _system_statistics(trial_results)
            completeness = _system_completeness(trial_results)
            system_results.append(
                SystemExperimentResult(
                    system_id=system.id,
                    mode=system.mode,
                    trials=trial_results,
                    statistics=statistics,
                    completeness=completeness,
                    finding_stability=_finding_stability(manifest, trial_results),
                    budget=_budget_eligibility(spec.budgets, statistics, completeness),
                )
            )

    by_id = {system.system_id: system for system in system_results}
    baseline = by_id[spec.baseline]
    paired = [
        _paired_comparison(baseline, system)
        for system in system_results
        if system.system_id != spec.baseline
    ]
    return ReviewExperimentResult(
        version=2,
        benchmark=spec.benchmark,
        benchmark_sha256=spec.benchmark_sha256,
        baseline=spec.baseline,
        systems=system_results,
        paired_comparisons=paired,
        efficiency_frontier=_efficiency_frontier(system_results),
    )
