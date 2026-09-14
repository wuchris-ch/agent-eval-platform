"""Deterministic evaluation for vendor-neutral pull-request review findings.

The benchmark intentionally uses only stable, inspectable matching rules.  A
prediction matches an expected finding when its normalized repository-relative
file and category are exact matches and its line falls inside the expected
range.  Maximum bipartite matching prevents input order from changing the
number of matches.
"""

from __future__ import annotations

import json
import posixpath
import re
from math import sqrt
from pathlib import Path
from typing import Any, Literal, NoReturn

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .limits import read_stable_bounded_file

Severity = Literal["blocker", "major", "minor", "info"]
CaseStatus = Literal[
    "scored",
    "missing_prediction",
    "incomplete_prediction",
]
_HIGH_SEVERITIES = frozenset(("blocker", "major"))
_WILSON_Z_95 = 1.959963984540054
_SAFE_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_URI_OR_DRIVE_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
MAX_BENCHMARK_BYTES = 16 * 1024 * 1024
MAX_PREDICTION_BYTES = 16 * 1024 * 1024


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = (
                "<<"
                if key_node.tag == "tag:yaml.org,2002:merge"
                else self.construct_object(key_node, deep=deep)
            )
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found unhashable key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
        return super().construct_mapping(node, deep=deep)


class _DuplicateJsonKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(f"found duplicate key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    """Reject JavaScript numeric extensions that are not valid JSON."""

    raise ValueError(f"non-finite JSON number {value!r} is not allowed")


def _normalize_file(path: str) -> str:
    """Normalize separators and redundant relative path components."""

    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        return ""
    return posixpath.normpath(normalized)


def _validate_repository_relative_file(path: str) -> str:
    candidate = path.strip().replace("\\", "/")
    normalized = _normalize_file(path)
    if (
        candidate.startswith("/") or _URI_OR_DRIVE_PREFIX.match(candidate) or normalized in ("", ".") or normalized.startswith(("/", "../")) or _URI_OR_DRIVE_PREFIX.match(normalized) or normalized == ".."
    ):
        raise ValueError("must be a repository-relative path")
    return path


class ExpectedFinding(BaseModel):
    """A single ground-truth review finding."""

    model_config = ConfigDict(extra="forbid")

    id: str
    severity: Severity
    category: str
    file: str
    line_start: int = Field(ge=1, strict=True)
    line_end: int = Field(
        default_factory=lambda validated_data: validated_data.get("line_start", 1),
        ge=1,
        strict=True,
    )

    @field_validator("id", "category", "file")
    @classmethod
    def _require_nonempty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("file")
    @classmethod
    def _require_repository_relative_file(cls, value: str) -> str:
        return _validate_repository_relative_file(value)

    @model_validator(mode="after")
    def _validate_line_range(self) -> ExpectedFinding:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self


class BenchmarkCase(BaseModel):
    """One pull-request review benchmark case."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    description: str | None = None
    changed_lines: int | None = Field(default=None, ge=0, strict=True)
    expected_findings: list[ExpectedFinding] = Field(
        default_factory=list,
        validation_alias=AliasChoices(
            "expected_findings",
            "expected",
            "findings",
        ),
    )

    @field_validator("id")
    @classmethod
    def _require_nonempty_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        if not _SAFE_CASE_ID.fullmatch(value):
            raise ValueError(
                "must contain only letters, digits, dots, underscores, and hyphens"
            )
        return value

    @model_validator(mode="after")
    def _validate_expected_findings(self) -> BenchmarkCase:
        finding_ids = [finding.id for finding in self.expected_findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError(f"case {self.id!r} contains duplicate finding ids")

        for index, finding in enumerate(self.expected_findings):
            for other in self.expected_findings[index + 1 :]:
                if (
                    _normalize_file(finding.file) == _normalize_file(other.file)
                    and finding.category == other.category
                    and finding.line_start <= other.line_end
                    and other.line_start <= finding.line_end
                ):
                    raise ValueError(
                        f"case {self.id!r} contains ambiguous overlapping ranges "
                        f"for findings {finding.id!r} and {other.id!r}"
                    )
        return self


class BenchmarkManifest(BaseModel):
    """Top-level YAML benchmark manifest."""

    model_config = ConfigDict(extra="forbid")

    cases: list[BenchmarkCase]

    @model_validator(mode="after")
    def _validate_unique_case_ids(self) -> BenchmarkManifest:
        case_ids = [case.id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("manifest contains duplicate case ids")
        return self


class PredictedFinding(BaseModel):
    """Normalized subset shared by native and generic prediction formats."""

    model_config = ConfigDict(extra="ignore")

    severity: str
    category: str = ""
    file: str = ""
    line: int | None = Field(default=None, strict=True)
    confidence: float = Field(default=1.0, ge=0, le=1, allow_inf_nan=False)

    @field_validator("file")
    @classmethod
    def _require_repository_relative_file(cls, value: str) -> str:
        return _validate_repository_relative_file(value)


class FindingMatch(BaseModel):
    """A matched expected/predicted pair."""

    expected_id: str
    prediction_index: int
    expected_severity: Severity
    predicted_severity: str
    severity_correct: bool


class ExpectedFindingResult(BaseModel):
    """Scoring disposition for one expected finding."""

    finding: ExpectedFinding
    matched: bool
    prediction_index: int | None = None
    severity_correct: bool | None = None


class PredictedFindingResult(BaseModel):
    """Scoring disposition for one active prediction."""

    prediction_index: int
    finding: PredictedFinding
    matched: bool
    expected_id: str | None = None


class CaseResult(BaseModel):
    """Detailed deterministic result for one manifest case."""

    case_id: str
    description: str | None = None
    changed_lines: int | None
    prediction_file: str
    status: CaseStatus
    note: str | None = None
    expected_count: int
    prediction_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    matches: list[FindingMatch] = Field(default_factory=list)
    expected_results: list[ExpectedFindingResult] = Field(default_factory=list)
    prediction_results: list[PredictedFindingResult] = Field(default_factory=list)

    @property
    def tp(self) -> int:
        return self.true_positives

    @property
    def fp(self) -> int:
        return self.false_positives

    @property
    def fn(self) -> int:
        return self.false_negatives


class WilsonInterval(BaseModel):
    """A two-sided 95 percent Wilson score interval."""

    confidence: float = 0.95
    lower: float
    upper: float


class AggregateMetrics(BaseModel):
    """Aggregate benchmark metrics and their explicit denominators."""

    case_count: int
    scored_case_count: int
    expected_finding_count: int
    prediction_count: int
    changed_lines: int | None
    true_positives: int
    false_positives: int
    false_negatives: int

    precision: float | None
    precision_denominator: int
    recall: float | None
    recall_denominator: int
    f1: float | None
    f1_denominator: int

    blocker_major_recall: float | None
    blocker_major_denominator: int
    severity_accuracy: float | None
    severity_accuracy_denominator: int

    false_positives_per_case: float | None
    false_positives_per_kloc: float | None
    clean_case_accuracy: float | None
    clean_case_denominator: int
    clean_cases_correct: int

    precision_wilson_95: WilsonInterval | None
    recall_wilson_95: WilsonInterval | None

    @property
    def tp(self) -> int:
        return self.true_positives

    @property
    def fp(self) -> int:
        return self.false_positives

    @property
    def fn(self) -> int:
        return self.false_negatives


class BenchmarkResult(BaseModel):
    """JSON-serializable benchmark result."""

    cases: list[CaseResult]
    metrics: AggregateMetrics


def parse_manifest_bytes(value: bytes) -> BenchmarkManifest:
    """Parse one already-captured benchmark manifest byte snapshot."""

    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("benchmark manifest must be valid UTF-8") from exc
    raw = yaml.load(text, Loader=_UniqueKeySafeLoader)
    if raw is None:
        raw = {}
    return BenchmarkManifest.model_validate(raw)


def load_manifest(path: str | Path) -> BenchmarkManifest:
    """Load and validate a YAML benchmark manifest."""

    return parse_manifest_bytes(
        read_stable_bounded_file(path, maximum_bytes=MAX_BENCHMARK_BYTES)
    )


def _predictions_from_raw(
    raw: object, path: Path
) -> tuple[list[PredictedFinding], str | None]:

    if not isinstance(raw, dict):
        raise ValueError(f"prediction file {path} must contain a JSON object")

    native = "llm" in raw
    container = raw.get("llm") if native else raw
    if container is None and native:
        return [], "native report field 'llm' is null"
    if not isinstance(container, dict):
        location = "llm" if native else "root"
        raise ValueError(f"prediction file {path} field {location!r} must be an object")

    items = container.get("findings")
    if items is None:
        return [], "findings payload is missing or null"
    if not isinstance(items, list):
        raise ValueError(f"prediction file {path} field 'findings' must be a list")

    predictions: list[PredictedFinding] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(
                f"prediction file {path} finding {index} must be an object"
            )
        if native:
            severity = str(item.get("severity") or "").strip().casefold()
            verdict = str(item.get("verdict") or "").strip().casefold()
            if item.get("verified") is not True or verdict == "rejected":
                continue
            if severity in _HIGH_SEVERITIES and verdict != "confirmed":
                continue
        normalized_item = dict(item)
        if normalized_item.get("confidence") is None:
            normalized_item["confidence"] = 1.0
        predictions.append(PredictedFinding.model_validate(normalized_item))
    return predictions, None


def _load_predictions(path: Path) -> tuple[list[PredictedFinding], str | None]:
    try:
        raw = json.loads(
            read_stable_bounded_file(
                path,
                maximum_bytes=MAX_PREDICTION_BYTES,
            ),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, json.JSONDecodeError, _DuplicateJsonKeyError) as exc:
        raise ValueError(f"could not load prediction file {path}: {exc}") from exc
    return _predictions_from_raw(raw, path)


def _prediction_sort_key(
    indexed_prediction: tuple[int, PredictedFinding],
) -> tuple[Any, ...]:
    index, prediction = indexed_prediction
    return (
        _normalize_file(prediction.file),
        prediction.category,
        prediction.line is None,
        prediction.line if prediction.line is not None else -1,
        prediction.severity,
        prediction.confidence,
        index,
    )


def _expected_sort_key(
    indexed_finding: tuple[int, ExpectedFinding],
) -> tuple[Any, ...]:
    index, finding = indexed_finding
    return (
        finding.id,
        _normalize_file(finding.file),
        finding.category,
        finding.line_start,
        finding.line_end,
        finding.severity,
        index,
    )


def _is_candidate(
    expected: ExpectedFinding,
    predicted: PredictedFinding,
    *,
    require_exact_severity: bool = False,
) -> bool:
    return (
        predicted.line is not None
        and _normalize_file(predicted.file) == _normalize_file(expected.file)
        and predicted.category == expected.category
        and (
            not require_exact_severity
            or predicted.severity == expected.severity
        )
        and expected.line_start <= predicted.line <= expected.line_end
    )


def _maximum_matching(
    expected: list[ExpectedFinding],
    predictions: list[PredictedFinding],
    *,
    require_exact_severity: bool = False,
) -> dict[int, int]:
    """Return expected-index -> prediction-index maximum bipartite matching."""

    expected_order = [
        index for index, _ in sorted(enumerate(expected), key=_expected_sort_key)
    ]
    prediction_order = [
        index
        for index, _ in sorted(enumerate(predictions), key=_prediction_sort_key)
    ]
    adjacency = {
        expected_index: [
            prediction_index
            for prediction_index in prediction_order
            if _is_candidate(
                expected[expected_index],
                predictions[prediction_index],
                require_exact_severity=require_exact_severity,
            )
        ]
        for expected_index in expected_order
    }

    prediction_to_expected: dict[int, int] = {}

    def augment(expected_index: int, seen_predictions: set[int]) -> bool:
        for prediction_index in adjacency[expected_index]:
            if prediction_index in seen_predictions:
                continue
            seen_predictions.add(prediction_index)
            current_expected = prediction_to_expected.get(prediction_index)
            if current_expected is None or augment(
                current_expected, seen_predictions
            ):
                prediction_to_expected[prediction_index] = expected_index
                return True
        return False

    for expected_index in expected_order:
        augment(expected_index, set())

    return {
        expected_index: prediction_index
        for prediction_index, expected_index in prediction_to_expected.items()
    }


def _score_case(
    case: BenchmarkCase,
    prediction_file: Path,
    predictions: list[PredictedFinding],
    status: CaseStatus,
    note: str | None,
    *,
    require_exact_severity: bool = False,
) -> CaseResult:
    expected_to_prediction = _maximum_matching(
        case.expected_findings,
        predictions,
        require_exact_severity=require_exact_severity,
    )
    prediction_to_expected = {
        prediction_index: expected_index
        for expected_index, prediction_index in expected_to_prediction.items()
    }

    expected_results: list[ExpectedFindingResult] = []
    matches: list[FindingMatch] = []
    for expected_index, expected in enumerate(case.expected_findings):
        prediction_index = expected_to_prediction.get(expected_index)
        if prediction_index is None:
            expected_results.append(
                ExpectedFindingResult(finding=expected, matched=False)
            )
            continue
        predicted = predictions[prediction_index]
        severity_correct = expected.severity == predicted.severity
        expected_results.append(
            ExpectedFindingResult(
                finding=expected,
                matched=True,
                prediction_index=prediction_index,
                severity_correct=severity_correct,
            )
        )
        matches.append(
            FindingMatch(
                expected_id=expected.id,
                prediction_index=prediction_index,
                expected_severity=expected.severity,
                predicted_severity=predicted.severity,
                severity_correct=severity_correct,
            )
        )

    prediction_results: list[PredictedFindingResult] = []
    for prediction_index, prediction in enumerate(predictions):
        expected_index = prediction_to_expected.get(prediction_index)
        prediction_results.append(
            PredictedFindingResult(
                prediction_index=prediction_index,
                finding=prediction,
                matched=expected_index is not None,
                expected_id=(
                    case.expected_findings[expected_index].id
                    if expected_index is not None
                    else None
                ),
            )
        )

    true_positives = len(expected_to_prediction)
    return CaseResult(
        case_id=case.id,
        description=case.description,
        changed_lines=case.changed_lines,
        prediction_file=str(prediction_file),
        status=status,
        note=note,
        expected_count=len(case.expected_findings),
        prediction_count=len(predictions),
        true_positives=true_positives,
        false_positives=len(predictions) - true_positives,
        false_negatives=len(case.expected_findings) - true_positives,
        matches=sorted(matches, key=lambda match: match.expected_id),
        expected_results=expected_results,
        prediction_results=prediction_results,
    )


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _wilson_interval(successes: int, total: int) -> WilsonInterval | None:
    if total == 0:
        return None
    proportion = successes / total
    z_squared = _WILSON_Z_95**2
    denominator = 1 + z_squared / total
    center = (proportion + z_squared / (2 * total)) / denominator
    margin = (
        _WILSON_Z_95
        * sqrt(
            proportion * (1 - proportion) / total
            + z_squared / (4 * total**2)
        )
        / denominator
    )
    return WilsonInterval(
        lower=max(0.0, center - margin),
        upper=min(1.0, center + margin),
    )


def _aggregate(cases: list[CaseResult]) -> AggregateMetrics:
    case_count = len(cases)
    scored_cases = [case for case in cases if case.status == "scored"]
    scored_case_count = len(scored_cases)
    expected_count = sum(case.expected_count for case in cases)
    prediction_count = sum(case.prediction_count for case in cases)
    has_complete_exposure = bool(scored_cases) and all(
        case.changed_lines is not None for case in scored_cases
    )
    changed_lines = (
        sum(case.changed_lines or 0 for case in scored_cases)
        if has_complete_exposure
        else None
    )
    true_positives = sum(case.true_positives for case in cases)
    false_positives = sum(case.false_positives for case in cases)
    false_negatives = sum(case.false_negatives for case in cases)

    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    f1_denominator = 2 * true_positives + false_positives + false_negatives

    high_expected = 0
    high_matched = 0
    severity_correct = 0
    for case in cases:
        matches_by_expected_id = {
            match.expected_id: match for match in case.matches
        }
        for result in case.expected_results:
            if result.finding.severity in _HIGH_SEVERITIES:
                high_expected += 1
                match = matches_by_expected_id.get(result.finding.id)
                if match and (
                    match.predicted_severity.strip().casefold() in _HIGH_SEVERITIES
                ):
                    high_matched += 1
            if result.severity_correct:
                severity_correct += 1

    clean_cases = [case for case in cases if case.expected_count == 0]
    clean_cases_correct = sum(
        case.status == "scored" and case.prediction_count == 0
        for case in clean_cases
    )

    return AggregateMetrics(
        case_count=case_count,
        scored_case_count=scored_case_count,
        expected_finding_count=expected_count,
        prediction_count=prediction_count,
        changed_lines=changed_lines,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=_rate(true_positives, precision_denominator),
        precision_denominator=precision_denominator,
        recall=_rate(true_positives, recall_denominator),
        recall_denominator=recall_denominator,
        f1=_rate(2 * true_positives, f1_denominator),
        f1_denominator=f1_denominator,
        blocker_major_recall=_rate(high_matched, high_expected),
        blocker_major_denominator=high_expected,
        severity_accuracy=_rate(severity_correct, true_positives),
        severity_accuracy_denominator=true_positives,
        false_positives_per_case=_rate(false_positives, scored_case_count),
        false_positives_per_kloc=(
            false_positives * 1000 / changed_lines
            if changed_lines is not None and changed_lines > 0
            else None
        ),
        clean_case_accuracy=_rate(clean_cases_correct, len(clean_cases)),
        clean_case_denominator=len(clean_cases),
        clean_cases_correct=clean_cases_correct,
        precision_wilson_95=_wilson_interval(
            true_positives, precision_denominator
        ),
        recall_wilson_95=_wilson_interval(true_positives, recall_denominator),
    )


def score_benchmark(
    manifest: BenchmarkManifest,
    reviews_dir: str | Path,
) -> BenchmarkResult:
    """Score all manifest cases against ``<reviews_dir>/<case_id>.json``."""

    reviews_path = Path(reviews_dir)
    cases: list[CaseResult] = []
    for case in manifest.cases:
        prediction_file = reviews_path / f"{case.id}.json"
        if prediction_file.is_file():
            predictions, incomplete_reason = _load_predictions(prediction_file)
            if incomplete_reason is None:
                status: CaseStatus = "scored"
                note = None
            else:
                status = "incomplete_prediction"
                note = f"{incomplete_reason}; scored as zero findings"
        else:
            predictions = []
            status = "missing_prediction"
            note = "prediction file not found; scored as zero findings"
        cases.append(
            _score_case(case, prediction_file, predictions, status, note)
        )
    return BenchmarkResult(cases=cases, metrics=_aggregate(cases))
