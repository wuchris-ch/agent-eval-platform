"""Normalized, content-minimized assessment records for completed runs."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AssessmentSource = Literal[
    "test", "scanner", "judge", "challenge", "policy", "outcome"
]
AssessmentStatus = Literal[
    "observed", "passed", "failed", "error", "skipped", "unavailable"
]
AssessmentDirection = Literal[
    "higher_is_better", "lower_is_better", "neutral"
]
AssessmentValueType = Literal["numeric", "boolean", "categorical", "text"]

_SAFE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_SAFE_DATASET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@~-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _strict_model() -> ConfigDict:
    return ConfigDict(extra="forbid", frozen=True, strict=True)


def _validate_safe_id(value: str, *, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a normalized lowercase identifier")
    return value


def _validate_printable(value: str, *, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isprintable()
    ):
        raise ValueError(f"{field} must be 1-{maximum} printable characters")
    return value


class EvaluatorIdentity(BaseModel):
    """Stable evaluator identity without prompts, rationales, or source content."""

    model_config = _strict_model()

    name: str
    version: str | None = None
    model: str | None = None
    config_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    prompt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rubric_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("name")
    @classmethod
    def _normalized_name(cls, value: str) -> str:
        return _validate_safe_id(value, field="evaluator name")

    @field_validator("version", "model")
    @classmethod
    def _printable_identity(cls, value: str | None, info: Any) -> str | None:
        if value is not None:
            return _validate_printable(value, field=info.field_name, maximum=256)
        return None


class AssessmentValue(BaseModel):
    """Discriminated scalar value with one and only one populated representation."""

    model_config = _strict_model()

    type: AssessmentValueType
    numeric: float | None = Field(default=None, allow_inf_nan=False)
    boolean: bool | None = None
    categorical: str | None = None
    text: str | None = None

    @field_validator("categorical")
    @classmethod
    def _normalized_category(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_safe_id(value, field="categorical value")
        return None

    @field_validator("text")
    @classmethod
    def _bounded_text(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_printable(value, field="text value", maximum=512)
        return None

    @model_validator(mode="after")
    def _one_matching_value(self) -> AssessmentValue:
        fields = {
            "numeric": self.numeric,
            "boolean": self.boolean,
            "categorical": self.categorical,
            "text": self.text,
        }
        populated = [name for name, value in fields.items() if value is not None]
        if populated != [self.type]:
            raise ValueError("assessment value type must match its only populated value")
        return self


class AssessmentError(BaseModel):
    """Low-cardinality error identity. Free-form error messages are prohibited."""

    model_config = _strict_model()

    type: str
    code: str

    @field_validator("type", "code")
    @classmethod
    def _normalized_error(cls, value: str, info: Any) -> str:
        return _validate_safe_id(value, field=info.field_name)


class Assessment(BaseModel):
    """Immutable normalized assessment suitable for durable querying."""

    model_config = _strict_model()

    schema_version: Literal["agent-eval.assessment/v1"] = (
        "agent-eval.assessment/v1"
    )
    assessment_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str
    name: str
    source_kind: AssessmentSource
    status: AssessmentStatus
    value: AssessmentValue | None = None
    direction: AssessmentDirection = "neutral"
    range_min: float | None = Field(default=None, allow_inf_nan=False)
    range_max: float | None = Field(default=None, allow_inf_nan=False)
    threshold: float | None = Field(default=None, allow_inf_nan=False)
    evaluator: EvaluatorIdentity
    dataset_id: str | None = None
    dataset_revision: str | None = None
    dataset_item_id: str | None = None
    started_at: datetime
    finished_at: datetime
    observed_at: datetime
    error: AssessmentError | None = None

    @field_validator("run_id")
    @classmethod
    def _valid_run_id(cls, value: str) -> str:
        return _validate_printable(value, field="run_id", maximum=256)

    @field_validator("name")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        return _validate_safe_id(value, field="assessment name")

    @field_validator("dataset_id", "dataset_revision", "dataset_item_id")
    @classmethod
    def _normalized_dataset_id(cls, value: str | None, info: Any) -> str | None:
        if value is not None and _SAFE_DATASET_ID.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be an exact safe identifier")
        return value

    @field_validator("started_at", "finished_at", "observed_at")
    @classmethod
    def _utc_timestamp(cls, value: datetime, info: Any) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{info.field_name} must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError(f"{info.field_name} must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _consistent_shape(self) -> Assessment:
        if self.finished_at < self.started_at:
            raise ValueError("assessment finish cannot precede its start")
        if not self.started_at <= self.observed_at <= self.finished_at:
            raise ValueError("assessment observation must be within its time range")
        if self.range_min is not None and self.range_max is not None:
            if self.range_min > self.range_max:
                raise ValueError("assessment range minimum exceeds maximum")
        numeric = self.value.numeric if self.value and self.value.type == "numeric" else None
        if numeric is not None:
            if self.range_min is not None and numeric < self.range_min:
                raise ValueError("numeric assessment is below its declared range")
            if self.range_max is not None and numeric > self.range_max:
                raise ValueError("numeric assessment is above its declared range")
        elif any(
            item is not None for item in (self.range_min, self.range_max, self.threshold)
        ):
            raise ValueError("range and threshold require a numeric assessment")
        if self.threshold is not None:
            if self.direction == "neutral":
                raise ValueError("threshold requires a directional assessment")
            if self.range_min is not None and self.threshold < self.range_min:
                raise ValueError("threshold is below the declared range")
            if self.range_max is not None and self.threshold > self.range_max:
                raise ValueError("threshold is above the declared range")
        if self.status == "error" and self.error is None:
            raise ValueError("error assessments require an error identity")
        if self.status in {"observed", "passed", "failed"} and self.value is None:
            raise ValueError("completed assessments require a value")
        return self


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_json(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def expected_assessment_id(assessment: Assessment) -> str:
    """Return the deterministic identity digest required for an assessment."""

    return _digest_json(
        {
            "run_id": assessment.run_id,
            "name": assessment.name,
            "source_kind": assessment.source_kind,
            "evaluator": assessment.evaluator.model_dump(mode="json"),
            "dataset_id": assessment.dataset_id,
            "dataset_revision": assessment.dataset_revision,
            "dataset_item_id": assessment.dataset_item_id,
        }
    )


def _component(value: object, fallback: str) -> str:
    raw = unicodedata.normalize("NFKC", str(value)).casefold()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-") or fallback
    digest = _digest_text(str(value))[:10]
    return f"{slug[:100].strip('-') or fallback}-{digest}"


def _identity_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if text and len(text) <= 256 and text.isprintable():
        return text
    return f"sha256:{_digest_text(text)}"


def _scanner_config_digest(record: Any, scanner: str) -> str | None:
    config = record.scans.scanner_configs.get(scanner)
    assurance = record.scans.scanner_assurance
    assurance_identity = (
        assurance.identity_sha256 if assurance is not None else None
    )
    if config is None and assurance_identity is None:
        return None
    return _digest_json(
        {
            "scanner": scanner,
            "config": config,
            "scanner_assurance_identity_sha256": assurance_identity,
        }
    )


def _timestamp(value: object, fallback: datetime) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return fallback
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return fallback
    return parsed.astimezone(UTC)


def _numeric(value: int | float) -> AssessmentValue:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("numeric assessment values must be numbers")
    converted = float(value)
    if not math.isfinite(converted):
        raise ValueError("numeric assessment values must be finite")
    return AssessmentValue(type="numeric", numeric=converted)


def _boolean(value: bool) -> AssessmentValue:
    return AssessmentValue(type="boolean", boolean=value)


def _categorical(value: str, *, known_values: frozenset[str]) -> AssessmentValue:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    categorical = (
        normalized
        if normalized in known_values and _SAFE_ID.fullmatch(normalized)
        else f"sha256-{_digest_text(value)}"
    )
    return AssessmentValue(type="categorical", categorical=categorical)


def _assessment(
    *,
    run_id: str,
    name: str,
    source_kind: AssessmentSource,
    status: AssessmentStatus,
    evaluator: EvaluatorIdentity,
    started_at: datetime,
    finished_at: datetime,
    value: AssessmentValue | None = None,
    direction: AssessmentDirection = "neutral",
    range_min: float | None = None,
    range_max: float | None = None,
    threshold: float | None = None,
    error: AssessmentError | None = None,
    dataset_id: str | None = None,
    dataset_revision: str | None = None,
    dataset_item_id: str | None = None,
) -> Assessment:
    draft = Assessment(
        assessment_id="0" * 64,
        run_id=run_id,
        name=name,
        source_kind=source_kind,
        status=status,
        value=value,
        direction=direction,
        range_min=range_min,
        range_max=range_max,
        threshold=threshold,
        evaluator=evaluator,
        dataset_id=dataset_id,
        dataset_revision=dataset_revision,
        dataset_item_id=dataset_item_id,
        started_at=started_at,
        finished_at=finished_at,
        observed_at=finished_at,
        error=error,
    )
    return draft.model_copy(
        update={"assessment_id": expected_assessment_id(draft)}
    )


def _bind_dataset(assessment: Assessment, dataset: Any | None) -> Assessment:
    if dataset is None:
        return assessment
    payload = assessment.model_dump()
    payload.update(
        {
            "dataset_id": dataset.id,
            "dataset_revision": dataset.revision,
            "dataset_item_id": dataset.item_id,
        }
    )
    bound = Assessment.model_validate(payload)
    return bound.model_copy(
        update={"assessment_id": expected_assessment_id(bound)}
    )


def derive_assessments(record: Any, task: Any) -> list[Assessment]:
    """Project existing evidence into deterministic, content-minimized records."""

    finished = _timestamp(record.finished_at, datetime.now(UTC))
    started = _timestamp(record.started_at, finished)
    started = min(started, finished)
    run_id = record.run_id
    harness_version = record.provenance.harness_version
    evaluation_digest = record.provenance.evaluation_spec_digest
    assessments: list[Assessment] = []

    tests = record.correctness
    test_error = None
    test_status: AssessmentStatus = "passed" if tests.resolved else "failed"
    if tests.infra_error:
        test_status = "error"
        test_error = AssessmentError(
            type="infrastructure", code="evaluation_infrastructure_error"
        )
    elif tests.integrity_error:
        test_status = "failed"
        test_error = AssessmentError(type="integrity", code="workspace_integrity_error")
    test_evaluator = EvaluatorIdentity(
        name="hidden-tests",
        version=_identity_text(harness_version),
        config_digest=evaluation_digest,
    )
    assessments.append(
        _assessment(
            run_id=run_id,
            name="tests.resolved",
            source_kind="test",
            status=test_status,
            value=_boolean(bool(tests.resolved)),
            evaluator=test_evaluator,
            started_at=started,
            finished_at=finished,
            error=test_error,
        )
    )
    counts_observed = tests.counts_observed or any(
        count > 0
        for count in (
            tests.total,
            tests.passed,
            tests.failed,
            tests.errors,
            tests.skipped,
        )
    )
    for name, count, direction in (
        ("tests.total", tests.total, "neutral"),
        ("tests.passed", tests.passed, "higher_is_better"),
        ("tests.failed", tests.failed, "lower_is_better"),
        ("tests.errors", tests.errors, "lower_is_better"),
        ("tests.skipped", tests.skipped, "lower_is_better"),
    ):
        assessments.append(
            _assessment(
                run_id=run_id,
                name=name,
                source_kind="test",
                status="observed" if counts_observed else "unavailable",
                value=_numeric(count) if counts_observed else None,
                direction=direction,
                range_min=0.0 if counts_observed else None,
                evaluator=test_evaluator,
                started_at=started,
                finished_at=finished,
            )
        )
    coverage_threshold = getattr(task.acceptance, "min_coverage_percent", None)
    coverage_status: AssessmentStatus = "unavailable"
    if tests.coverage_percent is not None:
        coverage_status = (
            "passed"
            if coverage_threshold is not None
            and tests.coverage_percent >= coverage_threshold
            else "failed"
            if coverage_threshold is not None
            else "observed"
        )
    assessments.append(
        _assessment(
            run_id=run_id,
            name="tests.coverage-percent",
            source_kind="test",
            status=coverage_status,
            value=(
                _numeric(tests.coverage_percent)
                if tests.coverage_percent is not None
                else None
            ),
            direction="higher_is_better",
            range_min=0.0 if tests.coverage_percent is not None else None,
            range_max=100.0 if tests.coverage_percent is not None else None,
            threshold=(
                float(coverage_threshold)
                if coverage_threshold is not None and tests.coverage_percent is not None
                else None
            ),
            evaluator=test_evaluator,
            started_at=started,
            finished_at=finished,
        )
    )

    scanner_thresholds = {
        "scanners.lint-errors": getattr(task.acceptance, "max_lint_errors", None),
        "scanners.security-high": getattr(
            task.acceptance, "max_security_findings_high", None
        ),
        "scanners.secrets": getattr(task.acceptance, "max_secrets", None),
        "scanners.vulnerabilities": getattr(
            task.acceptance, "max_vulnerabilities", None
        ),
    }
    scanner_counts = (
        ("scanners.lint-errors", "ruff", record.scans.lint_errors),
        ("scanners.security-high", "semgrep", record.scans.sec_findings_high),
        ("scanners.security-medium", "semgrep", record.scans.sec_findings_medium),
        ("scanners.security-low", "semgrep", record.scans.sec_findings_low),
        ("scanners.secrets", "gitleaks", record.scans.secrets_found),
        ("scanners.vulnerabilities", "trivy", record.scans.vulns),
    )
    for name, scanner, count in scanner_counts:
        version = record.scans.scanner_versions.get(scanner)
        evaluator = EvaluatorIdentity(
            name=f"scanner-{_component(scanner, 'scanner')}",
            version=_identity_text(version),
            config_digest=_scanner_config_digest(record, scanner),
        )
        threshold = scanner_thresholds.get(name)
        status: AssessmentStatus = "unavailable" if count is None else "observed"
        if count is not None and threshold is not None:
            status = "passed" if count <= threshold else "failed"
        assessments.append(
            _assessment(
                run_id=run_id,
                name=name,
                source_kind="scanner",
                status=status,
                value=_numeric(count) if count is not None else None,
                direction="lower_is_better",
                range_min=0.0 if count is not None else None,
                threshold=(
                    float(threshold)
                    if count is not None and threshold is not None
                    else None
                ),
                evaluator=evaluator,
                started_at=started,
                finished_at=finished,
            )
        )
    for scanner, scanner_state in sorted(record.scans.scanner_status.items()):
        normalized_state = str(scanner_state).casefold()
        status = (
            "passed"
            if normalized_state == "ok"
            else "skipped"
            if normalized_state == "not_applicable"
            else "unavailable"
            if normalized_state == "unavailable"
            else "error"
        )
        error = None
        if status == "error":
            error = AssessmentError(
                type="scanner",
                code=(
                    "scanner_error"
                    if normalized_state == "error"
                    else "unexpected_scanner_status"
                ),
            )
        evaluator = EvaluatorIdentity(
            name=f"scanner-{_component(scanner, 'scanner')}",
            version=_identity_text(record.scans.scanner_versions.get(scanner)),
            config_digest=_scanner_config_digest(record, scanner),
        )
        assessments.append(
            _assessment(
                run_id=run_id,
                name=f"scanners.{_component(scanner, 'scanner')}.status",
                source_kind="scanner",
                status=status,
                value=_categorical(
                    scanner_state,
                    known_values=frozenset(
                        {"ok", "error", "not_applicable", "unavailable"}
                    ),
                ),
                evaluator=evaluator,
                started_at=started,
                finished_at=finished,
                error=error,
            )
        )

    judge_enabled = bool(getattr(task.judge, "enabled", False))
    if judge_enabled or record.judge.scores:
        prompt_digest = _digest_text(task.prompt)
        rubric_digest = _digest_json(task.judge.weights)
        backend = record.judge.backend or getattr(task.judge, "backend", None)
        model = record.judge.model or getattr(task.judge, "model", None)
        judge_evaluator = EvaluatorIdentity(
            name=f"judge-{_component(backend or 'unknown', 'unknown')}",
            version=_identity_text(harness_version),
            model=_identity_text(model),
            config_digest=evaluation_digest,
            prompt_digest=prompt_digest,
            rubric_digest=rubric_digest,
        )
        for dimension, score in sorted(record.judge.scores.items()):
            assessments.append(
                _assessment(
                    run_id=run_id,
                    name=f"judge.{_component(dimension, 'dimension')}",
                    source_kind="judge",
                    status="observed",
                    value=_numeric(score),
                    direction="higher_is_better",
                    range_min=1.0,
                    range_max=5.0,
                    evaluator=judge_evaluator,
                    started_at=started,
                    finished_at=finished,
                )
            )
        threshold = getattr(task.acceptance, "min_judge_score", None)
        if record.judge.weighted_score is not None:
            status = (
                "passed"
                if threshold is not None and record.judge.weighted_score >= threshold
                else "failed"
                if threshold is not None
                else "observed"
            )
            assessments.append(
                _assessment(
                    run_id=run_id,
                    name="judge.weighted-score",
                    source_kind="judge",
                    status=status,
                    value=_numeric(record.judge.weighted_score),
                    direction="higher_is_better",
                    range_min=1.0,
                    range_max=5.0,
                    threshold=float(threshold) if threshold is not None else None,
                    evaluator=judge_evaluator,
                    started_at=started,
                    finished_at=finished,
                )
            )
        else:
            assessments.append(
                _assessment(
                    run_id=run_id,
                    name="judge.weighted-score",
                    source_kind="judge",
                    status="unavailable",
                    direction="higher_is_better",
                    evaluator=judge_evaluator,
                    started_at=started,
                    finished_at=finished,
                )
            )

    assurance = record.assurance
    if assurance is not None:
        challenge_evaluator = EvaluatorIdentity(
            name="challenge",
            version=_identity_text(harness_version),
            config_digest=evaluation_digest,
        )
        for challenge in assurance.challenges:
            assessments.append(
                _assessment(
                    run_id=run_id,
                    name=f"challenge.{_component(challenge.id, 'challenge')}",
                    source_kind="challenge",
                    status="passed" if challenge.passed else "failed",
                    value=_boolean(challenge.passed),
                    evaluator=challenge_evaluator,
                    started_at=started,
                    finished_at=finished,
                )
            )

    governance = record.governance
    if governance is not None:
        policy_evaluator = EvaluatorIdentity(
            name="governance",
            version=_identity_text(governance.policy_revision),
            config_digest=governance.policy_digest,
        )
        assessments.append(
            _assessment(
                run_id=run_id,
                name="policy.admission",
                source_kind="policy",
                status="passed" if governance.allowed else "failed",
                value=_boolean(governance.allowed),
                evaluator=policy_evaluator,
                started_at=started,
                finished_at=finished,
            )
        )

    if record.outcome is not None:
        outcome_status = record.outcome.status
        assessments.append(
            _assessment(
                run_id=run_id,
                name="outcome.status",
                source_kind="outcome",
                status=(
                    "passed"
                    if outcome_status == "accepted"
                    else "failed"
                    if outcome_status == "rejected"
                    else "error"
                ),
                value=_categorical(
                    outcome_status,
                    known_values=frozenset(
                        {"accepted", "rejected", "infra_error"}
                    ),
                ),
                evaluator=EvaluatorIdentity(
                    name="outcome",
                    version=_identity_text(harness_version),
                    config_digest=evaluation_digest,
                ),
                started_at=started,
                finished_at=finished,
                error=(
                    AssessmentError(
                        type="infrastructure", code="run_infrastructure_error"
                    )
                    if outcome_status == "infra_error"
                    else None
                ),
            )
        )

    dataset = getattr(task, "dataset", None)
    return [_bind_dataset(assessment, dataset) for assessment in assessments]
