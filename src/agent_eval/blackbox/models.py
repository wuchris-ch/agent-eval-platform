"""Versioned suites, observations, and results shared by every target transport."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from ..limits import MAX_RESULTS_JSON_BYTES, read_stable_bounded_file
from ..yaml_utils import UniqueKeyLoader
from .inspection_models import InspectionReport

MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_EVALUATIONS = 10_000


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


def json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(json_bytes(value)).hexdigest()


def parse_json(raw: bytes | str) -> JsonValue:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def finite(_value):
        raise ValueError("non-finite JSON value")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=finite)


class Metric(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["exact_match", "contains", "json_subset", "geval"]
    threshold: float = Field(default=1.0, ge=0, le=1)
    criteria: str | None = Field(default=None, min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def valid_criteria(self):
        if (self.kind == "geval") != (self.criteria is not None):
            raise ValueError("criteria is required only for geval metrics")
        return self


class Case(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    input: JsonValue
    expected_output: JsonValue
    tags: list[str] = Field(default_factory=list, max_length=100)
    # These are evaluator-only reference documents, never extra target inputs.
    context: list[str] = Field(default_factory=list, max_length=100)
    metrics: list[Metric] | None = Field(default=None, min_length=1, max_length=20)

    @model_validator(mode="after")
    def bounded_content(self):
        for value in (self.input, self.expected_output, self.context):
            if len(json_bytes(value)) > MAX_PAYLOAD_BYTES:
                raise ValueError("case content exceeds the byte limit")
        return self


class Suite(StrictModel):
    schema_version: Literal["1.0"]
    id: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    metrics: list[Metric] = Field(min_length=1, max_length=20)
    cases: list[Case] = Field(min_length=1, max_length=MAX_EVALUATIONS)

    @model_validator(mode="after")
    def validate_cases(self):
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("suite case IDs must be unique")
        for metrics in [
            self.metrics,
            *(case.metrics for case in self.cases if case.metrics),
        ]:
            names = [metric.name for metric in metrics]
            if len(names) != len(set(names)):
                raise ValueError("metric names must be unique")
        for case in self.cases:
            for metric in case.metrics or self.metrics:
                if metric.kind == "contains" and not (
                    isinstance(case.expected_output, str) and case.expected_output
                ):
                    raise ValueError("contains requires a nonempty expected string")
                if metric.kind == "json_subset" and not isinstance(
                    case.expected_output, dict
                ):
                    raise ValueError("json_subset requires an expected object")
        return self


def load_suite(path: Path) -> Suite:
    import yaml

    raw = read_stable_bounded_file(path, maximum_bytes=MAX_RESULTS_JSON_BYTES)
    value = (
        parse_json(raw)
        if path.suffix.lower() == ".json"
        else yaml.load(raw, Loader=UniqueKeyLoader)
    )
    return Suite.model_validate(value)


ErrorCode = Literal[
    "target_start",
    "target_exit",
    "target_timeout",
    "target_output_limit",
    "target_transport",
    "invalid_output",
    "missing_observation",
    "input_mismatch",
    "recorded_error",
    "judge_error",
]


class Observation(StrictModel):
    """One completed boundary request, never an individual intermediate LLM call."""

    case_id: str = Field(min_length=1, max_length=200)
    trial: int = Field(default=1, ge=1, le=MAX_EVALUATIONS)
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    actual_output: JsonValue
    status: Literal["completed", "error"] = "completed"
    latency_ms: float | None = Field(default=None, ge=0)
    # Token counts reported by a model endpoint. None means the target did not report usage.
    tokens_in: int | None = Field(default=None, ge=0)
    tokens_out: int | None = Field(default=None, ge=0)
    trace_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    span_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")

    @model_validator(mode="after")
    def valid_content(self):
        if len(json_bytes(self.actual_output)) > MAX_PAYLOAD_BYTES:
            raise ValueError("observation exceeds the byte limit")
        if (self.trace_id is None) != (self.span_id is None):
            raise ValueError("trace_id and span_id must be supplied together")
        if self.trace_id is not None and (
            int(self.trace_id, 16) == 0 or int(self.span_id, 16) == 0
        ):
            raise ValueError("trace and span IDs must be nonzero")
        return self


class MetricResult(StrictModel):
    name: str
    kind: Literal["exact_match", "contains", "json_subset", "geval"]
    threshold: float = Field(ge=0, le=1)
    score: float = Field(ge=0, le=1)
    passed: bool
    reason: str = ""


class Result(StrictModel):
    case_id: str
    trial: int
    input_sha256: str
    outcome: Literal["accepted", "rejected", "infra_error"]
    score: float | None = None
    metrics: list[MetricResult] = Field(default_factory=list)
    observation: Observation | None = None
    error: ErrorCode | None = None


class Report(StrictModel):
    schema_version: Literal["1.0", "1.1"] = "1.0"
    run_id: str
    parent_run_id: str | None = None
    created_at: str
    suite_id: str
    suite_version: str
    suite_sha256: str
    agent: str
    target_sha256: str
    mode: Literal["command", "http", "model", "replay"]
    trials: int
    evaluations: int
    accepted: int
    rejected: int
    infra_errors: int
    average_score: float
    median_latency_ms: float | None
    # Totals over observations that reported usage; None when none did.
    tokens_in: int | None = None
    tokens_out: int | None = None
    passed: bool
    results: list[Result]
    inspection: InspectionReport | None = None
    overall_passed: bool | None = None

    @model_validator(mode="after")
    def combined_gate(self):
        self.overall_passed = self.passed and (
            self.inspection is None
            or not self.inspection.required
            or self.inspection.status == "accepted"
        )
        return self
