"""Run one suite on several models and recommend the cheapest model that passes.

Every model gets the same cases, trials and checks. Cost comes from a price
table: hosted models are priced per token, and local models cost zero dollars
per token plus an optional hardware cost per hour of model time.
"""

from __future__ import annotations

import math
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ..limits import MAX_RESULTS_JSON_BYTES, read_stable_bounded_file
from ..yaml_utils import UniqueKeyLoader
from .models import Report, StrictModel, Suite, digest
from .runner import evaluate
from .targets import ModelTarget, Target

LABEL = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"


class ModelPrice(StrictModel):
    input_usd_per_million_tokens: float = Field(default=0, ge=0)
    output_usd_per_million_tokens: float = Field(default=0, ge=0)
    hardware_usd_per_hour: float = Field(default=0, ge=0)
    source: str | None = Field(default=None, max_length=500)


class ModelSpec(StrictModel):
    label: str = Field(pattern=LABEL)
    model: str = Field(min_length=1, max_length=200)
    deployment: Literal["local", "hosted"]
    base_url: str | None = None
    base_url_env: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    api_key_env: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    timeout: float = Field(default=120, gt=0)
    price: ModelPrice = Field(default_factory=ModelPrice)

    @model_validator(mode="after")
    def valid_route_and_price(self):
        if (self.base_url is None) == (self.base_url_env is None):
            raise ValueError("set exactly one of base_url or base_url_env")
        per_token = (
            self.price.input_usd_per_million_tokens
            or self.price.output_usd_per_million_tokens
        )
        if self.deployment == "local" and per_token:
            raise ValueError("local models cost zero dollars per token")
        if self.deployment == "hosted" and self.price.hardware_usd_per_hour:
            raise ValueError("hardware cost applies only to local models")
        return self


class ComparisonPlan(StrictModel):
    schema_version: Literal["1.0"]
    models: list[ModelSpec] = Field(min_length=2, max_length=20)

    @model_validator(mode="after")
    def unique_labels(self):
        labels = [spec.label for spec in self.models]
        if len(labels) != len(set(labels)):
            raise ValueError("model labels must be unique")
        return self


class ModelResult(StrictModel):
    label: str
    model: str
    deployment: Literal["local", "hosted"]
    run_id: str
    passed: bool
    evaluations: int
    accepted: int
    rejected: int
    infra_errors: int
    average_score: float
    tokens_in: int | None
    tokens_out: int | None
    # Evaluations whose endpoint reported both token counts.
    usage_measured: int
    median_latency_ms: float | None
    p95_latency_ms: float | None
    model_seconds: float
    cost_usd: float | None
    price: ModelPrice


class Comparison(StrictModel):
    schema_version: Literal["agent-eval.model-comparison/v1"] = (
        "agent-eval.model-comparison/v1"
    )
    created_at: str
    suite_id: str
    suite_version: str
    suite_sha256: str
    trials: int
    models: list[ModelResult]
    recommended: str | None
    reason: str


def load_plan(path: Path) -> ComparisonPlan:
    import yaml

    raw = read_stable_bounded_file(path, maximum_bytes=MAX_RESULTS_JSON_BYTES)
    return ComparisonPlan.model_validate(yaml.load(raw, Loader=UniqueKeyLoader))


def model_target(
    spec: ModelSpec, system_prompt: str | None, response_format: str
) -> ModelTarget:
    base_url = spec.base_url or os.environ[spec.base_url_env or ""]
    return ModelTarget(
        base_url,
        spec.model,
        system_prompt=system_prompt,
        response_format=response_format,
        timeout=spec.timeout,
        api_key=os.environ[spec.api_key_env] if spec.api_key_env else None,
    )


def run_cost(price: ModelPrice, report: Report) -> float | None:
    """Dollar cost of one run, or None when token usage is incomplete."""
    observations = [r.observation for r in report.results if r.observation]
    model_hours = sum(item.latency_ms or 0 for item in observations) / 3_600_000
    cost = price.hardware_usd_per_hour * model_hours
    if not (price.input_usd_per_million_tokens or price.output_usd_per_million_tokens):
        return cost
    measured = [
        item
        for item in observations
        if item.tokens_in is not None and item.tokens_out is not None
    ]
    if len(measured) < report.evaluations:
        return None
    return (
        cost
        + sum(item.tokens_in or 0 for item in measured)
        * price.input_usd_per_million_tokens
        / 1_000_000
        + sum(item.tokens_out or 0 for item in measured)
        * price.output_usd_per_million_tokens
        / 1_000_000
    )


def summarize(spec: ModelSpec, report: Report) -> ModelResult:
    observations = [r.observation for r in report.results if r.observation]
    latencies = sorted(
        item.latency_ms for item in observations if item.latency_ms is not None
    )
    return ModelResult(
        label=spec.label,
        model=spec.model,
        deployment=spec.deployment,
        run_id=report.run_id,
        passed=report.passed,
        evaluations=report.evaluations,
        accepted=report.accepted,
        rejected=report.rejected,
        infra_errors=report.infra_errors,
        average_score=report.average_score,
        tokens_in=report.tokens_in,
        tokens_out=report.tokens_out,
        usage_measured=sum(
            item.tokens_in is not None and item.tokens_out is not None
            for item in observations
        ),
        median_latency_ms=report.median_latency_ms,
        # Nearest-rank percentile keeps the value an observed latency.
        p95_latency_ms=latencies[math.ceil(0.95 * len(latencies)) - 1]
        if latencies
        else None,
        model_seconds=sum(latencies) / 1000,
        cost_usd=run_cost(spec.price, report),
        price=spec.price,
    )


def recommend(results: list[ModelResult]) -> tuple[str | None, str]:
    passing = [result for result in results if result.passed]
    if not passing:
        return None, "No model passed the release gate."
    priced = [result for result in passing if result.cost_usd is not None]
    if not priced:
        return None, (
            "Passing models lack complete token usage, so their cost is unknown."
        )
    # Equal cost, for example two free local models, falls back to speed.
    best = min(
        priced,
        key=lambda result: (
            result.cost_usd,
            result.median_latency_ms
            if result.median_latency_ms is not None
            else math.inf,
        ),
    )
    return best.label, (
        f"{best.label} is the cheapest of {len(passing)} model(s) that passed "
        f"the release gate, at ${best.cost_usd:.4f} for the run."
    )


def compare(
    suite: Suite, targets: list[tuple[ModelSpec, Target]], *, trials: int
) -> tuple[Comparison, list[Report]]:
    reports = [
        evaluate(suite, agent=spec.label, target=target, trials=trials)
        for spec, target in targets
    ]
    results = [
        summarize(spec, report)
        for (spec, _), report in zip(targets, reports, strict=True)
    ]
    recommended, reason = recommend(results)
    comparison = Comparison(
        created_at=datetime.now(UTC).isoformat(),
        suite_id=suite.id,
        suite_version=suite.version,
        suite_sha256=digest(suite.model_dump(mode="json")),
        trials=trials,
        models=results,
        recommended=recommended,
        reason=reason,
    )
    return comparison, reports


def _seconds(value_ms: float | None) -> str:
    return "-" if value_ms is None else f"{value_ms / 1000:.2f} s"


def render_markdown(comparison: Comparison) -> str:
    lines = [
        f"# Model comparison: {comparison.suite_id} {comparison.suite_version}",
        "",
        f"Recorded {comparison.created_at}. Each model ran every case "
        f"{comparison.trials} time(s). The release gate passes only when every "
        "evaluation is accepted.",
        "",
        "| Model | Deployment | Release gate | Accepted | Infra errors "
        "| Tokens in / out | Cost (USD) | Median latency | p95 latency |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for result in comparison.models:
        tokens = (
            "-"
            if result.tokens_in is None
            else f"{result.tokens_in:,} / {result.tokens_out:,}"
        )
        cost = "-" if result.cost_usd is None else f"${result.cost_usd:.4f}"
        lines.append(
            f"| {result.label} ({result.model}) | {result.deployment} "
            f"| {'PASS' if result.passed else 'FAIL'} "
            f"| {result.accepted} / {result.evaluations} | {result.infra_errors} "
            f"| {tokens} | {cost} | {_seconds(result.median_latency_ms)} "
            f"| {_seconds(result.p95_latency_ms)} |"
        )
    lines += [
        "",
        f"**Recommendation:** {comparison.recommended or 'none'}. {comparison.reason}",
        "",
        "Prices:",
        "",
    ]
    for result in comparison.models:
        price = result.price
        lines.append(
            f"- {result.label}: ${price.input_usd_per_million_tokens:g} input and "
            f"${price.output_usd_per_million_tokens:g} output per million tokens, "
            f"${price.hardware_usd_per_hour:g} hardware per hour"
            + (f" ({price.source})" if price.source else "")
            + "."
        )
    return "\n".join(lines) + "\n"
