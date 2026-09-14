"""Optional, content-minimized OpenTelemetry projection for completed runs.

The audit trail and persisted run record remain authoritative. This module is
disabled by default, imports OpenTelemetry lazily, and never raises to callers.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Any

from .assessments import Assessment

GENAI_SEMCONV_REVISION = "93a59e48a9b4ea162a4d76edac4ace2d415a759e"
TELEMETRY_SCHEMA_VERSION = "agent-eval.telemetry/v1"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_KNOWN_AGENTS = frozenset({"claude-code", "codex", "external", "oracle"})
_KNOWN_ENVIRONMENTS = frozenset({"development", "staging", "production", "test"})
_FIXED_ASSESSMENT_NAMES = frozenset(
    {
        "tests.resolved",
        "tests.total",
        "tests.passed",
        "tests.failed",
        "tests.errors",
        "tests.skipped",
        "tests.coverage-percent",
        "scanners.lint-errors",
        "scanners.security-high",
        "scanners.security-medium",
        "scanners.security-low",
        "scanners.secrets",
        "scanners.vulnerabilities",
        "judge.weighted-score",
        "policy.admission",
        "outcome.status",
    }
)
_RUN_ATTRIBUTE_KEYS = frozenset(
    {
        "agent_eval.agent.name",
        "agent_eval.assessment.count",
        "agent_eval.run.governed",
        "agent_eval.run.outcome",
        "agent_eval.telemetry.schema_version",
        "agent_eval.telemetry.semconv_revision",
    }
)
_ASSESSMENT_ATTRIBUTE_KEYS = frozenset(
    {
        "agent_eval.assessment.direction",
        "agent_eval.assessment.error.type",
        "agent_eval.assessment.name",
        "agent_eval.assessment.source_kind",
        "agent_eval.assessment.status",
        "agent_eval.assessment.value.boolean",
        "agent_eval.assessment.value.numeric",
        "agent_eval.assessment.value.type",
        "gen_ai.evaluation.name",
        "gen_ai.evaluation.score.value",
    }
)


@dataclass(frozen=True)
class _OtelRuntime:
    tracer: Any
    provider: Any


_runtime: _OtelRuntime | None = None
_runtime_lock = threading.Lock()


def _enabled() -> bool:
    return os.environ.get("AGENT_EVAL_OTEL_ENABLED", "").casefold() in _TRUE_VALUES


def _bounded_environment() -> str | None:
    value = os.environ.get("AGENT_EVAL_ENVIRONMENT", "").casefold()
    return value if value in _KNOWN_ENVIRONMENTS else None


def _load_otel() -> dict[str, Any]:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter as GrpcExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter as HttpExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    return {
        "BatchSpanProcessor": BatchSpanProcessor,
        "GrpcExporter": GrpcExporter,
        "HttpExporter": HttpExporter,
        "Resource": Resource,
        "TracerProvider": TracerProvider,
    }


def _create_runtime() -> _OtelRuntime:
    modules = _load_otel()
    protocol = os.environ.get(
        "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
        os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
    ).casefold()
    if protocol == "grpc":
        exporter_type = modules["GrpcExporter"]
    elif protocol == "http/protobuf":
        exporter_type = modules["HttpExporter"]
    else:
        raise ValueError("OTLP traces protocol must be grpc or http/protobuf")

    from . import __version__

    resource_attributes: dict[str, str] = {
        "service.name": "agent-eval",
        "service.version": __version__,
    }
    environment = _bounded_environment()
    if environment is not None:
        resource_attributes["deployment.environment.name"] = environment
    resource = modules["Resource"](attributes=resource_attributes)
    provider = modules["TracerProvider"](resource=resource)
    provider.add_span_processor(modules["BatchSpanProcessor"](exporter_type()))
    tracer = provider.get_tracer(
        "agent_eval.observability",
        __version__,
    )
    return _OtelRuntime(tracer=tracer, provider=provider)


def _get_runtime() -> _OtelRuntime:
    global _runtime
    if _runtime is not None:
        return _runtime
    with _runtime_lock:
        if _runtime is None:
            _runtime = _create_runtime()
    return _runtime


def _run_attributes(record: Any) -> dict[str, str | bool | int]:
    agent = record.agent if record.agent in _KNOWN_AGENTS else "other"
    outcome = getattr(record.outcome, "status", None)
    if outcome not in {"accepted", "rejected", "infra_error"}:
        outcome = "unavailable"
    attributes: dict[str, str | bool | int] = {
        "agent_eval.agent.name": agent,
        "agent_eval.assessment.count": len(record.assessments),
        "agent_eval.run.governed": record.governance is not None,
        "agent_eval.run.outcome": outcome,
        "agent_eval.telemetry.schema_version": TELEMETRY_SCHEMA_VERSION,
        "agent_eval.telemetry.semconv_revision": GENAI_SEMCONV_REVISION,
    }
    assert set(attributes) <= _RUN_ATTRIBUTE_KEYS
    return attributes


def assessment_event(
    assessment: Assessment,
) -> tuple[str, dict[str, str | bool | float]]:
    """Return the allowlisted event projection without free-form content."""

    if assessment.name in _FIXED_ASSESSMENT_NAMES:
        projected_name = assessment.name
    elif assessment.source_kind == "scanner":
        projected_name = "scanners.status"
    elif assessment.source_kind == "judge":
        projected_name = "judge.dimension"
    elif assessment.source_kind == "challenge":
        projected_name = "challenge.result"
    else:
        projected_name = f"{assessment.source_kind}.result"

    attributes: dict[str, str | bool | float] = {
        "agent_eval.assessment.direction": assessment.direction,
        "agent_eval.assessment.name": projected_name,
        "agent_eval.assessment.source_kind": assessment.source_kind,
        "agent_eval.assessment.status": assessment.status,
        "agent_eval.assessment.value.type": (
            assessment.value.type if assessment.value is not None else "unavailable"
        ),
    }
    if assessment.error is not None:
        attributes["agent_eval.assessment.error.type"] = assessment.error.type
    if assessment.value is not None:
        if assessment.value.type == "numeric":
            attributes["agent_eval.assessment.value.numeric"] = float(
                assessment.value.numeric
            )
        elif assessment.value.type == "boolean":
            attributes["agent_eval.assessment.value.boolean"] = bool(
                assessment.value.boolean
            )

    if assessment.source_kind == "judge":
        event_name = "gen_ai.evaluation.result"
        attributes["gen_ai.evaluation.name"] = f"agent_eval.{projected_name}"
        if assessment.value is not None and assessment.value.type == "numeric":
            attributes["gen_ai.evaluation.score.value"] = float(
                assessment.value.numeric
            )
    else:
        event_name = "agent_eval.assessment.result"
    assert set(attributes) <= _ASSESSMENT_ATTRIBUTE_KEYS
    return event_name, attributes


def _flush_timeout_ms() -> int:
    try:
        timeout = int(os.environ.get("AGENT_EVAL_OTEL_FLUSH_TIMEOUT_MS", "3000"))
    except ValueError:
        return 3000
    return min(max(timeout, 100), 10_000)


def export_run_assessments(record: Any) -> bool:
    """Best-effort completion export. Never changes or raises into run state."""

    if not _enabled():
        return False
    if os.environ.get("OTEL_TRACES_EXPORTER", "otlp").casefold() == "none":
        return False
    try:
        runtime = _get_runtime()
        with runtime.tracer.start_as_current_span(
            "agent_eval.run", attributes=_run_attributes(record)
        ) as span:
            for assessment in record.assessments:
                event_name, attributes = assessment_event(assessment)
                span.add_event(event_name, attributes=attributes)
        return bool(runtime.provider.force_flush(_flush_timeout_ms()))
    except Exception:
        return False
