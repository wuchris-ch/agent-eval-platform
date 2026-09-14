"""Tamper-evident, privacy-safe JSONL audit trails.

The chain proves integrity, ordering, and run/trace continuity for local audit
events.  It does not authenticate the producer: authenticity requires a
signature or an independently trusted transport in addition to this module.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

AUDIT_SCHEMA_VERSION = "agent-eval.audit/v1"
MAX_AUDIT_EVENT_BYTES = 64 * 1024
GENESIS_HASH = "0" * 64

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:[0-5]\d)"
    r"(?P<fraction>\.\d{1,9})?"
    r"(?P<offset>Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_SENSITIVE_ATTRIBUTE_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "password",
        "secret",
        "credential",
        "cookie",
        "prompt",
        "completion",
        "transcript",
        "stdout",
        "stderr",
        "content",
    }
)
_SENSITIVE_ATTRIBUTE_KEYS_COLLAPSED = frozenset(
    key.replace("_", "") for key in _SENSITIVE_ATTRIBUTE_KEYS
)
_CANONICAL_UUID_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_SAFE_ATTRIBUTE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]*$"
_EXACT_MODEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+~-]*$"
_EXCEPTION_TYPE_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]{0,127}$"
_IMAGE_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_GOVERNED_IMAGE_REF_PATTERN = (
    r"^agent-eval/[a-z0-9](?:[a-z0-9.-]{0,62}):governed-[0-9a-f]{64}$"
)
_PLATFORM_PATTERN = r"^linux/[a-z0-9_]+$"


class _AuditAttributes(BaseModel):
    """Strict scalar-only base for one lifecycle event's attributes."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _validate_optional_group(
    attributes: _AuditAttributes,
    fields: frozenset[str],
    *,
    nullable: frozenset[str] = frozenset(),
) -> None:
    """Require a documented optional field group to be wholly present or absent."""

    present = attributes.model_fields_set & fields
    if present and present != fields:
        raise ValueError("optional audit attribute group is incomplete")
    if any(getattr(attributes, field) is None for field in present - nullable):
        raise ValueError("optional audit attribute cannot be null")


class _EvaluationRequestedAttributes(_AuditAttributes):
    task_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    task_image_digest: str = Field(pattern=_IMAGE_DIGEST_PATTERN, strict=True)
    task_image_ref: str = Field(pattern=_GOVERNED_IMAGE_REF_PATTERN, strict=True)
    task_image_platform: str = Field(pattern=_PLATFORM_PATTERN, strict=True)
    request_id: str | None = Field(
        default=None,
        pattern=_CANONICAL_UUID_PATTERN,
        strict=True,
    )
    agent: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    model: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        pattern=_EXACT_MODEL_PATTERN,
        strict=True,
    )
    trial: int | None = Field(default=None, gt=0, strict=True)
    run_scans: bool | None = Field(default=None, strict=True)
    run_judge: bool | None = Field(default=None, strict=True)
    judge_backend: Literal["claude", "codex"] | None = None
    judge_model: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        pattern=_EXACT_MODEL_PATTERN,
        strict=True,
    )
    task_tree_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        strict=True,
    )
    execution_spec_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        strict=True,
    )

    @model_validator(mode="after")
    def _complete_governance_evidence(self) -> _EvaluationRequestedAttributes:
        _validate_optional_group(
            self,
            frozenset(
                {
                    "request_id",
                    "agent",
                    "model",
                    "trial",
                    "run_scans",
                    "run_judge",
                    "judge_backend",
                    "judge_model",
                    "task_tree_sha256",
                    "execution_spec_digest",
                }
            ),
            nullable=frozenset({"judge_backend", "judge_model"}),
        )
        if self.run_judge is True and (
            self.judge_backend is None or self.judge_model is None
        ):
            raise ValueError("enabled governed judge requires an exact identity")
        if self.run_judge is False and (
            self.judge_backend is not None or self.judge_model is not None
        ):
            raise ValueError("disabled governed judge cannot carry an identity")
        return self


class _PolicyAdmittedAttributes(_AuditAttributes):
    decision_id: str = Field(pattern=_CANONICAL_UUID_PATTERN, strict=True)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)
    policy_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    policy_revision: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)
    task_registry_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    task_registry_revision: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    task_registry_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)
    registry_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    registry_revision: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    registry_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)


class _AgentStartedAttributes(_AuditAttributes):
    agent: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    model: str = Field(
        min_length=1,
        max_length=256,
        pattern=_EXACT_MODEL_PATTERN,
        strict=True,
    )
    trial: int | None = Field(default=None, gt=0, strict=True)

    @model_validator(mode="after")
    def _valid_optional_trial(self) -> _AgentStartedAttributes:
        _validate_optional_group(self, frozenset({"trial"}))
        return self


class _AgentCompletedAttributes(_AuditAttributes):
    status: Literal["completed", "infrastructure_error"]
    exit_code: int | None = Field(default=None, strict=True)
    timed_out: bool | None = Field(default=None, strict=True)
    snapshot_available: bool | None = Field(default=None, strict=True)
    wall_time_s: float | None = Field(
        default=None,
        ge=0,
        allow_inf_nan=False,
        strict=True,
    )
    total_tokens: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def _complete_optional_metrics(self) -> _AgentCompletedAttributes:
        _validate_optional_group(
            self,
            frozenset(
                {
                    "exit_code",
                    "timed_out",
                    "snapshot_available",
                    "wall_time_s",
                    "total_tokens",
                }
            ),
            nullable=frozenset({"exit_code", "wall_time_s", "total_tokens"}),
        )
        return self


class _CleanupCompletedAttributes(_AuditAttributes):
    status: Literal["completed", "failed"]
    failure_count: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def _status_matches_failure_count(self) -> _CleanupCompletedAttributes:
        _validate_optional_group(self, frozenset({"failure_count"}))
        if self.failure_count is not None and (
            (self.status == "completed") != (self.failure_count == 0)
        ):
            raise ValueError("cleanup status does not match failure_count")
        return self


class _EvaluationStartedAttributes(_AuditAttributes):
    task_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SAFE_ATTRIBUTE_ID_PATTERN,
        strict=True,
    )
    trial: int = Field(gt=0, strict=True)


class _EvaluationFailedAttributes(_AuditAttributes):
    exception_type: str = Field(
        min_length=1,
        max_length=128,
        pattern=_EXCEPTION_TYPE_PATTERN,
        strict=True,
    )


class _TestsFinishedAttributes(_AuditAttributes):
    status: Literal["completed", "infrastructure_error"]
    resolved: bool = Field(strict=True)
    passed: int | None = Field(default=None, ge=0, strict=True)
    total: int | None = Field(default=None, ge=0, strict=True)
    command_exit_code: int | None = Field(default=None, strict=True)

    @model_validator(mode="after")
    def _passed_does_not_exceed_total(self) -> _TestsFinishedAttributes:
        _validate_optional_group(
            self,
            frozenset({"passed", "total", "command_exit_code"}),
            nullable=frozenset({"command_exit_code"}),
        )
        if (
            self.passed is not None
            and self.total is not None
            and self.passed > self.total
        ):
            raise ValueError("passed count exceeds total count")
        return self


class _TestsIntegrityRejectedAttributes(_AuditAttributes):
    status: Literal["integrity_rejected"]
    resolved: Literal[False]


class _ScannersFinishedAttributes(_AuditAttributes):
    status: Literal["completed"]
    finding_count: int | None = Field(default=None, ge=0, strict=True)
    scanner_count: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def _complete_optional_counts(self) -> _ScannersFinishedAttributes:
        _validate_optional_group(
            self,
            frozenset({"finding_count", "scanner_count"}),
        )
        return self


class _ScannersSkippedAttributes(_AuditAttributes):
    status: Literal["skipped"]


class _JudgeCompletedAttributes(_AuditAttributes):
    status: Literal["completed"]
    score_available: bool = Field(strict=True)
    dimension_count: int = Field(ge=0, strict=True)
    backend: Literal["claude", "codex"]
    model: str = Field(
        min_length=1,
        max_length=256,
        pattern=_EXACT_MODEL_PATTERN,
        strict=True,
    )


class _JudgeSkippedAttributes(_AuditAttributes):
    reason_code: Literal["disabled", "integrity", "secret_screen_incomplete"]


class _OutcomeDecidedAttributes(_AuditAttributes):
    status: Literal["accepted", "rejected", "infra_error"]
    check_count: int | None = Field(default=None, ge=0, strict=True)
    reason_count: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def _complete_optional_counts(self) -> _OutcomeDecidedAttributes:
        _validate_optional_group(
            self,
            frozenset({"check_count", "reason_count"}),
        )
        return self


class _RunCompletedAttributes(_AuditAttributes):
    status: Literal["accepted", "rejected", "infra_error"]


_EVENT_ATTRIBUTE_SCHEMAS: dict[str, TypeAdapter[Any]] = {
    "evaluation.requested": TypeAdapter(_EvaluationRequestedAttributes),
    "policy.admitted": TypeAdapter(_PolicyAdmittedAttributes),
    "agent.started": TypeAdapter(_AgentStartedAttributes),
    "agent.completed": TypeAdapter(_AgentCompletedAttributes),
    "cleanup.completed": TypeAdapter(_CleanupCompletedAttributes),
    "evaluation.started": TypeAdapter(_EvaluationStartedAttributes),
    "evaluation.failed": TypeAdapter(_EvaluationFailedAttributes),
    "tests.completed": TypeAdapter(
        _TestsFinishedAttributes | _TestsIntegrityRejectedAttributes
    ),
    "scanners.completed": TypeAdapter(
        _ScannersFinishedAttributes | _ScannersSkippedAttributes
    ),
    "judge.completed": TypeAdapter(_JudgeCompletedAttributes),
    "judge.skipped": TypeAdapter(_JudgeSkippedAttributes),
    "outcome.decided": TypeAdapter(_OutcomeDecidedAttributes),
    "run.completed": TypeAdapter(_RunCompletedAttributes),
}


class AuditError(ValueError):
    """Raised when an audit chain cannot be created or safely appended."""


def _normalize_attribute_key(key: str) -> str:
    normalized = unicodedata.normalize("NFKC", key)
    normalized = _CAMEL_BOUNDARY_RE.sub("_", normalized)
    return _NON_ALNUM_RE.sub("_", normalized.casefold()).strip("_")


def _json_attributes(
    value: Any, *, location: str = "attributes", depth: int = 0
) -> Any:
    """Return a detached, strict JSON value after applying the privacy policy."""

    if depth > 100:
        raise ValueError(f"{location} exceeds the maximum nesting depth")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{location} contains a non-finite number")
        return value
    if isinstance(value, list):
        return [
            _json_attributes(item, location=f"{location}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{location} contains a non-string key")
            normalized_key = _normalize_attribute_key(key)
            if (
                normalized_key in _SENSITIVE_ATTRIBUTE_KEYS
                or normalized_key.replace("_", "")
                in _SENSITIVE_ATTRIBUTE_KEYS_COLLAPSED
            ):
                raise ValueError(f"{location} contains forbidden sensitive key {key!r}")
            result[key] = _json_attributes(
                item,
                location=f"{location}.{key}",
                depth=depth + 1,
            )
        return result
    raise ValueError(f"{location} contains non-JSON type {type(value).__name__}")


def _validate_rfc3339(value: str) -> str:
    match = _RFC3339_RE.fullmatch(value)
    if match is None:
        raise ValueError("timestamp must be an RFC3339 date-time with a timezone")
    parsed_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(parsed_value)
    except ValueError as exc:
        raise ValueError("timestamp must be a valid RFC3339 date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value


class AuditEvent(BaseModel):
    """One strict event in an ``agent-eval.audit/v1`` hash chain."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["agent-eval.audit/v1"]
    sequence: int = Field(ge=0, strict=True)
    timestamp: str = Field(strict=True)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)
    span_id: str = Field(pattern=r"^[0-9a-f]{16}$", strict=True)
    parent_span_id: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{16}$",
        strict=True,
    )
    run_id: str = Field(min_length=1, strict=True)
    event_type: str = Field(min_length=1, strict=True)
    attributes: dict[str, Any]
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)

    @field_validator("timestamp")
    @classmethod
    def _timestamp_is_rfc3339(cls, value: str) -> str:
        return _validate_rfc3339(value)

    @field_validator("attributes", mode="before")
    @classmethod
    def _attributes_are_safe_json(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("attributes must be a JSON object")
        return _json_attributes(value)

    @model_validator(mode="after")
    def _event_attributes_match_schema(self) -> AuditEvent:
        attribute_schema = _EVENT_ATTRIBUTE_SCHEMAS.get(self.event_type)
        if attribute_schema is None:
            raise ValueError("event_type is not supported by the audit schema")
        try:
            attribute_schema.validate_python(self.attributes, strict=True)
        except ValidationError:
            raise ValueError(
                "attributes do not match the strict schema for this audit event type"
            ) from None
        return self


class AuditVerificationFailure(BaseModel):
    """One machine-readable reason an audit chain did not verify."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    code: str
    message: str
    line: int | None = None
    expected: str | None = None
    actual: str | None = None


class AuditVerificationResult(BaseModel):
    """Fail-closed verification result for an audit JSONL file."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: bool
    failures: list[AuditVerificationFailure] = Field(default_factory=list)
    event_count: int = Field(default=0, ge=0)
    final_hash: str | None = None
    run_id: str | None = None
    trace_id: str | None = None


def canonical_audit_json_bytes(value: Any) -> bytes:
    """Return the exact canonical UTF-8 representation used by audit events."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _event_payload(event: AuditEvent) -> dict[str, Any]:
    return event.model_dump(mode="json", exclude={"event_hash"})


def _event_digest(event: AuditEvent) -> str:
    return hashlib.sha256(canonical_audit_json_bytes(_event_payload(event))).hexdigest()


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class AuditChain:
    """Append-only writer for a new, durable audit hash chain.

    ``path`` must not already exist.  Creation uses ``O_EXCL`` and
    ``O_NOFOLLOW`` where available, and each successful append is flushed and
    fsynced before it is reported to the caller.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        run_id: str,
        trace_id: str | None = None,
    ) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise AuditError("run_id must be a non-empty string")
        if trace_id is None:
            trace_id = secrets.token_hex(16)
        if not isinstance(trace_id, str) or _TRACE_ID_RE.fullmatch(trace_id) is None:
            raise AuditError("trace_id must be 32 lowercase hexadecimal characters")

        try:
            target = os.fspath(path)
        except TypeError as exc:
            raise AuditError("path must be a filesystem path") from exc
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(target, flags, 0o600)
        except FileExistsError as exc:
            raise AuditError(f"audit path already exists: {path}") from exc
        except OSError as exc:
            raise AuditError(f"could not create audit path {path}: {exc}") from exc

        try:
            os.fchmod(fd, 0o600)
            opened = os.fdopen(fd, "wb")
        except Exception:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(target)
            raise

        self.path = Path(path)
        self._file = opened
        self._run_id = run_id
        self._trace_id = trace_id
        self._final_hash: str | None = None
        self._event_count = 0
        self._closed = False
        self._lock = threading.Lock()

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @property
    def final_hash(self) -> str | None:
        return self._final_hash

    @property
    def event_count(self) -> int:
        return self._event_count

    def append(
        self,
        event_type: str,
        attributes: dict[str, Any] | None = None,
        *,
        span_id: str | None = None,
        parent_span_id: str | None = None,
        timestamp: str | None = None,
    ) -> AuditEvent:
        """Validate, chain, durably append, and return one audit event."""

        with self._lock:
            if self._closed:
                raise AuditError("audit chain is closed")
            if span_id is None:
                span_id = secrets.token_hex(8)
            try:
                provisional = AuditEvent(
                    schema_version=AUDIT_SCHEMA_VERSION,
                    sequence=self._event_count,
                    timestamp=timestamp if timestamp is not None else _utc_timestamp(),
                    trace_id=self._trace_id,
                    span_id=span_id,
                    parent_span_id=parent_span_id,
                    run_id=self._run_id,
                    event_type=event_type,
                    attributes={} if attributes is None else attributes,
                    previous_hash=self._final_hash or GENESIS_HASH,
                    event_hash=GENESIS_HASH,
                )
            except ValidationError:
                raise AuditError(
                    "audit event failed strict schema validation"
                ) from None
            payload = _event_payload(provisional)
            digest = hashlib.sha256(canonical_audit_json_bytes(payload)).hexdigest()
            event = AuditEvent.model_validate({**payload, "event_hash": digest})
            encoded = canonical_audit_json_bytes(event.model_dump(mode="json"))
            if len(encoded) > MAX_AUDIT_EVENT_BYTES:
                raise AuditError(
                    f"serialized audit event exceeds {MAX_AUDIT_EVENT_BYTES} bytes"
                )

            try:
                self._file.write(encoded + b"\n")
                self._file.flush()
                os.fsync(self._file.fileno())
            except OSError as exc:
                self._closed = True
                try:
                    self._file.close()
                finally:
                    raise AuditError(
                        f"could not durably append audit event: {exc}"
                    ) from exc

            self._final_hash = digest
            self._event_count += 1
            return event

    def close(self) -> None:
        """Close the writer.  Calling ``close`` more than once is safe."""

        with self._lock:
            if not self._closed:
                self._file.close()
                self._closed = True

    def __enter__(self) -> AuditChain:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _failure(
    code: str,
    message: str,
    *,
    line: int | None = None,
    expected: object | None = None,
    actual: object | None = None,
) -> AuditVerificationFailure:
    return AuditVerificationFailure(
        code=code,
        message=message,
        line=line,
        expected=None if expected is None else str(expected),
        actual=None if actual is None else str(actual),
    )


def _result(
    failures: list[AuditVerificationFailure],
    *,
    event_count: int = 0,
    final_hash: str | None = None,
    run_id: str | None = None,
    trace_id: str | None = None,
) -> AuditVerificationResult:
    return AuditVerificationResult(
        ok=not failures,
        failures=failures,
        event_count=event_count,
        final_hash=final_hash,
        run_id=run_id,
        trace_id=trace_id,
    )


def _validation_code(error: ValidationError) -> str:
    locations = {str(item) for detail in error.errors() for item in detail["loc"]}
    for field, code in (
        ("sequence", "sequence_invalid"),
        ("timestamp", "timestamp_invalid"),
        ("trace_id", "trace_id_invalid"),
        ("run_id", "run_id_invalid"),
        ("previous_hash", "previous_hash_invalid"),
        ("event_hash", "event_hash_invalid"),
    ):
        if field in locations:
            return code
    return "schema_invalid"


def _verify_audit_chain(
    path: str | os.PathLike[str],
    *,
    expected_final_hash: str | None,
    expected_run_id: str | None,
) -> AuditVerificationResult:
    failures: list[AuditVerificationFailure] = []
    if expected_final_hash is not None and (
        not isinstance(expected_final_hash, str)
        or _SHA256_RE.fullmatch(expected_final_hash) is None
    ):
        failures.append(
            _failure(
                "expected_final_hash_invalid",
                "expected_final_hash must be 64 lowercase hexadecimal characters",
                actual=expected_final_hash,
            )
        )
        return _result(failures)
    if expected_run_id is not None and (
        not isinstance(expected_run_id, str) or not expected_run_id
    ):
        failures.append(
            _failure(
                "expected_run_id_invalid",
                "expected_run_id must be a non-empty string",
                actual=expected_run_id,
            )
        )
        return _result(failures)

    try:
        target = os.fspath(path)
        path_stat = os.lstat(target)
    except (OSError, TypeError) as exc:
        failures.append(
            _failure("file_unreadable", f"could not inspect audit file: {exc}")
        )
        return _result(failures)
    if stat.S_ISLNK(path_stat.st_mode):
        failures.append(
            _failure("symlink_rejected", "audit path must not be a symlink")
        )
        return _result(failures)
    if not stat.S_ISREG(path_stat.st_mode):
        failures.append(
            _failure("not_regular_file", "audit path must be a regular file")
        )
        return _result(failures)

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        failures.append(
            _failure("file_unreadable", f"could not open audit file: {exc}")
        )
        return _result(failures)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            failures.append(
                _failure("not_regular_file", "audit path must be a regular file")
            )
            return _result(failures)

        event_count = 0
        final_hash: str | None = None
        chain_run_id: str | None = None
        chain_trace_id: str | None = None
        with os.fdopen(fd, "rb", closefd=False) as stream:
            line_number = 0
            while True:
                raw = stream.readline(MAX_AUDIT_EVENT_BYTES + 2)
                if raw == b"":
                    break
                line_number += 1
                if not raw.endswith(b"\n"):
                    code = (
                        "event_too_large"
                        if len(raw) > MAX_AUDIT_EVENT_BYTES
                        else "noncanonical_json"
                    )
                    message = (
                        f"audit event exceeds {MAX_AUDIT_EVENT_BYTES} bytes"
                        if code == "event_too_large"
                        else "audit JSONL line must end with a newline"
                    )
                    failures.append(_failure(code, message, line=line_number))
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                encoded = raw[:-1]
                if len(encoded) > MAX_AUDIT_EVENT_BYTES:
                    failures.append(
                        _failure(
                            "event_too_large",
                            f"audit event exceeds {MAX_AUDIT_EVENT_BYTES} bytes",
                            line=line_number,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                try:
                    text = encoded.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    failures.append(
                        _failure(
                            "invalid_utf8",
                            f"audit event is not valid UTF-8: {exc}",
                            line=line_number,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                try:
                    value = json.loads(
                        text,
                        object_pairs_hook=_unique_object,
                        parse_constant=_reject_json_constant,
                    )
                except _DuplicateKeyError as exc:
                    failures.append(
                        _failure("duplicate_json_key", str(exc), line=line_number)
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                except (json.JSONDecodeError, ValueError, RecursionError) as exc:
                    failures.append(
                        _failure(
                            "invalid_json",
                            f"audit event is not valid JSON: {exc}",
                            line=line_number,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                try:
                    canonical = canonical_audit_json_bytes(value)
                except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                    failures.append(
                        _failure(
                            "invalid_json",
                            f"audit event cannot be represented safely: {exc}",
                            line=line_number,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                if encoded != canonical:
                    failures.append(
                        _failure(
                            "noncanonical_json",
                            "audit event is not canonical sorted compact JSON",
                            line=line_number,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                try:
                    event = AuditEvent.model_validate(value)
                except ValidationError as exc:
                    validation_code = _validation_code(exc)
                    model_level_error = any(
                        not detail["loc"] for detail in exc.errors()
                    )
                    claimed_hash = (
                        value.get("event_hash") if isinstance(value, dict) else None
                    )
                    if (
                        validation_code == "schema_invalid"
                        and model_level_error
                        and isinstance(claimed_hash, str)
                        and _SHA256_RE.fullmatch(claimed_hash) is not None
                    ):
                        payload = {
                            key: item
                            for key, item in value.items()
                            if key != "event_hash"
                        }
                        calculated_hash = hashlib.sha256(
                            canonical_audit_json_bytes(payload)
                        ).hexdigest()
                        if claimed_hash != calculated_hash:
                            failures.append(
                                _failure(
                                    "event_hash_mismatch",
                                    "audit event hash does not match its canonical payload",
                                    line=line_number,
                                    expected=calculated_hash,
                                    actual=claimed_hash,
                                )
                            )
                            return _result(
                                failures,
                                event_count=event_count,
                                final_hash=final_hash,
                                run_id=chain_run_id,
                                trace_id=chain_trace_id,
                            )
                    failures.append(
                        _failure(
                            validation_code,
                            "audit event does not match the strict schema",
                            line=line_number,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )

                if event.sequence != event_count:
                    failures.append(
                        _failure(
                            "sequence_mismatch",
                            "audit event sequence is not contiguous from zero",
                            line=line_number,
                            expected=event_count,
                            actual=event.sequence,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                if chain_trace_id is None:
                    chain_trace_id = event.trace_id
                elif event.trace_id != chain_trace_id:
                    failures.append(
                        _failure(
                            "trace_id_mismatch",
                            "audit event trace_id changed within the chain",
                            line=line_number,
                            expected=chain_trace_id,
                            actual=event.trace_id,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                if chain_run_id is None:
                    chain_run_id = event.run_id
                    if expected_run_id is not None and chain_run_id != expected_run_id:
                        failures.append(
                            _failure(
                                "run_id_mismatch",
                                "audit chain run_id does not match the expected run_id",
                                line=line_number,
                                expected=expected_run_id,
                                actual=chain_run_id,
                            )
                        )
                        return _result(
                            failures,
                            event_count=event_count,
                            final_hash=final_hash,
                            run_id=chain_run_id,
                            trace_id=chain_trace_id,
                        )
                elif event.run_id != chain_run_id:
                    failures.append(
                        _failure(
                            "run_id_mismatch",
                            "audit event run_id changed within the chain",
                            line=line_number,
                            expected=chain_run_id,
                            actual=event.run_id,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )

                expected_previous = final_hash or GENESIS_HASH
                if event.previous_hash != expected_previous:
                    failures.append(
                        _failure(
                            "previous_hash_mismatch",
                            "audit event does not reference the preceding event hash",
                            line=line_number,
                            expected=expected_previous,
                            actual=event.previous_hash,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )
                calculated_hash = _event_digest(event)
                if event.event_hash != calculated_hash:
                    failures.append(
                        _failure(
                            "event_hash_mismatch",
                            "audit event hash does not match its canonical payload",
                            line=line_number,
                            expected=calculated_hash,
                            actual=event.event_hash,
                        )
                    )
                    return _result(
                        failures,
                        event_count=event_count,
                        final_hash=final_hash,
                        run_id=chain_run_id,
                        trace_id=chain_trace_id,
                    )

                final_hash = event.event_hash
                event_count += 1

        if event_count == 0:
            failures.append(_failure("empty_chain", "audit chain contains no events"))
        elif expected_final_hash is not None and final_hash != expected_final_hash:
            failures.append(
                _failure(
                    "final_hash_mismatch",
                    "audit chain final hash does not match the expected hash",
                    expected=expected_final_hash,
                    actual=final_hash,
                )
            )
        return _result(
            failures,
            event_count=event_count,
            final_hash=final_hash,
            run_id=chain_run_id,
            trace_id=chain_trace_id,
        )
    finally:
        os.close(fd)


def verify_audit_chain(
    path: str | os.PathLike[str],
    expected_final_hash: str | None = None,
    expected_run_id: str | None = None,
) -> AuditVerificationResult:
    """Verify an audit chain without raising for malformed or unsafe input."""

    try:
        return _verify_audit_chain(
            path,
            expected_final_hash=expected_final_hash,
            expected_run_id=expected_run_id,
        )
    except Exception as exc:  # Defensive boundary for hostile audit input.
        return _result(
            [
                _failure(
                    "verification_error",
                    f"audit verification failed safely: {type(exc).__name__}: {exc}",
                )
            ]
        )
