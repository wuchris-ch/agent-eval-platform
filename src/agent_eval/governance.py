"""Fail-closed admission policy and audit evidence for evaluation runs.

The request is deliberately separate from runtime configuration.  Admission
checks both so that changing a task, agent, or model after authorization cannot
silently broaden what is executed.  Identities in request files are assertions,
not authentication claims; callers must authenticate them at their trust
boundary.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import json
import math
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Bundle loading surfaces this error to callers, so it is part of the governance
# public API. The redundant alias is the PEP 484 explicit re-export form that
# mypy requires under `no_implicit_reexport`.
from .yaml_utils import DuplicateKeyError as DuplicateKeyError  # noqa: PLC0414
from .yaml_utils import load_unique_yaml

REQUEST_SCHEMA_VERSION = "agent-eval.request/v2"
POLICY_SCHEMA_VERSION = "agent-eval.policy/v2"
DECISION_SCHEMA_VERSION = "agent-eval.decision/v2"
EVIDENCE_SCHEMA_VERSION = "agent-eval.governance-evidence/v2"

DataClassification = Literal["public", "internal", "confidential", "restricted"]
RetentionClass = Literal["ephemeral", "standard", "regulated"]
NetworkMode = Literal["proxy", "open"]
ModelStatus = Literal["approved", "deprecated", "blocked"]

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]*$")
_SAFE_GLOB = re.compile(r"^[A-Za-z0-9*?\[\]][A-Za-z0-9._:@/+~*?\[\]!-]*$")
_EXACT_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+~-]*$")
_LABEL_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GOVERNED_IMAGE_REF = re.compile(
    r"^agent-eval/[a-z0-9](?:[a-z0-9.-]{0,62}):governed-[0-9a-f]{64}$"
)
_PLATFORM = re.compile(r"^linux/[a-z0-9_]+$")


def _strict_config() -> ConfigDict:
    return ConfigDict(extra="forbid", strict=True, frozen=True)


def _validate_safe(value: str, *, field: str, maximum: int = 128) -> str:
    if len(value) > maximum or not _SAFE_VALUE.fullmatch(value):
        raise ValueError(f"{field} must be 1-{maximum} safe, non-whitespace characters")
    if "/" in value and any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError(f"{field} must not contain unsafe path segments")
    return value


def _validate_revision(value: str, *, field: str) -> str:
    return _validate_safe(value, field=field, maximum=128)


def _validate_unique(values: Sequence[str], *, field: str) -> list[str]:
    normalized = list(values)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field} must not contain duplicates")
    return normalized


def _validate_globs(values: Sequence[str], *, field: str) -> list[str]:
    normalized = _validate_unique(values, field=field)
    for value in normalized:
        if len(value) > 128 or not _SAFE_GLOB.fullmatch(value):
            raise ValueError(f"{field} contains an invalid glob pattern")
        index = 0
        while index < len(value):
            if value[index] == "]":
                raise ValueError(f"{field} contains an invalid glob pattern")
            if value[index] != "[":
                index += 1
                continue
            closing = value.find("]", index + 1)
            if closing == -1 or value[index + 1 : closing] in {"", "!"}:
                raise ValueError(f"{field} contains an invalid glob pattern")
            if "[" in value[index + 1 : closing]:
                raise ValueError(f"{field} contains an invalid glob pattern")
            index = closing + 1
        try:
            re.compile(fnmatch.translate(value))
        except re.error as exc:
            raise ValueError(f"{field} contains an invalid glob pattern") from exc
    return normalized


def _parse_canonical_uuid(value: object, *, field: str) -> object:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        return value
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a UUID") from exc
    if value != str(parsed):
        raise ValueError(f"{field} must use canonical lowercase UUID syntax")
    return parsed


class _EvaluationRequestBase(BaseModel):
    """Strict shared identity fields for versioned authorization requests."""

    model_config = _strict_config()

    request_id: UUID
    idempotency_key: str
    tenant_id: str
    project_id: str
    asserted_actor: str
    task_id: str
    agent: str
    model: str
    data_classification: DataClassification
    retention_class: RetentionClass
    labels: dict[str, str] = Field(default_factory=dict, max_length=32)

    @field_validator("request_id", mode="before")
    @classmethod
    def _valid_request_id(cls, value: object) -> object:
        return _parse_canonical_uuid(value, field="request_id")

    @field_validator("idempotency_key")
    @classmethod
    def _valid_idempotency_key(cls, value: str) -> str:
        return _validate_safe(value, field="idempotency_key", maximum=128)

    @field_validator("tenant_id", "project_id", "task_id", "agent")
    @classmethod
    def _valid_identifier(cls, value: str, info: Any) -> str:
        return _validate_safe(value, field=info.field_name, maximum=128)

    @field_validator("asserted_actor")
    @classmethod
    def _valid_actor(cls, value: str) -> str:
        return _validate_safe(value, field="asserted_actor", maximum=256)

    @field_validator("model")
    @classmethod
    def _valid_model(cls, value: str) -> str:
        if len(value) > 256 or not _EXACT_MODEL.fullmatch(value):
            raise ValueError("model must be a bounded exact model identifier")
        return value

    @field_validator("labels")
    @classmethod
    def _valid_labels(cls, labels: dict[str, str]) -> dict[str, str]:
        for key, value in labels.items():
            if len(key) > 63 or not _LABEL_KEY.fullmatch(key):
                raise ValueError("label keys must be bounded safe identifiers")
            if not value or len(value) > 256 or not value.isprintable():
                raise ValueError("label values must be 1-256 printable characters")
        return labels


class LegacyEvaluationRequestV1(_EvaluationRequestBase):
    """Read-only historical request shape with the original limit names."""

    schema_version: Literal["agent-eval.request/v1"]
    max_total_tokens: int | None = Field(default=None, gt=0, strict=True)
    max_cost_usd: float | None = Field(
        default=None, gt=0, allow_inf_nan=False, strict=True
    )


class EvaluationRequest(_EvaluationRequestBase):
    """A bounded v2 request with explicitly observed usage thresholds."""

    schema_version: Literal["agent-eval.request/v2"]
    max_observed_total_tokens: int | None = Field(default=None, gt=0, strict=True)
    max_observed_cost_usd: float | None = Field(
        default=None, gt=0, allow_inf_nan=False, strict=True
    )


class GovernanceRules(BaseModel):
    """Organization-level limits.  Empty allowlists intentionally match nothing."""

    model_config = _strict_config()

    allowed_tenants: list[str] = Field(max_length=128)
    allowed_projects: list[str] = Field(max_length=128)
    allowed_tasks: list[str] = Field(max_length=128)
    allowed_network_modes: list[NetworkMode] = Field(max_length=2)
    allowed_egress_domains: list[str] = Field(default_factory=list, max_length=128)
    allowed_proxy_images: list[str] = Field(default_factory=list, max_length=32)
    allowed_scanner_identities: list[str] = Field(default_factory=list, max_length=32)
    allowed_data_classifications: list[DataClassification] = Field(max_length=4)
    allowed_retention_classes: list[RetentionClass] = Field(max_length=3)
    require_scans: bool = True
    require_judge: bool = False
    require_broker_credentials: bool
    max_trials: int = Field(gt=0, strict=True)
    max_agent_seconds: int = Field(gt=0, strict=True)
    max_eval_seconds: int = Field(gt=0, strict=True)
    max_observed_total_tokens: int = Field(gt=0, strict=True)
    max_observed_cost_usd: float = Field(gt=0, allow_inf_nan=False, strict=True)

    @field_validator("allowed_tenants", "allowed_projects", "allowed_tasks")
    @classmethod
    def _valid_allowlist(cls, values: list[str], info: Any) -> list[str]:
        return _validate_globs(values, field=info.field_name)

    @field_validator("allowed_egress_domains")
    @classmethod
    def _valid_egress_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            domain = value.strip().lower()
            bare = domain.removeprefix(".")
            if not bare or "/" in domain or not re.fullmatch(r"[a-z0-9.-]+", bare):
                raise ValueError("allowed_egress_domains must contain DNS suffixes")
            suffix = f".{bare}"
            if suffix in normalized:
                raise ValueError("allowed_egress_domains must not contain duplicates")
            normalized.append(suffix)
        return normalized

    @field_validator("allowed_proxy_images")
    @classmethod
    def _valid_proxy_images(cls, values: list[str]) -> list[str]:
        normalized = _validate_unique(values, field="allowed_proxy_images")
        for value in normalized:
            prefix, separator, digest = value.rpartition("@sha256:")
            if (
                not separator
                or not prefix
                or _SHA256.fullmatch(digest) is None
                or len(value) > 512
            ):
                raise ValueError(
                    "allowed_proxy_images must be exact sha256-pinned images"
                )
        return normalized

    @field_validator("allowed_scanner_identities")
    @classmethod
    def _valid_scanner_identities(cls, values: list[str]) -> list[str]:
        normalized = _validate_unique(values, field="allowed_scanner_identities")
        if any(_SHA256.fullmatch(value) is None for value in normalized):
            raise ValueError(
                "allowed_scanner_identities must contain lowercase SHA-256 values"
            )
        return normalized

    @field_validator(
        "allowed_network_modes",
        "allowed_data_classifications",
        "allowed_retention_classes",
    )
    @classmethod
    def _unique_enum_allowlist(cls, values: list[str], info: Any) -> list[str]:
        return _validate_unique(values, field=info.field_name)

    @model_validator(mode="after")
    def _scanner_allowlist_required(self) -> GovernanceRules:
        if self.require_scans and not self.allowed_scanner_identities:
            raise ValueError(
                "require_scans requires at least one approved scanner identity"
            )
        return self


class ApprovedTaskImage(BaseModel):
    """One policy-approved, single-platform task image and build assertion.

    Governed execution never creates this approval.  An operator promotes an
    already-built manifest into the task registry after reviewing its builder
    evidence.  The policy snapshot is therefore the authorization boundary,
    while the runtime independently verifies the local OCI manifest digest.
    """

    model_config = _strict_config()

    platform: str
    reference: str
    manifest_digest: str
    builder_id: str
    build_type: str
    source_revision: str
    provenance_sha256: str

    @field_validator("platform")
    @classmethod
    def _valid_platform(cls, value: str) -> str:
        if _PLATFORM.fullmatch(value) is None:
            raise ValueError("approved image platform must be an exact Linux platform")
        return value

    @field_validator("reference")
    @classmethod
    def _valid_reference(cls, value: str) -> str:
        if _GOVERNED_IMAGE_REF.fullmatch(value) is None:
            raise ValueError(
                "approved image reference must be a content-derived governed ref"
            )
        return value

    @field_validator("manifest_digest")
    @classmethod
    def _valid_manifest_digest(cls, value: str) -> str:
        if _IMAGE_DIGEST.fullmatch(value) is None:
            raise ValueError("approved image manifest_digest must be sha256:<digest>")
        return value

    @field_validator("builder_id", "build_type")
    @classmethod
    def _valid_builder_identity(cls, value: str, info: Any) -> str:
        if (
            not 1 <= len(value) <= 512
            or not value.isprintable()
            or any(character.isspace() for character in value)
        ):
            raise ValueError(
                f"approved image {info.field_name} must be a bounded exact URI-like value"
            )
        return value

    @field_validator("source_revision")
    @classmethod
    def _valid_source_revision(cls, value: str) -> str:
        return _validate_revision(value, field="approved image source_revision")

    @field_validator("provenance_sha256")
    @classmethod
    def _valid_provenance_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError(
                "approved image provenance_sha256 must be a lowercase SHA-256 value"
            )
        return value

    @model_validator(mode="after")
    def _content_derived_identity(self) -> ApprovedTaskImage:
        digest = self.manifest_digest.removeprefix("sha256:")
        if not self.reference.endswith(f":governed-{digest}"):
            raise ValueError(
                "approved image reference must be derived from manifest_digest"
            )
        return self


class TaskRegistryEntry(BaseModel):
    """Exact approved task content and execution recipes.

    Name allowlists are useful for coarse policy, but they are not an integrity
    boundary.  A governed run must also match one immutable task tree and one
    explicitly approved execution-specification digest before any build or
    credential side effect is allowed.
    """

    model_config = _strict_config()

    task_id: str
    task_tree_sha256: str
    execution_spec_digests: list[str] = Field(min_length=1, max_length=32)
    approved_images: list[ApprovedTaskImage] = Field(min_length=1, max_length=32)
    status: ModelStatus = "approved"

    @field_validator("task_id")
    @classmethod
    def _valid_task_id(cls, value: str) -> str:
        return _validate_safe(value, field="task_id", maximum=128)

    @field_validator("task_tree_sha256")
    @classmethod
    def _valid_tree_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("task_tree_sha256 must be a lowercase SHA-256 value")
        return value

    @field_validator("execution_spec_digests")
    @classmethod
    def _valid_execution_digests(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("execution_spec_digests must not contain duplicates")
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError(
                "execution_spec_digests must contain lowercase SHA-256 values"
            )
        return values

    @field_validator("approved_images")
    @classmethod
    def _unique_approved_platforms(
        cls, values: list[ApprovedTaskImage]
    ) -> list[ApprovedTaskImage]:
        platforms = [value.platform for value in values]
        if len(platforms) != len(set(platforms)):
            raise ValueError(
                "approved_images must contain at most one image per platform"
            )
        return values

    @model_validator(mode="after")
    def _approved_images_match_task(self) -> TaskRegistryEntry:
        expected_prefix = f"agent-eval/{self.task_id}:governed-"
        if any(
            not image.reference.startswith(expected_prefix)
            for image in self.approved_images
        ):
            raise ValueError("approved image reference must match task_id")
        return self


class TaskRegistry(BaseModel):
    """Versioned exact task approvals, separate from model approvals."""

    model_config = _strict_config()

    registry_id: str
    revision: str
    tasks: list[TaskRegistryEntry] = Field(min_length=1, max_length=4096)

    @field_validator("registry_id")
    @classmethod
    def _valid_registry_id(cls, value: str) -> str:
        return _validate_safe(value, field="task_registry.registry_id", maximum=128)

    @field_validator("revision")
    @classmethod
    def _valid_revision(cls, value: str) -> str:
        return _validate_revision(value, field="task_registry.revision")

    @model_validator(mode="after")
    def _unique_tasks(self) -> TaskRegistry:
        task_ids = [entry.task_id for entry in self.tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("task registry contains a duplicate task_id")
        return self


class _RegistryIdentity(BaseModel):
    """Shared exact identity and data-handling approval for one model use."""

    model_config = _strict_config()

    adapter: str
    model: str
    provider: str
    status: ModelStatus
    allowed_data_classifications: list[DataClassification] = Field(
        min_length=1, max_length=4
    )

    @field_validator("adapter", "provider")
    @classmethod
    def _valid_safe_identifier(cls, value: str, info: Any) -> str:
        return _validate_safe(value, field=info.field_name, maximum=128)

    @field_validator("model")
    @classmethod
    def _valid_exact_model(cls, value: str) -> str:
        if len(value) > 256 or not _EXACT_MODEL.fullmatch(value):
            raise ValueError("model must be a bounded exact model identifier")
        if any(character in value for character in "*?["):
            raise ValueError("model registry entries must name an exact model")
        return value

    @field_validator("allowed_data_classifications")
    @classmethod
    def _unique_classifications(cls, values: list[str]) -> list[str]:
        return _validate_unique(values, field="allowed_data_classifications")


class ModelRegistryEntry(_RegistryIdentity):
    """One model registration and its post-run usage observation thresholds."""

    max_observed_total_tokens: int = Field(gt=0, strict=True)
    max_observed_cost_usd: float = Field(gt=0, allow_inf_nan=False, strict=True)

    @field_validator("adapter")
    @classmethod
    def _coding_adapter_only(cls, value: str) -> str:
        if value.startswith("judge:"):
            raise ValueError("coding model entries cannot use the judge: namespace")
        return value


class JudgeRegistryEntry(_RegistryIdentity):
    """One judge identity approval without unenforceable local spend claims."""

    adapter: Literal["judge:claude", "judge:codex"]


class ModelRegistry(BaseModel):
    model_config = _strict_config()

    registry_id: str
    revision: str
    models: list[ModelRegistryEntry | JudgeRegistryEntry] = Field(max_length=1024)

    @field_validator("registry_id")
    @classmethod
    def _valid_registry_id(cls, value: str) -> str:
        return _validate_safe(value, field="registry_id", maximum=128)

    @field_validator("revision")
    @classmethod
    def _valid_revision(cls, value: str) -> str:
        return _validate_revision(value, field="model_registry.revision")

    @model_validator(mode="after")
    def _unique_exact_models(self) -> ModelRegistry:
        keys = [(entry.adapter, entry.model) for entry in self.models]
        if len(keys) != len(set(keys)):
            raise ValueError("model registry contains a duplicate adapter/model entry")
        return self


class GovernanceBundle(BaseModel):
    """A versioned policy and exact model registry evaluated as one snapshot."""

    model_config = _strict_config()

    schema_version: Literal["agent-eval.policy/v2"]
    policy_id: str
    revision: str
    rules: GovernanceRules
    task_registry: TaskRegistry
    model_registry: ModelRegistry

    @field_validator("policy_id")
    @classmethod
    def _valid_policy_id(cls, value: str) -> str:
        return _validate_safe(value, field="policy_id", maximum=128)

    @field_validator("revision")
    @classmethod
    def _valid_revision(cls, value: str) -> str:
        return _validate_revision(value, field="revision")


class PolicyReason(BaseModel):
    model_config = _strict_config()

    code: str
    message: str

    @field_validator("code")
    @classmethod
    def _valid_code(cls, value: str) -> str:
        if len(value) > 64 or not re.fullmatch(r"[a-z][a-z0-9_]*", value):
            raise ValueError("reason code must be a bounded snake-case identifier")
        return value

    @field_validator("message")
    @classmethod
    def _valid_message(cls, value: str) -> str:
        if not value or len(value) > 512 or not value.isprintable():
            raise ValueError("reason message must be 1-512 printable characters")
        return value


class EffectiveLimits(BaseModel):
    """Hard execution limits plus post-run usage observation thresholds."""

    model_config = _strict_config()

    max_trials: int = Field(gt=0, strict=True)
    max_agent_seconds: int = Field(gt=0, strict=True)
    max_eval_seconds: int = Field(gt=0, strict=True)
    max_observed_total_tokens: int = Field(gt=0, strict=True)
    max_observed_cost_usd: float = Field(gt=0, allow_inf_nan=False, strict=True)


class PolicyDecision(BaseModel):
    """Deterministic admission result plus generated correlation metadata."""

    model_config = _strict_config()

    schema_version: Literal["agent-eval.decision/v2"] = DECISION_SCHEMA_VERSION
    decision_stage: Literal["preflight", "execution"]
    preflight_decision_id: UUID | None = None
    preflight_decision_digest: str | None = None
    decision_id: UUID = Field(default_factory=uuid4)
    trace_id: str = Field(default_factory=lambda: uuid4().hex)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    allowed: bool
    request_id: UUID
    request_digest: str
    policy_id: str
    policy_revision: str
    policy_digest: str
    task_registry_id: str
    task_registry_revision: str
    task_registry_digest: str
    registry_id: str
    registry_revision: str
    registry_digest: str
    sanitized_input: dict[str, Any]
    reasons: list[PolicyReason]
    effective_limits: EffectiveLimits
    matched_task: TaskRegistryEntry | None
    matched_model: ModelRegistryEntry | None
    matched_judge: JudgeRegistryEntry | None

    @field_validator(
        "decision_id", "preflight_decision_id", "request_id", mode="before"
    )
    @classmethod
    def _valid_uuid_fields(cls, value: object, info: Any) -> object:
        return _parse_canonical_uuid(value, field=info.field_name)

    @field_validator("trace_id")
    @classmethod
    def _valid_trace_id(cls, value: str) -> str:
        if not _TRACE_ID.fullmatch(value):
            raise ValueError("trace_id must be 32 lowercase hexadecimal characters")
        return value

    @field_validator("decided_at")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("decided_at must be timezone-aware")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("decided_at must use UTC")
        return value

    @field_validator(
        "request_digest",
        "policy_digest",
        "task_registry_digest",
        "registry_digest",
    )
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("digests must be lowercase SHA-256 values")
        return value

    @field_validator("preflight_decision_digest")
    @classmethod
    def _valid_optional_digest(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.fullmatch(value):
            raise ValueError("preflight decision digest must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def _valid_stage_link(self) -> PolicyDecision:
        linked = (
            self.preflight_decision_id is not None,
            self.preflight_decision_digest is not None,
        )
        if self.decision_stage == "preflight" and any(linked):
            raise ValueError("preflight decisions cannot link another preflight")
        if self.decision_stage == "execution" and not all(linked):
            raise ValueError("execution decisions must link their preflight")
        return self


class LegacyEffectiveLimitsV1(BaseModel):
    """Read-only pre-v2 names retained for historical evidence."""

    model_config = _strict_config()

    max_trials: int = Field(gt=0, strict=True)
    max_agent_seconds: int = Field(gt=0, strict=True)
    max_eval_seconds: int = Field(gt=0, strict=True)
    max_total_tokens: int = Field(gt=0, strict=True)
    max_cost_usd: float = Field(gt=0, allow_inf_nan=False, strict=True)


class LegacyModelRegistryEntryV1(_RegistryIdentity):
    """Read-only coding-model entry embedded in historical evidence."""

    max_total_tokens: int = Field(gt=0, strict=True)
    max_cost_usd: float = Field(gt=0, allow_inf_nan=False, strict=True)


class LegacyGovernanceEvidenceV1(BaseModel):
    """Read-only shape for pre-task-registry governed run history.

    Version 1 evidence remains parseable for reports and migration, but it must
    never be promoted to current evidence because it did not authorize an exact
    task registry entry.
    """

    model_config = _strict_config()

    schema_version: Literal["agent-eval.governance-evidence/v1"]
    decision_stage: Literal["execution"] = "execution"
    preflight_decision_id: UUID
    preflight_decision_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_id: UUID
    trace_id: str
    decided_at: datetime
    allowed: bool
    request_id: UUID
    idempotency_key: str
    tenant_id: str
    project_id: str
    asserted_actor: str
    identity_assurance: Literal["asserted-unverified"] = "asserted-unverified"
    data_classification: DataClassification
    retention_class: RetentionClass
    request_digest: str
    policy_id: str
    policy_revision: str
    policy_digest: str
    registry_id: str
    registry_revision: str
    registry_digest: str
    task_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_spec_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    task_image_ref: str = Field(
        pattern=(
            r"^agent-eval/[a-z0-9](?:[a-z0-9.-]{0,62}):"
            r"governed-[0-9a-f]{64}$"
        )
    )
    task_image_platform: str = Field(pattern=r"^linux/[a-z0-9_]+$")
    run_scans: bool
    run_judge: bool
    judge_backend: Literal["claude", "codex"] | None
    judge_model: str | None
    reason_codes: list[str]
    effective_limits: LegacyEffectiveLimitsV1
    matched_model: LegacyModelRegistryEntryV1 | None
    matched_judge: JudgeRegistryEntry | None


class GovernanceEvidence(BaseModel):
    """Governance subset intended for durable run attestations."""

    model_config = _strict_config()

    schema_version: Literal["agent-eval.governance-evidence/v2"] = (
        EVIDENCE_SCHEMA_VERSION
    )
    decision_stage: Literal["execution"] = "execution"
    preflight_decision_id: UUID
    preflight_decision_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_id: UUID
    trace_id: str
    decided_at: datetime
    allowed: bool
    request_id: UUID
    idempotency_key: str
    tenant_id: str
    project_id: str
    asserted_actor: str
    identity_assurance: Literal["asserted-unverified"] = "asserted-unverified"
    data_classification: DataClassification
    retention_class: RetentionClass
    request_digest: str
    policy_id: str
    policy_revision: str
    policy_digest: str
    task_registry_id: str
    task_registry_revision: str
    task_registry_digest: str
    registry_id: str
    registry_revision: str
    registry_digest: str
    task_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_spec_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    task_image_ref: str = Field(
        pattern=(
            r"^agent-eval/[a-z0-9](?:[a-z0-9.-]{0,62}):"
            r"governed-[0-9a-f]{64}$"
        )
    )
    task_image_platform: str = Field(pattern=r"^linux/[a-z0-9_]+$")
    run_scans: bool
    scanner_identity_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    scanner_promotion_ready: bool = False
    run_judge: bool
    judge_backend: Literal["claude", "codex"] | None
    judge_model: str | None
    reason_codes: list[str]
    effective_limits: EffectiveLimits
    matched_task: TaskRegistryEntry
    matched_model: ModelRegistryEntry | None
    matched_judge: JudgeRegistryEntry | None

    @classmethod
    def from_decision(
        cls, request: EvaluationRequest, decision: PolicyDecision
    ) -> GovernanceEvidence:
        """Bind an admission decision to its original asserted request identity."""

        expected_digest = sha256_json(request)
        if decision.request_id != request.request_id:
            raise ValueError("decision request_id does not match the request")
        if decision.request_digest != expected_digest:
            raise ValueError("decision request digest does not match the request")
        if decision.decision_stage != "execution":
            raise ValueError("governance evidence requires an execution decision")
        task_image_digest = decision.sanitized_input.get("task_image_digest")
        task_image_ref = decision.sanitized_input.get("task_image_ref")
        task_image_platform = decision.sanitized_input.get("task_image_platform")
        if (
            not isinstance(task_image_digest, str)
            or _IMAGE_DIGEST.fullmatch(task_image_digest) is None
        ):
            raise ValueError("governance evidence requires an exact task image digest")
        if (
            not isinstance(task_image_ref, str)
            or _GOVERNED_IMAGE_REF.fullmatch(task_image_ref) is None
            or not isinstance(task_image_platform, str)
            or _PLATFORM.fullmatch(task_image_platform) is None
        ):
            raise ValueError(
                "governance evidence requires an exact task image identity"
            )
        run_judge = decision.sanitized_input.get("run_judge")
        run_scans = decision.sanitized_input.get("run_scans")
        scanner_identity = decision.sanitized_input.get("scanner_identity_sha256")
        scanner_ready = decision.sanitized_input.get("scanner_promotion_ready")
        if run_scans is True:
            if (
                not isinstance(scanner_identity, str)
                or _SHA256.fullmatch(scanner_identity) is None
                or scanner_ready is not True
            ):
                raise ValueError(
                    "governance evidence requires a promotion-ready scanner identity"
                )
        elif scanner_identity is not None or scanner_ready is not False:
            raise ValueError("disabled scans cannot carry a scanner identity")
        judge_backend = decision.sanitized_input.get("judge_backend")
        judge_model = decision.sanitized_input.get("judge_model")
        if run_judge is True:
            if (
                judge_backend not in {"claude", "codex"}
                or not isinstance(judge_model, str)
                or decision.matched_judge is None
                or decision.matched_judge.adapter != f"judge:{judge_backend}"
                or decision.matched_judge.model != judge_model
            ):
                raise ValueError(
                    "governance evidence requires an approved exact judge identity"
                )
        elif judge_backend is not None or judge_model is not None:
            raise ValueError("disabled judge cannot carry a judge identity")
        if (
            decision.preflight_decision_id is None
            or decision.preflight_decision_digest is None
        ):
            raise ValueError("execution decision is missing its preflight link")
        if (
            decision.matched_task is None
            or decision.matched_task.status != "approved"
            or decision.matched_task.task_id != request.task_id
            or decision.matched_task.task_tree_sha256
            != decision.sanitized_input.get("task_tree_sha256")
            or decision.sanitized_input.get("execution_spec_digest")
            not in decision.matched_task.execution_spec_digests
        ):
            raise ValueError(
                "governance evidence requires an approved exact task identity"
            )
        return cls(
            decision_stage="execution",
            preflight_decision_id=decision.preflight_decision_id,
            preflight_decision_digest=decision.preflight_decision_digest,
            decision_id=decision.decision_id,
            trace_id=decision.trace_id,
            decided_at=decision.decided_at,
            allowed=decision.allowed,
            request_id=request.request_id,
            idempotency_key=request.idempotency_key,
            tenant_id=request.tenant_id,
            project_id=request.project_id,
            asserted_actor=request.asserted_actor,
            data_classification=request.data_classification,
            retention_class=request.retention_class,
            request_digest=decision.request_digest,
            policy_id=decision.policy_id,
            policy_revision=decision.policy_revision,
            policy_digest=decision.policy_digest,
            task_registry_id=decision.task_registry_id,
            task_registry_revision=decision.task_registry_revision,
            task_registry_digest=decision.task_registry_digest,
            registry_id=decision.registry_id,
            registry_revision=decision.registry_revision,
            registry_digest=decision.registry_digest,
            task_tree_sha256=decision.sanitized_input["task_tree_sha256"],
            execution_spec_digest=decision.sanitized_input["execution_spec_digest"],
            task_image_digest=task_image_digest,
            task_image_ref=task_image_ref,
            task_image_platform=task_image_platform,
            run_scans=run_scans,
            scanner_identity_sha256=scanner_identity,
            scanner_promotion_ready=scanner_ready,
            run_judge=run_judge,
            judge_backend=judge_backend,
            judge_model=judge_model,
            reason_codes=[reason.code for reason in decision.reasons],
            effective_limits=decision.effective_limits,
            matched_task=decision.matched_task,
            matched_model=decision.matched_model,
            matched_judge=decision.matched_judge,
        )


def validate_execution_continuity(
    preflight: PolicyDecision, execution: PolicyDecision
) -> None:
    """Require the final decision to add only its immutable image identity."""

    if (
        preflight.decision_stage != "preflight"
        or not preflight.allowed
        or execution.decision_stage != "execution"
        or execution.preflight_decision_id != preflight.decision_id
        or execution.preflight_decision_digest != sha256_json(preflight)
    ):
        raise ValueError("execution decision does not match its preflight")
    image_fields = {
        "task_image_digest",
        "task_image_ref",
        "task_image_platform",
    }
    if set(execution.sanitized_input) != set(preflight.sanitized_input):
        raise ValueError("execution decision input shape differs from preflight")
    if any(
        execution.sanitized_input[key] != preflight.sanitized_input[key]
        for key in execution.sanitized_input.keys() - image_fields
    ):
        raise ValueError("execution decision broadens or changes its preflight")
    if any(preflight.sanitized_input.get(key) is not None for key in image_fields):
        raise ValueError("preflight decision contains an image identity")

    # Re-evaluating the same sanitized runtime fields under a different policy
    # or registry is not continuity. Bind the complete authorization snapshot,
    # selected entries, reasons, and effective limits across both stages so an
    # execution decision cannot widen a previously admitted preflight.
    bound_fields = (
        "schema_version",
        "request_id",
        "request_digest",
        "policy_id",
        "policy_revision",
        "policy_digest",
        "task_registry_id",
        "task_registry_revision",
        "task_registry_digest",
        "registry_id",
        "registry_revision",
        "registry_digest",
        "reasons",
        "effective_limits",
        "matched_task",
        "matched_model",
        "matched_judge",
    )
    changed = [
        field
        for field in bound_fields
        if getattr(preflight, field) != getattr(execution, field)
    ]
    if changed:
        raise ValueError(
            "execution decision changes its preflight authorization snapshot: "
            + ", ".join(changed)
        )


def _load_yaml_object(path: Path | str) -> Mapping[str, Any]:
    source = Path(path)
    raw = load_unique_yaml(source.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError(f"{source} must contain a YAML object")
    return raw


def load_evaluation_request(path: Path | str) -> EvaluationRequest:
    """Load and strictly validate a duplicate-key-safe request YAML file."""

    document = _load_yaml_object(path)
    if document.get("schema_version") == "agent-eval.request/v1":
        legacy = LegacyEvaluationRequestV1.model_validate(document)
        normalized = legacy.model_dump(mode="python")
        normalized["schema_version"] = REQUEST_SCHEMA_VERSION
        normalized["max_observed_total_tokens"] = normalized.pop("max_total_tokens")
        normalized["max_observed_cost_usd"] = normalized.pop("max_cost_usd")
        return EvaluationRequest.model_validate(normalized)
    return EvaluationRequest.model_validate(document)


def load_governance_bundle(path: Path | str) -> GovernanceBundle:
    """Load and strictly validate a duplicate-key-safe policy YAML file."""

    document = _load_yaml_object(path)
    if document.get("schema_version") == "agent-eval.policy/v1":
        raise ValueError(
            "agent-eval.policy/v1 cannot be normalized safely; migrate to "
            "policy/v2 with a task registry, approved per-platform images, "
            "observed usage limits, and scanner identity allowlisting"
        )
    return GovernanceBundle.model_validate(document)


def _matches(value: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _policy_document(bundle: GovernanceBundle) -> dict[str, Any]:
    return {
        "schema_version": bundle.schema_version,
        "policy_id": bundle.policy_id,
        "revision": bundle.revision,
        "rules": bundle.rules,
    }


def evaluate_admission(
    request: EvaluationRequest,
    bundle: GovernanceBundle,
    *,
    actual_task_id: str,
    actual_agent: str,
    actual_model: str,
    trials: int,
    network_mode: str,
    agent_timeout_seconds: int,
    eval_timeout_seconds: int,
    broker_configured: bool,
    run_scans: bool,
    run_judge: bool,
    scanner_identity_sha256: str | None = None,
    scanner_promotion_ready: bool = False,
    task_tree_sha256: str,
    execution_spec_digest: str,
    judge_backend: str | None = None,
    judge_model: str | None = None,
    decision_stage: Literal["preflight", "execution"] = "preflight",
    task_image_digest: str | None = None,
    task_image_ref: str | None = None,
    task_image_platform: str | None = None,
    preflight_decision_id: UUID | None = None,
    preflight_decision_digest: str | None = None,
    effective_egress_domains: Sequence[str] = (),
    proxy_image: str | None = None,
) -> PolicyDecision:
    """Evaluate admission without side effects, accumulating ordered denials.

    The returned trial and timeout limits are hard execution controls.  Token
    and cost values are explicitly post-run observation thresholds because the
    bundled provider CLIs cannot guarantee generation-time interruption.  An
    ``allowed`` decision is not itself a resource limiter.
    """

    reasons: list[PolicyReason] = []

    def deny(code: str, message: str) -> None:
        reasons.append(PolicyReason(code=code, message=message))

    rules = bundle.rules

    if decision_stage not in {"preflight", "execution"}:
        raise ValueError("decision_stage must be preflight or execution")
    if decision_stage == "preflight":
        if preflight_decision_id is not None or preflight_decision_digest is not None:
            raise ValueError("preflight decisions cannot link another preflight")
        if any(
            value is not None
            for value in (task_image_digest, task_image_ref, task_image_platform)
        ):
            deny(
                "image_digest_unexpected",
                "Preflight decisions cannot claim a task image identity",
            )
    else:
        if preflight_decision_id is None or (
            not isinstance(preflight_decision_digest, str)
            or _SHA256.fullmatch(preflight_decision_digest) is None
        ):
            raise ValueError("execution decisions require an exact preflight link")
        if (
            not isinstance(task_image_digest, str)
            or _IMAGE_DIGEST.fullmatch(task_image_digest) is None
        ):
            deny(
                "image_digest_invalid",
                "Execution decisions require an exact SHA-256 task image digest",
            )
        if (
            not isinstance(task_image_ref, str)
            or _GOVERNED_IMAGE_REF.fullmatch(task_image_ref) is None
            or not isinstance(task_image_platform, str)
            or _PLATFORM.fullmatch(task_image_platform) is None
        ):
            deny(
                "image_identity_invalid",
                "Execution decisions require an exact governed image reference "
                "and Linux platform",
            )
        elif (
            isinstance(task_image_digest, str)
            and _IMAGE_DIGEST.fullmatch(task_image_digest) is not None
            and task_image_ref
            != (
                f"agent-eval/{actual_task_id}:governed-"
                f"{task_image_digest.removeprefix('sha256:')}"
            )
        ):
            deny(
                "image_identity_mismatch",
                "Governed image reference must be derived from the task and digest",
            )

    if (
        not isinstance(task_tree_sha256, str)
        or _SHA256.fullmatch(task_tree_sha256) is None
        or not isinstance(execution_spec_digest, str)
        or _SHA256.fullmatch(execution_spec_digest) is None
    ):
        deny(
            "task_evidence_invalid",
            "Task tree and execution specification digests are required",
        )

    matched_task = next(
        (
            entry
            for entry in bundle.task_registry.tasks
            if entry.task_id == actual_task_id
        ),
        None,
    )
    if matched_task is None:
        deny(
            "task_not_registered",
            "Runtime task has no exact entry in the approved task registry",
        )
    else:
        if matched_task.status != "approved":
            deny(
                f"task_{matched_task.status}",
                f"Registered task status is {matched_task.status}",
            )
        if task_tree_sha256 != matched_task.task_tree_sha256:
            deny(
                "task_tree_not_approved",
                "Runtime task tree digest does not match the approved task registry",
            )
        if execution_spec_digest not in matched_task.execution_spec_digests:
            deny(
                "execution_spec_not_approved",
                "Runtime execution specification is not approved for this task",
            )
        if decision_stage == "execution" and not any(
            image.platform == task_image_platform
            and image.reference == task_image_ref
            and image.manifest_digest == task_image_digest
            for image in matched_task.approved_images
        ):
            deny(
                "task_image_not_approved",
                "Runtime task image and platform are not preapproved in the task registry",
            )

    if actual_task_id != request.task_id:
        deny("task_mismatch", "Runtime task does not match the authorized request")
    if actual_agent != request.agent:
        deny("agent_mismatch", "Runtime agent does not match the authorized request")
    if actual_model != request.model:
        deny("model_mismatch", "Runtime model does not match the authorized request")
    if actual_agent == "codex":
        deny(
            "coding_model_observation_unsupported",
            "Governed Codex coding cannot yet prove the runtime model identity",
        )

    if not _matches(request.tenant_id, rules.allowed_tenants):
        deny("tenant_not_allowed", "Tenant is not allowed by policy")
    if not _matches(request.project_id, rules.allowed_projects):
        deny("project_not_allowed", "Project is not allowed by policy")
    if not _matches(actual_task_id, rules.allowed_tasks):
        deny("task_not_allowed", "Runtime task is not allowed by policy")
    if request.data_classification not in rules.allowed_data_classifications:
        deny(
            "data_classification_not_allowed",
            "Data classification is not allowed by policy",
        )
    if request.retention_class not in rules.allowed_retention_classes:
        deny("retention_not_allowed", "Retention class is not allowed by policy")
    if network_mode not in rules.allowed_network_modes:
        deny("network_mode_not_allowed", "Network mode is not allowed by policy")
    normalized_domains: list[str] = []
    domains_valid = True
    for value in effective_egress_domains:
        if not isinstance(value, str):
            domains_valid = False
            break
        domain = value.strip().lower()
        bare = domain.removeprefix(".")
        if not bare or "/" in domain or not re.fullmatch(r"[a-z0-9.-]+", bare):
            domains_valid = False
            break
        suffix = f".{bare}"
        if suffix not in normalized_domains:
            normalized_domains.append(suffix)
    normalized_domains.sort()
    if not domains_valid:
        deny("invalid_egress_domains", "Effective egress domains are invalid")
    elif network_mode == "proxy" and any(
        domain not in rules.allowed_egress_domains for domain in normalized_domains
    ):
        deny(
            "egress_domain_not_allowed",
            "An effective egress domain is not allowed by policy",
        )
    if network_mode == "proxy":
        if proxy_image is None:
            deny(
                "proxy_image_required",
                "Proxy mode requires an exact digest-pinned proxy image",
            )
        elif proxy_image not in rules.allowed_proxy_images:
            deny(
                "proxy_image_not_allowed",
                "The egress proxy image is not allowed by policy",
            )
    if not isinstance(run_scans, bool):
        deny("invalid_scan_configuration", "Scanner configuration must be boolean")
    elif rules.require_scans and not run_scans:
        deny("scans_required", "Policy requires the scanner phase")
    if run_scans is True:
        if (
            not isinstance(scanner_identity_sha256, str)
            or _SHA256.fullmatch(scanner_identity_sha256) is None
        ):
            deny(
                "scanner_identity_required",
                "Scanner execution requires an exact assurance identity",
            )
        elif scanner_identity_sha256 not in rules.allowed_scanner_identities:
            deny(
                "scanner_identity_not_allowed",
                "Scanner assurance identity is not approved by policy",
            )
        if scanner_promotion_ready is not True:
            deny(
                "scanner_identity_incomplete",
                "Scanner assurance inputs are incomplete for governed promotion",
            )
    elif scanner_identity_sha256 is not None or scanner_promotion_ready is not False:
        deny(
            "scanner_identity_unexpected",
            "Disabled scanner execution cannot claim an assurance identity",
        )
    if not isinstance(run_judge, bool):
        deny("invalid_judge_configuration", "Judge configuration must be boolean")
    elif rules.require_judge and not run_judge:
        deny("judge_required", "Policy requires the judge phase")
    if run_judge is True and run_scans is False:
        deny(
            "judge_requires_scans",
            "Judge execution requires the secret-screening scanner phase",
        )
    matched_judge = None
    if run_judge is True:
        if judge_backend not in {"claude", "codex"} or (
            not isinstance(judge_model, str)
            or len(judge_model) > 256
            or _EXACT_MODEL.fullmatch(judge_model) is None
        ):
            deny(
                "judge_identity_required",
                "Judge execution requires an exact backend and model",
            )
        elif judge_backend == "codex":
            deny(
                "judge_model_observation_unsupported",
                "Governed Codex judging cannot yet prove the runtime model identity",
            )
        else:
            matched_judge = next(
                (
                    entry
                    for entry in bundle.model_registry.models
                    if isinstance(entry, JudgeRegistryEntry)
                    and entry.adapter == f"judge:{judge_backend}"
                    and entry.model == judge_model
                ),
                None,
            )
            if matched_judge is None:
                deny(
                    "judge_model_not_registered",
                    "Judge backend and model are not registered",
                )
            else:
                if matched_judge.status != "approved":
                    deny(
                        f"judge_model_{matched_judge.status}",
                        f"Registered judge model status is {matched_judge.status}",
                    )
                if (
                    request.data_classification
                    not in matched_judge.allowed_data_classifications
                ):
                    deny(
                        "judge_model_classification_not_allowed",
                        "Judge model is not approved for the data classification",
                    )
    elif judge_backend is not None or judge_model is not None:
        deny(
            "judge_identity_unexpected",
            "Disabled judge execution cannot claim a judge identity",
        )
    if not isinstance(broker_configured, bool):
        deny(
            "invalid_broker_configuration",
            "Broker configuration state must be a boolean",
        )
    elif rules.require_broker_credentials and not broker_configured:
        deny("broker_credentials_required", "Broker credentials are required by policy")

    if isinstance(trials, bool) or not isinstance(trials, int) or trials <= 0:
        deny("invalid_trials", "Trials must be a positive integer")
    elif trials > rules.max_trials:
        deny("trial_limit_exceeded", "Requested trials exceed the policy limit")
    if (
        isinstance(agent_timeout_seconds, bool)
        or not isinstance(agent_timeout_seconds, int)
        or agent_timeout_seconds <= 0
    ):
        deny("invalid_agent_timeout", "Agent timeout must be a positive integer")
    elif agent_timeout_seconds > rules.max_agent_seconds:
        deny("agent_timeout_exceeded", "Agent timeout exceeds the policy limit")
    if (
        isinstance(eval_timeout_seconds, bool)
        or not isinstance(eval_timeout_seconds, int)
        or eval_timeout_seconds <= 0
    ):
        deny("invalid_eval_timeout", "Evaluator timeout must be a positive integer")
    elif eval_timeout_seconds > rules.max_eval_seconds:
        deny("eval_timeout_exceeded", "Evaluator timeout exceeds the policy limit")

    matched_model = next(
        (
            entry
            for entry in bundle.model_registry.models
            if isinstance(entry, ModelRegistryEntry)
            and entry.adapter == actual_agent
            and entry.model == actual_model
        ),
        None,
    )
    if matched_model is None:
        deny("model_not_registered", "Runtime adapter and model are not registered")
    else:
        if matched_model.status != "approved":
            deny(
                f"model_{matched_model.status}",
                f"Registered model status is {matched_model.status}",
            )
        if (
            request.data_classification
            not in matched_model.allowed_data_classifications
        ):
            deny(
                "model_classification_not_allowed",
                "Registered model is not approved for the data classification",
            )

    token_limits = [rules.max_observed_total_tokens]
    cost_limits = [rules.max_observed_cost_usd]
    if request.max_observed_total_tokens is not None:
        token_limits.append(request.max_observed_total_tokens)
    if request.max_observed_cost_usd is not None:
        cost_limits.append(request.max_observed_cost_usd)
    if matched_model is not None:
        token_limits.append(matched_model.max_observed_total_tokens)
        cost_limits.append(matched_model.max_observed_cost_usd)

    effective_limits = EffectiveLimits(
        max_trials=rules.max_trials,
        max_agent_seconds=rules.max_agent_seconds,
        max_eval_seconds=rules.max_eval_seconds,
        max_observed_total_tokens=min(token_limits),
        max_observed_cost_usd=min(cost_limits),
    )
    if not reasons:
        reasons.append(
            PolicyReason(code="admitted", message="All governance checks passed")
        )

    sanitized_input = {
        "tenant_id": request.tenant_id,
        "project_id": request.project_id,
        "requested_task_id": request.task_id,
        "actual_task_id": actual_task_id,
        "requested_agent": request.agent,
        "actual_agent": actual_agent,
        "requested_model": request.model,
        "actual_model": actual_model,
        "data_classification": request.data_classification,
        "retention_class": request.retention_class,
        "trials": trials,
        "network_mode": network_mode,
        "run_scans": run_scans,
        "scanner_identity_sha256": scanner_identity_sha256,
        "scanner_promotion_ready": scanner_promotion_ready,
        "run_judge": run_judge,
        "judge_backend": judge_backend,
        "judge_model": judge_model,
        "effective_egress_domains": normalized_domains,
        "proxy_image": proxy_image if network_mode == "proxy" else None,
        "agent_timeout_seconds": agent_timeout_seconds,
        "eval_timeout_seconds": eval_timeout_seconds,
        "broker_configured": broker_configured,
        "task_tree_sha256": task_tree_sha256,
        "execution_spec_digest": execution_spec_digest,
        "task_image_digest": task_image_digest,
        "task_image_ref": task_image_ref,
        "task_image_platform": task_image_platform,
    }
    return PolicyDecision(
        decision_stage=decision_stage,
        preflight_decision_id=preflight_decision_id,
        preflight_decision_digest=preflight_decision_digest,
        allowed=len(reasons) == 1 and reasons[0].code == "admitted",
        request_id=request.request_id,
        request_digest=sha256_json(request),
        policy_id=bundle.policy_id,
        policy_revision=bundle.revision,
        policy_digest=sha256_json(_policy_document(bundle)),
        task_registry_id=bundle.task_registry.registry_id,
        task_registry_revision=bundle.task_registry.revision,
        task_registry_digest=sha256_json(bundle.task_registry),
        registry_id=bundle.model_registry.registry_id,
        registry_revision=bundle.model_registry.revision,
        registry_digest=sha256_json(bundle.model_registry),
        sanitized_input=sanitized_input,
        reasons=reasons,
        effective_limits=effective_limits,
        matched_task=matched_task,
        matched_model=matched_model,
        matched_judge=matched_judge,
    )


def _json_value(value: Any, *, location: str = "value") -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    elif isinstance(value, Enum):
        value = value.value
    elif isinstance(value, (Path, UUID)):
        value = str(value)
    elif isinstance(value, (datetime, date)):
        value = value.isoformat()

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{location} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{location} contains a non-string key")
            normalized[key] = _json_value(item, location=f"{location}.{key}")
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _json_value(item, location=f"{location}[{index}]")
            for index, item in enumerate(value)
        ]
    raise ValueError(f"{location} contains unsupported type {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes with no trailing newline."""

    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    """Hash the canonical representation of a JSON-compatible value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def write_canonical_json(path: Path | str, value: Any) -> None:
    """Atomically write canonical JSON with owner-only file permissions."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json_bytes(value)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        try:
            directory_fd = os.open(destination.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise
