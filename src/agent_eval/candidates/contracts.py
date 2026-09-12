"""Evaluator-owned wire contracts. All digests use canonical JSON or explicit bytes."""

from __future__ import annotations

import base64
import hashlib
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from ..blackbox.models import StrictModel, digest, json_bytes, parse_json
from ..experiments.models import Identifier, Sha256

Revision = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
MAX_ARTIFACT_BYTES = 12 * 1024 * 1024
MAX_TREE_BYTES = 8 * 1024 * 1024


def raw_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or not path.parts
        or not value.isascii()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or path.is_absolute()
        or str(path) != value
        or any(c in value for c in ("\\", "\x00", ":"))
        or any(c in (".", "..", ".git", ".env") for c in path.parts)
    ):
        raise ValueError("unsupported candidate path")
    return value


class ArtifactEnvelope(StrictModel):
    schema_version: Literal["agent-eval.artifact/v2"] = "agent-eval.artifact/v2"
    encoding: Literal["base64"] = "base64"
    content_sha256: Sha256
    data: str = Field(max_length=16 * 1024 * 1024)

    def content(self) -> bytes:
        content = base64.b64decode(self.data, validate=True)
        if (
            len(content) > MAX_ARTIFACT_BYTES
            or raw_digest(content) != self.content_sha256
        ):
            raise ValueError("artifact content digest or size mismatch")
        if base64.b64encode(content).decode() != self.data:
            raise ValueError("noncanonical base64")
        return content

    @model_validator(mode="after")
    def valid_content(self):
        self.content()
        return self

    @classmethod
    def wrap(cls, content: bytes):
        return cls(
            content_sha256=raw_digest(content), data=base64.b64encode(content).decode()
        )


class ArtifactReference(StrictModel):
    role: Literal["candidate", "patch", "trace", "public-verification", "review"]
    # sha256 identifies raw bytes; storage_key identifies the canonical envelope.
    sha256: Sha256
    storage_key: Sha256


class CandidateFile(StrictModel):
    data: str = Field(max_length=12 * 1024 * 1024)
    mode: Literal[420, 493]


class CandidateManifest(StrictModel):
    schema_version: Literal["candidate/v1"] = "candidate/v1"
    base_revision: Revision
    tree_sha256: Sha256
    files: dict[str, CandidateFile] = Field(min_length=1, max_length=2000)
    changed_paths: list[str] = Field(max_length=2000)
    patch_sha256: Sha256

    @model_validator(mode="after")
    def valid_tree(self):
        total = 0
        folded = set()
        for name, file in self.files.items():
            safe_path(name)
            if name.casefold() in folded:
                raise ValueError("case-colliding candidate paths")
            folded.add(name.casefold())
            content = base64.b64decode(file.data, validate=True)
            if base64.b64encode(content).decode() != file.data:
                raise ValueError("noncanonical file encoding")
            total += len(content)
        for name in self.changed_paths:
            safe_path(name)
        if len(set(self.changed_paths)) != len(self.changed_paths):
            raise ValueError("duplicate changed path")
        if total > MAX_TREE_BYTES:
            raise ValueError("candidate tree too large")
        if (
            digest({k: v.model_dump() for k, v in self.files.items()})
            != self.tree_sha256
        ):
            raise ValueError("candidate tree digest mismatch")
        return self

    @classmethod
    def from_bytes(cls, data):
        value = cls.model_validate(parse_json(data))
        if json_bytes(value.model_dump(mode="json")) != data:
            raise ValueError("candidate manifest must use canonical JSON")
        return value


class CandidateIdentity(StrictModel):
    base_revision: Revision
    candidate_revision: Revision | None = None
    candidate_tree_sha256: Sha256
    candidate_manifest_sha256: Sha256


class Budget(StrictModel):
    max_model_requests: int = Field(ge=0, le=100)
    max_total_tokens: int = Field(ge=0, le=1000000)
    max_elapsed_seconds: int = Field(ge=1, le=3600)
    max_repairs: int = Field(ge=0, le=5)


class Recipe(StrictModel):
    schema_version: Literal["agent-eval.recipe/v2"] = "agent-eval.recipe/v2"
    name: str = Field(min_length=1, max_length=100)
    producer_sha256: Sha256
    capability_sha256: Sha256
    model_configuration_sha256: Sha256
    budget: Budget


class AcceptancePolicy(StrictModel):
    schema_version: Literal["agent-eval.acceptance-policy/v2"] = (
        "agent-eval.acceptance-policy/v2"
    )
    name: str = Field(min_length=1, max_length=100)
    required_checks: list[str] = Field(min_length=1, max_length=100)
    max_latency_ms: float | None = Field(default=None, gt=0)
    max_total_tokens: int | None = Field(default=None, ge=0)
    max_cost_usd: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def distinct_checks(self):
        if len(set(self.required_checks)) != len(self.required_checks):
            raise ValueError("duplicate required check")
        return self


class TrialIdentity(StrictModel):
    cohort_id: Identifier
    task_id: str = Field(min_length=1, max_length=100)
    family: str = Field(min_length=1, max_length=100)
    split: Literal["development", "regression", "capability", "held_out"]
    trial: int = Field(ge=1, le=100)
    arm: Literal["baseline", "candidate"]
    attempt_kind: Literal["initial", "assisted_correction"] = "initial"
    parent_execution_id: Identifier | None = None

    @model_validator(mode="after")
    def repair_link(self):
        if (self.attempt_kind == "initial") != (self.parent_execution_id is None):
            raise ValueError("assisted attempts require a distinct parent execution")
        return self


class ExecutionContract(CandidateIdentity):
    trial_ticket_sha256: Sha256
    schema_version: Literal["agent-eval.execution/v2"] = "agent-eval.execution/v2"
    execution_id: Identifier
    trial_identity: TrialIdentity
    recipe_sha256: Sha256
    suite_sha256: Sha256
    policy_sha256: Sha256
    evaluator_sha256: Sha256


class Usage(StrictModel):
    total_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)
    latency_ms: float | None = Field(default=None, ge=0)
    provenance: Literal[
        "producer_reported", "independently_observed", "unavailable"
    ] = "unavailable"

    @model_validator(mode="after")
    def unavailable_has_no_estimate(self):
        if self.provenance == "unavailable" and any(
            v is not None for v in (self.total_tokens, self.cost_usd, self.latency_ms)
        ):
            raise ValueError("unavailable usage cannot contain estimates")
        return self


class Submission(CandidateIdentity):
    trial_ticket_sha256: Sha256
    schema_version: Literal["agent-eval.submission/v2"] = "agent-eval.submission/v2"
    execution_id: Identifier
    execution_contract_sha256: Sha256
    producer_run_id: str = Field(min_length=1, max_length=200)
    recipe_sha256: Sha256
    suite_sha256: Sha256
    policy_sha256: Sha256
    evaluator_sha256: Sha256
    artifacts: list[ArtifactReference] = Field(min_length=2, max_length=100)
    producer_status: Literal["completed", "failed", "cancelled"]
    usage: Usage = Field(default_factory=Usage)


class ProductionFailure(StrictModel):
    """A reserved invocation without a candidate remains in the study denominator."""

    schema_version: Literal["agent-eval.production-failure/v2"] = (
        "agent-eval.production-failure/v2"
    )
    execution_id: Identifier
    trial_ticket_sha256: Sha256
    reason: Literal[
        "budget_exhausted",
        "timeout",
        "transport_error",
        "invalid_output",
        "verification_failed",
        "cancelled",
        "producer_error",
    ]
    usage: Usage = Field(default_factory=Usage)


class Check(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    passed: bool
    reason: str = Field(max_length=500)


class Assessment(CandidateIdentity):
    trial_ticket_sha256: Sha256
    schema_version: Literal["agent-eval.assessment/v2"] = "agent-eval.assessment/v2"
    execution_id: Identifier
    execution_contract_sha256: Sha256
    submission_sha256: Sha256
    recipe_sha256: Sha256
    suite_sha256: Sha256
    policy_sha256: Sha256
    evaluator_sha256: Sha256
    observation_sha256: Sha256
    checks: list[Check]
    outcome: Literal["pass", "fail", "inconclusive"]
    reasons: list[str]
    usage: Usage
    evaluation_latency_ms: float = Field(ge=0)


def validate_assessment(assessment: Assessment, submission: Submission) -> str:
    if assessment.submission_sha256 != digest(submission.model_dump(mode="json")):
        raise ValueError("stale submission evidence")
    fields = (
        "execution_id",
        "execution_contract_sha256",
        "trial_ticket_sha256",
        "base_revision",
        "candidate_revision",
        "candidate_tree_sha256",
        "candidate_manifest_sha256",
        "recipe_sha256",
        "suite_sha256",
        "policy_sha256",
        "evaluator_sha256",
    )
    if any(getattr(assessment, key) != getattr(submission, key) for key in fields):
        raise ValueError("stale or incompatible assessment")
    return assessment.outcome


class TrialTicket(StrictModel):
    schema_version: Literal["agent-eval.trial-ticket/v2"] = "agent-eval.trial-ticket/v2"
    execution_id: Identifier
    base_revision: Revision
    trial_identity: TrialIdentity
    recipe_sha256: Sha256
    suite_sha256: Sha256
    policy_sha256: Sha256
    evaluator_sha256: Sha256
