"""Bounded producer ingestion. A submission never constitutes acceptance."""

from typing import Literal

from pydantic import Field

from ..blackbox.models import StrictModel, digest
from ..experiments.models import Identifier, Sha256


class Artifact(StrictModel):
    role: Literal["patch", "trace", "tests", "candidate"]
    sha256: Sha256
    storage_key: Sha256


class Usage(StrictModel):
    total_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)


class Submission(StrictModel):
    schema_version: Literal["agent-eval.submission/v1"] = "agent-eval.submission/v1"
    execution_id: Identifier
    producer_run_id: str = Field(min_length=1, max_length=200)
    base_revision: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    candidate_revision: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    candidate_tree_sha256: Sha256
    recipe_sha256: Sha256
    artifacts: list[Artifact] = Field(min_length=1, max_length=100)
    trace_reference: str | None = Field(default=None, max_length=2000)
    usage: Usage = Field(default_factory=Usage)
    producer_status: Literal["completed", "failed", "cancelled"]


def ingest(store, project, submission: Submission, actor):
    contract = store.get(project, "execution-contract", submission.execution_id)
    value = submission.model_dump(mode="json")
    for field in (
        "base_revision",
        "candidate_revision",
        "candidate_tree_sha256",
        "recipe_sha256",
    ):
        if value[field] != contract[field]:
            raise ValueError("submission differs from issued execution identity")
    keys = set()
    for artifact in submission.artifacts:
        if artifact.storage_key in keys:
            raise ValueError("duplicate submission artifact")
        keys.add(artifact.storage_key)
        content = store.get(project, "producer-artifact", artifact.storage_key)
        if (
            digest(content) != artifact.sha256
            or artifact.sha256 != artifact.storage_key
        ):
            raise ValueError("submission artifact digest mismatch")
    identity = store.put(
        project, "submission", value, actor=actor, object_id=submission.execution_id
    )
    return {
        "id": identity,
        "submission_sha256": digest(value),
        "status": "awaiting_independent_evaluation",
    }


def import_external(store, project, source, value, actor):
    if source not in ("inspect", "harbor", "legacy") or not isinstance(value, dict):
        raise ValueError("unsupported external report")
    if source == "legacy":
        from ..blackbox.models import Report

        Report.model_validate(value)
    # Spikes deliberately preserve original schemas and specialized metrics.
    # External success is not converted to an independently verified gate.
    return store.put(
        project,
        "external-report",
        {
            "source": source,
            "original": value,
            "original_sha256": digest(value),
            "gate_eligible": False,
        },
        actor=actor,
    )
