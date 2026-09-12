"""Versioned experiment records; legacy black-box schemas remain unchanged."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from ..blackbox.models import (
    MAX_EVALUATIONS,
    ErrorCode,
    Observation,
    StrictModel,
    Suite,
    digest,
)
from ..blackbox.targets import ResponseDecoder

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[
    str, Field(pattern=r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
]
TrialState = Literal[
    "queued", "running", "observed", "completed", "reconciliation_required", "cancelled"
]


class CommandSpec(StrictModel):
    argv: list[str] = Field(min_length=1, max_length=256)
    timeout: float = Field(default=120.0, gt=0, le=86400)
    response_format: Literal["text", "json"] = "text"
    response_pointer: str | None = None
    env_names: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def valid_command(self):
        if any(not arg or "\x00" in arg for arg in self.argv):
            raise ValueError("command requires nonempty argv entries")
        ResponseDecoder(self.response_format, self.response_pointer)
        return self


class FileIdentity(StrictModel):
    path: str
    resolved_path: str
    sha256: Sha256


class Plan(StrictModel):
    schema_version: Literal["agent-eval.experiment/v1"] = "agent-eval.experiment/v1"
    experiment_id: Identifier
    created_at: str
    agent: str = Field(min_length=1, max_length=200)
    suite: Suite
    suite_sha256: Sha256
    trials: int = Field(ge=1, le=MAX_EVALUATIONS)
    command: CommandSpec
    target_sha256: Sha256
    files: list[FileIdentity] = Field(min_length=1, max_length=256)
    environment_hmac: Sha256
    evaluator_sha256: Sha256
    identity_scope: Literal["local-command-and-selected-files"] = (
        "local-command-and-selected-files"
    )

    @model_validator(mode="after")
    def valid_plan(self):
        if not self.agent.strip():
            raise ValueError("agent label cannot be blank")
        if self.suite_sha256 != digest(self.suite.model_dump(mode="json")):
            raise ValueError("suite digest mismatch")
        if self.trials * len(self.suite.cases) > MAX_EVALUATIONS:
            raise ValueError("experiment exceeds the evaluation limit")
        if any(
            metric.kind == "geval"
            for case in self.suite.cases
            for metric in case.metrics or self.suite.metrics
        ):
            raise ValueError("experiments currently support deterministic graders only")
        if len({file.path for file in self.files}) != len(self.files):
            raise ValueError("duplicate identity file")
        return self

    def case_trial(self, ordinal: int):
        if not 0 <= ordinal < self.trials * len(self.suite.cases):
            raise ValueError("trial ordinal outside plan")
        return self.suite.cases[ordinal % len(self.suite.cases)], ordinal // len(
            self.suite.cases
        ) + 1


class Receipt(StrictModel):
    schema_version: Literal["agent-eval.observation-receipt/v1"] = (
        "agent-eval.observation-receipt/v1"
    )
    plan_sha256: Sha256
    attempt_id: Identifier
    ordinal: int = Field(ge=0, lt=MAX_EVALUATIONS)
    observation: Observation | None = None
    error: ErrorCode | None = None

    @model_validator(mode="after")
    def one_result(self):
        if (self.observation is None) == (self.error is None):
            raise ValueError("receipt requires either an observation or an error")
        if self.observation is not None and self.observation.status != "completed":
            raise ValueError("an observed response must be completed")
        return self


class TrialStatus(StrictModel):
    ordinal: int
    attempt_id: Identifier
    case_sha256: Sha256
    trial: int
    state: TrialState


class ExperimentStatus(StrictModel):
    schema_version: Literal["agent-eval.experiment-status/v1"] = (
        "agent-eval.experiment-status/v1"
    )
    experiment_id: Identifier
    state: Literal[
        "queued", "in_progress", "completed", "reconciliation_required", "cancelled"
    ]
    planned: int
    completed: int
    accepted: int
    rejected: int
    infra_errors: int
    passed: bool | None
    trials: list[TrialStatus]
