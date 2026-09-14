"""Operator-registered profiles. Browser requests select IDs, never commands."""

from typing import Literal

from pydantic import Field, model_validator

from ..blackbox.models import StrictModel
from ..environments.world import Fault
from ..experiments.models import CommandSpec, Identifier


class TargetProfile(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    command: CommandSpec
    identity_files: list[str] = Field(default_factory=list)
    source_revision: str | None = Field(default=None, max_length=200)
    conditions: dict[str, str] = Field(default_factory=dict)
    identity_provenance: Literal["operator_asserted", "observed", "unknown"] = (
        "operator_asserted"
    )
    world: Literal["ticket", "order"] | None = None
    faults: list[Fault] = Field(default_factory=list)
    seed: int = 0
    model_calls: Literal["none", "possible"] = "possible"
    max_invocations: int = Field(default=100, ge=1, le=10000)
    trace_url: str | None = None


class Launch(StrictModel):
    target: str
    dataset: str
    trials: int = Field(default=1, ge=1, le=1000)
    budget_acknowledged: bool = False
    attempt_kind: Literal["initial", "infra_recovery", "assisted_correction"] = (
        "initial"
    )
    parent_experiment: Identifier | None = None

    @model_validator(mode="after")
    def linked_attempt(self):
        if (self.attempt_kind == "initial") != (self.parent_experiment is None):
            raise ValueError(
                "recovery/correction requires a parent; initial work has no parent"
            )
        return self
