"""Declarative final-state oracles, held outside the candidate runtime."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, JsonValue, model_validator

from ..blackbox.models import StrictModel
from .contracts import Check


class BehaviorCheck(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=500)
    response_indices: list[int] = Field(default_factory=list)
    expected_responses: list[JsonValue] = Field(default_factory=list)
    # SQL is operator-authored and never sent to the candidate. Read-only SQLite.
    state_query: str | None = None
    expected_rows: list[list[JsonValue]] | None = None

    @model_validator(mode="after")
    def valid_oracle(self):
        if len(self.response_indices) != len(self.expected_responses) or any(
            i < 0 for i in self.response_indices
        ):
            raise ValueError("oracle response indices mismatch")
        if (self.state_query is None) != (self.expected_rows is None):
            raise ValueError("state oracle needs both query and expected rows")
        if self.state_query and not self.state_query.lstrip().upper().startswith(
            "SELECT "
        ):
            raise ValueError("state oracle requires a read-only SELECT")
        if not self.response_indices and self.state_query is None:
            raise ValueError("empty behavior check")
        return self


class BehaviorSuite(StrictModel):
    schema_version: Literal["agent-eval.behavior-suite/v2"] = (
        "agent-eval.behavior-suite/v2"
    )
    task_id: str
    family: str
    split: Literal["development", "regression", "capability", "held_out"]
    # Immutable OCI reference; image contents are verified by Docker at dispatch.
    image: str = Field(pattern=r"^\S+@sha256:[a-f0-9]{64}$")
    runtime: Literal["python", "node"] = "python"
    entrypoint: str
    requests: list[dict[str, JsonValue]] = Field(min_length=1, max_length=100)
    checks: list[BehaviorCheck] = Field(min_length=1, max_length=100)
    timeout_seconds: int = Field(default=30, ge=1, le=120)

    @model_validator(mode="after")
    def valid_suite(self):
        from .contracts import safe_path

        safe_path(self.entrypoint)
        if len({c.id for c in self.checks}) != len(self.checks):
            raise ValueError("duplicate oracle ID")
        if any(
            i >= len(self.requests) for c in self.checks for i in c.response_indices
        ):
            raise ValueError("oracle response index outside requests")
        return self


def grade(suite: BehaviorSuite, observation) -> list[Check]:
    responses = observation.get("responses", [])
    states = observation.get("state_queries", {})
    checks = []
    for check in suite.checks:
        response_ok = all(
            i < len(responses) and responses[i] == expected
            for i, expected in zip(
                check.response_indices, check.expected_responses, strict=True
            )
        )
        state_ok = (
            check.state_query is None or states.get(check.id) == check.expected_rows
        )
        passed = (
            response_ok
            and state_ok
            and observation.get("exit_code") == 0
            and not observation.get("protocol_error")
        )
        checks.append(
            Check(
                id=check.id,
                passed=passed,
                reason="behavior and state matched"
                if passed
                else "response mismatch"
                if not response_ok
                else "final state mismatch"
                if not state_ok
                else "candidate process failed",
            )
        )
    return checks
