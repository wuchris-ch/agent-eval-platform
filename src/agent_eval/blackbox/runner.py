"""Run or replay a frozen suite, with every required gate owned by the evaluator."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from statistics import median

from .models import (
    MAX_EVALUATIONS,
    Case,
    ErrorCode,
    Observation,
    Report,
    Result,
    Suite,
    digest,
)
from .scoring import Judge, score
from .targets import Target, TargetError


def grade_observation(
    suite: Suite,
    case: Case,
    trial: int,
    observation: Observation | None,
    *,
    error: ErrorCode | None = None,
    judge: Judge | None = None,
) -> Result:
    """Grade one boundary observation without invoking the target."""
    metrics = []
    if error is None:
        if observation is None:
            error = "missing_observation"
        elif observation.input_sha256 != digest(case.input):
            error = "input_mismatch"
        elif observation.status != "completed":
            error = "recorded_error"
    if error is None:
        try:
            for metric in case.metrics or suite.metrics:
                metrics.append(score(metric, case, observation.actual_output, judge))
        except Exception:
            error = "judge_error"
    return Result(
        case_id=case.id,
        trial=trial,
        input_sha256=digest(case.input),
        outcome="infra_error"
        if error
        else ("accepted" if all(metric.passed for metric in metrics) else "rejected"),
        score=None if error else min(metric.score for metric in metrics),
        metrics=metrics,
        observation=observation,
        error=error,
    )


def evaluate(
    suite: Suite,
    *,
    agent: str,
    target: Target | None = None,
    observations: list[Observation] | None = None,
    trials: int = 1,
    judge: Judge | None = None,
) -> Report:
    if (target is None) == (observations is None):
        raise ValueError("provide exactly one live target or observation dataset")
    if not agent.strip() or len(agent) > 200:
        raise ValueError("agent label must contain 1 to 200 characters")
    if (
        isinstance(trials, bool)
        or not isinstance(trials, int)
        or not 1 <= trials <= MAX_EVALUATIONS // len(suite.cases)
    ):
        raise ValueError("requested trials exceed the evaluation limit")
    if judge is None and any(
        metric.kind == "geval"
        for case in suite.cases
        for metric in case.metrics or suite.metrics
    ):
        raise ValueError("suite requires GEval; enable the judge explicitly")
    # Snapshot before invocation, including for callers using the Python API.
    suite = suite.model_copy(deep=True)
    by_key = {}
    expected_keys = {
        (case.id, trial) for case in suite.cases for trial in range(1, trials + 1)
    }
    for observation in observations or []:
        key = observation.case_id, observation.trial
        if key in by_key or key not in expected_keys:
            raise ValueError(
                "recorded data contains duplicate or unexpected case/trial keys"
            )
        by_key[key] = observation

    results = []
    for trial in range(1, trials + 1):
        for case in suite.cases:
            input_sha = digest(case.input)
            observation = by_key.get((case.id, trial))
            error = None
            if target is not None:
                started = time.perf_counter()
                try:
                    actual = target.invoke(case.model_copy(deep=True).input)
                    observation = Observation(
                        case_id=case.id,
                        trial=trial,
                        input_sha256=input_sha,
                        actual_output=actual,
                        latency_ms=(time.perf_counter() - started) * 1000,
                    )
                except TargetError as exc:
                    error = exc.code
                except Exception:
                    # Custom transports must not leak exceptions containing response bodies.
                    error = "target_transport"
            elif observation is None:
                error = "missing_observation"
            elif observation.input_sha256 != input_sha:
                error = "input_mismatch"
            elif observation.status != "completed":
                error = "recorded_error"

            results.append(
                grade_observation(
                    suite, case, trial, observation, error=error, judge=judge
                )
            )
    accepted = sum(result.outcome == "accepted" for result in results)
    rejected = sum(result.outcome == "rejected" for result in results)
    latency = [
        result.observation.latency_ms
        for result in results
        if result.observation is not None and result.observation.latency_ms is not None
    ]
    return Report(
        run_id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc).isoformat(),
        suite_id=suite.id,
        suite_version=suite.version,
        suite_sha256=digest(suite.model_dump(mode="json")),
        agent=agent,
        target_sha256=target.identity
        if target
        else digest(
            [item.model_dump(mode="json") for _, item in sorted(by_key.items())]
        ),
        mode=target.mode if target else "replay",
        trials=trials,
        evaluations=len(results),
        accepted=accepted,
        rejected=rejected,
        infra_errors=len(results) - accepted - rejected,
        average_score=sum(result.score or 0 for result in results) / len(results),
        median_latency_ms=median(latency) if latency else None,
        passed=accepted == len(results),
        results=results,
    )
