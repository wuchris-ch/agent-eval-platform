"""Run queued work or grade sealed observations, never replay ambiguous calls."""

from __future__ import annotations

import time

from ..blackbox.models import Observation, digest
from ..blackbox.runner import grade_observation
from ..blackbox.targets import TargetCancelled, TargetError
from .journal import Journal, JournalError
from .models import Receipt
from .service import evaluator_identity, verify_target


def execute(
    experiment_id: str,
    *,
    max_new_trials: int | None = None,
    observer=None,
    end_ordinal=None,
):
    """Drain one experiment with an exclusive local worker lock.

    max_new_trials is an intentional pause boundary, not an early-stopping rule.
    KeyboardInterrupt preserves ambiguous dispatch state; CommandTarget stops
    its owned process group in its finally block. SIGKILL may orphan the target.
    """
    if end_ordinal is not None and type(end_ordinal) is not int:
        raise ValueError("end ordinal must be an integer")
    if max_new_trials is not None and (
        isinstance(max_new_trials, bool)
        or not isinstance(max_new_trials, int)
        or max_new_trials < 1
    ):
        raise ValueError("max-new-trials must be positive")
    with Journal.open(experiment_id, write=True) as journal:
        journal.recover()
        if journal.cancel_requested():
            journal.cancel_queued()
        snapshot = journal.status()  # Verify all existing evidence before dispatch.
        if snapshot.state in {"reconciliation_required", "cancelled"}:
            return snapshot
        if snapshot.state == "completed":
            journal.export_report()
            return snapshot
        if evaluator_identity() != journal.plan.evaluator_sha256:
            raise JournalError(
                "evaluator identity changed; resume requires the original implementation"
            )
        dispatched = 0
        if end_ordinal is not None:
            journal.plan.case_trial(end_ordinal)
        for row in journal.rows():
            if end_ordinal is not None and row["ordinal"] > end_ordinal:
                break
            if journal.cancel_requested():
                journal.cancel_queued()
                break
            if row["state"] == "completed":
                continue
            case, trial = journal.plan.case_trial(row["ordinal"])
            if row["state"] == "queued":
                if max_new_trials is not None and dispatched >= max_new_trials:
                    break
                # Recheck immediately before each invocation, including after an
                # earlier target may have modified selected files.
                target = verify_target(journal)
                target.cancel_check = journal.cancel_requested
                journal.claim(row["ordinal"])
                started = time.perf_counter()
                observation, error = None, None
                try:
                    actual = (
                        observer(journal, row, target, case.model_copy(deep=True).input)
                        if observer
                        else target.invoke(case.model_copy(deep=True).input)
                    )
                    observation = Observation(
                        case_id=case.id,
                        trial=trial,
                        input_sha256=digest(case.input),
                        actual_output=actual,
                        latency_ms=(time.perf_counter() - started) * 1000,
                    )
                except TargetCancelled:
                    journal._transition(
                        row["ordinal"], "running", "reconciliation_required"
                    )
                    journal.cancel_queued()
                    break
                except TargetError as exc:
                    error = exc.code
                except JournalError:
                    raise
                except Exception:
                    error = "target_transport"
                receipt = Receipt(
                    plan_sha256=journal.plan_sha256,
                    attempt_id=row["attempt_id"],
                    ordinal=row["ordinal"],
                    observation=observation,
                    error=error,
                )
                # No signal/error handler retries the target or manufactures an
                # observation when this persistence boundary has not completed.
                journal.observe(row, receipt)
                dispatched += 1
            current = journal.row(row["ordinal"])
            receipt, _ = journal.receipt(current)
            result = grade_observation(
                journal.plan.suite,
                case,
                trial,
                receipt.observation,
                error=receipt.error,
            )
            if result.error != receipt.error:
                raise JournalError(
                    "deterministic grader failed; observation retained for recovery"
                )
            journal.complete(current, result)
        snapshot = journal.status()
        if snapshot.state == "completed":
            journal.export_report()
        return snapshot
