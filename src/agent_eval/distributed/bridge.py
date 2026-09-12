"""Bind distributed boundary work back to canonical local experiment receipts."""

from __future__ import annotations

from ..blackbox.models import Observation, digest
from ..blackbox.runner import grade_observation
from ..experiments.journal import Journal, JournalError, immutable_json
from ..experiments.models import Receipt
from ..experiments.service import evaluator_identity


def payload_for(journal, row):
    case, _ = journal.plan.case_trial(row["ordinal"])
    return {
        "schema_version": "agent-eval.remote-invocation/v1",
        "command": journal.plan.command.model_dump(mode="json"),
        "command_sha256": journal.plan.target_sha256,
        "input": case.input,
        "files": [f.model_dump() for f in journal.plan.files],
    }


def enqueue_experiment(store, project, experiment, queue, *, reservation_micros):
    metadata = store.get(project, "experiment", experiment)
    if metadata["profile"]["world"]:
        raise ValueError("state worlds require their independent local observer")
    with Journal.open(experiment, write=True) as journal:
        journal.status()
        if journal.cancel_requested():
            raise JournalError("cancelled experiments cannot enqueue work")
        for row in journal.rows():
            if row["state"] in ("completed", "observed", "cancelled"):
                continue
            payload = payload_for(journal, row)
            if row["state"] == "queued":
                journal.claim(row["ordinal"])
            # The deterministic attempt ID is both queue identity and replay key.
            # A crash between local claim and enqueue can repeat this insertion;
            # the queue cannot dispatch an existing work record a second time.
            queue.enqueue(project, row["attempt_id"], payload, reservation_micros)
    return {"experiment": experiment, "state": "submitted"}


def collect_experiment(store, project, experiment, queue):
    store.get(project, "experiment", experiment)
    with Journal.open(experiment, write=True) as journal:
        if evaluator_identity() != journal.plan.evaluator_sha256:
            raise JournalError("grader changed; original evaluator required")
        for row in journal.rows():
            if row["state"] == "completed":
                continue
            remote = queue.status(project, row["attempt_id"])
            if remote["payload_sha"] != digest(payload_for(journal, row)):
                raise JournalError("remote invocation identity mismatch")
            if remote["state"] != "completed":
                continue
            value = remote["receipt"]
            case, trial = journal.plan.case_trial(row["ordinal"])
            if (
                value["execution_id"],
                value["payload_sha256"],
                value["input_sha256"],
                value["epoch"],
            ) != (
                row["attempt_id"],
                remote["payload_sha"],
                digest(case.input),
                remote["epoch"],
            ):
                raise JournalError("remote observation binding mismatch")
            observation = (
                Observation(
                    case_id=case.id,
                    trial=trial,
                    input_sha256=digest(case.input),
                    actual_output=value["actual_output"],
                    latency_ms=value["latency_ms"],
                )
                if value["error"] is None
                else None
            )
            receipt = Receipt(
                plan_sha256=journal.plan_sha256,
                attempt_id=row["attempt_id"],
                ordinal=row["ordinal"],
                observation=observation,
                error=value["error"],
            )
            sha = journal.blob(receipt.model_dump(mode="json"))
            immutable_json(
                journal.root / "receipts" / f"{row['attempt_id']}.json", {"sha256": sha}
            )
            journal.recover()
            current = journal.row(row["ordinal"])
            result = grade_observation(
                journal.plan.suite, case, trial, observation, error=value["error"]
            )
            if result.error != value["error"]:
                raise JournalError("remote observation grading unavailable")
            journal.complete(current, result)
        snapshot = journal.status()
        if snapshot.state == "completed":
            journal.export_report()
        return snapshot.model_dump(mode="json")


def cancel_experiment(store, project, experiment, queue):
    from ..experiments.journal import request_cancel

    store.get(project, "experiment", experiment)
    request_cancel(experiment)
    states = []
    with Journal.open(experiment, write=True) as journal:
        for row in journal.rows():
            if row["state"] in ("completed", "observed", "cancelled"):
                continue
            try:
                state = queue.cancel(project, row["attempt_id"])
            except KeyError:
                state = "cancelled"
            if state == "cancelled":
                journal._transition(row["ordinal"], row["state"], "cancelled")
            states.append(state)
        journal.recover()
    return {"states": states}
