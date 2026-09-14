"""One fenced boundary invocation per claim, with no hidden platform retries."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from ..blackbox.models import digest
from ..blackbox.targets import TargetCancelled, TargetError
from ..experiments.models import CommandSpec, FileIdentity
from ..experiments.service import file_identity, make_target
from .postgres import LeaseLost


def work_once(queue, tenant, worker, *, lease_seconds=30, kube_context=None):
    from .kubernetes import AdmissionDelayed, cleanup_job

    claim = queue.claim(tenant, worker, lease_seconds)
    if claim is None:
        return None
    identity, epoch = claim["id"], claim["epoch"]
    stop, lost = threading.Event(), threading.Event()

    def heartbeat():
        while not stop.wait(lease_seconds / 3):
            try:
                if not queue.heartbeat(tenant, identity, worker, epoch, lease_seconds):
                    lost.set()
                    return
            except Exception:
                # Loss of DB connectivity is not permission to keep spending.
                lost.set()
                return

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        payload = claim["payload"]
        if payload.get("schema_version") == "agent-eval.remote-job/v1":
            from .kubernetes import execute_job, job

            if set(payload) != {"schema_version", "job"} or not kube_context:
                raise ValueError(
                    "Kubernetes work requires a frozen Job and explicit controller context"
                )
            template = payload["job"]
            labels = template["metadata"]["labels"]
            if labels["agent-eval/execution"] != identity:
                raise ValueError("Job is not bound to the queue execution ID")
            container = template["spec"]["template"]["spec"]["containers"][0]
            parameters = {
                "execution_id": identity,
                "image": container["image"],
                "command": container["command"],
                "cpu": container["resources"]["limits"]["cpu"],
                "memory": container["resources"]["limits"]["memory"],
                "seconds": template["spec"]["activeDeadlineSeconds"],
            }
            if template != job(**parameters, epoch=int(labels["agent-eval/epoch"])):
                raise ValueError(
                    "Kubernetes queue accepts only the guarded execution profile"
                )
            manifest = job(**parameters, epoch=epoch)
            queue.dispatch(tenant, identity, worker, epoch)
            evidence = execute_job(
                manifest, context=kube_context, cancelled=lost.is_set
            )
            receipt = {
                "schema_version": "agent-eval.remote-job-observation/v1",
                "execution_id": identity,
                "epoch": epoch,
                "payload_sha256": claim["payload_sha"],
                "evidence": evidence,
                "usage": {"cost_usd": None, "total_tokens": None},
            }
            queue.complete(tenant, identity, worker, epoch, receipt)
            try:
                cleaned = cleanup_job(
                    context=kube_context,
                    name=manifest["metadata"]["name"],
                    uid=evidence["job_uid"],
                )
            except Exception:
                cleaned = False
            if not cleaned:
                with queue.db() as db:
                    queue.event(db, tenant, identity, "cleanup_required", epoch)
            return identity
        if payload.get("schema_version") != "agent-eval.remote-invocation/v1" or set(
            payload
        ) not in (
            {"schema_version", "command", "input", "command_sha256"},
            {"schema_version", "command", "input", "command_sha256", "files"},
        ):
            raise ValueError("unsupported invocation payload")
        target = make_target(CommandSpec.model_validate(payload["command"]))
        if target.identity != payload["command_sha256"]:
            raise ValueError("registered command identity mismatch")
        for item in payload.get("files", []):
            expected = FileIdentity.model_validate(item)
            if file_identity(Path(expected.path)) != expected:
                raise ValueError("remote target file identity changed")
        target.cancel_check = lost.is_set
        queue.dispatch(tenant, identity, worker, epoch)
        started = time.perf_counter()
        try:
            output = target.invoke(payload["input"])
            error = None
        except TargetError as exc:
            output, error = None, exc.code
        if lost.is_set():
            raise LeaseLost("worker authority lost during invocation")
        receipt = {
            "schema_version": "agent-eval.remote-observation/v1",
            "execution_id": identity,
            "epoch": epoch,
            "payload_sha256": claim["payload_sha"],
            "input_sha256": digest(payload["input"]),
            "actual_output": output,
            "error": error,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "usage": {"cost_usd": None, "total_tokens": None},
        }
        queue.complete(tenant, identity, worker, epoch, receipt)
        return identity
    except AdmissionDelayed:
        queue.defer_uncreated(tenant, identity, worker, epoch)
        return None
    except (TargetCancelled, LeaseLost):
        # Reconciler keeps an uncertain dispatched reservation. Never fabricate
        # a completion or requeue work that may have changed external state.
        return None
    finally:
        stop.set()
        thread.join(timeout=5)
