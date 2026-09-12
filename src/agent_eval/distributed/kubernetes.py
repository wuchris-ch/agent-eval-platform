"""Explicitly bounded experimental Jobs. No existing watcher/schedule mutation."""

from __future__ import annotations

import re

from ..blackbox.models import digest

NAMESPACE = "agent-eval-experiments"


class AdmissionDelayed(RuntimeError):
    """API admission definitively rejected creation before a Job existed."""


def job(
    *,
    execution_id,
    image,
    command,
    cpu="500m",
    memory="512Mi",
    seconds=300,
    epoch=1,
    network_probe=False,
):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,35}", execution_id) or not re.fullmatch(
        r"[^\s]+@sha256:[0-9a-f]{64}", image
    ):
        raise ValueError("canonical execution ID and immutable image digest required")
    if (
        not command
        or any(not isinstance(v, str) or not v or "\x00" in v for v in command)
        or not 1 <= seconds <= 86400
        or epoch < 1
    ):
        raise ValueError("invalid Job execution profile")
    if not re.fullmatch(r"[1-9][0-9]*m", cpu) or not re.fullmatch(
        r"[1-9][0-9]*(Mi|Gi)", memory
    ):
        raise ValueError("explicit bounded resources required")
    labels = {
        "app.kubernetes.io/part-of": "agent-eval-experiments",
        "agent-eval/execution": execution_id,
        "agent-eval/epoch": str(epoch),
    }
    manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": f"eval-{execution_id}-{epoch}",
            "namespace": NAMESPACE,
            "labels": labels,
            "annotations": {
                "agent-eval/network-mode": "probe" if network_probe else "guarded"
            },
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": seconds,
            "ttlSecondsAfterFinished": 86400,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "target",
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": command,
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "resources": {
                                "requests": {"cpu": cpu, "memory": memory},
                                "limits": {
                                    "cpu": cpu,
                                    "memory": memory,
                                    "ephemeral-storage": "1Gi",
                                },
                            },
                            "volumeMounts": [{"name": "scratch", "mountPath": "/tmp"}],
                        }
                    ],
                    "volumes": [
                        {"name": "scratch", "emptyDir": {"sizeLimit": "256Mi"}}
                    ],
                },
            },
        },
    }

    if not network_probe:
        # k3s may admit target traffic before its asynchronous policy controller
        # installs pod rules. A trusted init container waits for repeated denial
        # before the target image starts. Run a positive control in qualification
        # to distinguish policy enforcement from a dead probe destination.
        guard = """stable=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if printf 'GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n' | nc -w 1 1.1.1.1 80 | grep -q HTTP; then
    stable=0
  else
    stable=$((stable+1))
    if [ "$stable" -ge 3 ]; then echo egress-probe-denied; exit 0; fi
  fi
  sleep 1
done
echo egress-isolation-not-established >&2
exit 1
"""
        manifest["spec"]["template"]["spec"]["initContainers"] = [
            {
                "name": "network-ready",
                "image": "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662",
                "command": ["/bin/sh", "-c", guard],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "requests": {"cpu": "25m", "memory": "16Mi"},
                    "limits": {
                        "cpu": "50m",
                        "memory": "32Mi",
                        "ephemeral-storage": "32Mi",
                    },
                },
            }
        ]
    return manifest


def pod_receipt(pod):
    status = pod.get("status", {})
    containers = status.get("containerStatuses", []) + status.get(
        "initContainerStatuses", []
    )
    return {
        "pod_uid": pod.get("metadata", {}).get("uid"),
        "node": pod.get("spec", {}).get("nodeName"),
        "phase": status.get("phase"),
        "reason": status.get("reason"),
        "containers": [
            {
                "name": c.get("name"),
                "image_id": c.get("imageID"),
                "state": c.get("state"),
                "restart_count": c.get("restartCount"),
            }
            for c in containers
        ],
        "pod_sha256": digest(pod),
    }


def execute_job(manifest, *, context, cancelled=lambda: False):
    """Create one Job and collect bounded pod evidence under an explicit context.

    A dispatch/create timeout is ambiguous. The immutable Job name is the
    reconciliation key; this function never resubmits after an uncertain create.
    """
    import subprocess
    import time
    from ..blackbox.models import json_bytes, parse_json
    from ..blackbox.targets import TargetCancelled
    from ..limits import MAX_RESULTS_JSON_BYTES

    # Accept only manifests generated by this module, with no additional mounts,
    # host namespaces, service account or environment secrets.
    spec = manifest["spec"]
    container = spec["template"]["spec"]["containers"][0]
    labels = manifest["metadata"]["labels"]
    expected = job(
        execution_id=labels["agent-eval/execution"],
        image=container["image"],
        command=container["command"],
        cpu=container["resources"]["limits"]["cpu"],
        memory=container["resources"]["limits"]["memory"],
        seconds=spec["activeDeadlineSeconds"],
        epoch=int(labels["agent-eval/epoch"]),
        network_probe=manifest["metadata"]
        .get("annotations", {})
        .get("agent-eval/network-mode")
        == "probe",
    )
    if manifest != expected or not context:
        raise ValueError("unregistered Kubernetes execution profile")

    def kubectl(*args, body=None):
        # Redirect to bounded files so unexpectedly large API responses do not
        # accumulate unbounded bytes in the controller process.
        import tempfile

        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run(
                ["kubectl", "--context", context, "--namespace", NAMESPACE, *args],
                input=body,
                stdout=stdout,
                stderr=stderr,
                timeout=30,
            )
            if result.returncode:
                stderr.seek(0)
                error = stderr.read(65536)
                if (
                    args[0] == "create"
                    and b"Forbidden" in error
                    and b"exceeded quota" in error
                ):
                    raise AdmissionDelayed(
                        "Kubernetes quota unavailable; no Job was admitted"
                    )
                raise RuntimeError(
                    "Kubernetes operation failed; reconcile by execution ID"
                )
            stdout.seek(0)
            raw = stdout.read(MAX_RESULTS_JSON_BYTES + 1)
            if len(raw) > MAX_RESULTS_JSON_BYTES:
                raise ValueError("Kubernetes evidence exceeds limit")
            return raw

    created = parse_json(
        kubectl("create", "-f", "-", "-o", "json", body=json_bytes(manifest))
    )
    uid = created["metadata"]["uid"]
    name = manifest["metadata"]["name"]
    deadline = time.monotonic() + spec["activeDeadlineSeconds"] + 45
    while time.monotonic() < deadline:
        current = parse_json(kubectl("get", "job", name, "-o", "json"))
        if current["metadata"]["uid"] != uid:
            raise RuntimeError("Job identity changed")
        if cancelled():
            # The deletion precondition fences against replacement of a Job
            # with the same name. Absence is verified separately by reconciler.
            options = {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": uid},
                "propagationPolicy": "Foreground",
            }
            kubectl(
                "delete",
                "--raw",
                f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{name}",
                "-f",
                "-",
                body=json_bytes(options),
            )
            raise TargetCancelled("Job cancellation requested; confirm pod termination")
        conditions = current.get("status", {}).get("conditions", [])
        if any(
            c.get("status") == "True" and c.get("type") in ("Complete", "Failed")
            for c in conditions
        ):
            pods = parse_json(
                kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json")
            )["items"]
            owned = [
                p
                for p in pods
                if any(
                    r.get("uid") == uid
                    for r in p["metadata"].get("ownerReferences", [])
                )
            ]
            receipts = [pod_receipt(p) for p in owned]
            outputs = []
            for pod in owned:
                raw = kubectl("logs", pod["metadata"]["name"], "--limit-bytes=1048576")
                outputs.append(
                    {
                        "pod_uid": pod["metadata"]["uid"],
                        "stdout": raw.decode("utf-8", errors="replace"),
                    }
                )
            return {
                "job_uid": uid,
                "manifest_sha256": digest(manifest),
                "job_status": current.get("status", {}),
                "pods": receipts,
                "outputs": outputs,
            }
        time.sleep(0.5)
    raise TimeoutError("Job outcome unknown; reconcile by execution ID")


def cleanup_job(*, context, name, uid):
    """Delete only the owned Job after its receipt has been durably stored."""
    import subprocess
    from ..blackbox.models import json_bytes

    if (
        not context
        or not re.fullmatch(r"eval-[a-z0-9-]{1,60}", name)
        or not re.fullmatch(r"[0-9a-f-]{36}", uid)
    ):
        raise ValueError("invalid owned Job identity")
    options = {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid},
        "propagationPolicy": "Foreground",
    }
    result = subprocess.run(
        [
            "kubectl",
            "--context",
            context,
            "delete",
            "--raw",
            f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{name}",
            "-f",
            "-",
        ],
        input=json_bytes(options),
        capture_output=True,
        timeout=30,
    )
    return result.returncode == 0 or b"NotFound" in result.stderr
