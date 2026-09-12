"""One owned, network-disabled candidate container and externally collected state."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path

from ..blackbox.models import digest, json_bytes, parse_json
from ..experiments.journal import JournalError, immutable_json, read_json
from ..limits import read_stable_bounded_file
from ..paths import atomic_write_private, ensure_private_directory, get_state_dir
from .authority import materialize
from .contracts import CandidateManifest, ExecutionContract
from .oracles import BehaviorSuite


def docker(*args, timeout=30):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise JournalError("candidate container operation failed")
    return result.stdout


def directory(project, execution):
    return ensure_private_directory(
        get_state_dir() / "candidate-executions" / digest(project) / execution,
        parents=True,
    )


def inspect(name):
    value = subprocess.run(
        ["docker", "container", "inspect", name], capture_output=True, timeout=20
    )
    if value.returncode:
        # Distinguish absence from a disconnected Docker daemon before any create.
        docker("info", "--format", "{{.ServerVersion}}")
        return None
    return json.loads(value.stdout)[0]


def execute(
    project: str,
    contract: ExecutionContract,
    manifest: CandidateManifest,
    suite: BehaviorSuite,
):
    root = directory(project, contract.execution_id)
    contract_sha = digest(contract.model_dump(mode="json"))
    receipt = root / "observation.json"
    if receipt.exists():
        saved = read_json(receipt)
        if saved["contract_sha256"] != contract_sha:
            raise JournalError("saved candidate observation identity mismatch")
        return saved["observation"]
    name = "ae-candidate-" + contract.execution_id
    claim = root / "dispatch.json"
    existing = inspect(name)
    if claim.exists() and existing is None:
        raise JournalError(
            "candidate dispatch is ambiguous; owned container is unavailable"
        )
    if not claim.exists():
        if existing is not None:
            raise JournalError("candidate container name is already owned")
        if not (root / "candidate").exists():
            materialize(
                root / "candidate",
                {k: v.model_dump() for k, v in manifest.files.items()},
            )
        ensure_private_directory(root / "inputs")
        # The candidate receives only public request values, never checks or expected state.
        atomic_write_private(
            root / "inputs" / "requests.jsonl",
            b"\n".join(json_bytes(r) for r in suite.requests) + b"\n",
        )
        state = ensure_private_directory(root / "state")
        # The parent remains 0700. Only this disposable bind mount is writable to UID 65534.
        state.chmod(0o777)
        for p in (root / "candidate", root / "inputs"):
            for directory_path, folders, filenames in os.walk(p):
                Path(directory_path).chmod(0o755)
                for filename in filenames:
                    path = Path(directory_path) / filename
                    path.chmod(0o755 if os.stat(path).st_mode & 0o111 else 0o644)
        # Record the intent first. A crash before create is conservatively ambiguous.
        immutable_json(claim, {"contract_sha256": contract_sha, "container": name})
        docker(
            "create",
            "--name",
            name,
            "--label",
            "agent-eval.contract=" + contract_sha,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--user",
            "65534:65534",
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=1m",
            "--log-opt",
            "max-file=1",
            "--log-opt",
            "compress=false",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--mount",
            f"type=bind,src={root / 'candidate'},dst=/candidate,readonly",
            "--mount",
            f"type=bind,src={root / 'inputs'},dst=/inputs,readonly",
            "--mount",
            f"type=bind,src={state},dst=/state",
            "--workdir",
            "/candidate",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint",
            "/bin/sh",
            suite.image,
            "-c",
            'exec python -B "$1" < /inputs/requests.jsonl',
            "candidate",
            "/candidate/" + suite.entrypoint,
        )
        existing = inspect(name)
    if existing["Config"]["Labels"].get("agent-eval.contract") != contract_sha:
        raise JournalError("owned container identity mismatch")
    if existing["State"]["Status"] == "created":
        docker("start", name)
    while True:
        existing = inspect(name)
        if existing is None:
            raise JournalError("owned container disappeared")
        state = existing["State"]
        if state["Status"] in ("exited", "dead"):
            break
        from datetime import datetime, timezone

        started = datetime.fromisoformat(state["StartedAt"].replace("Z", "+00:00"))
        if (
            datetime.now(timezone.utc) - started
        ).total_seconds() > suite.timeout_seconds:
            docker("kill", name)
            existing = inspect(name)
            if existing["State"]["Running"]:
                raise JournalError("candidate termination unconfirmed")
            state = existing["State"]
            break
        time.sleep(0.1)
    logs = docker("logs", name)
    if len(logs) > 1024 * 1024:
        raise JournalError("candidate output exceeds limit")
    lines = logs.splitlines()
    responses = []
    protocol_error = len(lines) != len(suite.requests)
    try:
        responses = [parse_json(line) for line in lines]
    except (ValueError, UnicodeError):
        protocol_error = True
    state_values = {}
    db_path = root / "state" / "state.sqlite"
    if any(c.state_query for c in suite.checks) and db_path.exists():
        # Copy bounded regular bytes after the container has stopped, with no candidate connection.
        data = read_stable_bounded_file(db_path, maximum_bytes=8 * 1024 * 1024)
        observed = root / "observed.sqlite"
        atomic_write_private(observed, data)
        with sqlite3.connect(
            observed.as_uri() + "?mode=ro&immutable=1", uri=True
        ) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA query_only=ON")
            deadline = time.monotonic() + 2
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            for check in suite.checks:
                if check.state_query:
                    try:
                        state_values[check.id] = [
                            list(row)
                            for row in db.execute(check.state_query).fetchmany(1001)
                        ]
                    except sqlite3.Error:
                        state_values[check.id] = None
    observation = {
        "responses": responses,
        "state_queries": state_values,
        "exit_code": state["ExitCode"],
        "protocol_error": protocol_error,
        "image_id": existing["Image"],
        "container_id": existing["Id"],
        "started_at": state["StartedAt"],
        "finished_at": state["FinishedAt"],
    }
    immutable_json(
        receipt, {"contract_sha256": contract_sha, "observation": observation}
    )
    return observation


def cleanup(project, execution):
    root = directory(project, execution)
    if not (root / "observation.json").exists():
        raise JournalError("observation must be saved before cleanup")
    name = "ae-candidate-" + execution
    owned = inspect(name)
    if owned:
        expected = read_json(root / "dispatch.json")["contract_sha256"]
        if (
            owned["State"]["Running"]
            or owned["Config"]["Labels"].get("agent-eval.contract") != expected
        ):
            raise JournalError("container is running or not owned")
        docker("rm", name)
