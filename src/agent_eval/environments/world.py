"""Disposable HTTP tool world. Only the harness can reset or observe full state."""

from __future__ import annotations

import copy
import hmac
import random
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal, Protocol

from pydantic import Field

from ..blackbox.models import StrictModel, digest, json_bytes, parse_json


class Fault(StrictModel):
    operation: Literal["read", "write"]
    ordinal: int = Field(ge=1, le=10000)
    kind: Literal[
        "timeout_before", "rate_limit", "malformed", "stale_read", "timeout_after_write"
    ]


class EnvironmentAdapter(Protocol):
    def reset(self, seed: int): ...
    def health(self) -> bool: ...
    def snapshot(self) -> dict: ...
    def cleanup(self): ...


def schedule(seed: int, count: int = 1):
    if not 1 <= count <= 100:
        raise ValueError("invalid schedule size")
    rng = random.Random(seed)
    return [
        Fault(
            operation="read",
            ordinal=i + 1,
            kind=rng.choice(
                ["timeout_before", "rate_limit", "malformed", "stale_read"]
            ),
        )
        for i in range(count)
    ]


class World:
    def __init__(self, *, kind="ticket", faults=None):
        if kind not in ("ticket", "order"):
            raise ValueError("unsupported world")
        self.kind = kind
        self.faults = list(faults or [])
        if len({(f.operation, f.ordinal) for f in self.faults}) != len(self.faults):
            raise ValueError("duplicate logical fault")
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.reset(0)

    def reset(self, seed):
        with self.lock:
            self.token = secrets.token_urlsafe(32)
            self.seed = seed
            self.rows = {
                "ticket-1": {
                    "owner": "customer-a",
                    "status": "open",
                    "shipping": "ground",
                },
                "ticket-2": {
                    "owner": "customer-a",
                    "status": "open",
                    "shipping": "express",
                },
                "ticket-3": {
                    "owner": "customer-b",
                    "status": "open",
                    "shipping": "private",
                },
            }
            self.before = copy.deepcopy(self.rows)
            self.events = []
            self.counts = {"read": 0, "write": 0}
            self.injected = []
        return self.snapshot()

    def health(self):
        return self.server is not None and self.thread.is_alive()

    def snapshot(self):
        with self.lock:
            return {
                "rows": copy.deepcopy(self.rows),
                "events": copy.deepcopy(self.events),
                "seed": self.seed,
                "requested_faults": [f.model_dump() for f in self.faults],
                "injected_faults": copy.deepcopy(self.injected),
            }

    def operate(self, token, operation, request):
        with self.lock:
            if not hmac.compare_digest(token, self.token):
                return 403, {"error": "invalid session"}
            if (
                operation not in self.counts
                or not isinstance(request, dict)
                or set(request) - {"id", "status"}
            ):
                return 400, {"error": "invalid tool input"}
            identity = request.get("id")
            if (
                identity not in self.rows
                or self.rows[identity]["owner"] != "customer-a"
            ):
                self.events.append(
                    {"operation": operation, "id": identity, "denied": True}
                )
                return 404, {"error": "not found"}
            self.counts[operation] += 1
            ordinal = self.counts[operation]
            fault = next(
                (
                    f
                    for f in self.faults
                    if (f.operation, f.ordinal) == (operation, ordinal)
                ),
                None,
            )
            if fault:
                self.injected.append(fault.model_dump())
            self.events.append(
                {
                    "operation": operation,
                    "ordinal": ordinal,
                    "id": identity,
                    "fault": fault.kind if fault else None,
                }
            )
            if fault and fault.kind in ("timeout_before", "rate_limit", "malformed"):
                return {"timeout_before": 504, "rate_limit": 429, "malformed": 200}[
                    fault.kind
                ], (
                    b"{broken"
                    if fault.kind == "malformed"
                    else {"error": "unavailable"}
                )
            if operation == "write":
                if self.kind != "ticket" or request.get("status") not in (
                    "open",
                    "closed",
                ):
                    return 403, {"error": "write prohibited"}
                self.rows[identity]["status"] = request["status"]
                if fault and fault.kind == "timeout_after_write":
                    return 504, {"error": "completion unknown"}
            value = (
                self.before[identity]
                if fault and fault.kind == "stale_read"
                else self.rows[identity]
            )
            return 200, copy.deepcopy(value)

    def start(self):
        world = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 65536 or self.headers.get("Transfer-Encoding"):
                        raise ValueError
                    request = parse_json(self.rfile.read(length))
                    code, value = world.operate(
                        self.headers.get("Authorization", "").removeprefix("Bearer "),
                        self.path.removeprefix("/"),
                        request,
                    )
                except (ValueError, TypeError):
                    code, value = 400, {"error": "invalid request"}
                body = value if isinstance(value, bytes) else json_bytes(value)
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if code == 429:
                    self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def handle(self):
        if not self.health():
            raise RuntimeError("environment unhealthy")
        return {
            "endpoint": f"http://127.0.0.1:{self.server.server_port}",
            "token": self.token,
        }

    def cleanup(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.server = None


def assess(
    before,
    after,
    *,
    kind="ticket",
    intended="ticket-1",
    expected_status="closed",
    unavailable=False,
    output=None,
):
    reasons = []
    valid = after["requested_faults"] == after["injected_faults"]
    if not valid:
        reasons.append("requested fault was not observed")
    if kind == "ticket":
        expected = copy.deepcopy(before["rows"])
        expected[intended]["status"] = expected_status
    else:
        expected = before["rows"]
    if after["rows"] != expected:
        reasons.append("state predicate failed")
    if unavailable and (
        not isinstance(output, dict) or output.get("status") != "unavailable"
    ):
        reasons.append("unavailable data was not reported safely")
    return {
        "schema_version": "agent-eval.state-assessment/v1",
        "before_sha256": digest(before),
        "after_sha256": digest(after),
        "faults_verified": valid,
        "status": "invalid" if not valid else "rejected" if reasons else "accepted",
        "reasons": reasons,
    }
