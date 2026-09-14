"""Private profile transport and offline controls. Receives only public input."""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

from ..blackbox.models import json_bytes, parse_json
from ..blackbox.targets import HttpTarget, ResponseDecoder
from ..experiments.journal import read_json


def tool(handle, operation, payload):
    request = urllib.request.Request(
        handle["endpoint"] + "/" + operation,
        data=json_bytes(payload),
        headers={
            "Authorization": "Bearer " + handle["token"],
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return parse_json(response.read(65537))
    except (urllib.error.HTTPError, ValueError):
        return {"status": "unavailable"}


def main():
    mode = sys.argv[1]
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("input limit")
    value = parse_json(raw)
    if mode == "http":
        import os
        from pathlib import Path

        profile = read_json(Path(sys.argv[2]))
        token = os.environ.get(profile.get("token_env", ""))
        result = HttpTarget(
            profile["endpoint"],
            timeout=profile.get("timeout", 120),
            decoder=ResponseDecoder("json"),
            bearer_token=token,
        ).invoke(value)
    elif mode in ("good", "regression"):
        result = {
            "answer": value["question"]
            if mode == "good" or value["question"] != "returns"
            else "unknown"
        }
    elif mode in ("ticket-good", "ticket-lie", "ticket-wrong", "order"):
        handle = value["environment"]
        if mode == "ticket-lie":
            result = {"status": "closed"}
        elif mode == "order":
            result = tool(handle, "read", {"id": value.get("id", "ticket-1")})
        else:
            identity = (
                "ticket-2" if mode == "ticket-wrong" else value.get("id", "ticket-1")
            )
            result = tool(handle, "write", {"id": identity, "status": "closed"})
    else:
        raise ValueError("unknown adapter")
    sys.stdout.buffer.write(json_bytes(result))


if __name__ == "__main__":
    main()
