#!/usr/bin/env python3
"""Run one producer API phase using private local configuration and receipts."""

import argparse
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from swe_platform.producer import (
    EvaluatorClient,
    EvaluatorProfile,
    Producer,
    ProducerRequest,
)
from swe_platform.sandbox.docker import Docker
from swe_platform.workflow import Workflow
from swe_platform.workspace.snapshot import snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        choices=[
            "recipe",
            "run",
            "upload",
            "submit",
            "assessment",
            "inspect",
            "cancel",
            "preflight",
        ],
    )
    parser.add_argument("request", type=Path)
    parser.add_argument("--ticket", type=Path)
    parser.add_argument("--connection", type=Path)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    request = ProducerRequest.model_validate_json(args.request.read_bytes())
    if args.phase == "recipe":
        print(json.dumps(request.recipe_descriptor()))
        return
    if args.phase == "preflight":
        directory = Path(tempfile.mkdtemp(prefix="producer-preflight-"))
        base = snapshot(request.source, directory / "source")
        docker = Docker(directory / "containers", image=request.recipe.image)
        key = str(uuid.uuid4())
        try:
            result = docker.run(
                key,
                base["files"],
                request.recipe.argv,
                timeout=request.recipe.timeout,
            )
            if result["exit_code"] != 0 or result["reason"] is not None:
                raise ValueError("Public verification preflight failed")
            print(json.dumps({"passed": True, "model_calls": 0}))
        finally:
            if not docker.cancel(key):
                raise RuntimeError("Preflight termination is unconfirmed")
            docker.remove(key)
            shutil.rmtree(directory)
        return
    if args.phase in ("inspect", "cancel"):
        print(json.dumps(getattr(Workflow(args.root), args.phase)(request.key)))
        return
    connection = json.loads(args.connection.read_bytes())
    os.environ["STUDY_EVALUATOR_TOKEN"] = connection["token"]
    client = EvaluatorClient(
        EvaluatorProfile(
            base_url=connection["origin"],
            project=connection["project"],
            evaluator_sha256=connection["evaluator_sha256"],
            token_env="STUDY_EVALUATOR_TOKEN",
        )
    )
    producer = Producer(args.root, client)
    if args.phase == "run":
        result = producer.run(request, json.loads(args.ticket.read_bytes()))
    else:
        result = getattr(producer, args.phase)(request.key)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"error_class": type(exc).__name__}))
        raise SystemExit(1) from None
