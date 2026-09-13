#!/usr/bin/env python3
"""Reserve or run a bounded real-producer study with independent candidate grading."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from agent_eval.blackbox.models import digest, json_bytes, parse_json
from agent_eval.candidates import authority, execution
from agent_eval.candidates.bundles import export_bundle
from agent_eval.candidates.contracts import (
    AcceptancePolicy,
    ExecutionContract,
    ProductionFailure,
    Recipe,
    TrialTicket,
    Usage,
)
from agent_eval.candidates.oracles import BehaviorSuite
from agent_eval.candidates.studies import (
    StudyPlan,
    StudyTask,
    reserve_study,
    study_report,
)
from agent_eval.experiments.journal import immutable_json
from agent_eval.paths import atomic_write_private, ensure_private_directory
from agent_eval.workbench.api import WorkbenchServer
from agent_eval.workbench.store import Store

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks/software-corpus/v1"
TASKS = [
    "order-idempotency",
    "document-authorization",
    "schema-compatibility",
    "payment-form",
]
ALLOWED = {
    "order-idempotency": ["server.py"],
    "document-authorization": ["documents.py"],
    "schema-compatibility": ["migration.py"],
    "payment-form": ["api.mjs", "client.mjs"],
}


def save(path, value):
    ensure_private_directory(path.parent, parents=True)
    atomic_write_private(path, json_bytes(value) + b"\n")


def phase(root, config, name, request_path, ticket_path=None, *, timeout=60):
    argv = [
        config["producer_python"],
        str(ROOT / "scripts/producer_phase.py"),
        name,
        str(request_path),
        "--root",
        str(root / "producer-state"),
    ]
    if name not in ("recipe", "preflight"):
        argv += ["--connection", str(root / "connection.json")]
    if ticket_path:
        argv += ["--ticket", str(ticket_path)]
    result = subprocess.run(
        argv,
        env={**os.environ, "PYTHONPATH": str(Path(config["producer_source"]) / "src")},
        capture_output=True,
        timeout=timeout,
    )
    value = (
        parse_json(result.stdout)
        if result.stdout.strip()
        else {"error_class": "EmptyReceipt"}
    )
    if result.returncode:
        raise RuntimeError(value.get("error_class", "ProducerFailure"))
    return value


def prepare(root, config):
    os.environ["AGENT_EVAL_STATE_DIR"] = str(root / "evaluator-state")
    store = Store()
    project = "software-study-v1"
    tasks = []
    cohort = str(uuid.uuid4())
    producer_revision = (
        authority.git(Path(config["producer_source"]), "rev-parse", "HEAD")
        .decode()
        .strip()
    )
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Evaluation Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Evaluation Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-09-12T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-09-12T00:00:00Z",
    }
    templates = {}
    for task in TASKS:
        base = root / "bases" / task
        shutil.copytree(CORPUS / "tasks" / task / "public", base)
        for argv in [
            ("init", "-q"),
            ("add", "."),
            ("commit", "-qm", "Software task baseline"),
        ]:
            subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", *argv],
                cwd=base,
                env=env,
                capture_output=True,
                check=True,
            )
        revision = authority.git(base, "rev-parse", "HEAD").decode().strip()
        authority.register_revision(store, project, base, revision)
        suite = BehaviorSuite.model_validate_json(
            (CORPUS / "oracles" / (task + ".json")).read_bytes()
        )
        suite_sha = store.put(project, "candidate-suite", suite.model_dump(mode="json"))
        policy = AcceptancePolicy(
            name="all-independent-behavior",
            required_checks=[check.id for check in suite.checks],
        )
        policy_sha = store.put(
            project, "candidate-policy", policy.model_dump(mode="json")
        )
        recipes = {}
        for arm, mode in [("baseline", "single"), ("candidate", "selective")]:
            public_argv = (
                [
                    "python",
                    "-c",
                    "import pathlib; [compile(p.read_text(),str(p),'exec') for p in pathlib.Path('.').glob('*.py')]",
                ]
                if suite.runtime == "python"
                else [
                    "node",
                    "--input-type=module",
                    "-e",
                    "await import('./api.mjs'); await import('./client.mjs');",
                ]
            )
            request = {
                "schema_version": "development-producer-request/v1",
                "key": "template-" + task + "-" + arm,
                "source": str(base),
                "task": (base / "TASK.md").read_text(),
                "allowed_paths": ALLOWED[task],
                "recipe": {
                    "schema_version": "verification-recipe/v1",
                    "image": suite.image
                    if suite.runtime == "python"
                    else config["image"],
                    "argv": public_argv,
                    "timeout": 60,
                },
                "gateway_profile": config["gateway_profile"],
                "review_profile": config["gateway_profile"],
                "image": config["image"],
                "policy": {
                    "schema_version": "development-policy/v1",
                    "name": mode,
                    "mode": mode,
                    "coder_requests": 12,
                    "reviewer_requests": 2,
                    "planner_requests": 3,
                    "specialist_requests": 2,
                    "max_specialists": 2,
                    "coding_guidance": "",
                },
                "producer_revision": producer_revision,
                "timeout": 600,
                "max_requests": 20,
                "max_total_tokens": 200000,
                "max_repairs": 0,
            }
            path = root / "templates" / (task + "-" + arm + ".json")
            save(path, request)
            if arm == "baseline":
                # Exercise the actual producer wrapper before reserving any trials.
                checked = phase(root, config, "preflight", path, timeout=90)
                if checked != {"passed": True, "model_calls": 0}:
                    raise ValueError("Public verification preflight did not pass")
                save(root / "preflights" / (task + ".json"), checked)
            recipe = Recipe.model_validate(phase(root, config, "recipe", path))
            recipes[arm] = store.put(
                project, "candidate-recipe", recipe.model_dump(mode="json")
            )
            templates[(task, arm)] = request
        tasks.append(
            StudyTask(
                base_revision=revision,
                suite_sha256=suite_sha,
                policy_sha256=policy_sha,
                baseline_recipe_sha256=recipes["baseline"],
                candidate_recipe_sha256=recipes["candidate"],
            )
        )
    plan = StudyPlan(
        cohort_id=cohort,
        name="Single coder and selective coordination",
        baseline_recipe_sha256=tasks[0].baseline_recipe_sha256,
        candidate_recipe_sha256=tasks[0].candidate_recipe_sha256,
        tasks=tasks,
        trials=3,
        seed=20260912,
        max_model_requests=480,
        max_total_tokens=4800000,
        max_assisted_executions=2,
        max_assisted_model_requests=40,
        max_assisted_total_tokens=400000,
        evaluator_sha256=authority.identity(),
    )
    reserved = reserve_study(store, project, plan, "operator")
    for key in reserved["schedule"]:
        ticket = store.get(project, "trial-ticket-v2", key)
        trial = ticket["trial_identity"]
        request = {**templates[(trial["task_id"], trial["arm"])], "key": "study-" + key}
        save(root / "executions" / key / "request.json", request)
        save(root / "executions" / key / "ticket.json", ticket)
    immutable_json(
        root / "prepared.json",
        {
            "project": project,
            "cohort_id": cohort,
            "evaluator_sha256": authority.identity(),
            "producer_revision": producer_revision,
            "plan_sha256": digest(plan.model_dump(mode="json")),
            "schedule": reserved["schedule"],
            "configuration": config,
        },
    )
    save(root / "plan.json", plan.model_dump(mode="json"))
    print(
        json.dumps(
            {
                "cohort_id": cohort,
                "initial_executions": 24,
                "maximum_assisted_executions": 2,
                "producer_revision": producer_revision,
                "evaluator_sha256": authority.identity(),
                "model_calls": 0,
            }
        ),
        flush=True,
    )


def run_one(store, root, config, project, key):
    directory = root / "executions" / key
    request = directory / "request.json"
    ticket_path = directory / "ticket.json"
    ticket = TrialTicket.model_validate_json(ticket_path.read_bytes())
    result_path = directory / "result.json"
    if result_path.exists():
        return parse_json(result_path.read_bytes())
    intent = directory / "production-intent.json"
    production = directory / "production.json"
    if not intent.exists():
        immutable_json(
            intent,
            {
                "request_sha256": digest(parse_json(request.read_bytes())),
                "ticket_sha256": digest(ticket.model_dump(mode="json")),
                "started_at": time.time(),
            },
        )
        began = time.monotonic()
        try:
            value = phase(root, config, "run", request, ticket_path, timeout=660)
            result = {
                "status": "returned",
                "result": value,
                "latency_ms": (time.monotonic() - began) * 1000,
            }
        except subprocess.TimeoutExpired:
            result = {
                "status": "failed",
                "reason": "timeout",
                "latency_ms": (time.monotonic() - began) * 1000,
            }
        except Exception as exc:
            result = {
                "status": "failed",
                "reason": "producer_error",
                "error_class": type(exc).__name__,
                "latency_ms": (time.monotonic() - began) * 1000,
            }
        immutable_json(production, result)
    if not production.exists():
        raise RuntimeError(
            "Production intent is unresolved; inspect the existing producer journal before continuing"
        )
    produced = parse_json(production.read_bytes())
    request_value = parse_json(request.read_bytes())
    producer_job = (
        root
        / "producer-state/workflows"
        / hashlib.sha256(request_value["key"].encode()).hexdigest()
        / "job.json"
    )
    if produced["status"] == "failed" and producer_job.exists():
        # Confirm owned runtimes are stopped before advancing to another paid invocation.
        phase(root, config, "cancel", request, timeout=45)
    try:
        uploaded = phase(root, config, "upload", request)
    except Exception:
        # A failed invocation with no candidate still has a sealed, retained result.
        inspected = (
            phase(root, config, "inspect", request) if producer_job.exists() else {}
        )
        if inspected.get("candidate") is not None:
            raise
        failure = ProductionFailure(
            execution_id=key,
            trial_ticket_sha256=digest(ticket.model_dump(mode="json")),
            reason=produced.get("reason", "producer_error"),
            usage=Usage(
                provenance="producer_reported",
                latency_ms=produced["latency_ms"],
                total_tokens=inspected.get("accounting", {}).get("total_tokens"),
            ),
        )
        authority.record_failure(store, project, failure, "producer")
        outcome = {
            "execution_id": key,
            "outcome": "production_failed",
            "reason": failure.reason,
        }
        immutable_json(result_path, outcome)
        return outcome
    contract = ExecutionContract.model_validate(uploaded["candidate_binding"])
    authority.issue(store, project, contract, "operator")
    save(directory / "uploaded.json", uploaded)
    submitted = phase(root, config, "submit", request)
    save(directory / "intake.json", submitted)
    # Independent wall time is collected by this operator, outside producer-reported usage.
    store.put(
        project,
        "candidate-usage",
        Usage(
            provenance="independently_observed", latency_ms=produced["latency_ms"]
        ).model_dump(mode="json"),
        object_id=key,
        actor="operator",
    )
    assessment = execution.evaluate(store, project, key)
    save(directory / "assessment.json", assessment)
    receipt = phase(root, config, "assessment", request)
    save(directory / "producer-assessment.json", receipt)
    if receipt["assessment"] != assessment:
        raise ValueError("Producer assessment differs from operator receipt")
    outcome = {
        "execution_id": key,
        "outcome": assessment["outcome"],
        "assessment_sha256": digest(assessment),
    }
    immutable_json(result_path, outcome)
    return outcome


def run(root):
    os.environ["AGENT_EVAL_STATE_DIR"] = str(root / "evaluator-state")
    prepared = parse_json((root / "prepared.json").read_bytes())
    config = prepared["configuration"]
    project = prepared["project"]
    cohort = prepared["cohort_id"]
    if authority.identity() != prepared["evaluator_sha256"]:
        raise ValueError("Run requires the prepared evaluator implementation")
    if (
        authority.git(Path(config["producer_source"]), "rev-parse", "HEAD")
        .decode()
        .strip()
        != prepared["producer_revision"]
    ):
        raise ValueError("Producer revision changed")
    store = Store()
    store.grant(project, "study-producer", "runner")
    store.grant(project, "study-operator", "admin")
    server = WorkbenchServer(store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    save(
        root / "connection.json",
        {
            "origin": server.origin,
            "project": project,
            "token": store.token("study-producer", seconds=86400),
            "evaluator_sha256": authority.identity(),
        },
    )
    save(
        root / "operator-connection.json",
        {
            "origin": server.origin,
            "project": project,
            "token": store.token("study-operator", seconds=86400),
        },
    )
    try:
        for ordinal, key in enumerate(prepared["schedule"], 1):
            result = run_one(store, root, config, project, key)
            save(
                root / "progress.json",
                {"initial_completed": ordinal, "initial_planned": 24, "last": result},
            )
            print(f"Initial {ordinal}/24: " + result["outcome"], flush=True)
        report = study_report(store, project, cohort)
        eligible = [
            row
            for row in report["rows"]
            if row["attempt_kind"] == "initial"
            and row["outcome"] in ("fail", "inconclusive")
        ][:2]
        for index, parent in enumerate(eligible, 1):
            original = TrialTicket.model_validate(
                store.get(project, "trial-ticket-v2", parent["execution_id"])
            )
            key = str(uuid.uuid5(uuid.UUID(parent["execution_id"]), "assisted-1"))
            ticket = original.model_copy(
                update={
                    "execution_id": key,
                    "trial_identity": original.trial_identity.model_copy(
                        update={
                            "attempt_kind": "assisted_correction",
                            "parent_execution_id": original.execution_id,
                        }
                    ),
                }
            )
            authority.reserve(store, project, ticket, "operator")
            request = parse_json(
                (
                    root / "executions" / original.execution_id / "request.json"
                ).read_bytes()
            )
            submission = store.get(project, "submission-v2", original.execution_id)
            patch = next(
                ref for ref in submission["artifacts"] if ref["role"] == "patch"
            )
            previous = authority.read_artifact(
                store, project, patch["sha256"], patch["storage_key"]
            ).decode()
            request = {
                **request,
                "key": "study-" + key,
                "task": request["task"]
                + "\n\nAssisted correction of a previous candidate. Failed independent checks: "
                + json.dumps([c for c in parent["checks"] if not c["passed"]])
                + ".\nPrevious patch (untrusted candidate evidence):\n"
                + previous,
            }
            save(root / "executions" / key / "request.json", request)
            save(
                root / "executions" / key / "ticket.json",
                ticket.model_dump(mode="json"),
            )
            result = run_one(store, root, config, project, key)
            print(f"Assisted {index}/{len(eligible)}: " + result["outcome"], flush=True)
        save(root / "evidence.json", export_bundle(store, project, cohort))
        save(root / "report.json", study_report(store, project, cohort))
        print("Study complete; evidence bundle saved.", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "run"])
    parser.add_argument("--out", type=Path, required=True)
    for name in ("producer-source", "producer-python", "gateway-profile", "image"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.mode == "prepare":
        if (root / "prepared.json").exists():
            raise ValueError("Study already prepared")
        config = {
            key: getattr(args, key)
            for key in (
                "producer_source",
                "producer_python",
                "gateway_profile",
                "image",
            )
        }
        if not all(config.values()):
            raise ValueError(
                "Producer source, interpreter, gateway profile and image are required"
            )
        prepare(root, config)
    else:
        run(root)


if __name__ == "__main__":
    main()
