"""Operator commands for the experiment workbench and private registrations."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import typer

from ..blackbox.models import Suite, digest, load_suite
from ..experiments.journal import Journal, read_json
from ..experiments.models import CommandSpec
from ..paths import atomic_write_private, ensure_private_directory, get_state_dir
from . import service
from .analysis import Policy
from .datasets import CalibrationCase, Dataset, calibrate, quarantine, register_dataset
from .models import TargetProfile
from .store import Store

app = typer.Typer(
    help="Experiment UI, comparisons, private profiles and project controls.",
    no_args_is_help=True,
)


def command(name):
    """Keep private profile data out of exception rendering."""
    import functools

    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except typer.Exit:
                raise
            except Exception as exc:
                typer.echo("Operation failed: " + type(exc).__name__, err=True)
                raise typer.Exit(1) from None

        return app.command(name)(wrapped)

    return decorate


def emit(value):
    from ..blackbox.models import json_bytes

    typer.echo(json_bytes(value).decode())


@command("serve")
def serve(
    port: int = typer.Option(8765, min=0, max=65535),
    project: str = "local",
    oidc: bool = False,
):
    """Start a loopback-only API. Session credentials expire after one hour."""
    from .api import WorkbenchServer
    from .auth import OIDC

    store = Store()
    provider = None
    if oidc:
        provider = OIDC(
            **{
                name: os.environ["AGENT_EVAL_OIDC_" + name.upper()]
                for name in (
                    "endpoint",
                    "issuer",
                    "audience",
                    "client_id",
                    "client_secret",
                )
            }
        )
    server = WorkbenchServer(store, port, oidc=provider)
    if not provider:
        subject = "local-session:" + store.new_id()
        store.grant(project, subject, "admin")
        token = store.token(subject)
        atomic_write_private(
            get_state_dir() / "workbench" / "session-token", token.encode()
        )
        typer.echo(f"Workbench: {server.origin}/#token={token}", err=True)
    else:
        typer.echo(
            f"Workbench: {server.origin}/ (OIDC introspection enabled)", err=True
        )
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if not provider:
            store.revoke(subject)


@command("demo")
def demo(project: str = "local"):
    """Run both offline controls; the returns case contains a seeded regression."""
    emit(service.demo(Store(), project))


@command("register-target")
def register_target(path: Path, project: str = "local"):
    """Register a private JSON TargetProfile. No target is invoked."""
    profile = TargetProfile.model_validate(read_json(path))
    emit({"target": Store().put(project, "target", profile.model_dump(mode="json"))})


@command("register-http")
def register_http(
    path: Path, name: str = typer.Option(..., "--name"), project: str = "local"
):
    """Register private endpoint/token-env JSON for a fresh HTTP process per trial."""
    from ..blackbox.models import json_bytes
    from ..blackbox.targets import HttpTarget

    profile = read_json(path)
    if set(profile) - {"endpoint", "token_env", "timeout"}:
        raise ValueError("unknown HTTP configuration")
    HttpTarget(profile["endpoint"], timeout=profile.get("timeout", 120))
    root = ensure_private_directory(
        get_state_dir() / "workbench" / "http", parents=True
    )
    config = root / (digest(profile) + ".json")
    atomic_write_private(config, json_bytes(profile))
    target = TargetProfile(
        name=name,
        command=CommandSpec(
            argv=[
                sys.executable,
                "-m",
                "agent_eval.workbench.adapter",
                "http",
                str(config),
            ],
            response_format="json",
            env_names=[profile["token_env"]] if profile.get("token_env") else [],
        ),
        identity_files=[str(config), str(Path(__file__).with_name("adapter.py"))],
    )
    emit({"target": Store().put(project, "target", target.model_dump(mode="json"))})


@command("register-dataset")
def register(path: Path, project: str = "local"):
    emit(
        {
            "dataset": register_dataset(
                Store(), project, Dataset.model_validate(read_json(path)), "local"
            )
        }
    )


@command("policy")
def policy(path: Path, project: str = "local"):
    value = Policy.model_validate(read_json(path))
    emit({"policy": Store().put(project, "policy", value.model_dump(mode="json"))})


@command("compare")
def compare(baseline: str, candidate: str, project: str = "local"):
    emit(service.comparison(Store(), project, baseline, candidate))


@command("gate")
def gate(
    baseline: str,
    candidate: str,
    policy: str,
    candidate_artifact: str,
    project: str = "local",
):
    decision = service.gate(
        Store(), project, baseline, candidate, policy, candidate_artifact, "local"
    )
    emit(decision)
    if decision["verdict"] != "pass":
        raise typer.Exit(2 if decision["verdict"] == "fail" else 3)


@command("regrade")
def regrade(experiment: str, suite_path: Path, project: str = "local"):
    """Append a new assessment set from saved observations; never overwrite trials."""
    from ..blackbox.runner import grade_observation
    from ..experiments.service import evaluator_identity

    store = Store()
    store.get(project, "experiment", experiment)
    suite = load_suite(suite_path)
    with Journal.open(experiment) as journal:
        if journal.status().state != "completed":
            raise ValueError("regrading requires a complete cohort")
        original = {c.id: digest(c.input) for c in journal.plan.suite.cases}
        if {c.id: digest(c.input) for c in suite.cases} != original:
            raise ValueError("regrading cannot substitute cases or public inputs")
        if any(
            m.kind == "geval" for c in suite.cases for m in c.metrics or suite.metrics
        ):
            raise ValueError("live judging requires a separate budgeted run")
        cases = {c.id: c for c in suite.cases}
        results = []
        for row in journal.rows():
            receipt, _ = journal.receipt(row)
            case, trial = journal.plan.case_trial(row["ordinal"])
            results.append(
                grade_observation(
                    suite,
                    cases[case.id],
                    trial,
                    receipt.observation,
                    error=receipt.error,
                ).model_dump(mode="json")
            )
        value = {
            "experiment": experiment,
            "plan_sha256": journal.plan_sha256,
            "suite_sha256": digest(suite.model_dump(mode="json")),
            "grader_sha256": evaluator_identity(),
            "results": results,
        }
    emit({"assessment_set": store.put(project, "assessment-set", value)})


@command("calibrate")
def calibration(path: Path, grader_sha256: str, project: str = "local"):
    cases = [CalibrationCase.model_validate(v) for v in read_json(path)]
    value = calibrate(cases, grader_sha256)
    emit({"calibration": Store().put(project, "calibration", value), **value})


@command("import-report")
def import_report(path: Path, source: str = "legacy", project: str = "local"):
    from .submissions import import_external

    emit(
        {
            "external_report": import_external(
                Store(), project, source, read_json(path), "local"
            )
        }
    )


@command("quarantine")
def quarantine_case(path: Path, project: str = "local"):
    value = read_json(path)
    emit(
        {
            "quarantine": quarantine(
                Store(),
                project,
                value["input"],
                value["expected"],
                origin=value["origin"],
                actor="local",
            )
        }
    )


@command("approve-case")
def approve_case(
    identity: str,
    reviewed_suite: Path,
    reviewer: str = typer.Option(..., "--reviewer"),
    license: str = typer.Option(..., "--license"),
    project: str = "local",
):
    """Publish an explicitly reviewed quarantine item into a regression revision."""
    store = Store()
    item = store.get(project, "quarantine", identity)
    suite = Suite.model_validate(read_json(reviewed_suite))
    if len(suite.cases) != 1 or suite.cases[0].input != item["input"]:
        raise ValueError("reviewed case must preserve quarantined public input")
    dataset = Dataset(
        suite=suite,
        split="regression",
        origin=item["origin"],
        license=license,
        reviewed_by=reviewer,
        families={suite.cases[0].id: item["family"]},
    )
    dataset_id = register_dataset(store, project, dataset, reviewer)
    store.put(
        project,
        "quarantine-review",
        {"quarantine": identity, "dataset": dataset_id, "reviewer": reviewer},
    )
    emit({"dataset": dataset_id})


@command("grant")
def grant(project: str, subject: str, role: str):
    Store().grant(project, subject, role)
    emit({"granted": True})


@command("revoke")
def revoke(subject: str):
    Store().revoke(subject)
    emit({"revoked": True})


@command("audit")
def audit():
    emit(Store().verify_audit())


@command("backup")
def backup(destination: Path):
    from .lifecycle import backup

    emit(backup(Store(), destination))


@command("restore")
def restore(source: Path, destination: Path):
    from .lifecycle import restore

    emit(restore(source, destination))


@command("retention")
def retention(
    experiment: str,
    reason: str = typer.Option(..., "--reason"),
    project: str = "local",
    execute: bool = False,
):
    """Preview deletion by default. --execute removes the selected idle evidence."""
    from .lifecycle import expire

    emit(
        expire(
            Store(), project, experiment, actor="local", reason=reason, execute=execute
        )
    )


@command("paired-run")
def paired_run(
    baseline: Path,
    candidate: Path,
    key: str = typer.Option(..., "--key"),
    seed: int = 0,
    project: str = "local",
):
    """Run two frozen Launch JSON requests in randomized paired blocks."""
    from .models import Launch

    emit(
        service.paired_run(
            Store(),
            project,
            Launch.model_validate(read_json(baseline)),
            Launch.model_validate(read_json(candidate)),
            seed=seed,
            key=key,
            actor="local",
        )
    )


@command("register-flue")
def register_flue(
    repository: Path,
    project: str = "local",
    pass_env: list[str] = typer.Option([], "--pass-env"),
):
    """Register Flue's raw-diff CLI with its built code and lockfile identity."""
    import shutil
    import subprocess

    root = repository.resolve(strict=True)
    entry = root / "dist" / "cli.js"
    if not entry.is_file() or shutil.which("node") is None:
        raise ValueError("Flue must be built and Node available before registration")
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    files = sorted(str(p) for p in (root / "dist").rglob("*.js"))
    files += [
        str(p)
        for p in (root / "package.json", root / "package-lock.json")
        if p.is_file()
    ]
    profile = TargetProfile(
        name="Flue raw diff",
        command=CommandSpec(
            argv=[shutil.which("node"), str(entry)],
            response_format="json",
            env_names=pass_env,
        ),
        identity_files=files,
        conditions={
            "inner_retries": "target-managed; coverage may be unavailable",
        },
        identity_provenance="observed",
        source_revision=revision,
    )
    emit({"target": Store().put(project, "target", profile.model_dump(mode="json"))})


@command("adopt")
def adopt(experiment: str, project: str = "local"):
    """Add an existing local journal to the workbench without rerunning it."""
    store = Store()
    with Journal.open(experiment) as journal:
        dataset = Dataset(
            suite=journal.plan.suite,
            split="development",
            origin="existing local journal",
            license="operator supplied",
            reviewed_by="local operator",
            families={c.id: c.id for c in journal.plan.suite.cases},
        )
        profile = TargetProfile(
            name=journal.plan.agent,
            command=journal.plan.command,
            identity_files=[f.path for f in journal.plan.files],
            identity_provenance="observed",
        )
    dataset_id = register_dataset(store, project, dataset, "local")
    target_id = store.put(project, "target", profile.model_dump(mode="json"))
    store.put(
        project,
        "experiment",
        {
            "target": target_id,
            "dataset": dataset_id,
            "profile": profile.model_dump(mode="json"),
            "actor": "local",
            "adopted": True,
        },
        object_id=experiment,
    )
    emit({"experiment": experiment})


@command("attach-inspection")
def attach_inspection(experiment: str, report: Path, project: str = "local"):
    """Attach a legacy inspection derivative bound to the exact trial results."""
    from ..blackbox.models import Report

    store = Store()
    store.get(project, "experiment", experiment)
    inspection = Report.model_validate(read_json(report))
    with Journal.open(experiment) as journal:
        results = [journal.result(row) for row in journal.rows()]
        if (
            inspection.parent_run_id != experiment
            or inspection.suite_sha256 != journal.plan.suite_sha256
            or inspection.target_sha256 != journal.plan.target_sha256
            or inspection.results != results
            or inspection.inspection is None
        ):
            raise ValueError(
                "inspection derivative does not match the experiment evidence"
            )
    emit(
        {
            "inspection": store.put(
                project,
                "inspection",
                inspection.model_dump(mode="json"),
                object_id=experiment,
            )
        }
    )


@command("launch")
def launch(
    path: Path,
    project: str = "local",
    start: bool = False,
    key: str = typer.Option(..., "--key"),
):
    """Freeze a Launch request, optionally run it; corrections need an explicit parent."""
    from .models import Launch

    store = Store()
    identity = service.launch_experiment(
        store, project, Launch.model_validate(read_json(path)), actor="local", key=key
    )
    emit(
        service.run(store, project, identity)
        if start
        else service.detail(store, project, identity)
    )


@command("producer-artifact")
def producer_artifact(path: Path, project: str = "local"):
    """Register an approved bounded JSON artifact before producer submission."""
    value = read_json(path)
    emit({"storage_key": Store().put(project, "producer-artifact", value)})


@command("issue-execution")
def issue_execution(path: Path, project: str = "local"):
    """Register harness-selected expected candidate identity before submission."""
    from pydantic import TypeAdapter
    from ..experiments.models import Identifier, Sha256

    value = read_json(path)
    if set(value) != {
        "execution_id",
        "base_revision",
        "candidate_revision",
        "candidate_tree_sha256",
        "recipe_sha256",
    }:
        raise ValueError("invalid execution contract")
    identity = TypeAdapter(Identifier).validate_python(value.pop("execution_id"))
    for key in ("candidate_tree_sha256", "recipe_sha256"):
        TypeAdapter(Sha256).validate_python(value[key])
    import re

    if any(
        not re.fullmatch(r"[0-9a-f]{40,64}", value[k])
        for k in ("base_revision", "candidate_revision")
    ):
        raise ValueError("invalid source revision")
    emit(
        {
            "execution": Store().put(
                project, "execution-contract", value, object_id=identity
            )
        }
    )
