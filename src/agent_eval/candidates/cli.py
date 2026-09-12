"""Operator controls for independent candidate evaluation."""

from pathlib import Path

import typer

from ..blackbox.models import parse_json
from ..workbench.cli import emit
from ..workbench.store import Store
from . import authority
from .contracts import (
    AcceptancePolicy,
    ArtifactEnvelope,
    ExecutionContract,
    Recipe,
    Submission,
    TrialTicket,
)
from .execution import evaluate as run_evaluation
from .oracles import BehaviorSuite

app = typer.Typer(
    help="Issue candidate contracts, collect independent evidence and replay decisions.",
    no_args_is_help=True,
)


def command(name):
    import functools

    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except typer.Exit:
                raise
            except Exception as exc:
                typer.echo(
                    "Candidate operation failed: " + type(exc).__name__, err=True
                )
                raise typer.Exit(1) from None

        return app.command(name)(wrapped)

    return decorate


@command("identity")
def identity():
    emit({"evaluator_sha256": authority.identity(), "contract_version": 2})


@command("register-base")
def register_base(repository: Path, revision: str, project: str = "local"):
    emit(
        {
            "revision": authority.register_revision(
                Store(), project, repository, revision
            )
        }
    )


@command("register")
def register(kind: str, path: Path, project: str = "local"):
    models = {"suite": BehaviorSuite, "recipe": Recipe, "policy": AcceptancePolicy}
    value = (
        models[kind]
        .model_validate(parse_json(path.read_bytes()))
        .model_dump(mode="json")
    )
    emit({"sha256": Store().put(project, "candidate-" + kind, value)})


@command("artifact")
def artifact(path: Path, project: str = "local"):
    emit(
        authority.upload(
            Store(), project, ArtifactEnvelope.wrap(path.read_bytes()), "local"
        )
    )


@command("issue")
def issue(path: Path, project: str = "local"):
    emit(
        authority.issue(
            Store(),
            project,
            ExecutionContract.model_validate(parse_json(path.read_bytes())),
            "local",
        )
    )


@command("submit")
def submit(path: Path, project: str = "local"):
    emit(
        authority.ingest(
            Store(),
            project,
            Submission.model_validate(parse_json(path.read_bytes())),
            "local",
        )
    )


@command("evaluate")
def evaluate(execution_id: str, project: str = "local"):
    result = run_evaluation(Store(), project, execution_id)
    emit(result)
    if result.get("outcome") != "pass":
        raise typer.Exit(2 if result.get("outcome") == "fail" else 3)


@command("reserve")
def reserve(path: Path, project: str = "local"):
    emit(
        authority.reserve(
            Store(),
            project,
            TrialTicket.model_validate(parse_json(path.read_bytes())),
            "local",
        )
    )
