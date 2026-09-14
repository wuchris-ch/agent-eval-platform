"""Opt-in local command experiments. No model judging or remote execution."""

from __future__ import annotations

import shlex
from pathlib import Path

import typer

from ..blackbox.models import load_suite
from .executor import execute
from .journal import ExperimentBusy, Journal, JournalError
from .models import CommandSpec
from .service import create_experiment
from .service import status as read_status

app = typer.Typer(
    help="Durable local black-box experiments with deterministic graders.",
    no_args_is_help=True,
)


def _failure(exc: Exception):
    # Exceptions from paths, validation or SQLite can contain private inputs.
    message = str(exc) if isinstance(exc, JournalError) else type(exc).__name__
    typer.echo(f"Experiment failed: {message}", err=True)
    raise typer.Exit(3 if isinstance(exc, ExperimentBusy) else 1) from None


def _finish(snapshot):
    typer.echo(snapshot.model_dump_json(indent=2))
    if snapshot.state == "reconciliation_required":
        typer.echo(
            "An invocation has no durable receipt. It will not be retried. Reconcile possible side effects before starting a new experiment.",
            err=True,
        )
        raise typer.Exit(3)
    if snapshot.passed is False:
        raise typer.Exit(2)


@app.command("run")
def run(
    suite_path: Path = typer.Option(..., "--suite", exists=True, dir_okay=False),
    agent: str = typer.Option(..., "--agent"),
    command: str = typer.Option(
        ..., "--command", help="Argv command, no shell. Use absolute script paths."
    ),
    trials: int = typer.Option(1, "--trials", min=1),
    timeout: float = typer.Option(120, "--timeout", min=0.01, max=86400),
    response_format: str = typer.Option("text", "--response-format"),
    response_pointer: str | None = typer.Option(None, "--response-pointer"),
    pass_env: list[str] = typer.Option([], "--pass-env"),
    identity_files: list[Path] = typer.Option(
        [],
        "--identity-file",
        exists=True,
        dir_okay=False,
        help="Additional code/config files to bind. Repeatable.",
    ),
    prepare_only: bool = typer.Option(
        False, "--prepare-only", help="Freeze the plan without invoking the target."
    ),
    max_new_trials: int | None = typer.Option(
        None, "--max-new-trials", min=1, help="Pause after this many new invocations."
    ),
):
    """Freeze a suite and command, persist its trial matrix, then execute."""
    try:
        experiment_id = create_experiment(
            load_suite(suite_path),
            agent=agent,
            trials=trials,
            command=CommandSpec(
                argv=shlex.split(command),
                timeout=timeout,
                response_format=response_format,
                response_pointer=response_pointer,
                env_names=pass_env,
            ),
            identity_files=identity_files,
        )
        # Print identity before execution so it survives interruption.
        typer.echo(f"Experiment: {experiment_id}", err=True)
        snapshot = (
            read_status(experiment_id)
            if prepare_only
            else execute(experiment_id, max_new_trials=max_new_trials)
        )
    except KeyboardInterrupt:
        typer.echo(
            "Interrupted. Use experiment resume to inspect recovery state; no invocation is automatically retried.",
            err=True,
        )
        raise typer.Exit(130) from None
    except Exception as exc:
        _failure(exc)
    _finish(snapshot)


@app.command("status")
def status(experiment_id: str):
    """Read a consistent snapshot and verify referenced artifacts without invoking."""
    try:
        snapshot = read_status(experiment_id)
    except Exception as exc:
        _failure(exc)
    typer.echo(snapshot.model_dump_json(indent=2))


@app.command("resume")
def resume(
    experiment_id: str,
    max_new_trials: int | None = typer.Option(None, "--max-new-trials", min=1),
):
    """Continue unstarted trials or grade saved observations under the frozen plan."""
    try:
        snapshot = execute(experiment_id, max_new_trials=max_new_trials)
    except KeyboardInterrupt:
        typer.echo("Interrupted. The journal retains recovery state.", err=True)
        raise typer.Exit(130) from None
    except Exception as exc:
        _failure(exc)
    _finish(snapshot)


@app.command("export")
def export(experiment_id: str):
    """Rebuild report.json from completed canonical records without invoking."""
    try:
        with Journal.open(experiment_id, write=True) as journal:
            journal.export_report()
    except Exception as exc:
        _failure(exc)
    typer.echo("Rebuilt report.json in the private experiment directory.")


@app.command("cancel")
def cancel(experiment_id: str):
    """Persist cancellation; running calls may require side-effect reconciliation."""
    from .journal import request_cancel

    try:
        request_cancel(experiment_id)
        try:
            snapshot = execute(experiment_id)
        except ExperimentBusy:
            snapshot = read_status(experiment_id)
        typer.echo(snapshot.model_dump_json(indent=2))
    except Exception as exc:
        _failure(exc)
