"""Explicit opt-in distributed execution administration."""

import os
from pathlib import Path

import typer

from ..experiments.journal import read_json
from ..workbench.cli import emit
from .postgres import Queue

app = typer.Typer(
    help="Fenced PostgreSQL workers and experimental k3s Job profiles.",
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


def queue():
    return Queue(os.environ["AGENT_EVAL_DATABASE_URL"])


@command("migrate")
def migrate():
    queue().migrate()
    emit({"schema": 1})


@command("account")
def account(tenant: str, limit_micros: int):
    queue().account(tenant, limit_micros)
    emit({"configured": True})


@command("enqueue")
def enqueue(tenant: str, execution: str, payload: Path, reservation_micros: int):
    queue().enqueue(tenant, execution, read_json(payload), reservation_micros)
    emit({"queued": True})


@command("worker")
def worker(tenant: str, worker_id: str, kube_context: str | None = None):
    """Execute at most one claim. A supervisor can schedule further invocations."""
    from .worker import work_once

    emit(
        {"completed": work_once(queue(), tenant, worker_id, kube_context=kube_context)}
    )


@command("reconcile")
def reconcile(tenant: str):
    emit({"reconciled": queue().reconcile(tenant)})


@command("cancel")
def cancel(tenant: str, execution: str):
    emit({"state": queue().cancel(tenant, execution)})


@command("job")
def job(
    execution: str, image: str, command: list[str], seconds: int = 300, epoch: int = 1
):
    """Emit a restricted Job manifest. Applying it is a separate operator action."""
    from .kubernetes import job

    emit(
        job(
            execution_id=execution,
            image=image,
            command=command,
            seconds=seconds,
            epoch=epoch,
        )
    )


@command("job-run")
def job_run(manifest: Path, context: str):
    """Execute one validated experimental Job against an explicitly named context."""
    from .kubernetes import execute_job

    emit(execute_job(read_json(manifest), context=context))


@command("submit-experiment")
def submit_experiment(experiment: str, reservation_micros: int, project: str = "local"):
    from ..workbench.store import Store
    from .bridge import enqueue_experiment

    emit(
        enqueue_experiment(
            Store(), project, experiment, queue(), reservation_micros=reservation_micros
        )
    )


@command("collect-experiment")
def collect_experiment(experiment: str, project: str = "local"):
    from ..workbench.store import Store
    from .bridge import collect_experiment

    emit(collect_experiment(Store(), project, experiment, queue()))


@command("cancel-experiment")
def cancel_experiment(experiment: str, project: str = "local"):
    from ..workbench.store import Store
    from .bridge import cancel_experiment

    emit(cancel_experiment(Store(), project, experiment, queue()))
