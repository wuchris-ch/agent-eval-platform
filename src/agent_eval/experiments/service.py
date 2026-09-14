"""Freeze command identity and provide the local experiment service boundary."""

from __future__ import annotations

import hashlib
import hmac
import os
import platform
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pydantic

from ..blackbox import models as blackbox_models
from ..blackbox import runner, scoring, targets
from ..blackbox.models import Suite, digest, json_bytes
from ..blackbox.targets import CommandTarget, ResponseDecoder
from ..limits import MAX_RESULTS_JSON_BYTES, read_stable_bounded_file
from .journal import Journal, JournalError
from .models import CommandSpec, FileIdentity, Plan


def evaluator_identity() -> str:
    # Bind the actual deterministic grading implementation, including the caller.
    from ..environments import world
    from ..workbench import (
        analysis,
    )
    from ..workbench import (
        models as workbench_models,
    )
    from ..workbench import (
        service as workbench_service,
    )
    from . import executor, models

    return digest(
        {
            "python": platform.python_version(),
            "pydantic": pydantic.__version__,
            "files": {
                module.__name__: hashlib.sha256(
                    Path(module.__file__).read_bytes()
                ).hexdigest()
                for module in (
                    blackbox_models,
                    runner,
                    scoring,
                    targets,
                    executor,
                    models,
                    world,
                    workbench_service,
                    analysis,
                    workbench_models,
                )
            },
        }
    )


def file_identity(path: Path) -> FileIdentity:
    resolved = path.expanduser().resolve(strict=True)
    data = read_stable_bounded_file(resolved, maximum_bytes=256 * 1024 * 1024)
    return FileIdentity(
        path=os.path.abspath(path.expanduser()),
        resolved_path=str(resolved),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def make_target(spec: CommandSpec) -> CommandTarget:
    return CommandTarget(
        spec.argv,
        timeout=spec.timeout,
        decoder=ResponseDecoder(spec.response_format, spec.response_pointer),
        env_names=spec.env_names,
    )


def environment_identity(target: CommandTarget, key: bytes) -> str:
    # No environment values are persisted. A private key prevents public hashes
    # of low-entropy configuration values from becoming a guessing oracle.
    return hmac.new(key, json_bytes(target.environment), hashlib.sha256).hexdigest()


def create_experiment(
    suite: Suite,
    *,
    agent: str,
    command: CommandSpec,
    trials: int = 1,
    identity_files: list[Path] | None = None,
) -> str:
    spec = command.model_copy(deep=True)
    executable = shutil.which(spec.argv[0])
    if executable is None:
        raise ValueError("command executable was not found")
    # Freeze the selected path while retaining virtual-environment entry points.
    # FileIdentity separately binds the resolved inode content and symlink target.
    spec.argv[0] = os.path.abspath(executable)
    paths = {Path(spec.argv[0]), *(identity_files or [])}
    # Positional absolute script/config paths are common with a clean target cwd.
    paths.update(
        Path(arg)
        for arg in spec.argv[1:]
        if Path(arg).is_absolute() and Path(arg).is_file()
    )
    files = {item.path: item for item in (file_identity(path) for path in paths)}
    target = make_target(spec)
    key = os.urandom(32)
    plan = Plan(
        experiment_id=str(uuid.uuid4()),
        created_at=datetime.now(UTC).isoformat(),
        agent=agent,
        suite=suite.model_copy(deep=True),
        suite_sha256=digest(suite.model_dump(mode="json")),
        trials=trials,
        command=spec,
        target_sha256=target.identity,
        files=[files[path] for path in sorted(files)],
        environment_hmac=environment_identity(target, key),
        evaluator_sha256=evaluator_identity(),
    )
    if len(json_bytes(plan.model_dump(mode="json"))) >= MAX_RESULTS_JSON_BYTES:
        raise ValueError("plan exceeds the size limit")
    return Journal.create(plan, key)


def verify_target(journal: Journal) -> CommandTarget:
    plan = journal.plan
    target = make_target(plan.command)
    if target.identity != plan.target_sha256:
        raise JournalError("command identity changed")
    for item in plan.files:
        if file_identity(Path(item.path)) != item:
            raise JournalError("selected target file identity changed")
    key = read_stable_bounded_file(journal.root / "environment.key", maximum_bytes=32)
    if len(key) != 32 or not hmac.compare_digest(
        environment_identity(target, key), plan.environment_hmac
    ):
        raise JournalError("target environment changed; start a new experiment")
    return target


def status(experiment_id: str):
    with Journal.open(experiment_id) as journal:
        return journal.status()
