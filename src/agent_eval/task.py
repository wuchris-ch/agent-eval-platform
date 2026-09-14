"""Task definition: a task is a directory containing task.yaml, an environment
image, hidden tests, and an optional oracle solution overlay."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .assurance import ChallengeSpec
from .outcome import AcceptancePolicy
from .paths import BUNDLED_TASKS_DIR, task_search_paths
from .yaml_utils import load_unique_yaml

TASK_SCHEMA_VERSION = "agent-eval.task/v1"
LEGACY_TASK_VERSION = "legacy-unversioned"
DEFAULT_TASKS_ROOT = BUNDLED_TASKS_DIR

DEFAULT_SANDBOX_RESOURCES = {
    "requests": {"cpu": "100m", "memory": "128Mi", "ephemeral-storage": "256Mi"},
    "limits": {"cpu": "2", "memory": "2Gi", "ephemeral-storage": "4Gi"},
}

_QUANTITY_RE = re.compile(
    r"^(?P<number>(?:\d+(?:\.\d*)?|\.\d+))"
    r"(?P<suffix>m|[kMGTPE]|[KMGTPE]i|[eE][+-]?\d+)?$"
)
_TASK_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$")
_DATASET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@~-]{0,255}$")
_GENERATED_TASK_DIRECTORY_NAMES = {
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
_GENERATED_TASK_FILE_NAMES = {".coverage", ".DS_Store"}
_GENERATED_TASK_FILE_SUFFIXES = {".pyc", ".pyo"}
_MAX_TASK_TREE_ENTRIES = 50_000
_MAX_TASK_TREE_DEPTH = 64
_DECIMAL_SUFFIXES = {
    "m": Decimal("0.001"),
    "k": Decimal("1000"),
    "M": Decimal("1000000"),
    "G": Decimal("1000000000"),
    "T": Decimal("1000000000000"),
    "P": Decimal("1000000000000000"),
    "E": Decimal("1000000000000000000"),
}
_BINARY_SUFFIXES = {
    f"{prefix}i": Decimal(1024) ** exponent
    for exponent, prefix in enumerate("KMGTPE", start=1)
}


def _quantity_value(value: str) -> Decimal:
    match = _QUANTITY_RE.fullmatch(value)
    if match is None:
        raise ValueError("must be a positive Kubernetes resource quantity")
    number = Decimal(match.group("number"))
    suffix = match.group("suffix") or ""
    if suffix in _DECIMAL_SUFFIXES:
        number *= _DECIMAL_SUFFIXES[suffix]
    elif suffix in _BINARY_SUFFIXES:
        number *= _BINARY_SUFFIXES[suffix]
    elif suffix:
        number *= Decimal(10) ** int(suffix[1:])
    if number <= 0:
        raise ValueError("must be a positive Kubernetes resource quantity")
    return number


class ResourceQuantities(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    cpu: str
    memory: str
    ephemeral_storage: str = Field(alias="ephemeral-storage")

    @field_validator("cpu", "memory", "ephemeral_storage")
    @classmethod
    def _valid_quantity(cls, value: str) -> str:
        value = value.strip()
        _quantity_value(value)
        return value


class ResourceRequests(ResourceQuantities):
    cpu: str = DEFAULT_SANDBOX_RESOURCES["requests"]["cpu"]
    memory: str = DEFAULT_SANDBOX_RESOURCES["requests"]["memory"]
    ephemeral_storage: str = Field(
        default=DEFAULT_SANDBOX_RESOURCES["requests"]["ephemeral-storage"],
        alias="ephemeral-storage",
    )


class ResourceLimits(ResourceQuantities):
    cpu: str = DEFAULT_SANDBOX_RESOURCES["limits"]["cpu"]
    memory: str = DEFAULT_SANDBOX_RESOURCES["limits"]["memory"]
    ephemeral_storage: str = Field(
        default=DEFAULT_SANDBOX_RESOURCES["limits"]["ephemeral-storage"],
        alias="ephemeral-storage",
    )


class PodResources(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests: ResourceRequests = Field(default_factory=ResourceRequests)
    limits: ResourceLimits = Field(default_factory=ResourceLimits)

    @model_validator(mode="after")
    def _requests_within_limits(self) -> PodResources:
        for field in ("cpu", "memory", "ephemeral_storage"):
            request = _quantity_value(getattr(self.requests, field))
            limit = _quantity_value(getattr(self.limits, field))
            if request > limit:
                name = field.replace("_", "-")
                raise ValueError(f"{name} request must not exceed its limit")
        return self

    def as_kubernetes(self) -> dict[str, dict[str, str]]:
        return self.model_dump(by_alias=True)


class SandboxResources(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: PodResources = Field(default_factory=PodResources)
    eval: PodResources = Field(default_factory=PodResources)


class Timeouts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_seconds: int = 900
    eval_seconds: int = 300

    @field_validator("agent_seconds", "eval_seconds")
    @classmethod
    def _positive_timeout(cls, value: int) -> int:
        if isinstance(value, bool) or value <= 0:
            raise ValueError("timeouts must be positive integers")
        return value


class JudgeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    backend: Literal["claude", "codex"] | None = None
    model: str | None = None
    weights: dict[str, float] = Field(
        default={"spec_adherence": 0.4, "maintainability": 0.4, "test_quality": 0.2}
    )

    @model_validator(mode="after")
    def _valid_weights(self) -> JudgeConfig:
        if not self.weights or len(self.weights) > 32:
            raise ValueError("judge weights must contain between 1 and 32 dimensions")
        for name, weight in self.weights.items():
            if (
                not isinstance(name, str)
                or not 1 <= len(name) <= 64
                or not name.isprintable()
                or not name.strip()
                or isinstance(weight, bool)
                or not math.isfinite(weight)
                or weight <= 0
            ):
                raise ValueError(
                    "judge weight names must be bounded printable text and values "
                    "must be finite positive numbers"
                )
        if (self.backend is None) != (self.model is None):
            raise ValueError("judge backend and model must be configured together")
        if self.model is not None and (
            len(self.model) > 256
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+~-]*", self.model) is None
        ):
            raise ValueError("judge model must be an exact model identifier")
        return self


class SandboxSecurity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_as_non_root: bool = True
    run_as_user: int = Field(default=10001, ge=1)
    run_as_group: int = Field(default=10001, ge=1)
    read_only_root_filesystem: bool = True


class SandboxNetwork(BaseModel):
    """Egress policy for agent and evaluator pods.

    Evaluator egress is always denied.  Agent egress defaults to the bundled
    domain-aware proxy; ``open`` is an explicit compatibility escape hatch.
    """

    model_config = ConfigDict(extra="forbid")

    agent_mode: Literal["proxy", "open"] = "proxy"
    allowed_domains: list[str] = Field(default_factory=list)
    proxy_image: str = (
        "ubuntu/squid@sha256:"
        "6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
    )

    @field_validator("allowed_domains")
    @classmethod
    def _valid_domains(cls, values: list[str]) -> list[str]:
        result = []
        for value in values:
            domain = value.strip().lower()
            bare = domain.removeprefix(".")
            if (
                not bare
                or "://" in domain
                or "/" in domain
                or not re.fullmatch(r"[a-z0-9.-]+", bare)
            ):
                raise ValueError("allowed domains must be DNS suffixes, not URLs")
            normalized = f".{bare}"
            if normalized not in result:
                result.append(normalized)
        return result

    @field_validator("proxy_image")
    @classmethod
    def _digest_pinned_image(cls, value: str) -> str:
        normalized = value.strip()
        if re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", normalized) is None:
            raise ValueError("proxy_image must use an exact sha256 image digest")
        return normalized


class EvaluationReadiness(BaseModel):
    """Bounded HTTP readiness probe used before isolated hidden tests."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(strict=True, min_length=1, max_length=512)
    timeout_seconds: int = Field(default=30, ge=1, le=300, strict=True)

    @field_validator("path")
    @classmethod
    def _safe_absolute_http_path(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or value.startswith("//")
            or "?" in value
            or "#" in value
            or "\\" in value
            or re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", value) is None
            or any(segment in {".", ".."} for segment in value.split("/"))
        ):
            raise ValueError(
                "evaluation readiness path must be a safe absolute HTTP path"
            )
        return value


class EvaluationConfig(BaseModel):
    """How trusted tests communicate with the submitted workspace.

    ``cooperative`` preserves the legacy in-process contract. In
    ``isolated-black-box`` mode the submitted workspace runs in a separate pod
    and trusted tests can reach only its declared TCP port.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Literal["cooperative", "isolated-black-box"] = "cooperative"
    submission_command: str | None = Field(default=None, max_length=4096)
    submission_port: int | None = Field(
        default=None, ge=1024, le=65535, strict=True
    )
    readiness: EvaluationReadiness | None = None

    @model_validator(mode="after")
    def _complete_black_box_contract(self) -> EvaluationConfig:
        command = self.submission_command
        if command is not None and (not command.strip() or "\x00" in command):
            raise ValueError(
                "evaluation submission_command must be nonempty text without NULs"
            )
        if self.mode == "isolated-black-box":
            if (
                command is None
                or self.submission_port is None
                or self.readiness is None
            ):
                raise ValueError(
                    "isolated-black-box evaluation requires submission_command "
                    "submission_port, and readiness"
                )
        elif (
            command is not None
            or self.submission_port is not None
            or self.readiness is not None
        ):
            raise ValueError(
                "cooperative evaluation cannot configure submission or readiness"
            )
        return self


class DatasetMetadata(BaseModel):
    """Optional immutable identity for a task sourced from a dataset."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: str = Field(strict=True, min_length=1, max_length=256)
    revision: str = Field(strict=True, min_length=1, max_length=256)
    item_id: str = Field(strict=True, min_length=1, max_length=256)

    @field_validator("id", "revision", "item_id")
    @classmethod
    def _safe_identity(cls, value: str) -> str:
        if _DATASET_ID_RE.fullmatch(value) is None:
            raise ValueError(
                "dataset id, revision, and item_id must be exact safe identifiers"
            )
        return value


class Task(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-eval.task/v1"]
    version: str = Field(strict=True, min_length=1, max_length=128)
    manifest_binding: Literal["versioned", "legacy-unversioned"] = "versioned"
    dataset: DatasetMetadata | None = None
    id: str
    prompt: str
    language: str = "python"
    tags: list[str] = Field(default_factory=list)
    timeouts: Timeouts = Field(default_factory=Timeouts)
    resources: SandboxResources = Field(default_factory=SandboxResources)
    security: SandboxSecurity = Field(default_factory=SandboxSecurity)
    network: SandboxNetwork = Field(default_factory=SandboxNetwork)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    # In cooperative mode this runs with cwd=/workspace. In isolated black-box
    # mode it runs with cwd=/tests and receives AGENT_EVAL_SUBMISSION_URL.
    # Machine-readable output must be written under /results in either mode.
    test_command: str
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    acceptance: AcceptancePolicy = Field(default_factory=AcceptancePolicy)
    challenges: list[ChallengeSpec] = Field(default_factory=list)
    path: Path

    @field_validator("id")
    @classmethod
    def _safe_task_id(cls, value: str) -> str:
        if not _TASK_ID_RE.fullmatch(value):
            raise ValueError(
                "task id must be a lowercase DNS-style path segment with at "
                "most 63 characters"
            )
        return value

    @field_validator("version")
    @classmethod
    def _safe_version(cls, value: str) -> str:
        if _VERSION_RE.fullmatch(value) is None:
            raise ValueError("task version must be an exact safe version identifier")
        return value

    @field_validator("prompt")
    @classmethod
    def _prompt_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("task prompt must not be empty")
        return v

    @field_validator("challenges")
    @classmethod
    def _bounded_unique_challenges(
        cls, value: list[ChallengeSpec]
    ) -> list[ChallengeSpec]:
        if len(value) > 64:
            raise ValueError("tasks may define at most 64 challenges")
        identifiers = [challenge.id for challenge in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("challenge ids must be unique")
        return value

    @property
    def image_tag(self) -> str:
        return f"agent-eval/{self.id}:{self.environment_sha256[:12]}"

    @property
    def environment_sha256(self) -> str:
        """Hash the complete local Docker build context, including file modes."""

        digest = hashlib.sha256()
        if not self.environment_dir.is_dir():
            return digest.hexdigest()
        for candidate in sorted(self.environment_dir.rglob("*")):
            relative = candidate.relative_to(self.environment_dir)
            name = relative.as_posix()
            metadata = candidate.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                digest.update(
                    f"L\0{name}\0{mode:o}\0{candidate.readlink()}\n".encode()
                )
            elif stat.S_ISDIR(metadata.st_mode):
                digest.update(f"D\0{name}\0{mode:o}\n".encode())
            elif stat.S_ISREG(metadata.st_mode):
                digest.update(f"F\0{name}\0{mode:o}\0{metadata.st_size}\0".encode())
                digest.update(candidate.read_bytes())
                digest.update(b"\n")
            else:
                digest.update(f"S\0{name}\0{mode:o}\0{metadata.st_mode}\n".encode())
        return digest.hexdigest()

    @property
    def environment_dir(self) -> Path:
        return self.path / "environment"

    @property
    def workspace_dir(self) -> Path:
        return self.environment_dir / "workspace"

    @property
    def tests_dir(self) -> Path:
        return self.path / "tests"

    @property
    def solution_dir(self) -> Path:
        return self.path / "solution"

    def validate_layout(self) -> list[str]:
        problems = self.execution_root_errors()
        if not (self.environment_dir / "Dockerfile").is_file():
            problems.append("missing environment/Dockerfile")
        if not self.workspace_dir.is_dir():
            problems.append("missing environment/workspace/ starter directory")
        if not self.tests_dir.is_dir() or not any(self.tests_dir.iterdir()):
            problems.append("missing or empty tests/ directory")
        return problems

    def execution_root_errors(self) -> list[str]:
        """Reject task roots/files that escape through a symlinked boundary."""

        root = self.path.resolve()
        problems: list[str] = []
        if self.path.is_symlink():
            problems.append("task directory must not be a symlink")
        targets = {
            "task manifest": self.path / "task.yaml",
            "environment": self.environment_dir,
            "starter workspace": self.workspace_dir,
            "hidden tests": self.tests_dir,
            "environment Dockerfile": self.environment_dir / "Dockerfile",
        }
        if self.solution_dir.exists() or self.solution_dir.is_symlink():
            targets["oracle solution"] = self.solution_dir
        for label, path in targets.items():
            if path.is_symlink():
                problems.append(f"{label} must not be a symlink")
                continue
            if not path.exists():
                continue
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, ValueError):
                problems.append(f"{label} must stay beneath the task directory")
        hygiene_error = self._task_tree_hygiene_error()
        if hygiene_error is not None:
            problems.append(hygiene_error)
        return problems

    def _task_tree_hygiene_error(self) -> str | None:
        """Reject generated host state before it can enter task identity."""

        if not self.path.is_dir():
            return None
        entries_seen = 0
        pending = [(self.path, 0)]
        while pending:
            directory, depth = pending.pop()
            if depth > _MAX_TASK_TREE_DEPTH:
                return "task tree exceeds the maximum depth"
            try:
                entries = os.scandir(directory)
            except OSError as exc:
                return f"task tree is unreadable: {type(exc).__name__}"
            with entries:
                try:
                    ordered = sorted(entries, key=lambda entry: os.fsencode(entry.name))
                except OSError as exc:
                    return f"task tree is unreadable: {type(exc).__name__}"
            for entry in ordered:
                entries_seen += 1
                if entries_seen > _MAX_TASK_TREE_ENTRIES:
                    return f"task tree exceeds {_MAX_TASK_TREE_ENTRIES} entries"
                relative = Path(entry.path).relative_to(self.path).as_posix()
                if entry.name in _GENERATED_TASK_DIRECTORY_NAMES:
                    return f"generated task directory is not allowed: {relative}"
                if (
                    entry.name in _GENERATED_TASK_FILE_NAMES
                    or Path(entry.name).suffix in _GENERATED_TASK_FILE_SUFFIXES
                ):
                    return f"generated task file is not allowed: {relative}"
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    return (
                        f"task tree path {relative} is unreadable: "
                        f"{type(exc).__name__}"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((Path(entry.path), depth + 1))
        return None


def _task_roots(tasks_root: Path | None) -> tuple[Path, ...]:
    return (Path(tasks_root),) if tasks_root is not None else task_search_paths()


def load_task(task_id: str, tasks_root: Path | None = None) -> Task:
    if not _TASK_ID_RE.fullmatch(task_id):
        raise ValueError(
            "task id must be a lowercase DNS-style path segment with at most "
            "63 characters"
        )
    roots = _task_roots(tasks_root)
    task_dir: Path | None = None
    for tasks_directory in roots:
        candidate = tasks_directory.resolve() / task_id
        if candidate.exists() or candidate.is_symlink():
            task_dir = candidate
            break
    if task_dir is None:
        searched = ", ".join(str(root / task_id) for root in roots)
        raise FileNotFoundError(f"no task directory found; searched: {searched}")
    if task_dir.is_symlink():
        raise ValueError("task directory must not be a symlink")
    yaml_path = task_dir / "task.yaml"
    if yaml_path.is_symlink():
        raise ValueError("task manifest must not be a symlink")
    if not yaml_path.is_file():
        raise FileNotFoundError(f"no task.yaml at {yaml_path}")
    data = load_unique_yaml(yaml_path.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError(f"task manifest must be a YAML mapping: {yaml_path}")
    data = dict(data)
    internal_fields = {"path", "manifest_binding"} & data.keys()
    if internal_fields:
        raise ValueError(
            "task manifest must not define internal fields: "
            + ", ".join(sorted(internal_fields))
        )
    has_schema = "schema_version" in data
    has_version = "version" in data
    if has_schema != has_version:
        raise ValueError(
            "task manifest must define schema_version and version together"
        )
    if not has_schema:
        data["schema_version"] = TASK_SCHEMA_VERSION
        data["version"] = LEGACY_TASK_VERSION
        data["manifest_binding"] = "legacy-unversioned"
    else:
        data["manifest_binding"] = "versioned"
    data["path"] = task_dir
    task = Task.model_validate(data)
    if task.id != task_id:
        raise ValueError(
            f"task.yaml id {task.id!r} does not match directory {task_id!r}"
        )
    root_errors = task.execution_root_errors()
    if root_errors:
        raise ValueError(f"task execution roots are unsafe: {', '.join(root_errors)}")
    return task


def list_tasks(tasks_root: Path | None = None) -> list[Task]:
    tasks: list[Task] = []
    discovered: set[str] = set()
    for root in _task_roots(tasks_root):
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if entry.name in discovered:
                continue
            if (entry / "task.yaml").is_file():
                tasks.append(load_task(entry.name, root))
                discovered.add(entry.name)
    return tasks
