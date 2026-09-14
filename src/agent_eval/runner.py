"""Run pipeline: (agent phase) -> snapshot/diff -> eval phase -> scans -> judge.

Cooperative evaluation preserves the legacy in-process contract. Isolated
black-box evaluation runs submitted code in a separate, network-confined pod;
only the trusted evaluator pod receives hidden tests and result storage."""

from __future__ import annotations

import json
import os
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path

from pydantic import BaseModel
from rich.console import Console

from . import cluster as cluster_mod
from .assessments import Assessment, derive_assessments, expected_assessment_id
from .attestation import (
    capture_git_state,
    create_attestation,
    hash_tree,
    sha256_file,
)
from .audit import AuditChain
from .cluster import build_and_import_image, build_image_with_metadata
from .credentials import (
    CredentialRedactionError,
    CredentialRedactor,
    load_trial_credentials,
)
from .evaluators.tests import TestResults, parse_coverage_artifact, parse_junit
from .governance import (
    EvaluationRequest,
    GovernanceBundle,
    GovernanceEvidence,
    PolicyDecision,
    evaluate_admission,
    sha256_json,
    validate_execution_continuity,
    write_canonical_json,
)
from .kube import (
    MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_MEMBERS,
    CommandOutputLimitError,
    KubeError,
    Pod,
    UnsafeArchiveError,
    containerd_image_manifest_identity,
    create_black_box_link,
    create_egress_proxy,
    create_sandbox_pod,
    create_trial_secret,
    ensure_namespace,
    runtime_class_name,
)
from .metrics import DiffStats, RunRecord, now_iso, prepare_run_dir, save_run
from .observability import export_run_assessments
from .outcome import evaluate_outcome
from .paths import atomic_write_private, secure_run_tree
from .scanner_runtime import scanner_runtime_digest
from .task import Task

console = Console()
REPO_ROOT = Path(__file__).resolve().parents[2]
_PROVIDER_DOMAINS = {
    "claude-code": [".anthropic.com", ".claude.ai"],
    "codex": [".openai.com", ".chatgpt.com", ".oaiusercontent.com"],
}
_TRUSTED_PYTEST_RUNNER = Path(__file__).parent / "evaluators" / "trusted_pytest.py"
_EVALUATOR_CONTROL_FILES = {
    "conftest.py",
    "pytest.py",
    "sitecustomize.py",
    "usercustomize.py",
}
_EVALUATOR_CONTROL_PACKAGES = {"_pytest", "coverage", "pluggy", "pytest_cov"}
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_AGENT_QUIESCE_TIMEOUT_SECONDS = 5
DIFF_MAX_BYTES = 8 * 1024 * 1024
DIFF_NUMSTAT_MAX_BYTES = 4 * 1024 * 1024
DIFF_STDERR_MAX_BYTES = 64 * 1024
DIFF_TIMEOUT_SECONDS = 120
_DURABLE_AGENT_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
_DURABLE_AGENT_ARTIFACT_MAX_ENTRIES = 10_000
_AGENT_QUIESCE_COMMAND = r"""
set -eu
self=$$
[ "$self" -ne 1 ]
[ -r /proc/1/stat ]

signal_remaining() {
    signal=$1
    found=0
    for process in /proc/[0-9]*; do
        if [ ! -r "$process/stat" ]; then
            [ -e "$process" ] && exit 69
            continue
        fi
        pid=${process#/proc/}
        case "$pid" in
            1|"$self") continue ;;
        esac
        if ! IFS= read -r stat_line < "$process/stat"; then
            [ -e "$process" ] && exit 70
            continue
        fi
        stat_tail=${stat_line##*) }
        state=${stat_tail%% *}
        [ "$state" = "Z" ] && continue
        found=1
        if ! kill -s "$signal" "$pid" 2>/dev/null; then
            [ -e "$process" ] && exit 71
        fi
    done
    return "$found"
}

round=0
empty_scans=0
while [ "$round" -lt 20 ]; do
    signal=TERM
    [ "$round" -ge 5 ] && signal=KILL
    if signal_remaining "$signal"; then
        empty_scans=$((empty_scans + 1))
        [ "$empty_scans" -ge 3 ] && exit 0
    else
        empty_scans=0
    fi
    round=$((round + 1))
    sleep 0.1 || exit 72
done
exit 73
""".strip()


@dataclass(frozen=True)
class _BuiltImage:
    reference: str
    manifest_digest: str
    platform: str


def _governance_network_evidence(
    task: Task, agent: str
) -> tuple[list[str], str | None]:
    """Return the exact proxy domains and image that governed execution uses."""

    if task.network.agent_mode != "proxy":
        return [], None
    domains = sorted(
        set(_PROVIDER_DOMAINS.get(agent, [])) | set(task.network.allowed_domains)
    )
    return domains, task.network.proxy_image


def _governance_judge_evidence(
    task: Task, *, run_judge: bool
) -> tuple[str | None, str | None]:
    """Return the exact task-pinned judge identity sent governed diff data."""

    if not run_judge or not task.judge.enabled:
        return None, None
    return task.judge.backend, task.judge.model


def _governance_scanner_evidence(
    *, run_scans: bool
) -> tuple[str | None, bool]:
    """Inspect the exact local scanner stack admitted to a governed run."""

    if not isinstance(run_scans, bool):
        raise ValueError("governed scanner switch must be boolean")
    if not run_scans:
        return None, False
    from .evaluators.scanners import scanner_preflight_assurance_identity

    identity = scanner_preflight_assurance_identity()
    return identity.identity_sha256, identity.promotion_ready


def _governance_task_evidence(
    task: Task, *, run_scans: bool, run_judge: bool
) -> tuple[str, str]:
    """Hash task content and the normalized execution policy admitted by the CLI."""

    if not isinstance(run_scans, bool) or not isinstance(run_judge, bool):
        raise ValueError("governed grader switches must be booleans")
    tree_digest = hash_tree(task.path)
    execution_digest = sha256_json(
        {
            "task": task.model_dump(mode="json", exclude={"path"}),
            "task_tree_sha256": tree_digest,
            "image_tag": task.image_tag,
            "runtime": {
                "run_scans": run_scans,
                "run_judge": run_judge,
                "scanner_runtime_sha256": (
                    scanner_runtime_digest() if run_scans else None
                ),
                "runtime_class": runtime_class_name() or "runc",
                "k3s_image_digest": cluster_mod.K3S_IMAGE_DIGEST,
            },
        }
    )
    return tree_digest, execution_digest


def _snapshot_governed_task(
    task: Task,
    destination: Path,
    *,
    expected_tree_digest: str,
    expected_execution_digest: str,
    run_scans: bool,
    run_judge: bool,
) -> Task:
    """Copy and verify the exact admitted task used by every runtime phase."""

    snapshot_root = destination / task.id
    shutil.copytree(task.path, snapshot_root, symlinks=True)
    snapshot = task.model_copy(deep=True, update={"path": snapshot_root})
    root_errors = snapshot.execution_root_errors()
    if root_errors:
        raise ValueError("governed task snapshot is unsafe: " + ", ".join(root_errors))
    tree_digest, execution_digest = _governance_task_evidence(
        snapshot, run_scans=run_scans, run_judge=run_judge
    )
    if (
        tree_digest != expected_tree_digest
        or execution_digest != expected_execution_digest
    ):
        raise ValueError("governed task changed while its snapshot was created")
    return snapshot


def _sandbox_infra_error(phase: str, pod: Pod,
                         command_exit_code: int | None = None) -> str | None:
    evidence = pod.infrastructure_failure(command_exit_code)
    if evidence is None:
        return None
    return f"{phase} sandbox infrastructure failure: {evidence}"


def _quiesce_agent_processes(pod: Pod) -> str | None:
    """Stop all live non-control processes before snapshotting the workspace."""

    try:
        result = pod.exec(
            _AGENT_QUIESCE_COMMAND,
            timeout=_AGENT_QUIESCE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return (
            "agent process quiescence timed out after "
            f"{_AGENT_QUIESCE_TIMEOUT_SECONDS}s"
        )
    except (KubeError, OSError) as exc:
        return f"agent process quiescence failed: {type(exc).__name__}"
    if result.returncode != 0:
        return f"agent process quiescence failed with exit {result.returncode}"
    return None


def _output_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="surrogateescape")
    raise TypeError("agent output must be bytes, text, or None")


def _write_redacted_private(
    path: Path,
    value: bytes | str | None,
    redactor: CredentialRedactor | None,
    *,
    suffix: bytes = b"",
) -> None:
    """Redact exact projected credentials before one owner-private write."""

    output = _output_bytes(value) + suffix
    if redactor is not None:
        output = redactor.redact_bytes(output)
    atomic_write_private(path, output)


def _credential_hits_in_tree(
    root: Path,
    redactor: CredentialRedactor,
    *,
    maximum_bytes: int,
    maximum_entries: int,
    stop_after_first: bool = False,
    excluded_top_level: frozenset[str] = frozenset(),
) -> list[Path]:
    """Inspect a bounded regular-file tree without following links."""

    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise UnsafeArchiveError("credential inspection root is not a real directory")
    hits: list[Path] = []
    entries_seen = 0
    bytes_seen = 0
    pending = [(root, Path())]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            raise UnsafeArchiveError(
                "credential inspection found an unreadable directory"
            ) from exc
        for entry in entries:
            relative = relative_directory / entry.name
            if not relative_directory.parts and entry.name in excluded_top_level:
                continue
            entries_seen += 1
            if entries_seen > maximum_entries:
                raise UnsafeArchiveError(
                    "credential inspection exceeded its entry limit"
                )
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise UnsafeArchiveError(
                    "credential inspection found an unreadable entry"
                ) from exc
            path_hit = redactor.contains_bytes(os.fsencode(relative.as_posix()))
            if stat.S_ISDIR(metadata.st_mode):
                if path_hit:
                    hits.append(Path(entry.path))
                    if stop_after_first:
                        return hits
                else:
                    pending.append((Path(entry.path), relative))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise UnsafeArchiveError(
                    "credential inspection found a link or special file"
                )
            bytes_seen += metadata.st_size
            if bytes_seen > maximum_bytes:
                raise UnsafeArchiveError(
                    "credential inspection exceeded its byte limit"
                )
            if path_hit:
                hits.append(Path(entry.path))
                if stop_after_first:
                    return hits
                continue
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
                os, "O_NOFOLLOW", 0
            )
            try:
                descriptor = os.open(entry.path, flags)
            except OSError as exc:
                raise UnsafeArchiveError(
                    "credential inspection could not safely open a file"
                ) from exc
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or opened.st_size != metadata.st_size
                ):
                    raise UnsafeArchiveError(
                        "credential inspection observed a changing file"
                    )
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = -1
                    content_hit = redactor.contains_stream(
                        stream,
                        maximum_bytes=opened.st_size,
                    )
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            if content_hit:
                hits.append(Path(entry.path))
                if stop_after_first:
                    return hits
    return hits


def _promote_credential_clean_workspace(staged: Path, destination: Path) -> None:
    """Promote only a previously inspected private workspace snapshot."""

    if destination.exists() or destination.is_symlink():
        raise UnsafeArchiveError("durable workspace destination already exists")
    try:
        shutil.copytree(staged, destination, symlinks=False)
        secure_run_tree(destination.parent)
    except (OSError, ValueError) as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise UnsafeArchiveError(
            "credential-clean workspace could not be promoted"
        ) from exc


def _redact_run_record(
    record: RunRecord,
    redactor: CredentialRedactor | None,
) -> RunRecord:
    if redactor is None:
        return record

    def redact_persistence_value(value: object) -> object:
        if isinstance(value, BaseModel):
            # Pydantic field names are trusted schema literals, not agent data.
            # Dynamic mapping keys remain subject to the credential boundary.
            return {
                name: redact_persistence_value(getattr(value, name))
                for name in type(value).model_fields
            }
        if isinstance(value, dict):
            redacted_mapping: dict[object, object] = {}
            for key, item in value.items():
                safe_key = (
                    redactor.redact_text(key) if isinstance(key, str) else key
                )
                if safe_key in redacted_mapping:
                    raise CredentialRedactionError(
                        "credential redaction produced duplicate record fields"
                    )
                redacted_mapping[safe_key] = redact_persistence_value(item)
            return redacted_mapping
        if isinstance(value, list):
            return [redact_persistence_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(redact_persistence_value(item) for item in value)
        return redactor.redact_value(value)

    redacted = redact_persistence_value(record)
    if not isinstance(redacted, dict):
        raise CredentialRedactionError("run evidence could not be safely redacted")
    assessments = redacted.get("assessments")
    if isinstance(assessments, list):
        for payload in assessments:
            if not isinstance(payload, dict):
                raise CredentialRedactionError(
                    "run evidence could not be safely redacted"
                )
            payload["assessment_id"] = "0" * 64
            try:
                assessment = Assessment.model_validate(payload)
            except ValueError as exc:
                raise CredentialRedactionError(
                    "run evidence could not be safely redacted"
                ) from exc
            payload["assessment_id"] = expected_assessment_id(assessment)
    try:
        return RunRecord.model_validate(redacted)
    except ValueError as exc:
        raise CredentialRedactionError(
            "run evidence could not be safely redacted"
        ) from exc


def new_run_id(task: Task, agent: str) -> str:
    return (
        f"{task.id}--{agent}--{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:12]}"
    )


def _cluster_has_image(tag: str, expected_digest: str) -> bool:
    """Return whether every node resolves a tag to the host platform manifest."""

    try:
        listed = subprocess.run(
            ["k3d", "cluster", "list", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if listed.returncode != 0:
        return False
    try:
        clusters = json.loads(listed.stdout)
        cluster = next(
            item
            for item in clusters
            if isinstance(item, dict) and item.get("name") == "agent-eval"
        )
        nodes = [
            node["name"]
            for node in cluster.get("nodes", [])
            if node.get("role") in {"server", "agent"}
            and node.get("State", {}).get("Running") is True
        ]
    except (json.JSONDecodeError, KeyError, StopIteration, TypeError):
        return False
    if not nodes:
        return False
    for node in nodes:
        identity = containerd_image_manifest_identity(
            node,
            tag,
            expected_manifest_digest=expected_digest,
        )
        if identity is None or identity[0] != expected_digest:
            return False
    return True


def _cluster_has_manifest(
    image_ref: str,
    expected_manifest_digest: str,
) -> bool:
    """Return whether every node has the exact platform manifest under the ref."""

    try:
        listed = subprocess.run(
            ["k3d", "cluster", "list", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if listed.returncode != 0:
        return False
    try:
        clusters = json.loads(listed.stdout)
        cluster = next(
            item
            for item in clusters
            if isinstance(item, dict) and item.get("name") == "agent-eval"
        )
        nodes = [
            node["name"]
            for node in cluster.get("nodes", [])
            if node.get("role") in {"server", "agent"}
            and node.get("State", {}).get("Running") is True
        ]
    except (json.JSONDecodeError, KeyError, StopIteration, TypeError):
        return False
    if not nodes:
        return False
    for node in nodes:
        identity = containerd_image_manifest_identity(
            node,
            image_ref,
            expected_manifest_digest=expected_manifest_digest,
        )
        if identity is None or identity[0] != expected_manifest_digest:
            return False
    return True


def _local_manifest_digest(image_ref: str) -> str | None:
    """Return a local single-platform manifest digest, never an index/config ID."""

    try:
        proc = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                "--format={{json .Descriptor}}",
                image_ref,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        descriptor = json.loads(proc.stdout)
        media_type = descriptor["mediaType"]
        digest = descriptor["digest"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    if (
        media_type not in _MANIFEST_MEDIA_TYPES
        or not isinstance(digest, str)
        or _IMAGE_DIGEST_RE.fullmatch(digest) is None
    ):
        return None
    return digest


def ensure_image(
    task: Task,
    rebuild: bool = False,
    *,
    expected_digest: str | None = None,
    image_ref: str | None = None,
) -> str:
    """Make the task image available and return its exact image identity.

    Governed execution binds a single-platform manifest digest plus a
    content-derived reference. Both the host and every running k3d node must
    expose that manifest before a pod can use the reference with pull policy
    ``Never``. This path never rebuilds admitted content.
    """

    root_errors = task.execution_root_errors()
    if root_errors:
        raise ValueError(f"task execution roots are unsafe: {', '.join(root_errors)}")
    if expected_digest is not None:
        if rebuild:
            raise ValueError("a governed image cannot be rebuilt after admission")
        if not isinstance(image_ref, str) or not image_ref:
            raise ValueError("a governed image requires its admitted runtime reference")
        local_manifest = _local_manifest_digest(image_ref)
        if local_manifest != expected_digest:
            raise KubeError(
                "local task image manifest does not match the governed "
                f"digest {expected_digest}"
            )
        if _cluster_has_manifest(image_ref, expected_digest):
            return expected_digest
        imported = subprocess.run(
            ["k3d", "image", "import", image_ref, "-c", "agent-eval"],
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            raise KubeError(
                "could not import the governed task image into k3d: "
                f"{imported.stderr[-1000:]}"
            )
        if not _cluster_has_manifest(image_ref, expected_digest):
            raise KubeError(
                "imported task image manifest does not match the governed "
                "digest on every running k3d node"
            )
        return expected_digest
    if image_ref is not None:
        raise ValueError("image_ref is only valid with an expected digest")
    if not rebuild:
        local_digest = _image_digest(task.image_tag)
        if local_digest is not None:
            if _cluster_has_image(task.image_tag, local_digest):
                return local_digest
            # The image exists only in the host daemon after a cluster recreate.
            imported = subprocess.run(
                ["k3d", "image", "import", task.image_tag, "-c", "agent-eval"],
                capture_output=True,
                text=True,
            )
            if imported.returncode != 0:
                raise KubeError(
                    "could not import the task image into k3d: "
                    f"{imported.stderr[-1000:]}"
                )
            if not _cluster_has_image(task.image_tag, local_digest):
                raise KubeError(
                    "imported task image digest does not match the host image "
                    "on every running k3d node"
                )
            return local_digest
    build_and_import_image(str(task.environment_dir), task.image_tag)
    local_digest = _image_digest(task.image_tag)
    if local_digest is None:
        raise KubeError("built task image digest is unavailable")
    if not _cluster_has_image(task.image_tag, local_digest):
        raise KubeError(
            "built task image digest does not match on every running k3d node"
        )
    return local_digest


def _docker_platform() -> str:
    try:
        proc = subprocess.run(
            ["docker", "version", "--format={{.Server.Os}}/{{.Server.Arch}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KubeError("could not determine the Docker server platform") from exc
    value = proc.stdout.strip().lower()
    if proc.returncode != 0 or re.fullmatch(r"linux/[a-z0-9_]+", value) is None:
        raise KubeError("could not determine the Docker server platform")
    return value


def _build_task_image_candidate(task: Task) -> _BuiltImage:
    """Build an unapproved candidate and capture its platform manifest.

    This helper never grants governance approval.  A separate trusted
    promotion workflow must review the build evidence and add the exact result
    to a task registry before any governed run can consume it.
    """

    root_errors = task.execution_root_errors()
    if root_errors:
        raise ValueError(f"task execution roots are unsafe: {', '.join(root_errors)}")
    platform = _docker_platform()
    temporary_ref = f"agent-eval/{task.id}:governed-{uuid.uuid4().hex}"
    result: _BuiltImage | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="agent-eval-build-metadata-") as tmp:
            metadata_path = Path(tmp) / "metadata.json"
            build_image_with_metadata(
                str(task.environment_dir),
                temporary_ref,
                platform=platform,
                metadata_file=metadata_path,
            )
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                descriptor = metadata["containerimage.descriptor"]
                media_type = descriptor["mediaType"]
                manifest_digest = descriptor["digest"]
            except (
                OSError,
                UnicodeError,
                json.JSONDecodeError,
                KeyError,
                TypeError,
            ) as exc:
                raise KubeError("candidate build metadata is incomplete") from exc
        if (
            media_type not in _MANIFEST_MEDIA_TYPES
            or not isinstance(manifest_digest, str)
            or _IMAGE_DIGEST_RE.fullmatch(manifest_digest) is None
            or metadata.get("containerimage.digest") != manifest_digest
        ):
            raise KubeError("candidate build did not produce one platform manifest")
        if _local_manifest_digest(temporary_ref) != manifest_digest:
            raise KubeError(
                "loaded image manifest does not match candidate build metadata"
            )
        image_ref = (
            f"agent-eval/{task.id}:governed-{manifest_digest.removeprefix('sha256:')}"
        )
        existing_digest = _local_manifest_digest(image_ref)
        if existing_digest not in {None, manifest_digest}:
            raise KubeError(
                "content-derived candidate image reference already mismatches"
            )
        if existing_digest is None:
            tagged = subprocess.run(
                ["docker", "image", "tag", temporary_ref, image_ref],
                capture_output=True,
                text=True,
            )
            if (
                tagged.returncode != 0
                or _local_manifest_digest(image_ref) != manifest_digest
            ):
                raise KubeError(
                    "could not create the content-derived candidate image ref"
                )
        result = _BuiltImage(
            reference=image_ref,
            manifest_digest=manifest_digest,
            platform=platform,
        )
    finally:
        removed = subprocess.run(
            ["docker", "image", "rm", temporary_ref],
            capture_output=True,
            text=True,
        )
        if result is not None and removed.returncode != 0:
            raise KubeError("could not remove the temporary candidate image ref")
    return result


def _image_digest(tag: str) -> str | None:
    """Return the local Docker server platform's exact image manifest."""

    try:
        platform = _docker_platform()
    except KubeError:
        return None
    try:
        proc = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                "--platform",
                platform,
                "--format={{json .Descriptor}}",
                tag,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        descriptor = json.loads(proc.stdout)
        media_type = descriptor["mediaType"]
        digest = descriptor["digest"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    if (
        media_type not in _MANIFEST_MEDIA_TYPES
        or not isinstance(digest, str)
        or _IMAGE_DIGEST_RE.fullmatch(digest) is None
    ):
        return None
    return digest


def _tool_version(command: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=20
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    output = (proc.stdout or proc.stderr).strip().splitlines()
    return output[0][:300] if output else None


def _harness_version() -> str:
    try:
        value = package_version("agent-eval")
    except (PackageNotFoundError, ValueError):
        from . import __version__

        value = __version__
    if not value or len(value) > 128 or not value.isprintable():
        return "unknown"
    return value


def _set_evaluation_spec_digest(
    task: Task,
    record: RunRecord,
    *,
    run_scans: bool,
    run_judge: bool,
) -> None:
    if record.governance is not None:
        record.provenance.evaluation_spec_digest = (
            record.governance.execution_spec_digest
        )
        return
    _, evaluation_digest = _governance_task_evidence(
        task,
        run_scans=run_scans,
        run_judge=run_judge and task.judge.enabled,
    )
    record.provenance.evaluation_spec_digest = evaluation_digest


def _capture_provenance(task: Task, record: RunRecord) -> None:
    record.provenance.harness_version = _harness_version()
    with suppress(Exception):
        git = capture_git_state(REPO_ROOT)
        record.provenance.harness_commit = git.sha
        record.provenance.harness_dirty = git.dirty
        record.provenance.harness_worktree_sha256 = git.worktree_sha256
    with suppress(Exception):
        record.provenance.task_tree_sha256 = hash_tree(task.path)
    if record.governance is not None:
        record.provenance.image_tag = record.governance.task_image_ref
        record.provenance.local_image_digest = record.governance.task_image_digest
    else:
        record.provenance.image_tag = task.image_tag
        record.provenance.local_image_digest = _image_digest(task.image_tag)
    record.provenance.agent_image_digest = record.efficiency.runtime_image_digest
    record.provenance.eval_image_digest = record.correctness.runtime_image_digest
    record.provenance.submission_image_digest = (
        record.correctness.submission_runtime_image_digest
    )
    record.provenance.image_digest = (
        record.governance.task_image_digest
        if record.governance is not None
        else record.correctness.runtime_image_digest
        or record.efficiency.runtime_image_digest
    )
    record.provenance.tool_versions = {
        "python": sys.version.split()[0],
        "docker": _tool_version(["docker", "--version"]),
        "kubectl": _tool_version(["kubectl", "version", "--client"]),
        "k3d": _tool_version(["k3d", "version"]),
        "k3s-image-digest": cluster_mod.K3S_IMAGE_DIGEST,
        "runtime-class": runtime_class_name() or "runc",
        "egress-proxy-image": (
            task.network.proxy_image if task.network.agent_mode == "proxy" else None
        ),
    }


def _attestable_artifacts(run_dir: Path) -> list[str]:
    artifacts = []
    for path in sorted(run_dir.rglob("*")):
        if (
            path.is_file()
            and not path.is_symlink()
            and path.name not in ("attestation.json", "attestation.json.sha256")
        ):
            artifacts.append(path.relative_to(run_dir).as_posix())
    return artifacts


def _drop_uninspected_agent_artifacts(run_dir: Path) -> None:
    """Remove artifacts whose credential safety could not be established."""

    with os.scandir(run_dir) as entries:
        paths = [Path(entry.path) for entry in entries if entry.name != "workspace"]
    for path in paths:
        with suppress(FileNotFoundError):
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                shutil.rmtree(path)
            else:
                path.unlink()


def _contain_durable_agent_artifacts(
    run_dir: Path,
    credential_redactor: CredentialRedactor,
) -> str | None:
    """Remove any non-workspace artifact whose credential safety is not proven."""

    try:
        leaked_artifacts = _credential_hits_in_tree(
            run_dir,
            credential_redactor,
            maximum_bytes=_DURABLE_AGENT_ARTIFACT_MAX_BYTES,
            maximum_entries=_DURABLE_AGENT_ARTIFACT_MAX_ENTRIES,
            excluded_top_level=frozenset({"workspace"}),
        )
    except (CredentialRedactionError, UnsafeArchiveError):
        _drop_uninspected_agent_artifacts(run_dir)
        return (
            "credential containment failed: durable agent artifacts could "
            "not be inspected"
        )
    if not leaked_artifacts:
        return None
    # These are derived logs or evaluator artifacts, never the clean workspace
    # snapshot. Remove them instead of attesting a mutation.
    for artifact in sorted(
        leaked_artifacts,
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        with suppress(FileNotFoundError):
            metadata = artifact.lstat()
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                shutil.rmtree(artifact)
            else:
                artifact.unlink()
    return (
        "credential containment failed: unsafe durable agent artifact was removed"
    )


def _persist_run(
    task: Task,
    record: RunRecord,
    *,
    credential_redactor: CredentialRedactor | None = None,
) -> str | None:
    """Persist the record, then bind its artifacts into unsigned provenance."""

    if credential_redactor is not None:
        containment_error = _contain_durable_agent_artifacts(
            record.run_dir,
            credential_redactor,
        )
        if containment_error is not None:
            return containment_error
        # Defense in depth: no record may reach either results.json or SQLite
        # if task/evaluator derivation occurred after its last redaction pass.
        finalized = _redact_run_record(record, credential_redactor)
        if finalized.model_dump(mode="python") != record.model_dump(mode="python"):
            return (
                "credential containment failed: run evidence was not finalized "
                "after derivation"
            )
    save_run(record)
    provenance = record.provenance
    if not (
        provenance.image_tag
        and provenance.image_digest
        and provenance.harness_commit
        and provenance.harness_dirty is not None
        and provenance.harness_worktree_sha256
    ):
        if record.governance is not None:
            return "governed run attestation prerequisites are incomplete"
        return None
    try:
        create_attestation(
            statement_path=record.run_dir / "attestation.json",
            artifact_root=record.run_dir,
            artifact_paths=_attestable_artifacts(record.run_dir),
            task_root=task.path,
            task_id=task.id,
            image_tag=provenance.image_tag,
            image_digest=provenance.image_digest,
            harness_git_sha=provenance.harness_commit,
            harness_git_dirty=provenance.harness_dirty,
            harness_git_worktree_sha256=provenance.harness_worktree_sha256,
            models={
                "agent": record.efficiency.model,
                "agent-requested": record.efficiency.requested_model,
                "judge": record.judge.model,
            },
            tool_versions=provenance.tool_versions,
            outcome=(record.outcome.model_dump(mode="json") if record.outcome else {}),
            governance=(
                record.governance.model_dump(mode="json") if record.governance else {}
            ),
        )
        return None
    except Exception as exc:
        # The run remains usable, but absence of attestation is visible to a
        # verifier and can be made a CI gate by invoking verify-run.
        detail = str(exc)[:500]
        if credential_redactor is not None:
            detail = credential_redactor.redact_text(detail)
        console.print(
            f"[yellow]could not create run attestation: {detail}[/yellow]"
        )
        return f"attestation creation failed: {type(exc).__name__}: {detail}"


def _record_audit_failure(record: RunRecord, exc: Exception) -> None:
    """Turn a governed audit failure into explicit infrastructure evidence."""

    error = f"audit trail failure: {type(exc).__name__}: {str(exc)[:500]}"
    record.provenance.audit_error = error
    if record.efficiency.infra_error:
        if error not in record.efficiency.infra_error:
            record.efficiency.infra_error += f"; {error}"
    else:
        record.efficiency.infra_error = error


def _enforce_governed_model_evidence(record: RunRecord) -> None:
    """Require the adapter to observe the exact model admitted by governance."""

    governance = record.governance
    if governance is None or record.efficiency.wall_time_s is None:
        return
    expected = (
        governance.matched_model.model if governance.matched_model is not None else None
    )
    observed = record.efficiency.model
    if observed == expected and observed is not None:
        return
    evidence = "unavailable" if observed is None else repr(observed)
    error = (
        "governance model evidence mismatch: "
        f"observed {evidence}; requires exact model {expected!r}"
    )
    if record.efficiency.infra_error:
        record.efficiency.infra_error += f"; {error}"
    else:
        record.efficiency.infra_error = error


def _audit_event(
    record: RunRecord,
    audit: AuditChain | None,
    event_type: str,
    attributes: dict | None = None,
) -> None:
    """Append non-sensitive lifecycle evidence and fail closed on write errors."""

    if audit is None or record.provenance.audit_error is not None:
        return
    try:
        audit.append(event_type, attributes or {})
    except Exception as exc:
        _record_audit_failure(record, exc)


def _governed_scanner_assurance_error(
    record: RunRecord, *, require_evidence: bool
) -> str | None:
    """Return a durable scanner/governance identity consistency error."""

    governance = record.governance
    if governance is None or not hasattr(governance, "scanner_identity_sha256"):
        return None
    try:
        validated_scans = type(record.scans).model_validate(
            record.scans.model_dump(mode="python")
        )
    except ValueError:
        return "observed scanner assurance evidence is internally inconsistent"
    observed = validated_scans.scanner_assurance
    if not governance.run_scans:
        return (
            "disabled governed scanners contain unexpected assurance evidence"
            if observed is not None
            else None
        )
    if observed is None:
        return (
            "governed scanner assurance evidence is missing for the admitted "
            "grader recipe"
            if require_evidence
            else None
        )
    if not observed.promotion_ready:
        return (
            "observed scanner assurance is not promotion-ready: "
            + ", ".join(observed.promotion_blockers)[:1000]
        )
    if observed.identity_sha256 != governance.scanner_identity_sha256:
        return "observed scanner assurance identity does not match governance"
    return None


def _complete_record(
    task: Task,
    record: RunRecord,
    audit: AuditChain | None,
    *,
    credential_redactor: CredentialRedactor | None = None,
) -> RunRecord:
    """Decide the outcome, finalize governed audit evidence, and persist once."""

    record.provenance.harness_version = _harness_version()

    if record.governance is not None:
        governed_image_digest = record.governance.task_image_digest
        image_errors = []
        if record.correctness.evaluation_mode != "isolated-black-box":
            image_errors.append(
                "governed correctness evidence is not isolated-black-box"
            )
        if record.provenance.image_tag != record.governance.task_image_ref:
            image_errors.append(
                "run provenance image reference does not match governance"
            )
        if record.provenance.image_digest not in {None, governed_image_digest}:
            image_errors.append(
                "run provenance image digest does not match the governed digest"
            )
        if record.efficiency.runtime_image_digest not in {
            None,
            governed_image_digest,
        }:
            image_errors.append(
                "agent pod image digest does not match the governed digest"
            )
        if record.correctness.runtime_image_digest not in {
            None,
            governed_image_digest,
        }:
            image_errors.append(
                "evaluator pod image digest does not match the governed digest"
            )
        if record.correctness.submission_runtime_image_digest not in {
            None,
            governed_image_digest,
        }:
            image_errors.append(
                "submission pod image digest does not match the governed digest"
            )
        if (
            record.efficiency.infra_error is None
            and record.efficiency.runtime_image_digest is None
        ):
            image_errors.append("agent pod image digest evidence is missing")
        evaluation_completed = (
            record.correctness.infra_error is None
            and record.correctness.integrity_error is None
            and (
                record.correctness.command_exit_code is not None
                or record.correctness.total > 0
            )
        )
        if evaluation_completed and record.correctness.runtime_image_digest is None:
            image_errors.append("evaluator pod image digest evidence is missing")
        if (
            evaluation_completed
            and record.correctness.evaluation_mode == "isolated-black-box"
            and record.correctness.submission_runtime_image_digest is None
        ):
            image_errors.append("submission pod image digest evidence is missing")
        for image_error in image_errors:
            if record.efficiency.infra_error:
                if image_error not in record.efficiency.infra_error:
                    record.efficiency.infra_error += f"; {image_error}"
            else:
                record.efficiency.infra_error = image_error
        if record.governance.run_judge and record.judge.weighted_score is None:
            judge_error = (
                "governed judge evidence is missing for the admitted grader recipe"
            )
            if record.efficiency.infra_error:
                if judge_error not in record.efficiency.infra_error:
                    record.efficiency.infra_error += f"; {judge_error}"
            else:
                record.efficiency.infra_error = judge_error
        if record.governance.run_judge and (
            record.judge.backend != record.governance.judge_backend
            or record.judge.model != record.governance.judge_model
        ):
            judge_identity_error = (
                "observed judge identity does not match the governed backend/model"
            )
            if record.efficiency.infra_error:
                if judge_identity_error not in record.efficiency.infra_error:
                    record.efficiency.infra_error += f"; {judge_identity_error}"
            else:
                record.efficiency.infra_error = judge_identity_error
        scanner_error = _governed_scanner_assurance_error(
            record, require_evidence=True
        )
        if scanner_error is not None:
            if record.efficiency.infra_error:
                if scanner_error not in record.efficiency.infra_error:
                    record.efficiency.infra_error += f"; {scanner_error}"
            else:
                record.efficiency.infra_error = scanner_error
        try:
            current_task_digest = hash_tree(task.path)
            task_evidence_error = (
                None
                if current_task_digest == record.governance.task_tree_sha256
                else "governed task snapshot changed during execution"
            )
        except Exception as exc:
            task_evidence_error = (
                "governed task snapshot could not be verified: "
                f"{type(exc).__name__}: {str(exc)[:500]}"
            )
        if task_evidence_error is not None:
            if record.efficiency.infra_error:
                if task_evidence_error not in record.efficiency.infra_error:
                    record.efficiency.infra_error += f"; {task_evidence_error}"
            else:
                record.efficiency.infra_error = task_evidence_error

    record.finished_at = now_iso()
    record.outcome = evaluate_outcome(record, task.acceptance)
    _audit_event(
        record,
        audit,
        "outcome.decided",
        {
            "status": record.outcome.status,
            "check_count": len(record.outcome.checks),
            "reason_count": len(record.outcome.reasons),
        },
    )
    _audit_event(
        record,
        audit,
        "run.completed",
        {"status": record.outcome.status},
    )
    if audit is not None:
        record.provenance.audit_trace_id = audit.trace_id
        record.provenance.audit_final_hash = audit.final_hash
        record.provenance.audit_event_count = audit.event_count
        try:
            audit.close()
        except Exception as exc:
            _record_audit_failure(record, exc)
    if record.provenance.audit_error is not None:
        record.outcome = evaluate_outcome(record, task.acceptance)
    record.assessments = derive_assessments(record, task)

    # Scrub durable artifacts before record redaction. If schema validation of
    # the redacted record itself must fail closed, no raw transcript or derived
    # artifact is left behind as a side effect of that failure.
    pre_persist_containment_error = None
    if credential_redactor is not None:
        pre_persist_containment_error = _contain_durable_agent_artifacts(
            record.run_dir,
            credential_redactor,
        )
    if pre_persist_containment_error is not None:
        record.provenance.attestation_error = pre_persist_containment_error
        if record.efficiency.infra_error:
            record.efficiency.infra_error += f"; {pre_persist_containment_error}"
        else:
            record.efficiency.infra_error = pre_persist_containment_error
        record.outcome = evaluate_outcome(record, task.acceptance)
        record.assessments = derive_assessments(record, task)

    try:
        record = _redact_run_record(record, credential_redactor)
    except CredentialRedactionError:
        if credential_redactor is not None:
            _drop_uninspected_agent_artifacts(record.run_dir)
        raise

    if credential_redactor is None:
        attestation_error = _persist_run(task, record)
    else:
        attestation_error = _persist_run(
            task,
            record,
            credential_redactor=credential_redactor,
        )
    if pre_persist_containment_error is not None:
        attestation_error = pre_persist_containment_error
    containment_failed = bool(
        attestation_error
        and attestation_error.startswith("credential containment failed:")
    )
    if attestation_error is not None and (
        record.governance is not None or containment_failed
    ):
        record.provenance.attestation_error = attestation_error
        if record.efficiency.infra_error:
            if attestation_error not in record.efficiency.infra_error:
                record.efficiency.infra_error += f"; {attestation_error}"
        else:
            record.efficiency.infra_error = attestation_error
        record.outcome = evaluate_outcome(record, task.acceptance)
        record.assessments = derive_assessments(record, task)
        try:
            record = _redact_run_record(record, credential_redactor)
        except CredentialRedactionError:
            if credential_redactor is not None:
                _drop_uninspected_agent_artifacts(record.run_dir)
            raise
        # The only material introduced after the artifact gate is the trusted,
        # normalized record above. The immediately preceding redaction pass is
        # therefore the final boundary before this corrective save.
        save_run(record)
    with suppress(Exception):
        export_run_assessments(record)
    return record


def _governed_task(task: Task, decision: PolicyDecision) -> Task:
    """Apply admitted time limits and observed-usage outcome thresholds."""

    limits = decision.effective_limits
    governed = task.model_copy(deep=True)
    governed.timeouts.agent_seconds = min(
        governed.timeouts.agent_seconds, limits.max_agent_seconds
    )
    governed.timeouts.eval_seconds = min(
        governed.timeouts.eval_seconds, limits.max_eval_seconds
    )
    current_tokens = governed.acceptance.max_total_tokens
    governed.acceptance.max_total_tokens = min(
        limits.max_observed_total_tokens,
        current_tokens
        if current_tokens is not None
        else limits.max_observed_total_tokens,
    )
    current_cost = governed.acceptance.max_cost_usd
    governed.acceptance.max_cost_usd = min(
        limits.max_observed_cost_usd,
        current_cost
        if current_cost is not None
        else limits.max_observed_cost_usd,
    )
    return governed


def _validate_governance_decision(
    task: Task,
    *,
    agent: str,
    model: str | None,
    trial: int,
    run_scans: bool,
    run_judge: bool,
    request: EvaluationRequest,
    bundle: GovernanceBundle,
    decision: PolicyDecision,
    decision_stage: str,
    task_image_digest: str | None,
    task_image_ref: str | None,
    task_image_platform: str | None,
    preflight_decision: PolicyDecision | None = None,
) -> None:
    """Replay one governance stage against the exact observed runtime inputs."""

    if not isinstance(run_scans, bool) or not isinstance(run_judge, bool):
        raise ValueError("governed grader switches must be booleans")
    if task.evaluation.mode != "isolated-black-box":
        raise ValueError(
            "governed runs require isolated-black-box evaluation; cooperative "
            "test execution cannot authenticate correctness evidence"
        )
    effective_run_judge = run_judge and task.judge.enabled
    task_tree_digest, execution_spec_digest = _governance_task_evidence(
        task, run_scans=run_scans, run_judge=effective_run_judge
    )
    if decision.decision_stage != decision_stage:
        raise ValueError(f"governance decision must be a {decision_stage} decision")
    if decision_stage == "execution":
        if preflight_decision is None:
            raise ValueError("execution decision is missing its preflight")
        validate_execution_continuity(preflight_decision, decision)
    elif preflight_decision is not None:
        raise ValueError("preflight validation cannot accept a parent decision")
    if not decision.allowed:
        raise ValueError("a denied governance decision cannot start a trial")
    if request.task_id != task.id or request.agent != agent or request.model != model:
        raise ValueError("governance request does not match the runtime trial")
    if isinstance(trial, bool) or not isinstance(trial, int) or trial <= 0:
        raise ValueError("trial number must be a positive integer")
    if trial > decision.effective_limits.max_trials:
        raise ValueError("trial number exceeds the admitted trial limit")
    if [reason.code for reason in decision.reasons] != ["admitted"]:
        raise ValueError("allowed governance decision has invalid reason evidence")
    matched_task = decision.matched_task
    if (
        matched_task is None
        or matched_task.task_id != task.id
        or matched_task.status != "approved"
        or matched_task.task_tree_sha256 != task_tree_digest
        or execution_spec_digest not in matched_task.execution_spec_digests
    ):
        raise ValueError(
            "governance task registry does not match runtime evidence"
        )
    matched = decision.matched_model
    if (
        matched is None
        or matched.adapter != agent
        or matched.model != model
        or matched.status != "approved"
        or request.data_classification not in matched.allowed_data_classifications
    ):
        raise ValueError("governance decision has no matching approved model")
    judge_backend, judge_model = _governance_judge_evidence(
        task, run_judge=effective_run_judge
    )
    scanner_identity, scanner_ready = _governance_scanner_evidence(
        run_scans=run_scans
    )
    matched_judge = decision.matched_judge
    if effective_run_judge:
        if (
            matched_judge is None
            or matched_judge.adapter != f"judge:{judge_backend}"
            or matched_judge.model != judge_model
            or matched_judge.status != "approved"
            or request.data_classification
            not in matched_judge.allowed_data_classifications
        ):
            raise ValueError("governance decision has no matching approved judge")
    elif matched_judge is not None:
        raise ValueError("disabled judge cannot have matched model evidence")
    runtime_evidence = {
        "actual_task_id": task.id,
        "actual_agent": agent,
        "actual_model": model,
        "network_mode": task.network.agent_mode,
        "agent_timeout_seconds": task.timeouts.agent_seconds,
        "eval_timeout_seconds": task.timeouts.eval_seconds,
        "run_scans": run_scans,
        "scanner_identity_sha256": scanner_identity,
        "scanner_promotion_ready": scanner_ready,
        "run_judge": effective_run_judge,
        "judge_backend": judge_backend,
        "judge_model": judge_model,
        "broker_configured": bool(os.environ.get("AGENT_EVAL_CREDENTIAL_COMMAND")),
        "task_image_digest": task_image_digest,
        "task_image_ref": task_image_ref,
        "task_image_platform": task_image_platform,
    }
    domains, proxy_image = _governance_network_evidence(task, agent)
    runtime_evidence["effective_egress_domains"] = domains
    runtime_evidence["proxy_image"] = proxy_image
    runtime_evidence["task_tree_sha256"] = task_tree_digest
    runtime_evidence["execution_spec_digest"] = execution_spec_digest
    if any(
        decision.sanitized_input.get(key) != value
        for key, value in runtime_evidence.items()
    ):
        raise ValueError("governance decision does not match runtime evidence")
    admitted_trials = decision.sanitized_input.get("trials")
    if (
        isinstance(admitted_trials, bool)
        or not isinstance(admitted_trials, int)
        or trial > admitted_trials
    ):
        raise ValueError("trial was not covered by the governance decision")
    if task.timeouts.agent_seconds > decision.effective_limits.max_agent_seconds:
        raise ValueError("agent timeout exceeds the admitted limit")
    if task.timeouts.eval_seconds > decision.effective_limits.max_eval_seconds:
        raise ValueError("evaluator timeout exceeds the admitted limit")
    replayed = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=agent,
        actual_model=model,
        trials=admitted_trials,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=runtime_evidence["broker_configured"],
        run_scans=run_scans,
        scanner_identity_sha256=scanner_identity,
        scanner_promotion_ready=scanner_ready,
        run_judge=effective_run_judge,
        judge_backend=judge_backend,
        judge_model=judge_model,
        task_tree_sha256=task_tree_digest,
        execution_spec_digest=execution_spec_digest,
        decision_stage=decision_stage,
        task_image_digest=task_image_digest,
        task_image_ref=task_image_ref,
        task_image_platform=task_image_platform,
        preflight_decision_id=(
            preflight_decision.decision_id if preflight_decision is not None else None
        ),
        preflight_decision_digest=(
            sha256_json(preflight_decision) if preflight_decision is not None else None
        ),
        effective_egress_domains=domains,
        proxy_image=proxy_image,
    )
    replay_fields = {
        "decision_stage",
        "preflight_decision_id",
        "preflight_decision_digest",
        "allowed",
        "request_id",
        "request_digest",
        "policy_id",
        "policy_revision",
        "policy_digest",
        "task_registry_id",
        "task_registry_revision",
        "task_registry_digest",
        "registry_id",
        "registry_revision",
        "registry_digest",
        "sanitized_input",
        "reasons",
        "effective_limits",
        "matched_task",
        "matched_model",
        "matched_judge",
    }
    expected = decision.model_dump(mode="json", include=replay_fields)
    actual = replayed.model_dump(mode="json", include=replay_fields)
    if actual != expected:
        raise ValueError("governance decision does not replay from the policy bundle")


def _governance_evidence(
    task: Task,
    *,
    agent: str,
    model: str | None,
    trial: int,
    run_scans: bool,
    run_judge: bool,
    task_image_digest: str,
    task_image_ref: str,
    task_image_platform: str,
    preflight_decision: PolicyDecision,
    request: EvaluationRequest | None,
    bundle: GovernanceBundle | None,
    decision: PolicyDecision | None,
) -> GovernanceEvidence | None:
    """Validate and materialize the final image-bound execution evidence."""

    supplied = (request is not None, bundle is not None, decision is not None)
    if any(supplied) and not all(supplied):
        raise ValueError(
            "governance request, policy bundle, and decision must be supplied together"
        )
    if request is None or bundle is None or decision is None:
        return None
    _validate_governance_decision(
        task,
        agent=agent,
        model=model,
        trial=trial,
        run_scans=run_scans,
        run_judge=run_judge,
        request=request,
        bundle=bundle,
        decision=decision,
        decision_stage="execution",
        task_image_digest=task_image_digest,
        task_image_ref=task_image_ref,
        task_image_platform=task_image_platform,
        preflight_decision=preflight_decision,
    )
    return GovernanceEvidence.from_decision(request, decision)


def _finalize_execution_decision(
    task: Task,
    *,
    agent: str,
    model: str | None,
    run_scans: bool,
    run_judge: bool,
    task_image_digest: str,
    task_image_ref: str,
    task_image_platform: str,
    request: EvaluationRequest,
    bundle: GovernanceBundle,
    preflight_decision: PolicyDecision,
) -> PolicyDecision:
    """Issue the execution decision for an already approved image identity."""

    admitted_trials = preflight_decision.sanitized_input.get("trials")
    if isinstance(admitted_trials, bool) or not isinstance(admitted_trials, int):
        raise ValueError("preflight decision has an invalid trial count")
    effective_run_judge = run_judge and task.judge.enabled
    judge_backend, judge_model = _governance_judge_evidence(
        task, run_judge=effective_run_judge
    )
    domains, proxy_image = _governance_network_evidence(task, agent)
    scanner_identity, scanner_ready = _governance_scanner_evidence(
        run_scans=run_scans
    )
    task_tree_digest, execution_spec_digest = _governance_task_evidence(
        task, run_scans=run_scans, run_judge=effective_run_judge
    )
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=agent,
        actual_model=model,
        trials=admitted_trials,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=bool(os.environ.get("AGENT_EVAL_CREDENTIAL_COMMAND")),
        run_scans=run_scans,
        scanner_identity_sha256=scanner_identity,
        scanner_promotion_ready=scanner_ready,
        run_judge=effective_run_judge,
        judge_backend=judge_backend,
        judge_model=judge_model,
        task_tree_sha256=task_tree_digest,
        execution_spec_digest=execution_spec_digest,
        decision_stage="execution",
        task_image_digest=task_image_digest,
        task_image_ref=task_image_ref,
        task_image_platform=task_image_platform,
        preflight_decision_id=preflight_decision.decision_id,
        preflight_decision_digest=sha256_json(preflight_decision),
        effective_egress_domains=domains,
        proxy_image=proxy_image,
    )
    if not decision.allowed:
        codes = ", ".join(reason.code for reason in decision.reasons)
        raise ValueError(f"final execution decision denied: {codes}")
    validate_execution_continuity(preflight_decision, decision)
    return decision


def prepare_governed_execution(
    task: Task,
    *,
    agent: str,
    model: str | None,
    run_scans: bool,
    run_judge: bool,
    request: EvaluationRequest,
    bundle: GovernanceBundle,
    preflight_decision: PolicyDecision,
) -> PolicyDecision:
    """Verify and import a preapproved, single-platform task image.

    Image construction and promotion are deliberately outside the governed
    evaluation trust domain.  A run may consume only the exact manifest that
    an operator already placed in the task registry for the Docker platform.
    """

    _validate_governance_decision(
        task,
        agent=agent,
        model=model,
        trial=1,
        run_scans=run_scans,
        run_judge=run_judge,
        request=request,
        bundle=bundle,
        decision=preflight_decision,
        decision_stage="preflight",
        task_image_digest=None,
        task_image_ref=None,
        task_image_platform=None,
    )
    with tempfile.TemporaryDirectory(prefix="agent-eval-governed-snapshot-") as temporary:
        snapshot = _snapshot_governed_task(
            task,
            Path(temporary),
            expected_tree_digest=preflight_decision.sanitized_input["task_tree_sha256"],
            expected_execution_digest=preflight_decision.sanitized_input[
                "execution_spec_digest"
            ],
            run_scans=preflight_decision.sanitized_input["run_scans"],
            run_judge=preflight_decision.sanitized_input["run_judge"],
        )
        matched_task = preflight_decision.matched_task
        if matched_task is None:
            raise ValueError("governed preflight has no approved task registry entry")
        platform = _docker_platform()
        approved_image = next(
            (
                image
                for image in matched_task.approved_images
                if image.platform == platform
            ),
            None,
        )
        if approved_image is None:
            raise ValueError(
                f"task registry has no preapproved image for platform {platform}"
            )
        built_image = _BuiltImage(
            reference=approved_image.reference,
            manifest_digest=approved_image.manifest_digest,
            platform=approved_image.platform,
        )
        execution_decision = _finalize_execution_decision(
            snapshot,
            agent=agent,
            model=model,
            run_scans=run_scans,
            run_judge=run_judge,
            task_image_digest=built_image.manifest_digest,
            task_image_ref=built_image.reference,
            task_image_platform=built_image.platform,
            request=request,
            bundle=bundle,
            preflight_decision=preflight_decision,
        )
        # Cluster creation and import are authorized by the image-bound final
        # decision, not by a mutable tag or a run-time build.
        cluster_mod.ensure_cluster()
        ensure_image(
            snapshot,
            expected_digest=built_image.manifest_digest,
            image_ref=built_image.reference,
        )
        return execution_decision


def _delete_with_retries(resource: object, label: str, attempts: int = 3) -> str | None:
    """Delete one trial resource, retrying while preserving a final failure."""

    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            resource.delete()
            return None
        except Exception as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.1 * (2**attempt))
    assert last_error is not None
    resource_name = getattr(resource, "name", None)
    resource_detail = (
        f"; resource={str(resource_name)[:253]}" if resource_name else ""
    )
    cleanup_command = getattr(resource, "cleanup_command", None)
    remediation = (
        f"; remediation={cleanup_command}"
        if isinstance(cleanup_command, str) and cleanup_command
        else ""
    )
    return (
        f"{label} cleanup failed after {attempts} attempts: "
        f"{type(last_error).__name__}: {str(last_error)[:500]}"
        f"{resource_detail}{remediation}"
    )


def _judge_input_is_safe(record: RunRecord) -> bool:
    """Require complete zero-secret evidence before sending a diff to a model."""

    return record.diff.complete and (
        record.scans.scanner_status.get("gitleaks") == "ok"
        and record.scans.secrets_found == 0
    )


def _judge_credential_screen_error(
    task: Task,
    run_dir: Path,
    redactor: CredentialRedactor | None,
) -> str | None:
    """Fail closed if exact projected credentials could reach the judge."""

    if redactor is None:
        return None
    try:
        if redactor.contains_text(task.prompt):
            return (
                "judge skipped: projected credential material was detected in "
                "the task prompt"
            )
        for dimension in task.judge.weights:
            if redactor.contains_text(dimension):
                return (
                    "judge skipped: projected credential material was detected in "
                    "a rubric dimension"
                )

        diff_path = run_dir / "workspace.diff"
        metadata = diff_path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return (
                "judge skipped: exact projected-credential inspection did not "
                "complete"
            )
        if metadata.st_size > DIFF_MAX_BYTES:
            return (
                "judge skipped: exact projected-credential inspection did not "
                "complete"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        descriptor = os.open(diff_path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size
            ):
                return (
                    "judge skipped: exact projected-credential inspection did not "
                    "complete"
                )
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                if redactor.contains_stream(stream, maximum_bytes=DIFF_MAX_BYTES):
                    return (
                        "judge skipped: projected credential material was detected "
                        "in workspace.diff"
                    )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except (CredentialRedactionError, OSError):
        return (
            "judge skipped: exact projected-credential inspection did not complete"
        )
    return None


def _workspace_safety_error(workspace: Path) -> str | None:
    """Reject host-dangerous trees before diffing or invoking scanners."""

    try:
        root = workspace.resolve(strict=True)
    except OSError as exc:
        return f"workspace is unavailable: {type(exc).__name__}"
    if not root.is_dir():
        return "workspace is not a directory"

    def visit(directory: Path) -> str | None:
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            return f"workspace directory is unreadable: {type(exc).__name__}"
        for entry in entries:
            relative = Path(entry.path).relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                return f"workspace path {relative} is unreadable: {type(exc).__name__}"
            if stat.S_ISLNK(metadata.st_mode):
                return f"workspace symlink {relative} is not allowed"
            if stat.S_ISDIR(metadata.st_mode):
                if error := visit(Path(entry.path)):
                    return error
            elif not stat.S_ISREG(metadata.st_mode):
                return f"workspace special file {relative} is not allowed"
        return None

    return visit(root)


def _control_paths(root: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    if not root.is_dir():
        return paths
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root)
        if (
            candidate.name in _EVALUATOR_CONTROL_FILES
            or relative.parts[0] in _EVALUATOR_CONTROL_PACKAGES
        ):
            paths[relative.as_posix()] = candidate
    return paths


def _path_signature(path: Path | None) -> str:
    if path is None or not os.path.lexists(path):
        return "absent"
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if path.is_symlink():
        return f"link:{mode:o}:{path.readlink()}"
    if path.is_dir():
        return f"dir:{mode:o}:{hash_tree(path)}"
    return f"file:{mode:o}:{sha256_file(path)}"


def _evaluator_control_error(task: Task, workspace: Path) -> str | None:
    starter = _control_paths(task.workspace_dir)
    produced = _control_paths(workspace)
    for relative in sorted(set(starter) | set(produced)):
        if _path_signature(starter.get(relative)) != _path_signature(
            produced.get(relative)
        ):
            return f"evaluator-control path changed: {relative}"
    return None


def _trusted_test_command(
    command: str, *, isolated_black_box: bool = False
) -> tuple[str, bool]:
    """Replace ordinary pytest startup with an isolated trusted bootstrap."""

    working_directory = "/tests" if isolated_black_box else "/workspace"
    try:
        argv = shlex.split(command)
    except ValueError:
        return f"cd {working_directory} && {command}", False
    arguments: list[str] | None = None
    if (
        len(argv) >= 3
        and Path(argv[0]).name.startswith("python")
        and argv[1:3] == ["-m", "pytest"]
    ):
        arguments = argv[3:]
    elif argv and Path(argv[0]).name in {"pytest", "py.test"}:
        arguments = argv[1:]
    if arguments is None:
        return f"cd {working_directory} && {command}", False
    trusted = [
        "python",
        "-I",
        "/tests/.agent-eval-pytest.py",
        *arguments,
        "-c",
        "/dev/null",
        "--rootdir=/tests",
    ]
    return shlex.join(trusted), True


def _runtime_image_evidence(
    pod: Pod,
    expected: str | None,
    *,
    image_ref: str,
) -> tuple[str | None, str | None]:
    try:
        actual = pod.image_manifest_digest(
            image_ref,
            expected_manifest_digest=expected,
        )
    except (KubeError, subprocess.TimeoutExpired):
        actual = None
    if actual is None:
        return None, "runtime task image digest is unavailable"
    if expected is not None and actual != expected:
        return (
            actual,
            f"runtime image digest {actual} does not match expected {expected}",
        )
    return actual, None


def _run_hidden_tests_in_pod(
    task: Task,
    pod: Pod,
    run_dir: Path,
    runtime_digest: str | None,
    *,
    workspace: Path | None,
    isolated_black_box: bool,
    submission_url: str | None = None,
) -> TestResults:
    """Execute trusted tests in one prepared evaluator pod."""

    mode = "isolated-black-box" if isolated_black_box else "cooperative"

    def finish(**kwargs) -> TestResults:
        return TestResults(
            evaluation_mode=mode,
            runtime_image_digest=runtime_digest,
            **kwargs,
        )

    reset = pod.exec(
        "rm -rf /workspace/* /workspace/.[!.]* /workspace/..?*",
        timeout=30,
    )
    if reset.returncode != 0:
        error = _sandbox_infra_error("eval", pod, reset.returncode)
        if error is None:
            error = (
                "could not reset eval workspace before evaluation "
                f"(exit {reset.returncode})"
            )
        (run_dir / "eval-output.txt").write_text(f"{error}\n")
        return finish(command_exit_code=reset.returncode, infra_error=error)
    if workspace is not None:
        pod.copy_dir_to(workspace, "/workspace")
    pod.copy_dir_to(task.tests_dir, "/tests")
    test_command, trusted_pytest = _trusted_test_command(
        task.test_command, isolated_black_box=isolated_black_box
    )
    if trusted_pytest:
        with tempfile.TemporaryDirectory(prefix="agent-eval-pytest-runner-") as tmp:
            runner_dir = Path(tmp)
            shutil.copy2(
                _TRUSTED_PYTEST_RUNNER,
                runner_dir / ".agent-eval-pytest.py",
            )
            pod.copy_dir_to(runner_dir, "/tests")
    results_ready = pod.exec("mkdir -p /results", timeout=30)
    if results_ready.returncode != 0:
        error = (
            "eval sandbox infrastructure failure: could not prepare "
            f"result directory (exit {results_ready.returncode})"
        )
        return finish(
            command_exit_code=results_ready.returncode,
            infra_error=error,
        )

    console.print("running hidden tests in eval pod...")
    environment = None
    if isolated_black_box:
        assert submission_url is not None
        environment = {
            "AGENT_EVAL_EVALUATION_MODE": mode,
            "AGENT_EVAL_SUBMISSION_URL": submission_url,
        }
    try:
        proc = pod.exec(
            test_command,
            timeout=task.timeouts.eval_seconds,
            env=environment,
        )
        output = proc.stdout.decode(errors="replace") + proc.stderr.decode(
            errors="replace"
        )
    except subprocess.TimeoutExpired:
        infrastructure_error = _sandbox_infra_error("eval", pod)
        error = infrastructure_error or (
            f"test command timed out after {task.timeouts.eval_seconds}s"
        )
        (run_dir / "eval-output.txt").write_text(f"TIMEOUT\n{error}\n")
        if isolated_black_box and infrastructure_error is None:
            # A submitted service can deliberately stall its responses. Keep
            # that in the correctness denominator instead of allowing it to
            # manufacture an infrastructure exclusion.
            return finish(
                command_exit_code=124,
                failures=[error],
            )
        return finish(infra_error=error)
    except CommandOutputLimitError as exc:
        output = exc.stdout.decode(errors="replace") + exc.stderr.decode(
            errors="replace"
        )
        error = str(exc)
        (run_dir / "eval-output.txt").write_text(
            output + f"\nOUTPUT CAP REACHED\n{error}\n"
        )
        return finish(infra_error=error)
    (run_dir / "eval-output.txt").write_text(output)

    error = _sandbox_infra_error("eval", pod, proc.returncode)
    if error is not None:
        return finish(command_exit_code=proc.returncode, infra_error=error)

    quiescence_error = _quiesce_agent_processes(pod)
    if quiescence_error is not None:
        quiescence_error = quiescence_error.replace(
            "agent process", "evaluator process", 1
        )
        with (run_dir / "eval-output.txt").open("a") as output_file:
            output_file.write(f"\n{quiescence_error}\n")
        return finish(
            command_exit_code=proc.returncode,
            infra_error=quiescence_error,
        )

    results_dir = run_dir / "results"
    try:
        pod.copy_dir_from("/results", results_dir)
    except UnsafeArchiveError as exc:
        error = f"unsafe evaluator result archive: {exc}"
        return finish(
            command_exit_code=126,
            integrity_error=error,
            failures=[error],
        )
    test_results = parse_junit(
        results_dir / "junit.xml", command_exit_code=proc.returncode
    )
    test_results.evaluation_mode = mode
    test_results.runtime_image_digest = runtime_digest
    coverage = parse_coverage_artifact(results_dir / "coverage.json")
    test_results.coverage_percent = coverage.percent
    if coverage.integrity_error:
        if test_results.integrity_error:
            test_results.integrity_error += f"; {coverage.integrity_error}"
        else:
            test_results.integrity_error = coverage.integrity_error
        test_results.failures.append(coverage.integrity_error)
    if coverage.infra_error:
        if test_results.infra_error:
            test_results.infra_error += f"; {coverage.infra_error}"
        else:
            test_results.infra_error = coverage.infra_error
    return test_results


def _append_cleanup_error(
    result: TestResults,
    run_dir: Path,
    cleanup_error: str,
) -> None:
    with (run_dir / "eval-output.txt").open("a") as output_file:
        output_file.write(f"\n{cleanup_error}\n")
    if result.infra_error:
        result.infra_error += f"; {cleanup_error}"
    else:
        result.infra_error = cleanup_error


def _run_cooperative_eval_phase(
    task: Task,
    workspace: Path,
    run_dir: Path,
    *,
    expected_runtime_digest: str | None,
    runtime_image: str | None,
    image_pull_policy: str,
) -> TestResults:
    """Run the compatibility evaluator where submitted code shares pytest."""

    integrity_error = _workspace_safety_error(workspace)
    if task.evaluation.mode == "cooperative" and integrity_error is None:
        integrity_error = _evaluator_control_error(task, workspace)
    if integrity_error:
        (run_dir / "eval-output.txt").write_text(f"REJECTED: {integrity_error}\n")
        return TestResults(
            evaluation_mode="cooperative",
            command_exit_code=126,
            integrity_error=integrity_error,
            failures=[integrity_error],
        )

    pod: Pod | None = None
    result: TestResults | None = None
    try:
        ensure_namespace()
        pod = create_sandbox_pod(
            "eval",
            runtime_image or task.image_tag,
            active_deadline=task.timeouts.eval_seconds + 900,
            resources=task.resources.eval.as_kubernetes(),
            security=task.security.model_dump(),
            image_pull_policy=image_pull_policy,
            egress_mode="deny",
        )
        pod.wait_ready()
        runtime_digest, image_error = _runtime_image_evidence(
            pod,
            expected_runtime_digest,
            image_ref=runtime_image or task.image_tag,
        )
        if image_error:
            result = TestResults(
                evaluation_mode="cooperative",
                infra_error=f"eval sandbox infrastructure failure: {image_error}",
                runtime_image_digest=runtime_digest,
            )
        else:
            result = _run_hidden_tests_in_pod(
                task,
                pod,
                run_dir,
                runtime_digest,
                workspace=workspace,
                isolated_black_box=False,
            )
    except UnsafeArchiveError as exc:
        error = f"unsafe evaluator archive: {exc}"
        result = TestResults(
            evaluation_mode="cooperative",
            command_exit_code=126,
            integrity_error=error,
            failures=[error],
        )
    except (KubeError, subprocess.TimeoutExpired, OSError) as exc:
        error = _sandbox_infra_error("eval", pod) if pod is not None else None
        if error is None:
            error = f"eval sandbox setup failed: {type(exc).__name__}: {str(exc)[:500]}"
        (run_dir / "eval-output.txt").write_text(f"{error}\n")
        result = TestResults(evaluation_mode="cooperative", infra_error=error)
    finally:
        if pod is not None:
            cleanup_error = _delete_with_retries(pod, "eval pod")
            if cleanup_error:
                if result is None:
                    result = TestResults(evaluation_mode="cooperative")
                _append_cleanup_error(result, run_dir, cleanup_error)
    assert result is not None
    return result


def _submission_container_command(command: str) -> list[str]:
    """Wait for the host copy, then replace PID 1's shell with submitted code."""

    return [
        "sh",
        "-c",
        "set -eu\n"
        "while [ ! -e /tmp/agent-eval-start ]; do sleep 0.05; done\n"
        "cd /workspace\n"
        f"exec {command} >/dev/null 2>&1",
    ]


def _wait_for_submission_readiness(
    evaluator: Pod,
    *,
    address: str,
    port: int,
    path: str,
    timeout_seconds: int,
) -> bool:
    """Poll the isolated submission from the evaluator's network boundary."""

    script = "\n".join(
        (
            "import http.client, os, sys",
            "try:",
            "    connection = http.client.HTTPConnection(",
            "        os.environ['AGENT_EVAL_SUBMISSION_HOST'],",
            "        int(os.environ['AGENT_EVAL_SUBMISSION_PORT']),",
            "        timeout=1,",
            "    )",
            "    connection.request(",
            "        'GET',",
            "        os.environ['AGENT_EVAL_READINESS_PATH'],",
            "        headers={'Connection': 'close'},",
            "    )",
            "    response = connection.getresponse()",
            "    ready = 100 <= response.status <= 599",
            "    connection.close()",
            "except Exception:",
            "    ready = False",
            "sys.exit(0 if ready else 1)",
        )
    )
    command = shlex.join(["python", "-I", "-c", script])
    environment = {
        "AGENT_EVAL_SUBMISSION_HOST": address,
        "AGENT_EVAL_SUBMISSION_PORT": str(port),
        "AGENT_EVAL_READINESS_PATH": path,
    }
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            probe = evaluator.exec(command, timeout=3, env=environment)
        except subprocess.TimeoutExpired:
            probe = None
        if probe is not None and probe.returncode == 0:
            return True
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.1, remaining))
    return False


def _run_isolated_black_box_eval_phase(
    task: Task,
    workspace: Path,
    run_dir: Path,
    *,
    expected_runtime_digest: str | None,
    runtime_image: str | None,
    image_pull_policy: str,
) -> TestResults:
    """Run submitted code and trusted tests in separate network-confined pods."""

    integrity_error = _workspace_safety_error(workspace)
    if integrity_error:
        (run_dir / "eval-output.txt").write_text(f"REJECTED: {integrity_error}\n")
        return TestResults(
            evaluation_mode="isolated-black-box",
            command_exit_code=126,
            integrity_error=integrity_error,
            failures=[integrity_error],
        )

    configuration = task.evaluation
    assert configuration.submission_command is not None
    assert configuration.submission_port is not None
    assert configuration.readiness is not None
    submission: Pod | None = None
    evaluator: Pod | None = None
    link = None
    submission_digest: str | None = None
    result: TestResults | None = None
    try:
        ensure_namespace()
        submission = create_sandbox_pod(
            "submission",
            runtime_image or task.image_tag,
            active_deadline=task.timeouts.eval_seconds + 900,
            resources=task.resources.eval.as_kubernetes(),
            security=task.security.model_dump(),
            image_pull_policy=image_pull_policy,
            egress_mode="deny",
            container_command=_submission_container_command(
                configuration.submission_command
            ),
        )
        submission.wait_ready()
        submission_digest, image_error = _runtime_image_evidence(
            submission,
            expected_runtime_digest,
            image_ref=runtime_image or task.image_tag,
        )
        if image_error:
            result = TestResults(
                evaluation_mode="isolated-black-box",
                infra_error=(
                    "submission sandbox infrastructure failure: " + image_error
                ),
                submission_runtime_image_digest=submission_digest,
            )
        else:
            reset = submission.exec(
                "rm -rf /workspace/* /workspace/.[!.]* /workspace/..?*",
                timeout=30,
            )
            if reset.returncode != 0:
                error = _sandbox_infra_error(
                    "submission", submission, reset.returncode
                ) or (
                    "could not reset submission workspace before evaluation "
                    f"(exit {reset.returncode})"
                )
                result = TestResults(
                    evaluation_mode="isolated-black-box",
                    command_exit_code=reset.returncode,
                    infra_error=error,
                    submission_runtime_image_digest=submission_digest,
                )
            else:
                submission.copy_dir_to(workspace, "/workspace")

        if result is None:
            evaluator = create_sandbox_pod(
                "eval",
                runtime_image or task.image_tag,
                active_deadline=task.timeouts.eval_seconds + 900,
                resources=task.resources.eval.as_kubernetes(),
                security=task.security.model_dump(),
                image_pull_policy=image_pull_policy,
                egress_mode="deny",
            )
            evaluator.wait_ready()
            evaluator_digest, image_error = _runtime_image_evidence(
                evaluator,
                expected_runtime_digest or submission_digest,
                image_ref=runtime_image or task.image_tag,
            )
            if image_error:
                result = TestResults(
                    evaluation_mode="isolated-black-box",
                    infra_error=f"eval sandbox infrastructure failure: {image_error}",
                    runtime_image_digest=evaluator_digest,
                )
            else:
                link = create_black_box_link(
                    evaluator.name,
                    submission.name,
                    configuration.submission_port,
                )
                address = submission.ip_address()
                host = f"[{address}]" if ":" in address else address
                submission_url = (
                    f"http://{host}:{configuration.submission_port}"
                )
                started = submission.exec(
                    "touch /tmp/agent-eval-start", timeout=30
                )
                if started.returncode != 0:
                    error = _sandbox_infra_error(
                        "submission", submission, started.returncode
                    ) or (
                        "could not start isolated submission process "
                        f"(exit {started.returncode})"
                    )
                    result = TestResults(
                        evaluation_mode="isolated-black-box",
                        command_exit_code=started.returncode,
                        infra_error=error,
                        runtime_image_digest=evaluator_digest,
                    )
                else:
                    ready = _wait_for_submission_readiness(
                        evaluator,
                        address=address,
                        port=configuration.submission_port,
                        path=configuration.readiness.path,
                        timeout_seconds=configuration.readiness.timeout_seconds,
                    )
                    result = _run_hidden_tests_in_pod(
                        task,
                        evaluator,
                        run_dir,
                        evaluator_digest,
                        workspace=None,
                        isolated_black_box=True,
                        submission_url=submission_url,
                    )
                    if not ready:
                        with (run_dir / "eval-output.txt").open("a") as output_file:
                            output_file.write(
                                "\nsubmission readiness timed out; hidden tests "
                                "still ran for correctness evidence\n"
                            )
    except UnsafeArchiveError as exc:
        error = f"unsafe isolated evaluator archive: {exc}"
        result = TestResults(
            evaluation_mode="isolated-black-box",
            command_exit_code=126,
            integrity_error=error,
            failures=[error],
        )
    except (KubeError, subprocess.TimeoutExpired, OSError) as exc:
        error = None
        if evaluator is not None:
            error = _sandbox_infra_error("eval", evaluator)
        if error is None and submission is not None:
            error = _sandbox_infra_error("submission", submission)
        if error is None:
            error = (
                "isolated eval sandbox setup failed: "
                f"{type(exc).__name__}: {str(exc)[:500]}"
            )
        (run_dir / "eval-output.txt").write_text(f"{error}\n")
        result = TestResults(
            evaluation_mode="isolated-black-box",
            infra_error=error,
        )
    finally:
        for resource, label in (
            (evaluator, "isolated evaluator pod"),
            (link, "isolated evaluator network link"),
            (submission, "isolated submission pod"),
        ):
            if resource is None:
                continue
            cleanup_error = _delete_with_retries(resource, label)
            if cleanup_error:
                if result is None:
                    result = TestResults(evaluation_mode="isolated-black-box")
                _append_cleanup_error(result, run_dir, cleanup_error)
    assert result is not None
    result.submission_runtime_image_digest = submission_digest
    return result


def run_eval_phase(
    task: Task,
    workspace: Path,
    run_dir: Path,
    *,
    expected_runtime_digest: str | None = None,
    runtime_image: str | None = None,
    image_pull_policy: str = "IfNotPresent",
) -> TestResults:
    """Evaluate one produced workspace under the task's explicit trust mode."""

    arguments = {
        "expected_runtime_digest": expected_runtime_digest,
        "runtime_image": runtime_image,
        "image_pull_policy": image_pull_policy,
    }
    if task.evaluation.mode == "isolated-black-box":
        return _run_isolated_black_box_eval_phase(
            task, workspace, run_dir, **arguments
        )
    return _run_cooperative_eval_phase(task, workspace, run_dir, **arguments)


# derived artifacts the agent's tooling generates; excluded from diffing
JUNK_DIR_PATTERNS = (
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".git",
    "node_modules",
    ".venv",
    ".codex",
    ".claude",
    "*.pyc",
)


@dataclass(frozen=True)
class _CappedGitResult:
    returncode: int | None
    error_code: str | None
    stderr: str


def _kill_process_group(process: subprocess.Popen) -> None:
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(ProcessLookupError):
        process.kill()
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=5)


def _stream_git_output(
    command: list[str],
    *,
    cwd: Path,
    destination: Path,
    maximum_bytes: int,
) -> _CappedGitResult:
    """Stream untrusted git output to a bounded artifact with a hard deadline."""

    stderr = bytearray()
    written = 0
    error_code: str | None = None
    returncode: int | None = None
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("wb") as output:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            assert process.stdout is not None
            assert process.stderr is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            deadline = time.monotonic() + DIFF_TIMEOUT_SECONDS
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        error_code = "timeout"
                        break
                    events = selector.select(min(0.2, remaining))
                    for key, _ in events:
                        chunk = os.read(key.fd, 64 * 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        if key.data == "stdout":
                            room = maximum_bytes - written
                            if room > 0:
                                retained = chunk[:room]
                                output.write(retained)
                                written += len(retained)
                            if len(chunk) > room:
                                error_code = "output_limit"
                                break
                        else:
                            room = DIFF_STDERR_MAX_BYTES - len(stderr)
                            if room > 0:
                                stderr.extend(chunk[:room])
                            if len(chunk) > room:
                                error_code = "output_limit"
                                break
                    if error_code is not None:
                        break
                if error_code is not None:
                    _kill_process_group(process)
                else:
                    remaining = max(0.0, deadline - time.monotonic())
                    try:
                        returncode = process.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        error_code = "timeout"
                        _kill_process_group(process)
                output.flush()
                os.fsync(output.fileno())
            finally:
                selector.close()
                for pipe in (process.stdout, process.stderr):
                    if not pipe.closed:
                        pipe.close()
                if process.poll() is None:
                    _kill_process_group(process)
    except OSError as exc:
        return _CappedGitResult(
            returncode=None,
            error_code="git_error",
            stderr=type(exc).__name__,
        )

    if error_code is None and returncode not in (0, 1):
        error_code = "git_error"
    return _CappedGitResult(
        returncode=returncode,
        error_code=error_code,
        stderr=stderr.decode("utf-8", errors="replace"),
    )


def compute_diff(starter: Path, produced: Path, run_dir: Path) -> DiffStats:
    """Diff the starter workspace against what the agent produced, ignoring
    derived artifacts (bytecode caches, agent config dirs, etc.)."""
    with tempfile.TemporaryDirectory(prefix="agent-eval-diff-") as tmp:
        temporary = Path(tmp)
        ignore = shutil.ignore_patterns(*JUNK_DIR_PATTERNS)
        shutil.copytree(starter, temporary / "a", ignore=ignore, symlinks=True)
        shutil.copytree(produced, temporary / "b", ignore=ignore, symlinks=True)

        base_command = [
            "git",
            "-c",
            "core.quotePath=false",
            "diff",
            "--no-index",
        ]
        diff_result = _stream_git_output(
            [*base_command, "a", "b"],
            cwd=temporary,
            destination=run_dir / "workspace.diff",
            maximum_bytes=DIFF_MAX_BYTES,
        )
        numstat_path = temporary / "workspace.numstat"
        numstat_result = _stream_git_output(
            [*base_command, "--numstat", "a", "b"],
            cwd=temporary,
            destination=numstat_path,
            maximum_bytes=DIFF_NUMSTAT_MAX_BYTES,
        )
        stats = DiffStats()
        error_code = diff_result.error_code or numstat_result.error_code
        if error_code is not None:
            stats.complete = False
            stats.error_code = error_code
        for line in numstat_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                try:
                    added = int(parts[0]) if parts[0] != "-" else 0
                    removed = int(parts[1]) if parts[1] != "-" else 0
                except ValueError:
                    stats.complete = False
                    stats.error_code = "git_error"
                    continue
                stats.files_changed += 1
                stats.lines_added += added
                stats.lines_removed += removed
        return stats


def evaluate_workspace(
    task: Task,
    workspace: Path,
    *,
    agent: str = "external",
    trial: int = 1,
    run_id: str | None = None,
    record: RunRecord | None = None,
    run_scans: bool = True,
    run_judge: bool = True,
    audit: AuditChain | None = None,
    _credential_redactor: CredentialRedactor | None = None,
) -> RunRecord:
    """Eval pipeline on an already-produced workspace: tests, diff, scans, judge."""
    if record is None:
        record = RunRecord(
            run_id=run_id or new_run_id(task, agent),
            task_id=task.id,
            agent=agent,
            trial=trial,
            started_at=now_iso(),
        )
    _set_evaluation_spec_digest(
        task,
        record,
        run_scans=run_scans,
        run_judge=run_judge,
    )
    run_dir = record.run_dir
    prepare_run_dir(record)
    _audit_event(
        record,
        audit,
        "evaluation.started",
        {"task_id": task.id, "trial": record.trial},
    )

    integrity_error = _workspace_safety_error(workspace)
    if task.evaluation.mode == "cooperative" and integrity_error is None:
        integrity_error = _evaluator_control_error(task, workspace)
    if integrity_error:
        (run_dir / "eval-output.txt").write_text(f"REJECTED: {integrity_error}\n")
        record.correctness = TestResults(
            evaluation_mode=task.evaluation.mode,
            command_exit_code=126,
            integrity_error=integrity_error,
            failures=[integrity_error],
        )
        _audit_event(
            record,
            audit,
            "tests.completed",
            {"status": "integrity_rejected", "resolved": False},
        )
        _audit_event(record, audit, "scanners.completed", {"status": "skipped"})
        _audit_event(record, audit, "judge.skipped", {"reason_code": "integrity"})
        _capture_provenance(task, record)
        return _complete_record(
            task,
            record,
            audit,
            credential_redactor=_credential_redactor,
        )

    governed_image_digest = (
        record.governance.task_image_digest if record.governance is not None else None
    )
    governed_image_ref = (
        record.governance.task_image_ref if record.governance is not None else None
    )
    if governed_image_digest is None:
        ensure_image(task)
    else:
        ensure_image(
            task,
            expected_digest=governed_image_digest,
            image_ref=governed_image_ref,
        )
    _capture_provenance(task, record)
    record.correctness = run_eval_phase(
        task,
        workspace,
        run_dir,
        expected_runtime_digest=(
            governed_image_digest
            or record.efficiency.runtime_image_digest
            or record.provenance.local_image_digest
        ),
        runtime_image=governed_image_ref,
        image_pull_policy="Never" if governed_image_ref is not None else "IfNotPresent",
    )
    record.provenance.agent_image_digest = record.efficiency.runtime_image_digest
    record.provenance.eval_image_digest = record.correctness.runtime_image_digest
    record.provenance.submission_image_digest = (
        record.correctness.submission_runtime_image_digest
    )
    record.provenance.image_digest = (
        governed_image_digest
        or record.correctness.runtime_image_digest
        or record.efficiency.runtime_image_digest
    )
    if record.efficiency.infra_error and record.correctness.infra_error is None:
        record.correctness.infra_error = record.efficiency.infra_error
    _audit_event(
        record,
        audit,
        "tests.completed",
        {
            "status": (
                "infrastructure_error"
                if record.correctness.infra_error
                else "completed"
            ),
            "resolved": record.correctness.resolved,
            "passed": record.correctness.passed,
            "total": record.correctness.total,
            "command_exit_code": record.correctness.command_exit_code,
        },
    )
    record.diff = compute_diff(task.workspace_dir, workspace, run_dir)
    if not record.diff.complete:
        diff_error = (
            "workspace diff evidence incomplete: "
            f"{record.diff.error_code or 'unknown_error'}"
        )
        if record.correctness.integrity_error:
            record.correctness.integrity_error += f"; {diff_error}"
        else:
            record.correctness.integrity_error = diff_error
        if diff_error not in record.correctness.failures:
            record.correctness.failures.append(diff_error)

    if run_scans:
        from .evaluators.scanners import run_scanners

        # The judge receives the exact diff and task context, not only the
        # final workspace. Screen every dynamic prompt field so removed
        # credentials and secret-bearing diff metadata cannot reach it.
        with tempfile.TemporaryDirectory(prefix="agent-eval-judge-screen-") as tmp:
            scan_root = Path(tmp) / "workspace"
            shutil.copytree(workspace, scan_root)
            shutil.copyfile(
                run_dir / "workspace.diff",
                scan_root / ".agent-eval-workspace.diff",
            )
            (scan_root / ".agent-eval-model-context.txt").write_text(
                f"{task.prompt}\n{json.dumps(task.judge.weights, sort_keys=True)}\n"
            )
            record.scans = run_scanners(scan_root, run_dir, task.language)
            prefix = str(scan_root.resolve()) + "/"
            for finding in record.scans.findings:
                if isinstance(finding.get("path"), str):
                    finding["path"] = finding["path"].removeprefix(prefix)
        record.provenance.tool_versions.update(
            {
                f"scanner:{name}": version
                for name, version in record.scans.scanner_versions.items()
            }
        )
        record.provenance.tool_versions.update(
            {
                f"scanner-config:{name}": identity
                for name, identity in record.scans.scanner_configs.items()
            }
        )
        _audit_event(
            record,
            audit,
            "scanners.completed",
            {
                "status": "completed",
                "finding_count": len(record.scans.findings),
                "scanner_count": len(record.scans.scanner_status),
            },
        )
    else:
        _audit_event(record, audit, "scanners.completed", {"status": "skipped"})
    if run_judge and task.judge.enabled:
        credential_screen_error = _judge_credential_screen_error(
            task,
            run_dir,
            _credential_redactor,
        )
        if _judge_input_is_safe(record) and credential_screen_error is None:
            from .evaluators.judge import run_judge as judge_workspace

            record.judge = judge_workspace(
                task,
                run_dir,
                backend=(
                    record.governance.judge_backend
                    if record.governance is not None
                    else task.judge.backend
                ),
                model=(
                    record.governance.judge_model
                    if record.governance is not None
                    else task.judge.model
                ),
            )
            _audit_event(
                record,
                audit,
                "judge.completed",
                {
                    "status": "completed",
                    "score_available": record.judge.weighted_score is not None,
                    "dimension_count": len(record.judge.scores),
                    "backend": record.judge.backend,
                    "model": record.judge.model,
                },
            )
        else:
            reason = credential_screen_error or (
                "judge skipped: complete diff evidence and a successful zero-secret "
                "gitleaks scan are required before workspace.diff can be sent to a "
                "model"
            )
            (run_dir / "judge-skipped.txt").write_text(reason + "\n")
            console.print(f"[yellow]{reason}[/yellow]")
            _audit_event(
                record,
                audit,
                "judge.skipped",
                {"reason_code": "secret_screen_incomplete"},
            )
    else:
        _audit_event(
            record,
            audit,
            "judge.skipped",
            {"reason_code": "disabled"},
        )

    if task.challenges:
        from .assurance import evaluate_challenges

        record.assurance = evaluate_challenges(
            task.challenges, workspace, run_dir, record
        )

    return _complete_record(
        task,
        record,
        audit,
        credential_redactor=_credential_redactor,
    )


def _run_agent_trial_impl(
    task: Task,
    adapter,
    *,
    trial: int = 1,
    model: str | None = None,
    run_scans: bool = True,
    run_judge: bool = True,
    rebuild: bool = False,
    experiment_id: str | None = None,
    governance_request: EvaluationRequest | None = None,
    governance_bundle: GovernanceBundle | None = None,
    governance_decision: PolicyDecision | None = None,
    governance_execution_decision: PolicyDecision | None = None,
    _governed_snapshot_root: Path | None = None,
    _workspace_snapshot_root: Path | None = None,
) -> RunRecord:
    """Full-harness trial: launch the coding agent in a sandbox pod, snapshot
    its workspace, then evaluate that workspace."""
    supplied_governance = (
        governance_request is not None,
        governance_bundle is not None,
        governance_decision is not None,
    )
    if any(supplied_governance) and not all(supplied_governance):
        raise ValueError(
            "governance request, policy bundle, and decision must be supplied together"
        )
    if governance_execution_decision is not None and not all(supplied_governance):
        raise ValueError(
            "an execution decision requires its governance request, policy "
            "bundle, and preflight decision"
        )
    if _workspace_snapshot_root is None:
        raise RuntimeError("agent trial has no private workspace staging root")
    governance = None
    execution_decision = governance_execution_decision
    task_image_digest = None
    task_image_ref = None
    task_image_platform = None
    if all(supplied_governance):
        assert governance_request is not None
        assert governance_bundle is not None
        assert governance_decision is not None
        _validate_governance_decision(
            task,
            agent=adapter.name,
            model=model,
            trial=trial,
            run_scans=run_scans,
            run_judge=run_judge,
            request=governance_request,
            bundle=governance_bundle,
            decision=governance_decision,
            decision_stage="preflight",
            task_image_digest=None,
            task_image_ref=None,
            task_image_platform=None,
        )
        if execution_decision is None:
            execution_decision = prepare_governed_execution(
                task,
                agent=adapter.name,
                model=model,
                run_scans=run_scans,
                run_judge=run_judge,
                request=governance_request,
                bundle=governance_bundle,
                preflight_decision=governance_decision,
            )
        task_image_digest = execution_decision.sanitized_input.get("task_image_digest")
        task_image_ref = execution_decision.sanitized_input.get("task_image_ref")
        task_image_platform = execution_decision.sanitized_input.get(
            "task_image_platform"
        )
        if not all(
            isinstance(value, str)
            for value in (task_image_digest, task_image_ref, task_image_platform)
        ):
            raise ValueError("execution decision has no complete task image identity")
        if _governed_snapshot_root is None:
            raise RuntimeError("governed trial has no private snapshot root")
        task = _snapshot_governed_task(
            task,
            _governed_snapshot_root,
            expected_tree_digest=governance_decision.sanitized_input[
                "task_tree_sha256"
            ],
            expected_execution_digest=governance_decision.sanitized_input[
                "execution_spec_digest"
            ],
            run_scans=governance_decision.sanitized_input["run_scans"],
            run_judge=governance_decision.sanitized_input["run_judge"],
        )
        governance = _governance_evidence(
            task,
            agent=adapter.name,
            model=model,
            trial=trial,
            run_scans=run_scans,
            run_judge=run_judge,
            task_image_digest=task_image_digest,
            task_image_ref=task_image_ref,
            task_image_platform=task_image_platform,
            preflight_decision=governance_decision,
            request=governance_request,
            bundle=governance_bundle,
            decision=execution_decision,
        )
        task = _governed_task(task, execution_decision)
    elif rebuild:
        ensure_image(task, rebuild=True)
    else:
        ensure_image(task)

    record = RunRecord(
        run_id=new_run_id(task, adapter.name),
        task_id=task.id,
        agent=adapter.name,
        trial=trial,
        experiment_id=experiment_id,
        started_at=now_iso(),
        governance=governance,
    )
    _set_evaluation_spec_digest(
        task,
        record,
        run_scans=run_scans,
        run_judge=run_judge,
    )
    record.efficiency.requested_model = model
    if governance is not None:
        record.provenance.image_tag = governance.task_image_ref
        record.provenance.image_digest = governance.task_image_digest
        record.provenance.local_image_digest = governance.task_image_digest
    run_dir = record.run_dir
    prepare_run_dir(record, exist_ok=False)

    audit = None
    if governance is not None:
        assert governance_request is not None
        assert governance_bundle is not None
        assert governance_decision is not None
        assert execution_decision is not None
        write_canonical_json(run_dir / "governance-request.json", governance_request)
        write_canonical_json(run_dir / "policy-bundle.json", governance_bundle)
        write_canonical_json(run_dir / "preflight-decision.json", governance_decision)
        write_canonical_json(run_dir / "policy-decision.json", execution_decision)
        audit = AuditChain(
            run_dir / "audit.jsonl",
            record.run_id,
            trace_id=execution_decision.trace_id,
        )
        _audit_event(
            record,
            audit,
            "evaluation.requested",
            {
                "request_id": str(governance_request.request_id),
                "task_id": task.id,
                "agent": adapter.name,
                "model": model,
                "trial": trial,
                "run_scans": governance.run_scans,
                "run_judge": governance.run_judge,
                "judge_backend": governance.judge_backend,
                "judge_model": governance.judge_model,
                "task_tree_sha256": governance_decision.sanitized_input[
                    "task_tree_sha256"
                ],
                "execution_spec_digest": governance_decision.sanitized_input[
                    "execution_spec_digest"
                ],
                "task_image_digest": governance.task_image_digest,
                "task_image_ref": governance.task_image_ref,
                "task_image_platform": governance.task_image_platform,
            },
        )
        _audit_event(
            record,
            audit,
            "policy.admitted",
            {
                "decision_id": str(execution_decision.decision_id),
                "request_digest": execution_decision.request_digest,
                "policy_id": execution_decision.policy_id,
                "policy_revision": execution_decision.policy_revision,
                "policy_digest": execution_decision.policy_digest,
                "task_registry_id": execution_decision.task_registry_id,
                "task_registry_revision": execution_decision.task_registry_revision,
                "task_registry_digest": execution_decision.task_registry_digest,
                "registry_id": execution_decision.registry_id,
                "registry_revision": execution_decision.registry_revision,
                "registry_digest": execution_decision.registry_digest,
            },
        )
        if record.provenance.audit_error:
            record.correctness = TestResults(infra_error=record.provenance.audit_error)
            return _complete_record(task, record, audit)

    _audit_event(
        record,
        audit,
        "agent.started",
        {"agent": adapter.name, "model": model, "trial": trial},
    )
    if record.provenance.audit_error:
        record.correctness = TestResults(infra_error=record.provenance.audit_error)
        return _complete_record(task, record, audit)

    material = None
    credential_redactor = None
    secret = None
    proxy = None
    pod = None
    produced = run_dir / "workspace"
    staged_workspace = _workspace_snapshot_root / "workspace"
    snapshot_available = False
    snapshot_integrity_error = None
    try:
        if governance is not None:
            ensure_image(
                task,
                expected_digest=governance.task_image_digest,
                image_ref=governance.task_image_ref,
            )
        ensure_namespace()
        if adapter.name in _PROVIDER_DOMAINS or os.environ.get(
            "AGENT_EVAL_CREDENTIAL_COMMAND"
        ):
            material = load_trial_credentials(
                adapter.name,
                minimum_ttl_seconds=task.timeouts.agent_seconds + 300,
            )
            if material is not None:
                credential_redactor = CredentialRedactor.from_material(material)
        secret = (
            create_trial_secret(material, run_id=record.run_id) if material else None
        )
        if material:
            record.provenance.credential_source = material.source
            record.provenance.credential_mode = material.mode
            record.provenance.credential_expires_at = material.expires_at
        domains, _ = _governance_network_evidence(task, adapter.name)
        if task.network.agent_mode == "proxy" and domains:
            proxy = create_egress_proxy(task.network.proxy_image, domains)
        proxy_env = {}
        if proxy:
            proxy_env = {
                "HTTP_PROXY": proxy.endpoint,
                "HTTPS_PROXY": proxy.endpoint,
                "http_proxy": proxy.endpoint,
                "https_proxy": proxy.endpoint,
            }
        pod = create_sandbox_pod(
            "agent",
            governance.task_image_ref if governance is not None else task.image_tag,
            env_from_secret=secret.name if secret else None,
            credential_env_keys=material.env_keys if material else (),
            credential_file_items=material.file_items if material else {},
            extra_env=proxy_env,
            active_deadline=task.timeouts.agent_seconds + 900,
            resources=task.resources.agent.as_kubernetes(),
            security=task.security.model_dump(),
            egress_mode=(
                "proxy"
                if proxy
                else "deny"
                if task.network.agent_mode == "proxy"
                else "open"
            ),
            proxy_id=proxy.name if proxy else None,
            image_pull_policy="Never" if governance is not None else "IfNotPresent",
        )
        try:
            pod.wait_ready()
            expected_runtime_digest = (
                governance.task_image_digest
                if governance is not None
                else _image_digest(task.image_tag)
            )
            if expected_runtime_digest is None:
                raise KubeError("local task image digest is unavailable")
            runtime_digest, image_error = _runtime_image_evidence(
                pod,
                expected_runtime_digest,
                image_ref=(
                    governance.task_image_ref
                    if governance is not None
                    else task.image_tag
                ),
            )
            if image_error:
                raise KubeError(image_error)
            pod.copy_dir_to(task.workspace_dir, "/workspace")
            with tempfile.TemporaryDirectory() as tmp:
                from .agents import PROMPT_PATH

                prompt_dir = Path(tmp)
                (prompt_dir / Path(PROMPT_PATH).name).write_text(task.prompt)
                pod.copy_dir_to(prompt_dir, str(Path(PROMPT_PATH).parent))
            if hasattr(adapter, "prepare"):
                adapter.prepare(pod)

            console.print(
                f"running [bold]{adapter.name}[/bold] in sandbox pod "
                f"(timeout {task.timeouts.agent_seconds}s)..."
            )
            start = time.monotonic()
            timed_out = False
            try:
                proc = pod.exec(
                    adapter.build_command(model),
                    timeout=task.timeouts.agent_seconds,
                    env=adapter.env,
                )
                _write_redacted_private(
                    run_dir / "transcript.jsonl",
                    proc.stdout,
                    credential_redactor,
                )
                _write_redacted_private(
                    run_dir / "agent-stderr.log",
                    proc.stderr,
                    credential_redactor,
                )
                record.efficiency = adapter.parse_transcript(
                    run_dir / "transcript.jsonl"
                )
                record.efficiency.requested_model = model
                record.efficiency.runtime_image_digest = runtime_digest
                record.efficiency.agent_exit_code = proc.returncode
                record.efficiency.infra_error = _sandbox_infra_error(
                    "agent", pod, proc.returncode
                )
            except subprocess.TimeoutExpired as e:
                timed_out = True
                _write_redacted_private(
                    run_dir / "transcript.jsonl",
                    e.stdout,
                    credential_redactor,
                )
                _write_redacted_private(
                    run_dir / "agent-stderr.log",
                    e.stderr,
                    credential_redactor,
                    suffix=b"\nAGENT TIMED OUT",
                )
                record.efficiency = adapter.parse_transcript(
                    run_dir / "transcript.jsonl"
                )
                record.efficiency.requested_model = model
                record.efficiency.runtime_image_digest = runtime_digest
                record.efficiency.timed_out = True
                record.efficiency.infra_error = _sandbox_infra_error("agent", pod)
                if record.efficiency.infra_error is None:
                    record.efficiency.infra_error = (
                        f"agent timed out after {task.timeouts.agent_seconds}s"
                    )
            except CommandOutputLimitError as exc:
                _write_redacted_private(
                    run_dir / "transcript.jsonl",
                    exc.stdout,
                    credential_redactor,
                )
                _write_redacted_private(
                    run_dir / "agent-stderr.log",
                    exc.stderr,
                    credential_redactor,
                    suffix=b"\nAGENT OUTPUT CAP REACHED\n",
                )
                record.efficiency = adapter.parse_transcript(
                    run_dir / "transcript.jsonl"
                )
                record.efficiency.requested_model = model
                record.efficiency.runtime_image_digest = runtime_digest
                record.efficiency.infra_error = str(exc)
            record.efficiency.wall_time_s = round(time.monotonic() - start, 1)
            if timed_out:
                console.print(
                    "[yellow]agent timed out; evaluating partial work[/yellow]"
                )

            quiescence_error = _quiesce_agent_processes(pod)
            if quiescence_error is not None:
                if record.efficiency.infra_error:
                    record.efficiency.infra_error += f"; {quiescence_error}"
                else:
                    record.efficiency.infra_error = quiescence_error
            else:
                try:
                    pod.copy_dir_from("/workspace", staged_workspace)
                except UnsafeArchiveError as exc:
                    snapshot_integrity_error = (
                        f"unsafe agent workspace archive: {exc}"
                    )
                else:
                    try:
                        credential_hits = (
                            _credential_hits_in_tree(
                                staged_workspace,
                                credential_redactor,
                                maximum_bytes=MAX_SNAPSHOT_BYTES,
                                maximum_entries=MAX_SNAPSHOT_MEMBERS,
                                stop_after_first=True,
                            )
                            if credential_redactor is not None
                            else []
                        )
                        if credential_hits:
                            snapshot_integrity_error = (
                                "agent workspace contains projected credential material"
                            )
                            shutil.rmtree(staged_workspace, ignore_errors=True)
                        else:
                            _promote_credential_clean_workspace(
                                staged_workspace,
                                produced,
                            )
                            snapshot_available = True
                    except (CredentialRedactionError, UnsafeArchiveError) as exc:
                        snapshot_integrity_error = (
                            "agent workspace credential inspection failed: "
                            f"{type(exc).__name__}"
                        )
                        shutil.rmtree(staged_workspace, ignore_errors=True)
        except UnsafeArchiveError as exc:
            snapshot_integrity_error = f"unsafe agent workspace archive: {exc}"
        except (
            KubeError,
            subprocess.TimeoutExpired,
            RuntimeError,
            OSError,
            ValueError,
        ) as exc:
            error = _sandbox_infra_error("agent", pod)
            if error is None:
                error = (
                    f"agent trial setup failed: {type(exc).__name__}: {str(exc)[:500]}"
                )
            record.efficiency.infra_error = error
    except UnsafeArchiveError as exc:
        snapshot_integrity_error = f"unsafe agent workspace archive: {exc}"
    except (
        KubeError,
        subprocess.TimeoutExpired,
        RuntimeError,
        OSError,
        ValueError,
    ) as exc:
        error = _sandbox_infra_error("agent", pod) if pod else None
        if error is None:
            error = f"agent trial setup failed: {type(exc).__name__}: {str(exc)[:500]}"
        record.efficiency.infra_error = error
    finally:
        _enforce_governed_model_evidence(record)
        total_tokens = None
        if (
            record.efficiency.tokens_in is not None
            and record.efficiency.tokens_out is not None
        ):
            total_tokens = record.efficiency.tokens_in + record.efficiency.tokens_out
        _audit_event(
            record,
            audit,
            "agent.completed",
            {
                "status": (
                    "infrastructure_error"
                    if record.efficiency.infra_error
                    else "completed"
                ),
                "exit_code": record.efficiency.agent_exit_code,
                "timed_out": record.efficiency.timed_out,
                "snapshot_available": snapshot_available,
                "wall_time_s": record.efficiency.wall_time_s,
                "total_tokens": total_tokens,
            },
        )
        if proxy:
            try:
                _write_redacted_private(
                    run_dir / "egress-proxy.log",
                    proxy.logs(),
                    credential_redactor,
                )
            except Exception:
                proxy_log_error = (
                    "egress proxy log could not be safely persisted"
                )
                if record.efficiency.infra_error:
                    record.efficiency.infra_error += f"; {proxy_log_error}"
                else:
                    record.efficiency.infra_error = proxy_log_error
        cleanup_errors = []
        if pod and (error := _delete_with_retries(pod, "agent pod")):
            cleanup_errors.append(error)
        if proxy and (error := _delete_with_retries(proxy, "egress proxy")):
            cleanup_errors.append(error)
        if secret:
            if error := _delete_with_retries(secret, "credential Secret"):
                cleanup_errors.append(error)
        if cleanup_errors:
            cleanup_error = "; ".join(cleanup_errors)
            if record.efficiency.infra_error:
                record.efficiency.infra_error += f"; {cleanup_error}"
            else:
                record.efficiency.infra_error = cleanup_error
        _audit_event(
            record,
            audit,
            "cleanup.completed",
            {
                "status": "failed" if cleanup_errors else "completed",
                "failure_count": len(cleanup_errors),
            },
        )

    if not snapshot_available:
        if snapshot_integrity_error:
            record.correctness = TestResults(
                command_exit_code=126,
                integrity_error=snapshot_integrity_error,
                failures=[snapshot_integrity_error],
            )
        else:
            error = (
                record.efficiency.infra_error or "agent workspace snapshot unavailable"
            )
            record.correctness = TestResults(infra_error=error)
        _capture_provenance(task, record)
        if credential_redactor is None:
            return _complete_record(task, record, audit)
        return _complete_record(
            task,
            record,
            audit,
            credential_redactor=credential_redactor,
        )

    try:
        return evaluate_workspace(
            task,
            produced,
            record=record,
            run_scans=run_scans,
            run_judge=run_judge,
            audit=audit,
            _credential_redactor=credential_redactor,
        )
    except Exception as exc:
        if audit is None:
            raise
        error = f"governed evaluation failed: {type(exc).__name__}: {str(exc)[:500]}"
        record.correctness.infra_error = error
        _audit_event(
            record,
            audit,
            "evaluation.failed",
            {"exception_type": type(exc).__name__},
        )
        _capture_provenance(task, record)
        if credential_redactor is None:
            return _complete_record(task, record, audit)
        return _complete_record(
            task,
            record,
            audit,
            credential_redactor=credential_redactor,
        )


def run_agent_trial(
    task: Task,
    adapter,
    *,
    trial: int = 1,
    model: str | None = None,
    run_scans: bool = True,
    run_judge: bool = True,
    rebuild: bool = False,
    experiment_id: str | None = None,
    governance_request: EvaluationRequest | None = None,
    governance_bundle: GovernanceBundle | None = None,
    governance_decision: PolicyDecision | None = None,
    governance_execution_decision: PolicyDecision | None = None,
) -> RunRecord:
    """Run one trial and always remove any private governed task snapshot."""

    arguments = {
        "trial": trial,
        "model": model,
        "run_scans": run_scans,
        "run_judge": run_judge,
        "rebuild": rebuild,
        "experiment_id": experiment_id,
        "governance_request": governance_request,
        "governance_bundle": governance_bundle,
        "governance_decision": governance_decision,
        "governance_execution_decision": governance_execution_decision,
    }
    governed = any(
        value is not None
        for value in (
            governance_request,
            governance_bundle,
            governance_decision,
            governance_execution_decision,
        )
    )
    with tempfile.TemporaryDirectory(
        prefix="agent-eval-workspace-snapshot-"
    ) as workspace_temporary:
        workspace_snapshot_root = Path(workspace_temporary)
        os.chmod(workspace_snapshot_root, 0o700)
        if not governed:
            return _run_agent_trial_impl(
                task,
                adapter,
                **arguments,
                _workspace_snapshot_root=workspace_snapshot_root,
            )
        with tempfile.TemporaryDirectory(
            prefix="agent-eval-governed-task-"
        ) as temporary:
            return _run_agent_trial_impl(
                task,
                adapter,
                **arguments,
                _governed_snapshot_root=Path(temporary),
                _workspace_snapshot_root=workspace_snapshot_root,
            )


def validate_task(task: Task) -> RunRecord:
    """Overlay the oracle solution onto the starter workspace and require the
    hidden tests to pass. Proves the task + eval path work without any LLM."""
    problems = task.validate_layout()
    if problems:
        raise ValueError(f"task {task.id} layout invalid: {', '.join(problems)}")
    if not task.solution_dir.is_dir():
        raise ValueError(f"task {task.id} has no solution/ directory to validate with")

    ensure_image(task)
    expected_runtime_digest = _image_digest(task.image_tag)
    if expected_runtime_digest is None:
        raise ValueError(f"task {task.id} local image digest is unavailable")
    with tempfile.TemporaryDirectory(prefix="agent-eval-negative-control-") as tmp:
        baseline_dir = Path(tmp) / "baseline"
        baseline_dir.mkdir()
        baseline = run_eval_phase(
            task,
            task.workspace_dir,
            baseline_dir,
            expected_runtime_digest=expected_runtime_digest,
        )
    if baseline.infra_error:
        raise ValueError(
            f"task {task.id} starter negative control could not be evaluated: "
            f"{baseline.infra_error}"
        )
    if baseline.failed + baseline.errors == 0:
        raise ValueError(
            f"task {task.id} starter workspace must fail at least one hidden test"
        )

    with tempfile.TemporaryDirectory(prefix="agent-eval-oracle-") as tmp:
        oracle_ws = Path(tmp) / "workspace"
        shutil.copytree(task.workspace_dir, oracle_ws)
        shutil.copytree(task.solution_dir, oracle_ws, dirs_exist_ok=True)
        return evaluate_workspace(task, oracle_ws, agent="oracle",
                                  run_scans=False, run_judge=False)
