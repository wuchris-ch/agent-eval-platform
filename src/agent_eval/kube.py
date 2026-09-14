"""Thin kubectl wrapper. All cluster interaction shells out to kubectl; file
transfer uses tar pipes (more reliable than kubectl cp for directories)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid
from contextlib import closing, suppress
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from .task import DEFAULT_SANDBOX_RESOURCES

NAMESPACE = "agent-eval"
KUBE_CONTEXT = "k3d-agent-eval"
CREDENTIAL_MOUNT = "/var/run/agent-eval-credentials"
PROXY_PORT = 3128
PROXY_ACTIVE_DEADLINE_SECONDS = 3600
K3S_POD_CIDR = "10.42.0.0/16"
K3S_SERVICE_CIDR = "10.43.0.0/16"
K3S_CLUSTER_DNS_SERVICE_CIDR = "10.43.0.10/32"
# Squid checks these after resolving the request hostname. The list excludes
# destinations that must never be reachable through a task's domain allowlist,
# including the default k3s pod/service networks and common metadata services.
PROXY_BLOCKED_IPV4_CIDRS = (
    "0.0.0.0/8",  # current network and the unspecified address
    "10.0.0.0/8",  # RFC 1918; contains the k3s pod and service CIDRs
    "100.64.0.0/10",  # carrier-grade NAT and Alibaba metadata
    "127.0.0.0/8",  # loopback
    "168.63.129.16/32",  # Azure platform and metadata virtual address
    "169.254.0.0/16",  # link-local and common cloud metadata endpoints
    "172.16.0.0/12",  # RFC 1918
    "192.0.0.0/24",  # IETF protocol assignments and Oracle metadata
    "192.0.2.0/24",  # documentation
    "192.88.99.0/24",  # deprecated 6to4 relay anycast
    "192.168.0.0/16",  # RFC 1918
    "198.18.0.0/15",  # benchmark testing
    "198.51.100.0/24",  # documentation
    "203.0.113.0/24",  # documentation
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved and limited broadcast
)
PROXY_BLOCKED_IPV6_CIDRS = (
    "::/128",  # unspecified
    "::1/128",  # loopback
    "64:ff9b::/96",  # well-known NAT64 translation
    "64:ff9b:1::/48",  # local-use NAT64 translation
    "100::/64",  # discard-only
    "2001::/23",  # IETF special-use, including benchmark and ORCHID ranges
    "2001:db8::/32",  # documentation
    "2002::/16",  # deprecated 6to4
    "3fff::/20",  # documentation
    "fc00::/7",  # unique-local, including AWS IPv6 metadata
    "fe80::/10",  # link-local
    "fec0::/10",  # deprecated site-local
    "ff00::/8",  # multicast
)
# Kubernetes egress is allowlisted to global unicast IPv6. These special-use
# ranges sit inside 2000::/3 and therefore need explicit exclusions.
PROXY_PUBLIC_IPV6_CIDR = "2000::/3"
PROXY_PUBLIC_IPV6_EXCEPT_CIDRS = (
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
)
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_MEMBERS = 50_000
MAX_SNAPSHOT_PATH_BYTES = 4_096
MAX_ARCHIVE_STDERR_BYTES = 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
TRIAL_SECRET_ROLLBACK_ATTEMPTS = 3
POD_SECURITY_LEVEL = "restricted"
# cluster.py pins k3s v1.35.5+k3s1 by its multi-platform OCI index digest.
POD_SECURITY_VERSION = "v1.35"
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_IMAGE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINERD_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_CONTAINERD_INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_QUOTA_COUNT_DEFAULTS = {
    "pods": ("AGENT_EVAL_QUOTA_PODS", 32, 256),
    "secrets": ("AGENT_EVAL_QUOTA_SECRETS", 64, 512),
    "configmaps": ("AGENT_EVAL_QUOTA_CONFIGMAPS", 32, 256),
    "services": ("AGENT_EVAL_QUOTA_SERVICES", 16, 128),
}
_QUOTA_RESOURCE_DEFAULTS = {
    "cpu": (
        ("AGENT_EVAL_QUOTA_REQUESTS_CPU", 8, 256),
        ("AGENT_EVAL_QUOTA_LIMITS_CPU", 32, 512),
        "",
    ),
    "memory": (
        ("AGENT_EVAL_QUOTA_REQUESTS_MEMORY_GI", 16, 1024),
        ("AGENT_EVAL_QUOTA_LIMITS_MEMORY_GI", 64, 2048),
        "Gi",
    ),
    "ephemeral-storage": (
        ("AGENT_EVAL_QUOTA_REQUESTS_EPHEMERAL_STORAGE_GI", 32, 2048),
        ("AGENT_EVAL_QUOTA_LIMITS_EPHEMERAL_STORAGE_GI", 128, 4096),
        "Gi",
    ),
}
DEFAULT_SECURITY = {
    "run_as_non_root": True,
    "run_as_user": 10001,
    "run_as_group": 10001,
    "read_only_root_filesystem": True,
}


class KubeError(RuntimeError):
    pass


class UnsafeArchiveError(KubeError):
    """Raised when an untrusted pod snapshot is unsafe to extract."""


class CommandOutputLimitError(KubeError):
    """Raised after a pod command exceeds the bounded host output capture."""

    def __init__(self, stdout: bytes, stderr: bytes):
        super().__init__(
            f"pod command output exceeded {MAX_COMMAND_OUTPUT_BYTES} bytes"
        )
        self.stdout = stdout
        self.stderr = stderr


def _normalize_containerd_image_ref(image_ref: str) -> str | None:
    """Apply Docker's familiar-name normalization used by containerd."""

    if (
        not image_ref
        or any(character.isspace() for character in image_ref)
        or "@" in image_ref
    ):
        return None
    first, separator, _rest = image_ref.partition("/")
    if not separator:
        return f"docker.io/library/{image_ref}"
    if first == "localhost" or "." in first or ":" in first:
        return image_ref
    return f"docker.io/{image_ref}"


def containerd_image_manifest_identity(
    node_name: str,
    image_ref: str,
    *,
    expected_manifest_digest: str | None = None,
) -> tuple[str, str] | None:
    """Resolve a node ref to one Linux manifest and its config digest."""

    normalized_ref = _normalize_containerd_image_ref(image_ref)
    if (
        normalized_ref is None
        or (expected_manifest_digest is not None
        and _IMAGE_DIGEST_RE.fullmatch(expected_manifest_digest) is None)
    ):
        return None
    try:
        listed = _run_bounded_command(
            [
                "docker",
                "exec",
                node_name,
                "ctr",
                "-n",
                "k8s.io",
                "images",
                "list",
                f"name=={normalized_ref}",
            ],
            timeout=30,
        )
        listed_output = listed.stdout.decode("utf-8")
    except (
        CommandOutputLimitError,
        OSError,
        subprocess.TimeoutExpired,
        UnicodeError,
    ):
        return None
    if listed.returncode != 0:
        return None
    lines = [line for line in listed_output.splitlines() if line.strip()]
    expected_header = [
        "REF",
        "TYPE",
        "DIGEST",
        "SIZE",
        "PLATFORMS",
        "LABELS",
    ]
    if not lines or lines[0].split() != expected_header:
        return None
    rows = [line.split() for line in lines[1:]]
    if len(rows) != 1 or len(rows[0]) < 3:
        return None
    observed_ref, media_type, manifest_digest = rows[0][:3]
    if (
        observed_ref != normalized_ref
        or media_type
        not in _CONTAINERD_MANIFEST_MEDIA_TYPES | _CONTAINERD_INDEX_MEDIA_TYPES
        or _IMAGE_DIGEST_RE.fullmatch(manifest_digest) is None
    ):
        return None

    def content_for(digest: str) -> bytes | None:
        try:
            content = _run_bounded_command(
                [
                    "docker",
                    "exec",
                    node_name,
                    "ctr",
                    "-n",
                    "k8s.io",
                    "content",
                    "get",
                    digest,
                ],
                timeout=30,
            )
        except (CommandOutputLimitError, OSError, subprocess.TimeoutExpired):
            return None
        if content.returncode != 0:
            return None
        if "sha256:" + hashlib.sha256(content.stdout).hexdigest() != digest:
            return None
        return content.stdout

    manifest_content = content_for(manifest_digest)
    if manifest_content is None:
        return None
    try:
        manifest = json.loads(manifest_content)
    except (json.JSONDecodeError, TypeError, UnicodeError):
        return None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != media_type
    ):
        return None

    if media_type in _CONTAINERD_INDEX_MEDIA_TYPES:
        descriptors = manifest.get("manifests")
        if not isinstance(descriptors, list):
            return None
        candidates = []
        for descriptor in descriptors:
            if not isinstance(descriptor, dict):
                return None
            platform = descriptor.get("platform")
            if not isinstance(platform, dict):
                continue
            if (
                platform.get("os") == "linux"
                and platform.get("architecture") not in {None, "", "unknown"}
                and descriptor.get("mediaType") in _CONTAINERD_MANIFEST_MEDIA_TYPES
                and isinstance(descriptor.get("digest"), str)
                and _IMAGE_DIGEST_RE.fullmatch(descriptor["digest"]) is not None
            ):
                candidates.append(descriptor)
        if expected_manifest_digest is not None:
            candidates = [
                descriptor
                for descriptor in candidates
                if descriptor["digest"] == expected_manifest_digest
            ]
        if len(candidates) != 1:
            return None
        selected = candidates[0]
        media_type = selected["mediaType"]
        manifest_digest = selected["digest"]
        manifest_content = content_for(manifest_digest)
        if manifest_content is None:
            return None
        try:
            manifest = json.loads(manifest_content)
        except (json.JSONDecodeError, TypeError, UnicodeError):
            return None
        if not isinstance(manifest, dict):
            return None

    try:
        config_digest = manifest["config"]["digest"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != media_type
        or media_type not in _CONTAINERD_MANIFEST_MEDIA_TYPES
        or not isinstance(config_digest, str)
        or _IMAGE_DIGEST_RE.fullmatch(config_digest) is None
        or (expected_manifest_digest is not None
        and manifest_digest != expected_manifest_digest)
    ):
        return None
    return manifest_digest, config_digest


def runtime_class_name() -> str | None:
    """Return the validated sandbox RuntimeClass, if one is configured."""

    value = os.environ.get("AGENT_EVAL_RUNTIME_CLASS")
    if value is None:
        return None
    if _DNS_LABEL_RE.fullmatch(value) is None:
        raise ValueError(
            "AGENT_EVAL_RUNTIME_CLASS must be a lowercase DNS label of at "
            "most 63 characters"
        )
    return value


def _bounded_positive_env(name: str, default: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    if re.fullmatch(r"[1-9][0-9]*", raw) is None:
        raise ValueError(f"{name} must be a positive base-10 integer")
    value = int(raw)
    if value > maximum:
        raise ValueError(f"{name} must not exceed {maximum}")
    return value


def _namespace_manifest() -> dict:
    labels = {
        f"pod-security.kubernetes.io/{mode}": POD_SECURITY_LEVEL
        for mode in ("enforce", "audit", "warn")
    }
    labels.update(
        {
            f"pod-security.kubernetes.io/{mode}-version": POD_SECURITY_VERSION
            for mode in ("enforce", "audit", "warn")
        }
    )
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": NAMESPACE, "labels": labels},
    }


def _resource_quota_manifest() -> dict:
    hard = {
        resource: str(_bounded_positive_env(env_name, default, maximum))
        for resource, (env_name, default, maximum) in _QUOTA_COUNT_DEFAULTS.items()
    }
    for resource, (
        request_config,
        limit_config,
        suffix,
    ) in _QUOTA_RESOURCE_DEFAULTS.items():
        requests = _bounded_positive_env(*request_config)
        limits = _bounded_positive_env(*limit_config)
        if requests > limits:
            raise ValueError(
                f"namespace quota requests.{resource} cannot exceed limits.{resource}"
            )
        hard[f"requests.{resource}"] = f"{requests}{suffix}"
        hard[f"limits.{resource}"] = f"{limits}{suffix}"
    return {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": "agent-eval-quota"},
        "spec": {"hard": hard},
    }


def _bounded_output(streams: tuple, maximum: int) -> tuple[bytes, bytes]:
    remaining = maximum
    captured = []
    for stream in streams:
        stream.seek(0)
        data = stream.read(remaining)
        captured.append(data)
        remaining -= len(data)
    return captured[0], captured[1]


def _run_bounded_command(
    command: list[str], timeout: int | None, *, stdin=None
) -> subprocess.CompletedProcess:
    """Run a host command with disk-backed, size-bounded stdout and stderr."""

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            command, stdin=stdin, stdout=stdout, stderr=stderr
        )
        deadline = time.monotonic() + timeout if timeout is not None else None
        while process.poll() is None:
            size = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
            if size > MAX_COMMAND_OUTPUT_BYTES:
                process.kill()
                process.wait()
                captured = _bounded_output(
                    (stdout, stderr), MAX_COMMAND_OUTPUT_BYTES
                )
                raise CommandOutputLimitError(*captured)
            if deadline is not None and time.monotonic() >= deadline:
                process.kill()
                process.wait()
                captured = _bounded_output(
                    (stdout, stderr), MAX_COMMAND_OUTPUT_BYTES
                )
                raise subprocess.TimeoutExpired(
                    command, timeout, output=captured[0], stderr=captured[1]
                )
            time.sleep(0.05)
        size = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
        captured = _bounded_output((stdout, stderr), MAX_COMMAND_OUTPUT_BYTES)
        if size > MAX_COMMAND_OUTPUT_BYTES:
            raise CommandOutputLimitError(*captured)
        return subprocess.CompletedProcess(
            command, process.returncode, stdout=captured[0], stderr=captured[1]
        )


def _validate_local_transfer_tree(local_dir: Path) -> list[str]:
    """Validate and size a local tree before archiving it for a pod."""

    try:
        root = local_dir.resolve(strict=True)
    except OSError as exc:
        raise UnsafeArchiveError(
            f"local transfer tree is unavailable: {type(exc).__name__}"
        ) from exc
    if not root.is_dir():
        raise UnsafeArchiveError("local transfer tree is not a directory")

    member_count = 0
    expanded_bytes = 0
    top_entries: list[str] = []
    pending = [(root, Path())]
    while pending:
        directory, relative_dir = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise UnsafeArchiveError(
                "local transfer tree contains an unreadable directory"
            ) from exc
        with entries:
            iterator = iter(entries)
            while True:
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                except OSError as exc:
                    raise UnsafeArchiveError(
                        "local transfer tree contains an unreadable directory"
                    ) from exc
                relative = relative_dir / entry.name
                member_count += 1
                if member_count > MAX_SNAPSHOT_MEMBERS:
                    raise UnsafeArchiveError(
                        "local transfer tree contains more than "
                        f"{MAX_SNAPSHOT_MEMBERS} members"
                    )
                if len(os.fsencode(relative.as_posix())) > MAX_SNAPSHOT_PATH_BYTES:
                    raise UnsafeArchiveError(
                        "local transfer tree contains an overlong path"
                    )
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise UnsafeArchiveError(
                        f"local transfer path {relative} is unreadable"
                    ) from exc
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((Path(entry.path), relative))
                elif stat.S_ISREG(metadata.st_mode):
                    expanded_bytes += metadata.st_size
                    if expanded_bytes > MAX_SNAPSHOT_BYTES:
                        raise UnsafeArchiveError(
                            "local transfer tree expands beyond "
                            f"{MAX_SNAPSHOT_BYTES} bytes"
                        )
                else:
                    raise UnsafeArchiveError(
                        f"local transfer path {relative} is not a regular file "
                        "or directory"
                    )
                if not relative_dir.parts:
                    top_entries.append(f"./{entry.name}")
    return sorted(top_entries, key=os.fsencode)


def _local_archive_stream(local_dir: Path):
    """Create a disk-backed local tar with strict tree and stream caps."""

    entries = _validate_local_transfer_tree(local_dir)
    if not entries:
        return None
    archive = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    command = [
        "tar", "--no-xattrs", "-C", str(local_dir), "-cf", "-", *entries
    ]
    process = subprocess.Popen(
        command,
        stdout=archive,
        stderr=stderr,
        env={**os.environ, "COPYFILE_DISABLE": "1"},
    )
    deadline = time.monotonic() + 300
    try:
        while process.poll() is None:
            if os.fstat(archive.fileno()).st_size > MAX_SNAPSHOT_BYTES:
                process.kill()
                process.wait()
                raise UnsafeArchiveError(
                    f"local transfer archive exceeds {MAX_SNAPSHOT_BYTES} bytes"
                )
            if os.fstat(stderr.fileno()).st_size > MAX_ARCHIVE_STDERR_BYTES:
                process.kill()
                process.wait()
                raise UnsafeArchiveError(
                    "local transfer tar stderr exceeds "
                    f"{MAX_ARCHIVE_STDERR_BYTES} bytes"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise UnsafeArchiveError(
                    "local transfer archive timed out after 300s"
                )
            time.sleep(0.05)
        if os.fstat(archive.fileno()).st_size > MAX_SNAPSHOT_BYTES:
            raise UnsafeArchiveError(
                f"local transfer archive exceeds {MAX_SNAPSHOT_BYTES} bytes"
            )
        stderr_size = os.fstat(stderr.fileno()).st_size
        if stderr_size > MAX_ARCHIVE_STDERR_BYTES:
            raise UnsafeArchiveError(
                "local transfer tar stderr exceeds "
                f"{MAX_ARCHIVE_STDERR_BYTES} bytes"
            )
        if process.returncode != 0:
            stderr.seek(max(0, stderr_size - 2000))
            detail = stderr.read(2000).decode(errors="replace")
            raise UnsafeArchiveError(
                f"could not archive local transfer tree: {detail}"
            )
        archive.seek(0)
        return archive
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        archive.close()
        raise
    finally:
        stderr.close()


def _pod_archive_stream(pod_name: str, remote_dir: str):
    """Capture a pod tar stream to disk with a strict host-memory/size cap."""

    archive = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    command = [
        "kubectl", "--context", KUBE_CONTEXT, "-n", NAMESPACE,
        "exec", pod_name, "--", "tar", "-C", remote_dir, "-cf", "-", ".",
    ]
    process = subprocess.Popen(command, stdout=archive, stderr=stderr)
    deadline = time.monotonic() + 300
    try:
        while process.poll() is None:
            if os.fstat(archive.fileno()).st_size > MAX_SNAPSHOT_BYTES:
                process.kill()
                process.wait()
                raise UnsafeArchiveError(
                    f"pod snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"
                )
            if os.fstat(stderr.fileno()).st_size > MAX_ARCHIVE_STDERR_BYTES:
                process.kill()
                process.wait()
                raise KubeError(
                    "pod snapshot capture stderr exceeds "
                    f"{MAX_ARCHIVE_STDERR_BYTES} bytes"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise KubeError("pod snapshot capture timed out after 300s")
            time.sleep(0.05)
        returncode = process.returncode
        if os.fstat(stderr.fileno()).st_size > MAX_ARCHIVE_STDERR_BYTES:
            raise KubeError(
                "pod snapshot capture stderr exceeds "
                f"{MAX_ARCHIVE_STDERR_BYTES} bytes"
            )
        if returncode != 0:
            size = os.fstat(stderr.fileno()).st_size
            stderr.seek(max(0, size - 2000))
            detail = stderr.read(2000).decode(errors="replace")
            raise KubeError(
                f"could not capture pod snapshot (exit {returncode}): {detail}"
            )
        if os.fstat(archive.fileno()).st_size > MAX_SNAPSHOT_BYTES:
            raise UnsafeArchiveError(
                f"pod snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"
            )
        archive.seek(0)
        return archive
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        archive.close()
        raise
    finally:
        stderr.close()


def kubectl(*args: str, input: bytes | None = None, timeout: int | None = None,
            check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["kubectl", "--context", KUBE_CONTEXT, "-n", NAMESPACE, *args]
    proc = subprocess.run(cmd, input=input, capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise KubeError(
            f"kubectl {' '.join(args[:4])}... failed ({proc.returncode}): "
            f"{proc.stderr.decode(errors='replace')[-2000:]}"
        )
    return proc


def ensure_namespace() -> None:
    # Validate all pod-wide runtime configuration before the first cluster
    # mutation so a malformed RuntimeClass never reaches kubectl.
    runtime_class_name()
    namespace = _namespace_manifest()
    quota = _resource_quota_manifest()
    proc = subprocess.run(
        ["kubectl", "--context", KUBE_CONTEXT, "apply", "-f", "-"],
        input=json.dumps(namespace).encode(),
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise KubeError(proc.stderr.decode(errors="replace"))
    default_deny = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "sandbox-default-deny"},
        "spec": {
            # Select every current and future pod in the task namespace. A pod
            # receives connectivity only through a narrower additive policy.
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }
    for manifest in (quota, default_deny):
        kubectl("apply", "-f", "-", input=json.dumps(manifest).encode(), timeout=30)


@dataclass
class Pod:
    name: str
    network_policy_name: str | None = None

    def wait_ready(self, timeout: int = 300) -> None:
        kubectl("wait", "--for=condition=Ready", f"pod/{self.name}",
                f"--timeout={timeout}s", timeout=timeout + 30)

    def ip_address(self) -> str:
        """Return the validated current pod IP without using cluster DNS."""

        proc = kubectl("get", "pod", self.name, "-o", "json", timeout=30)
        try:
            value = json.loads(proc.stdout)["status"]["podIP"]
            return str(ipaddress.ip_address(value))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise KubeError(f"pod {self.name} has no valid IP address") from exc

    def copy_dir_to(self, local_dir: Path, remote_dir: str) -> None:
        """Copy the *contents* of local_dir into remote_dir (created if absent)."""
        archive = _local_archive_stream(local_dir)
        if archive is None:
            self.exec(f"mkdir -p {remote_dir}", timeout=60)
            return
        with closing(archive):
            self.exec(f"mkdir -p {remote_dir}", timeout=60)
            command = [
                "kubectl", "--context", KUBE_CONTEXT, "-n", NAMESPACE,
                "exec", "-i", self.name, "--", "tar",
                "--no-same-owner", "--no-same-permissions", "--touch",
                "-C", remote_dir, "-xf", "-",
            ]
            proc = _run_bounded_command(command, 300, stdin=archive)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout).decode(
                    errors="replace"
                )[-2000:]
                raise KubeError(
                    "could not copy local tree into pod "
                    f"(exit {proc.returncode}): {detail}"
                )

    def copy_dir_from(self, remote_dir: str, local_dir: Path) -> None:
        local_dir.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{local_dir.name}-extract-", dir=local_dir.parent)
        )
        try:
            with closing(_pod_archive_stream(self.name, remote_dir)) as stream:
                # Stream members instead of calling getmembers(): a tar near
                # the byte cap can otherwise allocate a huge in-memory list of
                # tiny TarInfo objects before any validation occurs.
                with tarfile.open(fileobj=stream, mode="r|*") as archive:
                    seen: set[str] = set()
                    expanded_bytes = 0
                    for member_count, member in enumerate(archive, start=1):
                        if member_count > MAX_SNAPSHOT_MEMBERS:
                            raise UnsafeArchiveError(
                                "pod snapshot contains more than "
                                f"{MAX_SNAPSHOT_MEMBERS} members"
                            )
                        if len(os.fsencode(member.name)) > MAX_SNAPSHOT_PATH_BYTES:
                            raise UnsafeArchiveError(
                                "pod snapshot contains an overlong member path"
                            )
                        if member.isfile():
                            expanded_bytes += member.size
                            if expanded_bytes > MAX_SNAPSHOT_BYTES:
                                raise UnsafeArchiveError(
                                    "pod snapshot expands beyond "
                                    f"{MAX_SNAPSHOT_BYTES} bytes"
                                )
                        elif not member.isdir():
                            raise UnsafeArchiveError(
                                "pod snapshot contains an unsafe archive "
                                f"member type for {member.name!r}"
                            )
                        normalized = os.path.normpath(member.name)
                        if normalized in seen:
                            raise UnsafeArchiveError(
                                "pod snapshot contains duplicate path "
                                f"{normalized!r}"
                            )
                        seen.add(normalized)
                        try:
                            tarfile.data_filter(member, temporary)
                        except (tarfile.FilterError, OSError) as exc:
                            raise UnsafeArchiveError(
                                "pod snapshot contains an unsafe archive "
                                f"member: {exc}"
                            ) from exc
                        archive.extract(member, temporary, filter="data")
            if local_dir.is_symlink() or local_dir.is_file():
                local_dir.unlink()
            elif local_dir.exists():
                shutil.rmtree(local_dir)
            os.replace(temporary, local_dir)
        except (tarfile.TarError, OSError) as exc:
            if isinstance(exc, UnsafeArchiveError):
                raise
            raise UnsafeArchiveError("pod snapshot is not a valid safe tar archive") from exc
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def exec(self, command: str, timeout: int | None = None,
             env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        """Run a shell command in the pod. Returns the completed process; the
        returncode is the remote command's exit code."""
        prefix = ""
        if env:
            prefix = " ".join(
                f"{key}={shlex.quote(value)}" for key, value in env.items()
            ) + " "
        host_command = [
            "kubectl", "--context", KUBE_CONTEXT, "-n", NAMESPACE,
            "exec", self.name, "--", "sh", "-c", prefix + command,
        ]
        return _run_bounded_command(host_command, timeout)

    def infrastructure_failure(self, command_exit_code: int | None = None) -> str | None:
        try:
            proc = kubectl(
                "get", "pod", self.name, "-o", "json", check=False, timeout=30
            )
        except subprocess.TimeoutExpired:
            proc = None
        if proc is not None and proc.returncode == 0:
            try:
                status = json.loads(proc.stdout).get("status", {})
            except (json.JSONDecodeError, AttributeError):
                status = {}
            candidates = [(status.get("reason"), status.get("message"))]
            for container in status.get("containerStatuses", []) or []:
                for state_name in ("state", "lastState"):
                    waiting = container.get(state_name, {}).get("waiting", {})
                    candidates.append(
                        (waiting.get("reason"), waiting.get("message"))
                    )
                    terminated = container.get(state_name, {}).get("terminated", {})
                    candidates.append((terminated.get("reason"), terminated.get("message")))
            for condition in status.get("conditions", []) or []:
                candidates.append((condition.get("reason"), condition.get("message")))
            for reason, message in candidates:
                detail = " ".join(part for part in (reason, message) if part)
                lowered = detail.lower()
                if reason in {
                    "OOMKilled",
                    "Evicted",
                    "DeadlineExceeded",
                    "Unschedulable",
                    "ErrImagePull",
                    "ImagePullBackOff",
                    "InvalidImageName",
                    "CreateContainerConfigError",
                    "CreateContainerError",
                    "RunContainerError",
                    "CrashLoopBackOff",
                } or any(
                    marker in lowered
                    for marker in (
                        "insufficient cpu",
                        "insufficient memory",
                        "ephemeral-storage",
                        "memory pressure",
                        "disk pressure",
                    )
                ):
                    return detail[:1000]
        if command_exit_code == 137:
            return "command exited 137 (SIGKILL; resource-limit termination possible)"
        return None

    def image_manifest_digest(
        self,
        image_ref: str,
        *,
        expected_manifest_digest: str | None = None,
    ) -> str | None:
        """Bind the running CRI config to the node's exact image manifest."""

        proc = kubectl("get", "pod", self.name, "-o", "json", check=False, timeout=30)
        if proc.returncode != 0:
            return None
        try:
            pod = json.loads(proc.stdout)
            node_name = pod["spec"]["nodeName"]
            spec_image = pod["spec"]["containers"][0]["image"]
            image_id = pod["status"]["containerStatuses"][0]["imageID"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            return None
        if (
            spec_image != image_ref
            or re.fullmatch(r"k3d-agent-eval-(?:server|agent)-\d+", node_name) is None
            or not isinstance(image_id, str)
            or not image_id
        ):
            return None
        image_id_match = re.search(r"sha256:[0-9a-fA-F]{64}", image_id)
        if image_id_match is None:
            return None
        running_config_digest = image_id_match.group(0).lower()
        try:
            inspected = _run_bounded_command(
                ["docker", "exec", node_name, "crictl", "inspecti", image_id],
                timeout=30,
            )
            inspected_output = inspected.stdout.decode("utf-8")
        except (
            CommandOutputLimitError,
            OSError,
            subprocess.TimeoutExpired,
            UnicodeError,
        ):
            return None
        if inspected.returncode != 0:
            return None
        try:
            status = json.loads(inspected_output)["status"]
            cri_config_digest = status["id"].lower()
            repo_tags = status["repoTags"]
            repo_digests = status["repoDigests"]
        except (AttributeError, json.JSONDecodeError, KeyError, TypeError):
            return None
        normalized_ref = _normalize_containerd_image_ref(image_ref)
        if (
            normalized_ref is None
            or not isinstance(repo_tags, list)
            or normalized_ref not in repo_tags
            or not isinstance(repo_digests, list)
        ):
            return None
        identity = containerd_image_manifest_identity(
            node_name,
            image_ref,
            expected_manifest_digest=expected_manifest_digest,
        )
        if identity is None:
            return None
        manifest_digest, manifest_config_digest = identity
        last_slash = normalized_ref.rfind("/")
        last_colon = normalized_ref.rfind(":")
        repository = (
            normalized_ref[:last_colon]
            if last_colon > last_slash
            else normalized_ref
        )
        expected_repo_digest = f"{repository}@{manifest_digest}"
        return (
            manifest_digest
            if (
                manifest_config_digest == running_config_digest
                and manifest_config_digest == cri_config_digest
                # k3d-imported local images commonly have an exact repoTag but
                # no repoDigest. If CRI does report repo digests, they must not
                # contradict the manifest bound independently above.
                and (not repo_digests or expected_repo_digest in repo_digests)
            )
            else None
        )

    def delete(self) -> None:
        kubectl(
            "delete", "pod", self.name, "--ignore-not-found", "--wait=true",
            timeout=60,
        )
        if self.network_policy_name:
            kubectl(
                "delete",
                "networkpolicy",
                self.network_policy_name,
                "--ignore-not-found",
                timeout=60,
            )


@dataclass
class TrialSecret:
    name: str

    def delete(self) -> None:
        kubectl(
            "delete", "secret", self.name, "--ignore-not-found",
            "--wait=true",
            timeout=30,
        )

    @property
    def cleanup_command(self) -> str:
        """Return a credential-free operator command for this exact Secret."""

        return shlex.join(
            [
                "kubectl",
                "--context",
                KUBE_CONTEXT,
                "-n",
                NAMESPACE,
                "delete",
                "secret",
                self.name,
                "--ignore-not-found",
                "--wait=true",
            ]
        )


@dataclass(frozen=True)
class SandboxLink:
    """Narrow evaluator-to-submission NetworkPolicy pair."""

    policy_names: tuple[str, str]

    def delete(self) -> None:
        failures = []
        for name in self.policy_names:
            try:
                kubectl(
                    "delete",
                    "networkpolicy",
                    name,
                    "--ignore-not-found",
                    timeout=30,
                )
            except (KubeError, subprocess.TimeoutExpired) as exc:
                failures.append(f"{name}: {type(exc).__name__}: {exc}")
        if failures:
            raise KubeError("sandbox link cleanup failed: " + "; ".join(failures))


@dataclass
class EgressProxy:
    name: str
    cluster_ip: str

    @property
    def endpoint(self) -> str:
        return f"http://{self.cluster_ip}:{PROXY_PORT}"

    def wait_ready(self, timeout: int = 180) -> None:
        kubectl(
            "wait", "--for=condition=Ready", f"pod/{self.name}",
            f"--timeout={timeout}s", timeout=timeout + 30,
        )

    def logs(self) -> str:
        proc = _run_bounded_command(
            [
                "kubectl",
                "--context",
                KUBE_CONTEXT,
                "-n",
                NAMESPACE,
                "logs",
                self.name,
            ],
            timeout=30,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).decode(errors="replace")[-2000:]
            raise KubeError(
                f"kubectl logs {self.name} failed ({proc.returncode}): {detail}"
            )
        return (proc.stdout + proc.stderr).decode(errors="replace")

    def delete(self) -> None:
        pod_deleted = False
        failures = []
        for resource in ("service", "pod", "configmap"):
            try:
                kubectl(
                    "delete", resource, self.name, "--ignore-not-found",
                    "--wait=true" if resource == "pod" else "--wait=false",
                    timeout=60,
                )
                if resource == "pod":
                    pod_deleted = True
            except (KubeError, subprocess.TimeoutExpired) as exc:
                failures.append(f"{resource}: {type(exc).__name__}: {exc}")
        if pod_deleted:
            try:
                kubectl(
                    "delete", "networkpolicy", self.name,
                    "--ignore-not-found", timeout=60,
                )
            except (KubeError, subprocess.TimeoutExpired) as exc:
                failures.append(f"networkpolicy: {type(exc).__name__}: {exc}")
        if failures:
            raise KubeError("egress proxy cleanup failed: " + "; ".join(failures))


def _rollback_trial_secret(secret: TrialSecret) -> bool:
    """Best-effort delete plus an independent API absence check."""

    for _attempt in range(TRIAL_SECRET_ROLLBACK_ATTEMPTS):
        # A delete timeout can still mean that the API server committed the
        # deletion, so always perform the independent read below.
        with suppress(Exception):
            secret.delete()
        try:
            observed = kubectl(
                "get",
                "secret",
                secret.name,
                "--ignore-not-found",
                "-o",
                "name",
                timeout=15,
            )
            if isinstance(observed.stdout, bytes) and not observed.stdout.strip():
                return True
        except Exception:
            pass
    return False


def create_trial_secret(material, *, run_id: str | None = None) -> TrialSecret:
    """Create a unique Secret from in-memory ``CredentialMaterial``.

    An apply failure is ambiguous because the API server may have committed the
    object before the client timed out. Retain the generated identity and do not
    return until deletion and absence have been confirmed, or an operator-safe
    remediation command can be reported.
    """

    name = f"agent-credential-{uuid.uuid4().hex}"
    secret = TrialSecret(name)
    labels = {
        "app": "agent-eval",
        "agent-eval-resource": "trial-credential",
    }
    annotations = {}
    if run_id is not None:
        run_digest = hashlib.sha256(run_id.encode()).hexdigest()
        labels["agent-eval-run-sha256"] = run_digest[:32]
        annotations["agent-eval-run-sha256"] = run_digest
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "labels": labels,
            **({"annotations": annotations} if annotations else {}),
        },
        "type": "Opaque",
        "stringData": material.values,
    }
    failure_type: str | None = None
    try:
        kubectl(
            "apply", "-f", "-", input=json.dumps(manifest).encode(), timeout=30
        )
    except Exception as exc:
        failure_type = type(exc).__name__
    if failure_type is not None:
        if _rollback_trial_secret(secret):
            raise KubeError(
                "credential Secret creation failed "
                f"({failure_type}); rollback confirmed for Secret {name}"
            )
        raise KubeError(
            "credential Secret creation failed "
            f"({failure_type}); rollback could not be confirmed for Secret {name} "
            f"after {TRIAL_SECRET_ROLLBACK_ATTEMPTS} attempts. "
            f"Run: {secret.cleanup_command}"
        )
    return secret


def egress_proxy_manifests(
    name: str, image: str, allowed_domains: list[str]
) -> list[dict]:
    """Build a Squid CONNECT proxy whose ACL is a DNS suffix allowlist."""

    if not allowed_domains:
        raise ValueError("proxy mode requires at least one allowed domain")
    configured_runtime_class = runtime_class_name()
    acl = " ".join(sorted(set(allowed_domains)))
    blocked_destinations = " ".join(
        (*PROXY_BLOCKED_IPV4_CIDRS, *PROXY_BLOCKED_IPV6_CIDRS)
    )
    config = (
        f"http_port {PROXY_PORT}\n"
        "acl SSL_ports port 443\n"
        "acl Safe_ports port 80 443\n"
        # A dst ACL is a DNS-resolving slow ACL. Evaluate it before the
        # non-resolving hostname allowlist and before any upstream connect.
        f"acl blocked_destination_ips dst {blocked_destinations}\n"
        # Disable reverse DNS so a direct IP request cannot acquire an allowed
        # hostname after the destination-IP checks.
        f"acl allowed_domains dstdomain -n {acl}\n"
        "http_access deny !Safe_ports\n"
        "http_access deny CONNECT !SSL_ports\n"
        "http_access deny blocked_destination_ips\n"
        "http_access allow allowed_domains\n"
        "http_access deny all\n"
        "access_log stdio:/dev/stdout\n"
        "cache deny all\n"
        "pid_filename /run/squid.pid\n"
        "coredump_dir /tmp\n"
    )
    labels = {"app": "agent-eval", "role": "egress-proxy", "proxy-id": name}
    return [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "labels": labels},
            "data": {"squid.conf": config},
        },
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name, "labels": labels},
            "spec": {
                **(
                    {"runtimeClassName": configured_runtime_class}
                    if configured_runtime_class is not None
                    else {}
                ),
                "automountServiceAccountToken": False,
                "enableServiceLinks": False,
                "activeDeadlineSeconds": PROXY_ACTIVE_DEADLINE_SECONDS,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 13,
                    "runAsGroup": 13,
                    "fsGroup": 13,
                    "fsGroupChangePolicy": "OnRootMismatch",
                },
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "proxy",
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "ports": [{"name": "proxy", "containerPort": PROXY_PORT}],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"},
                            "runAsNonRoot": True,
                            "runAsUser": 13,
                            "runAsGroup": 13,
                            "readOnlyRootFilesystem": True,
                        },
                        "volumeMounts": [
                            {
                                "name": "config",
                                "mountPath": "/etc/squid/squid.conf",
                                "subPath": "squid.conf",
                                "readOnly": True,
                            },
                            {"name": "run", "mountPath": "/run"},
                            {"name": "logs", "mountPath": "/var/log/squid"},
                            {"name": "spool", "mountPath": "/var/spool/squid"},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                        "resources": {
                            "requests": {
                                "cpu": "25m",
                                "memory": "64Mi",
                                "ephemeral-storage": "64Mi",
                            },
                            "limits": {
                                "cpu": "500m",
                                "memory": "256Mi",
                                "ephemeral-storage": "512Mi",
                            },
                        },
                    }
                ],
                "volumes": [
                    {"name": "config", "configMap": {"name": name}},
                    {"name": "run", "emptyDir": {}},
                    {"name": "logs", "emptyDir": {}},
                    {"name": "spool", "emptyDir": {}},
                    {"name": "tmp", "emptyDir": {}},
                ],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": name, "labels": labels},
            "spec": {
                "selector": {"proxy-id": name},
                "ports": [{"name": "proxy", "port": PROXY_PORT,
                           "targetPort": "proxy"}],
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "labels": labels},
            "spec": {
                "podSelector": {"matchLabels": {"proxy-id": name}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {"egress-proxy": name}
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": PROXY_PORT}],
                    }
                ],
                "egress": [
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "kube-system"
                                    }
                                },
                                "podSelector": {
                                    "matchLabels": {"k8s-app": "kube-dns"}
                                },
                            },
                            {
                                "ipBlock": {
                                    "cidr": K3S_CLUSTER_DNS_SERVICE_CIDR
                                }
                            },
                        ],
                        "ports": [
                            {"protocol": "UDP", "port": 53},
                            {"protocol": "TCP", "port": 53},
                        ],
                    },
                    {
                        "to": [
                            {
                                "ipBlock": {
                                    "cidr": "0.0.0.0/0",
                                    "except": list(PROXY_BLOCKED_IPV4_CIDRS),
                                }
                            }
                        ],
                        "ports": [
                            {"protocol": "TCP", "port": 80},
                            {"protocol": "TCP", "port": 443},
                        ],
                    },
                    {
                        "to": [
                            {
                                "ipBlock": {
                                    "cidr": PROXY_PUBLIC_IPV6_CIDR,
                                    "except": list(
                                        PROXY_PUBLIC_IPV6_EXCEPT_CIDRS
                                    ),
                                }
                            }
                        ],
                        "ports": [
                            {"protocol": "TCP", "port": 80},
                            {"protocol": "TCP", "port": 443},
                        ],
                    },
                ],
            },
        },
    ]


def create_egress_proxy(image: str, allowed_domains: list[str]) -> EgressProxy:
    name = f"egress-{uuid.uuid4().hex[:8]}"
    manifests = egress_proxy_manifests(name, image, allowed_domains)
    try:
        for manifest in manifests:
            kubectl(
                "apply", "-f", "-", input=json.dumps(manifest).encode(), timeout=60
            )
        service = kubectl("get", "service", name, "-o", "json", timeout=30)
        cluster_ip = json.loads(service.stdout)["spec"]["clusterIP"]
        ipaddress.ip_address(cluster_ip)
        proxy = EgressProxy(name, cluster_ip)
        proxy.wait_ready()
    except Exception:
        EgressProxy(name, "127.0.0.1").delete()
        raise
    return proxy


def sandbox_egress_policy_manifest(
    name: str, mode: str, *, proxy_id: str | None = None
) -> dict:
    if mode not in ("deny", "proxy", "open"):
        raise ValueError("network policy mode must be deny, proxy, or open")
    egress = []
    if mode == "open":
        egress = [{}]
    elif mode == "proxy":
        if not proxy_id:
            raise ValueError("proxy egress requires a proxy id")
        egress = [
            {
                "to": [{"podSelector": {"matchLabels": {"proxy-id": proxy_id}}}],
                "ports": [{"protocol": "TCP", "port": PROXY_PORT}],
            },
        ]
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": f"egress-{name}"},
        "spec": {
            "podSelector": {"matchLabels": {"sandbox-id": name}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": egress,
        },
    }


def black_box_link_policy_manifests(
    evaluator_name: str,
    submission_name: str,
    port: int,
) -> tuple[dict, dict]:
    """Allow one evaluator pod to connect only to one submission TCP port."""

    for label, value in (
        ("evaluator", evaluator_name),
        ("submission", submission_name),
    ):
        if _DNS_LABEL_RE.fullmatch(value) is None:
            raise ValueError(f"{label} pod name must be a lowercase DNS label")
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("black-box submission port must be between 1024 and 65535")

    egress_name = f"black-box-egress-{evaluator_name}"
    ingress_name = f"black-box-ingress-{submission_name}"
    if len(egress_name) > 63 or len(ingress_name) > 63:
        raise ValueError("black-box pod names are too long for policy names")
    peer_port = [{"protocol": "TCP", "port": port}]
    evaluator = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": egress_name},
        "spec": {
            "podSelector": {"matchLabels": {"sandbox-id": evaluator_name}},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [
                        {
                            "podSelector": {
                                "matchLabels": {"sandbox-id": submission_name}
                            }
                        }
                    ],
                    "ports": peer_port,
                }
            ],
        },
    }
    submission = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": ingress_name},
        "spec": {
            "podSelector": {"matchLabels": {"sandbox-id": submission_name}},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {"sandbox-id": evaluator_name}
                            }
                        }
                    ],
                    "ports": peer_port,
                }
            ],
        },
    }
    return evaluator, submission


def create_black_box_link(
    evaluator_name: str,
    submission_name: str,
    port: int,
) -> SandboxLink:
    """Apply the two additive policies for an isolated black-box evaluation."""

    manifests = black_box_link_policy_manifests(
        evaluator_name, submission_name, port
    )
    link = SandboxLink(
        tuple(manifest["metadata"]["name"] for manifest in manifests)
    )
    try:
        for manifest in manifests:
            kubectl(
                "apply",
                "-f",
                "-",
                input=json.dumps(manifest).encode(),
                timeout=60,
            )
    except Exception:
        with suppress(Exception):
            link.delete()
        raise
    return link


def sandbox_pod_manifest(
    name: str,
    prefix: str,
    image: str,
    *,
    env_from_secret: str | None = None,
    credential_env_keys: tuple[str, ...] = (),
    credential_file_items: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    active_deadline: int = 3600,
    resources: dict[str, dict[str, str]] | None = None,
    security: dict | None = None,
    image_pull_policy: str = "IfNotPresent",
    proxy_id: str | None = None,
    container_command: list[str] | None = None,
) -> dict:
    """Return the auditable pod manifest used for agent and eval sandboxes.

    The service-account token and service discovery environment are disabled,
    while the container gets seccomp, no privilege escalation, no Linux
    capabilities, and bounded resources. The caller applies an open, denied,
    or proxy-only egress policy separately.
    """
    if image_pull_policy not in {"IfNotPresent", "Never"}:
        raise ValueError("image pull policy must be IfNotPresent or Never")
    if container_command is not None and (
        not container_command
        or any(
            not isinstance(value, str) or not value or "\x00" in value
            for value in container_command
        )
    ):
        raise ValueError("container command must contain nonempty strings without NULs")
    configured_runtime_class = runtime_class_name()
    security = {**DEFAULT_SECURITY, **(security or {})}
    container_security = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
        "runAsNonRoot": security["run_as_non_root"],
        "runAsUser": security["run_as_user"],
        "runAsGroup": security["run_as_group"],
        "readOnlyRootFilesystem": security["read_only_root_filesystem"],
    }
    volume_mounts = [
        {"name": "workspace", "mountPath": "/workspace"},
        {"name": "tmp", "mountPath": "/tmp"},
        {"name": "home", "mountPath": "/home/agent"},
        {"name": "tests", "mountPath": "/tests"},
        {"name": "results", "mountPath": "/results"},
    ]
    volumes = [
        {"name": name, "emptyDir": {}}
        for name in ("workspace", "tmp", "home", "tests", "results")
    ]
    env = [
        {"name": "HOME", "value": "/home/agent"},
        {"name": "TMPDIR", "value": "/tmp"},
    ]
    for key, value in sorted((extra_env or {}).items()):
        env.append({"name": key, "value": value})

    spec: dict = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "labels": {
                "app": "agent-eval",
                "role": "sandbox",
                "phase": prefix,
                "sandbox-id": name,
                **({"egress-proxy": proxy_id} if proxy_id else {}),
            },
        },
        "spec": {
            **(
                {"runtimeClassName": configured_runtime_class}
                if configured_runtime_class is not None
                else {}
            ),
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "securityContext": {
                "runAsNonRoot": security["run_as_non_root"],
                "runAsUser": security["run_as_user"],
                "runAsGroup": security["run_as_group"],
                "fsGroup": security["run_as_group"],
                "fsGroupChangePolicy": "OnRootMismatch",
            },
            "restartPolicy": "Never",
            "activeDeadlineSeconds": active_deadline,
            "terminationGracePeriodSeconds": 1,
            "containers": [
                {
                    "name": "sandbox",
                    "image": image,
                    "imagePullPolicy": image_pull_policy,
                    "command": container_command or ["sleep", "infinity"],
                    "workingDir": "/workspace",
                    "env": env,
                    "securityContext": container_security,
                    "resources": deepcopy(
                        DEFAULT_SANDBOX_RESOURCES if resources is None else resources
                    ),
                    "volumeMounts": volume_mounts,
                }
            ],
            "volumes": volumes,
        },
    }
    if env_from_secret:
        for key in credential_env_keys:
            env.append(
                {
                    "name": key,
                    "valueFrom": {
                        "secretKeyRef": {"name": env_from_secret, "key": key}
                    },
                }
            )
        file_items = credential_file_items or {}
        if file_items:
            volumes.append(
                {
                    "name": "credentials",
                    "secret": {
                        "secretName": env_from_secret,
                        "defaultMode": 288,
                        "items": [
                            {"key": key, "path": path}
                            for key, path in sorted(file_items.items())
                        ],
                    },
                }
            )
            volume_mounts.append(
                {
                    "name": "credentials",
                    "mountPath": CREDENTIAL_MOUNT,
                    "readOnly": True,
                }
            )
    return spec


def create_sandbox_pod(
    prefix: str,
    image: str,
    *,
    env_from_secret: str | None = None,
    credential_env_keys: tuple[str, ...] = (),
    credential_file_items: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    active_deadline: int = 3600,
    resources: dict[str, dict[str, str]] | None = None,
    security: dict | None = None,
    image_pull_policy: str = "IfNotPresent",
    egress_mode: str = "open",
    proxy_id: str | None = None,
    container_command: list[str] | None = None,
) -> Pod:
    """Create a sandbox pod, sleeping by default for copy/exec workflows."""
    # Keep enough entropy that an orphaned exact-selector NetworkPolicy cannot
    # plausibly match a later sandbox after a cleanup failure.
    name = f"{prefix}-{uuid.uuid4().hex[:16]}"
    spec = sandbox_pod_manifest(
        name,
        prefix,
        image,
        env_from_secret=env_from_secret,
        credential_env_keys=credential_env_keys,
        credential_file_items=credential_file_items,
        extra_env=extra_env,
        active_deadline=active_deadline,
        resources=resources,
        security=security,
        image_pull_policy=image_pull_policy,
        proxy_id=proxy_id,
        container_command=container_command,
    )
    policy = sandbox_egress_policy_manifest(name, egress_mode, proxy_id=proxy_id)
    policy_name = policy["metadata"]["name"]
    kubectl("apply", "-f", "-", input=json.dumps(policy).encode(), timeout=60)
    try:
        kubectl("apply", "-f", "-", input=json.dumps(spec).encode(), timeout=60)
    except Exception:
        # An apply timeout is ambiguous: the API server may have created the
        # pod even though kubectl did not receive the response. Delete by the
        # deterministic name before dropping its policy.
        with suppress(Exception):
            kubectl(
                "delete",
                "pod",
                name,
                "--ignore-not-found",
                "--wait=true",
                check=False,
                timeout=60,
            )
        if policy_name:
            with suppress(Exception):
                kubectl(
                    "delete",
                    "networkpolicy",
                    policy_name,
                    "--ignore-not-found",
                    check=False,
                    timeout=30,
                )
        raise
    return Pod(name, network_policy_name=policy_name)
