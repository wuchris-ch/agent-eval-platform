"""k3d cluster lifecycle and task-image import."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

from .kube import KUBE_CONTEXT, NAMESPACE, KubeError, ensure_namespace

CLUSTER_NAME = "agent-eval"
K3S_IMAGE_DIGEST = (
    "sha256:2074403abe1bded11ef3dde09d457e13be8e0b64c218b1c4f8269b4565cfbc65"
)
K3S_IMAGE = f"rancher/k3s@{K3S_IMAGE_DIGEST}"
console = Console()


def _run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise KubeError(f"{' '.join(cmd[:3])} failed: {proc.stderr[-2000:]}")
    return proc


def _cluster_record() -> dict[str, Any] | None:
    proc = subprocess.run(
        ["k3d", "cluster", "list", "-o", "json"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        return None
    try:
        clusters = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(clusters, list):
        return None
    return next(
        (
            cluster
            for cluster in clusters
            if isinstance(cluster, dict) and cluster.get("name") == CLUSTER_NAME
        ),
        None,
    )


def cluster_exists() -> bool:
    return _cluster_record() is not None


def _cluster_running(cluster: dict[str, Any]) -> bool:
    servers = cluster.get("serversCount")
    agents = cluster.get("agentsCount")
    return (
        isinstance(servers, int)
        and servers > 0
        and cluster.get("serversRunning") == servers
        and isinstance(agents, int)
        and cluster.get("agentsRunning") == agents
    )


def _cluster_image_matches(cluster: dict[str, Any]) -> bool:
    """Require every k3s server and agent to use the reviewed image index."""

    nodes = cluster.get("nodes")
    if not isinstance(nodes, list):
        return False
    workers = [
        node
        for node in nodes
        if isinstance(node, dict) and node.get("role") in {"server", "agent"}
    ]
    return bool(workers) and all(
        node.get("image") == K3S_IMAGE_DIGEST for node in workers
    )


def cluster_up() -> None:
    cluster = _cluster_record()
    if cluster is not None and not _cluster_image_matches(cluster):
        raise KubeError(
            f"cluster {CLUSTER_NAME} does not use the required k3s image "
            f"{K3S_IMAGE_DIGEST}; delete and recreate it explicitly"
        )
    if cluster is not None and _cluster_running(cluster):
        console.print(f"[yellow]cluster {CLUSTER_NAME} already running[/yellow]")
    elif cluster is not None:
        console.print(f"starting existing k3d cluster [bold]{CLUSTER_NAME}[/bold]...")
        _run(["k3d", "cluster", "start", CLUSTER_NAME, "--wait"])
    else:
        console.print(f"creating k3d cluster [bold]{CLUSTER_NAME}[/bold]...")
        _run(
            [
                "k3d",
                "cluster",
                "create",
                CLUSTER_NAME,
                "--image",
                K3S_IMAGE,
                "--agents",
                "1",
                "--wait",
            ]
        )
    ensure_namespace()
    console.print("[green]cluster ready[/green]")


def ensure_cluster() -> None:
    """Create the cluster on first use so `agent-eval run` works cold."""
    cluster_up()


def cluster_down() -> None:
    _run(["k3d", "cluster", "delete", CLUSTER_NAME])
    console.print(f"[green]cluster {CLUSTER_NAME} deleted[/green]")


def cluster_status() -> None:
    cluster = _cluster_record()
    if cluster is None:
        console.print(
            f"[red]cluster {CLUSTER_NAME} does not exist[/red] "
            "(run: agent-eval cluster up)"
        )
        return
    if not _cluster_running(cluster):
        console.print(
            f"[yellow]cluster {CLUSTER_NAME} is stopped[/yellow] "
            "(run: agent-eval cluster up)"
        )
        return
    if not _cluster_image_matches(cluster):
        console.print(
            f"[red]cluster {CLUSTER_NAME} has an unapproved k3s image[/red] "
            "(delete and recreate it explicitly)"
        )
        return
    proc = subprocess.run(
        ["kubectl", "--context", KUBE_CONTEXT, "get", "nodes", "-o", "wide"],
        capture_output=True,
        text=True,
    )
    console.print(proc.stdout or proc.stderr)
    pods = subprocess.run(
        ["kubectl", "--context", KUBE_CONTEXT, "-n", NAMESPACE, "get", "pods"],
        capture_output=True,
        text=True,
    )
    console.print(pods.stdout or pods.stderr)


def build_image(context_dir: str, tag: str) -> None:
    console.print(f"building image [bold]{tag}[/bold]...")
    _run(["docker", "build", "-t", tag, context_dir], timeout=1800)


def build_image_with_metadata(
    context_dir: str,
    tag: str,
    *,
    platform: str,
    metadata_file: str | Path,
) -> None:
    """Load one platform image and atomically record its OCI build metadata."""

    console.print(f"building task image candidate [bold]{tag}[/bold]...")
    _run(
        [
            "docker",
            "buildx",
            "build",
            "--load",
            "--provenance=false",
            "--platform",
            platform,
            "--metadata-file",
            str(metadata_file),
            "-t",
            tag,
            context_dir,
        ],
        timeout=1800,
    )


def import_image(tag: str) -> None:
    console.print("importing image into cluster...")
    _run(["k3d", "image", "import", tag, "-c", CLUSTER_NAME], timeout=600)


def build_and_import_image(context_dir: str, tag: str) -> None:
    build_image(context_dir, tag)
    import_image(tag)
