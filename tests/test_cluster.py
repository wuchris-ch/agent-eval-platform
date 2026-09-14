import json
import subprocess

from agent_eval import cluster


def _completed(payload, returncode=0):
    stdout = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


def test_cluster_exists_parses_compact_k3d_json(monkeypatch):
    monkeypatch.setattr(
        cluster.subprocess,
        "run",
        lambda *args, **kwargs: _completed([{"name": "agent-eval", "serversCount": 1}]),
    )

    assert cluster.cluster_exists()


def test_cluster_exists_fails_closed_on_malformed_k3d_json(monkeypatch):
    monkeypatch.setattr(
        cluster.subprocess,
        "run",
        lambda *args, **kwargs: _completed("not json"),
    )

    assert not cluster.cluster_exists()


def test_cluster_up_starts_an_existing_stopped_cluster(monkeypatch):
    stopped = {
        "name": "agent-eval",
        "serversCount": 1,
        "serversRunning": 0,
        "agentsCount": 1,
        "agentsRunning": 0,
        "nodes": [
            {
                "name": "server",
                "role": "server",
                "image": cluster.K3S_IMAGE_DIGEST,
            },
            {
                "name": "agent",
                "role": "agent",
                "image": cluster.K3S_IMAGE_DIGEST,
            },
        ],
    }
    commands = []
    namespace_calls = []
    monkeypatch.setattr(cluster, "_cluster_record", lambda: stopped)
    monkeypatch.setattr(cluster, "_run", commands.append)
    monkeypatch.setattr(
        cluster, "ensure_namespace", lambda: namespace_calls.append(True)
    )

    cluster.cluster_up()

    assert commands == [["k3d", "cluster", "start", "agent-eval", "--wait"]]
    assert namespace_calls == [True]


def test_cluster_up_creates_with_digest_pinned_k3s_image(monkeypatch):
    commands = []
    monkeypatch.setattr(cluster, "_cluster_record", lambda: None)
    monkeypatch.setattr(cluster, "_run", commands.append)
    monkeypatch.setattr(cluster, "ensure_namespace", lambda: None)

    cluster.cluster_up()

    assert commands == [
        [
            "k3d",
            "cluster",
            "create",
            "agent-eval",
            "--image",
            cluster.K3S_IMAGE,
            "--agents",
            "1",
            "--wait",
        ]
    ]


def test_cluster_up_rejects_existing_cluster_with_different_node_image(monkeypatch):
    existing = {
        "name": "agent-eval",
        "nodes": [{"name": "server", "role": "server", "image": "sha256:" + "0" * 64}],
    }
    monkeypatch.setattr(cluster, "_cluster_record", lambda: existing)
    monkeypatch.setattr(
        cluster,
        "_run",
        lambda command: (_ for _ in ()).throw(AssertionError(command)),
    )

    try:
        cluster.cluster_up()
    except cluster.KubeError as exc:
        assert "does not use the required k3s image" in str(exc)
    else:
        raise AssertionError("mismatched cluster image was accepted")
