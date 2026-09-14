import json
import shutil
import subprocess
import sys
import time

import pytest

from agent_eval import metrics, runner
from agent_eval.attestation import CLEAN_WORKTREE_SHA256
from agent_eval.credentials import CredentialMaterial, CredentialRedactor
from agent_eval.evaluators.tests import TestResults as EvalTestResults
from agent_eval.kube import KubeError, UnsafeArchiveError
from agent_eval.metrics import AgentMetrics
from agent_eval.task import EvaluationConfig, SandboxResources, load_task

IMAGE_DIGEST = "sha256:" + "a" * 64


def _cooperative_task():
    return load_task("example-todo-api").model_copy(
        update={"evaluation": EvaluationConfig()}
    )


def test_codex_provider_network_includes_required_openai_asset_hosts():
    task = load_task("example-todo-api")

    domains, proxy_image = runner._governance_network_evidence(task, "codex")

    assert domains == [
        ".chatgpt.com",
        ".oaiusercontent.com",
        ".openai.com",
    ]
    assert proxy_image == task.network.proxy_image


class _EvalOOMPod:
    def __init__(self):
        self.deleted = False

    def wait_ready(self):
        return None

    def copy_dir_to(self, local_dir, remote_dir):
        return None

    def copy_dir_from(self, remote_dir, local_dir):
        raise AssertionError("results must not be trusted after an OOM termination")

    def exec(self, command, timeout=None, env=None):
        if command in (
            "rm -rf /workspace && mkdir -p /workspace",
            "mkdir -p /results",
        ):
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        return subprocess.CompletedProcess(command, 137, stdout=b"", stderr=b"Killed")

    def infrastructure_failure(self, command_exit_code=None):
        if command_exit_code == 137:
            return "OOMKilled container exceeded its memory limit"
        return None

    def image_digest(self):
        return IMAGE_DIGEST

    def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
        del image_ref, expected_manifest_digest
        return self.image_digest()

    def delete(self):
        self.deleted = True


class _AgentDeadlinePod:
    def __init__(self):
        self.deleted = False

    def wait_ready(self):
        raise KubeError("pod stopped before becoming ready")

    def infrastructure_failure(self, command_exit_code=None):
        return "DeadlineExceeded pod was active longer than its deadline"

    def delete(self):
        self.deleted = True


class _SuccessfulEvalPod:
    def __init__(self, test_exit_code=0, quiescence_exit_code=0):
        self.test_exit_code = test_exit_code
        self.quiescence_exit_code = quiescence_exit_code
        self.deleted = False
        self.events = []

    def wait_ready(self):
        self.events.append(("ready",))

    def copy_dir_to(self, local_dir, remote_dir):
        self.events.append(("copy_to", remote_dir))

    def copy_dir_from(self, remote_dir, local_dir):
        self.events.append(("copy_from", remote_dir))
        local_dir.mkdir(parents=True, exist_ok=True)
        (local_dir / "junit.xml").write_text(
            '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            '<testcase classname="t" name="ok"/>'
            "</testsuite></testsuites>"
        )

    def exec(self, command, timeout=None, env=None):
        self.events.append(("exec", command))
        if command == runner._AGENT_QUIESCE_COMMAND:
            code = self.quiescence_exit_code
        else:
            code = (
                self.test_exit_code
                if ".agent-eval-pytest.py" in command
                or command.startswith("cd /workspace")
                else 0
            )
        return subprocess.CompletedProcess(command, code, stdout=b"", stderr=b"")

    def infrastructure_failure(self, command_exit_code=None):
        return None

    def image_digest(self):
        return IMAGE_DIGEST

    def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
        del image_ref, expected_manifest_digest
        return self.image_digest()

    def delete(self):
        self.deleted = True


class _BlackBoxPod:
    def __init__(self, role):
        self.role = role
        self.name = f"{role}-12345678"
        self.deleted = False
        self.events = []

    def wait_ready(self):
        self.events.append(("ready",))

    def copy_dir_to(self, local_dir, remote_dir):
        self.events.append(("copy_to", remote_dir, local_dir.name))

    def copy_dir_from(self, remote_dir, local_dir):
        assert self.role == "eval", "submission artifacts must never reach the host"
        self.events.append(("copy_from", remote_dir))
        local_dir.mkdir(parents=True, exist_ok=True)
        (local_dir / "junit.xml").write_text(
            '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            '<testcase classname="blackbox" name="ok"/>'
            "</testsuite></testsuites>"
        )

    def exec(self, command, timeout=None, env=None):
        self.events.append(("exec", command, timeout, env))
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    def infrastructure_failure(self, command_exit_code=None):
        del command_exit_code

    def image_digest(self):
        return IMAGE_DIGEST

    def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
        del image_ref, expected_manifest_digest
        return self.image_digest()

    def ip_address(self):
        assert self.role == "submission"
        return "10.42.0.19"

    def delete(self):
        self.deleted = True


class _BlackBoxLink:
    def __init__(self):
        self.deleted = False

    def delete(self):
        self.deleted = True


class _AgentTimeoutPod:
    def __init__(self):
        self.deleted = False

    def wait_ready(self):
        return None

    def copy_dir_to(self, local_dir, remote_dir):
        return None

    def copy_dir_from(self, remote_dir, local_dir):
        local_dir.mkdir(parents=True, exist_ok=True)

    def exec(self, command, timeout=None, env=None):
        raise subprocess.TimeoutExpired(command, timeout, output=b"", stderr=b"")

    def infrastructure_failure(self, command_exit_code=None):
        return None

    def image_digest(self):
        return IMAGE_DIGEST

    def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
        del image_ref, expected_manifest_digest
        return self.image_digest()

    def delete(self):
        self.deleted = True


class _SnapshotAgentPod:
    def __init__(self, quiescence_exit_code=0):
        self.quiescence_exit_code = quiescence_exit_code
        self.deleted = False
        self.events = []

    def wait_ready(self):
        self.events.append("ready")

    def copy_dir_to(self, local_dir, remote_dir):
        del local_dir
        self.events.append(f"copy-to:{remote_dir}")

    def copy_dir_from(self, remote_dir, local_dir):
        self.events.append(f"snapshot:{remote_dir}")
        local_dir.mkdir(parents=True)

    def exec(self, command, timeout=None, env=None):
        del env
        if command == runner._AGENT_QUIESCE_COMMAND:
            self.events.append(f"quiesce:{timeout}")
            return subprocess.CompletedProcess(
                command,
                self.quiescence_exit_code,
                stdout=b"",
                stderr=b"",
            )
        self.events.append("agent-command")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    def infrastructure_failure(self, command_exit_code=None):
        del command_exit_code

    def image_digest(self):
        return IMAGE_DIGEST

    def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
        del image_ref, expected_manifest_digest
        return self.image_digest()

    def delete(self):
        self.deleted = True
        self.events.append("delete")


class _CredentialExfilPod:
    def __init__(
        self,
        starter,
        *,
        stdout=b"",
        stderr=b"",
        workspace_content=None,
        workspace_path=None,
    ):
        self.starter = starter
        self.stdout = stdout
        self.stderr = stderr
        self.workspace_content = workspace_content
        self.workspace_path = workspace_path
        self.deleted = False

    def wait_ready(self):
        return None

    def copy_dir_to(self, local_dir, remote_dir):
        del local_dir, remote_dir

    def copy_dir_from(self, remote_dir, local_dir):
        assert remote_dir == "/workspace"
        shutil.copytree(self.starter, local_dir)
        if self.workspace_content is not None:
            (local_dir / "credential-leak.txt").write_text(self.workspace_content)
        if self.workspace_path is not None:
            (local_dir / f"artifact-{self.workspace_path}.txt").write_text("clean")

    def exec(self, command, timeout=None, env=None):
        del timeout, env
        if command == runner._AGENT_QUIESCE_COMMAND:
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=self.stdout,
            stderr=self.stderr,
        )

    def infrastructure_failure(self, command_exit_code=None):
        del command_exit_code

    def image_digest(self):
        return IMAGE_DIGEST

    def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
        del image_ref, expected_manifest_digest
        return self.image_digest()

    def delete(self):
        self.deleted = True


class _CredentialProxy:
    name = "credential-proxy"
    endpoint = "http://10.0.0.2:3128"

    def __init__(self, log):
        self.log = log
        self.deleted = False

    def logs(self):
        return self.log

    def delete(self):
        self.deleted = True


class _TrialSecret:
    name = "trial-secret"

    def __init__(self):
        self.deleted = False

    def delete(self):
        self.deleted = True


def test_eval_resource_termination_is_infrastructure_evidence(monkeypatch, tmp_path):
    task = _cooperative_task().model_copy(
        update={
            "resources": SandboxResources.model_validate(
                {"eval": {"limits": {"memory": "5Gi"}}}
            )
        }
    )
    pod = _EvalOOMPod()
    create_args = {}

    def fake_create(*args, **kwargs):
        create_args.update(kwargs)
        return pod

    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(runner, "create_sandbox_pod", fake_create)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (tmp_path / "workspace").mkdir()

    result = runner.run_eval_phase(task, tmp_path / "workspace", run_dir)

    assert result.infra_error == (
        "eval sandbox infrastructure failure: "
        "OOMKilled container exceeded its memory limit"
    )
    assert create_args["resources"]["limits"]["memory"] == "5Gi"
    assert "Killed" in (run_dir / "eval-output.txt").read_text()
    assert pod.deleted is True


def test_cluster_image_check_requires_image_on_every_running_node(monkeypatch):
    nodes = {
        "name": "agent-eval",
        "nodes": [
            {"name": "server", "role": "server", "State": {"Running": True}},
            {"name": "agent", "role": "agent", "State": {"Running": True}},
            {"name": "lb", "role": "loadbalancer", "State": {"Running": True}},
        ],
    }
    missing = set()
    digests = {"server": IMAGE_DIGEST, "agent": IMAGE_DIGEST}

    def fake_run(command, **kwargs):
        del kwargs
        if command[:4] == ["k3d", "cluster", "list", "-o"]:
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps([nodes]), stderr=""
            )
        raise AssertionError(command)

    def fake_manifest_identity(node, image_ref, *, expected_manifest_digest=None):
        assert image_ref == "example:tag"
        assert expected_manifest_digest == IMAGE_DIGEST
        if node in missing:
            return None
        return digests[node], "sha256:" + "c" * 64

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(
        runner, "containerd_image_manifest_identity", fake_manifest_identity
    )

    assert runner._cluster_has_image("example:tag", IMAGE_DIGEST)
    digests["agent"] = "sha256:" + "b" * 64
    assert not runner._cluster_has_image("example:tag", IMAGE_DIGEST)
    digests["agent"] = IMAGE_DIGEST
    missing.add("agent")
    assert not runner._cluster_has_image("example:tag", IMAGE_DIGEST)


def test_cluster_manifest_check_uses_containerd_target_on_every_node(monkeypatch):
    nodes = {
        "name": "agent-eval",
        "nodes": [
            {
                "name": "k3d-agent-eval-server-0",
                "role": "server",
                "State": {"Running": True},
            },
            {
                "name": "k3d-agent-eval-agent-0",
                "role": "agent",
                "State": {"Running": True},
            },
        ],
    }
    manifest_by_node = {
        "k3d-agent-eval-server-0": IMAGE_DIGEST,
        "k3d-agent-eval-agent-0": IMAGE_DIGEST,
    }

    def fake_run(command, **kwargs):
        if command[:4] == ["k3d", "cluster", "list", "-o"]:
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps([nodes]), stderr=""
            )
        raise AssertionError(command)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(
        runner,
        "containerd_image_manifest_identity",
        lambda node, _image_ref, *, expected_manifest_digest: (
            (
                manifest_by_node[node],
                "sha256:" + "c" * 64,
            )
            if expected_manifest_digest == IMAGE_DIGEST
            else None
        ),
    )

    image_ref = "agent-eval/example:governed-" + "a" * 64
    assert runner._cluster_has_manifest(image_ref, IMAGE_DIGEST)
    manifest_by_node["k3d-agent-eval-agent-0"] = "sha256:" + "b" * 64
    assert not runner._cluster_has_manifest(image_ref, IMAGE_DIGEST)


@pytest.mark.parametrize(
    "media_type, expected",
    [
        ("application/vnd.oci.image.manifest.v1+json", IMAGE_DIGEST),
        ("application/vnd.oci.image.index.v1+json", None),
        ("application/vnd.oci.image.config.v1+json", None),
    ],
)
def test_local_manifest_digest_rejects_indexes_and_config_ids(
    monkeypatch, media_type, expected
):
    def fake_run(command, **kwargs):
        del kwargs
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"mediaType": media_type, "digest": IMAGE_DIGEST}),
            stderr="",
        )

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner._local_manifest_digest("agent-eval/example:tag") == expected


@pytest.mark.parametrize(
    "media_type, expected",
    [
        ("application/vnd.oci.image.manifest.v1+json", IMAGE_DIGEST),
        ("application/vnd.docker.distribution.manifest.v2+json", IMAGE_DIGEST),
        ("application/vnd.oci.image.index.v1+json", None),
        ("application/vnd.oci.image.config.v1+json", None),
    ],
)
def test_image_digest_selects_server_platform_manifest(
    monkeypatch, media_type, expected
):
    def fake_run(command, **kwargs):
        del kwargs
        assert command == [
            "docker",
            "image",
            "inspect",
            "--platform",
            "linux/arm64",
            "--format={{json .Descriptor}}",
            "agent-eval/example:tag",
        ]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"mediaType": media_type, "digest": IMAGE_DIGEST}),
            stderr="",
        )

    monkeypatch.setattr(runner, "_docker_platform", lambda: "linux/arm64")
    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner._image_digest("agent-eval/example:tag") == expected


def test_runtime_image_evidence_never_falls_back_to_config_digest():
    class ManifestPod:
        def image_digest(self):
            raise AssertionError("CRI config digest fallback must not be used")

        def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
            assert image_ref == "agent-eval/example:tag"
            assert expected_manifest_digest == IMAGE_DIGEST
            return IMAGE_DIGEST

    assert runner._runtime_image_evidence(
        ManifestPod(),
        IMAGE_DIGEST,
        image_ref="agent-eval/example:tag",
    ) == (IMAGE_DIGEST, None)
    with pytest.raises(TypeError, match="image_ref"):
        runner._runtime_image_evidence(ManifestPod(), IMAGE_DIGEST)


def test_image_identity_commands_fail_closed_on_timeout(monkeypatch):
    def timed_out(command, **kwargs):
        assert kwargs["timeout"] == 30
        raise subprocess.TimeoutExpired(command, 30)

    monkeypatch.setattr(runner.subprocess, "run", timed_out)

    assert not runner._cluster_has_image("agent-eval/example:tag", IMAGE_DIGEST)
    assert not runner._cluster_has_manifest("agent-eval/example:tag", IMAGE_DIGEST)
    assert runner._local_manifest_digest("agent-eval/example:tag") is None
    with pytest.raises(KubeError, match="Docker server platform"):
        runner._docker_platform()

    monkeypatch.setattr(runner, "_docker_platform", lambda: "linux/arm64")
    assert runner._image_digest("agent-eval/example:tag") is None


def test_candidate_build_binds_metadata_manifest_to_content_ref(monkeypatch):
    task = load_task("example-todo-api")
    state = {"temporary_ref": None, "tagged": False, "removed": False}

    def fake_build(context_dir, image_ref, *, platform, metadata_file):
        assert context_dir == str(task.environment_dir)
        assert platform == "linux/arm64"
        state["temporary_ref"] = image_ref
        metadata_file.write_text(
            json.dumps(
                {
                    "containerimage.digest": IMAGE_DIGEST,
                    "containerimage.descriptor": {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": IMAGE_DIGEST,
                    },
                }
            ),
            encoding="utf-8",
        )

    expected_ref = f"agent-eval/{task.id}:governed-{'a' * 64}"

    def fake_local(image_ref):
        if image_ref == state["temporary_ref"]:
            return IMAGE_DIGEST
        if image_ref == expected_ref and state["tagged"]:
            return IMAGE_DIGEST
        return None

    def fake_run(command, **kwargs):
        del kwargs
        if command[2] == "tag":
            assert command[-2:] == [state["temporary_ref"], expected_ref]
            state["tagged"] = True
        elif command[2] == "rm":
            assert command[-1] == state["temporary_ref"]
            state["removed"] = True
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(runner, "_docker_platform", lambda: "linux/arm64")
    monkeypatch.setattr(runner, "build_image_with_metadata", fake_build)
    monkeypatch.setattr(runner, "_local_manifest_digest", fake_local)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    built = runner._build_task_image_candidate(task)

    assert built == runner._BuiltImage(expected_ref, IMAGE_DIGEST, "linux/arm64")
    assert state["temporary_ref"].startswith(f"agent-eval/{task.id}:governed-")
    assert len(state["temporary_ref"].rpartition("-")[2]) == 32
    assert state["tagged"] is True
    assert state["removed"] is True


def test_candidate_build_rejects_multi_platform_index_metadata(monkeypatch):
    task = load_task("example-todo-api")
    cleaned = []

    def fake_build(context_dir, image_ref, *, platform, metadata_file):
        del context_dir, platform
        metadata_file.write_text(
            json.dumps(
                {
                    "containerimage.digest": IMAGE_DIGEST,
                    "containerimage.descriptor": {
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "digest": IMAGE_DIGEST,
                    },
                }
            ),
            encoding="utf-8",
        )
        cleaned.append(image_ref)

    def fake_run(command, **kwargs):
        del kwargs
        assert command[:3] == ["docker", "image", "rm"]
        assert command[-1] == cleaned[0]
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(runner, "_docker_platform", lambda: "linux/amd64")
    monkeypatch.setattr(runner, "build_image_with_metadata", fake_build)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    with pytest.raises(KubeError, match="one platform manifest"):
        runner._build_task_image_candidate(task)

    assert len(cleaned) == 1


@pytest.mark.parametrize("test_exit_code, resolved", [(0, True), (1, False)])
def test_eval_replaces_workspace_and_requires_test_command_success(
    monkeypatch, tmp_path, test_exit_code, resolved
):
    task = _cooperative_task()
    pod = _SuccessfulEvalPod(test_exit_code)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = runner.run_eval_phase(task, workspace, run_dir)

    assert pod.events[1] == (
        "exec",
        "rm -rf /workspace/* /workspace/.[!.]* /workspace/..?*",
    )
    assert pod.events[2] == ("copy_to", "/workspace")
    assert pod.events.index(("exec", runner._AGENT_QUIESCE_COMMAND)) < (
        pod.events.index(("copy_from", "/results"))
    )
    assert result.command_exit_code == test_exit_code
    assert result.resolved is resolved
    assert pod.deleted is True


@pytest.mark.parametrize("ready", [True, False])
def test_isolated_eval_keeps_submission_out_of_trusted_test_domain(
    monkeypatch, tmp_path, ready
):
    task = load_task("example-todo-api")
    submission = _BlackBoxPod("submission")
    evaluator = _BlackBoxPod("eval")
    pods = iter((submission, evaluator))
    create_calls = []
    link = _BlackBoxLink()

    def fake_create(prefix, image, **kwargs):
        pod = next(pods)
        assert pod.role == prefix
        create_calls.append((prefix, image, kwargs))
        return pod

    def fake_link(evaluator_name, submission_name, port):
        assert evaluator_name == evaluator.name
        assert submission_name == submission.name
        assert port == task.evaluation.submission_port == 8080
        return link

    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "create_sandbox_pod", fake_create)
    monkeypatch.setattr(runner, "create_black_box_link", fake_link)
    monkeypatch.setattr(
        runner,
        "_wait_for_submission_readiness",
        lambda *args, **kwargs: ready,
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    # This can affect cooperative pytest, but is inert in the submission-only pod.
    (workspace / "conftest.py").write_text("raise SystemExit('not imported')\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = runner.run_eval_phase(task, workspace, run_dir)

    assert result.resolved
    assert result.evaluation_mode == "isolated-black-box"
    assert result.runtime_image_digest == IMAGE_DIGEST
    assert result.submission_runtime_image_digest == IMAGE_DIGEST
    assert [event[1] for event in submission.events if event[0] == "copy_to"] == [
        "/workspace"
    ]
    assert all(event[0] != "copy_from" for event in submission.events)
    assert {event[1] for event in evaluator.events if event[0] == "copy_to"} == {
        "/tests"
    }
    assert [event[1] for event in evaluator.events if event[0] == "copy_from"] == [
        "/results"
    ]
    test_exec = next(
        event
        for event in evaluator.events
        if event[0] == "exec" and ".agent-eval-pytest.py" in event[1]
    )
    assert test_exec[3] == {
        "AGENT_EVAL_EVALUATION_MODE": "isolated-black-box",
        "AGENT_EVAL_SUBMISSION_URL": "http://10.42.0.19:8080",
    }
    submission_command = create_calls[0][2]["container_command"][-1]
    assert "exec python -m uvicorn" in submission_command
    assert ">/dev/null 2>&1" in submission_command
    assert create_calls[0][2]["egress_mode"] == "deny"
    assert create_calls[1][2]["egress_mode"] == "deny"
    assert submission.deleted and evaluator.deleted and link.deleted
    output = (run_dir / "eval-output.txt").read_text()
    assert ("readiness timed out" in output) is (not ready)


def test_submission_readiness_probe_runs_inside_evaluator_boundary():
    calls = []

    class ProbePod:
        def exec(self, command, timeout=None, env=None):
            calls.append((command, timeout, env))
            return subprocess.CompletedProcess(
                command,
                0 if len(calls) == 2 else 1,
                stdout=b"",
                stderr=b"",
            )

    assert runner._wait_for_submission_readiness(
        ProbePod(),
        address="10.42.0.19",
        port=8080,
        path="/openapi.json",
        timeout_seconds=2,
    )

    assert len(calls) == 2
    assert all(call[1] == 3 for call in calls)
    assert calls[0][2] == {
        "AGENT_EVAL_SUBMISSION_HOST": "10.42.0.19",
        "AGENT_EVAL_SUBMISSION_PORT": "8080",
        "AGENT_EVAL_READINESS_PATH": "/openapi.json",
    }
    assert "http.client.HTTPConnection" in calls[0][0]


def test_isolated_submission_stall_is_a_correctness_failure(monkeypatch, tmp_path):
    task = load_task("example-todo-api")

    class StalledSubmissionPod(_BlackBoxPod):
        def exec(self, command, timeout=None, env=None):
            if ".agent-eval-pytest.py" in command:
                raise subprocess.TimeoutExpired(command, timeout)
            return super().exec(command, timeout=timeout, env=env)

    pod = StalledSubmissionPod("eval")
    monkeypatch.setattr(runner, "_sandbox_infra_error", lambda *args: None)
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = runner._run_hidden_tests_in_pod(
        task,
        pod,
        run_dir,
        IMAGE_DIGEST,
        workspace=None,
        isolated_black_box=True,
        submission_url="http://10.42.0.19:8080",
    )

    assert result.infra_error is None
    assert result.command_exit_code == 124
    assert result.failures == ["test command timed out after 300s"]
    assert not result.resolved


def test_eval_quiescence_failure_blocks_result_copy(monkeypatch, tmp_path):
    task = _cooperative_task()
    pod = _SuccessfulEvalPod(quiescence_exit_code=73)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = runner.run_eval_phase(task, workspace, run_dir)

    assert result.command_exit_code == 0
    assert result.infra_error == "evaluator process quiescence failed with exit 73"
    assert ("copy_from", "/results") not in pod.events
    assert result.runtime_image_digest == IMAGE_DIGEST
    assert pod.deleted is True


def test_eval_preserves_coverage_integrity_evidence(monkeypatch, tmp_path):
    task = _cooperative_task()
    pod = _SuccessfulEvalPod()
    copy_results = pod.copy_dir_from

    def copy_invalid_coverage(remote_dir, local_dir):
        copy_results(remote_dir, local_dir)
        (local_dir / "coverage.json").write_text(
            '{"totals": {"percent_covered": 10}, "totals": {"percent_covered": 90}}'
        )

    pod.copy_dir_from = copy_invalid_coverage
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = runner.run_eval_phase(task, workspace, run_dir)

    assert result.infra_error is None
    assert "duplicate JSON key" in (result.integrity_error or "")
    assert result.failures[-1] == result.integrity_error
    assert not result.resolved


def test_eval_cleanup_failure_becomes_infrastructure_evidence(monkeypatch, tmp_path):
    task = _cooperative_task()
    pod = _SuccessfulEvalPod()
    delete_attempts = 0

    def fail_delete():
        nonlocal delete_attempts
        delete_attempts += 1
        raise KubeError("API unavailable")

    pod.delete = fail_delete
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = runner.run_eval_phase(task, workspace, run_dir)

    assert delete_attempts == 3
    assert not result.resolved
    assert "eval pod cleanup failed after 3 attempts" in result.infra_error
    assert "eval pod cleanup failed" in (run_dir / "eval-output.txt").read_text()


def test_eval_local_archive_failure_becomes_integrity_evidence(monkeypatch, tmp_path):
    task = _cooperative_task()
    pod = _SuccessfulEvalPod()

    def refuse_copy(local_dir, remote_dir):
        del local_dir, remote_dir
        raise UnsafeArchiveError("local transfer tree expands beyond limit")

    pod.copy_dir_to = refuse_copy
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = runner.run_eval_phase(task, workspace, run_dir)

    assert result.command_exit_code == 126
    assert "local transfer tree expands beyond limit" in result.integrity_error
    assert pod.deleted is True


def test_evaluate_workspace_promotes_eval_runtime_digest_to_provenance(
    monkeypatch, tmp_path
):
    task = load_task("example-todo-api")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    persisted = []

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(
        runner,
        "_capture_provenance",
        lambda task, record: setattr(record.provenance, "image_tag", task.image_tag),
    )
    monkeypatch.setattr(
        runner,
        "run_eval_phase",
        lambda *args, **kwargs: EvalTestResults(
            evaluation_mode="isolated-black-box",
            total=1,
            passed=1,
            command_exit_code=0,
            runtime_image_digest=IMAGE_DIGEST,
            submission_runtime_image_digest=IMAGE_DIGEST,
        ),
    )
    monkeypatch.setattr(runner, "compute_diff", lambda *args: runner.DiffStats())
    monkeypatch.setattr(
        runner, "_persist_run", lambda task, record: persisted.append(record)
    )

    record = runner.evaluate_workspace(
        task, workspace, run_scans=False, run_judge=False
    )

    assert record.provenance.eval_image_digest == IMAGE_DIGEST
    assert record.provenance.submission_image_digest == IMAGE_DIGEST
    assert record.provenance.image_digest == IMAGE_DIGEST
    assert persisted == [record]


def test_agent_process_quiescence_precedes_workspace_snapshot(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    pod = _SnapshotAgentPod()

    class Adapter:
        name = "test-agent"
        env = {}

        def build_command(self, model=None):
            del model
            return "run-agent"

        def parse_transcript(self, transcript):
            assert transcript.is_file()
            return AgentMetrics()

    def fake_evaluate(task, workspace, *, record, **kwargs):
        del task, workspace, kwargs
        pod.events.append("evaluate")
        record.correctness = EvalTestResults(
            total=1,
            passed=1,
            command_exit_code=0,
        )
        return record

    monkeypatch.delenv("AGENT_EVAL_CREDENTIAL_COMMAND", raising=False)
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    monkeypatch.setattr(runner, "evaluate_workspace", fake_evaluate)

    record = runner.run_agent_trial(task, Adapter())

    assert record.correctness.resolved
    assert pod.events.index("quiesce:5") < pod.events.index("snapshot:/workspace")
    assert pod.events.index("snapshot:/workspace") < pod.events.index("evaluate")
    assert pod.deleted is True


def test_failed_agent_quiescence_blocks_snapshot_and_evaluation(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    pod = _SnapshotAgentPod(quiescence_exit_code=73)

    class Adapter:
        name = "test-agent"
        env = {}

        def build_command(self, model=None):
            del model
            return "run-agent"

        def parse_transcript(self, transcript):
            assert transcript.is_file()
            return AgentMetrics()

    monkeypatch.delenv("AGENT_EVAL_CREDENTIAL_COMMAND", raising=False)
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    monkeypatch.setattr(
        runner,
        "evaluate_workspace",
        lambda *args, **kwargs: pytest.fail("unquiesced snapshot was evaluated"),
    )
    monkeypatch.setattr(runner, "_capture_provenance", lambda *args: None)
    monkeypatch.setattr(
        runner,
        "_complete_record",
        lambda task, record, audit: record,
    )

    record = runner.run_agent_trial(task, Adapter())

    expected = "agent process quiescence failed with exit 73"
    assert record.efficiency.infra_error == expected
    assert record.correctness.infra_error == expected
    assert not any(event.startswith("snapshot:") for event in pod.events)
    assert pod.deleted is True


def test_agent_quiescence_is_bounded_and_preserves_control_pids():
    calls = []

    class TimeoutPod:
        def exec(self, command, timeout=None, env=None):
            del env
            calls.append((command, timeout))
            raise subprocess.TimeoutExpired(command, timeout)

    error = runner._quiesce_agent_processes(TimeoutPod())

    command, timeout = calls[0]
    assert timeout == runner._AGENT_QUIESCE_TIMEOUT_SECONDS == 5
    assert '1|"$self") continue' in command
    assert "state=${stat_tail%% *}" in command
    assert '[ "$state" = "Z" ] && continue' in command
    assert '[ -e "$process" ] && exit 69' in command
    assert '[ -e "$process" ] && exit 71' in command
    assert "signal=KILL" in command
    assert error == "agent process quiescence timed out after 5s"


def test_agent_deadline_is_persisted_as_infrastructure_evidence(monkeypatch, tmp_path):
    task = load_task("example-todo-api").model_copy(
        update={
            "resources": SandboxResources.model_validate(
                {"agent": {"limits": {"cpu": "3"}}}
            )
        }
    )
    pod = _AgentDeadlinePod()
    create_args = {}
    saved = []

    def fake_create(*args, **kwargs):
        create_args.update(kwargs)
        return pod

    class Adapter:
        name = "test-agent"

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(runner, "create_sandbox_pod", fake_create)
    monkeypatch.setattr(runner, "save_run", saved.append)

    record = runner.run_agent_trial(task, Adapter())

    expected = (
        "agent sandbox infrastructure failure: "
        "DeadlineExceeded pod was active longer than its deadline"
    )
    assert record.efficiency.infra_error == expected
    assert record.correctness.infra_error == expected
    assert create_args["resources"]["limits"]["cpu"] == "3"
    assert saved == [record]
    assert pod.deleted is True


def test_agent_timeout_is_an_explicit_failed_outcome(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    pod = _AgentTimeoutPod()

    class Adapter:
        name = "test-agent"
        env = {}

        def build_command(self, model=None):
            return "run-agent"

        def parse_transcript(self, transcript):
            return AgentMetrics()

    def fake_evaluate(task, workspace, *, record, **kwargs):
        record.correctness = EvalTestResults(
            total=1,
            passed=1,
            command_exit_code=0,
            infra_error=record.efficiency.infra_error,
        )
        return record

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    monkeypatch.setattr(runner, "evaluate_workspace", fake_evaluate)

    record = runner.run_agent_trial(task, Adapter())

    assert record.efficiency.timed_out is True
    assert record.efficiency.infra_error == (
        "agent timed out after 900s; agent process quiescence timed out after 5s"
    )
    assert record.correctness.infra_error == record.efficiency.infra_error
    assert not record.correctness.resolved
    assert pod.deleted is True


def test_validate_task_rejects_a_starter_that_already_passes(monkeypatch):
    task = load_task("example-todo-api")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(
        runner,
        "run_eval_phase",
        lambda task, workspace, run_dir, **kwargs: EvalTestResults(
            total=1, passed=1, command_exit_code=0
        ),
    )

    with pytest.raises(ValueError, match="starter workspace must fail"):
        runner.validate_task(task)


def test_eval_rejects_submitted_pytest_shadow_before_starting_pod(
    monkeypatch, tmp_path
):
    task = _cooperative_task()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pytest.py").write_text(
        "open('/results/junit.xml', 'w').write('<testsuite tests=\"1\"/>')\n"
    )
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setattr(
        runner,
        "create_sandbox_pod",
        lambda *args, **kwargs: pytest.fail("unsafe workspace reached Kubernetes"),
    )

    result = runner.run_eval_phase(task, workspace, run_dir)

    assert not result.resolved
    assert result.command_exit_code == 126
    assert result.integrity_error == "evaluator-control path changed: pytest.py"


def test_isolated_evaluate_workspace_does_not_apply_cooperative_pytest_controls(
    monkeypatch, tmp_path
):
    task = load_task("example-todo-api")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "conftest.py").write_text("raise SystemExit('submission only')\n")

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "_capture_provenance", lambda task, record: None)
    monkeypatch.setattr(
        runner,
        "run_eval_phase",
        lambda *args, **kwargs: EvalTestResults(
            evaluation_mode="isolated-black-box",
            total=1,
            passed=1,
            command_exit_code=0,
            runtime_image_digest=IMAGE_DIGEST,
            submission_runtime_image_digest=IMAGE_DIGEST,
        ),
    )
    monkeypatch.setattr(runner, "compute_diff", lambda *args: runner.DiffStats())
    monkeypatch.setattr(runner, "_persist_run", lambda task, record: None)

    record = runner.evaluate_workspace(
        task,
        workspace,
        run_scans=False,
        run_judge=False,
    )

    assert record.correctness.resolved
    assert record.correctness.integrity_error is None


def test_workspace_symlinks_are_rejected_before_host_diffing(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "safe.txt").write_text("safe\n")
    (workspace / "alias.txt").symlink_to("safe.txt")

    error = runner._workspace_safety_error(workspace)

    assert error == "workspace symlink alias.txt is not allowed"


def test_judge_input_requires_successful_zero_secret_scan():
    from agent_eval.metrics import RunRecord, ScanResults

    record = RunRecord(run_id="r", task_id="t", agent="external")
    assert not runner._judge_input_is_safe(record)

    record.scans = ScanResults(secrets_found=1, scanner_status={"gitleaks": "ok"})
    assert not runner._judge_input_is_safe(record)

    record.scans = ScanResults(secrets_found=0, scanner_status={"gitleaks": "ok"})
    assert runner._judge_input_is_safe(record)

    record.diff.complete = False
    record.diff.error_code = "output_limit"
    assert not runner._judge_input_is_safe(record)


def test_compute_diff_caps_untrusted_output(monkeypatch, tmp_path):
    starter = tmp_path / "starter"
    produced = tmp_path / "produced"
    run_dir = tmp_path / "run"
    starter.mkdir()
    produced.mkdir()
    run_dir.mkdir()
    (starter / "payload.txt").write_text("old\n" * 1_000)
    (produced / "payload.txt").write_text("new\n" * 1_000)
    monkeypatch.setattr(runner, "DIFF_MAX_BYTES", 512)

    stats = runner.compute_diff(starter, produced, run_dir)

    assert stats.complete is False
    assert stats.error_code == "output_limit"
    assert stats.files_changed == 1
    assert stats.lines_added == 1_000
    assert stats.lines_removed == 1_000
    assert (run_dir / "workspace.diff").stat().st_size <= 512


def test_capped_git_output_enforces_deadline(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "DIFF_TIMEOUT_SECONDS", 0.01)
    started = time.monotonic()

    result = runner._stream_git_output(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=tmp_path,
        destination=tmp_path / "output",
        maximum_bytes=1_024,
    )

    assert result.error_code == "timeout"
    assert time.monotonic() - started < 1


def test_deleted_starter_secret_blocks_coding_judge(monkeypatch, tmp_path):
    from agent_eval.evaluators import judge, scanners
    from agent_eval.metrics import ScanResults

    task_dir = tmp_path / "task"
    starter = task_dir / "environment" / "workspace"
    tests_dir = task_dir / "tests"
    starter.mkdir(parents=True)
    tests_dir.mkdir()
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    (starter / "legacy.txt").write_text(f"token={secret}\n")
    (task_dir / "environment" / "Dockerfile").write_text("FROM scratch\n")
    task = load_task("example-todo-api").model_copy(update={"path": task_dir})
    produced = tmp_path / "produced"
    produced.mkdir()

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "_capture_provenance", lambda task, record: None)
    monkeypatch.setattr(
        runner,
        "run_eval_phase",
        lambda *args, **kwargs: EvalTestResults(total=1, passed=1, command_exit_code=0),
    )

    def fake_scanners(scan_root, *args, **kwargs):
        screened_diff = (scan_root / ".agent-eval-workspace.diff").read_text()
        model_context = (scan_root / ".agent-eval-model-context.txt").read_text()
        assert secret in screened_diff
        assert "spec_adherence" in model_context
        return ScanResults(
            secrets_found=1,
            scanner_status={"gitleaks": "ok"},
        )

    monkeypatch.setattr(scanners, "run_scanners", fake_scanners)
    monkeypatch.setattr(
        judge,
        "run_judge",
        lambda *args, **kwargs: pytest.fail("deleted secret reached judge"),
    )

    record = runner.evaluate_workspace(task, produced)

    assert record.judge.weighted_score is None
    assert (record.run_dir / "judge-skipped.txt").is_file()


@pytest.mark.parametrize("leak_location", ["prompt", "deleted-diff"])
def test_exact_projected_credential_blocks_judge_when_gitleaks_is_clear(
    monkeypatch,
    tmp_path,
    leak_location,
):
    from agent_eval.evaluators import judge, scanners
    from agent_eval.metrics import ScanResults

    task_dir = tmp_path / "task"
    starter = task_dir / "environment" / "workspace"
    tests_dir = task_dir / "tests"
    starter.mkdir(parents=True)
    tests_dir.mkdir()
    (task_dir / "environment" / "Dockerfile").write_text("FROM scratch\n")
    credential = "ordinary-projected-credential"
    produced = tmp_path / "produced"
    produced.mkdir()
    if leak_location == "prompt":
        (starter / "app.txt").write_text("old\n")
        (produced / "app.txt").write_text("new\n")
        prompt = f"Implement the change using {credential}."
    else:
        (starter / "legacy.txt").write_text(f"token={credential}\n")
        prompt = "Remove the obsolete credential file."
    task = load_task("example-todo-api").model_copy(
        update={"path": task_dir, "prompt": prompt}
    )
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": credential}, env_keys=("TOKEN",))
    )

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "_capture_provenance", lambda task, record: None)
    monkeypatch.setattr(
        runner,
        "run_eval_phase",
        lambda *args, **kwargs: EvalTestResults(total=1, passed=1, command_exit_code=0),
    )
    monkeypatch.setattr(
        scanners,
        "run_scanners",
        lambda *args, **kwargs: ScanResults(
            secrets_found=0,
            scanner_status={"gitleaks": "ok"},
        ),
    )
    monkeypatch.setattr(
        judge,
        "run_judge",
        lambda *args, **kwargs: pytest.fail(
            "exact projected credential reached the judge"
        ),
    )

    record = runner.evaluate_workspace(
        task,
        produced,
        _credential_redactor=redactor,
    )

    reason = (record.run_dir / "judge-skipped.txt").read_text()
    assert "projected credential material" in reason
    assert credential not in reason
    assert record.judge.weighted_score is None


def test_credential_setup_failure_is_persisted_as_infrastructure_outcome(
    monkeypatch, tmp_path
):
    task = load_task("example-todo-api")

    class Adapter:
        name = "codex"

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(
        runner,
        "load_trial_credentials",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("credential unavailable")
        ),
    )

    record = runner.run_agent_trial(task, Adapter())

    assert record.outcome.status == "infra_error"
    assert "credential unavailable" in record.efficiency.infra_error
    assert (record.run_dir / "results.json").is_file()
    assert (metrics.RUNS_ROOT / "metrics.db").is_file()


def test_agent_credentials_are_redacted_from_outputs_proxy_and_attestation(
    monkeypatch, tmp_path
):
    task = load_task("example-todo-api")
    api_key = "sk-agent-output-exfiltration-secret"
    access_token = "codex-access-token-from-auth-file"
    auth = json.dumps(
        {
            "tokens": {
                "access_token": access_token,
                "refresh_token": "codex-refresh-token-from-auth-file",
            },
            "mode": "chatgpt",
        }
    )
    material = CredentialMaterial(
        values={"API_KEY": api_key, "codex-auth": auth},
        env_keys=("API_KEY",),
        file_items={"codex-auth": "codex-auth.json"},
        source="test-broker",
    )
    stdout = (
        json.dumps(
            {
                "type": "agent.message",
                "api_key": api_key,
                "access_token": access_token,
                "auth_file": auth,
            }
        )
        + "\n"
    ).encode()
    pod = _CredentialExfilPod(
        task.workspace_dir,
        stdout=stdout,
        stderr=f"stderr={api_key} auth={auth}".encode(),
    )
    proxy = _CredentialProxy(
        f"CONNECT provider.invalid/path?key={api_key}&token={access_token}"
    )
    secret = _TrialSecret()

    class Adapter:
        name = "codex"
        env = {}

        def build_command(self, model=None):
            del model
            return "run-agent"

        def parse_transcript(self, transcript):
            persisted = transcript.read_bytes()
            assert api_key.encode() not in persisted
            assert access_token.encode() not in persisted
            assert auth.encode() not in persisted
            # A hostile/custom parser must not be able to reintroduce a known
            # credential into results.json or the attestation model identity.
            return AgentMetrics(model=api_key)

    def fake_evaluate(task, workspace, *, record, _credential_redactor, **kwargs):
        del kwargs
        assert workspace == record.run_dir / "workspace"
        record.correctness = EvalTestResults(
            evaluation_mode=task.evaluation.mode,
            total=1,
            passed=1,
            coverage_percent=100.0,
            command_exit_code=0,
            runtime_image_digest=IMAGE_DIGEST,
            submission_runtime_image_digest=IMAGE_DIGEST,
        )
        record.provenance.image_tag = task.image_tag
        record.provenance.image_digest = IMAGE_DIGEST
        record.provenance.harness_commit = "b" * 40
        record.provenance.harness_dirty = False
        record.provenance.harness_worktree_sha256 = CLEAN_WORKTREE_SHA256
        return runner._complete_record(
            task,
            record,
            None,
            credential_redactor=_credential_redactor,
        )

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(
        runner, "load_trial_credentials", lambda *args, **kwargs: material
    )
    monkeypatch.setattr(runner, "create_trial_secret", lambda value, **kwargs: secret)
    monkeypatch.setattr(runner, "create_egress_proxy", lambda *args, **kwargs: proxy)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    monkeypatch.setattr(runner, "evaluate_workspace", fake_evaluate)

    record = runner.run_agent_trial(
        task,
        Adapter(),
        run_scans=False,
        run_judge=False,
    )

    assert (record.run_dir / "attestation.json").is_file()
    assert b"redacted-credential" in (record.run_dir / "transcript.jsonl").read_bytes()
    assert b"redacted-credential" in (record.run_dir / "agent-stderr.log").read_bytes()
    assert b"redacted-credential" in (record.run_dir / "egress-proxy.log").read_bytes()
    for artifact in record.run_dir.rglob("*"):
        if artifact.is_file():
            contents = artifact.read_bytes()
            for credential in (api_key, access_token, auth):
                assert credential.encode() not in contents
    assert pod.deleted is True
    assert proxy.deleted is True
    assert secret.deleted is True


@pytest.mark.parametrize("leak_location", ["content", "path"])
def test_workspace_credential_exfiltration_is_dropped_before_durable_promotion(
    monkeypatch,
    tmp_path,
    leak_location,
):
    task = load_task("example-todo-api").model_copy(
        update={
            "network": load_task("example-todo-api").network.model_copy(
                update={"agent_mode": "open", "allowed_domains": []}
            )
        }
    )
    credential = "workspace-exfiltration-credential"
    material = CredentialMaterial(
        values={"API_KEY": credential},
        env_keys=("API_KEY",),
        source="test-broker",
    )
    pod = _CredentialExfilPod(
        task.workspace_dir,
        stdout=f"printed={credential}".encode(),
        workspace_content=credential if leak_location == "content" else None,
        workspace_path=credential if leak_location == "path" else None,
    )
    secret = _TrialSecret()

    class Adapter:
        name = "codex"
        env = {}

        def build_command(self, model=None):
            del model
            return "run-agent"

        def parse_transcript(self, transcript):
            assert credential.encode() not in transcript.read_bytes()
            return AgentMetrics()

    def capture(task, record):
        record.provenance.image_tag = task.image_tag
        record.provenance.image_digest = IMAGE_DIGEST

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda tag: IMAGE_DIGEST)
    monkeypatch.setattr(
        runner, "load_trial_credentials", lambda *args, **kwargs: material
    )
    monkeypatch.setattr(runner, "create_trial_secret", lambda value, **kwargs: secret)
    monkeypatch.setattr(runner, "create_sandbox_pod", lambda *args, **kwargs: pod)
    monkeypatch.setattr(runner, "_capture_provenance", capture)
    monkeypatch.setattr(
        runner,
        "evaluate_workspace",
        lambda *args, **kwargs: pytest.fail(
            "credential-bearing snapshot was evaluated"
        ),
    )

    record = runner.run_agent_trial(
        task,
        Adapter(),
        run_scans=False,
        run_judge=False,
    )

    assert record.correctness.integrity_error == (
        "agent workspace contains projected credential material"
    )
    assert not (record.run_dir / "workspace").exists()
    assert (record.run_dir / "results.json").is_file()
    for artifact in record.run_dir.rglob("*"):
        if artifact.is_file():
            assert credential.encode() not in artifact.read_bytes()
    assert pod.deleted is True
    assert secret.deleted is True


def test_non_governed_containment_failure_removes_artifact_and_persists_failure(
    monkeypatch,
    tmp_path,
):
    task = load_task("example-todo-api")
    credential = "late-derived-artifact-credential"
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": credential}, env_keys=("TOKEN",))
    )
    record = metrics.RunRecord(
        run_id="non-governed-containment",
        task_id=task.id,
        agent="codex",
        started_at=metrics.now_iso(),
    )
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    runner.prepare_run_dir(record, exist_ok=False)
    leaked = record.run_dir / "derived-agent-output.log"
    leaked.write_text(f"unsafe={credential}\n")

    completed = runner._complete_record(
        task,
        record,
        None,
        credential_redactor=redactor,
    )

    assert not leaked.exists()
    assert completed.outcome.status == "infra_error"
    assert "credential containment failed" in completed.efficiency.infra_error
    assert (completed.run_dir / "results.json").is_file()
    for artifact in completed.run_dir.rglob("*"):
        if artifact.is_file():
            assert credential.encode() not in artifact.read_bytes()


def test_task_derived_credential_is_redacted_before_every_persistence(
    monkeypatch,
    tmp_path,
):
    task = load_task("example-todo-api")
    assert task.dataset is not None
    credential = task.dataset.id
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": credential}, env_keys=("TOKEN",))
    )
    record = metrics.RunRecord(
        run_id="task-derived-credential",
        task_id=task.id,
        agent="codex",
        started_at=metrics.now_iso(),
    )
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    runner.prepare_run_dir(record, exist_ok=False)

    completed = runner._complete_record(
        task,
        record,
        None,
        credential_redactor=redactor,
    )

    assert all(
        assessment.dataset_id != credential for assessment in completed.assessments
    )
    for artifact in (tmp_path / "runs").rglob("*"):
        if artifact.is_file():
            assert credential.encode() not in artifact.read_bytes()


def test_record_redaction_failure_scrubs_artifacts_before_failing(
    monkeypatch,
    tmp_path,
):
    task = load_task("example-todo-api")
    credential = "agent"
    redactor = CredentialRedactor.from_material(
        CredentialMaterial(values={"TOKEN": credential}, env_keys=("TOKEN",))
    )
    record = metrics.RunRecord(
        run_id="schema-collision-credential",
        task_id=task.id,
        agent="codex",
        started_at=metrics.now_iso(),
    )
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    runner.prepare_run_dir(record, exist_ok=False)
    leaked = record.run_dir / "derived.log"
    leaked.write_text(f"unsafe={credential}\n")

    with pytest.raises(
        runner.CredentialRedactionError,
        match="run evidence could not be safely redacted",
    ):
        runner._complete_record(
            task,
            record,
            None,
            credential_redactor=redactor,
        )

    assert not leaked.exists()
    for artifact in record.run_dir.rglob("*"):
        if artifact.is_file():
            assert credential.encode() not in artifact.read_bytes()


def test_cleanup_resources_are_independent_when_pod_delete_fails(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    deleted = []

    class Adapter:
        name = "codex"

    class Secret:
        name = "secret"

        def delete(self):
            deleted.append("secret")

    class Proxy:
        name = "proxy"
        endpoint = "http://10.0.0.2:3128"

        def logs(self):
            return ""

        def delete(self):
            deleted.append("proxy")

    class FailingPod:
        def wait_ready(self):
            raise KubeError("not ready")

        def infrastructure_failure(self, command_exit_code=None):
            return "ImagePullBackOff"

        def delete(self):
            deleted.append("pod")
            raise subprocess.TimeoutExpired("delete", 60)

    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "ensure_image", lambda task: None)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(
        runner,
        "load_trial_credentials",
        lambda *args, **kwargs: CredentialMaterial(
            values={"codex-auth": "{}"},
            file_items={"codex-auth": "codex-auth.json"},
        ),
    )
    monkeypatch.setattr(
        runner, "create_trial_secret", lambda material, **kwargs: Secret()
    )
    monkeypatch.setattr(runner, "create_egress_proxy", lambda *args, **kwargs: Proxy())
    monkeypatch.setattr(
        runner, "create_sandbox_pod", lambda *args, **kwargs: FailingPod()
    )

    record = runner.run_agent_trial(task, Adapter())

    assert record.outcome.status == "infra_error"
    assert deleted == ["pod", "pod", "pod", "proxy", "secret"]
    assert "agent pod cleanup failed after 3 attempts" in record.efficiency.infra_error


def test_failed_secret_cleanup_includes_exact_operator_remediation(monkeypatch):
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)

    class Secret:
        name = "agent-credential-exact"
        cleanup_command = (
            "kubectl --context k3d-agent-eval -n agent-eval delete secret "
            "agent-credential-exact --ignore-not-found --wait=true"
        )

        def delete(self):
            raise KubeError("API unavailable")

    error = runner._delete_with_retries(Secret(), "credential Secret")

    assert error is not None
    assert "resource=agent-credential-exact" in error
    assert f"remediation={Secret.cleanup_command}" in error
