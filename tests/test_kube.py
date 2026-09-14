import hashlib
import io
import ipaddress
import json
import subprocess
import tarfile

import pytest
from pydantic import ValidationError

from agent_eval.kube import (
    DEFAULT_SANDBOX_RESOURCES,
    K3S_CLUSTER_DNS_SERVICE_CIDR,
    K3S_POD_CIDR,
    K3S_SERVICE_CIDR,
    PROXY_BLOCKED_IPV4_CIDRS,
    PROXY_BLOCKED_IPV6_CIDRS,
    PROXY_PUBLIC_IPV6_CIDR,
    PROXY_PUBLIC_IPV6_EXCEPT_CIDRS,
    CommandOutputLimitError,
    KubeError,
    Pod,
    SandboxLink,
    TrialSecret,
    UnsafeArchiveError,
    black_box_link_policy_manifests,
    create_egress_proxy,
    create_sandbox_pod,
    egress_proxy_manifests,
    ensure_namespace,
    sandbox_egress_policy_manifest,
    sandbox_pod_manifest,
)
from agent_eval.task import PodResources, SandboxResources, load_task


def test_sandbox_manifest_removes_ambient_cluster_privilege():
    manifest = sandbox_pod_manifest(
        "agent-deadbeef",
        "agent",
        "agent-eval/example:latest",
        env_from_secret="agent-api-keys",
        active_deadline=123,
    )

    pod = manifest["spec"]
    container = pod["containers"][0]
    security = container["securityContext"]
    assert container["command"] == ["sleep", "infinity"]

    assert pod["automountServiceAccountToken"] is False
    assert pod["enableServiceLinks"] is False
    assert pod["activeDeadlineSeconds"] == 123
    assert security == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "runAsGroup": 10001,
        "readOnlyRootFilesystem": True,
    }
    assert container["resources"] == DEFAULT_SANDBOX_RESOURCES
    assert container["env"][:2] == [
        {"name": "HOME", "value": "/home/agent"},
        {"name": "TMPDIR", "value": "/tmp"},
    ]
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert {mount["mountPath"] for mount in container["volumeMounts"]} >= {
        "/workspace", "/tmp", "/home/agent", "/tests", "/results"
    }


def test_runtime_class_propagates_to_all_workload_pods(monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_RUNTIME_CLASS", "gvisor-sandbox")

    sandbox = sandbox_pod_manifest(
        "agent-deadbeef", "agent", "agent-eval/example:latest"
    )
    proxy = egress_proxy_manifests(
        "egress-one", "ubuntu/squid:example", [".openai.com"]
    )[1]

    assert sandbox["spec"]["runtimeClassName"] == "gvisor-sandbox"
    assert proxy["spec"]["runtimeClassName"] == "gvisor-sandbox"
    assert proxy["spec"]["containers"][0]["resources"] == {
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
    }


def test_runtime_class_is_omitted_when_not_configured(monkeypatch):
    monkeypatch.delenv("AGENT_EVAL_RUNTIME_CLASS", raising=False)

    sandbox = sandbox_pod_manifest("eval-one", "eval", "image")
    proxy = egress_proxy_manifests(
        "egress-one", "ubuntu/squid:example", [".openai.com"]
    )[1]

    assert "runtimeClassName" not in sandbox["spec"]
    assert "runtimeClassName" not in proxy["spec"]


@pytest.mark.parametrize("creator", ["namespace", "sandbox", "proxy"])
def test_invalid_runtime_class_fails_before_kubectl(monkeypatch, creator):
    from agent_eval import kube

    monkeypatch.setenv("AGENT_EVAL_RUNTIME_CLASS", "../../unsafe")
    calls = []
    monkeypatch.setattr(kube, "kubectl", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(
        kube.subprocess,
        "run",
        lambda *args, **kwargs: calls.append(args),
    )

    with pytest.raises(ValueError, match="lowercase DNS label"):
        if creator == "namespace":
            ensure_namespace()
        elif creator == "sandbox":
            create_sandbox_pod("eval", "example:image", egress_mode="deny")
        else:
            create_egress_proxy("ubuntu/squid:example", [".openai.com"])

    assert calls == []


def test_ensure_namespace_applies_psa_labels_and_resource_quota(monkeypatch):
    from agent_eval import kube

    namespace_manifests = []
    namespaced_manifests = []
    monkeypatch.setenv("AGENT_EVAL_QUOTA_PODS", "48")
    monkeypatch.setenv("AGENT_EVAL_QUOTA_LIMITS_MEMORY_GI", "80")

    def fake_run(command, **kwargs):
        namespace_manifests.append(json.loads(kwargs["input"]))
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    def fake_kubectl(*args, **kwargs):
        namespaced_manifests.append(json.loads(kwargs["input"]))
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(kube.subprocess, "run", fake_run)
    monkeypatch.setattr(kube, "kubectl", fake_kubectl)

    ensure_namespace()

    assert namespace_manifests == [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "agent-eval",
                "labels": {
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/audit": "restricted",
                    "pod-security.kubernetes.io/warn": "restricted",
                    "pod-security.kubernetes.io/enforce-version": "v1.35",
                    "pod-security.kubernetes.io/audit-version": "v1.35",
                    "pod-security.kubernetes.io/warn-version": "v1.35",
                },
            },
        }
    ]
    quota = namespaced_manifests[0]
    assert quota["kind"] == "ResourceQuota"
    assert quota["spec"]["hard"] == {
        "pods": "48",
        "secrets": "64",
        "configmaps": "32",
        "services": "16",
        "requests.cpu": "8",
        "limits.cpu": "32",
        "requests.memory": "16Gi",
        "limits.memory": "80Gi",
        "requests.ephemeral-storage": "32Gi",
        "limits.ephemeral-storage": "128Gi",
    }
    assert namespaced_manifests[1]["kind"] == "NetworkPolicy"
    assert namespaced_manifests[1]["spec"] == {
        "podSelector": {},
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [],
        "egress": [],
    }


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "unbounded", "9999"])
def test_invalid_namespace_quota_fails_before_kubectl(monkeypatch, value):
    from agent_eval import kube

    monkeypatch.setenv("AGENT_EVAL_QUOTA_PODS", value)
    monkeypatch.setattr(
        kube.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("invalid quota reached kubectl"),
    )
    monkeypatch.setattr(
        kube,
        "kubectl",
        lambda *args, **kwargs: pytest.fail("invalid quota reached kubectl"),
    )

    with pytest.raises(ValueError, match="AGENT_EVAL_QUOTA_PODS"):
        ensure_namespace()


def test_eval_manifest_does_not_receive_agent_secret():
    manifest = sandbox_pod_manifest(
        "eval-deadbeef", "eval", "agent-eval/example:latest"
    )

    container = manifest["spec"]["containers"][0]
    assert all("valueFrom" not in item for item in container["env"])
    assert manifest["metadata"]["labels"]["phase"] == "eval"


def test_governed_manifest_never_pulls_and_rejects_unknown_policy():
    image = "agent-eval/example:governed-" + "a" * 64
    manifest = sandbox_pod_manifest(
        "agent-deadbeef",
        "agent",
        image,
        image_pull_policy="Never",
    )

    assert manifest["spec"]["containers"][0]["image"] == image
    assert manifest["spec"]["containers"][0]["imagePullPolicy"] == "Never"
    with pytest.raises(ValueError, match="image pull policy"):
        sandbox_pod_manifest(
            "agent-deadbeef",
            "agent",
            image,
            image_pull_policy="Always",
        )


@pytest.mark.parametrize(
    ("repo_digest_mode", "accepted"),
    [("empty", True), ("matching", True), ("contradictory", False)],
)
def test_running_image_manifest_binds_containerd_target_to_cri_config(
    monkeypatch,
    repo_digest_mode,
    accepted,
):
    from agent_eval import kube

    config_digest = "sha256:" + "c" * 64
    manifest_content = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": config_digest,
                "size": 123,
            },
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest_content).hexdigest()
    image_ref = f"agent-eval/example:governed-{manifest_digest[7:]}"
    normalized_ref = f"docker.io/{image_ref}"
    expected_repo_digest = f"{normalized_ref.rsplit(':', 1)[0]}@{manifest_digest}"
    repo_digests = {
        "empty": [],
        "matching": [expected_repo_digest],
        "contradictory": [f"{normalized_ref.rsplit(':', 1)[0]}@sha256:" + "f" * 64],
    }[repo_digest_mode]
    pod_value = {
        "spec": {
            "nodeName": "k3d-agent-eval-server-0",
            "containers": [{"image": image_ref}],
        },
        "status": {
            "containerStatuses": [
                {"imageID": f"{normalized_ref.rsplit(':', 1)[0]}@{config_digest}"}
            ]
        },
    }

    monkeypatch.setattr(
        kube,
        "kubectl",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args, 0, stdout=json.dumps(pod_value), stderr=""
        ),
    )

    def fake_bounded(command, timeout):
        assert timeout == 30
        if "crictl" in command:
            payload = {
                "status": {
                    "id": config_digest,
                    "repoTags": [normalized_ref],
                    "repoDigests": repo_digests,
                }
            }
            stdout = json.dumps(payload).encode()
        elif command[-3:-1] == ["images", "list"]:
            stdout = (
                "REF TYPE DIGEST SIZE PLATFORMS LABELS\n"
                f"{normalized_ref} "
                "application/vnd.docker.distribution.manifest.v2+json "
                f"{manifest_digest} 1.0 KiB linux/arm64 "
                "io.cri-containerd.image=managed\n"
            ).encode()
        elif command[-3:-1] == ["content", "get"]:
            stdout = manifest_content
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(kube, "_run_bounded_command", fake_bounded)

    observed = Pod("agent-one").image_manifest_digest(
        image_ref,
        expected_manifest_digest=manifest_digest,
    )
    assert observed == (manifest_digest if accepted else None)


def test_containerd_identity_selects_one_linux_manifest_from_oci_index(
    monkeypatch,
):
    from agent_eval import kube

    config_digest = "sha256:" + "c" * 64
    child_content = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 123,
            },
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    child_digest = "sha256:" + hashlib.sha256(child_content).hexdigest()
    attestation_digest = "sha256:" + "d" * 64
    index_content = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": child_digest,
                    "size": len(child_content),
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": attestation_digest,
                    "size": 1,
                    "platform": {"os": "unknown", "architecture": "unknown"},
                },
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    index_digest = "sha256:" + hashlib.sha256(index_content).hexdigest()
    image_ref = "agent-eval/example:tag"
    normalized_ref = f"docker.io/{image_ref}"

    def fake_bounded(command, timeout):
        assert timeout == 30
        if command[-3:-1] == ["images", "list"]:
            stdout = (
                "REF TYPE DIGEST SIZE PLATFORMS LABELS\n"
                f"{normalized_ref} application/vnd.oci.image.index.v1+json "
                f"{index_digest} 2.0 KiB linux/arm64 "
                "io.cri-containerd.image=managed\n"
            ).encode()
        elif command[-3:-1] == ["content", "get"]:
            stdout = {
                index_digest: index_content,
                child_digest: child_content,
            }[command[-1]]
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(kube, "_run_bounded_command", fake_bounded)

    assert kube.containerd_image_manifest_identity(
        "k3d-agent-eval-server-0", image_ref
    ) == (child_digest, config_digest)


def test_containerd_identity_selects_expected_manifest_from_multiarch_index(
    monkeypatch,
):
    from agent_eval import kube

    config_digest = "sha256:" + "c" * 64
    first_content = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
            },
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    first_digest = "sha256:" + hashlib.sha256(first_content).hexdigest()
    second_digest = "sha256:" + "b" * 64
    index_content = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": first_digest,
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": second_digest,
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    index_digest = "sha256:" + hashlib.sha256(index_content).hexdigest()
    image_ref = "agent-eval/example:tag"
    normalized_ref = f"docker.io/{image_ref}"

    def fake_bounded(command, timeout):
        assert timeout == 30
        if command[-3:-1] == ["images", "list"]:
            stdout = (
                "REF TYPE DIGEST SIZE PLATFORMS LABELS\n"
                f"{normalized_ref} application/vnd.oci.image.index.v1+json "
                f"{index_digest} 2.0 KiB linux/amd64,linux/arm64 "
                "io.cri-containerd.image=managed\n"
            ).encode()
        elif command[-3:-1] == ["content", "get"]:
            stdout = {
                index_digest: index_content,
                first_digest: first_content,
            }[command[-1]]
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(kube, "_run_bounded_command", fake_bounded)

    assert (
        kube.containerd_image_manifest_identity(
            "k3d-agent-eval-server-0", image_ref
        )
        is None
    )
    assert kube.containerd_image_manifest_identity(
        "k3d-agent-eval-server-0",
        image_ref,
        expected_manifest_digest=first_digest,
    ) == (first_digest, config_digest)
    assert (
        kube.containerd_image_manifest_identity(
            "k3d-agent-eval-server-0",
            image_ref,
            expected_manifest_digest="sha256:" + "f" * 64,
        )
        is None
    )


@pytest.mark.parametrize("malformed_content", [b"[]", b"null", b"\xff"])
def test_containerd_identity_rejects_malformed_target_json(
    monkeypatch, malformed_content
):
    from agent_eval import kube

    target_digest = "sha256:" + hashlib.sha256(malformed_content).hexdigest()
    image_ref = "agent-eval/example:tag"
    normalized_ref = f"docker.io/{image_ref}"

    def fake_bounded(command, timeout):
        assert timeout == 30
        if command[-3:-1] == ["images", "list"]:
            stdout = (
                "REF TYPE DIGEST SIZE PLATFORMS LABELS\n"
                f"{normalized_ref} application/vnd.oci.image.manifest.v1+json "
                f"{target_digest} 1 B linux/arm64 "
                "io.cri-containerd.image=managed\n"
            ).encode()
        elif command[-3:-1] == ["content", "get"]:
            stdout = malformed_content
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(kube, "_run_bounded_command", fake_bounded)

    assert (
        kube.containerd_image_manifest_identity(
            "k3d-agent-eval-server-0", image_ref
        )
        is None
    )


def test_credential_secret_projects_only_declared_env_and_files():
    manifest = sandbox_pod_manifest(
        "agent-deadbeef",
        "agent",
        "agent-eval/example:contenthash",
        env_from_secret="trial-secret",
        credential_env_keys=("ANTHROPIC_API_KEY",),
        credential_file_items={"codex-auth": "codex-auth.json"},
    )

    container = manifest["spec"]["containers"][0]
    projected = [item for item in container["env"] if "valueFrom" in item]
    assert projected == [
        {
            "name": "ANTHROPIC_API_KEY",
            "valueFrom": {
                "secretKeyRef": {
                    "name": "trial-secret",
                    "key": "ANTHROPIC_API_KEY",
                }
            },
        }
    ]
    credential_volume = next(
        volume for volume in manifest["spec"]["volumes"]
        if volume["name"] == "credentials"
    )
    assert credential_volume["secret"]["items"] == [
        {"key": "codex-auth", "path": "codex-auth.json"}
    ]


def test_eval_egress_is_empty_and_proxy_egress_is_narrow():
    denied = sandbox_egress_policy_manifest("eval-one", "deny")
    proxied = sandbox_egress_policy_manifest(
        "agent-one", "proxy", proxy_id="egress-one"
    )

    assert denied["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert denied["spec"]["ingress"] == []
    assert denied["spec"]["egress"] == []
    assert denied["spec"]["podSelector"]["matchLabels"] == {
        "sandbox-id": "eval-one"
    }
    proxy_rules = proxied["spec"]["egress"]
    assert len(proxy_rules) == 1
    assert proxy_rules[0]["to"] == [
        {"podSelector": {"matchLabels": {"proxy-id": "egress-one"}}}
    ]
    assert proxy_rules[0]["ports"] == [{"protocol": "TCP", "port": 3128}]


def test_black_box_peer_policies_are_directional_and_port_scoped():
    evaluator, submission = black_box_link_policy_manifests(
        "eval-1234", "submission-5678", 8080
    )

    assert evaluator["spec"] == {
        "podSelector": {"matchLabels": {"sandbox-id": "eval-1234"}},
        "policyTypes": ["Egress"],
        "egress": [
            {
                "to": [
                    {
                        "podSelector": {
                            "matchLabels": {"sandbox-id": "submission-5678"}
                        }
                    }
                ],
                "ports": [{"protocol": "TCP", "port": 8080}],
            }
        ],
    }
    assert submission["spec"] == {
        "podSelector": {"matchLabels": {"sandbox-id": "submission-5678"}},
        "policyTypes": ["Ingress"],
        "ingress": [
            {
                "from": [
                    {
                        "podSelector": {
                            "matchLabels": {"sandbox-id": "eval-1234"}
                        }
                    }
                ],
                "ports": [{"protocol": "TCP", "port": 8080}],
            }
        ],
    }


@pytest.mark.parametrize("port", [0, 1, 1023, 65536, True])
def test_black_box_peer_policy_rejects_unsafe_ports(port):
    with pytest.raises(ValueError, match="between 1024 and 65535"):
        black_box_link_policy_manifests("eval-1234", "submission-5678", port)


def test_pod_ip_is_validated(monkeypatch):
    from agent_eval import kube

    values = iter(["10.42.0.7", "not-an-address", None])

    def fake_kubectl(*args, **kwargs):
        del kwargs
        value = next(values)
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps({"status": {"podIP": value}}),
            stderr="",
        )

    monkeypatch.setattr(kube, "kubectl", fake_kubectl)

    assert Pod("submission-one").ip_address() == "10.42.0.7"
    with pytest.raises(KubeError, match="no valid IP"):
        Pod("submission-one").ip_address()
    with pytest.raises(KubeError, match="no valid IP"):
        Pod("submission-one").ip_address()


def test_sandbox_link_cleanup_attempts_every_policy(monkeypatch):
    from agent_eval import kube

    calls = []

    def fake_kubectl(*args, **kwargs):
        del kwargs
        calls.append(args[2])
        if args[2] == "policy-one":
            raise KubeError("API unavailable")
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(kube, "kubectl", fake_kubectl)

    with pytest.raises(KubeError, match="policy-one"):
        SandboxLink(("policy-one", "policy-two")).delete()

    assert calls == ["policy-one", "policy-two"]


def test_domain_proxy_config_is_default_deny_with_explicit_suffixes():
    manifests = egress_proxy_manifests(
        "egress-one", "ubuntu/squid:example", [".openai.com", ".chatgpt.com"]
    )
    config = manifests[0]["data"]["squid.conf"]

    assert (
        "acl allowed_domains dstdomain -n .chatgpt.com .openai.com" in config
    )
    blocked_acl = next(
        line
        for line in config.splitlines()
        if line.startswith("acl blocked_destination_ips dst ")
    )
    for cidr in (*PROXY_BLOCKED_IPV4_CIDRS, *PROXY_BLOCKED_IPV6_CIDRS):
        assert cidr in blocked_acl.split()
    assert config.index("http_access deny blocked_destination_ips") < config.index(
        "http_access allow allowed_domains"
    )
    assert "http_access allow allowed_domains" in config
    assert "access_log stdio:/dev/stdout" in config
    assert "http_access deny all" in config
    proxy_pod = manifests[1]
    assert proxy_pod["spec"]["activeDeadlineSeconds"] == 3600
    ingress_policy = manifests[3]
    assert ingress_policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert ingress_policy["spec"]["podSelector"]["matchLabels"] == {
        "proxy-id": "egress-one"
    }
    assert ingress_policy["spec"]["ingress"][0]["from"] == [
        {"podSelector": {"matchLabels": {"egress-proxy": "egress-one"}}}
    ]


def test_proxy_egress_allows_only_cluster_dns_and_public_web_destinations():
    policy = egress_proxy_manifests(
        "egress-one", "ubuntu/squid:example", [".openai.com"]
    )[3]["spec"]
    dns, public_ipv4, public_ipv6 = policy["egress"]

    assert dns == {
        "to": [
            {
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": "kube-system"
                    }
                },
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
            },
            {"ipBlock": {"cidr": K3S_CLUSTER_DNS_SERVICE_CIDR}},
        ],
        "ports": [
            {"protocol": "UDP", "port": 53},
            {"protocol": "TCP", "port": 53},
        ],
    }

    ipv4_block = public_ipv4["to"][0]["ipBlock"]
    assert ipv4_block == {
        "cidr": "0.0.0.0/0",
        "except": list(PROXY_BLOCKED_IPV4_CIDRS),
    }
    assert public_ipv4["ports"] == [
        {"protocol": "TCP", "port": 80},
        {"protocol": "TCP", "port": 443},
    ]
    for cluster_cidr in (K3S_POD_CIDR, K3S_SERVICE_CIDR):
        cluster_network = ipaddress.ip_network(cluster_cidr)
        assert any(
            cluster_network.subnet_of(ipaddress.ip_network(blocked))
            for blocked in PROXY_BLOCKED_IPV4_CIDRS
        )
    for metadata_address in (
        "100.100.100.200",
        "168.63.129.16",
        "169.254.169.254",
        "192.0.0.192",
    ):
        address = ipaddress.ip_address(metadata_address)
        assert any(
            address in ipaddress.ip_network(blocked)
            for blocked in PROXY_BLOCKED_IPV4_CIDRS
        )

    ipv6_block = public_ipv6["to"][0]["ipBlock"]
    assert ipv6_block == {
        "cidr": PROXY_PUBLIC_IPV6_CIDR,
        "except": list(PROXY_PUBLIC_IPV6_EXCEPT_CIDRS),
    }
    assert public_ipv6["ports"] == public_ipv4["ports"]
    for private_address in ("::1", "fd00:ec2::254", "fe80::1", "ff02::1"):
        address = ipaddress.ip_address(private_address)
        assert any(
            address in ipaddress.ip_network(blocked)
            for blocked in PROXY_BLOCKED_IPV6_CIDRS
        )


def test_proxy_client_label_is_bound_to_its_trial_proxy():
    manifest = sandbox_pod_manifest(
        "agent-one", "agent", "image", proxy_id="egress-one"
    )

    assert manifest["metadata"]["labels"]["role"] == "sandbox"
    assert manifest["metadata"]["labels"]["egress-proxy"] == "egress-one"


def test_ambiguous_pod_apply_failure_cleans_pod_before_policy(monkeypatch):
    calls = []
    apply_count = 0

    def fake_kubectl(*args, **kwargs):
        nonlocal apply_count
        calls.append(args)
        if args[:3] == ("apply", "-f", "-"):
            apply_count += 1
            if apply_count == 2:
                raise subprocess.TimeoutExpired(args, 60)
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr("agent_eval.kube.kubectl", fake_kubectl)

    with pytest.raises(subprocess.TimeoutExpired):
        create_sandbox_pod("eval", "example:image", egress_mode="deny")

    cleanup = [call for call in calls if call and call[0] == "delete"]
    assert cleanup[0][1] == "pod"
    assert cleanup[0][2].startswith("eval-")
    assert cleanup[1][1:3] == (
        "networkpolicy",
        f"egress-{cleanup[0][2]}",
    )


def test_pod_snapshot_rejects_link_escape_without_extracting(monkeypatch, tmp_path):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        member = tarfile.TarInfo("./escape")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)

    monkeypatch.setattr(
        "agent_eval.kube._pod_archive_stream",
        lambda *args: io.BytesIO(payload.getvalue()),
    )

    with pytest.raises(UnsafeArchiveError, match="unsafe archive member"):
        Pod("agent-one").copy_dir_from("/workspace", tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()


def test_pod_snapshot_extracts_regular_files(monkeypatch, tmp_path):
    payload = io.BytesIO()
    content = b"safe\n"
    with tarfile.open(fileobj=payload, mode="w") as archive:
        member = tarfile.TarInfo("./safe.txt")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    monkeypatch.setattr(
        "agent_eval.kube._pod_archive_stream",
        lambda *args: io.BytesIO(payload.getvalue()),
    )

    target = tmp_path / "snapshot"
    Pod("agent-one").copy_dir_from("/workspace", target)

    assert (target / "safe.txt").read_bytes() == content


def test_pod_snapshot_streams_with_member_and_expanded_size_caps(
    monkeypatch, tmp_path
):
    from agent_eval import kube

    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for name in ("first.txt", "second.txt"):
            member = tarfile.TarInfo(name)
            member.size = 4
            archive.addfile(member, io.BytesIO(b"data"))

    monkeypatch.setattr(
        kube,
        "_pod_archive_stream",
        lambda *args: io.BytesIO(payload.getvalue()),
    )
    monkeypatch.setattr(kube, "MAX_SNAPSHOT_MEMBERS", 1)

    with pytest.raises(UnsafeArchiveError, match="more than 1 members"):
        Pod("agent-one").copy_dir_from("/workspace", tmp_path / "member-cap")

    monkeypatch.setattr(kube, "MAX_SNAPSHOT_MEMBERS", 10)
    monkeypatch.setattr(kube, "MAX_SNAPSHOT_BYTES", 7)
    with pytest.raises(UnsafeArchiveError, match="expands beyond 7 bytes"):
        Pod("agent-one").copy_dir_from("/workspace", tmp_path / "size-cap")


def test_copy_to_non_root_volume_does_not_restore_archive_root_metadata(
    monkeypatch, tmp_path
):
    calls = []
    (tmp_path / "safe.txt").write_text("safe\n")
    monkeypatch.setattr(
        Pod,
        "exec",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, b"", b""),
    )

    def fake_run(command, timeout, *, stdin=None):
        calls.append((command, timeout, stdin.read(1)))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr("agent_eval.kube._run_bounded_command", fake_run)

    Pod("eval-one").copy_dir_to(tmp_path, "/workspace")

    command = calls[0][0]
    assert "--no-same-owner" in command
    assert "--no-same-permissions" in command
    assert "--touch" in command
    assert calls[0][1] == 300
    assert calls[0][2]


def test_copy_to_rejects_oversized_local_tree_before_pod_io(
    monkeypatch, tmp_path
):
    from agent_eval import kube

    (tmp_path / "large.bin").write_bytes(b"12345")
    monkeypatch.setattr(kube, "MAX_SNAPSHOT_BYTES", 4)
    monkeypatch.setattr(
        Pod,
        "exec",
        lambda *args, **kwargs: pytest.fail("oversized tree reached pod"),
    )

    with pytest.raises(UnsafeArchiveError, match="expands beyond 4 bytes"):
        Pod("eval-one").copy_dir_to(tmp_path, "/workspace")


def test_pod_keeps_policy_when_deletion_does_not_finish(monkeypatch):
    calls = []

    def fake_kubectl(*args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired(args, 60)

    monkeypatch.setattr("agent_eval.kube.kubectl", fake_kubectl)

    with pytest.raises(subprocess.TimeoutExpired):
        Pod("agent-one", network_policy_name="egress-agent-one").delete()

    assert calls == [
        ("delete", "pod", "agent-one", "--ignore-not-found", "--wait=true")
    ]


def test_secret_delete_raises_on_kubectl_failure(monkeypatch):
    def fake_kubectl(*args, **kwargs):
        raise KubeError("API unavailable")

    monkeypatch.setattr("agent_eval.kube.kubectl", fake_kubectl)

    with pytest.raises(KubeError, match="API unavailable"):
        TrialSecret("trial-secret").delete()


def test_trial_secret_apply_timeout_rolls_back_committed_secret(monkeypatch):
    from agent_eval import kube

    credential = "credential-must-not-appear-in-errors"
    run_id = "task--agent--20260715-010203-abcdef123456"
    expected_run_digest = hashlib.sha256(run_id.encode()).hexdigest()
    existing = set()
    calls = []
    applied_manifest = None

    class Material:
        values = {"API_KEY": credential}

    def fake_kubectl(*args, **kwargs):
        nonlocal applied_manifest
        calls.append(args)
        if args[0] == "apply":
            applied_manifest = json.loads(kwargs["input"])
            existing.add(applied_manifest["metadata"]["name"])
            raise subprocess.TimeoutExpired("kubectl apply", 30)
        if args[0] == "delete":
            existing.discard(args[2])
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if args[0] == "get":
            output = f"secret/{args[2]}\n".encode() if args[2] in existing else b""
            return subprocess.CompletedProcess(args, 0, stdout=output, stderr=b"")
        raise AssertionError(args)

    monkeypatch.setattr(kube.uuid, "uuid4", type("ID", (), {"hex": "a" * 32}))
    monkeypatch.setattr(kube, "kubectl", fake_kubectl)

    with pytest.raises(KubeError, match="rollback confirmed") as captured:
        kube.create_trial_secret(Material(), run_id=run_id)

    assert applied_manifest is not None
    assert applied_manifest["metadata"]["name"] == f"agent-credential-{'a' * 32}"
    assert applied_manifest["metadata"]["labels"]["agent-eval-run-sha256"] == (
        expected_run_digest[:32]
    )
    assert applied_manifest["metadata"]["annotations"][
        "agent-eval-run-sha256"
    ] == expected_run_digest
    assert existing == set()
    assert [call[0] for call in calls] == ["apply", "delete", "get"]
    assert credential not in str(captured.value)
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None


def test_trial_secret_failed_rollback_reports_exact_remediation(monkeypatch):
    from agent_eval import kube

    credential = "credential-must-not-appear-in-errors"
    name = f"agent-credential-{'b' * 32}"
    calls = []

    class Material:
        values = {"API_KEY": credential}

    def fake_kubectl(*args, **kwargs):
        calls.append(args)
        if args[0] == "apply":
            raise subprocess.TimeoutExpired("kubectl apply", 30)
        if args[0] == "delete":
            raise KubeError("API unavailable")
        if args[0] == "get":
            return subprocess.CompletedProcess(
                args, 0, stdout=f"secret/{name}\n".encode(), stderr=b""
            )
        raise AssertionError(args)

    monkeypatch.setattr(kube.uuid, "uuid4", type("ID", (), {"hex": "b" * 32}))
    monkeypatch.setattr(kube, "kubectl", fake_kubectl)

    with pytest.raises(KubeError, match="rollback could not be confirmed") as captured:
        kube.create_trial_secret(Material(), run_id="run-one")

    error = str(captured.value)
    assert name in error
    assert credential not in error
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None
    assert (
        "kubectl --context k3d-agent-eval -n agent-eval delete secret "
        f"{name} --ignore-not-found --wait=true"
    ) in error
    assert [call[0] for call in calls].count("delete") == 3
    assert [call[0] for call in calls].count("get") == 3


def test_pod_snapshot_stream_is_size_bounded(monkeypatch):
    from agent_eval import kube

    class Process:
        def __init__(self, stdout):
            stdout.write(b"12345")
            stdout.flush()
            self.returncode = None

        def kill(self):
            self.returncode = -9

        def wait(self, timeout=None):
            del timeout
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def poll(self):
            return self.returncode

    monkeypatch.setattr(kube, "MAX_SNAPSHOT_BYTES", 4)
    monkeypatch.setattr(
        kube.subprocess,
        "Popen",
        lambda *args, **kwargs: Process(kwargs["stdout"]),
    )

    with pytest.raises(UnsafeArchiveError, match="exceeds 4 bytes"):
        kube._pod_archive_stream("agent-one", "/workspace")


def test_pod_snapshot_rechecks_size_after_process_exit(monkeypatch):
    from agent_eval import kube

    class Process:
        def __init__(self, stdout):
            stdout.write(b"12345")
            stdout.flush()
            self.returncode = 0

        def poll(self):
            return self.returncode

    monkeypatch.setattr(kube, "MAX_SNAPSHOT_BYTES", 4)
    monkeypatch.setattr(
        kube.subprocess,
        "Popen",
        lambda *args, **kwargs: Process(kwargs["stdout"]),
    )

    with pytest.raises(UnsafeArchiveError, match="exceeds 4 bytes"):
        kube._pod_archive_stream("agent-one", "/workspace")


def test_pod_snapshot_caps_stderr_even_when_process_exits_immediately(monkeypatch):
    from agent_eval import kube

    class Process:
        def __init__(self, stdout, stderr):
            del stdout
            stderr.write(b"12345")
            stderr.flush()
            self.returncode = 1

        def poll(self):
            return self.returncode

    monkeypatch.setattr(kube, "MAX_ARCHIVE_STDERR_BYTES", 4)
    monkeypatch.setattr(
        kube.subprocess,
        "Popen",
        lambda *args, **kwargs: Process(kwargs["stdout"], kwargs["stderr"]),
    )

    with pytest.raises(KubeError, match="stderr exceeds 4 bytes"):
        kube._pod_archive_stream("agent-one", "/workspace")


def test_pod_exec_caps_output_even_when_process_exits_immediately(monkeypatch):
    from agent_eval import kube

    class Process:
        def __init__(self, stdout, stderr):
            stdout.write(b"12345")
            stderr.write(b"67890")
            stdout.flush()
            stderr.flush()
            self.returncode = 0

        def poll(self):
            return self.returncode

    monkeypatch.setattr(kube, "MAX_COMMAND_OUTPUT_BYTES", 8)
    monkeypatch.setattr(
        kube.subprocess,
        "Popen",
        lambda *args, **kwargs: Process(kwargs["stdout"], kwargs["stderr"]),
    )

    with pytest.raises(CommandOutputLimitError) as caught:
        Pod("agent-one").exec("produce-output")

    assert len(caught.value.stdout) + len(caught.value.stderr) == 8


def test_egress_proxy_logs_use_bounded_disk_backed_capture(monkeypatch):
    from agent_eval import kube

    command = None

    class Process:
        def __init__(self, stdout, stderr):
            stdout.write(b"12345")
            stderr.write(b"67890")
            stdout.flush()
            stderr.flush()
            self.returncode = 0

        def poll(self):
            return self.returncode

    def fake_popen(observed_command, **kwargs):
        nonlocal command
        command = observed_command
        return Process(kwargs["stdout"], kwargs["stderr"])

    monkeypatch.setattr(kube, "MAX_COMMAND_OUTPUT_BYTES", 8)
    monkeypatch.setattr(kube.subprocess, "Popen", fake_popen)

    with pytest.raises(CommandOutputLimitError) as caught:
        kube.EgressProxy("egress-one", "10.43.0.25").logs()

    assert command == [
        "kubectl",
        "--context",
        "k3d-agent-eval",
        "-n",
        "agent-eval",
        "logs",
        "egress-one",
    ]
    assert len(caught.value.stdout) + len(caught.value.stderr) == 8


def test_task_resources_default_and_override_each_phase():
    task = load_task("example-todo-api")
    assert task.resources.agent.as_kubernetes() == DEFAULT_SANDBOX_RESOURCES
    assert task.resources.eval.as_kubernetes() == DEFAULT_SANDBOX_RESOURCES

    resources = SandboxResources.model_validate(
        {
            "agent": {"limits": {"memory": "6Gi"}},
            "eval": {
                "requests": {"cpu": "250m", "memory": "512Mi"},
                "limits": {"cpu": "4", "memory": "8Gi"},
            },
        }
    )

    assert resources.agent.limits.memory == "6Gi"
    assert resources.agent.requests.memory == "128Mi"
    assert resources.eval.as_kubernetes() == {
        "requests": {
            "cpu": "250m",
            "memory": "512Mi",
            "ephemeral-storage": "256Mi",
        },
        "limits": {
            "cpu": "4",
            "memory": "8Gi",
            "ephemeral-storage": "4Gi",
        },
    }


def test_load_task_rejects_unknown_top_level_fields(tmp_path):
    task_dir = tmp_path / "typo"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: typo\n"
        "prompt: Test task\n"
        "test_command: pytest\n"
        "resouces:\n"
        "  agent:\n"
        "    limits:\n"
        "      memory: 9Gi\n"
    )

    with pytest.raises(ValidationError, match="resouces"):
        load_task("typo", tmp_path)


@pytest.mark.parametrize(
    "resources",
    [
        {"limits": {"memory": "not-a-quantity"}},
        {"limits": {"memory": "1K"}},
        {"requests": {"cpu": "3"}, "limits": {"cpu": "2"}},
        {"limits": {"gpu": "1"}},
    ],
)
def test_task_resources_reject_invalid_configuration(resources):
    with pytest.raises(ValidationError):
        PodResources.model_validate(resources)


def test_manifest_uses_custom_resources_without_mutating_them():
    resources = SandboxResources.model_validate(
        {"eval": {"limits": {"cpu": "3", "memory": "5Gi"}}}
    ).eval.as_kubernetes()

    manifest = sandbox_pod_manifest(
        "eval-deadbeef",
        "eval",
        "agent-eval/example:latest",
        resources=resources,
    )
    manifest["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "1"

    assert resources["limits"]["cpu"] == "3"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (
            {
                "containerStatuses": [
                    {"state": {"terminated": {"reason": "OOMKilled", "exitCode": 137}}}
                ]
            },
            "OOMKilled",
        ),
        (
            {
                "reason": "Evicted",
                "message": "The node was low on resource: ephemeral-storage.",
            },
            "Evicted",
        ),
        ({"reason": "DeadlineExceeded"}, "DeadlineExceeded"),
        (
            {
                "conditions": [
                    {
                        "reason": "Unschedulable",
                        "message": "0/1 nodes are available: Insufficient memory.",
                    }
                ]
            },
            "Insufficient memory",
        ),
        (
            {
                "conditions": [
                    {
                        "reason": "Unschedulable",
                        "message": (
                            "0/1 nodes are available: 1 node(s) had "
                            "untolerated taint"
                        ),
                    }
                ]
            },
            "untolerated taint",
        ),
    ],
)
def test_pod_preserves_infrastructure_failure_evidence(monkeypatch, status, expected):
    def fake_kubectl(*args, **kwargs):
        return subprocess.CompletedProcess(
            args, 0, stdout=json.dumps({"status": status}).encode(), stderr=b""
        )

    monkeypatch.setattr("agent_eval.kube.kubectl", fake_kubectl)

    assert expected in Pod("eval-deadbeef").infrastructure_failure()


def test_pod_marks_sigkill_as_possible_resource_failure(monkeypatch):
    def fake_kubectl(*args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"gone")

    monkeypatch.setattr("agent_eval.kube.kubectl", fake_kubectl)

    evidence = Pod("agent-deadbeef").infrastructure_failure(command_exit_code=137)
    assert evidence == "command exited 137 (SIGKILL; resource-limit termination possible)"
