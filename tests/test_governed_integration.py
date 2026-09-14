import hashlib
import json
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agent_eval import agents, cli, metrics, runner
from agent_eval.assessments import derive_assessments
from agent_eval.attestation import canonical_statement_bytes, capture_git_state
from agent_eval.audit import (
    GENESIS_HASH,
    AuditChain,
    canonical_audit_json_bytes,
    verify_audit_chain,
)
from agent_eval.evaluators import scanners
from agent_eval.evaluators.tests import TestResults as EvalTestResults
from agent_eval.governance import (
    EffectiveLimits,
    EvaluationRequest,
    GovernanceBundle,
    GovernanceEvidence,
    evaluate_admission,
    sha256_json,
    write_canonical_json,
)
from agent_eval.kube import KubeError
from agent_eval.metrics import (
    AgentMetrics,
    DiffStats,
    RunRecord,
    ScanResults,
    TrivyDatabaseIdentity,
)
from agent_eval.outcome import RunOutcome
from agent_eval.task import EvaluationConfig, load_task

IMAGE_DIGEST = "sha256:" + "a" * 64
IMAGE_REF = "agent-eval/example-todo-api:governed-" + "a" * 64
IMAGE_PLATFORM = "linux/amd64"
REQUEST_ID = "12345678-1234-4234-8234-123456789abc"
AGENT = "claude-code"
MODEL = "frontier-code-2026-07"
PROXY_IMAGE = (
    "ubuntu/squid@sha256:"
    "6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
)


def _approved_scan_results() -> ScanResults:
    results = ScanResults(
        lint_errors=0,
        sec_findings_high=0,
        sec_findings_medium=0,
        sec_findings_low=0,
        secrets_found=0,
        vulns=0,
        scanner_runtime_lock_sha256=scanners.scanner_runtime_lock_digest(),
        scanner_runtime_environment_sha256="3" * 64,
        scanner_status={
            "ruff": "ok",
            "semgrep": "ok",
            "gitleaks": "ok",
            "trivy": "ok",
        },
        scanner_versions={
            "ruff": "0.15.20",
            "semgrep": "1.176.0",
            "gitleaks": "8.30.1",
            "trivy": "0.72.0",
        },
        scanner_executable_sha256={
            "uv": "c" * 64,
            "python": "d" * 64,
            "ruff": "1" * 64,
            "semgrep": "2" * 64,
            "gitleaks": "e" * 64,
            "trivy": "f" * 64,
        },
        trivy_db=TrivyDatabaseIdentity(
            version=2,
            updated_at="2026-07-14T00:00:00Z",
            next_update="2026-07-15T00:00:00Z",
            downloaded_at="2026-07-14T01:00:00Z",
            content_sha256="b" * 64,
        ),
    )
    results.scanner_assurance = scanners.scanner_assurance_identity(results)
    return ScanResults.model_validate(results.model_dump(mode="python"))


SCANNER_RESULTS = _approved_scan_results()
SCANNER_ASSURANCE = SCANNER_RESULTS.scanner_assurance
assert SCANNER_ASSURANCE is not None
SCANNER_IDENTITY = SCANNER_ASSURANCE.identity_sha256


@pytest.fixture(autouse=True)
def _stable_governance_scanner_evidence(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_governance_scanner_evidence",
        lambda *, run_scans: (
            (SCANNER_IDENTITY, True) if run_scans else (None, False)
        ),
    )


def _request_data(
    task_id: str,
    *,
    agent: str = AGENT,
    model: str = MODEL,
    max_total_tokens: int = 40,
    max_cost_usd: float = 0.3,
) -> dict:
    return {
        "schema_version": "agent-eval.request/v2",
        "request_id": REQUEST_ID,
        "idempotency_key": "ci-run-42",
        "tenant_id": "tenant-a",
        "project_id": "project-a",
        "asserted_actor": "engineer@example.com",
        "task_id": task_id,
        "agent": agent,
        "model": model,
        "data_classification": "internal",
        "retention_class": "standard",
        "max_observed_total_tokens": max_total_tokens,
        "max_observed_cost_usd": max_cost_usd,
        "labels": {"environment": "test"},
    }


def _policy_data(
    *,
    registered_task=None,
    agent: str = AGENT,
    model: str = MODEL,
    tenants: list[str] | None = None,
    network_modes: list[str] | None = None,
    max_trials: int = 3,
    max_total_tokens: int = 80,
    max_cost_usd: float = 0.8,
    model_max_total_tokens: int = 25,
    model_max_cost_usd: float = 0.2,
) -> dict:
    registered_task = registered_task or load_task("example-todo-api")
    task_tree_sha256 = None
    execution_spec_digests: set[str] = set()
    for run_scans in (False, True):
        for run_judge in (False, True):
            tree_digest, execution_digest = runner._governance_task_evidence(
                registered_task,
                run_scans=run_scans,
                run_judge=run_judge,
            )
            task_tree_sha256 = tree_digest
            execution_spec_digests.add(execution_digest)
    assert task_tree_sha256 is not None
    return {
        "schema_version": "agent-eval.policy/v2",
        "policy_id": "enterprise-evals",
        "revision": "2026-07-14.1",
        "rules": {
            "allowed_tenants": tenants or ["tenant-a"],
            "allowed_projects": ["project-a"],
            "allowed_tasks": ["example-*"],
            "allowed_network_modes": network_modes or ["proxy"],
            "allowed_egress_domains": (
                [".openai.com", ".chatgpt.com", ".oaiusercontent.com"]
                if agent == "codex"
                else [".anthropic.com", ".claude.ai"]
            ),
            "allowed_proxy_images": [PROXY_IMAGE],
            "allowed_scanner_identities": [SCANNER_IDENTITY],
            "allowed_data_classifications": ["internal"],
            "allowed_retention_classes": ["standard"],
            "require_scans": True,
            "require_judge": False,
            "require_broker_credentials": False,
            "max_trials": max_trials,
            "max_agent_seconds": 900,
            "max_eval_seconds": 300,
            "max_observed_total_tokens": max_total_tokens,
            "max_observed_cost_usd": max_cost_usd,
        },
        "task_registry": {
            "registry_id": "approved-tasks",
            "revision": "2026-07-14.1",
            "tasks": [
                {
                    "task_id": registered_task.id,
                    "task_tree_sha256": task_tree_sha256,
                    "execution_spec_digests": sorted(execution_spec_digests),
                    "approved_images": [
                        {
                            "platform": IMAGE_PLATFORM,
                            "reference": IMAGE_REF,
                            "manifest_digest": IMAGE_DIGEST,
                            "builder_id": "https://ci.example/builders/task-images",
                            "build_type": "https://slsa.dev/container/v1",
                            "source_revision": "commit-123",
                            "provenance_sha256": "b" * 64,
                        }
                    ],
                    "status": "approved",
                }
            ],
        },
        "model_registry": {
            "registry_id": "approved-models",
            "revision": "2026-07-14.1",
            "models": [
                {
                    "adapter": agent,
                    "model": model,
                    "provider": "openai",
                    "status": "approved",
                    "allowed_data_classifications": ["internal"],
                    "max_observed_total_tokens": model_max_total_tokens,
                    "max_observed_cost_usd": model_max_cost_usd,
                },
                {
                    "adapter": "judge:claude",
                    "model": "claude-sonnet-4-5-20250929",
                    "provider": "anthropic",
                    "status": "approved",
                    "allowed_data_classifications": ["internal"],
                },
            ],
        },
    }


def _write_yaml(path: Path, value: dict) -> Path:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return path


def _task_evidence_args(
    task, *, run_scans: bool = True, run_judge: bool = True
) -> dict[str, object]:
    tree_digest, execution_digest = runner._governance_task_evidence(
        task, run_scans=run_scans, run_judge=run_judge
    )
    return {
        "run_scans": run_scans,
        "scanner_identity_sha256": SCANNER_IDENTITY if run_scans else None,
        "scanner_promotion_ready": run_scans,
        "run_judge": run_judge,
        "judge_backend": task.judge.backend if run_judge else None,
        "judge_model": task.judge.model if run_judge else None,
        "task_tree_sha256": tree_digest,
        "execution_spec_digest": execution_digest,
    }


def _execution_from_preflight(
    request: EvaluationRequest,
    bundle: GovernanceBundle,
    preflight,
    *,
    image_digest: str = IMAGE_DIGEST,
):
    admitted = preflight.sanitized_input
    return evaluate_admission(
        request,
        bundle,
        actual_task_id=admitted["actual_task_id"],
        actual_agent=admitted["actual_agent"],
        actual_model=admitted["actual_model"],
        trials=admitted["trials"],
        network_mode=admitted["network_mode"],
        agent_timeout_seconds=admitted["agent_timeout_seconds"],
        eval_timeout_seconds=admitted["eval_timeout_seconds"],
        broker_configured=admitted["broker_configured"],
        run_scans=admitted["run_scans"],
        scanner_identity_sha256=admitted["scanner_identity_sha256"],
        scanner_promotion_ready=admitted["scanner_promotion_ready"],
        run_judge=admitted["run_judge"],
        judge_backend=admitted["judge_backend"],
        judge_model=admitted["judge_model"],
        task_tree_sha256=admitted["task_tree_sha256"],
        execution_spec_digest=admitted["execution_spec_digest"],
        decision_stage="execution",
        task_image_digest=image_digest,
        task_image_ref=(
            f"agent-eval/{admitted['actual_task_id']}:governed-"
            f"{image_digest.removeprefix('sha256:')}"
        ),
        task_image_platform=IMAGE_PLATFORM,
        preflight_decision_id=preflight.decision_id,
        preflight_decision_digest=sha256_json(preflight),
        effective_egress_domains=admitted["effective_egress_domains"],
        proxy_image=admitted["proxy_image"],
    )


def _patch_cli_dependencies(monkeypatch, task, adapter) -> dict[str, int]:
    calls = {
        "cluster": 0,
        "image": 0,
        "trial": 0,
        "credentials": 0,
    }

    monkeypatch.setattr(cli, "load_task", lambda task_id: task)
    monkeypatch.setattr(agents, "get_adapter", lambda name: adapter)
    monkeypatch.setattr(cli, "print_runs_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "print_trial_summary", lambda *args, **kwargs: None)

    def called(name):
        def callback(*args, **kwargs):
            del args, kwargs
            calls[name] += 1
            raise AssertionError(f"{name} must not run before governance admission")

        return callback

    monkeypatch.setattr(cli.cluster_mod, "ensure_cluster", called("cluster"))
    monkeypatch.setattr(runner, "ensure_image", called("image"))
    monkeypatch.setattr(runner, "run_agent_trial", called("trial"))
    monkeypatch.setattr(runner, "load_trial_credentials", called("credentials"))
    return calls


@pytest.mark.parametrize(
    ("metrics_value", "expected"),
    [
        (AgentMetrics(cost_usd=0.1), "token usage evidence is unavailable"),
        (
            AgentMetrics(tokens_in=20, tokens_out=6, cost_usd=0.1),
            "observed token usage 26 exceeds 25",
        ),
        (
            AgentMetrics(tokens_in=1, tokens_out=1),
            "cost evidence is unavailable",
        ),
        (
            AgentMetrics(tokens_in=1, tokens_out=1, cost_usd=0.3),
            "observed cost 0.3 exceeds 0.2",
        ),
        (AgentMetrics(tokens_in=1, tokens_out=1, cost_usd=0.1), None),
    ],
)
def test_governed_cli_stops_before_another_call_on_usage_evidence_failure(
    metrics_value,
    expected,
):
    record = RunRecord(
        run_id="usage-stop",
        task_id="example-todo-api",
        agent=AGENT,
        efficiency=metrics_value,
    )
    limits = EffectiveLimits(
        max_trials=3,
        max_agent_seconds=900,
        max_eval_seconds=300,
        max_observed_total_tokens=25,
        max_observed_cost_usd=0.2,
    )

    assert cli._governed_usage_stop_reason(record, limits) == expected


def test_tasks_fingerprint_prints_exact_content_and_recipe_identity():
    task = load_task("example-todo-api")
    tree_digest, execution_digest = runner._governance_task_evidence(
        task, run_scans=True, run_judge=True
    )

    result = CliRunner().invoke(cli.app, ["tasks", "fingerprint", task.id])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "task_id": task.id,
        "task_tree_sha256": tree_digest,
        "execution_spec_digests": [execution_digest],
    }


def test_tasks_fingerprint_can_include_all_execution_recipes():
    result = CliRunner().invoke(
        cli.app,
        ["tasks", "fingerprint", "example-todo-api", "--all-recipes"],
    )

    assert result.exit_code == 0, result.output
    assert len(json.loads(result.output)["execution_spec_digests"]) == 3


def test_cli_requires_request_policy_pair_before_cluster(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    adapter = type("Adapter", (), {"name": AGENT})()
    request_path = _write_yaml(tmp_path / "request.yaml", _request_data(task.id))
    calls = _patch_cli_dependencies(monkeypatch, task, adapter)

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            "--task",
            task.id,
            "--agent",
            adapter.name,
            "--governance-request",
            str(request_path),
        ],
    )

    assert result.exit_code == 2
    assert "must be supplied together" in result.output
    assert calls == {"cluster": 0, "image": 0, "trial": 0, "credentials": 0}


def test_malformed_governance_yaml_exits_two_before_cluster(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    adapter = type("Adapter", (), {"name": AGENT})()
    request_path = tmp_path / "request.yaml"
    request_path.write_text("schema_version: [\n", encoding="utf-8")
    policy_path = _write_yaml(tmp_path / "policy.yaml", _policy_data())
    calls = _patch_cli_dependencies(monkeypatch, task, adapter)

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            "--task",
            task.id,
            "--agent",
            adapter.name,
            "--governance-request",
            str(request_path),
            "--governance-policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 2
    assert "governance configuration failed" in result.output
    assert calls == {"cluster": 0, "image": 0, "trial": 0, "credentials": 0}


def test_denied_policy_persists_evidence_before_any_runtime_work(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    adapter = type("Adapter", (), {"name": AGENT})()
    request_path = _write_yaml(tmp_path / "request.yaml", _request_data(task.id))
    policy_path = _write_yaml(
        tmp_path / "policy.yaml",
        _policy_data(tenants=["some-other-tenant"]),
    )
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    calls = _patch_cli_dependencies(monkeypatch, task, adapter)

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            "--task",
            task.id,
            "--agent",
            adapter.name,
            "--governance-request",
            str(request_path),
            "--governance-policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 3
    assert "tenant_not_allowed" in result.output
    assert calls == {"cluster": 0, "image": 0, "trial": 0, "credentials": 0}
    admission_dirs = list((metrics.RUNS_ROOT / "admissions").iterdir())
    assert len(admission_dirs) == 1
    admission = admission_dirs[0]
    decision = json.loads((admission / "preflight-decision.json").read_text())
    assert decision["allowed"] is False
    assert [reason["code"] for reason in decision["reasons"]] == ["tenant_not_allowed"]
    assert {path.name for path in admission.iterdir()} == {
        "request.json",
        "policy-bundle.json",
        "preflight-decision.json",
    }


def test_task_added_egress_domain_is_denied_before_runtime(monkeypatch, tmp_path):
    base_task = load_task("example-todo-api")
    task = base_task.model_copy(
        update={
            "network": base_task.network.model_copy(
                update={"allowed_domains": [".attacker.example"]}
            )
        }
    )
    adapter = type("Adapter", (), {"name": AGENT})()
    request_path = _write_yaml(tmp_path / "request.yaml", _request_data(task.id))
    policy_path = _write_yaml(tmp_path / "policy.yaml", _policy_data())
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    calls = _patch_cli_dependencies(monkeypatch, task, adapter)

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            "--task",
            task.id,
            "--agent",
            adapter.name,
            "--governance-request",
            str(request_path),
            "--governance-policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 3
    assert "egress_domain_not_allowed" in result.output
    assert calls == {"cluster": 0, "image": 0, "trial": 0, "credentials": 0}


def test_admitted_cli_uses_request_model_and_reuses_decision_for_trials(
    monkeypatch, tmp_path
):
    task = load_task("example-todo-api")
    adapter = type("Adapter", (), {"name": AGENT})()
    request_path = _write_yaml(tmp_path / "request.yaml", _request_data(task.id))
    policy_path = _write_yaml(tmp_path / "policy.yaml", _policy_data(max_trials=2))
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(cli, "load_task", lambda task_id: task)
    monkeypatch.setattr(agents, "get_adapter", lambda name: adapter)
    monkeypatch.setattr(cli, "print_runs_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "print_trial_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli.cluster_mod, "ensure_cluster", lambda: None)
    monkeypatch.setattr(runner, "ensure_image", lambda task, rebuild=False: None)
    preparations = []

    def fake_prepare(task, *, request, bundle, preflight_decision, **kwargs):
        del task, kwargs
        preparations.append(preflight_decision.decision_id)
        return _execution_from_preflight(request, bundle, preflight_decision)

    monkeypatch.setattr(runner, "prepare_governed_execution", fake_prepare)
    monkeypatch.delenv("AGENT_EVAL_CREDENTIAL_COMMAND", raising=False)
    observed = []

    def fake_trial(task_arg, adapter_arg, **kwargs):
        observed.append((task_arg, adapter_arg, kwargs))
        return RunRecord(
            run_id=f"cli-trial-{kwargs['trial']}",
            task_id=task_arg.id,
            agent=adapter_arg.name,
            trial=kwargs["trial"],
            correctness=EvalTestResults(total=1, passed=1, command_exit_code=0),
            efficiency=AgentMetrics(
                tokens_in=1,
                tokens_out=1,
                cost_usd=0.1,
            ),
        )

    monkeypatch.setattr(runner, "run_agent_trial", fake_trial)

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            "--task",
            task.id,
            "--agent",
            adapter.name,
            "--trials",
            "2",
            "--governance-request",
            str(request_path),
            "--governance-policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(observed) == 2
    assert len(preparations) == 1
    assert [item[2]["model"] for item in observed] == [MODEL, MODEL]
    requests = [item[2]["governance_request"] for item in observed]
    decisions = [item[2]["governance_decision"] for item in observed]
    execution_decisions = [
        item[2]["governance_execution_decision"] for item in observed
    ]
    assert requests[0] is requests[1]
    assert decisions[0] is decisions[1]
    assert execution_decisions[0] is execution_decisions[1]
    assert execution_decisions[0].decision_stage == "execution"
    assert requests[0].model == MODEL
    assert decisions[0].allowed is True
    assert decisions[0].matched_model.model == MODEL
    assert decisions[0].effective_limits.max_observed_total_tokens == 25
    assert decisions[0].effective_limits.max_observed_cost_usd == 0.2


def test_governed_prepare_uses_preapproved_image_without_runtime_build(monkeypatch):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=2,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    snapshot_roots = []
    lifecycle = []

    def fake_import(snapshot, rebuild=False, *, expected_digest=None, image_ref=None):
        assert rebuild is False
        assert snapshot.path != task.path
        snapshot_roots.append(snapshot.path)
        assert expected_digest == IMAGE_DIGEST
        assert image_ref == IMAGE_REF
        lifecycle.append("import")
        return expected_digest

    original_finalize = runner._finalize_execution_decision

    def capture_finalize(*args, **kwargs):
        lifecycle.append("final-decision")
        return original_finalize(*args, **kwargs)

    monkeypatch.delenv("AGENT_EVAL_CREDENTIAL_COMMAND", raising=False)
    monkeypatch.setattr(runner, "_docker_platform", lambda: IMAGE_PLATFORM)
    monkeypatch.setattr(
        runner,
        "_build_task_image_candidate",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("governed execution must not build an image")
        ),
    )
    monkeypatch.setattr(runner, "_finalize_execution_decision", capture_finalize)
    monkeypatch.setattr(
        runner.cluster_mod,
        "ensure_cluster",
        lambda: lifecycle.append("cluster"),
    )
    monkeypatch.setattr(runner, "ensure_image", fake_import)

    execution = runner.prepare_governed_execution(
        task,
        agent=AGENT,
        model=MODEL,
        run_scans=True,
        run_judge=True,
        request=request,
        bundle=bundle,
        preflight_decision=preflight,
    )

    assert lifecycle == ["final-decision", "cluster", "import"]
    assert snapshot_roots and all(not root.exists() for root in snapshot_roots)
    assert execution.decision_stage == "execution"
    assert execution.preflight_decision_id == preflight.decision_id
    assert execution.sanitized_input["task_image_digest"] == IMAGE_DIGEST
    assert execution.sanitized_input["task_image_ref"] == IMAGE_REF
    assert execution.sanitized_input["task_image_platform"] == IMAGE_PLATFORM


def test_governed_prepare_rejects_final_identity_drift_before_cluster(monkeypatch):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    other_identity = "7" * 64
    policy = _policy_data()
    policy["rules"]["allowed_scanner_identities"].append(other_identity)
    bundle = GovernanceBundle.model_validate(policy)
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    observed_identities = iter(
        [(SCANNER_IDENTITY, True), (other_identity, True)]
    )
    monkeypatch.setattr(
        runner,
        "_governance_scanner_evidence",
        lambda *, run_scans: next(observed_identities),
    )
    monkeypatch.setattr(runner, "_docker_platform", lambda: IMAGE_PLATFORM)
    monkeypatch.setattr(
        runner.cluster_mod,
        "ensure_cluster",
        lambda: pytest.fail("identity drift reached cluster setup"),
    )
    monkeypatch.setattr(
        runner,
        "ensure_image",
        lambda *args, **kwargs: pytest.fail("identity drift reached image import"),
    )

    with pytest.raises(ValueError, match="broadens or changes its preflight"):
        runner.prepare_governed_execution(
            task,
            agent=AGENT,
            model=MODEL,
            run_scans=True,
            run_judge=True,
            request=request,
            bundle=bundle,
            preflight_decision=preflight,
        )


def test_governed_prepare_rejects_cooperative_evaluation_before_side_effects(
    monkeypatch,
):
    task = load_task("example-todo-api").model_copy(
        update={"evaluation": EvaluationConfig()}
    )
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data(registered_task=task))
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    monkeypatch.setattr(
        runner.cluster_mod,
        "ensure_cluster",
        lambda: pytest.fail("cooperative task reached cluster setup"),
    )
    monkeypatch.setattr(
        runner,
        "ensure_image",
        lambda *args, **kwargs: pytest.fail("cooperative task reached image import"),
    )

    with pytest.raises(ValueError, match="require isolated-black-box"):
        runner.prepare_governed_execution(
            task,
            agent=AGENT,
            model=MODEL,
            run_scans=True,
            run_judge=True,
            request=request,
            bundle=bundle,
            preflight_decision=preflight,
        )


def test_governed_prepare_fails_before_cluster_without_platform_approval(monkeypatch):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    monkeypatch.setattr(runner, "_docker_platform", lambda: "linux/arm64")
    monkeypatch.setattr(
        runner.cluster_mod,
        "ensure_cluster",
        lambda: (_ for _ in ()).throw(
            AssertionError("cluster must not start without an approved image")
        ),
    )

    with pytest.raises(
        ValueError,
        match="no preapproved image for platform linux/arm64",
    ):
        runner.prepare_governed_execution(
            task,
            agent=AGENT,
            model=MODEL,
            run_scans=True,
            run_judge=True,
            request=request,
            bundle=bundle,
            preflight_decision=preflight,
        )


def test_post_binding_retag_fails_before_credentials_or_runtime(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    execution = _execution_from_preflight(request, bundle, preflight)
    calls = {"credentials": 0, "namespace": 0, "pod": 0}

    def retagged(*args, **kwargs):
        del args
        assert kwargs["expected_digest"] == IMAGE_DIGEST
        raise KubeError("local task image digest does not match governed digest")

    def forbidden(name):
        def callback(*args, **kwargs):
            del args, kwargs
            calls[name] += 1
            raise AssertionError(f"{name} must not run after a digest mismatch")

        return callback

    monkeypatch.delenv("AGENT_EVAL_CREDENTIAL_COMMAND", raising=False)
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "new_run_id", lambda *args: "retagged-run")
    monkeypatch.setattr(runner, "ensure_image", retagged)
    monkeypatch.setattr(runner, "ensure_namespace", forbidden("namespace"))
    monkeypatch.setattr(runner, "load_trial_credentials", forbidden("credentials"))
    monkeypatch.setattr(runner, "create_sandbox_pod", forbidden("pod"))
    monkeypatch.setattr(runner, "_capture_provenance", lambda *args: None)
    monkeypatch.setattr(runner, "_persist_run", lambda *args: None)

    adapter = type("Adapter", (), {"name": AGENT})()
    record = runner.run_agent_trial(
        task,
        adapter,
        model=MODEL,
        run_scans=True,
        run_judge=True,
        governance_request=request,
        governance_bundle=bundle,
        governance_decision=preflight,
        governance_execution_decision=execution,
    )

    assert calls == {"credentials": 0, "namespace": 0, "pod": 0}
    assert record.outcome.status == "infra_error"
    assert "does not match governed digest" in record.efficiency.infra_error


def test_execution_decision_without_preflight_triplet_is_rejected():
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        **_task_evidence_args(task),
    )
    execution = _execution_from_preflight(request, bundle, preflight)

    with pytest.raises(ValueError, match="execution decision requires"):
        runner.run_agent_trial(
            task,
            type("Adapter", (), {"name": AGENT})(),
            governance_execution_decision=execution,
        )


def test_execution_decision_cannot_escalate_preflight_trial_scope():
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data(max_trials=3))
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    admitted = preflight.sanitized_input
    escalated = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=2,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        run_scans=admitted["run_scans"],
        scanner_identity_sha256=admitted["scanner_identity_sha256"],
        scanner_promotion_ready=admitted["scanner_promotion_ready"],
        run_judge=admitted["run_judge"],
        judge_backend=admitted["judge_backend"],
        judge_model=admitted["judge_model"],
        task_tree_sha256=admitted["task_tree_sha256"],
        execution_spec_digest=admitted["execution_spec_digest"],
        decision_stage="execution",
        task_image_digest=IMAGE_DIGEST,
        task_image_ref=IMAGE_REF,
        task_image_platform=IMAGE_PLATFORM,
        preflight_decision_id=preflight.decision_id,
        preflight_decision_digest=sha256_json(preflight),
        effective_egress_domains=domains,
        proxy_image=proxy_image,
    )
    assert escalated.allowed is True

    with pytest.raises(ValueError, match="broadens or changes"):
        runner._validate_governance_decision(
            task,
            agent=AGENT,
            model=MODEL,
            trial=1,
            run_scans=True,
            run_judge=True,
            request=request,
            bundle=bundle,
            decision=escalated,
            decision_stage="execution",
            task_image_digest=IMAGE_DIGEST,
            task_image_ref=IMAGE_REF,
            task_image_platform=IMAGE_PLATFORM,
            preflight_decision=preflight,
        )


class _SuccessfulAgentPod:
    def __init__(self, starter: Path):
        self.starter = starter
        self.deleted = False

    def wait_ready(self):
        return None

    def image_digest(self):
        return IMAGE_DIGEST

    def image_manifest_digest(self, image_ref, *, expected_manifest_digest=None):
        assert image_ref == IMAGE_REF
        assert expected_manifest_digest == IMAGE_DIGEST
        return IMAGE_DIGEST

    def copy_dir_to(self, local_dir, remote_dir):
        del local_dir, remote_dir

    def exec(self, command, timeout=None, env=None):
        del timeout, env
        return subprocess.CompletedProcess(
            command, 0, stdout=b'{"type":"result"}\n', stderr=b""
        )

    def copy_dir_from(self, remote_dir, local_dir):
        assert remote_dir == "/workspace"
        shutil.copytree(self.starter, local_dir)

    def infrastructure_failure(self, command_exit_code=None):
        del command_exit_code

    def delete(self):
        self.deleted = True


def _attribute_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _attribute_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _attribute_keys(item)


def test_governed_run_writes_ordered_privacy_safe_audit_and_applies_budget(
    monkeypatch, tmp_path
):
    task = load_task("example-todo-api")
    task = task.model_copy(
        update={
            "network": task.network.model_copy(
                update={"agent_mode": "open", "allowed_domains": []}
            )
        }
    )
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(
        _policy_data(registered_task=task, network_modes=["open"])
    )
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode="open",
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        **_task_evidence_args(task, run_judge=False),
    )
    assert decision.allowed is True

    class Adapter:
        name = AGENT
        env = {}

        def build_command(self, model=None):
            assert model == MODEL
            return "run-agent"

        def parse_transcript(self, transcript):
            assert transcript.is_file()
            return AgentMetrics(
                tokens_in=10,
                tokens_out=10,
                cost_usd=0.1,
                model=MODEL,
            )

    runs_root = tmp_path / "runs"
    run_id = "governed-run"
    pod = _SuccessfulAgentPod(task.workspace_dir)
    captured_task_limits = []
    runtime_task_roots = []
    audit_at_credential_access = []
    source_test = next(path for path in task.tests_dir.rglob("*") if path.is_file())
    source_test_relative = source_test.relative_to(task.tests_dir)
    admitted_test_bytes = source_test.read_bytes()
    monkeypatch.setattr(metrics, "RUNS_ROOT", runs_root)
    monkeypatch.setattr(runner, "new_run_id", lambda task, agent: run_id)
    monkeypatch.setattr(runner, "ensure_namespace", lambda: None)
    monkeypatch.setattr(runner, "_image_digest", lambda image: IMAGE_DIGEST)

    def create_pod_after_source_change(*args, **kwargs):
        assert args[:2] == ("agent", IMAGE_REF)
        assert kwargs["image_pull_policy"] == "Never"
        source_test.write_text("changed after governed snapshot\n", encoding="utf-8")
        return pod

    monkeypatch.setattr(runner, "create_sandbox_pod", create_pod_after_source_change)

    def fake_credentials(*args, **kwargs):
        del args, kwargs
        audit_path = runs_root / run_id / "audit.jsonl"
        assert audit_path.is_file()
        events = [json.loads(line) for line in audit_path.read_text().splitlines()]
        audit_at_credential_access.extend(event["event_type"] for event in events)

    monkeypatch.setattr(runner, "load_trial_credentials", fake_credentials)
    monkeypatch.setattr(runner, "_docker_platform", lambda: IMAGE_PLATFORM)
    monkeypatch.setattr(
        runner,
        "ensure_image",
        lambda task, rebuild=False, expected_digest=None, image_ref=None: (
            expected_digest or IMAGE_DIGEST
        ),
    )
    monkeypatch.setattr(runner.cluster_mod, "ensure_cluster", lambda: None)

    def capture_provenance(governed_task, record):
        runtime_task_roots.append(governed_task.path)
        captured_task_limits.append(
            (
                governed_task.acceptance.max_total_tokens,
                governed_task.acceptance.max_cost_usd,
            )
        )
        assert record.governance is not None
        record.provenance.image_tag = record.governance.task_image_ref
        record.provenance.image_digest = record.governance.task_image_digest
        record.provenance.harness_commit = "b" * 40
        record.provenance.harness_dirty = False
        record.provenance.harness_worktree_sha256 = "c" * 64

    monkeypatch.setattr(runner, "_capture_provenance", capture_provenance)
    monkeypatch.setattr(runner, "create_attestation", lambda **kwargs: None)

    def fake_eval(governed_task, *args, **kwargs):
        del args
        assert kwargs["runtime_image"] == IMAGE_REF
        assert kwargs["image_pull_policy"] == "Never"
        runtime_task_roots.append(governed_task.path)
        assert governed_task.path != task.path
        assert (
            governed_task.tests_dir / source_test_relative
        ).read_bytes() == admitted_test_bytes
        return EvalTestResults(
            evaluation_mode="isolated-black-box",
            total=1,
            passed=1,
            command_exit_code=0,
            coverage_percent=100.0,
            runtime_image_digest=IMAGE_DIGEST,
            submission_runtime_image_digest=IMAGE_DIGEST,
        )

    monkeypatch.setattr(runner, "run_eval_phase", fake_eval)

    def fake_diff(starter, produced, run_dir):
        del starter, produced
        (run_dir / "workspace.diff").write_text("", encoding="utf-8")
        return DiffStats()

    monkeypatch.setattr(runner, "compute_diff", fake_diff)
    monkeypatch.setattr(
        scanners,
        "run_scanners",
        lambda *args, **kwargs: SCANNER_RESULTS.model_copy(deep=True),
    )

    try:
        record = runner.run_agent_trial(
            task,
            Adapter(),
            model=MODEL,
            governance_request=request,
            governance_bundle=bundle,
            governance_decision=decision,
            run_scans=True,
            run_judge=False,
        )
    finally:
        source_test.write_bytes(admitted_test_bytes)

    run_dir = runs_root / run_id
    assert audit_at_credential_access == [
        "evaluation.requested",
        "policy.admitted",
        "agent.started",
    ]
    assert captured_task_limits == [(25, 0.2)]
    assert runtime_task_roots
    assert all(root != task.path for root in runtime_task_roots)
    assert all(not root.exists() for root in runtime_task_roots)
    assert pod.deleted is True
    assert record.outcome.status == "accepted"
    assert record.governance is not None
    assert record.governance.preflight_decision_id == decision.decision_id
    assert record.governance.decision_id != decision.decision_id
    assert record.governance.task_image_digest == IMAGE_DIGEST
    assert json.loads((run_dir / "governance-request.json").read_text()) == (
        request.model_dump(mode="json")
    )
    assert json.loads((run_dir / "preflight-decision.json").read_text()) == (
        decision.model_dump(mode="json")
    )
    final_decision = json.loads((run_dir / "policy-decision.json").read_text())
    assert final_decision["decision_stage"] == "execution"
    assert final_decision["sanitized_input"]["task_image_digest"] == IMAGE_DIGEST
    for name in (
        "governance-request.json",
        "policy-bundle.json",
        "preflight-decision.json",
        "policy-decision.json",
        "audit.jsonl",
    ):
        assert stat.S_IMODE((run_dir / name).stat().st_mode) == 0o600

    events = [
        json.loads(line) for line in (run_dir / "audit.jsonl").read_text().splitlines()
    ]
    assert [event["event_type"] for event in events] == [
        "evaluation.requested",
        "policy.admitted",
        "agent.started",
        "agent.completed",
        "cleanup.completed",
        "evaluation.started",
        "tests.completed",
        "scanners.completed",
        "judge.skipped",
        "outcome.decided",
        "run.completed",
    ]
    forbidden = {
        "authorization",
        "apikey",
        "password",
        "secret",
        "credential",
        "cookie",
        "prompt",
        "completion",
        "transcript",
        "stdout",
        "stderr",
        "content",
    }
    for event in events:
        normalized_keys = {
            re.sub(r"[^a-z0-9]", "", key.casefold())
            for key in _attribute_keys(event["attributes"])
        }
        assert normalized_keys.isdisjoint(forbidden)

    verified = verify_audit_chain(
        run_dir / "audit.jsonl",
        expected_final_hash=record.provenance.audit_final_hash,
        expected_run_id=run_id,
    )
    assert verified.ok is True
    assert verified.event_count == len(events) == record.provenance.audit_event_count
    assert verified.final_hash == record.provenance.audit_final_hash
    assert verified.trace_id == final_decision["trace_id"]
    assert verified.trace_id == record.provenance.audit_trace_id
    persisted = RunRecord.model_validate_json((run_dir / "results.json").read_text())
    assert persisted.provenance.audit_final_hash == verified.final_hash
    assert cli._audit_lifecycle_failures(persisted, run_dir / "audit.jsonl") == []


def test_persist_run_binds_governance_and_audit_artifacts(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        **_task_evidence_args(task),
    )
    preflight = decision
    decision = _execution_from_preflight(request, bundle, preflight)
    evidence = GovernanceEvidence.from_decision(request, decision)
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    record = RunRecord(
        run_id="attested-governed-run",
        task_id=task.id,
        agent=AGENT,
        governance=evidence,
    )
    record.provenance.image_tag = record.governance.task_image_ref
    record.provenance.image_digest = IMAGE_DIGEST
    record.provenance.task_tree_sha256 = record.governance.task_tree_sha256
    record.provenance.harness_commit = "b" * 40
    record.provenance.harness_dirty = False
    record.provenance.harness_worktree_sha256 = "c" * 64
    record.run_dir.mkdir(parents=True)
    (record.run_dir / "audit.jsonl").write_text("audit\n")
    (record.run_dir / "governance-request.json").write_text("{}")
    (record.run_dir / "policy-bundle.json").write_text("{}")
    (record.run_dir / "preflight-decision.json").write_text("{}")
    (record.run_dir / "policy-decision.json").write_text("{}")
    captured = {}

    def capture_attestation(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(runner, "create_attestation", capture_attestation)

    runner._persist_run(task, record)

    assert captured["governance"] == evidence.model_dump(mode="json")
    assert {
        "results.json",
        "audit.jsonl",
        "governance-request.json",
        "policy-bundle.json",
        "preflight-decision.json",
        "policy-decision.json",
    } <= set(captured["artifact_paths"])


def test_governed_model_identity_must_be_observed_exactly():
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        **_task_evidence_args(task),
    )
    decision = _execution_from_preflight(request, bundle, decision)
    record = RunRecord(
        run_id="model-evidence",
        task_id=task.id,
        agent=AGENT,
        governance=GovernanceEvidence.from_decision(request, decision),
        efficiency=AgentMetrics(wall_time_s=1.0, model="provider-fallback"),
    )

    runner._enforce_governed_model_evidence(record)

    assert "observed 'provider-fallback'" in record.efficiency.infra_error
    assert MODEL in record.efficiency.infra_error


def test_task_changed_after_admission_is_rejected_before_trial(tmp_path):
    source = load_task("example-todo-api")
    tasks_root = tmp_path / "tasks"
    shutil.copytree(source.path, tasks_root / source.id)
    task = load_task(source.id, tasks_root)
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    changed_file = sorted(task.workspace_dir.rglob("*.py"))[0]
    changed_file.write_text(changed_file.read_text() + "\n# changed after admission\n")

    with pytest.raises(ValueError, match="runtime evidence"):
        runner._validate_governance_decision(
            task,
            agent=AGENT,
            model=MODEL,
            trial=1,
            run_scans=True,
            run_judge=True,
            request=request,
            bundle=bundle,
            decision=decision,
            decision_stage="preflight",
            task_image_digest=None,
            task_image_ref=None,
            task_image_platform=None,
        )


def test_execution_digest_binds_scanner_and_judge_recipe():
    task = load_task("example-todo-api")

    tree_a, all_graders = runner._governance_task_evidence(
        task, run_scans=True, run_judge=True
    )
    tree_b, no_judge = runner._governance_task_evidence(
        task, run_scans=True, run_judge=False
    )
    tree_c, no_scans = runner._governance_task_evidence(
        task, run_scans=False, run_judge=True
    )

    assert tree_a == tree_b == tree_c
    assert len({all_graders, no_judge, no_scans}) == 3


def test_execution_digest_binds_cluster_runtime(monkeypatch):
    task = load_task("example-todo-api")
    monkeypatch.delenv("AGENT_EVAL_RUNTIME_CLASS", raising=False)
    _, default_runtime = runner._governance_task_evidence(
        task, run_scans=True, run_judge=True
    )
    monkeypatch.setenv("AGENT_EVAL_RUNTIME_CLASS", "gvisor")
    _, hardened_runtime = runner._governance_task_evidence(
        task, run_scans=True, run_judge=True
    )

    assert default_runtime != hardened_runtime


def test_completion_recheck_fails_closed_if_governed_snapshot_changes(
    monkeypatch, tmp_path
):
    source = load_task("example-todo-api")
    tasks_root = tmp_path / "tasks"
    shutil.copytree(source.path, tasks_root / source.id)
    task = load_task(source.id, tasks_root)
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    decision = _execution_from_preflight(request, bundle, decision)
    record = RunRecord(
        run_id="changed-governed-snapshot",
        task_id=task.id,
        agent=AGENT,
        governance=GovernanceEvidence.from_decision(request, decision),
        correctness=EvalTestResults(total=1, passed=1, command_exit_code=0),
    )
    changed_file = next(path for path in task.tests_dir.rglob("*") if path.is_file())
    changed_file.write_text("changed during execution\n", encoding="utf-8")
    monkeypatch.setattr(runner, "_persist_run", lambda *args, **kwargs: None)

    completed = runner._complete_record(task, record, None)

    assert completed.outcome.status == "infra_error"
    assert "snapshot changed during execution" in completed.efficiency.infra_error


def test_completion_requires_admitted_judge_evidence(monkeypatch):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task, run_judge=True),
    )
    decision = _execution_from_preflight(request, bundle, decision)
    record = RunRecord(
        run_id="missing-governed-judge",
        task_id=task.id,
        agent=AGENT,
        governance=GovernanceEvidence.from_decision(request, decision),
        correctness=EvalTestResults(total=1, passed=1, command_exit_code=0),
    )
    monkeypatch.setattr(runner, "_persist_run", lambda *args, **kwargs: None)

    completed = runner._complete_record(task, record, audit=None)

    assert completed.outcome.status == "infra_error"
    assert "governed judge evidence is missing" in completed.efficiency.infra_error


def test_completion_rejects_a_scanner_identity_different_from_admission(monkeypatch):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task, run_judge=False),
    )
    decision = _execution_from_preflight(request, bundle, preflight)
    mismatched_scans = SCANNER_RESULTS.model_copy(deep=True)
    mismatched_scans.scanner_runtime_environment_sha256 = "0" * 64
    mismatched_scans.scanner_assurance = scanners.scanner_assurance_identity(
        mismatched_scans
    )
    mismatched_scans = ScanResults.model_validate(
        mismatched_scans.model_dump(mode="python")
    )
    record = RunRecord(
        run_id="mismatched-governed-scanner",
        task_id=task.id,
        agent=AGENT,
        governance=GovernanceEvidence.from_decision(request, decision),
        correctness=EvalTestResults(
            evaluation_mode="isolated-black-box",
            total=1,
            passed=1,
            command_exit_code=0,
        ),
        scans=mismatched_scans,
    )
    monkeypatch.setattr(runner, "_persist_run", lambda *args, **kwargs: None)

    completed = runner._complete_record(task, record, audit=None)

    assert completed.outcome.status == "infra_error"
    assert "scanner assurance identity does not match" in (
        completed.efficiency.infra_error
    )


def test_governed_snapshot_is_removed_when_run_setup_raises(monkeypatch):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    preflight = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task, run_judge=False),
    )
    execution = _execution_from_preflight(request, bundle, preflight)
    snapshot_paths = []
    real_snapshot = runner._snapshot_governed_task

    def capture_snapshot(*args, **kwargs):
        snapshot = real_snapshot(*args, **kwargs)
        snapshot_paths.append(snapshot.path)
        return snapshot

    monkeypatch.setattr(runner, "_snapshot_governed_task", capture_snapshot)

    def fail_prepare(*args, **kwargs):
        del args, kwargs
        raise OSError("injected")

    monkeypatch.setattr(runner, "prepare_run_dir", fail_prepare)
    adapter = type("Adapter", (), {"name": AGENT, "env": {}})()

    with pytest.raises(OSError, match="injected"):
        runner.run_agent_trial(
            task,
            adapter,
            model=MODEL,
            run_scans=True,
            run_judge=False,
            governance_request=request,
            governance_bundle=bundle,
            governance_decision=preflight,
            governance_execution_decision=execution,
        )

    assert snapshot_paths
    assert all(not path.exists() for path in snapshot_paths)


def test_audit_lifecycle_rejects_skipped_admitted_judge(tmp_path):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task, run_judge=True),
    )
    decision = _execution_from_preflight(request, bundle, decision)
    record = RunRecord(
        run_id="skipped-governed-judge",
        task_id=task.id,
        agent=AGENT,
        trial=1,
        governance=GovernanceEvidence.from_decision(request, decision),
        outcome=RunOutcome(status="infra_error", reasons=["missing judge"]),
    )
    audit_path = tmp_path / "audit.jsonl"
    with AuditChain(audit_path, record.run_id, trace_id=decision.trace_id) as audit:
        audit.append(
            "evaluation.requested",
            {
                "request_id": str(request.request_id),
                "task_id": task.id,
                "agent": record.agent,
                "model": request.model,
                "trial": 1,
                "run_scans": True,
                "run_judge": True,
                "judge_backend": decision.sanitized_input["judge_backend"],
                "judge_model": decision.sanitized_input["judge_model"],
                "task_tree_sha256": decision.sanitized_input["task_tree_sha256"],
                "execution_spec_digest": decision.sanitized_input[
                    "execution_spec_digest"
                ],
                "task_image_digest": decision.sanitized_input["task_image_digest"],
                "task_image_ref": decision.sanitized_input["task_image_ref"],
                "task_image_platform": decision.sanitized_input["task_image_platform"],
            },
        )
        audit.append(
            "policy.admitted",
            {
                "decision_id": str(decision.decision_id),
                "request_digest": decision.request_digest,
                "policy_id": decision.policy_id,
                "policy_revision": decision.policy_revision,
                "policy_digest": decision.policy_digest,
                "task_registry_id": decision.task_registry_id,
                "task_registry_revision": decision.task_registry_revision,
                "task_registry_digest": decision.task_registry_digest,
                "registry_id": decision.registry_id,
                "registry_revision": decision.registry_revision,
                "registry_digest": decision.registry_digest,
            },
        )
        audit.append("agent.started", {"agent": AGENT, "model": MODEL, "trial": 1})
        audit.append("agent.completed", {"status": "completed"})
        audit.append("cleanup.completed", {"status": "completed"})
        audit.append("evaluation.started", {"task_id": task.id, "trial": 1})
        audit.append("tests.completed", {"status": "completed", "resolved": True})
        audit.append("scanners.completed", {"status": "completed"})
        audit.append("judge.skipped", {"reason_code": "secret_screen_incomplete"})
        audit.append(
            "outcome.decided",
            {"status": "infra_error", "check_count": 0, "reason_count": 1},
        )
        audit.append("run.completed", {"status": "infra_error"})

    failures = cli._audit_lifecycle_failures(record, audit_path)

    assert "admitted judge recipe requires a completed judge result" in failures


def test_audit_lifecycle_rejects_completed_judge_without_score(tmp_path):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task, run_judge=True),
    )
    decision = _execution_from_preflight(request, bundle, decision)
    record = RunRecord(
        run_id="scoreless-governed-judge",
        task_id=task.id,
        agent=AGENT,
        trial=1,
        governance=GovernanceEvidence.from_decision(request, decision),
        outcome=RunOutcome(status="infra_error", reasons=["missing judge score"]),
    )
    audit_path = tmp_path / "audit.jsonl"

    with AuditChain(audit_path, record.run_id, trace_id=decision.trace_id) as audit:
        audit.append(
            "evaluation.requested",
            {
                "request_id": str(request.request_id),
                "task_id": task.id,
                "agent": record.agent,
                "model": request.model,
                "trial": 1,
                "run_scans": True,
                "run_judge": True,
                "judge_backend": decision.sanitized_input["judge_backend"],
                "judge_model": decision.sanitized_input["judge_model"],
                "task_tree_sha256": decision.sanitized_input["task_tree_sha256"],
                "execution_spec_digest": decision.sanitized_input[
                    "execution_spec_digest"
                ],
                "task_image_digest": decision.sanitized_input["task_image_digest"],
                "task_image_ref": decision.sanitized_input["task_image_ref"],
                "task_image_platform": decision.sanitized_input["task_image_platform"],
            },
        )
        audit.append(
            "policy.admitted",
            {
                "decision_id": str(decision.decision_id),
                "request_digest": decision.request_digest,
                "policy_id": decision.policy_id,
                "policy_revision": decision.policy_revision,
                "policy_digest": decision.policy_digest,
                "task_registry_id": decision.task_registry_id,
                "task_registry_revision": decision.task_registry_revision,
                "task_registry_digest": decision.task_registry_digest,
                "registry_id": decision.registry_id,
                "registry_revision": decision.registry_revision,
                "registry_digest": decision.registry_digest,
            },
        )
        audit.append("agent.started", {"agent": AGENT, "model": MODEL, "trial": 1})
        audit.append("agent.completed", {"status": "completed"})
        audit.append("cleanup.completed", {"status": "completed"})
        audit.append("evaluation.started", {"task_id": task.id, "trial": 1})
        audit.append("tests.completed", {"status": "completed", "resolved": True})
        audit.append("scanners.completed", {"status": "completed"})
        audit.append(
            "judge.completed",
            {
                "status": "completed",
                "score_available": False,
                "dimension_count": 0,
                "backend": decision.sanitized_input["judge_backend"],
                "model": decision.sanitized_input["judge_model"],
            },
        )
        audit.append(
            "outcome.decided",
            {"status": "infra_error", "check_count": 0, "reason_count": 1},
        )
        audit.append("run.completed", {"status": "infra_error"})

    failures = cli._audit_lifecycle_failures(record, audit_path)

    assert "completed admitted judge recipe has no score evidence" in failures


def test_missing_governed_attestation_prerequisites_fail_closed(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        **_task_evidence_args(task),
    )
    decision = _execution_from_preflight(request, bundle, decision)
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    record = RunRecord(
        run_id="missing-provenance",
        task_id=task.id,
        agent=AGENT,
        governance=GovernanceEvidence.from_decision(request, decision),
        correctness=EvalTestResults(total=1, passed=1, command_exit_code=0),
    )

    runner._complete_record(task, record, audit=None)

    assert record.outcome.status == "infra_error"
    assert "attestation prerequisites" in record.provenance.attestation_error
    persisted = RunRecord.model_validate_json(
        (record.run_dir / "results.json").read_text()
    )
    assert persisted.outcome.status == "infra_error"


def test_audit_cli_accepts_valid_chain_and_rejects_tampering(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    with AuditChain(audit_path, "run-1", trace_id="1" * 32) as chain:
        chain.append(
            "agent.started",
            {"agent": AGENT, "model": MODEL, "trial": 1},
        )
        chain.append("run.completed", {"status": "accepted"})
        final_hash = chain.final_hash

    cli_runner = CliRunner()
    valid = cli_runner.invoke(
        cli.app,
        [
            "audit",
            "verify",
            "--file",
            str(audit_path),
            "--expected-final-hash",
            final_hash,
            "--expected-run-id",
            "run-1",
        ],
    )
    assert valid.exit_code == 0, valid.output
    assert "verified" in valid.output

    audit_link = tmp_path / "audit-link.jsonl"
    audit_link.symlink_to(audit_path)
    linked = cli_runner.invoke(cli.app, ["audit", "verify", "--file", str(audit_link)])
    assert linked.exit_code == 2
    assert "symlink_rejected" in linked.output

    audit_path.write_text(
        audit_path.read_text().replace("run.completed", "run.tampered"),
        encoding="utf-8",
    )
    tampered = cli_runner.invoke(
        cli.app, ["audit", "verify", "--file", str(audit_path)]
    )
    assert tampered.exit_code == 2
    assert "event_hash_mismatch" in tampered.output


def test_verify_run_replays_policy_and_governed_lifecycle(monkeypatch, tmp_path):
    task = load_task("example-todo-api")
    request = EvaluationRequest.model_validate(_request_data(task.id))
    bundle = GovernanceBundle.model_validate(_policy_data())
    domains, proxy_image = runner._governance_network_evidence(task, AGENT)
    decision = evaluate_admission(
        request,
        bundle,
        actual_task_id=task.id,
        actual_agent=AGENT,
        actual_model=MODEL,
        trials=1,
        network_mode=task.network.agent_mode,
        agent_timeout_seconds=task.timeouts.agent_seconds,
        eval_timeout_seconds=task.timeouts.eval_seconds,
        broker_configured=False,
        effective_egress_domains=domains,
        proxy_image=proxy_image,
        **_task_evidence_args(task),
    )
    preflight = decision
    decision = _execution_from_preflight(request, bundle, preflight)
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    record = RunRecord(
        run_id="verified-governed-run",
        task_id=task.id,
        agent=AGENT,
        trial=1,
        started_at="2026-07-14T19:00:00+00:00",
        finished_at="2026-07-14T19:01:00+00:00",
        governance=GovernanceEvidence.from_decision(request, decision),
        outcome=RunOutcome(status="infra_error", reasons=["fixture"]),
        scans=SCANNER_RESULTS.model_copy(deep=True),
    )
    record.efficiency.requested_model = MODEL
    record.efficiency.infra_error = "fixture"
    record.correctness.evaluation_mode = "isolated-black-box"
    record.run_dir.mkdir(parents=True)
    write_canonical_json(record.run_dir / "governance-request.json", request)
    write_canonical_json(record.run_dir / "policy-bundle.json", bundle)
    write_canonical_json(record.run_dir / "preflight-decision.json", preflight)
    write_canonical_json(record.run_dir / "policy-decision.json", decision)
    with AuditChain(
        record.run_dir / "audit.jsonl",
        record.run_id,
        trace_id=decision.trace_id,
    ) as audit:
        audit.append(
            "evaluation.requested",
            {
                "request_id": str(request.request_id),
                "task_id": task.id,
                "agent": record.agent,
                "model": request.model,
                "trial": 1,
                "run_scans": record.governance.run_scans,
                "run_judge": record.governance.run_judge,
                "judge_backend": record.governance.judge_backend,
                "judge_model": record.governance.judge_model,
                "task_tree_sha256": record.governance.task_tree_sha256,
                "execution_spec_digest": record.governance.execution_spec_digest,
                "task_image_digest": record.governance.task_image_digest,
                "task_image_ref": record.governance.task_image_ref,
                "task_image_platform": record.governance.task_image_platform,
            },
        )
        audit.append(
            "policy.admitted",
            {
                "decision_id": str(decision.decision_id),
                "request_digest": decision.request_digest,
                "policy_id": decision.policy_id,
                "policy_revision": decision.policy_revision,
                "policy_digest": decision.policy_digest,
                "task_registry_id": decision.task_registry_id,
                "task_registry_revision": decision.task_registry_revision,
                "task_registry_digest": decision.task_registry_digest,
                "registry_id": decision.registry_id,
                "registry_revision": decision.registry_revision,
                "registry_digest": decision.registry_digest,
            },
        )
        audit.append("agent.started", {"agent": AGENT, "model": MODEL, "trial": 1})
        audit.append("agent.completed", {"status": "infrastructure_error"})
        audit.append("cleanup.completed", {"status": "completed"})
        audit.append("outcome.decided", {"status": "infra_error"})
        audit.append("run.completed", {"status": "infra_error"})
        record.provenance.audit_trace_id = audit.trace_id
        record.provenance.audit_final_hash = audit.final_hash
        record.provenance.audit_event_count = audit.event_count
    git = capture_git_state(Path(__file__).resolve().parents[1])
    record.provenance.image_tag = record.governance.task_image_ref
    record.provenance.image_digest = IMAGE_DIGEST
    record.provenance.local_image_digest = IMAGE_DIGEST
    record.provenance.task_tree_sha256 = record.governance.task_tree_sha256
    record.provenance.harness_commit = git.sha
    record.provenance.harness_dirty = git.dirty
    record.provenance.harness_worktree_sha256 = git.worktree_sha256
    effective_task = runner._governed_task(task, decision)
    record.assessments = derive_assessments(record, effective_task)

    assert runner._persist_run(task, record) is None
    result = CliRunner().invoke(cli.app, ["verify-run", "--run", record.run_id])

    assert result.exit_code == 0, result.output
    assert "verified" in result.output

    with metrics._connect() as connection:
        connection.execute(
            "UPDATE assessments SET status = 'failed' "
            "WHERE assessment_id = ("
            "SELECT assessment_id FROM assessments WHERE run_id = ? LIMIT 1"
            ")",
            (record.run_id,),
        )
    assessment_tamper = CliRunner().invoke(
        cli.app,
        ["verify-run", "--run", record.run_id],
    )
    assert assessment_tamper.exit_code == 2
    assert "normalized assessments differ" in assessment_tamper.output
    assert runner._persist_run(task, record) is None

    with metrics._connect() as connection:
        connection.execute(
            "UPDATE runs SET tests_passed = 999, tests_total = 999, cost_usd = 0 "
            "WHERE run_id = ?",
            (record.run_id,),
        )
    run_projection_tamper = CliRunner().invoke(
        cli.app,
        ["verify-run", "--run", record.run_id],
    )
    assert run_projection_tamper.exit_code == 2
    assert "run projection differs" in run_projection_tamper.output
    assert runner._persist_run(task, record) is None

    resolved_assessment = next(
        assessment
        for assessment in record.assessments
        if assessment.name == "tests.resolved"
    )
    assert resolved_assessment.value is not None
    record.assessments = [
        (
            assessment.model_copy(
                update={
                    "value": assessment.value.model_copy(update={"boolean": True})
                }
            )
            if assessment.name == "tests.resolved" and assessment.value is not None
            else assessment
        )
        for assessment in record.assessments
    ]
    assert runner._persist_run(task, record) is None
    stale_envelope = CliRunner().invoke(
        cli.app,
        ["verify-run", "--run", record.run_id],
    )
    assert stale_envelope.exit_code == 2
    assert "assessment envelope does not recompute" in stale_envelope.output
    record.assessments = derive_assessments(record, effective_task)
    assert runner._persist_run(task, record) is None

    mismatched_scans = SCANNER_RESULTS.model_copy(deep=True)
    mismatched_scans.scanner_runtime_environment_sha256 = "0" * 64
    mismatched_scans.scanner_assurance = scanners.scanner_assurance_identity(
        mismatched_scans
    )
    record.scans = ScanResults.model_validate(
        mismatched_scans.model_dump(mode="python")
    )
    assert runner._persist_run(task, record) is None
    scanner_mismatch = CliRunner().invoke(
        cli.app, ["verify-run", "--run", record.run_id]
    )
    assert scanner_mismatch.exit_code == 2
    assert "scanner assurance identity does not match" in scanner_mismatch.output
    record.scans = SCANNER_RESULTS.model_copy(deep=True)
    assert runner._persist_run(task, record) is None

    stored = json.loads(record.model_dump_json())
    stored["scans"]["scanner_assurance"][
        "runtime_environment_sha256"
    ] = "9" * 64
    with metrics._connect() as connection:
        connection.execute(
            "UPDATE runs SET results_json = ? WHERE run_id = ?",
            (json.dumps(stored), record.run_id),
        )
    scanner_material_tamper = CliRunner().invoke(
        cli.app, ["verify-run", "--run", record.run_id]
    )
    assert scanner_material_tamper.exit_code == 2
    assert "persisted run schema is invalid" in scanner_material_tamper.output
    assert "identity_sha256 does not match its material" in (
        scanner_material_tamper.output
    )
    assert runner._persist_run(task, record) is None

    audit_path = record.run_dir / "audit.jsonl"
    original_audit = audit_path.read_bytes()
    original_audit_hash = record.provenance.audit_final_hash
    events = [json.loads(line) for line in original_audit.splitlines()]
    for event in events:
        if event["event_type"] == "agent.started":
            event["attributes"]["model"] = "contradictory-model"
    previous_hash = GENESIS_HASH
    for event in events:
        event["previous_hash"] = previous_hash
        payload = {key: value for key, value in event.items() if key != "event_hash"}
        event["event_hash"] = hashlib.sha256(
            canonical_audit_json_bytes(payload)
        ).hexdigest()
        previous_hash = event["event_hash"]
    audit_path.write_bytes(
        b"".join(canonical_audit_json_bytes(event) + b"\n" for event in events)
    )
    record.provenance.audit_final_hash = previous_hash
    assert runner._persist_run(task, record) is None
    contradictory_audit = CliRunner().invoke(
        cli.app, ["verify-run", "--run", record.run_id]
    )
    assert contradictory_audit.exit_code == 2
    assert "agent.started does not match" in contradictory_audit.output

    audit_path.write_bytes(original_audit)
    record.provenance.audit_final_hash = original_audit_hash
    assert runner._persist_run(task, record) is None

    statement_path = record.run_dir / "attestation.json"
    statement_value = json.loads(statement_path.read_bytes())
    statement_value["predicate"]["models"]["agent"] = "unrecorded-model"
    statement_data = canonical_statement_bytes(statement_value)
    statement_path.write_bytes(statement_data)
    (record.run_dir / "attestation.json.sha256").write_text(
        hashlib.sha256(statement_data).hexdigest() + "\n",
        encoding="ascii",
    )
    semantic_mismatch = CliRunner().invoke(
        cli.app, ["verify-run", "--run", record.run_id]
    )
    assert semantic_mismatch.exit_code == 2
    assert "statement models do not match" in semantic_mismatch.output

    assert runner._persist_run(task, record) is None
    from agent_eval import attestation as attestation_module

    real_verify = attestation_module.verify_attestation
    results_path = record.run_dir / "results.json"

    def swap_results_after_verification(*args, **kwargs):
        verification = real_verify(*args, **kwargs)
        results_path.write_bytes(results_path.read_bytes() + b" ")
        return verification

    monkeypatch.setattr(
        attestation_module, "verify_attestation", swap_results_after_verification
    )
    swapped_results = CliRunner().invoke(
        cli.app, ["verify-run", "--run", record.run_id]
    )
    assert swapped_results.exit_code == 2
    assert (
        "results.json changed after attestation verification" in swapped_results.output
    )

    monkeypatch.setattr(attestation_module, "verify_attestation", real_verify)
    assert runner._persist_run(task, record) is None
    policy_path = record.run_dir / "policy-bundle.json"
    original_policy = policy_path.read_bytes()

    def swap_policy_after_verification(*args, **kwargs):
        verification = real_verify(*args, **kwargs)
        policy_path.write_bytes(b"{}")
        return verification

    monkeypatch.setattr(
        attestation_module, "verify_attestation", swap_policy_after_verification
    )
    swapped_policy = CliRunner().invoke(cli.app, ["verify-run", "--run", record.run_id])
    assert swapped_policy.exit_code == 2
    assert (
        "policy-bundle.json changed after attestation verification"
        in swapped_policy.output
    )
    monkeypatch.setattr(attestation_module, "verify_attestation", real_verify)
    policy_path.write_bytes(original_policy)

    original_outcome = record.outcome
    record.outcome = RunOutcome(status="accepted")
    assert runner._persist_run(task, record) is None
    wrong_outcome = CliRunner().invoke(cli.app, ["verify-run", "--run", record.run_id])
    assert wrong_outcome.exit_code == 2
    assert (
        "recorded outcome does not recompute from run evidence" in wrong_outcome.output
    )
    record.outcome = original_outcome

    record.efficiency.runtime_image_digest = "sha256:" + "f" * 64
    assert runner._persist_run(task, record) is None
    mismatched = CliRunner().invoke(cli.app, ["verify-run", "--run", record.run_id])

    assert mismatched.exit_code == 2
    assert "agent runtime digest does not match" in mismatched.output


def test_verify_run_rejects_unknown_persisted_result_fields(monkeypatch, tmp_path):
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    record = RunRecord(
        run_id="unknown-result-field",
        task_id="example-todo-api",
        agent=AGENT,
    )
    metrics.save_run(record)
    stored = json.loads(record.model_dump_json())
    stored["efficiency"]["unexpected_enterprise_field"] = True
    with metrics._connect() as connection:
        connection.execute(
            "UPDATE runs SET results_json = ? WHERE run_id = ?",
            (json.dumps(stored), record.run_id),
        )

    result = CliRunner().invoke(cli.app, ["verify-run", "--run", record.run_id])

    assert result.exit_code == 2
    assert "persisted run schema is invalid" in result.output
    assert "unexpected_enterprise_field" in result.output


def test_legacy_run_record_parses_without_governance_or_audit_fields():
    legacy = RunRecord.model_validate_json(
        json.dumps(
            {
                "run_id": "legacy-run",
                "task_id": "example-todo-api",
                "agent": AGENT,
                "trial": 1,
                "provenance": {
                    "image_tag": "agent-eval/example:legacy",
                    "tool_versions": {},
                },
            }
        )
    )

    assert legacy.governance is None
    assert legacy.provenance.audit_trace_id is None
    assert legacy.provenance.audit_final_hash is None
    assert legacy.provenance.audit_event_count is None
    assert legacy.provenance.audit_error is None
    assert legacy.provenance.attestation_error is None
