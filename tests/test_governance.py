from __future__ import annotations

import json
import math
import os
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from pydantic import ValidationError

from agent_eval import runner
from agent_eval.governance import (
    DuplicateKeyError,
    EvaluationRequest,
    GovernanceBundle,
    GovernanceEvidence,
    LegacyGovernanceEvidenceV1,
    canonical_json_bytes,
    evaluate_admission,
    load_evaluation_request,
    load_governance_bundle,
    sha256_json,
    validate_execution_continuity,
    write_canonical_json,
)
from agent_eval.task import load_task

PROXY_IMAGE = "ubuntu/squid@sha256:" + "a" * 64
SCANNER_IDENTITY = "9" * 64
REPO_ROOT = Path(__file__).resolve().parents[1]


def request_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema_version": "agent-eval.request/v2",
        "request_id": "12345678-1234-5678-9234-567812345678",
        "idempotency_key": "nightly:payment-api:42",
        "tenant_id": "frontier-labs",
        "project_id": "payments/api",
        "asserted_actor": "user:reviewer@example.com",
        "task_id": "repair-refund-race",
        "agent": "anthropic",
        "model": "claude-sonnet-4-5-20250929",
        "data_classification": "confidential",
        "retention_class": "regulated",
        "max_observed_total_tokens": 1_000,
        "max_observed_cost_usd": 0.5,
        "labels": {"team": "payments", "purpose": "release gate"},
    }
    data.update(overrides)
    return data


def bundle_data(**rule_overrides: object) -> dict[str, object]:
    rules: dict[str, object] = {
        "allowed_tenants": ["frontier-*"],
        "allowed_projects": ["payments/*"],
        "allowed_tasks": ["repair-*"],
        "allowed_network_modes": ["proxy"],
        "allowed_egress_domains": [".anthropic.com", ".claude.ai"],
        "allowed_proxy_images": [PROXY_IMAGE],
        "allowed_scanner_identities": [SCANNER_IDENTITY],
        "allowed_data_classifications": ["internal", "confidential"],
        "allowed_retention_classes": ["ephemeral", "regulated"],
        "require_scans": True,
        "require_judge": False,
        "require_broker_credentials": True,
        "max_trials": 5,
        "max_agent_seconds": 600,
        "max_eval_seconds": 300,
        "max_observed_total_tokens": 2_000,
        "max_observed_cost_usd": 2.0,
    }
    rules.update(rule_overrides)
    return {
        "schema_version": "agent-eval.policy/v2",
        "policy_id": "prod-evaluation",
        "revision": "2026-07-14.1",
        "rules": rules,
        "task_registry": {
            "registry_id": "frontier-tasks",
            "revision": "2026-07-14",
            "tasks": [
                {
                    "task_id": "repair-refund-race",
                    "task_tree_sha256": "b" * 64,
                    "execution_spec_digests": ["c" * 64],
                    "approved_images": [
                        {
                            "platform": "linux/amd64",
                            "reference": (
                                "agent-eval/repair-refund-race:governed-" + "d" * 64
                            ),
                            "manifest_digest": "sha256:" + "d" * 64,
                            "builder_id": "https://ci.example/builders/task-images",
                            "build_type": "https://slsa.dev/container/v1",
                            "source_revision": "commit-123",
                            "provenance_sha256": "e" * 64,
                        }
                    ],
                    "status": "approved",
                }
            ],
        },
        "model_registry": {
            "registry_id": "frontier-models",
            "revision": "2026-07-14",
            "models": [
                {
                    "adapter": "anthropic",
                    "model": "claude-sonnet-4-5-20250929",
                    "provider": "anthropic",
                    "status": "approved",
                    "allowed_data_classifications": [
                        "public",
                        "internal",
                        "confidential",
                    ],
                    "max_observed_total_tokens": 1_500,
                    "max_observed_cost_usd": 1.0,
                },
                {
                    "adapter": "judge:claude",
                    "model": "claude-sonnet-4-5-20250929",
                    "provider": "anthropic",
                    "status": "approved",
                    "allowed_data_classifications": [
                        "public",
                        "internal",
                        "confidential",
                    ],
                },
            ],
        },
    }


def request(**overrides: object) -> EvaluationRequest:
    return EvaluationRequest.model_validate(request_data(**overrides))


def bundle(**rule_overrides: object) -> GovernanceBundle:
    return GovernanceBundle.model_validate(bundle_data(**rule_overrides))


def admission(
    evaluation_request: EvaluationRequest | None = None,
    governance_bundle: GovernanceBundle | None = None,
    **overrides: object,
):
    arguments: dict[str, object] = {
        "actual_task_id": "repair-refund-race",
        "actual_agent": "anthropic",
        "actual_model": "claude-sonnet-4-5-20250929",
        "trials": 3,
        "network_mode": "proxy",
        "agent_timeout_seconds": 500,
        "eval_timeout_seconds": 200,
        "broker_configured": True,
        "run_scans": True,
        "scanner_identity_sha256": SCANNER_IDENTITY,
        "scanner_promotion_ready": True,
        "run_judge": True,
        "judge_backend": "claude",
        "judge_model": "claude-sonnet-4-5-20250929",
        "task_tree_sha256": "b" * 64,
        "execution_spec_digest": "c" * 64,
        "effective_egress_domains": [".anthropic.com", ".claude.ai"],
        "proxy_image": PROXY_IMAGE,
    }
    arguments.update(overrides)
    if arguments["run_scans"] is not True:
        if "scanner_identity_sha256" not in overrides:
            arguments["scanner_identity_sha256"] = None
        if "scanner_promotion_ready" not in overrides:
            arguments["scanner_promotion_ready"] = False
    if arguments["run_judge"] is not True:
        arguments["judge_backend"] = None
        arguments["judge_model"] = None
    return evaluate_admission(
        evaluation_request or request(),
        governance_bundle or bundle(),
        **arguments,  # type: ignore[arg-type]
    )


def execution_admission(
    evaluation_request: EvaluationRequest | None = None,
    governance_bundle: GovernanceBundle | None = None,
    **overrides: object,
):
    evaluation_request = evaluation_request or request()
    governance_bundle = governance_bundle or bundle()
    preflight = admission(evaluation_request, governance_bundle, **overrides)
    return admission(
        evaluation_request,
        governance_bundle,
        **overrides,
        decision_stage="execution",
        task_image_digest="sha256:" + "d" * 64,
        task_image_ref="agent-eval/repair-refund-race:governed-" + "d" * 64,
        task_image_platform="linux/amd64",
        preflight_decision_id=preflight.decision_id,
        preflight_decision_digest=sha256_json(preflight),
    )


def test_admission_allows_exact_runtime_and_uses_effective_minima():
    decision = admission()

    assert decision.allowed is True
    assert [reason.code for reason in decision.reasons] == ["admitted"]
    assert decision.effective_limits.model_dump() == {
        "max_trials": 5,
        "max_agent_seconds": 600,
        "max_eval_seconds": 300,
        "max_observed_total_tokens": 1_000,
        "max_observed_cost_usd": 0.5,
    }
    assert decision.matched_model is not None
    assert decision.matched_model.provider == "anthropic"
    assert decision.matched_task is not None
    assert decision.matched_task.task_tree_sha256 == "b" * 64
    assert isinstance(decision.decision_id, UUID)
    assert len(decision.trace_id) == 32
    assert decision.decided_at.utcoffset().total_seconds() == 0


def test_execution_denies_an_image_not_preapproved_by_platform_and_digest():
    data = bundle_data()
    image = data["task_registry"]["tasks"][0]["approved_images"][0]  # type: ignore[index]
    image["reference"] = "agent-eval/repair-refund-race:governed-" + "e" * 64
    image["manifest_digest"] = "sha256:" + "e" * 64
    governance_bundle = GovernanceBundle.model_validate(data)

    decision = execution_admission(governance_bundle=governance_bundle)

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == ["task_image_not_approved"]


def test_execution_continuity_binds_entire_authorization_snapshot():
    evaluation_request = request(
        max_observed_total_tokens=None,
        max_observed_cost_usd=None,
    )
    preflight_bundle = bundle()
    preflight = admission(evaluation_request, preflight_bundle)

    widened_data = bundle_data(
        max_observed_total_tokens=40_000,
        max_observed_cost_usd=40.0,
    )
    widened_data["revision"] = "2026-07-14.2"
    widened_model = widened_data["model_registry"]["models"][0]  # type: ignore[index]
    widened_model["max_observed_total_tokens"] = 40_000
    widened_model["max_observed_cost_usd"] = 40.0
    widened_bundle = GovernanceBundle.model_validate(widened_data)
    execution = admission(
        evaluation_request,
        widened_bundle,
        decision_stage="execution",
        task_image_digest="sha256:" + "d" * 64,
        task_image_ref="agent-eval/repair-refund-race:governed-" + "d" * 64,
        task_image_platform="linux/amd64",
        preflight_decision_id=preflight.decision_id,
        preflight_decision_digest=sha256_json(preflight),
    )

    assert preflight.allowed and execution.allowed
    assert (
        execution.effective_limits.max_observed_total_tokens
        > preflight.effective_limits.max_observed_total_tokens
    )
    with pytest.raises(ValueError, match="authorization snapshot"):
        validate_execution_continuity(preflight, execution)


def test_execution_continuity_accepts_only_image_bound_finalization():
    evaluation_request = request()
    governance_bundle = bundle()
    preflight = admission(evaluation_request, governance_bundle)
    execution = admission(
        evaluation_request,
        governance_bundle,
        decision_stage="execution",
        task_image_digest="sha256:" + "d" * 64,
        task_image_ref="agent-eval/repair-refund-race:governed-" + "d" * 64,
        task_image_platform="linux/amd64",
        preflight_decision_id=preflight.decision_id,
        preflight_decision_digest=sha256_json(preflight),
    )

    validate_execution_continuity(preflight, execution)


def test_request_limits_are_optional_and_harder_limits_still_apply():
    decision = admission(
        request(max_observed_total_tokens=None, max_observed_cost_usd=None)
    )

    assert decision.allowed is True
    assert decision.effective_limits.max_observed_total_tokens == 1_500
    assert decision.effective_limits.max_observed_cost_usd == 1.0


def test_governed_judge_requires_observable_registered_runtime_identity():
    missing = admission(judge_backend=None, judge_model=None)
    codex = admission(judge_backend="codex", judge_model="gpt-5.4")

    assert [reason.code for reason in missing.reasons] == ["judge_identity_required"]
    assert [reason.code for reason in codex.reasons] == [
        "judge_model_observation_unsupported"
    ]


def test_governed_codex_coding_is_denied_before_runtime_side_effects():
    data = bundle_data()
    data["model_registry"]["models"].append(  # type: ignore[index]
        {
            "adapter": "codex",
            "model": "gpt-5.4",
            "provider": "openai",
            "status": "approved",
            "allowed_data_classifications": [
                "public",
                "internal",
                "confidential",
            ],
            "max_observed_total_tokens": 1_500,
            "max_observed_cost_usd": 1.0,
        }
    )
    decision = admission(
        request(agent="codex", model="gpt-5.4"),
        GovernanceBundle.model_validate(data),
        actual_agent="codex",
        actual_model="gpt-5.4",
        run_judge=False,
    )

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == [
        "coding_model_observation_unsupported"
    ]


def test_judge_registry_identity_cannot_be_used_as_a_coding_agent():
    decision = admission(
        request(
            agent="judge:claude",
            model="claude-sonnet-4-5-20250929",
        ),
        actual_agent="judge:claude",
        run_judge=False,
    )

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == ["model_not_registered"]


def test_caller_ceiling_above_policy_is_clamped_not_treated_as_entitlement():
    decision = admission(
        request(max_observed_total_tokens=99_999, max_observed_cost_usd=99.0)
    )

    assert decision.allowed is True
    assert decision.effective_limits.max_observed_total_tokens == 1_500
    assert decision.effective_limits.max_observed_cost_usd == 1.0


def test_admission_accumulates_denials_in_stable_order():
    decision = admission(
        request(data_classification="restricted", retention_class="standard"),
        actual_task_id="other-task",
        actual_agent="openai",
        actual_model="gpt-unknown",
        trials=6,
        network_mode="open",
        agent_timeout_seconds=601,
        eval_timeout_seconds=301,
        broker_configured=False,
    )

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == [
        "task_not_registered",
        "task_mismatch",
        "agent_mismatch",
        "model_mismatch",
        "task_not_allowed",
        "data_classification_not_allowed",
        "retention_not_allowed",
        "network_mode_not_allowed",
        "judge_model_classification_not_allowed",
        "broker_credentials_required",
        "trial_limit_exceeded",
        "agent_timeout_exceeded",
        "eval_timeout_exceeded",
        "model_not_registered",
    ]
    assert decision.matched_model is None


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("trials", 0, "invalid_trials"),
        ("trials", True, "invalid_trials"),
        ("agent_timeout_seconds", -1, "invalid_agent_timeout"),
        ("agent_timeout_seconds", False, "invalid_agent_timeout"),
        ("eval_timeout_seconds", 0, "invalid_eval_timeout"),
    ],
)
def test_invalid_runtime_quantities_fail_closed(field: str, value: object, code: str):
    decision = admission(**{field: value})

    assert decision.allowed is False
    assert code in [reason.code for reason in decision.reasons]


def test_invalid_runtime_broker_state_fails_closed_even_when_not_required():
    decision = admission(
        governance_bundle=bundle(require_broker_credentials=False),
        broker_configured=1,
    )

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == [
        "invalid_broker_configuration"
    ]


def test_unapproved_effective_egress_domain_fails_closed():
    decision = admission(
        effective_egress_domains=[".anthropic.com", ".attacker.example"]
    )

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == ["egress_domain_not_allowed"]


def test_unapproved_proxy_image_fails_closed():
    decision = admission(proxy_image="registry.example/proxy@sha256:" + "b" * 64)

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == ["proxy_image_not_allowed"]


def test_proxy_mode_requires_an_exact_proxy_image():
    decision = admission(proxy_image=None)

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == ["proxy_image_required"]


def test_required_grader_phases_fail_closed():
    without_scans = admission(run_scans=False)
    without_judge = admission(
        governance_bundle=bundle(require_judge=True),
        run_judge=False,
    )

    assert [reason.code for reason in without_scans.reasons] == [
        "scans_required",
        "judge_requires_scans",
    ]
    assert [reason.code for reason in without_judge.reasons] == ["judge_required"]


def test_scanner_identity_must_be_approved_and_promotion_ready():
    unapproved = admission(scanner_identity_sha256="8" * 64)
    incomplete = admission(scanner_promotion_ready=False)

    assert [reason.code for reason in unapproved.reasons] == [
        "scanner_identity_not_allowed"
    ]
    assert [reason.code for reason in incomplete.reasons] == [
        "scanner_identity_incomplete"
    ]


def test_required_scans_require_a_nonempty_scanner_allowlist():
    data = bundle_data()
    data["rules"]["allowed_scanner_identities"] = []  # type: ignore[index]

    with pytest.raises(ValidationError, match="approved scanner identity"):
        GovernanceBundle.model_validate(data)


def test_governed_judge_requires_secret_screening_even_when_scans_are_optional():
    decision = admission(
        governance_bundle=bundle(require_scans=False),
        run_scans=False,
    )

    assert [reason.code for reason in decision.reasons] == ["judge_requires_scans"]


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("run_scans", "invalid_scan_configuration"),
        ("run_judge", "invalid_judge_configuration"),
    ],
)
def test_grader_phase_inputs_must_be_booleans(field: str, code: str):
    decision = admission(**{field: 1})

    assert code in [reason.code for reason in decision.reasons]


@pytest.mark.parametrize("status", ["deprecated", "blocked"])
def test_nonapproved_model_status_fails_closed(status: str):
    data = bundle_data()
    data["model_registry"]["models"][0]["status"] = status  # type: ignore[index]
    decision = admission(governance_bundle=GovernanceBundle.model_validate(data))

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == [f"model_{status}"]


def test_model_classification_is_a_separate_gate_from_policy():
    data = bundle_data(allowed_data_classifications=["restricted"])
    data["model_registry"]["models"][0][  # type: ignore[index]
        "allowed_data_classifications"
    ] = ["public"]
    decision = admission(
        request(data_classification="restricted"),
        GovernanceBundle.model_validate(data),
        run_judge=False,
    )

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == [
        "model_classification_not_allowed"
    ]


def test_empty_allowlist_matches_nothing():
    decision = admission(governance_bundle=bundle(allowed_tenants=[]))

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == ["tenant_not_allowed"]


def test_globs_are_case_sensitive():
    decision = admission(request(tenant_id="Frontier-labs"))

    assert decision.allowed is False
    assert [reason.code for reason in decision.reasons] == ["tenant_not_allowed"]


def test_decision_digests_bind_request_policy_and_registry_separately():
    first = admission()
    changed_request = admission(request(labels={"team": "risk"}))
    changed_policy = admission(governance_bundle=bundle(max_trials=4), trials=3)
    registry_data = bundle_data()
    registry_data["model_registry"]["revision"] = "2026-07-15"  # type: ignore[index]
    changed_registry = admission(
        governance_bundle=GovernanceBundle.model_validate(registry_data)
    )

    assert first.request_digest != changed_request.request_digest
    assert first.policy_digest == changed_request.policy_digest
    assert first.policy_digest != changed_policy.policy_digest
    assert first.registry_digest == changed_policy.registry_digest
    assert first.registry_digest != changed_registry.registry_digest


def test_admission_requires_exact_approved_task_content_and_execution_spec():
    wrong_tree = admission(task_tree_sha256="d" * 64)
    wrong_execution = admission(execution_spec_digest="e" * 64)
    missing = admission(actual_task_id="unregistered-task")

    assert [reason.code for reason in wrong_tree.reasons] == ["task_tree_not_approved"]
    assert [reason.code for reason in wrong_execution.reasons] == [
        "execution_spec_not_approved"
    ]
    assert "task_not_registered" in [reason.code for reason in missing.reasons]


def test_task_registry_digest_is_independent_and_task_status_fails_closed():
    first = admission()
    data = bundle_data()
    data["task_registry"]["revision"] = "2026-07-15"  # type: ignore[index]
    changed = admission(governance_bundle=GovernanceBundle.model_validate(data))
    blocked_data = bundle_data()
    blocked_data["task_registry"]["tasks"][0]["status"] = "blocked"  # type: ignore[index]
    blocked = admission(governance_bundle=GovernanceBundle.model_validate(blocked_data))

    assert first.task_registry_digest != changed.task_registry_digest
    assert first.policy_digest == changed.policy_digest
    assert first.registry_digest == changed.registry_digest
    assert [reason.code for reason in blocked.reasons] == ["task_blocked"]


def test_sanitized_input_omits_identity_idempotency_and_labels():
    decision = admission()

    serialized = json.dumps(decision.sanitized_input)
    assert "asserted_actor" not in decision.sanitized_input
    assert "idempotency" not in serialized
    assert "labels" not in serialized
    assert "reviewer@example.com" not in serialized
    assert decision.sanitized_input["actual_task_id"] == "repair-refund-race"


def test_evidence_marks_asserted_identity_unverified_and_carries_limits():
    evaluation_request = request()
    decision = execution_admission(evaluation_request)

    evidence = GovernanceEvidence.from_decision(evaluation_request, decision)

    assert evidence.asserted_actor == "user:reviewer@example.com"
    assert evidence.identity_assurance == "asserted-unverified"
    assert evidence.data_classification == "confidential"
    assert evidence.reason_codes == ["admitted"]
    assert evidence.policy_digest == decision.policy_digest
    assert evidence.task_registry_digest == decision.task_registry_digest
    assert evidence.registry_digest == decision.registry_digest
    assert evidence.task_image_digest == "sha256:" + "d" * 64
    assert evidence.preflight_decision_id == decision.preflight_decision_id
    assert evidence.effective_limits == decision.effective_limits


def test_legacy_evidence_remains_readable_without_inventing_task_approval():
    evaluation_request = request()
    current = GovernanceEvidence.from_decision(
        evaluation_request, execution_admission(evaluation_request)
    ).model_dump(mode="json")
    current["schema_version"] = "agent-eval.governance-evidence/v1"
    for field in (
        "task_registry_id",
        "task_registry_revision",
        "task_registry_digest",
        "matched_task",
        "scanner_identity_sha256",
        "scanner_promotion_ready",
    ):
        current.pop(field)
    current["effective_limits"]["max_total_tokens"] = current["effective_limits"].pop(
        "max_observed_total_tokens"
    )
    current["effective_limits"]["max_cost_usd"] = current["effective_limits"].pop(
        "max_observed_cost_usd"
    )
    current["matched_model"]["max_total_tokens"] = current["matched_model"].pop(
        "max_observed_total_tokens"
    )
    current["matched_model"]["max_cost_usd"] = current["matched_model"].pop(
        "max_observed_cost_usd"
    )

    legacy = LegacyGovernanceEvidenceV1.model_validate_json(json.dumps(current))

    assert legacy.schema_version == "agent-eval.governance-evidence/v1"
    assert legacy.task_tree_sha256 == "b" * 64
    assert "task_registry_id" not in legacy.model_dump()


def test_preflight_cannot_be_materialized_as_execution_evidence():
    evaluation_request = request()

    with pytest.raises(ValueError, match="requires an execution decision"):
        GovernanceEvidence.from_decision(
            evaluation_request, admission(evaluation_request)
        )


def test_evidence_rejects_decision_for_another_request():
    decision = admission()
    other = request(request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

    with pytest.raises(ValueError, match="request_id does not match"):
        GovernanceEvidence.from_decision(other, decision)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"schema_version": "v0"}, "schema_version"),
        ({"request_id": "not-a-uuid"}, "request_id"),
        ({"tenant_id": "has whitespace"}, "tenant_id"),
        ({"model": "gpt-*"}, "model"),
        ({"max_observed_total_tokens": "1000"}, "max_observed_total_tokens"),
        ({"max_observed_cost_usd": math.inf}, "max_observed_cost_usd"),
        ({"labels": {"bad key": "value"}}, "labels"),
        ({"unexpected": True}, "unexpected"),
    ],
)
def test_request_validation_is_strict(overrides: dict[str, object], message: str):
    with pytest.raises(ValidationError, match=message):
        request(**overrides)


def test_request_labels_are_bounded():
    with pytest.raises(ValidationError, match="at most 32"):
        request(labels={f"key-{index}": "value" for index in range(33)})


def test_registry_requires_unique_exact_adapter_model_entries():
    data = bundle_data()
    model = data["model_registry"]["models"][0]  # type: ignore[index]
    data["model_registry"]["models"].append(dict(model))  # type: ignore[index]

    with pytest.raises(ValidationError, match="duplicate adapter/model"):
        GovernanceBundle.model_validate(data)


def test_judge_registry_rejects_unenforceable_local_spend_limits():
    data = bundle_data()
    judge = data["model_registry"]["models"][1]  # type: ignore[index]
    judge["max_observed_total_tokens"] = 8_000

    with pytest.raises(ValidationError, match="max_observed_total_tokens"):
        GovernanceBundle.model_validate(data)


def test_coding_model_registry_requires_hard_budget_ceilings():
    data = bundle_data()
    model = data["model_registry"]["models"][0]  # type: ignore[index]
    del model["max_observed_cost_usd"]

    with pytest.raises(ValidationError, match="max_observed_cost_usd"):
        GovernanceBundle.model_validate(data)


def test_policy_rejects_duplicate_enum_allowlist_and_nonfinite_budget():
    with pytest.raises(ValidationError, match="must not contain duplicates"):
        bundle(allowed_network_modes=["proxy", "proxy"])
    with pytest.raises(ValidationError, match="max_observed_cost_usd"):
        bundle(max_observed_cost_usd=float("nan"))


@pytest.mark.parametrize("pattern", ["tenant[", "tenant]", "tenant[]", "tenant[!]"])
def test_policy_rejects_malformed_globs(pattern: str):
    with pytest.raises(ValidationError, match="invalid glob"):
        bundle(allowed_tenants=[pattern])


@pytest.mark.parametrize("value", ["../escape", "tenant/../escape", "tenant//project"])
def test_request_rejects_unsafe_path_segments(value: str):
    with pytest.raises(ValidationError, match="tenant_id"):
        request(tenant_id=value)


def test_loaders_accept_valid_yaml(tmp_path: Path):
    request_path = tmp_path / "request.yaml"
    policy_path = tmp_path / "policy.yaml"
    request_path.write_text(yaml.safe_dump(request_data()), encoding="utf-8")
    policy_path.write_text(yaml.safe_dump(bundle_data()), encoding="utf-8")

    loaded_request = load_evaluation_request(request_path)
    loaded_bundle = load_governance_bundle(policy_path)

    assert loaded_request.request_id == UUID(request_data()["request_id"])
    assert loaded_bundle.policy_id == "prod-evaluation"


def test_checked_in_governance_examples_load_and_bind_current_task_recipe():
    governance_bundle = load_governance_bundle(
        REPO_ROOT / "examples" / "governance" / "policy.yaml"
    )
    evaluation_request = load_evaluation_request(
        REPO_ROOT / "examples" / "governance" / "request.yaml"
    )
    task = load_task("example-todo-api")
    tree_digest, execution_digest = runner._governance_task_evidence(
        task,
        run_scans=True,
        run_judge=True,
    )
    entry = governance_bundle.task_registry.tasks[0]

    assert evaluation_request.task_id == task.id == entry.task_id
    assert entry.task_tree_sha256 == tree_digest
    assert entry.execution_spec_digests == [execution_digest]


def test_loader_normalizes_strict_legacy_v1_request_limits(tmp_path: Path):
    legacy = request_data()
    legacy["schema_version"] = "agent-eval.request/v1"
    legacy["max_total_tokens"] = legacy.pop("max_observed_total_tokens")
    legacy["max_cost_usd"] = legacy.pop("max_observed_cost_usd")
    request_path = tmp_path / "legacy-request.yaml"
    request_path.write_text(yaml.safe_dump(legacy), encoding="utf-8")

    loaded = load_evaluation_request(request_path)

    assert loaded.schema_version == "agent-eval.request/v2"
    assert loaded.max_observed_total_tokens == 1_000
    assert loaded.max_observed_cost_usd == 0.5
    with pytest.raises(ValidationError, match="schema_version"):
        EvaluationRequest.model_validate(legacy)


def test_policy_v1_requires_explicit_security_migration(tmp_path: Path):
    legacy = bundle_data()
    legacy["schema_version"] = "agent-eval.policy/v1"
    policy_path = tmp_path / "legacy-policy.yaml"
    policy_path.write_text(yaml.safe_dump(legacy), encoding="utf-8")

    with pytest.raises(ValueError, match="cannot be normalized safely"):
        load_governance_bundle(policy_path)


@pytest.mark.parametrize("loader", [load_evaluation_request, load_governance_bundle])
def test_loaders_reject_duplicate_keys_at_any_depth(tmp_path: Path, loader):
    path = tmp_path / "duplicate.yaml"
    path.write_text("outer:\n  value: first\n  value: second\n", encoding="utf-8")

    with pytest.raises(DuplicateKeyError, match="duplicate YAML key 'value'"):
        loader(path)


@pytest.mark.parametrize("content", ["", "- item\n- item\n"])
def test_loaders_require_a_yaml_object(tmp_path: Path, content: str):
    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a YAML object"):
        load_evaluation_request(path)


def test_canonical_json_is_sorted_compact_utf8_and_stable():
    value = {"z": [3, 2], "a": "café", "nested": {"b": True}}

    encoded = canonical_json_bytes(value)

    assert encoded == b'{"a":"caf\xc3\xa9","nested":{"b":true},"z":[3,2]}'
    assert sha256_json(value) == sha256_json(
        {"nested": {"b": True}, "a": "café", "z": [3, 2]}
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_canonical_json_rejects_nonfinite_numbers_even_when_nested(value: float):
    with pytest.raises(ValueError, match="non-finite"):
        canonical_json_bytes({"nested": [value]})


def test_canonical_json_rejects_nonstring_keys_and_unsupported_values():
    with pytest.raises(ValueError, match="non-string key"):
        canonical_json_bytes({1: "value"})
    with pytest.raises(ValueError, match="unsupported type"):
        canonical_json_bytes({"value": object()})


def test_write_canonical_json_atomically_replaces_with_mode_0600(tmp_path: Path):
    output = tmp_path / "evidence" / "decision.json"
    output.parent.mkdir()
    output.write_text("old", encoding="utf-8")
    os.chmod(output, 0o644)

    write_canonical_json(output, {"z": 2, "a": 1})

    assert output.read_bytes() == b'{"a":1,"z":2}'
    assert output.stat().st_mode & 0o777 == 0o600
    assert not list(output.parent.glob(f".{output.name}.*"))
