"""Independent re-verification of a recorded run.

Verification recomputes the evidence for a finished run rather than trusting
what was written: the attestation subjects, the audit chain and its lifecycle
meaning, the governance decisions replayed from the persisted policy bundle,
the normalized assessments, and the outcome. It reports every mismatch it finds
instead of stopping at the first, so an operator sees the whole picture in one
pass.

This module owns the checks. The CLI only renders the report it returns.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .assessments import derive_assessments
from .attestation import VerificationResult, verify_attestation
from .audit import verify_audit_chain
from .governance import (
    EvaluationRequest,
    GovernanceBundle,
    GovernanceEvidence,
    LegacyGovernanceEvidenceV1,
    PolicyDecision,
    evaluate_admission,
    sha256_json,
    validate_execution_continuity,
)
from .metrics import RunRecord, load_run
from .outcome import evaluate_outcome
from .runner import _governed_scanner_assurance_error
from .task import Task, load_task

VerificationStatus = Literal["verified", "failed", "missing"]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The complete result of re-verifying one run."""

    run_id: str
    status: VerificationStatus
    failures: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    subjects_checked: int = 0

    @property
    def ok(self) -> bool:
        return self.status == "verified"

    @classmethod
    def failed(cls, run_id: str, *failures: str) -> VerificationReport:
        return cls(run_id=run_id, status="failed", failures=tuple(failures))


def audit_lifecycle_failures(record: RunRecord, audit_path: Path) -> list[str]:
    """Check lifecycle meaning after byte-level chain verification succeeds."""

    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    event_types = [event["event_type"] for event in events]
    failures = []

    def single_attributes(event_type: str) -> dict[str, Any] | None:
        matching = [event for event in events if event["event_type"] == event_type]
        return matching[0]["attributes"] if len(matching) == 1 else None

    required = [
        "evaluation.requested",
        "policy.admitted",
        "agent.started",
        "agent.completed",
        "cleanup.completed",
        "outcome.decided",
        "run.completed",
    ]
    if event_types[:3] != required[:3]:
        failures.append(
            "audit must start with evaluation.requested, policy.admitted, "
            "then agent.started"
        )
    positions = []
    for event_type in required:
        if event_types.count(event_type) != 1:
            failures.append(f"audit requires exactly one {event_type} event")
        else:
            positions.append(event_types.index(event_type))
    if len(positions) == len(required) and positions != sorted(positions):
        failures.append("audit lifecycle events are out of order")
    if event_types[-2:] != ["outcome.decided", "run.completed"]:
        failures.append("audit must end with outcome.decided then run.completed")
    if "evaluation.started" in event_types:
        evaluation_stages = [
            "evaluation.started",
            "tests.completed",
            "scanners.completed",
        ]
        if "evaluation.failed" in event_types:
            if event_types.count("evaluation.failed") != 1:
                failures.append("failed evaluation requires one evaluation.failed")
            elif not (
                event_types.index("evaluation.started")
                < event_types.index("evaluation.failed")
                < event_types.index("outcome.decided")
            ):
                failures.append("evaluation.failed is out of order")
        else:
            for stage in evaluation_stages:
                if event_types.count(stage) != 1:
                    failures.append(f"evaluated audit requires exactly one {stage}")
            judge_count = event_types.count("judge.completed") + event_types.count(
                "judge.skipped"
            )
            if judge_count != 1:
                failures.append("evaluated audit requires exactly one judge result")
            elif all(
                event_types.count(stage) == 1
                for stage in [
                    "cleanup.completed",
                    *evaluation_stages,
                    "outcome.decided",
                ]
            ):
                judge_type = (
                    "judge.completed"
                    if "judge.completed" in event_types
                    else "judge.skipped"
                )
                stage_positions = [
                    event_types.index("cleanup.completed"),
                    *(event_types.index(stage) for stage in evaluation_stages),
                    event_types.index(judge_type),
                    event_types.index("outcome.decided"),
                ]
                if stage_positions != sorted(stage_positions):
                    failures.append("evaluation lifecycle events are out of order")

    agent_started = single_attributes("agent.started")
    if agent_started is not None:
        expected_started = {
            "agent": record.agent,
            "model": record.efficiency.requested_model,
            "trial": record.trial,
        }
        if any(
            agent_started.get(key) != value for key, value in expected_started.items()
        ):
            failures.append("agent.started does not match results.json")

    agent_completed = single_attributes("agent.completed")
    if agent_completed is not None:
        total_tokens = None
        if (
            record.efficiency.tokens_in is not None
            and record.efficiency.tokens_out is not None
        ):
            total_tokens = record.efficiency.tokens_in + record.efficiency.tokens_out
        expected_agent = {
            "exit_code": record.efficiency.agent_exit_code,
            "timed_out": record.efficiency.timed_out,
            "snapshot_available": "evaluation.started" in event_types,
            "wall_time_s": record.efficiency.wall_time_s,
            "total_tokens": total_tokens,
        }
        metric_keys_present = set(expected_agent) & set(agent_completed)
        if metric_keys_present and any(
            agent_completed.get(key) != expected_agent[key]
            for key in metric_keys_present
        ):
            failures.append("agent.completed metrics do not match results.json")
        if (
            agent_completed.get("status") == "infrastructure_error"
            and record.efficiency.infra_error is None
        ):
            failures.append("agent.completed status does not match results.json")

    cleanup_completed = single_attributes("cleanup.completed")
    if (
        cleanup_completed is not None
        and cleanup_completed.get("status") == "failed"
        and record.efficiency.infra_error is None
    ):
        failures.append("cleanup.completed status does not match results.json")

    evaluation_started = single_attributes("evaluation.started")
    if evaluation_started is not None and evaluation_started != {
        "task_id": record.task_id,
        "trial": record.trial,
    }:
        failures.append("evaluation.started does not match results.json")

    tests_completed = single_attributes("tests.completed")
    if tests_completed is not None:
        if tests_completed.get("status") == "integrity_rejected":
            if (
                record.correctness.integrity_error is None
                or record.correctness.resolved
            ):
                failures.append("tests.completed does not match results.json")
        else:
            expected_tests = {
                "status": (
                    "infrastructure_error"
                    if record.correctness.infra_error
                    else "completed"
                ),
                "resolved": record.correctness.resolved,
                "passed": record.correctness.passed,
                "total": record.correctness.total,
                "command_exit_code": record.correctness.command_exit_code,
            }
            if tests_completed != expected_tests:
                failures.append("tests.completed does not match results.json")

    scanners_completed = single_attributes("scanners.completed")
    if (
        scanners_completed is not None
        and scanners_completed.get("status") == "completed"
        and scanners_completed
        != {
            "status": "completed",
            "finding_count": len(record.scans.findings),
            "scanner_count": len(record.scans.scanner_status),
        }
    ):
        failures.append("scanners.completed does not match results.json")

    judge_completed = single_attributes("judge.completed")
    if judge_completed is not None and judge_completed != {
        "status": "completed",
        "score_available": record.judge.weighted_score is not None,
        "dimension_count": len(record.judge.scores),
        "backend": record.judge.backend,
        "model": record.judge.model,
    }:
        failures.append("judge.completed does not match results.json")

    expected_status = record.outcome.status if record.outcome else None
    for event_type in ("outcome.decided", "run.completed"):
        matching = [event for event in events if event["event_type"] == event_type]
        if (
            len(matching) == 1
            and matching[0]["attributes"].get("status") != expected_status
        ):
            failures.append(f"{event_type} status does not match results.json")
    outcome_decided = single_attributes("outcome.decided")
    if record.outcome is not None and outcome_decided is not None:
        expected_outcome_event = {
            "status": record.outcome.status,
            "check_count": len(record.outcome.checks),
            "reason_count": len(record.outcome.reasons),
        }
        count_keys_present = {
            "check_count",
            "reason_count",
        } & set(outcome_decided)
        if count_keys_present and any(
            outcome_decided.get(key) != expected_outcome_event[key]
            for key in count_keys_present
        ):
            failures.append("outcome.decided does not match results.json")
    governance = record.governance
    if governance is not None and len(events) >= 2:
        requested = events[0]["attributes"]
        expected_request = {
            "request_id": str(governance.request_id),
            "task_id": record.task_id,
            "agent": record.agent,
            "model": (
                governance.matched_model.model
                if governance.matched_model is not None
                else None
            ),
            "trial": record.trial,
            "run_scans": governance.run_scans,
            "run_judge": governance.run_judge,
            "judge_backend": governance.judge_backend,
            "judge_model": governance.judge_model,
            "task_tree_sha256": governance.task_tree_sha256,
            "execution_spec_digest": governance.execution_spec_digest,
            "task_image_digest": governance.task_image_digest,
            "task_image_ref": governance.task_image_ref,
            "task_image_platform": governance.task_image_platform,
        }
        if any(requested.get(key) != value for key, value in expected_request.items()):
            failures.append("evaluation.requested does not match results.json")
        scanner_events = [
            event for event in events if event["event_type"] == "scanners.completed"
        ]
        if len(scanner_events) == 1:
            scanners_skipped = (
                scanner_events[0]["attributes"].get("status") == "skipped"
            )
            if governance.run_scans == scanners_skipped:
                failures.append(
                    "scanner lifecycle does not match the admitted grader recipe"
                )
            if not scanners_skipped:
                from .runner import _governed_scanner_assurance_error

                scanner_error = _governed_scanner_assurance_error(
                    record, require_evidence=True
                )
                if scanner_error is not None:
                    failures.append(scanner_error)
        judge_events = [
            event
            for event in events
            if event["event_type"] in {"judge.completed", "judge.skipped"}
        ]
        if len(judge_events) == 1:
            judge_event = judge_events[0]
            if governance.run_judge and judge_event["event_type"] != "judge.completed":
                failures.append(
                    "admitted judge recipe requires a completed judge result"
                )
            elif governance.run_judge and (
                judge_event["attributes"].get("score_available") is not True
                or record.judge.weighted_score is None
            ):
                failures.append("completed admitted judge recipe has no score evidence")
            elif governance.run_judge and (
                judge_event["attributes"].get("backend") != governance.judge_backend
                or judge_event["attributes"].get("model") != governance.judge_model
                or record.judge.backend != governance.judge_backend
                or record.judge.model != governance.judge_model
            ):
                failures.append(
                    "completed judge identity does not match governance evidence"
                )
            elif not governance.run_judge and not (
                judge_event["event_type"] == "judge.skipped"
                and judge_event["attributes"].get("reason_code") == "disabled"
            ):
                failures.append(
                    "judge lifecycle does not match the admitted grader recipe"
                )
        admitted = events[1]["attributes"]
        expected_admission = {
            "decision_id": str(governance.decision_id),
            "request_digest": governance.request_digest,
            "policy_id": governance.policy_id,
            "policy_revision": governance.policy_revision,
            "policy_digest": governance.policy_digest,
            "registry_id": governance.registry_id,
            "registry_revision": governance.registry_revision,
            "registry_digest": governance.registry_digest,
        }
        if governance.schema_version == "agent-eval.governance-evidence/v2":
            expected_admission.update(
                {
                    "task_registry_id": governance.task_registry_id,
                    "task_registry_revision": governance.task_registry_revision,
                    "task_registry_digest": governance.task_registry_digest,
                }
            )
        if any(admitted.get(key) != value for key, value in expected_admission.items()):
            failures.append("policy.admitted does not match governance evidence")
    return failures


def _decision_replay_view(decision: PolicyDecision) -> dict[str, Any]:
    fields = {
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
    return decision.model_dump(mode="json", include=fields)


def _verified_subject_snapshot(
    verification,
    artifact_root: Path,
    name: str,
    failures: list[str],
) -> bytes | None:
    """Read one semantic artifact once and bind it to the verified statement."""

    from .attestation import read_regular_file

    expected = verification.subject_digests.get(name)
    if expected is None:
        failures.append(f"attestation has no valid subject digest for {name}")
        return None
    try:
        data = read_regular_file(artifact_root / name, label=name)
    except (OSError, ValueError) as exc:
        failures.append(f"{name} snapshot is unsafe or unreadable: {str(exc)[:1000]}")
        return None
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        failures.append(f"{name} changed after attestation verification")
        return None
    return data


def _governance_statement_failures(
    predicate: dict[str, Any],
    disk_record: RunRecord,
    *,
    predicate_tree: object,
    predicate_image_tag: object,
    predicate_digest: object,
) -> list[str]:
    """Check the governance section of the predicate against the record.

    Only governed runs carry this section; legacy runs are checked by the
    caller and skipped here.
    """

    failures: list[str] = []
    if disk_record.governance is not None:
        admitted_model = (
            disk_record.governance.matched_model.model
            if disk_record.governance.matched_model is not None
            else None
        )
        if (
            admitted_model is None
            or disk_record.efficiency.requested_model != admitted_model
        ):
            failures.append("requested coding model does not match governance evidence")
        model_observation_required = disk_record.efficiency.wall_time_s is not None or (
            disk_record.outcome is not None
            and disk_record.outcome.status != "infra_error"
        )
        if (
            model_observation_required
            and disk_record.efficiency.model != admitted_model
        ):
            failures.append("observed coding model does not match governance evidence")
        expected_image_digest = disk_record.governance.task_image_digest
        if f"sha256:{predicate_digest}" != expected_image_digest:
            failures.append("statement image digest does not match governance evidence")
        if predicate_image_tag != disk_record.governance.task_image_ref:
            failures.append(
                "statement image reference does not match governance evidence"
            )
        if predicate_tree != disk_record.governance.task_tree_sha256:
            failures.append("statement task tree does not match governance evidence")
        observed_image_digests = {
            "run provenance": disk_record.provenance.image_digest,
            "local image": disk_record.provenance.local_image_digest,
            "agent pod provenance": disk_record.provenance.agent_image_digest,
            "evaluator pod provenance": disk_record.provenance.eval_image_digest,
            "submission pod provenance": (
                disk_record.provenance.submission_image_digest
            ),
            "agent runtime": disk_record.efficiency.runtime_image_digest,
            "evaluator runtime": disk_record.correctness.runtime_image_digest,
            "submission runtime": (
                disk_record.correctness.submission_runtime_image_digest
            ),
        }
        for label, observed_digest in observed_image_digests.items():
            if observed_digest is not None and observed_digest != expected_image_digest:
                failures.append(f"{label} digest does not match governance evidence")
        if disk_record.efficiency.infra_error is None:
            for label in ("agent pod provenance", "agent runtime"):
                if observed_image_digests[label] is None:
                    failures.append(
                        f"completed agent phase is missing {label} digest evidence"
                    )
        evaluation_completed = (
            disk_record.correctness.infra_error is None
            and disk_record.correctness.integrity_error is None
            and (
                disk_record.correctness.command_exit_code is not None
                or disk_record.correctness.total > 0
            )
        )
        if evaluation_completed:
            for label in ("evaluator pod provenance", "evaluator runtime"):
                if observed_image_digests[label] is None:
                    failures.append(
                        f"completed evaluator phase is missing {label} digest evidence"
                    )
            if disk_record.correctness.evaluation_mode == "isolated-black-box":
                for label in (
                    "submission pod provenance",
                    "submission runtime",
                ):
                    if observed_image_digests[label] is None:
                        failures.append(
                            "completed evaluator phase is missing "
                            f"{label} digest evidence"
                        )
        if disk_record.correctness.evaluation_mode != "isolated-black-box":
            failures.append("governed correctness evidence is not isolated-black-box")
        scanner_error = _governed_scanner_assurance_error(
            disk_record,
            require_evidence=(
                disk_record.outcome is None
                or disk_record.outcome.status != "infra_error"
            ),
        )
        if scanner_error is not None:
            failures.append(scanner_error)
    return failures


def _statement_failures(
    result: VerificationResult, disk_record: RunRecord
) -> list[str]:
    """Check the verified in-toto predicate against the persisted record.

    The predicate is untrusted input: every field is shape-checked before it
    is compared, and a mismatch is recorded rather than raised so one pass
    reports every discrepancy.
    """

    failures: list[str] = []
    predicate = result.predicate or {}
    if result.predicate is None:
        failures.append(
            "statement_semantics_invalid: verified predicate is unavailable"
        )
    expected_outcome = (
        disk_record.outcome.model_dump(mode="json") if disk_record.outcome else {}
    )
    expected_governance = (
        disk_record.governance.model_dump(mode="json") if disk_record.governance else {}
    )
    if predicate.get("outcome", {}) != expected_outcome:
        failures.append("statement outcome does not match results.json")
    if predicate.get("governance", {}) != expected_governance:
        failures.append("statement governance does not match results.json")
    predicate_task = predicate.get("task", {})
    predicate_tree = (
        predicate_task.get("tree", {}).get("digest", {}).get("sha256")
        if isinstance(predicate_task, dict)
        and isinstance(predicate_task.get("tree"), dict)
        and isinstance(predicate_task.get("tree", {}).get("digest"), dict)
        else None
    )
    if (
        not isinstance(predicate_task, dict)
        or predicate_task.get("id") != disk_record.task_id
    ):
        failures.append("statement task identity does not match results.json")
    if predicate_tree != disk_record.provenance.task_tree_sha256:
        failures.append("statement task tree does not match results.json provenance")
    predicate_harness = predicate.get("harness", {})
    predicate_git = (
        predicate_harness.get("git", {})
        if isinstance(predicate_harness, dict)
        and isinstance(predicate_harness.get("git"), dict)
        else {}
    )
    expected_git = {
        "sha": disk_record.provenance.harness_commit,
        "dirty": disk_record.provenance.harness_dirty,
        "worktree_sha256": disk_record.provenance.harness_worktree_sha256,
    }
    if predicate_git != expected_git:
        failures.append("statement harness Git state does not match results.json")
    expected_models = {
        "agent": disk_record.efficiency.model,
        "agent-requested": disk_record.efficiency.requested_model,
        "judge": disk_record.judge.model,
    }
    if predicate.get("models") != expected_models:
        failures.append("statement models do not match results.json")
    if predicate.get("tools") != disk_record.provenance.tool_versions:
        failures.append("statement tools do not match results.json")
    predicate_image = predicate.get("image", {})
    predicate_image_tag = (
        predicate_image.get("tag") if isinstance(predicate_image, dict) else None
    )
    predicate_digest = (
        predicate_image.get("digest", {}).get("sha256")
        if isinstance(predicate_image, dict)
        and isinstance(predicate_image.get("digest"), dict)
        else None
    )
    if predicate_image_tag != disk_record.provenance.image_tag:
        failures.append("statement image reference does not match results.json")
    if f"sha256:{predicate_digest}" != disk_record.provenance.image_digest:
        failures.append("statement image digest does not match results.json")
    failures.extend(
        _governance_statement_failures(
            predicate,
            disk_record,
            predicate_tree=predicate_tree,
            predicate_image_tag=predicate_image_tag,
            predicate_digest=predicate_digest,
        )
    )
    return failures


def _audit_and_governance_failures(
    disk_record: RunRecord,
    result: VerificationResult,
    verified_task: Task,
    *,
    audit_fields: tuple[object, ...],
    has_audit_evidence: bool,
) -> tuple[list[str], list[str], Task]:
    """Re-verify the audit chain and replay the governance decisions.

    Returns the failures, any operator notes, and the task as governance
    actually constrained it, which later recomputation must use instead of
    the task as it exists on disk today.
    """

    failures: list[str] = []
    notes: list[str] = []
    effective_task = verified_task
    if disk_record.governance is not None or has_audit_evidence:
        if disk_record.provenance.audit_error:
            failures.append(
                f"recorded audit error: {disk_record.provenance.audit_error}"
            )
        if any(value is None for value in audit_fields):
            failures.append("governed audit evidence is incomplete")
        audit_data = _verified_subject_snapshot(
            result, disk_record.run_dir, "audit.jsonl", failures
        )
        audit_snapshot = None
        audit_result = None
        if audit_data is not None:
            audit_snapshot = tempfile.NamedTemporaryFile(
                prefix="agent-eval-audit-snapshot-", suffix=".jsonl"
            )
            audit_snapshot.write(audit_data)
            audit_snapshot.flush()
            audit_path = Path(audit_snapshot.name)
            audit_result = verify_audit_chain(
                audit_path,
                expected_final_hash=disk_record.provenance.audit_final_hash,
                expected_run_id=disk_record.run_id,
            )
            failures.extend(
                f"{failure.code}: {failure.message}"
                for failure in audit_result.failures
            )
        if audit_result is not None and audit_result.ok:
            if audit_result.trace_id != disk_record.provenance.audit_trace_id:
                failures.append("audit trace ID does not match results.json")
            if (
                disk_record.governance is not None
                and audit_result.trace_id != disk_record.governance.trace_id
            ):
                failures.append("audit trace ID does not match governance decision")
            if audit_result.event_count != disk_record.provenance.audit_event_count:
                failures.append("audit event count does not match results.json")
            try:
                failures.extend(audit_lifecycle_failures(disk_record, audit_path))
            except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
                failures.append(f"audit lifecycle is unreadable: {str(exc)[:1000]}")
        if isinstance(disk_record.governance, LegacyGovernanceEvidenceV1):
            failures.append(
                "legacy governance evidence v1 is readable but does not bind "
                "an approved task-registry entry"
            )
        elif disk_record.governance is not None:
            if (
                not disk_record.governance.allowed
                or disk_record.governance.reason_codes != ["admitted"]
            ):
                failures.append("governed run does not contain an admitted decision")
            try:
                semantic_names = (
                    "governance-request.json",
                    "policy-bundle.json",
                    "preflight-decision.json",
                    "policy-decision.json",
                )
                snapshots: dict[str, bytes] = {}
                for name in semantic_names:
                    snapshot = _verified_subject_snapshot(
                        result, disk_record.run_dir, name, failures
                    )
                    if snapshot is None:
                        raise ValueError("governance artifact snapshot is unverified")
                    snapshots[name] = snapshot
                request = EvaluationRequest.model_validate_json(
                    snapshots["governance-request.json"]
                )
                bundle = GovernanceBundle.model_validate_json(
                    snapshots["policy-bundle.json"]
                )
                preflight_decision = PolicyDecision.model_validate_json(
                    snapshots["preflight-decision.json"]
                )
                decision = PolicyDecision.model_validate_json(
                    snapshots["policy-decision.json"]
                )
                try:
                    validate_execution_continuity(preflight_decision, decision)
                except ValueError as exc:
                    failures.append(str(exc))
                preflight_trials = preflight_decision.sanitized_input.get("trials")
                execution_trials = decision.sanitized_input.get("trials")
                if (
                    isinstance(preflight_trials, bool)
                    or not isinstance(preflight_trials, int)
                    or isinstance(execution_trials, bool)
                    or not isinstance(execution_trials, int)
                ):
                    # Replaying admission needs an integer trial scope; without
                    # one there is nothing to check the recorded trial against.
                    failures.append("run trial is not covered by both decisions")
                    raise ValueError("decisions do not record an integer trial count")
                if (
                    disk_record.trial > preflight_trials
                    or disk_record.trial > execution_trials
                ):
                    failures.append("run trial is not covered by both decisions")
                preflight_broker = preflight_decision.sanitized_input.get(
                    "broker_configured"
                )
                execution_broker = decision.sanitized_input.get("broker_configured")
                if not isinstance(preflight_broker, bool) or not isinstance(
                    execution_broker, bool
                ):
                    raise ValueError("decisions do not record broker configuration")
                evidence = GovernanceEvidence.from_decision(request, decision)
                if evidence != disk_record.governance:
                    failures.append(
                        "governance request and decision do not match results.json"
                    )
                from .runner import (
                    _governance_judge_evidence,
                    _governance_network_evidence,
                    _governance_task_evidence,
                    _governed_task,
                )

                domains, proxy_image = _governance_network_evidence(
                    verified_task, disk_record.agent
                )
                task_tree_digest, execution_spec_digest = _governance_task_evidence(
                    verified_task,
                    run_scans=disk_record.governance.run_scans,
                    run_judge=disk_record.governance.run_judge,
                )
                judge_backend, judge_model = _governance_judge_evidence(
                    verified_task, run_judge=disk_record.governance.run_judge
                )
                replayed_preflight = evaluate_admission(
                    request,
                    bundle,
                    actual_task_id=verified_task.id,
                    actual_agent=disk_record.agent,
                    actual_model=request.model,
                    trials=preflight_trials,
                    network_mode=verified_task.network.agent_mode,
                    agent_timeout_seconds=verified_task.timeouts.agent_seconds,
                    eval_timeout_seconds=verified_task.timeouts.eval_seconds,
                    broker_configured=preflight_broker,
                    run_scans=disk_record.governance.run_scans,
                    scanner_identity_sha256=(
                        disk_record.governance.scanner_identity_sha256
                    ),
                    scanner_promotion_ready=(
                        disk_record.governance.scanner_promotion_ready
                    ),
                    run_judge=disk_record.governance.run_judge,
                    judge_backend=judge_backend,
                    judge_model=judge_model,
                    task_tree_sha256=task_tree_digest,
                    execution_spec_digest=execution_spec_digest,
                    effective_egress_domains=domains,
                    proxy_image=proxy_image,
                )
                if _decision_replay_view(replayed_preflight) != _decision_replay_view(
                    preflight_decision
                ):
                    failures.append(
                        "preflight decision does not replay from policy-bundle.json"
                    )
                replayed = evaluate_admission(
                    request,
                    bundle,
                    actual_task_id=verified_task.id,
                    actual_agent=disk_record.agent,
                    actual_model=request.model,
                    trials=execution_trials,
                    network_mode=verified_task.network.agent_mode,
                    agent_timeout_seconds=verified_task.timeouts.agent_seconds,
                    eval_timeout_seconds=verified_task.timeouts.eval_seconds,
                    broker_configured=execution_broker,
                    run_scans=disk_record.governance.run_scans,
                    scanner_identity_sha256=(
                        disk_record.governance.scanner_identity_sha256
                    ),
                    scanner_promotion_ready=(
                        disk_record.governance.scanner_promotion_ready
                    ),
                    run_judge=disk_record.governance.run_judge,
                    judge_backend=judge_backend,
                    judge_model=judge_model,
                    task_tree_sha256=task_tree_digest,
                    execution_spec_digest=execution_spec_digest,
                    decision_stage="execution",
                    task_image_digest=disk_record.governance.task_image_digest,
                    task_image_ref=disk_record.governance.task_image_ref,
                    task_image_platform=disk_record.governance.task_image_platform,
                    preflight_decision_id=preflight_decision.decision_id,
                    preflight_decision_digest=sha256_json(preflight_decision),
                    effective_egress_domains=domains,
                    proxy_image=proxy_image,
                )
                if _decision_replay_view(replayed) != _decision_replay_view(decision):
                    failures.append(
                        "governance decision does not replay from policy-bundle.json"
                    )
                effective_task = _governed_task(verified_task, replayed)
            except (OSError, UnicodeError, ValueError) as exc:
                failures.append(f"governance artifacts invalid: {str(exc)[:1000]}")
    else:
        notes.append("legacy run: no governed lifecycle audit was recorded")
    return failures, notes, effective_task


def verify_run(run_id: str) -> VerificationReport:
    """Recompute attestation, audit, and governance evidence for one run.

    Pure with respect to the terminal: every outcome is returned so callers
    other than the CLI can act on the individual failures.
    """

    notes: list[str] = []

    try:
        record = load_run(
            run_id,
            forbid_extra=True,
            validate_assessments=True,
        )
    except ValueError as exc:
        return VerificationReport.failed(
            run_id, f"persisted run schema is invalid: {str(exc)[:1000]}"
        )
    if record is None:
        return VerificationReport(run_id=run_id, status="missing")
    statement = record.run_dir / "attestation.json"
    if not statement.is_file():
        return VerificationReport.failed(run_id, f"run {run_id} has no attestation")
    verified_task = load_task(record.task_id)
    effective_task = verified_task
    result = verify_attestation(
        statement,
        artifact_root=record.run_dir,
        task_root=verified_task.path,
        harness_repo=Path(__file__).resolve().parents[2],
    )
    failures = [f"{failure.code}: {failure.message}" for failure in result.failures]
    results_data = _verified_subject_snapshot(
        result, record.run_dir, "results.json", failures
    )
    if results_data is None:
        return VerificationReport.failed(run_id, *failures)
    try:
        disk_record = RunRecord.model_validate_json(results_data, extra="forbid")
    except (UnicodeError, ValueError) as exc:
        failures.append(f"results_invalid: {str(exc)[:1000]}")
        return VerificationReport.failed(run_id, *failures)
    if disk_record.model_dump(mode="json") != record.model_dump(mode="json"):
        failures.append("results_mismatch: SQLite and results.json differ")
    failures.extend(_statement_failures(result, disk_record))

    audit_fields = (
        disk_record.provenance.audit_trace_id,
        disk_record.provenance.audit_final_hash,
        disk_record.provenance.audit_event_count,
    )
    has_audit_evidence = any(value is not None for value in audit_fields)
    if disk_record.provenance.attestation_error:
        failures.append(
            f"recorded attestation error: {disk_record.provenance.attestation_error}"
        )
    audit_failures, audit_notes, effective_task = _audit_and_governance_failures(
        disk_record,
        result,
        verified_task,
        audit_fields=audit_fields,
        has_audit_evidence=has_audit_evidence,
    )
    failures.extend(audit_failures)
    notes.extend(audit_notes)

    recomputed_assessments = derive_assessments(disk_record, effective_task)
    if [
        assessment.model_dump(mode="json") for assessment in disk_record.assessments
    ] != [assessment.model_dump(mode="json") for assessment in recomputed_assessments]:
        failures.append(
            "normalized assessment envelope does not recompute from run evidence"
        )

    recomputed_outcome = evaluate_outcome(disk_record, effective_task.acceptance)
    if disk_record.outcome is None or (
        disk_record.outcome.model_dump(mode="json")
        != recomputed_outcome.model_dump(mode="json")
    ):
        failures.append("recorded outcome does not recompute from run evidence")

    return VerificationReport(
        run_id=run_id,
        status="failed" if failures else "verified",
        failures=tuple(failures),
        notes=tuple(notes),
        subjects_checked=result.subjects_checked,
    )
