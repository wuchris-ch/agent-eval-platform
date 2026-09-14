import copy
import os
import uuid
from pathlib import Path

import pytest

from agent_eval.blackbox.models import digest
from agent_eval.candidates import authority, boundary, execution
from agent_eval.candidates.bundles import compare_policy, export_bundle, verify_bundle
from agent_eval.candidates.contracts import ProductionFailure, Recipe, Usage
from agent_eval.candidates.studies import (
    StudyPlan,
    StudyTask,
    reserve_study,
    study_report,
    summarize_rows,
)
from agent_eval.workbench.store import Conflict
from test_candidate_contract import fake_observation, prepare


def study(tmp_path, monkeypatch, *, assisted=0):
    store, ticket, contract, submission, suite = prepare(tmp_path, monkeypatch)
    recipe = Recipe.model_validate(
        store.get("local", "candidate-recipe", ticket.recipe_sha256)
    )
    alternate = recipe.model_copy(
        update={"name": "second policy", "producer_sha256": "a" * 64}
    )
    alt_sha = store.put("local", "candidate-recipe", alternate.model_dump(mode="json"))
    plan = StudyPlan(
        cohort_id=str(uuid.uuid4()),
        name="Paired study",
        baseline_recipe_sha256=alt_sha,
        candidate_recipe_sha256=ticket.recipe_sha256,
        tasks=[
            StudyTask(
                base_revision=ticket.base_revision,
                suite_sha256=ticket.suite_sha256,
                policy_sha256=ticket.policy_sha256,
            )
        ],
        trials=2,
        seed=17,
        max_model_requests=0,
        max_total_tokens=0,
        evaluator_sha256=authority.identity(),
        max_assisted_executions=assisted,
    )
    schedule = reserve_study(store, "local", plan, "operator")
    return store, plan, schedule, ticket, contract, submission, suite


def test_reservation_is_complete_deterministic_and_immutable(tmp_path, monkeypatch):
    store, plan, schedule, *_ = study(tmp_path, monkeypatch)
    assert len(set(schedule["schedule"])) == schedule["planned_initial"] == 4
    assert reserve_study(store, "local", plan, "operator") == schedule
    assert len(study_report(store, "local", plan.cohort_id)["rows"]) == 4
    with pytest.raises(Conflict):
        reserve_study(store, "local", plan.model_copy(update={"seed": 18}), "operator")


def test_missing_runs_keep_denominator_and_suppress_interval(tmp_path, monkeypatch):
    store, plan, schedule, *_ = study(tmp_path, monkeypatch)
    ticket = store.get("local", "trial-ticket-v2", schedule["schedule"][0])
    failure = ProductionFailure(
        execution_id=ticket["execution_id"],
        trial_ticket_sha256=digest(ticket),
        reason="timeout",
    )
    authority.record_failure(store, "local", failure, "producer")
    assert (
        authority.record_failure(store, "local", failure, "producer")
        == ticket["execution_id"]
    )
    report = study_report(store, "local", plan.cohort_id)
    assert len(report["rows"]) == 4
    assert sum(c["planned"] for c in report["summary"]["counts"].values()) == 4
    assert sum(c["pending"] for c in report["summary"]["counts"].values()) == 3
    assert (
        sum(c["production_failed"] for c in report["summary"]["counts"].values()) == 1
    )
    assert report["summary"]["interval"] is None
    assert report["summary"]["missing_pairs"] == 2
    for c in report["summary"]["counts"].values():
        assert c["metrics"]["total_tokens"]["total"] is None
    assert verify_bundle(export_bundle(store, "local", plan.cohort_id))["rows"] == 4


def test_unmatched_capabilities_cannot_enter_paired_study(tmp_path, monkeypatch):
    store, plan, *_ = study(tmp_path, monkeypatch)
    recipe = store.get("local", "candidate-recipe", plan.candidate_recipe_sha256)
    sha = store.put(
        "local", "candidate-recipe", {**recipe, "capability_sha256": "b" * 64}
    )
    changed = plan.model_copy(
        update={"cohort_id": str(uuid.uuid4()), "candidate_recipe_sha256": sha}
    )
    with pytest.raises(ValueError, match="unmatched study"):
        reserve_study(store, "local", changed, "operator")
    with pytest.raises(KeyError):
        store.get("local", "candidate-study", changed.cohort_id)


def completed_study(tmp_path, monkeypatch, *, assisted=0, passed=True):
    store, plan, schedule, old, old_contract, old_submission, suite = study(
        tmp_path, monkeypatch, assisted=assisted
    )
    monkeypatch.setattr(
        boundary, "execute", lambda *_: fake_observation(suite, passed=passed)
    )
    monkeypatch.setattr(boundary, "cleanup", lambda *_: None)
    for key in schedule["schedule"]:
        ticket = store.get("local", "trial-ticket-v2", key)
        contract = old_contract.model_copy(
            update={
                "execution_id": key,
                "trial_ticket_sha256": digest(ticket),
                "trial_identity": old.trial_identity.model_validate(
                    ticket["trial_identity"]
                ),
                "recipe_sha256": ticket["recipe_sha256"],
            }
        )
        authority.issue(store, "local", contract, "operator")
        submission = old_submission.model_copy(
            update={
                "execution_id": key,
                "trial_ticket_sha256": digest(ticket),
                "recipe_sha256": ticket["recipe_sha256"],
                "execution_contract_sha256": digest(contract.model_dump(mode="json")),
            }
        )
        authority.ingest(store, "local", submission, "producer")
        assert execution.evaluate(store, "local", key)["outcome"] == (
            "pass" if passed else "fail"
        )
    return store, plan, schedule


def test_portable_export_replays_and_rejects_resigned_stale_binding(
    tmp_path, monkeypatch
):
    store, plan, schedule = completed_study(tmp_path, monkeypatch)
    bundle = export_bundle(store, "local", plan.cohort_id)
    assert verify_bundle(bundle)["model_calls"] == 0
    assert bundle["report"]["summary"]["counts"]["candidate"]["accepted"] == 2
    forged = copy.deepcopy(bundle)
    key = "assessment-v2/" + schedule["schedule"][0]
    forged["records"][key]["candidate_tree_sha256"] = "f" * 64
    forged["record_sha256"][key] = digest(forged["records"][key])
    forged["bundle_sha256"] = digest(
        {k: v for k, v in forged.items() if k != "bundle_sha256"}
    )
    with pytest.raises(ValueError, match="stale or incompatible"):
        verify_bundle(forged)
    preview = compare_policy(bundle, max_total_tokens=2000)
    assert all(r["preview_outcome"] == "inconclusive" for r in preview["rows"])
    assert all(r["recorded_outcome"] == "pass" for r in preview["rows"])
    assert export_bundle(store, "local", plan.cohort_id) == bundle


def test_terminal_failure_cannot_be_replaced_by_candidate(tmp_path, monkeypatch):
    store, plan, schedule, _, old_contract, _, _ = study(tmp_path, monkeypatch)
    key = schedule["schedule"][0]
    ticket = store.get("local", "trial-ticket-v2", key)
    authority.record_failure(
        store,
        "local",
        {
            "execution_id": key,
            "trial_ticket_sha256": digest(ticket),
            "reason": "producer_error",
        },
        "producer",
    )
    contract = old_contract.model_copy(
        update={
            "execution_id": key,
            "trial_ticket_sha256": digest(ticket),
            "trial_identity": old_contract.trial_identity.model_validate(
                ticket["trial_identity"]
            ),
            "recipe_sha256": ticket["recipe_sha256"],
        }
    )
    with pytest.raises(ValueError, match="failure already sealed"):
        authority.issue(store, "local", contract, "operator")


def test_usage_claims_cannot_create_independent_measurements(tmp_path, monkeypatch):
    store, _, schedule, *_ = study(tmp_path, monkeypatch)
    key = schedule["schedule"][0]
    ticket = store.get("local", "trial-ticket-v2", key)
    with pytest.raises(ValueError, match="producer cannot claim"):
        authority.record_failure(
            store,
            "local",
            {
                "execution_id": key,
                "trial_ticket_sha256": digest(ticket),
                "reason": "timeout",
                "usage": {"provenance": "independently_observed", "total_tokens": 1},
            },
            "producer",
        )
    with pytest.raises(ValueError, match="unavailable usage"):
        Usage(total_tokens=0)


@pytest.mark.parametrize("kind", ["missing", "malformed", "symlink", "fifo"])
def test_untrusted_sqlite_state_is_bounded_failed_evidence(tmp_path, kind):
    from agent_eval.candidates.oracles import BehaviorSuite

    root = tmp_path.resolve()
    (root / "state").mkdir()
    path = root / "state/state.sqlite"
    if kind == "malformed":
        path.write_bytes(b"not a SQLite database")
    elif kind == "symlink":
        path.symlink_to(Path(__file__))
    elif kind == "fifo":
        os.mkfifo(path)
    suite = BehaviorSuite.model_validate_json(
        (Path(__file__).parent / "fixtures/candidates/order-oracle.json").read_bytes()
    )
    assert all(v is None for v in boundary.collect_state(root, suite).values())


def test_family_bootstrap_does_not_count_trials_as_independent_families():
    rows = []
    for family in ("a", "b"):
        for trial in range(1, 4):
            for arm in ("baseline", "candidate"):
                rows.append(
                    {
                        "arm": arm,
                        "outcome": "pass" if arm == "candidate" else "fail",
                        "task_id": family,
                        "trial": trial,
                        "family": family,
                        "suite_sha256": family,
                        "base_revision": "base",
                        "policy_sha256": "policy",
                        "evaluator_sha256": "evaluator",
                        "usage": {},
                    }
                )
    result = summarize_rows(rows)
    assert result["paired_families"] == 2
    assert result["effect"] == 1.0
    assert result["promotion_status"] == "inconclusive"
    assert result["counts"]["candidate"]["planned"] == 6


def test_study_correction_uses_separate_cap_and_frozen_failure_selection(
    tmp_path, monkeypatch
):
    from agent_eval.candidates.contracts import TrialTicket

    store, plan, schedule = completed_study(
        tmp_path, monkeypatch, assisted=2, passed=False
    )
    for index, key in enumerate(schedule["schedule"]):
        parent = TrialTicket.model_validate(store.get("local", "trial-ticket-v2", key))
        ticket = parent.model_copy(
            update={
                "execution_id": str(uuid.uuid4()),
                "trial_identity": parent.trial_identity.model_copy(
                    update={
                        "attempt_kind": "assisted_correction",
                        "parent_execution_id": key,
                    }
                ),
            }
        )
        if index < 2:
            authority.reserve(store, "local", ticket, "operator")
        else:
            with pytest.raises(ValueError, match="predeclared failure selection"):
                authority.reserve(store, "local", ticket, "operator")
    report = study_report(store, "local", plan.cohort_id)
    assert len(report["rows"]) == 6
    assert report["repairs"]["planned"] == 2
    assert report["summary"]["counts"]["candidate"]["planned"] == 2
    assert report["summary"]["counts"]["baseline"]["planned"] == 2


def test_browser_policy_preview_matches_python(tmp_path):
    import subprocess

    from agent_eval.candidates.contracts import AcceptancePolicy, Check
    from agent_eval.candidates.execution import policy_decision

    root = Path(__file__).resolve().parents[1]
    cases = []
    for passed in (True, False):
        for provenance in (
            "producer_reported",
            "independently_observed",
            "unavailable",
        ):
            for complete in (True, False):
                for field, limit in [
                    ("latency_ms", 500),
                    ("total_tokens", 500),
                    ("cost_usd", 0),
                ]:
                    usage = Usage(
                        provenance=provenance,
                        latency_ms=1000 if provenance != "unavailable" else None,
                    )
                    policy = AcceptancePolicy(
                        name="preview",
                        required_checks=["behavior"],
                        **{"max_" + field: limit},
                    )
                    check = Check(id="behavior", passed=passed, reason="fixture")
                    outcome, _ = policy_decision(
                        [check], policy, usage, completed=complete
                    )
                    cases.append(
                        {
                            "row": {
                                "assessment_sha256": "a" * 64,
                                "checks": [check.model_dump()],
                                "usage": usage.model_dump(),
                                "producer_completed": complete,
                            },
                            "limits": {field: limit},
                            "expected": outcome,
                        }
                    )
    import json
    import shutil

    if shutil.which("node") is None:
        pytest.skip("Node is required for browser policy parity")
    program = "import {previewDecision} from './docs/evidence-logic.mjs'; import {readFileSync} from 'node:fs'; const cases=JSON.parse(readFileSync(0,'utf8')); for(const item of cases) if(previewDecision(item.row,item.limits)!==item.expected)throw Error('policy mismatch'); console.log(cases.length);"
    result = subprocess.run(
        ["node", "--input-type=module", "-e", program],
        input=json.dumps(cases),
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )
    assert int(result.stdout) == 36
