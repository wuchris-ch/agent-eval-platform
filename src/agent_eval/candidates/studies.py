"""Predeclared paired studies, complete denominators and separate repair cohorts."""

from __future__ import annotations

import math
import random
import uuid
from collections import defaultdict
from statistics import median
from typing import Literal

from pydantic import Field, model_validator

from ..blackbox.models import StrictModel, digest
from ..experiments.models import Identifier, Sha256
from ..workbench.analysis import wilson
from . import authority
from .contracts import (
    AcceptancePolicy,
    Assessment,
    ExecutionContract,
    ProductionFailure,
    Recipe,
    Revision,
    Submission,
    TrialIdentity,
    TrialTicket,
    validate_assessment,
)
from .execution import policy_decision
from .oracles import BehaviorSuite


class StudyTask(StrictModel):
    base_revision: Revision
    suite_sha256: Sha256
    policy_sha256: Sha256
    baseline_recipe_sha256: Sha256 | None = None
    candidate_recipe_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def paired_overrides(self):
        if (self.baseline_recipe_sha256 is None) != (
            self.candidate_recipe_sha256 is None
        ):
            raise ValueError("task recipe overrides require both arms")
        return self


class StudyPlan(StrictModel):
    schema_version: Literal["agent-eval.study/v2"] = "agent-eval.study/v2"
    cohort_id: Identifier
    name: str = Field(min_length=1, max_length=120)
    baseline_recipe_sha256: Sha256
    candidate_recipe_sha256: Sha256
    tasks: list[StudyTask] = Field(min_length=1, max_length=100)
    trials: int = Field(default=3, ge=2, le=100)
    seed: int = 0
    max_model_requests: int = Field(ge=0, le=10000)
    max_total_tokens: int = Field(ge=0, le=10000000)
    max_assisted_executions: int = Field(default=0, ge=0, le=200)
    max_assisted_model_requests: int = Field(default=0, ge=0, le=10000)
    max_assisted_total_tokens: int = Field(default=0, ge=0, le=10000000)
    repair_selection: Literal["first_failed_in_schedule"] = "first_failed_in_schedule"
    evaluator_sha256: Sha256

    @model_validator(mode="after")
    def distinct_tasks(self):
        if len({t.suite_sha256 for t in self.tasks}) != len(self.tasks):
            raise ValueError("duplicate study task")
        return self


def matched_recipes(baseline: Recipe, candidate: Recipe):
    for field in ("capability_sha256", "model_configuration_sha256", "budget"):
        if getattr(baseline, field) != getattr(candidate, field):
            raise ValueError("unmatched study " + field)


def recipe_id(plan, task, arm):
    return getattr(task, arm + "_recipe_sha256") or getattr(
        plan, arm + "_recipe_sha256"
    )


def task_recipes(store, project, plan, task):
    recipes = {
        arm: Recipe.model_validate(
            store.get(project, "candidate-recipe", recipe_id(plan, task, arm))
        )
        for arm in ("baseline", "candidate")
    }
    matched_recipes(recipes["baseline"], recipes["candidate"])
    return recipes


def reserve_study(store, project, plan: StudyPlan, actor):
    if plan.evaluator_sha256 != authority.identity():
        raise ValueError("study evaluator identity changed")
    recipes = [task_recipes(store, project, plan, task) for task in plan.tasks]
    count = 2 * len(plan.tasks) * plan.trials
    budgets = [r["baseline"].budget for r in recipes]
    if (
        2 * plan.trials * sum(b.max_model_requests for b in budgets)
        > plan.max_model_requests
        or 2 * plan.trials * sum(b.max_total_tokens for b in budgets)
        > plan.max_total_tokens
    ):
        raise ValueError("study exceeds the declared aggregate budget")
    suites = [
        BehaviorSuite.model_validate(
            store.get(project, "candidate-suite", t.suite_sha256)
        )
        for t in plan.tasks
    ]
    if (
        len({s.task_id for s in suites}) != len(suites)
        or len({s.split for s in suites}) != 1
    ):
        raise ValueError("study tasks must have distinct IDs and one split")
    # Store the complete plan before ticket creation; interrupted setup resumes deterministically.
    store.put(
        project,
        "candidate-study",
        plan.model_dump(mode="json"),
        object_id=plan.cohort_id,
        actor=actor,
    )
    rng = random.Random(plan.seed)
    pairs = [
        (trial, index)
        for trial in range(1, plan.trials + 1)
        for index in range(len(plan.tasks))
    ]
    rng.shuffle(pairs)
    schedule = []
    for trial, index in pairs:
        task, suite = plan.tasks[index], suites[index]
        arms = ["baseline", "candidate"]
        rng.shuffle(arms)
        for arm in arms:
            execution = str(
                uuid.uuid5(
                    uuid.UUID(plan.cohort_id), f"{suite.task_id}:{trial}:{arm}:initial"
                )
            )
            ticket = TrialTicket(
                execution_id=execution,
                base_revision=task.base_revision,
                trial_identity=TrialIdentity(
                    cohort_id=plan.cohort_id,
                    task_id=suite.task_id,
                    family=suite.family,
                    split=suite.split,
                    trial=trial,
                    arm=arm,
                ),
                recipe_sha256=recipe_id(plan, task, arm),
                suite_sha256=task.suite_sha256,
                policy_sha256=task.policy_sha256,
                evaluator_sha256=plan.evaluator_sha256,
            )
            authority.reserve(store, project, ticket, actor)
            schedule.append(execution)
    store.put(
        project,
        "candidate-schedule",
        {"executions": schedule},
        object_id=plan.cohort_id,
        actor=actor,
    )
    return {
        "cohort_id": plan.cohort_id,
        "study_sha256": digest(plan.model_dump(mode="json")),
        "planned_initial": count,
        "schedule": schedule,
    }


def all_records(store, project, kind):
    values = []
    after = ""
    while True:
        page = store.list(project, kind, after=after, limit=200)
        values.extend(item["value"] for item in page["items"])
        if page["next"] is None:
            return values
        after = page["next"]


def percentile(values, fraction):
    return (
        sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]
        if values
        else None
    )


def summarize_rows(rows, *, seed=0, samples=2000):
    """Describe only a predeclared row matrix; missing rows never count as successes."""
    if not 100 <= samples <= 10000:
        raise ValueError("bootstrap count outside bounds")
    by_arm = {
        arm: [r for r in rows if r["arm"] == arm] for arm in ("baseline", "candidate")
    }
    counts = {}
    for arm, items in by_arm.items():
        passed = sum(r["outcome"] == "pass" for r in items)
        evaluable = sum(r["outcome"] in ("pass", "fail") for r in items)
        completed = sum(r["outcome"] != "pending" for r in items)
        metrics = {}
        for field in ("latency_ms", "total_tokens", "cost_usd"):
            values = [
                r["usage"][field] for r in items if r["usage"].get(field) is not None
            ]
            metrics[field] = {
                "observed": len(values),
                "planned": len(items),
                "median": median(values) if values else None,
                "p95": percentile(values, 0.95),
                "total": sum(values) if len(values) == len(items) and items else None,
                "provenance": sorted(
                    {
                        r["usage"].get("provenance", "unavailable")
                        for r in items
                        if r["usage"].get(field) is not None
                    }
                ),
            }
        counts[arm] = {
            "planned": len(items),
            "completed": completed,
            "accepted": passed,
            "rejected": sum(r["outcome"] == "fail" for r in items),
            "production_failed": sum(
                r["outcome"] == "production_failed" for r in items
            ),
            "pending": sum(r["outcome"] == "pending" for r in items),
            "unavailable": len(items) - evaluable,
            "success": passed / len(items) if items else None,
            "conditional_success": passed / evaluable if evaluable else None,
            "wilson_descriptive": wilson(passed, len(items)),
            "metrics": metrics,
        }
    pairs = defaultdict(dict)
    for row in rows:
        key = (row["task_id"], row["trial"])
        if row["arm"] in pairs[key]:
            raise ValueError("duplicate paired row")
        pairs[key][row["arm"]] = row
    deltas = defaultdict(list)
    missing = 0
    comparability = []
    for arms in pairs.values():
        if set(arms) != {"baseline", "candidate"} or any(
            r["outcome"] not in ("pass", "fail") for r in arms.values()
        ):
            missing += 1
            continue
        a, b = arms["baseline"], arms["candidate"]
        if any(
            a[k] != b[k]
            for k in (
                "suite_sha256",
                "base_revision",
                "policy_sha256",
                "evaluator_sha256",
                "family",
            )
        ):
            comparability.append("paired identity mismatch")
            continue
        deltas[a["family"]].append(
            int(b["outcome"] == "pass") - int(a["outcome"] == "pass")
        )
    effects = [sum(values) / len(values) for values in deltas.values()]
    interval = None
    if len(effects) >= 2 and not missing and not comparability:
        rng = random.Random(seed)
        draws = sorted(
            sum(rng.choices(effects, k=len(effects))) / len(effects)
            for _ in range(samples)
        )
        interval = [
            draws[int(samples * 0.025)],
            draws[min(samples - 1, int(samples * 0.975))],
        ]
    return {
        "counts": counts,
        "paired_families": len(effects),
        "missing_pairs": missing,
        "effect": sum(effects) / len(effects) if effects else None,
        "interval": interval,
        "method": "paired task-family percentile bootstrap",
        "seed": seed,
        "samples": samples,
        "comparability": sorted(set(comparability)),
        "inference_scope": "Observed task families; repeated trials share their task inputs and runtime.",
        "promotion_status": "inconclusive"
        if len(effects) < 10 or missing or comparability
        else "descriptive_comparison",
    }


def study_report(store, project, cohort):
    plan = StudyPlan.model_validate(store.get(project, "candidate-study", cohort))
    for task in plan.tasks:
        task_recipes(store, project, plan, task)
    scheduled = store.get(project, "candidate-schedule", cohort)["executions"]
    tickets = {
        t["execution_id"]: t
        for t in all_records(store, project, "trial-ticket-v2")
        if t["trial_identity"]["cohort_id"] == cohort
    }
    if any(execution not in tickets for execution in scheduled):
        raise ValueError("reserved study ticket missing")
    initial_tickets = [
        t for t in tickets.values() if t["trial_identity"]["attempt_kind"] == "initial"
    ]
    if len(scheduled) != 2 * len(plan.tasks) * plan.trials or set(scheduled) != {
        t["execution_id"] for t in initial_tickets
    }:
        raise ValueError("study schedule differs from complete planned denominator")
    assessments = {
        a["execution_id"]: a for a in all_records(store, project, "assessment-v2")
    }
    failures = {
        a["execution_id"]: a
        for a in all_records(store, project, "production-failure-v2")
    }
    rows = []
    for key in [
        *scheduled,
        *sorted(
            k
            for k, t in tickets.items()
            if t["trial_identity"]["attempt_kind"] != "initial"
        ),
    ]:
        ticket = tickets[key]
        assessment = assessments.get(key)
        failure = failures.get(key)
        trial = ticket["trial_identity"]
        if assessment and failure:
            raise ValueError("study row has conflicting terminal outcomes")
        task = next(
            (t for t in plan.tasks if t.suite_sha256 == ticket["suite_sha256"]), None
        )
        if task is None:
            raise ValueError("ticket task is outside the declared study")
        if trial["attempt_kind"] == "initial" and (
            ticket["recipe_sha256"] != recipe_id(plan, task, trial["arm"])
            or not 1 <= trial["trial"] <= plan.trials
        ):
            raise ValueError("study ticket recipe or trial differs from plan")
        if (
            not any(
                ticket["suite_sha256"] == t.suite_sha256
                and ticket["policy_sha256"] == t.policy_sha256
                and ticket["base_revision"] == t.base_revision
                for t in plan.tasks
            )
            or ticket["evaluator_sha256"] != plan.evaluator_sha256
        ):
            raise ValueError("study ticket differs from plan identity")
        if assessment:
            validate_recorded_assessment(store, project, ticket, assessment)
        if failure:
            failure = ProductionFailure.model_validate(failure).model_dump(mode="json")
            if failure["trial_ticket_sha256"] != digest(ticket):
                raise ValueError("production failure ticket mismatch")
        rows.append(
            {
                **trial,
                "execution_id": key,
                "base_revision": ticket["base_revision"],
                "suite_sha256": ticket["suite_sha256"],
                "policy_sha256": ticket["policy_sha256"],
                "evaluator_sha256": ticket["evaluator_sha256"],
                "recipe_sha256": ticket["recipe_sha256"],
                "trial_ticket_sha256": digest(ticket),
                "observation_sha256": assessment["observation_sha256"]
                if assessment
                else None,
                "submission_sha256": assessment["submission_sha256"]
                if assessment
                else None,
                "producer_completed": store.get(project, "submission-v2", key)[
                    "producer_status"
                ]
                == "completed"
                if assessment
                else None,
                "outcome": assessment["outcome"]
                if assessment
                else "production_failed"
                if failure
                else "pending",
                "usage": assessment["usage"]
                if assessment
                else failure["usage"]
                if failure
                else {},
                "candidate_tree_sha256": assessment["candidate_tree_sha256"]
                if assessment
                else None,
                "checks": assessment["checks"] if assessment else [],
                "reasons": assessment["reasons"]
                if assessment
                else [failure["reason"]]
                if failure
                else [],
                "assessment_sha256": digest(assessment) if assessment else None,
                "evaluation_latency_ms": assessment["evaluation_latency_ms"]
                if assessment
                else None,
            }
        )
    initial = [r for r in rows if r["attempt_kind"] == "initial"]
    repairs = [r for r in rows if r["attempt_kind"] == "assisted_correction"]
    summary = summarize_rows(initial, seed=plan.seed)
    # Assisted attempts are a selected subset of initial failures, not a replacement cohort.
    repair_summary = {
        "maximum": plan.max_assisted_executions,
        "selection": plan.repair_selection,
        "planned": len(repairs),
        "completed": sum(
            r["outcome"] in ("pass", "fail", "inconclusive") for r in repairs
        ),
        "accepted": sum(r["outcome"] == "pass" for r in repairs),
    }
    return {
        "schema_version": "agent-eval.study-report/v2",
        "cohort_id": cohort,
        "name": plan.name,
        "study_sha256": digest(plan.model_dump(mode="json")),
        "plan": plan.model_dump(mode="json"),
        "summary": summary,
        "repairs": repair_summary,
        "rows": rows,
        "record_kind": "recorded_evidence",
    }


def validate_recorded_assessment(store, project, ticket, value):
    """Validate saved evidence without requiring the original executor to run again."""
    assessment = Assessment.model_validate(value)
    submission = Submission.model_validate(
        store.get(project, "submission-v2", ticket["execution_id"])
    )
    contract = ExecutionContract.model_validate(
        store.get(project, "execution-v2", ticket["execution_id"])
    )
    validate_assessment(assessment, submission)
    if contract.trial_ticket_sha256 != digest(
        ticket
    ) or submission.execution_contract_sha256 != digest(
        contract.model_dump(mode="json")
    ):
        raise ValueError("recorded execution binding mismatch")
    for key in (
        "execution_id",
        "base_revision",
        "trial_identity",
        "recipe_sha256",
        "suite_sha256",
        "policy_sha256",
        "evaluator_sha256",
    ):
        if contract.model_dump(mode="json")[key] != ticket[key]:
            raise ValueError("recorded contract differs from ticket")
    for key in (
        "candidate_revision",
        "candidate_tree_sha256",
        "candidate_manifest_sha256",
        "base_revision",
        "recipe_sha256",
        "suite_sha256",
        "policy_sha256",
        "evaluator_sha256",
    ):
        if getattr(contract, key) != getattr(submission, key):
            raise ValueError("recorded submission differs from contract")
    policy = AcceptancePolicy.model_validate(
        store.get(project, "candidate-policy", ticket["policy_sha256"])
    )
    if len({c.id for c in assessment.checks}) != len(assessment.checks) or {
        c.id for c in assessment.checks
    } != set(policy.required_checks):
        raise ValueError("recorded behavioral checks differ from issued policy")
    outcome, reasons = policy_decision(
        assessment.checks,
        policy,
        assessment.usage,
        completed=submission.producer_status == "completed",
    )
    if (outcome, reasons) != (assessment.outcome, assessment.reasons):
        raise ValueError("recorded decision does not replay")
    return assessment
