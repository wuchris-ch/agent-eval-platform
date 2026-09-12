"""Paired task-family comparisons and immutable evidence-bound gates."""

from __future__ import annotations

import math
import random
from collections import defaultdict
from typing import Literal

from pydantic import Field

from ..blackbox.models import StrictModel, digest
from ..experiments.journal import Journal, JournalError
from ..experiments.models import Sha256


class Policy(StrictModel):
    schema_version: Literal["agent-eval.gate-policy/v1"] = "agent-eval.gate-policy/v1"
    regression_margin: float = Field(ge=0, le=1)
    minimum_families: int = Field(default=10, ge=2)
    bootstrap_samples: int = Field(default=2000, ge=100, le=10000)
    seed: int = 0
    max_latency_ms: float | None = Field(default=None, gt=0)
    required_inspection: bool = False
    require_state: bool = False


def cohort(experiment):
    with Journal.open(experiment) as journal:
        status = journal.status().model_dump(mode="json")
        rows = journal.rows()
        records = []
        state_receipts = {}
        if any(
            (journal.root / "receipts" / f"{r['attempt_id']}.state.json").exists()
            for r in rows
        ):
            from .service import state_evidence

            state_receipts = {v["attempt_id"]: v for v in state_evidence(journal)}
        for row in rows:
            case, trial = journal.plan.case_trial(row["ordinal"])
            result = (
                journal.result(row).model_dump(mode="json")
                if row["state"] == "completed"
                else None
            )
            effective = result["outcome"] if result else None
            state_receipt = state_receipts.get(row["attempt_id"])
            if state_receipt and state_receipt["assessment"]["status"] != "accepted":
                effective = (
                    "rejected"
                    if state_receipt["assessment"]["status"] == "rejected"
                    else "infra_error"
                )
            records.append(
                {
                    "case": case.id,
                    "ordinal": row["ordinal"],
                    "effective_outcome": effective,
                    "trial": trial,
                    "input": digest(case.input),
                    "state": row["state"],
                    "result": result,
                }
            )
        output_status = dict(status)
        status["accepted"] = sum(r["effective_outcome"] == "accepted" for r in records)
        status["rejected"] = sum(r["effective_outcome"] == "rejected" for r in records)
        status["infra_errors"] = sum(
            r["effective_outcome"] == "infra_error" for r in records
        )
        status["passed"] = (
            status["accepted"] == status["planned"]
            if status["state"] == "completed"
            else None
        )
        return {
            "output_status": output_status,
            "experiment": experiment,
            "plan": journal.plan_sha256,
            "suite": journal.plan.suite_sha256,
            "grader": journal.plan.evaluator_sha256,
            "target": digest(
                {
                    "command": journal.plan.target_sha256,
                    "files": [f.model_dump() for f in journal.plan.files],
                }
            ),
            "status": status,
            "records": records,
            "evidence": digest(
                {"rows": [dict(r) for r in rows], "state": state_receipts}
            ),
        }


def wilson(successes, total):
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = (
        z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    )
    return [max(0, center - half), min(1, center + half)]


def reliability(successes, total, k):
    if not 1 <= k <= total or not 0 <= successes <= total:
        raise ValueError("invalid exchangeable trial counts")
    return {
        "all_k": math.comb(successes, k) / math.comb(total, k) if successes >= k else 0,
        "at_least_one_k": 1
        - (
            math.comb(total - successes, k) / math.comb(total, k)
            if total - successes >= k
            else 0
        ),
    }


def compare(baseline, candidate, *, families=None, seed=0, samples=2000):
    if not 100 <= samples <= 10000:
        raise ValueError("bootstrap sample count outside bounds")
    a, b = cohort(baseline), cohort(candidate)
    reasons = []
    for field in ("suite", "grader"):
        if a[field] != b[field]:
            reasons.append(f"incompatible {field}")
    if baseline == candidate:
        reasons.append("baseline and candidate are the same experiment")

    def index(c):
        result = {}
        for record in c["records"]:
            key = (record["case"], record["trial"])
            if key in result:
                raise JournalError("duplicate paired trial")
            result[key] = record
        return result

    left, right = index(a), index(b)
    keys = sorted(set(left) | set(right))
    paired = defaultdict(list)
    cases = []
    missing = 0
    for key in keys:
        x, y = left.get(key), right.get(key)
        if not x or not y or x["input"] != y["input"]:
            missing += 1
            continue
        if not x["result"] or not y["result"]:
            missing += 1
            continue
        av, bv = (
            int(x["effective_outcome"] == "accepted"),
            int(y["effective_outcome"] == "accepted"),
        )
        family = (families or {}).get(key[0], key[0])
        paired[family].append(bv - av)
        cases.append(
            {
                "case": key[0],
                "trial": key[1],
                "family": family,
                "baseline": x["effective_outcome"],
                "baseline_ordinal": x["ordinal"],
                "candidate": y["effective_outcome"],
                "candidate_ordinal": y["ordinal"],
                "delta": bv - av,
            }
        )
    if missing:
        reasons.append("missing or mismatched pairs")
    if any(c["status"]["state"] != "completed" for c in (a, b)):
        reasons.append("incomplete cohort")
    effects = [sum(v) / len(v) for v in paired.values()]
    effect = sum(effects) / len(effects) if effects else None
    interval = None
    if len(effects) >= 2 and not reasons:
        rng = random.Random(seed)
        draws = sorted(
            sum(rng.choices(effects, k=len(effects))) / len(effects)
            for _ in range(samples)
        )
        interval = [
            draws[int(samples * 0.025)],
            draws[min(samples - 1, int(samples * 0.975))],
        ]

    def counts(c):
        s = c["status"]
        evaluable = s["accepted"] + s["rejected"]
        return {
            "planned": s["planned"],
            "completed": s["completed"],
            "accepted": s["accepted"],
            "infrastructure": s["infra_errors"],
            "first_invocation_success": s["accepted"] / s["planned"]
            if s["state"] == "completed"
            else None,
            "conditional_quality": s["accepted"] / evaluable if evaluable else None,
            "wilson_descriptive": wilson(s["accepted"], s["planned"])
            if s["state"] == "completed"
            else None,
        }

    return {
        "schema_version": "agent-eval.comparison/v1",
        "baseline": a,
        "candidate": b,
        "counts": {"baseline": counts(a), "candidate": counts(b)},
        "cases": cases,
        "families": len(effects),
        "missing_pairs": missing,
        "effect": effect,
        "interval": interval,
        "method": "paired task-family percentile bootstrap",
        "seed": seed,
        "samples": samples,
        "reasons": reasons,
        "attempt_kind": "initial",
        "limitations": "Few families and shared infrastructure can make intervals unreliable. Inner target retries are not separate measurements.",
    }


def decide(
    comparison, policy: Policy, candidate_artifact: str, *, inspection=None, state=None
):
    # A decision is only usable for this exact candidate and evidence cohort.
    from pydantic import TypeAdapter

    TypeAdapter(Sha256).validate_python(candidate_artifact)
    reasons = list(comparison["reasons"])
    if candidate_artifact != comparison["candidate"]["target"]:
        reasons.append("candidate artifact substitution")
    if comparison["families"] < policy.minimum_families:
        reasons.append("insufficient task families")
    if any(
        comparison["counts"][arm]["infrastructure"] for arm in ("baseline", "candidate")
    ):
        reasons.append("infrastructure evidence unavailable")
    if policy.required_inspection and inspection not in ("accepted", "rejected"):
        reasons.append("required inspection unavailable")
    if policy.require_state and state not in ("accepted", "rejected"):
        reasons.append("required state evidence unavailable")
    latencies = [
        r["result"]["observation"]["latency_ms"]
        for r in comparison["candidate"]["records"]
        if r["result"] and r["result"]["observation"]
    ]
    if policy.max_latency_ms is not None and (
        len(latencies) != comparison["candidate"]["status"]["planned"]
        or None in latencies
    ):
        reasons.append("latency coverage incomplete")
    verdict = "inconclusive"
    if (
        inspection == "rejected"
        or state == "rejected"
        or "candidate artifact substitution" in reasons
    ):
        verdict = "fail"
    elif not reasons and comparison["interval"] is not None:
        low, high = comparison["interval"]
        if low > -policy.regression_margin:
            verdict = "pass"
        elif high < -policy.regression_margin:
            verdict = "fail"
        if policy.max_latency_ms is not None and max(latencies) > policy.max_latency_ms:
            verdict = "fail"
            reasons.append("latency guardrail exceeded")
    return {
        "schema_version": "agent-eval.decision/v1",
        "candidate_artifact": candidate_artifact,
        "comparison_sha256": digest(comparison),
        "policy_sha256": digest(policy.model_dump(mode="json")),
        "assessment_set_sha256": comparison["candidate"]["evidence"],
        "verdict": verdict,
        "reasons": reasons,
    }
