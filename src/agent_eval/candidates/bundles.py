"""Portable recorded decisions: bind every record and replay without model calls."""

from __future__ import annotations

from ..blackbox.models import digest
from .contracts import AcceptancePolicy, Assessment, Submission
from .execution import policy_decision
from .studies import study_report

VERSION = "agent-eval.evidence-bundle/v2"
KINDS = {
    "candidate-study",
    "candidate-schedule",
    "trial-ticket-v2",
    "execution-v2",
    "submission-v2",
    "assessment-v2",
    "production-failure-v2",
    "candidate-recipe",
    "candidate-policy",
}


class RecordedStore:
    def __init__(self, records):
        self.records = records

    def get(self, _project, kind, identity):
        value = self.records[kind + "/" + identity]
        if (
            kind in {"candidate-policy", "candidate-recipe"}
            and digest(value) != identity
        ):
            raise ValueError("content-addressed record mismatch")
        return value

    def list(self, project, kind, *, after="", limit=200):
        prefix = kind + "/"
        keys = sorted(
            k[len(prefix) :]
            for k in self.records
            if k.startswith(prefix) and k[len(prefix) :] > after
        )
        return {
            "items": [
                {"id": k, "value": self.get(project, kind, k)} for k in keys[:limit]
            ],
            "next": keys[limit - 1] if len(keys) > limit else None,
        }


def export_bundle(store, project, cohort):
    report = study_report(store, project, cohort)
    records = {}

    def add(kind, identity, optional=False):
        try:
            value = store.get(project, kind, identity)
        except KeyError:
            if optional:
                return
            raise
        records[kind + "/" + identity] = value

    add("candidate-study", cohort)
    add("candidate-schedule", cohort)
    for row in report["rows"]:
        for kind in (
            "trial-ticket-v2",
            "execution-v2",
            "submission-v2",
            "assessment-v2",
            "production-failure-v2",
        ):
            add(kind, row["execution_id"], optional=kind != "trial-ticket-v2")
        add("candidate-recipe", row["recipe_sha256"])
        add("candidate-policy", row["policy_sha256"])
    payload = {
        "schema_version": VERSION,
        "cohort_id": cohort,
        "records": records,
        "record_sha256": {key: digest(value) for key, value in records.items()},
        "report": report,
    }
    bundle = {**payload, "bundle_sha256": digest(payload)}
    verify_bundle(bundle)
    return bundle


def verify_bundle(bundle):
    if (
        set(bundle)
        != {
            "schema_version",
            "cohort_id",
            "records",
            "record_sha256",
            "report",
            "bundle_sha256",
        }
        or bundle["schema_version"] != VERSION
    ):
        raise ValueError("unsupported evidence bundle")
    payload = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    if digest(payload) != bundle["bundle_sha256"]:
        raise ValueError("bundle digest mismatch")
    records = bundle["records"]
    if len(records) > 150000 or any(
        key.split("/", 1)[0] not in KINDS for key in records
    ):
        raise ValueError("unsupported bundled record")
    if {key: digest(value) for key, value in records.items()} != bundle[
        "record_sha256"
    ]:
        raise ValueError("record digest mismatch")
    replayed = study_report(RecordedStore(records), "recorded", bundle["cohort_id"])
    if replayed != bundle["report"]:
        raise ValueError("saved study report does not replay")
    return {
        "verified": True,
        "bundle_sha256": bundle["bundle_sha256"],
        "rows": len(replayed["rows"]),
        "model_calls": 0,
        "scope": "Record integrity, execution bindings and acceptance-policy replay",
    }


def compare_policy(
    bundle, *, max_latency_ms=None, max_total_tokens=None, max_cost_usd=None
):
    verify_bundle(bundle)
    store = RecordedStore(bundle["records"])
    rows = []
    for row in bundle["report"]["rows"]:
        key = row["execution_id"]
        result = {
            "execution_id": key,
            "task_id": row["task_id"],
            "arm": row["arm"],
            "attempt_kind": row["attempt_kind"],
            "recorded_outcome": row["outcome"],
        }
        if row["assessment_sha256"] is None:
            rows.append(
                {
                    **result,
                    "preview_outcome": "inconclusive",
                    "reasons": ["independent assessment unavailable"],
                }
            )
            continue
        original = store.get("recorded", "candidate-policy", row["policy_sha256"])
        policy = AcceptancePolicy.model_validate(
            {
                **original,
                "max_latency_ms": max_latency_ms,
                "max_total_tokens": max_total_tokens,
                "max_cost_usd": max_cost_usd,
            }
        )
        assessment = Assessment.model_validate(
            store.get("recorded", "assessment-v2", key)
        )
        submission = Submission.model_validate(
            store.get("recorded", "submission-v2", key)
        )
        outcome, reasons = policy_decision(
            assessment.checks,
            policy,
            assessment.usage,
            completed=submission.producer_status == "completed",
        )
        rows.append(
            {
                **result,
                "preview_outcome": outcome,
                "reasons": reasons,
                "preview_policy_sha256": digest(policy.model_dump(mode="json")),
            }
        )
    return {
        "record_kind": "policy_preview",
        "source_bundle_sha256": bundle["bundle_sha256"],
        "rows": rows,
        "model_calls": 0,
    }
