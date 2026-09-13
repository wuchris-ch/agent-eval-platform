#!/usr/bin/env python3
"""Build a content-minimized static catalog from verified recorded evidence."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
from statistics import median

from agent_eval.blackbox.models import digest, json_bytes
from agent_eval.candidates.bundles import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
BASELINE_SHA = "5ed5d8efceeeb5b9b23fcc0af5e3f4439623e9ac716f92fbcb79502096aee120"


def metric(label, value, note):
    return {"label": label, "value": value, "note": note}


def write(folder, name, value):
    (folder / name).write_bytes(json_bytes(value) + b"\n")
    return "evidence/" + name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-report", type=Path, required=True)
    parser.add_argument("--software-bundle", type=Path)
    parser.add_argument("--protocol-state", type=Path)
    parser.add_argument("--study-root", type=Path)
    args = parser.parse_args()
    folder = ROOT / "docs/evidence"
    folder.mkdir(exist_ok=True)
    raw = args.baseline_report.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA:
        raise ValueError("Historical baseline bytes changed")
    baseline = json.loads(raw)
    rows = []
    for r in baseline["results"]:
        d = r["first_attempt"]["deterministic"]
        outcome = (
            "pass"
            if r["outcome"] == "accepted"
            else "fail"
            if r["outcome"] == "rejected"
            else "inconclusive"
        )
        reasons = []
        if d["false_negatives"]:
            reasons.append(
                f"{d['false_negatives']} expected finding did not match the required location and category"
            )
        if d["false_positives"]:
            reasons.append(f"{d['false_positives']} unexpected or unmatched finding")
        if not d["verdict_correct"]:
            reasons.append("Blocking verdict differed from the reference")
        row = {
            "row_id": r["case_id"] + "/" + str(r["trial"]),
            "task_id": r["case_id"],
            "family": "reviewer-regression",
            "trial": r["trial"],
            "arm": "baseline",
            "arm_label": "Flue baseline",
            "attempt_kind": "initial",
            "outcome": outcome,
            "reasons": reasons,
            "usage": {
                "latency_ms": r["latency_ms"],
                "total_tokens": None,
                "cost_usd": None,
                "provenance": "independently_observed",
            },
            "checks": [
                {
                    "id": "blocking-verdict",
                    "passed": d["verdict_correct"],
                    "reason": "Blocking verdict matched"
                    if d["verdict_correct"]
                    else "Blocking verdict mismatch",
                },
                {
                    "id": "required-findings",
                    "passed": d["false_negatives"] == 0,
                    "reason": f"{d['false_negatives']} unmatched reference findings",
                },
                {
                    "id": "unexpected-findings",
                    "passed": d["false_positives"] == 0,
                    "reason": f"{d['false_positives']} unmatched reported findings",
                },
            ],
        }
        if r["case_id"] == "swallowed-error" and outcome == "fail":
            row["note"] = (
                "Input-sufficiency investigation: the self-test assertion that requires an exception is outside the supplied diff. The historical score remains unchanged. New software tasks state required behavior in their visible task contract."
            )
        rows.append(row)
    summary = {
        "schema_version": "agent-eval.reviewer-evidence/v1",
        "source_report_sha256": BASELINE_SHA,
        "release_gate": "FAIL",
        "accepted": 56,
        "planned": 60,
        "rows": rows,
    }
    link = write(folder, "reviewer-baseline.json", summary)
    collections = [
        {
            "id": "reviewer-baseline",
            "title": "Flue reviewer: preserved baseline",
            "kind_label": "LIVE REVIEWER BENCHMARK · 2026-09-12",
            "description": "Twenty review cases, three trials each. The run accepted 56 of 60 evaluations and failed its stricter release gate. Historical outcomes remain unchanged.",
            "revision_label": "reviewer 024f477 / evaluator 048a8d4",
            "latency_label": "Review latency",
            "metrics": [
                metric("Accepted", "56 / 60", "93.3% first-pass acceptance"),
                metric(
                    "Strict release gate", "FAIL", "18 / 21 security-blocker matches"
                ),
                metric(
                    "Median latency", "8.75 s", "Independent wall-clock measurement"
                ),
                metric("Planned trials", "60", "0 infrastructure errors"),
            ],
            "arms": [
                {
                    "label": "Recorded Flue baseline",
                    "accepted": 56,
                    "rejected": 4,
                    "planned": 60,
                    "note": "Three rounds across 20 cases; no judge or self-correction.",
                }
            ],
            "inference": "The strict gate also required stable verdicts across all three rounds. Stability was 17/20 cases. This run is preserved alongside later studies.",
            "download": link,
            "report": "https://github.com/wuchris-ch/agent-eval-platform/blob/main/benchmarks/reviewer-corpus/v1/results/2026-09-12-flue.md",
            "policy_replay": False,
            "rows": rows,
        }
    ]
    protocol = json.loads(
        (
            ROOT / "benchmarks/software-corpus/v1/results/protocol-controls.json"
        ).read_bytes()
    )
    controls = []
    for item in protocol["controls"]:
        a = item["assessment"]
        trial = item["ticket"]["trial_identity"]
        controls.append(
            {
                **a,
                **trial,
                "assessment_sha256": item["assessment_sha256"],
                "task_id": "order-idempotency / " + item["control"],
                "arm_label": item["control"] + " control",
                "usage": {
                    "latency_ms": a["evaluation_latency_ms"],
                    "total_tokens": 0,
                    "cost_usd": 0,
                    "provenance": "independently_observed",
                },
                "producer_completed": True,
            }
        )
        if args.protocol_state:
            receipt_path = (
                args.protocol_state
                / "candidate-executions"
                / digest("protocol-v2")
                / a["execution_id"]
                / "observation.json"
            )
            receipt = json.loads(receipt_path.read_bytes())
            observed = receipt["observation"]
            if (
                digest(observed) != a["observation_sha256"]
                or receipt["contract_sha256"] != a["execution_contract_sha256"]
            ):
                raise ValueError("Protocol observation identity changed")
            suite = json.loads(
                (ROOT / "tests/fixtures/candidates/order-oracle.json").read_bytes()
            )
            if digest(suite) != a["suite_sha256"]:
                raise ValueError("Protocol reference identity changed")
            controls[-1]["checks"] = [
                {
                    **check,
                    "description": oracle["description"],
                    "expected_responses": oracle["expected_responses"],
                    "observed_responses": [
                        observed["responses"][i] for i in oracle["response_indices"]
                    ],
                    "expected_state": oracle["expected_rows"],
                    "observed_state": observed["state_queries"].get(check["id"]),
                }
                for check, oracle in zip(a["checks"], suite["checks"], strict=True)
            ]
    link = write(folder, "protocol-controls.json", protocol)
    collections.append(
        {
            "id": "producer-bridge",
            "title": "Producer and evaluator: HTTP round trip",
            "kind_label": "PROTOCOL CONTROLS · ZERO MODEL CALLS",
            "description": "The actual producer uploaded, submitted and retrieved assessments through the authenticated evaluator API. Both candidates passed the public compile check. Independent behavior and final-state checks accepted the correct candidate and rejected the plausible incorrect one.",
            "revision_label": "producer 74cda99 / evaluator e028f37",
            "latency_label": "Check time",
            "metrics": [
                metric(
                    "Expected decisions",
                    "2 / 2",
                    "Correct accepted; incorrect rejected",
                ),
                metric(
                    "Independent checks",
                    "5 per candidate",
                    "Behavior plus durable SQLite state",
                ),
                metric("Model calls", "0", "Protocol controls use fixed candidates"),
                metric(
                    "Repeated retrieval",
                    "Unchanged",
                    "Exact assessment identities matched",
                ),
            ],
            "arms": [],
            "inference": "These fixed-candidate controls establish protocol behavior. A separate real-producer snapshot control recovered in a fresh process after a forced crash without another candidate invocation.",
            "download": link,
            "report": "https://github.com/wuchris-ch/agent-eval-platform/blob/main/contracts/v2/README.md",
            "policy_replay": False,
            "rows": controls,
        }
    )
    qualification = json.loads(
        (
            ROOT / "benchmarks/software-corpus/v1/results/oracle-qualification.json"
        ).read_bytes()
    )
    qualified = []
    for r in qualification["results"]:
        qualified.append(
            {
                **r,
                "trial": 1,
                "arm": "candidate" if r["control"] == "positive" else "baseline",
                "arm_label": r["control"] + " control",
                "split": "development",
                "attempt_kind": "initial",
                "outcome": r["observed_outcome"],
                "reasons": [c["reason"] for c in r["checks"] if not c["passed"]],
                "usage": {},
                "note": "This fixed control was expected to "
                + r["expected_outcome"]
                + ".",
            }
        )
    link = write(folder, "oracle-qualification.json", qualification)
    collections.append(
        {
            "id": "oracle-controls",
            "title": "Software corpus: independent oracle controls",
            "kind_label": "FIVE AUTHORED TASK FAMILIES",
            "description": "Known-correct and plausible incorrect implementations qualify independent response and final-state checks for backend tasks and a fullstack payment form/API. All controls ran in pinned, network-disabled containers.",
            "revision_label": "software corpus v1.0.0",
            "latency_label": "Check time",
            "metrics": [
                metric(
                    "Qualified controls", "10 / 10", "All expected outcomes observed"
                ),
                metric("Task families", "5", "Four backend families, one fullstack"),
                metric(
                    "Positive controls",
                    "5 / 5 accepted",
                    "Required behaviors and state matched",
                ),
                metric(
                    "Negative controls",
                    "5 / 5 rejected",
                    "At least one independent check failed",
                ),
            ],
            "arms": [],
            "inference": "These authored fixtures test oracle discrimination. Two additional families are sealed privately with zero agent invocations at sealing.",
            "download": link,
            "report": "https://github.com/wuchris-ch/agent-eval-platform/blob/main/benchmarks/software-corpus/v1/README.md",
            "policy_replay": False,
            "rows": qualified,
        }
    )
    if args.software_bundle:
        bundle = json.loads(args.software_bundle.read_bytes())
        verify_bundle(bundle)
        report = bundle["report"]
        rows = report["rows"]
        counts = report["summary"]["counts"]
        initial = [r for r in rows if r["attempt_kind"] == "initial"]
        arms = []
        for arm in ("baseline", "candidate"):
            c = counts[arm]
            independent_latency = sum(
                row["arm"] == arm
                and row["usage"].get("latency_ms") is not None
                and row["usage"]["provenance"] == "independently_observed"
                for row in initial
            )
            latency = c["metrics"]["latency_ms"]["median"]
            timing = (
                f"Median production time: {latency / 1000:.2f} s."
                if latency is not None
                else "Production time unavailable."
            )
            arms.append(
                {
                    "label": "Single coder"
                    if arm == "baseline"
                    else "Selective coordination",
                    "accepted": c["accepted"],
                    "rejected": c["rejected"],
                    "planned": c["planned"],
                    "note": f"{c['unavailable'] - c['production_failed'] - c['pending']} inconclusive; {c['production_failed']} production failures. {timing} Independent latency coverage: {independent_latency}/{c['planned']}.",
                }
            )
        for row in rows:
            row["arm_label"] = "Single" if row["arm"] == "baseline" else "Selective"
            if args.study_root:
                saved = json.loads(
                    (
                        args.study_root
                        / "executions"
                        / row["execution_id"]
                        / "production.json"
                    ).read_bytes()
                )
                produced = saved.get("result", {})
                inspection = (
                    args.study_root
                    / "executions"
                    / row["execution_id"]
                    / "producer-inspection.json"
                )
                if not produced and inspection.exists():
                    produced = json.loads(inspection.read_bytes())
                phases = []
                allowed_stages = {
                    "planner",
                    "analysis",
                    "coder-0",
                    "candidate-0",
                    "verify-0",
                    "reviewer-0",
                }
                for stage, details in produced.get("steps", {}).items():
                    if stage not in allowed_stages:
                        continue
                    events = [
                        e["at"]
                        for e in produced.get("events", [])
                        if e["event"] in (stage + ".intent", stage + ".completed")
                    ]
                    phases.append(
                        {
                            "stage": stage,
                            "status": "completed"
                            if "result" in details
                            else "unresolved",
                            "model_requests": details.get("result", {}).get(
                                "model_requests"
                            ),
                            "duration_seconds": max(events) - min(events)
                            if len(events) == 2
                            else None,
                        }
                    )
                row["phases"] = phases
                row["reported_accounting"] = {
                    key: produced.get("accounting", {}).get(key)
                    for key in (
                        "model_requests",
                        "total_tokens",
                        "tokens_used_or_reserved",
                        "unresolved_calls",
                    )
                }
        # Keep the verified bundle unchanged; presentation labels belong only to the catalog.
        original = json.loads(args.software_bundle.read_bytes())
        (folder / "software-study.json.gz").write_bytes(
            gzip.compress(json_bytes(original) + b"\n", mtime=0)
        )
        (folder / "software-study.json").unlink(missing_ok=True)
        link = "evidence/software-study.json.gz"
        elapsed = [
            r["usage"]["latency_ms"]
            for r in initial
            if r["usage"].get("latency_ms") is not None
        ]
        accepted = sum(r["outcome"] == "pass" for r in initial)
        failed = sum(r["outcome"] == "production_failed" for r in initial)
        effect = report["summary"]["effect"]
        interval = report["summary"]["interval"]
        effect_note = (
            "Paired effect unavailable."
            if effect is None
            else f"Family-weighted selective minus single acceptance: {effect * 100:+.1f} percentage points among evaluable pairs."
        )
        if report["summary"]["missing_pairs"]:
            effect_note = (
                f"{report['summary']['missing_pairs']} task/trial pairs lack complete pass-or-fail evidence; "
                "the paired effect is not interpreted. The arm counts retain every planned trial."
            )
        interval_note = (
            "The confidence interval is unavailable because complete paired evidence is required."
            if interval is None
            else f"Family-bootstrap 95% interval: {interval[0] * 100:+.1f} to {interval[1] * 100:+.1f} percentage points."
        )
        collections.insert(
            0,
            {
                "id": "software-study",
                "title": report["name"],
                "kind_label": "LIVE SOFTWARE STUDY · MATCHED TASK PAIRS",
                "description": "Four authored task families, three paired trials each. Initial candidates use zero internal repairs. Every reserved invocation remains in the denominator, and later assisted corrections are reported separately.",
                "revision_label": "producer a8f4f3e / evaluator 1e59f37",
                "latency_label": "Production time",
                "metrics": [
                    metric(
                        "Initial acceptance",
                        f"{accepted} / {len(initial)}",
                        "Across both policies",
                    ),
                    metric(
                        "Task families",
                        "4",
                        f"{report['summary']['paired_families']} have evaluable pairs",
                    ),
                    metric(
                        "Median production time",
                        f"{median(elapsed) / 1000:.2f} s" if elapsed else "Unavailable",
                        f"{len(elapsed)} / {len(initial)} measured",
                    ),
                    metric(
                        "Assisted corrections",
                        f"{report['repairs']['accepted']} / {report['repairs']['planned']}",
                        "Separate from all initial outcomes",
                    ),
                ],
                "arms": arms,
                "inference": f"{failed} production failures retained. {effect_note} {interval_note} This development study covers four authored families; promotion requires at least ten. Token and cost measurements appear only when available.",
                "download": link,
                "report": "https://github.com/wuchris-ch/agent-eval-platform/blob/main/benchmarks/software-corpus/v1/results/2026-09-13-software-study.md",
                "policy_replay": True,
                "rows": rows,
            },
        )
    recorded_rows = sum(len(c["rows"]) for c in collections)
    for collection in collections:
        rows = collection.pop("rows")
        collection["rows_files"] = []
        chunk = []
        size = 0
        for row in rows:
            row_size = len(json_bytes(row)) + 1
            if chunk and size + row_size > 24000:
                collection["rows_files"].append(
                    write(
                        folder,
                        f"{collection['id']}-rows-{len(collection['rows_files']) + 1}.json",
                        chunk,
                    )
                )
                chunk, size = [], 0
            chunk.append(row)
            size += row_size
        if chunk:
            collection["rows_files"].append(
                write(
                    folder,
                    f"{collection['id']}-rows-{len(collection['rows_files']) + 1}.json",
                    chunk,
                )
            )
    write(
        folder,
        "index.json",
        {
            "schema_version": "agent-eval.evidence-catalog/v1",
            "recorded_at": "2026-09-12 to 2026-09-13 UTC",
            "collections": collections,
        },
    )
    print(
        json.dumps(
            {
                "collections": len(collections),
                "recorded_rows": recorded_rows,
                "model_calls": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
