#!/usr/bin/env python3
"""Add a recorded model comparison to the static evidence explorer.

Reads comparison.json and reports/<label>.json from a compare-models output
directory, then inserts or replaces the "model-comparison" collection in
docs/evidence/index.json. Other collections are left unchanged.
"""

import argparse
import json
from pathlib import Path

from agent_eval.blackbox.comparison import Comparison
from agent_eval.blackbox.models import Report, json_bytes, load_suite

ROOT = Path(__file__).resolve().parents[1]
COLLECTION_ID = "model-comparison"
OUTCOMES = {"accepted": "pass", "rejected": "fail", "infra_error": "inconclusive"}


def write(folder, name, value):
    (folder / name).write_bytes(json_bytes(value) + b"\n")
    return "evidence/" + name


def evaluation_cost(price, observation):
    if observation is None or observation.tokens_in is None:
        return None
    hardware = price.hardware_usd_per_hour * (observation.latency_ms or 0) / 3_600_000
    return (
        hardware
        + observation.tokens_in * price.input_usd_per_million_tokens / 1_000_000
        + observation.tokens_out * price.output_usd_per_million_tokens / 1_000_000
    )


def field_checks(expected, actual):
    answered = actual if isinstance(actual, dict) else {}
    return [
        {
            "id": key,
            "passed": key in answered and answered[key] == value,
            "reason": f"{key}: expected {json.dumps(value)}, answered "
            + (json.dumps(answered[key]) if key in answered else "nothing"),
        }
        for key, value in expected.items()
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--report-url", required=True)
    parser.add_argument("--revision-label", required=True)
    parser.add_argument("--note", default="", help="Appended to the inference text.")
    args = parser.parse_args()
    comparison = Comparison.model_validate_json(
        (args.results / "comparison.json").read_bytes()
    )
    suite = load_suite(args.suite)
    expected = {case.id: case.expected_output for case in suite.cases}
    folder = ROOT / "docs/evidence"
    rows, arms = [], []
    for model in comparison.models:
        report = Report.model_validate_json(
            (args.results / "reports" / f"{model.label}.json").read_bytes()
        )
        if report.run_id != model.run_id:
            raise ValueError(f"{model.label} report does not match the comparison")
        for result in report.results:
            observation = result.observation
            checks = (
                field_checks(expected[result.case_id], observation.actual_output)
                if observation is not None
                else []
            )
            tokens = (
                observation.tokens_in + observation.tokens_out
                if observation is not None and observation.tokens_in is not None
                else None
            )
            rows.append(
                {
                    "row_id": f"{model.label}/{result.case_id}/{result.trial}",
                    "task_id": result.case_id,
                    "family": "incident triage",
                    "trial": result.trial,
                    "arm": model.label,
                    "arm_label": model.label,
                    "attempt_kind": "initial",
                    "outcome": OUTCOMES[result.outcome],
                    "reasons": [
                        check["reason"] for check in checks if not check["passed"]
                    ]
                    or ([result.error] if result.error else []),
                    "usage": {
                        "latency_ms": observation.latency_ms if observation else None,
                        "total_tokens": tokens,
                        "cost_usd": evaluation_cost(model.price, observation),
                        "provenance": "latency_timed_by_the_evaluator_and_tokens_reported_by_the_endpoint",
                    },
                    "checks": checks,
                }
            )
        cost = "unknown" if model.cost_usd is None else f"${model.cost_usd:.4f}"
        median = (
            "unavailable"
            if model.median_latency_ms is None
            else f"{model.median_latency_ms / 1000:.2f} s"
        )
        arms.append(
            {
                "label": model.label,
                "accepted": model.accepted,
                "rejected": model.rejected,
                "planned": model.evaluations,
                "note": f"{model.deployment.capitalize()} {model.model}. Release gate "
                f"{'PASS' if model.passed else 'FAIL'}. {model.tokens_in or 0:,} input and "
                f"{model.tokens_out or 0:,} output tokens. Cost {cost}. Median latency {median}.",
            }
        )
    passing = [model for model in comparison.models if model.passed]
    recommended = next(
        (m for m in comparison.models if m.label == comparison.recommended), None
    )
    evaluations = sum(model.evaluations for model in comparison.models)
    collection = {
        "id": COLLECTION_ID,
        "title": "Local and hosted models on one release suite",
        "kind_label": "MODEL COMPARISON · " + comparison.created_at[:10],
        "description": f"{len(comparison.models)} models ran the same {len(suite.cases)} "
        f"incident triage cases {comparison.trials} times each. The release gate "
        "passes only when every evaluation is accepted. Local models ran on Ollama "
        "at zero dollars per token. The hosted model is priced at its API list price.",
        "revision_label": args.revision_label,
        "latency_label": "Model latency",
        "metrics": [
            {
                "label": "Recommended",
                "value": comparison.recommended or "None",
                "note": "Cheapest model that passed the gate",
            },
            {
                "label": "Passed the gate",
                "value": f"{len(passing)} / {len(comparison.models)}",
                "note": "Every evaluation accepted",
            },
            {
                "label": "Recommended cost",
                "value": "-"
                if recommended is None or recommended.cost_usd is None
                else f"${recommended.cost_usd:.4f}",
                "note": f"For {recommended.evaluations if recommended else 0} evaluations",
            },
            {
                "label": "Evaluations",
                "value": str(evaluations),
                "note": "Same cases and trials per model",
            },
        ],
        "arms": arms,
        "inference": " ".join(filter(None, [comparison.reason, args.note])),
        "download": write(
            folder, "model-comparison.json", comparison.model_dump(mode="json")
        ),
        "report": args.report_url,
        "policy_replay": False,
        "rows_files": [],
    }
    chunks, size = [[]], 0
    for row in rows:
        row_size = len(json_bytes(row)) + 1
        if chunks[-1] and size + row_size > 24000:
            chunks.append([])
            size = 0
        chunks[-1].append(row)
        size += row_size
    for number, chunk in enumerate(chunks, start=1):
        name = f"{COLLECTION_ID}-rows-{number}.json"
        collection["rows_files"].append(write(folder, name, chunk))
    for stale in folder.glob(f"{COLLECTION_ID}-rows-*.json"):
        if "evidence/" + stale.name not in collection["rows_files"]:
            stale.unlink()
    index = json.loads((folder / "index.json").read_bytes())
    index["collections"] = [
        c for c in index["collections"] if c["id"] != COLLECTION_ID
    ] + [collection]
    first_day = index["recorded_at"].split(" to ")[0]
    index["recorded_at"] = f"{first_day} to {comparison.created_at[:10]} UTC"
    write(folder, "index.json", index)
    print(json.dumps({"rows": len(rows), "files": len(collection["rows_files"])}))


if __name__ == "__main__":
    main()
