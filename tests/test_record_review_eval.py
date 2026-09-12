"""Published release gates must reject incomplete or low-scoring cohorts."""

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

spec = importlib.util.spec_from_file_location(
    "record_review_eval",
    Path(__file__).parents[1] / "scripts" / "record_review_eval.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.mark.parametrize(
    "mutation", ["none", "missing_case", "duplicate_trial", "low_score", "infra"]
)
def test_published_gate_checks_complete_cohort_and_score(tmp_path, mutation):
    corpus = {
        "corpus_id": "fixture",
        "version": "1",
        "cases": [
            {"id": "blocker", "kind": "faulty"},
            {"id": "clean", "kind": "clean"},
        ],
    }
    benchmark = {
        "cases": [
            {
                "id": "blocker",
                "expected": [{"category": "security", "severity": "blocker"}],
            },
            {"id": "clean", "expected": []},
        ]
    }
    results = []
    for case in corpus["cases"]:
        for trial in range(1, 4):
            blocked = case["id"] == "blocker"
            results.append(
                {
                    "case_id": case["id"],
                    "trial": trial,
                    "outcome": "accepted",
                    "score": 1,
                    "first_attempt": {
                        "outcome": "accepted",
                        "deterministic": {"true_positives": int(blocked)},
                        "output": {"blocked": blocked, "findings": []},
                    },
                }
            )
    if mutation == "missing_case":
        results = [r for r in results if r["case_id"] == "blocker"]
    elif mutation == "duplicate_trial":
        results[2]["trial"] = 1
    elif mutation == "low_score":
        for result in results:
            result["score"] = 0.5
    elif mutation == "infra":
        results[0]["outcome"] = "infra_error"
    report = {
        "corpus_id": "fixture",
        "corpus_version": "1",
        "grade": "A",
        "results": results,
    }
    paths = [
        tmp_path / name for name in ("report.json", "corpus.yaml", "benchmark.yaml")
    ]
    paths[0].write_text(json.dumps(report))
    paths[1].write_text(yaml.safe_dump(corpus))
    paths[2].write_text(yaml.safe_dump(benchmark))
    record = module.build_record(
        *paths, model="fixture", evaluator_commit="a" * 40, reviewer_commit="b" * 40
    )
    verdict = "PASS" if mutation == "none" else "FAIL"
    assert f"**Release gate: {verdict}**" in record
