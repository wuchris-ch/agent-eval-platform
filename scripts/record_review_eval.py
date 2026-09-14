#!/usr/bin/env python3
"""Create a content-minimized, versionable Markdown evaluation record."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=Path("review-agent-eval.json"))
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("benchmarks/reviewer-corpus/v1/corpus.yaml"),
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=Path("benchmarks/reviewer-corpus/v1/benchmark.yaml"),
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--evaluator-commit", required=True)
    parser.add_argument("--reviewer-commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def _load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _chosen_attempt(result: dict[str, Any]) -> dict[str, Any]:
    corrected = result.get("corrected_attempt")
    if isinstance(corrected, dict) and corrected.get("outcome") != "infra_error":
        return corrected
    first = result.get("first_attempt")
    return first if isinstance(first, dict) else {}


def _signature(result: dict[str, Any]) -> tuple[Any, ...]:
    attempt = _chosen_attempt(result)
    output = attempt.get("output") if isinstance(attempt, dict) else None
    if not isinstance(output, dict):
        return (result.get("outcome"), result.get("score"), None)
    findings = output.get("findings")
    finding_signature = (
        tuple(
            sorted(
                (
                    item.get("severity"),
                    item.get("category"),
                    item.get("file"),
                    item.get("line"),
                )
                for item in findings
                if isinstance(item, dict)
            )
        )
        if isinstance(findings, list)
        else ()
    )
    return (
        result.get("outcome"),
        result.get("score"),
        output.get("blocked"),
        finding_signature,
    )


def _cell(result: dict[str, Any]) -> str:
    labels = {"accepted": "pass", "rejected": "fail", "infra_error": "infra"}
    outcome = labels.get(str(result.get("outcome")), "unknown")
    score = result.get("score")
    score_text = "n/a" if not isinstance(score, int | float) else f"{score:.2f}"
    corrected = " corrected" if result.get("corrected_attempt") else ""
    return f"{outcome} {score_text}{corrected}"


def _percent(numerator: int, denominator: int) -> str:
    return "n/a" if denominator == 0 else f"{100 * numerator / denominator:.1f}%"


def build_record(
    report_path: Path,
    corpus_path: Path,
    benchmark_path: Path,
    *,
    model: str,
    evaluator_commit: str,
    reviewer_commit: str,
) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", model):
        raise ValueError("model alias contains unsupported characters")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    corpus = _load(corpus_path)
    benchmark = _load(benchmark_path)
    results = report.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError("report has no results")

    corpus_cases = corpus.get("cases")
    benchmark_cases = benchmark.get("cases")
    if not isinstance(corpus_cases, list) or not isinstance(benchmark_cases, list):
        raise ValueError("corpus metadata is incomplete")
    kind_by_id = {
        str(item["id"]): str(item["kind"])
        for item in corpus_cases
        if isinstance(item, dict) and "id" in item and "kind" in item
    }
    security_blockers = {
        str(item["id"])
        for item in benchmark_cases
        if isinstance(item, dict)
        and any(
            isinstance(expected, dict)
            and expected.get("category") == "security"
            and expected.get("severity") == "blocker"
            for expected in item.get("expected", [])
        )
    }
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in results:
        if not isinstance(raw, dict) or not isinstance(raw.get("case_id"), str):
            raise ValueError("report contains an invalid result")
        by_case[raw["case_id"]].append(raw)
    for case_results in by_case.values():
        case_results.sort(key=lambda item: int(item.get("trial", 0)))

    rounds = max(int(item.get("trial", 0)) for item in results)
    evaluations = len(results)
    infra_errors = sum(item.get("outcome") == "infra_error" for item in results)
    accepted = sum(item.get("outcome") == "accepted" for item in results)
    clean = [
        item for item in results if kind_by_id.get(str(item.get("case_id"))) == "clean"
    ]
    clean_correct = sum(
        item.get("outcome") == "accepted"
        and isinstance((output := _chosen_attempt(item).get("output")), dict)
        and output.get("blocked") is False
        and output.get("findings") == []
        for item in clean
    )
    blocker_runs = [
        item for item in results if str(item.get("case_id")) in security_blockers
    ]
    blocker_hits = sum(
        isinstance((deterministic := _chosen_attempt(item).get("deterministic")), dict)
        and deterministic.get("true_positives", 0) >= 1
        for item in blocker_runs
    )
    stable_cases = sum(
        len({_signature(item) for item in case_results}) == 1
        for case_results in by_case.values()
    )
    first_pass = sum(
        isinstance(item.get("first_attempt"), dict)
        and item["first_attempt"].get("outcome") == "accepted"
        for item in results
    )
    complete_cohort = (
        set(by_case) == set(kind_by_id)
        and all(
            [int(item.get("trial", 0)) for item in case_results] == [1, 2, 3]
            for case_results in by_case.values()
        )
        and report.get("corpus_id") == corpus.get("corpus_id")
        and report.get("corpus_version") == corpus.get("version")
    )
    average_score = sum(float(item.get("score") or 0) for item in results) / evaluations
    report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
    generated = datetime.now(UTC).replace(microsecond=0).isoformat()
    clean_accuracy = _percent(clean_correct, len(clean))
    blocker_recall = _percent(blocker_hits, len(blocker_runs))
    stability = _percent(stable_cases, len(by_case))
    gate_passed = (
        complete_cohort
        and report.get("grade") == "A"
        and average_score >= 0.9
        and infra_errors == 0
        and bool(blocker_runs)
        and blocker_hits == len(blocker_runs)
        and bool(clean)
        and clean_correct / len(clean) >= 0.95
        and stable_cases == len(by_case)
    )

    lines = [
        f"# Reviewer baseline, {generated[:10]}",
        "",
        "This is a content-minimized record of the expanded reviewer corpus run.",
        "Raw model output remains local and is identified by its SHA-256 digest.",
        "",
        "## Run identity",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Recorded at | `{generated}` |",
        f"| Model alias | `{model}` |",
        f"| Corpus | `{report.get('corpus_id')}` `{report.get('corpus_version')}` |",
        f"| Cases | {len(by_case)} |",
        f"| Trial rounds | {rounds} |",
        f"| Evaluations | {evaluations} |",
        f"| Evaluator commit | `{evaluator_commit}` |",
        f"| Reviewer commit | `{reviewer_commit}` |",
        f"| Command SHA-256 | `{report.get('command_sha256')}` |",
        f"| Local raw-report SHA-256 | `{report_sha}` |",
        "",
        "## Summary",
        "",
        "| Metric | Result | Gate |",
        "|---|---:|---:|",
        f"| Overall grade | {report.get('grade')} | A |",
        f"| Average score | {average_score:.3f} | ≥ 0.900 |",
        f"| Complete three-trial corpus | {'yes' if complete_cohort else 'no'} | yes |",
        f"| Accepted evaluations | {accepted}/{evaluations} | Informational |",
        f"| Infrastructure errors | {infra_errors} | 0 |",
        f"| Security-blocker recall | {blocker_recall} ({blocker_hits}/{len(blocker_runs)}) | 100% |",
        f"| Clean-diff accuracy | {clean_accuracy} ({clean_correct}/{len(clean)}) | ≥ 95% |",
        f"| Case stability | {stability} ({stable_cases}/{len(by_case)}) | 100% |",
        f"| First-pass acceptance | {_percent(first_pass, evaluations)} ({first_pass}/{evaluations}) | Informational |",
        "",
        f"**Release gate: {'PASS' if gate_passed else 'FAIL'}**",
        "",
        "## Per-case results",
        "",
        "| Case | Kind | "
        + " | ".join(f"Trial {index}" for index in range(1, rounds + 1))
        + " |",
        "|---|---|" + "---|" * rounds,
    ]
    for case_id, case_kind in kind_by_id.items():
        case_results = by_case.get(case_id, [])
        cells = [_cell(item) for item in case_results]
        cells.extend(["missing"] * (rounds - len(cells)))
        lines.append(f"| `{case_id}` | {case_kind} | " + " | ".join(cells) + " |")
    lines.extend(
        [
            "",
            "## Gate definition",
            "",
            "The release gate requires the complete corpus with three trials per case,",
            "grade A, an average score of at least 0.900, zero infrastructure errors, and",
            "exact detection of every",
            "security-blocker golden, at least 95% clean-diff accuracy, and stable verdicts",
            "across all three trial rounds. DeepEval is intentionally excluded from this",
            "baseline until the deterministic gate is stable.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    args = _args()
    output = build_record(
        args.report,
        args.corpus,
        args.benchmark,
        model=args.model,
        evaluator_commit=args.evaluator_commit,
        reviewer_commit=args.reviewer_commit,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(output, encoding="utf-8")
    print(args.out)


if __name__ == "__main__":
    main()
