"""Terminal and markdown reporting over the SQLite run store."""

from __future__ import annotations

from math import comb

from rich.console import Console
from rich.table import Table

from .metrics import RunRecord, load_run, load_runs

console = Console()


def _fmt(value, suffix: str = "") -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:g}{suffix}"
    return f"{value}{suffix}"


def _correctness_observed(record: RunRecord) -> bool:
    return (
        record.correctness.command_exit_code is not None
        and record.correctness.infra_error is None
        and record.efficiency.infra_error is None
        and (record.outcome is None or record.outcome.status != "infra_error")
    )


def print_runs_table(task_id: str | None = None, limit: int = 50) -> None:
    rows = load_runs(task_id, limit)
    if not rows:
        console.print("[yellow]no runs recorded yet[/yellow]")
        return
    table = Table(title="agent-eval runs", show_lines=False)
    for col in (
        "run id",
        "agent",
        "outcome",
        "resolved",
        "tests",
        "cov%",
        "time s",
        "cost $",
        "tokens",
        "turns",
        "diff +/-",
        "judge",
    ):
        table.add_column(col)
    for r in rows:
        record = RunRecord.model_validate_json(r["results_json"])
        if (
            record.correctness.infra_error is not None
            or record.efficiency.infra_error is not None
            or (record.outcome is not None and record.outcome.status == "infra_error")
        ):
            resolved = "[yellow]n/a (infra)[/yellow]"
        elif record.correctness.command_exit_code is None:
            resolved = "[yellow]unknown (legacy)[/yellow]"
        else:
            resolved = (
                "[green]yes[/green]" if record.correctness.resolved else "[red]no[/red]"
            )
        outcome = record.outcome.status if record.outcome else "legacy"
        tokens = (
            f"{r['tokens_in']}/{r['tokens_out']}" if r["tokens_in"] is not None else "-"
        )
        table.add_row(
            r["run_id"],
            r["agent"],
            outcome,
            resolved,
            f"{_fmt(r['tests_passed'])}/{_fmt(r['tests_total'])}",
            _fmt(r["coverage"]),
            _fmt(r["wall_time_s"]),
            _fmt(r["cost_usd"]),
            tokens,
            _fmt(r["turns"]),
            f"+{r['diff_added']}/-{r['diff_removed']}",
            _fmt(r["judge_score"]),
        )
    console.print(table)


def print_run_detail(run_id: str) -> None:
    record = load_run(run_id)
    if record is None:
        console.print(f"[red]run {run_id} not found[/red]")
        return
    console.print_json(record.model_dump_json())


def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k estimator (Chen et al. 2021): n trials, c successes."""
    if any(
        isinstance(value, bool) or not isinstance(value, int) for value in (n, c, k)
    ):
        raise TypeError("pass@k inputs must be integers")
    if n <= 0 or c < 0 or c > n or k <= 0 or k > n:
        raise ValueError("pass@k requires 0 <= c <= n and 1 <= k <= n")
    if n - c < k:
        return 1.0
    return 1.0 - comb(n - c, k) / comb(n, k)


def print_trial_summary(records: list[RunRecord], k: int = 1) -> None:
    evaluable = [record for record in records if _correctness_observed(record)]
    n = len(evaluable)
    c = sum(1 for record in evaluable if record.correctness.resolved)
    accepted = sum(
        r.outcome is not None and r.outcome.status == "accepted" for r in records
    )
    rejected = sum(
        r.outcome is not None and r.outcome.status == "rejected" for r in records
    )
    infra = sum(
        r.outcome is not None and r.outcome.status == "infra_error" for r in records
    )
    pass_estimate = f"{pass_at_k(n, c, k):.2f}" if n >= k else "n/a"
    console.print(
        f"\ntrials: {len(records)}  correctness observed: {n}  resolved: {c}  "
        f"pass@{k}: {pass_estimate}  "
        f"outcomes accepted/rejected/infra: {accepted}/{rejected}/{infra}"
    )


def markdown_report(task_id: str | None = None, limit: int = 50) -> str:
    rows = load_runs(task_id, limit)
    lines = [
        "# agent-eval report",
        "",
        "| run id | agent | outcome | resolved | tests | cov% | time s | cost $ | tokens in/out | turns | diff | judge |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        record = RunRecord.model_validate_json(r["results_json"])
        resolved = (
            "n/a (infra)"
            if (
                record.correctness.infra_error is not None
                or record.efficiency.infra_error is not None
                or (
                    record.outcome is not None
                    and record.outcome.status == "infra_error"
                )
            )
            else "yes"
            if record.correctness.resolved
            else "no"
            if record.correctness.command_exit_code is not None
            else "unknown (legacy)"
        )
        outcome = record.outcome.status if record.outcome else "legacy"
        tokens = (
            f"{r['tokens_in']}/{r['tokens_out']}" if r["tokens_in"] is not None else "-"
        )
        lines.append(
            f"| {r['run_id']} | {r['agent']} | {outcome} | {resolved} "
            f"| {_fmt(r['tests_passed'])}/{_fmt(r['tests_total'])} | {_fmt(r['coverage'])} "
            f"| {_fmt(r['wall_time_s'])} | {_fmt(r['cost_usd'])} | {tokens} "
            f"| {_fmt(r['turns'])} | +{r['diff_added']}/-{r['diff_removed']} "
            f"| {_fmt(r['judge_score'])} |"
        )
    return "\n".join(lines) + "\n"
