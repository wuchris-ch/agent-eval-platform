"""agent-eval CLI: cluster lifecycle, task management, runs, and reports."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from . import cluster as cluster_mod
from .blackbox.cli import app as blackbox_app
from .candidates.cli import app as candidates_app
from .distributed.cli import app as distributed_app
from .experiments.cli import app as experiments_app
from .report import (
    markdown_report,
    print_run_detail,
    print_runs_table,
    print_trial_summary,
)
from .runner import evaluate_workspace, validate_task
from .task import list_tasks, load_task
from .workbench.cli import app as workbench_app

app = typer.Typer(
    help="Evaluation-only harness for agents through black-box CLI/HTTP interfaces, "
    "recorded outputs, or specialized coding and review benchmarks.",
    no_args_is_help=True,
)
cluster_app = typer.Typer(help="Manage the k3d/k3s cluster.", no_args_is_help=True)
tasks_app = typer.Typer(help="List and validate eval tasks.", no_args_is_help=True)
corpus_app = typer.Typer(
    help="Validate versioned reviewer corpora.", no_args_is_help=True
)
audit_app = typer.Typer(
    help="Verify tamper-evident lifecycle audit trails.", no_args_is_help=True
)
state_app = typer.Typer(
    help="Inspect or explicitly migrate local run state.", no_args_is_help=True
)
scanners_app = typer.Typer(
    help="Prepare and inspect the policy-bound scanner runtime.", no_args_is_help=True
)
app.add_typer(cluster_app, name="cluster")
app.add_typer(tasks_app, name="tasks")
app.add_typer(corpus_app, name="corpus")
app.add_typer(audit_app, name="audit")
app.add_typer(state_app, name="state")
app.add_typer(scanners_app, name="scanners")
app.add_typer(blackbox_app, name="blackbox")
app.add_typer(experiments_app, name="experiment")
app.add_typer(workbench_app, name="workbench")
app.add_typer(distributed_app, name="distributed")
app.add_typer(candidates_app, name="candidate")
console = Console()


def _print_scanner_identity(identity: Any) -> None:
    console.print_json(data=identity.model_dump(mode="json"))


@scanners_app.command("prepare")
def scanners_prepare() -> None:
    """Explicitly hydrate locked scanners and Trivy data for offline runs."""

    from .evaluators.scanners import prepare_scanner_runtime

    try:
        identity = prepare_scanner_runtime()
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]scanner preparation failed: {str(exc)[:1000]}[/red]")
        raise typer.Exit(2) from None
    _print_scanner_identity(identity)
    if not identity.promotion_ready:
        console.print(
            "[red]scanner runtime is not promotion-ready: "
            + ", ".join(identity.promotion_blockers)
            + "[/red]"
        )
        raise typer.Exit(3)
    console.print("[green]scanner runtime is promotion-ready[/green]")


@scanners_app.command("identity")
def scanners_identity() -> None:
    """Print the exact local scanner identity without downloading materials."""

    from .evaluators.scanners import scanner_preflight_assurance_identity

    try:
        identity = scanner_preflight_assurance_identity()
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]scanner identity failed: {str(exc)[:1000]}[/red]")
        raise typer.Exit(2) from None
    _print_scanner_identity(identity)
    if not identity.promotion_ready:
        raise typer.Exit(3)


def _governed_usage_stop_reason(record: Any, limits: Any) -> str | None:
    """Return why another provider call must not start after this trial."""

    observed_tokens = (
        record.efficiency.tokens_in + record.efficiency.tokens_out
        if record.efficiency.tokens_in is not None
        and record.efficiency.tokens_out is not None
        else None
    )
    if observed_tokens is None:
        return "token usage evidence is unavailable"
    if observed_tokens > limits.max_observed_total_tokens:
        return (
            f"observed token usage {observed_tokens} exceeds "
            f"{limits.max_observed_total_tokens}"
        )
    if record.efficiency.cost_usd is None:
        return "cost evidence is unavailable"
    if record.efficiency.cost_usd > limits.max_observed_cost_usd:
        return (
            f"observed cost {record.efficiency.cost_usd} exceeds "
            f"{limits.max_observed_cost_usd}"
        )
    return None


@cluster_app.command("up")
def cluster_up() -> None:
    """Create the k3d cluster and evaluation namespace."""
    cluster_mod.cluster_up()


@cluster_app.command("down")
def cluster_down() -> None:
    """Delete the k3d cluster."""
    cluster_mod.cluster_down()


@cluster_app.command("status")
def cluster_status() -> None:
    """Show cluster nodes and eval pods."""
    cluster_mod.cluster_status()


@state_app.command("path")
def state_path() -> None:
    """Print the active local run-state directory."""

    from .paths import get_state_dir

    console.print(str(get_state_dir()))


@state_app.command("migrate")
def state_migrate(
    source: Path = typer.Option(
        Path("runs"),
        "--from",
        exists=True,
        file_okay=False,
        readable=True,
        resolve_path=False,
        help="Legacy checkout-local runs directory.",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Perform the validated copy; omission is a read-only dry run.",
    ),
) -> None:
    """Dry-run or atomically migrate legacy checkout-local run history."""

    from . import metrics
    from .state import inspect_legacy_state, migrate_legacy_state

    try:
        inventory = inspect_legacy_state(source)
        if not apply:
            console.print(
                "[green]legacy state valid[/green]: "
                f"{inventory.run_count} run(s), {inventory.file_count} file(s), "
                f"{inventory.total_bytes} byte(s); destination {metrics.RUNS_ROOT}"
            )
            console.print("re-run with --apply to migrate")
            return
        migrated = migrate_legacy_state(source, metrics.RUNS_ROOT)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]state migration failed: {str(exc)[:1000]}[/red]")
        raise typer.Exit(2) from None
    console.print(
        f"[green]state migrated[/green]: {migrated.run_count} run(s) to "
        f"{metrics.RUNS_ROOT}"
    )


@tasks_app.command("list")
def tasks_list() -> None:
    """List available tasks."""
    for task in list_tasks():
        console.print(f"[bold]{task.id}[/bold]  ({task.language}, "
                      f"tags: {', '.join(task.tags) or '-'})")


@tasks_app.command("validate")
def tasks_validate(task_id: str) -> None:
    """Require the starter to fail and the oracle solution to pass."""
    task = load_task(task_id)
    cluster_mod.ensure_cluster()
    record = validate_task(task)
    c = record.correctness
    if c.resolved:
        console.print(f"[green]task {task_id} valid[/green]: oracle passes "
                      f"{c.passed}/{c.total} hidden tests")
    else:
        console.print(f"[red]task {task_id} INVALID[/red]: {c.passed}/{c.total} passed, "
                      f"failures: {c.failures or c.infra_error}")
        console.print(f"see {record.run_dir}/eval-output.txt")
        raise typer.Exit(1)


@tasks_app.command("fingerprint")
def tasks_fingerprint(
    task_id: str,
    scan: bool = typer.Option(True, "--scan/--no-scan"),
    judge: bool = typer.Option(True, "--judge/--no-judge"),
    all_recipes: bool = typer.Option(
        False,
        "--all-recipes",
        help="Approve every admissible scanner and judge switch combination.",
    ),
) -> None:
    """Print exact task content and execution-recipe fingerprints."""

    from .runner import _governance_task_evidence

    task = load_task(task_id)
    recipes = (
        [(False, False), (True, False), (True, True)]
        if all_recipes
        else [(scan, judge)]
    )
    tree_digest: str | None = None
    execution_digests = set()
    for run_scans, requested_judge in recipes:
        current_tree, execution_digest = _governance_task_evidence(
            task,
            run_scans=run_scans,
            run_judge=requested_judge and task.judge.enabled,
        )
        if tree_digest is not None and current_tree != tree_digest:
            raise RuntimeError("task changed while its registry entry was generated")
        tree_digest = current_tree
        execution_digests.add(execution_digest)
    assert tree_digest is not None
    console.print_json(
        data={
            "task_id": task.id,
            "task_tree_sha256": tree_digest,
            "execution_spec_digests": sorted(execution_digests),
        }
    )


@corpus_app.command("validate")
def corpus_validate(
    manifest: Path = typer.Argument(..., exists=True, dir_okay=False),
    allow_local_execution: bool = typer.Option(
        False,
        "--allow-local-execution/--no-execute",
        help=(
            "Run trusted base/head reproducers with this user's local filesystem "
            "permissions."
        ),
    ),
) -> None:
    """Statically validate corpus hashes and gold diff locations by default."""
    from .corpus import validate_corpus

    try:
        result = validate_corpus(manifest, execute=allow_local_execution)
    except (OSError, ValueError) as exc:
        console.print(f"[red]could not validate corpus: {exc}[/red]")
        raise typer.Exit(1) from None
    if result.valid:
        console.print(
            f"[green]corpus valid[/green]: {result.corpus_id} v{result.version}, "
            f"{len(result.reproducers)} reproducer(s) checked"
        )
        return
    for error in result.errors:
        console.print(f"[red]{error}[/red]")
    raise typer.Exit(2)


@app.command("eval-review-agent")
def eval_review_agent(
    agent_command: str = typer.Option(
        ...,
        "--command",
        help="Installed review-agent command. Parsed as argv and never run through a shell.",
    ),
    corpus: Path = typer.Option(
        Path("benchmarks/reviewer-corpus/v1/corpus.yaml"),
        "--corpus",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Versioned golden corpus manifest.",
    ),
    case_ids: list[str] = typer.Option(
        [],
        "--case",
        help="Run only this case ID. Repeat the option to select multiple cases.",
    ),
    trials: int = typer.Option(1, "--trials", min=1),
    threshold: float = typer.Option(0.6, "--threshold", min=0.0, max=1.0),
    self_correct: bool = typer.Option(
        True,
        "--self-correct/--no-self-correct",
        help="Allow one corrected attempt after a valid rejected first attempt.",
    ),
    judge: bool = typer.Option(
        False,
        "--judge/--no-judge",
        help="Also score with optional DeepEval GEval through the configured model gateway.",
    ),
    timeout_seconds: float = typer.Option(120, "--timeout", min=0.1),
    diff_file_flag: str = typer.Option(
        None,
        "--diff-file-flag",
        help="Append this flag and a temporary diff path instead of writing the diff to stdin.",
    ),
    out: Path = typer.Option(
        Path("review-agent-eval.json"),
        "--out",
        dir_okay=False,
        help="Evaluation result JSON.",
    ),
) -> None:
    """Evaluate a separately installed review-agent command against goldens."""

    from .external_review_eval import (
        DeepEvalGEvalJudge,
        evaluate_external_review_agent,
        parse_command,
    )

    try:
        command = parse_command(agent_command)
        output_judge = DeepEvalGEvalJudge() if judge else None
        summary = evaluate_external_review_agent(
            corpus_path=corpus,
            command=command,
            case_ids=case_ids,
            trials=trials,
            threshold=threshold,
            self_correct=self_correct,
            timeout_seconds=timeout_seconds,
            diff_file_flag=diff_file_flag,
            judge=output_judge,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]review-agent evaluation failed: {str(exc)[:1000]}[/red]")
        raise typer.Exit(1) from None

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(summary.model_dump_json(indent=2) + "\n", encoding="utf-8")
    table = Table(title="External review-agent evaluation", show_edge=False)
    table.add_column("grade")
    table.add_column("accepted")
    table.add_column("rejected")
    table.add_column("infra errors")
    table.add_column("average score")
    table.add_column("median latency")
    table.add_row(
        summary.grade,
        str(summary.accepted),
        str(summary.rejected),
        str(summary.infra_errors),
        f"{summary.average_score:.3f}",
        (
            f"{summary.median_latency_ms:.1f} ms"
            if summary.median_latency_ms is not None
            else "n/a"
        ),
    )
    console.print(table)
    console.print(f"result: {out}")
    if summary.rejected or summary.infra_errors:
        raise typer.Exit(2)


def _metric(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


@app.command("benchmark-review")
def benchmark_review(
    manifest: Path = typer.Option(
        ..., "--manifest", exists=True, dir_okay=False,
        help="Gold-labeled review benchmark YAML manifest.",
    ),
    reviews: Path = typer.Option(
        ..., "--reviews", file_okay=False,
        help="Directory containing <case-id>.json reviewer outputs.",
    ),
    out: Path = typer.Option(
        None, "--out", dir_okay=False,
        help="Write item-level benchmark results as JSON.",
    ),
    min_precision: float = typer.Option(
        None, "--min-precision", min=0.0, max=1.0,
        help="Fail if aggregate precision is below this value.",
    ),
    min_recall: float = typer.Option(
        None, "--min-recall", min=0.0, max=1.0,
        help="Fail if aggregate recall is below this value.",
    ),
    min_critical_recall: float = typer.Option(
        None, "--min-critical-recall", min=0.0, max=1.0,
        help="Fail if blocker/major recall is below this value.",
    ),
    max_fp_per_case: float = typer.Option(
        None, "--max-fp-per-case", min=0.0,
        help="Fail if average false positives per case exceeds this value.",
    ),
    fail_on_missing: bool = typer.Option(
        True, "--fail-on-missing/--allow-missing",
        help="Fail the regression gate when a case has no complete reviewer output.",
    ),
) -> None:
    """Score reviewer outputs against deterministic, gold-labeled findings."""
    import yaml

    from .review_benchmark import load_manifest, score_benchmark

    for option, threshold in (
        ("--min-precision", min_precision),
        ("--min-recall", min_recall),
        ("--min-critical-recall", min_critical_recall),
        ("--max-fp-per-case", max_fp_per_case),
    ):
        if threshold is not None and not math.isfinite(threshold):
            raise typer.BadParameter("must be finite", param_hint=option)

    try:
        result = score_benchmark(load_manifest(manifest), reviews)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        console.print(f"[red]could not score benchmark: {exc}[/red]")
        raise typer.Exit(1) from None

    metrics = result.metrics
    table = Table(title="AI reviewer benchmark", show_edge=False)
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("cases", str(metrics.case_count))
    table.add_row("complete cases", str(metrics.scored_case_count))
    table.add_row("TP / FP / FN", f"{metrics.tp} / {metrics.fp} / {metrics.fn}")
    table.add_row("precision", _metric(metrics.precision))
    table.add_row("recall", _metric(metrics.recall))
    table.add_row("F1", _metric(metrics.f1))
    table.add_row("blocker + major recall", _metric(metrics.blocker_major_recall))
    table.add_row("severity accuracy", _metric(metrics.severity_accuracy))
    table.add_row("false positives / case", _metric(metrics.false_positives_per_case))
    table.add_row("false positives / KLoC", _metric(metrics.false_positives_per_kloc))
    table.add_row("clean-case accuracy", _metric(metrics.clean_case_accuracy))
    console.print(table)

    unavailable = [
        case.case_id for case in result.cases
        if case.status != "scored"
    ]
    if unavailable:
        console.print(
            f"[yellow]{len(unavailable)} missing or incomplete reviewer "
            "output(s) were scored as zero findings[/yellow]"
        )
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        console.print(f"benchmark result: {out}")

    gates = [
        ("precision", metrics.precision, min_precision, "minimum"),
        ("recall", metrics.recall, min_recall, "minimum"),
        (
            "blocker + major recall",
            metrics.blocker_major_recall,
            min_critical_recall,
            "minimum",
        ),
        (
            "false positives / case",
            metrics.false_positives_per_case,
            max_fp_per_case,
            "maximum",
        ),
    ]
    failures = []
    if unavailable and fail_on_missing:
        failures.append(
            f"{len(unavailable)} benchmark case(s) have no reviewer output "
            "or an incomplete findings payload"
        )
    for name, value, threshold, direction in gates:
        if threshold is None:
            continue
        failed = value is None or (
            value < threshold if direction == "minimum" else value > threshold
        )
        if failed:
            failures.append(
                f"{name} {_metric(value)} does not meet "
                f"{direction} {threshold:.3f}"
            )
    if failures:
        for failure in failures:
            console.print(f"[red]gate failed: {failure}[/red]")
        raise typer.Exit(2)


@app.command("benchmark-experiment")
def benchmark_experiment(
    experiment: Path = typer.Option(
        ..., "--experiment", exists=True, dir_okay=False,
        help="Versioned repeated reviewer experiment YAML.",
    ),
    out: Path = typer.Option(None, "--out", dir_okay=False),
    require_budgets: bool = typer.Option(
        True,
        "--require-budgets/--allow-budget-failures",
        help="Exit 2 when any system is incomplete or exceeds a declared budget.",
    ),
) -> None:
    """Compare repeated single-reviewer and quorum-panel outputs."""
    from .review_experiment import run_experiment

    try:
        result = run_experiment(experiment)
    except (OSError, ValueError) as exc:
        console.print(f"[red]could not run reviewer experiment: {exc}[/red]")
        raise typer.Exit(1) from None
    table = Table(title="Reviewer experiment", show_edge=False)
    for column in ("system", "mode", "trials", "F1", "FP/case", "latency", "tokens", "cost", "stable", "budget"):
        table.add_column(column)
    for system in result.systems:
        stats = system.statistics
        table.add_row(
            system.system_id,
            system.mode,
            str(len(system.trials)),
            _metric(stats.f1.mean),
            _metric(stats.false_positives_per_case.mean),
            _metric(stats.latency_s.mean),
            _metric(stats.tokens.mean),
            _metric(stats.cost_usd.mean),
            _metric(system.finding_stability.mean_jaccard),
            "yes" if system.budget.eligible else "no",
        )
    console.print(table)
    for comparison in result.paired_comparisons:
        console.print(
            f"paired {comparison.candidate_system_id} vs "
            f"{comparison.baseline_system_id}: "
            f"{comparison.wins} win / {comparison.ties} tie / "
            f"{comparison.losses} loss, {comparison.compared_pairs}/"
            f"{comparison.expected_pairs} comparable"
        )
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        console.print(f"experiment result: {out}")
    ineligible = [system for system in result.systems if not system.budget.eligible]
    if require_budgets and ineligible:
        for system in ineligible:
            console.print(
                f"[red]budget failed for {system.system_id}: "
                f"{'; '.join(system.budget.failures)}[/red]"
            )
        raise typer.Exit(2)


@app.command()
def doctor() -> None:
    """Check local prerequisites and show which features each one unlocks."""
    import os
    import shutil as sh

    checks = [
        ("git", sh.which("git") is not None, "task and corpus versioning", "xcode-select --install"),
        ("uv", sh.which("uv") is not None, "locked ruff + semgrep runtime",
         "brew install uv"),
        ("codex CLI", sh.which("codex") is not None, "codex agent target + task judge",
         "npm i -g @openai/codex && codex login"),
        ("codex login", (Path.home() / ".codex" / "auth.json").is_file(),
         "codex auth inside sandbox pods", "codex login"),
        ("ANTHROPIC_API_KEY", bool(os.environ.get("ANTHROPIC_API_KEY")),
         "reusable claude fallback + claude judge", "export ANTHROPIC_API_KEY=..."),
        ("MODEL_GATEWAY_API_KEY", bool(os.environ.get("MODEL_GATEWAY_API_KEY")),
         "optional DeepEval GEval judge", "export MODEL_GATEWAY_API_KEY=..."),
        ("AGENT_EVAL_JUDGE_MODEL", bool(os.environ.get("AGENT_EVAL_JUDGE_MODEL")),
         "optional DeepEval GEval judge", "export AGENT_EVAL_JUDGE_MODEL=..."),
        ("credential broker", bool(os.environ.get("AGENT_EVAL_CREDENTIAL_COMMAND")),
         "provider-minted per-trial credentials (recommended)",
         "export AGENT_EVAL_CREDENTIAL_COMMAND='broker-command'"),
        ("docker", sh.which("docker") is not None, "agent benchmark mode (k3s)",
         "brew install colima docker && colima start"),
        ("kubectl", sh.which("kubectl") is not None, "agent benchmark mode (k3s)",
         "brew install kubectl"),
        ("k3d", sh.which("k3d") is not None, "agent benchmark mode (k3s)",
         "brew install k3d"),
        ("gitleaks", sh.which("gitleaks") is not None,
         "secret gate for task evaluation",
         "brew install gitleaks"),
        ("trivy", sh.which("trivy") is not None, "dependency vuln scanning (optional)",
         "brew install trivy"),
    ]
    table = Table(title="agent-eval doctor")
    for col in ("check", "status", "unlocks", "fix"):
        table.add_column(col)
    for name, ok, unlocks, fix in checks:
        table.add_row(name, "[green]ok[/green]" if ok else "[red]missing[/red]",
                      unlocks, "" if ok else fix)
    console.print(table)
    console.print(
        "\n`agent-eval eval-review-agent` needs a separately installed target "
        "command. Its deterministic score needs no model. `--judge` also needs "
        "the judge extra and generic model-gateway settings. `agent-eval run` "
        "needs docker/kubectl/k3d."
    )


@app.command()
def evaluate(
    task_id: str = typer.Option(..., "--task"),
    workspace: Path = typer.Option(..., "--workspace", exists=True, file_okay=False),
    scan: bool = typer.Option(True, help="Run static/security scanners."),
    judge: bool = typer.Option(True, help="Run the LLM judge."),
    gate: bool = typer.Option(
        False, "--gate", help="Exit 2 unless the task acceptance policy accepts."
    ),
) -> None:
    """Evaluate an already-produced workspace (eval-only mode)."""
    task = load_task(task_id)
    cluster_mod.ensure_cluster()
    record = evaluate_workspace(task, workspace.resolve(),
                                run_scans=scan, run_judge=judge)
    print_run_detail(record.run_id)
    print_runs_table(task_id, limit=5)
    if gate and (record.outcome is None or not record.outcome.accepted):
        raise typer.Exit(2)


def _persist_admission(request, bundle, decision) -> Path:
    """Persist the exact side-effect-free preflight inputs and decision."""

    from . import metrics as metrics_mod
    from .governance import write_canonical_json
    from .paths import ensure_private_directory, secure_run_tree

    ensure_private_directory(metrics_mod.RUNS_ROOT, parents=True)
    admissions = ensure_private_directory(metrics_mod.RUNS_ROOT / "admissions")
    destination = ensure_private_directory(
        admissions / str(decision.decision_id), exist_ok=False
    )
    write_canonical_json(destination / "request.json", request)
    write_canonical_json(destination / "policy-bundle.json", bundle)
    write_canonical_json(destination / "preflight-decision.json", decision)
    secure_run_tree(destination)
    return destination


@app.command()
def run(
    task_id: str = typer.Option(..., "--task"),
    agent: str = typer.Option("claude-code", "--agent"),
    trials: int = typer.Option(1, "--trials", min=1),
    model: str = typer.Option(None, "--model", help="Override the agent's model."),
    rebuild: bool = typer.Option(False, help="Force rebuild of the task image."),
    scan: bool = typer.Option(True, help="Run static/security scanners."),
    judge: bool = typer.Option(True, help="Run the LLM judge."),
    experiment_id: str = typer.Option(
        None, "--experiment-id", help="Pair trials across agents in comparisons."
    ),
    gate: bool = typer.Option(
        False, "--gate", help="Exit 2 if any trial is not accepted."
    ),
    governance_request_path: Path = typer.Option(
        None,
        "--governance-request",
        exists=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="Versioned evaluation request YAML.",
    ),
    governance_policy_path: Path = typer.Option(
        None,
        "--governance-policy",
        exists=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="Versioned policy and approved-model registry YAML.",
    ),
) -> None:
    """Full harness: launch the coding agent in k3s, then evaluate its output."""
    from .agents import get_adapter, is_builtin_adapter
    from .runner import (
        _governance_judge_evidence,
        _governance_network_evidence,
        _governance_scanner_evidence,
        _governance_task_evidence,
        prepare_governed_execution,
        run_agent_trial,
    )

    if (governance_request_path is None) != (governance_policy_path is None):
        console.print(
            "[red]--governance-request and --governance-policy must be supplied "
            "together[/red]"
        )
        raise typer.Exit(2)
    governed = governance_request_path is not None
    if governed:
        try:
            builtin = is_builtin_adapter(agent)
        except ValueError as exc:
            console.print(f"[red]invalid governed adapter: {exc}[/red]")
            raise typer.Exit(2) from None
        if not builtin:
            console.print(
                "[red]governed runs accept only built-in adapters; third-party "
                "plugin code has no policy-bound artifact identity[/red]"
            )
            raise typer.Exit(2)

    task = load_task(task_id)
    if governed and task.evaluation.mode != "isolated-black-box":
        console.print(
            "[red]governed runs require isolated-black-box evaluation; "
            "cooperative test execution cannot authenticate correctness evidence[/red]"
        )
        raise typer.Exit(2)
    adapter = None if governed else get_adapter(agent)
    governance_request = None
    governance_bundle = None
    governance_decision = None
    governance_execution_decision = None
    admission_dir = None
    if governance_request_path is not None and governance_policy_path is not None:
        from .governance import (
            evaluate_admission,
            load_evaluation_request,
            load_governance_bundle,
        )

        try:
            governance_request = load_evaluation_request(governance_request_path)
            governance_bundle = load_governance_bundle(governance_policy_path)
            selected_model = model or governance_request.model
            effective_domains, proxy_image = _governance_network_evidence(
                task, agent
            )
            effective_judge = judge and task.judge.enabled
            judge_backend, judge_model = _governance_judge_evidence(
                task, run_judge=effective_judge
            )
            task_tree_digest, execution_spec_digest = _governance_task_evidence(
                task, run_scans=scan, run_judge=effective_judge
            )
            scanner_identity, scanner_ready = _governance_scanner_evidence(
                run_scans=scan
            )
            governance_decision = evaluate_admission(
                governance_request,
                governance_bundle,
                actual_task_id=task.id,
                actual_agent=agent,
                actual_model=selected_model,
                trials=trials,
                network_mode=task.network.agent_mode,
                agent_timeout_seconds=task.timeouts.agent_seconds,
                eval_timeout_seconds=task.timeouts.eval_seconds,
                broker_configured=bool(os.environ.get("AGENT_EVAL_CREDENTIAL_COMMAND")),
                run_scans=scan,
                scanner_identity_sha256=scanner_identity,
                scanner_promotion_ready=scanner_ready,
                run_judge=effective_judge,
                judge_backend=judge_backend,
                judge_model=judge_model,
                task_tree_sha256=task_tree_digest,
                execution_spec_digest=execution_spec_digest,
                effective_egress_domains=effective_domains,
                proxy_image=proxy_image,
            )
            admission_dir = _persist_admission(
                governance_request, governance_bundle, governance_decision
            )
        except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
            console.print(
                "[red]governance configuration failed: "
                f"{type(exc).__name__}: {str(exc)[:1000]}[/red]"
            )
            raise typer.Exit(2) from None
        console.print(f"admission evidence: {admission_dir}")
        if not governance_decision.allowed:
            console.print("[red]governance denied this evaluation[/red]")
            for reason in governance_decision.reasons:
                console.print(f"[red]{reason.code}: {reason.message}[/red]")
            raise typer.Exit(3)
        model = selected_model
        # Only built-ins can reach this point. Importing and initializing an
        # external entry point before policy approval would execute unbound
        # third-party code in the host trust domain.
        adapter = get_adapter(agent)
        console.print(
            "[green]governance preflight admitted[/green]: "
            f"{governance_decision.policy_id}@"
            f"{governance_decision.policy_revision}, model {model}"
        )
    if (
        governance_request is not None
        and governance_bundle is not None
        and governance_decision is not None
    ):
        assert adapter is not None
        try:
            governance_execution_decision = prepare_governed_execution(
                task,
                agent=adapter.name,
                model=model,
                run_scans=scan,
                run_judge=judge,
                request=governance_request,
                bundle=governance_bundle,
                preflight_decision=governance_decision,
            )
            assert admission_dir is not None
            from .governance import write_canonical_json

            write_canonical_json(
                admission_dir / "execution-decision.json",
                governance_execution_decision,
            )
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            console.print(
                "[red]governed image preparation failed: "
                f"{type(exc).__name__}: {str(exc)[:1000]}[/red]"
            )
            raise typer.Exit(2) from None
    else:
        cluster_mod.ensure_cluster()
    assert adapter is not None
    records = []
    for trial in range(1, trials + 1):
        console.rule(f"trial {trial}/{trials}")
        record = run_agent_trial(
            task,
            adapter,
            trial=trial,
            model=model,
            run_scans=scan,
            run_judge=judge,
            rebuild=rebuild and trial == 1,
            experiment_id=experiment_id,
            governance_request=governance_request,
            governance_bundle=governance_bundle,
            governance_decision=governance_decision,
            governance_execution_decision=(governance_execution_decision),
        )
        records.append(record)
        status = "resolved" if record.correctness.resolved else "not resolved"
        console.print(
            f"trial {trial}: [bold]{status}[/bold] "
            f"({record.correctness.passed}/{record.correctness.total} tests)"
        )
        if governance_execution_decision is not None and trial < trials:
            limits = governance_execution_decision.effective_limits
            stop_reason = _governed_usage_stop_reason(record, limits)
            if stop_reason is not None:
                console.print(
                    "[yellow]stopping before the next governed trial: "
                    f"{stop_reason}[/yellow]"
                )
                break
    print_runs_table(task_id, limit=trials + 5)
    print_trial_summary(records)
    if gate and any(
        record.outcome is None or not record.outcome.accepted for record in records
    ):
        raise typer.Exit(2)


@app.command("compare")
def compare(
    task_id: str = typer.Option(..., "--task"),
    out: Path = typer.Option(None, "--out", dir_okay=False),
    limit: int = typer.Option(1000, "--limit", min=1),
    include_controls: bool = typer.Option(
        False,
        "--include-controls",
        help="Include oracle and external eval-only records.",
    ),
) -> None:
    """Compare persisted coding-agent outcomes by agent and model."""
    from .agent_comparison import compare_agents
    from .metrics import RunRecord, load_runs

    records = [
        RunRecord.model_validate_json(row["results_json"])
        for row in load_runs(task_id, limit)
    ]
    if not include_controls:
        records = [
            record for record in records
            if record.agent not in {"external", "oracle"}
        ]
    if not records:
        console.print("[yellow]no runs recorded yet[/yellow]")
        return
    result = compare_agents(records)
    table = Table(title="Coding-agent comparison", show_edge=False)
    for column in (
        "cohort", "agent/model", "n", "resolved", "accepted", "95% CI", "infra",
        "time p50/p95", "tokens p50", "cost p50", "judge p50",
    ):
        table.add_column(column)
    for summary in result.summaries:
        interval = summary.resolved_wilson_95
        table.add_row(
            (
                summary.cohort.cohort_id[:12]
                if summary.cohort.binding == "bound"
                else f"unbound/{summary.cohort.cohort_id[:8]}"
            ),
            f"{summary.agent}/{summary.model}",
            str(summary.sample_size),
            (
                f"{summary.resolved}/{summary.correctness_evidence_count} "
                f"({summary.resolved_rate:.1%})"
                if summary.resolved_rate is not None
                else "n/a (legacy evidence incomplete)"
            ),
            (
                f"{summary.accepted}/{summary.accepted_evidence_count} "
                f"({summary.accepted_rate:.1%})"
                if summary.accepted_rate is not None
                else "n/a"
            ),
            (
                f"{interval.lower:.1%}..{interval.upper:.1%}"
                if interval else "n/a"
            ),
            f"{summary.infrastructure_failure_rate:.1%}",
            f"{_metric(summary.wall_time_s.median)}/{_metric(summary.wall_time_s.p95)}",
            _metric(summary.total_tokens.median),
            _metric(summary.cost_usd.median),
            _metric(summary.judge_score.median),
        )
    console.print(table)
    if not result.paired:
        console.print(
            "[yellow]no paired comparison: use the same --experiment-id and "
            "trial numbers for each agent within one bound evaluation cohort[/yellow]"
        )
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        console.print(f"comparison result: {out}")


@audit_app.command("verify")
def audit_verify(
    path: Path = typer.Option(
        None,
        "--file",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Audit JSONL file to verify.",
    ),
    run_id: str = typer.Option(
        None, "--run", help="Load audit evidence from a persisted run."
    ),
    expected_final_hash: str = typer.Option(
        None, "--expected-final-hash", help="Expected terminal event hash."
    ),
    expected_run_id: str = typer.Option(
        None, "--expected-run-id", help="Expected run identifier."
    ),
) -> None:
    """Verify canonical bytes, event hashes, ordering, run, and trace continuity."""
    from .attestation import read_regular_file
    from .audit import verify_audit_chain
    from .metrics import load_run

    record = None
    if (path is None) == (run_id is None):
        console.print("[red]supply exactly one of --file or --run[/red]")
        raise typer.Exit(2)
    if run_id is not None:
        try:
            record = load_run(run_id, forbid_extra=True)
        except ValueError as exc:
            console.print(
                f"[red]persisted run schema is invalid: {str(exc)[:1000]}[/red]"
            )
            raise typer.Exit(2) from None
        if record is None:
            console.print(f"[red]run {run_id} not found[/red]")
            raise typer.Exit(1)
        path = record.run_dir / "audit.jsonl"
        expected_final_hash = expected_final_hash or record.provenance.audit_final_hash
        expected_run_id = expected_run_id or record.run_id
    assert path is not None
    try:
        audit_data = read_regular_file(path, label="audit trail")
    except (OSError, UnicodeError, ValueError) as exc:
        message = str(exc)[:1000]
        code = (
            "symlink_rejected"
            if "must not be a symlink" in message
            else "file_unreadable"
        )
        console.print(f"[red]{code}: {message}[/red]")
        raise typer.Exit(2) from None
    audit_snapshot = tempfile.NamedTemporaryFile(
        prefix="agent-eval-audit-snapshot-", suffix=".jsonl"
    )
    audit_snapshot.write(audit_data)
    audit_snapshot.flush()
    verified_path = Path(audit_snapshot.name)
    result = verify_audit_chain(
        verified_path,
        expected_final_hash=expected_final_hash,
        expected_run_id=expected_run_id,
    )
    semantic_failures: list[str] = []
    if result.ok and record is not None:
        if record.provenance.audit_error:
            semantic_failures.append(record.provenance.audit_error)
        expected_fields = (
            record.provenance.audit_trace_id,
            record.provenance.audit_final_hash,
            record.provenance.audit_event_count,
        )
        if any(value is None for value in expected_fields):
            semantic_failures.append("recorded audit evidence is incomplete")
        if result.trace_id != record.provenance.audit_trace_id:
            semantic_failures.append("audit trace ID does not match results")
        if result.final_hash != record.provenance.audit_final_hash:
            semantic_failures.append("audit final hash does not match results")
        if result.event_count != record.provenance.audit_event_count:
            semantic_failures.append("audit event count does not match results")
        if (
            record.governance is not None
            and result.trace_id != record.governance.trace_id
        ):
            semantic_failures.append(
                "audit trace ID does not match governance decision"
            )
        try:
            semantic_failures.extend(_audit_lifecycle_failures(record, verified_path))
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
            semantic_failures.append(
                f"audit lifecycle is unreadable: {str(exc)[:1000]}"
            )
    if semantic_failures:
        for failure in semantic_failures:
            console.print(f"[red]{failure}[/red]")
        raise typer.Exit(2)
    if result.ok:
        console.print(
            f"[green]verified[/green]: {result.event_count} event(s), "
            f"trace {result.trace_id}, final hash {result.final_hash}"
        )
        return
    for failure in result.failures:
        location = f" line {failure.line}" if failure.line is not None else ""
        console.print(f"[red]{failure.code}{location}: {failure.message}[/red]")
    raise typer.Exit(2)


def _audit_lifecycle_failures(record, audit_path: Path) -> list[str]:
    """Check lifecycle meaning after byte-level chain verification succeeds."""

    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    event_types = [event["event_type"] for event in events]
    failures = []

    def single_attributes(event_type: str) -> dict | None:
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


def _decision_replay_view(decision) -> dict:
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


@app.command("verify-run")
def verify_run(
    run_id: str = typer.Option(..., "--run"),
) -> None:
    """Recompute attestation, audit, and governance evidence for one run."""
    from .assessments import derive_assessments
    from .attestation import verify_attestation
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

    try:
        record = load_run(
            run_id,
            forbid_extra=True,
            validate_assessments=True,
        )
    except ValueError as exc:
        console.print(f"[red]persisted run schema is invalid: {str(exc)[:1000]}[/red]")
        raise typer.Exit(2) from None
    if record is None:
        console.print(f"[red]run {run_id} not found[/red]")
        raise typer.Exit(1)
    statement = record.run_dir / "attestation.json"
    if not statement.is_file():
        console.print(f"[red]run {run_id} has no attestation[/red]")
        raise typer.Exit(2)
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
        for failure in failures:
            console.print(f"[red]{failure}[/red]")
        raise typer.Exit(2)
    try:
        disk_record = RunRecord.model_validate_json(results_data, extra="forbid")
    except (UnicodeError, ValueError) as exc:
        failures.append(f"results_invalid: {str(exc)[:1000]}")
        for failure in failures:
            console.print(f"[red]{failure}[/red]")
        raise typer.Exit(2) from None
    if disk_record.model_dump(mode="json") != record.model_dump(mode="json"):
        failures.append("results_mismatch: SQLite and results.json differ")
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
            failures.append(
                "governed correctness evidence is not isolated-black-box"
            )
        scanner_error = _governed_scanner_assurance_error(
            disk_record,
            require_evidence=(
                disk_record.outcome is None
                or disk_record.outcome.status != "infra_error"
            ),
        )
        if scanner_error is not None:
            failures.append(scanner_error)

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
                failures.extend(_audit_lifecycle_failures(disk_record, audit_path))
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
                snapshots = {
                    name: _verified_subject_snapshot(
                        result, disk_record.run_dir, name, failures
                    )
                    for name in semantic_names
                }
                if any(value is None for value in snapshots.values()):
                    raise ValueError("governance artifact snapshot is unverified")
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
                    or disk_record.trial > preflight_trials
                    or disk_record.trial > execution_trials
                ):
                    failures.append("run trial is not covered by both decisions")
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
                    trials=preflight_decision.sanitized_input.get("trials"),
                    network_mode=verified_task.network.agent_mode,
                    agent_timeout_seconds=verified_task.timeouts.agent_seconds,
                    eval_timeout_seconds=verified_task.timeouts.eval_seconds,
                    broker_configured=preflight_decision.sanitized_input.get(
                        "broker_configured"
                    ),
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
                    trials=decision.sanitized_input.get("trials"),
                    network_mode=verified_task.network.agent_mode,
                    agent_timeout_seconds=verified_task.timeouts.agent_seconds,
                    eval_timeout_seconds=verified_task.timeouts.eval_seconds,
                    broker_configured=decision.sanitized_input.get("broker_configured"),
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
        console.print(
            "[yellow]legacy run: no governed lifecycle audit was recorded[/yellow]"
        )

    recomputed_assessments = derive_assessments(disk_record, effective_task)
    if [
        assessment.model_dump(mode="json")
        for assessment in disk_record.assessments
    ] != [
        assessment.model_dump(mode="json")
        for assessment in recomputed_assessments
    ]:
        failures.append(
            "normalized assessment envelope does not recompute from run evidence"
        )

    recomputed_outcome = evaluate_outcome(disk_record, effective_task.acceptance)
    if disk_record.outcome is None or (
        disk_record.outcome.model_dump(mode="json")
        != recomputed_outcome.model_dump(mode="json")
    ):
        failures.append("recorded outcome does not recompute from run evidence")

    if failures:
        for failure in failures:
            console.print(f"[red]{failure}[/red]")
        raise typer.Exit(2)
    console.print(
        f"[green]verified[/green]: {result.subjects_checked} artifact(s), "
        "task tree, harness Git state, governance, and lifecycle evidence match"
    )


@app.command()
def report(
    task_id: str = typer.Option(None, "--task"),
    run_id: str = typer.Option(None, "--run"),
    markdown: Path = typer.Option(None, "--markdown", help="Write a markdown report here."),
    limit: int = typer.Option(50, "--limit"),
) -> None:
    """Show recorded runs, one run's full results, or export markdown."""
    if run_id:
        print_run_detail(run_id)
        return
    if markdown:
        markdown.write_text(markdown_report(task_id, limit))
        console.print(f"wrote {markdown}")
        return
    print_runs_table(task_id, limit)


if __name__ == "__main__":
    app()
