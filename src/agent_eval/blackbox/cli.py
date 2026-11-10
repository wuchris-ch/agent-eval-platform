"""CLI for evaluating arbitrary agents without importing their implementation."""

from __future__ import annotations

import os
import shlex
import uuid
from datetime import UTC, datetime
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console

from ..limits import MAX_RESULTS_JSON_BYTES, read_stable_bounded_file
from ..paths import atomic_write_private, ensure_private_directory, get_state_dir
from .comparison import (
    ModelSpec,
    compare,
    load_plan,
    model_target,
    render_markdown,
)
from .inspection import (
    InspectionEvidence,
    finish_evidence,
    inspect_report,
    prepare_inspection,
)
from .models import (
    Case,
    Metric,
    Report,
    Suite,
    digest,
    json_bytes,
    load_suite,
    parse_json,
)
from .runner import evaluate
from .scoring import DeepEvalJudge
from .storage import load_database_observations, load_observations, save_report
from .targets import CommandTarget, HttpTarget, ModelTarget, ResponseDecoder, Target
from .telemetry import export_report

app = typer.Typer(
    help="Black-box evaluation through CLI, HTTP, or recorded observations.",
    no_args_is_help=True,
)
console = Console()


def _failure(context: str, exc: Exception):
    console.print(
        f"{context} failed ({type(exc).__name__}).", style="red", markup=False
    )
    if isinstance(exc, ValidationError):
        for error in exc.errors(
            include_input=False, include_url=False, include_context=False
        )[:10]:
            # No raw values, database exceptions, URLs, commands, or judge responses.
            console.print(f"Schema error: {error['type']}", markup=False)
    raise typer.Exit(1) from None


def _finish(suite: Suite, report: Report, evidence: InspectionEvidence | None = None):
    try:
        path = save_report(suite, report, evidence=evidence)
    except Exception as exc:
        _failure("Saving private run artifacts", exc)
    exported = export_report(report)
    console.print(
        f"{'PASS' if report.passed else 'FAIL'}  "
        f"accepted={report.accepted}/{report.evaluations}  rejected={report.rejected}  "
        f"infra_errors={report.infra_errors}  score={report.average_score:.3f}",
        markup=False,
    )
    if report.tokens_in is not None:
        console.print(
            f"Tokens: in={report.tokens_in} out={report.tokens_out}", markup=False
        )
    for result in report.results:
        if result.error:
            console.print(
                f"Trial {result.trial}, case {digest(result.case_id)[:12]}: {result.error}",
                markup=False,
            )
    if report.inspection is not None:
        for label, summary in (
            ("Source", report.inspection.source),
            ("Trace", report.inspection.trace),
        ):
            console.print(
                f"{label}: {summary.status}, accepted={summary.accepted}, rejected={summary.rejected}, unavailable={summary.unavailable}",
                markup=False,
            )
        for result in report.inspection.results:
            if result.error:
                console.print(
                    f"Inspection check {digest(result.name)[:12]}: {result.error}",
                    markup=False,
                )
        console.print(
            f"Overall: {'PASS' if report.overall_passed else 'FAIL'} (inspection {'required' if report.inspection.required else 'advisory'})",
            markup=False,
        )
    console.print(f"Report: {path}", markup=False)
    console.print(
        f"Telemetry: {'exported' if exported else 'disabled or unavailable'}",
        markup=False,
    )
    if not report.overall_passed:
        raise typer.Exit(2)


def _judge(
    suite: Suite,
    enabled: bool,
    evidence: InspectionEvidence | None = None,
    *,
    include_output: bool = True,
):
    needed = (
        include_output
        and any(
            metric.kind == "geval"
            for case in suite.cases
            for metric in case.metrics or suite.metrics
        )
    ) or (
        evidence is not None
        and any(check.kind.endswith("geval") for check in evidence.profile.checks)
    )
    if needed and not enabled:
        console.print(
            "The requested checks require GEval. Install the judge extra, configure the gateway, and add --judge.",
            markup=False,
        )
        raise typer.Exit(1)
    return DeepEvalJudge() if needed else None


def _inspection_setup(
    profile: Path | None, source_root: Path | None, traces: Path | None, required: bool
):
    if profile is None:
        if source_root is not None or traces is not None or required:
            raise ValueError(
                "--source-root, --traces, and --require-inspection require --inspection"
            )
        return None
    evidence = prepare_inspection(profile, source_root)
    if traces is not None and all(
        check.kind.startswith("source_") for check in evidence.profile.checks
    ):
        raise ValueError("the profile does not contain trace checks")
    return evidence


def _inspect(suite, report, evidence, source_root, traces, required, judge):
    if evidence is None:
        return report
    finish_evidence(evidence, source_root, traces)
    return inspect_report(suite, report, evidence, required=required, judge=judge)


@app.command("validate")
def validate(
    suite_path: Path = typer.Option(..., "--suite", exists=True, dir_okay=False),
):
    """Validate a generated or authored suite without invoking any agent."""
    try:
        suite = load_suite(suite_path)
    except Exception as exc:
        _failure("Suite validation", exc)
    console.print(
        f"Valid: {len(suite.cases)} cases, sha256={digest(suite.model_dump(mode='json'))}",
        markup=False,
    )


@app.command("run")
def run(
    suite_path: Path = typer.Option(..., "--suite", exists=True, dir_okay=False),
    agent: str = typer.Option(
        ..., "--agent", help="Your label for the agent/version under test."
    ),
    command: str | None = typer.Option(
        None, "--command", help="Argv command; use absolute script paths. No shell."
    ),
    url_env: str | None = typer.Option(
        None,
        "--url-env",
        help="Environment variable containing an HTTP endpoint, or the base URL "
        "of an OpenAI-compatible API when --model is set.",
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        help="Evaluate this model through the OpenAI-compatible API in --url-env, "
        "for example a local Ollama server at http://127.0.0.1:11434/v1.",
    ),
    system_prompt: Path | None = typer.Option(
        None,
        "--system-prompt",
        exists=True,
        dir_okay=False,
        help="File sent as the system message to a --model target.",
    ),
    token_env: str | None = typer.Option(
        None,
        "--token-env",
        help="Environment variable containing an optional bearer token.",
    ),
    response_format: str = typer.Option(
        "text", "--response-format", help="text or json"
    ),
    response_pointer: str | None = typer.Option(
        None,
        "--response-pointer",
        help="JSON Pointer to the native answer, e.g. /answer.",
    ),
    pass_env: list[str] = typer.Option(
        [],
        "--pass-env",
        help="Allow this environment variable into the command. Repeatable.",
    ),
    timeout: float = typer.Option(120, "--timeout", min=0.01),
    trials: int = typer.Option(1, "--trials", min=1),
    judge: bool = typer.Option(
        False,
        "--judge",
        help="Enable required GEval metrics through the configured model gateway.",
    ),
    inspection: Path | None = typer.Option(
        None,
        "--inspection",
        exists=True,
        dir_okay=False,
        help="Optional source/trace check profile.",
    ),
    source_root: Path | None = typer.Option(
        None,
        "--source-root",
        help="Agent repository to snapshot; code is never executed by inspection.",
    ),
    traces: Path | None = typer.Option(
        None,
        "--traces",
        help="Normalized JSONL or OTLP JSON export, read after execution.",
    ),
    require_inspection: bool = typer.Option(
        False,
        "--require-inspection",
        help="Also require all internal checks for the overall gate.",
    ),
):
    """Send only case inputs to a CLI or HTTP agent, then grade its native response."""
    if (
        (command is None) == (url_env is None)
        or (command is not None and token_env)
        or (url_env and pass_env)
        or (system_prompt is not None and model is None)
        or (model is not None and response_pointer is not None)
    ):
        console.print(
            "Choose --command or --url-env. --pass-env is for commands; --token-env is for HTTP. "
            "--model needs --url-env; --system-prompt needs --model; --response-pointer is not used with --model.",
            markup=False,
        )
        raise typer.Exit(1)
    try:
        suite = load_suite(suite_path)
        evidence = _inspection_setup(
            inspection, source_root, traces, require_inspection
        )
        output_judge = _judge(suite, judge, evidence)
        decoder = ResponseDecoder(response_format, response_pointer)
        target: CommandTarget | HttpTarget | ModelTarget
        if command is not None:
            target = CommandTarget(
                shlex.split(command),
                timeout=timeout,
                decoder=decoder,
                env_names=pass_env,
            )
        elif model is not None:
            target = ModelTarget(
                os.environ[url_env],
                model,
                system_prompt=system_prompt.read_text("utf-8")
                if system_prompt
                else None,
                response_format=response_format,
                timeout=timeout,
                api_key=os.environ[token_env] if token_env else None,
            )
        else:
            target = HttpTarget(
                os.environ[url_env],
                timeout=timeout,
                decoder=decoder,
                bearer_token=os.environ[token_env] if token_env else None,
            )
        report = evaluate(
            suite, agent=agent, target=target, trials=trials, judge=output_judge
        )
        report = _inspect(
            suite,
            report,
            evidence,
            source_root,
            traces,
            require_inspection,
            output_judge,
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _failure("Evaluation configuration or execution", exc)
    _finish(suite, report, evidence)


@app.command("replay")
def replay(
    suite_path: Path = typer.Option(..., "--suite", exists=True, dir_okay=False),
    observations: Path = typer.Option(
        ..., "--observations", exists=True, dir_okay=False
    ),
    agent: str = typer.Option(..., "--agent"),
    trials: int = typer.Option(1, "--trials", min=1),
    judge: bool = typer.Option(False, "--judge"),
    inspection: Path | None = typer.Option(
        None, "--inspection", exists=True, dir_okay=False
    ),
    source_root: Path | None = typer.Option(None, "--source-root"),
    traces: Path | None = typer.Option(None, "--traces"),
    require_inspection: bool = typer.Option(False, "--require-inspection"),
):
    """Evaluate recorded JSONL outputs without invoking the target again."""
    try:
        suite = load_suite(suite_path)
        evidence = _inspection_setup(
            inspection, source_root, traces, require_inspection
        )
        output_judge = _judge(suite, judge, evidence)
        report = evaluate(
            suite,
            agent=agent,
            observations=load_observations(observations),
            trials=trials,
            judge=output_judge,
        )
        report = _inspect(
            suite,
            report,
            evidence,
            source_root,
            traces,
            require_inspection,
            output_judge,
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _failure("Observation replay", exc)
    _finish(suite, report, evidence)


@app.command("replay-db")
def replay_db(
    suite_path: Path = typer.Option(..., "--suite", exists=True, dir_okay=False),
    query: Path = typer.Option(..., "--query", exists=True, dir_okay=False),
    agent: str = typer.Option(..., "--agent"),
    sqlite: Path | None = typer.Option(None, "--sqlite", exists=True, dir_okay=False),
    dsn_env: str | None = typer.Option(
        None, "--dsn-env", help="Environment variable holding a read-only Postgres DSN."
    ),
    trials: int = typer.Option(1, "--trials", min=1),
    judge: bool = typer.Option(False, "--judge"),
    inspection: Path | None = typer.Option(
        None, "--inspection", exists=True, dir_okay=False
    ),
    source_root: Path | None = typer.Option(None, "--source-root"),
    traces: Path | None = typer.Option(None, "--traces"),
    require_inspection: bool = typer.Option(False, "--require-inspection"),
):
    """Read final agent observations from a proxy/application database and evaluate them."""
    try:
        suite = load_suite(suite_path)
        evidence = _inspection_setup(
            inspection, source_root, traces, require_inspection
        )
        output_judge = _judge(suite, judge, evidence)
        observations = load_database_observations(
            query,
            sqlite_path=sqlite,
            postgres_dsn=os.environ[dsn_env] if dsn_env else None,
        )
        report = evaluate(
            suite,
            agent=agent,
            observations=observations,
            trials=trials,
            judge=output_judge,
        )
        report = _inspect(
            suite,
            report,
            evidence,
            source_root,
            traces,
            require_inspection,
            output_judge,
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _failure(
            "Database replay; check read access and the documented query columns", exc
        )
    _finish(suite, report, evidence)


@app.command("inspect")
def inspect_saved(
    report_path: Path = typer.Option(..., "--report", exists=True, dir_okay=False),
    inspection: Path = typer.Option(..., "--inspection", exists=True, dir_okay=False),
    source_root: Path | None = typer.Option(None, "--source-root"),
    traces: Path | None = typer.Option(None, "--traces"),
    require_inspection: bool = typer.Option(False, "--require-inspection"),
    judge: bool = typer.Option(False, "--judge"),
):
    """Inspect a saved run without invoking the agent or regrading its output."""
    try:
        suite = load_suite(report_path.parent / "suite.json")
        report = Report.model_validate(
            parse_json(
                read_stable_bounded_file(
                    report_path, maximum_bytes=MAX_RESULTS_JSON_BYTES
                )
            )
        )
        evidence = _inspection_setup(
            inspection, source_root, traces, require_inspection
        )
        output_judge = _judge(suite, judge, evidence, include_output=False)
        report = _inspect(
            suite,
            report,
            evidence,
            source_root,
            traces,
            require_inspection,
            output_judge,
        )
        report = Report.model_validate(
            report.model_dump(mode="json")
            | {
                "parent_run_id": report.run_id,
                "run_id": str(uuid.uuid4()),
                "created_at": datetime.now(UTC).isoformat(),
            }
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _failure("Saved-run inspection", exc)
    _finish(suite, report, evidence)


@app.command("import-goldens")
def import_goldens(
    goldens: Path = typer.Option(..., "--goldens", exists=True, dir_okay=False),
    suite_id: str = typer.Option(..., "--suite-id"),
    version: str = typer.Option(..., "--version"),
    kind: str = typer.Option(
        "exact_match", "--metric", help="exact_match, contains, json_subset, or geval"
    ),
    criteria: str | None = typer.Option(None, "--criteria", help="Required for geval."),
    threshold: float = typer.Option(1.0, "--threshold", min=0, max=1),
):
    """Freeze a generated [{id,input,expected_output,tags?}] file as a versioned suite."""
    try:
        raw = read_stable_bounded_file(goldens, maximum_bytes=MAX_RESULTS_JSON_BYTES)
        values = parse_json(raw)
        if not isinstance(values, list):
            raise ValueError("goldens must be a JSON array")
        suite = Suite(
            schema_version="1.0",
            id=suite_id,
            version=version,
            metrics=[
                Metric(name=kind, kind=kind, criteria=criteria, threshold=threshold)
            ],
            cases=[Case.model_validate(value) for value in values],
        )
        root = ensure_private_directory(
            get_state_dir() / "blackbox" / "suites", parents=True
        )
        suite_hash = digest(suite.model_dump(mode="json"))
        path = root / f"{suite_hash}.json"
        atomic_write_private(path, json_bytes(suite.model_dump(mode="json")) + b"\n")
    except Exception as exc:
        _failure("Golden import", exc)
    console.print(f"Frozen {len(suite.cases)} cases. Suite: {path}", markup=False)


@app.command("compare-models")
def compare_models(
    suite_path: Path = typer.Option(..., "--suite", exists=True, dir_okay=False),
    plan_path: Path = typer.Option(
        ...,
        "--models",
        exists=True,
        dir_okay=False,
        help="YAML list of models, endpoints and prices.",
    ),
    output: Path = typer.Option(
        ...,
        "--out",
        file_okay=False,
        help="Directory for comparison.json, comparison.md and per-model reports.",
    ),
    system_prompt: Path | None = typer.Option(
        None,
        "--system-prompt",
        exists=True,
        dir_okay=False,
        help="File sent to every model as the system message.",
    ),
    response_format: str = typer.Option(
        "text", "--response-format", help="text or json"
    ),
    trials: int = typer.Option(1, "--trials", min=1),
):
    """Run the same suite on each model and recommend the cheapest model that passes."""
    try:
        suite = load_suite(suite_path)
        plan = load_plan(plan_path)
        prompt = system_prompt.read_text("utf-8") if system_prompt else None
        targets: list[tuple[ModelSpec, Target]] = [
            (spec, model_target(spec, prompt, response_format)) for spec in plan.models
        ]
        comparison, reports = compare(suite, targets, trials=trials)
        for report in reports:
            save_report(suite, report)
        (output / "reports").mkdir(parents=True, exist_ok=True)
        for report in reports:
            (output / "reports" / f"{report.agent}.json").write_text(
                report.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
        (output / "comparison.json").write_text(
            comparison.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (output / "comparison.md").write_text(
            render_markdown(comparison), encoding="utf-8"
        )
    except Exception as exc:
        _failure("Model comparison", exc)
    for result in comparison.models:
        cost = "unknown" if result.cost_usd is None else f"${result.cost_usd:.4f}"
        console.print(
            f"{'PASS' if result.passed else 'FAIL'}  {result.label}  "
            f"accepted={result.accepted}/{result.evaluations}  "
            f"tokens={result.tokens_in}/{result.tokens_out}  cost={cost}",
            markup=False,
        )
    console.print(
        f"Recommended: {comparison.recommended or 'none'}. {comparison.reason}",
        markup=False,
    )
    console.print(f"Comparison: {output / 'comparison.md'}", markup=False)
    if comparison.recommended is None:
        raise typer.Exit(2)
