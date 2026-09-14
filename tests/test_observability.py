from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_eval import metrics, observability, runner
from agent_eval.agent_comparison import compare_agents
from agent_eval.assessments import (
    Assessment,
    AssessmentValue,
    EvaluatorIdentity,
    derive_assessments,
)
from agent_eval.assurance import (
    AssuranceResult,
    ChallengeCheckResult,
    ChallengeResult,
)
from agent_eval.evaluators import scanners
from agent_eval.evaluators.tests import TestResults as EvalTestResults
from agent_eval.metrics import (
    JudgeResult,
    RunRecord,
    ScanResults,
    TrivyDatabaseIdentity,
)
from agent_eval.outcome import AcceptancePolicy, RunOutcome
from agent_eval.task import load_task

_SECRET = "PROMPT-RATIONALE-SOURCE-CONTENT-MUST-NOT-LEAK"
_DIGEST = "a" * 64


def _task(*, revision: str = "1.0.0") -> SimpleNamespace:
    return SimpleNamespace(
        prompt=_SECRET,
        judge=SimpleNamespace(enabled=True, weights={"quality": 1.0}),
        acceptance=AcceptancePolicy(
            min_coverage_percent=80,
            min_judge_score=3,
            max_lint_errors=0,
            max_security_findings_high=0,
            max_secrets=0,
            max_vulnerabilities=0,
        ),
        dataset=SimpleNamespace(
            id="agent-eval/test", revision=revision, item_id="item-1"
        ),
    )


def _record() -> RunRecord:
    record = RunRecord(
        run_id="run-1",
        task_id="task-1",
        agent="codex",
        started_at="2026-07-14T19:00:00+00:00",
        finished_at="2026-07-14T19:01:00+00:00",
        correctness=EvalTestResults(
            total=2,
            passed=2,
            coverage_percent=95.0,
            command_exit_code=0,
        ),
        scans=ScanResults(
            lint_errors=0,
            sec_findings_high=0,
            sec_findings_medium=0,
            sec_findings_low=1,
            secrets_found=0,
            vulns=0,
            scanner_status={"ruff": "ok", "semgrep": "ok"},
            scanner_versions={
                "ruff": "0.15.20",
                "semgrep": "1.176.0",
                "gitleaks": "8.30.1",
                "trivy": "0.72.0",
            },
            scanner_configs={"ruff": _SECRET, "semgrep": _SECRET},
            findings=[{"path": _SECRET, "source": _SECRET}],
        ),
        judge=JudgeResult(
            scores={"quality": 4},
            weighted_score=4.0,
            rationale={"quality": _SECRET},
            backend="codex",
            model="gpt-test",
        ),
        assurance=AssuranceResult(
            passed=True,
            challenges=[
                ChallengeResult(
                    id="prompt-injection",
                    category="safety",
                    threat=_SECRET,
                    passed=True,
                    checks=[
                        ChallengeCheckResult(
                            type="content_absent", passed=True, evidence=_SECRET
                        )
                    ],
                )
            ],
        ),
        outcome=RunOutcome(status="accepted"),
    )
    record.provenance.harness_version = "0.3.0"
    record.provenance.evaluation_spec_digest = _DIGEST
    record.__dict__["governance"] = SimpleNamespace(
        allowed=True,
        policy_revision="v1",
        policy_digest="b" * 64,
    )
    return record


def test_models_are_strict_and_typed() -> None:
    with pytest.raises(ValidationError):
        EvaluatorIdentity(name="Not Normalized")
    with pytest.raises(ValidationError):
        AssessmentValue(type="numeric", numeric=1.0, text="also populated")
    with pytest.raises(ValidationError):
        AssessmentValue(type="numeric", numeric="1.0")

    timestamp = datetime(2026, 7, 14, tzinfo=UTC)
    with pytest.raises(ValidationError):
        Assessment(
            assessment_id="0" * 64,
            run_id="run-1",
            name="tests.score",
            source_kind="test",
            status="observed",
            value=AssessmentValue(type="boolean", boolean=True),
            direction="higher_is_better",
            range_min=0.0,
            evaluator=EvaluatorIdentity(name="tests"),
            started_at=timestamp,
            finished_at=timestamp,
            observed_at=timestamp,
        )
    legacy = RunRecord.model_validate(
        {"run_id": "legacy", "task_id": "task", "agent": "external"}
    )
    assert legacy.schema_version == "agent-eval.run/v2"
    with pytest.raises(ValidationError):
        RunRecord(run_id="bad-trial", task_id="task", agent="external", trial=0)
    with pytest.raises(ValidationError):
        RunRecord(run_id="bool-trial", task_id="task", agent="external", trial=True)


def test_normalization_covers_sources_without_content_and_binds_dataset() -> None:
    record = _record()
    assessments = derive_assessments(record, _task())

    assert {item.source_kind for item in assessments} == {
        "test",
        "scanner",
        "judge",
        "challenge",
        "policy",
        "outcome",
    }
    assert all(item.dataset_id == "agent-eval/test" for item in assessments)
    assert all(item.dataset_revision == "1.0.0" for item in assessments)
    assert all(item.dataset_item_id == "item-1" for item in assessments)
    serialized = json.dumps(
        [item.model_dump(mode="json") for item in assessments], sort_keys=True
    )
    assert _SECRET not in serialized

    next_revision = derive_assessments(record, _task(revision="2.0.0"))
    assert {item.assessment_id for item in assessments}.isdisjoint(
        {item.assessment_id for item in next_revision}
    )


def test_observed_scanner_identity_does_not_split_configured_recipe_cohort() -> None:
    records = [_record(), _record()]
    records[0].run_id = "scanner-a"
    records[1].run_id = "scanner-b"
    for index, record in enumerate(records):
        record.scans.scanner_runtime_lock_sha256 = (
            scanners.scanner_runtime_lock_digest()
        )
        record.scans.scanner_runtime_environment_sha256 = str(index + 4) * 64
        record.scans.scanner_status = {
            "ruff": "ok",
            "semgrep": "ok",
            "gitleaks": "ok",
            "trivy": "ok",
        }
        record.scans.scanner_executable_sha256 = {
            "uv": "1" * 64,
            "python": "2" * 64,
            "ruff": "3" * 64,
            "semgrep": "4" * 64,
            "gitleaks": "5" * 64,
            "trivy": "6" * 64,
        }
        record.scans.trivy_db = TrivyDatabaseIdentity(
            version=2,
            updated_at="2026-07-14T00:00:00Z",
            next_update="2026-07-15T00:00:00Z",
            downloaded_at="2026-07-14T01:00:00Z",
            content_sha256="7" * 64,
        )
        record.scans.scanner_assurance = scanners.scanner_assurance_identity(
            record.scans
        )
        record.scans = ScanResults.model_validate(
            record.scans.model_dump(mode="python")
        )
        record.provenance.evaluation_spec_digest = "a" * 64
        record.provenance.task_tree_sha256 = "b" * 64
        record.provenance.image_digest = "sha256:" + "c" * 64
        record.provenance.harness_version = "0.3.0"
        record.provenance.harness_commit = "d" * 40
        record.provenance.harness_dirty = False
        record.provenance.harness_worktree_sha256 = "e" * 64
        record.assessments = derive_assessments(record, _task())

    scanner_digests = [
        next(
            assessment.evaluator.config_digest
            for assessment in record.assessments
            if assessment.name == "scanners.lint-errors"
        )
        for record in records
    ]
    result = compare_agents(records)

    assert scanner_digests[0] != scanner_digests[1]
    assert len(result.summaries) == 1
    assert result.summaries[0].sample_size == 2
    assert result.summaries[0].cohort.binding == "bound"
    assert result.summaries[0].cohort.evaluation_recipe_digest == "a" * 64


def test_bundled_dataset_identity_flows_into_assessments() -> None:
    task = load_task("example-todo-api")
    assessments = derive_assessments(_record(), task)

    assert assessments
    assert all(item.dataset_id == "agent-eval/bundled" for item in assessments)
    assert all(item.dataset_revision == "2.0.0" for item in assessments)
    assert all(item.dataset_item_id == "example-todo-api" for item in assessments)


def test_integrity_error_keeps_content_free_error_identity() -> None:
    record = _record()
    record.correctness = EvalTestResults(
        command_exit_code=126,
        integrity_error=_SECRET,
        failures=[_SECRET],
    )
    resolved = next(
        item
        for item in derive_assessments(record, _task())
        if item.name == "tests.resolved"
    )
    assert resolved.status == "failed"
    assert resolved.error is not None
    assert resolved.error.type == "integrity"
    assert _SECRET not in resolved.model_dump_json()


def test_unobserved_test_counts_remain_unavailable_after_early_infra_error() -> None:
    record = _record()
    record.correctness = EvalTestResults(
        infra_error="evaluator pod unavailable",
        command_exit_code=None,
    )

    counts = [
        item
        for item in derive_assessments(record, _task())
        if item.name
        in {
            "tests.total",
            "tests.passed",
            "tests.failed",
            "tests.errors",
            "tests.skipped",
        }
    ]

    assert len(counts) == 5
    assert all(item.status == "unavailable" for item in counts)
    assert all(item.value is None for item in counts)


def test_unknown_categorical_source_content_is_digest_only() -> None:
    record = _record()
    record.scans.scanner_status["ruff"] = _SECRET

    status = next(
        item
        for item in derive_assessments(record, _task())
        if item.name.startswith("scanners.ruff-") and item.name.endswith(".status")
    )

    assert status.status == "error"
    assert status.value is not None
    assert status.value.categorical is not None
    assert status.value.categorical.startswith("sha256-")
    assert status.error is not None
    assert status.error.code == "unexpected_scanner_status"
    assert _SECRET.casefold() not in status.model_dump_json().casefold()


def test_telemetry_event_allowlist_never_exports_content() -> None:
    assessments = derive_assessments(_record(), _task())
    for assessment in assessments:
        event_name, attributes = observability.assessment_event(assessment)
        assert _SECRET not in json.dumps(attributes, sort_keys=True)
        if assessment.source_kind == "judge":
            assert event_name == "gen_ai.evaluation.result"
            assert attributes["gen_ai.evaluation.name"] in {
                "agent_eval.judge.dimension",
                "agent_eval.judge.weighted-score",
            }
            assert "gen_ai.evaluation.explanation" not in attributes
        else:
            assert event_name == "agent_eval.assessment.result"
            assert not any(key.startswith("gen_ai.") for key in attributes)
        assert attributes["agent_eval.assessment.name"] in (
            observability._FIXED_ASSESSMENT_NAMES
            | {"scanners.status", "judge.dimension", "challenge.result"}
        )


def test_telemetry_buckets_task_defined_names_without_leaking_them() -> None:
    record = _record()
    record.judge.scores = {_SECRET: 4}
    record.scans.scanner_status = {_SECRET: "ok"}
    record.assurance.challenges[0].id = _SECRET

    assessments = derive_assessments(record, _task())
    projections = [observability.assessment_event(item) for item in assessments]
    serialized = json.dumps(projections, sort_keys=True).casefold()

    assert _SECRET.casefold() not in serialized
    names = {attributes["agent_eval.assessment.name"] for _, attributes in projections}
    assert {"scanners.status", "judge.dimension", "challenge.result"} <= names


def test_enabled_judge_without_score_is_queryable_as_unavailable() -> None:
    record = _record()
    record.judge = JudgeResult(backend="codex", model="gpt-test")
    assessment = next(
        item
        for item in derive_assessments(record, _task())
        if item.name == "judge.weighted-score"
    )
    assert assessment.status == "unavailable"
    assert assessment.value is None
    assert assessment.evaluator.model == "gpt-test"
    outcome = next(
        item
        for item in derive_assessments(record, _task())
        if item.name == "outcome.status"
    )
    assert outcome.value is not None
    assert outcome.value.categorical == "accepted"


def test_telemetry_disabled_and_missing_sdk_are_noops(monkeypatch) -> None:
    record = _record()
    record.assessments = derive_assessments(record, _task())
    monkeypatch.delenv("AGENT_EVAL_OTEL_ENABLED", raising=False)
    monkeypatch.setattr(
        observability,
        "_load_otel",
        lambda: (_ for _ in ()).throw(AssertionError("must stay lazy")),
    )
    observability._runtime = None
    assert observability.export_run_assessments(record) is False

    monkeypatch.setenv("AGENT_EVAL_OTEL_ENABLED", "1")
    monkeypatch.setattr(
        observability,
        "_load_otel",
        lambda: (_ for _ in ()).throw(ImportError("SDK is not installed")),
    )
    observability._runtime = None
    assert observability.export_run_assessments(record) is False


def test_complete_record_persists_before_exporter_failure(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(metrics, "RUNS_ROOT", tmp_path / "runs")
    task = _task()
    task.acceptance = AcceptancePolicy()
    record = RunRecord(
        run_id="run-complete",
        task_id="task-1",
        agent="external",
        started_at="2026-07-14T19:00:00+00:00",
        correctness=EvalTestResults(
            total=1,
            passed=1,
            command_exit_code=0,
        ),
    )
    record.provenance.evaluation_spec_digest = _DIGEST
    export_calls = []

    def failing_export(completed: RunRecord) -> None:
        rows = metrics.load_assessments(completed.run_id, dataset_id="agent-eval/test")
        assert rows
        export_calls.append(completed.outcome.status)
        raise RuntimeError("collector unavailable")

    monkeypatch.setattr(runner, "export_run_assessments", failing_export)
    completed = runner._complete_record(task, record, audit=None)

    assert completed.outcome is not None
    assert completed.outcome.status == "accepted"
    assert completed.assessments
    assert completed.provenance.harness_version == "0.4.0"
    assert export_calls == ["accepted"]
    loaded = metrics.load_run(completed.run_id, forbid_extra=True)
    assert loaded is not None
    assert loaded.outcome == completed.outcome
    assert len(loaded.assessments) == len(completed.assessments)
    rows = metrics.load_assessments(
        completed.run_id,
        dataset_id="agent-eval/test",
        dataset_revision="1.0.0",
        dataset_item_id="item-1",
        source_kind="test",
    )
    assert rows
    assert all(row["dataset_revision"] == "1.0.0" for row in rows)
    with closing(metrics._connect()) as conn:
        versions = [
            row["version"]
            for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
    assert versions == [1, 2, 3]


def test_legacy_database_migrates_assessments_in_order(tmp_path, monkeypatch) -> None:
    root = tmp_path / "runs"
    root.mkdir(mode=0o700)
    database = root / "metrics.db"
    with sqlite3.connect(database) as conn:
        conn.execute(metrics._RUNS_SCHEMA)
    database.chmod(0o600)
    monkeypatch.setattr(metrics, "RUNS_ROOT", root)

    with closing(metrics._connect()) as conn:
        versions = [
            row["version"]
            for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(assessments)")
        }
    assert versions == [1, 2, 3]
    assert {"dataset_id", "dataset_revision", "dataset_item_id"} <= columns
