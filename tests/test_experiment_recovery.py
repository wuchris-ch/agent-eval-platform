from __future__ import annotations

import json
import os
import shlex
import signal
import sqlite3
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from agent_eval.blackbox.models import Case, Metric, Report, Suite, digest
from agent_eval.blackbox.runner import evaluate, grade_observation
from agent_eval.blackbox.targets import CommandTarget
from agent_eval.cli import app
from agent_eval.experiments.executor import execute
from agent_eval.experiments.journal import (
    ExperimentBusy,
    Journal,
    JournalError,
    directory,
)
from agent_eval.experiments.models import CommandSpec, Plan
from agent_eval.experiments.service import create_experiment, status
from agent_eval.paths import UnsafeStatePathError


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(root / "state"))
    monkeypatch.setenv("EXPERIMENT_TEST_LOG", str(root / "calls.jsonl"))
    target = root / "target.py"
    target.write_text(
        "import json,os,sys\n"
        "value=sys.stdin.read()\n"
        "with open(os.environ['EXPERIMENT_TEST_LOG'],'a') as f:\n"
        " f.write(json.dumps(value)+'\\n'); f.flush(); os.fsync(f.fileno())\n"
        "sys.stdout.write(value)\n"
    )
    suite = Suite(
        schema_version="1.0",
        id="offline",
        version="1",
        metrics=[Metric(name="correct", kind="exact_match")],
        cases=[
            Case(id=f"case-{i}", input=f"question-{i}", expected_output=f"question-{i}")
            for i in range(3)
        ],
    )
    spec = CommandSpec(
        argv=[sys.executable, str(target)], env_names=["EXPERIMENT_TEST_LOG"]
    )
    return root, target, suite, spec


def new(fixture, **kwargs):
    _, _, suite, spec = fixture
    return create_experiment(suite, agent="test-agent", command=spec, **kwargs)


def calls(fixture):
    path = fixture[0] / "calls.jsonl"
    return (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )


def test_resume_keeps_completed_trials_and_legacy_scoring(fixture):
    experiment_id = new(fixture, trials=2)
    prepared = status(experiment_id)
    assert prepared.planned == 6 and prepared.completed == 0 and prepared.passed is None
    paused = execute(experiment_id, max_new_trials=1)
    assert paused.completed == 1 and paused.passed is None
    with Journal.open(experiment_id) as journal:
        first = dict(journal.row(0))
        receipt = journal.receipt(journal.row(0))[0]
    assert execute(experiment_id).passed is True
    assert calls(fixture) == [f"question-{i}" for _ in range(2) for i in range(3)]
    with Journal.open(experiment_id) as journal:
        assert dict(journal.row(0)) == first
        report = Report.model_validate_json((journal.root / "report.json").read_text())
        observations = [r.observation for r in report.results]
    reference = evaluate(
        fixture[2], agent="test-agent", observations=observations, trials=2
    )
    assert report.results == reference.results
    assert (report.passed, report.average_score, report.infra_errors) == (
        reference.passed,
        reference.average_score,
        reference.infra_errors,
    )
    assert report.results[0].observation == receipt.observation
    execute(experiment_id)
    assert len(calls(fixture)) == 6


CRASH_WORKER = """
import os,signal,sys
import agent_eval.experiments.journal as storage
from agent_eval.experiments.executor import execute
from agent_eval.experiments.journal import Journal
stage=sys.argv[2]
def crash(): os.kill(os.getpid(),signal.SIGKILL)
original_transition=Journal._transition
def transition(self,ordinal,previous,state,**kwargs):
    if ordinal==0 and stage=='receipt' and state=='observed': crash()
    if ordinal==0 and stage=='result_blob' and state=='completed': crash()
    result=original_transition(self,ordinal,previous,state,**kwargs)
    if ordinal==0 and ((stage=='claimed' and state=='running') or
                     (stage=='observed' and state=='observed') or
                     (stage=='first_complete' and state=='completed')): crash()
    if ordinal==2 and stage=='all_complete' and state=='completed': crash()
    return result
Journal._transition=transition
original_observe=Journal.observe
def observe(self,row,receipt):
    if stage=='dispatched': crash()
    return original_observe(self,row,receipt)
Journal.observe=observe
original_immutable=storage.immutable_json
def immutable(path,value):
    if stage=='observation_blob' and path.parent.name=='receipts': crash()
    return original_immutable(path,value)
storage.immutable_json=immutable
execute(sys.argv[1])
"""


@pytest.mark.parametrize(
    "stage", ["receipt", "observed", "result_blob", "first_complete", "all_complete"]
)
def test_real_process_crash_resumes_from_durable_receipt(fixture, stage):
    experiment_id = new(fixture)
    child = subprocess.run(
        [sys.executable, "-c", CRASH_WORKER, experiment_id, stage],
        capture_output=True,
        timeout=20,
    )
    assert child.returncode == -signal.SIGKILL, child.stderr.decode()
    before = calls(fixture)
    assert before == (
        ["question-0", "question-1", "question-2"]
        if stage == "all_complete"
        else ["question-0"]
    )
    assert execute(experiment_id).passed is True
    assert calls(fixture) == ["question-0", "question-1", "question-2"]
    assert (directory(experiment_id) / "report.json").exists()


@pytest.mark.parametrize(
    "stage,invocations", [("claimed", 0), ("dispatched", 1), ("observation_blob", 1)]
)
def test_ambiguous_dispatch_never_reinvokes_or_continues(fixture, stage, invocations):
    experiment_id = new(fixture)
    child = subprocess.run(
        [sys.executable, "-c", CRASH_WORKER, experiment_id, stage],
        capture_output=True,
        timeout=20,
    )
    assert child.returncode == -signal.SIGKILL, child.stderr.decode()
    for _ in range(2):
        snapshot = execute(experiment_id)
        assert snapshot.state == "reconciliation_required" and snapshot.passed is None
        assert snapshot.trials[0].state == "reconciliation_required"
        assert len(calls(fixture)) == invocations
    assert not (directory(experiment_id) / "report.json").exists()
    result = CliRunner().invoke(app, ["experiment", "resume", experiment_id])
    assert result.exit_code == 3 and "will not be retried" in result.output


def test_duplicate_finalization_and_lost_report_rebuild(fixture):
    experiment_id = new(fixture)
    execute(experiment_id)
    with Journal.open(experiment_id, write=True) as journal:
        row = journal.row(0)
        result = journal.result(row)
        journal.complete(row, result)
        with pytest.raises(JournalError, match="conflicting"):
            journal.complete(row, result.model_copy(update={"score": 0.0}))
        path = journal.root / "report.json"
        original = path.read_bytes()
        path.unlink()
        journal.export_report()
        assert path.read_bytes() == original
        path.write_text("corrupt projection")
        journal.export_report()
        assert path.read_bytes() == original
    assert len(calls(fixture)) == 3


@pytest.mark.parametrize(
    "artifact", ["observation", "result", "receipt", "suite", "plan"]
)
def test_corrupt_evidence_cannot_pass_or_dispatch(fixture, artifact):
    experiment_id = new(fixture)
    execute(experiment_id, max_new_trials=1)
    with Journal.open(experiment_id) as journal:
        row = journal.row(0)
        paths = {
            "observation": journal.root
            / "artifacts"
            / f"{row['observation_sha256']}.json",
            "result": journal.root / "artifacts" / f"{row['result_sha256']}.json",
            "receipt": journal.root / "receipts" / f"{row['attempt_id']}.json",
            "suite": journal.root / "suite.json",
            "plan": journal.root / "plan.json",
        }
    paths[artifact].write_text("{}")
    with pytest.raises((JournalError, ValueError)):
        execute(experiment_id)
    assert calls(fixture) == ["question-0"]
    assert (
        CliRunner().invoke(app, ["experiment", "status", experiment_id]).exit_code == 1
    )


def test_missing_artifact_blocks_completed_status(fixture):
    experiment_id = new(fixture)
    execute(experiment_id)
    with Journal.open(experiment_id) as journal:
        (
            journal.root / "artifacts" / f"{journal.row(1)['observation_sha256']}.json"
        ).unlink()
    with pytest.raises(FileNotFoundError):
        status(experiment_id)


def test_command_file_and_environment_are_frozen(fixture, monkeypatch):
    experiment_id = new(fixture)
    execute(experiment_id, max_new_trials=1)
    target = fixture[1]
    original = target.read_text()
    target.write_text(original + "\n# modified\n")
    with pytest.raises(JournalError, match="file identity changed"):
        execute(experiment_id)
    target.write_text(original)
    monkeypatch.setenv("EXPERIMENT_TEST_LOG", "private-changed-value")
    with pytest.raises(JournalError, match="environment changed"):
        execute(experiment_id)
    assert calls(fixture) == ["question-0"]


def test_retargeted_script_symlink_is_detected(fixture):
    root, target, suite, spec = fixture
    link = root / "target-link.py"
    link.symlink_to(target)
    spec.argv[1] = str(link)
    experiment_id = create_experiment(suite, agent="test", command=spec)
    other = root / "other.py"
    other.write_text(target.read_text())
    link.unlink()
    link.symlink_to(other)
    with pytest.raises(JournalError, match="identity changed"):
        execute(experiment_id)
    assert not calls(fixture)


def test_saved_observation_grades_without_target_or_environment(fixture, monkeypatch):
    experiment_id = new(fixture)
    child = subprocess.run(
        [sys.executable, "-c", CRASH_WORKER, experiment_id, "observed"],
        capture_output=True,
        timeout=20,
    )
    assert child.returncode == -signal.SIGKILL
    fixture[1].unlink()
    monkeypatch.delenv("EXPERIMENT_TEST_LOG")
    with pytest.raises(ValueError):
        execute(experiment_id)
    # The saved first observation was graded before attempting to prepare case 2.
    assert status(experiment_id).completed == 1
    assert calls(fixture) == ["question-0"]


def test_writer_lock_excludes_second_process_but_allows_status(fixture):
    experiment_id = new(fixture)
    with Journal.open(experiment_id, write=True):
        with pytest.raises(ExperimentBusy):
            execute(experiment_id)
        child = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_eval.cli",
                "experiment",
                "resume",
                experiment_id,
            ],
            capture_output=True,
            timeout=20,
        )
        # Use direct invocation because cli.py also supports module execution.
        assert child.returncode == 3, child.stderr.decode()
        assert status(experiment_id).planned == 3
    assert not calls(fixture)


@pytest.mark.parametrize("kind", ["file", "ancestor", "sidecar"])
def test_symlink_state_is_rejected(fixture, monkeypatch, kind):
    root = fixture[0]
    experiment_id = new(fixture)
    if kind == "file":
        path = directory(experiment_id) / "plan.json"
        original = root / "real-plan.json"
        path.rename(original)
        path.symlink_to(original)
    elif kind == "sidecar":
        (directory(experiment_id) / "journal.db-journal").symlink_to(root / "missing")
    else:
        link = root / "state-link"
        link.symlink_to(root / "state")
        monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(link))
    with pytest.raises(UnsafeStatePathError):
        execute(experiment_id)
    assert not calls(fixture)


def test_newer_schema_and_missing_matrix_fail_closed(fixture):
    experiment_id = new(fixture)
    path = directory(experiment_id) / "journal.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(JournalError, match="schema"):
        execute(experiment_id)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=1")
        connection.execute("DELETE FROM trials WHERE ordinal=1")
    with pytest.raises(JournalError, match="matrix"):
        execute(experiment_id)
    assert not calls(fixture)


def test_plan_rejects_judging_and_limits_before_dispatch(fixture):
    _, _, suite, spec = fixture
    suite.metrics = [Metric(name="judge", kind="geval", criteria="secret rubric")]
    with pytest.raises(ValueError, match="deterministic"):
        create_experiment(suite, agent="test", command=spec)
    assert not calls(fixture)
    assert not (fixture[0] / "state" / "experiments").exists()


def test_error_and_quality_results_preserve_legacy_semantics(fixture):
    _, target, suite, _ = fixture
    target.write_text("import sys\nsys.exit(7)\n")
    experiment_id = new(fixture)
    snapshot = execute(experiment_id)
    assert snapshot.infra_errors == 3 and snapshot.passed is False
    report = Report.model_validate_json(
        (directory(experiment_id) / "report.json").read_text()
    )
    assert report.average_score == 0 and report.results[0].error == "target_exit"
    target.write_text("print('incorrect')\n")
    experiment_id = new(fixture)
    snapshot = execute(experiment_id)
    assert snapshot.rejected == 3 and snapshot.infra_errors == 0


def test_cli_private_files_and_machine_readable_status(fixture):
    root, target, suite, _ = fixture
    suite_path = root / "suite.json"
    suite_path.write_text(suite.model_dump_json())
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "experiment",
            "run",
            "--suite",
            str(suite_path),
            "--agent",
            "test",
            "--command",
            shlex.join([sys.executable, str(target)]),
            "--pass-env",
            "EXPERIMENT_TEST_LOG",
            "--prepare-only",
        ],
    )
    assert result.exit_code == 0, result.output
    snapshot = json.loads(result.stdout)
    experiment_id = snapshot["experiment_id"]
    assert snapshot["passed"] is None and not calls(fixture)
    assert runner.invoke(app, ["experiment", "resume", experiment_id]).exit_code == 0
    snapshot = runner.invoke(app, ["experiment", "status", experiment_id])
    assert json.loads(snapshot.stdout)["passed"] is True
    assert runner.invoke(app, ["experiment", "export", experiment_id]).exit_code == 0
    for path in directory(experiment_id).rglob("*"):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    plan_text = (directory(experiment_id) / "plan.json").read_text()
    assert os.environ["EXPERIMENT_TEST_LOG"] not in plan_text
    assert not (root / "state" / "blackbox").exists()


def test_input_blinding_survives_experiment_wrapper(fixture):
    _, target, suite, _ = fixture
    target.write_text(
        "import os,sys,json\nsys.stdout.write(json.dumps({'input':sys.stdin.read(),'files':os.listdir('.'),'plan':os.environ.get('AGENT_EVAL_STATE_DIR')}))\n"
    )
    suite.cases = [
        Case(
            id="secret-case",
            input="public-question",
            expected_output=json.dumps(
                {
                    "input": "public-question",
                    "files": [],
                    "plan": None,
                }
            ),
            context=["secret golden context"],
        )
    ]
    assert execute(new(fixture)).passed is True


def test_shared_grader_matches_existing_output_fixture(fixture):
    _, _, suite, _ = fixture
    target = CommandTarget(
        [sys.executable, "-c", "import sys;sys.stdout.write(sys.stdin.read())"]
    )
    report = evaluate(suite, agent="legacy", target=target)
    for case, result in zip(suite.cases, report.results, strict=True):
        assert grade_observation(suite, case, 1, result.observation) == result


def test_invalid_ids_do_not_escape_state_directory(fixture):
    for value in ("../outside", "/tmp", "not-a-uuid"):
        with pytest.raises(JournalError, match="ID"):
            status(value)


def test_frozen_plan_is_not_mutated_by_caller(fixture):
    experiment_id = new(fixture)
    fixture[2].cases[0].expected_output = "modified"
    fixture[3].argv = ["not-a-command"]
    assert execute(experiment_id).passed is True
    plan = Plan.model_validate_json(
        (directory(experiment_id) / "plan.json").read_text()
    )
    assert plan.suite_sha256 == digest(plan.suite.model_dump(mode="json"))
