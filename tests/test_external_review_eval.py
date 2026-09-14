from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agent_eval import external_review_eval as target
from agent_eval.cli import app
from agent_eval.review_benchmark import (
    BenchmarkCase,
    BenchmarkManifest,
    ExpectedFinding,
)

DIFF = b"""diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1,2 +1,2 @@
 def can_delete(user, owner):
-    return user == owner
+    return True
"""


def _output(
    *,
    diff: bytes = DIFF,
    blocked: bool = True,
    findings: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "1.0",
        "input_sha256": hashlib.sha256(diff).hexdigest(),
        "risk": "high" if blocked else "low",
        "blocked": blocked,
        "findings": findings
        if findings is not None
        else [
            {
                "severity": "blocker",
                "category": "security",
                "file": "auth.py",
                "line": 2,
                "detail": "Authorization is bypassed.",
            }
        ],
        "rationale": "The change must preserve authorization.",
    }


def _faulty_case() -> BenchmarkCase:
    return BenchmarkCase(
        id="auth-bypass",
        description="authorization bypass",
        changed_lines=1,
        expected=[
            ExpectedFinding(
                id="auth-1",
                severity="blocker",
                category="security",
                file="auth.py",
                line_start=2,
                line_end=2,
            )
        ],
    )


def _patch_dataset(monkeypatch, tmp_path: Path, case: BenchmarkCase) -> Path:
    corpus_path = tmp_path / "corpus.yaml"
    corpus_path.write_text("placeholder", encoding="utf-8")
    diff_path = tmp_path / "change.diff"
    diff_path.write_bytes(DIFF)
    corpus = SimpleNamespace(
        corpus_id="golden-review-corpus",
        version="1.0.0",
        benchmark_manifest="benchmark.yaml",
        cases=[SimpleNamespace(id=case.id, diff="change.diff")],
    )
    monkeypatch.setattr(
        target,
        "validate_corpus",
        lambda path, execute=False: SimpleNamespace(valid=True, errors=[]),
    )
    monkeypatch.setattr(target, "load_corpus", lambda path: (corpus, tmp_path))
    monkeypatch.setattr(
        target,
        "load_manifest",
        lambda path: BenchmarkManifest(cases=[case]),
    )
    monkeypatch.setattr(target, "export_trial_span", lambda *args, **kwargs: False)
    return corpus_path


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        json.dumps({**_output(), "unexpected": True}),
        json.dumps(_output()) + " trailing",
        '{"schema_version":"1.0","schema_version":"1.0"}',
        json.dumps({**_output(), "input_sha256": "NOT-A-DIGEST"}),
    ],
)
def test_contract_rejects_invalid_or_non_strict_output(payload: str) -> None:
    with pytest.raises((ValueError, ValidationError)):
        target.parse_review_output(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {**_output(), "risk": "medium"},
        {**_output(), "blocked": False},
        {
            **_output(blocked=False, findings=[]),
            "risk": "medium",
            "blocked": True,
        },
    ],
)
def test_contract_enforces_risk_and_block_consistency(payload: dict) -> None:
    with pytest.raises(ValidationError, match="highest finding severity"):
        target.ReviewAgentOutput.model_validate(payload)


@pytest.mark.parametrize("blocked", [0, "false", "off"])
def test_contract_rejects_non_boolean_blocked_values(blocked: object) -> None:
    payload = _output(blocked=False, findings=[])
    payload["blocked"] = blocked

    with pytest.raises(ValidationError, match="valid boolean"):
        target.ReviewAgentOutput.model_validate(payload)


@pytest.mark.parametrize(
    "file", [" auth.py ", "\ufeffauth.py", "auth.py\ufeff"]
)
def test_contract_rejects_whitespace_around_finding_path(file: str) -> None:
    payload = _output()
    payload["findings"][0]["file"] = file

    with pytest.raises(ValidationError, match="leading or trailing whitespace"):
        target.ReviewAgentOutput.model_validate(payload)


@pytest.mark.parametrize("file", ["a/../auth.py", "a\\..\\auth.py"])
def test_contract_rejects_parent_segments_in_finding_path(file: str) -> None:
    payload = _output()
    payload["findings"][0]["file"] = file

    with pytest.raises(ValidationError, match="parent-directory segment"):
        target.ReviewAgentOutput.model_validate(payload)


def test_contract_matches_ecmascript_trim_for_next_line_character() -> None:
    payload = _output()
    payload["findings"][0]["file"] = "\u0085auth.py"

    output = target.ReviewAgentOutput.model_validate(payload)

    assert output.findings[0].file == "\u0085auth.py"


@pytest.mark.parametrize("field", ["detail", "rationale"])
def test_contract_treats_bom_only_text_as_blank(field: str) -> None:
    payload = _output()
    if field == "detail":
        payload["findings"][0]["detail"] = "\ufeff"
    else:
        payload["rationale"] = "\ufeff"

    with pytest.raises(ValidationError, match="must not be empty"):
        target.ReviewAgentOutput.model_validate(payload)


def test_contract_requires_exact_raw_diff_digest(tmp_path: Path) -> None:
    script = tmp_path / "agent.py"
    payload = json.dumps({**_output(), "input_sha256": "0" * 64})
    script.write_text(
        f"print({payload!r})\n",
        encoding="utf-8",
    )

    result = target.invoke_review_agent(
        [sys.executable, str(script)], DIFF, timeout_seconds=5
    )

    assert result.output is None
    assert result.error == "invalid agent output: input_sha256 does not match the raw diff"


def test_diff_file_mode_passes_a_temporary_file_and_no_stdin(tmp_path: Path) -> None:
    script = tmp_path / "agent.py"
    path_log = tmp_path / "path.txt"
    script.write_text(
        "import hashlib, json, pathlib, sys\n"
        "assert sys.argv[2] == '--diff'\n"
        "diff_path = pathlib.Path(sys.argv[3])\n"
        "diff = diff_path.read_bytes()\n"
        "pathlib.Path(sys.argv[1]).write_text(str(diff_path))\n"
        "assert sys.stdin.buffer.read() == b''\n"
        "out = {'schema_version':'1.0','input_sha256':hashlib.sha256(diff).hexdigest(),"
        "'risk':'low','blocked':False,'findings':[],'rationale':'clean'}\n"
        "print(json.dumps(out))\n",
        encoding="utf-8",
    )

    result = target.invoke_review_agent(
        [sys.executable, str(script), str(path_log)],
        DIFF,
        timeout_seconds=5,
        diff_file_flag="--diff",
    )

    assert result.output is not None
    assert result.error is None
    assert not Path(path_log.read_text()).exists()


def test_agent_output_and_runtime_are_bounded(monkeypatch, tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.py"
    oversized.write_text("print('x' * 1000)\n", encoding="utf-8")
    monkeypatch.setattr(target, "MAX_AGENT_OUTPUT_BYTES", 64)

    output_result = target.invoke_review_agent(
        [sys.executable, str(oversized)], DIFF, timeout_seconds=5
    )

    assert output_result.output is None
    assert output_result.error == "agent stdout exceeded the 64-byte limit"

    slow = tmp_path / "slow.py"
    slow.write_text("import time; time.sleep(10)\n", encoding="utf-8")
    timeout_result = target.invoke_review_agent(
        [sys.executable, str(slow)], DIFF, timeout_seconds=0.05
    )

    assert timeout_result.output is None
    assert timeout_result.error == "agent timed out after 0.05 seconds"


def test_successful_agent_cannot_leave_a_background_descendant(tmp_path: Path) -> None:
    script = tmp_path / "agent.py"
    ready = tmp_path / "child-ready"
    survived = tmp_path / "child-survived"
    child_pid = tmp_path / "child-pid"
    payload = json.dumps(_output())
    child_source = (
        "import pathlib, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text('ready'); "
        "time.sleep(0.5); "
        "pathlib.Path(sys.argv[2]).write_text('survived'); "
        "time.sleep(10)"
    )
    script.write_text(
        "import pathlib, subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_source!r}, "
        "sys.argv[1], sys.argv[2]], stdin=subprocess.DEVNULL, "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "pathlib.Path(sys.argv[3]).write_text(str(child.pid))\n"
        "while not pathlib.Path(sys.argv[1]).exists(): time.sleep(0.01)\n"
        f"print({payload!r})\n",
        encoding="utf-8",
    )

    result = target.invoke_review_agent(
        [sys.executable, str(script), str(ready), str(survived), str(child_pid)],
        DIFF,
        timeout_seconds=5,
    )
    pid = int(child_pid.read_text())
    try:
        assert result.output is not None
        assert result.error is None
        time.sleep(0.75)
        assert not survived.exists()
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf"), 0])
def test_nonfinite_or_nonpositive_timeout_is_rejected(timeout: float) -> None:
    invocation = target.invoke_review_agent(
        ["command-that-must-not-start"], DIFF, timeout_seconds=timeout
    )

    assert invocation.output is None
    assert invocation.latency_ms == 0
    assert invocation.error == "invalid agent timeout"

    with pytest.raises(ValueError, match="timeout must be positive"):
        target.evaluate_external_review_agent(
            corpus_path=Path("not-read"),
            command=["command-that-must-not-start"],
            timeout_seconds=timeout,
        )


def test_v1_diff_cap_fails_before_the_target_starts() -> None:
    result = target.invoke_review_agent(
        ["command-that-must-not-start"],
        b"x" * (64 * 1024 + 1),
        timeout_seconds=5,
    )

    assert result.output is None
    assert result.latency_ms == 0
    assert result.error == "raw diff exceeded the safe byte limit"


def test_deterministic_scoring_uses_goldens_and_block_decision() -> None:
    case = _faulty_case()

    correct = target.score_review_output(
        case, target.ReviewAgentOutput.model_validate(_output())
    )
    missed = target.score_review_output(
        case,
        target.ReviewAgentOutput.model_validate(
            _output(blocked=False, findings=[])
        ),
    )

    assert (correct.true_positives, correct.false_positives, correct.false_negatives) == (
        1,
        0,
        0,
    )
    assert correct.score == 1
    assert missed.score == 0
    assert target.score_to_grade(0.95) == "A"
    assert target.score_to_grade(0.8) == "B"
    assert target.score_to_grade(0.65) == "C"
    assert target.score_to_grade(0.59) == "F"


def test_deterministic_scoring_requires_exact_severity() -> None:
    wrong_severity = _output()
    wrong_severity["risk"] = "medium"
    wrong_severity["findings"][0]["severity"] = "major"

    score = target.score_review_output(
        _faulty_case(), target.ReviewAgentOutput.model_validate(wrong_severity)
    )

    assert (score.true_positives, score.false_positives, score.false_negatives) == (
        0,
        1,
        1,
    )
    assert score.verdict_correct is True
    assert score.f1 == 0
    assert score.score == 0.5


def test_minor_golden_does_not_require_a_block_decision() -> None:
    case = BenchmarkCase(
        id="minor-style",
        expected=[
            ExpectedFinding(
                id="style-1",
                severity="minor",
                category="style",
                file="formatting.py",
                line_start=4,
            )
        ],
    )
    output = target.ReviewAgentOutput.model_validate(
        _output(
            blocked=False,
            findings=[
                {
                    "severity": "minor",
                    "category": "style",
                    "file": "formatting.py",
                    "line": 4,
                    "detail": "Formatting can be simplified.",
                }
            ],
        )
    )

    score = target.score_review_output(case, output)

    assert score.verdict_correct is True
    assert score.score == 1


def test_retry_passes_feedback_without_mutating_diff_and_preserves_baseline(
    monkeypatch, tmp_path: Path
) -> None:
    corpus_path = _patch_dataset(monkeypatch, tmp_path, _faulty_case())
    log_path = tmp_path / "calls.jsonl"
    script = tmp_path / "agent.py"
    script.write_text(
        "import hashlib, json, os, pathlib, sys\n"
        "diff = sys.stdin.buffer.read()\n"
        "feedback = os.environ.get('AGENT_EVAL_FEEDBACK')\n"
        "record = {'sha': hashlib.sha256(diff).hexdigest(), "
        "'feedback': feedback, 'leaked': os.environ.get('HOST_SECRET'), "
        "'model': os.environ.get('REVIEW_AGENT_MODEL'), "
        "'legacy_model': os.environ.get('AGENT_MODEL'), "
        "'ssl_cert_file': os.environ.get('SSL_CERT_FILE'), "
        "'ssl_cert_dir': os.environ.get('SSL_CERT_DIR'), "
        "'node_extra_ca_certs': os.environ.get('NODE_EXTRA_CA_CERTS'), "
        "'otel_endpoint': os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT'), "
        "'otel_headers': os.environ.get('OTEL_EXPORTER_OTLP_HEADERS')}\n"
        "with pathlib.Path(sys.argv[1]).open('a') as stream: "
        "stream.write(json.dumps(record) + '\\n')\n"
        "finding = {'severity':'blocker','category':'security','file':'auth.py',"
        "'line':2,'detail':'Authorization is bypassed.'}\n"
        "output = {'schema_version':'1.0','input_sha256':record['sha'],"
        "'risk':'high' if feedback else 'low','blocked':bool(feedback),"
        "'findings':[finding] if feedback else [],'rationale':'checked'}\n"
        "print(json.dumps(output))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOST_SECRET", "must-not-reach-child")
    monkeypatch.setenv("REVIEW_AGENT_MODEL", "review-model")
    monkeypatch.setenv("AGENT_MODEL", "legacy-model")
    monkeypatch.setenv("SSL_CERT_FILE", "/certs/ca.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "/certs")
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/certs/node-ca.pem")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=secret")

    summary = target.evaluate_external_review_agent(
        corpus_path=corpus_path,
        command=[sys.executable, str(script), str(log_path)],
        self_correct=True,
    )

    result = summary.results[0]
    calls = [json.loads(line) for line in log_path.read_text().splitlines()]
    expected_digest = hashlib.sha256(DIFF).hexdigest()
    assert calls == [
        {
            "sha": expected_digest,
            "feedback": None,
            "leaked": None,
            "model": "review-model",
            "legacy_model": "legacy-model",
            "ssl_cert_file": "/certs/ca.pem",
            "ssl_cert_dir": "/certs",
            "node_extra_ca_certs": "/certs/node-ca.pem",
            "otel_endpoint": "http://127.0.0.1:4318",
            "otel_headers": None,
        },
        {
            "sha": expected_digest,
            "feedback": calls[1]["feedback"],
            "leaked": None,
            "model": "review-model",
            "legacy_model": "legacy-model",
            "ssl_cert_file": "/certs/ca.pem",
            "ssl_cert_dir": "/certs",
            "node_extra_ca_certs": "/certs/node-ca.pem",
            "otel_endpoint": "http://127.0.0.1:4318",
            "otel_headers": None,
        },
    ]
    assert calls[1]["feedback"]
    assert result.outcome == "accepted"
    assert result.first_attempt.outcome == "rejected"
    assert result.first_attempt.score == 0
    assert result.first_attempt.output is not None
    assert result.first_attempt.output.findings == []
    assert result.corrected_attempt is not None
    assert result.corrected_attempt.outcome == "accepted"
    assert result.corrected_attempt.score == 1
    assert result.score == 1
    assert summary.trials == 1
    assert summary.cases == 1
    assert summary.evaluations == 1


@pytest.mark.parametrize("judge_reason", ["judge\x00critique", "\ud800", "ok\udfff"])
def test_invalid_retry_feedback_is_a_corrected_attempt_infra_error(
    judge_reason: str, monkeypatch, tmp_path: Path
) -> None:
    corpus_path = _patch_dataset(monkeypatch, tmp_path, _faulty_case())
    script = tmp_path / "agent.py"
    script.write_text(f"print({json.dumps(_output())!r})\n", encoding="utf-8")

    class Judge:
        def score(self, case, output, diff):
            return target.JudgeScore(score=0.4, reason=judge_reason)

    summary = target.evaluate_external_review_agent(
        corpus_path=corpus_path,
        command=[sys.executable, str(script)],
        judge=Judge(),
    )

    result = summary.results[0]
    assert result.outcome == "infra_error"
    assert result.first_attempt.outcome == "rejected"
    assert result.first_attempt.score == 0.4
    assert result.corrected_attempt is not None
    assert result.corrected_attempt.outcome == "infra_error"
    assert result.corrected_attempt.output is None
    assert result.corrected_attempt.error == "invalid retry feedback"
    assert summary.infra_errors == 1


@pytest.mark.parametrize(
    ("source", "expected_error"),
    [
        ("import sys; sys.exit(7)", "agent exited with status 7"),
        ("print('not json')", "invalid agent output"),
    ],
)
def test_nonzero_and_invalid_json_are_infra_errors(
    source: str,
    expected_error: str,
    monkeypatch,
    tmp_path: Path,
) -> None:
    corpus_path = _patch_dataset(monkeypatch, tmp_path, _faulty_case())
    script = tmp_path / "agent.py"
    script.write_text(source, encoding="utf-8")

    summary = target.evaluate_external_review_agent(
        corpus_path=corpus_path,
        command=[sys.executable, str(script)],
    )

    result = summary.results[0]
    assert result.outcome == "infra_error"
    assert result.score is None
    assert result.first_attempt.outcome == "infra_error"
    assert expected_error in (result.first_attempt.error or "")
    assert result.corrected_attempt is None
    assert summary.infra_errors == 1
    assert summary.grade == "F"


@pytest.mark.parametrize(
    ("case_ids", "message"),
    [
        (["missing-case"], "unknown case ID(s): missing-case"),
        (["auth-bypass", "auth-bypass"], "case IDs must not be repeated"),
    ],
)
def test_case_filter_rejects_unknown_or_duplicate_ids(
    case_ids: list[str], message: str, monkeypatch, tmp_path: Path
) -> None:
    corpus_path = _patch_dataset(monkeypatch, tmp_path, _faulty_case())

    with pytest.raises(ValueError, match=re.escape(message)):
        target.evaluate_external_review_agent(
            corpus_path=corpus_path,
            command=[sys.executable, "agent.py"],
            case_ids=case_ids,
        )


def test_optional_judge_can_tighten_but_not_override_golden_score(
    monkeypatch, tmp_path: Path
) -> None:
    corpus_path = _patch_dataset(monkeypatch, tmp_path, _faulty_case())
    script = tmp_path / "agent.py"
    payload = json.dumps(_output())
    script.write_text(f"print({payload!r})\n", encoding="utf-8")

    class Judge:
        def score(self, case, output, diff):
            assert diff == DIFF
            return target.JudgeScore(score=0.4, reason="Explanation is incomplete.")

    summary = target.evaluate_external_review_agent(
        corpus_path=corpus_path,
        command=[sys.executable, str(script)],
        self_correct=False,
        judge=Judge(),
    )

    result = summary.results[0]
    assert result.outcome == "rejected"
    assert result.first_attempt.deterministic is not None
    assert result.first_attempt.deterministic.score == 1
    assert result.first_attempt.judge == target.JudgeScore(
        score=0.4, reason="Explanation is incomplete."
    )
    assert result.score == 0.4


def test_judge_failure_is_infra_error_without_discarding_valid_agent_output(
    monkeypatch, tmp_path: Path
) -> None:
    corpus_path = _patch_dataset(monkeypatch, tmp_path, _faulty_case())
    script = tmp_path / "agent.py"
    payload = json.dumps(_output())
    script.write_text(f"print({payload!r})\n", encoding="utf-8")

    class Judge:
        def score(self, case, output, diff):
            raise RuntimeError("network content must not be persisted")

    summary = target.evaluate_external_review_agent(
        corpus_path=corpus_path,
        command=[sys.executable, str(script)],
        judge=Judge(),
    )

    attempt = summary.results[0].first_attempt
    assert attempt.outcome == "infra_error"
    assert attempt.output is not None
    assert attempt.deterministic is not None
    assert attempt.error == "judge failed: RuntimeError"
    assert "network content" not in attempt.model_dump_json()


def test_otel_projection_has_metrics_but_no_evaluation_content() -> None:
    sensitive = "RAW-DIFF-OUTPUT-EXPECTED-JUDGE-REASON"
    attempt = target.AttemptResult(
        attempt=1,
        outcome="accepted",
        score=1,
        deterministic=target.FindingScore(
            true_positives=1,
            false_positives=0,
            false_negatives=0,
            precision=1,
            recall=1,
            f1=1,
            verdict_correct=True,
            score=1,
            reason=sensitive,
        ),
        judge=target.JudgeScore(score=1, reason=sensitive),
        output=target.ReviewAgentOutput.model_validate(_output()),
        latency_ms=10,
    )
    result = target.TrialResult(
        case_id="auth-bypass",
        trial=1,
        outcome="accepted",
        score=1,
        first_attempt=attempt,
        latency_ms=10,
    )

    attributes = target.trial_span_attributes(
        result,
        corpus_id="goldens",
        corpus_version="1.0.0",
        command_sha256="a" * 64,
    )

    assert sensitive not in json.dumps(attributes)
    assert attributes["agent_eval.trial.outcome"] == "accepted"
    assert attributes["gen_ai.evaluation.score.value"] == 1
    assert attributes["agent_eval.findings.true_positives"] == 1
    assert not any(
        term in key.casefold()
        for key in attributes
        for term in ("input", "output", "expected", "reason", "rationale")
    )


def test_cli_is_evaluation_only() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "eval-review-agent" in result.output
    assert "evaluation-only harness" in result.output.casefold()
    assert "  review " not in result.output
