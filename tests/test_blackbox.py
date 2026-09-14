from __future__ import annotations

import json
import shlex
import sqlite3
import sys
import threading
import time
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agent_eval.blackbox.models import (
    Case,
    Metric,
    Observation,
    Suite,
    digest,
    load_suite,
)
from agent_eval.blackbox.runner import evaluate
from agent_eval.blackbox.scoring import DeepEvalJudge
from agent_eval.blackbox.storage import (
    load_database_observations,
    load_observations,
    save_report,
)
from agent_eval.blackbox.targets import (
    CommandTarget,
    HttpTarget,
    ResponseDecoder,
    TargetError,
)
from agent_eval.blackbox.telemetry import export_report, result_attributes
from agent_eval.cli import app


def suite(expected="answer", input_value="question", metrics=None):
    return Suite(
        schema_version="1.0",
        id="test-suite",
        version="1",
        metrics=metrics or [Metric(name="correctness", kind="exact_match")],
        cases=[Case(id="case-a", input=input_value, expected_output=expected)],
    )


def recorded(s, actual="answer", trial=1, **kwargs):
    return Observation(
        case_id=s.cases[0].id,
        trial=trial,
        input_sha256=digest(s.cases[0].input),
        actual_output=actual,
        **kwargs,
    )


def script(code, **kwargs):
    return CommandTarget([sys.executable, "-c", code], **kwargs)


def test_command_is_blind_and_environment_is_explicit(monkeypatch):
    monkeypatch.setenv("TEST_HIDDEN_GOLDEN", "secret-answer")
    monkeypatch.setenv("AGENT_TEST_CREDENTIAL", "test-credential")
    target = script(
        "import json,os,sys; print(json.dumps({'input':sys.stdin.read(),"
        "'secret':os.environ.get('TEST_HIDDEN_GOLDEN'),"
        "'credential':os.environ.get('AGENT_TEST_CREDENTIAL'),"
        "'files':os.listdir('.')}))",
        env_names=["AGENT_TEST_CREDENTIAL"],
        decoder=ResponseDecoder("json"),
    )
    s = suite(
        expected={
            "input": "question",
            "secret": None,
            "credential": "test-credential",
            "files": [],
        }
    )
    s.cases[0].context = ["hidden reference"]
    assert evaluate(s, agent="any-agent", target=target).passed


def test_command_sends_native_json_and_accepts_native_text():
    s = suite(expected='{"a":1,"b":2}', input_value={"b": 2, "a": 1})
    report = evaluate(
        s,
        agent="any-agent",
        target=script("import sys; sys.stdout.write(sys.stdin.read())"),
    )
    assert report.passed
    assert report.results[0].observation.latency_ms >= 0


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (
            "import sys; print('private content',file=sys.stderr); sys.exit(7)",
            "target_exit",
        ),
        ("import time; time.sleep(10)", "target_timeout"),
        ("import os,time; os.close(1); os.close(2); time.sleep(10)", "target_timeout"),
        ("print('x' * 1100000)", "target_output_limit"),
        ("import sys; sys.stderr.write('x' * 70000)", "target_output_limit"),
        ("import sys; sys.stdout.buffer.write(b'\\xff')", "invalid_output"),
    ],
)
def test_command_failures_are_infrastructure_errors(code, error):
    report = evaluate(suite(), agent="test", target=script(code, timeout=0.2))
    assert report.infra_errors == 1 and report.average_score == 0
    assert report.results[0].error == error
    assert "private content" not in report.model_dump_json()


def test_missing_command_is_infrastructure_error():
    report = evaluate(
        suite(), agent="test", target=CommandTarget(["/not-an-agent-command"])
    )
    assert report.results[0].error == "target_start"


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), 0, -1])
def test_invalid_timeouts(timeout):
    with pytest.raises(ValueError):
        CommandTarget(["test"], timeout=timeout)


@pytest.mark.parametrize(
    "raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b"{} trailing"]
)
def test_json_output_rejects_ambiguous_or_nonfinite_values(raw):
    with pytest.raises(TargetError, match="invalid_output"):
        ResponseDecoder("json").decode(raw)


def test_native_json_pointer():
    assert (
        ResponseDecoder("json", "/choices/0/message/content").decode(
            b'{"choices":[{"message":{"content":"answer"}}]}'
        )
        == "answer"
    )
    assert ResponseDecoder("json", "/a~1b/~0").decode(b'{"a/b":{"~":42}}') == 42
    with pytest.raises(TargetError):
        ResponseDecoder("json", "/missing").decode(b'{"answer":"private"}')


@contextmanager
def http_server(body=b'{"answer":"answer"}', status=200, delay=0, drip_headers=False):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            calls.append(
                (
                    self.path,
                    dict(self.headers),
                    self.rfile.read(int(self.headers["Content-Length"])),
                )
            )
            if drip_headers:
                try:
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-test: ")
                    for _ in range(30):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.02)
                    self.wfile.write(b"\r\nContent-Length: 0\r\n\r\n")
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            time.sleep(delay)
            self.send_response(status)
            self.send_header("Location", "/should-not-follow")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/ask", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_http_native_request_auth_and_response_pointer():
    with http_server() as (url, calls):
        target = HttpTarget(
            url,
            decoder=ResponseDecoder("json", "/answer"),
            bearer_token="example-token",
        )
        s = suite(input_value={"question": "Where is help?"})
        report = evaluate(s, agent="faq-http", target=target)
    assert report.passed
    assert json.loads(calls[0][2]) == {"question": "Where is help?"}
    assert calls[0][1]["Authorization"] == "Bearer example-token"
    assert "example-token" not in report.model_dump_json()
    assert url not in report.model_dump_json()


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"status": 302}, "target_transport"),
        ({"status": 500}, "target_transport"),
        ({"delay": 0.2}, "target_timeout"),
        ({"drip_headers": True}, "target_timeout"),
        ({"body": b"x" * 1100000}, "target_output_limit"),
    ],
)
def test_http_errors_and_redirects(kwargs, error):
    with http_server(**kwargs) as (url, calls):
        report = evaluate(suite(), agent="test", target=HttpTarget(url, timeout=0.1))
    assert len(calls) == 1
    assert report.results[0].error == error


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/file",
        "http://user:password@example.com",
        "http://example.com/#fragment",
        "http://example.com:bad",
    ],
)
def test_http_configuration_rejects_invalid_endpoints(url):
    with pytest.raises(ValueError):
        HttpTarget(url)


@pytest.mark.parametrize(
    ("kind", "expected", "actual", "passed"),
    [
        ("exact_match", True, 1, False),
        ("exact_match", "answer", "answer\n", False),
        ("exact_match", None, None, True),
        ("contains", "answer", "The answer is here.", True),
        ("contains", "answer", {"answer": True}, False),
        ("json_subset", {"ok": True}, {"ok": True, "detail": "native response"}, True),
        ("json_subset", {"ok": True}, {"ok": 1}, False),
        ("json_subset", {"a": [{"b": 1}]}, {"a": [{"b": 1, "c": 2}]}, True),
    ],
)
def test_metric_behavior(kind, expected, actual, passed):
    s = suite(expected, metrics=[Metric(name="check", kind=kind)])
    report = evaluate(s, agent="test", observations=[recorded(s, actual)])
    assert report.passed is passed
    assert report.rejected == int(not passed)


def test_judge_cannot_override_failed_deterministic_gate():
    s = suite(
        metrics=[
            Metric(name="exact", kind="exact_match"),
            Metric(name="quality", kind="geval", criteria="Correctness", threshold=0.6),
        ]
    )
    judge = SimpleNamespace(measure=lambda *_args: (1.0, "good"))
    report = evaluate(s, agent="test", observations=[recorded(s, "wrong")], judge=judge)
    assert report.rejected == 1 and report.results[0].score == 0


@pytest.mark.parametrize("value", [None, float("nan"), float("inf"), -1, 1.01, True])
def test_bad_judge_evidence_fails_closed(value):
    s = suite(metrics=[Metric(name="quality", kind="geval", criteria="Correctness")])
    report = evaluate(
        s,
        agent="test",
        observations=[recorded(s)],
        judge=SimpleNamespace(measure=lambda *_: (value, "private reason")),
    )
    assert report.results[0].error == "judge_error"
    assert report.average_score == 0 and not report.passed


def test_judge_required_before_target_invocation():
    s = suite(metrics=[Metric(name="quality", kind="geval", criteria="Correctness")])
    with pytest.raises(ValueError, match="enable the judge"):
        evaluate(
            s,
            agent="test",
            target=SimpleNamespace(invoke=lambda _: pytest.fail("target called")),
        )


def test_replay_missing_failed_and_mismatched_records():
    s = suite()
    observations = [
        recorded(s),
        recorded(s, trial=2, status="error"),
        recorded(s, trial=3),
    ]
    observations[2].input_sha256 = "0" * 64
    report = evaluate(s, agent="test", observations=observations, trials=4)
    assert (report.accepted, report.infra_errors, report.average_score) == (1, 3, 0.25)
    assert [result.error for result in report.results] == [
        None,
        "recorded_error",
        "input_mismatch",
        "missing_observation",
    ]
    assert report.median_latency_ms is None


def test_replay_duplicate_and_extra_trials_are_rejected():
    s = suite()
    for observations in ([recorded(s), recorded(s)], [recorded(s, trial=2)]):
        with pytest.raises(ValueError, match="duplicate or unexpected"):
            evaluate(s, agent="test", observations=observations)


@pytest.mark.parametrize(
    "change",
    [
        {"cases": []},
        {"metrics": []},
        {"metrics": [{"name": "x", "kind": "geval"}]},
        {"metrics": [{"name": "x", "kind": "exact_match", "threshold": float("nan")}]},
    ],
)
def test_invalid_suites(change):
    payload = suite().model_dump()
    payload.update(change)
    with pytest.raises(ValidationError):
        Suite.model_validate(payload)


def test_suite_duplicate_keys_and_ids_are_rejected(tmp_path):
    path = tmp_path / "suite.yaml"
    path.write_text("id: one\nid: two\n")
    with pytest.raises(ValueError):
        load_suite(path)
    s = suite().model_dump()
    s["cases"].append(s["cases"][0])
    with pytest.raises(ValidationError):
        Suite.model_validate(s)


def test_private_snapshot_and_replay_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "private"))
    s = suite()
    report = evaluate(
        s, agent="agent-a-v1", target=script("import sys; sys.stdout.write('answer')")
    )
    path = save_report(s, report)
    s.cases[0].expected_output = "changed after run"
    frozen = load_suite(path.parent / "suite.json")
    assert digest(frozen.model_dump(mode="json")) == report.suite_sha256
    replay = evaluate(
        frozen,
        agent="agent-a-v1",
        observations=load_observations(path.parent / "observations.jsonl"),
    )
    assert replay.passed
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    with sqlite3.connect(path.parent.parent / "metrics.db") as conn:
        assert conn.execute("SELECT accepted, agent FROM blackbox_runs").fetchone() == (
            1,
            "agent-a-v1",
        )


def test_sqlite_read_only_replay_and_json_values(tmp_path):
    database = tmp_path / "proxy.db"
    s = suite()
    with sqlite3.connect(database) as conn:
        conn.execute(
            "CREATE TABLE observed (case_id TEXT, input_sha256 TEXT, actual_output_json TEXT)"
        )
        conn.execute(
            "INSERT INTO observed VALUES (?, ?, ?)",
            ("case-a", digest("question"), json.dumps("answer")),
        )
    query = tmp_path / "read.sql"
    query.write_text("SELECT * FROM observed")
    values = load_database_observations(query, sqlite_path=database)
    assert evaluate(s, agent="from-proxy", observations=values).passed
    for statement in (
        "DELETE FROM observed",
        "ATTACH DATABASE ':memory:' AS more",
        "PRAGMA user_version = 1",
        "SELECT load_extension('bad')",
    ):
        query.write_text(statement)
        with pytest.raises(sqlite3.DatabaseError):
            load_database_observations(query, sqlite_path=database)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM observed").fetchone()[0] == 1


def test_trace_export_is_content_free_and_failure_is_nonfatal(monkeypatch):
    s = suite(expected="private-output", input_value="private-prompt")
    s.cases[0].id = "private-case"
    report = evaluate(
        s, agent="private-agent", observations=[recorded(s, "private-output")]
    )
    serialized = json.dumps(result_attributes(report, report.results[0]))
    for private in (
        "private-output",
        "private-prompt",
        "private-case",
        "private-agent",
    ):
        assert private not in serialized
    monkeypatch.setenv("AGENT_EVAL_OTEL_ENABLED", "1")
    monkeypatch.setattr(
        "agent_eval.observability._get_runtime",
        lambda: (_ for _ in ()).throw(RuntimeError("private endpoint")),
    )
    assert export_report(report) is False
    assert report.passed


def test_otel_spans_and_source_link(monkeypatch):
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setenv("AGENT_EVAL_OTEL_ENABLED", "1")
    monkeypatch.delenv("OTEL_TRACES_EXPORTER", raising=False)
    monkeypatch.setattr(
        "agent_eval.observability._get_runtime",
        lambda: SimpleNamespace(provider=provider, tracer=provider.get_tracer("test")),
    )
    s = suite()
    obs = recorded(s, trace_id="1" * 32, span_id="2" * 16)
    assert export_report(evaluate(s, agent="test", observations=[obs]))
    spans = exporter.get_finished_spans()
    assert len(spans) == 2
    trial = next(span for span in spans if span.name.endswith("trial"))
    assert trial.links[0].context.trace_id == int("1" * 32, 16)
    assert trial.events[0].attributes["gen_ai.evaluation.score.value"] == 1
    provider.shutdown()


def test_actual_deepeval_contract_without_model_network(monkeypatch):
    deepeval = pytest.importorskip("deepeval.metrics")
    calls = []

    class MetricStub:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def measure(self, case):
            calls.append(case)
            self.score, self.reason = 0.8, "supported"

    monkeypatch.setattr(deepeval, "GEval", MetricStub)
    monkeypatch.setenv("MODEL_GATEWAY_API_KEY", "unit-test-placeholder")
    monkeypatch.setenv("AGENT_EVAL_JUDGE_MODEL", "test-model")
    monkeypatch.setenv("MODEL_GATEWAY_BASE_URL", "http://127.0.0.1:1/v1")
    s = suite(
        metrics=[
            Metric(name="quality", kind="geval", criteria="Correctness", threshold=0.6)
        ]
    )
    s.cases[0].context = ["reference document"]
    report = evaluate(
        s, agent="test", observations=[recorded(s)], judge=DeepEvalJudge()
    )
    assert report.passed
    assert calls[1].context == ["reference document"]
    assert calls[1].expected_output == "answer"


def test_real_geval_scores_with_schema_based_model_responses(monkeypatch):
    pytest.importorskip("deepeval.metrics")
    monkeypatch.setenv("MODEL_GATEWAY_API_KEY", "unit-test-placeholder")
    monkeypatch.setenv("AGENT_EVAL_JUDGE_MODEL", "test-model")
    monkeypatch.setenv("MODEL_GATEWAY_BASE_URL", "http://127.0.0.1:1/v1")
    judge = DeepEvalJudge()
    prompts = []

    def generate(prompt, schema=None):
        prompts.append(prompt)
        if "steps" in schema.model_fields:
            return schema(steps=["Compare the answer with the reference."])
        return schema(score=8, reason="The answer matches the reference.")

    monkeypatch.setattr(judge.model, "generate", generate)
    s = suite(
        metrics=[
            Metric(
                name="correctness",
                kind="geval",
                criteria="Check reference facts.",
                threshold=0.6,
            )
        ]
    )
    report = evaluate(s, agent="test", observations=[recorded(s)], judge=judge)
    assert report.passed
    assert report.average_score == pytest.approx(0.8)
    assert len(prompts) == 2


def test_changed_suite_cannot_be_saved_with_old_report(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    s = suite()
    report = evaluate(s, agent="test", observations=[recorded(s)])
    s.cases[0].expected_output = "changed"
    with pytest.raises(ValueError, match="snapshot"):
        save_report(s, report)


def test_cli_live_import_and_replay(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    runner = CliRunner()
    goldens = tmp_path / "generated.json"
    goldens.write_text(
        json.dumps(
            [
                {
                    "id": "case-a",
                    "input": "question",
                    "expected_output": "answer",
                    "tags": ["faq"],
                }
            ]
        )
    )
    result = runner.invoke(
        app,
        [
            "blackbox",
            "import-goldens",
            "--goldens",
            str(goldens),
            "--suite-id",
            "generated",
            "--version",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    path = next((tmp_path / "state" / "blackbox" / "suites").glob("*.json"))
    command = shlex.join(
        [sys.executable, "-c", "import sys; sys.stdout.write('answer')"]
    )
    result = runner.invoke(
        app,
        [
            "blackbox",
            "run",
            "--suite",
            str(path),
            "--agent",
            "custom",
            "--command",
            command,
        ],
    )
    assert result.exit_code == 0, result.output
    report = next((tmp_path / "state" / "blackbox").glob("*/report.json"))
    result = runner.invoke(
        app,
        [
            "blackbox",
            "replay",
            "--suite",
            str(path),
            "--agent",
            "custom",
            "--observations",
            str(report.parent / "observations.jsonl"),
        ],
    )
    assert result.exit_code == 0, result.output


def test_cli_rejection_exit_and_no_sensitive_output(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    path = tmp_path / "suite.json"
    path.write_text(suite().model_dump_json())
    command = shlex.join([sys.executable, "-c", "print('private-answer')"])
    result = CliRunner().invoke(
        app,
        [
            "blackbox",
            "run",
            "--suite",
            str(path),
            "--agent",
            "test",
            "--command",
            command,
        ],
    )
    assert result.exit_code == 2
    assert "private-answer" not in result.output
