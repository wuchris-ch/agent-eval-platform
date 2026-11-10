"""Model targets: any OpenAI-compatible chat API, including a local Ollama server."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from typer.testing import CliRunner

from agent_eval.blackbox.models import Case, Metric, Suite
from agent_eval.blackbox.runner import evaluate
from agent_eval.blackbox.targets import ModelTarget
from agent_eval.cli import app


def triage_suite():
    return Suite(
        schema_version="1.0",
        id="model-suite",
        version="1",
        metrics=[Metric(name="decision", kind="json_subset")],
        cases=[
            Case(
                id="outage",
                input={"incident": "All requests fail."},
                expected_output={"severity": "critical"},
            )
        ],
    )


@contextmanager
def chat_server(content, usage=None, body=None):
    """Serve a fixed chat completion and record each request."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, dict(self.headers), json.loads(raw)))
            reply = {
                "choices": [{"message": {"role": "assistant", "content": content}}]
            }
            if usage is not None:
                reply["usage"] = usage
            encoded = body if body is not None else json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_model_target_sends_only_input_and_records_reported_usage():
    with chat_server(
        '{"severity": "critical", "escalate": true}',
        usage={"prompt_tokens": 40, "completion_tokens": 9},
    ) as (base_url, requests):
        target = ModelTarget(
            base_url,
            "qwen2.5:7b",
            system_prompt="Classify the incident.",
            response_format="json",
            api_key="test-key",
        )
        report = evaluate(triage_suite(), agent="local", target=target, trials=2)

    assert report.mode == "model"
    assert report.passed and report.accepted == 2
    assert (report.tokens_in, report.tokens_out) == (80, 18)
    assert all(r.observation.tokens_in == 40 for r in report.results)
    path, headers, request = requests[0]
    assert path == "/v1/chat/completions"
    assert headers["Authorization"] == "Bearer test-key"
    assert request["model"] == "qwen2.5:7b"
    assert request["response_format"] == {"type": "json_object"}
    assert request["messages"] == [
        {"role": "system", "content": "Classify the incident."},
        {"role": "user", "content": '{"incident":"All requests fail."}'},
    ]
    # The expected answer never reaches the model.
    assert "critical" not in json.dumps(request)


def test_non_json_answer_is_a_rejection_and_missing_usage_stays_missing():
    with chat_server("It looks critical to me.") as (base_url, _):
        target = ModelTarget(base_url, "llama3.2:3b", response_format="json")
        report = evaluate(triage_suite(), agent="local", target=target)

    assert report.rejected == 1 and report.infra_errors == 0
    assert report.results[0].observation.actual_output == "It looks critical to me."
    assert report.tokens_in is None and report.tokens_out is None


def test_malformed_completion_is_an_infrastructure_error():
    with chat_server("", body=b'{"error": "model not found"}') as (base_url, _):
        report = evaluate(
            triage_suite(), agent="local", target=ModelTarget(base_url, "missing")
        )

    assert report.infra_errors == 1
    assert report.results[0].error == "invalid_output"


def test_cli_runs_a_model_target(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    suite_path = tmp_path / "suite.json"
    suite_path.write_text(triage_suite().model_dump_json())
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Return JSON with a severity field.")
    with chat_server(
        '{"severity": "critical"}',
        usage={"prompt_tokens": 12, "completion_tokens": 5},
    ) as (base_url, requests):
        monkeypatch.setenv("LOCAL_MODEL_URL", base_url)
        result = CliRunner().invoke(
            app,
            [
                "blackbox",
                "run",
                "--suite",
                str(suite_path),
                "--agent",
                "ollama-qwen",
                "--url-env",
                "LOCAL_MODEL_URL",
                "--model",
                "qwen2.5:7b",
                "--system-prompt",
                str(prompt),
                "--response-format",
                "json",
            ],
        )

    assert result.exit_code == 0, result.output
    assert "Tokens: in=12 out=5" in result.output
    assert requests[0][2]["messages"][0]["content"] == prompt.read_text()


def test_cli_requires_a_model_for_a_system_prompt(tmp_path):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("instructions")
    suite_path = tmp_path / "suite.json"
    suite_path.write_text(triage_suite().model_dump_json())
    result = CliRunner().invoke(
        app,
        [
            "blackbox",
            "run",
            "--suite",
            str(suite_path),
            "--agent",
            "x",
            "--url-env",
            "UNUSED",
            "--system-prompt",
            str(prompt),
        ],
    )
    assert result.exit_code == 1
