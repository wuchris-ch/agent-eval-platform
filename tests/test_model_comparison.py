"""Model comparison: same suite on several models, cheapest passing model wins."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agent_eval.blackbox.comparison import (
    ComparisonPlan,
    ModelPrice,
    ModelSpec,
    compare,
    recommend,
    render_markdown,
    run_cost,
    summarize,
)
from agent_eval.blackbox.models import Case, Metric, Observation, Suite, digest
from agent_eval.blackbox.runner import evaluate
from agent_eval.blackbox.targets import MeteredOutput
from agent_eval.cli import app
from test_model_target import chat_server

SUITE = Suite(
    schema_version="1.0",
    id="release",
    version="1",
    metrics=[Metric(name="decision", kind="json_subset")],
    cases=[
        Case(
            id="outage", input={"incident": "down"}, expected_output={"s": "critical"}
        ),
        Case(id="typo", input={"incident": "typo"}, expected_output={"s": "low"}),
    ],
)
CORRECT = {"down": "critical", "typo": "low"}


class FakeModel:
    """A fake model client that answers each case and reports fixed usage."""

    mode = "model"

    def __init__(self, name, wrong=(), tokens=(100, 20)):
        self.identity = digest(name)
        self.wrong = set(wrong)
        self.tokens = tokens
        self.inputs = []

    def invoke(self, input_value):
        self.inputs.append(input_value)
        incident = input_value["incident"]
        answer = "medium" if incident in self.wrong else CORRECT[incident]
        return MeteredOutput({"s": answer}, *self.tokens)


def hosted(label, input_price=5.0, output_price=30.0):
    return ModelSpec(
        label=label,
        model=label,
        deployment="hosted",
        base_url_env="MODEL_GATEWAY_BASE_URL",
        price=ModelPrice(
            input_usd_per_million_tokens=input_price,
            output_usd_per_million_tokens=output_price,
        ),
    )


def local(label, hardware=0.0):
    return ModelSpec(
        label=label,
        model=label,
        deployment="local",
        base_url="http://127.0.0.1:11434/v1",
        price=ModelPrice(hardware_usd_per_hour=hardware),
    )


def replayed(latencies, tokens=(10, 5)):
    """A report built from recorded observations with chosen latency and usage."""
    observations = [
        Observation(
            case_id=case.id,
            input_sha256=digest(case.input),
            actual_output=case.expected_output,
            latency_ms=latency,
            tokens_in=tokens[0],
            tokens_out=tokens[1],
        )
        for case, latency in zip(SUITE.cases, latencies, strict=True)
    ]
    return evaluate(SUITE, agent="replay", observations=observations)


def test_cheapest_passing_model_is_recommended_and_failures_are_shown():
    big = FakeModel("hosted-big", tokens=(1000, 200))
    good_local = FakeModel("local-good")
    weak_local = FakeModel("local-weak", wrong={"down"})
    comparison, reports = compare(
        SUITE,
        [
            (hosted("hosted-big"), big),
            (local("local-good"), good_local),
            (local("local-weak"), weak_local),
        ],
        trials=2,
    )

    by_label = {result.label: result for result in comparison.models}
    assert by_label["hosted-big"].passed and by_label["local-good"].passed
    assert not by_label["local-weak"].passed
    assert by_label["local-weak"].accepted == 2 and by_label["local-weak"].rejected == 2
    # 4 evaluations x (1000 in at $5/M + 200 out at $30/M).
    assert by_label["hosted-big"].cost_usd == pytest.approx(4 * (0.005 + 0.006))
    assert by_label["local-good"].cost_usd == 0
    assert by_label["local-good"].tokens_in == 400
    assert comparison.recommended == "local-good"
    assert [report.agent for report in reports] == [
        "hosted-big",
        "local-good",
        "local-weak",
    ]
    # Every model received exactly the same inputs.
    assert big.inputs == good_local.inputs == weak_local.inputs
    table = render_markdown(comparison)
    assert "| local-weak (local-weak) | local | FAIL | 2 / 4 |" in table
    assert "**Recommendation:** local-good." in table


def test_free_model_that_fails_the_gate_is_never_recommended():
    comparison, _ = compare(
        SUITE,
        [
            (local("local-weak"), FakeModel("local-weak", wrong={"typo"})),
            (hosted("hosted-mini", 0.75, 4.5), FakeModel("hosted-mini")),
            (hosted("hosted-big"), FakeModel("hosted-big")),
        ],
        trials=1,
    )
    assert comparison.recommended == "hosted-mini"


def test_no_recommendation_when_every_model_fails():
    comparison, _ = compare(
        SUITE,
        [
            (local("a"), FakeModel("a", wrong={"down"})),
            (hosted("b"), FakeModel("b", wrong={"typo"})),
        ],
        trials=1,
    )
    assert comparison.recommended is None
    assert comparison.reason == "No model passed the release gate."


def test_local_hardware_cost_uses_model_time():
    report = replayed([1800_000, 1800_000])
    # One hour of model time at $0.40 per hour; tokens are free locally.
    assert run_cost(local("x", hardware=0.4).price, report) == pytest.approx(0.4)
    assert run_cost(hosted("y", 2, 10).price, report) == pytest.approx(
        (20 * 2 + 10 * 10) / 1_000_000
    )


def test_missing_usage_makes_hosted_cost_unknown_and_blocks_recommendation():
    report = replayed([10, 10], tokens=(None, None))
    assert run_cost(hosted("y").price, report) is None
    assert run_cost(local("x").price, report) == 0
    result = summarize(hosted("y"), report)
    assert result.passed and result.usage_measured == 0
    assert recommend([result]) == (
        None,
        "Passing models lack complete token usage, so their cost is unknown.",
    )


def test_equal_cost_falls_back_to_faster_median_latency():
    slow = summarize(local("slow"), replayed([3000, 3000]))
    fast = summarize(local("fast"), replayed([1000, 1200]))
    assert recommend([slow, fast])[0] == "fast"
    assert fast.p95_latency_ms == 1200 and fast.model_seconds == pytest.approx(2.2)


@pytest.mark.parametrize(
    "change, message",
    [
        ({"deployment": "local"}, "zero dollars per token"),
        ({"base_url": "http://127.0.0.1:11434/v1"}, "exactly one"),
        ({"price": {"hardware_usd_per_hour": 1}}, "only to local"),
    ],
)
def test_model_specs_reject_inconsistent_prices_and_routes(change, message):
    value = hosted("h").model_dump() | change
    with pytest.raises(ValidationError, match=message):
        ModelSpec.model_validate(value)


def test_plan_needs_two_uniquely_labelled_models():
    with pytest.raises(ValidationError, match="unique"):
        ComparisonPlan(schema_version="1.0", models=[local("a"), local("a")])
    with pytest.raises(ValidationError):
        ComparisonPlan(schema_version="1.0", models=[local("a")])


def test_cli_compares_models_and_writes_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    suite_path = tmp_path / "suite.json"
    suite_path.write_text(SUITE.model_dump_json())
    out = tmp_path / "comparison"
    with (
        chat_server(
            '{"s": "critical"}', usage={"prompt_tokens": 30, "completion_tokens": 4}
        ) as (good_url, _),
        chat_server(
            '{"s": "low"}', usage={"prompt_tokens": 30, "completion_tokens": 4}
        ) as (bad_url, _),
    ):
        monkeypatch.setenv("TEST_GATEWAY_URL", bad_url)
        plan = tmp_path / "models.yaml"
        plan.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "models": [
                        {
                            "label": "hosted",
                            "model": "gateway-model",
                            "deployment": "hosted",
                            "base_url_env": "TEST_GATEWAY_URL",
                            "price": {
                                "input_usd_per_million_tokens": 5,
                                "output_usd_per_million_tokens": 30,
                            },
                        },
                        {
                            "label": "ollama",
                            "model": "qwen2.5:7b",
                            "deployment": "local",
                            "base_url": good_url,
                        },
                    ],
                }
            )
        )
        result = CliRunner().invoke(
            app,
            [
                "blackbox",
                "compare-models",
                "--suite",
                str(suite_path),
                "--models",
                str(plan),
                "--out",
                str(out),
                "--response-format",
                "json",
            ],
        )

    # Each fake server answers every case the same way, so each passes one of two cases.
    assert result.exit_code == 2, result.output
    assert "FAIL  hosted  accepted=1/2  tokens=60/8  cost=$0.0005" in result.output
    assert "Recommended: none." in result.output
    saved = json.loads((out / "comparison.json").read_text())
    assert [model["label"] for model in saved["models"]] == ["hosted", "ollama"]
    assert (out / "reports" / "ollama.json").exists()
    assert (
        "| ollama (qwen2.5:7b) | local | FAIL |" in (out / "comparison.md").read_text()
    )
