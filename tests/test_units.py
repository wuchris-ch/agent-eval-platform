import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_eval.agents.claude_code import ClaudeCodeAdapter
from agent_eval.evaluators import tests as evaluator_tests
from agent_eval.evaluators.tests import (
    parse_coverage,
    parse_coverage_artifact,
    parse_junit,
)
from agent_eval.report import pass_at_k
from agent_eval.task import EvaluationConfig, JudgeConfig, SandboxNetwork, load_task

REPO = Path(__file__).resolve().parents[1]


def test_load_example_task():
    task = load_task("example-todo-api")
    assert task.schema_version == "agent-eval.task/v1"
    assert task.version == "2.0.0"
    assert task.manifest_binding == "versioned"
    assert task.dataset is not None
    assert task.dataset.id == "agent-eval/bundled"
    assert task.dataset.revision == "2.0.0"
    assert task.dataset.item_id == task.id
    assert task.image_tag.startswith("agent-eval/example-todo-api:")
    assert task.image_tag != "agent-eval/example-todo-api:latest"
    assert len(task.image_tag.rsplit(":", 1)[1]) == 12
    assert "junit.xml" in task.test_command
    assert task.evaluation.mode == "isolated-black-box"
    assert task.evaluation.submission_port == 8080
    assert task.evaluation.readiness is not None
    assert task.evaluation.readiness.path == "/openapi.json"
    assert task.validate_layout() == []
    assert abs(sum(task.judge.weights.values()) - 1.0) < 1e-9


def test_evaluation_config_defaults_to_cooperative_for_legacy_tasks():
    configuration = EvaluationConfig.model_validate({})

    assert configuration.mode == "cooperative"
    assert configuration.submission_command is None
    assert configuration.submission_port is None
    assert configuration.readiness is None


@pytest.mark.parametrize(
    "configuration",
    [
        {"mode": "isolated-black-box"},
        {
            "mode": "isolated-black-box",
            "submission_command": "python service.py",
            "submission_port": 1023,
            "readiness": {"path": "/ready"},
        },
        {
            "mode": "isolated-black-box",
            "submission_command": "python service.py",
            "submission_port": 8080,
            "readiness": {"path": "//other-host/ready"},
        },
        {
            "mode": "isolated-black-box",
            "submission_command": "python service.py",
            "submission_port": 8080,
            "readiness": {"path": "/../ready"},
        },
        {
            "mode": "cooperative",
            "submission_command": "python service.py",
        },
    ],
)
def test_evaluation_config_rejects_incomplete_or_unsafe_contract(configuration):
    with pytest.raises(ValidationError):
        EvaluationConfig.model_validate(configuration)


def test_load_task_rejects_non_mapping_yaml(tmp_path):
    task_dir = tmp_path / "not-a-mapping"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text("- this\n- is\n- a-list\n")

    with pytest.raises(ValueError, match="task manifest must be a YAML mapping"):
        load_task("not-a-mapping", tmp_path)


def test_load_task_rejects_duplicate_yaml_keys(tmp_path):
    task_dir = tmp_path / "duplicate-key"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: duplicate-key\n"
        "prompt: first\n"
        "prompt: second\n"
        "test_command: pytest\n"
    )

    with pytest.raises(ValueError, match="duplicate YAML key 'prompt'"):
        load_task("duplicate-key", tmp_path)


def test_task_rejects_duplicate_challenge_ids(tmp_path):
    task_dir = tmp_path / "duplicate-challenges"
    task_dir.mkdir()
    challenge = (
        "  - id: duplicate\n"
        "    category: ASI01\n"
        "    threat: bounded threat\n"
        "    checks:\n"
        "      - type: no_infra_failure\n"
    )
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: duplicate-challenges\n"
        "prompt: Test\n"
        "test_command: pytest\n"
        "challenges:\n"
        f"{challenge}{challenge}"
    )

    with pytest.raises(ValidationError, match="challenge ids must be unique"):
        load_task("duplicate-challenges", tmp_path)


def test_judge_weights_are_bounded_and_finite():
    with pytest.raises(ValidationError, match="between 1 and 32"):
        JudgeConfig(weights={f"dimension-{index}": 1.0 for index in range(33)})
    with pytest.raises(ValidationError, match="finite positive"):
        JudgeConfig(weights={"quality": float("nan")})
    with pytest.raises(ValidationError, match="finite positive"):
        JudgeConfig(weights={"x" * 65: 1.0})


def test_proxy_image_requires_exact_digest():
    with pytest.raises(ValidationError, match="exact sha256"):
        SandboxNetwork(proxy_image="ubuntu/squid:latest")
    with pytest.raises(ValidationError, match="exact sha256"):
        SandboxNetwork(proxy_image="ubuntu/squid@sha256:not-a-digest")


def test_load_task_normalizes_legacy_manifest_with_visible_identity(tmp_path):
    task_dir = tmp_path / "unversioned"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        "id: unversioned\nprompt: Test\ntest_command: pytest\n"
    )

    task = load_task("unversioned", tmp_path)

    assert task.schema_version == "agent-eval.task/v1"
    assert task.version == "legacy-unversioned"
    assert task.manifest_binding == "legacy-unversioned"


@pytest.mark.parametrize(
    "version_lines",
    ["schema_version: agent-eval.task/v1\n", "version: 1.0.0\n"],
)
def test_load_task_rejects_partially_versioned_manifest(tmp_path, version_lines):
    task_dir = tmp_path / "partially-versioned"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        version_lines
        + "id: partially-versioned\n"
        + "prompt: Test\n"
        + "test_command: pytest\n"
    )

    with pytest.raises(ValueError, match="define schema_version and version together"):
        load_task("partially-versioned", tmp_path)


def test_load_task_rejects_unknown_schema_version(tmp_path):
    task_dir = tmp_path / "future-schema"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v2\n"
        "version: 1.0.0\n"
        "id: future-schema\n"
        "prompt: Test\n"
        "test_command: pytest\n"
    )

    with pytest.raises(ValidationError, match="agent-eval.task/v1"):
        load_task("future-schema", tmp_path)


def test_load_task_rejects_internal_path_field(tmp_path):
    task_dir = tmp_path / "forged-path"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: forged-path\n"
        "prompt: Test\n"
        "test_command: pytest\n"
        "path: /tmp/other-task\n"
    )

    with pytest.raises(ValueError, match="must not define internal fields: path"):
        load_task("forged-path", tmp_path)


@pytest.mark.parametrize(
    ("dataset", "field"),
    [
        ("id: source\n    revision: rev", "item_id"),
        ("id: source\n    revision: 7\n    item_id: item", "revision"),
        (
            "id: source\n    revision: rev\n    item_id: item\n    unexpected: true",
            "unexpected",
        ),
    ],
)
def test_load_task_dataset_metadata_is_strict(tmp_path, dataset, field):
    task_dir = tmp_path / "dataset-task"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: dataset-task\n"
        "prompt: Test\n"
        "test_command: pytest\n"
        f"dataset:\n    {dataset}\n"
    )

    with pytest.raises(ValidationError, match=field):
        load_task("dataset-task", tmp_path)


@pytest.mark.parametrize(
    "task_id",
    ["../example-todo-api", "nested/task", "Uppercase", "trailing-", "a" * 64],
)
def test_load_task_rejects_unsafe_path_ids(tmp_path, task_id):
    with pytest.raises(ValueError, match="DNS-style path segment"):
        load_task(task_id, tmp_path)


def test_load_task_rejects_symlinked_task_directory(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: linked-task\nprompt: Test\ntest_command: pytest\n"
    )
    (tmp_path / "linked-task").symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="must not be a symlink"):
        load_task("linked-task", tmp_path)


def test_load_task_rejects_symlinked_manifest(tmp_path):
    task_dir = tmp_path / "linked-manifest"
    task_dir.mkdir()
    manifest = tmp_path / "outside.yaml"
    manifest.write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: linked-manifest\nprompt: Test\ntest_command: pytest\n"
    )
    (task_dir / "task.yaml").symlink_to(manifest)

    with pytest.raises(ValueError, match="manifest must not be a symlink"):
        load_task("linked-manifest", tmp_path)


def test_load_task_rejects_symlinked_workspace_root(tmp_path):
    task_dir = tmp_path / "linked-workspace"
    environment = task_dir / "environment"
    tests_dir = task_dir / "tests"
    environment.mkdir(parents=True)
    tests_dir.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: linked-workspace\nprompt: Test\ntest_command: pytest\n"
    )
    (environment / "Dockerfile").write_text("FROM scratch\n")
    outside = tmp_path / "outside-workspace"
    outside.mkdir()
    (outside / "host-secret").write_text("must not be copied\n")
    (environment / "workspace").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="starter workspace must not be a symlink"):
        load_task("linked-workspace", tmp_path)


def test_task_image_tag_changes_with_build_context(tmp_path):
    from agent_eval.task import load_task

    task_dir = tmp_path / "content-task"
    workspace = task_dir / "environment" / "workspace"
    tests = task_dir / "tests"
    workspace.mkdir(parents=True)
    tests.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: content-task\nprompt: Change it\ntest_command: pytest\n"
    )
    (task_dir / "environment" / "Dockerfile").write_text("FROM python:3.12\n")
    source = workspace / "app.py"
    source.write_text("value = 1\n")
    (tests / "test_app.py").write_text("def test_x(): assert True\n")
    first = load_task("content-task", tmp_path).image_tag

    source.write_text("value = 2\n")
    second = load_task("content-task", tmp_path).image_tag

    assert first != second


def test_task_image_tag_binds_modes_and_rejects_generated_context_files(tmp_path):
    task_dir = tmp_path / "content-task"
    workspace = task_dir / "environment" / "workspace"
    tests = task_dir / "tests"
    workspace.mkdir(parents=True)
    tests.mkdir()
    (task_dir / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: content-task\nprompt: Change it\ntest_command: pytest\n"
    )
    (task_dir / "environment" / "Dockerfile").write_text("FROM python:3.12\n")
    source = workspace / "tool.py"
    source.write_text("value = 1\n")
    (tests / "test_app.py").write_text("def test_x(): assert True\n")

    original = load_task("content-task", tmp_path).image_tag
    source.chmod(0o755)
    executable = load_task("content-task", tmp_path).image_tag
    assert executable != original

    cache = workspace / "__pycache__"
    cache.mkdir()
    (cache / "tool.pyc").write_bytes(b"generated")
    with pytest.raises(ValueError, match="generated task directory is not allowed"):
        load_task("content-task", tmp_path)


def test_parse_junit(tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="3" failures="1" errors="0" skipped="0">'
        '<testcase classname="t" name="ok"/>'
        '<testcase classname="t" name="ok2"/>'
        '<testcase classname="t" name="bad"><failure>boom</failure></testcase>'
        "</testsuite></testsuites>"
    )
    r = parse_junit(junit)
    assert (r.total, r.passed, r.failed) == (3, 2, 1)
    assert r.counts_observed is True
    assert r.failures == ["t::bad"]
    assert not r.resolved


def test_parse_junit_missing_is_infra_error(tmp_path):
    r = parse_junit(tmp_path / "nope.xml")
    assert r.counts_observed is False
    assert r.infra_error and not r.resolved


@pytest.mark.parametrize(
    ("contents", "error"),
    [
        ("<not-junit/>", "root must be"),
        ('<testsuite tests="many"/>', "non-negative integer"),
        ('<testsuite tests="-1"/>', "non-negative integer"),
        (
            '<testsuite tests="1" failures="1" errors="1" skipped="0"/>',
            "exceed tests count",
        ),
        (
            '<testsuites tests="2"><testsuite tests="1"/></testsuites>',
            "does not match",
        ),
    ],
)
def test_parse_junit_rejects_invalid_structure_and_counts(tmp_path, contents, error):
    junit = tmp_path / "junit.xml"
    junit.write_text(contents)

    result = parse_junit(junit, command_exit_code=0)

    assert result.infra_error and error in result.infra_error
    assert not result.resolved


def test_parse_junit_fails_closed_for_unreadable_or_unicode_invalid_artifacts(
    monkeypatch, tmp_path
):
    junit = tmp_path / "junit.xml"
    junit.write_bytes(b'\xff\xfe<testsuite tests="1"/>')
    invalid_encoding = parse_junit(junit, command_exit_code=0)
    assert invalid_encoding.infra_error
    assert not invalid_encoding.resolved

    def unreadable(*_args, **_kwargs):
        raise PermissionError("untrusted artifact is not readable")

    monkeypatch.setattr(evaluator_tests.ET, "iterparse", unreadable)
    unreadable_result = parse_junit(junit, command_exit_code=0)
    assert unreadable_result.infra_error == "junit xml unreadable: PermissionError"
    assert not unreadable_result.resolved


def test_parse_junit_fails_closed_for_unknown_xml_encoding(tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_bytes(
        b'<?xml version="1.0" encoding="x-unknown"?><testsuite tests="1"/>'
    )

    result = parse_junit(junit, command_exit_code=0)

    assert result.infra_error == "junit xml unreadable: LookupError"
    assert not result.resolved


def test_parse_junit_requires_successful_command_and_a_passed_test(tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="t" name="ok"/>'
        "</testsuite></testsuites>"
    )

    assert parse_junit(junit, command_exit_code=0).resolved
    failed_command = parse_junit(junit, command_exit_code=1)
    assert failed_command.command_exit_code == 1
    assert not failed_command.resolved

    junit.write_text(
        '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="1">'
        '<testcase classname="t" name="skipped"><skipped/></testcase>'
        "</testsuite></testsuites>"
    )
    all_skipped = parse_junit(junit, command_exit_code=0)
    assert all_skipped.passed == 0
    assert not all_skipped.resolved


def test_parse_junit_rejects_symlink_and_oversized_artifacts(monkeypatch, tmp_path):
    target = tmp_path / "target.xml"
    target.write_text('<testsuite tests="1"/>')
    linked = tmp_path / "junit.xml"
    linked.symlink_to(target)

    linked_result = parse_junit(linked, command_exit_code=0)

    assert linked_result.infra_error is None
    assert "must not be a symbolic link" in (linked_result.integrity_error or "")
    assert linked_result.failures == [linked_result.integrity_error]

    oversized = tmp_path / "oversized.xml"
    oversized.write_text('<testsuite tests="1"><testcase name="ok"/></testsuite>')
    monkeypatch.setattr(evaluator_tests, "MAX_JUNIT_BYTES", 16)

    oversized_result = parse_junit(oversized, command_exit_code=0)

    assert oversized_result.infra_error is None
    assert "exceeds 16 bytes" in (oversized_result.integrity_error or "")


@pytest.mark.parametrize(
    ("constant", "value", "contents", "error"),
    [
        (
            "MAX_JUNIT_CASES",
            1,
            '<testsuite tests="1"><testcase name="one"/>'
            '<testcase name="two"/></testsuite>',
            "testcase elements exceed",
        ),
        (
            "MAX_JUNIT_FAILURES",
            1,
            '<testsuite tests="2" failures="1"><testcase name="one">'
            '<failure/></testcase><testcase name="two"><failure/>'
            "</testcase></testsuite>",
            "failed testcase elements exceed",
        ),
        (
            "MAX_JUNIT_IDENTITY_CHARS",
            3,
            '<testsuite tests="1"><testcase classname="case" name="long"/></testsuite>',
            "testcase 'classname' exceeds",
        ),
    ],
)
def test_parse_junit_streaming_caps_are_integrity_evidence(
    monkeypatch, tmp_path, constant, value, contents, error
):
    monkeypatch.setattr(evaluator_tests, constant, value)
    junit = tmp_path / "junit.xml"
    junit.write_text(contents)

    result = parse_junit(junit, command_exit_code=0)

    assert result.infra_error is None
    assert error in (result.integrity_error or "")
    assert not result.resolved


def test_parse_coverage(tmp_path):
    cov = tmp_path / "coverage.json"
    cov.write_text(json.dumps({"totals": {"percent_covered": 87.5}}))
    assert parse_coverage(cov) == 87.5
    assert parse_coverage(tmp_path / "nope.json") is None


def test_parse_coverage_rejects_symlink_oversize_and_duplicate_keys(
    monkeypatch, tmp_path
):
    target = tmp_path / "target.json"
    target.write_text('{"totals": {"percent_covered": 100}}')
    linked = tmp_path / "coverage.json"
    linked.symlink_to(target)

    linked_result = parse_coverage_artifact(linked)

    assert linked_result.infra_error is None
    assert "must not be a symbolic link" in (linked_result.integrity_error or "")
    assert parse_coverage(linked) is None

    oversized = tmp_path / "oversized.json"
    oversized.write_text('{"totals": {"percent_covered": 100}}')
    monkeypatch.setattr(evaluator_tests, "MAX_COVERAGE_BYTES", 8)
    oversized_result = parse_coverage_artifact(oversized)
    assert "exceeds 8 bytes" in (oversized_result.integrity_error or "")

    monkeypatch.setattr(evaluator_tests, "MAX_COVERAGE_BYTES", 1_024)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"totals": {"percent_covered": 10}, "totals": {"percent_covered": 90}}'
    )
    duplicate_result = parse_coverage_artifact(duplicate)
    assert "duplicate JSON key" in (duplicate_result.integrity_error or "")


@pytest.mark.parametrize(
    "payload",
    [
        b"{not json",
        b"\xff\xfe{not utf-8}",
        b'{"totals": {"percent_covered": true}}',
        b'{"totals": {"percent_covered": "100"}}',
        b'{"totals": {"percent_covered": -0.1}}',
        b'{"totals": {"percent_covered": 100.1}}',
        b'{"totals": {"percent_covered": NaN}}',
        b'{"totals": {"percent_covered": ' + (b"9" * 400) + b"}}",
    ],
)
def test_parse_coverage_fails_closed_for_untrusted_artifacts(tmp_path, payload):
    coverage = tmp_path / "coverage.json"
    coverage.write_bytes(payload)

    assert parse_coverage(coverage) is None


def test_parse_coverage_fails_closed_when_artifact_becomes_unreadable(
    monkeypatch, tmp_path
):
    coverage = tmp_path / "coverage.json"
    coverage.write_text('{"totals": {"percent_covered": 100}}')

    def unreadable(*_args, **_kwargs):
        raise PermissionError("untrusted artifact is not readable")

    monkeypatch.setattr(evaluator_tests._BoundedReader, "read", unreadable)
    assert parse_coverage(coverage) is None
    result = parse_coverage_artifact(coverage)
    assert result.infra_error == "coverage json unreadable: PermissionError"


def test_claude_transcript_parsing(tmp_path):
    transcript = tmp_path / "transcript.jsonl"
    events = [
        {"type": "system", "subtype": "init", "model": "claude-haiku-4-5"},
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "text": "editing"},
                    {"type": "tool_use", "name": "Edit", "input": {}},
                ]
            },
        },
        {
            "type": "assistant",
            "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {}}]},
        },
        {
            "type": "result",
            "subtype": "success",
            "num_turns": 4,
            "total_cost_usd": 0.0123,
            "usage": {"input_tokens": 1000, "output_tokens": 250},
        },
    ]
    transcript.write_text("\n".join(json.dumps(e) for e in events))
    m = ClaudeCodeAdapter().parse_transcript(transcript)
    assert m.model == "claude-haiku-4-5"
    assert m.tool_calls == 2
    assert m.turns == 4
    assert m.cost_usd == 0.0123
    assert (m.tokens_in, m.tokens_out) == (1000, 250)


def test_claude_command_shape():
    cmd = ClaudeCodeAdapter().build_command(model="claude-haiku-4-5")
    assert "--output-format stream-json" in cmd
    assert "--dangerously-skip-permissions" in cmd
    assert "claude-haiku-4-5" in cmd


def test_codex_transcript_parsing(tmp_path):
    from agent_eval.agents.codex import CodexAdapter

    transcript = tmp_path / "transcript.jsonl"
    events = [
        {"type": "thread.started", "thread_id": "t1"},
        {
            "type": "item.completed",
            "item": {"type": "command_execution", "command": "ls"},
        },
        {"type": "item.completed", "item": {"type": "file_change"}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "done"}},
        {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 900,
                "cached_input_tokens": 100,
                "output_tokens": 200,
            },
        },
    ]
    transcript.write_text("\n".join(json.dumps(e) for e in events))
    m = CodexAdapter().parse_transcript(transcript)
    assert m.tool_calls == 2
    assert m.turns == 1
    assert (m.tokens_in, m.tokens_out) == (900, 200)
    assert m.cost_usd is None


def test_codex_missing_usage_remains_unobserved(tmp_path):
    from agent_eval.agents.codex import CodexAdapter

    transcript = tmp_path / "transcript.jsonl"
    events = [
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 900, "output_tokens": 200},
        },
        {"type": "turn.completed"},
    ]
    transcript.write_text("\n".join(json.dumps(e) for e in events))

    metrics = CodexAdapter().parse_transcript(transcript)

    assert metrics.turns == 2
    assert metrics.tokens_in is None
    assert metrics.tokens_out is None


@pytest.mark.parametrize(
    "usage",
    [
        {"input_tokens": -1, "output_tokens": 1},
        {"input_tokens": True, "output_tokens": 1},
        {"input_tokens": "1", "output_tokens": 1},
        {"input_tokens": 1, "output_tokens": -1},
        [],
    ],
)
def test_codex_rejects_invalid_usage(tmp_path, usage):
    from agent_eval.agents.codex import CodexAdapter

    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text(json.dumps({"type": "turn.completed", "usage": usage}))

    with pytest.raises(ValueError, match="invalid .*accounting"):
        CodexAdapter().parse_transcript(transcript)


def test_codex_command_shape():
    from agent_eval.agents.codex import CodexAdapter

    cmd = CodexAdapter().build_command(model="gpt-5.1-codex-mini")
    assert "--json" in cmd and "--dangerously-bypass-approvals-and-sandbox" in cmd
    assert "-m gpt-5.1-codex-mini" in cmd


def test_pass_at_k():
    assert pass_at_k(1, 1, 1) == 1.0
    assert pass_at_k(3, 0, 1) == 0.0
    assert abs(pass_at_k(3, 1, 1) - 1 / 3) < 1e-9
    assert pass_at_k(3, 1, 3) == 1.0
