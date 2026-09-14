from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from agent_eval import agents
from agent_eval.agents import registry
from agent_eval.agents.codex import CodexAdapter
from agent_eval.metrics import AgentMetrics


class FakeEntryPoint:
    group = registry.ENTRY_POINT_GROUP

    def __init__(self, name, loaded, *, distribution="test-plugin"):
        self.name = name
        self.value = f"{distribution}:adapter"
        self.dist = SimpleNamespace(name=distribution)
        self.loaded = loaded
        self.load_calls = 0

    def load(self):
        self.load_calls += 1
        return self.loaded


class DemoAdapter:
    name = "demo-agent"
    env = {"DEMO_MODE": "safe"}

    def build_command(self, model=None):
        return f"demo --model {model}" if model else "demo"

    def parse_transcript(self, transcript: Path):
        return AgentMetrics(model=transcript.name)


@pytest.fixture(autouse=True)
def clear_plugin_cache():
    registry._load_plugin.cache_clear()
    yield
    registry._load_plugin.cache_clear()


def install_entry_points(monkeypatch, *entry_points):
    def discover(**filters):
        return tuple(
            entry_point
            for entry_point in entry_points
            if all(getattr(entry_point, key) == value for key, value in filters.items())
        )

    monkeypatch.setattr(registry.metadata, "entry_points", discover)


def test_list_adapters_reports_metadata_without_loading_plugins(monkeypatch):
    plugin = FakeEntryPoint("demo-agent", DemoAdapter)
    install_entry_points(monkeypatch, plugin)

    discovered = agents.list_adapters()

    assert [(item.name, item.kind, item.available) for item in discovered] == [
        ("claude-code", "builtin", True),
        ("codex", "builtin", True),
        ("demo-agent", "plugin", True),
    ]
    assert discovered[-1].distribution == "test-plugin"
    assert discovered[-1].entry_point == "test-plugin:adapter"
    assert plugin.load_calls == 0


def test_get_adapter_loads_only_selected_plugin_and_caches_it(monkeypatch):
    selected = FakeEntryPoint("demo-agent", DemoAdapter)
    unselected = FakeEntryPoint("other-agent", DemoAdapter)
    install_entry_points(monkeypatch, selected, unselected)

    adapter = agents.get_adapter("demo-agent")

    assert adapter.name == "demo-agent"
    assert adapter.env == {"DEMO_MODE": "safe"}
    assert adapter.build_command("model-1") == "demo --model model-1"
    assert agents.get_adapter("demo-agent") is adapter
    assert selected.load_calls == 1
    assert unselected.load_calls == 0


def test_builtin_cannot_be_shadowed(monkeypatch):
    shadow = FakeEntryPoint("codex", lambda: pytest.fail("plugin was loaded"))
    install_entry_points(monkeypatch, shadow)

    adapter = agents.get_adapter("codex")
    metadata = agents.list_adapters()

    assert isinstance(adapter, CodexAdapter)
    assert shadow.load_calls == 0
    blocked = [item for item in metadata if item.kind == "plugin"]
    assert len(blocked) == 1
    assert not blocked[0].available
    assert blocked[0].issue == "entry point uses a reserved built-in adapter name"


def test_builtin_check_never_discovers_or_loads_plugins(monkeypatch):
    plugin = FakeEntryPoint("demo-agent", DemoAdapter)

    def fail_discovery(**filters):
        pytest.fail(f"plugin discovery was attempted: {filters}")

    monkeypatch.setattr(registry.metadata, "entry_points", fail_discovery)

    assert agents.is_builtin_adapter("codex") is True
    assert agents.is_builtin_adapter("demo-agent") is False
    assert plugin.load_calls == 0


def test_governed_cli_rejects_plugin_before_discovery_or_import(monkeypatch, tmp_path):
    from agent_eval.cli import app

    request = tmp_path / "request.yaml"
    policy = tmp_path / "policy.yaml"
    request.write_text("not: parsed\n", encoding="utf-8")
    policy.write_text("not: parsed\n", encoding="utf-8")
    monkeypatch.setattr(
        registry.metadata,
        "entry_points",
        lambda **filters: pytest.fail(f"plugin discovery was attempted: {filters}"),
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--task",
            "example-todo-api",
            "--agent",
            "demo-agent",
            "--governance-request",
            str(request),
            "--governance-policy",
            str(policy),
        ],
    )

    assert result.exit_code == 2
    assert "governed runs accept only built-in adapters" in result.output


@pytest.mark.parametrize(
    "name",
    ["UPPER", "two words", "../escape", "ends-", "a" * 64, ""],
)
def test_unsafe_requested_name_is_rejected_before_discovery(monkeypatch, name):
    discovery_calls = 0

    def discover(**filters):
        nonlocal discovery_calls
        discovery_calls += 1
        return ()

    monkeypatch.setattr(registry.metadata, "entry_points", discover)

    with pytest.raises(ValueError, match="lowercase DNS labels"):
        agents.get_adapter(name)

    assert discovery_calls == 0


def test_entry_point_name_must_match_adapter_name(monkeypatch):
    class MismatchedAdapter(DemoAdapter):
        name = "different-agent"

    plugin = FakeEntryPoint("demo-agent", MismatchedAdapter)
    install_entry_points(monkeypatch, plugin)

    with pytest.raises(ValueError, match="returned adapter 'different-agent'"):
        agents.get_adapter("demo-agent")


@pytest.mark.parametrize(
    ("env", "error"),
    [
        (["not", "a", "mapping"], "env must be a mapping"),
        ({"BAD-NAME": "value"}, "invalid environment variable name"),
        ({"VALID": 1}, "environment values must be strings"),
        ({"VALID": "bad\x00value"}, "cannot contain NUL bytes"),
    ],
)
def test_plugin_env_is_validated(monkeypatch, env, error):
    plugin_adapter = type(
        "PluginAdapter",
        (),
        {
            "name": "demo-agent",
            "env": env,
            "build_command": lambda self, model=None: "demo",
            "parse_transcript": lambda self, transcript: AgentMetrics(),
        },
    )
    plugin = FakeEntryPoint("demo-agent", plugin_adapter)
    install_entry_points(monkeypatch, plugin)

    with pytest.raises((TypeError, ValueError), match=error):
        agents.get_adapter("demo-agent")


@pytest.mark.parametrize(
    ("attributes", "error"),
    [
        ({"build_command": None}, "callable build_command"),
        ({"parse_transcript": None}, "callable parse_transcript"),
        ({"prepare": "not-callable"}, "prepare attribute must be callable"),
    ],
)
def test_plugin_callables_are_validated(monkeypatch, attributes, error):
    values = {
        "name": "demo-agent",
        "env": {},
        "build_command": lambda self, model=None: "demo",
        "parse_transcript": lambda self, transcript: AgentMetrics(),
        **attributes,
    }
    plugin = FakeEntryPoint("demo-agent", type("PluginAdapter", (), values))
    install_entry_points(monkeypatch, plugin)

    with pytest.raises(TypeError, match=error):
        agents.get_adapter("demo-agent")


def test_duplicate_plugin_names_fail_without_loading_either(monkeypatch):
    first = FakeEntryPoint("demo-agent", DemoAdapter, distribution="first")
    second = FakeEntryPoint("demo-agent", DemoAdapter, distribution="second")
    install_entry_points(monkeypatch, first, second)

    with pytest.raises(RuntimeError, match="multiple agent adapter entry points"):
        agents.get_adapter("demo-agent")

    assert first.load_calls == 0
    assert second.load_calls == 0
    plugin_metadata = [item for item in agents.list_adapters() if item.kind == "plugin"]
    assert all(not item.available for item in plugin_metadata)


def test_plugin_instance_is_supported_and_env_is_copied(monkeypatch):
    instance = DemoAdapter()
    instance.env = dict(instance.env)
    plugin = FakeEntryPoint("demo-agent", instance)
    install_entry_points(monkeypatch, plugin)

    adapter = agents.get_adapter("demo-agent")
    instance.env["CHANGED_AFTER_LOAD"] = "unsafe"

    assert adapter.env == {"DEMO_MODE": "safe"}
