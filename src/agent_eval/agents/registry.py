"""Discovery and validation for built-in and third-party agent adapters."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import cache
from importlib import metadata
from pathlib import Path
from typing import Any, Literal, cast

from ..metrics import AgentMetrics
from .base import AgentAdapter
from .claude_code import ClaudeCodeAdapter
from .codex import CodexAdapter

ENTRY_POINT_GROUP = "agent_eval.agents"

_ADAPTER_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_MISSING = object()

_BUILTIN_ADAPTERS: dict[str, AgentAdapter] = {
    ClaudeCodeAdapter.name: ClaudeCodeAdapter(),
    CodexAdapter.name: CodexAdapter(),
}
BUILTIN_ADAPTER_NAMES = frozenset(_BUILTIN_ADAPTERS)


@dataclass(frozen=True, slots=True)
class AdapterMetadata:
    """Installation metadata discovered without importing plugin code."""

    name: str
    kind: Literal["builtin", "plugin"]
    available: bool
    distribution: str | None = None
    entry_point: str | None = None
    issue: str | None = None


class _ValidatedAdapter:
    """Stable facade over the plugin surface validated at load time."""

    def __init__(
        self,
        *,
        name: str,
        env: dict[str, str],
        build_command: Callable[[str | None], str],
        parse_transcript: Callable[[Path], AgentMetrics],
        prepare: object = _MISSING,
    ) -> None:
        self.name = name
        self.env = env
        self._build_command = build_command
        self._parse_transcript = parse_transcript
        self._prepare = prepare

    def build_command(self, model: str | None = None) -> str:
        return self._build_command(model)

    def parse_transcript(self, transcript: Path) -> AgentMetrics:
        return self._parse_transcript(transcript)

    def __getattr__(self, name: str) -> Any:
        if name == "prepare" and self._prepare is not _MISSING:
            return self._prepare
        raise AttributeError(name)


def _validate_adapter_name(name: object) -> str:
    if not isinstance(name, str) or _ADAPTER_NAME_RE.fullmatch(name) is None:
        raise ValueError(
            "adapter names must be lowercase DNS labels of at most 63 characters"
        )
    return name


def _plugin_entry_points(*, name: str | None = None) -> tuple[metadata.EntryPoint, ...]:
    filters = {"group": ENTRY_POINT_GROUP}
    if name is not None:
        filters["name"] = name
    discovered = metadata.entry_points(**filters)
    return tuple(
        entry_point
        for entry_point in discovered
        if entry_point.group == ENTRY_POINT_GROUP
        and (name is None or entry_point.name == name)
    )


def _distribution_name(entry_point: metadata.EntryPoint) -> str | None:
    distribution = entry_point.dist
    if distribution is None:
        return None
    try:
        name = distribution.name
    except Exception:
        return None
    return name if isinstance(name, str) else None


def list_adapters() -> tuple[AdapterMetadata, ...]:
    """Return built-in and entry-point metadata without loading plugins.

    Invalid, conflicting, and built-in-shadowing entry points are included for
    operator visibility but marked unavailable.
    """

    result = [
        AdapterMetadata(name=name, kind="builtin", available=True)
        for name in sorted(_BUILTIN_ADAPTERS)
    ]
    entry_points = _plugin_entry_points()
    name_counts = Counter(entry_point.name for entry_point in entry_points)

    for entry_point in sorted(
        entry_points,
        key=lambda item: (
            item.name,
            _distribution_name(item) or "",
            item.value,
        ),
    ):
        issue = None
        try:
            plugin_name = _validate_adapter_name(entry_point.name)
        except ValueError as exc:
            plugin_name = entry_point.name
            issue = str(exc)
        else:
            if plugin_name in _BUILTIN_ADAPTERS:
                issue = "entry point uses a reserved built-in adapter name"
            elif name_counts[plugin_name] > 1:
                issue = "multiple entry points use this adapter name"

        result.append(
            AdapterMetadata(
                name=plugin_name,
                kind="plugin",
                available=issue is None,
                distribution=_distribution_name(entry_point),
                entry_point=entry_point.value,
                issue=issue,
            )
        )

    return tuple(result)


def _looks_like_adapter(value: object) -> bool:
    return all(
        hasattr(value, attribute)
        for attribute in ("name", "env", "build_command", "parse_transcript")
    )


def _instantiate_plugin(entry_point: metadata.EntryPoint) -> object:
    try:
        loaded = entry_point.load()
    except Exception as exc:
        raise RuntimeError(
            f"failed to import agent adapter {entry_point.name!r}"
        ) from exc

    if not isinstance(loaded, type) and _looks_like_adapter(loaded):
        return loaded
    if not callable(loaded):
        raise TypeError(
            f"agent adapter entry point {entry_point.name!r} must resolve to "
            "an adapter, class, or zero-argument factory"
        )
    try:
        return loaded()
    except Exception as exc:
        raise RuntimeError(
            f"failed to initialize agent adapter {entry_point.name!r}"
        ) from exc


def _validate_env(adapter_name: str, value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"agent adapter {adapter_name!r} env must be a mapping")

    validated: dict[str, str] = {}
    for key, env_value in value.items():
        if not isinstance(key, str) or _ENV_NAME_RE.fullmatch(key) is None:
            raise ValueError(
                f"agent adapter {adapter_name!r} has an invalid environment "
                "variable name"
            )
        if not isinstance(env_value, str):
            raise TypeError(
                f"agent adapter {adapter_name!r} environment values must be strings"
            )
        if "\x00" in env_value:
            raise ValueError(
                f"agent adapter {adapter_name!r} environment values cannot "
                "contain NUL bytes"
            )
        validated[key] = env_value
    return validated


def _validate_plugin(adapter: object, *, expected_name: str) -> AgentAdapter:
    actual_name = _validate_adapter_name(getattr(adapter, "name", None))
    if actual_name != expected_name:
        raise ValueError(
            f"agent adapter entry point {expected_name!r} returned adapter "
            f"{actual_name!r}"
        )

    env = _validate_env(actual_name, getattr(adapter, "env", None))
    build_command = getattr(adapter, "build_command", None)
    parse_transcript = getattr(adapter, "parse_transcript", None)
    if not callable(build_command):
        raise TypeError(
            f"agent adapter {actual_name!r} must define callable build_command"
        )
    if not callable(parse_transcript):
        raise TypeError(
            f"agent adapter {actual_name!r} must define callable parse_transcript"
        )

    prepare = getattr(adapter, "prepare", _MISSING)
    if prepare is not _MISSING and not callable(prepare):
        raise TypeError(
            f"agent adapter {actual_name!r} prepare attribute must be callable"
        )

    return cast(
        AgentAdapter,
        _ValidatedAdapter(
            name=actual_name,
            env=env,
            build_command=build_command,
            parse_transcript=parse_transcript,
            prepare=prepare,
        ),
    )


@cache
def _load_plugin(name: str) -> AgentAdapter:
    if name in _BUILTIN_ADAPTERS:
        raise ValueError(f"{name!r} is reserved for a built-in agent adapter")

    matches = _plugin_entry_points(name=name)
    if not matches:
        available = sorted(
            metadata.name for metadata in list_adapters() if metadata.available
        )
        raise KeyError(f"unknown agent {name!r}; available: {', '.join(available)}")
    if len(matches) > 1:
        raise RuntimeError(
            f"multiple agent adapter entry points are registered as {name!r}"
        )

    return _validate_plugin(_instantiate_plugin(matches[0]), expected_name=name)


def get_adapter(name: str) -> AgentAdapter:
    """Return a built-in adapter or load only the selected plugin adapter."""

    validated_name = _validate_adapter_name(name)
    builtin = _BUILTIN_ADAPTERS.get(validated_name)
    if builtin is not None:
        return builtin
    return _load_plugin(validated_name)


def is_builtin_adapter(name: str) -> bool:
    """Check the reserved adapter set without discovering or importing plugins."""

    return _validate_adapter_name(name) in BUILTIN_ADAPTER_NAMES


__all__ = [
    "BUILTIN_ADAPTER_NAMES",
    "ENTRY_POINT_GROUP",
    "AdapterMetadata",
    "get_adapter",
    "is_builtin_adapter",
    "list_adapters",
]
