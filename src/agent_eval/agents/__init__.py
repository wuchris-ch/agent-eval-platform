"""Agent adapters: how to invoke a coding agent inside the sandbox pod and how
to parse its transcript into efficiency metrics."""

from __future__ import annotations

from .base import PROMPT_PATH, AgentAdapter
from .registry import (
    BUILTIN_ADAPTER_NAMES,
    ENTRY_POINT_GROUP,
    AdapterMetadata,
    get_adapter,
    is_builtin_adapter,
    list_adapters,
)

__all__ = [
    "BUILTIN_ADAPTER_NAMES",
    "ENTRY_POINT_GROUP",
    "PROMPT_PATH",
    "AdapterMetadata",
    "AgentAdapter",
    "get_adapter",
    "is_builtin_adapter",
    "list_adapters",
]
