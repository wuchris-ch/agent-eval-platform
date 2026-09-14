"""Claude Code headless adapter. Runs `claude -p` with stream-json output and
parses the JSONL transcript for tokens, cost, turns, and tool calls."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ..metrics import AgentMetrics
from .base import PROMPT_PATH


class ClaudeCodeAdapter:
    name = "claude-code"
    # Claude Code refuses --dangerously-skip-permissions as root unless it can
    # tell it is sandboxed; the pod is our sandbox.
    env = {"IS_SANDBOX": "1"}

    def build_command(self, model: str | None = None) -> str:
        cmd = (
            f'claude -p "$(cat {PROMPT_PATH})" '
            f"--output-format stream-json --verbose "
            f"--dangerously-skip-permissions"
        )
        if model:
            cmd += f" --model {shlex.quote(model)}"
        return cmd

    def parse_transcript(self, transcript: Path) -> AgentMetrics:
        metrics = AgentMetrics()
        if not transcript.is_file():
            return metrics
        tool_calls = 0
        for line in transcript.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            etype = event.get("type")
            if etype == "system" and event.get("subtype") == "init":
                metrics.model = event.get("model")
            elif etype == "assistant":
                content = (event.get("message") or {}).get("content") or []
                tool_calls += sum(
                    1
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "tool_use"
                )
            elif etype == "result":
                usage = event.get("usage") or {}
                metrics.tokens_in = usage.get("input_tokens")
                metrics.tokens_out = usage.get("output_tokens")
                metrics.cost_usd = event.get("total_cost_usd")
                metrics.turns = event.get("num_turns")
        metrics.tool_calls = tool_calls
        return metrics
