from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..metrics import AgentMetrics

# The runner copies the task prompt here before invoking the agent, so prompts
# never need shell-escaping into the command line.
PROMPT_PATH = "/tmp/agent-eval/prompt.txt"


class AgentAdapter(Protocol):
    name: str
    # extra env vars set on the agent command (secrets come from the pod's envFrom)
    env: dict[str, str]

    # Adapters may also define `prepare(pod)` to stage credentials or config in
    # the pod before the agent command runs (e.g. codex copies ~/.codex/auth.json).

    def build_command(self, model: str | None = None) -> str:
        """Shell command that runs the agent against $PROMPT_PATH with cwd
        /workspace, writing a machine-readable transcript to stdout."""
        ...

    def parse_transcript(self, transcript: Path) -> AgentMetrics: ...
