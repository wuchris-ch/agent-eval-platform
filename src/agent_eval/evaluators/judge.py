"""LLM judge: scores the produced diff against the task prompt on the task's
rubric dimensions. Deterministic tests remain the source of truth; this adds a
supplementary quality score with rationale.

Backends (env AGENT_EVAL_JUDGE = claude | codex | auto, default auto):
- claude: Anthropic API structured output (needs ANTHROPIC_API_KEY)
- codex:  `codex exec --output-schema` on the host (ChatGPT subscription auth)
- auto:   claude if ANTHROPIC_API_KEY is set, else codex if the CLI is present
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field
from rich.console import Console

from ..metrics import JudgeResult
from ..task import Task

console = Console()
CLAUDE_JUDGE_MODEL = "claude-sonnet-4-5-20250929"
MAX_DIFF_CHARS = 60_000
CODEX_TIMEOUT = 600

DIMENSION_GUIDE = {
    "spec_adherence": "How completely and precisely the change implements what the task asked for, nothing more, nothing less.",
    "maintainability": "Code clarity, naming, structure, idiomatic use of the framework, absence of dead code or needless complexity.",
    "test_quality": "Quality of any tests the agent wrote for its own change (0 tests written is a 2 unless the task said not to).",
}


class DimensionScore(BaseModel):
    dimension: str
    score: int = Field(ge=1, le=5)
    rationale: str


class JudgeResponse(BaseModel):
    scores: list[DimensionScore]


# strict JSON schema for codex --output-schema (needs additionalProperties: false)
_JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "scores": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "dimension": {"type": "string"},
                    "score": {"type": "integer"},
                    "rationale": {"type": "string"},
                },
                "required": ["dimension", "score", "rationale"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["scores"],
    "additionalProperties": False,
}


def pick_backend() -> str | None:
    backend = os.environ.get("AGENT_EVAL_JUDGE", "auto")
    if backend in ("claude", "codex"):
        return backend
    if backend != "auto":
        return None
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    codex_authenticated = (
        bool(os.environ.get("OPENAI_API_KEY")) or (codex_home / "auth.json").is_file()
    )
    if shutil.which("codex") and codex_authenticated:
        return "codex"
    return None


def _judge_model_env() -> str | None:
    return os.environ.get("AGENT_EVAL_JUDGE_MODEL")


def structured_completion(
    system: str,
    user: str,
    response_model: type,
    schema: dict,
    *,
    backend: str | None = None,
    model: str | None = None,
) -> tuple[object, str]:
    """One structured LLM call through whichever backend is available.

    Returns (parsed response_model instance, backend/model label). Raises
    RuntimeError when no backend is available or the call fails."""
    backend = backend or pick_backend()
    if backend is None:
        raise RuntimeError(
            "no LLM backend available (need ANTHROPIC_API_KEY or a logged-in codex CLI)"
        )
    if backend == "claude":
        return _complete_claude(system, user, response_model, model=model)
    return _complete_codex(system, user, response_model, schema, model=model)


def _build_prompts(task: Task, diff: str) -> tuple[str, str]:
    dim_lines = "\n".join(
        f"- {d}: {DIMENSION_GUIDE.get(d, 'Score this dimension on its plain meaning.')}"
        for d in task.judge.weights
    )
    system = (
        "You are a strict senior engineer judging a code change produced by a "
        "coding agent. Score each rubric dimension from 1 (poor) to 5 (excellent) "
        "with a concise, evidence-based rationale citing specifics from the diff. "
        "Judge only what is in the diff against the task; do not reward unrequested "
        "extras."
    )
    user = (
        f"# Task given to the coding agent\n\n{task.prompt}\n\n"
        f"# Rubric dimensions\n\n{dim_lines}\n\n"
        f"# Diff produced by the agent\n\n```diff\n{diff}\n```\n\n"
        f"Score every dimension listed above, one entry per dimension."
    )
    return system, user


def _complete_claude(
    system: str,
    user: str,
    response_model: type,
    *,
    model: str | None = None,
) -> tuple[object, str]:
    import anthropic

    model = model or _judge_model_env() or CLAUDE_JUDGE_MODEL
    client = anthropic.Anthropic()
    response = client.messages.parse(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user}],
        output_format=response_model,
    )
    observed_model = getattr(response, "model", None)
    if not isinstance(observed_model, str) or not observed_model:
        raise RuntimeError("Anthropic response omitted observed model identity")
    return response.parsed_output, observed_model


def _complete_codex(
    system: str,
    user: str,
    response_model: type,
    json_schema: dict,
    *,
    model: str | None = None,
) -> tuple[object, str]:
    env_model = model or _judge_model_env()
    model = env_model if env_model and not env_model.startswith("claude") else None
    with tempfile.TemporaryDirectory(prefix="agent-eval-judge-") as tmp:
        schema = Path(tmp) / "schema.json"
        schema.write_text(json.dumps(json_schema))
        last_message = Path(tmp) / "last_message.json"
        cmd = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "-s",
            "read-only",
            "-C",
            tmp,
            "--output-schema",
            str(schema),
            "-o",
            str(last_message),
        ]
        if model:
            cmd += ["-m", model]
        cmd.append(f"{system}\n\n{user}")
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CODEX_TIMEOUT
        )
        if proc.returncode != 0 or not last_message.is_file():
            raise RuntimeError(
                f"codex exec failed ({proc.returncode}): "
                f"{(proc.stderr or proc.stdout)[-1000:]}"
            )
        parsed = response_model.model_validate_json(last_message.read_text())
    return parsed, model or "codex/default"


def run_judge(
    task: Task,
    run_dir: Path,
    *,
    backend: str | None = None,
    model: str | None = None,
) -> JudgeResult:
    diff_path = run_dir / "workspace.diff"
    if diff_path.is_file():
        with diff_path.open(encoding="utf-8", errors="replace") as stream:
            diff = stream.read(MAX_DIFF_CHARS + 1)
    else:
        diff = ""
    if not diff.strip():
        return JudgeResult(
            backend=backend,
            model=model,
            rationale={"_error": "no diff produced; nothing to judge"},
        )
    if len(diff) > MAX_DIFF_CHARS:
        diff = diff[:MAX_DIFF_CHARS] + "\n... [diff truncated for judging]"

    if (backend is None) != (model is None):
        return JudgeResult(
            backend=backend,
            model=model,
            rationale={"_error": "judge backend and model must be pinned together"},
        )
    backend = backend or pick_backend()
    if backend is None:
        console.print(
            "[yellow]no judge backend available (need ANTHROPIC_API_KEY "
            "or a logged-in codex CLI); skipping judge[/yellow]"
        )
        return JudgeResult(rationale={"_error": "no judge backend available"})

    system, user = _build_prompts(task, diff)
    console.print(f"judging with [bold]{backend}[/bold] backend...")
    try:
        parsed, observed_model = structured_completion(
            system,
            user,
            JudgeResponse,
            _JUDGE_SCHEMA,
            backend=backend,
            model=model,
        )
    except Exception as e:  # judge is supplementary; never fail the run
        console.print(f"[yellow]judge failed: {e}[/yellow]")
        return JudgeResult(
            backend=backend,
            model=model,
            rationale={"_error": str(e)},
        )

    returned_dimensions = [entry.dimension for entry in parsed.scores]
    expected_dimensions = list(task.judge.weights)
    if len(returned_dimensions) != len(expected_dimensions) or set(
        returned_dimensions
    ) != set(expected_dimensions):
        result = JudgeResult(
            backend=backend,
            model=observed_model,
            rationale={
                "_error": (
                    "judge returned an incomplete or duplicate dimension set: "
                    f"expected {expected_dimensions}, got {returned_dimensions}"
                )
            },
        )
        (run_dir / "judge.json").write_text(result.model_dump_json(indent=2))
        return result

    result = JudgeResult(backend=backend, model=observed_model)
    for entry in parsed.scores:
        if entry.dimension in task.judge.weights:
            result.scores[entry.dimension] = max(1, min(5, entry.score))
            result.rationale[entry.dimension] = entry.rationale
    if result.scores:
        total_weight = sum(task.judge.weights[d] for d in result.scores)
        result.weighted_score = round(
            sum(task.judge.weights[d] * s for d, s in result.scores.items())
            / total_weight,
            2,
        )
    (run_dir / "judge.json").write_text(result.model_dump_json(indent=2))
    return result
