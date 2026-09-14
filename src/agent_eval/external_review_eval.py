"""Evaluate an external code-review agent against a versioned golden corpus.

The harness owns the corpus, scoring, retries, outcome, and telemetry.  The
review agent is a separate executable.  It receives an unchanged unified diff
on standard input and must return the strict JSON contract defined here.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import shlex
import signal
import subprocess
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from statistics import median
from typing import Any, Literal, NoReturn, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .corpus import load_corpus, validate_corpus
from .limits import read_stable_bounded_file
from .review_benchmark import (
    BenchmarkCase,
    PredictedFinding,
    _score_case,
    load_manifest,
)

DEFAULT_THRESHOLD = 0.6
MAX_AGENT_OUTPUT_BYTES = 1024 * 1024
MAX_AGENT_ERROR_BYTES = 4096
MAX_DIFF_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_URI_OR_DRIVE_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_ECMASCRIPT_TRIM_CHARACTERS = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_CHILD_ENV_ALLOWLIST = (
    "AGENT_MODEL",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "MODEL_GATEWAY_API_KEY",
    "MODEL_GATEWAY_BASE_URL",
    "NODE_EXTRA_CA_CERTS",
    "NO_COLOR",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
    "OTEL_SERVICE_NAME",
    "OTEL_TRACES_EXPORTER",
    "PATH",
    "REVIEW_AGENT_MODEL",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _ecmascript_trim(value: str) -> str:
    return value.strip(_ECMASCRIPT_TRIM_CHARACTERS)


class ReviewFinding(_StrictModel):
    severity: Literal["blocker", "major", "minor", "info"]
    category: Literal["security", "correctness", "style", "performance"]
    file: str
    line: int = Field(ge=1, strict=True)
    detail: str

    @field_validator("file", "detail")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not _ecmascript_trim(value):
            raise ValueError("must not be empty")
        return value

    @field_validator("file")
    @classmethod
    def _repository_relative(cls, value: str) -> str:
        if value != _ecmascript_trim(value):
            raise ValueError("must not contain leading or trailing whitespace")
        normalized = value.replace("\\", "/")
        segments = normalized.split("/")
        if ".." in segments:
            raise ValueError("must not contain a parent-directory segment")
        if (
            normalized in {"", "."}
            or normalized.startswith("/")
            or _URI_OR_DRIVE_PREFIX.match(normalized)
            or not any(segment not in {"", "."} for segment in segments)
        ):
            raise ValueError("must be a repository-relative path")
        return value


class ReviewAgentOutput(_StrictModel):
    schema_version: Literal["1.0"]
    input_sha256: str
    risk: Literal["low", "medium", "high"]
    blocked: bool
    findings: list[ReviewFinding]
    rationale: str

    @field_validator("input_sha256")
    @classmethod
    def _valid_input_digest(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("must be a lowercase SHA-256 digest")
        return value

    @field_validator("rationale")
    @classmethod
    def _rationale_is_present(cls, value: str) -> str:
        if not _ecmascript_trim(value):
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _risk_and_block_decision_match_findings(self) -> ReviewAgentOutput:
        severities = {finding.severity for finding in self.findings}
        if "blocker" in severities:
            expected = ("high", True)
        elif "major" in severities:
            expected = ("medium", True)
        else:
            expected = ("low", False)
        if (self.risk, self.blocked) != expected:
            raise ValueError(
                "risk and blocked must agree with the highest finding severity"
            )
        return self


class JudgeScore(_StrictModel):
    score: float = Field(ge=0, le=1, allow_inf_nan=False)
    reason: str = ""


class FindingScore(_StrictModel):
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision: float | None
    recall: float | None
    f1: float
    verdict_correct: bool
    score: float
    reason: str


Outcome = Literal["accepted", "rejected", "infra_error"]


class AttemptResult(_StrictModel):
    attempt: Literal[1, 2]
    outcome: Outcome
    score: float | None = None
    deterministic: FindingScore | None = None
    judge: JudgeScore | None = None
    output: ReviewAgentOutput | None = None
    latency_ms: float = Field(ge=0)
    error: str | None = None


class TrialResult(_StrictModel):
    case_id: str
    trial: int = Field(ge=1)
    outcome: Outcome
    score: float | None = None
    first_attempt: AttemptResult
    corrected_attempt: AttemptResult | None = None
    latency_ms: float = Field(ge=0)


class CohortSummary(_StrictModel):
    corpus_id: str
    corpus_version: str
    command_sha256: str
    trials: int
    cases: int
    evaluations: int
    accepted: int
    rejected: int
    infra_errors: int
    average_score: float
    median_latency_ms: float | None
    grade: Literal["A", "B", "C", "F"]
    results: list[TrialResult]


class OutputJudge(Protocol):
    def score(
        self, case: BenchmarkCase, output: ReviewAgentOutput, diff: bytes
    ) -> JudgeScore: ...


class _DuplicateJsonKeyError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKeyError(f"duplicate key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number {value!r} is not allowed")


def parse_review_output(value: bytes | str) -> ReviewAgentOutput:
    """Parse one complete stdout payload. Extra text and keys are rejected."""

    if isinstance(value, bytes):
        if len(value) > MAX_AGENT_OUTPUT_BYTES:
            raise ValueError("agent stdout exceeded the safe byte limit")
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("agent stdout must be valid UTF-8") from exc
    else:
        text = value
        if len(text.encode("utf-8")) > MAX_AGENT_OUTPUT_BYTES:
            raise ValueError("agent stdout exceeded the safe byte limit")
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, _DuplicateJsonKeyError) as exc:
        raise ValueError(f"agent stdout is not one strict JSON object: {exc}") from exc
    return ReviewAgentOutput.model_validate(raw)


class AgentInvocation(_StrictModel):
    output: ReviewAgentOutput | None = None
    latency_ms: float = Field(ge=0)
    error: str | None = None


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        if process.poll() is None:
            process.kill()
    process.wait()


def _child_environment(feedback: str | None) -> dict[str, str]:
    environment = {
        key: value
        for key in _CHILD_ENV_ALLOWLIST
        if (value := os.environ.get(key)) is not None
    }
    if feedback is not None:
        environment["AGENT_EVAL_FEEDBACK"] = feedback[:4000]
    return environment


def _bounded_process_output(
    process: subprocess.Popen[bytes], *, timeout_seconds: float
) -> tuple[bytes | None, bytes, str | None]:
    """Drain stdout/stderr with strict byte and time bounds."""

    assert process.stdout is not None
    assert process.stderr is not None
    streams = {
        process.stdout: ("stdout", MAX_AGENT_OUTPUT_BYTES),
        process.stderr: ("stderr", MAX_AGENT_ERROR_BYTES),
    }
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for stream, (name, _) in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, data=name)
    deadline = time.monotonic() + timeout_seconds
    failure: str | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"agent timed out after {timeout_seconds:g} seconds"
                break
            for key, _ in selector.select(timeout=min(remaining, 0.1)):
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                name = key.data
                limit = streams[stream][1]
                remaining_capacity = limit - len(buffers[name])
                buffers[name].extend(chunk[:remaining_capacity])
                if len(chunk) > remaining_capacity:
                    failure = f"agent {name} exceeded the {limit}-byte limit"
                    break
            if failure is not None:
                break
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
        # Every invocation owns a fresh session. Terminate its process group on
        # success too, so a parent cannot leave redirected descendants behind.
        _terminate(process)
    if failure is not None:
        return None, bytes(buffers["stderr"][:MAX_AGENT_ERROR_BYTES]), failure
    return bytes(buffers["stdout"]), bytes(buffers["stderr"]), None


def invoke_review_agent(
    command: Sequence[str],
    diff: bytes,
    *,
    timeout_seconds: float,
    feedback: str | None = None,
    diff_file_flag: str | None = None,
) -> AgentInvocation:
    """Invoke an external agent without a shell.

    On a retry the raw diff remains unchanged and prior critique is available
    only through ``AGENT_EVAL_FEEDBACK``.  A command that prefers a file can opt
    into ``diff_file_flag``; the harness appends ``<flag> <temporary-path>``.
    """

    if not command or any(not item or "\x00" in item for item in command):
        return AgentInvocation(latency_ms=0, error="invalid agent command")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        return AgentInvocation(latency_ms=0, error="invalid agent timeout")
    if feedback is not None:
        try:
            encoded_feedback = os.fsencode(feedback[:4000])
        except UnicodeError:
            return AgentInvocation(latency_ms=0, error="invalid retry feedback")
        if b"\x00" in encoded_feedback:
            return AgentInvocation(latency_ms=0, error="invalid retry feedback")
    if len(diff) > MAX_DIFF_BYTES:
        return AgentInvocation(
            latency_ms=0, error="raw diff exceeded the safe byte limit"
        )
    environment = _child_environment(feedback)

    temporary_path: str | None = None
    argv = list(command)
    stdin_file: Any = tempfile.TemporaryFile()
    stdin_file.write(diff)
    stdin_file.seek(0)
    stdin: Any = stdin_file
    if diff_file_flag is not None:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix="agent-eval-", suffix=".diff"
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(diff)
            argv.extend((diff_file_flag, temporary_path))
            stdin_file.close()
            stdin = subprocess.DEVNULL
        except Exception:
            Path(temporary_path).unlink(missing_ok=True)
            raise

    started = time.perf_counter()
    try:
        try:
            process = subprocess.Popen(
                argv,
                env=environment,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except (OSError, ValueError, UnicodeError) as exc:
            return AgentInvocation(
                latency_ms=(time.perf_counter() - started) * 1000,
                error=f"agent could not start: {type(exc).__name__}",
            )
        try:
            stdout, _stderr, process_error = _bounded_process_output(
                process, timeout_seconds=timeout_seconds
            )
        finally:
            if not stdin_file.closed:
                stdin_file.close()
        if process_error is not None:
            return AgentInvocation(
                latency_ms=(time.perf_counter() - started) * 1000,
                error=process_error,
            )
        latency_ms = (time.perf_counter() - started) * 1000
        if process.returncode != 0:
            return AgentInvocation(
                latency_ms=latency_ms,
                error=f"agent exited with status {process.returncode}",
            )
        assert stdout is not None
        try:
            output = parse_review_output(stdout)
        except (ValueError, TypeError) as exc:
            return AgentInvocation(
                latency_ms=latency_ms,
                error=f"invalid agent output: {str(exc)[:1000]}",
            )
        expected_digest = hashlib.sha256(diff).hexdigest()
        if output.input_sha256 != expected_digest:
            return AgentInvocation(
                latency_ms=latency_ms,
                error="invalid agent output: input_sha256 does not match the raw diff",
            )
        return AgentInvocation(output=output, latency_ms=latency_ms)
    finally:
        if not stdin_file.closed:
            stdin_file.close()
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)


def score_review_output(case: BenchmarkCase, output: ReviewAgentOutput) -> FindingScore:
    """Combine exact finding matching with the explicit block decision."""

    predictions = [
        PredictedFinding(
            severity=finding.severity,
            category=finding.category,
            file=finding.file,
            line=finding.line,
        )
        for finding in output.findings
    ]
    scored = _score_case(
        case,
        Path(f"{case.id}.json"),
        predictions,
        "scored",
        None,
        require_exact_severity=True,
    )
    tp = scored.true_positives
    fp = scored.false_positives
    fn = scored.false_negatives
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    denominator = 2 * tp + fp + fn
    finding_f1 = (2 * tp / denominator) if denominator else 1.0
    expected_blocked = any(
        finding.severity in {"blocker", "major"} for finding in case.expected_findings
    )
    verdict_correct = output.blocked is expected_blocked
    score = (finding_f1 + float(verdict_correct)) / 2
    reason = (
        f"finding F1={finding_f1:.3f}; block decision "
        f"{'correct' if verdict_correct else 'incorrect'}; "
        f"TP={tp} FP={fp} FN={fn}"
    )
    return FindingScore(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=finding_f1,
        verdict_correct=verdict_correct,
        score=score,
        reason=reason,
    )


def score_to_grade(score: float) -> Literal["A", "B", "C", "F"]:
    if score >= 0.9:
        return "A"
    if score >= 0.75:
        return "B"
    if score >= 0.6:
        return "C"
    return "F"


def _final_score(deterministic: FindingScore, judge: JudgeScore | None) -> float:
    # A model judge may tighten a result but cannot override golden evidence.
    return (
        min(deterministic.score, judge.score)
        if judge is not None
        else deterministic.score
    )


def _retry_feedback(deterministic: FindingScore, judge: JudgeScore | None) -> str:
    parts = [deterministic.reason]
    if judge is not None and judge.reason:
        parts.append(f"Judge critique: {judge.reason}")
    parts.append(
        "Review the unchanged diff again and return the required JSON contract."
    )
    return " ".join(parts)


def trial_span_attributes(
    result: TrialResult,
    *,
    corpus_id: str,
    corpus_version: str,
    command_sha256: str,
) -> dict[str, str | bool | int | float]:
    """Return the content-free, allowlisted OTel projection for one trial."""

    attributes: dict[str, str | bool | int | float] = {
        "agent_eval.telemetry.schema_version": "agent-eval.external-review/v1",
        "agent_eval.corpus.id": corpus_id,
        "agent_eval.corpus.version": corpus_version,
        "agent_eval.case.id": result.case_id,
        "agent_eval.trial.number": result.trial,
        "agent_eval.trial.outcome": result.outcome,
        "agent_eval.trial.attempts": 2 if result.corrected_attempt else 1,
        "agent_eval.trial.latency_ms": result.latency_ms,
        "agent_eval.agent.command_sha256": command_sha256,
        "agent_eval.contract.valid": (
            result.corrected_attempt or result.first_attempt
        ).output
        is not None,
    }
    if result.score is not None:
        attributes["gen_ai.evaluation.score.value"] = result.score
    final_attempt = result.corrected_attempt or result.first_attempt
    if result.first_attempt.score is not None:
        attributes["agent_eval.first_attempt.score"] = result.first_attempt.score
    if (
        result.corrected_attempt is not None
        and result.corrected_attempt.score is not None
    ):
        attributes["agent_eval.corrected_attempt.score"] = (
            result.corrected_attempt.score
        )
    if final_attempt.deterministic is not None:
        attributes.update(
            {
                "agent_eval.findings.true_positives": final_attempt.deterministic.true_positives,
                "agent_eval.findings.false_positives": final_attempt.deterministic.false_positives,
                "agent_eval.findings.false_negatives": final_attempt.deterministic.false_negatives,
            }
        )
    return attributes


def export_trial_span(
    result: TrialResult,
    *,
    corpus_id: str,
    corpus_version: str,
    command_sha256: str,
) -> bool:
    """Best-effort optional export that never changes an evaluation outcome."""

    from . import observability

    if not observability._enabled():
        return False
    if os.environ.get("OTEL_TRACES_EXPORTER", "otlp").casefold() == "none":
        return False
    try:
        runtime = observability._get_runtime()
        attributes = trial_span_attributes(
            result,
            corpus_id=corpus_id,
            corpus_version=corpus_version,
            command_sha256=command_sha256,
        )
        with runtime.tracer.start_as_current_span(
            "agent_eval.external_review.trial", attributes=attributes
        ):
            pass
        return bool(runtime.provider.force_flush(observability._flush_timeout_ms()))
    except Exception:
        return False


def _command_digest(command: Sequence[str]) -> str:
    encoded = json.dumps(
        list(command), ensure_ascii=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _one_attempt(
    command: Sequence[str],
    diff: bytes,
    case: BenchmarkCase,
    *,
    timeout_seconds: float,
    feedback: str | None,
    diff_file_flag: str | None,
    judge: OutputJudge | None,
) -> tuple[AgentInvocation, FindingScore | None, JudgeScore | None, float | None]:
    invocation = invoke_review_agent(
        command,
        diff,
        timeout_seconds=timeout_seconds,
        feedback=feedback,
        diff_file_flag=diff_file_flag,
    )
    if invocation.output is None:
        return invocation, None, None, None
    deterministic = score_review_output(case, invocation.output)
    try:
        judged = (
            judge.score(case, invocation.output, diff) if judge is not None else None
        )
    except Exception as exc:
        failed = invocation.model_copy(
            update={"error": f"judge failed: {type(exc).__name__}"}
        )
        return failed, deterministic, None, None
    return invocation, deterministic, judged, _final_score(deterministic, judged)


def _attempt_result(
    attempt: Literal[1, 2],
    invocation: AgentInvocation,
    deterministic: FindingScore | None,
    judge: JudgeScore | None,
    score: float | None,
    *,
    threshold: float,
) -> AttemptResult:
    if invocation.output is None or invocation.error is not None:
        outcome: Outcome = "infra_error"
    else:
        assert score is not None
        outcome = "accepted" if score >= threshold else "rejected"
    return AttemptResult(
        attempt=attempt,
        outcome=outcome,
        score=score,
        deterministic=deterministic,
        judge=judge,
        output=invocation.output,
        latency_ms=invocation.latency_ms,
        error=invocation.error,
    )


def evaluate_external_review_agent(
    *,
    corpus_path: Path,
    command: Sequence[str],
    case_ids: Sequence[str] | None = None,
    trials: int = 1,
    threshold: float = DEFAULT_THRESHOLD,
    self_correct: bool = True,
    timeout_seconds: float = 120,
    diff_file_flag: str | None = None,
    judge: OutputJudge | None = None,
) -> CohortSummary:
    """Run an external review agent over every golden case and trial."""

    if trials < 1:
        raise ValueError("trials must be at least 1")
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between 0 and 1")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout must be positive")

    validation = validate_corpus(corpus_path, execute=False)
    if not validation.valid:
        raise ValueError("corpus validation failed: " + "; ".join(validation.errors))
    corpus, root = load_corpus(corpus_path)
    manifest = load_manifest(root / corpus.benchmark_manifest)
    benchmark_by_id = {case.id: case for case in manifest.cases}
    requested_case_ids = tuple(case_ids or ())
    if len(requested_case_ids) != len(set(requested_case_ids)):
        raise ValueError("case IDs must not be repeated")
    unknown_case_ids = sorted(set(requested_case_ids) - set(benchmark_by_id))
    if unknown_case_ids:
        raise ValueError("unknown case ID(s): " + ", ".join(unknown_case_ids))
    selected_case_ids = set(requested_case_ids)
    selected_cases = [
        corpus_case
        for corpus_case in corpus.cases
        if not selected_case_ids or corpus_case.id in selected_case_ids
    ]
    command_sha256 = _command_digest(command)
    results: list[TrialResult] = []

    for trial_number in range(1, trials + 1):
        for corpus_case in selected_cases:
            case = benchmark_by_id[corpus_case.id]
            diff = read_stable_bounded_file(
                root / corpus_case.diff,
                maximum_bytes=MAX_DIFF_BYTES,
            )
            invocation, deterministic, judged, score = _one_attempt(
                command,
                diff,
                case,
                timeout_seconds=timeout_seconds,
                feedback=None,
                diff_file_flag=diff_file_flag,
                judge=judge,
            )
            first_attempt = _attempt_result(
                1,
                invocation,
                deterministic,
                judged,
                score,
                threshold=threshold,
            )
            total_latency = first_attempt.latency_ms

            if first_attempt.outcome == "infra_error":
                result = TrialResult(
                    case_id=case.id,
                    trial=trial_number,
                    outcome="infra_error",
                    first_attempt=first_attempt,
                    latency_ms=total_latency,
                )
            else:
                assert deterministic is not None and score is not None
                corrected_attempt = None
                if score < threshold and self_correct:
                    retry = _one_attempt(
                        command,
                        diff,
                        case,
                        timeout_seconds=timeout_seconds,
                        feedback=_retry_feedback(deterministic, judged),
                        diff_file_flag=diff_file_flag,
                        judge=judge,
                    )
                    retry_invocation, retry_deterministic, retry_judged, retry_score = (
                        retry
                    )
                    corrected_attempt = _attempt_result(
                        2,
                        retry_invocation,
                        retry_deterministic,
                        retry_judged,
                        retry_score,
                        threshold=threshold,
                    )
                    total_latency += corrected_attempt.latency_ms
                    if corrected_attempt.outcome == "infra_error":
                        result = TrialResult(
                            case_id=case.id,
                            trial=trial_number,
                            outcome="infra_error",
                            first_attempt=first_attempt,
                            corrected_attempt=corrected_attempt,
                            latency_ms=total_latency,
                        )
                        export_trial_span(
                            result,
                            corpus_id=corpus.corpus_id,
                            corpus_version=corpus.version,
                            command_sha256=command_sha256,
                        )
                        results.append(result)
                        continue
                    assert retry_deterministic is not None and retry_score is not None
                    invocation = retry_invocation
                    deterministic = retry_deterministic
                    judged = retry_judged
                    score = retry_score

                result = TrialResult(
                    case_id=case.id,
                    trial=trial_number,
                    outcome="accepted" if score >= threshold else "rejected",
                    score=score,
                    first_attempt=first_attempt,
                    corrected_attempt=corrected_attempt,
                    latency_ms=total_latency,
                )

            export_trial_span(
                result,
                corpus_id=corpus.corpus_id,
                corpus_version=corpus.version,
                command_sha256=command_sha256,
            )
            results.append(result)

    accepted = sum(result.outcome == "accepted" for result in results)
    rejected = sum(result.outcome == "rejected" for result in results)
    infra_errors = sum(result.outcome == "infra_error" for result in results)
    average = (
        sum(result.score or 0 for result in results) / len(results) if results else 0
    )
    latencies = [result.latency_ms for result in results]
    return CohortSummary(
        corpus_id=corpus.corpus_id,
        corpus_version=corpus.version,
        command_sha256=command_sha256,
        trials=trials,
        cases=len(selected_cases),
        evaluations=len(results),
        accepted=accepted,
        rejected=rejected,
        infra_errors=infra_errors,
        average_score=average,
        median_latency_ms=median(latencies) if latencies else None,
        grade=score_to_grade(average),
        results=results,
    )


class DeepEvalGEvalJudge:
    """Optional GEval judge over a generic OpenAI-compatible model gateway."""

    def __init__(self) -> None:
        try:
            from deepeval.metrics import GEval
            from deepeval.models import DeepEvalBaseLLM
            from deepeval.test_case import LLMTestCase, SingleTurnParams
            from openai import AsyncOpenAI, OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "DeepEval judging requires the 'judge' extra: uv sync --extra judge"
            ) from exc

        api_key = os.environ.get("MODEL_GATEWAY_API_KEY")
        model = os.environ.get("AGENT_EVAL_JUDGE_MODEL")
        if not api_key or not model:
            raise RuntimeError(
                "MODEL_GATEWAY_API_KEY and AGENT_EVAL_JUDGE_MODEL are required"
            )
        base_url = os.environ.get("MODEL_GATEWAY_BASE_URL") or None

        class GatewayModel(DeepEvalBaseLLM):
            def __init__(self) -> None:
                self._sync = OpenAI(api_key=api_key, base_url=base_url)
                self._async = AsyncOpenAI(api_key=api_key, base_url=base_url)

            def load_model(self) -> Any:
                return self._sync

            def get_model_name(self) -> str:
                return model

            def generate(
                self, prompt: str, schema: type[BaseModel] | None = None
            ) -> Any:
                return self._generate(prompt, schema)

            async def a_generate(
                self, prompt: str, schema: type[BaseModel] | None = None
            ) -> Any:
                full = _schema_prompt(prompt, schema)
                response = await self._async.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": full}],
                    response_format={"type": "json_object"} if schema else None,
                )
                text = response.choices[0].message.content or ""
                return schema.model_validate_json(text) if schema else text.strip()

            def _generate(self, prompt: str, schema: type[BaseModel] | None) -> Any:
                full = _schema_prompt(prompt, schema)
                response = self._sync.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": full}],
                    response_format={"type": "json_object"} if schema else None,
                )
                text = response.choices[0].message.content or ""
                return schema.model_validate_json(text) if schema else text.strip()

        self._test_case_type = LLMTestCase
        self._metric = GEval(
            name="Review quality",
            criteria=(
                "Determine whether the review output is correct, complete, concise, "
                "and consistent with the golden expectations. Penalize invented findings."
            ),
            evaluation_params=[
                SingleTurnParams.INPUT,
                SingleTurnParams.ACTUAL_OUTPUT,
                SingleTurnParams.EXPECTED_OUTPUT,
            ],
            model=GatewayModel(),
            threshold=DEFAULT_THRESHOLD,
            async_mode=False,
        )

    def score(
        self, case: BenchmarkCase, output: ReviewAgentOutput, diff: bytes
    ) -> JudgeScore:
        expected = {
            "blocked": any(
                finding.severity in {"blocker", "major"}
                for finding in case.expected_findings
            ),
            "findings": [
                finding.model_dump(mode="json") for finding in case.expected_findings
            ],
        }
        test_case = self._test_case_type(
            input=diff.decode("utf-8", errors="replace"),
            actual_output=output.model_dump_json(),
            expected_output=json.dumps(expected, sort_keys=True),
        )
        self._metric.measure(test_case)
        return JudgeScore(
            score=float(self._metric.score or 0),
            reason=str(self._metric.reason or ""),
        )


def _schema_prompt(prompt: str, schema: type[BaseModel] | None) -> str:
    if schema is None:
        return prompt
    schema_json = json.dumps(schema.model_json_schema(), sort_keys=True)
    return f"{prompt}\n\nReturn only JSON matching this schema:\n{schema_json}"


def parse_command(value: str) -> list[str]:
    """Parse a user-supplied command line into an argv without using a shell."""

    command = shlex.split(value)
    if not command:
        raise ValueError("agent command must not be empty")
    return command
