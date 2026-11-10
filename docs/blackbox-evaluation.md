# Evaluate any agent through its public interface

`agent-eval blackbox` evaluates observable behavior without importing an agent's
source, requiring a particular framework, or inspecting its prompts and tool
calls. Use it for FAQ assistants, triage services, reviewers, and other agents
that accept an input and produce a final response. Python, Node, Bun, and remote
services all use the same suite and scoring engine.

```text
Generated or authored suite -> frozen inputs -> CLI or HTTP agent -> final output
                                   |                                  |
                                   +------ independent checks <-------+
                                                      |
Application/proxy DB -> read-only query -> replay ------+
                                                      |
                                private JSON + SQLite + optional OTel/Phoenix
```

The existing `eval-review-agent`, `benchmark-review`, and k3s coding-agent
commands remain specialized evaluation modes. This new interface does not
require review findings, severity fields, a block decision, or an agent-specific
transcript parser.

For optional repository and execution visibility, see
[source and trace inspection](agent-inspection.md). Internal checks produce
separate results while preserving this shared input/output score.

## Quick start without credentials

From the repository root on macOS:

```sh
uv run agent-eval blackbox validate --suite examples/blackbox/faq.yaml

uv run agent-eval blackbox run \
  --suite examples/blackbox/faq.yaml --agent faq-smoke \
  --command "python3 $PWD/examples/blackbox/smoke_target.py" --trials 3

uv run agent-eval blackbox run \
  --suite examples/blackbox/triage.yaml --agent triage-smoke \
  --command "python3 $PWD/examples/blackbox/smoke_target.py" \
  --response-format json
```

The example target is a deterministic transport fixture. Passing these small
examples verifies the connection and scoring path, not a production agent's
quality. Real evaluation requires representative, independently checked cases.

## Live agents

**CLI:** `--command` is parsed into argv and executed without a shell. A string
input is sent unchanged on stdin. An object, array, number, boolean, or null is
sent as canonical JSON. Stdout is the response; stderr is discarded. Text output
preserves whitespace, including trailing newlines. Use an absolute executable or
script path because each invocation starts in a fresh temporary directory.

Only basic process environment variables are inherited. Explicitly pass any
credentials or settings your target needs with repeatable `--pass-env NAME`.
For a locally authenticated CLI, this may include `--pass-env HOME`. Keep
credentials and private endpoints in the environment or Keychain, not argv.

```sh
uv run agent-eval blackbox run --suite /absolute/path/suite.yaml \
  --agent assistant-v2 --command "bun /absolute/path/agent.ts" \
  --pass-env MODEL_GATEWAY_API_KEY --pass-env MODEL_GATEWAY_BASE_URL
```

**HTTP:** the suite's `input` is the exact JSON POST body. It can match an
existing service's native request shape, including a `messages` array or a
`question` field. Configure the endpoint and optional bearer token in environment
variables, then refer to their names. Responses can be text or JSON. A JSON
Pointer can select an answer from an existing response envelope.

```sh
# Terminal 1, a disposable local transport fixture:
uv run python examples/blackbox/smoke_target.py --http

# Terminal 2:
export AGENT_EVAL_TARGET_URL="http://127.0.0.1:8099"
uv run agent-eval blackbox run \
  --suite examples/blackbox/triage.yaml --agent triage-http \
  --url-env AGENT_EVAL_TARGET_URL --response-format json

# For an existing authenticated service with {"answer": ...} responses:
uv run agent-eval blackbox run --suite /absolute/path/suite.yaml \
  --agent assistant-v2 --url-env AGENT_EVAL_TARGET_URL \
  --token-env AGENT_EVAL_TARGET_TOKEN --response-format json --response-pointer /answer
```

No changes to the agent are needed when its interface already fits one of these
transports. Otherwise, use a small external wrapper to map stdin or HTTP into
the agent's native call and return its final answer. The wrapper receives no
goldens. For example, a PR tool that takes a PR URL can accept that URL as input
and return the resulting review text. Publication and repository access remain
the wrapper's responsibility; this evaluator does not post reviews to GitHub.

### Models behind an OpenAI-compatible API

`--model` evaluates a model directly. `--url-env` then names a variable that
holds the base URL of an OpenAI-compatible chat API. This works with a hosted
model gateway and with a local Ollama server:

```sh
ollama pull qwen2.5:7b
export OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
uv run agent-eval blackbox run --suite benchmarks/model-release/v1/suite.yaml \
  --agent ollama-qwen2.5-7b --url-env OLLAMA_BASE_URL --model qwen2.5:7b \
  --system-prompt benchmarks/model-release/v1/system-prompt.md \
  --response-format json --trials 3
```

The model receives the system prompt and the case input only. With
`--response-format json`, the request asks for a JSON object. A reply that is not
JSON stays text, so the checks reject it as a model answer. Each observation
records latency and the `prompt_tokens` and `completion_tokens` that the endpoint
reports. The report adds `tokens_in` and `tokens_out` totals. Use
`--token-env` for a gateway key. To run the same suite on several models and
pick the cheapest one that passes, see [model comparison](model-comparison.md).

## Suites and generated goldens

A suite declares `schema_version`, `id`, `version`, `metrics`, and `cases`.
Each case has `id`, `input`, and `expected_output`, with optional `tags`, judge
`context`, and case-specific `metrics` that replace the suite defaults.

The agent receives only `input`. Case IDs, expected outputs, reference context,
criteria, thresholds, and scores stay with the evaluator. Information the agent
needs to answer must be included in `input` or already available in its own
knowledge base; `context` supplies independent judge evidence.

Goldens may be generated from a CSV, documents, or another trusted source before
a run. A generator can write a suite directly, or produce a simple JSON array:

```json
[
  {
    "id": "support-hours",
    "input": "When is support available?",
    "expected_output": "09:00 to 17:00 UTC",
    "tags": ["faq"]
  }
]
```

Freeze that generated file with:

```sh
uv run agent-eval blackbox import-goldens \
  --goldens /absolute/path/generated-goldens.json \
  --suite-id support-faq --version 2026-09-04 --metric contains
```

The command prints the path of a private, content-addressed suite. Pass it to
`--suite`. Every evaluation stores another canonical suite snapshot and its
SHA-256 digest. Regenerating the source file later cannot change that run's
saved expectations. Compare agents using the same suite digest, input data,
trial count, and judge settings. The target digest identifies invocation
configuration, not the executable's contents; use a versioned agent label and
pinned target deployment when comparing releases.

Generated answers still need independent review. Deriving the expected answer
from the same answer being graded creates circular evidence. Automatic corpus
generation and refresh scheduling are deliberately separate from agent execution.

## Metrics and outcomes

| Metric | Evidence |
|---|---|
| `exact_match` | Identical canonical JSON values; text is whitespace-sensitive. |
| `contains` | A nonempty expected string occurs in the actual text, case-sensitive. |
| `json_subset` | Expected object keys and nested values match; extra object keys are allowed. Arrays preserve length and order. |
| `geval` | DeepEval evaluates configurable criteria against input, output, expected output, and optional reference context. |

Every metric has its own threshold. All configured metrics must pass. A trial's
reported score is the lowest metric score, so a high judge score cannot conceal
a failed deterministic check. No critique or expected answer is fed back to the
target, and no automatic retries replace a first attempt. `--trials` creates
separate requests and preserves each result. Stateful HTTP targets must provide
their own reset or fresh-session behavior in the input or wrapper.

`accepted` means every gate passed; `rejected` means the response failed a
quality gate; `infra_error` means trustworthy evidence could not be collected.
Timeouts, nonzero exits, malformed JSON, missing replay records, digest
mismatches, and failed judges are infrastructure errors. They contribute zero
to the cohort average, remain separately counted, and make the run fail.
Missing latency stays null. Token usage and costs are not inferred from text.

Exit codes are `0` for a passing run, `2` for quality or infrastructure failures,
and `1` for configuration, import, or persistence errors.

For GEval, install the optional dependencies and configure the gateway:

```sh
uv sync --extra judge
# Set MODEL_GATEWAY_API_KEY, AGENT_EVAL_JUDGE_MODEL, and optionally
# MODEL_GATEWAY_BASE_URL in your private environment.
uv run agent-eval blackbox run --suite examples/blackbox/faq-geval.yaml \
  --agent faq-smoke --command "python3 $PWD/examples/blackbox/smoke_target.py" --judge
```

Judging sends input, actual output, expected output, and context to the configured
judge. It requires explicit `--judge`; adding a metric to a suite cannot silently
enable model calls. The integration was checked against DeepEval 4.2.0 on
September 4, 2026. See the [official GEval contract](https://deepeval.com/docs/metrics-llm-evals).

## Replay from a proxy or application database

Store one observation for the **final agent response**. An individual model call
inside a multi-step agent is not sufficient evidence of the whole agent's
behavior. A model proxy can supply observations if its records capture the final
request/response boundary, or if a trusted query joins them to the application
request and final result. Choose the specific run and agent version in your query.

JSONL records follow this contract:

```text
case_id          required, matches the suite
trial            integer, defaults to 1
input_sha256     required, SHA-256 of canonical JSON encoding of suite input
actual_output    required, native JSON value, including text or null
status           completed or error, defaults to completed
latency_ms       optional, null means unavailable
trace_id/span_id optional pair, lowercase nonzero OTel IDs
```

Use `agent_eval.blackbox.models.digest(input_value)` to compute the input digest.
Canonical JSON uses sorted keys, ASCII escaping, no separator whitespace, and
finite numbers. Even string inputs are JSON-encoded for this digest. Replay
requires one observation per requested case/trial. Missing records fail the
run, while duplicate or unexpected keys reject the import. A digest checks
alignment, not authenticity; import only from a trusted observation store.

```sh
uv run agent-eval blackbox replay --suite /absolute/path/suite.json \
  --agent assistant-v2 --observations /absolute/path/observations.jsonl --trials 3
```

For SQL, supply a read-only query that maps your schema to the observation
fields. Use `actual_output_json` for **JSON-encoded text**, then optional columns
with the names above. Do not select goldens or intermediate spans as outputs.

```sql
SELECT case_id, trial, input_sha256,
       actual_output_json, latency_ms, status, trace_id, span_id
FROM agent_observations
WHERE run_id = 'the-run-to-evaluate'
ORDER BY case_id, trial;
```

For a plain text answer column, use SQLite's `json_quote(answer)` or Postgres's
`to_jsonb(answer)::text AS actual_output_json`. For JSONB, cast to text.

```sh
uv run agent-eval blackbox replay-db --suite /absolute/path/suite.json \
  --agent assistant-v2 --sqlite /absolute/path/proxy.db --query /absolute/path/read.sql

uv sync --extra database
# Set AGENT_EVAL_SOURCE_DSN privately using a read-only Postgres account.
uv run agent-eval blackbox replay-db --suite /absolute/path/suite.json \
  --agent assistant-v2 --dsn-env AGENT_EVAL_SOURCE_DSN --query /absolute/path/read.sql
```

SQLite opens in read-only mode and rejects writes, ATTACH, and unsafe pragmas.
Postgres uses a read-only transaction and prepared single-statement execution.
Queries have a 30-second statement limit and bounded row/content import. Use a
read-only account as an additional boundary, especially for custom SQL functions.
The evaluator does not assume that Phoenix's internal database, an OTel exporter,
and your model proxy use the same schema.

## Private records and optional telemetry

On macOS, artifacts default to
`~/Library/Application Support/agent-eval/blackbox/<run-id>/`:

- `suite.json`, the canonical input and golden snapshot;
- `report.json`, the authoritative per-trial output and scoring evidence;
- `observations.jsonl`, captured responses for later replay;
- `../metrics.db`, a queryable summary index across runs and agent labels.

Directories are owner-only and files are mode `0600`. Override the state root
with `AGENT_EVAL_STATE_DIR`. Raw inputs, goldens, answers, and judge reasons stay
in those private local artifacts, which should not be committed or published.

Install `--extra observability` and set `AGENT_EVAL_OTEL_ENABLED=1` to send scores,
outcomes, latency, hashes, and numeric metrics through the existing Collector.
Raw content, agent labels, case names, credentials, and endpoints are excluded
from the projection. Recorded OTel IDs create span links for investigation.
Agent instrumentation is optional, and unavailable telemetry never changes a
score. A local record remains authoritative when Phoenix is unavailable.

CLI blinding is an interface boundary, not a security sandbox. A process running
as your user can access that user's files. Evaluate untrusted executables inside
a separate container or service, and use the existing isolated k3s task mode
when you need its stronger execution boundary. Input/output evaluation measures
observable results; separate environment checks are needed to prove side effects.
