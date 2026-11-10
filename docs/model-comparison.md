# Compare local and hosted models

`agent-eval blackbox compare-models` runs the same black-box suite on two or
more models and recommends the cheapest model that passes the release gate.
Each model can be a local open-weight model served by Ollama or a hosted model
behind an OpenAI-compatible gateway.

## How it works

1. Every model receives the same system prompt, cases and number of trials.
   The model sees only the case input. Expected outputs and checks stay with
   the evaluator.
2. Each model run is an ordinary black-box report. The release gate passes only
   when every evaluation is accepted. A rejected answer or an infrastructure
   error fails the gate.
3. Each observation records latency and the `prompt_tokens` and
   `completion_tokens` that the endpoint reports.
4. Cost comes from the price table in the models file. A hosted model costs
   its input tokens times the input price plus its output tokens times the
   output price, per million tokens. A local model costs zero dollars per
   token, plus `hardware_usd_per_hour` times the summed model time when you
   set it.
   If a priced model did not report token usage for every evaluation, its cost
   is unknown. A missing count is never treated as zero.
5. The recommendation is the passing model with the lowest cost. Equal costs,
   for example two free local models, fall back to the lower median latency.
   When no model passes, there is no recommendation and the command exits
   with status 2.

## Models file

```yaml
schema_version: "1.0"
models:
  - label: ollama-qwen2.5-7b
    model: qwen2.5:7b
    deployment: local
    base_url: http://127.0.0.1:11434/v1
    price:
      hardware_usd_per_hour: 0.10    # optional
  - label: hosted-model
    model: gateway-model-name
    deployment: hosted
    base_url_env: MODEL_GATEWAY_BASE_URL
    api_key_env: MODEL_GATEWAY_API_KEY
    price:
      input_usd_per_million_tokens: 5.00
      output_usd_per_million_tokens: 30.00
      source: provider list price, checked 2026-11-09
```

Each model sets exactly one of `base_url` or `base_url_env`. Use
`base_url_env` and `api_key_env` for private gateways so that endpoints and
keys stay out of files. Local models cannot have a per-token price, and hosted
models cannot have a hardware price.

## Run a comparison

```sh
brew install ollama
ollama serve                          # or: brew services start ollama
ollama pull llama3.2:3b
ollama pull qwen2.5:7b
ollama pull qwen2.5:14b

export MODEL_GATEWAY_BASE_URL=...     # hosted OpenAI-compatible base URL
export MODEL_GATEWAY_API_KEY=...

uv run agent-eval blackbox compare-models \
  --suite benchmarks/model-release/v1/suite.yaml \
  --models benchmarks/model-release/v1/models.yaml \
  --system-prompt benchmarks/model-release/v1/system-prompt.md \
  --response-format json --trials 3 --out /tmp/model-comparison
```

The command prints one line per model and the recommendation. It writes
three outputs to the `--out` directory:

- `comparison.json` holds the per-model gate result, counts, tokens, cost,
  median and p95 latency, the price used and the recommendation.
- `comparison.md` shows the same comparison as a Markdown table.
- `reports/<label>.json` is the complete black-box report for each model,
  including every answer and check.

Each report is also saved in the private black-box state directory, like any
other run.

## Limits

- Token counts come from the endpoint. Gateways that wrap the model in their
  own prompt report more input tokens than a direct API call would.
- Hosted cost uses the list price you supply. It does not apply cached-input
  discounts unless the price table reflects them.
- Local latency depends on the machine and on whether the model is already
  loaded in memory.
- Suites that require a GEval judge are not supported in comparisons.
