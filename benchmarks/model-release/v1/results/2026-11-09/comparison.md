# Model comparison: model-release-triage 1.0.0

Recorded 2026-11-10T04:30:29.625315+00:00. Each model ran every case 3 time(s). The release gate passes only when every evaluation is accepted.

| Model | Deployment | Release gate | Accepted | Infra errors | Tokens in / out | Cost (USD) | Median latency | p95 latency |
|---|---|---|---:|---:|---:|---:|---:|---:|
| ollama-llama3.2-3b (llama3.2:3b) | local | FAIL | 15 / 36 | 0 | 13,356 / 600 | $0.0000 | 0.37 s | 0.54 s |
| ollama-qwen2.5-7b (qwen2.5:7b) | local | FAIL | 27 / 36 | 0 | 12,954 / 864 | $0.0000 | 1.18 s | 1.38 s |
| ollama-qwen2.5-14b (qwen2.5:14b) | local | FAIL | 33 / 36 | 0 | 12,954 / 672 | $0.0000 | 2.00 s | 2.54 s |
| hosted-gpt-6.1-sol (gpt-6.1-sol) | hosted | PASS | 36 / 36 | 0 | 659,561 / 684 | $1.3260 | 3.83 s | 4.86 s |

**Recommendation:** hosted-gpt-6.1-sol. hosted-gpt-6.1-sol is the cheapest of 1 model(s) that passed the release gate, at $1.3260 for the run.

Prices:

- ollama-llama3.2-3b: $0 input and $0 output per million tokens, $0 hardware per hour.
- ollama-qwen2.5-7b: $0 input and $0 output per million tokens, $0 hardware per hour.
- ollama-qwen2.5-14b: $0 input and $0 output per million tokens, $0 hardware per hour.
- hosted-gpt-6.1-sol: $2 input and $10 output per million tokens, $0 hardware per hour (OpenAI API standard short-context list price for gpt-6.1-sol, checked 2026-11-09).
