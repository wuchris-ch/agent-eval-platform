# Agent Eval Platform

[![Assurance](https://github.com/wuchris-ch/agent-eval-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/wuchris-ch/agent-eval-platform/actions/workflows/ci.yml)
[![Python 3.12–3.14](https://img.shields.io/badge/python-3.12%E2%80%933.14-3776AB)](pyproject.toml)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-2f855a)](LICENSE)

An evaluation platform that checks what agents produce against independent
behavior and final-state evidence. Reserve matched trials before dispatch,
evaluate the exact candidate, investigate failures, and replay saved decisions
under different resource limits.

Evaluate coding agents, pull-request reviewers, CLI tools, HTTP services, or
recorded database responses. Versioned contracts and deterministic checks work
across agent frameworks; optional DeepEval judging supports additional criteria.

[Open the evidence explorer](https://wuchris-ch.github.io/agent-eval-platform/)
to compare recorded trials, inspect independent checks and receipt identities,
preview resource policies, and download the evidence.

[![Agent evaluation and observability architecture](docs/local-review-platform.svg)](https://wuchris-ch.github.io/agent-eval-platform/architecture.html)

[Explore the architecture](https://wuchris-ch.github.io/agent-eval-platform/architecture.html)
to zoom, pan, and move between the supporting system diagrams.

This repository contains the evaluation system. The separately deployable
reviewer lives in [`pr-review-agent-flue`](https://github.com/wuchris-ch/pr-review-agent-flue).

The [Agent Reliability & Evaluation Platform upgrade plan](docs/platform-plan/README.md)
contains the September 11, 2026 research, current-state assessment, proposed
architecture, and phased implementation plan. The [implementation status](docs/platform-plan/status.md)
separates working features from operational qualifications.

The [experiment workbench](docs/workbench.md) provides a packaged local UI, durable
trials, independent state checks, paired comparisons, annotations, release policies,
private target profiles, and opt-in PostgreSQL/Kubernetes execution.

```sh
uv run --frozen agent-eval workbench demo
uv run --frozen agent-eval workbench serve
```

Open the printed local URL to inspect the seeded regression. The demo makes no
model calls. See [journal recovery](docs/experiments.md) for crash and cancellation
semantics. Production deployment and hostile hosted execution require separate
qualification.

## Start with black-box evaluation

```sh
uv run agent-eval blackbox run \
  --suite examples/blackbox/faq.yaml --agent faq-smoke \
  --command "python3 $PWD/examples/blackbox/smoke_target.py"
```

This credential-free fixture demonstrates the connection and scoring path.
Replace the command with your agent, use `--url-env` for an HTTP service, or
use `blackbox replay-db` to evaluate final responses from SQLite or Postgres.
Generated golden files can be frozen with `blackbox import-goldens`.

Read the [black-box evaluation guide](docs/blackbox-evaluation.md) for FAQ and
triage examples, native JSON response mapping, DeepEval metrics, generated
goldens, database queries, and private result storage.

For agents with available source or execution traces, add
[optional source and trace inspection](docs/agent-inspection.md). It supports
repository checks, tool-call checks, and DeepEval inspection while keeping the
shared input/output score separate. Saved runs can be inspected without rerunning
the agent.

## Platform verification

Verified September 11, 2026 (Vancouver; September 12 UTC), on released evaluator revision `048a8d4`.

| Check | Observed result |
|---|---|
| Python 3.12, 3.13 and 3.14 | **1,012 passed, 4 skipped on each version** |
| Package and task images | Build, pinned scanner controls, dependency audits and installed-wheel checks passed |
| Workbench persistence | Existing experiments and notes survived restart; isolated wheel/API/restart smoke passed |
| Live PostgreSQL → k3s | Fenced claim, real Job, receipt persistence, exact output and owned-pod cleanup passed |

[Verification details and skip explanations](benchmarks/platform/results/2026-09-12.md) · [Post-merge CI](https://github.com/wuchris-ch/agent-eval-platform/actions/runs/34663061627) · [Live execution evidence](benchmarks/platform/results/2026-09-12-distributed.json).

## Live software producer study

Recorded September 12, 2026 in Vancouver, September 13 UTC: **four task families
× three trials × two policies**, plus two separately reported assisted attempts.
All 24 initial tickets were reserved before the actual producer called the live
model gateway. The evaluator independently checked candidate behavior and final
SQLite state.

| Initial result | Single coder | Selective coordination |
| --- | ---: | ---: |
| Accepted / planned | **9 / 12** | **4 / 12** |
| Inconclusive with candidate | 3 | 5 |
| Failed before candidate | 0 | 3 |
| Median recorded production time | 21.52 s | 35.28 s |
| Producer-reported model requests | 60 | 79 |

All 21 returned candidates passed independent behavior checks. Eight remained
inconclusive because producer completion was not established. The study found
a form-task verifier image missing Python, three planner validation failures,
and two workflows requiring attention. A new verifier preflight catches the
image prerequisite before future trial admission; its positive and negative
controls made zero model calls. Eight incomplete task/trial pairs prevent a
paired confidence interval. The complete report retains every outcome and
measurement's provenance.

[Explore the 26 records](https://wuchris-ch.github.io/agent-eval-platform/?collection=software-study)
· [Full methods and results](benchmarks/software-corpus/v1/results/2026-09-13-software-study.md)
· [Download the verifiable bundle](docs/evidence/software-study.json.gz).

Release verification passed **1,048 regression tests** with 5 skipped, plus
two new preflight tests. Independent oracle controls produced **10/10 expected
decisions**; actual authenticated producer/evaluator controls produced **2/2**.

## Preserved live reviewer baseline

On September 11, 2026 (September 12 UTC), the released evaluator ran the actual
Flue reviewer against the live model gateway: **20 cases × 3 trials**, with no
evaluator self-correction or LLM judge. All 60 first attempts are included.

| Metric | Result | Required gate |
|---|---:|---:|
| Release gate | **FAIL** | PASS |
| Overall grade | A | A |
| Average score | 0.958 | ≥ 0.900 |
| Accepted / first-pass evaluations | 56/60 (93.3%) | Informational |
| Infrastructure errors | 0 | 0 |
| Security-blocker exact-match recall | 85.7% (18/21) | 100% |
| Clean-diff accuracy | 100% (21/21) | ≥ 95% |
| Case stability | 85% (17/20) | 100% |
| Median / p95 invocation latency | 8.75 s / 28.39 s | Informational |

Three security findings failed the exact source-line match; one trial missed a
swallowed-error bug. The aggregate A grade does **not** override the failed gate.
This is a known regression corpus, not a held-out production-quality estimate.

The [complete live result](benchmarks/reviewer-corpus/v1/results/2026-09-12-flue.md)
contains every trial, pinned code/image identities, methodology, and limitations.
Raw responses and private gateway configuration remain local. The
[September 3 result](benchmarks/reviewer-corpus/v1/results/2026-09-03.md) is historical
and used a different reviewer/model and correction policy.

## What makes the evaluation trustworthy

- **Blind execution.** The target receives the declared input, raw diff, or task
  workspace. Case IDs, goldens, scoring thresholds, and expected answers remain
  with the evaluator.
- **Independent evidence.** The harness owns hidden tests, scanners, golden
  matches, acceptance policy, and the final result.
- **Explicit failure semantics.** `accepted`, `rejected`, and `infra_error`
  prevent a broken model request from being counted as a clean result.
- **Reproducible inputs.** Corpus artifacts, expected findings, task images,
  commands, and reports are bound to hashes and versioned metadata.
- **Separate correction metrics.** First attempts and critique-guided corrections
  are recorded separately, so retries cannot rewrite the baseline.
- **Privacy-aware observability.** Traces retain scores, latency, attempts, and
  counts while excluding prompts, diffs, completions, credentials, and private
  endpoints.

## Evaluation modes

| Mode | Target | Evidence |
|---|---|---|
| Independent software candidate | A producer's exact Git base, candidate tree and patch | Pre-dispatch trial tickets, isolated behavior checks, independently queried final state, paired studies and portable decision replay |
| General black-box evaluation | Any CLI or HTTP agent; recorded JSONL, SQLite, or Postgres observations | Versioned input/output cases, exact/contains/JSON checks, optional configurable GEval, repeated trials |
| Reviewer benchmark | External review-agent executable | 20 golden diffs, exact finding matches, block decisions, stability, optional GEval |
| Coding-agent run | Agent working inside k3s | Hidden tests, coverage, Semgrep, Gitleaks, Trivy, Ruff, challenges, optional judge |
| Existing workspace | Already-produced code | The same evaluator without launching an agent |

### Reviewer benchmark

Each case binds a raw unified diff to expected file, category, severity, and
changed-line ranges. Deterministic scoring combines finding F1 with the expected
block decision. A valid rejected result may receive one critique-guided retry,
but both attempts remain in the report.

The strict cohort gate requires:

- zero infrastructure errors;
- 100% recall for security-blocker goldens;
- at least 95% accuracy on clean diffs; and
- identical verdict signatures across all three trial rounds.

An optional DeepEval GEval judge can make a score stricter, but it cannot
override failed deterministic evidence.

### Isolated coding-agent evaluation

The strongest task mode is `isolated-black-box`:

1. The agent receives a prompt and starter workspace in its own pod.
2. Hidden tests remain inside a separate evaluator image.
3. The produced application is exposed through one declared TCP port.
4. The evaluator runs hidden tests, coverage, scanners, and policy checks.
5. The agent cannot edit its evaluator or final result.

## Platform stack

| Layer | Technology | Responsibility |
|---|---|---|
| Runtime | Python 3.12+, Pydantic, Typer, uv | Typed evaluation contracts, orchestration, reporting, and reproducible dependency resolution |
| Local cloud | k3d, k3s, Kubernetes | Long-running reviewer worker, isolated evaluation jobs, nightly scheduling, Secrets, Services, and persistent volumes |
| Evaluation | Deterministic goldens, hidden pytest suites, coverage, DeepEval GEval | Combines exact evidence with an optional model judge without allowing subjective grading to weaken a failed hard gate |
| Security evidence | Semgrep, Gitleaks, Trivy, Ruff | Static analysis, secret detection, vulnerability scanning, and code-quality signals with pinned invocation policy |
| Observability | OpenTelemetry SDK, OTLP, OpenTelemetry Collector, Phoenix | End-to-end traces for runs, attempts, scores, latency, and failures, with sensitive review content removed before export |
| Evidence store | Versioned JSON, SQLite, SHA-256 digests | Preserves the canonical run record, queryable metrics, provenance, and later verification |
| Automation | GitHub watcher, Kubernetes Deployment, CronJob | Reviews new pull-request revisions continuously and runs the three-trial release benchmark every night |
| Delivery | Docker, pinned images, GitHub Actions | Reproducible task isolation, multi-version tests, scanner verification, package builds, and supply-chain checks |

### Always-on local control plane

The platform runs as a small local AI operations environment rather than a
one-shot script. A persistent Kubernetes worker polls configured repositories
once per minute, reviews each new pull-request head exactly once per policy
version, publishes the verdict, and reports a GitHub commit status. A nightly
CronJob then re-evaluates the reviewer against the complete golden corpus.

```text
GitHub pull request -> k3s reviewer -> model gateway -> validated verdict -> GitHub
                              |                 |
                              +-> OTLP Collector +-> Phoenix trace explorer

Versioned corpus -> isolated evaluator -> evidence gates -> JSON + SQLite -> release grade
```

Kubernetes provides declarative recovery for the reviewer, telemetry pipeline,
trace UI, scheduler, and result persistence. On a laptop, work pauses while the
machine sleeps and resumes when Docker and the local cluster return.

## Outputs and observability

The detailed JSON report is the authoritative record. It contains every trial,
first and corrected attempt, score component, outcome, and timing measurement.
A content-minimized Markdown record can be published with:

```sh
./record-review-eval gemini-3.8-flash
```

OpenTelemetry spans flow through a checked-in Collector configuration before
reaching Phoenix. The projection includes corpus identity, case, trial,
outcome, attempt count, scores, latency, finding counts, and a command digest.
The Collector removes prompt, completion, provider, server-address, and
authorization attributes.

Local result files remain authoritative if telemetry is unavailable.

## Outcome model

| Outcome | Meaning |
|---|---|
| `accepted` | The target completed and met every configured requirement. |
| `rejected` | The target completed, but its evidence failed a quality gate. |
| `infra_error` | The harness could not collect trustworthy evidence. |

Infrastructure errors contribute zero to cohort averages, so broken execution
cannot inflate a grade. Grades are A at `0.90`, B at `0.75`, C at `0.60`, and F
below `0.60`.

## Repository map

```text
benchmarks/        versioned reviewer corpora, goldens, and public records
deploy/            evaluator image and local k3s manifests
observability/     Docker Compose and privacy-filtering OTel configuration
src/agent_eval/    runner, evaluators, policy, evidence, and reporting
tasks/             isolated coding-agent tasks and hidden evaluators
tests/             unit, integration, adversarial, and assurance tests
```

## Reproduce

Verify the independent observer with fixed positive and negative candidates:

```sh
uv sync --frozen --all-extras
uv run python scripts/qualify_software_corpus.py --out /tmp/software-qualification
```

This runs ten controls in the corpus's pinned Docker images without model calls.
Use a new output directory. The [software corpus](benchmarks/software-corpus/v1/README.md)
defines task contracts, checks, matched budgets, and family-level comparisons.

The [candidate contract guide](contracts/v2/README.md) documents authenticated
producer intake, independent assessment, crash recovery, and study reservation.
The local workbench's **Candidate studies** view exposes comparisons, failure
investigation, resource-policy previews, and evidence export to authorized
project members. Raw reference observations require curator access.

Replay the published study without model calls:

```sh
gzip -dc docs/evidence/software-study.json.gz > /tmp/software-study.json
uv run agent-eval candidate verify /tmp/software-study.json
uv run agent-eval candidate policy-preview /tmp/software-study.json \
  --max-latency-ms 30000
```

## Development

```sh
uv run ruff check .
uv run pytest
uv build --no-sources
```

The CI matrix tests Python 3.12, 3.13, and 3.14, builds the isolated task
images, verifies embedded agent binaries, runs pinned secret and vulnerability
scanners, and proves the packaged wheel works without the source tree.

See [DETAILS.md](DETAILS.md) for the exact contracts, metrics, governance,
attestation, isolation model, and security boundaries.

## Reviewer migration

The review stack uses Flue for both continuous GitHub reviews and the independent daily evaluation. `./review-stack up` builds revision-tagged images from the sibling `pr-review-agent-flue` checkout, imports them into k3s, and waits for rollout completion. The single worker uses Recreate upgrades to avoid overlapping review publication. The existing runtime Secret, watched repositories, status context, and completion markers are preserved. No database migration is required.

## License

Apache-2.0. See [LICENSE](LICENSE).
