# Current state and gaps

Inspected September 11, 2026. Links below refer to this worktree's source. `README` statements, historical reports, task messages, source inspection, locally executed tests, and live configuration observations are different evidence classes.

## Revision and scope

This worktree and `/Users/chris/Projects/agent-eval-k3s` both started at `9b68ab520427e93a104a8d36966401a499f2fd92`, package `0.4.0`. The original checkout had no tracked modifications; only `.DS_Store` and `benchmarks/.DS_Store` were untracked. Its ignored local `AGENTS.md` supplies the public-repository privacy boundary. It was read and remains local-only. No runtime endpoints, credentials, or raw private responses belong in this plan.

The original checkout and sibling repositories were inspected read-only. This plan introduces no release or runtime changes. Recheck revision and dirty state when implementing; this is a dated snapshot, not a promise that concurrent work stopped.

## Verified implementation map

| Area | Source evidence | What exists and what it does not establish |
|---|---|---|
| General transport | [targets.py](../../src/agent_eval/blackbox/targets.py), [CLI](../../src/agent_eval/blackbox/cli.py) | CLI and HTTP targets, bounded output/deadlines, environment allowlisting, JSON decoding and pointer mapping. `Target.invoke(input)` receives the input only. Local processes still share the user's OS authority; blinding is not a sandbox. |
| Frozen cases and scoring | [models.py](../../src/agent_eval/blackbox/models.py), [scoring.py](../../src/agent_eval/blackbox/scoring.py) | Strict suite schema `1.0`, input/golden/context snapshots, exact/contains/JSON-subset checks, optional GEval. All configured metrics gate; the minimum score prevents a judge from hiding a hard failure. No generic final-state observer contract yet. |
| Trials and failures | [blackbox runner](../../src/agent_eval/blackbox/runner.py) | Sequential case/trial loop, no automatic response correction. Timeouts, invalid output, transport and judge failures map to `infra_error`; errors contribute zero to the average. The whole report is constructed in memory before saving. There is no durable per-trial resume journal here. |
| Replay and persistence | [storage.py](../../src/agent_eval/blackbox/storage.py), [paths.py](../../src/agent_eval/paths.py) | JSONL, read-only SQLite/Postgres import; rejects missing, duplicated, unexpected and digest-mismatched observations. Private atomic files plus a SQLite summary index. Files and index are separate writes, not one transaction; the index is reconstructible. Replay alignment hashes do not authenticate the observer. |
| Inspection | [inspection.py](../../src/agent_eval/blackbox/inspection.py), [trace models](../../src/agent_eval/blackbox/inspection_models.py), [trace loader](../../src/agent_eval/blackbox/trace_evidence.py) | Source snapshots, tool presence/order/budget/error checks, optional source/trace GEval. Saved-run inspection creates a derivative report. Missing/incomplete evidence is unavailable. Output `passed` stays separate from required inspection `overall_passed`. Collector completeness is an assertion requiring trust, not a proof produced by a hash. |
| Reviewer evaluation | [external evaluator](../../src/agent_eval/external_review_eval.py), [benchmark](../../src/agent_eval/review_benchmark.py) | Raw-diff contract, finding matching, block decision, repeated rounds, first versus corrected attempt, strict cohort gate. `_retry_feedback` uses deterministic/judge reasons. Treat correction as assisted development evidence, never independent held-out success. |
| Existing experiments | [review_experiment.py](../../src/agent_eval/review_experiment.py), [agent_comparison.py](../../src/agent_eval/agent_comparison.py) | Reviewer single/panel comparisons, completeness and efficiency summaries; coding comparisons include cohort identities, Wilson intervals and paired deltas. Do not claim statistics are absent. Generalize carefully: these are specialized models, not a shared experiment scheduler/UI. |
| Coding and governance | [runner.py](../../src/agent_eval/runner.py), [kube.py](../../src/agent_eval/kube.py), [governance.py](../../src/agent_eval/governance.py), [task.py](../../src/agent_eval/task.py) | Existing-workspace and agent execution; governed tasks require isolated black-box evaluation, protected evaluator/results, preapproved image identity and policy. Same-node containers share a kernel. Policy assertions and local provenance are not a hosted trust service. |
| Assurance | [scanners](../../src/agent_eval/evaluators/scanners.py), [audit](../../src/agent_eval/audit.py), [attestation](../../src/agent_eval/attestation.py), [assessments](../../src/agent_eval/assessments.py) | Frozen scanner policy/runtime, normalized assessments, audit chains and provenance. Local ownership, hash chains and schemas alone do not establish authenticated tenants, signed remote provenance or trusted time. Preserve these mechanisms rather than replacing them. |
| Usage limits | [governance.py](../../src/agent_eval/governance.py), [outcome.py](../../src/agent_eval/outcome.py) | Observed token/cost thresholds reject missing/excessive evidence and can prevent later trials. They are not in-flight spend reservations, shared accounting, or guaranteed provider cancellation. |
| Operations/UI | [stack.yaml](../../deploy/k3s/stack.yaml), [observability](../../observability/otel-collector.yaml), [viewer.js](../viewer.js) | Flue worker, nightly evaluator, Collector/Phoenix configuration, privacy-aware projections and architecture explorer. The explorer is not a run-management interface. Telemetry remains optional and non-authoritative. |

## Observations from this task

- `uv run --frozen ruff check .` passed on the inspected tree.
- The credential-free documented FAQ CLI path completed with **2/2 accepted, zero infrastructure errors, score 1.000**, telemetry disabled. This validates plumbing, not AI quality.
- A first smoke invocation used `/tmp` for private state and failed with `UnsafeStatePathError`. On this Mac `/tmp` is a symlink and `paths.py` rejects symlink components. Retrying with a direct worktree path succeeded. Its generated fixture artifacts were moved out of the repository to `/private/tmp/agent-eval-planning-verification-20260911`. This is a useful onboarding edge case, not evidence of model failure.
- The full offline pytest result is recorded in the verification note below. It includes mocked orchestration; `test_governed_integration.py` patches scanner evidence. Passing it does not re-prove live network isolation or scanner binaries.
- Five recent local black-box reports were read only for summary fields. They were September 4 fixture-sized runs, schema `1.0`/`1.1`, with two or six evaluations. Their presence establishes local use of run/replay/inspection, not a broad agent benchmark.
- A read-only Kubernetes API query found one ready `pr-review-worker`, Recreate strategy, image tag `pr-review-agent-flue:024f477e613de41a23a4b6a8986c735f703bbdae`. The nightly CronJob schedule was `0 2 * * *`, using evaluator tag `9b68ab...-024f477...`, with last successful time `2026-09-11T20:40:29Z`. These are controller/configuration observations. No new Job ran, no raw cluster result was fetched, and neither image digest nor quality was independently verified here.

The [September 3 public benchmark](../../benchmarks/reviewer-corpus/v1/results/2026-09-03.md) records 60/60 accepted, 57/60 first-pass, reviewer revision `53527626060488db6c095aaea8adee3ce55e0ec5`, and evaluator revision `b1d38735ef75d21a52ebf43c5847e5204ab43a20`. It is historical evidence for that reviewer and corpus. **It does not establish the current Flue reviewer's performance.** Three corrected trials also prevent describing it as 60 first-attempt successes. Raw-report authenticity was not reverified in this task.

## Recent decisions and usage

Read task history for **Generalize agent evaluation** (`01a06dfc-a0c3-71a0-a023-6d3119c2234e`, September 4), **Assess eval agent compatibility** (`01a07583-e8b1-7093-af30-84d198a59d97`, September 6), **Modernize agent eval platform** (`019f63af-ecbf-77c1-9d79-862eb35ffcaf`, July), and the available recent history/preview for **Migrate PR reviews to Flue** (`01a0921c-64a4-7fb2-8dd1-3406363ba214`, September 11).

Preserve these decisions: broad input/final-output integration; optional source and traces; independent environment checks for real side effects; protected evaluation; private local data; and Flue replacing the old reviewer without changing the GitHub review workflow. Earlier messages report live checks and releases, but those are historical reports, not checks executed today. The September 4 release history specifically found and repaired private-volume permissions, which warrants an installation diagnostic.

The companion planning task `01a092a1-f438-7e40-9592-c995d8771bd5` was active when read; the intended destination directory was not yet present during the initial inspection. Available status favors an accountable writer, optional specialists and independent review. This plan does not depend on its completion and does not modify its files. Its contract is a proposal, not a jointly validated integration.

## Related implementations worth using

| Project snapshot | Inspected ideas | Reuse and boundary |
|---|---|---|
| `pr-review-agent-flue` `024f477e613de41a23a4b6a8986c735f703bbdae`, clean | `src/agents/runtime.ts`, CLI, README | One-shot raw diff to strict JSON. Fresh in-memory Flue conversation, format correction and framework transport retries. Cost placeholders are not spend evidence. Keep the watcher separate and run the one-shot interface privately. |
| `agent-reliability-lab` `3879e88378805074b4c39809fd835aa45171afd3`, clean | `src/order_agent_lab/evaluation.py`, `fake_erp.py`, MCP paths, README | Twenty order-status cases, typed grounding, request-scoped faults, scripted/live planners and trace checks. Use as a non-coding target plus pinned fake ERP. Build independent platform graders instead of importing its final pass bit. Its customer ID is a fixture, not authentication. |
| `agent-gauntlet` `c020256546c95d1fa6076677d503e9cc762576fe` | `src/graders/index.ts`, README | State `exists/absent/count/field`, trajectory and output checks, good/sloppy scripted agents. Port a narrow declarative state predicate model and negative controls, not the TypeScript episode runtime. A snapshot is trustworthy only when collected independently. Untracked lessons/reference/media and notes existed and were left alone. |
| `deepswe-claude-code-eval` `a64d833d8f55b31c1c397ebf79c548a5089cea6d` | `harness/scoring.py`, `report.py`, README, artifact inventory | Correctness, scope and test-integrity checks; task/prompt/model matrix and trajectories. Temporary directories with hidden paths are weaker than separate evaluator authority. Do not inherit completed-run-only performance denominators or historical model rankings. Only untracked Finder metadata observed. |
| `nexus-mcp-gateway` `20815a1e8c936cec99006e8ac34713647065db40` plus dirty tree | `gateway/src/router.py`, `ratelimit.py`, README | Useful tool boundary for scoped fault injection and tool-call audit. Current limiter is in-memory per process, not an atomic multi-worker budget. Tracked routing/config/README edits and untracked audit, limiter, tests, utils server and docs existed; any reuse must pin the eventual committed implementation. Do not assume it is a completed agent runtime. |

No sibling test suites or paid evaluations were run. Their README metrics are not reproduced results here.

## Priority gaps

1. Durable generic experiment identity, per-attempt persistence, cancellation and crash reconciliation.
2. Usable experiment list, comparison and annotation workflow, with evidence completeness visible.
3. Independent state snapshots and deterministic fault scheduling, including fresh sessions for HTTP targets.
4. Shared statistical semantics across black-box, reviewer and coding modes, including correlated trials and missingness.
5. Calibration and suite lifecycle: known-good/bad controls, reviewed failures, contamination tracking and held-out access.
6. Multi-worker budgets, trusted artifact ingestion, hardened execution and operational recovery.
7. Team identity, authorization, tenant isolation, retention and audit enforcement. These are implementation projects, not boxes to label enterprise-ready.

## Verification note

`uv run --frozen pytest -q` completed with **923 passed, 7 skipped in 122.16 seconds**, CPython 3.12.11. Skip reasons were not printed by this invocation, so the seven skipped checks are not claimed as verified. No live coding job, image build, deployment or paid benchmark is part of this verification. The fresh worktree environment used the existing lockfile without modifying it.
