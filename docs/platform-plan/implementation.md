# Implementation, verification and learning plan

Design snapshot, September 11, 2026. See [implementation status](status.md) for completed code and verification; this document retains the original proposed acceptance criteria. Milestones are sequential unless a dependency is explicitly optional. Acceptance criteria below are proposed, not completed. Finish a small usable release after M2; do not make hosted infrastructure a prerequisite for personal use.

## M0: Lock the compatibility baseline

**Deliverable:** an architecture decision approving the new envelope, a sanitized fixture catalog, and compatibility tests for legacy black-box, inspection, reviewer and coding reports. Inventory current private artifacts through metadata only. Pin the implementation starting revision and inspect concurrent changes again.

**Acceptance:** current commands retain flags, exit codes, scores, input blinding and private paths; fixture import/export preserves legacy semantics. Known-good/bad fixtures catch grading defects. A new Flue baseline is explicitly marked missing until it is actually run. The existing watcher and nightly schedule are untouched.

**Learn and explain:** `blackbox/models.py`, `blackbox/runner.py`, `blackbox/storage.py`, `external_review_eval.py`, and `agent_comparison.py`. Explain why output quality, execution success, and observability are different. Independently alter an input digest, omit a trace, and create duplicate replay keys; predict which validation fails before running it.

**Interview evidence:** an API compatibility and migration story backed by fixtures, not a rewrite claim.

## M1: Durable generic experiments

**Deliverable:** opt-in experiment plan/journal, immutable identity, per-attempt artifacts, read/status/resume commands and a single-worker executor. Factor reusable evaluation logic while leaving existing `blackbox run` behavior intact. Use schema migrations with backup, forward migration and old-report readers; fail closed on a newer unknown schema.

**Acceptance:** kill the worker after one of three trials, after dispatch, after observation persistence, and during finalization. Completed observations survive. Resume never reruns a completed trial. A finished observation can be graded without reinvocation. Ambiguous non-idempotent execution becomes reconciliation-required. Duplicate finalization produces one authoritative decision. Losing the summary index does not lose evidence. Missing or corrupt artifacts prevent a passing gate.

**Learn and explain:** existing `paths.py` and `state.py`, plus proposed `experiments/models.py`, `journal.py`, `service.py`, `executor.py`. Explain transaction boundaries, crash windows and idempotency. Independently kill a fixture subprocess, corrupt a copied manifest, and rebuild the disposable index.

**Interview evidence:** a reproducible crash/recovery demonstration and the tradeoff between exactly-once records and at-least-once execution.

## M2: A workbench Chris uses daily

**Deliverable:** loopback API and packaged UI; experiment list, launch preview, baseline/candidate case comparison, trial detail and annotations. Register Flue and the order-status agent through private target profiles. Begin with recorded observations and scripted/mock endpoints, then enable budgeted live runs separately.

**Acceptance:** from a fresh local install, launch the offline demo, identify a seeded regression, compare its evidence, annotate it, restart the service and find the same annotation. Show cancelled/incomplete runs distinctly. Browser refresh/reconnect preserves progress. Missing Phoenix remains usable. Required inspection failures are visible alongside unchanged passing output scores. Run one installed-wheel smoke outside the source checkout. Escape malicious output HTML and reject cross-origin mutation requests.

**Learn and explain:** proposed `api/`, `ui/src/`, and `experiments/service.py`; existing inspection/telemetry modules. Explain API pagination, stable IDs, optimistic updates, access to private content and frontend loading/error states. Disable Phoenix, return malformed JSON, and disconnect the event stream without asking assistance for the first diagnosis.

**Interview evidence:** a complete product workflow with accessibility, error handling and persistent state. Record Chris's actual time to find a seeded failure; do not invent a productivity gain.

**Scope check:** run a small Phoenix projection spike before implementing a full trace or annotation editor. Reuse its UI when semantics and privacy survive; retain canonical annotations or explicit imported references in this platform.

## M3: State outcomes and controlled faults

**Deliverable:** independent `EnvironmentAdapter`, state snapshots/predicates, fault schedule receipts, fresh HTTP sessions and order-agent integration. Add the ticket mutation fixture. Keep target runtime code in its own project.

**Acceptance:** a fake successful message without the expected database change fails; changing the wrong row fails; a valid alternate tool path succeeds. Verify cross-customer isolation, unchanged prohibited fields and correct unavailable-data behavior. Known-good and known-bad scripted agents produce expected grades. Same seed reproduces logical faults. A requested but absent fault invalidates the trial. Reset failure stops subsequent trials. Test timeout after a write to distinguish ambiguous completion from safe retry.

**Learn and explain:** proposed `environments/`, `observers/`, `graders/state.py`, `faults/`; compare with `agent-gauntlet/src/graders/index.ts` and the order lab's `evaluation.py`. Explain state invariants, idempotent writes, reset isolation and why traces alone cannot prove final state. Independently insert stale data and omit one observer event, then investigate the difference.

**Interview evidence:** an integration bug caught through state validation that a text-only evaluator missed, supported by a saved fixture and report.

## M4: Trustworthy comparisons and release gates

**Deliverable:** shared comparison service, suite splits and provenance, calibrated graders, immutable gate policies and small Inspect/Harbor import spikes. Preserve existing reviewer metrics rather than flattening them into an unrelated generic score.

**Acceptance:** seeded datasets demonstrate paired improvements, regressions and inconclusive results; missing pairs and duplicate trials cannot inflate evidence. Export separate first-invocation, assisted and infrastructure-recovery results. Regrading leaves old records intact. Known-bad graders fail calibration. Held-out tests/goldens are inaccessible from target fixtures. Changing model, environment, suite or grader identity either partitions the cohort or requires an explicit design that varies that factor. A gate binds the exact candidate artifact and fails on substitution.

**Learn and explain:** `review_benchmark.py`, `review_experiment.py`, `agent_comparison.py`, proposed `statistics/`, `datasets/`, `gates/`. Explain the estimand, pairing, clustered uncertainty, practical margins and repeated testing. Independently build a toy example where filtering out infrastructure failures reverses the apparent winner, then make the UI show both denominators.

**Interview evidence:** a defensible experimental result, including a null result, with reproducible analysis and explicit limitations.

## M5: Recoverable k3s execution

**Deliverable:** PostgreSQL journal/claims, lease fencing, transactional budget ledger/outbox, k3s Job execution and reconciliation. Preserve current protected grading. Test on a separate experimental namespace before connecting any schedule.

**Acceptance:** two workers race for one trial and only one current lease finalizes it. Kill a worker, stop a pod, delay a heartbeat, deliver completion twice, fill artifact storage and disconnect telemetry. Demonstrate safe recovery or explicit reconciliation-required state. Cancellation terminates owned work and records unconfirmed remote work honestly. No stale worker can spend a newly released reservation. Under two concurrent experiments, quota exhaustion delays work without silently changing profiles. Existing watcher service remains healthy during the controlled test.

Use explicit Job deadlines and no platform-hidden retries. Capture observed pod reason, resource profile, node architecture and image identity. Verify actual network denial with probe fixtures, not only YAML inspection. Exercise backup/restore and compare restored report hashes and decision counts.

**Learn and explain:** existing `kube.py`, `runner.py`, `governance.py`; proposed `workers/`, `repositories/postgres.py`, `budgets.py`, `outbox.py`. Explain leases, fencing, isolation levels, resource scheduling and uncertain external effects. Independently recover a stale lease and diagnose an OOM versus an injected tool timeout.

**Interview evidence:** a bounded distributed-systems failure demonstration with measured recovery behavior. Publish actual concurrency and recovery timings only after collecting them.

## M6: Team pilot and reviewed failure ingestion

**Deliverable:** OIDC, project roles, tenant authorization, hardened execution profile, artifact retention, audit trail and export/restore procedures. Add an opt-in pipeline from production failures to quarantined candidate cases. The initial pilot may be two local test identities; do not claim enterprise readiness from that alone.

**Acceptance:** cross-tenant attempts through API, artifact keys, traces, caches and worker credentials fail. Expired/revoked credentials cannot launch or download work. Roles separate viewer, runner, case curator and policy administrator. Test retention deletion and restore behavior on disposable data; document backup retention exceptions. Redact and review imported production cases before publication. Duplicates/near-duplicates remain in one task family/split. Held-out data is not visible to diagnosis agents or case generation. Admission of a generated grader requires oracle and calibration tests. A sandbox escape boundary review and live isolation tests precede any untrusted hosted pilot.

**Learn and explain:** proposed `auth/`, `retention/`, `ingestion/`; existing audit/attestation concepts. Explain authentication versus authorization, object access, revocation and audit limitations. Independently attempt an insecure direct object reference, expire a credential mid-run, and trace a deletion through derived artifacts.

**Interview evidence:** a threat-model-to-test story and a real operating runbook. Remaining gaps are part of the story, not concealed by an enterprise label.

## Benchmark and measurement protocol

Start with the existing 20-case reviewer corpus as a **development/regression** suite and the order lab's 20 cases as imported, independently reviewed fixtures. Keep their results separate. Add capability cases that the current systems do not already saturate: multi-file context, misleading but clean diffs, ambiguous entities, stale evidence, tool schema changes and partial side effects. Review licensing and task validity before importing external packs.

The first new Flue benchmark compares two explicitly pinned configurations of Flue, not a presumed reproduction of the old reviewer. A historical result may appear for context with an incompatibility label. Where Flue inner-call evidence is missing, record it as unavailable. Real model runs, including judges, require a later explicit budgeted execution task.

### Design before execution

1. Freeze suite, task-family IDs, baseline/candidate revisions, grader, resource profile, repetitions and primary metric. Keep a separate held-out set outside public source; do not tune on its failures. Treat the existing public suites as exposed.
2. Begin with three replicates per case for workflow/regression checks. This is an affordable initial design, not proof of high reliability. Run a pilot to estimate variance and choose a fixed sample size for a consequential comparison. Predeclare a practical regression margin and maximum budget; do not keep sampling until a favorable result appears.
3. Randomize/interleave baseline and candidate order within blocks of case, environment and time window. Use identical fault schedules and clean resets. Shared seeds do not guarantee deterministic model output. Record provider incidents, node pressure and runtime version drift.
4. Use the same task-family weighting across arms. A family with many paraphrases should not dominate. Separate fault-free, faulted and capability strata. Do not pool distinct model/environment conditions unless that mixture is the stated estimand.

### Metrics and uncertainty

- **First-invocation end-to-end success:** accepted initial invocations divided by all scheduled trials in a fully executed plan. Show planned, started, completed and unavailable counts. Cancellation makes the cohort incomplete; report bounds or completed-subset description, not a final comparable rate.
- **Conditional quality:** accepted divided by trustworthy evaluable trials, alongside infrastructure rate and missingness. Never use this alone to hide operational failure. Legacy score averages still count infrastructure errors as zero; label this compatibility metric separately.
- **Reliability:** show the fraction of cases succeeding in all `k` fresh trials and success in at least one. For exchangeable independent trials with `n` observations and `c` successes per task, estimators are `C(c,k)/C(n,k)` for all-success and `1 - C(n-c,k)/C(n,k)` for at-least-one, only when `n >= k`. Do not apply them to critique-linked attempts or declare repeated shared-environment trials independent.
- **Uncertainty:** retain Wilson intervals for descriptive binary proportions where appropriate. For comparative conclusions, use a paired bootstrap over task families, carrying both arms and all within-family repeats together. Store resampling seed and method. Few families or correlated infrastructure can make intervals unreliable; state that limitation. Report effect size and interval, not only a p-value. Multiple exploratory slices are labeled exploratory.
- **Efficiency:** wall time, tool/model calls, tokens and cost including failed attempts and judges when measured; show coverage for every field. Missing values remain null. Latency of cancelled work is censored, not zero. Report success and cost together instead of optimizing cost among successful runs only.
- **Reviewer-specific:** blocker recall, clean-diff false positives, finding precision/recall, severity and changed-line validity, plus repeat stability. The specialized historical gate remains available under its own policy version.

Example proposed gate: complete frozen cohort; all required evidence available; no critical safety regression; candidate minus baseline primary success lower confidence bound above a predeclared negative margin; declared latency/cost guardrails satisfied with sufficient measurement coverage. The result is **inconclusive** if the sample is too small or evidence is missing. Do not silently relax the margin, switch metrics or substitute an assisted attempt. Chris must choose the practical margin for the actual workflow when defining that release policy.

### Grader calibration and task health

Build a small adjudicated calibration set covering pass, fail, borderline, invalid evidence, prompt injection and plausible alternate solutions. Chris labels it independently before seeing model-judge scores; add a second human for the team phase and record disagreements rather than calling one opinion universal ground truth. Keep calibration development and validation examples separate.

Measure per-category confusion, especially false acceptance of unsafe behavior, agreement and abstention rates. Fix rubric/threshold on the development portion, validate once, and version the result. A judge/model change invalidates its old calibration record. Model judging cannot override a failed deterministic/state safety condition. Reference solutions must pass; seeded flawed solutions must fail. Negative controls include grader-output forgery, modified tests, environment reset failure and incomplete traces. Test grader prompt injection as untrusted content.

Production ingestion is opt-in: capture final boundary evidence, minimize sensitive fields, quarantine, deduplicate by task family, reproduce in a sandbox, review expected outcome, then approve a new development/regression revision. Suggested fixes and graders are untrusted proposals. Keep holdout access separate and rotate exposed holdout cases into development with an exposure record, replacing them deliberately.

## First implementation task

**Title:** Add an opt-in resumable journal for black-box experiment trials.

**Scope:** one local worker, existing trusted CLI target, deterministic graders and a new experiment envelope. No UI, PostgreSQL, Kubernetes change, paid model, watcher modification or legacy-report migration is required in this task.

Proposed files:

- `src/agent_eval/experiments/models.py`: immutable plan, identity, trial and attempt records.
- `src/agent_eval/experiments/journal.py`: private SQLite schema/migration, conditional state changes, observation manifest references.
- `src/agent_eval/experiments/service.py`: admission, status and resume decisions.
- `src/agent_eval/experiments/executor.py`: invokes existing transport/scoring with per-trial persistence.
- `src/agent_eval/experiments/cli.py`: proposed `agent-eval experiment run|status|resume`, registered in existing `cli.py`.
- `tests/test_experiment_recovery.py`: subprocess crash fixtures and semantic compatibility assertions.

Prefer extracting a pure single-result scoring helper from `blackbox/runner.py` if needed, with existing tests guarding output. Do not call the whole in-memory suite repeatedly and pretend its regenerated IDs are durable trial identity. Persist the full planned matrix before dispatch and write observation artifacts before grading; recovery then knows whether invocation, collection or grading remains uncertain.

**Concrete acceptance:** a three-case offline fixture is interrupted after case one. After restart, case one has exactly one invocation and unchanged evidence; cases two/three finish. Interruption after target dispatch without a receipt is recorded as ambiguous, not automatically retried. A corrupt observation cannot produce a pass. Old FAQ and inspection CLI fixtures still produce the same scores and exit codes. Files remain private and symlink paths are rejected. `ruff`, focused recovery/black-box tests and the existing test suite pass with environment skips documented.

**Review checkpoint:** Chris explains the crash windows on paper, manually kills the fixture at two boundaries, and reconstructs the report from the journal without relying on an assistant. Save the demonstration as a short runbook. This is the first meaningful engineering artifact of the upgrade.

## Verification of this planning task

Executed against `9b68ab520427e93a104a8d36966401a499f2fd92` with CPython 3.12.11: `uv run --frozen pytest -q` finished **923 passed, 7 skipped in 122.16 seconds**; `uv run --frozen ruff check .` passed. The skip reasons were not printed by this invocation, so the seven unavailable checks are not counted as verified. The fixture CLI passed 2/2 after selecting a non-symlink private state path. No dependency update, live model evaluation, live coding job or deployment was performed.

Document verification checks local links, required coverage, formatting/privacy boundaries and final git status. This planning evidence does not claim the proposed implementation exists.
