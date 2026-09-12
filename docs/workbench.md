# Experiment workbench

The workbench adds a local application, independent state evaluation, comparisons, and project controls around the durable experiment journal. The distributed commands provide a PostgreSQL queue, fenced workers, and experimental Kubernetes Jobs. Legacy evaluation commands and their output scores retain their existing meanings.

## Start with the offline demo

From the source checkout:

```sh
uv sync --frozen
uv run --frozen agent-eval workbench demo
uv run --frozen agent-eval workbench serve
```

Open the printed loopback URL. Its fragment contains a one-hour local session token; the page removes the fragment after loading. The token stays in the browser's session storage. The API requires authentication for every data request. Shutdown revokes the session token. Use a new server session after expiry.

The demo runs two synthetic support agents with three trials per case. The baseline answers all nine correctly. The candidate answers six correctly and fails each `returns` trial. In **Comparison**, choose the good baseline and regression candidate, then open a rejected trial and add an investigation note. Notes are stored in the private catalog, survive service restarts, and appear in **Review queue**. This is a workflow control, not a model benchmark or a statistically decisive release experiment.

The UI is packaged in the wheel and needs no Node server or frontend build. It works without Phoenix. A registered HTTP(S) trace link can open an existing trace explorer; the workbench does not copy its span editor or make telemetry availability a scoring requirement.

Use `AGENT_EVAL_STATE_DIR` for a separate test directory. On macOS use a real absolute path, such as a directory under `/private/tmp`, rather than the `/tmp` symlink. For an installed wheel, omit `uv run --frozen` from the commands.

## Private registrations and launch preview

Only an operator CLI can register commands, local file paths, or endpoint configurations. Browser clients select registered IDs. They cannot submit arbitrary shell commands or filesystem paths.

`workbench register-dataset dataset.json` takes a versioned `Dataset` envelope containing an existing strict black-box `Suite`, a split, origin, license, reviewer, and a complete mapping of case IDs to task-family IDs. Revisions are content addressed. The catalog transaction prevents the same task family from being registered in different splits. Public examples are exposed development/regression material. Local launch rejects `held_out`; hidden data needs the existing protected evaluator boundary.

`workbench register-target profile.json` takes a `TargetProfile`. A minimal offline example is:

```json
{
  "name": "Scripted support control",
  "command": {
    "argv": ["/absolute/venv/bin/python", "-m", "agent_eval.workbench.adapter", "good"],
    "response_format": "json"
  },
  "identity_files": ["/absolute/installed/agent_eval/workbench/adapter.py"],
  "model_calls": "none",
  "max_invocations": 100,
  "conditions": {"environment": "local-fixture-v1"}
}
```

`identity_files` freezes selected dependencies in addition to the executable and absolute file arguments. Virtual-environment entry points keep their original executable path while the resolved target and content are separately checked. This is selected-file identity, not a container or full dependency closure. Local CLI execution is cooperative and is unsuitable for hostile code with the same operating-system account.

The browser preview displays the invocation count, suite split, identity certainty, isolation, deterministic judging, possible model use, and spend coverage. `max_invocations` is enforced. A dollar cap is not provider enforced; missing usage stays null. A profile that may call models requires explicit launch acknowledgement. No live model calls are needed for the included demo or tests.

A `Launch` JSON contains `target`, `dataset`, `trials`, and `budget_acknowledged`. `workbench launch launch.json --key RUN_KEY --start` exposes the same workflow in
the CLI. For an explicit recovery or assisted correction, set `attempt_kind` to
`infra_recovery` or `assisted_correction` and provide `parent_experiment`. These
create new records and do not overwrite the parent. Comparisons cannot pool them
with initial invocations, and the initial-invocation release policy cannot accept
them as substitute trials.

The API creates a plan separately from starting it. Repeating an idempotency key with the same body returns the same experiment; changing its body conflicts.

### Flue and order-status integrations

`workbench register-flue /absolute/flue-checkout` registers the built `dist/cli.js` raw-diff entry point, built JavaScript, package files, and source revision. It does not invoke the watcher, inspect a PR, publish a review, or run a model. Explicit `--pass-env NAME` arguments allow required existing environment variables into the target. Add complete fixed `model`, `environment`, and `retry_policy` conditions to a private profile for a consequential comparison. Unknown inner retries and usage remain unknown. Preserve specialized finding metrics using the existing reviewer evaluator or imported original reports.

`workbench register-http endpoint.json --name 'Order status'` registers a private HTTP profile:

```json
{"endpoint":"http://127.0.0.1:8000/v1/query","timeout":30}
```

An optional `token_env` names an existing bearer-token environment variable. Values are read at execution and not copied into the profile. Each invocation creates a new process and HTTP connection. The order lab's public input is `{"message":"...","customer_id":"..."}`. Configure the external lab's scripted planner and disposable ERP before an offline integration run. Endpoint registration does not prove a live deployment's identity or reset behavior. The external agent continues to own its runtime and MCP integration.

`workbench adopt EXPERIMENT_ID` makes an existing local journal visible without rerunning it. An experiment has one project owner. `workbench import-report report.json --source legacy` validates and retains a black-box report. `inspect` and `harbor` are bounded, opaque import spikes: they preserve original schemas and metrics as references and cannot qualify as independent gate evidence.

## Independent state and controlled faults

Profiles can set `world` to `ticket` or `order`. The independent harness hosts a fresh disposable tool service per experiment and resets it before each trial. A rotated random bearer capability exposes only customer-scoped reads and allowed writes. Target input receives an `environment` handle; it never receives the private expected state, full snapshot, or grader configuration.

The ticket fixture permits status changes and protects owner fields and other rows. `ticket-good`, `ticket-lie`, and `ticket-wrong` are scripted adapter modes. All can report success, but the independent observer rejects the latter two. The order fixture is read-only and checks unchanged storage. These are synthetic controls. They do not claim to be the production order agent.

Faults bind an operation, logical ordinal, and kind: `timeout_before`, `rate_limit`, `malformed`, `stale_read`, or `timeout_after_write`. Seeded schedules are reproducible. Each snapshot records requested and observed injections. Missing injection makes evidence invalid. A timeout after a write can retain the mutation; it is not evidence that retrying a non-idempotent operation is safe. Reset or observer failure stops execution. JSON-subset output requirements can separately require safe unavailable-data responses.

State evidence is sealed before the boundary observation and bound to the plan, attempt, output, and snapshot digests. Comparison uses independently accepted outcomes while retaining original output-only counts. A state failure cannot be turned into acceptance by an annotation or a passing text score.

## Comparisons and policies

`workbench paired-run baseline-launch.json candidate-launch.json --key study-1 --seed 42` freezes a fixed schedule and randomizes arm order within each case/replicate block. Resume preserves that schedule and completed evidence. The normal UI also compares existing runs; those runs are not retrospectively described as randomized.

`workbench compare BASELINE CANDIDATE` returns planned/completed/evaluable denominators, missing pairs, first-invocation success, conditional quality, paired case outcomes, and a task-family bootstrap effect and interval. Infrastructure failures remain in the primary denominator. Cancellation or missing pairs prevents a complete-cohort rate. Suite/grader drift and changes to fixed conditions make a cohort incompatible. Live profiles without complete model/environment/retry identity remain inconclusive.

Every family has equal weight; within-family repetitions travel together in the bootstrap. The method, seed, and sample count are recorded. Wilson intervals are descriptive. Few families, shared infrastructure, exposed tasks, and correlated model runs limit interpretation. Inner retries do not become independent trials. Reliability helpers implement all-`k` and at-least-one-`k` estimators only for valid counts; independence remains an experimental assumption.

Register an explicit policy with `workbench policy policy.json`:

```json
{
  "regression_margin": 0.02,
  "minimum_families": 10,
  "bootstrap_samples": 2000,
  "seed": 42,
  "required_inspection": false,
  "require_state": false
}
```

The margin is illustrative, not an approved production threshold. `workbench gate BASELINE CANDIDATE POLICY_ID CANDIDATE_ARTIFACT_SHA` stores an immutable pass/fail/inconclusive decision. Use the exact `candidate.target` artifact digest from the comparison. Substitution fails. Missing evidence and insufficient families are inconclusive. Optional latency limits require complete coverage. The command exits 0 for pass, 2 for fail, and 3 for inconclusive. Deployment authority remains external.

`workbench attach-inspection EXPERIMENT inspection-report.json` checks a legacy derivative against the exact original results and identities. A required failed inspection makes `overall_passed` false while `passed` and the original output scores remain unchanged.

`workbench regrade EXPERIMENT new-suite.json` reuses completed observations and appends an assessment set. It cannot change public inputs or overwrite old results. Current comparison/gate commands use the original canonical assessment set; regraded sets are explicit separate records, not silently substituted outcomes.

`workbench calibrate labels.json GRADER_SHA` checks a supplied development/validation calibration corpus, category confusion, agreement, and false acceptance. Validation requires positive and negative controls. A changed grader has a different calibration identity. The tool cannot supply human adjudication: independently reviewed labels and a real held-out validation exercise remain operator responsibilities.

## Distributed execution

Install the database extra, then configure a private `AGENT_EVAL_DATABASE_URL`:

```sh
uv sync --frozen --extra database
uv run --frozen --extra database agent-eval distributed migrate
uv run --frozen --extra database agent-eval distributed account local 1000000
uv run --frozen --extra database agent-eval distributed submit-experiment EXPERIMENT_ID 100000 --project local
uv run --frozen --extra database agent-eval distributed worker local worker-1
uv run --frozen --extra database agent-eval distributed collect-experiment EXPERIMENT_ID --project local
```

The numbers are reservation/accounting microdollars, not a provider-enforced spend guarantee. Run the worker again for each remaining claim, or supervise the command. The worker and controller require registered executable paths/dependencies. Selected file digests are checked on the execution host. Only public input is sent to the queue worker; the controller retains expected outcomes and performs grading. Independent local worlds are not submitted to this command worker.

A claim reserves capacity and increments its epoch transactionally. Dispatch, completion, settlement, and outbox records use conditional fenced transactions. Expired undispatched claims can return to the queue. Expired dispatched work becomes reconciliation-required and keeps its reservation. A stale worker cannot finalize or spend a newly released reservation. Missing usage conservatively consumes the reservation and remains unmeasured. Late conflicting completions fail; duplicate identical completion settles once.

`distributed reconcile TENANT` reconciles leases. `distributed cancel-experiment EXPERIMENT` coordinates queue cancellation with the local journal. HTTP acceptance, process termination, and remote side-effect completion are different facts. Dispatched cancellation does not release uncertain spend. The outbox reader can replay undelivered events until the consumer acknowledges them; telemetry outage cannot rewrite a decision.

The PostgreSQL repository includes forced row-level security and `Queue.provision_worker(tenant, password)` for separate tenant database logins. Queue administration uses a trusted migration/account role. Workers are trusted harness infrastructure, not target code. Do not give database credentials to an agent. The target command environment excludes those credentials unless an operator explicitly passes them, which is outside the intended protected-worker setup.

### Experimental k3s Jobs

`deploy/k3s/experiments.yaml` creates a separate restricted namespace with quota and default-deny policy. It is opt-in and does not modify existing deployments or schedules. `distributed job` emits an immutable-image Job with explicit resources/deadline, no retries, no service-account token, a read-only root filesystem, dropped capabilities, seccomp, and bounded scratch space. `distributed job-run manifest.json --context CONTEXT` executes a validated manifest and collects pod/image/termination evidence. For queue-managed Jobs, enqueue `{"schema_version":"agent-eval.remote-job/v1","job":GENERATED_MANIFEST}` under the manifest's execution ID, then use `distributed worker TENANT WORKER --kube-context CONTEXT`. The controller regenerates only the Job's lease epoch, persists dispatch before creation, heartbeats while watching it, and fences completion in PostgreSQL. The queue accepts the guarded profile only. Confirmed quota admission rejections return to the queue without spending the reservation. Completed Jobs are deleted with a UID precondition only after the receipt commits; failed cleanup emits an outbox event, and TTL cleanup remains a fallback. These receipts are execution evidence; they do not assert output correctness or replace the protected coding grader.

Job names and UIDs provide reconciliation identity. Cancellation uses a UID deletion precondition; acceptance of deletion is distinct from confirmed absence.

**Observed on September 11, 2026, k3s v1.35.5+k3s1, arm64:** an immediately running pod reached a numeric external HTTP endpoint despite a pre-existing deny policy. A repeated probe from the same pod subsequently became blocked. This is evidence of asynchronous policy installation, not proof that the YAML was ineffective forever. K3s documents its policy controller, and kube-router describes its asynchronous watch/rule updates: [K3s networking](https://docs.k3s.io/networking/networking-services), [kube-router operation](https://www.kube-router.io/docs/how-it-works/).

The default Job now uses a trusted init container that waits for three denied probes before the target starts. In the controlled rerun the target's first probe was denied; the separate permitted control reached the endpoint. The probe mode is only for explicit diagnostics. This guard addresses the observed startup window. A failed probe can also mean an unavailable destination, so qualification requires the positive control and repeated tests on every supported node/profile. A single TCP destination is not a comprehensive egress or sandbox-escape proof. A hostile hosted pilot still requires that broader review.

## Team controls, ingestion, and retention

The API remains loopback-only. `workbench serve --oidc` uses a configured provider's HTTPS token-introspection endpoint on every API request. Configure `AGENT_EVAL_OIDC_ENDPOINT`, `ISSUER`, `AUDIENCE`, `CLIENT_ID`, and `CLIENT_SECRET` with the common `AGENT_EVAL_OIDC_` prefix. The provider must return active status, issuer, audience, subject, and expiry. No redirects or token-result caching are allowed. Token acquisition/sign-in uses the operator's OIDC client; no browser authorization-code flow is included.

`workbench grant PROJECT SUBJECT ROLE` assigns viewer, runner, curator, or admin rights. For OIDC, a subject is `ISSUER#SUB`. Local tokens and membership checks run on every API request. `workbench revoke SUBJECT` revokes local tokens; revoke OIDC tokens at the identity provider and remove/change membership separately. Same-project viewers can read private evidence; this is not a public sharing service. Binding to a public interface or adding a proxy does not make it a qualified hosted service.

`workbench producer-artifact artifact.json` registers approved bounded JSON evidence; `workbench issue-execution contract.json` issues expected identities. Producer submissions use `agent-eval.submission/v1`, pre-issued execution identities, approved project artifact keys, immutable candidate/recipe digests, and replay checks. They are retained as `awaiting_independent_evaluation`; producer success and self-tests never become acceptance. Use the existing protected coding evaluator for executable submissions. The generic ingestion contract does not reconstruct arbitrary repositories or publish changes.

`workbench quarantine case.json` minimizes text and credentials before storing a candidate. Redaction is deliberately limited and requires human review. `workbench approve-case ID reviewed-suite.json --reviewer NAME --license LICENSE` publishes a reviewed regression revision with a stable family. Quarantine content never automatically enters a suite. Held-out exposure and semantic near-duplicates require explicit review.

`workbench audit` verifies the private catalog's hash chain. This detects ordinary corruption; it is not an external signature against a malicious account owner. `workbench backup /absolute/new-backup.zip` locks idle journals and writes a bounded archive with file digests. `workbench restore backup.zip /absolute/new-directory` rejects traversal, duplicates, oversized files and digest changes, and never overwrites an existing directory. Back up PostgreSQL separately with supported database tools; restore it alongside the matching local evidence archive and verify both before restarting workers.

`workbench retention EXPERIMENT --reason '...'` previews deletion. `--execute` deletes that specific idle experiment's journal, annotations, linked inspection/regrade content, and matching imported derivatives, and records a tombstone. Original files imported from outside state are not owned by this retention operation. Unconfirmed work blocks deletion. Existing backups keep their copies until separately expired; restoring an older backup can restore deleted data. No legal-hold, object-replica deletion, or regulatory compliance claim is implied.

## Verification and operating limits

The test suite includes local process crash windows, cancellation, corrupt receipts, installed command transports, persistent notes, HTML escaping, origin rejection, tenant denial, state controls, paired scheduling, calibration negative controls, producer replay, backup/restore, real PostgreSQL races, budget settlement, row-level security, and distributed-to-local receipt collection. PostgreSQL integration tests require the optional driver and local server binaries; they use an isolated temporary database.

Browser verification uses the packaged UI against the synthetic demo. The first live network probe failed and led to the startup guard described above. Job cancellation was requested with a UID precondition, then Job/pod absence was checked separately. The four pre-existing deployments remained ready, and the temporary experimental namespace was removed after verification.

Live model benchmarks, independent human calibration, OIDC interoperability with a real configured provider, a production release, comprehensive hostile sandbox qualification, and enterprise backup/retention guarantees are not established by these fixtures. The implementation supplies the local workflows and opt-in execution/governance components; those operational qualifications need their own evidence.


## Release verification

Released evaluator revision `048a8d4` passed the corrected Python 3.12–3.14 matrix (1,012 passed, four skipped per version), installed-wheel/API/restart checks, and a live PostgreSQL-to-k3s execution with durable receipt persistence and owned-pod cleanup. See [the dated verification record](../benchmarks/platform/results/2026-09-12.md). This supersedes the earlier database-to-Job controlled-executor limitation for the smoke path; broader sandbox and provider qualification remains separate.
