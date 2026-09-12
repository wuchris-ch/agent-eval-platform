# Implementation status

September 11, 2026. This describes implemented scope, not a declaration that every operational acceptance exercise or team pilot is complete.

| Area | Implemented | Evidence and remaining qualification |
|---|---|---|
| Compatibility and journal | Existing commands/scores retained; frozen plans; immutable receipts; writer lock; recovery; cancellation; schema-1 backup and forward migration; reconstructible reports | Subprocess crash tests cover claim, dispatch, observation sealing, and completion. Unknown calls are not retried. Old evaluator identities remain required to continue their ungraded plans. |
| Workbench | Packaged HTML/CSS/JS UI; authenticated loopback API; list/launch preview; comparisons; trial/state evidence; notes and review queue; CLI and HTTP profiles; Flue registration | Browser inspected the seeded regression and saved a note. API tests cover persistence, origin/Host checks, malicious HTML as text, pagination and authorization. No frontend build service is needed. |
| Environments | Independent ticket/read-only order worlds; customer isolation; immutable-field predicates; seeded logical faults; requested/observed receipts | Good, lying and wrong-row agents distinguish state acceptance from output success. External Flue/order live baselines and deployment-specific ERP reset guarantees remain unmeasured. |
| Analysis and gates | Family-weighted paired bootstrap; fixed randomized paired launch schedule; complete/missing denominators; separate linked recovery/assisted experiments; policy/artifact-bound decisions; immutable regrading; calibration controls | Synthetic regressions and unavailable cohorts are tested. Human adjudication, practical production margins and adequate sample sizes are not supplied by fixture tests. Regraded sets remain separate from default gates. |
| Integrations | Private CLI/HTTP profiles; legacy report and Inspect/Harbor reference imports; companion submission schema, approved artifacts, identity/replay checks | Inspect/Harbor imports preserve opaque native data and are not gate eligible. Producer completion is never acceptance. Arbitrary repository reconstruction and publication are not part of ingestion. |
| Distributed work | PostgreSQL claims/epochs; reservations/settlement; outbox; reconciliation; tenant RLS/logins; boundary worker; local journal submission/collection; restricted Kubernetes Job generator/executor | Real PostgreSQL tests cover races, fences, quotas, unknown usage, tenant denial and receipt collection. Live k3s tests exposed and addressed a policy-installation startup window. Broader hostile sandbox and egress qualification remains necessary. |
| Team and operations | Roles; per-request local token checks; OIDC-provider introspection; project/object authorization; audit chain; quarantine/review; split/family guards; backup/restore; retention preview and deletion | OIDC claims are tested with controlled responses, not an actual provider deployment. Local restore and deletion are tested on disposable evidence. Enterprise object storage, legal hold, replica deletion and compliance guarantees are not claimed. |

## Design changes made during implementation

The UI uses packaged browser-native JavaScript rather than adding a React build/runtime dependency for four small views. SQLite continues to own local evidence and the catalog. PostgreSQL owns distributed claims/budgets; a bridge collects boundary observations into the independent local grader. These are explicit deployment modes, not an automatic migration of existing nightly work.

Kubernetes policy existence was insufficient in a real cold-start test. An immediate request escaped, while later requests from the same pod were blocked. A trusted init container now waits for repeated denial before starting the target. A permitted control connected and the guarded target's first request was denied. The existing four deployments remained ready. All temporary test Jobs, pods, policies and namespace were removed afterward.

The platform keeps original output scores, independent state outcomes, required inspection outcomes, and annotations separate. It does not reinterpret old reviewer success as evidence for current Flue. Model spend is never inferred from placeholder zero values.

## Release verification

The implementation and follow-up evidence-read fixes were merged in [PR #9](https://github.com/wuchris-ch/agent-eval-platform/pull/9) and [PR #10](https://github.com/wuchris-ch/agent-eval-platform/pull/10). Released evaluator revision `048a8d498085e3d371ecf6008b9c2018b0f27112` passed the corrected Python 3.12–3.14 CI matrix: 1,012 tests passed and four skipped on each version. The matrix now asserts the actual interpreter, overriding the development pin.

A live PostgreSQL worker drove the real Kubernetes executor through Job completion, durable receipt commit, and owned-pod cleanup. The disposable database and namespace were removed. The earlier controlled-executor limitation is superseded for this smoke path. See [the release verification record](../../benchmarks/platform/results/2026-09-12.md) for evidence, package/restart checks, skip explanations, and remaining qualifications.

## Initial implementation verification record

See [workbench operation and limits](../workbench.md) and [journal recovery](../experiments.md). Tests use synthetic or local fixture targets; no model or judge calls are needed. Verification on CPython 3.12.11:

- Full repository suite: **992 passed, 7 skipped in 333.43 seconds**.
- Follow-up workbench/database suite after the final gate fixes: **41 passed in 191.97 seconds**.
- Latest PostgreSQL/controller checks, including schema rejection, backup/restore, and queue-managed Job fencing, admission deferral, and owned cleanup: **12 passed in 6.34 seconds**.
- Additional private HTTP registration/execution check: **1 passed in 6.78 seconds**.
- Ruff and whitespace checks passed; the source distribution and wheel built successfully. An isolated installed-wheel demo/API/restart smoke passed. Packaged UI assets and distributed modules were checked in the wheel.

The seven full-suite skips were four OpenTelemetry SDK checks, two optional DeepEval checks, and the exact Trivy executable/prepared test database fixture. They are not counted as verified. Local PostgreSQL **14.23** was started in a disposable database for integration tests. Live k3s verification used **v1.35.5+k3s1 on arm64**. The standalone Job executor was exercised live; queue-to-Job orchestration was additionally checked with the real database and a controlled executor fixture.

The subsequent [live Flue benchmark](../../benchmarks/reviewer-corpus/v1/results/2026-09-12-flue.md) completed all 60 first attempts with 56 accepted and no infrastructure errors. It failed the strict reviewer gate because exact security-line recall and stability fell short. An independently labeled held-out corpus, real-provider OIDC interoperability, and a hostile hosted pilot remain unqualified.
