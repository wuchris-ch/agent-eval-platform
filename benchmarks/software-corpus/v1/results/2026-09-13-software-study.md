# Live software study: single coder and selective coordination

Recorded September 12, 2026 in Vancouver, September 13 UTC. Four authored
development task families, three trials per policy, with all 24 initial
executions reserved before dispatch. The actual producer used the live model
gateway and submitted exact candidate bytes to an independent evaluator.

## Results

| Initial outcome or measurement | Single coder | Selective coordination |
| --- | ---: | ---: |
| Accepted / planned | **9 / 12 (75.0%)** | **4 / 12 (33.3%)** |
| Rejected by behavior checks | 0 | 0 |
| Inconclusive with a candidate | 3 | 5 |
| Production failed without a candidate | 0 | 3 |
| Pending | 0 | 0 |
| Median recorded production time | 21.52 s | 35.28 s |
| Production-time coverage | 12 / 12 | 12 / 12 |
| Independently labeled time coverage | 12 / 12 | 9 / 12 |
| Producer-reported model requests | 60 | 79 |
| Producer-reported tokens | 145,769 | 174,102 |

Acceptance requires both successful producer completion and every independent
behavior/state check. All 21 returned initial candidates met their behavior
checks. Eight could not establish complete workflow success and remained
inconclusive. The three remaining invocations failed before producing a candidate.

| Task | Single coder | Selective coordination |
| --- | --- | --- |
| Document authorization | 3 accepted | 3 production failures during planner validation |
| Order idempotency | 3 accepted | 1 accepted, 2 inconclusive with producer state `needs_attention` |
| Payment form | 3 inconclusive | 3 inconclusive |
| Schema compatibility | 3 accepted | 3 accepted |

The payment task exposed a runtime prerequisite mismatch. The producer wrapper
starts Python before invoking the public Node check, while the study's pinned
Playwright image lacked the `python` executable. Verification stopped before
the public check could run. The independent Node observer still evaluated the
sealed candidates and their final SQLite state. Those successful observations
did not override incomplete producer execution.

The single-coder policy had more accepted complete workflows in this recorded
cohort. Eight of twelve task/trial pairs lack complete pass-or-fail outcomes,
so the paired confidence interval is withheld. The stored conditional effect
is zero among the remaining evaluable pairs; it does not describe the full
planned population. Promotion remains **inconclusive**. Broader inference
requires additional task families and a complete paired comparison.

## Assisted attempts and accounting

The frozen schedule selected its first two unsuccessful assessments for one
assisted child each, after all 24 initial executions finished. Both selected
payment-form candidates again passed independent checks, but retained the
runtime prerequisite failure: **0 / 2 accepted, 2 inconclusive**. Initial
outcomes were unchanged.

Producer ledger coverage is 24/24 initial and 2/2 assisted executions. Initial
production used 139 reported requests and 319,871 reported tokens; assistance
used 14 requests and 51,406 tokens. All 26 ledgers reported zero unresolved calls.
Token counts have producer-reported provenance. Monetary cost is unavailable.
Three initial production-failure time values also retain producer-reported
provenance in the frozen contract; policy previews requiring independent
measurements treat them accordingly. Unknown measurements are never zero-filled.

## Frozen conditions

| Identity or condition | Value |
| --- | --- |
| Cohort | `918e1154-7c6d-413c-8f82-0ed7571849da` |
| Producer revision | `a8f4f3e6d1a77992602b343589265baac884cf99` |
| Evaluator revision | `1e59f37fb402e0b82b4b92a2d748b88e5be7d4b4` |
| Evaluator content identity | `541c485b7f74ea6d31429587a8ca24b9fa2d2c7a2ea8e2d7b3e4719febd6dab3` |
| Plan hash | `facd741be5aae5367386e6a8cc956773eac847705737ffddec7cd355aaed13d9` |
| Randomization seed | `20260912` |
| Per-invocation budget | 20 model requests, 200,000 tokens, 600 seconds |
| Internal producer repairs | 0 |
| Initial aggregate allowance | 480 requests, 4,800,000 tokens |
| Assisted allowance | 2 executions, 40 requests, 400,000 tokens |
| Decision-bundle hash | `005f5f3738f252ce49e94d691597ef17eb1497efe90a749ffed5c528c70a39f6` |

Within each task pair, model configuration, capabilities and aggregate budgets
matched. The single policy uses one coder. Selective coordination can add a
bounded planner, read-only specialists and reviewer within the same total
allowance. Pair and arm order were randomized before dispatch. No failed
invocation was replaced. Two separately sealed authored families remain unused.

The evaluator reconstructed each submitted patch against its own Git base,
checked candidate-tree identity, ran isolated response checks, and queried final
SQLite state outside the candidate process. Reference checks were never mounted
in producer or candidate containers. The producer retrieved each assessment
through the authenticated HTTP contract and verified its exact bindings.

## Verification and follow-up

The [portable bundle](../../../../docs/evidence/software-study.json.gz) contains all
26 records, the complete plan and schedule, and bound tickets, contracts,
submissions, assessments and production failures. Verification recomputes
record hashes, validates identity bindings, and reproduces saved decisions
without model calls:

```sh
gzip -dc docs/evidence/software-study.json.gz > /tmp/software-study.json
uv run agent-eval candidate verify /tmp/software-study.json
uv run agent-eval candidate policy-preview /tmp/software-study.json \
  --max-latency-ms 30000
```

The release adds a public-verifier preflight before future trial admission.
An actual producer sandbox control rejected the incompatible image and accepted
a pinned Python-and-Node image with zero model calls. See the
[preflight record](verifier-preflight.json). The frozen cohort above is unchanged.

The platform regression run passed 1,048 tests with 5 skipped. Two additional
preflight tests passed, including a failing runtime that prevents every trial
from being admitted. Separate [oracle controls](oracle-qualification.json)
accepted five known-correct candidates and rejected five plausible baselines.
The [HTTP protocol controls](protocol-controls.json) verified actual producer
upload, intake, independent decisions and repeated assessment retrieval.

The [evidence explorer](https://wuchris-ch.github.io/agent-eval-platform/?collection=software-study)
shows initial and assisted outcomes, measurement provenance, production stage
counts and resource-policy previews. Decision replay checks recorded evidence;
fresh execution uses the original candidate artifacts and pinned runtime.

## Every recorded attempt

| Attempt | Task / trial | Policy | Outcome | Time | Execution |
| --- | --- | --- | --- | ---: | --- |
| initial | payment-form / 2 | Selective | inconclusive | 37.35 s | `f2bfbd8f-e36f-5e38-8b36-f7ed23999aa6` |
| initial | payment-form / 2 | Single | inconclusive | 26.22 s | `7d2de9e7-2fd2-5a56-be95-263745ebee25` |
| initial | schema-compatibility / 1 | Single | pass | 14.71 s | `eb546618-bb3a-5d52-aa65-1c090fb5c996` |
| initial | schema-compatibility / 1 | Selective | pass | 26.16 s | `707ef6ae-be19-532d-b55e-b8bd85cc0352` |
| initial | document-authorization / 3 | Single | pass | 19.56 s | `4bd6543e-498c-5db0-93b6-03beb7122d7a` |
| initial | document-authorization / 3 | Selective | production failed | 9.21 s | `f6aaf61f-ef87-553e-b49f-469254bb8893` |
| initial | order-idempotency / 3 | Selective | pass | 51.74 s | `0ad471c2-2b6a-5cf6-8c00-8f76c4902dae` |
| initial | order-idempotency / 3 | Single | pass | 30.29 s | `994f45cd-6345-5560-aa19-8a808274f22e` |
| initial | document-authorization / 2 | Selective | production failed | 9.79 s | `3a02f81c-9de7-51f7-944e-f106097140b1` |
| initial | document-authorization / 2 | Single | pass | 17.78 s | `c44611b7-3a5e-5889-9715-cf7faa3cafb2` |
| initial | order-idempotency / 2 | Single | pass | 51.97 s | `79bd7e74-db01-5886-9f2f-234c73206f10` |
| initial | order-idempotency / 2 | Selective | inconclusive | 50.49 s | `66758b6f-eff4-5682-ae9e-418de045ffdd` |
| initial | payment-form / 3 | Single | inconclusive | 27.17 s | `7cdd4672-6858-5f42-acf4-453f9dedc7ef` |
| initial | payment-form / 3 | Selective | inconclusive | 34.05 s | `2102c50e-fa95-5931-aa75-6520554e7e50` |
| initial | document-authorization / 1 | Selective | production failed | 6.83 s | `fa060eaf-af55-5370-a2d7-dbd3325aef85` |
| initial | document-authorization / 1 | Single | pass | 17.00 s | `308ccd34-9b0e-5c72-b76b-25c54f1faaf9` |
| initial | payment-form / 1 | Single | inconclusive | 23.49 s | `fce08bbd-1a22-568d-bde2-2e5848609983` |
| initial | payment-form / 1 | Selective | inconclusive | 35.01 s | `289af2bb-0a3d-55ae-9516-0122e3fa424d` |
| initial | schema-compatibility / 2 | Selective | pass | 35.54 s | `18b64374-1df7-5e46-8519-9ce485b3d662` |
| initial | schema-compatibility / 2 | Single | pass | 15.63 s | `55b312a9-7a0e-5a9b-8081-6e8fea37a321` |
| initial | schema-compatibility / 3 | Single | pass | 15.18 s | `0f15cb50-b660-5082-84a9-8136634d165a` |
| initial | schema-compatibility / 3 | Selective | pass | 40.68 s | `c4fdf4fe-55d0-5618-9df1-d85f63547016` |
| initial | order-idempotency / 1 | Single | pass | 27.41 s | `a7f82b6a-ca61-52ad-84d2-9ca38dd8b6ff` |
| initial | order-idempotency / 1 | Selective | inconclusive | 54.14 s | `5e8be7ad-e466-5591-be44-5d10f2ffaab9` |
| assisted correction | payment-form / 2 | Single | inconclusive | 25.09 s | `656d5253-e961-5f29-94fa-36f4a6dbe92d` |
| assisted correction | payment-form / 2 | Selective | inconclusive | 35.98 s | `eee1fe57-09b6-5ba1-8fca-72be6ec03f26` |
