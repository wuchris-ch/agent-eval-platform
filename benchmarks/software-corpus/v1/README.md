# Software corpus v1

Five authored task families exercise backend behavior and a fullstack browser form/API contract. The producer receives only each task's `public` directory. Independent response and final-state expectations live in `oracles` and are never mounted in the candidate container.

| Task | Family | Independent checks |
| --- | --- | --- |
| Order idempotency | Idempotent writes | Replay, payload conflict, tenant scope, final orders |
| Document authorization | Object authorization | Authentication, tenant/owner boundaries, unchanged unauthorized rows |
| Schema compatibility | Additive schema evolution | Repeated migration, original records, API compatibility, durable values |
| Cursor pagination | Stable pagination | Equal timestamps, complete traversal, final-page cursor |
| Payment form | Form/API contract parity | Decimal parsing, direct-client validation, ID sequence, durable integer cents |

Every behavioral requirement is stated in the producer-visible `TASK.md`. The qualification run accepted all five known-correct controls and rejected all five plausible unchanged baselines. It used real isolated containers and made zero model calls. [Recorded qualification](results/oracle-qualification.json) identifies each candidate tree, suite, evaluator and assessment.

```sh
uv sync --frozen --all-extras
uv run python scripts/qualify_software_corpus.py --out /tmp/software-qualification
```

Use a new output directory for each run. Docker must have the pinned images referenced by the suites. Python tasks use the pinned Python image; the payment task uses the pinned Node-capable image. The observer disables networking, mounts candidate sources read-only, separates request inputs from reference outcomes, and queries SQLite state after the candidate has stopped. Special files, malformed databases and unavailable state cannot establish acceptance.

## Study design

A study reserves its complete schedule before dispatch. Recipes may vary across tasks because allowed paths and public verification differ. Within each task pair, capabilities, model configuration, and request/token/time budgets must match. Randomization permutes pairs and arm order from a recorded seed. No failed or missing invocation is replaced.

The initial live cohort selects order idempotency, document authorization, schema compatibility and payment form, with three paired trials per task. The two policies are a single coder and selective planning with bounded read-only specialists and review. Both receive the same global limits. Internal retries are disabled so the initial execution retains its first candidate. Any later correction uses a separate ticket linked to that exact initial execution.

At most two assisted executions are selected from the first unsuccessful independent assessments in the original schedule after all initial outcomes finish. They have a separate aggregate budget. Their success is reported separately from the initial cohort.

Study preparation now runs the public verification command through the actual
producer sandbox before reserving any trial. Its wrapper requires Python even
when the public check invokes Node. Node tasks therefore default to the pinned
producer image supplied by `--image`, which must contain both runtimes.
The independent observer keeps its separately pinned suite image. The
[recorded preflight controls](results/verifier-preflight.json) rejected the
incompatible image and accepted the compatible runtime with zero model calls.
This preparation change does not alter earlier tickets or assessments.

Repeated runs of one task share inputs and are not independent task families. Reports retain the planned denominator, measurement coverage and provenance, paired family effects, and a seeded family bootstrap interval when complete. A four-family development study does not establish general production superiority. The promotion status remains inconclusive below ten paired families.

## Reserved families

[Holdout commitments](held-out-commitments.json) seal two additional families outside public source and producer workspaces. Their private inputs and expected outcomes were hashed before live dispatch. The commitment records zero agent invocations at sealing. These are reserved authored families, not a claim of performance on an external benchmark.

The producer's separate real-repository exercises are reported as such. They are distinct from this authored corpus and from the protocol controls.

## Design references

Independent final-state checks and repeated trials follow the evaluation concerns described in [Anthropic's agent evaluation guide](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents). Matched budgets and task-family comparisons test the architecture-dependent tradeoffs discussed in [Google Research's agent-systems experiments](https://research.google/blog/towards-a-science-of-scaling-agent-systems-when-and-why-agent-systems-work/). These references inform the design; the stored executions establish the observed results here.
