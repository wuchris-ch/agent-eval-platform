# Agent Reliability & Evaluation Platform

Planning snapshot: **September 11, 2026**. See the implementation update below for current scope.

Implementation update: the local workbench, state/fault controls, comparison and
governance services, and opt-in distributed components are implemented. See the
[workbench guide](../workbench.md) and [evidence/status matrix](status.md). The plan
below is the design snapshot; operational qualification is tracked separately.

Build an experiment workbench around this repository's independent evaluators. Chris should be able to select an agent revision, run a frozen suite, compare it with a baseline, inspect failures, and decide whether a change is safe to use. Preserve CLI/HTTP/replay compatibility, protected grading, private artifacts, and the existing k3s runner. Do not rebuild an agent runtime or a general tracing product.

## Read this plan

1. [Current state and evidence](current-state.md): inspected revision, actual capabilities, test observations, related projects, and gaps.
2. [Research and decisions](research.md): dated primary sources, reuse choices, and limits of the evidence.
3. [Architecture and contracts](architecture.md): trust boundaries, lifecycle, storage, adapters, UI, and deployment modes.
4. [Implementation and verification](implementation.md): milestones, acceptance tests, benchmark design, learning exercises, and the first task.

These documents extend [the July architecture decision](../enterprise-direction-2026-07-14.md). Its independent evidence and telemetry boundaries remain. The proposed scope now explicitly covers multiple agent types and adds a narrow experiment UI. Existing guides remain the source of truth for commands that work today.

## Recommended design

- **Local first:** Python service and one worker, private SQLite journal and artifact files, a small packaged UI served on loopback. No cluster required for trusted CLI/HTTP/replay experiments.
- **Evidence first:** freeze experiment identity before execution; persist each attempt; distinguish execution status, quality, infrastructure, and evidence completeness. Preserve legacy report semantics through explicit exports.
- **Two real integrations:** the current Flue diff reviewer and the order-status MCP agent from `agent-reliability-lab`. Add an isolated state-changing fixture inspired by `agent-gauntlet` to prove that claimed actions match actual state.
- **Reuse:** retain DeepEval as an optional grader and Phoenix/OTel for trace investigation. Add bounded Inspect/Harbor interoperability after a compatibility spike. Keep the protected evaluator authoritative.
- **Distributed next:** k3s Jobs managed by leases and reconciliation; PostgreSQL when multiple workers need transactional claims and shared budgets. Team access and hardened hosted execution are later, testable milestones.

The companion Multi-Agent Software Engineering Platform performs work and submits an immutable candidate. This platform independently evaluates it. A Flue finding is one assessment, not authority to accept its own output or the coding platform's work. The integration can be built against a contract fixture before that platform exists.

## Chris's intended experience

Today, use the [black-box guide](../blackbox-evaluation.md) and [inspection guide](../agent-inspection.md). The credential-free FAQ fixture was exercised during this planning task. Real model judging remains opt-in.

After milestones 1 and 2, install with `uv sync --frozen --extra platform` and start `uv run agent-eval platform serve`. **Both the extra and command are proposed.** The wheel should contain the built UI, so daily use requires no Node toolchain. UI development uses a pinned Node toolchain and `npm ci` in the proposed `ui/` directory. Docker is needed only for container tasks or the optional Phoenix stack; k3d is needed only for k3s execution.

First launch opens an empty experiment list with an offline demo. Register a local executable or HTTP endpoint using a private target profile; select a frozen suite and agent identity; preview case count, trial count, isolation level, and resource budget; run. See progress after each trial, inspect output versus expected evidence, annotate a failure, and compare a candidate with its baseline. Unknown model version, missing usage, partial traces, and incomplete cohorts are visible states. A friendly agent name alone is never a reproducibility claim.

Daily use is: change an agent, run the small regression suite, investigate changed cases, and keep or revert the change using evidence. Run larger capability and fault suites deliberately under a budget. Production failures may become reviewed development cases; they never silently enter the held-out test set. Existing GitHub review publication stays with the Flue watcher.

## Start here

The [first implementation task](implementation.md#first-implementation-task) is an opt-in, resumable black-box experiment journal. It solves an observed source-level gap and supplies the UI's durable foundation without changing existing commands. The first useful release stops after milestone 2; later phases add stateful evaluation, statistical rigor, distributed operations, and team controls.

No commits, pushes, deployments, paid evaluations, or changes to sibling projects were made for this plan. Proposed acceptance thresholds are engineering targets, not measured achievements.
