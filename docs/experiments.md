# Resumable local experiments

`agent-eval experiment` runs a frozen black-box suite against a local command and
saves each observation before grading it. It supports deterministic metrics and
one active worker per experiment. Existing `blackbox` commands and report schemas
retain their behavior.

This guide covers the underlying journal. The [workbench guide](workbench.md)
covers the packaged UI, private HTTP profiles, state observers, comparisons, and
shared worker queue. Model judging remains available in the existing
[black-box commands](blackbox-evaluation.md); journal experiments use deterministic
metrics.

## Start and resume

Run this from the repository on macOS or Linux. It uses a credential-free fixture:

```sh
uv sync --frozen
uv run agent-eval experiment run \
  --suite examples/blackbox/faq.yaml \
  --agent faq-smoke \
  --command "python3 $PWD/examples/blackbox/smoke_target.py" \
  --trials 3 \
  --max-new-trials 1
```

The experiment ID is printed to stderr before execution. Stdout contains a JSON
status. This example has six planned invocations: two cases repeated three times.
It pauses after the first invocation and reports `passed: null`, since the cohort
is incomplete. The pause limit counts newly invoked case/trial pairs, not rounds
of the entire suite.

Replace `EXPERIMENT_ID` below with the printed ID:

```sh
uv run agent-eval experiment status EXPERIMENT_ID
uv run agent-eval experiment resume EXPERIMENT_ID
uv run agent-eval experiment export EXPERIMENT_ID
```

Resume grades any saved observations and then runs cases that have never started.
It does not repeat completed calls. Export rebuilds `report.json` from the journal
and evidence without invoking an agent. A completed experiment also rebuilds the
report when resumed. A lost or corrupted export therefore does not require a new
evaluation. A missing or corrupt canonical artifact stops verification.

`--prepare-only` freezes the plan without invoking the target. Use
`--response-format json` and optionally `--response-pointer /answer` for native
JSON responses. The command is parsed as argv, without a shell. Use absolute
script paths because the target runs in a fresh temporary working directory.

## Identity and credentials

The plan records the suite and grader implementation digests, command settings,
resolved executable bytes, and file identities. Existing absolute file arguments
are included automatically. Repeat `--identity-file /absolute/path` for other
code, prompt or configuration files that affect behavior. These files are hashed,
not copied into the target working directory.

The selected file identities and target environment are checked before every new
invocation. Changing the interpreter, script, selected file, a selected symlink's
destination, or effective environment stops further dispatch. Resume the original
configuration or create a new experiment to compare the changed version. This is
a preflight identity check, not proof that a remote model or a dependency retained
the same version throughout execution. Imported modules, directory contents and
remote deployments are not automatically captured. An agent label is descriptive.

Use `--pass-env ENVIRONMENT_VARIABLE` for explicitly selected environment values.
Values are not stored in the plan; a keyed HMAC detects changes to the effective
target environment. The key stays in the private experiment directory. Keep
credentials out of argv because argv is stored in the private plan. Raw target
responses may contain sensitive data and remain private. This command does not
export telemetry or enable judging.

Targets receive only each case's input. Case IDs, goldens, reference context,
grading policy and the private state directory are not added to their request or
environment. This is still a trusted, same-user command execution mode, not an OS
security sandbox. A process with the same user privileges can access that user's
files. Use the existing isolated task runner for stronger separation.

## Recovery rules

| Last durable state | Resume behavior |
|---|---|
| `queued` | Validate identity and invoke once. |
| `running` with a sealed receipt | Recover the receipt, then grade without invoking. |
| `observed` | Grade the saved response or transport error. |
| `completed` | Verify its artifacts and keep the result. |
| `running` without a sealed receipt | Mark `reconciliation_required` and stop the whole experiment. |

A receipt is sealed when both its content-addressed artifact and its named
pointer have been durably written. A crash after writing the artifact but before
writing that pointer leaves an uncommitted artifact; it does not establish that
the observation was committed. The SQLite update may be recovered from a sealed
receipt. Results are finalized with a conditional transaction and can be finalized
again only with the same content.

After an ambiguous dispatch, the target may still be running or may already have
changed something. No force-retry command is provided. Inspect and reconcile its
side effects independently, then start a fresh experiment if appropriate. The
old incomplete experiment remains available and cannot become a passing report.
Known completed transport errors retain legacy `infra_error` scoring and are not
retried either.

Ctrl-C stops the active command's owned process group through the existing
transport cleanup. Without a saved receipt, it still leaves an ambiguous trial:
termination cannot undo side effects. SIGKILL can leave a target process running;
the journal does not kill processes later using a potentially reused PID. `status`
does not infer whether a stored `running` state is still live. `resume` takes the
exclusive worker lock before checking for abandoned work. A second active worker
is rejected while `status` can still read the journal.

## Storage and exits

Default macOS location:

```text
~/Library/Application Support/agent-eval/experiments/<experiment-id>/
  plan.json          Frozen suite, target settings and identity
  suite.json         Legacy-compatible suite snapshot
  journal.db         Canonical trial states and artifact references, schema 2
  environment.key    Private environment fingerprint key
  writer.lock        Process-lifetime exclusive writer lock
  receipts/          Named observation commit pointers
  artifacts/         Content-addressed observation and result records
  report.json        Rebuildable legacy black-box report, only when complete
```

Directories are `0700`; files are `0600`. Override the root with
`AGENT_EVAL_STATE_DIR`. The path must not contain symlink components. On macOS use
`/private/tmp` instead of the `/tmp` symlink for temporary experiments. An interrupted
initial creation may leave an uninitialized directory; it is not runnable and no
target was dispatched. Schema 1 is readable and migrates to schema 2 under the exclusive writer lock,
with a private `journal.v1.backup.db` first. Unknown newer schemas fail closed. There is no migration of existing black-box databases.

The full planned matrix is stored before execution. Each observation is bounded
by the existing transport limits. Plans/artifacts and exported reports are
bounded by the 16 MiB evidence-file limit. If a complete aggregate exceeds the
export limit, per-trial evidence remains available. Back up the whole experiment
directory while no writer is active; `report.json` alone is not a recovery backup.
The local hashes detect accidental changes and alignment errors; they do not
authenticate an adversary with write access to the entire directory.

| Exit | Meaning |
|---|---|
| `0` | Operation succeeded, including a deliberate pause or a status read. Inspect JSON `state` and `passed`; zero alone is not a release gate. |
| `1` | Configuration, identity, schema, evidence or persistence error. |
| `2` | Execution completed with rejected or infrastructure-error results. |
| `3` | Active worker conflict or reconciliation required. |
| `130` | Interactive interruption. |

The exported report retains `accepted`, `rejected`, `infra_error`, the existing
metric thresholds and the average that counts infrastructure errors as zero.
The neighboring `suite.json` also permits saved-run black-box inspection. Such
inspection remains a separate derivative result and does not modify this journal.

## Debugging exercise

1. Run the example with `--max-new-trials 1`. Read status and identify the one
   completed attempt. Explain why `passed` is null.
2. Resume to completion and record the report's SHA-256. Move only `report.json`
   aside, export it again, and compare its SHA-256. No target should run.
3. Prepare a new experiment, change a copy of the target script, and resume. The
   file identity check should stop dispatch. Restore the script and resume.
4. Use a disposable target that records invocation then blocks. Interrupt the
   worker and resume. Explain why a missing receipt cannot safely be retried even
   if the target produced no visible output.

The automated subprocess tests kill real worker processes at eight boundaries:
claim, dispatch, observation artifact, receipt, observed transaction, result
artifact, first completion and last completion. Run them locally with:

```sh
uv run pytest -q tests/test_experiment_recovery.py
```

Read `experiments/executor.py` for the recovery decisions and `journal.py` for the
receipt/transaction boundary. These tests establish local process-crash behavior;
they do not simulate power loss, hostile code, or a distributed worker system.

## Verification record

Checked September 11, 2026 on CPython 3.12.11: **954 tests passed, 7 skipped**.
The skips require optional OpenTelemetry/DeepEval dependencies or a prepared
Trivy executable/database. Ruff and the package build passed. An installed wheel
in a separate environment outside the checkout completed the six-invocation FAQ
experiment after pausing at one, rebuilt an identical report, and passed saved-run
source inspection through the existing black-box command. No live model call or
deployment was used for this verification.


## Explicit cancellation

`agent-eval experiment cancel EXPERIMENT_ID` seals a cancellation request. The
worker checks it between trials and while draining an owned command process.
Queued work becomes cancelled. A stopped active invocation without a sealed
observation becomes reconciliation-required because external effects may already
have occurred. Cancellation does not convert an incomplete cohort into a pass.
Use `distributed cancel-experiment` for work submitted to the shared queue.
