# Candidate evaluation contract v2

The evaluator reserves trials, owns reference checks and issues assessments. A producer supplies candidate bytes and execution evidence. Successful intake returns `awaiting_independent_evaluation`.

## Lifecycle

1. An operator registers an independently read base Git commit, a behavior suite, an acceptance policy and a production recipe.
2. Before coding, the operator reserves `agent-eval.trial-ticket/v2`. Its UUID binds the task family, split, paired trial, arm, attempt kind, base commit, recipe, suite, policy and evaluator implementation. Reserved trials remain part of the cohort even when production fails.
3. The producer runs against that ticket, seals its candidate and uploads artifacts. `candidate_revision` is `null` for an uncommitted tree. A non-null commit must have been independently read and registered by the evaluator.
4. The operator issues `agent-eval.execution/v2` for the ticket's single candidate. The evaluator reconstructs the submitted patch against its own base snapshot and checks the complete resulting tree.
5. The producer posts `agent-eval.submission/v2`. The evaluator checks the ticket, issued contract and every artifact reference before recording intake.
6. The operator starts independent evaluation. Submitted code runs in an owned, bounded container without network access. Reference checks stay outside that container. The evaluator checks responses and reads final SQLite state independently.
7. `agent-eval.assessment/v2` binds the exact submission, candidate, recipe, suite, policy, evaluator and observed evidence. A caller verifies these bindings and the authenticated origin before using `outcome`.

A saved observation can be graded after a crash. An owned container can be reconciled without restarting it. Missing dispatch evidence requires reconciliation; the evaluator does not replay an ambiguous invocation.

## Canonical bytes and identities

All JSON hashes use SHA-256 over UTF-8 JSON with sorted keys, compact separators, ASCII escaping and no non-finite numbers. Base64 uses its canonical padded encoding. An artifact reference has two hashes:

| Field | Identifies |
|---|---|
| `sha256` | Raw artifact bytes |
| `storage_key` | Canonical `agent-eval.artifact/v2` envelope |
| `candidate_manifest_sha256` | Raw canonical `candidate/v1` JSON |
| `candidate_tree_sha256` | Canonical `files` map in the candidate manifest |
| `trial_ticket_sha256` | Complete canonical pre-dispatch ticket |
| `execution_contract_sha256` | Complete canonical issued execution contract |
| `submission_sha256` | Complete canonical submitted envelope |

Candidate files use `{data: <base64>, mode: 420|493}`. The manifest's `changed_paths` must equal the independently observed difference from the base, and `patch_sha256` must reconstruct those bytes. The wire format supports up to 2,000 regular files and 8 MiB of source content; individual raw artifacts are bounded at 12 MiB. Symlinks, submodules, path aliases and credential files are excluded from this profile.

## Authenticated API

The loopback workbench requires `Authorization: Bearer <token>` and `X-Project: <project>`. Host and origin checks apply to every request. Roles and project access are rechecked at invocation. The `/v1` transport supports both the existing submission v1 and the new explicitly versioned v2 envelopes.

| Method | Route | Role | Result |
|---|---|---|---|
| GET | `/v1/authority` | viewer | Current evaluator content identity |
| POST | `/v1/trial-tickets` | admin | Pre-dispatch trial reservation |
| POST | `/v1/producer-artifacts` | runner | Raw and envelope hashes |
| POST | `/v1/execution-contracts` | admin | Candidate-bound execution identity |
| POST | `/v1/submissions` | runner | Intake receipt |
| POST | `/v1/submissions/{execution_id}/evaluate` | admin | Queued independent evaluation |
| GET | `/v1/trial-tickets/{execution_id}` | viewer | Reserved trial |
| GET | `/v1/execution-contracts/{execution_id}` | viewer | Issued identity |
| GET | `/v1/submissions/{execution_id}` | viewer | Submitted evidence |
| GET | `/v1/assessments/{execution_id}` | viewer | Bound independent assessment |

Base revisions, suites, recipes and policies are registered through operator CLI commands. Producers cannot supply executable graders or self-issue acceptance.

## Usage and policy

Behavior checks operate on independent observations. Usage included in a producer submission is labeled `producer_reported`; it cannot claim independent provenance. A policy with a usage limit needs independently observed usage. Missing token or cost observations produce an inconclusive resource decision, not a zero estimate. Repair attempts link to a prior execution and remain separate from first-attempt comparisons.

## Executable compatibility check

`producer_fixture.py` is a standalone standard-library exporter with no evaluator import. It produces a real base Git revision and a content-addressed uncommitted candidate. The executable contract tests validate replay, stale identities, artifact substitution, patch reconstruction, project isolation and recovery:

```sh
uv run pytest -q tests/test_candidate_contract.py
AGENT_EVAL_LIVE_CANDIDATE=1 uv run pytest -q tests/test_candidate_contract.py -k live
```

The live checks use disposable state and the pinned Python image in the fixture suite. They verify both a correct implementation and a plausible implementation that passes the first request but duplicates durable orders on replay.

The recorded request/assessment and binary envelopes in `fixtures/` came from a successful disposable producer round trip. `index.json` lists their file hashes. To repeat the complete positive, negative and process-crash controls with the producer's real snapshot/sealing code:

```sh
uv run python scripts/candidate_roundtrip.py \
  --producer-root /path/to/multi-agent-software-development-platform \
  --out /private/tmp/candidate-authority-roundtrip
```

The command reads a pinned producer checkout into a private clone, creates a separate disposable repository, and invokes no model. The summary records the actual producer and base commits. Omit `--producer-root` to use the standalone fixture exporter.
