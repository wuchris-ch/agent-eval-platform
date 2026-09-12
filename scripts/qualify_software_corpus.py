#!/usr/bin/env python3
"""Qualify authored software oracles with positive and plausible negative controls."""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from agent_eval.blackbox.models import digest, json_bytes, parse_json
from agent_eval.candidates import authority, execution
from agent_eval.candidates.contracts import (
    AcceptancePolicy,
    ArtifactEnvelope,
    ArtifactReference,
    Budget,
    ExecutionContract,
    Recipe,
    Submission,
    TrialIdentity,
    TrialTicket,
)
from agent_eval.candidates.oracles import BehaviorSuite
from agent_eval.workbench.store import Store

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks/software-corpus/v1"
FIXTURES = ROOT / "tests/fixtures/candidates/software-corpus"
REPLACEMENTS = {
    "order-idempotency": {
        "server.py": ROOT / "tests/fixtures/candidates/idempotency_good.py"
    },
    "document-authorization": {"documents.py": FIXTURES / "documents_good.py"},
    "schema-compatibility": {"migration.py": FIXTURES / "migration_good.py"},
    "cursor-pagination": {"catalog.py": FIXTURES / "catalog_good.py"},
    "payment-form": {
        "client.mjs": FIXTURES / "client_good.mjs",
        "api.mjs": FIXTURES / "api_good.mjs",
    },
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.environ["AGENT_EVAL_STATE_DIR"] = str(root / "state")
    store = Store()
    project = "oracle-qualification"
    cohort = str(uuid.uuid4())
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Evaluation Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Evaluation Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-09-12T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-09-12T00:00:00Z",
    }
    results = []
    recipe = Recipe(
        name="oracle-control",
        producer_sha256=hashlib.sha256(
            (ROOT / "contracts/v2/producer_fixture.py").read_bytes()
        ).hexdigest(),
        capability_sha256=digest("fixture-source-replacement"),
        model_configuration_sha256=digest("no-model"),
        budget=Budget(
            max_model_requests=0,
            max_total_tokens=0,
            max_elapsed_seconds=120,
            max_repairs=0,
        ),
    )
    recipe_sha = store.put(project, "candidate-recipe", recipe.model_dump(mode="json"))
    for case in parse_json((CORPUS / "manifest.json").read_bytes())["cases"]:
        task = case["id"]
        base = root / task / "base"
        shutil.copytree(CORPUS / case["public_path"], base)
        for argv in [
            ("init", "-q"),
            ("add", "."),
            ("commit", "-qm", "Software task baseline"),
        ]:
            subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", *argv],
                cwd=base,
                env=env,
                capture_output=True,
                check=True,
            )
        revision = authority.git(base, "rev-parse", "HEAD").decode().strip()
        authority.register_revision(store, project, base, revision)
        suite = BehaviorSuite.model_validate_json(
            (CORPUS / "oracles" / (task + ".json")).read_bytes()
        )
        policy = AcceptancePolicy(
            name="all-independent-behavior",
            required_checks=[c.id for c in suite.checks],
        )
        suite_sha = store.put(project, "candidate-suite", suite.model_dump(mode="json"))
        policy_sha = store.put(
            project, "candidate-policy", policy.model_dump(mode="json")
        )
        assert suite_sha == case["oracle_sha256"]
        for positive in [True, False]:
            label = "positive" if positive else "negative"
            out = root / task / label
            ticket = TrialTicket(
                execution_id=str(uuid.uuid4()),
                base_revision=revision,
                trial_identity=TrialIdentity(
                    cohort_id=cohort,
                    task_id=task,
                    family=suite.family,
                    split=suite.split,
                    trial=1,
                    arm="candidate" if positive else "baseline",
                ),
                recipe_sha256=recipe_sha,
                suite_sha256=suite_sha,
                policy_sha256=policy_sha,
                evaluator_sha256=authority.identity(),
            )
            authority.reserve(store, project, ticket, "operator")
            argv = [
                sys.executable,
                str(ROOT / "contracts/v2/producer_fixture.py"),
                str(base),
                str(out),
            ]
            if positive:
                replacements = root / task / "replacements"
                replacements.mkdir()
                for name, path in REPLACEMENTS[task].items():
                    shutil.copyfile(path, replacements / name)
                argv += ["--replacement", str(replacements)]
            subprocess.run(argv, capture_output=True, check=True)
            refs = []
            for role, name in [
                ("candidate", "candidate.json"),
                ("patch", "candidate.patch"),
            ]:
                refs.append(
                    ArtifactReference(
                        role=role,
                        **authority.upload(
                            store,
                            project,
                            ArtifactEnvelope.wrap((out / name).read_bytes()),
                            "fixture",
                        ),
                    )
                )
            manifest = parse_json((out / "candidate.json").read_bytes())
            contract = ExecutionContract(
                **ticket.model_dump(exclude={"schema_version"}),
                trial_ticket_sha256=digest(ticket.model_dump(mode="json")),
                candidate_tree_sha256=manifest["tree_sha256"],
                candidate_manifest_sha256=refs[0].sha256,
            )
            authority.issue(store, project, contract, "operator")
            submission = Submission(
                **contract.model_dump(exclude={"schema_version", "trial_identity"}),
                execution_contract_sha256=digest(contract.model_dump(mode="json")),
                producer_run_id="oracle-control-" + task + "-" + label,
                artifacts=refs,
                producer_status="completed",
            )
            authority.ingest(store, project, submission, "fixture")
            assessment = execution.evaluate(store, project, ticket.execution_id)
            for name, value in [
                ("ticket", ticket.model_dump(mode="json")),
                ("execution", contract.model_dump(mode="json")),
                ("submission", submission.model_dump(mode="json")),
                ("assessment", assessment),
            ]:
                (out / (name + ".json")).write_bytes(json_bytes(value) + b"\n")
            correct = assessment["outcome"] == ("pass" if positive else "fail")
            results.append(
                {
                    "task_id": task,
                    "family": suite.family,
                    "control": label,
                    "expected_outcome": "pass" if positive else "fail",
                    "observed_outcome": assessment["outcome"],
                    "qualified": correct,
                    "base_revision": revision,
                    "execution_id": ticket.execution_id,
                    "candidate_tree_sha256": contract.candidate_tree_sha256,
                    "suite_sha256": suite_sha,
                    "evaluator_sha256": ticket.evaluator_sha256,
                    "assessment_sha256": digest(assessment),
                    "checks": assessment["checks"],
                }
            )
            print(task + " " + label + ": " + assessment["outcome"], flush=True)
    result = {
        "schema_version": "agent-eval.oracle-qualification/v1",
        "corpus_sha256": hashlib.sha256(
            (CORPUS / "manifest.json").read_bytes()
        ).hexdigest(),
        "model_calls": 0,
        "results": results,
        "passed": all(r["qualified"] for r in results),
    }
    (root / "qualification.json").write_bytes(json_bytes(result) + b"\n")
    if not result["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
