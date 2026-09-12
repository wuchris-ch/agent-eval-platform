#!/usr/bin/env python3
"""Exercise the candidate authority against a disposable actual producer snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
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
    Assessment,
    Budget,
    ExecutionContract,
    Recipe,
    Submission,
    TrialIdentity,
    TrialTicket,
    validate_assessment,
)
from agent_eval.candidates.oracles import BehaviorSuite
from agent_eval.workbench.store import Store

ROOT = Path(__file__).resolve().parents[1]


def make_base(root):
    shutil.copytree(ROOT / "examples/candidate-roundtrip/base", root)
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="Evaluation Fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="Evaluation Fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
        GIT_AUTHOR_DATE="2026-09-12T00:00:00Z",
        GIT_COMMITTER_DATE="2026-09-12T00:00:00Z",
    )
    for args in [
        ("init", "-q"),
        ("add", "."),
        ("commit", "-qm", "Order service baseline"),
    ]:
        subprocess.run(
            ["git", *args], cwd=root, env=env, check=True, capture_output=True
        )
    return authority.git(root, "rev-parse", "HEAD").decode().strip()


def produce(base, output, replacement, producer_root, pinned_source):
    if producer_root is None:
        args = [
            sys.executable,
            str(ROOT / "contracts/v2/producer_fixture.py"),
            str(base),
            str(output),
        ]
        if replacement:
            args += ["--replacement", str(replacement)]
        subprocess.run(args, check=True, capture_output=True)
        return
    code = """import json,sys,shutil
from pathlib import Path
from swe_platform.workspace.snapshot import snapshot,seal
from swe_platform.io import Artifacts,canonical
base,out,source=map(Path,sys.argv[1:])
out.mkdir(parents=True)
workspace=out/'workspace'
info=snapshot(base,workspace)
if source.is_file():shutil.copyfile(source,workspace/'server.py')
artifacts=Artifacts(out/'artifacts')
sha,manifest=seal(workspace,artifacts,info['base_revision'],['server.py'])
(out/'candidate.json').write_bytes(artifacts.get(sha))
(out/'candidate.patch').write_bytes(artifacts.get(manifest['patch_sha256']))
"""
    env = {**os.environ, "PYTHONPATH": str(pinned_source / "src")}
    subprocess.run(
        [
            str(producer_root / ".venv/bin/python"),
            "-c",
            code,
            str(base),
            str(output),
            str(replacement or output / "no-replacement"),
        ],
        env=env,
        check=True,
        capture_output=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--producer-root", type=Path)
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.environ["AGENT_EVAL_STATE_DIR"] = str(root / "evaluator-state")
    producer_revision = None
    pinned_source = None
    if args.producer_root:
        producer_revision = (
            authority.git(args.producer_root, "rev-parse", "HEAD").decode().strip()
        )
        pinned_source = root / "producer-source"
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-local",
                "--no-hardlinks",
                str(args.producer_root),
                str(pinned_source),
            ],
            check=True,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", "--detach", producer_revision],
            cwd=pinned_source,
            check=True,
        )
    base = root / "base"
    revision = make_base(base)
    store = Store()
    authority.register_revision(store, "local", base, revision)
    suite = BehaviorSuite.model_validate_json(
        (ROOT / "tests/fixtures/candidates/order-oracle.json").read_bytes()
    )
    policy = AcceptancePolicy(
        name="all-behavior", required_checks=[c.id for c in suite.checks]
    )
    recipe = Recipe(
        name="actual-producer-snapshot"
        if args.producer_root
        else "standalone-exporter",
        producer_sha256=digest({"revision": producer_revision})
        if producer_revision
        else hashlib.sha256(
            (ROOT / "contracts/v2/producer_fixture.py").read_bytes()
        ).hexdigest(),
        capability_sha256=digest("bounded-fixture-source-edit"),
        model_configuration_sha256=digest("no-model"),
        budget=Budget(
            max_model_requests=0,
            max_total_tokens=0,
            max_elapsed_seconds=60,
            max_repairs=0,
        ),
    )
    ids = {
        name + "_sha256": store.put(
            "local", "candidate-" + name, value.model_dump(mode="json")
        )
        for name, value in [("suite", suite), ("recipe", recipe), ("policy", policy)]
    }
    cohort = str(uuid.uuid4())
    cases = []
    for index, mode in enumerate(["correct", "incorrect", "crash-resume"], 1):
        ticket = TrialTicket(
            execution_id=str(uuid.uuid4()),
            base_revision=revision,
            trial_identity=TrialIdentity(
                cohort_id=cohort,
                task_id=suite.task_id,
                family=suite.family,
                split="development",
                trial=index,
                arm="candidate",
            ),
            **ids,
            evaluator_sha256=authority.identity(),
        )
        authority.reserve(store, "local", ticket, "operator")
        output = root / mode
        produce(
            base,
            output,
            None
            if mode == "incorrect"
            else ROOT / "tests/fixtures/candidates/idempotency_good.py",
            args.producer_root,
            pinned_source,
        )
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
                        "local",
                        ArtifactEnvelope.wrap((output / name).read_bytes()),
                        "producer",
                    ),
                )
            )
        manifest = parse_json((output / "candidate.json").read_bytes())
        contract = ExecutionContract(
            **ticket.model_dump(exclude={"schema_version"}),
            trial_ticket_sha256=digest(ticket.model_dump(mode="json")),
            candidate_revision=None,
            candidate_manifest_sha256=refs[0].sha256,
            candidate_tree_sha256=manifest["tree_sha256"],
        )
        authority.issue(store, "local", contract, "operator")
        submission = Submission(
            **contract.model_dump(exclude={"schema_version", "trial_identity"}),
            execution_contract_sha256=digest(contract.model_dump(mode="json")),
            producer_run_id="fixture-" + mode,
            artifacts=refs,
            producer_status="completed",
        )
        intake = authority.ingest(store, "local", submission, "producer")
        assert intake["status"] == "awaiting_independent_evaluation"
        if mode == "crash-resume":
            # Real process death after the independent receipt, before journal grading.
            code = """import os,sys
from agent_eval.experiments.journal import Journal
from agent_eval.candidates.execution import evaluate
from agent_eval.workbench.store import Store
Journal.complete=lambda *args:os._exit(86)
evaluate(Store(),'local',sys.argv[1])
"""
            child = subprocess.run(
                [sys.executable, "-c", code, ticket.execution_id],
                env=os.environ,
                capture_output=True,
            )
            assert child.returncode == 86
        assessment = Assessment.model_validate(
            execution.evaluate(Store(), "local", ticket.execution_id)
        )
        assert assessment.outcome == ("fail" if mode == "incorrect" else "pass")
        assert execution.evaluate(
            Store(), "local", ticket.execution_id
        ) == assessment.model_dump(mode="json")
        stale = False
        try:
            validate_assessment(
                assessment, submission.model_copy(update={"policy_sha256": "0" * 64})
            )
        except ValueError:
            stale = True
        assert stale
        for name, value in [
            ("ticket", ticket),
            ("execution", contract),
            ("submission", submission),
            ("assessment", assessment),
        ]:
            (output / (name + ".json")).write_bytes(
                json_bytes(value.model_dump(mode="json")) + b"\n"
            )
        raw_path = next(
            (root / "evaluator-state/candidate-executions").glob(
                "*/" + ticket.execution_id + "/observation.json"
            )
        )
        raw = parse_json(raw_path.read_bytes())["observation"]
        cases.append(
            {
                "mode": mode,
                "execution_id": ticket.execution_id,
                "outcome": assessment.outcome,
                "candidate_tree_sha256": assessment.candidate_tree_sha256,
                "observation_sha256": assessment.observation_sha256,
                "container_id": raw["container_id"],
                "stale_policy_rejected": stale,
                "replay_preserved_assessment": True,
            }
        )
    result = {
        "schema_version": "agent-eval.contract-roundtrip/v2",
        "producer_revision": producer_revision,
        "base_revision": revision,
        "evaluator_sha256": authority.identity(),
        "suite_sha256": ids["suite_sha256"],
        "model_requests": 0,
        "cases": cases,
    }
    (root / "summary.json").write_bytes(json_bytes(result) + b"\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
