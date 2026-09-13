import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

from agent_eval.blackbox.models import digest, json_bytes
from agent_eval.candidates import authority, boundary, execution
from agent_eval.candidates.contracts import (
    AcceptancePolicy,
    ArtifactEnvelope,
    ArtifactReference,
    Assessment,
    Budget,
    CandidateManifest,
    ExecutionContract,
    Recipe,
    Submission,
    TrialIdentity,
    TrialTicket,
    validate_assessment,
)
from agent_eval.candidates.oracles import BehaviorSuite
from agent_eval.workbench.store import Conflict, Store

ROOT = Path(__file__).resolve().parents[1]


def git(path, *args):
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="Evaluation Fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="Evaluation Fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
        GIT_AUTHOR_DATE="2026-09-12T00:00:00Z",
        GIT_COMMITTER_DATE="2026-09-12T00:00:00Z",
    )
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=path,
        env=env,
        stderr=subprocess.DEVNULL,
    )


def prepare(tmp_path, monkeypatch, *, good=True, trial=1, cohort=None):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    base = tmp_path / "base"
    base.mkdir()
    for p in (ROOT / "examples/candidate-roundtrip/base").iterdir():
        (base / p.name).write_bytes(p.read_bytes())
    git(base, "init", "-q")
    git(base, "add", ".")
    git(base, "commit", "-qm", "Order service baseline")
    revision = git(base, "rev-parse", "HEAD").decode().strip()
    store = Store()
    authority.register_revision(store, "local", base, revision)
    spec = importlib.util.spec_from_file_location(
        "producer_fixture", ROOT / "contracts/v2/producer_fixture.py"
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    payload = tmp_path / "payload"
    manifest = fixture.export(
        base,
        ROOT / "tests/fixtures/candidates/idempotency_good.py" if good else None,
        payload,
    )
    refs = []
    for role, name in [("candidate", "candidate.json"), ("patch", "candidate.patch")]:
        envelope = ArtifactEnvelope.wrap((payload / name).read_bytes())
        refs.append(
            ArtifactReference(
                role=role, **authority.upload(store, "local", envelope, "producer")
            )
        )
    suite = BehaviorSuite.model_validate_json(
        (ROOT / "tests/fixtures/candidates/order-oracle.json").read_bytes()
    )
    policy = AcceptancePolicy(
        name="all-behavior", required_checks=[c.id for c in suite.checks]
    )
    recipe = Recipe(
        name="bounded-fixture",
        producer_sha256=hashlib.sha256(
            (ROOT / "contracts/v2/producer_fixture.py").read_bytes()
        ).hexdigest(),
        capability_sha256=digest("fixture"),
        model_configuration_sha256=digest("no-model"),
        budget=Budget(
            max_model_requests=0,
            max_total_tokens=0,
            max_elapsed_seconds=30,
            max_repairs=0,
        ),
    )
    ids = {
        kind + "_sha256": store.put(
            "local", "candidate-" + kind, value.model_dump(mode="json")
        )
        for kind, value in [("suite", suite), ("policy", policy), ("recipe", recipe)]
    }
    ticket = TrialTicket(
        execution_id=str(uuid.uuid4()),
        base_revision=revision,
        trial_identity=TrialIdentity(
            cohort_id=cohort or str(uuid.uuid4()),
            task_id=suite.task_id,
            family=suite.family,
            split=suite.split,
            trial=trial,
            arm="candidate",
        ),
        **ids,
        evaluator_sha256=authority.identity(),
    )
    authority.reserve(store, "local", ticket, "operator")
    contract = ExecutionContract(
        **ticket.model_dump(exclude={"schema_version"}),
        trial_ticket_sha256=digest(ticket.model_dump(mode="json")),
        candidate_revision=None,
        candidate_tree_sha256=manifest["tree_sha256"],
        candidate_manifest_sha256=refs[0].sha256,
    )
    authority.issue(store, "local", contract, "operator")
    submission = Submission(
        **contract.model_dump(exclude={"schema_version", "trial_identity"}),
        execution_contract_sha256=digest(contract.model_dump(mode="json")),
        producer_run_id="standalone-fixture",
        artifacts=refs,
        producer_status="completed",
    )
    return store, ticket, contract, submission, suite


def test_intake_is_not_acceptance_and_survives_restart(tmp_path, monkeypatch):
    store, ticket, contract, submission, _ = prepare(tmp_path, monkeypatch)
    result = authority.ingest(store, "local", submission, "producer")
    assert result["status"] == "awaiting_independent_evaluation"
    assert authority.ingest(Store(), "local", submission, "producer") == result
    with pytest.raises(KeyError):
        store.get("local", "assessment-v2", ticket.execution_id)
    assert contract.candidate_revision is None
    with pytest.raises(KeyError):
        authority.ingest(store, "other-project", submission, "producer")


@pytest.mark.parametrize(
    "field",
    [
        "trial_ticket_sha256",
        "execution_contract_sha256",
        "candidate_tree_sha256",
        "candidate_manifest_sha256",
        "recipe_sha256",
        "suite_sha256",
        "policy_sha256",
        "evaluator_sha256",
    ],
)
def test_stale_submission_bindings_rejected(tmp_path, monkeypatch, field):
    store, _, _, submission, _ = prepare(tmp_path, monkeypatch)
    altered = submission.model_copy(update={field: "0" * 64})
    with pytest.raises((ValueError, KeyError)):
        authority.ingest(store, "local", altered, "producer")


def test_candidate_commit_must_be_observed(tmp_path, monkeypatch):
    store, _, contract, _, _ = prepare(tmp_path, monkeypatch)
    with pytest.raises(KeyError):
        authority.issue(
            store,
            "local",
            contract.model_copy(update={"candidate_revision": "0" * 40}),
            "operator",
        )


def test_ticket_cannot_issue_another_candidate_or_duplicate_trial(
    tmp_path, monkeypatch
):
    store, ticket, _, _, _ = prepare(tmp_path, monkeypatch)
    with pytest.raises(Conflict):
        authority.reserve(
            store,
            "local",
            ticket.model_copy(update={"execution_id": str(uuid.uuid4())}),
            "operator",
        )


def test_patch_must_reconstruct_candidate(tmp_path, monkeypatch):
    store, _, contract, submission, _ = prepare(tmp_path, monkeypatch)
    raw = json.loads(
        authority.read_artifact(store, "local", contract.candidate_manifest_sha256)
    )
    empty = ArtifactEnvelope.wrap(b"")
    authority.upload(store, "local", empty, "producer")
    raw["patch_sha256"] = empty.content_sha256
    manifest = ArtifactEnvelope.wrap(json_bytes(raw))
    authority.upload(store, "local", manifest, "producer")
    with pytest.raises(ValueError):
        authority.manifest_for(
            store,
            "local",
            contract.model_copy(
                update={"candidate_manifest_sha256": manifest.content_sha256}
            ),
        )


def test_envelope_raw_and_storage_hashes_are_distinct():
    envelope = ArtifactEnvelope.wrap(b"patch bytes")
    assert envelope.content_sha256 != digest(envelope.model_dump(mode="json"))
    with pytest.raises(ValueError):
        ArtifactEnvelope(data=envelope.data, content_sha256="0" * 64)
    with pytest.raises(ValueError):
        ArtifactEnvelope(data="Zg==\n", content_sha256=hashlib.sha256(b"f").hexdigest())


@pytest.mark.parametrize(
    "name", ["../outside", "a/../x", "/root", "a//x", ".git/config", ".", "a\\b"]
)
def test_unsafe_candidate_paths_rejected(name):
    files = {name: {"data": base64.b64encode(b"x").decode(), "mode": 420}}
    with pytest.raises(ValueError):
        CandidateManifest(
            base_revision="0" * 40,
            tree_sha256=digest(files),
            files=files,
            changed_paths=[],
            patch_sha256="0" * 64,
        )


def fake_observation(suite, *, passed=True):
    responses = [None] * len(suite.requests)
    states = {}
    for check in suite.checks:
        for i, expected in zip(
            check.response_indices, check.expected_responses, strict=True
        ):
            responses[i] = expected
        if check.state_query:
            states[check.id] = check.expected_rows if passed else []
    return {
        "responses": responses,
        "state_queries": states,
        "exit_code": 0,
        "protocol_error": False,
        "started_at": "2026-09-12T00:00:00Z",
        "finished_at": "2026-09-12T00:00:01Z",
    }


def test_saved_observation_reconciles_without_duplicate_invocation(
    tmp_path, monkeypatch
):
    store, ticket, _, submission, suite = prepare(tmp_path, monkeypatch)
    authority.ingest(store, "local", submission, "producer")
    calls = []

    def observe(*args):
        calls.append("dispatch")
        return fake_observation(suite)

    monkeypatch.setattr(boundary, "execute", observe)
    monkeypatch.setattr(boundary, "cleanup", lambda *_: None)
    # Kill the evaluator at the journal publication boundary, after a durable named receipt.
    from agent_eval.experiments.journal import Journal

    complete = Journal.complete

    def crash(*_):
        raise KeyboardInterrupt

    monkeypatch.setattr(Journal, "complete", crash)
    with pytest.raises(KeyboardInterrupt):
        execution.evaluate(store, "local", ticket.execution_id)
    assert calls == ["dispatch"]
    monkeypatch.setattr(Journal, "complete", complete)
    result = execution.evaluate(Store(), "local", ticket.execution_id)
    assert result["outcome"] == "pass"
    # Boundary receipt reads occur during aggregation, but the journal never invokes again.
    assert len(calls) == 2
    before = len(calls)
    assert execution.evaluate(Store(), "local", ticket.execution_id) == result
    assert len(calls) == before
    assessment = Assessment.model_validate(result)
    assert validate_assessment(assessment, submission) == "pass"
    with pytest.raises(ValueError):
        validate_assessment(
            assessment, submission.model_copy(update={"policy_sha256": "0" * 64})
        )


@pytest.mark.skipif(
    os.environ.get("AGENT_EVAL_LIVE_CANDIDATE") != "1",
    reason="requires explicit disposable Docker execution",
)
@pytest.mark.parametrize("good", [True, False])
def test_live_independent_final_state(tmp_path, monkeypatch, good):
    store, ticket, _, submission, _ = prepare(tmp_path, monkeypatch, good=good)
    authority.ingest(store, "local", submission, "producer")
    result = execution.evaluate(store, "local", ticket.execution_id)
    assert result["outcome"] == ("pass" if good else "fail")
    assert (
        next(x for x in result["checks"] if x["id"] == "durable-orders")["passed"]
        == good
    )
    assert boundary.inspect("ae-candidate-" + ticket.execution_id) is None


def test_http_roles_project_scope_and_versioned_ticket(tmp_path, monkeypatch):
    import http.client
    import threading
    from agent_eval.workbench.api import WorkbenchServer

    store, ticket, contract, submission, _ = prepare(tmp_path, monkeypatch)
    for actor, role in [
        ("producer", "runner"),
        ("operator", "admin"),
        ("reader", "viewer"),
    ]:
        store.grant("local", actor, role)
    tokens = {actor: store.token(actor) for actor in ["producer", "operator", "reader"]}
    server = WorkbenchServer(store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(actor, method, path, data=None, project="local"):
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=10
        )
        headers = {
            "Authorization": "Bearer " + tokens[actor],
            "X-Project": project,
            "Content-Type": "application/json",
        }
        connection.request(
            method,
            "/v1/" + path,
            body=json_bytes(data) if data is not None else None,
            headers=headers,
        )
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result

    try:
        assert request("reader", "GET", "trial-tickets/" + ticket.execution_id)[
            1
        ] == ticket.model_dump(mode="json")
        assert (
            request(
                "producer",
                "POST",
                "execution-contracts",
                contract.model_dump(mode="json"),
            )[0]
            == 403
        )
        assert (
            request(
                "reader", "POST", "submissions", submission.model_dump(mode="json")
            )[0]
            == 403
        )
        status, result = request(
            "producer", "POST", "submissions", submission.model_dump(mode="json")
        )
        assert status == 201 and result["status"] == "awaiting_independent_evaluation"
        assert (
            request(
                "producer",
                "POST",
                "submissions/" + ticket.execution_id + "/evaluate",
                {},
            )[0]
            == 403
        )
        assert (
            request(
                "producer", "GET", "submissions/" + ticket.execution_id, project="other"
            )[0]
            == 403
        )
        assert request("reader", "GET", "assessments/" + ticket.execution_id)[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
