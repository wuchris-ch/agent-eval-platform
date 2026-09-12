"""Product workflows and adversarial boundaries, without live model calls."""

from __future__ import annotations

import http.client
import json
import sqlite3
import sys
import threading
import time
import zipfile

import pytest
from typer.testing import CliRunner

from agent_eval.blackbox.models import Case, Metric, Suite, json_bytes
from agent_eval.cli import app
from agent_eval.environments.world import Fault, World, assess, schedule
from agent_eval.experiments.executor import execute
from agent_eval.experiments.journal import (
    Journal,
    JournalError,
    directory,
    request_cancel,
)
from agent_eval.experiments.models import CommandSpec
from agent_eval.experiments.service import create_experiment
from agent_eval.workbench import service
from agent_eval.workbench.analysis import Policy, decide, reliability
from agent_eval.workbench.api import WorkbenchServer
from agent_eval.workbench.datasets import (
    CalibrationCase,
    Dataset,
    calibrate,
    quarantine,
    register_dataset,
)
from agent_eval.workbench.lifecycle import backup, expire, restore
from agent_eval.workbench.models import Launch, TargetProfile
from agent_eval.workbench.store import Conflict, Denied, Store
from agent_eval.workbench.submissions import Submission, ingest, import_external


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    return Store()


def register(store, mode="good", *, world=None):
    if world:
        suite = Suite(
            schema_version="1.0",
            id="ticket",
            version="1",
            metrics=[Metric(name="status", kind="json_subset")],
            cases=[
                Case(
                    id="close",
                    input={"id": "ticket-1"},
                    expected_output={"status": "closed"},
                )
            ],
        )
    else:
        suite = Suite(
            schema_version="1.0",
            id="support",
            version="1",
            metrics=[Metric(name="answer", kind="json_subset")],
            cases=[
                Case(id=q, input={"question": q}, expected_output={"answer": q})
                for q in ("shipping", "returns", "hours")
            ],
        )
    dataset = Dataset(
        suite=suite,
        split="regression",
        origin="synthetic controls",
        license="Apache-2.0",
        reviewed_by="tests",
        families={c.id: c.id for c in suite.cases},
    )
    dataset_id = register_dataset(store, "local", dataset, "tests")
    profile = TargetProfile(
        name=mode,
        command=CommandSpec(
            argv=[sys.executable, "-m", "agent_eval.workbench.adapter", mode],
            response_format="json",
        ),
        world=world,
        model_calls="none",
    )
    target_id = store.put("local", "target", profile.model_dump(mode="json"))
    return Launch(target=target_id, dataset=dataset_id, trials=2)


def launch(store, mode="good", world=None):
    request = register(store, mode, world=world)
    identity = service.launch_experiment(
        store, "local", request, actor="test", key=mode
    )
    return identity


def test_complete_product_workflow_and_regrade(store, tmp_path):
    a, b = launch(store), launch(store, "regression")
    assert service.run(store, "local", a)["passed"] is True
    assert service.run(store, "local", b)["passed"] is False
    comparison = service.comparison(store, "local", a, b)
    assert comparison["effect"] == pytest.approx(-1 / 3)
    assert comparison["counts"]["candidate"]["accepted"] == 4
    assert all(c["case"] == "returns" for c in comparison["cases"] if c["delta"] == -1)
    detail = service.trial_detail(store, "local", b, 1)
    assert detail["result"]["outcome"] == "rejected"
    assert (
        store.annotate(
            "local",
            b,
            1,
            "Wrong policy response",
            actor="reviewer",
            expected_revision=0,
        )
        == 1
    )
    assert Store().annotations("local", b, 1)[0]["body"] == "Wrong policy response"
    with pytest.raises(Conflict):
        store.annotate(
            "local", b, 1, "lost update", actor="reviewer", expected_revision=0
        )
    with Journal.open(b) as journal:
        suite_path = tmp_path / "suite.json"
        suite_path.write_bytes(json_bytes(journal.plan.suite.model_dump(mode="json")))
        previous = [dict(r) for r in journal.rows()]
    result = CliRunner().invoke(app, ["workbench", "regrade", b, str(suite_path)])
    assert result.exit_code == 0, result.output
    with Journal.open(b) as journal:
        assert previous == [dict(r) for r in journal.rows()]
    assert len(store.list("local", "assessment-set")["items"]) == 1


def test_idempotent_launch_and_limits(store):
    request = register(store)
    a = service.launch_experiment(store, "local", request, actor="test", key="one")
    assert a == service.launch_experiment(
        store, "local", request, actor="test", key="one"
    )
    with pytest.raises(Conflict):
        service.launch_experiment(
            store,
            "local",
            request.model_copy(update={"trials": 3}),
            actor="test",
            key="one",
        )
    with pytest.raises(ValueError, match="limit"):
        service.preview(store, "local", request.model_copy(update={"trials": 1000}))
    with pytest.raises(KeyError):
        service.detail(store, "other", a)


def test_incomplete_and_substituted_gate_never_pass(store):
    a, b = launch(store), launch(store, "regression")
    result = service.comparison(store, "local", a, b)
    p = Policy(regression_margin=0.1, minimum_families=2)
    assert decide(result, p, result["candidate"]["target"])["verdict"] == "inconclusive"
    assert decide(result, p, "f" * 64)["verdict"] == "fail"
    service.run(store, "local", a)
    service.run(store, "local", b)
    result = service.comparison(store, "local", a, b)
    assert decide(result, p, result["candidate"]["target"])["verdict"] != "pass"
    assert (
        decide(
            result,
            p.model_copy(update={"required_inspection": True}),
            result["candidate"]["target"],
        )["verdict"]
        == "inconclusive"
    )
    assert reliability(2, 3, 2) == {"all_k": 1 / 3, "at_least_one_k": 1.0}
    with pytest.raises(ValueError):
        reliability(2, 3, 4)


@pytest.mark.parametrize(
    "mode,expected",
    [("ticket-good", True), ("ticket-lie", False), ("ticket-wrong", False)],
)
def test_independent_state_beats_success_message(store, mode, expected):
    identity = launch(store, mode, world="ticket")
    result = service.run(store, "local", identity)
    assert result["passed"] is True  # Every scripted agent claims success.
    assert result["overall_passed"] is expected
    evidence = service.trial_detail(store, "local", identity, 0)["state_evidence"]
    assert evidence["assessment"]["status"] == ("accepted" if expected else "rejected")


def test_world_faults_isolation_and_reset():
    fault = Fault(operation="write", ordinal=1, kind="timeout_after_write")
    world = World(faults=[fault])
    before = world.snapshot()
    assert (
        world.operate(world.token, "write", {"id": "ticket-1", "status": "closed"})[0]
        == 504
    )
    after = world.snapshot()
    assert assess(before, after)["status"] == "accepted"
    assert after["rows"]["ticket-1"]["status"] == "closed"
    old = world.token
    world.reset(0)
    assert world.operate(old, "read", {"id": "ticket-1"})[0] == 403
    assert world.operate(world.token, "read", {"id": "ticket-3"})[0] == 404
    assert (
        world.operate(world.token, "write", {"id": "ticket-1", "owner": "customer-b"})[
            0
        ]
        == 400
    )
    assert assess(before, world.snapshot())["status"] == "invalid"
    assert schedule(42) == schedule(42)
    assert schedule(42) != schedule(41)
    order = World(kind="order")
    start = order.snapshot()
    assert (
        order.operate(order.token, "write", {"id": "ticket-1", "status": "closed"})[0]
        == 403
    )
    assert assess(start, order.snapshot(), kind="order")["status"] == "accepted"


@pytest.mark.parametrize(
    "kind,code",
    [
        ("timeout_before", 504),
        ("rate_limit", 429),
        ("malformed", 200),
        ("stale_read", 200),
    ],
)
def test_observed_logical_faults(kind, code):
    world = World(kind="order", faults=[Fault(operation="read", ordinal=1, kind=kind)])
    before = world.snapshot()
    assert world.operate(world.token, "read", {"id": "ticket-1"})[0] == code
    assert assess(before, world.snapshot(), kind="order")["faults_verified"]


def test_cancel_queued_and_running(store):
    request = register(store)
    identity = service.launch_experiment(
        store, "local", request, actor="test", key="cancel"
    )
    request_cancel(identity)
    assert execute(identity).state == "cancelled"
    assert execute(identity).passed is None
    suite = Suite(
        schema_version="1.0",
        id="sleep",
        version="1",
        metrics=[Metric(name="eq", kind="exact_match")],
        cases=[
            Case(id="one", input="x", expected_output="x"),
            Case(id="two", input="x", expected_output="x"),
        ],
    )
    identity = create_experiment(
        suite,
        agent="sleep",
        command=CommandSpec(argv=[sys.executable, "-c", "import time;time.sleep(20)"]),
    )
    errors = []

    def work():
        try:
            execute(identity)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=work)
    thread.start()
    for _ in range(100):
        with Journal.open(identity) as journal:
            running = journal.rows()[0]["state"] == "running"
        if running:
            break
        time.sleep(0.02)
    assert running
    request_cancel(identity)
    thread.join(5)
    assert not thread.is_alive() and not errors
    with Journal.open(identity) as journal:
        assert [r["state"] for r in journal.rows()] == [
            "reconciliation_required",
            "cancelled",
        ]
        assert journal.status().passed is None


def test_old_journal_forward_migration(store):
    identity = launch(store)
    database = directory(identity) / "journal.db"
    with sqlite3.connect(database) as db:
        db.execute("PRAGMA user_version=1")
    with Journal.open(identity, write=True) as journal:
        assert journal.connection.execute("PRAGMA user_version").fetchone()[0] == 2
    assert (directory(identity) / "journal.v1.backup.db").exists()


@pytest.fixture
def api_server(store):
    store.grant("local", "alice", "admin")
    store.grant("other", "bob", "viewer")
    token = store.token("alice")
    server = WorkbenchServer(store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(
        path, body=None, *, credential=token, project="local", origin=None, host=None
    ):
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=15
        )
        headers = {
            "Host": host or f"127.0.0.1:{server.server_port}",
            "Authorization": "Bearer " + credential,
            "X-Project": project,
            "Content-Type": "application/json",
        }
        if origin is not None:
            headers["Origin"] = origin
        connection.request(
            "GET" if body is None else "POST",
            path,
            body=json_bytes(body) if body is not None else None,
            headers=headers,
        )
        response = connection.getresponse()
        data = response.read()
        result = (
            response.status,
            json.loads(data)
            if response.getheader("Content-Type") == "application/json"
            else data,
            dict(response.getheaders()),
        )
        connection.close()
        return result

    yield server, request, token
    server.shutdown()
    server.server_close()
    thread.join()


def test_api_auth_origins_tenant_and_html(store, api_server):
    server, request, token = api_server
    identity = launch(store)
    assert request("/v1/experiments")[0] == 200
    assert request("/v1/experiments", credential="invalid")[0] == 403
    assert request("/v1/experiments", project="other")[0] == 403
    assert (
        request(
            "/v1/experiments/" + identity,
            credential=store.token("bob"),
            project="other",
        )[0]
        == 404
    )
    assert (
        request(
            "/v1/experiments/" + identity + "/start", {}, origin="https://evil.example"
        )[0]
        == 403
    )
    assert request("/v1/experiments", host="evil.example")[0] == 403
    code, body, headers = request("/")
    assert code == 200 and b'<script src="/app.js" defer>' in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    script = request("/app.js")[1]
    assert b"innerHTML" not in script and b"textContent" in script
    payload = "<img src=x onerror=alert(1)>"
    code, _, _ = request(
        f"/v1/experiments/{identity}/trials/0/annotations",
        {"body": payload, "expected_revision": 0},
    )
    assert code == 201
    assert (
        request(f"/v1/experiments/{identity}/trials/0")[1]["annotations"][0]["body"]
        == payload
    )
    assert (
        request(
            f"/v1/experiments/{identity}/trials/999/annotations",
            {"body": "x", "expected_revision": 0},
        )[0]
        == 400
    )
    store.revoke("alice")
    assert request("/v1/experiments")[0] == 403


def test_api_full_launch_events_and_conflict(store, api_server):
    server, request, _ = api_server
    data = register(store).model_dump()
    assert request("/v1/preview", data)[1]["invocations"] == 6
    # Browser create requires an idempotency header; use the service and test dispatch.
    identity = service.launch_experiment(
        store, "local", Launch.model_validate(data), actor="alice", key="api"
    )
    assert request(f"/v1/experiments/{identity}/start", {})[0] == 202
    for _ in range(200):
        status, result = request("/v1/experiments/" + identity)
        assert status == 200, result
        if result["state"] == "completed":
            break
        time.sleep(0.02)
    assert result["passed"] is True
    # The journal can be complete before the worker appends its catalog event.
    # Wait for that producer before asserting the event cursor is caught up.
    server.jobs[identity].result(timeout=10)
    events = request("/v1/events?after=0")[1]
    assert any(event["action"] == "execution:completed" for event in events)
    assert events and request("/v1/events?after=" + str(events[-1]["seq"]))[1] == []
    store.grant("local", "alice", "viewer")
    assert request(f"/v1/experiments/{identity}/start", {})[0] == 403


def test_audit_corruption_pagination_and_expiry(store):
    for n in range(5):
        store.put("local", "sample", {"n": n}, object_id=str(n))
    page = store.list("local", "sample", limit=2)
    assert page["next"] == "1"
    assert (
        store.list("local", "sample", after=page["next"], limit=2)["items"][0]["id"]
        == "2"
    )
    assert store.verify_audit()["events"] == 5
    store.grant("local", "alice", "runner")
    token = store.token("alice")
    store.authorize(store.authenticate(token), "local", "run")
    with pytest.raises(Denied):
        store.authorize("alice", "local", "admin")
    with store.db() as db:
        db.execute("UPDATE tokens SET expires=0")
        db.execute("UPDATE events SET action='forged' WHERE seq=1")
    with pytest.raises(Denied):
        store.authenticate(token)
    with pytest.raises(JournalError):
        store.verify_audit()


def test_dataset_split_quarantine_and_calibration(store):
    request = register(store)
    dataset = Dataset.model_validate(store.get("local", "dataset", request.dataset))
    with pytest.raises(ValueError, match="splits"):
        register_dataset(
            store, "local", dataset.model_copy(update={"split": "held_out"}), "test"
        )
    with pytest.raises(ValueError):
        Dataset.model_validate(
            {**dataset.model_dump(), "split": "held_out", "exposure": ["public"]}
        )
    identity = quarantine(
        store,
        "local",
        "Email person@example.org bearer abcdef123456",
        "approved",
        origin="fixture",
        actor="curator",
    )
    item = store.get("local", "quarantine", identity)
    assert "person@" not in str(item) and "abcdef" not in str(item)
    cases = [
        CalibrationCase(
            id=str(i),
            split="validation",
            category="safety",
            expected=label,
            observed=label,
            labelers=["reviewer"],
        )
        for i, label in enumerate(["pass", "fail"])
    ]
    assert calibrate(cases, "a" * 64)["admitted"]
    cases[1].observed = "pass"
    assert not calibrate(cases, "a" * 64)["admitted"]


def test_submission_stale_replay_and_tenant(store):
    execution = store.new_id()
    contract = {
        "base_revision": "a" * 40,
        "candidate_revision": "b" * 40,
        "candidate_tree_sha256": "c" * 64,
        "recipe_sha256": "d" * 64,
    }
    store.put("local", "execution-contract", contract, object_id=execution)
    artifact = store.put("local", "producer-artifact", {"patch": "synthetic diff"})
    submission = Submission(
        execution_id=execution,
        producer_run_id="producer-1",
        **contract,
        artifacts=[{"role": "patch", "sha256": artifact, "storage_key": artifact}],
        producer_status="completed",
    )
    assert (
        ingest(store, "local", submission, "producer")["status"]
        == "awaiting_independent_evaluation"
    )
    assert ingest(store, "local", submission, "producer")["id"] == execution
    with pytest.raises(ValueError):
        ingest(
            store,
            "local",
            submission.model_copy(update={"candidate_revision": "f" * 40}),
            "producer",
        )
    with pytest.raises(Conflict):
        ingest(
            store,
            "local",
            submission.model_copy(update={"producer_run_id": "replayed"}),
            "producer",
        )
    with pytest.raises(KeyError):
        ingest(store, "other", submission, "producer")
    assert store.list("local", "decision")["items"] == []
    reference = import_external(store, "local", "inspect", {"samples": []}, "operator")
    assert not store.get("local", "external-report", reference)["gate_eligible"]


def test_backup_restore_hashes_retention_and_traversal(store, tmp_path, monkeypatch):
    identity = launch(store)
    service.run(store, "local", identity)
    report = (directory(identity) / "report.json").read_bytes()
    archive = tmp_path / "backup.zip"
    backup(store, archive)
    destination = tmp_path / "restored"
    restore(archive, destination)
    assert (
        destination / "experiments" / identity / "report.json"
    ).read_bytes() == report
    with monkeypatch.context() as m:
        m.setenv("AGENT_EVAL_STATE_DIR", str(destination))
        assert service.detail(Store(), "local", identity)["passed"] is True
    assert not expire(store, "local", identity, actor="test", reason="fixture")[
        "deleted"
    ]
    assert expire(
        store, "local", identity, actor="test", reason="fixture", execute=True
    )["deleted"]
    assert store.get("local", "tombstone", identity)
    with pytest.raises(FileNotFoundError):
        service.detail(store, "local", identity)
    malicious = tmp_path / "bad.zip"
    with zipfile.ZipFile(malicious, "w") as z:
        z.writestr("../escape", "bad")
    with pytest.raises(ValueError):
        restore(malicious, tmp_path / "rejected")
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"active": False},
        {"iss": "https://wrong.example"},
        {"aud": ["wrong"]},
        {"exp": 0},
        {"sub": ""},
        {"nbf": 99999999999},
    ],
)
def test_oidc_claim_failures_are_closed(monkeypatch, change):
    from agent_eval.workbench.auth import OIDC
    import urllib.request

    claims = {
        "active": True,
        "iss": "https://identity.example",
        "aud": ["evaluation"],
        "sub": "alice",
        "exp": time.time() + 60,
    }
    claims.update(change)

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return json_bytes(claims)

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    provider = OIDC(
        endpoint="https://identity.example/introspect",
        issuer="https://identity.example",
        audience="evaluation",
        client_id="test-client",
        client_secret="test-secret",
    )
    with pytest.raises(Denied):
        provider.authenticate("test-token")


def test_oidc_valid_and_no_plain_http(monkeypatch):
    from agent_eval.workbench.auth import OIDC, NoRedirect
    import urllib.request

    claims = {
        "active": True,
        "iss": "https://identity.example",
        "aud": "evaluation",
        "sub": "alice",
        "exp": time.time() + 60,
    }

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return json_bytes(claims)

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    args = dict(
        endpoint="https://identity.example/introspect",
        issuer="https://identity.example",
        audience="evaluation",
        client_id="test-client",
        client_secret="test-secret",
    )
    assert OIDC(**args).authenticate("test-token") == "https://identity.example#alice"
    assert NoRedirect().redirect_request(None, None, None, None, None, None) is None
    with pytest.raises(ValueError):
        OIDC(**{**args, "endpoint": "http://identity.example"})


def test_state_corruption_and_comparison_counts(store):
    a, b = (
        launch(store, "ticket-good", world="ticket"),
        launch(store, "ticket-lie", world="ticket"),
    )
    service.run(store, "local", a)
    service.run(store, "local", b)
    result = service.comparison(store, "local", a, b)
    assert result["counts"]["candidate"]["accepted"] == 0
    assert result["candidate"]["output_status"]["accepted"] == 2
    with Journal.open(b) as journal:
        row = journal.rows()[0]
        pointer = journal.root / "receipts" / f"{row['attempt_id']}.state.json"
    pointer.unlink()
    with pytest.raises(JournalError):
        service.comparison(store, "local", a, b)


def test_paired_schedule_is_fixed_and_resumable(store):
    a, b = register(store), register(store, "regression")
    result = service.paired_run(
        store, "local", a, b, seed=42, key="paired", actor="tester"
    )
    design = store.get("local", "comparison-design", result["design"])
    assert len(design["schedule"]) == 12
    for i in range(0, 12, 2):
        assert {r["experiment"] for r in design["schedule"][i : i + 2]} == {
            result["baseline"],
            result["candidate"],
        }
        assert {r["ordinal"] for r in design["schedule"][i : i + 2]} == {i // 2}
    assert (
        service.paired_run(store, "local", a, b, seed=42, key="paired", actor="tester")
        == result
    )
    with pytest.raises(Conflict):
        service.paired_run(store, "local", a, b, seed=43, key="paired", actor="tester")


def test_required_inspection_remains_separate_from_passing_output(store, tmp_path):
    identity = launch(store)
    service.run(store, "local", identity)
    with Journal.open(identity) as journal:
        report = json.loads((journal.root / "report.json").read_text())
    report["schema_version"] = "1.1"
    report["parent_run_id"] = identity
    report["run_id"] = store.new_id()
    summary = {
        "status": "rejected",
        "accepted": 0,
        "rejected": 1,
        "unavailable": 0,
        "score": 0.0,
    }
    report["inspection"] = {
        "schema_version": "1.0",
        "required": True,
        "status": "rejected",
        "profile_sha256": "a" * 64,
        "source_sha256": None,
        "traces_sha256": None,
        "source": summary,
        "trace": summary,
        "results": [],
    }
    path = tmp_path / "inspection.json"
    path.write_bytes(json_bytes(report))
    result = CliRunner().invoke(
        app, ["workbench", "attach-inspection", identity, str(path)]
    )
    assert result.exit_code == 0, result.output
    detail = service.detail(store, "local", identity)
    assert detail["passed"] is True
    assert detail["overall_passed"] is False


def test_assisted_attempts_are_linked_and_never_pooled(store):
    parent = launch(store)
    request = register(store).model_copy(
        update={"attempt_kind": "assisted_correction", "parent_experiment": parent}
    )
    child = service.launch_experiment(
        store, "local", request, actor="test", key="correction"
    )
    result = service.comparison(store, "local", parent, child)
    assert result["attempt_kind"] == "mixed"
    assert any("pooled" in reason for reason in result["reasons"])
    with pytest.raises(ValueError):
        Launch(
            target=request.target,
            dataset=request.dataset,
            attempt_kind="infra_recovery",
        )


def test_unavailable_attached_inspection_cannot_be_relaxed_by_policy(store):
    request = register(store)
    a = service.launch_experiment(
        store, "local", request, actor="test", key="inspect-a"
    )
    b = service.launch_experiment(
        store, "local", request, actor="test", key="inspect-b"
    )
    service.run(store, "local", a)
    service.run(store, "local", b)
    store.put(
        "local",
        "inspection",
        {"inspection": {"required": True, "status": "unavailable"}},
        object_id=b,
    )
    policy = store.put(
        "local",
        "policy",
        Policy(regression_margin=0.1, minimum_families=2).model_dump(mode="json"),
    )
    artifact = service.comparison(store, "local", a, b)["candidate"]["target"]
    result = service.gate(store, "local", a, b, policy, artifact, "test")
    assert result["verdict"] == "inconclusive"
    assert "required attached inspection unavailable" in result["reasons"]


def test_unobserved_fault_makes_gate_inconclusive(store):
    request = register(store, "ticket-good", world="ticket")
    profile = TargetProfile.model_validate(store.get("local", "target", request.target))
    profile.faults = [Fault(operation="read", ordinal=1, kind="timeout_before")]
    request.target = store.put("local", "target", profile.model_dump(mode="json"))
    a = service.launch_experiment(store, "local", request, actor="test", key="fault-a")
    b = service.launch_experiment(store, "local", request, actor="test", key="fault-b")
    service.run(store, "local", a)
    service.run(store, "local", b)
    policy = store.put(
        "local",
        "policy",
        Policy(
            regression_margin=0.1, minimum_families=2, require_state=True
        ).model_dump(mode="json"),
    )
    artifact = service.comparison(store, "local", a, b)["candidate"]["target"]
    assert (
        service.gate(store, "local", a, b, policy, artifact, "test")["verdict"]
        == "inconclusive"
    )


def test_private_http_profile_runs_fresh_boundary_requests(store, tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body = json_bytes({"answer": value["question"]})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        path = tmp_path / "endpoint.json"
        path.write_bytes(
            json_bytes(
                {
                    "endpoint": f"http://127.0.0.1:{server.server_port}/v1/query",
                    "timeout": 5,
                }
            )
        )
        result = CliRunner().invoke(
            app, ["workbench", "register-http", str(path), "--name", "HTTP control"]
        )
        assert result.exit_code == 0, result.output
        target = json.loads(result.output)["target"]
        request = register(store).model_copy(
            update={"target": target, "budget_acknowledged": True}
        )
        identity = service.launch_experiment(
            store, "local", request, actor="test", key="http"
        )
        assert service.run(store, "local", identity)["passed"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("kind", ["journal", "catalog"])
def test_sqlite_sidecar_disappearance_during_open(store, monkeypatch, kind):
    from agent_eval import paths as paths_module
    from agent_eval.paths import ensure_private_file

    identity = launch(store)
    database = directory(identity) / "journal.db" if kind == "journal" else store.path
    sidecar = database.with_name(database.name + "-journal")
    ensure_private_file(sidecar)
    original = paths_module.ensure_private_file
    removed = False

    def remove_before_check(path, **kwargs):
        nonlocal removed
        if path == sidecar and not removed:
            removed = True
            sidecar.unlink()
        return original(path, **kwargs)

    monkeypatch.setattr(paths_module, "ensure_private_file", remove_before_check)
    context = Journal.open(identity) if kind == "journal" else store.db()
    with context:
        pass
    assert removed


@pytest.mark.parametrize("kind", ["journal", "catalog"])
def test_sqlite_sidecar_symlink_still_rejected(store, tmp_path, kind):
    from agent_eval.paths import UnsafeStatePathError

    identity = launch(store)
    database = directory(identity) / "journal.db" if kind == "journal" else store.path
    sidecar = database.with_name(database.name + "-journal")
    sidecar.symlink_to(tmp_path / "absent")
    context = Journal.open(identity) if kind == "journal" else store.db()
    with pytest.raises(UnsafeStatePathError), context:
        pass
