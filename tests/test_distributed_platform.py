"""Real PostgreSQL races, fences, tenant roles and budget reconciliation."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_eval.blackbox.models import digest
from agent_eval.distributed.kubernetes import job, pod_receipt
from agent_eval.distributed.postgres import LeaseLost, Queue
from agent_eval.distributed.worker import work_once
from agent_eval.experiments.models import CommandSpec
from agent_eval.experiments.service import make_target


@pytest.fixture(scope="module")
def database(tmp_path_factory):
    pytest.importorskip("psycopg")
    initdb, postgres = shutil.which("initdb"), shutil.which("postgres")
    if not initdb or not postgres:
        pytest.skip("local PostgreSQL server binaries unavailable")
    import tempfile
    from pathlib import Path

    root = Path(
        tempfile.mkdtemp(
            prefix="ae-pg-", dir="/private/tmp" if sys.platform == "darwin" else "/tmp"
        )
    )
    data = root / "data"
    result = subprocess.run(
        [initdb, "-D", str(data), "-A", "trust", "--no-locale", "--encoding=UTF8"],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    logfile = (root / "postgres.log").open("wb")
    process = subprocess.Popen(
        [postgres, "-D", str(data), "-k", str(root), "-p", str(port), "-h", ""],
        stdout=logfile,
        stderr=logfile,
    )
    dsn = f"host={root} port={port} dbname=postgres user={os.environ.get('USER', 'postgres')}"
    import time
    import psycopg

    for _ in range(100):
        try:
            with psycopg.connect(dsn):
                break
        except psycopg.OperationalError:
            time.sleep(0.05)
    else:
        process.terminate()
        raise RuntimeError("PostgreSQL did not start")
    queue = Queue(dsn)
    queue.migrate()
    yield queue, root, port
    process.terminate()
    process.wait(timeout=15)
    logfile.close()
    shutil.rmtree(root)


@pytest.fixture
def queue(database):
    queue, _, _ = database
    with queue.db() as db:
        db.execute("TRUNCATE ae_outbox,ae_work,ae_accounts RESTART IDENTITY")
    queue.account("a", 100)
    queue.account("b", 100)
    return queue


def expire(queue, identity):
    with queue.db() as db:
        db.execute(
            "UPDATE ae_work SET expires=clock_timestamp()-interval '1 second' WHERE tenant='a' AND id=%s",
            (identity,),
        )


def test_racing_workers_one_authority_and_idempotent_completion(queue):
    queue.enqueue("a", "trial", {"input": "public"}, 30)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(
            pool.map(lambda worker: queue.claim("a", worker), ["worker-1", "worker-2"])
        )
    assert sum(c is not None for c in claims) == 1
    claim = next(c for c in claims if c)
    args = ("a", "trial", claim["worker"], claim["epoch"])
    queue.dispatch(*args)
    receipt = {"output": "ok"}
    queue.complete(*args, receipt, measured_micros=12)
    queue.complete(*args, receipt, measured_micros=12)
    with pytest.raises(ValueError):
        queue.complete(*args, {"output": "different"}, measured_micros=12)
    with queue.db() as db:
        assert db.execute(
            "SELECT reserved,spent FROM ae_accounts WHERE tenant='a'"
        ).fetchone() == {"reserved": 0, "spent": 12}
    events = queue.outbox("a")
    assert [r["event"]["action"] for r in events] == [
        "leased",
        "dispatched",
        "completed",
    ]
    queue.outbox("b", acknowledge=events[-1]["seq"])
    assert len(queue.outbox("a")) == 3
    queue.outbox("a", acknowledge=events[-1]["seq"])
    assert len(queue.outbox("a")) == 2


def test_expired_predispatch_safe_requeue_but_dispatched_reconciles(queue):
    queue.enqueue("a", "one", {"input": "x"}, 60)
    old = queue.claim("a", "old")
    expire(queue, "one")
    assert queue.reconcile("a") == 1
    new = queue.claim("a", "new")
    assert new["epoch"] > old["epoch"]
    with pytest.raises(LeaseLost):
        queue.dispatch("a", "one", "old", old["epoch"])
    queue.dispatch("a", "one", "new", new["epoch"])
    expire(queue, "one")
    queue.reconcile("a")
    assert queue.status("a", "one")["state"] == "reconciliation_required"
    assert queue.claim("a", "third") is None
    with pytest.raises(LeaseLost):
        queue.complete("a", "one", "new", new["epoch"], {"output": "late"})
    with queue.db() as db:
        assert (
            db.execute("SELECT reserved FROM ae_accounts WHERE tenant='a'").fetchone()[
                "reserved"
            ]
            == 60
        )


def test_concurrent_budgets_cancellation_and_unknown_usage(queue):
    for identity in ("one", "two"):
        queue.enqueue("a", identity, {"id": identity}, 70)
    a = queue.claim("a", "one")
    assert queue.claim("a", "two") is None
    assert queue.cancel("a", a["id"]) == "cancelled"
    b = queue.claim("a", "two")
    assert b is not None
    queue.dispatch("a", b["id"], "two", b["epoch"])
    assert queue.cancel("a", b["id"]) == "reconciliation_required"
    with pytest.raises(LeaseLost):
        queue.complete("a", b["id"], "two", b["epoch"], {"done": True})
    with queue.db() as db:
        assert (
            db.execute("SELECT reserved FROM ae_accounts WHERE tenant='a'").fetchone()[
                "reserved"
            ]
            == 70
        )
    queue.enqueue("b", "third", {}, 100)
    c = queue.claim("b", "worker")
    queue.dispatch("b", "third", "worker", c["epoch"])
    queue.complete("b", "third", "worker", c["epoch"], {"done": True})
    with queue.db() as db:
        assert db.execute(
            "SELECT reserved,spent FROM ae_accounts WHERE tenant='b'"
        ).fetchone() == {"reserved": 0, "spent": 100}


def test_actual_worker_receipt_and_corruption(queue):
    spec = CommandSpec(
        argv=[sys.executable, "-c", "import sys;print(sys.stdin.read())"]
    )
    payload = {
        "schema_version": "agent-eval.remote-invocation/v1",
        "command": spec.model_dump(mode="json"),
        "command_sha256": make_target(spec).identity,
        "input": "public-only",
    }
    queue.enqueue("a", "echo", payload, 20)
    assert work_once(queue, "a", "worker") == "echo"
    receipt = queue.status("a", "echo")["receipt"]
    assert receipt["actual_output"] == "public-only\n"
    assert receipt["input_sha256"] == digest("public-only")
    assert receipt["usage"]["cost_usd"] is None
    with queue.db() as db:
        db.execute("UPDATE ae_work SET receipt_sha='corrupt' WHERE tenant='a'")
    with pytest.raises(ValueError):
        queue.status("a", "echo")


def test_database_enforced_tenant_roles(queue, database):
    import psycopg

    _, root, port = database
    queue.account("platform_worker_a", 100)
    queue.provision_worker("platform_worker_a", "disposable-test-password")
    queue.enqueue("a", "secret", {"secret": "other tenant"}, 1)
    scoped = Queue(f"host={root} port={port} dbname=postgres user=platform_worker_a")
    with scoped.db() as db:
        assert db.execute("SELECT * FROM ae_work WHERE tenant='a'").fetchall() == []
        assert (
            db.execute("UPDATE ae_accounts SET reserved=0 WHERE tenant='a'").rowcount
            == 0
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute(
                "INSERT INTO ae_work(tenant,id,payload,payload_sha,reservation) VALUES('a','forged','{}','x',0)"
            )
    scoped.enqueue("platform_worker_a", "own", {"ok": True}, 10)
    assert scoped.claim("platform_worker_a", "worker")["id"] == "own"
    with pytest.raises(KeyError):
        scoped.claim("a", "worker")


def test_newer_database_schema_rejected(queue):
    with queue.db() as db:
        db.execute("UPDATE ae_platform_version SET version=999")
    try:
        with pytest.raises(ValueError, match="schema"):
            queue.migrate()
    finally:
        import psycopg

        with psycopg.connect(queue.dsn) as db:
            db.execute("UPDATE ae_platform_version SET version=1")


def test_kubernetes_profiles_are_immutable_restricted_and_observed():
    spec = job(
        execution_id="fixture",
        image="busybox@sha256:" + "a" * 64,
        command=["echo", "ok"],
    )
    pod = spec["spec"]["template"]["spec"]
    assert spec["spec"]["backoffLimit"] == 0
    assert not pod["automountServiceAccountToken"]
    assert pod["containers"][0]["securityContext"]["capabilities"]["drop"] == ["ALL"]
    with pytest.raises(ValueError):
        job(execution_id="fixture", image="busybox:latest", command=["echo", "ok"])
    receipt = pod_receipt(
        {
            "metadata": {"uid": "pod-one"},
            "status": {
                "phase": "Failed",
                "containerStatuses": [
                    {
                        "name": "target",
                        "imageID": "actual-digest",
                        "state": {"terminated": {"reason": "OOMKilled"}},
                    }
                ],
            },
        }
    )
    assert receipt["containers"][0]["state"]["terminated"]["reason"] == "OOMKilled"


def test_local_journal_distributed_round_trip(queue, tmp_path, monkeypatch):
    from agent_eval.workbench.store import Store
    from agent_eval.workbench.models import TargetProfile, Launch
    from agent_eval.workbench.datasets import Dataset, register_dataset
    from agent_eval.workbench.service import launch_experiment
    from agent_eval.blackbox.models import Suite, Case, Metric
    from agent_eval.distributed.bridge import enqueue_experiment, collect_experiment
    from agent_eval.experiments.journal import Journal

    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    store = Store()
    suite = Suite(
        schema_version="1.0",
        id="remote",
        version="1",
        metrics=[Metric(name="exact", kind="exact_match")],
        cases=[Case(id="echo", input="public", expected_output="public")],
    )
    dataset = Dataset(
        suite=suite,
        split="regression",
        origin="fixture",
        license="Apache-2.0",
        reviewed_by="test",
        families={"echo": "echo"},
    )
    dataset_id = register_dataset(store, "a", dataset, "test")
    spec = CommandSpec(
        argv=[sys.executable, "-c", "import sys;sys.stdout.write(sys.stdin.read())"]
    )
    profile = TargetProfile(name="echo", command=spec, model_calls="none")
    target = store.put("a", "target", profile.model_dump(mode="json"))
    experiment = launch_experiment(
        store,
        "a",
        Launch(target=target, dataset=dataset_id),
        actor="test",
        key="remote",
    )
    enqueue_experiment(store, "a", experiment, queue, reservation_micros=20)
    enqueue_experiment(store, "a", experiment, queue, reservation_micros=20)
    with Journal.open(experiment) as journal:
        attempt = journal.rows()[0]["attempt_id"]
    assert work_once(queue, "a", "remote-worker") == attempt
    assert collect_experiment(store, "a", experiment, queue)["passed"] is True
    assert collect_experiment(store, "a", experiment, queue)["passed"] is True
    assert queue.claim("a", "unexpected") is None


def test_postgres_backup_restore_preserves_receipts_and_budget(
    queue, database, tmp_path
):
    pg_dump, pg_restore = shutil.which("pg_dump"), shutil.which("pg_restore")
    if not pg_dump or not pg_restore:
        pytest.skip("PostgreSQL backup binaries unavailable")
    import psycopg

    queue.enqueue("a", "restored-trial", {"public": "input"}, 20)
    claim = queue.claim("a", "worker")
    queue.dispatch("a", "restored-trial", "worker", claim["epoch"])
    queue.complete("a", "restored-trial", "worker", claim["epoch"], {"output": "ok"}, 7)
    before = queue.status("a", "restored-trial")
    dump = tmp_path / "database.dump"
    result = subprocess.run(
        [pg_dump, "--format=custom", "--file", str(dump), "--dbname", queue.dsn],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode()
    with psycopg.connect(queue.dsn, autocommit=True) as db:
        db.execute("CREATE DATABASE platform_restored")
    restored = Queue(queue.dsn.replace("dbname=postgres", "dbname=platform_restored"))
    result = subprocess.run(
        [pg_restore, "--exit-on-error", "--dbname", restored.dsn, str(dump)],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode()
    after = restored.status("a", "restored-trial")
    assert before["receipt_sha"] == after["receipt_sha"]
    with restored.db() as db:
        assert db.execute(
            "SELECT reserved,spent FROM ae_accounts WHERE tenant='a'"
        ).fetchone() == {"reserved": 0, "spent": 7}
        assert (
            db.execute(
                "SELECT count(*) AS n FROM ae_work WHERE state='completed'"
            ).fetchone()["n"]
            == 1
        )


def test_kubernetes_worker_binds_job_to_current_lease(queue, monkeypatch):
    from agent_eval.distributed import kubernetes

    manifest = job(
        execution_id="queued-job",
        image="busybox@sha256:" + "a" * 64,
        command=["echo", "ok"],
    )
    queue.enqueue(
        "a",
        "queued-job",
        {"schema_version": "agent-eval.remote-job/v1", "job": manifest},
        20,
    )
    old = queue.claim("a", "old")
    expire(queue, "queued-job")
    queue.reconcile("a")
    captured = []

    def execute(manifest, *, context, cancelled):
        assert context == "explicit-fixture-context" and not cancelled()
        captured.append(manifest)
        return {
            "job_uid": "owned-job",
            "pods": [{"phase": "Succeeded"}],
            "outputs": [{"stdout": "ok"}],
        }

    monkeypatch.setattr(kubernetes, "execute_job", execute)
    monkeypatch.setattr(kubernetes, "cleanup_job", lambda **kwargs: True)
    assert (
        work_once(queue, "a", "controller", kube_context="explicit-fixture-context")
        == "queued-job"
    )
    row = queue.status("a", "queued-job")
    assert row["epoch"] > old["epoch"]
    assert int(captured[0]["metadata"]["labels"]["agent-eval/epoch"]) == row["epoch"]
    assert row["receipt"]["payload_sha256"] == digest(
        {"schema_version": "agent-eval.remote-job/v1", "job": manifest}
    )
    assert queue.claim("a", "extra") is None


def test_confirmed_quota_rejection_defers_without_spending(queue, monkeypatch):
    from agent_eval.distributed import kubernetes

    manifest = job(
        execution_id="quota-job",
        image="busybox@sha256:" + "a" * 64,
        command=["echo", "ok"],
    )
    queue.enqueue(
        "a",
        "quota-job",
        {"schema_version": "agent-eval.remote-job/v1", "job": manifest},
        50,
    )

    def reject(*args, **kwargs):
        raise kubernetes.AdmissionDelayed("quota")

    monkeypatch.setattr(kubernetes, "execute_job", reject)
    assert work_once(queue, "a", "controller", kube_context="fixture") is None
    record = queue.status("a", "quota-job")
    assert record["state"] == "queued" and record["receipt"] is None
    with queue.db() as db:
        assert db.execute(
            "SELECT reserved,spent FROM ae_accounts WHERE tenant='a'"
        ).fetchone() == {"reserved": 0, "spent": 0}
    assert queue.claim("a", "next")["epoch"] > record["epoch"]


def test_job_cleanup_uses_uid_precondition(monkeypatch):
    from agent_eval.distributed.kubernetes import cleanup_job
    import json

    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)
    uid = "12345678-1234-1234-1234-123456789abc"
    assert cleanup_job(context="fixture", name="eval-owned-1", uid=uid)
    assert json.loads(calls[0][1]["input"])["preconditions"] == {"uid": uid}
    with pytest.raises(ValueError):
        cleanup_job(context="fixture", name="../other", uid=uid)
