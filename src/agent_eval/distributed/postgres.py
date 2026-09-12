"""Fenced work claims and budget/outbox changes in one PostgreSQL transaction.

Receipts are boundary observations. Protected graders decide acceptance elsewhere.
Unconfirmed dispatch retains its reservation and never becomes retryable work.
"""

from __future__ import annotations

from contextlib import contextmanager

from ..blackbox.models import digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS ae_platform_version(version integer NOT NULL);
INSERT INTO ae_platform_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM ae_platform_version);
CREATE TABLE IF NOT EXISTS ae_accounts(
    tenant text PRIMARY KEY, limit_micros bigint NOT NULL CHECK(limit_micros>=0),
    reserved bigint NOT NULL DEFAULT 0 CHECK(reserved>=0), spent bigint NOT NULL DEFAULT 0 CHECK(spent>=0));
CREATE TABLE IF NOT EXISTS ae_work(
    tenant text NOT NULL REFERENCES ae_accounts(tenant), id text NOT NULL,
    payload jsonb NOT NULL, payload_sha text NOT NULL, reservation bigint NOT NULL CHECK(reservation>=0),
    state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','leased','dispatched','completed','reconciliation_required','cancelled')),
    epoch bigint NOT NULL DEFAULT 0, worker text, expires timestamptz,
    receipt jsonb, receipt_sha text, measured_micros bigint, cancel_requested boolean NOT NULL DEFAULT false,
    PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS ae_outbox(
    seq bigserial PRIMARY KEY, tenant text NOT NULL, work_id text NOT NULL,
    event jsonb NOT NULL, delivered boolean NOT NULL DEFAULT false);
"""


class LeaseLost(RuntimeError):
    pass


class Queue:
    def __init__(self, dsn):
        self.dsn = dsn

    @contextmanager
    def db(self):
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(self.dsn, row_factory=dict_row) as db:
            exists = db.execute(
                "SELECT to_regclass('ae_platform_version') AS name"
            ).fetchone()["name"]
            if exists and db.execute(
                "SELECT version FROM ae_platform_version"
            ).fetchall() != [{"version": 1}]:
                raise ValueError("unsupported PostgreSQL journal schema")
            yield db

    def migrate(self):
        with self.db() as db:
            db.execute("SELECT pg_advisory_xact_lock(824670031)")
            exists = db.execute(
                "SELECT to_regclass('ae_platform_version') AS name"
            ).fetchone()["name"]
            if exists:
                versions = db.execute(
                    "SELECT version FROM ae_platform_version"
                ).fetchall()
                if versions != [{"version": 1}]:
                    raise ValueError("unsupported PostgreSQL journal schema")
            db.execute(SCHEMA)
            for table in ("ae_accounts", "ae_work", "ae_outbox"):
                from psycopg import sql

                db.execute(
                    sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(
                        sql.Identifier(table)
                    )
                )
                db.execute(
                    sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(
                        sql.Identifier(table)
                    )
                )
                exists = db.execute(
                    "SELECT 1 FROM pg_policies WHERE tablename=%s AND policyname='tenant_scope'",
                    (table,),
                ).fetchone()
                if not exists:
                    db.execute(
                        sql.SQL(
                            "CREATE POLICY tenant_scope ON {} USING (tenant = current_user) WITH CHECK (tenant = current_user)"
                        ).format(sql.Identifier(table))
                    )

    def provision_worker(self, tenant, password):
        """Create a distinct database login, constrained to its tenant by RLS."""
        from psycopg import sql

        if not tenant or not password:
            raise ValueError("worker credentials required")
        with self.db() as db:
            db.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(tenant), sql.Literal(password)
                )
            )
            db.execute(
                sql.SQL("GRANT SELECT ON ae_platform_version TO {}").format(
                    sql.Identifier(tenant)
                )
            )
            db.execute(
                sql.SQL(
                    "GRANT SELECT,INSERT,UPDATE ON ae_accounts,ae_work,ae_outbox TO {}"
                ).format(sql.Identifier(tenant))
            )
            db.execute(
                sql.SQL(
                    "GRANT USAGE,SELECT ON SEQUENCE ae_outbox_seq_seq TO {}"
                ).format(sql.Identifier(tenant))
            )

    def account(self, tenant, limit_micros):
        if not tenant or type(limit_micros) is not int or limit_micros < 0:
            raise ValueError("invalid account")
        with self.db() as db:
            db.execute(
                "INSERT INTO ae_accounts(tenant,limit_micros) VALUES(%s,%s) ON CONFLICT(tenant) DO UPDATE SET limit_micros=excluded.limit_micros",
                (tenant, limit_micros),
            )

    def enqueue(self, tenant, identity, payload, reservation):
        from psycopg.types.json import Jsonb

        if type(reservation) is not int or reservation < 0 or not identity:
            raise ValueError("invalid reservation")
        sha = digest(payload)
        with self.db() as db:
            db.execute(
                "INSERT INTO ae_work(tenant,id,payload,payload_sha,reservation) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (tenant, identity, Jsonb(payload), sha, reservation),
            )
            row = db.execute(
                "SELECT payload_sha,reservation FROM ae_work WHERE tenant=%s AND id=%s",
                (tenant, identity),
            ).fetchone()
            if row != {"payload_sha": sha, "reservation": reservation}:
                raise ValueError("enqueue idempotency conflict")

    def event(self, db, tenant, identity, action, epoch):
        from psycopg.types.json import Jsonb

        db.execute(
            "INSERT INTO ae_outbox(tenant,work_id,event) VALUES(%s,%s,%s)",
            (tenant, identity, Jsonb({"action": action, "epoch": epoch})),
        )

    def claim(self, tenant, worker, seconds=30):
        if not worker or not 1 <= seconds <= 3600:
            raise ValueError("invalid worker lease")
        with self.db() as db:
            # All operations lock account first, then work, avoiding lock-order inversion.
            account = db.execute(
                "SELECT * FROM ae_accounts WHERE tenant=%s FOR UPDATE", (tenant,)
            ).fetchone()
            if account is None:
                raise KeyError("tenant not registered")
            row = db.execute(
                "SELECT * FROM ae_work WHERE tenant=%s AND state='queued' AND NOT cancel_requested AND reservation<=%s ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1",
                (
                    tenant,
                    account["limit_micros"] - account["reserved"] - account["spent"],
                ),
            ).fetchone()
            if row is None:
                return None
            claimed = db.execute(
                "UPDATE ae_work SET state='leased',epoch=epoch+1,worker=%s,expires=clock_timestamp()+(%s * interval '1 second') WHERE tenant=%s AND id=%s RETURNING *",
                (worker, seconds, tenant, row["id"]),
            ).fetchone()
            db.execute(
                "UPDATE ae_accounts SET reserved=reserved+%s WHERE tenant=%s",
                (row["reservation"], tenant),
            )
            self.event(db, tenant, row["id"], "leased", claimed["epoch"])
            return claimed

    def _locked(self, db, tenant, identity, worker, epoch, *, completed=False):
        db.execute(
            "SELECT tenant FROM ae_accounts WHERE tenant=%s FOR UPDATE", (tenant,)
        ).fetchone()
        row = db.execute(
            "SELECT *,expires>clock_timestamp() AS live FROM ae_work WHERE tenant=%s AND id=%s FOR UPDATE",
            (tenant, identity),
        ).fetchone()
        if not row or row["worker"] != worker or row["epoch"] != epoch:
            raise LeaseLost("worker epoch is no longer authoritative")
        if completed and row["state"] == "completed":
            return row
        if not row["live"] or row["state"] not in ("leased", "dispatched"):
            raise LeaseLost("worker lease expired")
        return row

    def heartbeat(self, tenant, identity, worker, epoch, seconds=30):
        if not 1 <= seconds <= 3600:
            raise ValueError("invalid lease duration")
        with self.db() as db:
            row = self._locked(db, tenant, identity, worker, epoch)
            db.execute(
                "UPDATE ae_work SET expires=clock_timestamp()+(%s * interval '1 second') WHERE tenant=%s AND id=%s",
                (seconds, tenant, identity),
            )
            return not row["cancel_requested"]

    def dispatch(self, tenant, identity, worker, epoch):
        with self.db() as db:
            row = self._locked(db, tenant, identity, worker, epoch)
            if row["cancel_requested"]:
                raise LeaseLost("cancellation prevents dispatch")
            if row["state"] != "leased":
                raise LeaseLost("dispatch already recorded")
            db.execute(
                "UPDATE ae_work SET state='dispatched' WHERE tenant=%s AND id=%s",
                (tenant, identity),
            )
            self.event(db, tenant, identity, "dispatched", epoch)

    def complete(self, tenant, identity, worker, epoch, receipt, measured_micros=None):
        from psycopg.types.json import Jsonb

        if measured_micros is not None and (
            type(measured_micros) is not int or measured_micros < 0
        ):
            raise ValueError("invalid measured spend")
        sha = digest(receipt)
        with self.db() as db:
            row = self._locked(db, tenant, identity, worker, epoch, completed=True)
            if row["state"] == "completed":
                if (
                    row["receipt_sha"] != sha
                    or row["measured_micros"] != measured_micros
                ):
                    raise ValueError("conflicting completion")
                return
            if row["state"] != "dispatched" or row["cancel_requested"]:
                raise LeaseLost("completion is not authoritative")
            debit = (
                measured_micros if measured_micros is not None else row["reservation"]
            )
            db.execute(
                "UPDATE ae_work SET state='completed',receipt=%s,receipt_sha=%s,measured_micros=%s WHERE tenant=%s AND id=%s",
                (Jsonb(receipt), sha, measured_micros, tenant, identity),
            )
            db.execute(
                "UPDATE ae_accounts SET reserved=reserved-%s,spent=spent+%s WHERE tenant=%s",
                (row["reservation"], debit, tenant),
            )
            self.event(db, tenant, identity, "completed", epoch)

    def defer_uncreated(self, tenant, identity, worker, epoch):
        """Release only a current claim whose API creation was definitively refused."""
        with self.db() as db:
            row = self._locked(db, tenant, identity, worker, epoch)
            db.execute(
                "UPDATE ae_accounts SET reserved=reserved-%s WHERE tenant=%s",
                (row["reservation"], tenant),
            )
            db.execute(
                "UPDATE ae_work SET state='queued',epoch=epoch+1,worker=NULL,expires=NULL WHERE tenant=%s AND id=%s",
                (tenant, identity),
            )
            self.event(db, tenant, identity, "admission_delayed", epoch + 1)

    def cancel(self, tenant, identity):
        with self.db() as db:
            db.execute(
                "SELECT tenant FROM ae_accounts WHERE tenant=%s FOR UPDATE", (tenant,)
            )
            row = db.execute(
                "SELECT * FROM ae_work WHERE tenant=%s AND id=%s FOR UPDATE",
                (tenant, identity),
            ).fetchone()
            if row is None:
                raise KeyError("work not found")
            if row["state"] in ("completed", "cancelled"):
                return row["state"]
            state = (
                "cancelled"
                if row["state"] in ("queued", "leased")
                else "reconciliation_required"
            )
            db.execute(
                "UPDATE ae_work SET cancel_requested=true,state=%s,epoch=epoch+1 WHERE tenant=%s AND id=%s",
                (state, tenant, identity),
            )
            if row["state"] == "leased":
                db.execute(
                    "UPDATE ae_accounts SET reserved=reserved-%s WHERE tenant=%s",
                    (row["reservation"], tenant),
                )
            self.event(db, tenant, identity, state, row["epoch"] + 1)
            return state

    def reconcile(self, tenant):
        with self.db() as db:
            db.execute(
                "SELECT tenant FROM ae_accounts WHERE tenant=%s FOR UPDATE", (tenant,)
            )
            rows = db.execute(
                "SELECT * FROM ae_work WHERE tenant=%s AND state IN ('leased','dispatched') AND expires<=clock_timestamp() FOR UPDATE",
                (tenant,),
            ).fetchall()
            for row in rows:
                state = (
                    "queued" if row["state"] == "leased" else "reconciliation_required"
                )
                if row["state"] == "leased":
                    db.execute(
                        "UPDATE ae_accounts SET reserved=reserved-%s WHERE tenant=%s",
                        (row["reservation"], tenant),
                    )
                db.execute(
                    "UPDATE ae_work SET state=%s,epoch=epoch+1 WHERE tenant=%s AND id=%s",
                    (state, tenant, row["id"]),
                )
                self.event(db, tenant, row["id"], state, row["epoch"] + 1)
            return len(rows)

    def status(self, tenant, identity):
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM ae_work WHERE tenant=%s AND id=%s", (tenant, identity)
            ).fetchone()
            if row is None:
                raise KeyError("work not found")
            if digest(row["payload"]) != row["payload_sha"] or (
                row["receipt"] is not None
                and digest(row["receipt"]) != row["receipt_sha"]
            ):
                raise ValueError("distributed artifact digest mismatch")
            return row

    def outbox(self, tenant, *, acknowledge=None):
        with self.db() as db:
            if acknowledge is not None:
                db.execute(
                    "UPDATE ae_outbox SET delivered=true WHERE tenant=%s AND seq=%s",
                    (tenant, acknowledge),
                )
            return db.execute(
                "SELECT seq,work_id,event FROM ae_outbox WHERE tenant=%s AND NOT delivered ORDER BY seq LIMIT 100",
                (tenant,),
            ).fetchall()
