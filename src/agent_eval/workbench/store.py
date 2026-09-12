"""Private, transactional catalog. Experiment evidence stays in its own journal."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

from ..blackbox.models import digest, json_bytes, parse_json
from ..experiments.journal import JournalError
from ..paths import (
    ensure_private_directory,
    ensure_private_file,
    ensure_private_sqlite_sidecar,
    get_state_dir,
)

ROLES = {
    "viewer": {"read"},
    "runner": {"read", "run", "annotate"},
    "curator": {"read", "annotate", "curate"},
    "admin": {"read", "run", "annotate", "curate", "admin"},
}


class Conflict(JournalError):
    pass


class Denied(JournalError):
    pass


class Store:
    def __init__(self):
        root = ensure_private_directory(get_state_dir() / "workbench", parents=True)
        self.path = ensure_private_file(root / "catalog.db")
        with self.db() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise JournalError("unsupported catalog schema")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS records (
                    project TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
                    body TEXT NOT NULL, sha TEXT NOT NULL, created REAL NOT NULL,
                    PRIMARY KEY(project,kind,id));
                CREATE UNIQUE INDEX IF NOT EXISTS experiment_owner ON records(id) WHERE kind='experiment';
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY, project TEXT NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT NOT NULL,
                    created REAL NOT NULL, previous TEXT NOT NULL, sha TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS annotations (
                    project TEXT NOT NULL, experiment TEXT NOT NULL, ordinal INTEGER NOT NULL,
                    revision INTEGER NOT NULL, actor TEXT NOT NULL, body TEXT NOT NULL,
                    created REAL NOT NULL, PRIMARY KEY(project,experiment,ordinal,revision));
                CREATE TABLE IF NOT EXISTS requests (
                    project TEXT NOT NULL, key TEXT NOT NULL, sha TEXT NOT NULL,
                    object_id TEXT NOT NULL, PRIMARY KEY(project,key));
                CREATE TABLE IF NOT EXISTS members (
                    project TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL,
                    PRIMARY KEY(project,subject));
                CREATE TABLE IF NOT EXISTS tokens (
                    sha TEXT PRIMARY KEY, subject TEXT NOT NULL, expires REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0);
                PRAGMA user_version=1;
            """)

    @contextmanager
    def db(self):
        for suffix in ("-journal", "-wal", "-shm"):
            path = self.path.with_name(self.path.name + suffix)
            ensure_private_sqlite_sidecar(path)
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA synchronous=FULL")
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def audit(self, db, project, actor, action, object_id):
        last = db.execute("SELECT sha FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        previous = last[0] if last else "0" * 64
        created = time.time()
        value = [project, actor, action, object_id, created, previous]
        db.execute(
            "INSERT INTO events(project,actor,action,object_id,created,previous,sha) VALUES(?,?,?,?,?,?,?)",
            (*value, digest(value)),
        )

    def verify_audit(self):
        previous = "0" * 64
        with self.db() as db:
            rows = db.execute("SELECT * FROM events ORDER BY seq").fetchall()
            for row in rows:
                value = [
                    row[k]
                    for k in (
                        "project",
                        "actor",
                        "action",
                        "object_id",
                        "created",
                        "previous",
                    )
                ]
                if row["previous"] != previous or digest(value) != row["sha"]:
                    raise JournalError("audit chain mismatch")
                previous = row["sha"]
        return {"events": len(rows), "head": previous}

    def put(self, project, kind, value, *, actor="local", object_id=None, db=None):
        identity = object_id or digest(value)
        if db is None:
            with self.db() as connection:
                return self.put(
                    project, kind, value, actor=actor, object_id=identity, db=connection
                )
        body = json_bytes(value).decode()
        if len(body) > 4 * 1024 * 1024:
            raise ValueError("catalog record too large")
        old = db.execute(
            "SELECT sha FROM records WHERE project=? AND kind=? AND id=?",
            (project, kind, identity),
        ).fetchone()
        if old:
            if old[0] != digest(value):
                raise Conflict("immutable record conflict")
            return identity
        db.execute(
            "INSERT INTO records VALUES (?,?,?,?,?,?)",
            (project, kind, identity, body, digest(value), time.time()),
        )
        self.audit(db, project, actor, f"create:{kind}", identity)
        return identity

    def get(self, project, kind, identity, *, db=None):
        if db is None:
            with self.db() as connection:
                return self.get(project, kind, identity, db=connection)
        row = db.execute(
            "SELECT body,sha FROM records WHERE project=? AND kind=? AND id=?",
            (project, kind, identity),
        ).fetchone()
        if row is None:
            raise KeyError("record not found")
        value = parse_json(row[0])
        if digest(value) != row[1]:
            raise JournalError("catalog digest mismatch")
        return value

    def list(self, project, kind, *, after="", limit=50):
        if not 1 <= limit <= 200:
            raise ValueError("invalid page size")
        with self.db() as db:
            rows = db.execute(
                "SELECT id,created FROM records WHERE project=? AND kind=? AND id>? ORDER BY id LIMIT ?",
                (project, kind, after, limit + 1),
            ).fetchall()
            items = [
                {
                    "id": r[0],
                    "created": r[1],
                    "value": self.get(project, kind, r[0], db=db),
                }
                for r in rows[:limit]
            ]
        return {
            "items": items,
            "next": rows[limit - 1][0] if len(rows) > limit else None,
        }

    def annotate(self, project, experiment, ordinal, body, *, actor, expected_revision):
        if (
            not isinstance(body, str)
            or not body.strip()
            or len(body) > 10000
            or ordinal < 0
        ):
            raise ValueError("invalid annotation")
        with self.db() as db:
            self.get(project, "experiment", experiment, db=db)
            current = db.execute(
                "SELECT COALESCE(MAX(revision),0) FROM annotations WHERE project=? AND experiment=? AND ordinal=?",
                (project, experiment, ordinal),
            ).fetchone()[0]
            if current != expected_revision:
                raise Conflict("annotation changed; reload before editing")
            db.execute(
                "INSERT INTO annotations VALUES (?,?,?,?,?,?,?)",
                (project, experiment, ordinal, current + 1, actor, body, time.time()),
            )
            self.audit(db, project, actor, "annotate", experiment)
            return current + 1

    def annotations(self, project, experiment, ordinal):
        with self.db() as db:
            self.get(project, "experiment", experiment, db=db)
            return [
                dict(r)
                for r in db.execute(
                    "SELECT revision,actor,body,created FROM annotations WHERE project=? AND experiment=? AND ordinal=? ORDER BY revision",
                    (project, experiment, ordinal),
                )
            ]

    def events(self, project, after=0):
        with self.db() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT seq,action,object_id,created FROM events WHERE project=? AND seq>? ORDER BY seq LIMIT 200",
                    (project, after),
                )
            ]

    def grant(self, project, subject, role):
        if role not in ROLES or not project or not subject:
            raise ValueError("invalid membership")
        with self.db() as db:
            db.execute(
                "INSERT INTO members VALUES(?,?,?) ON CONFLICT(project,subject) DO UPDATE SET role=excluded.role",
                (project, subject, role),
            )
            self.audit(db, project, "operator", "membership", subject)

    def token(self, subject, seconds=3600):
        if not 1 <= seconds <= 86400:
            raise ValueError("token lifetime outside bounds")
        value = secrets.token_urlsafe(32)
        with self.db() as db:
            db.execute(
                "INSERT INTO tokens VALUES(?,?,?,0)",
                (
                    hashlib.sha256(value.encode()).hexdigest(),
                    subject,
                    time.time() + seconds,
                ),
            )
        return value

    def authenticate(self, token):
        with self.db() as db:
            row = db.execute(
                "SELECT subject FROM tokens WHERE sha=? AND expires>? AND revoked=0",
                (hashlib.sha256(token.encode()).hexdigest(), time.time()),
            ).fetchone()
        if row is None:
            raise Denied("credential expired, revoked or invalid")
        return row[0]

    def revoke(self, subject):
        with self.db() as db:
            db.execute("UPDATE tokens SET revoked=1 WHERE subject=?", (subject,))
            self.audit(db, "system", "operator", "revoke", subject)

    def authorize(self, subject, project, action):
        with self.db() as db:
            row = db.execute(
                "SELECT role FROM members WHERE project=? AND subject=?",
                (project, subject),
            ).fetchone()
        if row is None or action not in ROLES.get(row[0], set()):
            raise Denied("project access denied")

    def new_id(self):
        return str(uuid.uuid4())

    def review_queue(self, project, after=0):
        with self.db() as db:
            return [
                dict(row)
                for row in db.execute(
                    """
                SELECT a.rowid AS cursor,a.experiment,a.ordinal,a.revision,a.actor,a.body,a.created
                FROM annotations a WHERE a.project=? AND a.rowid>?
                AND a.revision=(SELECT MAX(b.revision) FROM annotations b WHERE b.project=a.project AND b.experiment=a.experiment AND b.ordinal=a.ordinal)
                ORDER BY a.rowid LIMIT 100
            """,
                    (project, after),
                )
            ]
