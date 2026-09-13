"""Packaged loopback workbench, origin checked and authenticated on every API call."""

from __future__ import annotations

import concurrent.futures
import hmac
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from ..blackbox.models import json_bytes, parse_json
from ..experiments.journal import Journal, JournalError, request_cancel
from . import service
from .datasets import quarantine
from .models import Launch
from .store import Conflict, Denied
from .submissions import Submission, ingest


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, store, port=0, *, oidc=None):
        self.store, self.oidc = store, oidc
        self.pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="experiment"
        )
        self.jobs = {}
        self.candidate_jobs = {}
        self.jobs_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    def start_run(self, project, experiment, subject):
        service.detail(self.store, project, experiment)
        with self.jobs_lock:
            if experiment in self.jobs and not self.jobs[experiment].done():
                return

            def worker():
                self.store.authorize(subject, project, "run")
                try:
                    return service.run(self.store, project, experiment)
                except Exception:
                    with self.store.db() as db:
                        self.store.audit(
                            db,
                            project,
                            "worker",
                            "execution:attention_required",
                            experiment,
                        )
                    raise

            self.jobs[experiment] = self.pool.submit(worker)

    def start_candidate(self, project, execution, subject):
        from ..candidates.execution import evaluate

        self.store.get(project, "submission-v2", execution)
        with self.jobs_lock:
            old = self.candidate_jobs.get(execution)
            if old is not None and not old.done():
                return

            def worker():
                self.store.authorize(subject, project, "admin")
                return evaluate(self.store, project, execution)

            self.candidate_jobs[execution] = self.pool.submit(worker)

    def server_close(self):
        with self.jobs_lock:
            for identity, future in self.jobs.items():
                if not future.done():
                    request_cancel(identity)
        self.pool.shutdown(wait=True, cancel_futures=True)
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        pass  # No credentials, private paths or target output in access logs.

    def reply(self, code, value, content_type="application/json"):
        body = value if isinstance(value, bytes) else json_bytes(value)
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, mutation):
        try:
            host = self.headers.get("Host", "")
            if not hmac.compare_digest(host, urlsplit(self.server.origin).netloc):
                raise Denied("invalid host")
            origin = self.headers.get("Origin")
            if origin is not None and not hmac.compare_digest(
                origin, self.server.origin
            ):
                raise Denied("cross-origin request rejected")
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                raise Denied("cross-site request rejected")
            url = urlsplit(self.path)
            if not mutation and url.path in ("/", "/app.js", "/style.css"):
                name = {
                    "/": "index.html",
                    "/app.js": "app.js",
                    "/style.css": "style.css",
                }[url.path]
                kind = {
                    "/": "text/html; charset=utf-8",
                    "/app.js": "text/javascript; charset=utf-8",
                    "/style.css": "text/css; charset=utf-8",
                }[url.path]
                return self.reply(
                    200,
                    files("agent_eval.workbench").joinpath("ui", name).read_bytes(),
                    kind,
                )
            if not url.path.startswith("/v1/"):
                return self.reply(404, {"error": "not found"})
            authorization = self.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                raise Denied("bearer credential required")
            token = authorization[7:]
            store = self.server.store
            subject = (
                self.server.oidc.authenticate(token)
                if self.server.oidc
                else store.authenticate(token)
            )
            project = self.headers.get("X-Project", "local")
            store.authorize(subject, project, "read")
            query = parse_qs(url.query, max_num_fields=10)
            if any(len(v) != 1 for v in query.values()):
                raise ValueError("duplicate query parameter")
            query = {k: v[0] for k, v in query.items()}
            path = url.path.split("/")[2:]
            data = None
            if mutation:
                if (
                    self.headers.get("Transfer-Encoding")
                    or self.headers.get_content_type() != "application/json"
                ):
                    raise ValueError("JSON content length required")
                length = int(self.headers.get("Content-Length", "0"))
                maximum = (
                    20 * 1024 * 1024 if path == ["producer-artifacts"] else 1024 * 1024
                )
                if not 0 < length <= maximum:
                    raise ValueError("request size outside bounds")
                data = parse_json(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("object required")
            result, code = self.route(
                store, subject, project, path, query, data, mutation
            )
            if path == ["events"] and "text/event-stream" in self.headers.get(
                "Accept", ""
            ):
                body = "".join(
                    f"id: {event['seq']}\ndata: {json_bytes(event).decode()}\n\n"
                    for event in result
                )
                return self.reply(code, body.encode(), "text/event-stream")
            self.reply(code, result)
        except Denied as exc:
            self.reply(403, {"error": str(exc)})
        except Conflict as exc:
            self.reply(409, {"error": str(exc)})
        except (KeyError, FileNotFoundError):
            self.reply(404, {"error": "not found or retained evidence expired"})
        except (ValueError, TypeError, IndexError):
            self.reply(400, {"error": "invalid request"})
        except JournalError:
            self.reply(
                409,
                {"error": "evidence unavailable, changed or worker requires attention"},
            )
        except Exception:
            self.reply(500, {"error": "operation failed; private details omitted"})

    def route(self, store, subject, project, path, query, data, mutation):
        from ..candidates import authority
        from ..candidates import contracts as candidate_contracts
        from ..candidates import studies

        if not mutation:
            if path == ["authority"]:
                return {
                    "contract_version": 2,
                    "evaluator_sha256": authority.identity(),
                }, 200
            if len(path) == 2 and path[0] in (
                "execution-contracts",
                "trial-tickets",
                "assessments",
                "submissions",
            ):
                kind = {
                    "trial-tickets": "trial-ticket-v2",
                    "execution-contracts": "execution-v2",
                    "assessments": "assessment-v2",
                    "submissions": "submission-v2",
                }[path[0]]
                return store.get(project, kind, path[1]), 200
            if path == ["candidate-runs"]:
                return store.list(
                    project, "trial-ticket-v2", after=query.get("after", "")
                ), 200
            if path == ["studies"]:
                return store.list(
                    project, "candidate-study", after=query.get("after", "")
                ), 200
            if len(path) == 2 and path[0] == "studies":
                return studies.study_report(store, project, path[1]), 200
            if len(path) == 3 and path[0] == "studies" and path[2] == "export":
                from ..candidates.bundles import export_bundle

                store.authorize(subject, project, "curate")
                return export_bundle(store, project, path[1]), 200
            if (
                len(path) == 3
                and path[0] == "candidate-runs"
                and path[2] == "investigate"
            ):
                from ..candidates.investigation import investigate

                store.authorize(subject, project, "curate")
                return investigate(store, project, path[1]), 200
            if path == ["experiments"]:
                page = store.list(
                    project,
                    "experiment",
                    after=query.get("after", ""),
                    limit=int(query.get("limit", "50")),
                )
                for item in page["items"]:
                    try:
                        item["value"] = service.detail(store, project, item["id"])
                    except (JournalError, FileNotFoundError):
                        item["value"] = {
                            "experiment_id": item["id"],
                            "state": "evidence_unavailable",
                            "passed": None,
                        }
                return page, 200
            if path in (["targets"], ["datasets"], ["policies"]):
                kind = {
                    "targets": "target",
                    "datasets": "dataset",
                    "policies": "policy",
                }[path[0]]
                page = store.list(
                    project,
                    kind,
                    after=query.get("after", ""),
                    limit=int(query.get("limit", "50")),
                )
                for item in page["items"]:
                    v = item["value"]
                    if kind == "target":
                        item["value"] = {
                            k: v[k]
                            for k in (
                                "name",
                                "model_calls",
                                "identity_provenance",
                                "max_invocations",
                                "world",
                            )
                        }
                    elif kind == "dataset":
                        item["value"] = {
                            "name": v["suite"]["id"],
                            "split": v["split"],
                            "cases": len(v["suite"]["cases"]),
                        }
                return page, 200
            if path == ["review"]:
                return store.review_queue(project, int(query.get("after", "0"))), 200
            if path == ["events"]:
                return store.events(
                    project,
                    int(query.get("after", self.headers.get("Last-Event-ID", "0"))),
                ), 200
            if path == ["comparisons"]:
                result = service.comparison(
                    store, project, query["baseline"], query["candidate"]
                )
                # Full outputs belong to the selected trial view, not list payloads.
                for arm in ("baseline", "candidate"):
                    result[arm].pop("records")
                return result, 200
            if len(path) == 2 and path[0] == "experiments":
                return service.detail(store, project, path[1]), 200
            if len(path) == 4 and path[0] == "experiments" and path[2] == "trials":
                return service.trial_detail(store, project, path[1], int(path[3])), 200
            if len(path) == 2 and path[0] == "decisions":
                return store.get(project, "decision", path[1]), 200
        else:
            if path == ["studies"]:
                store.authorize(subject, project, "admin")
                return studies.reserve_study(
                    store, project, studies.StudyPlan.model_validate(data), subject
                ), 201
            if path == ["production-failures"]:
                store.authorize(subject, project, "run")
                return {
                    "execution_id": authority.record_failure(
                        store, project, data, subject
                    )
                }, 201
            if len(path) == 3 and path[0] == "studies" and path[2] == "policy-preview":
                from ..candidates.bundles import compare_policy, export_bundle

                store.authorize(subject, project, "curate")
                if set(data) - {"max_latency_ms", "max_total_tokens", "max_cost_usd"}:
                    raise ValueError("unsupported policy limit")
                return compare_policy(
                    export_bundle(store, project, path[1]), **data
                ), 200
            if path == ["producer-artifacts"]:
                store.authorize(subject, project, "run")
                return authority.upload(
                    store,
                    project,
                    candidate_contracts.ArtifactEnvelope.model_validate(data),
                    subject,
                ), 201
            if path == ["trial-tickets"]:
                store.authorize(subject, project, "admin")
                return authority.reserve(
                    store,
                    project,
                    candidate_contracts.TrialTicket.model_validate(data),
                    subject,
                ), 201
            if path == ["execution-contracts"]:
                store.authorize(subject, project, "admin")
                return authority.issue(
                    store,
                    project,
                    candidate_contracts.ExecutionContract.model_validate(data),
                    subject,
                ), 201
            if len(path) == 3 and path[0] == "submissions" and path[2] == "evaluate":
                store.authorize(subject, project, "admin")
                self.server.start_candidate(project, path[1], subject)
                return {"execution_id": path[1], "status": "evaluation_queued"}, 202
            if path in (["preview"], ["experiments"]):
                store.authorize(subject, project, "run")
                launch = Launch.model_validate(data)
                if path == ["preview"]:
                    return service.preview(store, project, launch), 200
                identity = service.launch_experiment(
                    store,
                    project,
                    launch,
                    actor=subject,
                    key=self.headers.get("Idempotency-Key"),
                )
                return {"experiment_id": identity}, 201
            if (
                len(path) == 3
                and path[0] == "experiments"
                and path[2] in ("start", "cancel")
            ):
                store.authorize(subject, project, "run")
                store.get(project, "experiment", path[1])
                if path[2] == "start":
                    self.server.start_run(project, path[1], subject)
                else:
                    request_cancel(path[1])
                    self.server.start_run(project, path[1], subject)
                return {
                    "experiment_id": path[1],
                    "request": path[2],
                    "status": "pending",
                }, 202
            if (
                len(path) == 5
                and path[0] == "experiments"
                and path[2] == "trials"
                and path[4] == "annotations"
            ):
                store.authorize(subject, project, "annotate")
                store.get(project, "experiment", path[1])
                with Journal.open(path[1]) as journal:
                    journal.row(int(path[3]))
                revision = store.annotate(
                    project,
                    path[1],
                    int(path[3]),
                    data["body"],
                    actor=subject,
                    expected_revision=data["expected_revision"],
                )
                return {"revision": revision}, 201
            if path == ["decisions"]:
                store.authorize(subject, project, "admin")
                return service.gate(
                    store,
                    project,
                    data["baseline"],
                    data["candidate"],
                    data["policy"],
                    data["candidate_artifact"],
                    subject,
                ), 201
            if path == ["quarantine"]:
                store.authorize(subject, project, "curate")
                return {
                    "id": quarantine(
                        store,
                        project,
                        data["input"],
                        data["expected"],
                        origin=data["origin"],
                        actor=subject,
                    )
                }, 201
            if path == ["submissions"]:
                store.authorize(subject, project, "run")
                if data.get("schema_version") == "agent-eval.submission/v2":
                    return authority.ingest(
                        store,
                        project,
                        candidate_contracts.Submission.model_validate(data),
                        subject,
                    ), 201
                return ingest(
                    store, project, Submission.model_validate(data), subject
                ), 201
        return {"error": "not found"}, 404
