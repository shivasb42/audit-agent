"""Local review page: `audit-agent ui` serves projects, their apps and task queues, and each
project's API map on 127.0.0.1 only. Everything shown is read from the audit database.

Write requests must send the `X-Audit-Agent` header and a JSON body. Browsers will not send a
custom header cross-origin without a CORS preflight, which this server never approves, so other
websites cannot change tasks. The Host header is checked to block DNS-rebinding attacks.
"""

from __future__ import annotations

import json
import re
import sqlite3
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from audit_agent import review, store, views

PAGE = Path(__file__).with_name("web") / "index.html"
WRITE_HEADER = "X-Audit-Agent"
MAX_BODY_BYTES = 1_000_000


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status


def _filter_from(params: dict) -> review.TaskFilter:
    def one(name: str) -> str | None:
        value = params.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        return value or None

    try:
        return review.TaskFilter(one("status"), one("folder"), one("tests"), one("search"), one("app"))
    except ValueError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc


def _ids(body: dict) -> list[int]:
    ids = body.get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
        raise ApiError(HTTPStatus.BAD_REQUEST, "body must include 'ids', a list of task ids")
    return ids


def _audits(conn: sqlite3.Connection) -> list[dict]:
    rows = []
    for audit in store.list_audits(conn):
        counts = dict(
            conn.execute(
                "SELECT status, COUNT(*) FROM audit_tasks WHERE audit_id = ? GROUP BY status", (audit["id"],)
            ).fetchall()
        )
        rows.append(
            {
                "id": audit["id"],
                "repo_name": audit["repo_name"],
                "repo_path": audit["repo_path"],
                "status": audit["status"],
                "commit": (audit["head_commit"] or "")[:12],
                "task_counts": {s: counts.get(s, 0) for s in store.TASK_STATUSES},
            }
        )
    return rows


def _audit_tasks(conn: sqlite3.Connection, audit_id: int, params: dict) -> dict:
    tasks = review.find_tasks(conn, audit_id, _filter_from(params))
    everything = review.find_tasks(conn, audit_id, review.TaskFilter(app=_filter_from(params).app))
    counts = {s: 0 for s in store.TASK_STATUSES}
    for task in everything:
        counts[task["status"]] += 1
    return {
        "audit_id": audit_id,
        "total": len(everything),
        "counts": counts,
        "tasks": [
            {k: t[k] for k in ("id", "title", "status", "priority", "priority_reason", "line_count", "file_count",
                               "test_only", "app_root")}
            for t in tasks
        ],
        "not_covered": [dict(r) for r in store.not_covered(conn, audit_id)],
    }


ROUTES_GET = [
    (re.compile(r"^/api/projects$"), lambda conn, m, q: views.project_overview(conn)),
    (re.compile(r"^/api/projects/(\d+)/api-map$"), lambda conn, m, q: views.api_map_view(conn, int(m[1]))),
    (re.compile(r"^/api/audits$"), lambda conn, m, q: _audits(conn)),
    (re.compile(r"^/api/audits/(\d+)/tasks$"), lambda conn, m, q: _audit_tasks(conn, int(m[1]), q)),
    (re.compile(r"^/api/tasks/(\d+)$"), lambda conn, m, q: views.task_detail(conn, int(m[1]))),
]

ROUTES_POST = [
    (re.compile(r"^/api/tasks/cancel$"), lambda conn, m, b: {"changed": review.cancel_tasks(conn, _ids(b))}),
    (re.compile(r"^/api/tasks/restore$"), lambda conn, m, b: {"changed": review.restore_tasks(conn, _ids(b))}),
    (
        re.compile(r"^/api/audits/(\d+)/cancel$"),
        lambda conn, m, b: {"changed": review.cancel_matching(conn, int(m[1]), _filter_from(b.get("filter") or {}))},
    ),
    (
        re.compile(r"^/api/audits/(\d+)/restore$"),
        lambda conn, m, b: {"changed": review.restore_matching(conn, int(m[1]), _filter_from(b.get("filter") or {}))},
    ),
]


class ReviewHandler(BaseHTTPRequestHandler):
    server: "ReviewServer"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, data: object) -> None:
        self._send(status, json.dumps(data).encode(), "application/json")

    def _host_allowed(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _dispatch(self, routes, path: str, payload) -> None:
        for pattern, handler in routes:
            if match := pattern.match(path):
                conn = store.connect(self.server.db_path)
                try:
                    self._json(HTTPStatus.OK, handler(conn, match, payload))
                except ApiError as exc:
                    self._json(exc.status, {"error": str(exc)})
                except store.StoreError as exc:
                    self._json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                finally:
                    conn.close()
                return
        self._json(HTTPStatus.NOT_FOUND, {"error": f"no route for {path}"})

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            return self._send(HTTPStatus.OK, PAGE.read_bytes(), "text/html; charset=utf-8")
        self._dispatch(ROUTES_GET, url.path, parse_qs(url.query))

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        if self.headers.get(WRITE_HEADER) != "1" or not self.headers.get("Content-Type", "").startswith(
            "application/json"
        ):
            return self._json(HTTPStatus.FORBIDDEN, {"error": f"write requests need {WRITE_HEADER}: 1 and a JSON body"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "body is not valid JSON"})
        if not isinstance(body, dict):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
        self._dispatch(ROUTES_POST, urlparse(self.path).path, body)


class ReviewServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, db_path: Path, port: int = 8765):
        self.db_path = db_path
        super().__init__(("127.0.0.1", port), ReviewHandler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/"


def serve(db_path: Path, port: int, open_browser: bool) -> None:
    store.connect(db_path).close()
    server = ReviewServer(db_path, port)
    print(f"Task review page: {server.url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
