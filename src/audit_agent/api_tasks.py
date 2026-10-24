"""API-call tasks: one investigation per distinct call between apps.

A file task audits a group of files from one repository. An API-call task follows one call across
the project instead: the frontend files that make it, the wrapper function it goes through, the
backend file that declares the route, and the handler that serves it, so Claude can check that
both sides agree. Every call site of the same endpoint from the same app shares one task. A call
that reaches no route, or uses the wrong method, gets a task of its own with the closest route's
files, so Claude can tell a real bug from dead code.

Built from the saved API map; no Claude calls.
"""

from __future__ import annotations

import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from audit_agent import store, views

PROBLEM_STATUSES = ("broken", "wrong_method")
SENSITIVE_PATH = re.compile(r"auth|login|logout|signup|register|token|password|payment|stripe|checkout|admin|wallet",
                            re.I)
MAX_WRAPPER_DEPTH = 3


@dataclass
class ApiTask:
    audit_id: int
    app_root: str | None
    key: str
    title: str
    priority: int
    priority_reason: str
    files: list[tuple[int, str, str]] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    line_count: int = 0


def _definition(name: str) -> re.Pattern:
    n = re.escape(name)
    return re.compile(
        rf"\bfunction\s+{n}\b|\b{n}\s*[:=]\s*(?:async\s*)?(?:function\b|\()|\b{n}\s*\([^)]*\)\s*(?:async\s*)?(?:\{{|=>)"
    )


class _WrapperFinder:
    """Finds the file that defines a wrapper function a call goes through, by following the
    calling file's imports (wrappers of wrappers are usually a few imports away)."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.imports: dict[int, dict[str, list[str]]] = {}
        self.texts: dict[tuple[int, str], str | None] = {}
        self.roots: dict[int, Path] = {}

    def _imports(self, audit_id: int) -> dict[str, list[str]]:
        if audit_id not in self.imports:
            graph: dict[str, list[str]] = defaultdict(list)
            for row in self.conn.execute(
                """SELECT source_path, target_path FROM inventory_relationships
                   WHERE audit_id = ? AND kind = 'internal' AND target_path IS NOT NULL""",
                (audit_id,),
            ):
                graph[row["source_path"]].append(row["target_path"])
            self.imports[audit_id] = graph
            self.roots[audit_id] = Path(store.get_audit(self.conn, audit_id)["repo_path"])
        return self.imports[audit_id]

    def _text(self, audit_id: int, path: str) -> str | None:
        if (audit_id, path) not in self.texts:
            try:
                self.texts[(audit_id, path)] = (self.roots[audit_id] / path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                self.texts[(audit_id, path)] = None
        return self.texts[(audit_id, path)]

    def find(self, audit_id: int, caller: str, name: str) -> str | None:
        graph = self._imports(audit_id)
        pattern = _definition(name)
        frontier, seen = [caller], {caller}
        for _ in range(MAX_WRAPPER_DEPTH):
            following = []
            for path in frontier:
                for target in graph.get(path, []):
                    if target in seen:
                        continue
                    seen.add(target)
                    text = self._text(audit_id, target)
                    if text and pattern.search(text):
                        return target
                    following.append(target)
            frontier = following
        text = self._text(audit_id, caller)
        return caller if text and pattern.search(text) else None


def _route_files(route: dict, role_prefix: str = "") -> list[tuple[int, str, str]]:
    files = [(route["audit_id"], route["file_path"], f"{role_prefix}route")]
    if route["handler_path"] and route["handler_path"] != route["file_path"]:
        files.append((route["audit_id"], route["handler_path"], f"{role_prefix}handler"))
    return files


def build(conn: sqlite3.Connection, project_id: int) -> list[ApiTask]:
    audit_ids = [a["id"] for a in store.project_audits(conn, project_id)]
    apps = {(a["audit_id"], a["root"]): a for a in views.app_rows(conn, audit_ids)}
    routes = {
        r["id"]: dict(r)
        for r in conn.execute(
            """SELECT r.id, r.audit_id, r.method, r.path, r.pattern, r.file_path, r.handler_path, a.repo_name
               FROM api_routes r JOIN audits a ON a.id = r.audit_id WHERE r.project_id = ?""",
            (project_id,),
        )
    }
    lines = {
        (r["audit_id"], r["path"]): r["line_count"] or 0
        for r in conn.execute(
            f"SELECT audit_id, path, line_count FROM inventory_files WHERE audit_id IN ({', '.join('?' * len(audit_ids))})",
            audit_ids,
        )
    }
    wrappers = _WrapperFinder(conn)
    groups: dict[tuple, dict] = {}
    for c in conn.execute(
        """SELECT c.audit_id, c.source_path, c.line, c.method, COALESCE(c.pattern, c.raw) AS url, c.pattern,
                  c.status, c.via, c.route_id, a.repo_name, f.app_root
           FROM api_calls c JOIN audits a ON a.id = c.audit_id
           LEFT JOIN inventory_files f ON f.audit_id = c.audit_id AND f.path = c.source_path
           WHERE c.project_id = ? AND c.status IN ('matched', 'wrong_method', 'broken')
           ORDER BY c.audit_id, c.source_path, c.line""",
        (project_id,),
    ):
        route = routes.get(c["route_id"])
        if c["status"] == "matched" and route:
            key = f"api:{c['app_root'] or '.'}:{route['method']} {route['path']}@{route['repo_name']}"
        else:
            key = f"api-{c['status']}:{c['source_path']}:{c['line']}:{c['method']} {c['url']}"
        group = groups.setdefault((c["audit_id"], key), {"calls": [], "first": c, "route": route})
        group["calls"].append(c)

    tasks = []
    for (audit_id, key), group in groups.items():
        first, route, calls = group["first"], group["route"], group["calls"]
        app = apps.get((audit_id, first["app_root"]))
        app_name = app["name"] if app else first["repo_name"]
        app_label = views.TYPE_LABELS[app["type"]] if app else "Unknown"
        status = first["status"]

        files: list[tuple[int, str, str]] = []
        for call in calls:
            files.append((audit_id, call["source_path"], "caller"))
            if call["via"] and call["via"].startswith("wrapper "):
                name = call["via"].split(" ", 1)[1]
                if (found := wrappers.find(audit_id, call["source_path"], name)) and found != call["source_path"]:
                    files.append((audit_id, found, "wrapper"))
        closest = None
        if status == "matched":
            files += _route_files(route)
        else:
            closest = route or views.closest_route(first["pattern"], first["method"], list(routes.values()))
            if closest:
                files += _route_files(closest, "closest ")
        roles: dict[tuple[int, str], str] = {}
        for file_audit, path, role in files:
            roles.setdefault((file_audit, path), role)
        files = [(file_audit, path, role) for (file_audit, path), role in roles.items()]

        call_files = len({c["source_path"] for c in calls})
        if status == "matched":
            title = f"API: {app_label} → {route['method']} {route['path']}"
            mutating = route["method"] not in ("GET", "HEAD", "OPTIONS")
            sensitive = bool(SENSITIVE_PATH.search(route["path"]))
            priority = 30 + min(5 * call_files, 30) + (20 if mutating else 0) + (15 if sensitive else 0)
            reasons = [f"{len(calls)} call site{'s' if len(calls) != 1 else ''} in {call_files} file{'s' if call_files != 1 else ''}"]
            if mutating:
                reasons.append("changes data")
            if sensitive:
                reasons.append("auth, payment, or admin path")
            reasons.append(f"handled in {route['repo_name']}: {route['handler_path'] or route['file_path']}")
        else:
            problem = "no route" if status == "broken" else "wrong method"
            title = f"API ({problem}): {app_label} → {first['method']} {first['url']}"
            priority = 110 if status == "wrong_method" else 100
            reasons = ["path exists, but not with this method" if status == "wrong_method" else "no backend route matches"]
            reasons.append(f"closest route {closest['method']} {closest['path']}" if closest else "no similar route")

        tasks.append(ApiTask(
            audit_id=audit_id,
            app_root=first["app_root"],
            key=key,
            title=title,
            priority=priority,
            priority_reason=", ".join(reasons),
            files=files,
            line_count=sum(lines.get((a, p), 0) for a, p, _ in files),
            detail={
                "status": status,
                "caller_app": app_name,
                "caller_type": app["type"] if app else "unknown",
                "calls": [{"file": c["source_path"], "line": c["line"], "method": c["method"], "url": c["url"],
                           "via": c["via"]} for c in calls],
                "route": _route_detail(route) if status == "matched" else None,
                "closest": _route_detail(closest) if closest else None,
            },
        ))
    tasks.sort(key=lambda t: (-t.priority, t.title))
    return tasks


def _route_detail(route: dict | None) -> dict | None:
    if not route:
        return None
    return {"method": route["method"], "path": route["path"], "repo": route["repo_name"],
            "file": route["file_path"], "handler": route["handler_path"]}


def plan_project(conn: sqlite3.Connection, project_id: int) -> dict[str, int]:
    """Create or refresh the project's API-call tasks from its current API map."""
    audit_ids = [a["id"] for a in store.project_audits(conn, project_id)]
    tasks = build(conn, project_id)
    counts = store.save_api_tasks(conn, audit_ids, tasks)
    return {**counts, "total": len(tasks)}
