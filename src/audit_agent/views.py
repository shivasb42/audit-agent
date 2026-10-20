"""Text and JSON views of a stored inventory. Everything here reads from the database."""

from __future__ import annotations

import sqlite3

from audit_agent import store

SECTION_COLUMNS = {
    "files": ["path", "category", "language", "supported", "line_count", "size_bytes", "note"],
    "modules": ["path", "package_root", "languages", "file_count", "line_count"],
    "dependencies": ["manifest_path", "ecosystem", "name", "version_spec", "scope"],
    "entry-points": ["kind", "path", "source_path", "detail"],
    "relationships": ["source_path", "line", "kind", "specifier", "target_path", "target_package"],
    "unsupported": ["technology", "kind", "file_count", "evidence_path", "reason"],
    "skipped": ["reason", "file_count", "example_path"],
}


def _counts(conn: sqlite3.Connection, sql: str, audit_id: int) -> list[sqlite3.Row]:
    return conn.execute(sql, (audit_id,)).fetchall()


def _join_counts(rows: list[sqlite3.Row]) -> str:
    return ", ".join(f"{row[0]} {row[1]}" for row in rows) or "none"


def summary(conn: sqlite3.Connection, audit_id: int) -> dict:
    audit = store.get_audit(conn, audit_id)

    def one(sql: str) -> int:
        return conn.execute(sql, (audit_id,)).fetchone()[0]

    return {
        "audit": dict(audit),
        "files_by_category": {
            r["category"]: r["n"]
            for r in _counts(
                conn,
                "SELECT category, COUNT(*) AS n FROM inventory_files WHERE audit_id = ? GROUP BY category ORDER BY n DESC",
                audit_id,
            )
        },
        "languages": [
            dict(r)
            for r in _counts(
                conn,
                """SELECT language, MAX(supported) AS supported, COUNT(*) AS files,
                          COALESCE(SUM(line_count), 0) AS lines
                   FROM inventory_files WHERE audit_id = ? AND category = 'source'
                   GROUP BY language ORDER BY files DESC, language""",
                audit_id,
            )
        ],
        "modules": one("SELECT COUNT(*) FROM inventory_modules WHERE audit_id = ?"),
        "manifests": one("SELECT COUNT(DISTINCT manifest_path) FROM inventory_dependencies WHERE audit_id = ?"),
        "dependencies_by_ecosystem": {
            r[0]: r[1]
            for r in _counts(
                conn,
                "SELECT ecosystem, COUNT(*) FROM inventory_dependencies WHERE audit_id = ? GROUP BY ecosystem",
                audit_id,
            )
        },
        "entry_points_by_kind": {
            r[0]: r[1]
            for r in _counts(
                conn,
                "SELECT kind, COUNT(*) AS n FROM inventory_entry_points WHERE audit_id = ? GROUP BY kind ORDER BY n DESC",
                audit_id,
            )
        },
        "relationships_by_kind": {
            r[0]: r[1]
            for r in _counts(
                conn,
                "SELECT kind, COUNT(*) AS n FROM inventory_relationships WHERE audit_id = ? GROUP BY kind ORDER BY n DESC",
                audit_id,
            )
        },
        "cross_module_links": one(
            """SELECT COUNT(DISTINCT s.module_path || '>' || t.module_path)
               FROM inventory_relationships r
               JOIN inventory_files s ON s.audit_id = r.audit_id AND s.path = r.source_path
               JOIN inventory_files t ON t.audit_id = r.audit_id AND t.path = r.target_path
               WHERE r.audit_id = ? AND r.kind = 'internal' AND s.module_path != t.module_path"""
        ),
        "unsupported": [dict(r) for r in store.load_section(conn, audit_id, "unsupported")],
        "skipped": [dict(r) for r in store.load_section(conn, audit_id, "skipped")],
    }


def format_summary(data: dict) -> str:
    audit = data["audit"]
    commit = (audit["head_commit"] or "no commits")[:12]
    branch = audit["branch"] or "detached HEAD"
    lines = [
        f"Audit #{audit['id']}: {audit['repo_name']} ({audit['repo_path']})",
        f"Status: {audit['status']}" + (f" ({audit['error']})" if audit["error"] else ""),
        f"Commit {commit} on {branch}"
        + (" (working tree has uncommitted changes)" if audit["working_tree_dirty"] else ""),
        "Scope: tracked files" + (" plus untracked code, config, and docs" if audit["include_untracked"] else ""),
        "",
        f"Files: {sum(data['files_by_category'].values())} ("
        + ", ".join(f"{n} {c}" for c, n in data["files_by_category"].items())
        + ")",
        "Languages:",
    ]
    if data["languages"]:
        width = max(len(lang["language"]) for lang in data["languages"])
        for lang in data["languages"]:
            support = "supported" if lang["supported"] else "unsupported"
            lines.append(
                f"  {lang['language']:<{width}}  {lang['files']:>5} files  {lang['lines']:>8,} lines  {support}"
            )
    else:
        lines.append("  none")
    deps = data["dependencies_by_ecosystem"]
    lines += [
        f"Modules: {data['modules']} ({data['cross_module_links']} cross-module import links)",
        f"Dependencies: {sum(deps.values())} from {data['manifests']} manifests ({_join_counts(list(deps.items()))})",
        f"Entry points: {sum(data['entry_points_by_kind'].values())} "
        f"({_join_counts([(n, k) for k, n in data['entry_points_by_kind'].items()])})",
        f"Relationships: {sum(data['relationships_by_kind'].values())} imports "
        f"({_join_counts([(n, k) for k, n in data['relationships_by_kind'].items()])})",
        "Unsupported:",
    ]
    if data["unsupported"]:
        for item in data["unsupported"]:
            lines.append(f"  {item['technology']} ({item['kind']}, {item['file_count']} files): {item['reason']}")
    else:
        lines.append("  none")
    lines.append("Skipped (not stored):")
    if data["skipped"]:
        for item in data["skipped"]:
            lines.append(f"  {item['file_count']} {item['reason']}, e.g. {item['example_path']}")
    else:
        lines.append("  none")
    return "\n".join(lines)


TASK_COLUMNS = ["id", "priority", "status", "file_count", "line_count", "title", "priority_reason"]


def task_rows(conn: sqlite3.Connection, audit_id: int, status: str | None = None) -> list[dict]:
    store.get_audit(conn, audit_id)
    return [{c: row[c] for c in TASK_COLUMNS} for row in store.list_tasks(conn, audit_id, status)]


def format_task_list(conn: sqlite3.Connection, audit_id: int, rows: list[dict]) -> str:
    audit = store.get_audit(conn, audit_id)
    counts = dict(
        conn.execute(
            "SELECT status, COUNT(*) FROM audit_tasks WHERE audit_id = ? GROUP BY status", (audit_id,)
        ).fetchall()
    )
    lines = [
        f"Audit #{audit_id}: {audit['repo_name']}",
        f"Tasks: {sum(counts.values())} ("
        + ", ".join(f"{counts.get(s, 0)} {s}" for s in store.TASK_STATUSES)
        + ")",
        "",
        format_table(rows, TASK_COLUMNS),
        "",
        "Not covered by any task:",
    ]
    gaps = store.not_covered(conn, audit_id)
    lines += [f"  {g['what']}: {g['file_count']} files, e.g. {g['example_path']}" for g in gaps] or ["  none"]
    lines.append("\nShow one task with: audit-agent task <id>")
    return "\n".join(lines)


def task_detail(conn: sqlite3.Connection, task_id: int) -> dict:
    return {
        "task": dict(store.get_task(conn, task_id)),
        **{name: [dict(r) for r in rows] for name, rows in store.task_context(conn, task_id).items()},
        "findings": [dict(r) for r in store.list_findings(conn, task_id=task_id)],
        "runs": [dict(r) for r in store.task_runs(conn, task_id)],
    }


def format_findings(rows: list, runs: list | None = None) -> str:
    lines = []
    for run in runs or []:
        cost = f", ${run['cost_usd']:.2f}" if run["cost_usd"] is not None else ""
        took = f", {run['duration_ms'] / 1000:.0f}s" if run["duration_ms"] else ""
        lines.append(f"Run #{run['id']} ({run['agent']} agent): {run['status']}{took}{cost}")
        if run["error"]:
            lines.append(f"  error: {run['error']}")
    findings = [r for r in rows if r["kind"] == "finding"]
    review = [r for r in rows if r["kind"] == "needs_review"]
    lines.append(f"\nFindings ({len(findings)}):" if lines else f"Findings ({len(findings)}):")
    for f in findings:
        lines += [
            f"  [{f['severity'].upper()}] {f['bug_type']}: {f['title']}",
            f"    {f['file_path']}:{f['line']}  (task #{f['task_id']}, {f['agent']} agent)",
            *[f"      | {code}" for code in (f["evidence"] or "").splitlines()[:6]],
            f"    {f['explanation']}",
        ]
    if not findings:
        lines.append("  none")
    lines.append(f"\nNeeds your review ({len(review)}), not counted as bugs:")
    for n in review:
        where = f"{n['file_path']}:{n['line']}  " if n["file_path"] else ""
        lines += [
            f"  - {n['title']}",
            f"    {where}(task #{n['task_id']})",
            f"    Suspicion: {n['explanation']}",
            f"    Not confirmed because: {n['why_unconfirmed'] or 'not stated'}",
        ]
    if not review:
        lines.append("  none")
    return "\n".join(lines)


def format_task_detail(data: dict) -> str:
    task = data["task"]
    lines = [
        f"Task #{task['id']}: {task['title']}",
        f"Audit #{task['audit_id']}  status: {task['status']}  priority: {task['priority']} ({task['priority_reason']})",
        "",
        f"Files to audit ({len(data['files'])}, {task['line_count']:,} lines):",
        *[f"  {f['path']}  ({f['line_count']} lines)" for f in data["files"]],
    ]

    def block(title: str, rows: list[dict], render) -> None:
        lines.append("")
        lines.append(f"{title} ({len(rows)}):")
        lines.extend(f"  {render(r)}" for r in rows[:25])
        if len(rows) > 25:
            lines.append(f"  ... and {len(rows) - 25} more")
        if not rows:
            lines.append("  none")

    block("Entry points", data["entry_points"], lambda r: f"{r['path']}  {r['kind']}: {r['detail']}")
    block("Imports these files from elsewhere in the repo", data["imports"], lambda r: r["path"])
    block("Imported by", data["imported_by"], lambda r: r["path"])
    block("Packages used", data["packages"], lambda r: f"{r['name']} ({r['uses']})")
    block("Imports of missing files", data["unresolved"], lambda r: f"{r['path']}:{r['line']}  {r['specifier']}")

    def call_line(r: dict) -> str:
        where = f"{r['path']}:{r['line']}  {r['method']} {r['url']}"
        if r["status"] == "matched":
            return f"{where}  ->  {r['route_repo']}: {r['handler_path']}"
        if r["status"] == "wrong_method":
            return f"{where}  [WRONG METHOD: route is {r['route_method']} {r['route_path']}]"
        return f"{where}  [{r['status'].upper()}]"

    block("API calls made here", data["api_calls"], call_line)
    block("API routes handled here", data["api_routes"], lambda r: f"{r['method']} {r['path']}  ({r['callers']} callers)")
    if data.get("runs") or data.get("findings"):
        lines += ["", format_findings(data["findings"], data["runs"])]
    return "\n".join(lines)


API_SECTIONS = {
    "calls": ["repo_name", "source_path", "line", "method", "pattern", "status", "route_path", "route_repo", "via"],
    "broken": ["repo_name", "source_path", "line", "method", "pattern", "via"],
    "wrong-method": ["repo_name", "source_path", "line", "method", "pattern", "route_method", "route_path", "via"],
    "unresolved": ["repo_name", "source_path", "line", "method", "raw", "via"],
    "routes": ["repo_name", "method", "path", "file_path", "handler_path", "callers"],
    "mentioned": ["repo_name", "method", "path", "mention_repo", "source_path", "line", "text"],
    "unused": ["repo_name", "method", "path", "file_path"],
}


def api_rows(conn: sqlite3.Connection, project_id: int, section: str) -> list[dict]:
    columns = API_SECTIONS[section]
    if section == "routes":
        rows = store.api_routes(conn, project_id)
    elif section == "mentioned":
        rows = store.mentioned_api_routes(conn, project_id)
    elif section == "unused":
        rows = store.unused_api_routes(conn, project_id)
    else:
        status = {"broken": "broken", "wrong-method": "wrong_method", "unresolved": "unresolved"}.get(section)
        rows = store.api_calls(conn, project_id, status)
    return [{c: row[c] for c in columns} for row in rows]


def format_api_summary(conn: sqlite3.Connection, project_id: int) -> str:
    project = store.get_project(conn, project_id)
    audits = store.project_audits(conn, project_id)
    counts = dict(
        conn.execute(
            "SELECT status, COUNT(*) FROM api_calls WHERE project_id = ? GROUP BY status", (project_id,)
        ).fetchall()
    )
    routes = conn.execute("SELECT COUNT(*) FROM api_routes WHERE project_id = ?", (project_id,)).fetchone()[0]
    mentioned = conn.execute(
        "SELECT COUNT(DISTINCT route_id) FROM api_mentions WHERE project_id = ?", (project_id,)
    ).fetchone()[0]
    via = dict(
        conn.execute(
            """SELECT CASE WHEN via LIKE 'wrapper%' THEN 'through a wrapper'
                           WHEN via LIKE 'direct%' THEN 'direct HTTP client call'
                           ELSE 'by function name only' END, COUNT(*)
               FROM api_calls WHERE project_id = ? GROUP BY 1""",
            (project_id,),
        ).fetchall()
    )
    lines = [
        f"Project #{project['id']}: {project['name']}",
        "Audits: " + ", ".join(f"#{a['id']} {a['repo_name']}" for a in audits),
        f"API map built: {project['api_mapped_at'] or 'not yet'}",
        "",
        f"Backend routes: {routes}  ({mentioned} only mentioned in frontend code, "
        f"{len(store.unused_api_routes(conn, project_id))} not referenced anywhere)",
        f"Frontend calls: {sum(counts.values())}  (" + ", ".join(f"{n} {k}" for k, n in sorted(via.items())) + ")",
    ]
    labels = {
        "matched": "matched to a route",
        "wrong_method": "path exists, but not with this HTTP method",
        "broken": "no route with this path",
        "unresolved": "URL built at runtime, can't be matched",
        "external": "calls to other services",
    }
    lines += [f"  {counts.get(s, 0):>5}  {labels[s]}" for s in store.API_CALL_STATUSES]
    problems = [dict(r) for r in store.api_calls(conn, project_id) if r["status"] in ("broken", "wrong_method")]
    if problems:
        lines += ["", "Calls that don't reach a route:"]
        for p in problems:
            target = f"  (closest: {p['route_method']} {p['route_path']})" if p["route_path"] else ""
            lines.append(f"  {p['repo_name']}: {p['source_path']}:{p['line']}  {p['method']} {p['pattern']}{target}")
    lines.append(
        "\nList more with: audit-agent api "
        + (project["name"] if " " not in project["name"] else f'"{project["name"]}"')
        + " --section broken|wrong-method|unresolved|routes|mentioned|unused|calls"
    )
    return "\n".join(lines)


def section_rows(conn: sqlite3.Connection, audit_id: int, section: str) -> list[dict]:
    store.get_audit(conn, audit_id)
    columns = SECTION_COLUMNS[section]
    return [{c: row[c] for c in columns} for row in store.load_section(conn, audit_id, section)]


def format_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return "(none)"
    cells = [["" if row[c] is None else str(row[c]) for c in columns] for row in rows]
    widths = [min(60, max(len(c), *(len(r[i]) for r in cells))) for i, c in enumerate(columns)]

    def render(values: list[str]) -> str:
        return "  ".join(
            (v if len(v) <= w else v[: w - 1] + "…").ljust(w) for v, w in zip(values, widths)
        ).rstrip()
    return "\n".join([render(columns), render(["-" * w for w in widths]), *map(render, cells)])
