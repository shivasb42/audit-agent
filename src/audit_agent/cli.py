"""Command-line interface: audits, inventory, tasks, projects and their API map, and the review page."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit_agent import api_map, planning, store, views, web
from audit_agent import investigate as investigation
from audit_agent.inventory import discover
from audit_agent.repo import RepositoryError, open_repository


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db",
        type=Path,
        default=None,
        help="audit database path (default: $AUDIT_AGENT_DB or ~/.audit-agent/audit.db)",
    )

    parser = argparse.ArgumentParser(prog="audit-agent", description="Autonomous Code Audit")
    commands = parser.add_subparsers(dest="command", required=True)

    start = commands.add_parser("start", parents=[common], help="start an audit and build the repository inventory")
    start.add_argument("repo", type=Path, help="path to a local Git repository")
    start.add_argument(
        "--include-untracked",
        action="store_true",
        help="also inventory untracked, non-ignored code, config, and docs (default: tracked files only)",
    )

    commands.add_parser("audits", parents=[common], help="list audits in the database")

    inventory = commands.add_parser("inventory", parents=[common], help="show the saved inventory for an audit")
    inventory.add_argument("audit_id", type=int)
    inventory.add_argument("--section", choices=sorted(views.SECTION_COLUMNS), help="list one part of the inventory")
    inventory.add_argument("--json", action="store_true", help="print JSON instead of text")

    plan = commands.add_parser("plan", parents=[common], help="generate audit tasks from an audit's inventory")
    plan.add_argument("audit_id", type=int)

    tasks = commands.add_parser("tasks", parents=[common], help="list an audit's tasks, highest priority first")
    tasks.add_argument("audit_id", type=int)
    tasks.add_argument("--status", choices=store.TASK_STATUSES, help="only show tasks with this status")
    tasks.add_argument("--json", action="store_true", help="print JSON instead of text")

    task = commands.add_parser("task", parents=[common], help="show one task: its files and what they connect to")
    task.add_argument("task_id", type=int)
    task.add_argument("--json", action="store_true", help="print JSON instead of text")

    project = commands.add_parser("project", parents=[common], help="group audits into a project, e.g. a backend and its apps")
    project.add_argument("name")
    project.add_argument("audit_ids", type=int, nargs="+")

    commands.add_parser("projects", parents=[common], help="list projects")

    map_api = commands.add_parser("map-api", parents=[common], help="match frontend API calls to backend routes in a project")
    map_api.add_argument("project", help="project name or id")

    api = commands.add_parser("api", parents=[common], help="show a project's API map")
    api.add_argument("project", help="project name or id")
    api.add_argument("--section", choices=sorted(views.API_SECTIONS), help="list one part of the map")
    api.add_argument("--json", action="store_true", help="print JSON instead of text")

    investigate = commands.add_parser("investigate", parents=[common], help="run a Claude Code agent on a task")
    investigate.add_argument("task_id", type=int)
    investigate.add_argument("--model", help="Claude model alias or name, e.g. sonnet or opus")
    investigate.add_argument("--max-turns", type=int, default=40, help="limit on agent turns (default: 40)")
    investigate.add_argument("--timeout", type=int, default=900, help="seconds before giving up (default: 900)")
    investigate.add_argument("--max-budget-usd", type=float, help="stop the run once its estimated cost reaches this")
    investigate.add_argument("--again", action="store_true", help="investigate a task that is already done")
    investigate.add_argument("--show-prompt", action="store_true", help="print the prompt and exit without running Claude")

    findings = commands.add_parser("findings", parents=[common], help="list findings for an audit or a task")
    findings.add_argument("audit_id", type=int, nargs="?")
    findings.add_argument("--task", type=int, help="only findings from this task")
    findings.add_argument("--kind", choices=store.FINDING_KINDS, help="findings or needs_review items only")
    findings.add_argument("--json", action="store_true", help="print JSON instead of text")

    ui = commands.add_parser("ui", parents=[common], help="open a local page to review and cancel tasks")
    ui.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default: 8765)")
    ui.add_argument("--no-browser", action="store_true", help="don't open the page in a browser")
    return parser


def _start(args: argparse.Namespace, db_path: Path) -> int:
    repo = open_repository(args.repo)
    store.ensure_outside_repository(db_path, repo)
    conn = store.connect(db_path)
    try:
        audit_id = store.create_audit(conn, repo, args.include_untracked)
        print(f"Discovering {repo.root} ...", file=sys.stderr)
        try:
            inventory = discover(repo, include_untracked=args.include_untracked)
            store.save_inventory(conn, audit_id, inventory)
        except Exception as exc:
            store.mark_failed(conn, audit_id, f"{exc.__class__.__name__}: {exc}")
            raise
        print(views.format_summary(views.summary(conn, audit_id)))
        print(f"\nSaved to {db_path}. List any part with: audit-agent inventory {audit_id} --section files")
        print(f"Next, generate audit tasks with: audit-agent plan {audit_id}")
    finally:
        conn.close()
    return 0


def _audits(args: argparse.Namespace, conn) -> int:
    rows = [
        {
            "id": a["id"],
            "repo_name": a["repo_name"],
            "status": a["status"],
            "commit": (a["head_commit"] or "")[:12],
            "created_at": a["created_at"],
            "repo_path": a["repo_path"],
        }
        for a in store.list_audits(conn)
    ]
    print(views.format_table(rows, ["id", "repo_name", "status", "commit", "created_at", "repo_path"]))
    return 0


def _inventory(args: argparse.Namespace, conn) -> int:
    if args.section:
        rows = views.section_rows(conn, args.audit_id, args.section)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(views.format_table(rows, views.SECTION_COLUMNS[args.section]))
        return 0
    data = views.summary(conn, args.audit_id)
    if args.json:
        data["sections"] = {s: views.section_rows(conn, args.audit_id, s) for s in views.SECTION_COLUMNS}
        print(json.dumps(data, indent=2))
    else:
        print(views.format_summary(data))
    return 0


def _plan(args: argparse.Namespace, conn) -> int:
    count, created = planning.plan_audit(conn, args.audit_id)
    if created:
        print(f"Created {count} tasks for audit #{args.audit_id}.\n")
    else:
        print(f"Audit #{args.audit_id} already has {count} tasks; nothing changed.\n")
    print(views.format_task_list(conn, args.audit_id, views.task_rows(conn, args.audit_id)))
    return 0


def _tasks(args: argparse.Namespace, conn) -> int:
    rows = views.task_rows(conn, args.audit_id, args.status)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(views.format_task_list(conn, args.audit_id, rows))
    return 0


def _task(args: argparse.Namespace, conn) -> int:
    data = views.task_detail(conn, args.task_id)
    print(json.dumps(data, indent=2) if args.json else views.format_task_detail(data))
    return 0


def _project(args: argparse.Namespace, conn) -> int:
    project_id = store.create_project(conn, args.name, args.audit_ids)
    print(f"Project #{project_id} {args.name!r} now includes:")
    for audit in store.project_audits(conn, project_id):
        print(f"  #{audit['id']} {audit['repo_name']}  {audit['repo_path']}")
    print(f'\nNext, build its API map with: audit-agent map-api "{args.name}"')
    return 0


def _projects(args: argparse.Namespace, conn) -> int:
    rows = [dict(r) for r in store.list_projects(conn)]
    print(views.format_table(rows, ["id", "name", "audits", "api_mapped_at"]))
    return 0


def _map_api(args: argparse.Namespace, conn) -> int:
    project = store.get_project(conn, args.project)
    summary = api_map.map_project(conn, project["id"])
    if summary["unreadable_files"]:
        print(f"Note: {summary['unreadable_files']} inventoried files could not be read from disk.\n")
    print(views.format_api_summary(conn, project["id"]))
    return 0


def _api(args: argparse.Namespace, conn) -> int:
    project = store.get_project(conn, args.project)
    if not args.section:
        print(views.format_api_summary(conn, project["id"]))
        return 0
    rows = views.api_rows(conn, project["id"], args.section)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(views.format_table(rows, views.API_SECTIONS[args.section]))
    return 0


def _investigate(args: argparse.Namespace, conn) -> int:
    settings = investigation.AgentSettings(
        model=args.model, max_turns=args.max_turns, timeout_s=args.timeout, max_budget_usd=args.max_budget_usd
    )
    task = store.get_task(conn, args.task_id)
    if args.show_prompt:
        audit = store.get_audit(conn, task["audit_id"])
        secrets = [r[0] for r in conn.execute(
            "SELECT path FROM inventory_files WHERE audit_id = ? AND category = 'secret'", (audit["id"],)
        )]
        print(investigation.build_prompt(conn, task, audit, secrets))
        return 0
    print(f"Investigating task #{task['id']}: {task['title']} ...", file=sys.stderr)
    summary = investigation.investigate(conn, args.task_id, settings, again=args.again)
    print(views.format_findings(store.list_findings(conn, task_id=args.task_id), store.task_runs(conn, args.task_id)[-1:]))
    if summary["rejected"]:
        print(f"\nRejected {len(summary['rejected'])} claims that cited code that doesn't exist:")
        for item in summary["rejected"]:
            print(f"  - {item['title']}: {item['reason']}")
    return 0


def _findings(args: argparse.Namespace, conn) -> int:
    if args.audit_id is None and args.task is None:
        print("error: give an audit id or --task", file=sys.stderr)
        return 1
    rows = store.list_findings(conn, audit_id=args.audit_id, task_id=args.task, kind=args.kind)
    if args.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
    else:
        print(views.format_findings(rows))
    return 0


COMMANDS = {
    "investigate": _investigate,
    "findings": _findings,
    "audits": _audits,
    "inventory": _inventory,
    "plan": _plan,
    "tasks": _tasks,
    "task": _task,
    "project": _project,
    "projects": _projects,
    "map-api": _map_api,
    "api": _api,
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    db_path = (args.db or store.default_db_path()).expanduser().resolve()
    try:
        if args.command == "start":
            return _start(args, db_path)
        if args.command == "ui":
            try:
                web.serve(db_path, args.port, open_browser=not args.no_browser)
            except OSError as exc:
                print(f"error: could not start the page on port {args.port}: {exc.strerror}", file=sys.stderr)
                return 1
            return 0
        conn = store.connect(db_path)
        try:
            return COMMANDS[args.command](args, conn)
        finally:
            conn.close()
    except (RepositoryError, store.StoreError, planning.PlanningError, investigation.InvestigationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
