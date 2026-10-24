"""Command-line interface: audits, inventory, tasks, projects and their API map, and the review page."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from audit_agent import api_map, api_tasks, batches, credentials, github_issues, planning, store, views, web
from audit_agent import investigate as investigation
from audit_agent.inventory import discover
from audit_agent.inventory.apps import APP_TYPES
from audit_agent.repo import RepositoryError, find_repositories


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

    start = commands.add_parser(
        "start", parents=[common],
        help="audit a repository or a folder of repositories: inventory, apps, tasks, and API map, as one project",
    )
    start.add_argument("folder", type=Path, help="a local Git repository, or a folder containing Git repositories")
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

    apps = commands.add_parser("apps", parents=[common], help="list apps and their types (backend, web, mobile) with the evidence")
    apps.add_argument("project", nargs="?", help="project name or id (default: the latest audit of every repository)")
    apps.add_argument("--json", action="store_true", help="print JSON instead of text")

    app_type = commands.add_parser("app-type", parents=[common], help="correct an app's type; kept for later audits")
    app_type.add_argument("app", help="app name (e.g. football_fantasy/client) or folder path")
    app_type.add_argument("type", choices=APP_TYPES)

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
    investigate.add_argument(
        "--runner",
        choices=investigation.RUNNERS,
        default="auto",
        help="api: call the Anthropic API with the saved key; cli: use the claude command; "
        "auto (default): api if a key is saved, otherwise cli",
    )
    investigate.add_argument("--show-prompt", action="store_true", help="print the prompt and exit without running Claude")

    batch_send = commands.add_parser("batch-send", parents=[common],
                                     help="send tasks to Claude as a batch: half price, results within 24 hours")
    batch_send.add_argument("task_ids", type=int, nargs="+")
    batch_send.add_argument("--model", help="Claude model name (default: the API runner's default)")
    commands.add_parser("batches", parents=[common], help="list Claude batches and what they're waiting for")
    commands.add_parser("batch-check", parents=[common], help="check open batches and import finished results")
    commands.add_parser("batch-recover", parents=[common],
                        help="find batches this database lost track of on the Anthropic account and import them")
    batch_cancel = commands.add_parser("batch-cancel", parents=[common], help="cancel a batch in progress")
    batch_cancel.add_argument("batch_id", type=int)

    issues = commands.add_parser("issues", parents=[common],
                                 help="preview (or, with --create, create) GitHub issues for a task's findings")
    issues.add_argument("task_id", type=int)
    issues.add_argument("--create", action="store_true", help="create the issues and add them to the project board")

    findings = commands.add_parser("findings", parents=[common], help="list findings for an audit or a task")
    findings.add_argument("audit_id", type=int, nargs="?")
    findings.add_argument("--task", type=int, help="only findings from this task")
    findings.add_argument("--kind", choices=store.FINDING_KINDS, help="findings or needs_review items only")
    findings.add_argument("--json", action="store_true", help="print JSON instead of text")

    key = commands.add_parser("set-api-key", parents=[common], help="save an Anthropic API key outside every repository")
    key.add_argument("--clear", action="store_true", help="delete the saved key")
    key.add_argument("--show", action="store_true", help="show where the key comes from, masked")

    ui = commands.add_parser("ui", parents=[common], help="open a local page to review tasks and send them to Claude")
    ui.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default: 8765)")
    ui.add_argument("--no-browser", action="store_true", help="don't open the page in a browser")
    ui.add_argument("--parallel", type=int, default=2, help="investigations run at once (default: 2; the page can change it)")
    ui.add_argument("--runner", choices=investigation.RUNNERS, default="auto",
                    help="how tasks sent from the page call Claude (default: auto, as for investigate)")
    ui.add_argument("--model", help="Claude model alias or name for tasks sent from the page")
    ui.add_argument("--max-turns", type=int, default=40, help="limit on agent turns per task (default: 40)")
    ui.add_argument("--timeout", type=int, default=900, help="seconds before a task gives up (default: 900)")
    return parser


def _start(args: argparse.Namespace, db_path: Path) -> int:
    folder = args.folder.expanduser().resolve()
    repos = find_repositories(folder)
    for repo in repos:
        store.ensure_outside_repository(db_path, repo)
    project_root = repos[0].root if folder.is_relative_to(repos[0].root) else folder
    conn = store.connect(db_path)
    try:
        audit_ids = []
        for repo in repos:
            audit_id = store.create_audit(conn, repo, args.include_untracked)
            print(f"Discovering {repo.root} ...", file=sys.stderr)
            try:
                inventory = discover(repo, include_untracked=args.include_untracked)
                store.save_inventory(conn, audit_id, inventory)
            except Exception as exc:
                store.mark_failed(conn, audit_id, f"{exc.__class__.__name__}: {exc}")
                raise
            count, _ = planning.plan_audit(conn, audit_id)
            audit_ids.append(audit_id)
            print(views.format_summary(views.summary(conn, audit_id)))
            print(f"Tasks: {count} created. List them with: audit-agent tasks {audit_id}\n")

        project_id = store.create_folder_project(conn, str(project_root), audit_ids)
        print(f"Mapping API calls in {project_root} ...", file=sys.stderr)
        api_map.map_project(conn, project_id)
        api_counts = api_tasks.plan_project(conn, project_id)
        project = store.get_project(conn, project_id)
        print(views.format_apps(views.app_rows(conn, audit_ids)))
        print()
        print(views.format_api_summary(conn, project_id))
        print(f"\nAPI-call tasks: {api_counts['total']} (one per endpoint each app calls, plus one per call that "
              "reaches no route). They are listed with each app's tasks.")
        print(f"\nSaved to {db_path} as project {project['name']!r}.")
        print("List any part of an audit with: audit-agent inventory <audit id> --section files|apps|...")
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
    print(views.format_table(rows, ["id", "name", "audits", "api_mapped_at", "root_path"]))
    return 0


def _apps(args: argparse.Namespace, conn) -> int:
    if args.project:
        audit_ids = [a["id"] for a in store.project_audits(conn, store.get_project(conn, args.project)["id"])]
    else:
        latest = {a["repo_path"]: a["id"] for a in store.list_audits(conn)}
        audit_ids = sorted(latest.values())
    rows = views.app_rows(conn, audit_ids)
    print(json.dumps(rows, indent=2) if args.json else views.format_apps(rows))
    return 0


def _app_type(args: argparse.Namespace, conn) -> int:
    path = store.find_app_path(conn, args.app)
    changed = store.set_app_type(conn, path, args.type)
    print(f"{path} is now {views.TYPE_LABELS[args.type]}; later audits of this folder keep it.")
    for project_id in store.projects_of(conn, changed):
        api_map.map_project(conn, project_id)
        api_tasks.plan_project(conn, project_id)
        print(f"Rebuilt the API map and API-call tasks of project {store.get_project(conn, project_id)['name']!r}.")
    return 0


def _map_api(args: argparse.Namespace, conn) -> int:
    project = store.get_project(conn, args.project)
    summary = api_map.map_project(conn, project["id"])
    if summary["unreadable_files"]:
        print(f"Note: {summary['unreadable_files']} inventoried files could not be read from disk.\n")
    print(views.format_api_summary(conn, project["id"]))
    counts = api_tasks.plan_project(conn, project["id"])
    print(f"\nAPI-call tasks: {counts['total']} ({counts['created']} new, {counts['updated']} refreshed, "
          f"{counts['removed']} removed because their call is gone)")
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
        model=args.model,
        max_turns=args.max_turns,
        timeout_s=args.timeout,
        max_budget_usd=args.max_budget_usd,
        runner=args.runner,
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


BATCH_COLUMNS = ["id", "anthropic_id", "status", "round", "model", "request_count", "waiting", "continued",
                 "succeeded", "errored", "expired", "canceled", "recovered", "created_at", "error"]


def _batch_send(args: argparse.Namespace, conn) -> int:
    result = batches.submit(conn, args.task_ids, args.model)
    for skipped in result["skipped"]:
        print(f"Skipped task #{skipped['id']}: {skipped['reason']}")
    if result["queued"]:
        print(f"Sent {len(result['queued'])} task(s) in batch(es) {', '.join(f'#{b}' for b in result['batches'])}. "
              "Collect results with: audit-agent batch-check (or keep `audit-agent ui` open)")
    return 0


def _batches(args: argparse.Namespace, conn) -> int:
    rows = batches.batch_rows(conn)
    print(views.format_table(rows, BATCH_COLUMNS))
    return 0


def _batch_check(args: argparse.Namespace, conn) -> int:
    result = batches.check(conn)
    print(f"Checked {result['checked']} open batch(es): {result['imported']} imported, {result['in_progress']} still running.")
    return 0


def _batch_recover(args: argparse.Namespace, conn) -> int:
    result = batches.recover(conn)
    print(f"Matched {result['matched']} batch(es) sent without a saved id, adopted {result['adopted']} lost batch(es).")
    if result["unrecognized_in_progress"]:
        print(f"{result['unrecognized_in_progress']} batch(es) in progress on the account aren't recognized yet; "
              "run this again after they end to check whether they're ours.")
    return 0


def _batch_cancel(args: argparse.Namespace, conn) -> int:
    batches.cancel(conn, args.batch_id)
    print(f"Batch #{args.batch_id} is being cancelled. Requests that already finished will still be imported.")
    return 0


def _issues(args: argparse.Namespace, conn) -> int:
    if args.create:
        result = github_issues.create(conn, args.task_id)
        for item in result["created"]:
            print(f"Created {item['url']}")
        for item in result["skipped"]:
            print(f"Skipped finding #{item['finding_id']}: {item['reason']}")
        for warning in result["warnings"]:
            print(f"Warning: {warning}")
        if result["board"]:
            print(f"Project board {result['board']['title']!r}: {result['board']['url']}")
        return 0
    plan = github_issues.preview(conn, args.task_id)
    print(f"Task #{args.task_id}: {len(plan['issues'])} finding(s); board {plan['board']!r}\n")
    for issue in plan["issues"]:
        state = issue["issue_url"] or issue["problem"] or f"would create in {issue['repo']}"
        print(f"  #{issue['finding_id']} {issue['title']}\n     labels: {', '.join(issue['labels'])}\n     {state}")
    print("\nCreate them with: audit-agent issues", args.task_id, "--create")
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


def _set_api_key(args: argparse.Namespace) -> int:
    if args.clear:
        print("Deleted the saved key." if credentials.clear_api_key() else "No saved key to delete.")
        return 0
    if args.show:
        if os.environ.get("ANTHROPIC_API_KEY"):
            print(f"Using ANTHROPIC_API_KEY from the environment: {credentials.masked(os.environ['ANTHROPIC_API_KEY'])}")
        elif key := credentials.get_api_key():
            print(f"Using the key saved in {credentials.credentials_path()}: {credentials.masked(key)}")
        else:
            print("No API key is set.")
        return 0
    key = getpass.getpass("Anthropic API key (input is hidden): ").strip()
    if not key:
        print("error: no key entered", file=sys.stderr)
        return 1
    if not key.startswith("sk-ant-"):
        print("warning: this doesn't look like an Anthropic key (they start with sk-ant-).", file=sys.stderr)
    path = credentials.save_api_key(key)
    print(f"Saved to {path} (readable only by you): {credentials.masked(key)}")
    return 0


COMMANDS = {
    "issues": _issues,
    "batch-send": _batch_send,
    "batches": _batches,
    "batch-check": _batch_check,
    "batch-recover": _batch_recover,
    "batch-cancel": _batch_cancel,
    "investigate": _investigate,
    "findings": _findings,
    "audits": _audits,
    "inventory": _inventory,
    "plan": _plan,
    "tasks": _tasks,
    "task": _task,
    "project": _project,
    "projects": _projects,
    "apps": _apps,
    "app-type": _app_type,
    "map-api": _map_api,
    "api": _api,
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    db_path = (args.db or store.default_db_path()).expanduser().resolve()
    try:
        if args.command == "start":
            return _start(args, db_path)
        if args.command == "set-api-key":
            return _set_api_key(args)
        if args.command == "ui":
            try:
                settings = investigation.AgentSettings(
                    model=args.model, max_turns=args.max_turns, timeout_s=args.timeout, runner=args.runner
                )
                web.serve(db_path, args.port, open_browser=not args.no_browser, settings=settings, parallel=args.parallel)
            except OSError as exc:
                print(f"error: could not start the page on port {args.port}: {exc.strerror}", file=sys.stderr)
                return 1
            return 0
        conn = store.connect(db_path)
        try:
            return COMMANDS[args.command](args, conn)
        finally:
            conn.close()
    except (RepositoryError, store.StoreError, planning.PlanningError, investigation.InvestigationError,
            batches.BatchError, github_issues.IssueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
