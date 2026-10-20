"""Run a Claude Code agent on one audit task and save what it finds.

The agent runs through the `claude` CLI in print mode, inside the task's repository, with
read-only tools only. Its answer is validated before anything is saved: a finding must cite a
file and line that exist and quote code that is actually there; otherwise it is downgraded to
"needs review" or rejected.
"""

from typing import Literal


from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from audit_agent import store
from audit_agent.repo import open_repository

GENERAL_AGENT = "general"
READ_ONLY_TOOLS = "Read,Grep,Glob"
SECRET_PATTERNS = ("**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore")
RUNNABLE_STATUSES = ("pending", "failed", "blocked")
BUG_TYPE_ALIASES = {"concurrency and reliability": "concurrency", "reliability": "concurrency", "race": "concurrency"}

CHECKLIST = """\
Security
- Missing or bypassable authentication/authorization (routes or screens reachable without the right checks, IDOR: acting on another user's resource by id)
- Trusting user input: injection (NoSQL/SQL/command/path), unvalidated redirects, mass assignment of request bodies into database writes
- Secrets or tokens exposed in code, logs, responses, or client bundles; insecure token storage
- Unsafe defaults: permissive CORS, missing rate limits on sensitive actions, webhook handlers that don't verify signatures

Logic
- Wrong conditions, inverted checks, off-by-one, wrong comparison or units
- Unhandled null/undefined/empty cases and missing error handling that leaves bad state
- Calls whose method, path, or payload don't match what the other side expects (use the API information below)
- State updates that can leave data inconsistent (partial writes, missing rollback, double counting)

Concurrency and reliability
- Race conditions on shared state or database documents (read-modify-write without atomic operations or locks)
- Missing await, fire-and-forget promises, unhandled rejections, async work in loops without limits
- Jobs, queues, cron, or sockets that can process the same item twice, never retry, or retry forever
- Timeouts, retries, and cleanup missing around network calls and external services
"""

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "bug_type": {"type": "string", "enum": list[Literal['logic', 'security', 'concurrency']](store.BUG_TYPES)},
                    "severity": {"type": "string", "enum": list[Literal['low', 'medium', 'high', 'critical']](store.SEVERITIES)},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "evidence": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["title", "bug_type", "severity", "file", "line", "evidence", "explanation"],
            },
        },
        "needs_review": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "suspicion": {"type": "string"},
                    "files_examined": {"type": "array", "items": {"type": "string"}},
                    "why_unconfirmed": {"type": "string"},
                },
                "required": ["title", "suspicion", "why_unconfirmed"],
            },
        },
    },
    "required": ["findings", "needs_review"],
}


class InvestigationError(Exception):
    pass


@dataclass
class AgentSettings:
    executable: str = "claude"
    model: str | None = None
    max_turns: int = 40
    timeout_s: int = 900
    max_budget_usd: float | None = None


@dataclass
class AgentResult:
    report: dict
    cost_usd: float | None
    duration_ms: int | None
    num_turns: int | None
    session_id: str | None
    raw: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def find_claude(settings: AgentSettings) -> str:
    executable = os.environ.get("AUDIT_AGENT_CLAUDE") or settings.executable
    resolved = shutil.which(executable) or (executable if Path(executable).is_file() else None)
    if not resolved:
        raise InvestigationError(
            "The `claude` command was not found. Install Claude Code (npm install -g @anthropic-ai/claude-code), "
            "run `claude` once to log in, or point AUDIT_AGENT_CLAUDE at it."
        )
    return resolved


def claude_command(executable: str, settings: AgentSettings, secret_paths: list[Path], extra_dirs: list[Path]) -> list[str]:
    deny = ["mcp__*", "Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"]
    deny += [f"Read({pattern})" for pattern in SECRET_PATTERNS]
    deny += [f"Read(/{path})" for path in secret_paths]
    command = [
        executable,
        "-p",
        "--output-format", "json",
        "--json-schema", json.dumps(RESULT_SCHEMA),
        "--tools", READ_ONLY_TOOLS,
        "--allowedTools", READ_ONLY_TOOLS,
        "--disallowedTools", *deny,
        "--permission-mode", "dontAsk",
        "--strict-mcp-config",
        "--no-session-persistence",
        "--max-turns", str(settings.max_turns),
    ]
    for directory in extra_dirs:
        command += ["--add-dir", str(directory)]
    if settings.model:
        command += ["--model", settings.model]
    if settings.max_budget_usd:
        command += ["--max-budget-usd", str(settings.max_budget_usd)]
    return command


def _extract_report(data: dict) -> dict:
    report = data.get("structured_output")
    if isinstance(report, dict):
        return report
    text = data.get("result") or ""
    block = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    candidate = block.group(1) if block else text[text.find("{") : text.rfind("}") + 1]
    try:
        report = json.loads(candidate)
    except (json.JSONDecodeError, ValueError) as exc:
        raise InvestigationError(f"Claude's answer was not valid JSON: {text[:300]!r}") from exc
    if not isinstance(report, dict):
        raise InvestigationError("Claude's answer was not a JSON object")
    return report


def run_claude(prompt: str, repo_root: Path, settings: AgentSettings, secret_paths: list[Path], extra_dirs: list[Path]) -> AgentResult:
    command = claude_command(find_claude(settings), settings, secret_paths, extra_dirs)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command, input=prompt, cwd=repo_root, capture_output=True, text=True, timeout=settings.timeout_s
        )
    except subprocess.TimeoutExpired as exc:
        raise InvestigationError(f"Claude did not finish within {settings.timeout_s} seconds") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[-800:]
        raise InvestigationError(f"claude exited with code {proc.returncode}: {detail}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise InvestigationError(f"claude did not return JSON output: {proc.stdout[:300]!r}") from exc
    if data.get("is_error"):
        raise InvestigationError(f"claude reported an error: {str(data.get('result'))[:500]}")
    return AgentResult(
        report=_extract_report(data),
        cost_usd=data.get("total_cost_usd"),
        duration_ms=data.get("duration_ms") or int((time.monotonic() - started) * 1000),
        num_turns=data.get("num_turns"),
        session_id=data.get("session_id"),
        raw=proc.stdout[-200_000:],
    )


def build_prompt(conn: sqlite3.Connection, task: sqlite3.Row, audit: sqlite3.Row, secrets: list[str]) -> str:
    context = store.task_context(conn, task["id"])

    def section(title: str, rows: list[str], limit: int = 25) -> str:
        if not rows:
            return ""
        more = f"\n  ... and {len(rows) - limit} more" if len(rows) > limit else ""
        return f"\n{title}:\n" + "\n".join(f"  - {r}" for r in rows[:limit]) + more

    api_calls = []
    for c in context["api_calls"]:
        where = f"{c['path']}:{c['line']} {c['method']} {c['url']}"
        if c["status"] == "matched":
            api_calls.append(f"{where} -> handled by {c['route_repo']}: {c['handler_path']} ({c['route_method']} {c['route_path']})")
        elif c["status"] == "wrong_method":
            api_calls.append(f"{where} -> NO route with this method; closest is {c['route_method']} {c['route_path']}")
        elif c["status"] == "broken":
            api_calls.append(f"{where} -> NO backend route matches this path")
        else:
            api_calls.append(f"{where} -> URL built at runtime, not resolved")

    parts = [
        f"You are auditing part of the repository \"{audit['repo_name']}\" for real bugs. "
        "You can only read files; you cannot run or change anything.",
        f"\nTask #{task['id']}: {task['title']}",
        section(
            "Files to audit (start here; open other files in the repository whenever you need context)",
            [f"{f['path']} ({f['line_count']} lines)" for f in context["files"]],
            100,
        ),
        section("Entry points in these files", [f"{e['path']}: {e['kind']} ({e['detail']})" for e in context["entry_points"]]),
        section("Files these import from elsewhere in the repo", [r["path"] for r in context["imports"]]),
        section("Files that import these", [r["path"] for r in context["imported_by"]], 15),
        section("Imports of files that don't exist", [f"{u['path']}:{u['line']} {u['specifier']}" for u in context["unresolved"]]),
        section("API calls made from these files (from static analysis)", api_calls, 40),
        section(
            "Backend routes handled in these files",
            [f"{r['method']} {r['path']} ({r['callers']} frontend callers found)" for r in context["api_routes"]],
            40,
        ),
        section(
            "Other repositories in the same project that you can also read (for example, the backend these calls reach)",
            [f"{a['repo_name']}: {a['repo_path']}" for a in store.related_audits(conn, audit["id"])],
        ),
        section("Never open these files; they may contain secrets", secrets, 50),
        "\nLook for these kinds of bugs:\n" + CHECKLIST,
        """
Rules:
- Report only problems you can show in the code. For each finding, quote the exact code (1-10 lines, copied
  verbatim) from the file at the line you cite, and explain what goes wrong and when.
- If you suspect a problem but can't show it in the code (it depends on configuration, runtime data, or code you
  can't see), put it under "needs_review" with what you suspect and why you couldn't confirm it.
- Don't report style, formatting, naming, performance, missing tests, or TODO comments.
- Use file paths relative to the repository root.
- If you find nothing, return empty lists. Don't invent problems to have something to report.

Return your result as JSON with "findings" and "needs_review" lists.""",
    ]
    return "\n".join(p for p in parts if p)


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _locate_evidence(lines: list[str], line: int, evidence: str) -> int | None:
    """Line number where the quoted code appears, preferring the cited line's neighborhood."""
    quoted = [_normalize(q) for q in evidence.splitlines() if len(_normalize(q)) >= 6]
    if not quoted:
        return None
    probe = quoted[0]
    normalized = [_normalize(text) for text in lines]
    start, end = max(0, line - 16), min(len(lines), line + 15)
    for index in range(start, end):
        if probe in normalized[index]:
            return index + 1
    for index, text in enumerate(normalized):
        if probe in text:
            return index + 1
    return None


def _relative(path: str, roots: dict[str, Path]) -> tuple[Path, str] | None:
    """Resolve a reported path to (repo root, relative path) inside one of the allowed repos."""
    candidate = Path(path.strip())
    for root in roots.values():
        absolute = candidate if candidate.is_absolute() else root / candidate.as_posix().removeprefix("./")
        try:
            resolved = absolute.resolve()
        except OSError:
            continue
        if resolved.is_relative_to(root) and resolved.is_file():
            return root, resolved.relative_to(root).as_posix()
    return None


def validate_report(report: dict, roots: dict[str, Path], secrets: set[Path]) -> tuple[list[dict], list[dict], list[dict]]:
    """Split an agent report into (findings, needs_review, rejected) after checking every citation."""
    findings, needs_review, rejected = [], [], []
    for item in report.get("findings") or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip() or "Untitled finding"
        bug_type = str(item.get("bug_type") or "").strip().lower()
        bug_type = BUG_TYPE_ALIASES.get(bug_type, bug_type)
        severity = str(item.get("severity") or "medium").strip().lower()
        try:
            line = int(item.get("line"))
        except (TypeError, ValueError):
            line = 0
        located = _relative(str(item.get("file") or ""), roots)
        if bug_type not in store.BUG_TYPES:
            rejected.append({"title": title, "reason": f"unknown bug type {bug_type!r}"})
            continue
        if located is None:
            rejected.append({"title": title, "reason": f"cited file {item.get('file')!r} does not exist in the repository"})
            continue
        root, rel = located
        if (root / rel).resolve() in secrets:
            rejected.append({"title": title, "reason": f"cites a secret file {rel}"})
            continue
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        if not 1 <= line <= len(lines):
            rejected.append({"title": title, "reason": f"line {line} is outside {rel} ({len(lines)} lines)"})
            continue
        evidence = str(item.get("evidence") or "")
        actual = _locate_evidence(lines, line, evidence)
        explanation = str(item.get("explanation") or "").strip()
        if actual is None:
            needs_review.append(
                {
                    "title": title,
                    "bug_type": bug_type,
                    "file_path": rel,
                    "line": line,
                    "evidence": evidence,
                    "explanation": explanation,
                    "why_unconfirmed": "The quoted code was not found in the cited file, so the claim couldn't be checked against the code.",
                    "files_examined": [rel],
                }
            )
            continue
        findings.append(
            {
                "title": title,
                "bug_type": bug_type,
                "severity": severity if severity in store.SEVERITIES else "medium",
                "file_path": rel,
                "line": actual,
                "evidence": evidence,
                "explanation": explanation,
            }
        )
    for item in report.get("needs_review") or []:
        if not isinstance(item, dict):
            continue
        needs_review.append(
            {
                "title": str(item.get("title") or "Unconfirmed suspicion").strip(),
                "explanation": str(item.get("suspicion") or item.get("explanation") or "").strip(),
                "why_unconfirmed": str(item.get("why_unconfirmed") or "").strip(),
                "files_examined": [str(f) for f in item.get("files_examined") or []],
            }
        )
    return findings, needs_review, rejected


def _repo_state(root: Path) -> str:
    repo = open_repository(root)
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "-uall"],
        capture_output=True, text=True, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
    ).stdout
    return f"{repo.head_commit}\n{status}"


def investigate(conn: sqlite3.Connection, task_id: int, settings: AgentSettings | None = None, again: bool = False) -> dict:
    settings = settings or AgentSettings()
    task = store.get_task(conn, task_id)
    if task["status"] == "cancelled":
        raise InvestigationError(f"Task {task_id} is cancelled. Restore it before sending it to Claude.")
    if task["status"] == "running":
        raise InvestigationError(f"Task {task_id} is already running.")
    if task["status"] == "done" and not again:
        raise InvestigationError(f"Task {task_id} is already done. Pass --again to investigate it again.")
    audit = store.get_audit(conn, task["audit_id"])
    root = Path(audit["repo_path"])
    if not root.is_dir():
        raise InvestigationError(f"The repository {root} no longer exists.")

    # The agent may also read the other repositories in the same project (for example the backend
    # a mobile app calls), so their secret files are denied too.
    audits = [audit, *store.related_audits(conn, audit["id"])]
    audit_roots = {a["id"]: Path(a["repo_path"]) for a in audits if Path(a["repo_path"]).is_dir()}
    roots = {a["repo_name"]: audit_roots[a["id"]] for a in audits if a["id"] in audit_roots}
    marks = ",".join("?" * len(audit_roots))
    secret_rows = conn.execute(
        f"SELECT audit_id, path FROM inventory_files WHERE category = 'secret' AND audit_id IN ({marks})",
        list(audit_roots),
    ).fetchall()
    secret_paths = [audit_roots[r["audit_id"]] / r["path"] for r in secret_rows]
    own_secrets = {r["path"] for r in secret_rows if r["audit_id"] == audit["id"]}

    prompt = build_prompt(conn, task, audit, sorted(own_secrets))
    before = _repo_state(root)
    run_id = store.start_run(conn, task_id, GENERAL_AGENT)
    try:
        result = run_claude(prompt, root, settings, secret_paths, [p for n, p in roots.items() if p != root])
    except InvestigationError as exc:
        store.finish_run(conn, run_id, task_id, "failed", error=str(exc))
        raise
    if _repo_state(root) != before:
        error = "The repository changed while the agent was running; results were discarded."
        store.finish_run(conn, run_id, task_id, "failed", error=error, raw_output=result.raw)
        raise InvestigationError(error)

    findings, needs_review, rejected = validate_report(result.report, roots, {p.resolve() for p in secret_paths})
    store.save_findings(conn, run_id, task_id, audit["id"], GENERAL_AGENT, findings, needs_review)
    store.finish_run(
        conn, run_id, task_id, "done",
        duration_ms=result.duration_ms, cost_usd=result.cost_usd, num_turns=result.num_turns,
        session_id=result.session_id, rejected=json.dumps(rejected), raw_output=result.raw,
    )
    return {
        "run_id": run_id,
        "findings": len(findings),
        "needs_review": len(needs_review),
        "rejected": rejected,
        "cost_usd": result.cost_usd,
        "duration_ms": result.duration_ms,
    }
