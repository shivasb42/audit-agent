"""SQLite persistence for audits and their repository inventories."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from audit_agent.inventory.models import Inventory
from audit_agent.repo import GitRepository

SCHEMA_VERSION = 7

SCHEMA = """
CREATE TABLE audits (
    id INTEGER PRIMARY KEY,
    repo_path TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    head_commit TEXT,
    branch TEXT,
    working_tree_dirty INTEGER NOT NULL,
    include_untracked INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE inventory_skipped (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    example_path TEXT NOT NULL
);

CREATE TABLE inventory_files (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    category TEXT NOT NULL,
    language TEXT,
    supported INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    line_count INTEGER,
    module_path TEXT,
    note TEXT,
    PRIMARY KEY (audit_id, path)
);

CREATE TABLE inventory_modules (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    package_root TEXT,
    languages TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    line_count INTEGER NOT NULL,
    PRIMARY KEY (audit_id, path)
);

CREATE TABLE inventory_dependencies (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    manifest_path TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version_spec TEXT,
    scope TEXT NOT NULL
);

CREATE TABLE inventory_entry_points (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT,
    kind TEXT NOT NULL,
    source_path TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE inventory_relationships (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    kind TEXT NOT NULL,
    specifier TEXT NOT NULL,
    target_path TEXT,
    target_package TEXT,
    line INTEGER NOT NULL
);

CREATE TABLE inventory_unsupported (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    technology TEXT NOT NULL,
    kind TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    reason TEXT NOT NULL
);

CREATE INDEX inventory_relationships_source ON inventory_relationships (audit_id, source_path);
CREATE INDEX inventory_relationships_target ON inventory_relationships (audit_id, target_path);
"""

TASK_STATUSES = ("pending", "running", "done", "failed", "blocked", "cancelled")


def _audit_tasks_ddl(name: str) -> str:
    return f"""
CREATE TABLE {name} (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    line_count INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    priority_reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN {TASK_STATUSES}),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


TASK_TABLES = _audit_tasks_ddl("audit_tasks") + """
-- The primary key keeps any file from belonging to two tasks in the same audit.
CREATE TABLE audit_task_files (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    PRIMARY KEY (audit_id, path)
);

CREATE INDEX audit_task_files_task ON audit_task_files (task_id);
"""

API_CALL_STATUSES = ("matched", "wrong_method", "broken", "unresolved", "external")

API_TABLES = f"""
CREATE TABLE projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    api_mapped_at TEXT
);

CREATE TABLE project_audits (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, audit_id)
);

CREATE TABLE api_routes (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    pattern TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    handler_path TEXT,
    mounted INTEGER NOT NULL
);

CREATE TABLE api_calls (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    method TEXT NOT NULL,
    raw TEXT NOT NULL,
    pattern TEXT,
    status TEXT NOT NULL CHECK (status IN {API_CALL_STATUSES}),
    route_id INTEGER REFERENCES api_routes(id) ON DELETE SET NULL
);

CREATE INDEX api_calls_source ON api_calls (audit_id, source_path);
CREATE INDEX api_routes_file ON api_routes (audit_id, file_path);
"""

API_TRACE_TABLES = """
ALTER TABLE api_calls ADD COLUMN via TEXT;

-- Frontend text that mentions a route no traced call reaches (from the reverse search).
CREATE TABLE api_mentions (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    route_id INTEGER NOT NULL REFERENCES api_routes(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    text TEXT NOT NULL
);
"""

FINDING_KINDS = ("finding", "needs_review")
BUG_TYPES = ("logic", "security", "concurrency")
SEVERITIES = ("low", "medium", "high", "critical")

FINDING_TABLES = f"""
CREATE TABLE task_runs (
    id INTEGER PRIMARY KEY,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'done', 'failed')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER,
    cost_usd REAL,
    num_turns INTEGER,
    session_id TEXT,
    error TEXT,
    rejected TEXT,
    raw_output TEXT
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN {FINDING_KINDS}),
    bug_type TEXT CHECK (bug_type IS NULL OR bug_type IN {BUG_TYPES}),
    severity TEXT CHECK (severity IS NULL OR severity IN {SEVERITIES}),
    title TEXT NOT NULL,
    file_path TEXT,
    line INTEGER,
    evidence TEXT,
    explanation TEXT NOT NULL,
    why_unconfirmed TEXT,
    files_examined TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX findings_task ON findings (task_id);
CREATE INDEX task_runs_task ON task_runs (task_id);
"""

SCHEMA += TASK_TABLES + API_TABLES + API_TRACE_TABLES + FINDING_TABLES

SECTIONS = {
    "files": ("inventory_files", "path"),
    "modules": ("inventory_modules", "path"),
    "dependencies": ("inventory_dependencies", "manifest_path, name"),
    "entry-points": ("inventory_entry_points", "kind, path"),
    "relationships": ("inventory_relationships", "source_path, line"),
    "unsupported": ("inventory_unsupported", "kind, technology"),
    "skipped": ("inventory_skipped", "file_count DESC"),
}

# Each entry upgrades the schema from version N to N + 1.
MIGRATIONS = {
    1: """
    -- Version 1 audits always included untracked files.
    ALTER TABLE audits ADD COLUMN include_untracked INTEGER NOT NULL DEFAULT 1;
    CREATE TABLE inventory_skipped (
        id INTEGER PRIMARY KEY,
        audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
        reason TEXT NOT NULL,
        file_count INTEGER NOT NULL,
        example_path TEXT NOT NULL
    );
    """,
    2: TASK_TABLES,
    # SQLite cannot change a CHECK constraint in place, so the table is rebuilt to allow
    # 'cancelled'. Foreign keys are off during migrations, so task files survive the rebuild.
    3: _audit_tasks_ddl("audit_tasks_new")
    + """
    INSERT INTO audit_tasks_new
        SELECT id, audit_id, title, line_count, priority, priority_reason, status, created_at, updated_at
        FROM audit_tasks;
    DROP TABLE audit_tasks;
    ALTER TABLE audit_tasks_new RENAME TO audit_tasks;
    """,
    4: API_TABLES,
    5: API_TRACE_TABLES,
    6: FINDING_TABLES,
}


class StoreError(Exception):
    pass


def default_db_path() -> Path:
    if env := os.environ.get("AUDIT_AGENT_DB"):
        return Path(env).expanduser()
    return Path.home() / ".audit-agent" / "audit.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        conn.executescript(f"BEGIN; {SCHEMA} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;")
    elif version > SCHEMA_VERSION:
        conn.close()
        raise StoreError(f"{path} uses schema version {version}; this build only knows up to {SCHEMA_VERSION}")
    while version and version < SCHEMA_VERSION:
        conn.executescript(f"BEGIN; {MIGRATIONS[version]} PRAGMA user_version = {version + 1}; COMMIT;")
        version += 1
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_outside_repository(db_path: Path, repo: GitRepository) -> None:
    resolved = Path(db_path).expanduser().resolve()
    if resolved.is_relative_to(repo.root):
        raise StoreError(
            f"The audit database {resolved} is inside the repository being audited. "
            "Choose a location outside it so the audit leaves the repository unchanged."
        )


def create_audit(conn: sqlite3.Connection, repo: GitRepository, include_untracked: bool = False) -> int:
    now = _now()
    with conn:
        cursor = conn.execute(
            """INSERT INTO audits (repo_path, repo_name, head_commit, branch, working_tree_dirty,
                                   include_untracked, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 'discovering', ?, ?)""",
            (str(repo.root), repo.name, repo.head_commit, repo.branch, int(repo.dirty),
             int(include_untracked), now, now),
        )
    return cursor.lastrowid


def mark_failed(conn: sqlite3.Connection, audit_id: int, error: str) -> None:
    with conn:
        conn.execute(
            "UPDATE audits SET status = 'failed', error = ?, updated_at = ? WHERE id = ?",
            (error, _now(), audit_id),
        )


def save_inventory(conn: sqlite3.Connection, audit_id: int, inventory: Inventory) -> None:
    with conn:
        conn.executemany(
            """INSERT INTO inventory_files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (audit_id, f.path, f.category, f.language, int(f.supported), f.size_bytes,
                 f.line_count, f.module_path, f.note)
                for f in inventory.files
            ],
        )
        conn.executemany(
            "INSERT INTO inventory_modules VALUES (?, ?, ?, ?, ?, ?)",
            [
                (audit_id, m.path, m.package_root, ",".join(m.languages), m.file_count, m.line_count)
                for m in inventory.modules
            ],
        )
        conn.executemany(
            """INSERT INTO inventory_dependencies (audit_id, manifest_path, ecosystem, name, version_spec, scope)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(audit_id, d.manifest_path, d.ecosystem, d.name, d.version_spec, d.scope) for d in inventory.dependencies],
        )
        conn.executemany(
            """INSERT INTO inventory_entry_points (audit_id, path, kind, source_path, detail)
               VALUES (?, ?, ?, ?, ?)""",
            [(audit_id, e.path, e.kind, e.source_path, e.detail) for e in inventory.entry_points],
        )
        conn.executemany(
            """INSERT INTO inventory_relationships
                   (audit_id, source_path, kind, specifier, target_path, target_package, line)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (audit_id, r.source_path, r.kind, r.specifier, r.target_path, r.target_package, r.line)
                for r in inventory.relationships
            ],
        )
        conn.executemany(
            """INSERT INTO inventory_unsupported (audit_id, technology, kind, evidence_path, file_count, reason)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(audit_id, u.technology, u.kind, u.evidence_path, u.file_count, u.reason) for u in inventory.unsupported],
        )
        conn.executemany(
            "INSERT INTO inventory_skipped (audit_id, reason, file_count, example_path) VALUES (?, ?, ?, ?)",
            [(audit_id, s.reason, s.file_count, s.example_path) for s in inventory.skipped],
        )
        conn.execute(
            "UPDATE audits SET status = 'inventoried', updated_at = ? WHERE id = ?",
            (_now(), audit_id),
        )


def get_audit(conn: sqlite3.Connection, audit_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if row is None:
        raise StoreError(f"No audit with id {audit_id}")
    return row


def list_audits(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM audits ORDER BY id").fetchall()


def load_section(conn: sqlite3.Connection, audit_id: int, section: str) -> list[sqlite3.Row]:
    table, order = SECTIONS[section]
    return conn.execute(
        f"SELECT * FROM {table} WHERE audit_id = ? ORDER BY {order}", (audit_id,)
    ).fetchall()


def save_tasks(conn: sqlite3.Connection, audit_id: int, tasks: list) -> None:
    """Insert planned tasks in the order given and mark the audit as planned."""
    now = _now()
    with conn:
        for task in tasks:
            cursor = conn.execute(
                """INSERT INTO audit_tasks (audit_id, title, line_count, priority, priority_reason,
                                            created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (audit_id, task.title, task.line_count, task.priority, task.priority_reason, now, now),
            )
            conn.executemany(
                "INSERT INTO audit_task_files (audit_id, path, task_id) VALUES (?, ?, ?)",
                [(audit_id, path, cursor.lastrowid) for path in task.files],
            )
        conn.execute(
            "UPDATE audits SET status = 'planned', updated_at = ? WHERE id = ?", (now, audit_id)
        )


def task_count(conn: sqlite3.Connection, audit_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM audit_tasks WHERE audit_id = ?", (audit_id,)).fetchone()[0]


def list_tasks(conn: sqlite3.Connection, audit_id: int, status: str | None = None) -> list[sqlite3.Row]:
    sql = """SELECT t.*, COUNT(f.path) AS file_count
             FROM audit_tasks t LEFT JOIN audit_task_files f ON f.task_id = t.id
             WHERE t.audit_id = ?"""
    params: list = [audit_id]
    if status:
        sql += " AND t.status = ?"
        params.append(status)
    sql += " GROUP BY t.id ORDER BY t.priority DESC, t.id"
    return conn.execute(sql, params).fetchall()


def get_task(conn: sqlite3.Connection, task_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM audit_tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise StoreError(f"No task with id {task_id}")
    return row


def task_context(conn: sqlite3.Connection, task_id: int) -> dict[str, list[sqlite3.Row]]:
    """A task's files and what they connect to, read from the audit's inventory."""
    task = get_task(conn, task_id)
    params = {"audit": task["audit_id"], "task": task_id}
    in_task = "SELECT path FROM audit_task_files WHERE task_id = :task"
    queries = {
        "files": f"""SELECT f.path, f.language, f.line_count FROM inventory_files f
                     WHERE f.audit_id = :audit AND f.path IN ({in_task}) ORDER BY f.path""",
        "imports": f"""SELECT r.target_path AS path, COUNT(*) AS links FROM inventory_relationships r
                       WHERE r.audit_id = :audit AND r.kind = 'internal'
                         AND r.source_path IN ({in_task}) AND r.target_path NOT IN ({in_task})
                       GROUP BY r.target_path ORDER BY links DESC, path""",
        "imported_by": f"""SELECT r.source_path AS path, COUNT(*) AS links FROM inventory_relationships r
                           WHERE r.audit_id = :audit AND r.kind = 'internal'
                             AND r.target_path IN ({in_task}) AND r.source_path NOT IN ({in_task})
                           GROUP BY r.source_path ORDER BY links DESC, path""",
        "packages": f"""SELECT r.target_package AS name, COUNT(*) AS uses FROM inventory_relationships r
                        WHERE r.audit_id = :audit AND r.kind = 'package' AND r.source_path IN ({in_task})
                        GROUP BY r.target_package ORDER BY uses DESC, name""",
        "unresolved": f"""SELECT r.source_path AS path, r.line, r.specifier FROM inventory_relationships r
                          WHERE r.audit_id = :audit AND r.kind = 'unresolved' AND r.source_path IN ({in_task})
                          ORDER BY r.source_path, r.line""",
        "entry_points": f"""SELECT e.path, e.kind, e.detail FROM inventory_entry_points e
                            WHERE e.audit_id = :audit AND e.path IN ({in_task}) ORDER BY e.path""",
        "api_calls": f"""SELECT c.source_path AS path, c.line, c.method, COALESCE(c.pattern, c.raw) AS url, c.status, c.via,
                                r.method AS route_method, r.path AS route_path, r.handler_path,
                                ra.repo_name AS route_repo
                         FROM api_calls c
                         LEFT JOIN api_routes r ON r.id = c.route_id
                         LEFT JOIN audits ra ON ra.id = r.audit_id
                         WHERE c.audit_id = :audit AND c.source_path IN ({in_task}) AND c.status != 'external'
                         ORDER BY CASE c.status WHEN 'broken' THEN 0 WHEN 'wrong_method' THEN 1
                                  WHEN 'unresolved' THEN 2 ELSE 3 END, c.source_path, c.line""",
        "api_routes": f"""SELECT r.method, r.path, r.file_path, r.handler_path,
                                 COUNT(c.id) AS callers
                          FROM api_routes r
                          LEFT JOIN api_calls c ON c.route_id = r.id AND c.status = 'matched'
                          WHERE r.audit_id = :audit
                            AND (r.file_path IN ({in_task}) OR r.handler_path IN ({in_task}))
                          GROUP BY r.id ORDER BY r.path, r.method""",
    }
    return {name: conn.execute(sql, params).fetchall() for name, sql in queries.items()}


def create_project(conn: sqlite3.Connection, name: str, audit_ids: list[int]) -> int:
    """Create a project (or reuse one with the same name) and add audits to it."""
    for audit_id in audit_ids:
        get_audit(conn, audit_id)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO projects (name, created_at) VALUES (?, ?)", (name, _now())
        )
        project_id = conn.execute("SELECT id FROM projects WHERE name = ?", (name,)).fetchone()[0]
        conn.executemany(
            "INSERT OR IGNORE INTO project_audits (project_id, audit_id) VALUES (?, ?)",
            [(project_id, a) for a in audit_ids],
        )
    return project_id


def get_project(conn: sqlite3.Connection, ref: str | int) -> sqlite3.Row:
    """Look a project up by id or by name."""
    ref = str(ref)
    row = conn.execute("SELECT * FROM projects WHERE name = ?", (ref,)).fetchone()
    if row is None and ref.isdigit():
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (int(ref),)).fetchone()
    if row is None:
        raise StoreError(f"No project named or numbered {ref!r}")
    return row


def list_projects(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT p.*, GROUP_CONCAT(a.id || ' ' || a.repo_name, ', ') AS audits
           FROM projects p
           LEFT JOIN project_audits pa ON pa.project_id = p.id
           LEFT JOIN audits a ON a.id = pa.audit_id
           GROUP BY p.id ORDER BY p.id"""
    ).fetchall()


def related_audits(conn: sqlite3.Connection, audit_id: int) -> list[sqlite3.Row]:
    """Other audits that share a project with this one."""
    return conn.execute(
        """SELECT DISTINCT a.* FROM audits a
           JOIN project_audits pa ON pa.audit_id = a.id
           WHERE pa.project_id IN (SELECT project_id FROM project_audits WHERE audit_id = ?)
             AND a.id != ?
           ORDER BY a.id""",
        (audit_id, audit_id),
    ).fetchall()


def start_run(conn: sqlite3.Connection, task_id: int, agent: str) -> int:
    now = _now()
    with conn:
        cursor = conn.execute(
            "INSERT INTO task_runs (task_id, agent, status, started_at) VALUES (?, ?, 'running', ?)",
            (task_id, agent, now),
        )
        conn.execute("UPDATE audit_tasks SET status = 'running', updated_at = ? WHERE id = ?", (now, task_id))
    return cursor.lastrowid


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    task_id: int,
    status: str,
    *,
    error: str | None = None,
    duration_ms: int | None = None,
    cost_usd: float | None = None,
    num_turns: int | None = None,
    session_id: str | None = None,
    rejected: str | None = None,
    raw_output: str | None = None,
) -> None:
    now = _now()
    with conn:
        conn.execute(
            """UPDATE task_runs SET status = ?, finished_at = ?, error = ?, duration_ms = ?, cost_usd = ?,
                   num_turns = ?, session_id = ?, rejected = ?, raw_output = ?
               WHERE id = ?""",
            (status, now, error, duration_ms, cost_usd, num_turns, session_id, rejected, raw_output, run_id),
        )
        conn.execute("UPDATE audit_tasks SET status = ?, updated_at = ? WHERE id = ?", (status, now, task_id))


def save_findings(
    conn: sqlite3.Connection,
    run_id: int,
    task_id: int,
    audit_id: int,
    agent: str,
    findings: list[dict],
    needs_review: list[dict],
) -> None:
    now = _now()
    rows = [
        (task_id, run_id, audit_id, agent, "finding", f["bug_type"], f["severity"], f["title"], f["file_path"],
         f["line"], f["evidence"], f["explanation"], None, None, now)
        for f in findings
    ] + [
        (task_id, run_id, audit_id, agent, "needs_review", n.get("bug_type"), None, n["title"], n.get("file_path"),
         n.get("line"), n.get("evidence"), n["explanation"], n.get("why_unconfirmed"),
         json.dumps(n.get("files_examined") or []), now)
        for n in needs_review
    ]
    with conn:
        conn.executemany(
            """INSERT INTO findings (task_id, run_id, audit_id, agent, kind, bug_type, severity, title, file_path,
                                     line, evidence, explanation, why_unconfirmed, files_examined, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )


def list_findings(conn: sqlite3.Connection, *, audit_id: int | None = None, task_id: int | None = None,
                  kind: str | None = None) -> list[sqlite3.Row]:
    sql = """SELECT f.*, t.title AS task_title FROM findings f JOIN audit_tasks t ON t.id = f.task_id WHERE 1 = 1"""
    params: list = []
    if audit_id is not None:
        sql += " AND f.audit_id = ?"
        params.append(audit_id)
    if task_id is not None:
        sql += " AND f.task_id = ?"
        params.append(task_id)
    if kind:
        sql += " AND f.kind = ?"
        params.append(kind)
    sql += """ ORDER BY f.kind, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
               WHEN 'low' THEN 3 ELSE 4 END, f.file_path, f.line"""
    return conn.execute(sql, params).fetchall()


def task_runs(conn: sqlite3.Connection, task_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT id, agent, status, started_at, finished_at, duration_ms, cost_usd, num_turns, error, rejected
           FROM task_runs WHERE task_id = ? ORDER BY id""",
        (task_id,),
    ).fetchall()


def project_audits(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT a.* FROM audits a JOIN project_audits pa ON pa.audit_id = a.id
           WHERE pa.project_id = ? ORDER BY a.id""",
        (project_id,),
    ).fetchall()


def unused_api_routes(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    """Routes no traced call reaches and no frontend code even mentions."""
    return conn.execute(
        """SELECT r.*, a.repo_name FROM api_routes r JOIN audits a ON a.id = r.audit_id
           WHERE r.project_id = ?
             AND NOT EXISTS (SELECT 1 FROM api_calls c WHERE c.route_id = r.id)
             AND NOT EXISTS (SELECT 1 FROM api_mentions m WHERE m.route_id = r.id)
           ORDER BY a.repo_name, r.path, r.method""",
        (project_id,),
    ).fetchall()


def mentioned_api_routes(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    """Routes with no traced call whose path still appears in frontend code."""
    return conn.execute(
        """SELECT r.method, r.path, ra.repo_name, ma.repo_name AS mention_repo,
                  m.source_path, m.line, m.text
           FROM api_mentions m
           JOIN api_routes r ON r.id = m.route_id
           JOIN audits ra ON ra.id = r.audit_id
           JOIN audits ma ON ma.id = m.audit_id
           WHERE m.project_id = ?
           ORDER BY r.path, r.method, m.source_path, m.line""",
        (project_id,),
    ).fetchall()


def api_calls(conn: sqlite3.Connection, project_id: int, status: str | None = None) -> list[sqlite3.Row]:
    sql = """SELECT c.*, a.repo_name, r.method AS route_method, r.path AS route_path,
                    r.handler_path, ra.repo_name AS route_repo
             FROM api_calls c
             JOIN audits a ON a.id = c.audit_id
             LEFT JOIN api_routes r ON r.id = c.route_id
             LEFT JOIN audits ra ON ra.id = r.audit_id
             WHERE c.project_id = ?"""
    params: list = [project_id]
    if status:
        sql += " AND c.status = ?"
        params.append(status)
    sql += " ORDER BY a.repo_name, c.source_path, c.line"
    return conn.execute(sql, params).fetchall()


def api_routes(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT r.*, a.repo_name,
                  (SELECT COUNT(*) FROM api_calls c WHERE c.route_id = r.id AND c.status = 'matched') AS callers
           FROM api_routes r JOIN audits a ON a.id = r.audit_id
           WHERE r.project_id = ? ORDER BY a.repo_name, r.path, r.method""",
        (project_id,),
    ).fetchall()


def not_covered(conn: sqlite3.Connection, audit_id: int) -> list[sqlite3.Row]:
    """Source files that no task can cover: unsupported languages and files too large to read."""
    return conn.execute(
        """SELECT CASE WHEN supported = 0 THEN language ELSE language || ' over 2 MB' END AS what,
                  COUNT(*) AS file_count, MIN(path) AS example_path
           FROM inventory_files
           WHERE audit_id = ? AND category = 'source' AND (supported = 0 OR line_count IS NULL)
           GROUP BY what ORDER BY file_count DESC, what""",
        (audit_id,),
    ).fetchall()
