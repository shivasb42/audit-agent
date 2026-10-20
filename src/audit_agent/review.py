"""Reviewing an audit's tasks before they run: filtering, cancelling, and restoring."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from audit_agent import store
from audit_agent.planning import is_test_path

CANCELLABLE_STATUSES = ("pending", "blocked", "failed")
TEST_FILTERS = ("only", "hide")


@dataclass(frozen=True)
class TaskFilter:
    status: str | None = None
    folder: str | None = None
    tests: str | None = None
    search: str | None = None

    def __post_init__(self) -> None:
        if self.status and self.status not in store.TASK_STATUSES:
            raise ValueError(f"unknown status {self.status!r}")
        if self.tests and self.tests not in TEST_FILTERS:
            raise ValueError(f"tests must be one of {TEST_FILTERS}")


def _task_files(conn: sqlite3.Connection, audit_id: int) -> dict[int, list[str]]:
    files: dict[int, list[str]] = defaultdict(list)
    for row in conn.execute(
        "SELECT task_id, path FROM audit_task_files WHERE audit_id = ? ORDER BY path", (audit_id,)
    ):
        files[row["task_id"]].append(row["path"])
    return files


def _matches(task: dict, files: list[str], f: TaskFilter) -> bool:
    if f.status and task["status"] != f.status:
        return False
    if f.folder:
        prefix = f.folder.strip("/") + "/"
        # Every file must be under the folder, so a bulk cancel never catches code outside it.
        if not files or not all(p.startswith(prefix) for p in files):
            return False
    if f.tests == "only" and not task["test_only"]:
        return False
    if f.tests == "hide" and task["test_only"]:
        return False
    if f.search:
        needle = f.search.lower()
        if needle not in task["title"].lower() and not any(needle in p.lower() for p in files):
            return False
    return True


def find_tasks(conn: sqlite3.Connection, audit_id: int, f: TaskFilter = TaskFilter()) -> list[dict]:
    """Tasks matching the filter, highest priority first, each with its files and a test-only flag."""
    store.get_audit(conn, audit_id)
    files = _task_files(conn, audit_id)
    found = []
    for row in store.list_tasks(conn, audit_id):
        task = dict(row)
        task_paths = files.get(task["id"], [])
        task["files"] = task_paths
        task["test_only"] = bool(task_paths) and all(is_test_path(p) for p in task_paths)
        if _matches(task, task_paths, f):
            found.append(task)
    return found


def _set_status(conn: sqlite3.Connection, task_ids: list[int], new: str, allowed: tuple[str, ...]) -> int:
    if not task_ids:
        return 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    marks = ",".join("?" * len(task_ids))
    allowed_marks = ",".join("?" * len(allowed))
    with conn:
        cursor = conn.execute(
            f"UPDATE audit_tasks SET status = ?, updated_at = ? "
            f"WHERE id IN ({marks}) AND status IN ({allowed_marks})",
            (new, now, *task_ids, *allowed),
        )
    return cursor.rowcount


def cancel_tasks(conn: sqlite3.Connection, task_ids: list[int]) -> int:
    """Cancel tasks so they are never sent to Claude. Done and running tasks are left alone.
    Returns how many tasks changed."""
    return _set_status(conn, task_ids, "cancelled", CANCELLABLE_STATUSES)


def restore_tasks(conn: sqlite3.Connection, task_ids: list[int]) -> int:
    """Put cancelled tasks back in the queue as pending. Returns how many tasks changed."""
    return _set_status(conn, task_ids, "pending", ("cancelled",))


def cancel_matching(conn: sqlite3.Connection, audit_id: int, f: TaskFilter) -> int:
    return cancel_tasks(conn, [t["id"] for t in find_tasks(conn, audit_id, f)])


def restore_matching(conn: sqlite3.Connection, audit_id: int, f: TaskFilter) -> int:
    return restore_tasks(conn, [t["id"] for t in find_tasks(conn, audit_id, f)])
