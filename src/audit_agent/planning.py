"""Turn an audit's inventory into audit tasks: groups of whole files for an agent to investigate.

Tasks do not name a bug type. The agent decides during investigation whether there is a bug
and what kind it is. Planning only decides which files are looked at together, and in what order.
"""

from __future__ import annotations

import math
import posixpath
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field

from audit_agent import store

MAX_TASK_LINES = 1500
SMALL_CHUNK_LINES = 400
PLANNABLE_STATUSES = ("inventoried",)
TEST_ENTRY_KINDS = frozenset({"dart-test"})
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "integration_test", "test_driver", "e2e"})
_TEST_NAME = re.compile(r"(\.|_)(test|spec)\.[^.]+$|^test_[^/]+\.py$")


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    return any(p in _TEST_DIRS for p in parts[:-1]) or bool(_TEST_NAME.search(parts[-1]))


@dataclass
class Chunk:
    folders: list[str]
    files: list[tuple[str, int]]
    package_root: str | None = None
    part: tuple[int, int] | None = None

    @property
    def line_count(self) -> int:
        return sum(lines for _, lines in self.files)

    @property
    def whole_folders(self) -> bool:
        return self.part is None


@dataclass
class PlannedTask:
    title: str
    files: list[str]
    line_count: int
    priority: int
    priority_reason: str
    signals: dict[str, int] = field(default_factory=dict)


class PlanningError(Exception):
    pass


def _parent(folder: str) -> str:
    return "" if folder == "." else posixpath.dirname(folder)


def chunk_files(files: list[tuple[str, str, int]], package_roots: dict[str, str | None] | None = None) -> list[Chunk]:
    """Group (path, folder, line_count) into chunks of whole files, at most MAX_TASK_LINES each.

    A file larger than the limit gets a chunk of its own. Small folders that share a parent and
    belong to the same package (per `package_roots`, folder -> package root) are merged so tiny
    folders do not each become a task.
    """
    package_roots = package_roots or {}
    by_folder: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for path, folder, lines in files:
        by_folder[folder].append((path, lines))

    chunks: list[Chunk] = []
    for folder, members in sorted(by_folder.items()):
        bins: list[list[tuple[str, int]]] = []
        current: list[tuple[str, int]] = []
        total = 0
        for path, lines in sorted(members):
            if lines >= MAX_TASK_LINES:
                bins.append([(path, lines)])
                continue
            if current and total + lines > MAX_TASK_LINES:
                bins.append(current)
                current, total = [], 0
            current.append((path, lines))
            total += lines
        if current:
            bins.append(current)
        root = package_roots.get(folder)
        if len(bins) == 1:
            chunks.append(Chunk([folder], bins[0], root))
        else:
            chunks.extend(Chunk([folder], b, root, (i + 1, len(bins))) for i, b in enumerate(bins))

    merged: list[Chunk] = []
    for chunk in chunks:
        previous = merged[-1] if merged else None
        if (
            previous is not None
            and previous.whole_folders
            and chunk.whole_folders
            and chunk.line_count < SMALL_CHUNK_LINES
            and previous.package_root == chunk.package_root
            and is_test_path(previous.files[0][0]) == is_test_path(chunk.files[0][0])
            and _parent(previous.folders[0]) == _parent(chunk.folders[0])
            and previous.line_count + chunk.line_count <= MAX_TASK_LINES
        ):
            previous.folders.extend(chunk.folders)
            previous.files.extend(chunk.files)
        else:
            merged.append(chunk)
    return merged


def _folder_label(folder: str) -> str:
    return "the repository root" if folder == "." else folder


def _title(chunk: Chunk) -> str:
    if len(chunk.files) == 1 and chunk.files[0][1] >= MAX_TASK_LINES:
        return f"Audit {chunk.files[0][0]}"
    if chunk.part:
        return f"Audit {_folder_label(chunk.folders[0])} (part {chunk.part[0]} of {chunk.part[1]})"
    if len(chunk.folders) <= 3:
        return "Audit " + ", ".join(_folder_label(f) for f in chunk.folders)
    parent = _parent(chunk.folders[0]) or "the repository root"
    return f"Audit {len(chunk.folders)} folders under {parent}"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _priority(signals: dict[str, int], line_count: int, test_only: bool) -> tuple[int, str]:
    """Rank by facts in the inventory: entry points, how many files depend on this code (on a
    log scale, so 350 importers outranks 50 without drowning everything else), imports that point
    at missing files, and size. Test-only code ranks below the code it tests."""
    score = (
        40 * min(signals["entry_points"], 2)
        + min(round(8 * math.log2(1 + signals["imported_by"])), 70)
        + 10 * min(signals["unresolved"], 2)
        + min(line_count // 100, 15)
    )
    reasons = []
    if signals["entry_points"]:
        reasons.append(_plural(signals["entry_points"], "entry point"))
    if signals["imported_by"]:
        reasons.append(f"imported by {_plural(signals['imported_by'], 'other file')}")
    if signals["unresolved"]:
        reasons.append(_plural(signals["unresolved"], "import") + " of missing files")
    reasons.append(f"{line_count:,} lines")
    if test_only:
        score //= 3
        reasons.append("test code")
    return score, ", ".join(reasons)


def build_plan(conn: sqlite3.Connection, audit_id: int) -> list[PlannedTask]:
    files = conn.execute(
        """SELECT path, module_path, line_count FROM inventory_files
           WHERE audit_id = ? AND category = 'source' AND supported = 1 AND line_count IS NOT NULL""",
        (audit_id,),
    ).fetchall()
    package_roots = {
        row["path"]: row["package_root"]
        for row in conn.execute("SELECT path, package_root FROM inventory_modules WHERE audit_id = ?", (audit_id,))
    }
    chunks = chunk_files([(f["path"], f["module_path"], f["line_count"]) for f in files], package_roots)

    entry_points: dict[str, int] = defaultdict(int)
    for row in conn.execute(
        "SELECT path, kind FROM inventory_entry_points WHERE audit_id = ? AND path IS NOT NULL", (audit_id,)
    ):
        if row["kind"] not in TEST_ENTRY_KINDS and not is_test_path(row["path"]):
            entry_points[row["path"]] += 1
    importers: dict[str, set[str]] = defaultdict(set)
    unresolved: dict[str, int] = defaultdict(int)
    for row in conn.execute(
        """SELECT source_path, target_path, kind FROM inventory_relationships
           WHERE audit_id = ? AND kind IN ('internal', 'unresolved')""",
        (audit_id,),
    ):
        if row["kind"] == "internal":
            importers[row["target_path"]].add(row["source_path"])
        else:
            unresolved[row["source_path"]] += 1

    tasks: list[PlannedTask] = []
    for chunk in chunks:
        paths = [path for path, _ in chunk.files]
        members = set(paths)
        outside_importers = set().union(*(importers[p] for p in paths)) - members
        signals = {
            "entry_points": sum(entry_points[p] for p in paths),
            "imported_by": len(outside_importers),
            "unresolved": sum(unresolved[p] for p in paths),
        }
        score, reason = _priority(signals, chunk.line_count, all(is_test_path(p) for p in paths))
        tasks.append(PlannedTask(_title(chunk), paths, chunk.line_count, score, reason, signals))
    tasks.sort(key=lambda t: (-t.priority, t.title))
    return tasks


def plan_audit(conn: sqlite3.Connection, audit_id: int) -> tuple[int, bool]:
    """Create the audit's tasks. Returns (task count, whether tasks were created now).

    Planning an audit that already has tasks changes nothing, so it never creates duplicates.
    """
    audit = store.get_audit(conn, audit_id)
    existing = store.task_count(conn, audit_id)
    if existing:
        return existing, False
    if audit["status"] not in PLANNABLE_STATUSES:
        raise PlanningError(
            f"Audit {audit_id} is '{audit['status']}'; only an inventoried audit can be planned."
        )
    tasks = build_plan(conn, audit_id)
    store.save_tasks(conn, audit_id, tasks)
    return len(tasks), True
