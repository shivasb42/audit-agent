import tempfile
import unittest
from pathlib import Path

from audit_agent import planning, store
from audit_agent.inventory import discover
from audit_agent.planning import MAX_TASK_LINES, chunk_files
from audit_agent.repo import open_repository
from tests.helpers import make_repo
from tests.test_inventory import DART_REPO, NODE_REPO


def lines(n: int) -> str:
    return "x = 1;\n" * n


class ChunkFilesTest(unittest.TestCase):
    def test_files_are_never_split_and_large_files_stand_alone(self):
        chunks = chunk_files(
            [
                ("app/big.ts", "app", MAX_TASK_LINES + 500),
                ("app/a.ts", "app", 900),
                ("app/b.ts", "app", 900),
                ("app/c.ts", "app", 100),
            ]
        )
        files = [[p for p, _ in c.files] for c in chunks]
        self.assertEqual(files, [["app/a.ts"], ["app/big.ts"], ["app/b.ts", "app/c.ts"]])
        self.assertEqual([c.part for c in chunks], [(1, 3), (2, 3), (3, 3)])
        self.assertEqual(planning._title(chunks[1]), "Audit app/big.ts")
        self.assertEqual(planning._title(chunks[2]), "Audit app (part 3 of 3)")

    def test_small_sibling_folders_merge_only_within_one_package(self):
        chunks = chunk_files(
            [
                ("server/routes/a.ts", "server/routes", 50),
                ("server/models/b.ts", "server/models", 50),
                ("server/tests/c.test.ts", "server/tests", 50),
                ("web/x.ts", "web", 50),
                ("api/y.ts", "api", 50),
            ],
            {"server/routes": ".", "server/models": ".", "server/tests": ".", "web": "web", "api": "."},
        )
        groups = sorted(sorted(c.folders) for c in chunks)
        self.assertEqual(groups, [["api"], ["server/models", "server/routes"], ["server/tests"], ["web"]])


class PlanAuditTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.conn = store.connect(self.base / "audit.db")
        self.addCleanup(self.conn.close)

    def _audit(self, files) -> int:
        repo = open_repository(make_repo(self.base / f"repo{len(list(self.base.iterdir()))}", files))
        audit_id = store.create_audit(self.conn, repo)
        store.save_inventory(self.conn, audit_id, discover(repo))
        return audit_id

    def _task_files(self, audit_id: int) -> list[str]:
        return [r[0] for r in self.conn.execute("SELECT path FROM audit_task_files WHERE audit_id = ?", (audit_id,))]

    def test_every_supported_file_is_in_exactly_one_task(self):
        audit_id = self._audit(NODE_REPO)
        count, created = planning.plan_audit(self.conn, audit_id)

        self.assertTrue(created)
        supported = {
            r[0]
            for r in self.conn.execute(
                "SELECT path FROM inventory_files WHERE audit_id = ? AND category = 'source' AND supported = 1",
                (audit_id,),
            )
        }
        task_files = self._task_files(audit_id)
        self.assertEqual(sorted(task_files), sorted(supported))
        self.assertEqual(len(task_files), len(set(task_files)))
        self.assertEqual(store.get_audit(self.conn, audit_id)["status"], "planned")
        self.assertTrue(all(t["status"] == "pending" for t in store.list_tasks(self.conn, audit_id)))
        self.assertEqual(count, store.task_count(self.conn, audit_id))

    def test_planning_twice_creates_no_duplicates(self):
        audit_id = self._audit(NODE_REPO)
        first, _ = planning.plan_audit(self.conn, audit_id)
        second, created = planning.plan_audit(self.conn, audit_id)
        self.assertFalse(created)
        self.assertEqual(first, second)
        self.assertEqual(store.task_count(self.conn, audit_id), first)

    def test_unsupported_files_are_listed_as_not_covered(self):
        audit_id = self._audit(DART_REPO)
        planning.plan_audit(self.conn, audit_id)
        self.assertNotIn("ios/Runner/AppDelegate.swift", self._task_files(audit_id))
        gaps = {r["what"]: r["file_count"] for r in store.not_covered(self.conn, audit_id)}
        self.assertEqual(gaps, {"Swift": 1, "Kotlin": 1})

    def test_task_shows_its_files_and_connections(self):
        audit_id = self._audit(DART_REPO)
        planning.plan_audit(self.conn, audit_id)
        tasks = {t["title"]: t for t in store.list_tasks(self.conn, audit_id)}

        widgets = store.task_context(self.conn, tasks["Audit lib/src/widgets"]["id"])
        self.assertEqual([f["path"] for f in widgets["files"]], ["lib/src/widgets/button.dart"])
        self.assertEqual([r["path"] for r in widgets["imports"]], ["lib/src/api.dart"])
        self.assertEqual([r["path"] for r in widgets["imported_by"]], ["lib/main.dart"])

        lib = store.task_context(self.conn, tasks["Audit lib"]["id"])
        self.assertEqual([e["path"] for e in lib["entry_points"]], ["lib/main.dart"])
        self.assertEqual([u["specifier"] for u in lib["unresolved"]], ["package:myapp/missing.dart"])
        self.assertIn("flutter", [p["name"] for p in lib["packages"]])
        self.assertIn("1 entry point", tasks["Audit lib"]["priority_reason"])

        ranked = [t["title"] for t in store.list_tasks(self.conn, audit_id)]
        self.assertEqual(ranked[0], "Audit lib", "the app's entry point is audited first")
        self.assertEqual(ranked[-1], "Audit test", "test-only code is audited last")

    def test_only_inventoried_audits_can_be_planned(self):
        audit_id = self._audit(NODE_REPO)
        store.mark_failed(self.conn, audit_id, "boom")
        with self.assertRaises(planning.PlanningError):
            planning.plan_audit(self.conn, audit_id)


if __name__ == "__main__":
    unittest.main()
