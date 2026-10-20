import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import make_repo, repo_fingerprint
from tests.test_inventory import NODE_REPO

SRC = Path(__file__).resolve().parent.parent / "src"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, PYTHONPATH=str(SRC))
    return subprocess.run([sys.executable, "-m", "audit_agent", *args], capture_output=True, text=True, env=env)


class CliTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.db = str(self.base / "state" / "audit.db")

    def test_start_then_list_inventory_from_a_new_process(self):
        root = make_repo(self.base / "repo", NODE_REPO)
        before = repo_fingerprint(root)

        started = run_cli("start", str(root), "--db", self.db)
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertIn("Audit #1: repo", started.stdout)
        self.assertIn("Shell (language, 1 files)", started.stdout)
        self.assertEqual(before, repo_fingerprint(root))

        audits = run_cli("audits", "--db", self.db)
        self.assertIn("inventoried", audits.stdout)

        summary = run_cli("inventory", "1", "--db", self.db)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertIn("JavaScript", summary.stdout)

        rows = json.loads(run_cli("inventory", "1", "--section", "relationships", "--json", "--db", self.db).stdout)
        self.assertIn({"source_path": "src/index.js", "target_path": "src/lib/util.js"},
                      [{k: r[k] for k in ("source_path", "target_path")} for r in rows])

    def test_plan_then_list_and_show_tasks(self):
        root = make_repo(self.base / "repo", NODE_REPO)
        run_cli("start", str(root), "--db", self.db)

        planned = run_cli("plan", "1", "--db", self.db)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        self.assertIn("Created", planned.stdout)
        self.assertIn("Not covered by any task:", planned.stdout)
        self.assertIn("already has", run_cli("plan", "1", "--db", self.db).stdout)

        tasks = json.loads(run_cli("tasks", "1", "--json", "--db", self.db).stdout)
        self.assertTrue(tasks)
        self.assertTrue(all(t["status"] == "pending" for t in tasks))

        detail = run_cli("task", str(tasks[0]["id"]), "--db", self.db)
        self.assertEqual(detail.returncode, 0, detail.stderr)
        self.assertIn("Files to audit", detail.stdout)
        self.assertIn("Imported by", detail.stdout)

        missing = run_cli("task", "999", "--db", self.db)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("No task with id 999", missing.stderr)

    def test_errors_are_reported_without_a_traceback(self):
        plain = self.base / "plain"
        plain.mkdir()
        result = run_cli("start", str(plain), "--db", self.db)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not inside a Git working tree", result.stderr)

        root = make_repo(self.base / "repo", NODE_REPO)
        inside = run_cli("start", str(root), "--db", str(root / "audit.db"))
        self.assertEqual(inside.returncode, 1)
        self.assertIn("inside the repository being audited", inside.stderr)
        self.assertFalse((root / "audit.db").exists())

        missing = run_cli("inventory", "99", "--db", self.db)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("No audit with id 99", missing.stderr)


if __name__ == "__main__":
    unittest.main()
