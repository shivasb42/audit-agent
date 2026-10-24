import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from audit_agent import api_map, api_tasks, investigate, review, store, views
from audit_agent.inventory import discover
from audit_agent.repo import open_repository
from tests.helpers import make_repo, repo_fingerprint
from tests.test_api_map import BACKEND, MOBILE
from tests.test_investigate import FAKE_CLAUDE


class ApiTasksTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.conn = store.connect(self.base / "audit.db")
        self.addCleanup(self.conn.close)
        self.roots, ids = {}, []
        for name, files in (("server", BACKEND), ("mobile", MOBILE)):
            root = make_repo(self.base / name, files)
            self.roots[name] = root
            repo = open_repository(root)
            audit_id = store.create_audit(self.conn, repo)
            store.save_inventory(self.conn, audit_id, discover(repo))
            ids.append(audit_id)
        self.server_id, self.mobile_id = ids
        self.project_id = store.create_project(self.conn, "Demo", ids)
        api_map.map_project(self.conn, self.project_id)
        self.counts = api_tasks.plan_project(self.conn, self.project_id)

    def tasks(self) -> dict[str, dict]:
        rows = self.conn.execute("SELECT * FROM audit_tasks WHERE kind = 'api'").fetchall()
        return {r["title"]: dict(r) for r in rows}

    def files(self, task_id: int) -> set[tuple[str, str, str]]:
        return {(f["repo_name"], f["path"], f["role"]) for f in store.api_task_files(self.conn, task_id)}

    def test_each_call_gets_the_files_on_both_sides(self):
        tasks = self.tasks()
        web = tasks["API: Web → GET /api/users/me"]
        self.assertEqual(web["audit_id"], self.server_id)
        self.assertEqual(web["app_root"], "web")
        self.assertEqual(self.files(web["id"]), {
            ("server", "web/Profile.tsx", "caller"),
            ("server", "web/api.ts", "wrapper"),
            ("server", "routes/users.ts", "route"),
            ("server", "controllers/users.ts", "handler"),
        })
        mobile = tasks["API: Unknown → GET /api/teams"]
        self.assertEqual(mobile["audit_id"], self.mobile_id)
        self.assertEqual(self.files(mobile["id"]), {
            ("mobile", "lib/screens/team.dart", "caller"),
            ("mobile", "lib/api/api_service.dart", "wrapper"),
            ("server", "routes/teams.ts", "route"),
            ("server", "controllers/teams.js", "handler"),
        })
        detail = json.loads(mobile["detail"])
        self.assertEqual(detail["route"]["handler"], "controllers/teams.js")
        self.assertEqual([c["via"] for c in detail["calls"]], ["wrapper getRequest"])

    def test_calls_that_reach_no_route_get_their_own_task_with_the_closest_route(self):
        tasks = self.tasks()
        broken = tasks["API (no route): Web → GET /api/users/settings/notifications"]
        wrong = tasks["API (wrong method): Web → POST /api/users/me"]
        self.assertGreater(broken["priority"], tasks["API: Web → GET /api/users/me"]["priority"])
        self.assertIn(("server", "web/Profile.tsx", "caller"), self.files(broken["id"]))
        self.assertTrue(any(role.startswith("closest") for _, _, role in self.files(broken["id"])))
        self.assertEqual(json.loads(wrong["detail"])["closest"]["path"], "/api/users/me")
        self.assertIsNone(json.loads(broken["detail"])["route"])

    def test_external_and_unresolved_calls_get_no_task(self):
        titles = " ".join(self.tasks())
        self.assertNotIn("football.example.com", titles)
        self.assertNotIn("api.example.com", titles)
        self.assertNotIn("pickEndpoint", titles)

    def test_planning_again_keeps_status_and_removes_only_untouched_stale_tasks(self):
        tasks = self.tasks()
        done = tasks["API: Web → GET /api/users/me"]["id"]
        self.conn.execute("UPDATE audit_tasks SET status = 'done' WHERE id = ?", (done,))
        self.conn.commit()
        again = api_tasks.plan_project(self.conn, self.project_id)
        self.assertEqual((again["created"], again["removed"], again["total"]), (0, 0, self.counts["total"]))
        self.assertEqual(store.get_task(self.conn, done)["status"], "done")

        self.conn.execute("DELETE FROM api_calls WHERE project_id = ?", (self.project_id,))
        self.conn.commit()
        cleared = api_tasks.plan_project(self.conn, self.project_id)
        self.assertEqual(cleared["removed"], self.counts["total"] - 1, "pending tasks for vanished calls are removed")
        self.assertEqual(list(self.tasks()), ["API: Web → GET /api/users/me"], "the finished one is kept")

    def test_file_planning_is_not_blocked_by_api_tasks(self):
        from audit_agent import planning
        count, created = planning.plan_audit(self.conn, self.server_id)
        self.assertTrue(created and count)

    def test_api_tasks_are_listed_with_the_calling_app(self):
        web_tasks = review.find_tasks(self.conn, self.server_id, review.TaskFilter(app="web", kind="api"))
        self.assertTrue(web_tasks)
        self.assertTrue(all(t["kind"] == "api" and t["app_root"] == "web" for t in web_tasks))
        self.assertTrue(all(t["file_count"] >= 2 for t in web_tasks))
        found = review.find_tasks(self.conn, self.mobile_id, review.TaskFilter(search="api_service"))
        self.assertTrue(found, "search covers an API task's files")
        detail = views.task_detail(self.conn, web_tasks[0]["id"])
        self.assertEqual(detail["api"]["caller_app"], "server/web")
        self.assertIn("role", detail["files"][0])
        self.assertIn("API call from", views.format_task_detail(detail))

    def test_prompt_names_every_file_with_its_role_and_the_checks(self):
        task = store.get_task(self.conn, self.tasks()["API: Unknown → GET /api/teams"]["id"])
        prompt = investigate.build_prompt(self.conn, task, store.get_audit(self.conn, self.mobile_id), [])
        self.assertIn("lib/screens/team.dart:3 GET /teams (through wrapper getRequest)", prompt)
        self.assertIn("It reaches GET /api/teams in server, declared in routes/teams.ts and handled in "
                      "controllers/teams.js.", prompt)
        self.assertIn("[route] server: routes/teams.ts", prompt)
        self.assertIn(str(self.roots["server"].resolve() / "controllers/teams.js"), prompt)
        self.assertIn("Check that both sides agree", prompt)
        self.assertIn("Authentication and authorization", prompt)

    def test_a_finding_in_the_backend_records_its_repository(self):
        fake = self.base / "fake-claude"
        fake.write_text(FAKE_CLAUDE.format(python=sys.executable))
        fake.chmod(0o755)
        handler = self.roots["server"].resolve() / "controllers/teams.js"
        report = {"findings": [{"title": "Teams list has no auth", "bug_type": "security", "severity": "high",
                                "file": str(handler), "line": 1, "evidence": "exports.listTeams = () => {};",
                                "explanation": "Anyone can call it."}], "needs_review": []}
        (self.base / "report.json").write_text(json.dumps(report))
        task_id = self.tasks()["API: Unknown → GET /api/teams"]["id"]
        before = {name: repo_fingerprint(root) for name, root in self.roots.items()}
        env = {"AUDIT_AGENT_CLAUDE": str(fake), "FAKE_CLAUDE_REPORT": str(self.base / "report.json")}
        with mock.patch.dict(os.environ, env):
            summary = investigate.investigate(self.conn, task_id, investigate.AgentSettings(runner="cli"))
        self.assertEqual(summary["findings"], 1)
        finding = store.list_findings(self.conn, task_id=task_id)[0]
        self.assertEqual((finding["file_path"], finding["file_audit_id"], finding["file_repo"]),
                         ("controllers/teams.js", self.server_id, "server"))
        self.assertEqual(finding["audit_id"], self.mobile_id)
        self.assertEqual(before, {name: repo_fingerprint(root) for name, root in self.roots.items()})


if __name__ == "__main__":
    unittest.main()
