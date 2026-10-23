import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from audit_agent import api_runner, credentials, investigate, planning, store
from audit_agent.inventory import discover
from audit_agent.repo import open_repository
from tests.helpers import make_repo, repo_fingerprint
from tests.test_inventory import NODE_REPO


def tool_use(name, arguments, block_id):
    return {"type": "tool_use", "id": block_id, "name": name, "input": arguments}


def response(*blocks, stop="tool_use", input_tokens=1000, output_tokens=200):
    return {
        "id": "msg_1",
        "content": list(blocks),
        "stop_reason": stop,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }


REPORT = {
    "findings": [
        {
            "title": "Unresolved import breaks startup",
            "bug_type": "logic",
            "severity": "high",
            "file": "src/index.js",
            "line": 5,
            "evidence": "const missing = require('../outside/missing');",
            "explanation": "The required file doesn't exist, so loading this module throws.",
        }
    ],
    "needs_review": [],
}


class ScriptedApi:
    """Stands in for the Anthropic API: returns scripted responses and records every request."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, body, api_key, timeout):
        self.requests.append(json.loads(json.dumps(body)))
        return self.responses.pop(0)


class ReadOnlyToolsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = make_repo(Path(tmp.name) / "repo", NODE_REPO)
        self.other = make_repo(Path(tmp.name) / "other", {"api/routes.js": "router.get('/me', getMe);\n"})
        self.tools = api_runner.ReadOnlyTools(self.root, [self.other], {self.root / ".env"})

    def test_reads_files_with_line_numbers_and_paging(self):
        out = self.tools.read_file("src/index.js", start_line=3, end_line=3)
        self.assertIn("    3  const util = require('./lib/util');", out)
        self.assertIn("showing lines 3-3", out)

    def test_other_project_repos_are_readable_by_absolute_path(self):
        self.assertIn("router.get", self.tools.read_file(str(self.other / "api/routes.js")))

    def test_secrets_git_and_outside_paths_are_refused(self):
        for path in (".env", "../../etc/passwd", ".git/config", "/etc/hosts"):
            with self.assertRaises(api_runner.ToolError, msg=path):
                self.tools.read_file(path)
        self.assertNotIn(".env", self.tools.list_files("."))
        self.assertEqual(self.tools.search("super-secret-value"), "No matches.")

    def test_search_and_list(self):
        self.assertIn("src/index.js:3:", self.tools.search(r"require\('\./lib/util'\)"))
        self.assertIn("src/index.js:", self.tools.search("express", glob="*.js"))
        self.assertIn("lib/", self.tools.list_files("src"))


class RunApiTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.conn = store.connect(self.base / "audit.db")
        self.addCleanup(self.conn.close)
        self.root = make_repo(self.base / "repo", NODE_REPO)
        repo = open_repository(self.root)
        self.audit_id = store.create_audit(self.conn, repo)
        store.save_inventory(self.conn, self.audit_id, discover(repo))
        planning.plan_audit(self.conn, self.audit_id)
        self.task_id = {t["title"]: t["id"] for t in store.list_tasks(self.conn, self.audit_id)}["Audit src"]
        key = mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test-key"})
        key.start()
        self.addCleanup(key.stop)

    def run_with(self, responses, **settings):
        api = ScriptedApi(responses)
        with mock.patch.object(api_runner, "_send", api):
            summary = investigate.investigate(self.conn, self.task_id, investigate.AgentSettings(**settings))
        return api, summary

    def test_agent_reads_code_then_submits_a_validated_report(self):
        before = repo_fingerprint(self.root)
        api, summary = self.run_with(
            [
                response(tool_use("read_file", {"path": "src/index.js"}, "t1")),
                response(tool_use("read_file", {"path": ".env"}, "t2"), tool_use("search", {"pattern": "require"}, "t3")),
                response(tool_use("submit_report", REPORT, "t4"), input_tokens=3000, output_tokens=500),
            ]
        )
        self.assertEqual(before, repo_fingerprint(self.root))
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(store.get_task(self.conn, self.task_id)["status"], "done")

        first = api.requests[0]
        self.assertEqual(first["model"], api_runner.DEFAULT_MODEL)
        self.assertEqual({t["name"] for t in first["tools"]}, {"read_file", "search", "list_files", "submit_report"})
        self.assertIn("Files to audit", first["messages"][0]["content"])

        results = api.requests[2]["messages"][-1]["content"]
        env_result = next(r for r in results if r["tool_use_id"] == "t2")
        self.assertTrue(env_result["is_error"])
        self.assertIn("secrets", env_result["content"])

        run = store.task_runs(self.conn, self.task_id)[-1]
        self.assertEqual(run["num_turns"], 3)
        self.assertAlmostEqual(run["cost_usd"], (5000 * 2.0 + 900 * 10.0) / 1_000_000)

    def test_agent_is_nudged_when_it_stops_without_a_report(self):
        _, summary = self.run_with(
            [
                response({"type": "text", "text": "I think it's fine."}, stop="end_turn"),
                response(tool_use("submit_report", {"findings": [], "needs_review": []}, "t1")),
            ]
        )
        self.assertEqual(summary["findings"], 0)

    def test_budget_stops_the_run(self):
        with self.assertRaises(investigate.InvestigationError) as caught:
            self.run_with(
                [response(tool_use("list_files", {"path": "."}, "t1"), input_tokens=500_000, output_tokens=0)],
                max_budget_usd=0.5,
            )
        self.assertIn("budget", str(caught.exception))
        self.assertEqual(store.get_task(self.conn, self.task_id)["status"], "failed")

    def test_runner_choice(self):
        self.assertIsNot(investigate.choose_runner(investigate.AgentSettings()), investigate.run_claude)
        self.assertIs(investigate.choose_runner(investigate.AgentSettings(runner="cli")), investigate.run_claude)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY")
            self.assertIs(investigate.choose_runner(investigate.AgentSettings()), investigate.run_claude)
            with self.assertRaises(investigate.InvestigationError):
                investigate.choose_runner(investigate.AgentSettings(runner="api"))

    def test_network_is_off_in_tests(self):
        with self.assertRaises(investigate.InvestigationError) as caught:
            api_runner._send({}, "sk-ant-test-key", timeout=1)
        self.assertIn("turned off", str(caught.exception))


class CredentialsTest(unittest.TestCase):
    def test_key_is_saved_privately_and_env_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "credentials"
            with mock.patch.dict(os.environ, {"AUDIT_AGENT_CREDENTIALS": str(path)}):
                os.environ.pop("ANTHROPIC_API_KEY", None)
                self.assertIsNone(credentials.get_api_key())
                credentials.save_api_key("  sk-ant-saved-key  ")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(credentials.get_api_key(), "sk-ant-saved-key")
                with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-env-key"}):
                    self.assertEqual(credentials.get_api_key(), "sk-ant-env-key")
                self.assertTrue(credentials.clear_api_key())
                self.assertIsNone(credentials.get_api_key())
        self.assertNotIn("saved-key", credentials.masked("sk-ant-saved-key-1234567890"))


if __name__ == "__main__":
    unittest.main()
