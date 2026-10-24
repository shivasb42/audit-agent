import json
import threading
import time
import unittest
from unittest import mock

from audit_agent import investigate, review, runner, store, web
from tests import test_review
from tests.test_review import ReviewTestCase


def fake_investigation(conn, task_id, settings, fail=False, delay=0.0):
    """Stands in for a Claude run: records a run and a finding the way investigate() does."""
    run_id = store.start_run(conn, task_id, investigate.GENERAL_AGENT)
    time.sleep(delay)
    if fail:
        store.finish_run(conn, run_id, task_id, "failed", error="claude exited with code 1: boom")
        raise investigate.InvestigationError("claude exited with code 1: boom")
    store.save_findings(conn, run_id, task_id, store.get_task(conn, task_id)["audit_id"], investigate.GENERAL_AGENT,
                        [{"bug_type": "logic", "severity": "high", "title": "Off by one", "file_path": "lib/main.dart",
                          "line": 1, "evidence": "void main() {}", "explanation": "x"}], [])
    store.finish_run(conn, run_id, task_id, "done", cost_usd=0.01, duration_ms=5)
    return {"findings": 1, "needs_review": 0, "cost_usd": 0.01}


class RunnerTest(ReviewTestCase):
    def make_runner(self, fn=fake_investigation, parallel=2, log=None):
        return runner.Runner(self.db_path, investigate.AgentSettings(runner="cli"), parallel, fn, log or (lambda m: None))

    def test_progress_is_logged_to_the_server_terminal(self):
        lines = []
        failing = self.tasks["Audit lib/src"]["id"]
        work = self.make_runner(fn=lambda conn, tid, s: fake_investigation(conn, tid, s, fail=tid == failing),
                                log=lines.append)
        ok = self.tasks["Audit lib"]["id"]
        work.submit([ok, failing])
        self.assertTrue(work.wait_idle(5))
        text = "\n".join(lines)
        self.assertIn("Queued 2 task(s) for Claude (Claude Code (claude command), 2 at a time)", text)
        self.assertIn(f"Task #{ok} started: Audit lib", text)
        self.assertIn(f"Task #{ok} done: 1 findings, 0 to review, $0.01", text)
        self.assertIn(f"Task #{failing} failed: claude exited with code 1: boom", text)

    def test_tasks_run_and_their_findings_are_saved(self):
        work = self.make_runner()
        ids = [self.tasks["Audit lib"]["id"], self.tasks["Audit lib/src"]["id"]]
        self.assertEqual(work.submit(ids)["queued"], ids)
        self.assertTrue(work.wait_idle(5))
        self.assertEqual({self.status("Audit lib"), self.status("Audit lib/src")}, {"done"})
        self.assertEqual(len(store.list_findings(self.conn, task_id=ids[0])), 1)
        self.assertEqual({f["status"] for f in work.status()["finished"]}, {"done"})

    def test_only_runnable_tasks_are_queued(self):
        cancelled, done = self.tasks["Audit test"]["id"], self.tasks["Audit lib/src"]["id"]
        review.cancel_tasks(self.conn, [cancelled])
        self.conn.execute("UPDATE audit_tasks SET status = 'done' WHERE id = ?", (done,))
        self.conn.commit()
        result = self.make_runner(fn=lambda *a: time.sleep(0.2)).submit([cancelled, done, 99999])
        self.assertEqual(result["queued"], [])
        self.assertEqual([s["reason"] for s in result["skipped"]], ["task is cancelled", "task is done", "no such task"])

    def test_send_all_pending_respects_the_filter(self):
        work = self.make_runner()
        result = work.submit_matching(self.audit_id, review.TaskFilter(folder="lib/scripts"))
        self.assertTrue(result["queued"])
        work.wait_idle(5)
        for task in review.find_tasks(self.conn, self.audit_id):
            inside = all(p.startswith("lib/scripts/") for p in task["files"])
            self.assertEqual(task["status"], "done" if inside else "pending", task["title"])

    def test_no_more_than_the_parallel_limit_run_at_once(self):
        lock, active, peak = threading.Lock(), [0], [0]

        def slow(conn, task_id, settings):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            try:
                return fake_investigation(conn, task_id, settings, delay=0.1)
            finally:
                with lock:
                    active[0] -= 1

        work = self.make_runner(fn=slow, parallel=2)
        work.submit([t["id"] for t in self.tasks.values()])
        self.assertTrue(work.wait_idle(10))
        self.assertEqual(peak[0], 2)
        self.assertTrue(all(self.status(title) == "done" for title in self.tasks))

    def test_a_failed_task_does_not_stop_the_others(self):
        failing = self.tasks["Audit lib"]["id"]
        work = self.make_runner(fn=lambda conn, tid, s: fake_investigation(conn, tid, s, fail=tid == failing))
        work.submit([t["id"] for t in self.tasks.values()])
        self.assertTrue(work.wait_idle(10))
        self.assertEqual(self.status("Audit lib"), "failed")
        self.assertTrue(all(self.status(t) == "done" for t in self.tasks if t != "Audit lib"))
        failed = [f for f in work.status()["finished"] if f["status"] == "failed"]
        self.assertEqual([(f["id"], f["error"]) for f in failed], [(failing, "claude exited with code 1: boom")])

    def test_rate_limits_wait_and_retry(self):
        calls = []

        def limited(conn, task_id, settings):
            calls.append(task_id)
            if len(calls) == 1:
                raise investigate.InvestigationError("claude reported an error: usage limit reached")
            return fake_investigation(conn, task_id, settings)

        with mock.patch.object(runner, "RETRY_WAITS_S", (0.05,)):
            work = self.make_runner(fn=limited)
            work.submit([self.tasks["Audit lib"]["id"]])
            self.assertTrue(work.wait_idle(5))
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.status("Audit lib"), "done")

    def test_stop_drops_queued_tasks_and_running_ones_finish(self):
        work = self.make_runner(fn=lambda conn, tid, s: fake_investigation(conn, tid, s, delay=0.3), parallel=1)
        ids = [t["id"] for t in self.tasks.values()]
        work.submit(ids)
        time.sleep(0.1)
        self.assertEqual(work.stop(), len(ids) - 1)
        self.assertTrue(work.wait_idle(5))
        statuses = [store.get_task(self.conn, i)["status"] for i in ids]
        self.assertEqual(statuses.count("done"), 1)
        self.assertEqual(statuses.count("pending"), len(ids) - 1)

    def test_a_task_can_only_be_claimed_once(self):
        task_id = self.tasks["Audit lib"]["id"]
        store.start_run(self.conn, task_id, "general")
        with self.assertRaises(store.StoreError):
            store.start_run(self.conn, task_id, "general")

    def test_runs_left_running_by_a_stopped_process_are_marked_failed(self):
        task_id = self.tasks["Audit lib"]["id"]
        store.start_run(self.conn, task_id, "general")
        self.assertEqual(store.fail_interrupted_runs(self.conn), 1)
        self.assertEqual(self.status("Audit lib"), "failed")
        self.assertIn("Interrupted", store.task_runs(self.conn, task_id)[0]["error"])


class SendFromPageTest(ReviewTestCase):
    request = test_review.ReviewPageTest.request
    post = test_review.ReviewPageTest.post

    def setUp(self):
        super().setUp()
        fake = runner.Runner(self.db_path, investigate.AgentSettings(runner="cli"), 2, fake_investigation,
                             lambda m: None)
        self.server = web.ReviewServer(self.db_path, port=0, runner=fake)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def test_send_selected_and_watch_progress(self):
        ids = [self.tasks["Audit lib"]["id"], self.tasks["Audit test"]["id"]]
        status, data = self.post("/api/run", {"ids": ids, "parallel": 3})
        self.assertEqual(status, 200)
        sent = json.loads(data)
        self.assertEqual(sent["queued"], ids)
        self.assertEqual(sent["status"]["parallel"], 3)
        self.assertEqual(sent["status"]["runner"], "Claude Code (claude command)")
        self.assertTrue(self.server.runner.wait_idle(5))

        progress = json.loads(self.request("GET", "/api/run")[1])
        self.assertFalse(progress["active"])
        self.assertEqual(sorted(f["id"] for f in progress["finished"]), sorted(ids))
        detail = json.loads(self.request("GET", f"/api/tasks/{ids[0]}")[1])
        self.assertEqual([f["title"] for f in detail["findings"]], ["Off by one"])
        self.assertEqual(detail["runs"][0]["status"], "done")

    def test_send_all_pending_for_an_app(self):
        status, data = self.post("/api/run", {"audit_id": self.audit_id, "filter": {"tests": "only"}})
        self.assertEqual(json.loads(data)["queued"], [self.tasks["Audit test"]["id"]])
        self.assertTrue(self.server.runner.wait_idle(5))
        self.assertEqual(self.status("Audit test"), "done")
        self.assertEqual(self.status("Audit lib"), "pending")

    def test_sending_needs_the_page_header_and_a_valid_limit(self):
        task_id = self.tasks["Audit lib"]["id"]
        status, _ = self.request("POST", "/api/run", {"ids": [task_id]}, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 403)
        status, _ = self.post("/api/run", {"ids": [task_id], "parallel": 50})
        self.assertEqual(status, 400)
        self.assertEqual(self.status("Audit lib"), "pending")

    def test_page_has_the_claude_controls(self):
        page = self.request("GET", "/")[1]
        for control in (b'id="send-selected"', b'id="send-matching"', b'id="run-stop"', b'id="parallel"'):
            self.assertIn(control, page)

    def test_default_server_uses_the_real_investigation(self):
        server = web.ReviewServer(self.db_path, port=0)
        self.addCleanup(server.server_close)
        self.assertIs(server.runner.investigate_fn, investigate.investigate)


if __name__ == "__main__":
    unittest.main()
