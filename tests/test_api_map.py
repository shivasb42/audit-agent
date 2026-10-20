import json
import tempfile
import unittest
from pathlib import Path

from audit_agent import api_map, api_trace, planning, store
from audit_agent.inventory import discover
from audit_agent.repo import open_repository
from tests.helpers import make_repo, repo_fingerprint
from tests.test_cli import run_cli

BACKEND = {
    "package.json": json.dumps({"name": "server", "dependencies": {"express": "^4.18.0", "axios": "^1.6.0"}}),
    "routes/index.ts": (
        'import usersRouter from "./users";\n'
        'import teamsRouter from "./teams";\n'
        'import { requireAuth } from "../middleware/auth";\n'
        "export default function routes(app) {\n"
        '  app.use("/api/users", requireAuth, usersRouter);\n'
        "  app.use(\n    \"/api/teams\",\n    teamsRouter,\n  );\n"
        '  app.get("/api/health", (req, res) => res.send("ok"));\n'
        '  app.get("*", (req, res) => res.sendFile("index.html"));\n'
        "}\n"
    ),
    "routes/users.ts": (
        'import { Router } from "express";\n'
        'import { getMe, updateMe } from "../controllers/users";\n'
        "const router = Router();\n"
        'router.get("/me", getMe);\n'
        'router.put("/me", updateMe);\n'
        'router.get("/:id/posts", getMe);\n'
        'router.post("/avatar", updateMe);\n'
        'router.get("/legacy-export", getMe);\n'
        "export default router;\n"
    ),
    "routes/teams.ts": (
        'const express = require("express");\n'
        'const { listTeams, createTeam } = require("../controllers/teams");\n'
        "const router = express.Router();\n"
        "router\n  .route(\"/\")\n  .get(listTeams)\n  .post(createTeam);\n"
        'router.delete("/:teamId", listTeams);\n'
        "module.exports = router;\n"
    ),
    "controllers/users.ts": "export const getMe = () => {};\nexport const updateMe = () => {};\n",
    "controllers/teams.js": "exports.listTeams = () => {};\nexports.createTeam = () => {};\n",
    "middleware/auth.ts": "export const requireAuth = () => {};\n",
    "scripts/sync.js": (
        'const axios = require("axios");\n'
        'const football = axios.create({ baseURL: "https://football.example.com/v3" });\n'
        "async function syncTeams() {\n"
        '  const res = await football.get("/teams");\n'
        "  return res.data;\n"
        "}\n"
    ),
    "web/axios.ts": (
        'import axios from "axios";\n'
        "let url = `${import.meta.env.VITE_SERVER_URL}/api`;\n"
        "const axiosInstance = axios.create({ baseURL: url, timeout: 1000 });\n"
        "export default axiosInstance;\n"
    ),
    "web/api.ts": (
        'import axiosInstance from "./axios";\n'
        "export const getAction = async (route: string, callback?: any) => {\n"
        "  const res = await axiosInstance.get(route);\n"
        "  return res;\n"
        "};\n"
        "export function postAction(route, data) {\n"
        "  return axiosInstance.post(route, data);\n"
        "}\n"
        "export async function apiRequest(method: string, url: string, data?: unknown) {\n"
        '  const res = await fetch(url, { method, credentials: "include" });\n'
        "  return res;\n"
        "}\n"
        "export async function callServer(path, method) {\n"
        "  return fetch(path, { method });\n"
        "}\n"
    ),
    "web/endpoints.ts": 'export const ENDPOINTS = { avatar: "/users/avatar" };\n',
    "web/Profile.tsx": (
        'import { getAction, postAction, callServer, apiRequest } from "./api";\n'
        'const BASE_URL = "";\n'
        "export async function load(id: string) {\n"
        '  await getAction("/users/me");\n'
        "  const postsUrl = `/users/${id}/posts?limit=5`;\n"
        "  await getAction(postsUrl);\n"
        '  await postAction("/users/me", {});\n'
        '  await getAction("users/settings/notifications");\n'
        '  await apiRequest("GET", `${BASE_URL}/api/teams`);\n'
        '  await callServer("/api/health", "GET");\n'
        '  await fetch("https://api.example.com/v1/x");\n'
        "  await getAction(pickEndpoint());\n"
        '  // await getAction("/commented/out");\n'
        "}\n"
    ),
    "tests/users.test.ts": "await getAction('/does/not/exist');\n",
}

MOBILE = {
    "pubspec.yaml": "name: mobile\n",
    "lib/api/api_service.dart": (
        "class ApiService {\n"
        "  late Dio _dio;\n"
        "  late String _baseUrl;\n"
        "  ApiService() {\n"
        "    _dio = Dio(BaseOptions(connectTimeout: 5));\n"
        "    _baseUrl = Constants.apiBaseUrl;\n"
        "  }\n"
        "  Future<Response> getRequest(String route) async {\n"
        "    final url = '$_baseUrl$route';\n"
        "    return await _dio.get(url);\n"
        "  }\n"
        "  Future<Response> deleteRequest(String route) async {\n"
        "    return _dio.delete('$_baseUrl$route');\n"
        "  }\n"
        "}\n"
    ),
    "lib/screens/team.dart": (
        "import '../api/api_service.dart';\n"
        "Future<void> load(String teamId) async {\n"
        "  await api.getRequest('/teams');\n"
        "  await api.deleteRequest('/teams/$teamId');\n"
        "  await api.getRequest('/teams/${team.id}/players');\n"
        "}\n"
    ),
}


class CallPatternTest(unittest.TestCase):
    def test_literals_become_path_patterns(self):
        cases = [
            ("'/users/me'", "Dart", "/users/me"),
            ("'/teams/$teamId/players'", "Dart", "/teams/:/players"),
            ("'/teams/${team.id}'", "Dart", "/teams/:"),
            ("`${BASE_URL}/api/raffles/active`", "TypeScript", "/api/raffles/active"),
            ("`/match-stats/time?gameWeek=${week}`", "TypeScript", "/match-stats/time"),
            ('"/Users/ME/"', "JavaScript", "/users/me"),
        ]
        for literal, language, expected in cases:
            self.assertEqual(api_map.call_pattern(literal, language, False), (expected, "path"), literal)

    def test_external_and_unknown_urls(self):
        self.assertEqual(api_map.call_pattern("'https://api.example.com/x'", "Dart", False), (None, "external"))
        self.assertEqual(api_map.call_pattern("'users/me'", "Dart", False), (None, "unresolved"))
        self.assertEqual(api_map.call_pattern('"/users/"', "JavaScript", True), ("/users/:", "path"))
        self.assertEqual(api_map.call_pattern('"/users"', "JavaScript", True), (None, "unresolved"))

    def test_base_url_is_joined_like_axios(self):
        base = [("expr", "env"), ("text", "/api")]
        join = api_trace.join_base
        render = api_trace.parts_to_url
        self.assertEqual(render(join(base, [("text", "/users")])), "\x00/api/users")
        self.assertEqual(render(join(base, [("text", "users")])), "\x00/api/users")
        self.assertEqual(render(join(base, [("text", "https://x.io/a")])), "https://x.io/a")
        self.assertEqual(render(join(base, [("param", 0)])), "\x00/api/\x00")


class MapProjectTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.conn = store.connect(self.base / "audit.db")
        self.addCleanup(self.conn.close)
        self.roots = {}
        ids = []
        for name, files in (("server", BACKEND), ("mobile", MOBILE)):
            root = make_repo(self.base / name, files)
            self.roots[name] = root
            repo = open_repository(root)
            audit_id = store.create_audit(self.conn, repo)
            store.save_inventory(self.conn, audit_id, discover(repo))
            ids.append(audit_id)
        self.server_id, self.mobile_id = ids
        self.project_id = store.create_project(self.conn, "Demo", ids)
        self.before = {name: repo_fingerprint(root) for name, root in self.roots.items()}
        self.summary = api_map.map_project(self.conn, self.project_id)
        self.calls = {(c["source_path"], c["line"]): c for c in store.api_calls(self.conn, self.project_id)}

    def call(self, path: str, line: int):
        return self.calls[(path, line)]

    def test_routes_get_full_paths_methods_and_handlers(self):
        routes = {(r["method"], r["path"]): r for r in store.api_routes(self.conn, self.project_id)}
        self.assertEqual(routes[("GET", "/api/users/me")]["handler_path"], "controllers/users.ts")
        self.assertEqual(routes[("PUT", "/api/users/me")]["handler_path"], "controllers/users.ts")
        self.assertEqual(routes[("POST", "/api/teams")]["handler_path"], "controllers/teams.js")
        self.assertEqual(routes[("DELETE", "/api/teams/:teamId")]["file_path"], "routes/teams.ts")
        self.assertEqual(routes[("GET", "/api/health")]["handler_path"], "routes/index.ts")
        self.assertTrue(all(r["mounted"] for r in routes.values()))

    def test_calls_are_traced_through_wrappers_of_any_name(self):
        me = self.call("web/Profile.tsx", 4)
        self.assertEqual((me["status"], me["route_path"], me["via"]), ("matched", "/api/users/me", "wrapper getAction"))
        self.assertEqual(me["pattern"], "/api/users/me", "the axios base URL path is applied")
        posts = self.call("web/Profile.tsx", 6)
        self.assertEqual((posts["status"], posts["route_path"]), ("matched", "/api/users/:id/posts"))
        teams = self.call("web/Profile.tsx", 9)
        self.assertEqual((teams["method"], teams["route_path"], teams["via"]), ("GET", "/api/teams", "wrapper apiRequest"))
        health = self.call("web/Profile.tsx", 10)
        self.assertEqual((health["route_path"], health["via"]), ("/api/health", "wrapper callServer"))

    def test_mobile_calls_are_traced_through_the_dio_service(self):
        teams = self.call("lib/screens/team.dart", 3)
        self.assertEqual((teams["status"], teams["route_repo"], teams["route_path"], teams["via"]),
                         ("matched", "server", "/api/teams", "wrapper getRequest"))
        delete = self.call("lib/screens/team.dart", 4)
        self.assertEqual((delete["method"], delete["route_path"]), ("DELETE", "/api/teams/:teamId"))

    def test_problems_are_reported(self):
        wrong = self.call("web/Profile.tsx", 7)
        self.assertEqual((wrong["status"], wrong["method"]), ("wrong_method", "POST"))
        broken = self.call("web/Profile.tsx", 8)
        self.assertEqual((broken["status"], broken["pattern"]), ("broken", "/api/users/settings/notifications"))
        self.assertEqual(self.call("lib/screens/team.dart", 5)["status"], "broken", "the catch-all page route must not match API calls")
        self.assertEqual(self.call("web/Profile.tsx", 11)["status"], "external")
        self.assertEqual(self.call("scripts/sync.js", 4)["status"], "external", "a client with another host's base URL is external")
        unresolved = self.call("web/Profile.tsx", 12)
        self.assertEqual((unresolved["status"], unresolved["raw"]), ("unresolved", "pickEndpoint()"))

    def test_unused_routes_are_checked_with_a_reverse_search(self):
        unused = {(r["method"], r["path"]) for r in store.unused_api_routes(self.conn, self.project_id)}
        mentioned = {(r["method"], r["path"]): r for r in store.mentioned_api_routes(self.conn, self.project_id)}
        self.assertIn(("GET", "/api/users/legacy-export"), unused)
        self.assertNotIn(("GET", "/api/users/me"), unused)
        self.assertEqual(mentioned[("POST", "/api/users/avatar")]["source_path"], "web/endpoints.ts")
        self.assertNotIn(("POST", "/api/users/avatar"), unused)

    def test_wrappers_definitions_comments_and_tests_are_not_calls(self):
        sources = {path for path, _ in self.calls}
        self.assertNotIn("lib/api/api_service.dart", sources)
        self.assertNotIn("web/api.ts", sources)
        self.assertNotIn("web/axios.ts", sources)
        self.assertNotIn("tests/users.test.ts", sources)
        self.assertNotIn("/commented/out", [c["pattern"] for c in self.calls.values()])
        self.assertEqual(self.summary["calls"], len(self.calls))

    def test_task_connections_include_api_links(self):
        planning.plan_audit(self.conn, self.server_id)

        def task_with(path: str) -> int:
            return self.conn.execute(
                "SELECT task_id FROM audit_task_files WHERE audit_id = ? AND path = ?", (self.server_id, path)
            ).fetchone()[0]

        controllers = store.task_context(self.conn, task_with("controllers/users.ts"))
        handled = {(r["method"], r["path"]): r["callers"] for r in controllers["api_routes"]}
        self.assertEqual(handled[("GET", "/api/users/me")], 1)
        self.assertEqual(handled[("PUT", "/api/users/me")], 0)

        web = store.task_context(self.conn, task_with("web/Profile.tsx"))
        statuses = [c["status"] for c in web["api_calls"]]
        self.assertEqual(statuses[:2], ["broken", "wrong_method"], "problems are listed first")
        self.assertNotIn("external", statuses)

    def test_remapping_replaces_the_previous_map(self):
        again = api_map.map_project(self.conn, self.project_id)
        self.assertEqual(again["calls"], self.summary["calls"])
        for table in ("api_calls", "api_mentions"):
            count = self.conn.execute(f"SELECT COUNT(*) FROM {table} WHERE project_id = ?", (self.project_id,)).fetchone()[0]
            self.assertEqual(count, self.summary["calls"] if table == "api_calls" else count)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM api_calls WHERE project_id = ?", (self.project_id,)).fetchone()[0],
            self.summary["calls"],
        )

    def test_repositories_are_unchanged(self):
        for name, root in self.roots.items():
            self.assertEqual(self.before[name], repo_fingerprint(root), name)

    def test_cli_project_map_and_sections(self):
        db = str(self.base / "cli.db")
        for root in self.roots.values():
            self.assertEqual(run_cli("start", str(root), "--db", db).returncode, 0)
        created = run_cli("project", "Demo App", "1", "2", "--db", db)
        self.assertEqual(created.returncode, 0, created.stderr)

        mapped = run_cli("map-api", "Demo App", "--db", db)
        self.assertEqual(mapped.returncode, 0, mapped.stderr)
        self.assertIn("no route with this path", mapped.stdout)
        self.assertIn("through a wrapper", mapped.stdout)

        broken = json.loads(run_cli("api", "Demo App", "--section", "broken", "--json", "--db", db).stdout)
        self.assertEqual({b["pattern"] for b in broken}, {"/api/users/settings/notifications", "/teams/:/players"})
        mentioned = json.loads(run_cli("api", "Demo App", "--section", "mentioned", "--json", "--db", db).stdout)
        self.assertIn("/api/users/avatar", {m["path"] for m in mentioned})
        self.assertIn("Demo App", run_cli("projects", "--db", db).stdout)
        self.assertEqual(run_cli("api", "Nope", "--db", db).returncode, 1)


if __name__ == "__main__":
    unittest.main()
