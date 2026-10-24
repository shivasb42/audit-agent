import json
import tempfile
import unittest
from pathlib import Path

from audit_agent import review, store, views
from audit_agent.inventory import apps, discover
from audit_agent.repo import open_repository
from tests.helpers import make_repo, repo_fingerprint
from tests.test_cli import run_cli

SERVER = {
    "package.json": json.dumps(
        {"name": "server", "dependencies": {"express": "^4", "mongoose": "^8", "passport": "^0.7", "axios": "^1"}}
    ),
    "index.html": "<html><body>API docs</body></html>\n",
    "App.ts": (
        'import express from "express";\n'
        'import userRouter from "./routes/User/User";\n'
        "const app = express();\n"
        'app.use("/users", userRouter);\n'
        "app.listen(3000);\n"
    ),
    "routes/User/User.ts": (
        'import { Router } from "express";\n'
        "const router = Router();\n"
        'router.get("/me", (req, res) => res.send("me"));\n'
        "export default router;\n"
    ),
    "utils/scripts/updateTeams.js": (
        'const axios = require("axios");\n'
        "async function run() {\n"
        '  await axios.get("/teams");\n'
        "}\n"
    ),
    "client/package.json": json.dumps(
        {"name": "client", "dependencies": {"react": "^18", "react-dom": "^18"}, "devDependencies": {"vite": "^5"}}
    ),
    "client/index.html": '<div id="root"></div>\n',
    "client/vite.config.js": "export default {};\n",
    "client/src/App.jsx": (
        "export default function App() {\n"
        '  fetch("/users/me");\n'
        "  return null;\n"
        "}\n"
    ),
}

MOBILE = {
    "pubspec.yaml": "name: mobile\ndependencies:\n  flutter:\n    sdk: flutter\n  dio: ^5.0.0\n",
    "lib/main.dart": "void main() {}\n",
    "lib/api.dart": (
        "import 'package:dio/dio.dart';\n"
        "final dio = Dio();\n"
        "Future<void> load() async {\n"
        "  await dio.get('/users/me');\n"
        "}\n"
    ),
    "web/index.html": "<html></html>\n",
    "android/build.gradle.kts": "plugins {}\n",
    "android/app/build.gradle.kts": "plugins {}\n",
    "android/app/src/main/kotlin/MainActivity.kt": "class MainActivity\n",
    "ios/Runner/AppDelegate.swift": "class AppDelegate {}\n",
}


class DetectTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def inventory(self, name: str, files: dict[str, str]):
        return discover(open_repository(make_repo(self.base / name, files)))

    def test_backend_with_index_html_and_web_app_inside_the_same_repository(self):
        inventory = self.inventory("server", SERVER)
        found = {a.root: a for a in inventory.apps}
        self.assertEqual({r: a.app_type for r, a in found.items()}, {".": "backend", "client": "web"})
        backend = [e["signal"] for e in found["."].evidence if e["type"] == "backend"]
        self.assertIn("routes declared in routes/User/User.ts", backend)
        self.assertIn("server started in App.ts (app.listen)", backend)
        self.assertIn("express in package.json", backend)
        self.assertIn(
            {"type": "web", "strength": "supporting", "signal": "index.html"}, found["."].evidence,
            "the root index.html is kept as evidence but does not decide the type",
        )
        self.assertEqual(found["client"].manifests, ["client/package.json"])
        roots = {f.path: f.app_root for f in inventory.files}
        self.assertEqual(roots["client/src/App.jsx"], "client")
        self.assertEqual(roots["App.ts"], ".")
        self.assertEqual(roots["utils/scripts/updateTeams.js"], ".")

    def test_flutter_app_with_web_and_native_folders_is_one_mobile_app(self):
        inventory = self.inventory("mobile", MOBILE)
        self.assertEqual([(a.root, a.app_type, a.also_targets) for a in inventory.apps], [(".", "mobile", ["web"])])
        signals = [e["signal"] for e in inventory.apps[0].evidence]
        self.assertIn("flutter in pubspec.yaml", signals)
        self.assertIn("android/ and ios/ folders", signals)
        sources = [f for f in inventory.files if f.category == "source"]
        self.assertTrue(all(f.app_root == "." for f in sources), [(f.path, f.app_root) for f in sources])

    def test_lone_supporting_signal_and_ties_give_unknown(self):
        static = self.inventory("static", {"index.html": "<html></html>\n", "main.js": "console.log(1);\n"})
        self.assertEqual([(a.root, a.app_type, a.manifests) for a in static.apps], [(".", "unknown", [])])
        tie = self.inventory("tie", {
            "package.json": json.dumps({"dependencies": {"express": "^4", "react-native": "^0.74"}}),
            "index.js": "module.exports = {};\n",
        })
        self.assertEqual(tie.apps[0].app_type, "unknown")

    def test_react_native_with_react_dom_is_mobile_that_also_targets_web(self):
        inventory = self.inventory("expo", {
            "package.json": json.dumps({"dependencies": {"expo": "^51", "react-native": "^0.74", "react-dom": "^18"}}),
            "App.tsx": "export default function App() { return null; }\n",
        })
        self.assertEqual((inventory.apps[0].app_type, inventory.apps[0].also_targets), ("mobile", ["web"]))

    def test_server_start_is_described_briefly(self):
        inventory = self.inventory("redirect", {
            "package.json": json.dumps({"dependencies": {"express": "^4"}}),
            "server.js": 'http.createServer((req, res) => {\n  res.writeHead(301, { Location: "/" });\n}).listen(80);\n',
        })
        self.assertIn("server started in server.js (createServer(...).listen)",
                      [e["signal"] for e in inventory.apps[0].evidence])

    def test_choose_type(self):
        strong = {"strength": "strong", "signal": "x"}
        supporting = {"strength": "supporting", "signal": "x"}
        self.assertEqual(apps.choose_type([]), "unknown")
        self.assertEqual(apps.choose_type([{**supporting, "type": "web"}] * 3), "unknown")
        self.assertEqual(apps.choose_type([{**strong, "type": "web"}, {**supporting, "type": "backend"}]), "web")
        self.assertEqual(apps.choose_type([{**strong, "type": "web"}, {**strong, "type": "backend"}]), "unknown")


class StartFolderTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.folder = self.base / "TC"
        self.server = make_repo(self.folder / "server", SERVER)
        self.mobile = make_repo(self.folder / "mobile", MOBILE)
        (self.folder / "node_modules" / "dep").mkdir(parents=True)
        make_repo(self.folder / "node_modules" / "dep" / "vendored", {"package.json": "{}"})
        self.db = str(self.base / "state" / "audit.db")

    def apps(self, conn, audit_ids):
        return {
            store.app_name(r["repo_name"], r["root"]): r
            for r in store.list_apps(conn, audit_ids)
        }

    def test_start_on_a_folder_builds_one_project_with_typed_apps(self):
        before = {p: repo_fingerprint(p) for p in (self.server, self.mobile)}
        started = run_cli("start", str(self.folder), "--db", self.db)
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertIn("server/client  Web", started.stdout)
        self.assertIn("mobile         Mobile, also targets web", started.stdout)
        self.assertIn("project 'TC'", started.stdout)
        self.assertEqual(before, {p: repo_fingerprint(p) for p in before}, "repositories are unchanged")

        conn = store.connect(Path(self.db))
        self.addCleanup(conn.close)
        project = store.get_project(conn, "TC")
        self.assertEqual(project["root_path"], str(self.folder.resolve()))
        self.assertIsNotNone(project["api_mapped_at"])
        audits = store.project_audits(conn, project["id"])
        self.assertEqual(sorted(a["repo_name"] for a in audits), ["mobile", "server"], "vendored repos are skipped")
        ids = [a["id"] for a in audits]
        self.assertTrue(all(store.task_count(conn, i) for i in ids))

        found = self.apps(conn, ids)
        self.assertEqual(
            {name: r["app_type"] for name, r in found.items()},
            {"server": "backend", "server/client": "web", "mobile": "mobile"},
        )
        unassigned = conn.execute(
            "SELECT path FROM inventory_files WHERE category = 'source' AND app_root IS NULL"
        ).fetchall()
        self.assertEqual(unassigned, [], "every source file belongs to an app")

        calls = {c["source_path"]: c for c in store.api_calls(conn, project["id"])}
        self.assertEqual((calls["client/src/App.jsx"]["status"], calls["client/src/App.jsx"]["route_path"]),
                         ("matched", "/users/me"))
        self.assertEqual(calls["lib/api.dart"]["status"], "matched")
        self.assertEqual(calls["utils/scripts/updateTeams.js"]["status"], "external",
                         "a backend's own HTTP calls go to other services")

    def test_corrected_type_is_kept_and_the_folder_project_is_reused(self):
        self.assertEqual(run_cli("start", str(self.folder), "--db", self.db).returncode, 0)
        corrected = run_cli("app-type", "server/client", "mobile", "--db", self.db)
        self.assertEqual(corrected.returncode, 0, corrected.stderr)
        self.assertIn("Rebuilt the API map and API-call tasks of project 'TC'", corrected.stdout)
        self.assertEqual(run_cli("app-type", "nothing/here", "web", "--db", self.db).returncode, 1)

        self.assertEqual(run_cli("start", str(self.folder), "--db", self.db).returncode, 0)
        conn = store.connect(Path(self.db))
        self.addCleanup(conn.close)
        self.assertEqual([p["name"] for p in store.list_projects(conn)], ["TC"])
        ids = [a["id"] for a in store.project_audits(conn, store.get_project(conn, "TC")["id"])]
        self.assertEqual(sorted(ids), [3, 4], "the project holds only the latest audits")
        client = self.apps(conn, ids)["server/client"]
        self.assertEqual((client["app_type"], client["detected_type"], client["type_source"]),
                         ("mobile", "web", "engineer"))

        listed = json.loads(run_cli("apps", "TC", "--json", "--db", self.db).stdout)
        self.assertEqual({a["name"]: a["type"] for a in listed},
                         {"server": "backend", "server/client": "mobile", "mobile": "mobile"})

    def test_review_page_shows_the_project_its_apps_and_api_map(self):
        self.assertEqual(run_cli("start", str(self.folder), "--db", self.db).returncode, 0)
        before = {p: repo_fingerprint(p) for p in (self.server, self.mobile)}
        conn = store.connect(Path(self.db))
        self.addCleanup(conn.close)

        groups = views.project_overview(conn)
        self.assertEqual([g["name"] for g in groups], ["TC"])
        found = {a["name"]: a for a in groups[0]["apps"]}
        self.assertEqual({n: a["type"] for n, a in found.items()},
                         {"server": "backend", "server/client": "web", "mobile": "mobile"})
        self.assertTrue(found["server"]["evidence"], "each label comes with its evidence")
        client = found["server/client"]
        tasks = review.find_tasks(conn, client["audit_id"], review.TaskFilter(app=client["root"]))
        self.assertEqual(sum(client["task_counts"].values()), len(tasks))
        file_tasks = [t for t in tasks if t["kind"] == "files"]
        self.assertTrue(file_tasks and all(all(p.startswith("client/") for p in t["files"]) for t in file_tasks),
                        "tasks are grouped by app")
        self.assertEqual([t["title"] for t in tasks if t["kind"] == "api"], ["API: Web → GET /users/me"],
                         "the app's API calls are its tasks too")
        backend_tasks = review.find_tasks(conn, client["audit_id"], review.TaskFilter(app="."))
        self.assertFalse(any(p.startswith("client/") for t in backend_tasks for p in t["files"]))

        api = views.api_map_view(conn, groups[0]["id"])
        links = {(l["from_type"], l["to_type"]): l["calls"] for l in api["links"]}
        self.assertEqual(links, {("web", "backend"): 1, ("mobile", "backend"): 1})
        route = next(r for r in api["routes"] if r["path"] == "/users/me")
        self.assertEqual(route["handler_path"], "routes/User/User.ts")
        self.assertEqual({(c["app"], c["path"]) for c in route["callers"]},
                         {("server/client", "client/src/App.jsx"), ("mobile", "lib/api.dart")})
        self.assertEqual(api["counts"]["external"], 1)
        self.assertEqual(before, {p: repo_fingerprint(p) for p in before}, "the page reads, it changes nothing")

    def test_calls_that_reach_no_route_show_the_closest_route(self):
        files = dict(SERVER)
        files["client/src/App.jsx"] = 'export function a() { fetch("/users/mine"); fetch("/nothing/like/this/at/all"); }\n'
        server = make_repo(self.base / "other" / "server", files)
        self.assertEqual(run_cli("start", str(server), "--db", self.db).returncode, 0)
        conn = store.connect(Path(self.db))
        self.addCleanup(conn.close)
        problems = {p["url"]: p for p in views.api_map_view(conn, 1)["problems"]}
        self.assertEqual(problems["/users/mine"]["app"], "server/client")
        self.assertEqual(problems["/users/mine"]["closest"], {"method": "GET", "path": "/users/me", "app": "server"})
        self.assertIsNone(problems["/nothing/like/this/at/all"]["closest"])

    def test_start_on_a_single_repository_names_the_project_after_it(self):
        started = run_cli("start", str(self.mobile / "lib"), "--db", self.db)
        self.assertEqual(started.returncode, 0, started.stderr)
        conn = store.connect(Path(self.db))
        self.addCleanup(conn.close)
        self.assertEqual([(p["name"], p["root_path"]) for p in store.list_projects(conn)],
                         [("mobile", str(self.mobile.resolve()))])


if __name__ == "__main__":
    unittest.main()
