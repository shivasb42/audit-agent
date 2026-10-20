import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from audit_agent import store
from audit_agent.inventory import discover
from audit_agent.repo import RepositoryError, open_repository
from tests.helpers import make_repo, repo_fingerprint

NODE_REPO = {
    "package.json": json.dumps(
        {
            "name": "node-app",
            "main": "src/index.js",
            "scripts": {"start": "node src/index.js", "build": "vite build"},
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"@types/node": "^20.0.0"},
        }
    ),
    "tsconfig.json": '{\n  // aliases\n  "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./src/*"] }, },\n}\n',
    "src/index.js": (
        "const express = require('express');\n"
        "const fs = require('node:fs');\n"
        "const util = require('./lib/util');\n"
        "// require('./commented-out')\n"
        "const missing = require('../outside/missing');\n"
        "if (require.main === module) { express(); }\n"
    ),
    "src/lib/util.js": "module.exports = { add: (a, b) => a + b };\n",
    "src/view.tsx": "import { add } from '@/lib/util';\nimport type { Thing } from './types.js';\nexport const V = () => add(1, 2);\n",
    "src/types.ts": "export type Thing = { id: string };\n",
    "scripts/deploy.sh": "#!/bin/bash\necho deploy\n",
    "Dockerfile": 'FROM node:20\nCMD ["node", "src/index.js"]\n',
    ".env": "API_KEY=super-secret-value\n",
    "logo.png": "\x89PNG\x00\x00binary",
    ".DS_Store": "\x00\x00\x00\x01Bud1",
    "web/dist/assets/index-abc123.js": "console.log('built');\n",
    "web/vendor.js": "var a=1;" * 200 + "\n",
    "web/index.html": "<!doctype html><script src='/src/view.tsx'></script>\n",
    "web/email.html": "<table>" + "<tr><td>hi</td></tr>" * 100 + "</table>\n",
    "data/big.json": "[" + "1," * 1_100_000 + "1]\n",
    "server.log": "started\n",
}

NODE_UNTRACKED = {
    "notes.md": "# scratch\n",
    "src/wip.js": "const util = require('./lib/util');\n",
    "tmp/render.png": "\x89PNG\x00\x00binary",
    "tmp/.DS_Store": "\x00\x00\x00\x01Bud1",
}

PYTHON_REPO = {
    "pyproject.toml": (
        '[project]\nname = "pyapp"\ndependencies = ["requests>=2.31", "click"]\n'
        '[project.optional-dependencies]\ndev = ["pytest"]\n'
        '[project.scripts]\npyapp = "pyapp.cli:main"\n'
    ),
    "src/pyapp/__init__.py": "",
    "src/pyapp/cli.py": (
        "import os\nimport requests\nfrom .core import run\nfrom pyapp import helpers\n\n"
        "def main():\n    run()\n\nif __name__ == '__main__':\n    main()\n"
    ),
    "src/pyapp/core.py": "def run():\n    return 1\n",
    "src/pyapp/helpers.py": "X = 1\n",
    "tools/report.py": "import sibling\n",
    "tools/sibling.py": "Y = 2\n",
    "src/pyapp/broken.py": "def oops(:\n",
    "service/main.go": "package main\n\nfunc main() {}\n",
    "service/go.mod": "module example.com/service\n",
}


DART_REPO = {
    "pubspec.yaml": (
        "name: myapp\n"
        'description: "A # in a string"\n'
        "environment:\n  sdk: \">=3.4.1 <4.0.0\"\n\n"
        "dependencies:\n"
        "  flutter:\n    sdk: flutter\n"
        "  http: ^1.2.0 # comment\n"
        "  shared_utils:\n    git:\n      url: https://example.com/utils.git\n      ref: main\n"
        "  local_pkg:\n    path: ../local_pkg\n"
        "dev_dependencies:\n  flutter_test:\n    sdk: flutter\n\n"
        "flutter:\n  uses-material-design: true\n  assets:\n    - assets/\n"
    ),
    "lib/main.dart": (
        "import 'dart:async';\n"
        "import 'package:flutter/material.dart';\n"
        "import 'package:myapp/src/api.dart' as api;\n"
        "import 'src/widgets/button.dart' show Button;\n"
        "// import 'package:myapp/old.dart';\n"
        "import 'src/io_stub.dart' if (dart.library.io) 'src/io_real.dart';\n"
        "import 'package:myapp/missing.dart';\n\n"
        "void main() async {\n  runApp(const App());\n}\n"
    ),
    "lib/src/api.dart": "part 'api.g.dart';\nclass Api {}\n",
    "lib/src/api.g.dart": "part of 'api.dart';\n// GENERATED CODE\n",
    "lib/src/widgets/button.dart": "import '../api.dart';\nclass Button {}\n",
    "lib/src/io_stub.dart": "void open() {}\n",
    "lib/src/io_real.dart": "import 'dart:io';\nvoid open() {}\n",
    "test/widget_test.dart": "import 'package:flutter_test/flutter_test.dart';\nimport 'package:myapp/main.dart';\nvoid main() {}\n",
    "android/app/build.gradle.kts": "plugins {}\n",
    "ios/Runner/AppDelegate.swift": "import Flutter\n",
    "ios/Runner/Info.plist": "<plist></plist>\n",
    "assets/logo.png": "\x89PNG\x00\x00binary",
}


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def _inventory(self, files, untracked=None, include_untracked=False):
        root = make_repo(self.base / "repo", files, untracked)
        before = repo_fingerprint(root)
        repo = open_repository(root)
        inventory = discover(repo, include_untracked=include_untracked)
        self.assertEqual(before, repo_fingerprint(root), "discovery changed the target repository")
        return repo, inventory

    def test_node_repository_inventory(self):
        repo, inv = self._inventory(NODE_REPO, untracked=NODE_UNTRACKED)
        files = {f.path: f for f in inv.files}

        self.assertEqual(repo.branch, "main")
        self.assertFalse(set(NODE_UNTRACKED) & set(files), "untracked files are excluded by default")
        for junk in (".DS_Store", "web/dist/assets/index-abc123.js", "web/vendor.js"):
            self.assertNotIn(junk, files)
        skipped = {s.reason: s.file_count for s in inv.skipped}
        self.assertEqual(skipped["untracked file (pass --include-untracked to include)"], len(NODE_UNTRACKED))
        self.assertEqual(skipped["OS metadata or log file"], 2)
        self.assertEqual(skipped["generated or build output"], 2)
        self.assertEqual((files["web/index.html"].category, files["web/index.html"].language), ("source", "HTML"))
        self.assertIn("web/email.html", files, "single-line HTML is not mistaken for minified build output")
        self.assertNotIn("data/big.json", files)
        self.assertEqual(skipped["data or docs file over 2 MB"], 1)
        self.assertEqual((files["src/index.js"].category, files["src/index.js"].language), ("source", "JavaScript"))
        self.assertEqual(files["src/view.tsx"].language, "TypeScript")
        self.assertEqual(files["scripts/deploy.sh"].language, "Shell")
        self.assertFalse(files["scripts/deploy.sh"].supported)
        self.assertNotIn("logo.png", files)
        self.assertEqual(skipped["non-code file (images, media, fonts, binaries)"], 1)
        self.assertEqual(files[".env"].category, "secret")
        self.assertIsNone(files[".env"].line_count)

        deps = {(d.name, d.scope) for d in inv.dependencies}
        self.assertEqual(deps, {("express", "runtime"), ("@types/node", "dev")})

        entries = {(e.kind, e.path) for e in inv.entry_points}
        self.assertIn(("package-main", "src/index.js"), entries)
        self.assertIn(("npm-script", "src/index.js"), entries)
        self.assertIn(("npm-script", None), entries)
        self.assertIn(("node-main", "src/index.js"), entries)
        self.assertIn(("docker", "src/index.js"), entries)

        rels = {(r.source_path, r.specifier): r for r in inv.relationships}
        self.assertEqual(rels[("src/index.js", "./lib/util")].target_path, "src/lib/util.js")
        self.assertEqual(rels[("src/index.js", "express")].kind, "package")
        self.assertEqual(rels[("src/index.js", "node:fs")].kind, "builtin")
        self.assertEqual(rels[("src/index.js", "../outside/missing")].kind, "unresolved")
        self.assertNotIn(("src/index.js", "./commented-out"), rels)
        self.assertEqual(rels[("src/view.tsx", "@/lib/util")].target_path, "src/lib/util.js")
        self.assertEqual(rels[("src/view.tsx", "./types.js")].target_path, "src/types.ts")
        self.assertEqual(rels[("src/index.js", "./lib/util")].line, 3)

        modules = {m.path: m for m in inv.modules}
        self.assertEqual(set(modules), {"src", "src/lib", "scripts", "web"})
        self.assertEqual(modules["src/lib"].package_root, ".")

        unsupported = {(u.technology, u.kind) for u in inv.unsupported}
        self.assertEqual(unsupported, {("Shell", "language"), ("HTML", "language")})

    def test_include_untracked_keeps_code_and_docs_only(self):
        _, inv = self._inventory(NODE_REPO, untracked=NODE_UNTRACKED, include_untracked=True)
        files = {f.path for f in inv.files}

        self.assertIn("notes.md", files)
        self.assertIn("src/wip.js", files)
        self.assertNotIn("tmp/render.png", files)
        self.assertNotIn("tmp/.DS_Store", files)
        skipped = {s.reason: s.file_count for s in inv.skipped}
        self.assertEqual(skipped["non-code file (images, media, fonts, binaries)"], 2)
        self.assertEqual(skipped["OS metadata or log file"], 3)
        self.assertNotIn("untracked file (pass --include-untracked to include)", skipped)
        rels = {(r.source_path, r.target_path) for r in inv.relationships}
        self.assertIn(("src/wip.js", "src/lib/util.js"), rels)

    def test_python_repository_inventory(self):
        _, inv = self._inventory(PYTHON_REPO)
        files = {f.path: f for f in inv.files}

        deps = {(d.name, d.version_spec, d.scope) for d in inv.dependencies}
        self.assertEqual(deps, {("requests", ">=2.31", "runtime"), ("click", None, "runtime"), ("pytest", None, "optional:dev")})

        entries = {(e.kind, e.path) for e in inv.entry_points}
        self.assertIn(("python-script", "src/pyapp/cli.py"), entries)
        self.assertIn(("python-main", "src/pyapp/cli.py"), entries)

        rels = {(r.source_path, r.specifier, r.target_path): r for r in inv.relationships}
        kinds = {(r.source_path, r.specifier): (r.kind, r.target_path) for r in inv.relationships}
        self.assertEqual(kinds[("src/pyapp/cli.py", "os")], ("builtin", None))
        self.assertEqual(kinds[("src/pyapp/cli.py", "requests")], ("package", None))
        self.assertEqual(kinds[("src/pyapp/cli.py", ".core")], ("internal", "src/pyapp/core.py"))
        self.assertIn(("src/pyapp/cli.py", "pyapp", "src/pyapp/helpers.py"), rels)
        self.assertEqual(kinds[("tools/report.py", "sibling")], ("internal", "tools/sibling.py"))

        self.assertTrue(files["src/pyapp/broken.py"].note.startswith("could not parse"))

        unsupported = {(u.technology, u.kind) for u in inv.unsupported}
        self.assertEqual(unsupported, {("Go", "language"), ("Go modules", "manifest")})
        modules = {m.path: m.package_root for m in inv.modules}
        self.assertEqual(modules["service"], "service")
        self.assertEqual(modules["src/pyapp"], ".")

    def test_flutter_repository_inventory(self):
        _, inv = self._inventory(DART_REPO)
        files = {f.path: f for f in inv.files}

        self.assertTrue(files["lib/main.dart"].supported)
        self.assertNotIn("lib/src/api.g.dart", files, "generated Dart is skipped")
        self.assertEqual(files["ios/Runner/Info.plist"].category, "config")

        deps = {(d.name, d.version_spec, d.scope) for d in inv.dependencies}
        self.assertEqual(
            deps,
            {
                ("flutter", "sdk: flutter", "runtime"),
                ("http", "^1.2.0", "runtime"),
                ("shared_utils", "git: https://example.com/utils.git", "runtime"),
                ("local_pkg", "path: ../local_pkg", "runtime"),
                ("flutter_test", "sdk: flutter", "dev"),
            },
        )

        entries = {(e.kind, e.path) for e in inv.entry_points}
        self.assertEqual(entries, {("dart-main", "lib/main.dart"), ("dart-test", "test/widget_test.dart")})

        rels = {(r.source_path, r.specifier): (r.kind, r.target_path or r.target_package) for r in inv.relationships}
        self.assertEqual(rels[("lib/main.dart", "dart:async")], ("builtin", "dart:async"))
        self.assertEqual(rels[("lib/main.dart", "package:flutter/material.dart")], ("package", "flutter"))
        self.assertEqual(rels[("lib/main.dart", "package:myapp/src/api.dart")], ("internal", "lib/src/api.dart"))
        self.assertEqual(rels[("lib/main.dart", "src/widgets/button.dart")], ("internal", "lib/src/widgets/button.dart"))
        self.assertEqual(rels[("lib/main.dart", "src/io_stub.dart")], ("internal", "lib/src/io_stub.dart"))
        self.assertEqual(rels[("lib/main.dart", "src/io_real.dart")], ("internal", "lib/src/io_real.dart"))
        self.assertEqual(rels[("lib/main.dart", "package:myapp/missing.dart")], ("unresolved", None))
        self.assertNotIn(("lib/main.dart", "package:myapp/old.dart"), rels)
        self.assertEqual(rels[("lib/src/api.dart", "api.g.dart")], ("generated", "lib/src/api.g.dart"))
        self.assertEqual(rels[("lib/src/widgets/button.dart", "../api.dart")], ("internal", "lib/src/api.dart"))
        self.assertEqual(rels[("test/widget_test.dart", "package:myapp/main.dart")], ("internal", "lib/main.dart"))

        unsupported = {(u.technology, u.kind) for u in inv.unsupported}
        self.assertEqual(unsupported, {("Swift", "language"), ("Kotlin", "language"), ("Gradle", "manifest")})
        self.assertEqual({m.path: m.package_root for m in inv.modules}["lib/src/widgets"], ".")

    def test_inventory_persists_and_reloads(self):
        root = make_repo(self.base / "repo", NODE_REPO)
        db_path = self.base / "data" / "audit.db"
        repo = open_repository(root)
        conn = store.connect(db_path)
        audit_id = store.create_audit(conn, repo)
        store.save_inventory(conn, audit_id, discover(repo))
        conn.close()

        reopened = store.connect(db_path)
        self.addCleanup(reopened.close)
        self.assertEqual(store.get_audit(reopened, audit_id)["status"], "inventoried")
        paths = {row["path"] for row in store.load_section(reopened, audit_id, "files")}
        self.assertIn("src/index.js", paths)
        for section in store.SECTIONS:
            self.assertTrue(store.load_section(reopened, audit_id, section), f"{section} is empty")
        dumped = json.dumps([dict(r) for s in store.SECTIONS for r in store.load_section(reopened, audit_id, s)])
        self.assertNotIn("super-secret-value", dumped)

    def test_version_1_database_is_upgraded_in_place(self):
        db_path = self.base / "old.db"
        old = sqlite3.connect(db_path)
        old.executescript(
            """CREATE TABLE audits (id INTEGER PRIMARY KEY, repo_path TEXT NOT NULL, repo_name TEXT NOT NULL,
                   head_commit TEXT, branch TEXT, working_tree_dirty INTEGER NOT NULL, status TEXT NOT NULL,
                   error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
               INSERT INTO audits VALUES (1, '/r', 'r', NULL, 'main', 0, 'inventoried', NULL, 't', 't');
               PRAGMA user_version = 1;"""
        )
        old.close()

        conn = store.connect(db_path)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], store.SCHEMA_VERSION)
        self.assertEqual(store.get_audit(conn, 1)["include_untracked"], 1)
        self.assertEqual(store.load_section(conn, 1, "skipped"), [])

    def test_database_inside_target_repository_is_refused(self):
        repo = open_repository(make_repo(self.base / "repo", NODE_REPO))
        with self.assertRaises(store.StoreError):
            store.ensure_outside_repository(repo.root / ".audit" / "audit.db", repo)
        store.ensure_outside_repository(self.base / "audit.db", repo)

    def test_non_git_directory_is_rejected(self):
        plain = self.base / "plain"
        plain.mkdir()
        with self.assertRaises(RepositoryError):
            open_repository(plain)


if __name__ == "__main__":
    unittest.main()
