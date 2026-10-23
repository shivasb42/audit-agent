"""Find the apps inside a repository and label each one backend, web, mobile, or unknown.

Every folder with a dependency manifest is an app candidate, except the native platform folders
of a mobile app (`android/`, `ios/`, ...), which belong to that app even when they carry their own
Gradle or Swift manifests. Each file belongs to the nearest app root above it.

Types are scored from facts the inventory already has. A strong signal outweighs all of a type's
supporting ones together, a type needs at least one strong signal to win, and a tie gives "unknown"
rather than a guess. Every signal found is kept as evidence, including those for types that lost.
"""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from pathlib import PurePosixPath

from audit_agent.inventory import manifests
from audit_agent.inventory.languages import is_test_path
from audit_agent.inventory.models import AppRecord, Dependency, EntryPoint, FileRecord

APP_TYPES = ("backend", "web", "mobile", "unknown")
MOBILE_PLATFORM_DIRS = ("android", "ios", "web", "macos", "linux", "windows")
WEIGHTS = {"strong": 10, "supporting": 1}

SERVER_FRAMEWORKS = frozenset(
    {"express", "fastify", "@nestjs/core", "koa", "@hapi/hapi", "restify", "flask", "fastapi", "django"}
)
DATA_PACKAGES = frozenset(
    {
        "mongoose", "mongodb", "prisma", "@prisma/client", "pg", "mysql2", "sequelize", "typeorm", "knex",
        "ioredis", "redis", "bull", "bullmq", "amqplib", "sqlalchemy", "psycopg2", "psycopg2-binary",
        "celery", "pymongo",
    }
)
UI_FRAMEWORKS = frozenset({"react-dom", "vue", "svelte", "@angular/core", "next", "nuxt"})
MOBILE_FRAMEWORKS = frozenset({"react-native", "expo"})
BUNDLER_CONFIG = re.compile(r"^(?:vite|webpack|next|nuxt|svelte|rollup)\.config\.[cm]?[jt]s$|^angular\.json$")
INDEX_HTML = ("index.html", "public/index.html", "src/index.html")
COMPONENT_SUFFIXES = (".jsx", ".tsx", ".vue", ".svelte")
PROCESS_ENTRY_KINDS = frozenset({"docker", "pm2", "procfile"})
_NOT_APP_DIRS = frozenset({"fixtures", "__fixtures__", "testdata", "__mocks__"})

_JS_ROUTE = re.compile(
    r"""\b(?:app|router|server|fastify|[A-Za-z_$][\w$]*Router)\s*\.\s*(?:get|post|put|patch|delete|all|route)\s*\(\s*['"`]/"""
)
_NEST_ROUTE = re.compile(r"""@(?:Get|Post|Put|Patch|Delete|All)\s*\(""")
_PY_ROUTE = re.compile(
    r"""^[ \t]*@\s*[A-Za-z_][\w.]*\.(?:get|post|put|patch|delete|route|api_route)\s*\(\s*['"]/""", re.M
)
_DJANGO_ROUTE = re.compile(r"""\b(?:re_)?path\s*\(\s*r?['"]""")
_JS_LISTEN = re.compile(
    r"""\b(?:app|server|httpServer|fastify|[A-Za-z_$][\w$]*Server)\s*\.\s*listen\s*\("""
    r"""|createServer\s*\((?:[^()]|\([^()]*\))*\)\s*\.\s*listen\s*\("""
)
_PY_LISTEN = re.compile(r"""\buvicorn\.run\s*\(|\b(?:app|application)\.run\s*\(|\bweb\.run_app\s*\(""")


def manifest_root(path: str) -> str | None:
    """The folder a manifest makes an app candidate ("" for the repository root), or None."""
    p = PurePosixPath(path)
    if manifests.is_package_root_marker(path):
        return posixpath.dirname(path)
    if manifests.is_requirements_file(path):
        parent = posixpath.dirname(path)
        return posixpath.dirname(parent) if p.parent.name == "requirements" else parent
    return None


def _label(root: str) -> str:
    return root or "."


def _prefix(root: str) -> str:
    return f"{root}/" if root else ""


def _nearest(path: str, roots: set[str]) -> str | None:
    current = posixpath.dirname(path)
    while True:
        if current in roots:
            return current
        if not current:
            return None
        current = posixpath.dirname(current)


def _files_phrase(paths: list[str]) -> str:
    paths = sorted(paths)
    if len(paths) == 1:
        return paths[0]
    other = len(paths) - 1
    return f"{paths[0]} and {other} other file{'s' if other > 1 else ''}"


def _names_in(deps: list[Dependency], wanted: frozenset[str]) -> dict[str, list[str]]:
    """Manifest path -> the wanted dependency names it declares."""
    found: dict[str, list[str]] = defaultdict(list)
    for dep in deps:
        if dep.name in wanted and dep.name not in found[dep.manifest_path]:
            found[dep.manifest_path].append(dep.name)
    return {m: names for m, names in found.items() if names}


def _dependency_signals(app_type: str, strength: str, deps: list[Dependency], wanted: frozenset[str]) -> list[dict]:
    return [
        {"type": app_type, "strength": strength, "signal": f"{', '.join(names)} in {manifest}"}
        for manifest, names in sorted(_names_in(deps, wanted).items())
    ]


def _signals(
    root: str,
    members: list[FileRecord],
    texts: dict[str, str],
    deps: list[Dependency],
    entry_points: list[EntryPoint],
) -> list[dict]:
    prefix = _prefix(root)
    paths = {f.path for f in members}
    local = {f.path[len(prefix):] for f in members}
    code = [
        (f.path, texts[f.path], f.language)
        for f in members
        if f.path in texts and f.language in ("JavaScript", "TypeScript", "Python") and not is_test_path(f.path)
    ]
    evidence: list[dict] = []

    routes, starts = [], []
    for path, text, language in code:
        if language == "Python":
            declares = _PY_ROUTE.search(text) or (
                PurePosixPath(path).name == "urls.py" and _DJANGO_ROUTE.search(text)
            )
            listen = _PY_LISTEN.search(text)
        else:
            declares = _JS_ROUTE.search(text) or ("@nestjs/" in text and _NEST_ROUTE.search(text))
            listen = _JS_LISTEN.search(text)
        if declares:
            routes.append(path)
        if listen:
            call = re.sub(r"\s+", "", listen.group(0)).rstrip("(")
            starts.append((path, "createServer(...).listen" if call.startswith("createServer") else call))
    if routes:
        evidence.append({"type": "backend", "strength": "strong", "signal": f"routes declared in {_files_phrase(routes)}"})
    if starts:
        first = sorted(starts)[0]
        more = f" and {len(starts) - 1} other files" if len(starts) > 1 else ""
        evidence.append({"type": "backend", "strength": "strong", "signal": f"server started in {first[0]} ({first[1]}){more}"})
    evidence += _dependency_signals("backend", "strong", deps, SERVER_FRAMEWORKS)
    evidence += _dependency_signals("backend", "supporting", deps, DATA_PACKAGES)
    starters = sorted({e.source_path for e in entry_points if e.kind in PROCESS_ENTRY_KINDS and e.source_path in paths})
    if starters:
        evidence.append({"type": "backend", "strength": "supporting", "signal": f"started by {', '.join(starters)}"})

    if any(d.name in MOBILE_FRAMEWORKS for d in deps):
        # react-dom next to react-native is react-native-web: the mobile app's web target.
        evidence += _dependency_signals("web", "strong", deps, UI_FRAMEWORKS - {"react-dom"})
        evidence += _dependency_signals("web", "supporting", deps, frozenset({"react-dom"}))
    else:
        evidence += _dependency_signals("web", "strong", deps, UI_FRAMEWORKS)
    bundlers = sorted(p for p in local if "/" not in p and BUNDLER_CONFIG.match(p))
    if bundlers:
        evidence.append({"type": "web", "strength": "supporting", "signal": "bundler config " + ", ".join(prefix + b for b in bundlers)})
    if pages := [prefix + p for p in INDEX_HTML if p in local]:
        evidence.append({"type": "web", "strength": "supporting", "signal": ", ".join(pages)})
    components = [p for p in paths if p.endswith(COMPONENT_SUFFIXES) and not is_test_path(p)]
    if components:
        kinds = "/".join(sorted({PurePosixPath(p).suffix for p in components}))
        evidence.append({"type": "web", "strength": "supporting", "signal": f"{len(components)} {kinds} components"})

    flutter = [d.manifest_path for d in deps if d.ecosystem == "pub" and d.name == "flutter"]
    if flutter:
        evidence.append({"type": "mobile", "strength": "strong", "signal": f"flutter in {flutter[0]}"})
    evidence += _dependency_signals("mobile", "strong", deps, MOBILE_FRAMEWORKS)
    native = [d for d in ("android", "ios") if any(p.startswith(f"{d}/") for p in local)]
    if native:
        evidence.append({"type": "mobile", "strength": "supporting", "signal": " and ".join(f"{prefix}{d}/" for d in native) + " folders"})
    return evidence


def choose_type(evidence: list[dict]) -> str:
    """The type with the highest score, if it has a strong signal and no other type ties it."""
    scores = {t: 0 for t in APP_TYPES[:-1]}
    strong = set()
    for item in evidence:
        scores[item["type"]] += WEIGHTS[item["strength"]]
        if item["strength"] == "strong":
            strong.add(item["type"])
    best = max(scores.values())
    winners = [t for t, s in scores.items() if s == best]
    if len(winners) != 1 or winners[0] not in strong:
        return "unknown"
    return winners[0]


def detect(
    files: list[FileRecord],
    texts: dict[str, str],
    dependencies: list[Dependency],
    entry_points: list[EntryPoint],
) -> list[AppRecord]:
    """Find app roots, set `app_root` on every file under one, and label each app."""
    manifests_by_root: dict[str, list[str]] = defaultdict(list)
    for f in files:
        parts = f.path.split("/")[:-1]
        if is_test_path(f.path) or _NOT_APP_DIRS.intersection(parts):
            continue
        root = manifest_root(f.path)
        if root is not None:
            manifests_by_root[root].append(f.path)

    deps_by_root: dict[str, list[Dependency]] = defaultdict(list)
    for dep in dependencies:
        root = manifest_root(dep.manifest_path)
        if root is not None:
            deps_by_root[root].append(dep)

    mobile_roots = [
        root
        for root in manifests_by_root
        if any((d.ecosystem == "pub" and d.name == "flutter") or d.name in MOBILE_FRAMEWORKS for d in deps_by_root[root])
    ]
    roots = set(manifests_by_root)
    for mobile in mobile_roots:
        platforms = tuple(f"{_prefix(mobile)}{d}" for d in MOBILE_PLATFORM_DIRS)
        roots -= {r for r in roots if r != mobile and (r in platforms or r.startswith(tuple(p + "/" for p in platforms)))}

    for f in files:
        f.app_root = None
        if (root := _nearest(f.path, roots)) is not None:
            f.app_root = _label(root)
    if "" not in roots and any(f.category == "source" and f.app_root is None for f in files):
        roots.add("")
        for f in files:
            if f.app_root is None:
                f.app_root = "."

    members: dict[str, list[FileRecord]] = defaultdict(list)
    for f in files:
        if f.app_root is not None:
            members[f.app_root].append(f)

    apps = []
    for root in sorted(roots):
        label = _label(root)
        app_files = members.get(label, [])
        evidence = _signals(root, app_files, texts, deps_by_root.get(root, []), entry_points)
        app_type = choose_type(evidence)
        also = []
        if app_type == "mobile" and (
            f"{_prefix(root)}web/index.html" in {f.path for f in app_files}
            or any(d.name in UI_FRAMEWORKS for d in deps_by_root.get(root, []))
        ):
            also.append("web")
        apps.append(
            AppRecord(
                root=label,
                app_type=app_type,
                manifests=sorted(manifests_by_root.get(root, [])),
                file_count=sum(1 for f in app_files if f.category == "source"),
                evidence=evidence,
                also_targets=also,
            )
        )
    return apps
