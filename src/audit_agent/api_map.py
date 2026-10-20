"""Map frontend API calls to the backend routes that handle them, across a project's audits.

Routes come from Express (`router.get(...)`, `router.route(...).post(...)`, mounted with
`app.use("/prefix", router)`) and from Python decorators (`@app.get(...)`, `@app.route(...)`).
Calls come from verb-named helpers and methods (`getRequest('/x')`, `postAction("/x")`,
`api.get("/x")`), method-first helpers (`apiRequest("GET", "/x")`), and `fetch("/x")`.

Everything is read from the files on disk for each audit's inventory; no AI is involved.
"""

from __future__ import annotations

import posixpath
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from audit_agent import api_trace, store
from audit_agent.inventory.imports import _js_relationship, strip_js_comments
from audit_agent.planning import is_test_path

VERBS = ("get", "post", "put", "patch", "delete")
JS_LANGUAGES = ("JavaScript", "TypeScript")
_STRING = r"""(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`)"""

_ROUTER_VAR = re.compile(r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>]+\s*)?=\s*(?:express\s*\.\s*)?(?:Router|express)\s*\(""")
_ROUTE_CALL = re.compile(rf"""\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*({_STRING})""")
_ROUTE_CHAIN = re.compile(rf"""\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*({_STRING})\s*\)""")
_CHAIN_VERB = re.compile(r"""\.\s*(get|post|put|patch|delete|all)\s*\(""")
# A `.route(...)` chain ends at a semicolon or at a new line that doesn't continue the chain.
_CHAIN_END = re.compile(r""";|\n[ \t]*(?=[^\s.)\],])""")
_MOUNT = re.compile(rf"""\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(\s*({_STRING})\s*,""")
_PY_ROUTE = re.compile(
    r"""^[ \t]*@\s*[A-Za-z_][\w.]*\.(get|post|put|patch|delete|route|api_route)\s*\(\s*(['"])([^'"\n]+)\2([^\n]*)""",
    re.M,
)

_VERB_CALL = re.compile(
    rf"""(?<![\w$])(?:([A-Za-z_$][\w$]*)\s*\.\s*)?(get|post|put|patch|delete)(Request|Action|Data|Api)?\s*\(\s*({_STRING})?"""
)
_METHOD_FIRST = re.compile(rf"""\b[A-Za-z_$][\w$]*\s*\(\s*['"](GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*({_STRING}|[A-Za-z_$][\w$.]*)""")
_FETCH = re.compile(rf"""(?<![\w$.])fetch\s*\(\s*({_STRING}|[A-Za-z_$][\w$.\[\]]*)""")
_FETCH_METHOD = re.compile(r"""\bmethod\s*:\s*['"`](\w+)['"`]""")

_JS_BINDINGS = (
    re.compile(r"""\bimport\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s+from\s+['"]([^'"]+)['"]"""),
    re.compile(r"""\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]"""),
    re.compile(r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
)
_JS_NAMED = (
    re.compile(r"""\bimport\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]"""),
    re.compile(r"""\b(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
)


@dataclass
class Route:
    audit_id: int
    method: str
    path: str
    file_path: str
    line: int
    handler_path: str | None
    mounted: bool

    @property
    def pattern(self) -> str:
        return route_pattern(self.path)


@dataclass
class Call:
    audit_id: int
    source_path: str
    line: int
    method: str
    raw: str
    pattern: str | None
    status: str = "unresolved"
    route: Route | None = None
    via: str = "name"


@dataclass
class _RouterFile:
    routes: list[tuple[str, str, int, str | None]] = field(default_factory=list)
    mounts: list[tuple[str, str]] = field(default_factory=list)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _literal_body(literal: str) -> str:
    return literal[1:-1]


def _join(*parts: str) -> str:
    joined = "/".join(p.strip("/") for p in parts if p and p.strip("/"))
    return "/" + joined


def route_pattern(path: str) -> str:
    segments = []
    for seg in path.lower().split("/"):
        if not seg:
            continue
        segments.append(":" if seg.startswith(":") else seg)
    return "/" + "/".join(segments)


def call_pattern(literal: str, language: str | None, followed_by_plus: bool) -> tuple[str | None, str]:
    """Turn a string literal used as a URL into (pattern, status hint).

    Returns status 'external' for absolute URLs, 'unresolved' when the path can't be known.
    Interpolations become ':' segments, a leading base-URL interpolation is dropped, and the
    query string is ignored."""
    body = _literal_body(literal)
    interpolation = r"\$\{[^}]*\}|\$[A-Za-z_]\w*" if language == "Dart" else r"\$\{[^}]*\}"
    return normalize_url(re.sub(interpolation, "\x00", body), followed_by_plus)


def normalize_url(body: str, followed_by_plus: bool = False) -> tuple[str | None, str]:
    """Normalize a URL in which \\x00 marks unknown values. A leading unknown value is a base URL
    and is dropped; unknown values inside the path become ':' segments."""
    body = re.sub(r"^\x00+", "", body)
    if re.match(r"^[a-z][a-z0-9+.-]*://", body, re.I):
        return None, "external"
    if not body.startswith("/"):
        return None, "unresolved"
    body = re.split(r"[?#]", body, maxsplit=1)[0]
    if followed_by_plus:
        if not body.endswith("/"):
            return None, "unresolved"
        body += "\x00"
    segments = []
    for seg in body.lower().split("/"):
        if not seg:
            continue
        segments.append(":" if "\x00" in seg or seg.startswith(":") else seg)
    return "/" + "/".join(segments), "path"


def _split_args(text: str, start: int) -> tuple[list[str], int]:
    """Split call arguments starting just after '(' into top-level pieces."""
    depth, quote, args, current, i = 0, None, [], [], start
    while i < len(text):
        c = text[i]
        if quote:
            current.append(c)
            if c == "\\":
                current.append(text[i + 1 : i + 2])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
            current.append(c)
        elif c in "([{":
            depth += 1
            current.append(c)
        elif c in ")]}":
            if depth == 0:
                args.append("".join(current).strip())
                return [a for a in args if a], i
            depth -= 1
            current.append(c)
        elif c == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(c)
        i += 1
    return [a for a in args if a], i


def _callee_name(arg: str) -> str | None:
    match = re.match(r"^([A-Za-z_$][\w$]*)", arg.strip())
    return match.group(1) if match else None


def _js_bindings(source: str, code: str, file_set: set[str]) -> dict[str, str]:
    """Local names bound by imports/requires, mapped to the repo file they come from."""
    raw: dict[str, str] = {}
    for pattern in _JS_BINDINGS:
        for name, spec in pattern.findall(code):
            raw[name] = spec
    for pattern in _JS_NAMED:
        for names, spec in pattern.findall(code):
            for part in names.split(","):
                part = part.strip()
                if not part:
                    continue
                local = re.split(r"\s+as\s+|\s*:\s*", part)[-1].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
                    raw[local] = spec
    bindings = {}
    for name, spec in raw.items():
        rel = _js_relationship(source, spec, 0, file_set, [])
        if rel.target_path:
            bindings[name] = rel.target_path
    return bindings


def _scan_js_routes(path: str, code: str, file_set: set[str]) -> _RouterFile | None:
    receivers = {"app", "router"} | set(_ROUTER_VAR.findall(code))
    result = _RouterFile()
    bindings: dict[str, str] | None = None

    def handler_for(args: list[str]) -> str | None:
        nonlocal bindings
        if bindings is None:
            bindings = _js_bindings(path, code, file_set)
        name = _callee_name(args[-1]) if args else None
        return bindings.get(name) if name else None

    for m in _ROUTE_CALL.finditer(code):
        if m.group(1) not in receivers or m.group(3)[0] == "`" and "${" in m.group(3):
            continue
        args, _ = _split_args(code, m.end())
        result.routes.append((m.group(2), _literal_body(m.group(3)), _line(code, m.start()), handler_for(args)))
    for m in _ROUTE_CHAIN.finditer(code):
        if m.group(1) not in receivers:
            continue
        chain = code[m.end() : m.end() + 3000]
        if stop := _CHAIN_END.search(chain):
            chain = chain[: stop.start()]
        for verb in _CHAIN_VERB.finditer(chain):
            args, _ = _split_args(chain, verb.end())
            result.routes.append(
                (verb.group(1), _literal_body(m.group(2)), _line(code, m.start()), handler_for(args))
            )
    for m in _MOUNT.finditer(code):
        if m.group(1) not in receivers:
            continue
        args, _ = _split_args(code, m.end())
        if bindings is None:
            bindings = _js_bindings(path, code, file_set)
        for arg in reversed(args):
            name = _callee_name(arg)
            if name in bindings:
                result.mounts.append((_literal_body(m.group(2)), bindings[name]))
                break
            req = re.match(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", arg)
            if req:
                rel = _js_relationship(path, req.group(1), 0, file_set, [])
                if rel.target_path:
                    result.mounts.append((_literal_body(m.group(2)), rel.target_path))
                break
    return result if result.routes or result.mounts else None


def _python_routes(audit_id: int, path: str, text: str) -> list[Route]:
    routes = []
    for m in _PY_ROUTE.finditer(text):
        verb, route_path, rest = m.group(1), m.group(3), m.group(4)
        if verb in ("route", "api_route"):
            methods = re.findall(r"""['"](GET|POST|PUT|PATCH|DELETE)['"]""", rest, re.I) or ["GET"]
        else:
            methods = [verb]
        for method in methods:
            routes.append(Route(audit_id, method.upper(), route_path, path, _line(text, m.start()), path, True))
    return routes


def _resolve_prefixes(routers: dict[str, _RouterFile]) -> dict[str, set[str]]:
    """Every full prefix each router file is reachable at, following mounts from root files."""
    mounted_by: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for parent, info in routers.items():
        for prefix, child in info.mounts:
            mounted_by[child].append((parent, prefix))
    prefixes: dict[str, set[str]] = {}

    def resolve(path: str, seen: frozenset[str]) -> set[str]:
        if path in prefixes:
            return prefixes[path]
        parents = [(p, pre) for p, pre in mounted_by.get(path, []) if p not in seen]
        if not parents:
            return {""}
        found = set()
        for parent, prefix in parents:
            for base in resolve(parent, seen | {path}):
                found.add(_join(base, prefix))
        return found

    for path in routers:
        prefixes[path] = resolve(path, frozenset({path}))
    return prefixes


def _is_definition(code: str, start: int, end: int, args: list[str]) -> bool:
    """True for `function getAction(route) {`, `Future<Response> getRequest(String route) async {`."""
    before = code[max(0, start - 40) : start]
    after = code[end + 1 : end + 20].lstrip()
    if re.search(r"\b(function|def)\s+$", before) or after.startswith(("{", "=>", "async")):
        return True
    return bool(re.fullmatch(r"[A-Za-z_][\w<>?,\s]*\s+[A-Za-z_]\w*", args[0]))


def _scan_calls(audit_id: int, path: str, code: str, language: str, receivers: set[str]) -> list[Call]:
    calls: list[Call] = []
    seen: set[int] = set()

    def add(pos: int, method: str, literal: str | None, raw: str) -> None:
        if pos in seen:
            return
        seen.add(pos)
        if literal is None or literal[0] not in "'\"`":
            calls.append(Call(audit_id, path, _line(code, pos), method, raw, None, "unresolved"))
            return
        after = code[pos + len(raw) :].lstrip()[:1] if raw.endswith(literal) else ""
        pattern, hint = call_pattern(literal, language, after == "+")
        calls.append(Call(audit_id, path, _line(code, pos), method, literal, pattern, hint if hint != "path" else "unresolved"))

    for m in _VERB_CALL.finditer(code):
        receiver, verb, suffix, literal = m.group(1), m.group(2), m.group(3), m.group(4)
        if receiver in receivers and not suffix:
            continue
        if literal is None:
            if suffix:
                args, end = _split_args(code, m.end())
                if args and not _is_definition(code, m.start(), end, args):
                    add(m.start(), verb.upper(), None, args[0])
            continue
        body = _literal_body(literal)
        looks_like_url = re.match(r"^(?:\$\{[^}]*\}|\$[A-Za-z_]\w*)*(/|https?://)", body)
        if not looks_like_url:
            continue
        add(m.start(4), verb.upper(), literal, literal)
    for m in _METHOD_FIRST.finditer(code):
        target = m.group(2)
        if target[0] in "'\"`":
            add(m.start(2), m.group(1).upper(), target, target)
        else:
            add(m.start(2), m.group(1).upper(), None, target)
    for m in _FETCH.finditer(code):
        target = m.group(1)
        args, _ = _split_args(code, m.start(1))
        options = args[1] if len(args) > 1 else ""
        method = (_FETCH_METHOD.search(options).group(1) if _FETCH_METHOD.search(options) else "GET").upper()
        if target[0] in "'\"`":
            add(m.start(1), method, target, target)
        else:
            add(m.start(1), method, None, target)
    return calls


def _segments(pattern: str) -> list[str]:
    return [s for s in pattern.split("/") if s]


def _score(call: list[str], route: list[str]) -> float | None:
    if route and route[-1] == "*":
        if len(call) < len(route) - 1:
            return None
        route = route[:-1]
        call = call[: len(route)]
    elif len(call) != len(route):
        return None
    score = 0.0
    for c, r in zip(call, route):
        if c == r:
            score += 1
        elif r == ":" or c == ":":
            score += 0.25 if r == c else 0
        else:
            return None
    return score


def _common_prefixes(routes: list[Route]) -> list[str]:
    firsts = Counter(_segments(r.pattern)[0] for r in routes if _segments(r.pattern))
    total = max(1, len(routes))
    return [f"/{seg}" for seg, n in firsts.most_common() if n >= 5 and n / total >= 0.3]


def match_calls(calls: list[Call], routes: list[Route]) -> None:
    prefixes = _common_prefixes(routes)
    by_length: dict[int, list[Route]] = defaultdict(list)
    wildcard: list[Route] = []
    for route in routes:
        segs = _segments(route.pattern)
        if segs == ["*"]:
            # A bare catch-all (`app.get("*", ...)`) is a page fallback, not an API endpoint.
            continue
        (wildcard if segs and segs[-1] == "*" else by_length[len(segs)]).append(route)
    for call in calls:
        if call.pattern is None:
            continue
        candidates = [call.pattern] + [p + call.pattern for p in prefixes if not call.pattern.startswith(p + "/")]
        best: tuple[float, Route] | None = None
        best_any_method: tuple[float, Route] | None = None
        for candidate in candidates:
            segs = _segments(candidate)
            for route in by_length.get(len(segs), []) + wildcard:
                score = _score(segs, _segments(route.pattern))
                if score is None:
                    continue
                if best_any_method is None or score > best_any_method[0]:
                    best_any_method = (score, route)
                if route.method in (call.method, "ALL") and (best is None or score > best[0]):
                    best = (score, route)
        if best:
            call.status, call.route = "matched", best[1]
        elif best_any_method:
            call.status, call.route = "wrong_method", best_any_method[1]
        else:
            call.status = "broken"


def scan_project(conn: sqlite3.Connection, project_id: int) -> tuple[list[Route], list[Call], int, list[tuple]]:
    """Read every audit's supported source files from disk and collect routes, calls, and
    mentions of otherwise-unreached routes. Returns (routes, calls, unreadable files, mentions)."""
    routes: list[Route] = []
    calls: list[Call] = []
    frontend_texts: dict[tuple[int, str], str] = {}
    unreadable = 0
    for audit in store.project_audits(conn, project_id):
        root = Path(audit["repo_path"])
        files = conn.execute(
            """SELECT path, language FROM inventory_files
               WHERE audit_id = ? AND category = 'source' AND supported = 1 AND line_count IS NOT NULL""",
            (audit["id"],),
        ).fetchall()
        file_set = {f["path"] for f in files}
        routers: dict[str, _RouterFile] = {}
        texts: dict[str, tuple[str, str]] = {}
        for f in files:
            if is_test_path(f["path"]):
                continue
            try:
                text = (root / f["path"]).read_text(encoding="utf-8", errors="replace")
            except OSError:
                unreadable += 1
                continue
            language = f["language"]
            code = text if language == "Python" else strip_js_comments(text)
            texts[f["path"]] = (code, language)
            if language in JS_LANGUAGES and (info := _scan_js_routes(f["path"], code, file_set)):
                routers[f["path"]] = info
            elif language == "Python":
                routes.extend(_python_routes(audit["id"], f["path"], text))

        prefixes = _resolve_prefixes(routers)
        mounted_children = {child for info in routers.values() for _, child in info.mounts}
        for path, info in routers.items():
            is_mounted = path in mounted_children or bool(info.mounts)
            for verb, route_path, line, handler in info.routes:
                for prefix in sorted(prefixes.get(path, {""})):
                    routes.append(
                        Route(audit["id"], verb.upper(), _join(prefix, route_path), path, line, handler or path, is_mounted)
                    )

        wrapper_lines: set[tuple[str, int]] = set()
        audit_calls = _trace_calls(conn, audit["id"], texts, wrapper_lines)
        traced_lines = {(c.source_path, c.line) for c in audit_calls} | wrapper_lines
        for path, (code, language) in texts.items():
            if language not in JS_LANGUAGES + ("Dart",):
                continue
            receivers = {"app", "router"} | set(_ROUTER_VAR.findall(code))
            for call in _scan_calls(audit["id"], path, code, language, receivers):
                if (call.source_path, call.line) not in traced_lines:
                    audit_calls.append(call)
        calls.extend(audit_calls)
        frontend_texts.update(
            {(audit["id"], p): code for p, (code, lang) in texts.items()
             if p not in routers and lang in JS_LANGUAGES + ("Dart",)}
        )

    match_calls(calls, routes)
    mentions = find_mentions(routes, calls, frontend_texts)
    return routes, calls, unreadable, mentions


def _trace_calls(
    conn: sqlite3.Connection, audit_id: int, texts: dict[str, tuple[str, str]], wrapper_lines: set[tuple[str, int]]
) -> list[Call]:
    """Calls found by following code to the real HTTP client call (see api_trace). Lines inside
    wrappers, where the URL is still a parameter, are added to `wrapper_lines`."""
    imports = {
        (row["source_path"], row["specifier"]): row["target_path"]
        for row in conn.execute(
            "SELECT source_path, specifier, target_path FROM inventory_relationships WHERE audit_id = ? AND kind = 'internal'",
            (audit_id,),
        )
    }
    files = {
        path: api_trace.build_file(path, code, language)
        for path, (code, language) in texts.items()
        if language in JS_LANGUAGES + ("Dart",)
    }
    resolved, unresolved, inside_wrappers = api_trace.trace_project(
        files, lambda path, spec: imports.get((path, spec))
    )
    calls = []
    wrapper_lines.update((path, _line(files[path].code, pos)) for path, pos in inside_wrappers)
    for traced, known in [(t, True) for t in resolved] + [(t, False) for t in unresolved]:
        code = files[traced.path].code
        url = api_trace.parts_to_url(traced.parts)
        pattern, hint = normalize_url(url) if known else (None, "unresolved")
        status = "external" if hint == "external" else "unresolved"
        raw = traced.raw if pattern is None else url.replace("\x00", "{…}")
        calls.append(
            Call(audit_id, traced.path, _line(code, traced.pos), traced.method, raw, pattern, status, None, traced.via)
        )
    return calls


def find_mentions(routes: list[Route], calls: list[Call], texts: dict[tuple[int, str], str]) -> list[tuple]:
    """For routes no call reaches, search frontend code for their path (with the project's common
    prefix optional). Returns (route, audit_id, path, line, text) for up to 3 hits per route."""
    reached = {id(c.route) for c in calls if c.route}
    prefixes = _common_prefixes(routes)
    lowered = {key: code.lower() for key, code in texts.items()}
    found = []
    for route in routes:
        segs = _segments(route.pattern)
        if id(route) in reached or not segs or "*" in segs:
            continue
        variants = [segs]
        if len(segs) > 1 and f"/{segs[0]}" in prefixes:
            variants.append(segs[1:])
        hits = 0
        for variant in variants:
            literals = [s for s in variant if s != ":"]
            if not literals or max(len(s) for s in literals) < 3:
                continue
            anchor = max(literals, key=len)
            # A route parameter only matches a value filled in by code (`${id}`, `$id`), and the
            # path must end where the route ends, so `/leagues/:id` doesn't match `/leagues/x/top`.
            param = r"(?:\$\{[^}]*\}|\$[a-z_]\w*)"
            body = "/".join(re.escape(s) if s != ":" else param for s in variant)
            regex = re.compile(rf"(?<![\w/.-])/{body}(?![\w/-])")
            for (audit_id, path), code in lowered.items():
                if anchor not in code:
                    continue
                for m in regex.finditer(code):
                    line_start = code.rfind("\n", 0, m.start()) + 1
                    line_end = code.find("\n", m.end())
                    original = texts[(audit_id, path)][line_start : line_end if line_end != -1 else None]
                    found.append((route, audit_id, path, code.count("\n", 0, m.start()) + 1, original.strip()[:200]))
                    hits += 1
                    if hits >= 3:
                        break
                if hits >= 3:
                    break
            if hits:
                break
    return found


def map_project(conn: sqlite3.Connection, project_id: int) -> dict:
    """Rebuild the project's API map and return a summary."""
    routes, calls, unreadable, mentions = scan_project(conn, project_id)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    route_ids: dict[int, int] = {}
    with conn:
        conn.execute("DELETE FROM api_mentions WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM api_calls WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM api_routes WHERE project_id = ?", (project_id,))
        for route in routes:
            cursor = conn.execute(
                """INSERT INTO api_routes (project_id, audit_id, method, path, pattern, file_path, line,
                                           handler_path, mounted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (project_id, route.audit_id, route.method, route.path, route.pattern, route.file_path,
                 route.line, route.handler_path, int(route.mounted)),
            )
            route_ids[id(route)] = cursor.lastrowid
        conn.executemany(
            """INSERT INTO api_calls (project_id, audit_id, source_path, line, method, raw, pattern, status,
                                      route_id, via)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (project_id, c.audit_id, c.source_path, c.line, c.method, c.raw[:300], c.pattern, c.status,
                 route_ids.get(id(c.route)) if c.route else None, c.via)
                for c in calls
            ],
        )
        conn.executemany(
            """INSERT INTO api_mentions (project_id, route_id, audit_id, source_path, line, text)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(project_id, route_ids[id(r)], audit_id, path, line, text) for r, audit_id, path, line, text in mentions],
        )
        conn.execute("UPDATE projects SET api_mapped_at = ? WHERE id = ?", (now, project_id))
    statuses = Counter(c.status for c in calls)
    return {
        "routes": len(routes),
        "calls": len(calls),
        "statuses": {s: statuses.get(s, 0) for s in store.API_CALL_STATUSES},
        "unused_routes": len(store.unused_api_routes(conn, project_id)),
        "mentioned_routes": len({m[0].path + m[0].method for m in mentions}),
        "via": dict(Counter(c.via.split(" ")[0] for c in calls)),
        "unreadable_files": unreadable,
    }
