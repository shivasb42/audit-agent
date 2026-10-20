"""Find API calls by following code to the real HTTP client call.

1. Find HTTP clients in each file: `fetch`, `axios` and instances from `axios.create(...)`
   (also when imported from another file), Dart `Dio(...)` instances, and Dart `http`.
2. Find every request made on a client and evaluate its URL argument. A URL built only from
   text and outside values is a call. A URL that comes from the enclosing function's own
   parameter makes that function a wrapper, whatever it is called.
3. Find each wrapper's call sites (through imports), read the URL from the matching argument,
   and repeat for wrappers of wrappers.

URLs are kept as a list of parts: ("text", s), ("param", index), or ("expr", source). Values
held in local variables are followed a few steps. This is static reading of the code, so URLs
built from runtime data stay unresolved rather than guessed.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

Part = tuple[str, object]

JS_LANGUAGES = ("JavaScript", "TypeScript")
_KEYWORDS = frozenset(
    "if for while switch catch with return function await new typeof super else do case "
    "throw yield delete void in of instanceof try finally".split()
)
_IDENT = r"[A-Za-z_$][\w$]*"
_REQUEST_VERBS = ("get", "post", "put", "patch", "delete", "head", "request")


@dataclass
class Func:
    name: str | None
    params: list[str]
    body_start: int
    body_end: int
    header: int


@dataclass
class Client:
    name: str
    base: list[Part] | None = None


@dataclass
class FileCtx:
    path: str
    code: str
    language: str
    pairs: dict[int, int]
    funcs: list[Func]
    clients: dict[str, Client] = field(default_factory=dict)
    _imports: tuple | None = None
    _default_export: str | None | bool = False

    @property
    def imports(self) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
        if self._imports is None:
            self._imports = _js_imports(self.code) if self.language in JS_LANGUAGES else ({}, {})
        return self._imports

    @property
    def default_export(self) -> str | None:
        if self._default_export is False:
            self._default_export = default_export(self.code) if self.language in JS_LANGUAGES else None
        return self._default_export


@dataclass
class Traced:
    """A resolved request: the URL parts with the client's base already applied."""

    path: str
    pos: int
    method: str
    parts: list[Part]
    raw: str
    via: str


@dataclass
class Wrapper:
    path: str
    name: str
    url_parts: list[Part]
    method: str | None
    method_param: int | None
    via: str


# ---------------------------------------------------------------- parsing helpers


def match_pairs(code: str) -> dict[int, int]:
    """Map each opening bracket to its closing bracket, skipping string contents."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    quote: str | None = None
    i, n = 0, len(code)
    closers = {")": "(", "]": "[", "}": "{"}
    while i < n:
        c = code[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote or (c == "\n" and quote != "`"):
                quote = None
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            stack.append(i)
        elif c in closers:
            while stack and code[stack[-1]] != closers[c]:
                stack.pop()
            if stack:
                pairs[stack.pop()] = i
        i += 1
    return pairs


def split_top(text: str, sep: str = ",") -> list[str]:
    """Split on a separator at bracket depth zero, outside strings."""
    parts, depth, quote, current = [], 0, None, []
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            current.append(c)
            if c == "\\" and i + 1 < len(text):
                current.append(text[i + 1])
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
            depth -= 1
            current.append(c)
        elif c == sep and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(c)
        i += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _args(ctx: FileCtx, open_pos: int) -> list[str]:
    close = ctx.pairs.get(open_pos)
    if close is None:
        return []
    return split_top(ctx.code[open_pos + 1 : close])


def _line(code: str, pos: int) -> int:
    return code.count("\n", 0, pos) + 1


def _param_name(arg: str, language: str) -> str | None:
    arg = arg.strip()
    if not arg or arg[0] in "{[":
        return None
    arg = arg.lstrip(".").split("=", 1)[0].strip()
    names = re.findall(_IDENT, arg)
    if not names:
        return None
    if language == "Dart":
        return names[-1]
    names = [n for n in names if n not in ("readonly", "public", "private", "protected")]
    return names[0] if names else None


def find_functions(code: str, pairs: dict[int, int], language: str) -> list[Func]:
    funcs: list[Func] = []
    for open_pos, close in pairs.items():
        if code[open_pos] != "(":
            continue
        after = code[close + 1 : close + 160]
        head = re.match(r"\s*(?:async\s*\*?\s*|sync\s*\*\s*)?(?::\s*[^{=;()]+?\s*)?(\{|=>)", after)
        if not head:
            continue
        before = code[max(0, open_pos - 120) : open_pos]
        ident = re.search(rf"({_IDENT})\s*$", before)
        name = ident.group(1) if ident else None
        if name in _KEYWORDS and name != "function":
            continue
        if name in (None, "async", "function"):
            assigned = re.search(rf"({_IDENT})\s*[=:]\s*(?:async\s*)?(?:function\s*)?$", before)
            name = assigned.group(1) if assigned else None
        params = []
        for arg in split_top(code[open_pos + 1 : close]):
            if arg.startswith(("{", "[")):
                break
            params.append(_param_name(arg, language) or "")
        body_open = close + 1 + head.start(1)
        if head.group(1) == "{":
            body_end = pairs.get(body_open, len(code))
        else:
            expression = body_open + 2
            body_end = expression + _statement_end(code[expression : expression + 20000])
        funcs.append(Func(name, params, body_open, body_end, open_pos))
    return funcs


def enclosing(funcs: list[Func], pos: int) -> Func | None:
    best = None
    for f in funcs:
        if f.body_start <= pos <= f.body_end and (best is None or f.body_start > best.body_start):
            best = f
    return best


# ---------------------------------------------------------------- evaluating URL expressions


def _strip_casts(expr: str) -> str:
    expr = expr.strip()
    expr = re.sub(r"\s+as\s+[\w.<>\[\]|]+$", "", expr)
    return expr.rstrip("!").strip()


def _literal_parts(literal: str, language: str, resolve) -> list[Part]:
    quote, body = literal[0], literal[1:-1]
    if language == "Dart":
        token = re.compile(r"\$\{([^}]*)\}|\$([A-Za-z_]\w*)")
    elif quote == "`":
        token = re.compile(r"\$\{([^}]*)\}")
    else:
        return [("text", body)]
    parts: list[Part] = []
    last = 0
    for m in token.finditer(body):
        if m.start() > last:
            parts.append(("text", body[last : m.start()]))
        parts.extend(resolve((m.group(1) or m.group(2) or "").strip()))
        last = m.end()
    if last < len(body):
        parts.append(("text", body[last:]))
    return parts


def _statement_end(text: str) -> int:
    """Index where the expression at the start of `text` ends."""
    depth, quote, i = 0, None, 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote or (c == "\n" and quote != "`"):
                quote = None
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and c in ";,":
            return i
        elif depth == 0 and c == "\n" and text[i + 1 :].lstrip()[:1] not in ("+", "?", ":", ".", "|", "&"):
            return i
        i += 1
    return len(text)


def _declared_value(ctx: FileCtx, name: str, start: int, end: int) -> str | None:
    """The expression last assigned to `name` between start and end, if any."""
    pattern = re.compile(rf"(?<![\w$.]){re.escape(name)}\s*=(?![=>])\s*")
    value = None
    for m in pattern.finditer(ctx.code, start, end):
        rest = ctx.code[m.end() : end]
        value = rest[: _statement_end(rest)].strip()
    return value


def evaluate(ctx: FileCtx, expr: str, func: Func | None, pos: int, depth: int = 0) -> list[Part]:
    expr = _strip_casts(expr)
    if not expr or depth > 4:
        return [("expr", expr)]

    def resolve(inner: str) -> list[Part]:
        return evaluate(ctx, inner, func, pos, depth + 1)

    if len(expr) >= 2 and expr[0] in "'\"`" and expr[-1] == expr[0] and expr.count(expr[0]) == 2 + expr[1:-1].count("\\" + expr[0]):
        return _literal_parts(expr, ctx.language, resolve)
    pieces = split_top(expr, "+")
    if len(pieces) > 1:
        out: list[Part] = []
        for piece in pieces:
            out.extend(resolve(piece))
        return out
    wrapped = re.fullmatch(r"(?:Uri\.parse|new\s+URL|encodeURI)\s*\((.*)\)", expr, re.S)
    if wrapped:
        return resolve(split_top(wrapped.group(1))[0] if split_top(wrapped.group(1)) else "")
    if re.fullmatch(_IDENT, expr):
        if func and expr in func.params:
            return [("param", func.params.index(expr))]
        scope_start = func.body_start if func else 0
        value = _declared_value(ctx, expr, scope_start, pos)
        if value is None and func is not None:
            value = _declared_value(ctx, expr, 0, func.header)
        if value is not None and value != expr:
            return resolve(value)
    return [("expr", expr)]


def has_param(parts: list[Part]) -> bool:
    return any(kind == "param" for kind, _ in parts)


def starts_with_param(parts: list[Part]) -> bool:
    """True when the URL itself comes from a parameter (`getRequest(route)`), as opposed to a
    parameter filling one segment of a fixed path (`'/activity/post/$postId'`). A leading unknown
    value is a base URL and is skipped."""
    for kind, value in parts:
        if kind in ("expr", "sep") or (kind == "text" and not str(value).strip("/ ")):
            continue
        return kind == "param"
    return False


def _path_is_known(parts: list[Part]) -> bool:
    """True if the request's own path (after any client base URL) contains known text."""
    seps = [i for i, (kind, _) in enumerate(parts) if kind == "sep"]
    own = parts[seps[-1] + 1 :] if seps else parts
    return any(kind == "text" and str(value).strip("/ ") for kind, value in own)


def substitute(template: list[Part], args: list[list[Part]]) -> list[Part]:
    out: list[Part] = []
    for kind, value in template:
        if kind == "param":
            out.extend(args[value] if value < len(args) else [("expr", f"arg{value}")])
        else:
            out.append((kind, value))
    return out


def join_base(base: list[Part] | None, parts: list[Part]) -> list[Part]:
    """Apply a client's base URL the way axios does: absolute URLs ignore it."""
    if not base:
        return parts
    first = parts[0] if parts else ("text", "")
    if first[0] == "text" and re.match(r"^[a-z][a-z0-9+.-]*://", str(first[1]), re.I):
        return parts
    # The separator becomes "/" only if the path doesn't already start with one, decided once the
    # path is known (a wrapper's path is only filled in at its call sites).
    return list(base) + [("sep", "/")] + parts


# ---------------------------------------------------------------- clients


_JS_DEFAULT_IMPORT = re.compile(rf"""\bimport\s+({_IDENT})\s*(?:,\s*\{{[^}}]*\}})?\s+from\s+['"]([^'"]+)['"]""")
_JS_REQUIRE = re.compile(rf"""\b(?:const|let|var)\s+({_IDENT})\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_JS_NAMED_IMPORT = re.compile(rf"""\bimport\s+(?:{_IDENT}\s*,\s*)?\{{([^}}]*)\}}\s*from\s+['"]([^'"]+)['"]""")


def _js_imports(code: str) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """(default-or-require name -> specifier, local name -> (specifier, exported name))."""
    defaults = {name: spec for name, spec in _JS_DEFAULT_IMPORT.findall(code)}
    defaults.update({name: spec for name, spec in _JS_REQUIRE.findall(code)})
    named: dict[str, tuple[str, str]] = {}
    for names, spec in _JS_NAMED_IMPORT.findall(code):
        for item in names.split(","):
            item = item.strip()
            if not item:
                continue
            exported, _, local = item.partition(" as ")
            exported = exported.replace("type ", "").strip()
            named[(local or exported).strip()] = (spec, exported)
    return defaults, named


def _object_value(obj: str, key: str) -> str | None:
    for entry in split_top(obj.strip()[1:-1] if obj.strip().startswith("{") else obj):
        k, sep, v = entry.partition(":")
        if sep and k.strip().strip("'\"") == key:
            return v.strip()
    return None


def find_local_clients(ctx: FileCtx, imports_axios: set[str]) -> dict[str, Client]:
    clients: dict[str, Client] = {}
    code = ctx.code
    if ctx.language in JS_LANGUAGES:
        for name in imports_axios:
            clients[name] = Client(name)
            for m in re.finditer(rf"({_IDENT})\s*=\s*{re.escape(name)}\s*\.\s*create\s*\(", code):
                args = _args(ctx, m.end() - 1)
                base_expr = _object_value(args[0], "baseURL") if args else None
                base = evaluate(ctx, base_expr, None, m.start()) if base_expr else None
                clients[m.group(1)] = Client(m.group(1), base)
    elif ctx.language == "Dart":
        for m in re.finditer(rf"({_IDENT})\s*=\s*Dio\s*\(", code):
            args = _args(ctx, m.end() - 1)
            base = None
            if args:
                opts = re.search(r"baseUrl\s*:\s*([^,)]+)", args[0])
                if opts:
                    base = evaluate(ctx, opts.group(1), None, m.start())
            clients[m.group(1)] = Client(m.group(1), base)
        http_alias = re.search(r"""import\s+['"]package:http/http\.dart['"]\s+as\s+(\w+)""", code)
        if http_alias:
            clients[http_alias.group(1)] = Client(http_alias.group(1))
    return clients


def default_export(code: str) -> str | None:
    m = re.search(rf"\bexport\s+default\s+({_IDENT})\s*;?\s*$", code, re.M) or re.search(
        rf"\bmodule\.exports\s*=\s*({_IDENT})\s*;?", code
    )
    return m.group(1) if m else None


# ---------------------------------------------------------------- tracing


def _method_from_options(ctx: FileCtx, options: str | None, func: Func | None) -> tuple[str | None, int | None]:
    if not options:
        return "GET", None
    text = options.strip()
    value = _object_value(text, "method")
    if value is None and re.search(r"(?:^\{|,)\s*method\s*(?:,|\})", text):
        value = "method"
    if value is None:
        return "GET", None
    literal = re.fullmatch(r"""['"`](\w+)['"`]""", value.strip())
    if literal:
        return literal.group(1).upper(), None
    if func and value.strip() in func.params:
        return None, func.params.index(value.strip())
    return "GET", None


def trace_project(files: dict[str, FileCtx], resolve_import) -> tuple[list[Traced], list[Traced], set[tuple[str, int]]]:
    """Return (resolved calls, unresolved requests, positions inside wrappers). Positions inside
    wrappers are requests whose URL is a parameter; they are not calls themselves.
    `resolve_import(path, spec)` maps an import specifier in `path` to a repo file path or None."""
    js_files = [c for c in files.values() if c.language in JS_LANGUAGES]
    exported_clients: dict[str, Client] = {}
    for ctx in files.values():
        axios_names = set()
        if ctx.language in JS_LANGUAGES:
            defaults, _ = ctx.imports
            axios_names = {name for name, spec in defaults.items() if spec == "axios"}
        ctx.clients = find_local_clients(ctx, axios_names)
        exported = ctx.default_export
        if exported and exported in ctx.clients:
            exported_clients[ctx.path] = ctx.clients[exported]
    for ctx in js_files:
        defaults, _ = ctx.imports
        for local, spec in defaults.items():
            target = resolve_import(ctx.path, spec)
            if target in exported_clients and local not in ctx.clients:
                client = exported_clients[target]
                ctx.clients[local] = Client(local, client.base)

    calls: list[Traced] = []
    unresolved: list[Traced] = []
    wrappers: list[Wrapper] = []
    seen_wrappers: set[tuple[str, str]] = set()
    inside_wrappers: set[tuple[str, int]] = set()

    def record(ctx: FileCtx, pos: int, raw: str, parts: list[Part], url_from_param: bool,
               method: str | None, method_param: int | None, func: Func | None, via: str) -> None:
        if url_from_param or method_param is not None:
            if func and func.name:
                inside_wrappers.add((ctx.path, pos))
                if (ctx.path, func.name) not in seen_wrappers:
                    seen_wrappers.add((ctx.path, func.name))
                    wrappers.append(Wrapper(ctx.path, func.name, parts, method, method_param, via))
                return
            if url_from_param:
                unresolved.append(Traced(ctx.path, pos, method or "GET", parts, raw, via))
                return
        target = calls if _path_is_known(parts) else unresolved
        target.append(Traced(ctx.path, pos, method or "GET", parts, raw, via))

    for ctx in files.values():
        if ctx.language not in JS_LANGUAGES + ("Dart",):
            continue
        sinks = []
        for name, client in ctx.clients.items():
            verbs = "|".join(_REQUEST_VERBS)
            for m in re.finditer(rf"(?<![\w$]){re.escape(name)}\s*\.\s*({verbs})\s*\(", ctx.code):
                sinks.append((m, client, m.group(1)))
        if ctx.language in JS_LANGUAGES:
            for m in re.finditer(r"(?<![\w$.])fetch\s*\(", ctx.code):
                sinks.append((m, Client("fetch"), "fetch"))
        for m, client, verb in sinks:
            open_pos = m.end() - 1
            args = _args(ctx, open_pos)
            if not args:
                continue
            func = enclosing(ctx.funcs, m.start())
            if func and func.header == open_pos:
                continue
            arg_pos = ctx.code.find(args[0], open_pos)
            parts = evaluate(ctx, args[0], func, m.start())
            if verb == "fetch":
                method, method_param = _method_from_options(ctx, args[1] if len(args) > 1 else None, func)
            elif verb == "request":
                method, method_param = _method_from_options(ctx, args[0], func)
                url_expr = _object_value(args[0], "url")
                parts = evaluate(ctx, url_expr, func, m.start()) if url_expr else [("expr", args[0])]
            else:
                method, method_param = verb.upper(), None
            via = "direct" if verb == "fetch" else f"direct ({client.name})"
            record(ctx, arg_pos, args[0], join_base(client.base, parts), starts_with_param(parts),
                   method, method_param, func, via)

    dart_importers: dict[str, list[FileCtx]] = {}
    processed = 0
    while processed < len(wrappers) and processed < 500:
        wrapper = wrappers[processed]
        processed += 1
        owner = files.get(wrapper.path)
        if owner is None:
            continue
        candidates: list[tuple[FileCtx, str]] = [(owner, wrapper.name)]
        if owner.language in JS_LANGUAGES:
            for ctx in js_files:
                if ctx is owner:
                    continue
                defaults, named = ctx.imports
                for local, (spec, exported) in named.items():
                    if exported == wrapper.name and resolve_import(ctx.path, spec) == wrapper.path:
                        candidates.append((ctx, local))
                for local, spec in defaults.items():
                    if owner.default_export == wrapper.name and resolve_import(ctx.path, spec) == wrapper.path:
                        candidates.append((ctx, local))
        elif owner.language == "Dart":
            if wrapper.path not in dart_importers:
                dart_importers[wrapper.path] = [
                    ctx for ctx in files.values()
                    if ctx.language == "Dart" and ctx is not owner
                    and any(resolve_import(ctx.path, spec) == wrapper.path
                            for spec in re.findall(r"""^\s*import\s+['"]([^'"]+)['"]""", ctx.code, re.M))
                ]
            candidates += [(ctx, wrapper.name) for ctx in dart_importers[wrapper.path]]

        for ctx, local in candidates:
            prefix = r"(?:(?<=\.)|(?<![\w$.]))" if ctx.language == "Dart" else r"(?<![\w$.])"
            for m in re.finditer(rf"{prefix}{re.escape(local)}\s*\(", ctx.code):
                open_pos = m.end() - 1
                if any(f.header == open_pos for f in ctx.funcs):
                    continue
                args = _args(ctx, open_pos)
                func = enclosing(ctx.funcs, m.start())
                arg_parts = [evaluate(ctx, a, func, m.start()) for a in args]
                parts = substitute(wrapper.url_parts, arg_parts)
                method, method_param = wrapper.method, None
                if wrapper.method_param is not None:
                    if wrapper.method_param < len(args):
                        literal = re.fullmatch(r"""['"`](\w+)['"`]""", args[wrapper.method_param].strip())
                        if literal:
                            method = literal.group(1).upper()
                        elif func and args[wrapper.method_param].strip() in func.params:
                            method_param = func.params.index(args[wrapper.method_param].strip())
                        else:
                            method = "GET"
                    else:
                        method = "GET"
                url_index = next((v for k, v in wrapper.url_parts if k == "param"), 0)
                raw = args[url_index] if url_index < len(args) else ""
                arg_pos = ctx.code.find(raw, open_pos) if raw else open_pos
                from_param = url_index < len(arg_parts) and starts_with_param(arg_parts[url_index])
                record(ctx, arg_pos, raw, parts, from_param, method, method_param, func, f"wrapper {wrapper.name}")
    return calls, unresolved, inside_wrappers


def parts_to_url(parts: list[Part]) -> str:
    """Render parts as a URL string with \\x00 marking values that aren't known."""
    out = ""
    pending_sep = False
    for kind, value in parts:
        if kind == "sep":
            pending_sep = True
            continue
        piece = str(value) if kind == "text" else "\x00"
        if pending_sep and piece:
            if re.match(r"^[a-z][a-z0-9+.-]*://", piece, re.I):
                out = ""  # an absolute URL replaces the client's base URL
            else:
                out = out.rstrip("/") + ("" if piece.startswith("/") else "/")
            pending_sep = False
        out += piece
    return out


def build_file(path: str, code: str, language: str) -> FileCtx:
    pairs = match_pairs(code)
    return FileCtx(path, code, language, pairs, find_functions(code, pairs, language))


def dart_import_target(source: str, spec: str, packages: dict[str, str], file_set: set[str]) -> str | None:
    if spec.startswith("package:"):
        package, _, rest = spec[len("package:") :].partition("/")
        if package not in packages:
            return None
        target = posixpath.normpath(posixpath.join(packages[package], "lib", rest))
    elif ":" in spec:
        return None
    else:
        target = posixpath.normpath(posixpath.join(posixpath.dirname(source), spec))
    return target if target in file_set else None
