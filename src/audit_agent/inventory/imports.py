"""Import relationships for JavaScript, TypeScript, and Python files."""

from __future__ import annotations

import ast
import json
import posixpath
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from audit_agent.inventory.models import Relationship

JS_RESOLVE_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".json")

NODE_BUILTINS = frozenset(
    """
    assert async_hooks buffer child_process cluster console constants crypto dgram
    diagnostics_channel dns domain events fs http http2 https inspector module net os path
    perf_hooks process punycode querystring readline repl stream string_decoder sys test
    timers tls trace_events tty url util v8 vm wasi worker_threads zlib
    """.split()
)

_JS_STATIC = re.compile(
    r"""(?<![\w$.])(?:import|export)\s+(?:[\w$*{}\s,]+?\s+from\s+)?['"]([^'"\n]+)['"]"""
)
_JS_CALL = re.compile(r"""(?<![\w$.])(?:require|import)\s*\(\s*['"]([^'"\n]+)['"]\s*\)""")
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


@dataclass(frozen=True)
class JsPathConfig:
    """`baseUrl` and `paths` from a tsconfig/jsconfig, with targets made repo-relative."""

    directory: str
    base_url: str | None
    paths: tuple[tuple[str, tuple[str, ...]], ...]

    def applies_to(self, source: str) -> bool:
        return not self.directory or source.startswith(self.directory + "/")


def is_js_path_config(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.endswith(".json") and name.startswith(("tsconfig", "jsconfig"))


def parse_js_path_config(path: str, text: str) -> JsPathConfig | None:
    data = json.loads(_TRAILING_COMMA.sub(r"\1", strip_js_comments(text)))
    options = data.get("compilerOptions") if isinstance(data, dict) else None
    if not isinstance(options, dict):
        return None
    base_url, paths = options.get("baseUrl"), options.get("paths")
    if not isinstance(base_url, str) and not isinstance(paths, dict):
        return None
    directory = posixpath.dirname(path)
    root = posixpath.normpath(posixpath.join(directory, base_url or "."))
    root = "" if root == "." else root
    rules = tuple(
        (pattern, tuple(posixpath.normpath(posixpath.join(root, t)) for t in targets if isinstance(t, str)))
        for pattern, targets in (paths or {}).items()
        if isinstance(targets, list)
    )
    return JsPathConfig(directory, root if isinstance(base_url, str) else None, rules)


def strip_js_comments(text: str) -> str:
    """Blank out // and /* */ comments, keeping string literals and line numbers intact."""
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            # A stray apostrophe (for example in JSX text) must not swallow the rest of the file.
            if c == quote or (c == "\n" and quote != "`"):
                quote = None
            i += 1
        elif c in "'\"`":
            quote = c
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:end]))
            i = end
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _js_package_name(specifier: str) -> str:
    parts = specifier.split("/")
    if specifier.startswith("@") and len(parts) > 1:
        return "/".join(parts[:2])
    return parts[0]


_TS_SOURCE_FOR = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}


def _resolve_js_path(base: str, file_set: set[str]) -> str | None:
    if base in file_set:
        return base
    stem, ext = posixpath.splitext(base)
    for ts_ext in _TS_SOURCE_FOR.get(ext, ()):
        if stem + ts_ext in file_set:
            return stem + ts_ext
    for ext in JS_RESOLVE_EXTENSIONS:
        if base + ext in file_set:
            return base + ext
    for ext in JS_RESOLVE_EXTENSIONS:
        candidate = posixpath.join(base, "index" + ext)
        if candidate in file_set:
            return candidate
    return None


def _resolve_js_alias(specifier: str, configs: list[JsPathConfig], file_set: set[str]) -> str | None:
    for config in configs:
        for pattern, targets in config.paths:
            if "*" in pattern:
                prefix, suffix = pattern.split("*", 1)
                if not (
                    specifier.startswith(prefix)
                    and specifier.endswith(suffix)
                    and len(specifier) >= len(prefix) + len(suffix)
                ):
                    continue
                star = specifier[len(prefix) : len(specifier) - len(suffix)]
            elif pattern == specifier:
                star = ""
            else:
                continue
            for target in targets:
                if resolved := _resolve_js_path(target.replace("*", star, 1), file_set):
                    return resolved
        if config.base_url is not None:
            base = posixpath.normpath(posixpath.join(config.base_url, specifier))
            if resolved := _resolve_js_path(base, file_set):
                return resolved
    return None


def _js_relationship(
    source: str, specifier: str, line: int, file_set: set[str], configs: list[JsPathConfig]
) -> Relationship:
    if specifier.startswith("."):
        base = posixpath.normpath(posixpath.join(posixpath.dirname(source), specifier))
        target = _resolve_js_path(base, file_set)
        if target:
            return Relationship(source, "internal", specifier, target, None, line)
        return Relationship(source, "unresolved", specifier, None, None, line)
    if target := _resolve_js_alias(specifier, configs, file_set):
        return Relationship(source, "internal", specifier, target, None, line)
    if specifier.startswith(("/", "@/", "~/", "#")):
        return Relationship(source, "unresolved", specifier, None, None, line)
    bare = specifier.removeprefix("node:")
    package = _js_package_name(bare)
    if specifier.startswith("node:") or package in NODE_BUILTINS:
        return Relationship(source, "builtin", specifier, None, package, line)
    return Relationship(source, "package", specifier, None, package, line)


def js_relationships(
    source: str, text: str, file_set: set[str], configs: Iterable[JsPathConfig] = ()
) -> list[Relationship]:
    applicable = sorted(
        (c for c in configs if c.applies_to(source)), key=lambda c: c.directory.count("/") + bool(c.directory), reverse=True
    )
    code = strip_js_comments(text)
    seen: set[str] = set()
    found: list[Relationship] = []
    matches = sorted(
        [*_JS_STATIC.finditer(code), *_JS_CALL.finditer(code)], key=lambda m: m.start(1)
    )
    for match in matches:
        specifier = match.group(1)
        if specifier in seen:
            continue
        seen.add(specifier)
        line = code.count("\n", 0, match.start(1)) + 1
        found.append(_js_relationship(source, specifier, line, file_set, applicable))
    return found


_DART_DIRECTIVE = re.compile(
    r"""^[ \t]*(?:import|export|part(?:[ \t]+of)?)[ \t]+['"]([^'"\n]+)['"]([^;]*);""", re.M
)
_DART_CONDITIONAL = re.compile(r"""\bif\s*\([^)]*\)\s*['"]([^'"\n]+)['"]""")


def _dart_relationship(
    source: str,
    specifier: str,
    line: int,
    file_set: set[str],
    packages: dict[str, str],
    generated: set[str],
) -> Relationship:
    if specifier.startswith("dart:"):
        return Relationship(source, "builtin", specifier, None, specifier, line)
    if specifier.startswith("package:"):
        package, _, rest = specifier[len("package:") :].partition("/")
        if package not in packages:
            return Relationship(source, "package", specifier, None, package, line)
        target = posixpath.normpath(posixpath.join(packages[package], "lib", rest))
    elif ":" in specifier:
        return Relationship(source, "unresolved", specifier, None, None, line)
    else:
        target = posixpath.normpath(posixpath.join(posixpath.dirname(source), specifier))
    if target in file_set:
        return Relationship(source, "internal", specifier, target, None, line)
    if target in generated:
        return Relationship(source, "generated", specifier, target, None, line)
    return Relationship(source, "unresolved", specifier, None, None, line)


def dart_relationships(
    source: str,
    text: str,
    file_set: set[str],
    packages: dict[str, str],
    generated: set[str] = frozenset(),
) -> list[Relationship]:
    """`packages` maps each pubspec `name` in the repository to its directory ("" for the root)."""
    code = strip_js_comments(text)
    seen: set[str] = set()
    found: list[Relationship] = []
    for match in _DART_DIRECTIVE.finditer(code):
        line = code.count("\n", 0, match.start(1)) + 1
        specifiers = [match.group(1), *_DART_CONDITIONAL.findall(match.group(2))]
        for specifier in specifiers:
            if specifier in seen:
                continue
            seen.add(specifier)
            found.append(_dart_relationship(source, specifier, line, file_set, packages, generated))
    return found


def python_module_index(py_files: Iterable[str], roots: Iterable[str]) -> dict[str, str]:
    """Map dotted module names to files, for each directory imports could be rooted at."""
    root_list = sorted({r.strip("/") for r in roots}, key=lambda r: (r != "", r))
    index: dict[str, str] = {}
    for path in sorted(py_files):
        for root in root_list:
            prefix = f"{root}/" if root else ""
            if not path.startswith(prefix):
                continue
            parts = list(PurePosixPath(path[len(prefix):]).with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            if parts and all(p.isidentifier() for p in parts):
                index.setdefault(".".join(parts), path)
    return index


def _py_module_file(base: PurePosixPath, file_set: set[str]) -> str | None:
    for candidate in (f"{base}.py", f"{base}/__init__.py"):
        candidate = posixpath.normpath(candidate)
        if candidate in file_set:
            return candidate
    return None


def _py_absolute(
    source: str, module: str, line: int, index: dict[str, str], file_set: set[str]
) -> Relationship:
    parts = module.split(".")
    for end in range(len(parts), 0, -1):
        target = index.get(".".join(parts[:end]))
        if target:
            return Relationship(source, "internal", module, target, None, line)
    # A script's own directory is first on sys.path, so `import helper` can mean a sibling file.
    script_dir = PurePosixPath(source).parent
    for end in range(len(parts), 0, -1):
        if target := _py_module_file(script_dir.joinpath(*parts[:end]), file_set):
            return Relationship(source, "internal", module, target, None, line)
    top = parts[0]
    kind = "builtin" if top in sys.stdlib_module_names or top == "__future__" else "package"
    return Relationship(source, kind, module, None, top, line)


def python_relationships(
    source: str, text: str, file_set: set[str], index: dict[str, str]
) -> tuple[list[Relationship], str | None]:
    """Return relationships and, if the file could not be parsed, the reason."""
    try:
        tree = ast.parse(text, filename=source)
    except (SyntaxError, ValueError) as exc:
        return [], f"could not parse: {exc.__class__.__name__}"
    found: list[Relationship] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append(_py_absolute(source, alias.name, node.lineno, index, file_set))
        elif isinstance(node, ast.ImportFrom):
            names = [a.name for a in node.names if a.name != "*"]
            module = node.module or ""
            if node.level == 0:
                submodules = [index.get(f"{module}.{n}") for n in names]
                resolved = [t for t in submodules if t]
                if resolved:
                    found.extend(
                        Relationship(source, "internal", module, t, None, node.lineno)
                        for t in dict.fromkeys(resolved)
                    )
                else:
                    found.append(_py_absolute(source, module, node.lineno, index, file_set))
                continue
            specifier = "." * node.level + module
            base = PurePosixPath(source).parent
            for _ in range(node.level - 1):
                base = base.parent
            base = base.joinpath(*module.split(".")) if module else base
            targets = [_py_module_file(base / n, file_set) for n in names]
            resolved = [t for t in targets if t] or [_py_module_file(base, file_set)]
            resolved = [t for t in resolved if t]
            if not resolved:
                found.append(Relationship(source, "unresolved", specifier, None, None, node.lineno))
            for target in dict.fromkeys(resolved):
                found.append(Relationship(source, "internal", specifier, target, None, node.lineno))
    found.sort(key=lambda r: r.line)
    return found, None
