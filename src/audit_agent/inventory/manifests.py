"""Dependency manifests: declared dependencies and the entry points they name."""

from __future__ import annotations

import configparser
import json
import posixpath
import re
import shlex
import tomllib
from pathlib import PurePosixPath

from audit_agent.inventory.models import Dependency, EntryPoint, Unsupported

UNSUPPORTED_MANIFESTS = {
    "go.mod": "Go modules",
    "Cargo.toml": "Cargo (Rust)",
    "Gemfile": "Bundler (Ruby)",
    "pom.xml": "Maven (Java)",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle",
    "composer.json": "Composer (PHP)",
    "Package.swift": "Swift Package Manager",
    "mix.exs": "Mix (Elixir)",
}
PACKAGE_ROOT_NAMES = frozenset(
    {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "pubspec.yaml", *UNSUPPORTED_MANIFESTS}
)
PUBSPEC_SCOPES = {"dependencies": "runtime", "dev_dependencies": "dev", "dependency_overrides": "override"}

RUNNABLE_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".py", ".sh")

_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def unsupported_manifest_name(path: str) -> str | None:
    name = PurePosixPath(path).name
    if name in UNSUPPORTED_MANIFESTS:
        return UNSUPPORTED_MANIFESTS[name]
    if name.endswith(".csproj"):
        return "NuGet (.NET)"
    return None


def is_package_root_marker(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in PACKAGE_ROOT_NAMES or name.endswith(".csproj")


def is_requirements_file(path: str) -> bool:
    p = PurePosixPath(path)
    if p.suffix != ".txt":
        return False
    return p.name.startswith("requirements") or p.parent.name == "requirements"


def referenced_files(command: str, base_dir: str, file_set: set[str]) -> list[str]:
    """Files in the repository that a shell-style command names, resolved from base_dir."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    found: list[str] = []
    for token in tokens:
        token = token.strip(",;&|()")
        if not token.endswith(RUNNABLE_EXTENSIONS):
            continue
        for base in dict.fromkeys((base_dir, "")):
            candidate = posixpath.normpath(posixpath.join(base, token)).lstrip("/")
            if candidate in file_set:
                found.append(candidate)
                break
    return list(dict.fromkeys(found))


def _resolve_node_path(base_dir: str, target: str, file_set: set[str]) -> str | None:
    base = posixpath.normpath(posixpath.join(base_dir, target))
    for candidate in (base, base + ".js", posixpath.join(base, "index.js")):
        if candidate in file_set:
            return candidate
    return None


def _split_requirement(spec: str) -> tuple[str, str | None] | None:
    match = _REQUIREMENT.match(spec)
    if not match:
        return None
    version = match.group(3).strip() or None
    return match.group(1), version


def parse_package_json(
    path: str, text: str, file_set: set[str]
) -> tuple[list[Dependency], list[EntryPoint]]:
    data = json.loads(text)
    if not isinstance(data, dict):
        return [], []
    base = posixpath.dirname(path)
    deps: list[Dependency] = []
    for key, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    ):
        section = data.get(key)
        if isinstance(section, dict):
            deps.extend(
                Dependency(path, "npm", name, str(version), scope) for name, version in section.items()
            )

    entries: list[EntryPoint] = []
    main = data.get("main")
    if isinstance(main, str):
        entries.append(
            EntryPoint(_resolve_node_path(base, main, file_set), "package-main", path, f"main: {main}")
        )
    bin_field = data.get("bin")
    if isinstance(bin_field, str):
        bin_field = {data.get("name", "bin"): bin_field}
    if isinstance(bin_field, dict):
        for name, target in bin_field.items():
            if isinstance(target, str):
                entries.append(
                    EntryPoint(
                        _resolve_node_path(base, target, file_set), "package-bin", path, f"bin {name}: {target}"
                    )
                )
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if not isinstance(command, str):
                continue
            detail = f"npm script {name}: {command}"
            targets = referenced_files(command, base, file_set)
            if not targets:
                entries.append(EntryPoint(None, "npm-script", path, detail))
            entries.extend(EntryPoint(t, "npm-script", path, detail) for t in targets)
    return deps, entries


def parse_pyproject(
    path: str, text: str, module_index: dict[str, str]
) -> tuple[list[Dependency], list[EntryPoint]]:
    data = tomllib.loads(text)
    deps: list[Dependency] = []

    def add(spec: object, scope: str) -> None:
        if isinstance(spec, str) and (parsed := _split_requirement(spec)):
            deps.append(Dependency(path, "pypi", parsed[0], parsed[1], scope))

    project = data.get("project", {})
    for spec in project.get("dependencies", []):
        add(spec, "runtime")
    for extra, specs in project.get("optional-dependencies", {}).items():
        for spec in specs:
            add(spec, f"optional:{extra}")
    for group, specs in data.get("dependency-groups", {}).items():
        for spec in specs:
            add(spec, f"group:{group}")

    poetry = data.get("tool", {}).get("poetry", {})

    def add_poetry(section: dict, scope: str) -> None:
        for name, spec in section.items():
            if name.lower() == "python":
                continue
            version = spec if isinstance(spec, str) else spec.get("version") if isinstance(spec, dict) else None
            deps.append(Dependency(path, "pypi", name, version, scope))

    add_poetry(poetry.get("dependencies", {}), "runtime")
    add_poetry(poetry.get("dev-dependencies", {}), "dev")
    for group, body in poetry.get("group", {}).items():
        add_poetry(body.get("dependencies", {}), f"group:{group}")

    entries: list[EntryPoint] = []
    scripts = {**poetry.get("scripts", {}), **project.get("scripts", {})}
    for name, target in scripts.items():
        if not isinstance(target, str):
            continue
        module = target.split(":", 1)[0].strip()
        entries.append(
            EntryPoint(module_index.get(module), "python-script", path, f"script {name}: {target}")
        )
    return deps, entries


def parse_setup_cfg(path: str, text: str) -> list[Dependency]:
    parser = configparser.ConfigParser()
    parser.read_string(text)
    deps: list[Dependency] = []
    raw = parser.get("options", "install_requires", fallback="")
    for line in raw.splitlines():
        if (parsed := _split_requirement(line.split("#", 1)[0])) and line.strip():
            deps.append(Dependency(path, "pypi", parsed[0], parsed[1], "runtime"))
    return deps


def parse_requirements(path: str, text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", ".", "/")) or "://" in line:
            continue
        if parsed := _split_requirement(line):
            deps.append(Dependency(path, "pypi", parsed[0], parsed[1], "runtime"))
    return deps


def _yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def parse_pubspec(path: str, text: str) -> tuple[str | None, list[Dependency]]:
    """Package name and dependencies from a pubspec.yaml.

    Only the block-style mappings pubspec files use in practice are understood: a version
    string (`http: ^1.0.0`) or a nested source (`sdk:`, `path:`, `git:` with `url:`, `hosted:`).
    """
    name: str | None = None
    deps: list[Dependency] = []
    scope: str | None = None
    dep_indent: int | None = None
    current: Dependency | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = re.sub(r"\s+#.*$", "", raw.rstrip())
        indent = len(line) - len(line.lstrip(" "))
        key, _, value = line.strip().partition(":")
        value = _yaml_scalar(value)
        if indent == 0:
            if key == "name":
                name = value or None
            scope, dep_indent, current = PUBSPEC_SCOPES.get(key), None, None
            continue
        if scope is None or key.startswith("- "):
            continue
        if dep_indent is None or indent <= dep_indent:
            dep_indent = indent
            current = Dependency(path, "pub", key, value or None, scope)
            deps.append(current)
            continue
        if current is None:
            continue
        if key == "version":
            current.version_spec = value
        elif key == "url" and current.version_spec == "git":
            current.version_spec = f"git: {value}"
        elif key in ("sdk", "path", "git", "hosted") and current.version_spec is None:
            current.version_spec = f"{key}: {value}" if value else key
    return name, deps


def unsupported_manifests(technology: str, paths: list[str]) -> Unsupported:
    names = ", ".join(sorted({PurePosixPath(p).name for p in paths}))
    return Unsupported(
        technology=technology,
        kind="manifest",
        evidence_path=paths[0],
        file_count=len(paths),
        reason=f"{names} files are recorded, but their dependencies are not parsed in v1.",
    )
