"""Discover a repository's files, languages, dependencies, modules, entry points, imports, and apps."""

from __future__ import annotations

import configparser
import json
import posixpath
import stat
import tomllib
from collections import defaultdict
from pathlib import PurePosixPath

from audit_agent.inventory import apps, entry_points, imports, manifests
from audit_agent.inventory.languages import (
    SUPPORTED_LANGUAGES,
    classify,
    is_generated_path,
    is_junk_file,
    is_secret_file,
    looks_minified,
    shebang_language,
)
from audit_agent.inventory.models import (
    FileRecord,
    Inventory,
    ModuleRecord,
    Skipped,
    Unsupported,
)
from audit_agent.repo import GitRepository, list_tracked_files, list_untracked_files

MAX_READ_BYTES = 2 * 1024 * 1024
READABLE_CATEGORIES = frozenset[str]({"source", "config", "docs"})


def _module_path(path: str) -> str:
    return posixpath.dirname(path) or "."


def _nearest_root(directory: str, roots: set[str]) -> str | None:
    current = "" if directory == "." else directory
    while True:
        if current in roots:
            return current or "."
        if not current:
            return None
        current = posixpath.dirname(current)


SKIP_NOT_INCLUDED = "untracked file (pass --include-untracked to include)"
SKIP_JUNK = "OS metadata or log file"
SKIP_GENERATED = "generated or build output"
SKIP_NON_CODE = "non-code file (images, media, fonts, binaries)"
SKIP_LARGE_DATA = "data or docs file over 2 MB"
SKIP_SYMLINK = "symlink, not followed"


def _read_files(
    repo: GitRepository, include_untracked: bool
) -> tuple[list[FileRecord], dict[str, str], list[Skipped], set[str]]:
    records: list[FileRecord] = []
    texts: dict[str, str] = {}
    skipped: dict[str, list[str]] = defaultdict(list)

    untracked = list_untracked_files(repo.root)
    candidates = [(p, True) for p in list_tracked_files(repo.root)]
    if include_untracked:
        candidates += [(p, False) for p in untracked]
    else:
        skipped[SKIP_NOT_INCLUDED].extend(untracked)

    for rel, tracked in sorted(candidates):
        if is_junk_file(rel):
            skipped[SKIP_JUNK].append(rel)
            continue
        if is_generated_path(rel):
            skipped[SKIP_GENERATED].append(rel)
            continue
        absolute = repo.root / rel
        try:
            info = absolute.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            skipped[SKIP_SYMLINK].append(rel)
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if is_secret_file(rel):
            records.append(
                FileRecord(rel, "secret", None, False, info.st_size, None, None, "may contain secrets; contents not read")
            )
            continue

        category, language = classify(rel)
        note = None
        if category == "other" and "." not in PurePosixPath(rel).name and info.st_size:
            with absolute.open("rb") as handle:
                if detected := shebang_language(handle.read(256)):
                    category, language = "source", detected

        if category not in READABLE_CATEGORIES:
            skipped[SKIP_NON_CODE].append(rel)
            continue
        if info.st_size > MAX_READ_BYTES and category != "source":
            skipped[SKIP_LARGE_DATA].append(rel)
            continue

        text = None
        if info.st_size > MAX_READ_BYTES:
            note = "too large to analyze"
        else:
            data = absolute.read_bytes()
            if b"\0" in data[:8192]:
                skipped[SKIP_NON_CODE].append(rel)
                continue
            text = data.decode("utf-8", errors="replace")
            if looks_minified(language, text):
                skipped[SKIP_GENERATED].append(rel)
                continue
            texts[rel] = text

        line_count = None if text is None else text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        records.append(
            FileRecord(
                path=rel,
                category=category,
                language=language,
                supported=language in SUPPORTED_LANGUAGES,
                size_bytes=info.st_size,
                line_count=line_count,
                module_path=_module_path(rel) if category == "source" else None,
                note=note,
            )
        )
    summary = [Skipped(reason, len(paths), paths[0]) for reason, paths in skipped.items() if paths]
    return records, texts, summary, set(skipped[SKIP_GENERATED])


def discover(repo: GitRepository, include_untracked: bool = False) -> Inventory:
    files, texts, skipped, generated = _read_files(repo, include_untracked)
    inventory = Inventory(files=files, skipped=skipped)
    file_set = {f.path for f in files}
    by_path = {f.path: f for f in files}
    languages = {f.path: f.language for f in files}

    package_roots = {posixpath.dirname(f.path) for f in files if manifests.is_package_root_marker(f.path)}

    py_files = [f.path for f in files if f.language == "Python"]
    python_roots = {"", "src"} | package_roots | {posixpath.join(r, "src") for r in package_roots if r}
    module_index = imports.python_module_index(py_files, python_roots)

    dart_packages: dict[str, str] = {}
    for path, text in sorted(texts.items()):
        name = PurePosixPath(path).name
        try:
            if name == "pubspec.yaml":
                package_name, deps = manifests.parse_pubspec(path, text)
                if package_name:
                    dart_packages.setdefault(package_name, posixpath.dirname(path))
                entries = []
            elif name == "package.json":
                deps, entries = manifests.parse_package_json(path, text, file_set)
            elif name == "pyproject.toml":
                deps, entries = manifests.parse_pyproject(path, text, module_index)
            elif name == "setup.cfg":
                deps, entries = manifests.parse_setup_cfg(path, text), []
            elif manifests.is_requirements_file(path):
                deps, entries = manifests.parse_requirements(path, text), []
            else:
                continue
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, configparser.Error) as exc:
            by_path[path].note = f"manifest could not be parsed: {exc.__class__.__name__}"
            continue
        inventory.dependencies.extend(deps)
        inventory.entry_points.extend(entries)

    unparsed_manifests: dict[str, list[str]] = defaultdict(list)
    for f in files:
        if technology := manifests.unsupported_manifest_name(f.path):
            unparsed_manifests[technology].append(f.path)
    for technology, paths in sorted(unparsed_manifests.items()):
        inventory.unsupported.append(manifests.unsupported_manifests(technology, paths))

    inventory.entry_points.extend(entry_points.scan(texts, languages, file_set))

    js_configs = []
    for path, text in sorted(texts.items()):
        if not imports.is_js_path_config(path):
            continue
        try:
            if config := imports.parse_js_path_config(path, text):
                js_configs.append(config)
        except json.JSONDecodeError as exc:
            by_path[path].note = f"config could not be parsed: {exc.__class__.__name__}"

    for path, text in sorted(texts.items()):
        language = languages.get(path)
        if language in ("JavaScript", "TypeScript"):
            inventory.relationships.extend(imports.js_relationships(path, text, file_set, js_configs))
        elif language == "Dart":
            inventory.relationships.extend(
                imports.dart_relationships(path, text, file_set, dart_packages, generated)
            )
        elif language == "Python":
            found, problem = imports.python_relationships(path, text, file_set, module_index)
            inventory.relationships.extend(found)
            if problem:
                by_path[path].note = problem

    modules: dict[str, list[FileRecord]] = defaultdict(list)
    for f in files:
        if f.module_path:
            modules[f.module_path].append(f)
    for path, members in sorted(modules.items()):
        inventory.modules.append(
            ModuleRecord(
                path=path,
                package_root=_nearest_root(path, package_roots),
                languages=sorted({m.language for m in members if m.language}),
                file_count=len(members),
                line_count=sum(m.line_count or 0 for m in members),
            )
        )

    unsupported_languages: dict[str, list[FileRecord]] = defaultdict(list)
    for f in files:
        if f.category == "source" and f.language and not f.supported:
            unsupported_languages[f.language].append(f)
    for language, members in sorted(unsupported_languages.items()):
        inventory.unsupported.append(
            Unsupported(
                technology=language,
                kind="language",
                evidence_path=members[0].path,
                file_count=len(members),
                reason=(
                    f"{language} files are inventoried, but their dependencies, entry points, "
                    "and relationships are not analyzed in v1."
                ),
            )
        )
    too_large = [f for f in files if f.note == "too large to analyze"]
    if too_large:
        inventory.unsupported.append(
            Unsupported(
                technology="Source files over 2 MB",
                kind="file-size",
                evidence_path=too_large[0].path,
                file_count=len(too_large),
                reason="Source files this large are inventoried but not read or analyzed.",
            )
        )
    inventory.apps = apps.detect(files, texts, inventory.dependencies, inventory.entry_points)
    return inventory
