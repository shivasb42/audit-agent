from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FileRecord:
    path: str
    category: str
    language: str | None
    supported: bool
    size_bytes: int
    line_count: int | None
    module_path: str | None
    note: str | None = None


@dataclass
class ModuleRecord:
    path: str
    package_root: str | None
    languages: list[str]
    file_count: int
    line_count: int


@dataclass
class Dependency:
    manifest_path: str
    ecosystem: str
    name: str
    version_spec: str | None
    scope: str


@dataclass
class EntryPoint:
    path: str | None
    kind: str
    source_path: str
    detail: str


@dataclass
class Relationship:
    source_path: str
    kind: str
    specifier: str
    target_path: str | None
    target_package: str | None
    line: int


@dataclass
class Unsupported:
    technology: str
    kind: str
    evidence_path: str
    file_count: int
    reason: str


@dataclass
class Skipped:
    reason: str
    file_count: int
    example_path: str


@dataclass
class Inventory:
    files: list[FileRecord] = field(default_factory=list)
    modules: list[ModuleRecord] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    unsupported: list[Unsupported] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
