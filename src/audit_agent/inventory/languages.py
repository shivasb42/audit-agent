"""File classification by name, extension, and shebang."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

SUPPORTED_LANGUAGES = frozenset({"JavaScript", "TypeScript", "Python", "Dart"})

SOURCE_EXTENSIONS = {
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".tsx": "TypeScript",
    ".py": "Python",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".swift": "Swift",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".lua": "Lua",
    ".pl": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".bat": "Batch",
    ".ps1": "PowerShell",
    ".ejs": "HTML",
    ".hbs": "HTML",
    ".handlebars": "HTML",
    ".pug": "HTML",
    ".njk": "HTML",
    ".sql": "SQL",
    ".sol": "Solidity",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".sass": "CSS",
    ".less": "CSS",
}

CONFIG_EXTENSIONS = frozenset(
    {
        ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties", ".lock",
        ".gradle", ".cmake", ".plist", ".xcconfig", ".entitlements", ".pbxproj", ".xcworkspacedata",
        ".xcscheme", ".storyboard", ".xib", ".modulemap", ".csproj", ".sln", ".arb", ".pro",
        ".graphql", ".gql", ".proto", ".prisma", ".tf", ".hcl", ".xcsettings", ".rc", ".manifest",
    }
)
CONFIG_NAMES = frozenset(
    {
        "Dockerfile",
        "Makefile",
        "CMakeLists.txt",
        "Podfile",
        "go.mod",
        "go.sum",
        "Jenkinsfile",
        "Vagrantfile",
        "Brewfile",
        "Fastfile",
        "Appfile",
        "Matchfile",
        "Pluginfile",
        "apple-app-site-association",
        ".fvmrc",
        ".metadata",
        ".babelrc",
        "Procfile",
        "Gemfile",
        ".gitignore",
        ".gitattributes",
        ".dockerignore",
        ".npmrc",
        ".nvmrc",
        ".editorconfig",
        ".prettierrc",
        ".eslintrc",
    }
)
DOC_EXTENSIONS = frozenset({".md", ".rst", ".txt", ".adoc"})

SHEBANG_LANGUAGES = {
    "python": "Python",
    "python3": "Python",
    "node": "JavaScript",
    "bash": "Shell",
    "sh": "Shell",
    "zsh": "Shell",
    "ruby": "Ruby",
    "perl": "Perl",
}


JUNK_NAMES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})
JUNK_SUFFIXES = (".log", ".err")
GENERATED_DIRS = frozenset(
    {"dist", "build", ".next", ".nuxt", ".svelte-kit", "coverage", "node_modules", "__pycache__", ".venv", "venv"}
)
GENERATED_SUFFIXES = (
    ".min.js", ".min.css", ".bundle.js", ".map", ".pyc",
    ".g.dart", ".freezed.dart", ".mocks.dart", ".gr.dart", ".pb.dart", ".pbenum.dart", ".pbjson.dart",
)
GENERATED_DIRS_EXTRA = frozenset({".dart_tool", ".pub-cache", "Pods", ".gradle"})
MINIFIED_AVERAGE_LINE_LENGTH = 500


_TEST_DIRS = frozenset({"test", "tests", "__tests__", "integration_test", "test_driver", "e2e"})
_TEST_NAME = re.compile(r"(\.|_)(test|spec)\.[^.]+$|^test_[^/]+\.py$")


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    return any(p in _TEST_DIRS for p in parts[:-1]) or bool(_TEST_NAME.search(parts[-1]))


def is_junk_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in JUNK_NAMES or name.endswith(JUNK_SUFFIXES)


def is_generated_path(path: str) -> bool:
    p = PurePosixPath(path)
    return (
        any(part in GENERATED_DIRS or part in GENERATED_DIRS_EXTRA for part in p.parts[:-1])
        or p.name.endswith(GENERATED_SUFFIXES)
    )


MINIFIABLE_LANGUAGES = frozenset({"JavaScript", "TypeScript", "CSS"})


def looks_minified(language: str | None, text: str) -> bool:
    if language not in MINIFIABLE_LANGUAGES:
        return False
    lines = text.count("\n") + 1
    return len(text) / lines > MINIFIED_AVERAGE_LINE_LENGTH


def is_secret_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return (
        name == ".env"
        or name.startswith(".env.")
        or name.endswith((".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"))
    )


def is_dockerfile(path: str) -> bool:
    name = PurePosixPath(path).name
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile")


def classify(path: str) -> tuple[str, str | None]:
    """Return (category, language) from the path alone."""
    p = PurePosixPath(path)
    suffix = p.suffix.lower()
    if suffix in SOURCE_EXTENSIONS:
        return "source", SOURCE_EXTENSIONS[suffix]
    if p.name in CONFIG_NAMES or is_dockerfile(path) or suffix in CONFIG_EXTENSIONS:
        return "config", None
    if (
        suffix in DOC_EXTENSIONS
        or p.name.upper().startswith(("README", "LICENSE", "CHANGELOG"))
        or (p.parent.name == "docs" and not suffix)
    ):
        return "docs", None
    return "other", None


def shebang_language(head: bytes) -> str | None:
    if not head.startswith(b"#!"):
        return None
    line = head.split(b"\n", 1)[0].decode("utf-8", errors="replace")
    parts = line[2:].split()
    if not parts:
        return None
    interpreter = parts[0].rsplit("/", 1)[-1]
    if interpreter == "env" and len(parts) > 1:
        interpreter = parts[1]
    return SHEBANG_LANGUAGES.get(interpreter)
