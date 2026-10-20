"""Entry points declared in source files, Dockerfiles, Procfiles, and PM2 configs."""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import PurePosixPath

from audit_agent.inventory.languages import is_dockerfile
from audit_agent.inventory.manifests import referenced_files
from audit_agent.inventory.models import EntryPoint

_PY_MAIN = re.compile(r"""^if\s+__name__\s*==\s*['"]__main__['"]\s*:""", re.M)
_NODE_MAIN = re.compile(
    r"require\.main\s*===?\s*module|module\s*===?\s*require\.main|import\.meta\.main\b"
    r"|import\.meta\.url\s*===?\s*[^\n;]*process\.argv\[1\]"
)
_DART_MAIN = re.compile(r"^(?:Future<void>\s+|void\s+)?main\s*\(", re.M)
_DART_TEST_DIRS = ("test/", "integration_test/", "test_driver/")
_DOCKER_RUN = re.compile(r"^\s*(CMD|ENTRYPOINT)\s+(.+)$", re.I | re.M)
_PM2_SCRIPT = re.compile(r"""\bscript\s*:\s*['"]([^'"]+)['"]""")


def _docker_command(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("["):
        try:
            return " ".join(str(part) for part in json.loads(raw))
        except json.JSONDecodeError:
            pass
    return raw


def scan(texts: dict[str, str], languages: dict[str, str | None], file_set: set[str]) -> list[EntryPoint]:
    entries: list[EntryPoint] = []
    for path, text in sorted(texts.items()):
        language = languages.get(path)
        name = PurePosixPath(path).name
        base = posixpath.dirname(path)

        if language == "Python":
            if name == "__main__.py":
                entries.append(EntryPoint(path, "python-package-main", path, "package __main__ module"))
            elif _PY_MAIN.search(text):
                entries.append(EntryPoint(path, "python-main", path, 'if __name__ == "__main__"'))
        elif language == "Dart":
            if match := _DART_MAIN.search(text):
                is_test = name.endswith("_test.dart") or any(
                    path.startswith(d) or f"/{d}" in path for d in _DART_TEST_DIRS
                )
                kind = "dart-test" if is_test else "dart-main"
                entries.append(EntryPoint(path, kind, path, match.group(0).strip() + ")"))
        elif language in ("JavaScript", "TypeScript"):
            if match := _NODE_MAIN.search(text):
                entries.append(EntryPoint(path, "node-main", path, match.group(0)))
            if name.startswith("ecosystem.config."):
                for script in _PM2_SCRIPT.findall(text):
                    targets = referenced_files(script, base, file_set) or [None]
                    entries.extend(EntryPoint(t, "pm2", path, f"pm2 script: {script}") for t in targets)

        if is_dockerfile(path):
            for match in _DOCKER_RUN.finditer(text):
                command = _docker_command(match.group(2))
                detail = f"{match.group(1).upper()} {command}"
                targets = referenced_files(command, base, file_set) or [None]
                entries.extend(EntryPoint(t, "docker", path, detail) for t in targets)
        elif name == "Procfile":
            for line in text.splitlines():
                if ":" not in line or line.lstrip().startswith("#"):
                    continue
                process, command = line.split(":", 1)
                detail = f"{process.strip()}: {command.strip()}"
                targets = referenced_files(command, base, file_set) or [None]
                entries.extend(EntryPoint(t, "procfile", path, detail) for t in targets)
    return entries
