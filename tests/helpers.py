from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


def make_repo(root: Path, files: dict[str, str], untracked: dict[str, str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    git = ["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.com"]
    subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "initial"], check=True)
    for rel, content in (untracked or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def repo_fingerprint(root: Path) -> str:
    """Hash of git state plus every file's path, size, mtime, and content under the repo."""
    digest = hashlib.sha256()
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    for args in (["status", "--porcelain=v1", "-uall"], ["rev-parse", "HEAD"], ["branch", "--list"]):
        digest.update(subprocess.run(["git", "-C", str(root), *args], capture_output=True, env=env).stdout)
    for path in sorted(root.rglob("*")):
        if path.is_file():
            info = path.stat()
            digest.update(f"{path.relative_to(root)}:{info.st_size}:{info.st_mtime_ns}".encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()
