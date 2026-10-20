"""Read-only access to the Git repository being audited."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


class RepositoryError(Exception):
    pass


@dataclass(frozen=True)
class GitRepository:
    root: Path
    head_commit: str | None
    branch: str | None
    dirty: bool

    @property
    def name(self) -> str:
        return self.root.name


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # GIT_OPTIONAL_LOCKS=0 stops commands like `git status` from refreshing the index,
    # which would otherwise write to the target repository.
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )


def _git_output(repo: Path, *args: str) -> str:
    result = _git(repo, *args)
    if result.returncode != 0:
        message = result.stderr.strip() or f"git {' '.join(args)} failed"
        raise RepositoryError(message)
    return result.stdout


def _git_optional(repo: Path, *args: str) -> str | None:
    result = _git(repo, *args)
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def open_repository(path: str | os.PathLike[str]) -> GitRepository:
    path = Path(path).expanduser().resolve()
    if not path.is_dir():
        raise RepositoryError(f"{path} is not a directory")
    top = _git(path, "rev-parse", "--show-toplevel")
    if top.returncode != 0 or not top.stdout.strip():
        raise RepositoryError(f"{path} is not inside a Git working tree")
    root = Path(top.stdout.strip()).resolve()
    return GitRepository(
        root=root,
        head_commit=_git_optional(root, "rev-parse", "--verify", "--quiet", "HEAD"),
        branch=_git_optional(root, "symbolic-ref", "--quiet", "--short", "HEAD"),
        dirty=bool(_git_output(root, "status", "--porcelain").strip()),
    )


def _ls_files(root: Path, *args: str) -> list[str]:
    output = _git_output(root, "ls-files", "-z", *args)
    return sorted({p for p in output.split("\0") if p})


def list_tracked_files(root: Path) -> list[str]:
    """Files tracked by git, as repo-relative POSIX paths."""
    return _ls_files(root, "--cached")


def list_untracked_files(root: Path) -> list[str]:
    """Untracked files that are not gitignored, as repo-relative POSIX paths."""
    return _ls_files(root, "--others", "--exclude-standard")
