"""Where the Anthropic API key lives: the ANTHROPIC_API_KEY environment variable, or a file
outside every repository that only the current user can read (~/.audit-agent/credentials)."""

from __future__ import annotations

import json
import os
from pathlib import Path


def credentials_path() -> Path:
    if env := os.environ.get("AUDIT_AGENT_CREDENTIALS"):
        return Path(env).expanduser()
    return Path.home() / ".audit-agent" / "credentials"


def get_api_key() -> str | None:
    if key := os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return key
    path = credentials_path()
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    key = data.get("anthropic_api_key") if isinstance(data, dict) else None
    return key.strip() if isinstance(key, str) and key.strip() else None


def save_api_key(key: str) -> Path:
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"anthropic_api_key": key.strip()}, handle)
    os.chmod(path, 0o600)
    return path


def clear_api_key() -> bool:
    try:
        credentials_path().unlink()
        return True
    except FileNotFoundError:
        return False


def masked(key: str) -> str:
    return f"{key[:10]}…{key[-4:]}" if len(key) > 16 else "…"
