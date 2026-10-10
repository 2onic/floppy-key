"""Session-scoped lockout manager for FloppyKey.

Tracks consecutive authentication failures in XDG_RUNTIME_DIR (/run/user/<uid>).
Enforces a hard lockout after 3 consecutive failures until re-login.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("floppy_key.lockout")

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_FILE_NAME = "lockout.json"


def get_runtime_dir() -> Path:
    """Return session runtime dir in tmpfs RAM (/run/user/<uid>/floppy-key)."""
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base:
        p = Path(base) / "floppy-key"
    else:
        p = Path(f"/run/user/{os.getuid()}/floppy-key")
    return p


def get_lockout_file() -> Path:
    """Return the path to the lockout state file."""
    return get_runtime_dir() / LOCKOUT_FILE_NAME


def load_state() -> Dict[str, Any]:
    """Load the current session failure state."""
    path = get_lockout_file()
    if path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"failed_attempts": 0, "locked_out": False}


def save_state(state: Dict[str, Any]) -> None:
    """Persist session failure state atomically."""
    d = get_runtime_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = get_lockout_file()
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    tmp.replace(path)


def is_locked_out() -> bool:
    """Check if floppy unlocking is locked out for the current session."""
    state = load_state()
    return bool(state.get("locked_out", False))


def get_failed_count() -> int:
    """Get the current count of consecutive failed attempts."""
    state = load_state()
    return int(state.get("failed_attempts", 0))


def record_failure() -> bool:
    """Record an authentication failure. Returns True if lockout was triggered."""
    state = load_state()
    if state.get("locked_out", False):
        return True

    count = state.get("failed_attempts", 0) + 1
    state["failed_attempts"] = min(count, MAX_FAILED_ATTEMPTS)
    if count >= MAX_FAILED_ATTEMPTS:
        state["locked_out"] = True
        logger.warning(
            "Security lockout triggered (%d/%d failed attempts). Floppy unlock disabled for this session.",
            MAX_FAILED_ATTEMPTS,
            MAX_FAILED_ATTEMPTS,
        )
    else:
        logger.warning(
            "Authentication failure recorded (%d/%d failed attempts).",
            count,
            MAX_FAILED_ATTEMPTS,
        )
    save_state(state)
    return state["locked_out"]


def record_success() -> None:
    """Record a successful unlock and reset consecutive failure count."""
    state = load_state()
    if not state.get("locked_out", False):
        if state.get("failed_attempts", 0) > 0:
            state["failed_attempts"] = 0
            save_state(state)


def reset_lockout() -> None:
    """Reset session lockout state."""
    path = get_lockout_file()
    if path.is_file():
        try:
            path.unlink()
        except Exception:
            pass
