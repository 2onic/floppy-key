"""Host configuration manager for FloppyKey v2.

Stores pairing state and cryptographic hashes under ~/.config/floppy-key/
with strict filesystem permissions (0600). Writes are durable (fsync of file
and directory) because the rolling-token two-phase commit relies on the host
record reaching disk before the floppy is written.
"""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

CONFIG_DIR_NAME = "floppy-key"
CONFIG_FILE_NAME = "config.json"
LOCK_FILE_NAME = "config.lock"


def get_config_dir() -> Path:
    """Return the configuration directory path (~/.config/floppy-key)."""
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        config_dir = Path(base) / CONFIG_DIR_NAME
    else:
        config_dir = Path.home() / ".config" / CONFIG_DIR_NAME
    return config_dir


def get_config_path() -> Path:
    """Return the configuration file path."""
    return get_config_dir() / CONFIG_FILE_NAME


def _ensure_config_dir() -> Path:
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o700)
    return config_dir


@contextmanager
def locked() -> Iterator[None]:
    """Hold an exclusive advisory lock serialising pairing state changes.

    Used by the daemon, `pair`, `rotate` and `revoke` so that concurrent
    processes never overwrite each other's config or floppy writes.
    """
    lock_path = _ensure_config_dir() / LOCK_FILE_NAME
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def is_paired() -> bool:
    """Check if the current host is paired with a key."""
    return get_config_path().is_file()


def load_config() -> Optional[Dict[str, Any]]:
    """Load and parse the host configuration file."""
    path = get_config_path()
    if not path.is_file():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def save_config(config_data: Dict[str, Any]) -> Path:
    """Durably save the host configuration file with secure permissions (0600)."""
    config_dir = _ensure_config_dir()
    config_path = get_config_path()
    tmp_path = config_path.with_suffix(".tmp")

    try:
        tmp_path.unlink()
    except FileNotFoundError:
        pass

    data = (json.dumps(config_data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)

    os.replace(tmp_path, config_path)

    dir_fd = os.open(config_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

    return config_path


def revoke_config() -> bool:
    """Remove host configuration file to invalidate pairing."""
    config_path = get_config_path()
    if config_path.is_file():
        config_path.unlink()
        return True
    return False
