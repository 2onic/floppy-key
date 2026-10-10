"""Host configuration manager for FloppyKey v2.

Stores pairing state and cryptographic hashes under ~/.config/floppy-key/
with strict filesystem permissions (0600).
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

CONFIG_DIR_NAME = "floppy-key"
CONFIG_FILE_NAME = "config.json"


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


def is_paired() -> bool:
    """Check if the current host is paired with a key."""
    path = get_config_path()
    return path.is_file()


def load_config() -> Optional[Dict[str, Any]]:
    """Load and parse the host configuration file."""
    path = get_config_path()
    if not path.is_file():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_config(config_data: Dict[str, Any]) -> Path:
    """Save the host configuration file with secure permissions (0600)."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o700)

    config_path = get_config_path()
    # Write to a temporary file in the same directory, then atomic rename
    tmp_path = config_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    os.chmod(tmp_path, 0o600)
    tmp_path.replace(config_path)
    return config_path


def revoke_config() -> bool:
    """Remove host configuration file to invalidate pairing."""
    config_path = get_config_path()
    if config_path.is_file():
        config_path.unlink()
        return True
    return False
