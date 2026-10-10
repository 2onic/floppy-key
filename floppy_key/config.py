"""Host configuration manager for FloppyKey v2.

Stores pairing state and cryptographic hashes under ~/.config/floppy-key/
with strict filesystem permissions (0600).
Supports hardware-backed sealing via TPM 2.0 (PCR 7).
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from floppy_key import tpm

logger = logging.getLogger("floppy_key.config")

CONFIG_DIR_NAME = "floppy-key"
CONFIG_FILE_NAME = "config.json"
SEALED_CONFIG_NAME = "config.tpm2"


def get_config_dir() -> Path:
    """Return the configuration directory path (~/.config/floppy-key)."""
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        config_dir = Path(base) / CONFIG_DIR_NAME
    else:
        config_dir = Path.home() / ".config" / CONFIG_DIR_NAME
    return config_dir


def get_config_path() -> Path:
    """Return the plaintext configuration file path."""
    return get_config_dir() / CONFIG_FILE_NAME


def get_sealed_config_path() -> Path:
    """Return the TPM 2.0 sealed configuration file path."""
    return get_config_dir() / SEALED_CONFIG_NAME


def is_tpm2_sealed() -> bool:
    """Check if the configuration is sealed with TPM 2.0 hardware."""
    return get_sealed_config_path().is_file()


def is_paired() -> bool:
    """Check if the current host is paired with a key."""
    return get_sealed_config_path().is_file() or get_config_path().is_file()


def load_config() -> Optional[Dict[str, Any]]:
    """Load and parse the host configuration file.

    If a TPM 2.0 sealed config exists, unseals via TPM 2.0 hardware.
    Falls back to plaintext config for backward compatibility.
    """
    sealed_path = get_sealed_config_path()
    if sealed_path.is_file():
        try:
            sealed_data = sealed_path.read_bytes()
            unsealed = tpm.unseal_data(sealed_data)
            if unsealed:
                return json.loads(unsealed.decode("utf-8"))
            else:
                logger.error("Failed to unseal configuration via TPM 2.0 (platform state mismatch).")
                return None
        except Exception as e:
            logger.error("Error reading TPM 2.0 sealed config: %s", e)
            return None

    plaintext_path = get_config_path()
    if plaintext_path.is_file():
        try:
            with open(plaintext_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    return None


def save_config(config_data: Dict[str, Any]) -> Path:
    """Save host configuration with TPM 2.0 sealing if available, else plaintext 0600."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o700)

    raw_bytes = json.dumps(config_data, indent=2, ensure_ascii=False).encode("utf-8")

    # Try TPM 2.0 hardware sealing
    if tpm.is_tpm2_available():
        sealed_bytes = tpm.seal_data(raw_bytes)
        if sealed_bytes:
            sealed_path = get_sealed_config_path()
            tmp_path = sealed_path.with_suffix(".tmp")
            tmp_path.write_bytes(sealed_bytes)
            os.chmod(tmp_path, 0o600)
            tmp_path.replace(sealed_path)

            # Purge plaintext config if it exists so no unsealed secrets linger
            plaintext_path = get_config_path()
            if plaintext_path.is_file():
                try:
                    plaintext_path.unlink()
                except Exception:
                    pass

            return sealed_path

    # Software fallback
    config_path = get_config_path()
    tmp_path = config_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    os.chmod(tmp_path, 0o600)
    tmp_path.replace(config_path)
    return config_path


def revoke_config() -> bool:
    """Remove host configuration files to invalidate pairing."""
    revoked = False
    sealed_path = get_sealed_config_path()
    if sealed_path.is_file():
        sealed_path.unlink()
        revoked = True

    plaintext_path = get_config_path()
    if plaintext_path.is_file():
        plaintext_path.unlink()
        revoked = True

    return revoked
