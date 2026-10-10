"""Cryptographic operations for FloppyKey v2.

Zero third-party dependencies: relies only on Python standard library
(secrets, hashlib, hmac, uuid, datetime, pathlib).
Binds token verification to host machine-id.
"""

from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import secrets
from typing import Any, Dict, Tuple
import uuid


def get_machine_id() -> str:
    """Retrieve host machine-id to bind key to this physical system."""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        path = Path(p)
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8").strip()
                if content:
                    return content
            except Exception:
                pass
    return "unknown-machine"


def generate_key_pair(username: str, volume_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate a high-entropy floppy key token and corresponding host verification record.

    Binds the generated host hash to the unique machine-id and volume identifier.

    Returns:
        (floppy_payload, host_payload)
    """
    key_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    created_at = datetime.now(timezone.utc).isoformat()
    machine_id = get_machine_id()

    # SHA-256(salt:machine_id:volume_id:token)
    payload_buf = bytearray(f"{salt}:{machine_id}:{volume_id}:{token}".encode("utf-8"))
    digest = hashlib.sha256(payload_buf).hexdigest()

    # Zero out sensitive buffer
    for i in range(len(payload_buf)):
        payload_buf[i] = 0

    floppy_payload = {
        "version": 2,
        "key_id": key_id,
        "token": token,
        "user": username,
        "created_at": created_at,
    }

    host_payload = {
        "version": 2,
        "key_id": key_id,
        "machine_id": machine_id,
        "volume_id": volume_id,
        "salt": salt,
        "hash": digest,
        "user": username,
        "paired_at": created_at,
    }

    return floppy_payload, host_payload


def verify_token(token: str, key_id: str, host_config: Dict[str, Any], volume_id: str = "") -> bool:
    """Verify that the floppy token and key_id match the host configuration, machine ID, and volume ID."""
    if not token or not key_id or not host_config:
        return False

    stored_key_id = host_config.get("key_id")
    stored_salt = host_config.get("salt")
    stored_hash = host_config.get("hash")
    stored_machine_id = host_config.get("machine_id")
    stored_volume_id = host_config.get("volume_id")

    if not stored_key_id or not stored_salt or not stored_hash:
        return False

    current_machine_id = get_machine_id()

    # If machine_id is recorded in host config, enforce strict match
    if stored_machine_id and not hmac.compare_digest(stored_machine_id, current_machine_id):
        return False

    # If volume_id is recorded in host config, enforce strict match
    if stored_volume_id and volume_id and not hmac.compare_digest(stored_volume_id, volume_id):
        return False

    # Check key_id matches
    if not hmac.compare_digest(key_id, stored_key_id):
        return False

    # Check with volume_id
    calc_buf = bytearray(f"{stored_salt}:{current_machine_id}:{volume_id}:{token}".encode("utf-8"))
    expected_hash = hashlib.sha256(calc_buf).hexdigest()
    matched = hmac.compare_digest(expected_hash, stored_hash)

    # Zero buffer
    for i in range(len(calc_buf)):
        calc_buf[i] = 0

    if matched:
        return True

    # Fallback without volume_id for backward compatibility
    calc_buf = bytearray(f"{stored_salt}:{current_machine_id}:{token}".encode("utf-8"))
    expected_hash = hashlib.sha256(calc_buf).hexdigest()
    matched = hmac.compare_digest(expected_hash, stored_hash)
    for i in range(len(calc_buf)):
        calc_buf[i] = 0

    if matched:
        return True

    # Legacy fallback without machine_id
    if not stored_machine_id:
        calc_buf = bytearray(f"{stored_salt}:{token}".encode("utf-8"))
        legacy_hash = hashlib.sha256(calc_buf).hexdigest()
        matched = hmac.compare_digest(legacy_hash, stored_hash)
        for i in range(len(calc_buf)):
            calc_buf[i] = 0
        if matched:
            return True

    return False
