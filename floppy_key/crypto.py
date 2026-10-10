"""Cryptographic operations for FloppyKey v2.

Zero third-party dependencies: relies only on Python standard library
(secrets, hashlib, hmac, uuid, datetime, pathlib, enum).
Binds token verification to host machine-id and volume-id.
Supports dynamic rolling tokens with clone / replay attack detection.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional, Tuple
import uuid


class TokenVerifyStatus(str, Enum):
    VALID = "valid"
    PENDING_COMMIT = "pending_commit"
    CLONE_DETECTED = "clone_detected"
    INVALID = "invalid"


MAX_RETIRED_TOKENS = 20


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


def compute_token_hash(token: str, salt: str, machine_id: str = "", volume_id: str = "") -> str:
    """Calculate SHA-256 digest of salt:machine_id:volume_id:token."""
    payload_buf = bytearray(f"{salt}:{machine_id}:{volume_id}:{token}".encode("utf-8"))
    digest = hashlib.sha256(payload_buf).hexdigest()
    for i in range(len(payload_buf)):
        payload_buf[i] = 0
    return digest


def generate_key_pair(username: str, volume_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate initial key pair with dynamic rolling token tracking."""
    key_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    created_at = datetime.now(timezone.utc).isoformat()
    machine_id = get_machine_id()

    digest = compute_token_hash(token, salt, machine_id, volume_id)

    floppy_payload = {
        "version": 2,
        "key_id": key_id,
        "token": token,
        "counter": 1,
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
        "counter": 1,
        "pending": None,
        "retired": [],
        "user": username,
        "paired_at": created_at,
    }

    return floppy_payload, host_payload


def verify_token_state(
    token: str, key_id: str, host_config: Dict[str, Any], volume_id: str = ""
) -> Tuple[TokenVerifyStatus, Optional[str]]:
    """Verify presented floppy token against current, pending, and retired records.

    Returns:
        (TokenVerifyStatus, detail_message)
    """
    if not token or not key_id or not host_config:
        return TokenVerifyStatus.INVALID, "Missing credentials"

    stored_key_id = host_config.get("key_id")
    if not stored_key_id or not hmac.compare_digest(key_id, stored_key_id):
        return TokenVerifyStatus.INVALID, "Key ID mismatch"

    current_machine_id = get_machine_id()
    stored_machine_id = host_config.get("machine_id")
    if stored_machine_id and not hmac.compare_digest(stored_machine_id, current_machine_id):
        return TokenVerifyStatus.INVALID, "Machine ID mismatch"

    stored_volume_id = host_config.get("volume_id")
    if stored_volume_id and volume_id and not hmac.compare_digest(stored_volume_id, volume_id):
        return TokenVerifyStatus.INVALID, "Volume ID mismatch"

    # 1. Check current active token
    current_salt = host_config.get("salt", "")
    current_hash = host_config.get("hash", "")
    if current_salt and current_hash:
        expected = compute_token_hash(token, current_salt, current_machine_id, volume_id)
        if hmac.compare_digest(expected, current_hash):
            return TokenVerifyStatus.VALID, None

        # Fallback without volume_id for legacy pairings
        expected_no_vol = compute_token_hash(token, current_salt, current_machine_id, "")
        if hmac.compare_digest(expected_no_vol, current_hash):
            return TokenVerifyStatus.VALID, None

    # 2. Check pending transaction (interrupted previous roll commit)
    pending = host_config.get("pending")
    if isinstance(pending, dict):
        p_salt = pending.get("salt", "")
        p_hash = pending.get("hash", "")
        if p_salt and p_hash:
            expected_p = compute_token_hash(token, p_salt, current_machine_id, volume_id)
            if hmac.compare_digest(expected_p, p_hash):
                return TokenVerifyStatus.PENDING_COMMIT, None

    # 3. Check retired records (CLONE / REPLAY DETECTION)
    retired_list = host_config.get("retired", [])
    if isinstance(retired_list, list):
        for rec in retired_list:
            if not isinstance(rec, dict):
                continue
            r_salt = rec.get("salt", "")
            r_hash = rec.get("hash", "")
            if r_salt and r_hash:
                expected_r = compute_token_hash(token, r_salt, current_machine_id, volume_id)
                if hmac.compare_digest(expected_r, r_hash):
                    return (
                        TokenVerifyStatus.CLONE_DETECTED,
                        f"Presented token matches retired sequence #{rec.get('counter', '?')}",
                    )

    return TokenVerifyStatus.INVALID, "Token hash mismatch"


def verify_token(token: str, key_id: str, host_config: Dict[str, Any], volume_id: str = "") -> bool:
    """Backward-compatible helper returning boolean validation."""
    status, _ = verify_token_state(token, key_id, host_config, volume_id)
    return status in (TokenVerifyStatus.VALID, TokenVerifyStatus.PENDING_COMMIT)


def prepare_next_token(
    host_config: Dict[str, Any], volume_id: str = ""
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Prepare next dynamic token for floppy and staging record for host (Two-Phase Commit).

    Returns:
        (next_floppy_payload, host_config_with_pending)
    """
    next_token = secrets.token_urlsafe(32)
    next_salt = secrets.token_hex(16)
    next_counter = host_config.get("counter", 1) + 1
    machine_id = get_machine_id()
    key_id = host_config.get("key_id", "")
    username = host_config.get("user", "")
    timestamp = datetime.now(timezone.utc).isoformat()

    next_hash = compute_token_hash(next_token, next_salt, machine_id, volume_id)

    next_floppy_payload = {
        "version": 2,
        "key_id": key_id,
        "token": next_token,
        "counter": next_counter,
        "user": username,
        "rolled_at": timestamp,
    }

    host_config_with_pending = dict(host_config)
    host_config_with_pending["pending"] = {
        "salt": next_salt,
        "hash": next_hash,
        "counter": next_counter,
        "staged_at": timestamp,
    }

    return next_floppy_payload, host_config_with_pending


def commit_roll(host_config: Dict[str, Any]) -> Dict[str, Any]:
    """Promote staged pending token to current active state and retire previous token."""
    updated = dict(host_config)
    pending = updated.get("pending")
    if not isinstance(pending, dict):
        return updated

    # Retire current token into historical ring buffer
    retired = list(updated.get("retired", []))
    retired.append(
        {
            "salt": updated.get("salt", ""),
            "hash": updated.get("hash", ""),
            "counter": updated.get("counter", 1),
            "retired_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    # Keep up to MAX_RETIRED_TOKENS entries
    if len(retired) > MAX_RETIRED_TOKENS:
        retired = retired[-MAX_RETIRED_TOKENS:]

    updated["retired"] = retired
    updated["salt"] = pending["salt"]
    updated["hash"] = pending["hash"]
    updated["counter"] = pending.get("counter", updated.get("counter", 1) + 1)
    updated["last_rolled_at"] = datetime.now(timezone.utc).isoformat()
    updated["pending"] = None

    return updated
