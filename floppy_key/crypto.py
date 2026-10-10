"""Cryptographic operations for FloppyKey v2.

Zero third-party dependencies: relies only on Python standard library
(secrets, hashlib, hmac, uuid, datetime, pathlib, enum).

Key modes:
- static  (default): the floppy token never changes unless `floppy-key rotate`
  is run manually. The disk can stay write-protected.
- rolling (opt-in via `pair --rolling`): the token is replaced after every
  lock-screen unlock using a two-phase commit; presenting a retired token is
  treated as evidence of a cloned disk and permanently invalidates the pairing.

Hashes are bound to the host machine-id (not a security boundary, it only
prevents accidentally reusing a config on another machine). Legacy pairings
also mixed a floppy volume-id into the hash; that value is now taken from the
stored config only and never re-read from the disk.
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
    COMPROMISED = "compromised"
    INVALID = "invalid"


MAX_RETIRED_TOKENS = 20


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_ascii_str(value: Any) -> bool:
    return isinstance(value, str) and value.isascii()


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
    return hashlib.sha256(f"{salt}:{machine_id}:{volume_id}:{token}".encode("utf-8")).hexdigest()


def is_rolling(host_config: Dict[str, Any]) -> bool:
    """Return True if the pairing uses rolling tokens. Legacy configs are static."""
    return bool(host_config.get("rolling", False))


def is_compromised(host_config: Dict[str, Any]) -> bool:
    return bool(host_config.get("compromised"))


def generate_key_pair(username: str, rolling: bool = False) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate initial floppy payload and host verification record."""
    key_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    created_at = _now()
    machine_id = get_machine_id()

    digest = compute_token_hash(token, salt, machine_id)

    floppy_payload = {
        "version": 2,
        "key_id": key_id,
        "token": token,
        "counter": 1,
        "user": username,
        "created_at": created_at,
    }

    host_payload = {
        "version": 3,
        "key_id": key_id,
        "machine_id": machine_id,
        "rolling": bool(rolling),
        "salt": salt,
        "hash": digest,
        "counter": 1,
        "pending": None,
        "retired": [],
        "compromised": None,
        "user": username,
        "paired_at": created_at,
    }

    return floppy_payload, host_payload


def _record_matches(token: str, record: Dict[str, Any], machine_id: str, volume_ids: List[str]) -> bool:
    salt = record.get("salt")
    expected_hash = record.get("hash")
    if not _is_ascii_str(salt) or not _is_ascii_str(expected_hash) or not salt or not expected_hash:
        return False
    for vol in volume_ids:
        if hmac.compare_digest(compute_token_hash(token, salt, machine_id, vol), expected_hash):
            return True
    return False


def verify_token_state(
    token: Any, key_id: Any, host_config: Optional[Dict[str, Any]]
) -> Tuple[TokenVerifyStatus, Optional[str]]:
    """Verify presented floppy token against current, pending, and retired records.

    Never raises on malformed input; malformed values are reported as INVALID.

    Returns:
        (TokenVerifyStatus, detail_message)
    """
    if not isinstance(host_config, dict) or not host_config:
        return TokenVerifyStatus.INVALID, "Host not paired"

    if is_compromised(host_config):
        return TokenVerifyStatus.COMPROMISED, "Pairing was invalidated after clone detection; re-pair required"

    if not _is_ascii_str(token) or not _is_ascii_str(key_id) or not token or not key_id:
        return TokenVerifyStatus.INVALID, "Missing or malformed credentials"

    stored_key_id = host_config.get("key_id")
    if not _is_ascii_str(stored_key_id) or not hmac.compare_digest(key_id, stored_key_id):
        return TokenVerifyStatus.INVALID, "Key ID mismatch"

    current_machine_id = get_machine_id()
    stored_machine_id = host_config.get("machine_id")
    if _is_ascii_str(stored_machine_id) and stored_machine_id:
        if not hmac.compare_digest(stored_machine_id, current_machine_id):
            return TokenVerifyStatus.INVALID, "Machine ID mismatch"

    # Legacy pairings mixed a volume-id into the hash; new hashes use "".
    stored_volume_id = host_config.get("volume_id")
    volume_ids = [""]
    if isinstance(stored_volume_id, str) and stored_volume_id:
        volume_ids.insert(0, stored_volume_id)

    # 1. Current active token
    if _record_matches(token, host_config, current_machine_id, volume_ids):
        return TokenVerifyStatus.VALID, None

    # 2. Pending transaction (interrupted previous roll)
    pending = host_config.get("pending")
    if isinstance(pending, dict) and _record_matches(token, pending, current_machine_id, volume_ids):
        return TokenVerifyStatus.PENDING_COMMIT, None

    # 3. Retired records (clone / replay detection)
    retired_list = host_config.get("retired", [])
    if isinstance(retired_list, list):
        for rec in retired_list:
            if isinstance(rec, dict) and _record_matches(token, rec, current_machine_id, volume_ids):
                return (
                    TokenVerifyStatus.CLONE_DETECTED,
                    f"Presented token matches retired sequence #{rec.get('counter', '?')}",
                )

    return TokenVerifyStatus.INVALID, "Token hash mismatch"


def verify_token(token: Any, key_id: Any, host_config: Optional[Dict[str, Any]]) -> bool:
    """Backward-compatible helper returning boolean validation."""
    status, _ = verify_token_state(token, key_id, host_config)
    return status in (TokenVerifyStatus.VALID, TokenVerifyStatus.PENDING_COMMIT)


def prepare_next_token(host_config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Prepare next token for floppy and staging record for host (Two-Phase Commit).

    Returns:
        (next_floppy_payload, host_config_with_pending)
    """
    next_token = secrets.token_urlsafe(32)
    next_salt = secrets.token_hex(16)
    next_counter = int(host_config.get("counter", 1) or 1) + 1
    machine_id = get_machine_id()
    timestamp = _now()

    next_hash = compute_token_hash(next_token, next_salt, machine_id)

    next_floppy_payload = {
        "version": 2,
        "key_id": host_config.get("key_id", ""),
        "token": next_token,
        "counter": next_counter,
        "user": host_config.get("user", ""),
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

    retired = list(updated.get("retired") or [])
    retired.append(
        {
            "salt": updated.get("salt", ""),
            "hash": updated.get("hash", ""),
            "counter": updated.get("counter", 1),
            "retired_at": _now(),
        }
    )
    if len(retired) > MAX_RETIRED_TOKENS:
        retired = retired[-MAX_RETIRED_TOKENS:]

    updated["retired"] = retired
    updated["salt"] = pending["salt"]
    updated["hash"] = pending["hash"]
    updated["counter"] = pending.get("counter", int(updated.get("counter", 1) or 1) + 1)
    updated["last_rolled_at"] = _now()
    updated["pending"] = None

    return updated


def mark_compromised(host_config: Dict[str, Any], detail: Optional[str]) -> Dict[str, Any]:
    """Permanently invalidate the pairing after clone detection.

    The system cannot tell whether the retired token was presented by the owner
    (meaning an attacker holds the currently valid copy) or by the attacker, so
    every outstanding credential is destroyed. Only `floppy-key pair` recovers.
    """
    updated = dict(host_config)
    updated["compromised"] = {"at": _now(), "detail": detail or ""}
    updated["salt"] = ""
    updated["hash"] = ""
    updated["pending"] = None
    return updated
