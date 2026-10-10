"""Cryptographic operations for FloppyKey v2.

Zero third-party dependencies: relies only on Python standard library
(secrets, hashlib, hmac, uuid, datetime).
"""

from datetime import datetime, timezone
import hashlib
import hmac
import secrets
from typing import Any, Dict, Tuple
import uuid


def generate_key_pair(username: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate a high-entropy floppy key token and corresponding host verification record.

    Returns:
        (floppy_payload, host_payload)
    """
    key_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    created_at = datetime.now(timezone.utc).isoformat()

    # SHA-256(salt + token)
    digest = hashlib.sha256(f"{salt}:{token}".encode("utf-8")).hexdigest()

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
        "salt": salt,
        "hash": digest,
        "user": username,
        "paired_at": created_at,
    }

    return floppy_payload, host_payload


def verify_token(token: str, key_id: str, host_config: Dict[str, Any]) -> bool:
    """Verify that the floppy token and key_id match the host configuration."""
    if not token or not key_id or not host_config:
        return False

    stored_key_id = host_config.get("key_id")
    stored_salt = host_config.get("salt")
    stored_hash = host_config.get("hash")

    if not stored_key_id or not stored_salt or not stored_hash:
        return False

    # Check key_id matches
    if not hmac.compare_digest(key_id, stored_key_id):
        return False

    # Compute expected hash
    expected_hash = hashlib.sha256(f"{stored_salt}:{token}".encode("utf-8")).hexdigest()

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_hash, stored_hash)
