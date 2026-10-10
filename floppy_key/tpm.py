"""TPM 2.0 Hardware Security Sealing for FloppyKey.

Utilizes systemd-creds and the Linux kernel TPM Resource Manager (/dev/tpmrm0)
to seal host configuration credentials to the motherboard's TPM 2.0 chip
bound to Secure Boot (PCR 7).
"""

import functools
import logging
from pathlib import Path
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger("floppy_key.tpm")


@functools.lru_cache(maxsize=1)
def is_tpm2_available() -> bool:
    """Check if TPM 2.0 hardware and systemd-creds are available."""
    if not Path("/dev/tpmrm0").exists() and not Path("/dev/tpm0").exists():
        return False

    if not shutil.which("systemd-creds"):
        return False

    try:
        res = subprocess.run(
            ["systemd-analyze", "has-tpm2"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return "yes" in res.stdout.lower()
    except Exception:
        # Fallback test with systemd-creds directly
        try:
            p = subprocess.run(
                ["systemd-creds", "encrypt", "--with-key=tpm2", "-", "-"],
                input=b"probe",
                capture_output=True,
                timeout=4,
            )
            return p.returncode == 0
        except Exception:
            return False


def seal_data(data: bytes, pcr: int = 7) -> Optional[bytes]:
    """Seal data with TPM 2.0 chip bound to PCR 7 (Secure Boot).

    Falls back to TPM 2.0 sealing without PCR if PCR 7 is not supported.
    """
    if not is_tpm2_available():
        return None

    # Try sealing with PCR 7
    try:
        res = subprocess.run(
            ["systemd-creds", "encrypt", "--with-key=tpm2", f"--tpm2-pcrs={pcr}", "-", "-"],
            input=data,
            capture_output=True,
            timeout=8,
        )
        if res.returncode == 0 and res.stdout:
            logger.info("Successfully sealed credentials with TPM 2.0 (PCR %d bound)", pcr)
            return res.stdout
    except Exception as e:
        logger.debug("TPM 2.0 PCR %d sealing failed: %s", pcr, e)

    # Fallback: seal with TPM 2.0 without PCR binding
    try:
        res = subprocess.run(
            ["systemd-creds", "encrypt", "--with-key=tpm2", "-", "-"],
            input=data,
            capture_output=True,
            timeout=8,
        )
        if res.returncode == 0 and res.stdout:
            logger.info("Successfully sealed credentials with TPM 2.0 (standard hardware seal)")
            return res.stdout
    except Exception as e:
        logger.warning("TPM 2.0 sealing fallback failed: %s", e)

    return None


def unseal_data(sealed_data: bytes) -> Optional[bytes]:
    """Unseal data via TPM 2.0 chip.

    Returns None if the platform state does not match or if TPM unsealing fails.
    """
    if not is_tpm2_available() or not sealed_data:
        return None

    try:
        res = subprocess.run(
            ["systemd-creds", "decrypt", "-", "-"],
            input=sealed_data,
            capture_output=True,
            timeout=8,
        )
        if res.returncode == 0 and res.stdout:
            return res.stdout
        else:
            logger.error("TPM 2.0 unsealing rejected (platform state mismatch or tampered credentials): %s", res.stderr.strip())
            return None
    except Exception as e:
        logger.error("TPM 2.0 unsealing failed: %s", e)
        return None
