"""Process and memory security hardening for FloppyKey.

Provides:
- Core dump and ptrace disabling via Linux prctl(PR_SET_DUMPABLE, 0)
- Desktop security alert notifications via notify-send
- Sensitive memory wiping
"""

import ctypes
import logging
import subprocess

logger = logging.getLogger("floppy_key.security")


def disable_coredump() -> bool:
    """Disable core dumping and unprivileged ptrace inspection via prctl."""
    try:
        libc = ctypes.CDLL(None)
        PR_SET_DUMPABLE = 4
        res = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        return res == 0
    except Exception as e:
        logger.debug("Failed to set PR_SET_DUMPABLE: %s", e)
        return False


def send_security_alert(title: str, message: str) -> bool:
    """Send a critical desktop security notification to the user."""
    try:
        subprocess.run(
            ["notify-send", "-u", "critical", "-a", "FloppyKey", title, message],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return True
    except Exception as e:
        logger.debug("notify-send failed: %s", e)
        return False


def zero_memory(buf: bytearray) -> None:
    """Explicitly zero out mutable memory buffers containing sensitive material."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
