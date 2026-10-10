"""Desktop notifications for FloppyKey.

Threat model note: FloppyKey only defends against a physical attacker sitting
at the lock screen without the paired floppy. Any process already running as
the user can call `loginctl unlock-session` directly, so in-process memory
hardening (prctl, buffer zeroing) is intentionally not attempted.
"""

import logging
import subprocess

logger = logging.getLogger("floppy_key.security")


def notify(title: str, message: str, urgency: str = "normal") -> bool:
    """Send a desktop notification via notify-send."""
    try:
        subprocess.run(
            ["notify-send", "-u", urgency, "-a", "FloppyKey", title, message],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return True
    except Exception as e:
        logger.debug("notify-send failed: %s", e)
        return False


def send_security_alert(title: str, message: str) -> bool:
    """Send a critical desktop security notification to the user."""
    return notify(title, message, urgency="critical")
