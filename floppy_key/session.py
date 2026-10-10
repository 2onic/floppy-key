"""Session and Desktop Lock/Unlock Controller for GNOME Wayland/X11.

Uses native systemd-logind and GNOME ScreenSaver D-Bus interfaces without
requiring root privileges or external dependencies.
"""

import getpass
import logging
import os
import subprocess
from typing import Optional

logger = logging.getLogger("floppy_key.session")


def get_current_username() -> str:
    """Get the current running username."""
    return os.environ.get("USER") or getpass.getuser()


def get_display_session_id() -> Optional[str]:
    """Retrieve the logind graphical session ID for the current user."""
    username = get_current_username()
    try:
        res = subprocess.run(
            ["loginctl", "show-user", username, "-p", "Display", "--value"],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )
        session_id = res.stdout.strip()
        if session_id:
            return session_id
    except Exception as e:
        logger.debug("Failed to get Display session via show-user: %s", e)

    # Fallback: scan active sessions for graphical session
    try:
        res = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[2] == username:
                sid = parts[0]
                # verify session type
                chk = subprocess.run(
                    ["loginctl", "show-session", sid, "-p", "Type", "--value"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if chk.stdout.strip() in ("wayland", "x11"):
                    return sid
    except Exception as e:
        logger.debug("Fallback session scan failed: %s", e)

    return None


def is_screen_locked() -> bool:
    """Check if GNOME ScreenSaver is currently locked and active."""
    try:
        res = subprocess.run(
            ["busctl", "--user", "call", "org.gnome.ScreenSaver",
             "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver", "GetActive"],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )
        # Output format is "b true" or "b false"
        out = res.stdout.strip()
        return "true" in out
    except Exception as e:
        logger.debug("Error checking ScreenSaver GetActive: %s", e)
        # Default to True if we cannot determine, so unlock is attempted
        return True


def wake_up_screen() -> bool:
    """Deactivate screen saver / wake up via GNOME ScreenSaver SetActive false."""
    try:
        subprocess.run(
            ["busctl", "--user", "call", "org.gnome.ScreenSaver",
             "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver", "SetActive", "b", "false"],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )
        return True
    except Exception as e:
        logger.debug("SetActive false via ScreenSaver D-Bus failed: %s", e)
        return False


def unlock_desktop() -> bool:
    """Unlock the current user's desktop session.

    Dismisses the lock shield via D-Bus and loginctl unlock-session.
    """
    wake_up_screen()

    session_id = get_display_session_id()
    if not session_id:
        logger.error("Could not determine display session ID to unlock.")
        return False

    try:
        subprocess.run(
            ["loginctl", "unlock-session", session_id],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        logger.info("Successfully requested unlock for session %s", session_id)
        return True
    except Exception as e:
        logger.error("loginctl unlock-session failed for session %s: %s", session_id, e)
        return False


def lock_desktop() -> bool:
    """Lock the current user's desktop session (optional utility)."""
    session_id = get_display_session_id()
    if not session_id:
        return False

    try:
        subprocess.run(
            ["loginctl", "lock-session", session_id],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return True
    except Exception as e:
        logger.error("loginctl lock-session failed: %s", e)
        return False
