"""Command Line Interface for FloppyKey v2.

Provides subcommands:
  pair    - Pair an inserted floppy disk as the desktop unlock key
  daemon  - Run the background media monitor and unlocker daemon
  status  - Diagnose hardware, media, pairing, and session states
  unlock  - Test desktop screen wake-up and unlock directly
  revoke  - Invalidate and remove host and disk pairing credentials
  reset   - Reset session failed attempt count and lockout state
"""

import argparse
import fcntl
import logging
import os
import subprocess
import sys
import time

from floppy_key import __version__
from floppy_key import config
from floppy_key import crypto
from floppy_key import hardware
from floppy_key import lockout
from floppy_key import security
from floppy_key import session

logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
logger = logging.getLogger("floppy-key")


def print_banner():
    banner = r"""
  ===========================================================
    FloppyKey v2 - Physical Desktop Key for Linux
  ===========================================================
"""
    print(banner)


def cmd_pair(args) -> int:
    """Pair an inserted floppy disk with the current user account."""
    security.disable_coredump()
    username = session.get_current_username()
    print(f"[*] Pairing floppy key for user: {username}")

    dev = hardware.find_floppy_device()
    if not dev:
        print("[!] Error: No USB floppy drive found in system.")
        return 1

    print(f"[*] Found floppy drive: {dev.name} ({dev.vendor} {dev.model})")

    if not hardware.is_disk_present(dev):
        print("[!] Error: No floppy disk inserted. Please insert a 3.5\" floppy disk into the drive.")
        return 1

    print("[*] Physical floppy disk detected (1.44MB).")

    if config.is_paired() and not args.force:
        print("[!] Host is already paired with a key.")
        resp = input("[?] Overwrite existing pairing? [y/N]: ").strip().lower()
        if resp not in ("y", "yes"):
            print("[-] Pairing aborted.")
            return 0

    mount_point = hardware.ensure_mounted(dev, require_writable=True)
    if not mount_point:
        print("[!] Error: Could not mount floppy disk via udisks.")
        return 1

    print(f"[*] Floppy disk mounted at: {mount_point}")

    # Generate volume identifier and cryptographic key pair
    volume_id = hardware.get_disk_volume_id(dev, mount_point, create_if_missing=True)
    print("[*] Generating 256-bit high-entropy secret token & SHA-256 salt...")
    floppy_payload, host_payload = crypto.generate_key_pair(username, volume_id)

    # Write key to floppy
    key_file = hardware.write_key_file(mount_point, floppy_payload)
    print(f"[+] Floppy key written to: {key_file}")

    # Save host config
    cfg_file = config.save_config(host_payload)
    print(f"[+] Host pairing saved to: {cfg_file}")
    lockout.reset_lockout()

    print("\n" + "=" * 55)
    print(" Pairing Complete! Floppy is now your physical key.")
    print(f"    Key ID : {host_payload['key_id']}")
    print(f"    User   : {username}")
    print("=" * 55 + "\n")
    return 0


def acquire_daemon_lock():
    """Acquire exclusive flock to prevent multiple daemon instances from running concurrently."""
    lock_dir = lockout.get_runtime_dir()
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_file = lock_dir / "daemon.lock"
    f = open(lock_file, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except (BlockingIOError, OSError):
        f.close()
        return None


def cmd_daemon(args) -> int:
    """Run the background media monitoring and auto-unlock loop."""
    security.disable_coredump()
    lock_handle = acquire_daemon_lock()
    service_taken_over = False

    if not lock_handle:
        if getattr(args, "takeover", False):
            logger.info("Stopping floppy-key.service to run in foreground test mode...")
            subprocess.run(["systemctl", "--user", "stop", "floppy-key.service"], check=False)
            time.sleep(0.5)
            lock_handle = acquire_daemon_lock()
            if not lock_handle:
                logger.error("Could not acquire daemon lock even after stopping floppy-key.service.")
                return 1
            service_taken_over = True
        else:
            logger.error(
                "Another daemon instance is already running (e.g. floppy-key.service).\n"
                "  * View live background logs : journalctl --user -u floppy-key.service -f\n"
                "  * Run foreground test mode  : floppy-key daemon --takeover\n"
                "  * Or stop service manually  : systemctl --user stop floppy-key.service"
            )
            return 1

    interval = max(0.5, args.interval)
    logger.info("FloppyKey daemon started (poll interval: %.1fs)", interval)

    last_present = None
    unlocked_for_current_insertion = False
    last_screen_locked = session.is_screen_locked()
    alert_notified_for_lockout = False

    try:
        while True:
            # Monitor lock state transition to notify user upon manual password unlock
            current_screen_locked = session.is_screen_locked()
            if last_screen_locked and not current_screen_locked:
                if lockout.is_locked_out() and not alert_notified_for_lockout:
                    security.send_security_alert(
                        "FloppyKey Security Notice",
                        f"Notice: {lockout.get_failed_count()} unauthorized unlock attempts were blocked while locked.",
                    )
                    alert_notified_for_lockout = True
            elif not current_screen_locked and not lockout.is_locked_out():
                alert_notified_for_lockout = False
            last_screen_locked = current_screen_locked

            dev = hardware.find_floppy_device()
            if not dev:
                if last_present is not None:
                    logger.warning("Floppy drive disconnected.")
                    last_present = None
                time.sleep(interval * 2)
                continue

            current_present = hardware.is_disk_present(dev)

            # Ejected transition (size == 0)
            if not current_present:
                if last_present is True or last_present is None:
                    if last_present is True:
                        logger.info("Floppy disk physically ejected.")
                    hardware.force_unmount_if_stale(dev)
                    unlocked_for_current_insertion = False
                last_present = False

            # Inserted transition (size == 2880)
            else:
                if last_present is False or last_present is None:
                    logger.info("Floppy disk physically inserted into %s", dev.name)
                    last_present = True
                    unlocked_for_current_insertion = False

                # If disk is present and we haven't processed unlock for this insertion
                if not unlocked_for_current_insertion:
                    if lockout.is_locked_out():
                        logger.warning(
                            "Floppy unlock disabled due to previous failed attempts. Password unlock required."
                        )
                        unlocked_for_current_insertion = True
                    else:
                        host_cfg = config.load_config()
                        if not host_cfg:
                            logger.warning("No host pairing config found (~/.config/floppy-key/config.json).")
                            lockout.record_failure()
                            unlocked_for_current_insertion = True
                        else:
                            mount_point = hardware.ensure_mounted(dev)
                            if not mount_point:
                                logger.warning("Failed to access mounted floppy disk.")
                                lockout.record_failure()
                                unlocked_for_current_insertion = True
                            else:
                                key_data = hardware.read_key_file(mount_point)
                                if not key_data:
                                    logger.warning("No valid .floppy-key found on the inserted disk.")
                                    lockout.record_failure()
                                    unlocked_for_current_insertion = True
                                else:
                                    token = key_data.get("token")
                                    key_id = key_data.get("key_id")
                                    volume_id = hardware.get_disk_volume_id(dev, mount_point)
                                    if crypto.verify_token(token, key_id, host_cfg, volume_id):
                                        lockout.record_success()
                                        logger.info("Key verified! Unlocking desktop session...")
                                        session.unlock_desktop()
                                        unlocked_for_current_insertion = True
                                    else:
                                        logger.warning("Floppy key verification failed (token, key_id, or volume mismatch).")
                                        lockout.record_failure()
                                        unlocked_for_current_insertion = True

            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Daemon received interrupt signal, shutting down.")
        return 0
    finally:
        if lock_handle:
            try:
                lock_handle.close()
            except Exception:
                pass
        if service_taken_over:
            logger.info("Restoring background floppy-key.service...")
            subprocess.run(["systemctl", "--user", "start", "floppy-key.service"], check=False)


def cmd_status(args) -> int:
    """Display comprehensive diagnostics of hardware, media, pairing, and desktop."""
    print_banner()

    # 1. Hardware Drive
    print("-- 1. Floppy Drive Hardware --")
    dev = hardware.find_floppy_device()
    if dev:
        print(f"  Device node : {dev.dev_path}")
        print(f"  Model       : {dev.vendor} {dev.model}")
        print(f"  Sysfs Path  : {dev.sysfs_path}")
    else:
        print("  Status      : [!] No USB floppy drive detected.")

    # 2. Media Presence
    print("\n-- 2. Physical Media Sensor --")
    if dev:
        present = hardware.is_disk_present(dev)
        if present:
            print("  Status      : [OK] 1.44MB Floppy Disk PRESENT (/sys size == 2880)")
            mp = hardware.get_current_mount_point(dev)
            if mp:
                print(f"  Mount Point : {mp}")
            else:
                print("  Mount Point : [!] Not mounted")
        else:
            print("  Status      : [-] Drive is EMPTY / EJECTED (/sys size == 0)")
    else:
        print("  Status      : [-] N/A")

    # 3. Host Pairing Configuration
    print("\n-- 3. Host Pairing State --")
    cfg = config.load_config()
    if cfg:
        print("  Status      : [OK] PAIRED")
        print(f"  Config Path : {config.get_config_path()}")
        print(f"  Key ID      : {cfg.get('key_id')}")
        print(f"  User        : {cfg.get('user')}")
        print(f"  Paired At   : {cfg.get('paired_at')}")
    else:
        print("  Status      : [-] NOT PAIRED (run 'floppy-key pair' to create key)")

    # 4. Floppy Disk Credential Check
    print("\n-- 4. Key Credential Verification --")
    if dev and hardware.is_disk_present(dev):
        mp = hardware.ensure_mounted(dev)
        if mp:
            key_data = hardware.read_key_file(mp)
            if key_data:
                print(f"  Disk Key ID : {key_data.get('key_id')}")
                print(f"  Disk User   : {key_data.get('user')}")
                if cfg:
                    volume_id = hardware.get_disk_volume_id(dev, mp)
                    match = crypto.verify_token(key_data.get("token"), key_data.get("key_id"), cfg, volume_id)
                    if match:
                        print("  Match Result: [OK] VALID & MATCHES HOST CONFIG")
                    else:
                        print("  Match Result: [FAIL] MISMATCH (Token does not match host)")
                else:
                    print("  Match Result: [-] Cannot verify (host not paired)")
            else:
                print("  Disk Status : [-] No .floppy-key found on disk.")
        else:
            print("  Disk Status : [!] Cannot mount floppy to inspect key.")
    else:
        print("  Disk Status : [-] No floppy inserted to inspect.")

    # 5. Desktop & Session
    print("\n-- 5. Desktop & Session State --")
    sid = session.get_display_session_id()
    print(f"  Current User: {session.get_current_username()}")
    print(f"  Session ID  : {sid if sid else 'Not found'}")
    locked = session.is_screen_locked()
    print(f"  Screen Saver: {'[LOCKED]' if locked else '[UNLOCKED]'}")

    # 6. Service Status
    print("\n-- 6. Background Service --")
    try:
        res = subprocess.run(
            ["systemctl", "--user", "is-active", "floppy-key.service"],
            capture_output=True,
            text=True,
        )
        svc_state = res.stdout.strip()
        print(f"  systemd unit: floppy-key.service ({svc_state})")
    except Exception:
        print("  systemd unit: Unknown")

    print("\n" + "=" * 55)
    return 0


def cmd_unlock(args) -> int:
    """Manually test waking the screen and unlocking the desktop session."""
    print("[*] Testing desktop unlock pipeline...")
    success = session.unlock_desktop()
    if success:
        print("[+] Screen wake-up and unlock request dispatched successfully.")
        return 0
    else:
        print("[!] Unlock request failed. Check logind and ScreenSaver D-Bus.")
        return 1


def cmd_revoke(args) -> int:
    """Revoke pairing credentials on host and optionally wipe the floppy key."""
    print("[*] Revoking FloppyKey pairing...")
    removed_host = config.revoke_config()
    if removed_host:
        print("[+] Host pairing credentials deleted (~/.config/floppy-key/config.json).")
    else:
        print("[-] Host was not paired.")

    if args.wipe_disk:
        dev = hardware.find_floppy_device()
        if dev and hardware.is_disk_present(dev):
            mp = hardware.ensure_mounted(dev, require_writable=True)
            if mp:
                wiped = hardware.wipe_key_file(mp)
                if wiped:
                    print("[+] Key file securely wiped from floppy disk.")
                else:
                    print("[-] No key file found on floppy to wipe.")
        else:
            print("[-] No floppy disk present to wipe.")

    lockout.reset_lockout()
    print("[+] Revocation complete.")
    return 0


def cmd_reset(args) -> int:
    """Reset session failure count and lockout state."""
    if lockout.is_locked_out() or lockout.get_failed_count() > 0:
        lockout.reset_lockout()
        print("[+] Session lockout and failed attempts reset successfully.")
    else:
        print("[-] No active lockout or failed attempts to reset.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="floppy-key",
        description="FloppyKey v2 - Physical Floppy Disk Desktop Key for Linux",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # pair
    p_pair = subparsers.add_parser("pair", help="Pair an inserted floppy disk")
    p_pair.add_argument("-f", "--force", action="store_true", help="Force overwrite existing pairing")
    p_pair.set_defaults(func=cmd_pair)

    # daemon
    p_daemon = subparsers.add_parser("daemon", help="Run the background unlock daemon")
    p_daemon.add_argument(
        "-i", "--interval", type=float, default=1.0, help="Polling interval in seconds (default: 1.0)"
    )
    p_daemon.add_argument(
        "-t", "--takeover", action="store_true", help="Temporarily stop background service and run in foreground, auto-restarting on exit"
    )
    p_daemon.set_defaults(func=cmd_daemon)

    # status
    p_status = subparsers.add_parser("status", help="Show system and key diagnostics")
    p_status.set_defaults(func=cmd_status)

    # unlock
    p_unlock = subparsers.add_parser("unlock", help="Manually wake and unlock desktop")
    p_unlock.set_defaults(func=cmd_unlock)

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Revoke current pairing credentials")
    p_revoke.add_argument("-w", "--wipe-disk", action="store_true", help="Also wipe key file on floppy disk")
    p_revoke.set_defaults(func=cmd_revoke)

    # reset
    p_reset = subparsers.add_parser("reset", help="Reset failed attempts and session lockout")
    p_reset.set_defaults(func=cmd_reset)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
