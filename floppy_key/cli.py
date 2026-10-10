"""Command Line Interface for FloppyKey v2.

Provides subcommands:
  pair    - Pair an inserted floppy disk as the desktop unlock key
  daemon  - Run the background media monitor and unlocker daemon
  status  - Diagnose hardware, media, pairing, and session states
  rotate  - Manually rotate the current key token
  unlock  - Test desktop screen wake-up and unlock directly
  revoke  - Invalidate and remove host and disk pairing credentials
  reset   - Reset session failed attempt count and lockout state
"""

import argparse
import fcntl
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Optional

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


def perform_roll(host_cfg: dict, mount_point: Path) -> dict:
    """Perform dynamic token rotation (Two-Phase Commit).

    1. Prepare next token and staged host config (with pending)
    2. Save host config with pending
    3. Write key file to floppy
    4. Commit roll on host config and save
    5. Notify user that key has been updated and disk is safe to remove
    """
    next_payload, staged_cfg = crypto.prepare_next_token(host_cfg)
    config.save_config(staged_cfg)
    try:
        hardware.write_key_file(mount_point, next_payload)
    except hardware.WriteProtectedError as e:
        staged_cfg.pop("pending", None)
        config.save_config(staged_cfg)
        raise
    except Exception as e:
        logger.warning("Could not write dynamic token to disk (%s); retaining pending transaction.", e)
        # Retain pending in host config so future insertion can recover
        return staged_cfg

    committed_cfg = crypto.commit_roll(staged_cfg)
    config.save_config(committed_cfg)
    logger.info("Successfully rolled dynamic token (counter: #%d)", committed_cfg.get("counter", 1))
    security.notify("FloppyKey", "Floppy key updated. Safe to remove.")
    return committed_cfg


def cmd_pair(args) -> int:
    """Pair an inserted floppy disk with the current user account."""
    username = session.get_current_username()
    mode_str = "Dynamic Rolling" if args.rolling else "Static"
    print(f"[*] Pairing floppy key for user: {username} (Mode: {mode_str})")

    dev = hardware.find_floppy_device()
    if not dev:
        print("[!] Error: No USB floppy drive found in system.")
        return 1

    print(f"[*] Found floppy drive: {dev.name} ({dev.vendor} {dev.model})")

    if not hardware.is_disk_present(dev):
        print("[!] Error: No floppy disk inserted. Please insert a 3.5\" floppy disk into the drive.")
        return 1

    print("[*] Physical floppy disk detected (1.44MB).")

    # Prompt user BEFORE taking config.locked() to prevent blocking daemon
    if config.is_paired() and not args.force:
        print("[!] Host is already paired with a key.")
        resp = input("[?] Overwrite existing pairing? [y/N]: ").strip().lower()
        if resp not in ("y", "yes"):
            print("[-] Pairing aborted.")
            return 0

    with config.locked():
        mount_point = hardware.ensure_mounted(dev, require_writable=True)
        if not mount_point:
            print("[!] Error: Could not mount floppy disk via udisks.")
            return 1

        print(f"[*] Floppy disk mounted at: {mount_point}")
        print("[*] Generating 256-bit high-entropy secret token & SHA-256 salt...")
        floppy_payload, host_payload = crypto.generate_key_pair(username, rolling=args.rolling)

        # Write key to floppy
        try:
            key_file = hardware.write_key_file(mount_point, floppy_payload)
            print(f"[+] Floppy key written to: {key_file}")
        except hardware.WriteProtectedError as e:
            print(f"[!] Write failed: {e}")
            return 1
        except Exception as e:
            print(f"[!] Error writing key to floppy disk: {e}")
            return 1

        # Save host config
        cfg_file = config.save_config(host_payload)
        print(f"[+] Host pairing saved to: {cfg_file}")
        lockout.reset_lockout()

    print("\n" + "=" * 55)
    print(" Pairing Complete! Floppy is now your physical key.")
    print(f"    Key ID  : {host_payload['key_id']}")
    print(f"    User    : {username}")
    print(f"    Mode    : {mode_str}")
    print(f"    Counter : #{host_payload.get('counter', 1)}")
    if not args.rolling:
        print("    Tip     : You can now engage the write-protect tab on the disk.")
    print("=" * 55 + "\n")
    return 0


def cmd_rotate(args) -> int:
    """Manually rotate the current key token on the inserted floppy."""
    dev = hardware.find_floppy_device()
    if not dev:
        print("[!] Error: No USB floppy drive found in system.")
        return 1

    if not hardware.is_disk_present(dev):
        print("[!] Error: No floppy disk inserted.")
        return 1

    with config.locked():
        host_cfg = config.load_config()
        if not host_cfg:
            print("[!] Host is not paired. Run 'floppy-key pair' first.")
            return 1

        if crypto.is_compromised(host_cfg):
            print("[!] Current pairing is COMPROMISED. Token rotation disabled. Run 'floppy-key pair' to re-pair.")
            return 1

        mount_point = hardware.ensure_mounted(dev, require_writable=True)
        if not mount_point:
            print("[!] Error: Could not mount floppy disk.")
            return 1

        try:
            key_data = hardware.read_key_file(mount_point)
        except hardware.KeyFileError as e:
            print(f"[!] Error reading key file: {e}")
            return 1

        if not key_data:
            print("[!] No key file found on inserted floppy disk.")
            return 1

        status, detail = crypto.verify_token_state(
            token=key_data.get("token"),
            key_id=key_data.get("key_id"),
            host_config=host_cfg,
        )
        if status == crypto.TokenVerifyStatus.CLONE_DETECTED:
            host_cfg = crypto.mark_compromised(host_cfg, detail)
            config.save_config(host_cfg)
            print(f"[!] CLONE DETECTED: {detail}. Pairing invalidated!")
            return 1
        elif status not in (crypto.TokenVerifyStatus.VALID, crypto.TokenVerifyStatus.PENDING_COMMIT):
            print(f"[!] Floppy key verification failed: {detail}")
            return 1

        if status == crypto.TokenVerifyStatus.PENDING_COMMIT:
            host_cfg = crypto.commit_roll(host_cfg)
            config.save_config(host_cfg)

        print("[*] Rotating key token...")
        try:
            updated_cfg = perform_roll(host_cfg, mount_point)
        except hardware.WriteProtectedError as e:
            print(f"[!] Error: Floppy is write-protected (tab locked). Cannot rotate key: {e}")
            return 1

        if updated_cfg.get("pending"):
            print("[!] Warning: Write to floppy failed or was interrupted. Pending transaction retained.")
            return 1

    print(f"[+] Key rotated successfully! Current counter: #{updated_cfg.get('counter', 1)}")
    return 0


def acquire_daemon_lock():
    """Acquire exclusive flock to prevent multiple daemon instances from running concurrently."""
    lock_dir = lockout.get_runtime_dir()
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_file = lock_dir / "daemon.lock"
    f = open(lock_file, "a")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except (BlockingIOError, OSError):
        f.close()
        return None


def handle_insertion(dev: hardware.FloppyDevice) -> bool:
    """Handle a newly inserted floppy disk.

    Returns True if the insertion was processed (success or terminal failure),
    or False if a transient hardware/mount error occurred and retry is appropriate.
    """
    with config.locked():
        host_cfg = config.load_config()
        if not host_cfg:
            logger.info("Floppy disk inserted, but host is not paired. Ignoring.")
            return True

        if crypto.is_compromised(host_cfg):
            logger.warning("FloppyKey pairing is COMPROMISED. Unlock disabled. Run 'floppy-key pair' to re-pair.")
            return True

        screen_locked = session.is_screen_locked()
        if screen_locked and lockout.is_locked_out():
            logger.warning("Floppy unlock disabled due to previous failed attempts. Password unlock required.")
            return True

        need_write = screen_locked and crypto.is_rolling(host_cfg)
        mount_point = hardware.ensure_mounted(
            dev,
            require_writable=need_write,
            read_only=(screen_locked and not need_write),
        )
        if not mount_point:
            logger.warning("Floppy disk detected but could not be mounted (drive motor may still be spinning up).")
            return False

        try:
            key_data = hardware.read_key_file(mount_point)
        except hardware.KeyFileError as e:
            logger.warning("Corrupt or invalid key file on floppy disk: %s", e)
            if screen_locked:
                lockout.record_failure()
            return True

        if not key_data:
            logger.info("No floppy-key credential found on inserted disk.")
            return True

        token = key_data.get("token")
        key_id = key_data.get("key_id")
        verify_status, err_detail = crypto.verify_token_state(
            token=token,
            key_id=key_id,
            host_config=host_cfg,
        )

        if verify_status == crypto.TokenVerifyStatus.CLONE_DETECTED:
            logger.critical("SECURITY ALERT: Retired token presented! Possible clone or replay: %s", err_detail)
            host_cfg = crypto.mark_compromised(host_cfg, err_detail)
            config.save_config(host_cfg)
            security.send_security_alert(
                "FloppyKey Security Alert",
                f"CRITICAL: Key pairing invalidated due to clone/replay detection! ({err_detail})"
            )
            lockout.record_failure()
            return True

        if verify_status == crypto.TokenVerifyStatus.COMPROMISED:
            logger.warning("FloppyKey pairing is compromised. Unlock disabled.")
            return True

        if verify_status == crypto.TokenVerifyStatus.INVALID:
            logger.warning("Floppy key verification failed: %s", err_detail)
            if screen_locked:
                lockout.record_failure()
            return True

        # Verification succeeded: status is VALID or PENDING_COMMIT
        if verify_status == crypto.TokenVerifyStatus.PENDING_COMMIT:
            host_cfg = crypto.commit_roll(host_cfg)
            config.save_config(host_cfg)
            logger.info(
                "Finalized pending transaction from previous session (counter: #%d)",
                host_cfg.get("counter", 1),
            )

        if not screen_locked:
            logger.info(
                "Key verified (counter: #%s), but screen is currently unlocked. No action taken.",
                key_data.get("counter", 1),
            )
            return True

        # Screen is locked: unlock desktop first
        lockout.record_success()
        logger.info("Key verified! Unlocking desktop session...")
        session.unlock_desktop()

        if crypto.is_rolling(host_cfg):
            try:
                perform_roll(host_cfg, mount_point)
            except hardware.WriteProtectedError as e:
                logger.warning("Floppy is physically write-protected; token rolling deferred: %s", e)

        return True


def cmd_daemon(args) -> int:
    """Run the background media monitoring and auto-unlock loop."""
    lock_handle = acquire_daemon_lock()
    service_taken_over = False

    def restore_service():
        nonlocal service_taken_over
        if service_taken_over:
            logger.info("Restoring background floppy-key.service...")
            subprocess.run(["systemctl", "--user", "start", "floppy-key.service"], check=False)
            service_taken_over = False

    def sig_handler(signum, frame):
        restore_service()
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGHUP, sig_handler)

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

    cached_dev: Optional[hardware.FloppyDevice] = None
    last_present: Optional[bool] = None
    unlocked_for_current_insertion = False
    mount_retries = 0
    last_screen_locked = session.is_screen_locked()
    alert_notified_for_lockout = False

    try:
        while True:
            try:
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

                # Device discovery with caching
                if cached_dev and not hardware.device_still_attached(cached_dev):
                    logger.warning("Floppy drive disconnected.")
                    cached_dev = None
                    last_present = None

                if not cached_dev:
                    cached_dev = hardware.find_floppy_device()
                    if not cached_dev:
                        time.sleep(interval * 2)
                        continue

                current_present = hardware.is_disk_present(cached_dev)

                # Ejected transition (size == 0)
                if not current_present:
                    if last_present is True or last_present is None:
                        if last_present is True:
                            logger.info("Floppy disk physically ejected.")
                        hardware.force_unmount_if_stale(cached_dev)
                        unlocked_for_current_insertion = False
                        mount_retries = 0
                    last_present = False

                # Inserted transition (size == 2880)
                else:
                    if last_present is False or last_present is None:
                        logger.info("Floppy disk physically inserted into %s", cached_dev.name)
                        last_present = True
                        unlocked_for_current_insertion = False
                        mount_retries = 0

                    if not unlocked_for_current_insertion:
                        processed = handle_insertion(cached_dev)
                        if processed:
                            unlocked_for_current_insertion = True
                        else:
                            mount_retries += 1
                            if mount_retries >= 3:
                                logger.warning("Could not access disk after 3 attempts; pausing retries for this insertion.")
                                unlocked_for_current_insertion = True

            except Exception as loop_err:
                logger.error("Unexpected error in daemon monitoring loop: %s", loop_err, exc_info=True)

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
        restore_service()


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
        is_comp = crypto.is_compromised(cfg)
        status_label = "[!] COMPROMISED" if is_comp else "[OK] PAIRED"
        mode_label = "Dynamic Rolling" if crypto.is_rolling(cfg) else "Static"
        print(f"  Status      : {status_label}")
        print(f"  Config Path : {config.get_config_path()}")
        print(f"  Key ID      : {cfg.get('key_id')}")
        print(f"  User        : {cfg.get('user')}")
        print(f"  Mode        : {mode_label}")
        print(f"  Counter     : #{cfg.get('counter', 1)}")
        if is_comp:
            comp_info = cfg.get("compromised", {})
            print(f"  Compromised : {comp_info.get('detail')} at {comp_info.get('at')}")
            print("  Action      : Re-pairing required! Run 'floppy-key pair'.")
        retired_count = len(cfg.get("retired") or [])
        if retired_count > 0:
            print(f"  Retired Keys: {retired_count} historical tokens tracked")
        print(f"  Paired At   : {cfg.get('paired_at')}")
    else:
        print("  Status      : [-] NOT PAIRED (run 'floppy-key pair' to create key)")

    # 4. Floppy Disk Credential Check
    print("\n-- 4. Key Credential Verification --")
    if dev and hardware.is_disk_present(dev):
        was_mounted = hardware.get_current_mount_point(dev) is not None
        mp = hardware.ensure_mounted(dev, read_only=True)
        try:
            if mp:
                try:
                    key_data = hardware.read_key_file(mp)
                except hardware.KeyFileError as kfe:
                    key_data = None
                    print(f"  Disk Status : [!] Key file corrupt: {kfe}")

                if key_data:
                    print(f"  Disk Key ID : {key_data.get('key_id')}")
                    print(f"  Disk User   : {key_data.get('user')}")
                    if cfg:
                        status, detail = crypto.verify_token_state(
                            token=key_data.get("token"),
                            key_id=key_data.get("key_id"),
                            host_config=cfg,
                        )
                        disk_counter = key_data.get("counter", 1)
                        if status == crypto.TokenVerifyStatus.VALID:
                            print(f"  Match Result: [OK] VALID (Counter #{disk_counter})")
                        elif status == crypto.TokenVerifyStatus.PENDING_COMMIT:
                            print(f"  Match Result: [OK] VALID (Pending commit #{disk_counter})")
                        elif status == crypto.TokenVerifyStatus.CLONE_DETECTED:
                            print(f"  Match Result: [!] CRITICAL: CLONED DISK / RETIRED TOKEN DETECTED ({detail})")
                        elif status == crypto.TokenVerifyStatus.COMPROMISED:
                            print(f"  Match Result: [!] HOST COMPROMISED ({detail})")
                        else:
                            print(f"  Match Result: [FAIL] MISMATCH ({detail})")
                    else:
                        print("  Match Result: [-] Cannot verify (host not paired)")
                elif not mp.joinpath(hardware.KEY_FILE_NAME).exists():
                    print("  Disk Status : [-] No .floppy-key found on disk.")
            else:
                print("  Disk Status : [!] Cannot mount floppy to inspect key.")
        finally:
            if not was_mounted and mp:
                hardware.unmount_device(dev)
    else:
        print("  Disk Status : [-] No floppy inserted to inspect.")

    # 5. Desktop & Session
    print("\n-- 5. Desktop & Session State --")
    sid = session.get_display_session_id()
    print(f"  Current User: {session.get_current_username()}")
    print(f"  Session ID  : {sid if sid else 'Not found'}")
    locked = session.is_screen_locked()
    print(f"  Screen Saver: {'[LOCKED]' if locked else '[UNLOCKED]'}")
    lockout_state = lockout.is_locked_out()
    fail_count = lockout.get_failed_count()
    if lockout_state:
        print(f"  Lockout     : [LOCKED OUT] ({fail_count} failed attempts)")
    elif fail_count > 0:
        print(f"  Fail Count  : {fail_count} consecutive failure(s)")

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
    wipe_failed = False
    with config.locked():
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
                    try:
                        wiped = hardware.wipe_key_file(mp)
                        if wiped:
                            print("[+] Key file securely wiped from floppy disk.")
                        else:
                            print("[-] No key file found on floppy to wipe.")
                    except hardware.WriteProtectedError as e:
                        print(f"[!] Error: Floppy disk is write-protected (tab locked). Cannot wipe key file: {e}")
                        wipe_failed = True
                    except OSError as e:
                        print(f"[!] Error wiping key file from floppy disk: {e}")
                        wipe_failed = True
                else:
                    print("[!] Error: Could not mount floppy disk to wipe key file.")
                    wipe_failed = True
            else:
                print("[-] No floppy disk present to wipe.")
                wipe_failed = True

        lockout.reset_lockout()
    if wipe_failed:
        print("[!] Revocation partially complete (floppy wipe failed).")
        return 1
    print("[+] Revocation complete.")
    return 0


def cmd_reset(args) -> int:
    """Reset session failure count and lockout state."""
    host_cfg = config.load_config()
    if host_cfg and crypto.is_compromised(host_cfg):
        print("[!] Warning: Host pairing is COMPROMISED. Session lockout cleared, but floppy unlock remains disabled until re-paired ('floppy-key pair').")

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
    p_pair.add_argument(
        "-r", "--rolling", action="store_true", help="Enable dynamic rolling tokens (default: static key)"
    )
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

    # rotate
    p_rotate = subparsers.add_parser("rotate", help="Manually rotate key token on floppy and host")
    p_rotate.set_defaults(func=cmd_rotate)

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
