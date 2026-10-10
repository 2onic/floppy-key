import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from floppy_key import cli
from floppy_key import config
from floppy_key import crypto
from floppy_key import hardware
from floppy_key import lockout
from floppy_key import session


class TestCliFlow(unittest.TestCase):
    def setUp(self):
        self.tmp_cfg_dir = tempfile.TemporaryDirectory()
        self.tmp_run_dir = tempfile.TemporaryDirectory()
        self.tmp_floppy_dir = tempfile.TemporaryDirectory()

        self.orig_cfg = os.environ.get("XDG_CONFIG_HOME")
        self.orig_run = os.environ.get("XDG_RUNTIME_DIR")

        os.environ["XDG_CONFIG_HOME"] = self.tmp_cfg_dir.name
        os.environ["XDG_RUNTIME_DIR"] = self.tmp_run_dir.name

        self.mount_point = Path(self.tmp_floppy_dir.name)
        self.mock_dev = hardware.FloppyDevice(
            name="sda_mock",
            dev_path="/dev/sda_mock",
            sysfs_path=Path("/sys/block/mock"),
            vendor="Mock",
            model="Drive",
        )

    def tearDown(self):
        if self.orig_cfg is not None:
            os.environ["XDG_CONFIG_HOME"] = self.orig_cfg
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)

        if self.orig_run is not None:
            os.environ["XDG_RUNTIME_DIR"] = self.orig_run
        else:
            os.environ.pop("XDG_RUNTIME_DIR", None)

        self.tmp_cfg_dir.cleanup()
        self.tmp_run_dir.cleanup()
        self.tmp_floppy_dir.cleanup()

    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.session.is_screen_locked")
    @patch("floppy_key.session.unlock_desktop")
    def test_screen_unlocked_verifies_without_unlock_or_roll(
        self, mock_unlock, mock_is_locked, mock_mounted
    ):
        mock_mounted.return_value = self.mount_point
        mock_is_locked.return_value = False  # Screen is NOT locked

        # Setup paired host and floppy in rolling mode
        floppy, host = crypto.generate_key_pair("testuser", rolling=True)
        config.save_config(host)
        hardware.write_key_file(self.mount_point, floppy)

        cli.handle_insertion(self.mock_dev)

        # Unlock should NOT be called
        mock_unlock.assert_not_called()
        # No failure counted
        self.assertEqual(lockout.get_failed_count(), 0)
        # Token on disk did not change (no roll performed while screen is unlocked)
        disk_data = hardware.read_key_file(self.mount_point)
        self.assertEqual(disk_data["token"], floppy["token"])
        self.assertEqual(disk_data["counter"], 1)

    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.session.is_screen_locked")
    @patch("floppy_key.session.unlock_desktop")
    def test_screen_locked_static_key_unlocks_without_roll(
        self, mock_unlock, mock_is_locked, mock_mounted
    ):
        mock_mounted.return_value = self.mount_point
        mock_is_locked.return_value = True  # Screen is locked

        floppy, host = crypto.generate_key_pair("testuser", rolling=False)
        config.save_config(host)
        hardware.write_key_file(self.mount_point, floppy)

        cli.handle_insertion(self.mock_dev)

        # Unlock SHOULD be called
        mock_unlock.assert_called_once()
        self.assertEqual(lockout.get_failed_count(), 0)
        # Token did not roll
        disk_data = hardware.read_key_file(self.mount_point)
        self.assertEqual(disk_data["token"], floppy["token"])
        self.assertEqual(disk_data["counter"], 1)

    @patch("floppy_key.security.notify")
    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.session.is_screen_locked")
    @patch("floppy_key.session.unlock_desktop")
    def test_screen_locked_rolling_key_unlocks_and_rolls(
        self, mock_unlock, mock_is_locked, mock_mounted, mock_notify
    ):
        mock_mounted.return_value = self.mount_point
        mock_is_locked.return_value = True  # Screen is locked

        floppy, host = crypto.generate_key_pair("testuser", rolling=True)
        config.save_config(host)
        hardware.write_key_file(self.mount_point, floppy)

        cli.handle_insertion(self.mock_dev)

        # Unlock was called first
        mock_unlock.assert_called_once()
        mock_notify.assert_called_once()

        # Token was rolled on disk and on host
        disk_data = hardware.read_key_file(self.mount_point)
        self.assertNotEqual(disk_data["token"], floppy["token"])
        self.assertEqual(disk_data["counter"], 2)

        updated_host = config.load_config()
        self.assertEqual(updated_host["counter"], 2)
        self.assertIsNone(updated_host["pending"])
        self.assertEqual(len(updated_host["retired"]), 1)

    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.session.is_screen_locked")
    def test_missing_or_non_paired_does_not_count_failure(
        self, mock_is_locked, mock_mounted
    ):
        mock_mounted.return_value = self.mount_point
        mock_is_locked.return_value = True

        # 1. No host pairing -> no failure
        cli.handle_insertion(self.mock_dev)
        self.assertEqual(lockout.get_failed_count(), 0)

        # 2. Host paired, but no key file on disk (e.g. data floppy) -> no failure
        _, host = crypto.generate_key_pair("testuser")
        config.save_config(host)

        cli.handle_insertion(self.mock_dev)
        self.assertEqual(lockout.get_failed_count(), 0)

    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.session.is_screen_locked")
    def test_corrupt_key_or_invalid_token_counts_failure_when_locked(
        self, mock_is_locked, mock_mounted
    ):
        mock_mounted.return_value = self.mount_point
        mock_is_locked.return_value = True

        _, host = crypto.generate_key_pair("testuser")
        config.save_config(host)

        # 1. Corrupt key file
        (self.mount_point / hardware.KEY_FILE_NAME).write_text("corrupted", encoding="utf-8")
        cli.handle_insertion(self.mock_dev)
        self.assertEqual(lockout.get_failed_count(), 1)

        # 2. Valid JSON but wrong token
        hardware.write_key_file(self.mount_point, {"key_id": host["key_id"], "token": "wrong-token"})
        cli.handle_insertion(self.mock_dev)
        self.assertEqual(lockout.get_failed_count(), 2)

    @patch("floppy_key.security.send_security_alert")
    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.session.is_screen_locked")
    def test_clone_detection_marks_compromised_permanently(
        self, mock_is_locked, mock_mounted, mock_alert
    ):
        mock_mounted.return_value = self.mount_point
        mock_is_locked.return_value = True

        floppy1, host = crypto.generate_key_pair("testuser", rolling=True)
        config.save_config(host)
        # Roll token once so floppy1 becomes retired
        cli.perform_roll(host, self.mount_point)

        # Now insert floppy1 (retired key)
        hardware.write_key_file(self.mount_point, floppy1)
        cli.handle_insertion(self.mock_dev)

        # Alert sent
        mock_alert.assert_called_once()
        self.assertEqual(lockout.get_failed_count(), 1)

        # Host marked as compromised and secrets wiped
        updated_host = config.load_config()
        self.assertTrue(crypto.is_compromised(updated_host))
        self.assertEqual(updated_host["salt"], "")

        # Subsequent attempts are permanently rejected
        cli.handle_insertion(self.mock_dev)
        # Failure count not incremented for compromised rejected attempts
        self.assertEqual(lockout.get_failed_count(), 1)

    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.session.is_screen_locked")
    def test_transient_mount_failure_returns_false(self, mock_is_locked, mock_mounted):
        mock_mounted.return_value = None  # Mounting failed transiently
        mock_is_locked.return_value = True

        _, host = crypto.generate_key_pair("testuser")
        config.save_config(host)

        processed = cli.handle_insertion(self.mock_dev)
        self.assertFalse(processed)
        # Does NOT count as a security failure
        self.assertEqual(lockout.get_failed_count(), 0)

    @patch("floppy_key.hardware.find_floppy_device")
    @patch("floppy_key.hardware.is_disk_present")
    @patch("floppy_key.hardware.ensure_mounted")
    @patch("floppy_key.hardware.write_key_file")
    def test_cmd_rotate_write_protected_returns_error(
        self, mock_write, mock_mounted, mock_present, mock_find
    ):
        mock_find.return_value = self.mock_dev
        mock_present.return_value = True
        mock_mounted.return_value = self.mount_point
        floppy, host = crypto.generate_key_pair("testuser", rolling=False)
        config.save_config(host)
        (self.mount_point / hardware.KEY_FILE_NAME).write_text(json.dumps(floppy), encoding="utf-8")
        mock_write.side_effect = hardware.WriteProtectedError("Disk is read-only")

        args = MagicMock()
        ret = cli.cmd_rotate(args)
        self.assertEqual(ret, 1)

        # Config was not modified or left in pending
        current_cfg = config.load_config()
        self.assertEqual(current_cfg["counter"], 1)
        self.assertIsNone(current_cfg.get("pending"))


if __name__ == "__main__":
    unittest.main()
