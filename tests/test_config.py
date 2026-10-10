import os
from pathlib import Path
import stat
import tempfile
import unittest
from floppy_key import config


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.orig_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self.tmp_dir.name

    def tearDown(self):
        if self.orig_xdg is not None:
            os.environ["XDG_CONFIG_HOME"] = self.orig_xdg
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)
        self.tmp_dir.cleanup()

    def test_save_and_load_config_permissions(self):
        self.assertFalse(config.is_paired())
        payload = {"key_id": "test", "token_hash": "abc"}
        path = config.save_config(payload)

        self.assertTrue(config.is_paired())
        self.assertTrue(path.exists())

        # Check file permissions (0600)
        mode = stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(mode, 0o600)

        # Check directory permissions (0700)
        dir_mode = stat.S_IMODE(config.get_config_dir().stat().st_mode)
        self.assertEqual(dir_mode, 0o700)

        loaded = config.load_config()
        self.assertEqual(loaded, payload)

    def test_corrupt_config_returns_none(self):
        config_path = config.get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("invalid json contents", encoding="utf-8")

        self.assertIsNone(config.load_config())

    def test_revoke_config(self):
        config.save_config({"key_id": "test"})
        self.assertTrue(config.is_paired())
        revoked = config.revoke_config()
        self.assertTrue(revoked)
        self.assertFalse(config.is_paired())
        self.assertFalse(config.revoke_config())

    def test_locked_context(self):
        with config.locked():
            lock_path = config.get_config_dir() / config.LOCK_FILE_NAME
            self.assertTrue(lock_path.exists())


if __name__ == "__main__":
    unittest.main()
