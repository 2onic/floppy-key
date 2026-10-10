import json
from pathlib import Path
import tempfile
import unittest
from floppy_key import hardware


class TestHardware(unittest.TestCase):
    def test_unescape_mount_path(self):
        raw = r"/run/media/user/My\040Disk\011Tab\012Newline\134Slash"
        unescaped = hardware.unescape_mount_path(raw)
        self.assertEqual(unescaped, "/run/media/user/My Disk\tTab\nNewline\\Slash")

    def test_read_write_key_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mp = Path(tmp_dir)
            payload = {"version": 2, "key_id": "k123", "token": "tok456"}

            written_path = hardware.write_key_file(mp, payload)
            self.assertTrue(written_path.exists())

            read_data = hardware.read_key_file(mp)
            self.assertEqual(read_data, payload)

    def test_read_key_file_fallback_to_tmp(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mp = Path(tmp_dir)
            payload = {"version": 2, "key_id": "k123", "token": "tok456"}

            # Simulate interrupted write: only .floppy-key.tmp exists
            tmp_path = mp / hardware.KEY_TMP_FILE_NAME
            tmp_path.write_text(json.dumps(payload), encoding="utf-8")

            read_data = hardware.read_key_file(mp)
            self.assertEqual(read_data, payload)

    def test_read_key_file_corrupt_raises_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mp = Path(tmp_dir)
            key_path = mp / hardware.KEY_FILE_NAME

            # 1. Invalid JSON
            key_path.write_text("invalid json", encoding="utf-8")
            with self.assertRaises(hardware.KeyFileError):
                hardware.read_key_file(mp)

            # 2. JSON is a list, not dict
            key_path.write_text("[]", encoding="utf-8")
            with self.assertRaises(hardware.KeyFileError):
                hardware.read_key_file(mp)

            # 3. Missing or non-ascii fields
            key_path.write_text(json.dumps({"key_id": "test", "token": "non_ascii_é"}), encoding="utf-8")
            with self.assertRaises(hardware.KeyFileError):
                hardware.read_key_file(mp)

    def test_wipe_key_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mp = Path(tmp_dir)
            payload = {"version": 2, "key_id": "k123", "token": "tok456"}
            hardware.write_key_file(mp, payload)

            # Create legacy anchor as well
            anchor = mp / hardware.LEGACY_VOLUME_ANCHOR_FILE
            anchor.write_text("anchor-uuid", encoding="utf-8")

            wiped = hardware.wipe_key_file(mp)
            self.assertTrue(wiped)
            self.assertFalse((mp / hardware.KEY_FILE_NAME).exists())
            self.assertFalse((mp / hardware.KEY_TMP_FILE_NAME).exists())
            self.assertFalse(anchor.exists())


if __name__ == "__main__":
    unittest.main()
