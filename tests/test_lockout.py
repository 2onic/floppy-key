import os
import tempfile
import unittest
from floppy_key import lockout


class TestLockout(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.orig_runtime = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = self.tmp_dir.name

    def tearDown(self):
        if self.orig_runtime is not None:
            os.environ["XDG_RUNTIME_DIR"] = self.orig_runtime
        else:
            os.environ.pop("XDG_RUNTIME_DIR", None)
        self.tmp_dir.cleanup()

    def test_record_failures_and_lockout(self):
        self.assertEqual(lockout.get_failed_count(), 0)
        self.assertFalse(lockout.is_locked_out())

        # Attempt 1
        locked = lockout.record_failure()
        self.assertFalse(locked)
        self.assertEqual(lockout.get_failed_count(), 1)

        # Attempt 2
        locked = lockout.record_failure()
        self.assertFalse(locked)
        self.assertEqual(lockout.get_failed_count(), 2)

        # Attempt 3 -> Lockout
        locked = lockout.record_failure()
        self.assertTrue(locked)
        self.assertTrue(lockout.is_locked_out())
        self.assertEqual(lockout.get_failed_count(), 3)

        # Subsequent attempts capped at MAX_FAILED_ATTEMPTS
        locked = lockout.record_failure()
        self.assertTrue(locked)
        self.assertEqual(lockout.get_failed_count(), 3)

    def test_record_success_clears_counter(self):
        lockout.record_failure()
        self.assertEqual(lockout.get_failed_count(), 1)

        lockout.record_success()
        self.assertEqual(lockout.get_failed_count(), 0)

    def test_record_success_does_not_clear_lockout(self):
        # Once locked out, record_success doesn't clear lockout
        for _ in range(lockout.MAX_FAILED_ATTEMPTS):
            lockout.record_failure()
        self.assertTrue(lockout.is_locked_out())

        lockout.record_success()
        self.assertTrue(lockout.is_locked_out())

    def test_reset_lockout(self):
        for _ in range(lockout.MAX_FAILED_ATTEMPTS):
            lockout.record_failure()
        self.assertTrue(lockout.is_locked_out())

        lockout.reset_lockout()
        self.assertFalse(lockout.is_locked_out())
        self.assertEqual(lockout.get_failed_count(), 0)

    def test_corrupted_state_file_resilience(self):
        lockout_file = lockout.get_lockout_file()
        lockout_file.parent.mkdir(parents=True, exist_ok=True)
        lockout_file.write_text("corrupted json!", encoding="utf-8")

        self.assertFalse(lockout.is_locked_out())
        self.assertEqual(lockout.get_failed_count(), 0)
        # Still records safely
        lockout.record_failure()
        self.assertEqual(lockout.get_failed_count(), 1)


if __name__ == "__main__":
    unittest.main()
