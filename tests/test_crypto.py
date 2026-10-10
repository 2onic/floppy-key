import unittest
from floppy_key import crypto


class TestCrypto(unittest.TestCase):
    def test_generate_key_pair_static_by_default(self):
        floppy, host = crypto.generate_key_pair("alice")
        self.assertFalse(host.get("rolling"))
        self.assertFalse(crypto.is_rolling(host))
        self.assertEqual(floppy["counter"], 1)
        self.assertEqual(host["counter"], 1)
        self.assertEqual(floppy["user"], "alice")
        self.assertEqual(host["user"], "alice")

    def test_generate_key_pair_rolling(self):
        floppy, host = crypto.generate_key_pair("bob", rolling=True)
        self.assertTrue(host.get("rolling"))
        self.assertTrue(crypto.is_rolling(host))

    def test_legacy_config_is_static(self):
        legacy = {
            "version": 2,
            "key_id": "test-id",
            "salt": "abc",
            "hash": "def",
        }
        self.assertFalse(crypto.is_rolling(legacy))

    def test_verify_valid_token(self):
        floppy, host = crypto.generate_key_pair("alice")
        status, detail = crypto.verify_token_state(floppy["token"], floppy["key_id"], host)
        self.assertEqual(status, crypto.TokenVerifyStatus.VALID)
        self.assertIsNone(detail)
        self.assertTrue(crypto.verify_token(floppy["token"], floppy["key_id"], host))

    def test_verify_malformed_input_no_crash(self):
        floppy, host = crypto.generate_key_pair("alice")
        # Non-ascii
        status, _ = crypto.verify_token_state("töken", floppy["key_id"], host)
        self.assertEqual(status, crypto.TokenVerifyStatus.INVALID)
        status, _ = crypto.verify_token_state(floppy["token"], "kéy-id", host)
        self.assertEqual(status, crypto.TokenVerifyStatus.INVALID)
        # Numbers
        status, _ = crypto.verify_token_state(12345, floppy["key_id"], host)
        self.assertEqual(status, crypto.TokenVerifyStatus.INVALID)
        status, _ = crypto.verify_token_state(floppy["token"], 67890, host)
        self.assertEqual(status, crypto.TokenVerifyStatus.INVALID)
        # None / Empty
        status, _ = crypto.verify_token_state(None, None, host)
        self.assertEqual(status, crypto.TokenVerifyStatus.INVALID)
        status, _ = crypto.verify_token_state("", "", host)
        self.assertEqual(status, crypto.TokenVerifyStatus.INVALID)
        status, _ = crypto.verify_token_state("valid", "id", None)
        self.assertEqual(status, crypto.TokenVerifyStatus.INVALID)

    def test_rolling_two_phase_commit_and_clone_detection(self):
        floppy1, host1 = crypto.generate_key_pair("alice", rolling=True)

        # 1. Prepare roll
        floppy2, staged_host = crypto.prepare_next_token(host1)
        self.assertIsNotNone(staged_host["pending"])
        self.assertEqual(floppy2["counter"], 2)

        # Floppy 2 before commit matches PENDING_COMMIT
        status, _ = crypto.verify_token_state(floppy2["token"], floppy2["key_id"], staged_host)
        self.assertEqual(status, crypto.TokenVerifyStatus.PENDING_COMMIT)

        # Floppy 1 before commit still matches VALID
        status, _ = crypto.verify_token_state(floppy1["token"], floppy1["key_id"], staged_host)
        self.assertEqual(status, crypto.TokenVerifyStatus.VALID)

        # 2. Commit roll
        committed_host = crypto.commit_roll(staged_host)
        self.assertIsNone(committed_host["pending"])
        self.assertEqual(committed_host["counter"], 2)
        self.assertEqual(len(committed_host["retired"]), 1)

        # Floppy 2 is now VALID
        status, _ = crypto.verify_token_state(floppy2["token"], floppy2["key_id"], committed_host)
        self.assertEqual(status, crypto.TokenVerifyStatus.VALID)

        # Floppy 1 (retired) is now detected as CLONE_DETECTED
        status, detail = crypto.verify_token_state(floppy1["token"], floppy1["key_id"], committed_host)
        self.assertEqual(status, crypto.TokenVerifyStatus.CLONE_DETECTED)
        self.assertIn("#1", detail)

    def test_compromised_state_wipe(self):
        floppy, host = crypto.generate_key_pair("alice", rolling=True)
        compromised_host = crypto.mark_compromised(host, "Replay attack detected")

        self.assertTrue(crypto.is_compromised(compromised_host))
        self.assertEqual(compromised_host["salt"], "")
        self.assertEqual(compromised_host["hash"], "")
        self.assertIsNone(compromised_host["pending"])

        # Token verification fails permanently as COMPROMISED
        status, detail = crypto.verify_token_state(floppy["token"], floppy["key_id"], compromised_host)
        self.assertEqual(status, crypto.TokenVerifyStatus.COMPROMISED)
        self.assertIn("re-pair required", detail)

    def test_legacy_volume_id_compatibility(self):
        # Emulate old config generated with volume_id
        key_id = "test-id"
        token = "secret-token"
        salt = "salt123"
        volume_id = "vol-456"
        machine_id = crypto.get_machine_id()
        h = crypto.compute_token_hash(token, salt, machine_id, volume_id)

        legacy_host = {
            "key_id": key_id,
            "machine_id": machine_id,
            "volume_id": volume_id,
            "salt": salt,
            "hash": h,
            "counter": 1,
        }

        # Verification succeeds even though we don't pass volume_id
        status, _ = crypto.verify_token_state(token, key_id, legacy_host)
        self.assertEqual(status, crypto.TokenVerifyStatus.VALID)


if __name__ == "__main__":
    unittest.main()
