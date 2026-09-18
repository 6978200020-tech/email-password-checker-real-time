import unittest

from hash_audit import audit_records, classify_hash


class HashAuditTests(unittest.TestCase):
    def test_classifies_safe_and_legacy_formats(self):
        self.assertEqual(classify_hash("$2b$12$" + "a" * 53)["algorithm"], "bcrypt")
        self.assertEqual(classify_hash("a" * 32)["risk"], "high")

    def test_unknown_and_missing_hashes_are_flagged(self):
        self.assertEqual(classify_hash("")["risk"], "critical")
        self.assertEqual(classify_hash("not-a-hash")["algorithm"], "unknown")

    def test_reuse_is_reported_without_recovering_password(self):
        rows = audit_records([("one", "a" * 32), ("two", "a" * 32)])
        self.assertTrue(all(row["reused_hash"] for row in rows))
        self.assertNotIn("password", rows[0])


if __name__ == "__main__":
    unittest.main()
