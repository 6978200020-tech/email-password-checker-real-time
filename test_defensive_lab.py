import unittest

from defensive_lab import build_lab_report, make_synthetic_records


class DefensiveLabTests(unittest.TestCase):
    def test_fixture_generation_is_bounded_and_metadata_only(self):
        records = make_synthetic_records(3)
        self.assertEqual(len(records), 3)
        self.assertTrue(all(user.startswith("lab-user-") for user, _ in records))
        self.assertTrue(all(len(value) == 64 for _, value in records))

    def test_report_is_explicitly_offline(self):
        report = build_lab_report(1)
        self.assertEqual(report["mode"], "offline-synthetic")
        self.assertIn("no password recovery", report["warning"].lower())


if __name__ == "__main__":
    unittest.main()
