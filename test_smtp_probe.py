"""Fast, network-free regression tests for the safe probe helpers."""
import unittest
from unittest import mock

import smtp_probe


class ProbeHelperTests(unittest.TestCase):
    def test_normalize_email_and_domain(self):
        self.assertEqual(smtp_probe.normalize_domain(" User@Gmail.com. "), "gmail.com")
        self.assertEqual(smtp_probe.normalize_domain("https://Example.com/path"), "example.com")
        self.assertEqual(smtp_probe.normalize_domain("not a domain"), "")

    def test_email_report_never_claims_account_verification(self):
        parsed = smtp_probe.split_email_address("User@gmail.com")
        self.assertEqual(parsed["domain"], "gmail.com")
        self.assertTrue(parsed["valid"])
        report = smtp_probe.build_email_report("not-an-email", probe_domain_result=False)
        self.assertFalse(report["valid_email_syntax"])
        self.assertEqual(report["account_verification"], "not_performed")
        self.assertEqual(report["credential_check"], "not_performed")

    def test_email_report_classifies_public_google_infrastructure(self):
        domain_result = {
            "status": "active",
            "mail_provider": "Google Workspace",
            "signals": {"mail_exchange_present": True},
        }
        with mock.patch("smtp_probe.probe_domain", return_value=domain_result):
            report = smtp_probe.build_email_report("user@company.example")
        self.assertEqual(report["mail_provider"], "Google Workspace")
        self.assertIn("Google-hosted", report["provider_scope"])
        self.assertEqual(report["account_verification"], "not_performed")

    def test_provider_detection_uses_mx_only(self):
        self.assertEqual(
            smtp_probe.identify_mail_provider(
                ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
            ),
            "Google Workspace",
        )
        self.assertEqual(
            smtp_probe.identify_mail_provider(["example.mail.protection.outlook.com"]),
            "Microsoft 365",
        )
        self.assertEqual(
            smtp_probe.identify_mail_provider(["mx.example.org"]),
            "Other/Custom",
        )

    def test_empty_mx_does_not_claim_provider(self):
        self.assertEqual(smtp_probe.identify_mail_provider([]), "Other/Custom")

    def test_gmail_report_adds_public_alias_and_scope_signals(self):
        domain_result = {
            "status": "active",
            "mail_provider": "Google Workspace",
            "signals": {"mail_exchange_present": True},
        }
        with mock.patch("smtp_probe.probe_domain", return_value=domain_result):
            report = smtp_probe.build_email_report("User+tag@gmail.com")
        self.assertEqual(report["google_account_scope"], "Google consumer mail domain")
        self.assertEqual(report["address_type"], "individual_or_unknown")
        self.assertEqual(
            report["deliverability_signal"],
            "public_mail_infrastructure_present",
        )
        self.assertTrue(report["gmail_alias_notes"])
        self.assertEqual(report["account_verification"], "not_performed")

    def test_policy_check_has_explicit_sections(self):
        with mock.patch("smtp_probe.lookup_txt", return_value={"txt": []}):
            with mock.patch("smtp_probe.fetch_mta_sts_policy", return_value={"published": False}):
                result = smtp_probe.check_policy_records("example.com")
        self.assertEqual(set(result), {"mta_sts", "tls_rpt", "dkim", "mta_sts_policy"})

    def test_mta_sts_policy_is_parsed(self):
        response = mock.Mock(status=200)
        response.read.return_value = b"version: STSv1\nmode: enforce\nmx: *.example.com\n"
        response.__enter__ = lambda value: response
        response.__exit__ = mock.Mock(return_value=False)
        with mock.patch("smtp_probe.urlopen", return_value=response):
            result = smtp_probe.fetch_mta_sts_policy("example.com")
        self.assertTrue(result["valid"])


if __name__ == "__main__":
    unittest.main()
