"""Fast, network-free regression tests for the safe probe helpers."""
import unittest
from unittest import mock

import smtp_probe


class ProbeHelperTests(unittest.TestCase):
    def test_normalize_email_and_domain(self):
        self.assertEqual(smtp_probe.normalize_domain(" User@Gmail.com. "), "gmail.com")
        self.assertEqual(smtp_probe.normalize_domain("https://Example.com/path"), "example.com")
        self.assertEqual(smtp_probe.normalize_domain("not a domain"), "")

    def test_email_parser_rejects_invalid_dot_placement(self):
        for email in (".user@example.com", "user.@example.com", "us..er@example.com"):
            with self.subTest(email=email):
                self.assertFalse(smtp_probe.split_email_address(email)["valid"])
        self.assertTrue(smtp_probe.split_email_address("user+tag@example.com")["valid"])

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

    def test_email_report_can_reuse_domain_evidence_without_network_lookup(self):
        domain_result = {
            "status": "active",
            "mail_provider": "Google Workspace",
            "signals": {"mail_exchange_present": True},
        }
        with mock.patch("smtp_probe.probe_domain") as probe:
            report = smtp_probe.build_email_report(
                "person@company.example",
                probe_domain_result=False,
                domain_result=domain_result,
            )
        probe.assert_not_called()
        self.assertEqual(report["mail_provider"], "Google Workspace")
        self.assertEqual(report["domain_report"], domain_result)

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
        self.assertEqual(report["mail_provider"], "Google consumer Gmail")
        self.assertEqual(
            report["google_alias_canonical_hint"],
            "user@gmail.com",
        )
        self.assertEqual(report["address_type"], "individual_or_unknown")
        self.assertEqual(
            report["deliverability_signal"],
            "public_mail_infrastructure_present",
        )
        self.assertTrue(report["gmail_alias_notes"])
        self.assertEqual(report["verification_limit"][:10], "A specific")
        self.assertEqual(report["account_verification"], "not_performed")

    def test_public_mail_security_summary_is_explicit(self):
        result = {
            "spf": {"spf": ["v=spf1 -all"]},
            "dmarc": {"dmarc": ["v=DMARC1; p=reject"]},
            "mail_security": {
                "dkim": {"google": {"txt": ["v=DKIM1"]}},
                "mta_sts": {"txt": []},
                "tls_rpt": {"txt": []},
            },
        }
        summary = smtp_probe.summarize_public_mail_security(result)
        self.assertEqual(summary["published_controls"], 3)
        self.assertEqual(
            summary["assessment"],
            "published_mail_security_signals_found",
        )

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
