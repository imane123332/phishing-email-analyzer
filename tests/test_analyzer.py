import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import analyzer  # noqa: E402

S = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def rules(report):
    return {f["rule"] for f in report["findings"]}


class TestPhish(unittest.TestCase):
    def setUp(self):
        self.r = analyzer.analyze(os.path.join(S, "phish.eml"))

    def test_verdict(self):
        self.assertEqual(self.r["verdict"], "MALICIOUS")

    def test_header_rules(self):
        self.assertTrue({"reply_to_mismatch", "return_path_mismatch", "brand_spoofing",
                         "spf_fail", "dmarc_fail"} <= rules(self.r))

    def test_url_rules(self):
        self.assertTrue({"link_text_mismatch", "ip_url", "url_shortener"} <= rules(self.r))

    def test_attachment(self):
        self.assertIn("double_extension", rules(self.r))
        self.assertEqual(len(self.r["iocs"]["attachments"][0]["sha256"]), 64)

    def test_iocs(self):
        self.assertIn("185.220.101.5", self.r["iocs"]["received_ips"])
        self.assertIn("bit.ly", self.r["iocs"]["domains"])

    def test_urgency(self):
        self.assertIn("urgency_language", rules(self.r))


class TestBenign(unittest.TestCase):
    def test_clean(self):
        r = analyzer.analyze(os.path.join(S, "benign.eml"))
        self.assertEqual(r["verdict"], "LIKELY BENIGN")
        self.assertLess(r["score"], 30)


class TestHtml(unittest.TestCase):
    def test_html_report(self):
        r = analyzer.analyze(os.path.join(S, "phish.eml"))
        out = analyzer.render_html(r)
        self.assertIn("MALICIOUS", out)
        self.assertIn("link_text_mismatch", out)

    def test_html_escapes(self):
        r = analyzer.analyze(os.path.join(S, "benign.eml"))
        r["subject"] = "<script>alert(1)</script>"
        self.assertNotIn("<script>alert", analyzer.render_html(r))


class TestHelpers(unittest.TestCase):
    def test_domain_of(self):
        self.assertEqual(analyzer.domain_of("a@B.com"), "b.com")

    def test_host_of(self):
        self.assertEqual(analyzer.host_of("http://X.com/a"), "x.com")


if __name__ == "__main__":
    unittest.main()
