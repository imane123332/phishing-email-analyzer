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


class TestEvaluate(unittest.TestCase):
    def test_counts(self):
        import io
        import contextlib
        import tempfile
        import shutil
        import evaluate
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "p"))
            os.makedirs(os.path.join(d, "h"))
            shutil.copy(os.path.join(S, "phish.eml"), os.path.join(d, "p"))
            shutil.copy(os.path.join(S, "benign.eml"), os.path.join(d, "h"))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                evaluate.main(["--phish", os.path.join(d, "p"), "--ham", os.path.join(d, "h")])
        self.assertIn("TP=1 FN=0 FP=0 TN=1", buf.getvalue())


class TestNewRules(unittest.TestCase):
    def test_content_rules(self):
        names = {f.rule for f in analyzer.check_language("Claim 400 free spins", "")}
        self.assertIn("spam_keywords", names)

    def test_rules_count_once(self):
        r = analyzer.analyze(os.path.join(S, "phish.eml"))
        names = [f["rule"] for f in r["findings"]]
        self.assertEqual(len(names), len(set(names)))

    def test_newsletter_return_path_ok_when_dmarc_passes(self):
        import email
        from email import policy
        raw = ("Authentication-Results: mx; dmarc=pass\nFrom: News <a@brand.com>\n"
               "Return-Path: <bounce@esp-mail.net>\n\nhi")
        m = email.message_from_string(raw, policy=policy.default)
        self.assertNotIn("return_path_mismatch", {f.rule for f in analyzer.check_headers(m)[0]})

    def test_invalid_sender_domain(self):
        import email
        from email import policy
        m = email.message_from_string("From: Correios <alerta@correios123>\n\nhi", policy=policy.default)
        names = {f.rule for f in analyzer.check_headers(m)[0]}
        self.assertIn("invalid_sender_domain", names)


class TestWebApp(unittest.TestCase):
    def test_upload_flow(self):
        import json
        import threading
        import urllib.request
        import webapp
        srv = webapp.make_server(0)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            home = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
            self.assertIn("Phishing Email Analyzer", home)
            data = open(os.path.join(S, "phish.eml"), "rb").read()
            req = urllib.request.Request(f"http://127.0.0.1:{port}/analyze?name=phish.eml",
                                         data=data, method="POST")
            out = json.loads(urllib.request.urlopen(req).read())
            self.assertEqual(out["verdict"], "MALICIOUS")
            self.assertEqual(out["name"], "phish.eml")
            self.assertIn("link_text_mismatch", out["html"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_binds_localhost_only(self):
        import webapp
        srv = webapp.make_server(0)
        try:
            self.assertEqual(srv.server_address[0], "127.0.0.1")
        finally:
            srv.server_close()


class TestHelpers(unittest.TestCase):
    def test_domain_of(self):
        self.assertEqual(analyzer.domain_of("a@B.com"), "b.com")

    def test_host_of(self):
        self.assertEqual(analyzer.host_of("http://X.com/a"), "x.com")


if __name__ == "__main__":
    unittest.main()
