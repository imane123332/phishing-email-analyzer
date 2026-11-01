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

    def test_html_keeps_auth_chips_and_one_attack_card(self):
        out = analyzer.render_html(analyzer.analyze(os.path.join(S, "phish.eml")))
        self.assertIn("SPF: fail", out)
        self.assertIn("DMARC: fail", out)
        self.assertEqual(out.count("MITRE ATT&amp;CK techniques"), 1)
        self.assertEqual(out.count("T1566.002"), 1)

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
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
                home = resp.read().decode()
            self.assertIn("Phishing Email Analyzer", home)
            with open(os.path.join(S, "phish.eml"), "rb") as f:
                data = f.read()
            req = urllib.request.Request(f"http://127.0.0.1:{port}/analyze?name=phish.eml",
                                         data=data, method="POST")
            with urllib.request.urlopen(req) as resp:
                out = json.loads(resp.read())
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


class TestDemoSite(unittest.TestCase):
    DOCS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs")

    def test_docs_copy_is_in_sync(self):
        with open(os.path.join(os.path.dirname(self.DOCS), "analyzer.py"), "rb") as f:
            a = f.read()
        with open(os.path.join(self.DOCS, "analyzer.py"), "rb") as f:
            b = f.read()
        self.assertEqual(a.replace(b"\r\n", b"\n"), b.replace(b"\r\n", b"\n"),
                         "docs/analyzer.py is out of date: copy analyzer.py into docs/")

    def test_demo_samples_behave_as_described(self):
        expect = {"phish-bank": "MALICIOUS", "phish-m365": "MALICIOUS", "phish-parcel": "MALICIOUS",
                  "phish-invoice": "MALICIOUS", "phish-correios": "MALICIOUS",
                  "benign-newsletter": "LIKELY BENIGN", "benign-github": "LIKELY BENIGN",
                  "benign-university": "LIKELY BENIGN", "scam-ceo": "LIKELY BENIGN"}
        for name, verdict in expect.items():
            r = analyzer.analyze(os.path.join(self.DOCS, "samples", name + ".eml"))
            self.assertEqual(r["verdict"], verdict, name)


class TestAttack(unittest.TestCase):
    def test_phish_has_expected_techniques(self):
        r = analyzer.analyze(os.path.join(S, "phish.eml"))
        ids = {t["id"] for t in r["attack"]}
        self.assertTrue({"T1566", "T1566.001", "T1566.002", "T1036.007", "T1656"} <= ids)

    def test_benign_has_none(self):
        self.assertEqual(analyzer.analyze(os.path.join(S, "benign.eml"))["attack"], [])

    def test_every_mapped_id_has_a_name(self):
        for ids in analyzer.RULE_TECHNIQUES.values():
            for i in ids:
                self.assertIn(i, analyzer.TECHNIQUES)


class TestReports(unittest.TestCase):
    def setUp(self):
        import reports
        self.reports = reports
        self.r = analyzer.analyze(os.path.join(S, "phish.eml"))

    def test_incident_report(self):
        md = self.reports.incident_report_md(self.r)
        self.assertIn("MALICIOUS", md)
        self.assertIn("hxxp://185[.]220[.]101[.]5/login", md)   # defanged
        self.assertNotIn("http://185.220.101.5", md)
        self.assertIn("T1566.002", md)
        self.assertIn("A.8.23", md)
        self.assertIn("isolated sandbox", md)                    # has an attachment

    def test_benign_report_has_no_actions_to_block(self):
        md = self.reports.incident_report_md(analyzer.analyze(os.path.join(S, "benign.eml")))
        self.assertIn("No action needed", md)
        self.assertNotIn("Suggested ISO", md)

    def test_markdown_injection_is_neutralised(self):
        r = analyzer.analyze(os.path.join(S, "benign.eml"))
        r["subject"] = "x | `evil` \n# heading"
        md = self.reports.incident_report_md(r)
        self.assertNotIn("\n# heading", md)
        self.assertIn("\\|", md)

    def test_csv_and_formula_injection(self):
        out = self.reports.iocs_csv(self.r)
        self.assertTrue(out.startswith("type,value,verdict,score,source_file"))
        self.assertIn("185.220.101.5", out)
        self.assertEqual(self.reports._csv_safe("=1+1"), "'=1+1")

    def test_stix_bundle(self):
        b = self.reports.stix_bundle(self.r)
        self.assertEqual(b["type"], "bundle")
        kinds = {o["pattern"].split(":")[0] for o in b["objects"]}
        self.assertTrue({"[url", "[ipv4-addr", "[file"} <= kinds)
        for o in b["objects"]:
            self.assertTrue(o["id"].startswith("indicator--"))
            self.assertEqual(o["spec_version"], "2.1")
        self.assertIsNone(self.reports.stix_bundle(analyzer.analyze(os.path.join(S, "benign.eml"))))
        self.assertNotIn("bit.ly'", " ".join(o["pattern"] for o in b["objects"] if "domain-name" in o["pattern"]))

    def test_cli_exports(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            md, csvf, st = (os.path.join(d, n) for n in ("a.md", "a.csv", "a.json"))
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                code = analyzer.main([os.path.join(S, "phish.eml"), "--incident-report", md,
                                      "--iocs-csv", csvf, "--stix", st])
            self.assertEqual(code, 2)
            for f in (md, csvf, st):
                self.assertTrue(os.path.getsize(f) > 0)


class FakeResp:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        import json
        return json.dumps(self.payload).encode()


class TestEnrich(unittest.TestCase):
    def setUp(self):
        import enrich
        self.enrich = enrich
        self.calls = []

    def opener(self, malicious=5, abuse=90, fail=None):
        import urllib.error

        def _open(req, timeout=0):
            url = req.full_url
            self.calls.append(url)
            if fail:
                import io
                raise urllib.error.HTTPError(url, fail, "x", {}, io.BytesIO(b""))
            if "virustotal" in url:
                return FakeResp({"data": {"attributes": {"last_analysis_stats": {
                    "malicious": malicious, "suspicious": 0, "harmless": 60, "undetected": 10}}}})
            return FakeResp({"data": {"abuseConfidenceScore": abuse, "totalReports": 12, "countryCode": "RU"}})
        return _open

    def make(self, **kw):
        return self.enrich.Enricher(vt_key="k", abuse_key="k2", delay=0, opener=self.opener(**kw))

    def test_enrichment_adds_findings_and_rescores(self):
        r = analyzer.analyze(os.path.join(S, "benign.eml"))
        r["iocs"]["domains"] = ["evil.example", "198.51.100.7"]
        before = r["score"]
        r["iocs"]["received_ips"] = ["8.8.8.8", "10.0.0.5"]       # private one must be skipped
        self.enrich.enrich_report(r, self.make())
        rules = {f["rule"] for f in r["findings"]}
        self.assertIn("reputation_malicious", rules)
        self.assertGreater(r["score"], before)
        self.assertTrue(r["enrichment"]["results"])
        self.assertFalse(any("10.0.0.5" in c for c in self.calls))

    def test_failures_never_raise_and_are_not_cached(self):
        r = analyzer.analyze(os.path.join(S, "benign.eml"))
        r["iocs"]["domains"] = ["evil.example"]
        e = self.make(fail=429)
        self.enrich.enrich_report(r, e)
        self.assertIn("rate limited", r["enrichment"]["results"][0]["summary"])
        self.assertEqual(e.cache, {})

    def test_not_found_is_not_evidence(self):
        r = analyzer.analyze(os.path.join(S, "benign.eml"))
        r["iocs"]["domains"] = ["unknown.example"]
        self.enrich.enrich_report(r, self.make(fail=404))
        self.assertNotIn("reputation_malicious", {f["rule"] for f in r["findings"]})

    def test_cache_avoids_second_request(self):
        e = self.make()
        e.virustotal("domain", "evil.example")
        n = len(self.calls)
        e.virustotal("domain", "evil.example")
        self.assertEqual(len(self.calls), n)

    def test_key_never_in_report(self):
        r = analyzer.analyze(os.path.join(S, "phish.eml"))
        e = self.enrich.Enricher(vt_key="SECRETKEY123", abuse_key="SECRETKEY456", delay=0, opener=self.opener())
        self.enrich.enrich_report(r, e)
        import json
        self.assertNotIn("SECRETKEY", json.dumps(r))

    def test_enrichment_card_in_html(self):
        r = analyzer.analyze(os.path.join(S, "phish.eml"))
        self.enrich.enrich_report(r, self.make())
        self.assertIn("Threat intelligence lookups", analyzer.render_html(r))


class TestHelpers(unittest.TestCase):
    def test_domain_of(self):
        self.assertEqual(analyzer.domain_of("a@B.com"), "b.com")

    def test_host_of(self):
        self.assertEqual(analyzer.host_of("http://X.com/a"), "x.com")


if __name__ == "__main__":
    unittest.main()
