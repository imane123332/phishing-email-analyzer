#!/usr/bin/env python3
"""phishing-analyzer: static analysis of .eml files (stdlib only).

Usage: python analyzer.py samples/phish.eml [--json]
"""
import argparse
import hashlib
import html as htmllib
import json
import re
import sys
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
                 ".lnk", ".iso", ".img", ".hta", ".docm", ".xlsm", ".html", ".htm"}
DOUBLE_EXT_RE = re.compile(r"\.\w{2,5}\.(exe|scr|js|vbs|bat|cmd|lnk|hta|ps1)$", re.I)
BRANDS = ["paypal", "microsoft", "apple", "amazon", "google", "netflix", "dhl",
          "attijariwafa", "cih", "bmce", "maroc telecom", "inwi", "orange", "cnss", "dgi"]
URGENCY = ["urgent", "immediately", "verify your account", "suspended", "act now",
           "password expires", "urgence", "immédiatement", "vérifiez votre compte",
           "compte suspendu", "mot de passe expire", "dernier avertissement"]
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RECV_IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)


@dataclass
class Finding:
    rule: str
    points: int
    detail: str


class LinkExtractor(HTMLParser):
    """Collect (href, visible text) pairs from HTML."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def parse_eml(path: str):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_bodies(msg):
    plain = html = ""
    p = msg.get_body(preferencelist=("plain",))
    h = msg.get_body(preferencelist=("html",))
    if p:
        plain = p.get_content()
    if h:
        html = h.get_content()
    return plain, html


def check_headers(msg):
    findings = []
    disp, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = domain_of(from_addr)

    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    if reply_to and domain_of(reply_to) != from_dom:
        findings.append(Finding("reply_to_mismatch", 20,
                                f"From={from_dom} but Reply-To={domain_of(reply_to)}"))

    _, ret_path = parseaddr(str(msg.get("Return-Path", "")))
    if ret_path and domain_of(ret_path) != from_dom:
        findings.append(Finding("return_path_mismatch", 10,
                                f"From={from_dom} but Return-Path={domain_of(ret_path)}"))

    d = disp.lower()
    if "@" in d and domain_of(d.split()[-1]) != from_dom:
        findings.append(Finding("display_name_has_email", 15, f"Display name '{disp}'"))
    for brand in BRANDS:
        if brand in d and brand.replace(" ", "") not in from_dom.replace("-", ""):
            findings.append(Finding("brand_spoofing", 25,
                                    f"Display name mentions '{brand}', sender domain is {from_dom}"))
            break

    auth = {}
    for h in msg.get_all("Authentication-Results", []):
        for mech, res in AUTH_RE.findall(str(h)):
            auth[mech.lower()] = res.lower()
    for mech in ("spf", "dkim", "dmarc"):
        res = auth.get(mech)
        if res in ("fail", "softfail", "permerror", "temperror"):
            findings.append(Finding(f"{mech}_{res}", 15, f"{mech.upper()}={res}"))
        elif res is None:
            findings.append(Finding(f"{mech}_missing", 5, f"No {mech.upper()} result in headers"))
    return findings, {"from": from_addr, "display_name": disp, "reply_to": reply_to,
                      "return_path": ret_path, "auth": auth}


def received_ips(msg):
    ips = []
    for h in msg.get_all("Received", []):
        ips.extend(RECV_IP_RE.findall(str(h)))
    return list(dict.fromkeys(ips))


def check_urls(plain, html):
    findings, urls = [], set(URL_RE.findall(plain))
    ext = LinkExtractor()
    if html:
        ext.feed(html)
        urls.update(h for h, _ in ext.links if h and h.startswith("http"))
    for href, text in ext.links:
        if href and text and re.match(r"(https?://|www\.)", text, re.I):
            shown = host_of(text if text.startswith("http") else "http://" + text)
            real = host_of(href)
            if shown and real and shown != real:
                findings.append(Finding("link_text_mismatch", 25,
                                        f"Text shows {shown}, href goes to {real}"))
    for u in sorted(urls):
        h = host_of(u)
        if IP_RE.match(h):
            findings.append(Finding("ip_url", 20, u))
        if h in SHORTENERS:
            findings.append(Finding("url_shortener", 10, u))
        if "xn--" in h:
            findings.append(Finding("punycode_domain", 20, h))
        if h.count(".") >= 4:
            findings.append(Finding("many_subdomains", 10, h))
        if u.lower().startswith("http://"):
            findings.append(Finding("plain_http", 5, u))
    return findings, sorted(urls)


def check_attachments(msg):
    findings, items = [], []
    for part in msg.iter_attachments():
        name = part.get_filename() or "(unnamed)"
        data = part.get_payload(decode=True) or b""
        items.append({"filename": name, "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()})
        low = name.lower()
        if DOUBLE_EXT_RE.search(low):
            findings.append(Finding("double_extension", 30, name))
        elif any(low.endswith(e) for e in DANGEROUS_EXT):
            findings.append(Finding("dangerous_attachment", 25, name))
    return findings, items


def check_language(plain, html):
    text = (plain + " " + re.sub(r"<[^>]+>", " ", html)).lower()
    hits = [k for k in URGENCY if k in text]
    if hits:
        return [Finding("urgency_language", min(5 * len(hits), 15), ", ".join(hits))]
    return []


def verdict(score: int) -> str:
    if score >= 60:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "LIKELY BENIGN"


def analyze(path: str) -> dict:
    msg = parse_eml(path)
    plain, html = get_bodies(msg)
    f_head, meta = check_headers(msg)
    f_url, urls = check_urls(plain, html)
    f_att, atts = check_attachments(msg)
    findings = f_head + f_url + f_att + check_language(plain, html)
    score = min(sum(f.points for f in findings), 100)
    return {
        "file": path,
        "subject": str(msg.get("Subject", "")),
        "meta": meta,
        "score": score,
        "verdict": verdict(score),
        "findings": [asdict(f) for f in findings],
        "iocs": {"urls": urls, "domains": sorted({host_of(u) for u in urls}),
                 "received_ips": received_ips(msg), "attachments": atts},
    }


def render(report: dict) -> str:
    lines = [f"File    : {report['file']}",
             f"Subject : {report['subject']}",
             f"From    : {report['meta']['display_name']} <{report['meta']['from']}>",
             f"Score   : {report['score']}/100 -> {report['verdict']}", "", "Findings:"]
    for f in report["findings"] or [{"rule": "none", "points": 0, "detail": ""}]:
        lines.append(f"  [+{f['points']:>2}] {f['rule']}: {f['detail']}")
    ioc = report["iocs"]
    lines += ["", "IOCs:", f"  domains : {', '.join(ioc['domains']) or '-'}",
              f"  ips     : {', '.join(ioc['received_ips']) or '-'}"]
    for a in ioc["attachments"]:
        lines.append(f"  attach  : {a['filename']} sha256={a['sha256']}")
    return "\n".join(lines)


HTML_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:32px}
.wrap{max-width:980px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}.sub{color:#8b949e;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:18px}
.top{display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.gauge{width:130px;height:130px;border-radius:50%;display:grid;place-items:center;flex:none}
.gauge div{width:100px;height:100px;border-radius:50%;background:#161b22;display:grid;place-items:center;text-align:center}
.gauge b{font-size:30px;display:block;line-height:1}.gauge span{font-size:11px;color:#8b949e}
.verdict{font-size:24px;font-weight:700}.kv{color:#8b949e}.kv code{color:#e6edf3}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin:0 0 12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-word}
th{color:#8b949e;font-weight:600;font-size:12px}code{font-family:SFMono-Regular,Consolas,monospace;font-size:13px;color:#79c0ff}
.pill{display:inline-block;min-width:44px;text-align:center;padding:2px 8px;border-radius:999px;font-weight:700;font-size:12px}
.hi{background:#da363433;color:#ff7b72}.md{background:#d2992233;color:#e3b341}.lo{background:#2f81f733;color:#79c0ff}
.auth{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}.chip{padding:3px 10px;border-radius:6px;font-size:13px;font-weight:600}
.pass{background:#23863633;color:#3fb950}.bad{background:#da363433;color:#ff7b72}.none{background:#30363d;color:#8b949e}
.foot{color:#6e7681;font-size:12px;text-align:center;margin-top:20px}
"""


def render_html(report: dict) -> str:
    e = htmllib.escape
    score = report["score"]
    color = "#ff7b72" if score >= 60 else "#e3b341" if score >= 30 else "#3fb950"
    meta = report["meta"]
    ioc = report["iocs"]

    def pill(pts):
        cls = "hi" if pts >= 20 else "md" if pts >= 10 else "lo"
        return f'<span class="pill {cls}">+{pts}</span>'

    rows = "".join(
        f"<tr><td>{pill(f['points'])}</td><td><code>{e(f['rule'])}</code></td><td>{e(f['detail'])}</td></tr>"
        for f in report["findings"]
    ) or '<tr><td colspan="3">No findings</td></tr>'

    chips = ""
    for mech in ("spf", "dkim", "dmarc"):
        res = meta["auth"].get(mech)
        cls = "pass" if res == "pass" else "none" if res is None else "bad"
        chips += f'<span class="chip {cls}">{mech.upper()}: {e(res or "n/a")}</span>'

    def list_rows(items):
        return "".join(f"<tr><td><code>{e(i)}</code></td></tr>" for i in items) or "<tr><td>-</td></tr>"

    atts = "".join(
        f"<tr><td>{e(a['filename'])}</td><td>{a['size']} B</td><td><code>{a['sha256']}</code></td></tr>"
        for a in ioc["attachments"]
    ) or '<tr><td colspan="3">-</td></tr>'

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Phishing report</title>
<style>{HTML_CSS}</style></head><body><div class="wrap">
<h1>Phishing Email Analysis</h1><div class="sub">{e(report['file'])}</div>
<div class="card top">
<div class="gauge" style="background:conic-gradient({color} {score * 3.6}deg,#30363d 0)"><div><p style="margin:0"><b>{score}</b><span>/ 100</span></p></div></div>
<div><div class="verdict" style="color:{color}">{e(report['verdict'])}</div>
<div class="kv">Subject: <code>{e(report['subject'])}</code></div>
<div class="kv">From: <code>{e(meta['display_name'])} &lt;{e(meta['from'])}&gt;</code></div>
<div class="kv">Reply-To: <code>{e(meta['reply_to'] or '-')}</code> &nbsp; Return-Path: <code>{e(meta['return_path'] or '-')}</code></div>
<div class="auth">{chips}</div></div></div>
<div class="card"><h2>Findings ({len(report['findings'])})</h2><table><tr><th>Points</th><th>Rule</th><th>Detail</th></tr>{rows}</table></div>
<div class="card"><h2>Indicators of Compromise</h2>
<table><tr><th>Domains</th></tr>{list_rows(ioc['domains'])}</table><br>
<table><tr><th>Received IPs</th></tr>{list_rows(ioc['received_ips'])}</table><br>
<table><tr><th>Attachment</th><th>Size</th><th>SHA-256</th></tr>{atts}</table></div>
<div class="foot">phishing-email-analyzer &middot; static analysis only</div>
</div></body></html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Static phishing analysis of .eml files")
    ap.add_argument("eml")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--html", metavar="FILE", help="also write a dark HTML report")
    args = ap.parse_args(argv)
    report = analyze(args.eml)
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else render(report))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(report))
    return 0 if report["score"] < 60 else 2


if __name__ == "__main__":
    sys.exit(main())
