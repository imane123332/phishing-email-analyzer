"""Turn an analysis report into things a SOC can use: incident report, IOC CSV, STIX 2.1.

All functions take the dict returned by analyzer.analyze() and use only the standard library.
"""
import csv
import io
import re
import uuid
from datetime import datetime, timezone

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _now(now=None):
    return now or datetime.now(timezone.utc)


def defang(value: str) -> str:
    """hxxp://evil[.]example: safe to paste into tickets and chats."""
    return str(value).replace("http", "hxxp").replace(".", "[.]")


URL_RE = re.compile(r"https?://[^\s;,)\]]+", re.I)


def defang_urls(text) -> str:
    """Defang every http(s) URL inside a longer text."""
    return URL_RE.sub(lambda m: defang(m.group(0)), str(text))


def _md(value) -> str:
    """Untrusted text from an email, made safe for a Markdown table or line."""
    text = re.sub(r"\s+", " ", str(value)).replace("`", "'").replace("|", "\\|")
    return text[:300]


def _is_flagged(report) -> bool:
    return report["verdict"] != "LIKELY BENIGN"


def indicators(report):
    """(type, value) pairs that are worth blocking or hunting for."""
    ioc = report["iocs"]
    out = []
    for u in ioc["urls"]:
        out.append(("url", u))
    for d in ioc["domains"]:
        if IP_RE.match(d):
            out.append(("ipv4", d))
        elif d not in SHORTENERS:
            out.append(("domain", d))
    for a in ioc["attachments"]:
        if a.get("sha256"):
            out.append(("sha256", a["sha256"]))
    seen, uniq = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


# ---------------------------------------------------------------- incident report
CONTROLS = {
    "A.5.7": "Threat intelligence",
    "A.5.26": "Response to information security incidents",
    "A.5.28": "Collection of evidence",
    "A.6.3": "Information security awareness, education and training",
    "A.8.7": "Protection against malware",
    "A.8.16": "Monitoring activities",
    "A.8.23": "Web filtering",
}


def incident_report_md(report, now=None) -> str:
    ts = _now(now).strftime("%Y-%m-%d %H:%M UTC")
    verdict, score = report["verdict"], report["score"]
    meta = report["meta"]
    L = ["# Phishing email incident report", "",
         f"Generated: {ts} by phishing-email-analyzer (static analysis, nothing was opened or executed).", "",
         "## Summary",
         f"- **Verdict:** {verdict} (score {score}/100)",
         f"- **Subject:** `{_md(defang_urls(report['subject']))}`",
         f"- **Sender:** `{_md(meta['display_name'])} <{_md(meta['from'])}>`",
         f"- **Source file:** `{_md(report['file'])}`", "",
         "## Why it was flagged", "", "| Points | Rule | Detail |", "|---|---|---|"]
    for f in report["findings"] or [{"points": 0, "rule": "none", "detail": "No rule fired"}]:
        L.append(f"| +{f['points']} | `{_md(f['rule'])}` | `{_md(defang_urls(f['detail']))}` |")

    if report.get("attack"):
        L += ["", "## MITRE ATT&CK techniques", ""]
        for t in report["attack"]:
            L.append(f"- **{t['id']}** {t['name']} (evidence: {', '.join('`' + r + '`' for r in t['rules'])})")

    ind = indicators(report)
    L += ["", "## Indicators of compromise (defanged)", ""]
    if ind:
        for kind, value in ind:
            L.append(f"- {kind}: `{defang(value) if kind != 'sha256' else value}`")
    else:
        L.append("- None extracted.")

    enr = report.get("enrichment")
    if enr and enr.get("results"):
        L += ["", "## Threat intelligence lookups", "", "| Source | Indicator | Result |", "|---|---|---|"]
        for x in enr["results"]:
            L.append(f"| {_md(x['source'])} | `{defang(x['value']) if x['type'] != 'sha256' else x['value']}` | `{_md(defang_urls(x['summary']))}` |")

    L += ["", "## Recommended actions", ""]
    if _is_flagged(report):
        steps = [
            "Keep the original `.eml` file as evidence. Do not forward it as a normal email.",
            "After checking they are not legitimate services, block the sender, the URLs and the attachment hashes above at the mail gateway, proxy and endpoint tools.",
            "Search all mailboxes for the same sender, subject or attachment hash, and remove copies that were not opened.",
            "Find out who received it. If someone clicked a link or opened the attachment: reset the password, revoke active sessions, check for new MFA devices and mail-forwarding rules, and review sign-in and endpoint logs.",
            "Tell the affected users and add this example to awareness training.",
            "If it targets your organisation, report it to your CERT (in Morocco: maCERT, run by the DGSSI).",
        ]
        if report["iocs"]["attachments"]:
            steps.insert(1, "Open the attachment only in an isolated sandbox, never on a normal workstation.")
        L += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
        ctrl = ["A.5.7", "A.5.26", "A.5.28", "A.6.3", "A.8.16"]
        if report["iocs"]["attachments"]:
            ctrl.append("A.8.7")
        if report["iocs"]["urls"]:
            ctrl.append("A.8.23")
        L += ["", "## Suggested ISO/IEC 27001:2022 Annex A controls", "",
              "A starting point to check against your own statement of applicability, not an audit result.", ""]
        L += [f"- **{c}** {CONTROLS[c]}" for c in sorted(ctrl)]
    else:
        L += ["No action needed on the technical evidence.",
              "",
              "Static analysis cannot see scams that have no technical red flag (for example a gift-card request "
              "from a real mailbox). If the content looks wrong, check it by hand or ask the sender through another channel."]
    L += ["", "## Limits", "",
          "Automated static analysis. The score is a heuristic: review the evidence before blocking anything.", ""]
    return "\n".join(L)


# ---------------------------------------------------------------- CSV
def _csv_safe(value: str) -> str:
    """Stop spreadsheets from running a cell that starts with = + - or @."""
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


def iocs_csv(report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["type", "value", "verdict", "score", "source_file"])
    for kind, value in indicators(report):
        w.writerow([kind, _csv_safe(value), report["verdict"], report["score"], _csv_safe(str(report["file"]))])
    return buf.getvalue()


# ---------------------------------------------------------------- STIX 2.1
def _stix_str(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(kind, value):
    v = _stix_str(value)
    return {"url": f"[url:value = '{v}']",
            "domain": f"[domain-name:value = '{v}']",
            "ipv4": f"[ipv4-addr:value = '{v}']",
            "sha256": f"[file:hashes.'SHA-256' = '{v}']"}[kind]


def stix_bundle(report, now=None):
    """STIX 2.1 bundle of indicators. Returns None when the email looks benign."""
    if not _is_flagged(report):
        return None
    when = _now(now).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    itype = "malicious-activity" if report["verdict"] == "MALICIOUS" else "anomalous-activity"
    objects = []
    for kind, value in indicators(report):
        pattern = _pattern(kind, value)
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, pattern)),
            "created": when, "modified": when, "valid_from": when,
            "name": f"Phishing {kind}",
            "description": "Extracted automatically by phishing-email-analyzer from a "
                           f"{report['verdict']} email. Review before blocking.",
            "indicator_types": [itype], "pattern": pattern, "pattern_type": "stix",
        })
    if not objects:
        return None
    bundle_id = "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(o["id"] for o in objects)))
    return {"type": "bundle", "id": bundle_id, "objects": objects}
