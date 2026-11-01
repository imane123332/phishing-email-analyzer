"""Optional threat-intelligence lookups for a report from analyzer.analyze().

Off by default. When used, domains, IP addresses and attachment hashes are sent to
VirusTotal and AbuseIPDB. API keys come from the environment only:
    VT_API_KEY        VirusTotal v3 key (free key: about 4 requests per minute)
    ABUSEIPDB_API_KEY AbuseIPDB v2 key
Errors never stop the analysis and never print a key.
"""
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import analyzer

VT_API = "https://www.virustotal.com/api/v3"
ABUSE_API = "https://api.abuseipdb.com/api/v2/check"
TTL = 24 * 3600
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


class Enricher:
    def __init__(self, vt_key=None, abuse_key=None, cache_path=None, opener=None,
                 delay=15.0, max_per_type=5, sleep=time.sleep, clock=time.time):
        self.vt_key, self.abuse_key = vt_key, abuse_key
        self.cache_path = cache_path
        self.opener = opener or urllib.request.urlopen
        self.delay, self.max_per_type = delay, max_per_type
        self.sleep, self.clock = sleep, clock
        self._vt_calls = 0
        self.cache = {}
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
                    self.cache = json.load(f)
            except (OSError, ValueError):
                self.cache = {}

    @classmethod
    def from_env(cls, **kw):
        return cls(vt_key=os.environ.get("VT_API_KEY"), abuse_key=os.environ.get("ABUSEIPDB_API_KEY"), **kw)

    @property
    def enabled(self) -> bool:
        return bool(self.vt_key or self.abuse_key)

    # ---- http
    def _get_json(self, url, headers):
        req = urllib.request.Request(url, headers=headers)
        with self.opener(req, timeout=15) as resp:
            return json.load(resp)

    def _cached(self, key, fetch):
        hit = self.cache.get(key)
        if hit and self.clock() - hit["ts"] < TTL:
            return hit["value"]
        value = fetch()
        self.cache[key] = {"ts": self.clock(), "value": value}
        return value

    def save_cache(self):
        if self.cache_path:
            try:
                with open(self.cache_path, "w", encoding="utf-8") as f:
                    json.dump(self.cache, f)
            except OSError:
                pass

    # ---- VirusTotal
    def virustotal(self, kind, value):
        path = {"domain": "domains", "ipv4": "ip_addresses", "sha256": "files"}[kind]
        gui = {"domain": "domain", "ipv4": "ip-address", "sha256": "file"}[kind]
        link = f"https://www.virustotal.com/gui/{gui}/{urllib.parse.quote(value)}"

        def fetch():
            if self._vt_calls and self.delay:
                self.sleep(self.delay)
            self._vt_calls += 1
            try:
                data = self._get_json(f"{VT_API}/{path}/{urllib.parse.quote(value)}", {"x-apikey": self.vt_key})
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return {"summary": "not found on VirusTotal", "malicious": 0, "suspicious": 0, "ok": True}
                if exc.code == 429:
                    return {"summary": "rate limited (try again later)", "malicious": 0, "suspicious": 0, "ok": False}
                return {"summary": f"lookup failed (HTTP {exc.code})", "malicious": 0, "suspicious": 0, "ok": False}
            except Exception as exc:  # network down, bad JSON, timeout...
                return {"summary": f"lookup failed ({type(exc).__name__})", "malicious": 0, "suspicious": 0, "ok": False}
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
            total = sum(int(v) for v in stats.values()) or 0
            return {"summary": f"{mal} malicious, {sus} suspicious of {total} engines",
                    "malicious": mal, "suspicious": sus, "ok": True}

        res = dict(self._cached(f"vt:{kind}:{value}", fetch))
        # do not keep failures in the cache
        if not res.get("ok", True):
            self.cache.pop(f"vt:{kind}:{value}", None)
        return {"source": "VirusTotal", "type": kind, "value": value, "link": link, **res}

    # ---- AbuseIPDB
    def abuseipdb(self, ip):
        def fetch():
            q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
            try:
                data = self._get_json(f"{ABUSE_API}?{q}", {"Key": self.abuse_key, "Accept": "application/json"})
            except urllib.error.HTTPError as exc:
                return {"summary": f"lookup failed (HTTP {exc.code})", "score": 0, "ok": False}
            except Exception as exc:
                return {"summary": f"lookup failed ({type(exc).__name__})", "score": 0, "ok": False}
            d = data.get("data", {})
            score = int(d.get("abuseConfidenceScore", 0))
            return {"summary": f"abuse confidence {score}%, {d.get('totalReports', 0)} reports, country {d.get('countryCode') or '?'}",
                    "score": score, "ok": True}

        res = dict(self._cached(f"abuse:{ip}", fetch))
        if not res.get("ok", True):
            self.cache.pop(f"abuse:{ip}", None)
        return {"source": "AbuseIPDB", "type": "ipv4", "value": ip,
                "link": f"https://www.abuseipdb.com/check/{ip}", **res}


def targets(report, limit):
    ioc = report["iocs"]
    domains = [d for d in ioc["domains"] if not IP_RE.match(d) and d not in analyzer.SHORTENERS]
    ips = [d for d in ioc["domains"] if IP_RE.match(d)] + list(ioc["received_ips"])
    ips = [i for i in dict.fromkeys(ips) if _is_public_ip(i)]
    hashes = [a["sha256"] for a in ioc["attachments"] if a.get("sha256")]
    return domains[:limit], ips[:limit], hashes[:limit]


def apply_reputation(report, results):
    """Add reputation findings and recompute score and verdict."""
    mal = max((r.get("malicious", 0) for r in results if r["source"] == "VirusTotal"), default=0)
    abuse = max((r.get("score", 0) for r in results if r["source"] == "AbuseIPDB"), default=0)
    sus = max((r.get("suspicious", 0) for r in results if r["source"] == "VirusTotal"), default=0)
    add = []
    if mal >= 3:
        add.append({"rule": "reputation_malicious", "points": 30, "detail": f"VirusTotal: up to {mal} engines flag an indicator"})
    elif mal + sus >= 1:
        add.append({"rule": "reputation_suspicious", "points": 10, "detail": f"VirusTotal: {mal} malicious, {sus} suspicious"})
    if abuse >= 50:
        add.append({"rule": "ip_reputation_bad", "points": 20, "detail": f"AbuseIPDB confidence up to {abuse}%"})
    report["findings"] = report["findings"] + add
    report["score"] = min(sum(f["points"] for f in report["findings"]), 100)
    report["verdict"] = analyzer.verdict(report["score"])


def enrich_report(report, enricher):
    """Look up indicators, store the results in report['enrichment'], rescore. Never raises."""
    results = []
    domains, ips, hashes = targets(report, enricher.max_per_type)
    try:
        if enricher.vt_key:
            results += [enricher.virustotal("domain", d) for d in domains]
            results += [enricher.virustotal("ipv4", i) for i in ips]
            results += [enricher.virustotal("sha256", h) for h in hashes]
        if enricher.abuse_key:
            results += [enricher.abuseipdb(i) for i in ips]
    finally:
        enricher.save_cache()
    report["enrichment"] = {"results": results}
    apply_reputation(report, results)
    return report
