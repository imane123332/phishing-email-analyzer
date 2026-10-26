# phishing-email-analyzer

![Report](samples/screenshot_phish.png)

Static analysis of `.eml` files: header forensics, URL and attachment checks, risk score, IOC extraction. Python stdlib only.

## Usage
```bash
python analyzer.py samples/phish.eml          # human-readable report
python analyzer.py samples/phish.eml --json   # machine-readable (exit code 2 if MALICIOUS)
python analyzer.py samples/phish.eml --html report.html   # dark HTML report
python -m unittest discover -s tests -v       # tests
```

## Detection rules
| Area | Rules |
|---|---|
| Headers | Reply-To / Return-Path mismatch, display-name spoofing (brands, embedded email), SPF/DKIM/DMARC fail or missing |
| URLs | link text vs href mismatch, IP-based URL, shorteners, punycode, many subdomains, plain HTTP |
| Attachments | dangerous extensions, double extension (`.pdf.exe`), SHA-256 hashes |
| Content | urgency language (FR/EN/PT/ES/AR), spam keywords, hidden HTML text |

Score 0-100: >=60 MALICIOUS, >=30 SUSPICIOUS, else LIKELY BENIGN.

## Evaluation on real emails
Run on real phishing from [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (honeypot samples, 12k+ `.eml`).
Rules were tuned on one random set of 1,500 emails, then measured on a **separate** set of 1,500 that was not used for tuning.

| Version | Set | Phishing flagged (score >= 30) | Parse errors |
|---|---|---|---|
| v1 (first rules) | holdout (1,499) | 39.0% | 1 |
| v2 (+ SPF/DKIM/DMARC "none", hidden text, invalid sender domain, spam words, more languages) | holdout (1,500) | 67.6% | 0 |
| v2 | tuning set (1,500) | 68.6% | 0 |

```bash
python evaluate.py --phish data/phish --ham data/ham --csv results.csv
```

**Limits (honest):**
- Only the phishing side is measured. **False-positive rate on legitimate email is not measured yet** (TODO: test on my own legitimate mail, anonymised). Some rules (hidden text, SPF/DKIM "none") also appear in legitimate marketing mail, so the real false-positive rate may not be zero.
- ~31% of the real phishing samples still score below 30. Many are plain text or image-only scams with no technical red flag, which static rules cannot catch. Next step: URL/IP reputation lookups.
- Static analysis only. Nothing is opened or executed.

## Roadmap
- [ ] VirusTotal / AbuseIPDB enrichment (hash, IP, domain)
- [ ] MITRE ATT&CK mapping (T1566.001 / .002)
- [ ] Batch mode on a folder + CSV export
- [ ] Hand-off to IR playbook (TheHive / Shuffle)
