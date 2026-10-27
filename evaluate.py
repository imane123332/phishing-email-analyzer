#!/usr/bin/env python3
"""Run the analyzer on folders of real emails and measure how well it works.

Usage:
  python evaluate.py --phish data/phish --ham data/ham [--threshold 30] [--csv results.csv]
"""
import argparse
import csv
import os
import sys
from collections import Counter

import analyzer


def scan(folder, label, threshold):
    rows, errors = [], 0
    for root, _, files in os.walk(folder):
        for name in sorted(files):
            if not name.lower().endswith(".eml"):
                continue
            path = os.path.join(root, name)
            try:
                r = analyzer.analyze(path)
            except Exception as exc:  # real emails are messy: count, do not crash
                errors += 1
                print(f"[error] {path}: {exc}", file=sys.stderr)
                continue
            rows.append({"file": path, "label": label, "score": r["score"],
                         "verdict": r["verdict"], "flagged": r["score"] >= threshold,
                         "rules": ";".join(sorted({f["rule"] for f in r["findings"]}))})
    return rows, errors


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "n/a"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", required=True, help="folder of real phishing .eml")
    ap.add_argument("--ham", required=True, help="folder of legitimate .eml")
    ap.add_argument("--threshold", type=int, default=30, help="score >= this counts as flagged")
    ap.add_argument("--csv", help="write per-email results")
    a = ap.parse_args(argv)

    p_rows, p_err = scan(a.phish, "phish", a.threshold)
    h_rows, h_err = scan(a.ham, "ham", a.threshold)
    tp = sum(r["flagged"] for r in p_rows)
    fn = len(p_rows) - tp
    fp = sum(r["flagged"] for r in h_rows)
    tn = len(h_rows) - fp

    print(f"Threshold: {a.threshold}   Phish: {len(p_rows)}   Ham: {len(h_rows)}   "
          f"Parse errors: {p_err + h_err}")
    print(f"Detection rate (recall): {pct(tp, tp + fn)}   False-positive rate: {pct(fp, fp + tn)}   "
          f"Precision: {pct(tp, tp + fp)}")
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")

    for title, rows in (("phish", p_rows), ("ham", h_rows)):
        c = Counter(rule for r in rows for rule in r["rules"].split(";") if rule)
        print(f"\nTop rules on {title}:")
        for rule, n in c.most_common(8):
            print(f"  {rule:<24}{n:>5}  ({pct(n, len(rows))})")

    misses = [r for r in p_rows if not r["flagged"]][:10]
    wrong = [r for r in h_rows if r["flagged"]][:10]
    print("\nMissed phishing (first 10):", *[f"\n  {r['file']} score={r['score']}" for r in misses])
    print("\nFalse alarms (first 10):", *[f"\n  {r['file']} score={r['score']}" for r in wrong])

    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["file", "label", "score", "verdict", "flagged", "rules"])
            w.writeheader()
            w.writerows(p_rows + h_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
