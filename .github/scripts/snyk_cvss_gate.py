#!/usr/bin/env python3
"""
Snyk CVSS Gate
──────────────
Reads snyk-results.json (raw Snyk JSON output) and gates on CVSS scores.

Gate axes (evaluated in order):

  BLOCK if:
    - Any finding has cvssScore >= CVSS_BLOCK_THRESHOLD  (default 9.0)
    - OR critical count > CRIT_CEILING                   (count fallback)
    - OR high count     > HIGH_CEILING                   (count fallback)

  WARN if:
    - Any finding has cvssScore >= CVSS_WARN_THRESHOLD   (default 7.0)

The count fallback catches findings that Snyk does not assign a CVSS score
(rare, but possible for very new or proprietary advisories).

Exit codes:  0 = pass   1 = block
             WARN_IS_BLOCK=true promotes warnings to exit code 1.

Thresholds — override via environment variables:
  CVSS_BLOCK_THRESHOLD   float, default 9.0
  CVSS_WARN_THRESHOLD    float, default 7.0
  CRIT_CEILING           int,   default 0   (0 = any critical blocks)
  HIGH_CEILING           int,   default 5
  WARN_IS_BLOCK          bool,  default false
  SNYK_JSON_FILE         str,   default snyk-results.json
"""

import json
import os
import sys

# ── Thresholds ────────────────────────────────────────────────────────────────
CVSS_BLOCK_THRESHOLD = float(os.getenv("CVSS_BLOCK_THRESHOLD", "9.0"))
CVSS_WARN_THRESHOLD  = float(os.getenv("CVSS_WARN_THRESHOLD",  "7.0"))
CRIT_CEILING         = int(os.getenv("CRIT_CEILING",           "0"))
HIGH_CEILING         = int(os.getenv("HIGH_CEILING",           "5"))
WARN_IS_BLOCK        = os.getenv("WARN_IS_BLOCK", "false").lower() == "true"
SNYK_JSON_FILE       = os.getenv("SNYK_JSON_FILE", "snyk-results.json")


def load_snyk_json(path):
    with open(path) as f:
        return json.load(f)


def parse_findings(data):
    """
    Extract normalised finding list from Snyk JSON.
    Each finding: {id, title, severity, cvss_score, package, version, url}
    """
    findings = []
    for vuln in data.get("vulnerabilities", []):
        cvss_raw = vuln.get("cvssScore")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else None
        except (TypeError, ValueError):
            cvss = None

        findings.append({
            "id":       vuln.get("id", "unknown"),
            "title":    vuln.get("title", ""),
            "severity": vuln.get("severity", "unknown").lower(),
            "cvss":     cvss,
            "package":  vuln.get("packageName", ""),
            "version":  vuln.get("version", ""),
            "url":      vuln.get("url", ""),
        })
    return findings


def print_report(findings):
    crits  = [f for f in findings if f["severity"] == "critical"]
    highs  = [f for f in findings if f["severity"] == "high"]
    meds   = [f for f in findings if f["severity"] == "medium"]
    lows   = [f for f in findings if f["severity"] == "low"]

    # Findings with CVSS scores
    scored = [f for f in findings if f["cvss"] is not None]
    block_hits = [f for f in scored if f["cvss"] >= CVSS_BLOCK_THRESHOLD]
    warn_hits  = [f for f in scored
                  if CVSS_WARN_THRESHOLD <= f["cvss"] < CVSS_BLOCK_THRESHOLD]

    print("=" * 70)
    print("  SNYK CVSS GATE REPORT")
    print("=" * 70)
    print(f"  Input file       : {SNYK_JSON_FILE}")
    print(f"  Total findings   : {len(findings)}")
    print(f"  Severity counts  : critical={len(crits)}  high={len(highs)}"
          f"  medium={len(meds)}  low={len(lows)}")
    print(f"  CVSS scored      : {len(scored)} / {len(findings)}")
    print()
    print(f"  Thresholds")
    print(f"    BLOCK  : CVSS >= {CVSS_BLOCK_THRESHOLD}  OR  "
          f"critical > {CRIT_CEILING}  OR  high > {HIGH_CEILING}")
    print(f"    WARN   : CVSS >= {CVSS_WARN_THRESHOLD}")
    print()

    # ── CVSS-block findings ──────────────────────────────────────────────────
    if block_hits:
        print(f"  ── Findings at CVSS >= {CVSS_BLOCK_THRESHOLD} (BLOCK) "
              f"{'─' * 30}")
        _print_finding_table(block_hits)
        print()

    # ── CVSS-warn findings ───────────────────────────────────────────────────
    if warn_hits:
        print(f"  ── Findings at CVSS {CVSS_WARN_THRESHOLD}–{CVSS_BLOCK_THRESHOLD} (WARN) "
              f"{'─' * 30}")
        _print_finding_table(warn_hits[:10])
        if len(warn_hits) > 10:
            print(f"  ... and {len(warn_hits) - 10} more (see snyk-results.json)")
        print()

    # ── Count fallback ───────────────────────────────────────────────────────
    print("  ── Count fallback ──────────────────────────────────────────────────")
    _flag = lambda count, ceil: "🔴 BLOCK" if count > ceil else "✅ OK"
    print(f"  Critical : {len(crits):>3}  ceiling={CRIT_CEILING}  {_flag(len(crits), CRIT_CEILING)}")
    print(f"  High     : {len(highs):>3}  ceiling={HIGH_CEILING}  {_flag(len(highs), HIGH_CEILING)}")
    print()


def _print_finding_table(findings):
    print(f"  {'CVSS':>5}  {'Severity':<10}  {'ID':<42}  Title")
    print(f"  {'─'*5}  {'─'*10}  {'─'*42}  {'─'*30}")
    for f in sorted(findings, key=lambda x: x["cvss"] or 0, reverse=True):
        cvss_str = f"{f['cvss']:.1f}" if f["cvss"] is not None else " N/A"
        title    = f["title"][:40]
        print(f"  {cvss_str:>5}  {f['severity']:<10}  {f['id']:<42}  {title}")


def gate_decision(findings):
    """Return (decision, reason). Decision is BLOCK, WARN, or PASS."""
    crits = [f for f in findings if f["severity"] == "critical"]
    highs = [f for f in findings if f["severity"] == "high"]

    # ── CVSS axis (primary) ──────────────────────────────────────────────────
    block_hits = [f for f in findings
                  if f["cvss"] is not None and f["cvss"] >= CVSS_BLOCK_THRESHOLD]
    if block_hits:
        worst = max(block_hits, key=lambda f: f["cvss"])
        return ("BLOCK",
                f"{worst['id']} has CVSS {worst['cvss']:.1f} >= {CVSS_BLOCK_THRESHOLD} "
                f"({worst['title'][:60]})")

    # ── Count fallback axis ──────────────────────────────────────────────────
    if len(crits) > CRIT_CEILING:
        return ("BLOCK",
                f"Critical count {len(crits)} exceeds ceiling {CRIT_CEILING}")
    if len(highs) > HIGH_CEILING:
        return ("BLOCK",
                f"High count {len(highs)} exceeds ceiling {HIGH_CEILING}")

    # ── WARN axis ────────────────────────────────────────────────────────────
    warn_hits = [f for f in findings
                 if f["cvss"] is not None
                 and CVSS_WARN_THRESHOLD <= f["cvss"] < CVSS_BLOCK_THRESHOLD]
    if warn_hits:
        worst = max(warn_hits, key=lambda f: f["cvss"])
        return ("WARN",
                f"{worst['id']} has CVSS {worst['cvss']:.1f} >= warn threshold "
                f"{CVSS_WARN_THRESHOLD} ({worst['title'][:60]})")

    return ("PASS", "All findings within acceptable CVSS thresholds")


def main():
    if not os.path.exists(SNYK_JSON_FILE):
        print(f"[ERROR] Snyk JSON not found: {SNYK_JSON_FILE}")
        sys.exit(1)

    print(f"\n[*] Loading {SNYK_JSON_FILE}...")
    data     = load_snyk_json(SNYK_JSON_FILE)
    findings = parse_findings(data)
    print(f"[*] Parsed {len(findings)} findings")

    print_report(findings)

    decision, reason = gate_decision(findings)

    print("=" * 70)
    print(f"  GATE DECISION : {decision}")
    print(f"  REASON        : {reason}")
    print("=" * 70)
    print()

    # Write report artifact
    report = {
        "gate":     decision,
        "reason":   reason,
        "thresholds": {
            "cvss_block": CVSS_BLOCK_THRESHOLD,
            "cvss_warn":  CVSS_WARN_THRESHOLD,
            "crit_ceiling": CRIT_CEILING,
            "high_ceiling": HIGH_CEILING,
        },
        "summary": {
            "total":    len(findings),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high":     len([f for f in findings if f["severity"] == "high"]),
            "medium":   len([f for f in findings if f["severity"] == "medium"]),
            "low":      len([f for f in findings if f["severity"] == "low"]),
        },
        "findings": findings,
    }
    with open("snyk_cvss_report.json", "w") as fp:
        json.dump(report, fp, indent=2)
    print("[*] Report written to snyk_cvss_report.json")

    if decision == "BLOCK":
        sys.exit(1)
    elif decision == "WARN" and WARN_IS_BLOCK:
        print("[*] WARN_IS_BLOCK=true — treating WARN as BLOCK")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()