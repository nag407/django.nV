#!/usr/bin/env python3
"""
Snyk SARIF Gate with EPSS Enrichment
─────────────────────────────────────
Reads snyk.sarif, extracts CVE IDs, calls FIRST.org EPSS API,
enriches each finding, then applies a two-axis gate:

  BLOCK if:
    - Any CVE has EPSS score >= EPSS_BLOCK_THRESHOLD  (default 0.3)
      AND its severity is critical or high
    - OR raw critical count  > RAW_CRIT_CEILING       (hard fallback)
    - OR raw high count      > RAW_HIGH_CEILING       (hard fallback)

  WARN  if:
    - Any CVE has EPSS score >= EPSS_WARN_THRESHOLD   (default 0.1)

The hard-count fallback keeps the gate working even when Snyk
doesn't emit a CVE ID (e.g. non-NVD advisories).

Exit codes:  0 = pass   1 = block   2 = warn (configurable via WARN_IS_BLOCK)
"""

import json
import sys
import os
import re
import urllib.request
import urllib.error
from collections import defaultdict

# ── Tuneable thresholds (override via env vars in the workflow) ──────────────
EPSS_BLOCK_THRESHOLD = float(os.getenv("EPSS_BLOCK_THRESHOLD", "0.3"))
EPSS_WARN_THRESHOLD  = float(os.getenv("EPSS_WARN_THRESHOLD",  "0.1"))
RAW_CRIT_CEILING     = int(os.getenv("RAW_CRIT_CEILING",       "6"))
RAW_HIGH_CEILING     = int(os.getenv("RAW_HIGH_CEILING",       "18"))
WARN_IS_BLOCK        = os.getenv("WARN_IS_BLOCK", "false").lower() == "true"
SARIF_FILE           = os.getenv("SARIF_FILE", "snyk.sarif")
EPSS_API             = "https://api.first.org/data/1.0/epss"

# ── Regex to extract CVE IDs from any string field ──────────────────────────
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def load_sarif(path):
    with open(path) as f:
        return json.load(f)


def build_rule_map(run):
    """Return {rule_id: level} — checks driver AND extensions (CodeQL pattern)."""
    rule_map = {}
    for rule in run["tool"]["driver"].get("rules", []):
        rule_map[rule["id"]] = (
            rule.get("defaultConfiguration", {}).get("level", "warning")
        )
    for ext in run["tool"].get("extensions", []):
        for rule in ext.get("rules", []):
            rule_map[rule["id"]] = (
                rule.get("defaultConfiguration", {}).get("level", "warning")
            )
    return rule_map


def extract_findings(sarif):
    """Return list of dicts: {rule_id, level, message, cves, location}."""
    findings = []
    for run in sarif.get("runs", []):
        rule_map = build_rule_map(run)
        for result in run.get("results", []):
            rid   = result.get("ruleId", "unknown")
            level = result.get("level") or rule_map.get(rid, "warning")
            msg   = result.get("message", {}).get("text", "")

            # Hunt for CVE IDs in ruleId, message, and related locations
            cve_candidates = " ".join([rid, msg])
            for loc in result.get("relatedLocations", []):
                cve_candidates += " " + loc.get("message", {}).get("text", "")
            # Also check rule help text via rule_map source
            cves = list(set(CVE_RE.findall(cve_candidates)))

            loc_str = ""
            locs = result.get("locations", [])
            if locs:
                pl = locs[0].get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                line = pl.get("region", {}).get("startLine", "")
                loc_str = f"{uri}:{line}" if line else uri

            findings.append({
                "rule_id":  rid,
                "level":    level.lower(),
                "message":  msg[:120],
                "cves":     cves,
                "location": loc_str,
                "epss":     {},   # filled in later
            })
    return findings


def fetch_epss(cve_ids):
    """
    Call FIRST EPSS API in batches of 30.
    Returns {cve_id: {"epss": float, "percentile": float}}.
    """
    if not cve_ids:
        return {}

    scores = {}
    batch_size = 30
    cve_list   = list(set(cve_id.upper() for cve_id in cve_ids))

    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i + batch_size]
        params = "&".join(f"cve={c}" for c in batch)
        url    = f"{EPSS_API}?{params}"
        try:
            req  = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            for item in data.get("data", []):
                cid = item.get("cve", "").upper()
                scores[cid] = {
                    "epss":       float(item.get("epss",       0)),
                    "percentile": float(item.get("percentile", 0)),
                }
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            print(f"  [WARN] EPSS API call failed for batch {i//batch_size+1}: {e}")
            # Fail open — missing EPSS doesn't block the gate

    return scores


def enrich_findings(findings, epss_scores):
    """Attach EPSS data to each finding that has CVE IDs."""
    for f in findings:
        best = {"epss": 0.0, "percentile": 0.0, "cve": None}
        for cve in f["cves"]:
            data = epss_scores.get(cve.upper(), {})
            if data.get("epss", 0) > best["epss"]:
                best = {"epss": data["epss"], "percentile": data["percentile"], "cve": cve}
        f["epss"] = best
    return findings


def print_report(findings, epss_scores):
    """Pretty-print enrichment table and summary stats."""
    crits  = [f for f in findings if f["level"] == "error"]
    highs  = [f for f in findings if f["level"] == "warning"]
    others = [f for f in findings if f["level"] not in ("error", "warning")]

    all_cves   = set()
    epss_hits_block = []
    epss_hits_warn  = []

    for f in findings:
        for cve in f["cves"]:
            all_cves.add(cve.upper())
        score = f["epss"].get("epss", 0)
        if score >= EPSS_BLOCK_THRESHOLD and f["level"] in ("error", "warning"):
            epss_hits_block.append(f)
        elif score >= EPSS_WARN_THRESHOLD:
            epss_hits_warn.append(f)

    print("=" * 70)
    print("  SNYK GATE — EPSS ENRICHMENT REPORT")
    print("=" * 70)
    print(f"  SARIF file      : {SARIF_FILE}")
    print(f"  Total findings  : {len(findings)}  "
          f"(critical={len(crits)}, high={len(highs)}, other={len(others)})")
    print(f"  Unique CVEs     : {len(all_cves)}")
    print(f"  EPSS API base   : {EPSS_API}")
    print(f"  Block threshold : EPSS >= {EPSS_BLOCK_THRESHOLD}")
    print(f"  Warn  threshold : EPSS >= {EPSS_WARN_THRESHOLD}")
    print()

    if all_cves:
        print("  ── CVE EPSS Scores ──────────────────────────────────────────────")
        print(f"  {'CVE':<22} {'EPSS':>8}  {'Percentile':>12}  {'Action':>8}")
        print(f"  {'-'*22} {'-'*8}  {'-'*12}  {'-'*8}")
        for cve in sorted(all_cves):
            d = epss_scores.get(cve, {})
            score      = d.get("epss", None)
            percentile = d.get("percentile", None)
            if score is None:
                action = "no data"
                score_str = "N/A"
                pct_str   = "N/A"
            else:
                score_str = f"{score:.4f}"
                pct_str   = f"{percentile*100:.1f}%"
                if score >= EPSS_BLOCK_THRESHOLD:
                    action = "🔴 BLOCK"
                elif score >= EPSS_WARN_THRESHOLD:
                    action = "🟡 WARN"
                else:
                    action = "✅ OK"
            print(f"  {cve:<22} {score_str:>8}  {pct_str:>12}  {action:>8}")
        print()

    if epss_hits_block:
        print("  ── High-EPSS Findings (>= block threshold) ─────────────────────")
        for f in epss_hits_block:
            cve   = f["epss"].get("cve", "N/A")
            score = f["epss"].get("epss", 0)
            print(f"  [{f['level'].upper():8}] {f['rule_id']}")
            print(f"           CVE: {cve}  EPSS: {score:.4f}")
            print(f"           {f['message'][:80]}")
            print(f"           @ {f['location']}")
        print()

    print("  ── Raw Count Fallback ───────────────────────────────────────────────")
    print(f"  Critical (error) : {len(crits):>3}  ceiling={RAW_CRIT_CEILING}")
    print(f"  High (warning)   : {len(highs):>3}  ceiling={RAW_HIGH_CEILING}")
    print()


def gate_decision(findings, epss_scores):
    """
    Returns (decision, reason) where decision is 'BLOCK', 'WARN', or 'PASS'.
    """
    crits = [f for f in findings if f["level"] == "error"]
    highs = [f for f in findings if f["level"] == "warning"]

    # ── EPSS axis ────────────────────────────────────────────────────────────
    for f in findings:
        score = f["epss"].get("epss", 0)
        if score >= EPSS_BLOCK_THRESHOLD and f["level"] in ("error", "warning"):
            cve = f["epss"].get("cve", f["rule_id"])
            return ("BLOCK",
                    f"CVE {cve} has EPSS score {score:.4f} >= {EPSS_BLOCK_THRESHOLD} "
                    f"and severity {f['level']}")

    # ── Raw count fallback axis ───────────────────────────────────────────────
    if len(crits) > RAW_CRIT_CEILING:
        return ("BLOCK",
                f"Critical count {len(crits)} exceeds ceiling {RAW_CRIT_CEILING}")
    if len(highs) > RAW_HIGH_CEILING:
        return ("BLOCK",
                f"High count {len(highs)} exceeds ceiling {RAW_HIGH_CEILING}")

    # ── Warn axis ─────────────────────────────────────────────────────────────
    for f in findings:
        score = f["epss"].get("epss", 0)
        if score >= EPSS_WARN_THRESHOLD:
            cve = f["epss"].get("cve", f["rule_id"])
            return ("WARN",
                    f"CVE {cve} has EPSS score {score:.4f} >= warn threshold {EPSS_WARN_THRESHOLD}")

    return ("PASS", "All findings within acceptable thresholds")


def main():
    if not os.path.exists(SARIF_FILE):
        print(f"[ERROR] SARIF file not found: {SARIF_FILE}")
        sys.exit(1)

    print(f"\n[*] Loading {SARIF_FILE}...")
    sarif    = load_sarif(SARIF_FILE)
    findings = extract_findings(sarif)
    print(f"[*] Found {len(findings)} results in SARIF")

    # Collect all CVE IDs across all findings
    all_cves = set()
    for f in findings:
        all_cves.update(f["cves"])

    print(f"[*] Extracted {len(all_cves)} unique CVE IDs: "
          f"{', '.join(sorted(all_cves)[:5])}{'...' if len(all_cves)>5 else ''}")

    if all_cves:
        print(f"[*] Querying FIRST EPSS API for {len(all_cves)} CVEs...")
        epss_scores = fetch_epss(all_cves)
        print(f"[*] Received EPSS data for {len(epss_scores)} CVEs")
    else:
        print("[*] No CVE IDs found — skipping EPSS API call, using raw count gate only")
        epss_scores = {}

    findings = enrich_findings(findings, epss_scores)
    print_report(findings, epss_scores)

    decision, reason = gate_decision(findings, epss_scores)

    print("=" * 70)
    print(f"  GATE DECISION: {decision}")
    print(f"  REASON       : {reason}")
    print("=" * 70)
    print()

    # Write enriched JSON artifact for downstream jobs / PR comment
    report = {
        "gate":     decision,
        "reason":   reason,
        "findings": [
            {
                "rule_id":  f["rule_id"],
                "level":    f["level"],
                "cves":     f["cves"],
                "epss":     f["epss"],
                "location": f["location"],
            }
            for f in findings
        ],
        "epss_scores": {k: v for k, v in epss_scores.items()},
    }
    with open("snyk_epss_report.json", "w") as fp:
        json.dump(report, fp, indent=2)
    print("[*] Enriched report written to snyk_epss_report.json")

    if decision == "BLOCK":
        sys.exit(1)
    elif decision == "WARN" and WARN_IS_BLOCK:
        print("[*] WARN_IS_BLOCK=true — treating WARN as BLOCK")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()