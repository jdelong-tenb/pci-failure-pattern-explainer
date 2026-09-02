#!/usr/bin/env python3
"""
pci_failure_summary.py — Print an attestation-blocking findings summary for a completed PCI scan.

Run this standalone to get a quick text summary before invoking the full
PCI Failure Pattern Explainer skill in Claude Code.

Usage:
    export TIO_ACCESS_KEY="your-access-key"
    export TIO_SECRET_KEY="your-secret-key"

    # List recent PCI/ASV scans:
    python3 scripts/pci_failure_summary.py

    # Summarize failures from a specific scan:
    python3 scripts/pci_failure_summary.py <scan_id>

Generate API keys: Settings > My Account > API Keys
Requires: Python 3 (stdlib only)
"""

import json
import os
import sys
import urllib.request
import urllib.error

BASE_URL = "https://cloud.tenable.com"

SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
# Severity 2 = Medium = CVSS 4.0+ = blocks PCI ASV attestation
PCI_BLOCK_THRESHOLD = 2


def get_headers():
    access_key = os.environ.get("TIO_ACCESS_KEY")
    secret_key = os.environ.get("TIO_SECRET_KEY")
    if not access_key or not secret_key:
        print("ERROR: TIO_ACCESS_KEY and TIO_SECRET_KEY environment variables are required.")
        print("Generate API keys at: Settings > My Account > API Keys")
        sys.exit(1)
    return {
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        "Accept": "application/json",
    }


def api_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers=get_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": f"HTTP {e.code}: {body[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def list_pci_scans():
    resp = api_get("/scans")
    if "error" in resp:
        print(f"Could not retrieve scans: {resp['error']}")
        return
    scans = resp.get("scans") or []
    pci_scans = [
        s for s in scans
        if "pci" in s.get("name", "").lower() or "asv" in s.get("name", "").lower()
    ]
    if not pci_scans:
        print("No PCI/ASV scans found.")
        print("Run a PCI ASV scan first, or use the PCI ASV Scan Copilot skill to set one up.")
        return
    print("PCI/ASV scans (most recent first):")
    for s in pci_scans[:10]:
        status = s.get("status", "?")
        scan_id = s.get("id", "?")
        name = s.get("name", "?")
        print(f"  ID {scan_id:6}  status: {status:12}  name: {name}")
    print()
    print("Usage: python3 scripts/pci_failure_summary.py <scan_id>")


def summarize_scan(scan_id):
    resp = api_get(f"/scans/{scan_id}")
    if "error" in resp:
        print(f"Could not retrieve scan {scan_id}: {resp['error']}")
        return

    info = resp.get("info", {})
    status = info.get("status", "unknown")
    scan_name = info.get("name", f"Scan {scan_id}")

    print(f"Scan: {scan_name} (ID: {scan_id})")
    print(f"Status: {status}")

    if status != "completed":
        print(f"\nScan is not complete (status: {status}).")
        print("Wait for completion before running the failure analysis.")
        return

    vuln_list = resp.get("vulnerabilities") or []
    blocking = [v for v in vuln_list if v.get("severity", 0) >= PCI_BLOCK_THRESHOLD]
    non_blocking = [v for v in vuln_list if v.get("severity", 0) < PCI_BLOCK_THRESHOLD]

    crit = [v for v in blocking if v.get("severity") == 4]
    high = [v for v in blocking if v.get("severity") == 3]
    med = [v for v in blocking if v.get("severity") == 2]

    print()
    print(f"Findings: {len(vuln_list)} total")
    print(f"  Attestation-blocking (CVSS >= 4.0): {len(blocking)}")
    print(f"    Critical: {len(crit)}, High: {len(high)}, Medium: {len(med)}")
    print(f"  Below threshold (Low/Info):          {len(non_blocking)}")

    if not blocking:
        print()
        print("No findings that block PCI ASV attestation.")
        print("Verify with your ASV and QSA before submitting.")
        return

    print()
    print("Attestation-blocking findings (must fix or dispute):")
    print("-" * 70)
    for v in sorted(blocking, key=lambda x: x.get("severity", 0), reverse=True):
        sev = SEVERITY_LABELS.get(v.get("severity", 0), "?")
        plugin_id = v.get("plugin_id", "?")
        plugin_name = v.get("plugin_name", f"Plugin {plugin_id}")
        count = v.get("count", 1)
        print(f"  [{sev:8}] {plugin_name[:55]:<55} plugin {plugin_id} | {count} host(s)")

    print()
    print("Run the PCI Failure Pattern Explainer skill in Claude Code for:")
    print("  - Plain-English explanation of each finding")
    print("  - PCI DSS v4.0 requirement cross-references")
    print("  - Dispute vs. fix recommendation with evidence guidance")


def main():
    if len(sys.argv) > 1:
        try:
            scan_id = int(sys.argv[1])
            summarize_scan(scan_id)
        except ValueError:
            print(f"Invalid scan ID '{sys.argv[1]}' — must be a number.")
            sys.exit(1)
    else:
        list_pci_scans()


if __name__ == "__main__":
    main()
