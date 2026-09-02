---
name: pci-failure-pattern-explainer
description: Analyzes a completed PCI scan and produces plain-English explanations of each failure category, PCI DSS v4.0 requirement cross-references, remediation priority ranking (critical path to pass attestation versus secondary improvements), and a dispute-or-fix recommendation per finding type. Invoke when someone says things like "explain my PCI scan failures," "which PCI findings are critical to fix," "I don't understand what this PCI finding means," "which findings can I dispute vs. must fix," or "help me prioritize my PCI remediation."
---

# PCI Failure Pattern Explainer

## Why this exists

A completed PCI ASV scan produces a list of plugin IDs, CVSS scores, and technical descriptions — none of which tell you which failures will actually block your attestation, which are worth disputing, or what the PCI DSS requirement behind each one is. This skill reads a completed scan and produces a structured analysis: what each failure means in plain language, which DSS v4.0 requirement it falls under, whether it is on the critical path to passing, and whether a dispute or remediation is the right response.

This is a community-built skill, not official Tenable support and not PCI DSS compliance advice. For authoritative PCI DSS interpretation, consult your QSA.

## Step 1 — Identify the scan

Ask the user: "Which scan should I analyze? You can give me a scan name or scan ID, or I can list your recent scans."

Call `mcp__tenable-vpod__scan_list_scans` to show recent scans if the user doesn't know the ID. Filter to scans with "pci" or "asv" in the name to shorten the list. If the scan is still running, tell the user to wait for it to complete before this analysis will be meaningful.

Once a scan is selected, call `mcp__tenable-vpod__scan_results` with that scan_id to retrieve the findings.

First check for PCI verdict plugins in the scan results: plugin 33930 (COMPLIANT) means the scan passed — no failures to explain. Plugin 33929 (NOT COMPLIANT) confirms the scan failed — proceed to analyze individual findings below.

**Example user prompts:**
- "Explain my PCI scan failures"
- "Analyze my most recent PCI scan"
- "I don't understand the failures from my ASV scan last week"

## Step 2 — Categorize findings

From `mcp__tenable-vpod__scan_results`, group findings by severity:
- **Critical / High (CVSS 7.0–10.0):** block attestation; must be remediated or successfully disputed
- **Medium (CVSS 4.0–6.9):** block attestation; must be remediated or successfully disputed
- **Low (CVSS 0.1–3.9):** do not block PCI ASV attestation
- **Informational (CVSS 0.0):** do not block attestation

Note: scan_results returns integer severity levels (0=info through 4=critical), not CVSS base scores. Call `mcp__tenable-vpod__plugins_get_plugin_details` for each severity >= 2 finding to retrieve the CVSS base score for accurate PCI threshold evaluation.

For each critical, high, or medium finding, call `mcp__tenable-vpod__plugins_get_plugin_details` to retrieve the full plugin description, CVSS score, CVEs, and solution text.

For findings where the initial scan_results data is insufficient to assess dispute viability, call `mcp__tenable-vpod__workbenches_get_vulnerability_outputs` to get the raw scanner output — useful for confirming whether a TLS finding is a real cipher-suite weakness or a scanner artifact.

Note: workbenches tools aggregate data across all scans (not just the one you selected). For PCI attestation analysis, use scan_results and scan_host_details for the specific scan under review. Workbench tools are useful for cross-scan trending but may include findings from other scan targets.

## Step 3 — Plain-English explanations and DSS cross-references

For each finding that blocks attestation (CVSS ≥ 4.0), produce:

**Finding: [Plugin name]**
- **What it means:** One to two sentence plain-language description of what the scanner found and why it is a risk to cardholder data
- **PCI DSS v4.0 requirement:** Requirement number and name
- **Affected host(s):** IP or hostname list
- **CVSS score:** Score and base vector

Plugins do not include PCI DSS requirement numbers in their cross-references. Use this DSS v4.0 mapping to categorize all findings by requirement:

| Finding pattern | DSS Req | Requirement name |
|---|---|---|
| Expired or self-signed TLS certificate | 4.2.1 | Use strong cryptography for data-in-transit |
| Weak or deprecated cipher suites (SSLv3, TLS 1.0, RC4, DES, 3DES, EXPORT) | 4.2.1 | Use strong cryptography for data-in-transit |
| Unpatched software with known CVE (high CVSS) | 6.3.3 | All system components protected from known vulnerabilities |
| Unnecessary open network services or ports | 1.3.2 | Restrict inbound traffic to only what is necessary |
| Default or vendor-supplied credentials | 2.2.2 | Vendor defaults managed before installation |
| SQL injection or cross-site scripting | 6.2.4 | Coding practices prevent common vulnerabilities |
| Remote code execution or privilege escalation | 6.3.3 | All system components protected from known vulnerabilities |
| HTTP without HTTPS redirect | 4.2.1 | Use strong cryptography for data-in-transit |
| Missing security patch for OS-level vulnerability | 6.3.3 | All system components protected from known vulnerabilities |

## Step 4 — Remediation priority ranking

Rank findings into three priority levels:

**Priority 1 — Critical path (fix first, blocks attestation):**
Any finding with CVSS ≥ 7.0 that is not a strong dispute candidate. These must be fixed before you can pass. Order by CVSS score descending. For each, provide the specific remediation action (exact version to upgrade to, service to disable, configuration to change) pulled from `plugins_get_plugin_details` remediation text.

**Priority 2 — Attestation blockers with dispute potential:**
CVSS ≥ 4.0 findings where a legitimate dispute or compensating control exists. These block attestation if not addressed, but a successful dispute (accepted by the ASV) removes them from the blocking list. See Step 5 for dispute assessment.

**Priority 3 — Informational or below attestation threshold:**
CVSS < 4.0 findings. These do not block PCI ASV attestation but are real vulnerabilities worth tracking. Present a brief count and a note that they are secondary to the attestation blockers.

**Example user prompts:**
- "Which findings are the most critical to fix?"
- "Give me a prioritized remediation list"
- "What should I fix first to pass my PCI scan?"

## Step 5 — Dispute vs. fix recommendation

For each finding in Priority 1 and Priority 2, provide a clear recommendation: **Dispute** or **Fix**.

**Recommend dispute when one or more of the following is true:**
- The finding is a known scanner artifact on this type of infrastructure (e.g., TLS version negotiation artifact on a load balancer that actually enforces TLS 1.2+; banner version disclosure where the software is fully patched)
- The specific attack vector requires a precondition that is demonstrably absent in this environment (e.g., a finding requires local authenticated access and access is strictly controlled)
- The finding is a theoretical vulnerability with no publicly known exploit and a documented mitigating control is in place

**Recommend fix when:**
- A patch or configuration change is available and the finding reflects a genuinely exploitable condition
- The finding involves weak cryptography (cipher suite, protocol version) on a host that actually terminates cardholder data traffic
- CVSS base score ≥ 9.0 (near-universal recommendation to fix rather than dispute)

For each dispute recommendation, provide:
1. The dispute category (false positive or compensating control)
2. Evidence to collect: what screenshots, architecture diagrams, configuration exports, or version proofs the ASV will expect
3. A narrative framing: one to two sentences suitable for the ASV dispute form

For each fix recommendation, provide the exact remediation step from `plugins_get_plugin_details` plus a time estimate (urgent: under 24 hours for CVSS 9+; high priority: within 7 days for CVSS 7–8.9; standard: within 30 days for CVSS 4–6.9).

**Example user prompts:**
- "Which of these can I dispute?"
- "Should I dispute the SSL/TLS finding or fix it?"
- "What evidence do I need to dispute this finding?"

## MCP tools used

- `mcp__tenable-vpod__scan_list_scans` — list recent scans to find the right one
- `mcp__tenable-vpod__scan_results` — retrieve completed scan findings
- `mcp__tenable-vpod__workbenches_list_assets_with_vulnerabilities` — required to get asset UUIDs before calling `workbenches_get_asset_vulnerabilities`
- `mcp__tenable-vpod__workbenches_get_asset_vulnerabilities` — per-asset vulnerability detail
- `mcp__tenable-vpod__workbenches_get_vulnerability_details` — full vulnerability description
- `mcp__tenable-vpod__workbenches_get_vulnerability_outputs` — raw scanner output for dispute evidence
- `mcp__tenable-vpod__plugins_get_plugin_details` — plugin description, CVSS, remediation text, DSS cross-references

## Known limitations

- **DSS cross-references depend on plugin data.** Tenable's plugins include PCI DSS cross-references for many findings, but not all. The mapping table in Step 3 is a best-effort approximation — your QSA may categorize the same finding under a different requirement.
- **Dispute acceptance is not guaranteed.** Identifying a finding as a dispute candidate and assembling documentation is the first step; the ASV makes the final call on whether the dispute is accepted. This skill cannot predict that outcome.
- **CVSS base score is used throughout.** This skill uses CVSS base score (the standard PCI ASV threshold) rather than temporal or environmental scores. Confirm with your ASV which score they apply.
- **Findings are per-scan.** If you have multiple scans covering different parts of your external scope, run this skill against each one, or use the vulnerability workbench for an aggregate view.
