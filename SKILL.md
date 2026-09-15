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

Call `mcp__tenable-vpod__scan_list_scans` to show recent scans if the user doesn't know the ID. Filter to scans with "pci" or "asv" in the name to shorten the list. If the name filter returns no results, fall back to filtering by owner email — look for "pciasv" or "asv" in the owner field. As a second fallback, if you have the attestation's last-modified date, look for scans completed within 7 days of that date. If the scan is still running, tell the user to wait for it to complete before this analysis will be meaningful.

Once a scan is selected, call `mcp__tenable-vpod__scan_results` with that scan_id to retrieve the findings.

First check for PCI verdict plugins in the scan results: plugin 33930 (COMPLIANT) means the scan passed — no failures to explain. Plugin 33929 (NOT COMPLIANT) confirms the scan failed — proceed to analyze individual findings below.

**Scan age:** After identifying the scan, surface the scan date from the results. PCI DSS scan results are valid for 90 days — if this scan is more than 60 days old, flag it prominently before continuing the analysis: "This scan is [N] days old. PCI ASV scan results are only valid for 90 days. You may need to re-scan before your triage work here is actionable." Do not proceed silently past a scan that may already be expired.

**Quarterly trend comparison (offer after surfacing scan age):**

Call `mcp__tenable-vpod__scan_list_scans` and filter for other completed PCI/ASV scans sorted by completion date descending. If a prior scan exists within the last 120 days (one quarter plus a buffer for scheduling slippage), offer to run a trend comparison against it.

For the comparison, compare finding sets by plugin ID + host pair:
- **New findings** (current scan only): newly introduced since last quarter — flag immediately if CVSS ≥ 7.0, as these represent regression.
- **Resolved findings** (prior scan only): confirmed remediations — acknowledge explicitly so the infrastructure team sees credit for work done.
- **Repeat findings** (both scans, same plugin ID + host): systemic, unaddressed issues. Lead the analysis with these — a finding that survived a full quarter without remediation signals a process gap, not just a technical one. Exception: a finding may recur after a previously accepted dispute expires — ASV disputes must be re-submitted each quarterly scan cycle. Before treating a repeat finding as unaddressed, check the attestation portal to confirm whether it was disputed last quarter.

Present the trend summary before Step 2's detailed categorization:
> "Compared to your [prior scan date] scan: **N new** findings, **N resolved**, **N repeat offenders**. Repeat offenders are analyzed first below."

If the prior scan is more than 90 days old, note the compliance gap (see also: scan cadence check).

**Known limitation — scope changes:** Scope changes between scans (e.g., hostname vs. IP address for the same host, or a CIDR range that now includes additional hosts) can cause the comparison to misclassify same-host findings as "new" or "resolved." Review apparent regressions in context of any scope changes.

**Example user prompts:**
- "Explain my PCI scan failures"
- "Analyze my most recent PCI scan"
- "I don't understand the failures from my ASV scan last week"
- "How did this scan compare to last quarter?"
- "Which findings have we seen before?"

## Step 2 — Categorize findings

**What counts as a passing scan:** A PCI ASV scan passes only when ALL findings with CVSS ≥ 4.0 are either resolved or have an accepted dispute on file with the ASV. Plugin 33930 (COMPLIANT) in the results indicates the scan passed; plugin 33929 (NOT COMPLIANT) indicates failure. A scan with any unresolved CVSS ≥ 4.0 finding cannot receive a passing attestation even if compensating controls exist — compensating controls require a separate Attestation of Compliance process with a QSA, not just the ASV scanner.

From `mcp__tenable-vpod__scan_results`, group findings by severity:
- **Critical / High (CVSS 7.0–10.0):** block attestation; must be remediated or successfully disputed
- **Medium (CVSS 4.0–6.9):** block attestation; must be remediated or successfully disputed
- **Low (CVSS 0.1–3.9):** do not block PCI ASV attestation
- **Informational (CVSS 0.0):** do not block attestation

Note: scan_results returns integer severity levels (0=info through 4=critical), not CVSS base scores. Call `mcp__tenable-vpod__plugins_get_plugin_details` for each severity >= 2 finding to retrieve the CVSS base score for accurate PCI threshold evaluation.

For each critical, high, or medium finding, call `mcp__tenable-vpod__plugins_get_plugin_details` to retrieve the full plugin description, CVSS score, CVEs, and solution text.

For findings where the initial scan_results data is insufficient to assess dispute viability, call `mcp__tenable-vpod__workbenches_get_vulnerability_outputs` to get the raw scanner output — useful for confirming whether a TLS finding is a real cipher-suite weakness or a scanner artifact.

Note: workbenches tools aggregate data across all scans (not just the one you selected). For PCI attestation analysis, use scan_results and scan_host_details for the specific scan under review. Workbench tools are useful for cross-scan trending but may include findings from other scan targets.

**Truncation warning:** The workbench vulnerability listing caps at 5,000 results. If the returned count equals exactly 5,000, the list is likely truncated and some blocking findings may be missing. Note this explicitly in the analysis output and recommend that the user filter by plugin family to get complete counts for each pattern cluster.

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
| End-of-Life / Unsupported Software | 6.3.3 + 12.3.4 | All system components protected from known vulnerabilities; hardware and software reviewed annually for continued support |

Note: Unsupported software cannot pass an ASV scan regardless of compensating controls — the only valid remediation path is upgrade or replacement.

## Step 3.5 — Remediation leverage calculation

Before presenting priority rankings, calculate which remediation actions have the highest cross-host impact — "fix this one thing, clear N host-findings." This step produces the ranked remediation roadmap that appears at the top of the Step 4 output and (if requested) the HTML report.

**Algorithm:**

For each unique normalized solution text from `plugins_get_plugin_details` (strip version numbers from solution text, normalize whitespace), compute:
- **Hosts affected** — count of distinct hosts with at least one finding that this solution resolves
- **Findings cleared** — total finding instances resolved across all affected hosts
- **CVSS max** — highest CVSS base score among all findings in the group
- **KEV** — whether any CVE in the group appears in the CISA Known Exploited Vulnerabilities catalog (check plugin CVE list against KEV if available; otherwise mark as Unknown)

**Assign one effort tier per solution group:**

| Tier | Description |
|---|---|
| **Config** | No software change required — firewall rule, TLS protocol setting, cipher suite configuration change |
| **Patch** | OS or application update within the same major version; KB rollup or vendor patch |
| **Version Upgrade** | Major version change within supported lifecycle — e.g., Tomcat 9.0.x to 9.0.latest, Apache 2.4.x to current 2.4 branch |
| **Major Upgrade** | Version jump that requires application code changes or migration — e.g., Tomcat 9 to 10 (javax.* to jakarta.* namespace break), PHP 7 to 8 |
| **Decommission** | EOL OS or software with no supported upgrade path; the asset must be retired |

**Sort order:** CISA KEV entries first, then by (hosts × findings) descending, then CVSS max descending.

**Output format:** a ranked table with these columns:

| Rank | Action | Affected Hosts | Findings Cleared | CVSS Max | Effort | KEV? |
|---|---|---|---|---|---|---|

**Important callouts to include with this output:**

- **KB rollup grouping:** When multiple plugins share a single Microsoft KB rollup or vendor update bundle (common pattern: one Windows cumulative update resolves 50–150+ plugin IDs), group them under that single KB or update reference — do not list them as separate remediations. The "Findings Cleared" count for that row should reflect the full bundle.
- **EOL assets:** End-of-life operating systems must be framed as infrastructure projects, not patch tickets. Include the asset owner (if known from scan metadata) and ask the customer for an expected decommission timeline. An EOL system that cannot be upgraded within the attestation cycle should be removed from PCI scope if possible.
- **Version targets:** "Upgrade to a currently supported release" without a specific target version means you must check the vendor's current supported release list before presenting a remediation action. Do not guess version numbers — state that the customer should verify the current stable release from the vendor.
- **ESU patches do not satisfy the ASV scanner.** Microsoft Extended Security Updates (ESU) and similar paid lifecycle extension programs deliver security patches, but the Tenable PCI ASV scanner still flags the OS as unsupported because the OS version itself is EOL. ESU is not a PCI-compliant remediation — the OS must be upgraded or the asset removed from scope.
- **Tomcat 9 to 10 is a Major Upgrade, not a Version Upgrade.** The javax.* to jakarta.* namespace change in Tomcat 10 requires application code changes. Do not classify this as a routine within-lifecycle patch.

## Step 4 — Remediation priority ranking

> **Start Here — triage for automatic scan failures first.** Before reviewing CVSS rankings, check for findings with any of these plugin IDs: **10409** (SubSeven trojan), **106629** (WinShell backdoor), **87501** (JSP webshell), **7137** (cleartext credential leakage). These are automatic scan failures that may indicate active compromise — they must be triaged for signs of breach before any remediation work proceeds. If any of these are present, notify the customer immediately and recommend they engage their incident response process before treating this as a routine patch cycle.

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

**Draft ASV dispute submission:**

When the recommendation is to dispute, generate a complete draft submission — not just an evidence checklist. The user should be able to copy this text directly into their ASV's dispute portal.

The templates below cover the three most common dispute patterns. Adapt the justification to the actual scanner output from `workbenches_get_vulnerability_outputs` — do not paste template language that doesn't match the finding.

For each dispute-recommended finding, produce:

```
Vulnerability: [Plugin name] (Plugin ID: [plugin_id])
Host: [IP or hostname]
Dispute Type: [False Positive | Compensating Control | Acceptable Use]

Justification:
[2–3 sentences specific to this finding type, written in plain English:
 - What the scanner detected and why it triggered
 - Why the finding does not represent actual exploitable risk in this environment
 - The specific evidence that supports this position]

Supporting Evidence to Attach:
- [Specific item 1 — e.g., "Screenshot of load balancer TLS configuration showing TLS 1.2+ enforcement"]
- [Specific item 2 — e.g., "Architecture diagram showing external traffic terminates at the load balancer, not the flagged host"]
```

Tailor the justification language to the finding type:
- **TLS negotiation artifact on load balancer:** "The scanner detected [protocol/cipher] during the handshake negotiation phase, but the load balancer enforces [TLS 1.2/1.3] for all cardholder data traffic. The flagged negotiation artifact occurs at the inspection layer before the actual connection is established and does not reflect the cipher suite applied to cardholder data."
- **Banner version disclosure:** "The [software] version string returned in the service banner indicates [version], but the installed software has been patched to [current patched state] and does not contain the vulnerability associated with this CVE. Version display in banners does not reflect actual patch level."
- **Port serving legitimate function:** "Port [N] is required by [business function] and is listed in the cardholder data environment's approved service inventory. Traffic on this port is restricted to [specific source/destination] via [firewall rule/ACL reference]."
- **Network-unreachable service:** "The scanner detected [vulnerability] on [service] at [port]. While the vulnerability is present, the service is not reachable from an external network position — [network segment/firewall rule] prevents inbound access from outside the CDE perimeter. The finding was triggered because the ASV scanner has a network vantage point within the environment that is not representative of an external attacker's access."

Fill in all bracketed placeholders before submitting — the values in brackets (e.g., `[firewall rule/ACL reference]`, `[specific source/destination]`) cannot be derived from scan data and must be supplied by the customer.

The actual dispute is submitted through the ASV's attestation portal — this draft gives the user the language to paste in.

**Example user prompts:**
- "Which of these can I dispute?"
- "Should I dispute the SSL/TLS finding or fix it?"
- "What evidence do I need to dispute this finding?"

## Step 6 — HTML report (optional)

After completing Steps 1–5, ask the user: "Would you like an HTML report of these findings organized by asset, with specific remediation steps for each? This is useful for sharing with your infrastructure team. (yes/no)"

**If no:** Continue with text output only.

**If yes:** Generate a self-contained HTML file with no external dependencies (all CSS and JavaScript inline). Structure the report as follows:

**Summary header:**
- Total blocking findings (CVSS ≥ 4.0), total assets affected, scan date, scan name

**Remediation roadmap table** (from Step 3.5 output) immediately below the header — this is the "what to fix first" view:
- Columns: Rank | Action | Affected Hosts | Findings Cleared | CVSS Max | Effort | KEV?
- KEV entries highlighted with a red left border

**Per-asset sections** (one collapsible section per hostname/IP, sorted by finding count descending):
- Asset header: hostname or IP, OS (if available from scan metadata), total finding count
- Each finding within the section includes:
  - Severity badge (colored pill: Critical=red, High=orange, Medium=amber, Low=blue)
  - Plugin name and ID
  - What it means in plain English (from Step 3 output)
  - Specific fix action (from `plugins_get_plugin_details` solution text)
  - Effort tier (from Step 3.5 classification)
  - Dispute eligible? (yes/no with one-line rationale)

**Color and brand:**
- Background: white (`#ffffff`)
- Primary text: near-black (`#1e2426`)
- Accent / section borders: Tenable yellow (`#e7ff00`)
- Severity badges: Critical `#d32f2f`, High `#f57c00`, Medium `#f9a825`, Low `#1976d2`
- All CSS and JavaScript must be inline — no `<link>` or `<script src>` tags referencing external URLs

**Save location:** Write the file to the user's current working directory as `pci_remediation_report_<scan_date>.html` where `<scan_date>` is formatted as YYYY-MM-DD from the scan's completion date.

## Re-scan guidance

After remediating findings, the customer must trigger a new scan to confirm the fix. Remind them:

1. Launch a new scan using the same PCI ASV scan template and the same target scope used in the original scan — do not change the scope or policy mid-attestation cycle, as scope changes can invalidate the attestation period.
2. Wait for the scan to complete fully before analyzing results.
3. Check for plugin 33930 (COMPLIANT) in the new results to confirm a passing verdict. If plugin 33929 (NOT COMPLIANT) still appears, repeat Steps 2–5 against the new scan to identify remaining blockers.
4. If the re-scan shows no new CVSS ≥ 4.0 findings and plugin 33930 (COMPLIANT) appears, the scan is clean. The customer can proceed with their attestation process.

## MCP tools used

- `mcp__tenable-vpod__scan_list_scans` — list recent scans to find the right one
- `mcp__tenable-vpod__scan_results` — retrieve completed scan findings
- `mcp__tenable-vpod__workbenches_list_assets_with_vulnerabilities` — required to get asset UUIDs before calling `workbenches_get_asset_vulnerabilities`
- `mcp__tenable-vpod__workbenches_get_vulnerability_outputs` — raw scanner output for dispute evidence
- `mcp__tenable-vpod__plugins_get_plugin_details` — plugin description, CVSS, remediation text, DSS cross-references

## Known limitations

- **DSS cross-references depend on plugin data.** Tenable's plugins include PCI DSS cross-references for many findings, but not all. The mapping table in Step 3 is a best-effort approximation — your QSA may categorize the same finding under a different requirement.
- **Dispute acceptance is not guaranteed.** Identifying a finding as a dispute candidate and assembling documentation is the first step; the ASV makes the final call on whether the dispute is accepted. This skill cannot predict that outcome.
- **CVSS base score is used throughout.** This skill uses CVSS base score (the standard PCI ASV threshold) rather than temporal or environmental scores. Confirm with your ASV which score they apply.
- **Findings are per-scan.** If you have multiple scans covering different parts of your external scope, run this skill against each one, or use the vulnerability workbench for an aggregate view.
