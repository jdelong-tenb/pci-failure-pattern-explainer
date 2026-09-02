# PCI Failure Pattern Explainer

A Claude Code skill that takes a completed PCI ASV scan and produces plain-English explanations of each failure, PCI DSS v4.0 requirement cross-references, prioritized remediation guidance, and dispute-or-fix recommendations — so you know exactly what you need to do to pass attestation.

## What it does

A completed PCI scan returns plugin IDs and CVSS scores, but it does not tell you which failures actually block your quarterly attestation, which are disputable false positives, or what the PCI DSS requirement behind each finding is. This skill:

1. **Categorizes findings** by attestation impact (blocks attestation vs. informational) and severity
2. **Explains each failure** in plain language with the PCI DSS v4.0 requirement it maps to
3. **Ranks remediation priority** into three levels: fix immediately, fix-or-dispute, and informational
4. **Recommends dispute or fix** per finding type with specific evidence guidance for dispute cases

This is a community-built skill, not official Tenable support and not PCI DSS compliance advice. Consult your QSA for authoritative compliance guidance.

## Prerequisites

- Claude Code (or another skill-compatible client) with the `tenable-vpod` MCP server configured and connected.
- A Tenable Vulnerability Management account with API access. Generate an API key pair under **Settings > My Account > API Keys**.
- A completed PCI ASV scan in your account. This skill analyzes an existing completed scan — it does not run the scan itself. See the PCI ASV Scan Copilot skill if you need to run the scan first.

## How to run

1. Copy or symlink this directory into your Claude Code skills path:
   ```bash
   cp -r pci-failure-pattern-explainer ~/.claude/skills/
   ```
2. Ensure the `tenable-vpod` MCP server is configured in your Claude Code environment.
3. In a Claude Code session, say something like:
   - "Explain my PCI scan failures"
   - "Which PCI findings are critical to fix?"
   - "Help me prioritize my PCI remediation"

You can also get a quick text summary of a specific scan's PCI-relevant failures from the command line:
```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
python3 scripts/pci_failure_summary.py <scan_id>
```
Omit the scan_id to list recent PCI-related scans.

## What it produces

For each finding that blocks PCI attestation (CVSS ≥ 4.0), the skill outputs:
- Plain-language description of what the finding is and why it is a risk
- PCI DSS v4.0 requirement cross-reference
- Priority level: critical path fix, dispute candidate, or informational
- Dispute recommendation with evidence checklist, or fix recommendation with specific remediation steps and time estimate

## Known limitations

See [SKILL.md Known Limitations](SKILL.md#known-limitations) — most importantly: this skill gives best-effort DSS cross-references, but your QSA is the authoritative source on how specific findings map to requirements.

## License

MIT — see [LICENSE](LICENSE).
