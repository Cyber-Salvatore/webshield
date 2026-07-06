"""
Markdown Report Generator — WebShield
Produces a clean, CI-friendly Markdown report suitable for:
  • GitHub/GitLab PR comments
  • Slack/Teams notifications
  • Jira/Confluence embedding
  • Terminal readability (pandoc → plain text)
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from .base_reporter import BaseReporter
from ..models.scan_result import ScanResult
from ..models.vulnerability import Vulnerability, Severity

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

_SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Info": "ℹ️",
}

_SEVERITY_BADGE = {
    "Critical": "![Critical](https://img.shields.io/badge/severity-Critical-red)",
    "High": "![High](https://img.shields.io/badge/severity-High-orange)",
    "Medium": "![Medium](https://img.shields.io/badge/severity-Medium-yellow)",
    "Low": "![Low](https://img.shields.io/badge/severity-Low-blue)",
    "Info": "![Info](https://img.shields.io/badge/severity-Info-lightgrey)",
}


class MarkdownReporter(BaseReporter):
    """Generates a Markdown (.md) vulnerability report."""

    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        output_path = self._make_path(result, "md", filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = self._render(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return str(output_path)

    def _render(self, result: ScanResult) -> str:
        counts = result.severity_counts()
        total = len(result.vulnerabilities)
        risk = result.risk_score()
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        vulns_by_sev: Dict[str, List[Vulnerability]] = result.vulns_by_severity()

        lines: List[str] = []

        # ── Header ────────────────────────────────────────────────────────
        lines.append("# 🛡️ WebShield Security Scan Report\n")
        lines.append(f"**Target:** `{result.target_url}`  ")
        lines.append(f"**Scan ID:** `{result.scan_id}`  ")
        lines.append(f"**Profile:** `{result.scan_profile}`  ")
        lines.append(f"**Generated:** {generated_at}  ")
        lines.append(f"**Duration:** {result.stats.duration_seconds:.1f}s  ")
        lines.append("")

        # ── Risk Score ────────────────────────────────────────────────────
        risk_bar = self._risk_bar(risk)
        lines.append(f"## Risk Score: {risk:.1f}/10 {risk_bar}")
        lines.append("")

        # ── Summary Table ─────────────────────────────────────────────────
        lines.append("## Findings Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in _SEVERITY_ORDER:
            count = counts.get(sev, 0)
            if count > 0:
                emoji = _SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} **{sev}** | {count} |")
        lines.append(f"| **Total** | **{total}** |")
        lines.append("")

        # ── Attack Chains & Contextual Risk (Phase 3) ─────────────────────
        self._render_chains(lines, result)

        # ── Compliance & Remediation (Phase 3) ────────────────────────────
        self._render_compliance(lines, result)

        # ── Scan Statistics ───────────────────────────────────────────────
        lines.append("## Scan Statistics\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| URLs Crawled | {result.stats.urls_crawled} |")
        lines.append(f"| Endpoints Discovered | {result.stats.endpoints_discovered} |")
        lines.append(f"| Endpoints Tested | {result.stats.endpoints_tested} |")
        lines.append(f"| Requests Sent | {result.stats.requests_sent} |")
        if result.stats.js_files_analyzed:
            lines.append(f"| JS Files Analyzed | {result.stats.js_files_analyzed} |")
        if result.stats.openapi_endpoints_found:
            lines.append(f"| OpenAPI Endpoints | {result.stats.openapi_endpoints_found} |")
        if result.stats.websocket_endpoints_found:
            lines.append(f"| WebSocket Endpoints | {result.stats.websocket_endpoints_found} |")
        lines.append("")

        # ── Vulnerability Details ─────────────────────────────────────────
        if total == 0:
            lines.append("## ✅ No Vulnerabilities Found\n")
            lines.append("> The scan completed without detecting any security issues.")
            lines.append("")
        else:
            lines.append("## Vulnerability Details\n")
            for sev in _SEVERITY_ORDER:
                vulns = vulns_by_sev.get(sev, [])
                if not vulns:
                    continue
                emoji = _SEVERITY_EMOJI.get(sev, "")
                lines.append(f"### {emoji} {sev} ({len(vulns)})\n")

                for i, vuln in enumerate(vulns, 1):
                    lines.append(f"#### {i}. {vuln.title}")
                    lines.append("")
                    lines.append(f"| Field | Value |")
                    lines.append(f"|-------|-------|")
                    lines.append(f"| **URL** | `{vuln.url}` |")
                    lines.append(f"| **Method** | `{vuln.method}` |")
                    if vuln.parameter:
                        lines.append(f"| **Parameter** | `{vuln.parameter}` |")
                    if vuln.payload:
                        payload_escaped = vuln.payload.replace("|", "\\|").replace("`", "'")
                        lines.append(f"| **Payload** | `{payload_escaped[:120]}` |")
                    cvss_val = vuln.cvss_score()
                    if cvss_val is not None:
                        lines.append(f"| **CVSS Score** | `{cvss_val:.1f}` |")
                    if vuln.cwe_id:
                        lines.append(f"| **CWE** | [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-','')}.html) |")
                    if vuln.owasp_category:
                        lines.append(f"| **OWASP** | {vuln.owasp_category} |")
                    lines.append(f"| **Confidence** | {vuln.confidence} |")
                    lines.append("")

                    if vuln.description:
                        lines.append(f"**Description:** {vuln.description[:500]}")
                        lines.append("")

                    if vuln.evidence:
                        lines.append(f"**Evidence:**")
                        lines.append(f"```")
                        lines.append(vuln.evidence[:300])
                        lines.append(f"```")
                        lines.append("")

                    if vuln.remediation:
                        lines.append(f"**Remediation:** {vuln.remediation}")
                        lines.append("")

                    if vuln.references:
                        lines.append(f"**References:**")
                        for ref in vuln.references[:3]:
                            lines.append(f"- {ref}")
                        lines.append("")

                    lines.append("---")
                    lines.append("")

        # ── Footer ────────────────────────────────────────────────────────
        lines.append("> ⚠️ **Legal Notice:** This report is for authorized security testing only.")
        lines.append(f"> Generated by [WebShield](https://github.com/AlaaElBadawi/webshield) v3.1.0")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _render_chains(lines: List[str], result: ScanResult) -> None:
        """Render the correlation / attack-chain and contextual-risk section."""
        corr = result.metadata.get("correlation") or {}
        risk = result.metadata.get("risk_analysis") or {}
        chains = corr.get("chains", [])
        if not chains and not risk:
            return

        if risk:
            lines.append("## Contextual Risk Analysis\n")
            lines.append(
                f"**Aggregate contextual risk:** {risk.get('aggregate_risk', 0.0):.1f}/10 "
                f"(**{risk.get('aggregate_level', 'Info')}**) — {risk.get('method', '')}"
            )
            for note in risk.get("notes", []):
                lines.append(f"> {note}")
            lines.append("")

        if chains:
            lines.append(f"## 🔗 Attack Chains ({len(chains)})\n")
            for c in chains:
                tag = "POTENTIAL" if c.get("is_potential") else "CONFIRMED"
                lines.append(f"### {c.get('name','')} `[{tag}]`")
                lines.append("")
                lines.append(
                    f"- **Severity:** {c.get('severity','')} "
                    f"· **Kill-chain stage:** {c.get('kill_chain_stage','')} "
                    f"· **Combined risk:** {c.get('combined_risk',0)}/10 "
                    f"· **Confidence:** {c.get('confidence','')}"
                )
                lines.append(f"- **Host:** `{c.get('host','')}`")
                lines.append(f"- **Impact:** {c.get('impact','')}")
                members = c.get("member_titles", [])
                if members:
                    lines.append(f"- **Chained findings:**")
                    for m in members:
                        lines.append(f"  - {m}")
                lines.append("")
            lines.append("---")
            lines.append("")

    @staticmethod
    def _render_compliance(lines: List[str], result: ScanResult) -> None:
        """Render compliance-standard rollups and remediation guidance."""
        comp = result.metadata.get("compliance") or {}
        rem = result.metadata.get("remediation") or {}

        summary = comp.get("summary", {})
        if summary:
            lines.append("## Compliance Impact\n")
            lines.append("| Standard | Findings |")
            lines.append("|----------|----------|")
            for name, cnt in summary.items():
                lines.append(f"| {name} | {cnt} |")
            lines.append("")

        guidance = rem.get("guidance", [])
        if guidance:
            lang = rem.get("detected_language")
            suffix = f" (examples tailored for `{lang}`)" if lang else ""
            lines.append(f"## Remediation Guidance{suffix}\n")
            seen = set()
            for g in guidance:
                vt = g.get("vuln_type")
                if vt in seen:
                    continue
                seen.add(vt)
                lines.append(f"### {vt} — _{g.get('priority','Planned')}_")
                lines.append("")
                lines.append(g.get("summary", ""))
                lines.append("")
                if g.get("steps"):
                    lines.append("**Fix steps:**")
                    for s in g["steps"]:
                        lines.append(f"1. {s}")
                    lines.append("")
                if g.get("common_mistakes"):
                    lines.append("**Common mistakes:**")
                    for s in g["common_mistakes"]:
                        lines.append(f"- {s}")
                    lines.append("")
                if g.get("verification"):
                    lines.append("**Verify the fix:**")
                    for s in g["verification"]:
                        lines.append(f"- {s}")
                    lines.append("")
                if g.get("code_example"):
                    lines.append(f"```{g.get('code_language','') if g.get('code_language') != 'generic' else ''}")
                    lines.append(g["code_example"])
                    lines.append("```")
                    lines.append("")
            lines.append("---")
            lines.append("")

    @staticmethod
    def _risk_bar(risk: float) -> str:
        """Generate a text-based risk indicator."""
        if risk >= 9:
            return "🔴🔴🔴🔴🔴 **CRITICAL RISK**"
        elif risk >= 7:
            return "🔴🔴🔴🔴⬜ **HIGH RISK**"
        elif risk >= 4:
            return "🟠🟠🟠⬜⬜ **MEDIUM RISK**"
        elif risk >= 2:
            return "🟡🟡⬜⬜⬜ **LOW RISK**"
        else:
            return "🟢⬜⬜⬜⬜ **MINIMAL RISK**"
