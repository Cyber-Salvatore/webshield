"""
PDF Report Generator — Phase 5.2
===================================
Generates professional PDF security reports using weasyprint.

Falls back to a minimal HTML-to-PDF approach when weasyprint is unavailable,
so the scanner never crashes due to a missing optional dependency.

Report structure:
  Page 1   — Executive Summary (risk score, severity chart, key findings)
  Page 2+  — Technical Findings (one section per severity)
  Appendix — Remediation Roadmap (sorted by CVSS score)
  Appendix — Raw Request/Response evidence

Usage::
    from webshield.reporters.pdf_reporter import PDFReporter
    path = PDFReporter("./reports").generate(result)

Requirements (optional):
    pip install weasyprint==62.3

If weasyprint is not installed the reporter generates an HTML file that
can be printed to PDF from a browser, and logs a warning.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import warnings
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from .base_reporter import BaseReporter
from ..models.scan_result import ScanResult
from ..models.vulnerability import Severity, Vulnerability
from ..utils.helpers import sanitize_for_html

try:
    import weasyprint as _wp
    _WEASYPRINT_AVAILABLE = True
except ImportError:
    _WEASYPRINT_AVAILABLE = False

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

_SEV_COLORS = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#ca8a04",
    "Low":      "#2563eb",
    "Info":     "#0891b2",
}

_SEV_ICONS = {
    "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "ℹ️",
}


class PDFReporter(BaseReporter):
    """
    Phase 5.2 — PDF Report Generator.

    Generates print-ready PDF via weasyprint if available,
    otherwise saves print-optimised HTML for browser printing.
    """

    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        html_content = self._render_pdf_html(result)

        if _WEASYPRINT_AVAILABLE:
            output_path = self._make_path(result, "pdf", filename)
            try:
                _wp.HTML(string=html_content).write_pdf(str(output_path))
                return str(output_path)
            except Exception as exc:
                warnings.warn(f"weasyprint failed ({exc}); falling back to HTML")

        # Fallback: save as HTML with print CSS
        output_path = self._make_path(result, "pdf.html", filename)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return str(output_path)

    # =========================================================================
    # HTML template (print-optimised, light theme for printing)
    # =========================================================================

    def _render_pdf_html(self, result: ScanResult) -> str:
        risk   = result.risk_score()
        counts = result.severity_counts()
        total  = len(result.vulnerabilities)
        now    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        risk_color = (
            "#dc2626" if risk >= 7 else
            "#ea580c" if risk >= 4 else
            "#ca8a04" if risk >= 2 else "#16a34a"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebShield Security Report — {sanitize_for_html(result.target_url)}</title>
{self._pdf_css(risk_color, risk)}
</head>
<body>

{self._exec_summary(result, risk, risk_color, counts, total, now)}
{self._findings_section(result)}
{self._remediation_appendix(result)}

</body>
</html>"""

    # =========================================================================
    # CSS (light, print-friendly)
    # =========================================================================

    def _pdf_css(self, risk_color: str, risk: float = 0.0) -> str:
        return f"""<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Helvetica Neue', Arial, sans-serif;
        font-size: 10pt; color: #1e293b; line-height: 1.5; }}
h1 {{ font-size: 22pt; font-weight: 800; color: #0f172a; }}
h2 {{ font-size: 13pt; font-weight: 700; color: #0f172a;
      border-bottom: 2px solid #0f172a; padding-bottom: 4px; margin: 18px 0 10px; }}
h3 {{ font-size: 10pt; font-weight: 700; color: #334155; margin: 12px 0 6px; }}
a  {{ color: #2563eb; }}

/* Page layout */
.page {{ width: 100%; max-width: 760px; margin: 0 auto; padding: 32px 40px; }}
@page {{ size: A4; margin: 20mm; }}
.page-break {{ page-break-before: always; }}

/* Header band */
.report-header {{ background: #0f172a; color: white; padding: 24px 32px;
                   margin-bottom: 28px; border-radius: 6px; }}
.report-header .logo {{ font-size: 20pt; font-weight: 800; color: #38bdf8; }}
.report-header .sub  {{ font-size: 9pt; color: #94a3b8; margin-top: 4px; }}

/* Risk score */
.risk-box {{ display: flex; align-items: center; gap: 24px;
             border: 2px solid {risk_color}; border-radius: 8px;
             padding: 16px 24px; margin: 20px 0; background: #f8fafc; }}
.risk-num {{ font-size: 36pt; font-weight: 900; color: {risk_color}; line-height: 1; }}
.risk-label {{ font-size: 8pt; color: #64748b; text-transform: uppercase;
               letter-spacing: .08em; }}
.risk-bar {{ flex: 1; height: 10px; background: #e2e8f0; border-radius: 5px; overflow: hidden; }}
.risk-fill {{ height: 100%; width: {min(risk*10, 100):.1f}%;
              background: linear-gradient(90deg, #16a34a, #ca8a04, #dc2626); }}

/* Summary grid */
.summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 16px 0; }}
.sev-cell {{ text-align: center; padding: 12px 8px;
             border-radius: 6px; border: 1px solid #e2e8f0; }}
.sev-count {{ font-size: 20pt; font-weight: 800; }}
.sev-label {{ font-size: 7.5pt; color: #64748b; text-transform: uppercase;
              letter-spacing: .06em; margin-top: 2px; }}

/* Stats table */
table {{ width: 100%; border-collapse: collapse; font-size: 9pt; margin: 8px 0 16px; }}
th {{ background: #f1f5f9; padding: 7px 10px; text-align: left;
      font-size: 8pt; text-transform: uppercase; letter-spacing: .06em;
      border-bottom: 2px solid #e2e8f0; }}
td {{ padding: 7px 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
tr:nth-child(even) td {{ background: #f8fafc; }}

/* Finding cards */
.finding {{ border: 1px solid #e2e8f0; border-radius: 6px; margin: 12px 0;
            overflow: hidden; page-break-inside: avoid; }}
.finding-header {{ padding: 10px 14px; display: flex;
                   justify-content: space-between; align-items: center; }}
.finding-title {{ font-weight: 700; font-size: 10pt; }}
.finding-body {{ padding: 10px 14px; border-top: 1px solid #e2e8f0;
                 font-size: 9pt; background: #fafafa; }}
.label {{ font-size: 7.5pt; font-weight: 700; color: #64748b;
          text-transform: uppercase; letter-spacing: .06em; margin: 8px 0 2px; }}
.code {{ font-family: 'Courier New', monospace; background: #1e293b; color: #a5f3fc;
         padding: 6px 10px; border-radius: 4px; font-size: 8pt;
         word-break: break-all; white-space: pre-wrap; }}
.badge {{ padding: 2px 8px; border-radius: 20px; font-size: 7.5pt;
          font-weight: 700; text-transform: uppercase; }}
.tag {{ display: inline-block; background: #f1f5f9; color: #475569;
        padding: 1px 6px; border-radius: 3px; font-size: 7.5pt;
        margin: 1px 2px; }}
.remediation {{ color: #166534; font-size: 9pt; margin-top: 6px; }}

/* Remediation roadmap */
.roadmap-item {{ padding: 8px 12px; border-left: 4px solid #e2e8f0;
                 margin: 8px 0; page-break-inside: avoid; }}

/* Footer */
.footer {{ text-align: center; color: #94a3b8; font-size: 8pt;
           border-top: 1px solid #e2e8f0; padding-top: 12px; margin-top: 24px; }}
</style>"""

    # =========================================================================
    # Executive Summary
    # =========================================================================

    def _exec_summary(
        self,
        result: ScanResult,
        risk: float,
        risk_color: str,
        counts: Dict[str, int],
        total: int,
        now: str,
    ) -> str:
        stats = result.stats

        sev_cells = "".join(
            f'<div class="sev-cell">'
            f'<div class="sev-count" style="color:{_SEV_COLORS.get(s,"#94a3b8")};">{counts.get(s,0)}</div>'
            f'<div class="sev-label">{_SEV_ICONS.get(s,"•")} {s}</div>'
            f'</div>'
            for s in _SEVERITY_ORDER
        )

        # Top 3 critical/high findings summary
        top_vulns = [
            v for v in result.vulnerabilities
            if v.severity.value in ("Critical", "High")
        ][:5]
        top_rows = "".join(
            f'<tr><td><span class="badge" style="background:{_SEV_COLORS.get(v.severity.value,"#94a3b8")}22;'
            f'color:{_SEV_COLORS.get(v.severity.value,"#94a3b8")};">{v.severity.value}</span></td>'
            f'<td>{sanitize_for_html(v.title[:60])}</td>'
            f'<td>{sanitize_for_html(v.vuln_type.value)}</td>'
            f'<td>{f"{v.cvss_score():.1f}" if v.cvss_score() is not None else "N/A"}</td></tr>'
            for v in top_vulns
        )

        stat_rows = "".join(
            f"<tr><td style='color:#64748b;'>{k}</td><td>{sanitize_for_html(v)}</td></tr>"
            for k, v in [
                ("Target",        result.target_url),
                ("Scan Profile",  result.scan_profile),
                ("Scan Date",     now),
                ("Duration",      f"{stats.duration_seconds:.1f}s"),
                ("URLs Crawled",  str(stats.urls_crawled)),
                ("Requests Sent", str(stats.requests_sent)),
                ("Total Findings",str(total)),
                ("Risk Score",    f"{risk:.1f} / 10"),
            ]
        )

        return f"""<div class="page">
  <div class="report-header">
    <div class="logo">WebShield</div>
    <div class="sub">Security Assessment Report — {sanitize_for_html(result.target_url)}</div>
    <div class="sub" style="margin-top:8px;">Generated: {now} | Scan ID: {sanitize_for_html(result.scan_id)}</div>
  </div>

  <h2>Executive Summary</h2>

  <div class="risk-box">
    <div>
      <div class="risk-label">Overall Risk Score</div>
      <div class="risk-num">{risk:.1f}</div>
      <div class="risk-label">/ 10</div>
    </div>
    <div style="flex:1;">
      <div class="risk-bar"><div class="risk-fill"></div></div>
      <div style="font-size:8pt;color:#64748b;margin-top:4px;">
        {total} total finding{'s' if total != 1 else ''} across {len(result.unique_vuln_types())} vulnerability type{'s' if len(result.unique_vuln_types()) != 1 else ''}
      </div>
    </div>
  </div>

  <div class="summary-grid">{sev_cells}</div>

  <h2>Scan Information</h2>
  <table><tbody>{stat_rows}</tbody></table>

  {'<h2>Critical &amp; High Findings Summary</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Type</th><th>CVSS</th></tr></thead><tbody>' + top_rows + '</tbody></table>' if top_rows else ''}

  <div class="footer">WebShield Security Scanner — For authorized security research only | CVSS v3.1 | OWASP Top 10 2021</div>
</div>"""

    # =========================================================================
    # Findings section
    # =========================================================================

    def _findings_section(self, result: ScanResult) -> str:
        vulns_by_sev = result.vulns_by_severity()
        html = '<div class="page page-break"><h2>Technical Findings</h2>'

        for sev in _SEVERITY_ORDER:
            vulns = vulns_by_sev.get(sev, [])
            if not vulns:
                continue
            color = _SEV_COLORS.get(sev, "#94a3b8")
            icon  = _SEV_ICONS.get(sev, "•")
            html += f'<h3 style="color:{color};">{icon} {sev} Severity ({len(vulns)})</h3>'

            for v in vulns:
                score = f"{v.cvss_score():.1f}" if v.cvss_score() is not None else "N/A"
                html += f"""<div class="finding">
  <div class="finding-header" style="background:{color}18;">
    <span class="finding-title">{sanitize_for_html(v.title)}</span>
    <div>
      <span class="badge" style="background:{color}22;color:{color};">{sev}</span>
      <span class="tag">CVSS {score}</span>
      <span class="tag">{sanitize_for_html(v.vuln_type.value)}</span>
    </div>
  </div>
  <div class="finding-body">
    <div class="label">Description</div>
    <div>{sanitize_for_html(v.description[:400])}</div>

    <div class="label">URL</div>
    <div class="code">{sanitize_for_html(v.url[:120])}</div>

    {"<div class='label'>Parameter</div><div><span class='tag'>" + sanitize_for_html(v.parameter) + "</span></div>" if v.parameter else ""}
    {"<div class='label'>Payload</div><div class='code'>" + sanitize_for_html(str(v.payload)[:200]) + "</div>" if v.payload else ""}
    {"<div class='label'>Evidence</div><div class='code'>" + sanitize_for_html(str(v.evidence)[:200]) + "</div>" if v.evidence else ""}

    <div class="label">Remediation</div>
    <div class="remediation">{sanitize_for_html(v.remediation[:300])}</div>

    <div style="margin-top:8px;font-size:8pt;color:#94a3b8;">
      {sanitize_for_html(v.cwe_id or "")}
      {" | " + sanitize_for_html(v.owasp_category[:60]) if v.owasp_category else ""}
      {" | Confidence: " + sanitize_for_html(v.confidence)}
      {" | ID: " + v.vuln_id}
    </div>
  </div>
</div>"""

        html += "</div>"
        return html

    # =========================================================================
    # Remediation roadmap appendix
    # =========================================================================

    def _remediation_appendix(self, result: ScanResult) -> str:
        if not result.vulnerabilities:
            return ""

        # Sort by CVSS score descending, then severity
        sev_order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: (
                sev_order.get(v.severity.value, 99),
                -(v.cvss_score() or 0),
            ),
        )

        items = ""
        for i, v in enumerate(sorted_vulns[:30], 1):
            color = _SEV_COLORS.get(v.severity.value, "#94a3b8")
            items += f"""<div class="roadmap-item" style="border-left-color:{color};">
  <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
    <strong>{i}. {sanitize_for_html(v.title[:70])}</strong>
    <span class="tag">CVSS {f"{v.cvss_score():.1f}" if v.cvss_score() else "N/A"}</span>
  </div>
  <div style="font-size:9pt;color:#166534;">{sanitize_for_html(v.remediation[:200])}</div>
  <div style="font-size:8pt;color:#94a3b8;margin-top:2px;">
    {sanitize_for_html(v.url[:80])}
    {" | " + sanitize_for_html(v.cwe_id) if v.cwe_id else ""}
  </div>
</div>"""

        return f"""<div class="page page-break">
  <h2>Remediation Roadmap</h2>
  <p style="font-size:9pt;color:#64748b;margin-bottom:14px;">
    Findings sorted by risk priority (Critical → Info, then CVSS score).
    Address Critical and High items first.
  </p>
  {items}
  <div class="footer">WebShield — Remediation Roadmap — {datetime.utcnow().strftime("%Y-%m-%d")}</div>
</div>"""
