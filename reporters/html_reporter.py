"""
Interactive HTML Report Generator — Phase 5.1
===============================================
Professional dark-theme report with:
  • Risk score banner with animated gauge
  • Severity distribution cards
  • Scan statistics + coverage metrics (Phase 4.3)
  • Screenshots embedded as base64 (Phase 4.1)
  • Search & filter bar (Phase 4.2)
  • Finding timeline (chronological order)
  • Attack flow visualization (parameter → response)
  • Request/Response replay (copy-to-clipboard)
  • Scan coverage dashboard (endpoints discovered vs tested)
  • Attack surface map (URL tree)
  • Collapsible vuln cards with full details
  • Export button (print / save as PDF)
  • CVSS v3.1 vector display
  • CWE + OWASP links
"""

from __future__ import annotations

import base64
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .base_reporter import BaseReporter
from ..models.scan_result import ScanResult
from ..models.vulnerability import Vulnerability, Severity
from ..utils.helpers import sanitize_for_html


# ---------------------------------------------------------------------------
# Color maps
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "Critical": ("#dc2626", "#3f1212", "#fca5a5"),
    "High":     ("#ea580c", "#3b1a07", "#fdba74"),
    "Medium":   ("#ca8a04", "#38290a", "#fde047"),
    "Low":      ("#2563eb", "#0d2252", "#93c5fd"),
    "Info":     ("#0891b2", "#0b2d38", "#67e8f9"),
}

SEVERITY_ICONS = {
    "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "ℹ️",
}

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


# ---------------------------------------------------------------------------
# HTMLReporter
# ---------------------------------------------------------------------------

class HTMLReporter(BaseReporter):

    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        output_path = self._make_path(result, "html", filename)
        html = self._render_report(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(output_path)

    # =========================================================================
    # Main render
    # =========================================================================

    def _render_report(self, result: ScanResult) -> str:
        self._result = result
        counts = result.severity_counts()
        vulns_by_sev = result.vulns_by_severity()
        total = len(result.vulnerabilities)
        risk = result.risk_score()
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        risk_color = (
            "#dc2626" if risk >= 7 else
            "#ea580c" if risk >= 4 else
            "#ca8a04" if risk >= 2 else "#16a34a"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WebShield — {sanitize_for_html(result.target_url)}</title>
  {self._css(risk_color, risk)}
</head>
<body>

{self._render_header(result, generated_at)}

<div class="container">

  {self._render_risk_banner(risk, risk_color, total)}
  {self._render_nav_tabs()}
  {self._render_tab_overview(result, counts)}
  {self._render_tab_findings(vulns_by_sev, total)}
  {self._render_tab_chains(result)}
  {self._render_tab_compliance(result)}
  {self._render_tab_coverage(result)}
  {self._render_tab_surface(result)}
  {self._render_tab_timeline(result)}

</div>

{self._render_footer()}
{self._js()}
</body>
</html>"""

    # =========================================================================
    # CSS
    # =========================================================================

    def _css(self, risk_color: str, risk: float) -> str:
        bar_width = min(risk * 10, 100)
        return f"""<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
:root {{
  --bg: #0f172a; --surface: #1e293b; --surface2: #263348; --surface3: #0d1b2e;
  --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
  --accent: #38bdf8; --green: #86efac; --red: #f87171;
  --yellow: #fde047; --orange: #fdba74;
  --radius: 8px; --radius-lg: 12px;
}}
body {{ font-family: 'Inter','Segoe UI',system-ui,sans-serif;
        background: var(--bg); color: var(--text); line-height: 1.6; font-size: 14px; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.container {{ max-width: 1280px; margin: 0 auto; padding: 0 24px 48px; }}

/* Header */
header {{ background: linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);
          border-bottom: 2px solid var(--accent); padding: 28px 0 20px; margin-bottom: 28px; }}
header .inner {{ max-width:1280px; margin:0 auto; padding:0 24px;
                  display:flex; justify-content:space-between; align-items:flex-end;
                  flex-wrap:wrap; gap:16px; }}
.logo {{ font-size:1.8rem; font-weight:800; color:var(--accent); letter-spacing:-1px; }}
.logo span {{ color:#e2e8f0; }}
.meta {{ text-align:right; color:var(--muted); font-size:0.8rem; line-height:1.8; }}
.meta strong {{ color:var(--text); }}

/* Risk banner */
.risk-banner {{ display:flex; align-items:center; gap:20px;
                background:var(--surface); border:1px solid var(--border);
                border-radius:var(--radius-lg); padding:20px 28px; margin-bottom:24px; }}
.risk-score {{ font-size:3rem; font-weight:900; color:{risk_color}; line-height:1; min-width:70px; }}
.risk-label {{ font-size:0.7rem; color:var(--muted); text-transform:uppercase;
               letter-spacing:.1em; margin-top:2px; }}
.risk-bar-wrap {{ flex:1; height:14px; background:var(--surface2);
                  border-radius:7px; overflow:hidden; }}
.risk-bar {{ height:100%; width:{bar_width:.1f}%;
             background: linear-gradient(90deg,#16a34a 0%,#ca8a04 50%,#dc2626 100%);
             border-radius:7px; transition:width .8s ease; }}
.stat-pill {{ text-align:center; min-width:80px; }}
.stat-pill .val {{ font-size:1.6rem; font-weight:800; }}

/* Nav tabs */
.tabs {{ display:flex; gap:4px; border-bottom:2px solid var(--border);
         margin-bottom:28px; overflow-x:auto; padding-bottom:0; }}
.tab-btn {{ background:none; border:none; color:var(--muted); cursor:pointer;
            padding:10px 20px; font-size:.85rem; font-weight:600; letter-spacing:.04em;
            text-transform:uppercase; border-bottom:2px solid transparent;
            margin-bottom:-2px; transition:all .15s; white-space:nowrap; }}
.tab-btn:hover {{ color:var(--text); }}
.tab-btn.active {{ color:var(--accent); border-bottom-color:var(--accent); }}
.tab-pane {{ display:none; }}
.tab-pane.active {{ display:block; }}

/* Cards grid */
.cards {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(140px,1fr));
          gap:12px; margin-bottom:28px; }}
.card {{ background:var(--surface); border:1px solid var(--border);
         border-radius:var(--radius); padding:16px; text-align:center;
         transition:transform .15s; }}
.card:hover {{ transform:translateY(-2px); }}
.card-count {{ font-size:2rem; font-weight:800; line-height:1; }}
.card-label {{ font-size:.7rem; color:var(--muted); text-transform:uppercase;
               letter-spacing:.08em; margin-top:4px; }}

/* Section */
.section {{ margin-bottom:36px; }}
.section-title {{ font-size:.95rem; font-weight:700; color:var(--accent);
                  border-bottom:1px solid var(--border); padding-bottom:8px;
                  margin-bottom:16px; text-transform:uppercase; letter-spacing:.05em; }}
table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
th {{ background:var(--surface2); color:var(--muted); padding:9px 14px;
      text-align:left; font-weight:600; text-transform:uppercase;
      font-size:.7rem; letter-spacing:.08em; border-bottom:1px solid var(--border); }}
td {{ padding:9px 14px; border-bottom:1px solid var(--border); vertical-align:top; }}
tr:last-child td {{ border-bottom:none; }}
tr:hover td {{ background:var(--surface2); }}

/* Filter bar */
.filter-bar {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center;
               margin-bottom:16px; padding:14px 16px;
               background:var(--surface); border:1px solid var(--border);
               border-radius:var(--radius); }}
.filter-bar input, .filter-bar select {{
  background:var(--surface2); border:1px solid var(--border); color:var(--text);
  padding:7px 12px; border-radius:6px; font-size:.85rem; outline:none;
  transition:border-color .15s; }}
.filter-bar input {{ flex:1; min-width:180px; }}
.filter-bar input:focus, .filter-bar select:focus {{
  border-color: var(--accent); }}
.filter-bar select {{ cursor:pointer; }}
#wsVisibleCount {{ color:var(--muted); font-size:.8rem; white-space:nowrap; margin-left:auto; }}

/* Vuln cards */
.findings-section {{ margin-bottom:36px; }}
.sev-header {{ display:flex; align-items:center; gap:10px;
               font-size:.9rem; font-weight:700; margin-bottom:10px;
               padding:10px 16px; border-radius:var(--radius); }}
.vuln-card {{ background:var(--surface); border:1px solid var(--border);
              border-radius:var(--radius); margin-bottom:10px;
              overflow:hidden; transition:box-shadow .15s; }}
.vuln-card:hover {{ box-shadow:0 4px 20px rgba(0,0,0,.4); }}
.vuln-header {{ display:flex; justify-content:space-between; align-items:flex-start;
                padding:13px 18px; cursor:pointer; user-select:none; gap:12px; }}
.vuln-title {{ font-weight:600; font-size:.9rem; line-height:1.4; }}
.vuln-meta {{ display:flex; gap:6px; align-items:center; flex-shrink:0; flex-wrap:wrap; }}
.badge {{ padding:2px 9px; border-radius:20px; font-size:.68rem;
          font-weight:700; text-transform:uppercase; letter-spacing:.06em; }}
.cvss-badge {{ background:var(--surface2); color:var(--muted);
               padding:2px 9px; border-radius:20px; font-size:.68rem; font-weight:600; }}
.conf-badge {{ padding:2px 8px; border-radius:20px; font-size:.65rem;
               font-weight:600; border:1px solid var(--border); color:var(--muted); }}
.vuln-body {{ padding:0 18px 16px; border-top:1px solid var(--border); display:none; }}
.vuln-body.open {{ display:block; }}
.vuln-field {{ margin-top:12px; }}
.vuln-field-label {{ font-size:.68rem; font-weight:700; color:var(--muted);
                     text-transform:uppercase; letter-spacing:.08em; margin-bottom:4px; }}
.code {{ font-family:'Fira Code','Consolas',monospace; background:var(--surface3);
         border:1px solid var(--border); border-radius:4px; padding:8px 12px;
         font-size:.78rem; white-space:pre-wrap; word-break:break-all;
         color:#a5f3fc; overflow-x:auto; max-height:220px; overflow-y:auto; }}
.code-replay {{ position:relative; }}
.copy-btn {{ position:absolute; top:6px; right:6px; background:var(--surface2);
             border:1px solid var(--border); color:var(--muted); cursor:pointer;
             padding:3px 8px; border-radius:4px; font-size:.68rem; transition:all .15s; }}
.copy-btn:hover {{ background:var(--accent); color:#0f172a; border-color:var(--accent); }}
.tag {{ display:inline-block; background:var(--surface2); color:var(--muted);
        padding:2px 8px; border-radius:4px; font-size:.7rem; margin:2px 2px 2px 0; }}
.ref-list {{ list-style:none; margin-top:4px; }}
.ref-list li::before {{ content:"→ "; color:var(--accent); }}
.ref-list li {{ margin-bottom:2px; font-size:.82rem; }}

/* Timeline */
.timeline {{ position:relative; padding-left:28px; }}
.timeline::before {{ content:""; position:absolute; left:10px; top:0; bottom:0;
                      width:2px; background:var(--border); }}
.tl-item {{ position:relative; margin-bottom:14px; }}
.tl-dot {{ position:absolute; left:-22px; top:4px; width:12px; height:12px;
           border-radius:50%; border:2px solid var(--bg); }}
.tl-card {{ background:var(--surface); border:1px solid var(--border);
            border-radius:var(--radius); padding:10px 14px; }}
.tl-time {{ font-size:.7rem; color:var(--muted); margin-bottom:3px; }}
.tl-title {{ font-size:.85rem; font-weight:600; }}
.tl-meta {{ font-size:.72rem; color:var(--muted); margin-top:2px; }}

/* Coverage bars */
.cov-bar-wrap {{ background:var(--surface2); border-radius:6px;
                 overflow:hidden; height:12px; flex:1; }}
.cov-bar {{ height:100%; border-radius:6px; transition:width .6s; }}
.cov-row {{ display:flex; align-items:center; gap:12px; margin-bottom:10px; }}
.cov-label {{ width:180px; font-size:.8rem; color:var(--muted); text-align:right;
              flex-shrink:0; }}
.cov-pct {{ width:48px; text-align:right; font-size:.8rem; font-weight:700; flex-shrink:0; }}

/* Attack surface tree */
.tree {{ font-family:'Fira Code','Consolas',monospace; font-size:.78rem;
         background:var(--surface3); border:1px solid var(--border);
         border-radius:var(--radius); padding:16px; overflow-x:auto;
         max-height:500px; overflow-y:auto; }}
.tree-node {{ padding:2px 0; }}
.tree-path {{ color:#a5f3fc; }}
.tree-vuln {{ color:#f87171; font-size:.7rem; margin-left:8px; }}
.tree-method {{ color:#fde047; margin-right:6px; }}

/* Empty */
.empty {{ text-align:center; padding:48px 24px; color:var(--muted); }}
.empty-icon {{ font-size:3rem; margin-bottom:12px; }}

/* Print / Export */
@media print {{
  header {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .tabs, .filter-bar, .copy-btn {{ display:none !important; }}
  .tab-pane {{ display:block !important; }}
  .vuln-body {{ display:block !important; }}
}}

/* Footer */
footer {{ border-top:1px solid var(--border); padding:20px 0;
          text-align:center; color:var(--muted); font-size:.76rem;
          margin-top:48px; }}
</style>"""

    # =========================================================================
    # Header
    # =========================================================================

    def _render_header(self, result: ScanResult, generated_at: str) -> str:
        return f"""<header>
  <div class="inner">
    <div>
      <div class="logo">Web<span>Shield</span></div>
      <div style="color:var(--muted);font-size:.8rem;margin-top:4px;">
        Security Assessment Framework — Scan ID: {sanitize_for_html(result.scan_id)}
      </div>
    </div>
    <div class="meta">
      <div><strong>Target:</strong> {sanitize_for_html(result.target_url)}</div>
      <div><strong>Profile:</strong> {sanitize_for_html(result.scan_profile)}</div>
      <div><strong>Generated:</strong> {generated_at}</div>
      <div><strong>Duration:</strong> {result.stats.duration_seconds:.1f}s &nbsp;|&nbsp;
           <strong>Requests:</strong> {result.stats.requests_sent}</div>
    </div>
  </div>
</header>"""

    # =========================================================================
    # Risk banner
    # =========================================================================

    def _render_risk_banner(self, risk: float, risk_color: str, total: int) -> str:
        counts = self._result.severity_counts()
        crits  = counts.get("Critical", 0)
        highs  = counts.get("High", 0)
        return f"""<div class="risk-banner">
  <div>
    <div class="risk-label">Risk Score</div>
    <div class="risk-score">{risk:.1f}</div>
    <div class="risk-label">/ 10</div>
  </div>
  <div class="risk-bar-wrap"><div class="risk-bar"></div></div>
  <div class="stat-pill">
    <div class="val" style="color:#f87171;">{crits}</div>
    <div class="risk-label">Critical</div>
  </div>
  <div class="stat-pill">
    <div class="val" style="color:#fdba74;">{highs}</div>
    <div class="risk-label">High</div>
  </div>
  <div class="stat-pill">
    <div class="val">{total}</div>
    <div class="risk-label">Total</div>
  </div>
  <div>
    <button onclick="window.print()"
            style="background:var(--surface2);border:1px solid var(--border);
                   color:var(--text);padding:8px 16px;border-radius:6px;
                   cursor:pointer;font-size:.8rem;">
      📄 Export / Print
    </button>
  </div>
</div>"""

    # =========================================================================
    # Nav tabs
    # =========================================================================

    def _render_nav_tabs(self) -> str:
        tabs = [
            ("tab-overview",  "📊 Overview"),
            ("tab-findings",  "🔍 Findings"),
            ("tab-chains",    "🔗 Attack Chains"),
            ("tab-compliance","🛡️ Compliance & Fixes"),
            ("tab-coverage",  "📈 Coverage"),
            ("tab-surface",   "🗺️ Attack Surface"),
            ("tab-timeline",  "🕐 Timeline"),
        ]
        btns = "".join(
            f'<button class="tab-btn{" active" if i == 0 else ""}" '
            f'data-tab="{tid}" onclick="switchTab(this)">{label}</button>'
            for i, (tid, label) in enumerate(tabs)
        )
        return f'<div class="tabs">{btns}</div>'

    # =========================================================================
    # Tab: Overview
    # =========================================================================

    def _render_tab_overview(self, result: ScanResult, counts: dict) -> str:
        cards_html = "".join(
            f"""<div class="card" style="border-top:3px solid {SEVERITY_COLORS.get(sev, ('#94a3b8','#1e293b','#334155'))[0]};">
  <div class="card-count" style="color:{SEVERITY_COLORS.get(sev,('#94a3b8','#1e293b','#334155'))[0]};">{counts.get(sev,0)}</div>
  <div class="card-label">{SEVERITY_ICONS.get(sev,'•')} {sev}</div>
</div>"""
            for sev in _SEVERITY_ORDER
        )

        stats = result.stats
        stat_rows = [
            ("URLs Crawled",     str(stats.urls_crawled)),
            ("URLs Scanned",     str(stats.urls_scanned)),
            ("Requests Sent",    str(stats.requests_sent)),
            ("Errors",           str(stats.errors)),
            ("Duration",         f"{stats.duration_seconds:.1f}s"),
            ("Start Time",       stats.start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if stats.start_time else "N/A"),
            ("End Time",         stats.end_time.strftime("%Y-%m-%d %H:%M:%S UTC") if stats.end_time else "N/A"),
            ("Vulnerability Types", ", ".join(result.unique_vuln_types()) or "None"),
        ]
        if stats.js_files_analyzed:
            stat_rows.append(("JS Files Analyzed", str(stats.js_files_analyzed)))
        if stats.openapi_endpoints_found:
            stat_rows.append(("OpenAPI Endpoints", str(stats.openapi_endpoints_found)))
        if stats.websocket_endpoints_found:
            stat_rows.append(("WebSocket Endpoints", str(stats.websocket_endpoints_found)))
        if stats.passive_requests_imported:
            stat_rows.append(("Passive Requests", str(stats.passive_requests_imported)))
        if stats.parameters_tested:
            stat_rows.append(("Parameters Tested", str(stats.parameters_tested)))
        if result.screenshots:
            stat_rows.append(("Screenshots", str(len(result.screenshots))))

        rows_html = "".join(
            f"<tr><td style='color:var(--muted);width:220px;'>{k}</td>"
            f"<td>{sanitize_for_html(v)}</td></tr>"
            for k, v in stat_rows
        )

        # Top 5 vuln types chart (CSS bars)
        type_counts: Dict[str, int] = defaultdict(int)
        for v in result.vulnerabilities:
            type_counts[v.vuln_type.value] += 1
        top5 = sorted(type_counts.items(), key=lambda x: -x[1])[:5]
        max_count = max((c for _, c in top5), default=1)
        type_bars = "".join(
            f"""<div class="cov-row">
  <div class="cov-label">{sanitize_for_html(t[:28])}</div>
  <div class="cov-bar-wrap">
    <div class="cov-bar" style="width:{c/max_count*100:.1f}%;background:#38bdf8;"></div>
  </div>
  <div class="cov-pct">{c}</div>
</div>"""
            for t, c in top5
        ) if top5 else '<div style="color:var(--muted);font-size:.85rem;">No findings</div>'

        return f"""<div id="tab-overview" class="tab-pane active">
  <div class="section">
    <div class="section-title">Severity Distribution</div>
    <div class="cards">{cards_html}</div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:28px;">
    <div class="section" style="margin:0">
      <div class="section-title">Scan Statistics</div>
      <table><tbody>{rows_html}</tbody></table>
    </div>
    <div class="section" style="margin:0">
      <div class="section-title">Top Finding Types</div>
      {type_bars}
    </div>
  </div>
</div>"""

    # =========================================================================
    # Tab: Findings
    # =========================================================================

    def _render_tab_findings(self, vulns_by_sev: dict, total: int) -> str:
        filter_bar = self._render_filter_bar() if total > 0 else ""
        vulns_html = self._render_all_vulns(vulns_by_sev) if total > 0 else self._empty_state()
        return f"""<div id="tab-findings" class="tab-pane">
  {filter_bar}
  {vulns_html}
</div>"""

    # =========================================================================
    # Tab: Attack Chains (Phase 3 correlation + risk analysis)
    # =========================================================================

    def _render_tab_chains(self, result: ScanResult) -> str:
        corr = result.metadata.get("correlation") or {}
        risk = result.metadata.get("risk_analysis") or {}
        chains = corr.get("chains", [])
        groups = corr.get("correlation_groups", [])

        if not chains and not groups and not risk:
            body = self._empty_state()
            return f"""<div id="tab-chains" class="tab-pane">{body}</div>"""

        # Contextual-risk banner
        risk_html = ""
        if risk:
            agg = risk.get("aggregate_risk", 0.0)
            level = risk.get("aggregate_level", "Info")
            color = SEVERITY_COLORS.get(level, ("#94a3b8", "#1e293b", "#334155"))[0]
            notes = "".join(f"<li>{sanitize_for_html(n)}</li>" for n in risk.get("notes", []))
            notes_html = f"<ul style='margin:.5rem 0 0 1.1rem;color:var(--muted);font-size:.85rem;'>{notes}</ul>" if notes else ""
            risk_html = f"""<div class="section">
    <div class="section-title">Contextual Risk (beyond CVSS)</div>
    <div class="card" style="border-top:3px solid {color};">
      <div class="card-count" style="color:{color};">{agg:.1f}<span style="font-size:1rem;color:var(--muted);">/10</span></div>
      <div class="card-label">{sanitize_for_html(level)} — {sanitize_for_html(risk.get('method',''))}</div>
      {notes_html}
    </div>
  </div>"""

        # Attack-chain cards
        if chains:
            chain_cards = "".join(self._render_chain_card(c) for c in chains)
            chains_section = f"""<div class="section">
    <div class="section-title">Attack Chains ({len(chains)})</div>
    {chain_cards}
  </div>"""
        else:
            chains_section = """<div class="section">
    <div class="section-title">Attack Chains</div>
    <div style="color:var(--muted);font-size:.9rem;">No multi-step attack chains correlated from the current findings.</div>
  </div>"""

        # Correlation groups (same endpoint, multiple findings)
        groups_section = ""
        if groups:
            rows = "".join(
                f"""<tr>
  <td>{sanitize_for_html(g.get('method',''))} {sanitize_for_html(g.get('url',''))}</td>
  <td style="text-align:center;">{g.get('count', 0)}</td>
  <td>{sanitize_for_html(', '.join(g.get('vuln_types', [])))}</td>
</tr>"""
                for g in groups
            )
            groups_section = f"""<div class="section">
    <div class="section-title">Correlated Endpoints ({len(groups)})</div>
    <table><thead><tr><th>Endpoint</th><th>Findings</th><th>Types</th></tr></thead>
    <tbody>{rows}</tbody></table>
  </div>"""

        return f"""<div id="tab-chains" class="tab-pane">
  {risk_html}
  {chains_section}
  {groups_section}
</div>"""

    def _render_chain_card(self, c: dict) -> str:
        sev = c.get("severity", "Medium")
        color = SEVERITY_COLORS.get(sev, ("#94a3b8", "#1e293b", "#334155"))[0]
        potential = c.get("is_potential")
        badge = (
            '<span style="font-size:.7rem;padding:2px 8px;border-radius:10px;'
            'background:#334155;color:#cbd5e1;margin-left:8px;">POTENTIAL</span>'
            if potential else
            '<span style="font-size:.7rem;padding:2px 8px;border-radius:10px;'
            'background:#7f1d1d;color:#fecaca;margin-left:8px;">CONFIRMED</span>'
        )
        members = "".join(
            f"<li>{sanitize_for_html(t)}</li>" for t in c.get("member_titles", [])
        )
        refs = "".join(
            f'<a href="{sanitize_for_html(r)}" style="color:#38bdf8;font-size:.8rem;display:block;">{sanitize_for_html(r)}</a>'
            for r in c.get("references", [])
        )
        return f"""<div class="vuln-card" style="border-left:3px solid {color};margin-bottom:14px;">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;">
    <div style="font-weight:600;">{sanitize_for_html(c.get('name',''))}{badge}</div>
    <div style="font-size:.8rem;color:var(--muted);">{sanitize_for_html(c.get('kill_chain_stage',''))} ·
      {sanitize_for_html(sev)} · risk {c.get('combined_risk', 0)}/10 · {sanitize_for_html(c.get('confidence',''))}</div>
  </div>
  <div style="margin-top:.5rem;font-size:.9rem;">{sanitize_for_html(c.get('description',''))}</div>
  <div style="margin-top:.5rem;font-size:.88rem;"><strong>Impact:</strong> {sanitize_for_html(c.get('impact',''))}</div>
  <div style="margin-top:.5rem;font-size:.85rem;color:var(--muted);">Host: {sanitize_for_html(c.get('host',''))}</div>
  <div style="margin-top:.4rem;font-size:.85rem;"><strong>Chained findings:</strong>
    <ul style="margin:.3rem 0 0 1.1rem;">{members}</ul></div>
  {f'<div style="margin-top:.4rem;">{refs}</div>' if refs else ''}
</div>"""

    # =========================================================================
    # Tab: Compliance & Fixes (Phase 3 compliance + remediation)
    # =========================================================================

    def _render_tab_compliance(self, result: ScanResult) -> str:
        comp = result.metadata.get("compliance") or {}
        rem = result.metadata.get("remediation") or {}
        if not comp and not rem:
            return f"""<div id="tab-compliance" class="tab-pane">{self._empty_state()}</div>"""

        # Compliance: per-standard summary + failed controls
        comp_html = ""
        summary = comp.get("summary", {})
        failed = comp.get("standards_failed", {})
        std_names = comp.get("standards", {})
        if summary:
            cards = "".join(
                f"""<div class="card" style="border-top:3px solid #38bdf8;">
  <div class="card-count" style="color:#38bdf8;">{cnt}</div>
  <div class="card-label">{sanitize_for_html(name)}</div>
</div>"""
                for name, cnt in summary.items()
            )
            tables = ""
            for std_key, hits in failed.items():
                if not hits:
                    continue
                rows = "".join(
                    f"""<tr><td>{sanitize_for_html(h.get('control',''))}</td>
  <td style="text-align:center;">{h.get('count',0)}</td></tr>"""
                    for h in hits
                )
                tables += f"""<div class="section">
    <div class="section-title">{sanitize_for_html(std_names.get(std_key, std_key))} — failed controls</div>
    <table><thead><tr><th>Control</th><th>Findings</th></tr></thead><tbody>{rows}</tbody></table>
  </div>"""
            comp_html = f"""<div class="section">
    <div class="section-title">Standards Impacted</div>
    <div class="cards">{cards}</div>
  </div>{tables}"""

        # Remediation: prioritised guidance cards
        rem_html = ""
        guidance = rem.get("guidance", [])
        if guidance:
            lang = rem.get("detected_language")
            lang_note = (f' <span style="color:var(--muted);font-size:.8rem;">'
                         f'(examples tailored for {sanitize_for_html(str(lang))})</span>') if lang else ""
            # de-duplicate guidance by vuln type — one fix card per type
            seen = set()
            cards = ""
            for g in guidance:
                vt = g.get("vuln_type")
                if vt in seen:
                    continue
                seen.add(vt)
                cards += self._render_remediation_card(g)
            rem_html = f"""<div class="section">
    <div class="section-title">Remediation Guidance{lang_note}</div>
    {cards}
  </div>"""

        return f"""<div id="tab-compliance" class="tab-pane">
  {comp_html}
  {rem_html}
</div>"""

    def _render_remediation_card(self, g: dict) -> str:
        prio = g.get("priority", "Planned")
        prio_color = {"Immediate": "#dc2626", "Planned": "#ca8a04", "Backlog": "#2563eb"}.get(prio, "#64748b")
        steps = "".join(f"<li>{sanitize_for_html(s)}</li>" for s in g.get("steps", []))
        practices = "".join(f"<li>{sanitize_for_html(s)}</li>" for s in g.get("best_practices", []))
        mistakes = "".join(f"<li>{sanitize_for_html(s)}</li>" for s in g.get("common_mistakes", []))
        verify = "".join(f"<li>{sanitize_for_html(s)}</li>" for s in g.get("verification", []))
        code = g.get("code_example")
        code_html = ""
        if code:
            code_html = (f'<div style="margin-top:.5rem;"><strong>Example ({sanitize_for_html(str(g.get("code_language","")))}):</strong>'
                         f'<pre style="background:#0b1220;padding:10px;border-radius:6px;overflow-x:auto;'
                         f'font-size:.82rem;">{sanitize_for_html(code)}</pre></div>')
        return f"""<div class="vuln-card" style="border-left:3px solid {prio_color};margin-bottom:14px;">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;">
    <div style="font-weight:600;">{sanitize_for_html(g.get('vuln_type',''))}</div>
    <span style="font-size:.7rem;padding:2px 8px;border-radius:10px;background:{prio_color};color:#fff;">{sanitize_for_html(prio)}</span>
  </div>
  <div style="margin-top:.5rem;font-size:.9rem;">{sanitize_for_html(g.get('summary',''))}</div>
  <div style="margin-top:.5rem;font-size:.85rem;"><strong>Fix steps:</strong><ul style="margin:.3rem 0 0 1.1rem;">{steps}</ul></div>
  {f'<div style="margin-top:.4rem;font-size:.85rem;"><strong>Best practices:</strong><ul style="margin:.3rem 0 0 1.1rem;">{practices}</ul></div>' if practices else ''}
  {f'<div style="margin-top:.4rem;font-size:.85rem;"><strong>Common mistakes:</strong><ul style="margin:.3rem 0 0 1.1rem;">{mistakes}</ul></div>' if mistakes else ''}
  {f'<div style="margin-top:.4rem;font-size:.85rem;"><strong>Verify the fix:</strong><ul style="margin:.3rem 0 0 1.1rem;">{verify}</ul></div>' if verify else ''}
  {code_html}
</div>"""

    def _render_filter_bar(self) -> str:
        types = sorted({v.vuln_type.value for v in self._result.vulnerabilities})
        type_opts = '<option value="all">All Types</option>' + "".join(
            f'<option value="{sanitize_for_html(t)}">{sanitize_for_html(t)}</option>'
            for t in types
        )
        total = len(self._result.vulnerabilities)
        return f"""<div class="filter-bar">
  <input type="text" id="wsSearchInput" placeholder="🔍 Search title, URL, payload, evidence...">
  <select id="wsSeverityFilter">
    <option value="all">All Severities</option>
    <option value="Critical">🔴 Critical</option>
    <option value="High">🟠 High</option>
    <option value="Medium">🟡 Medium</option>
    <option value="Low">🔵 Low</option>
    <option value="Info">ℹ️ Info</option>
  </select>
  <select id="wsTypeFilter">{type_opts}</select>
  <select id="wsConfFilter">
    <option value="all">All Confidence</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
    <option value="Speculative">Speculative</option>
    <option value="Needs">Needs Verification</option>
  </select>
  <button onclick="expandAll()" style="background:var(--surface2);border:1px solid var(--border);
          color:var(--text);padding:6px 12px;border-radius:6px;cursor:pointer;font-size:.78rem;">
    ⬇ Expand All
  </button>
  <button onclick="collapseAll()" style="background:var(--surface2);border:1px solid var(--border);
          color:var(--text);padding:6px 12px;border-radius:6px;cursor:pointer;font-size:.78rem;">
    ⬆ Collapse All
  </button>
  <span id="wsVisibleCount">{total} findings</span>
</div>"""

    def _render_all_vulns(self, vulns_by_sev: dict) -> str:
        html = ""
        for sev in _SEVERITY_ORDER:
            vulns = vulns_by_sev.get(sev, [])
            if not vulns:
                continue
            color, bg, border_color = SEVERITY_COLORS.get(sev, ("#94a3b8", "#1e293b", "#334155"))
            icon = SEVERITY_ICONS.get(sev, "•")

            by_type: Dict[str, List[Vulnerability]] = defaultdict(list)
            for v in vulns:
                by_type[v.vuln_type.value].append(v)

            inner = ""
            for vtype, type_vulns in sorted(by_type.items()):
                if len(by_type) > 1:
                    inner += f'<div style="margin:8px 0 4px;font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;padding-left:2px;">{sanitize_for_html(vtype)} ({len(type_vulns)})</div>'
                inner += "".join(self._render_vuln_card(v, color, bg) for v in type_vulns)

            html += f"""<div class="findings-section">
  <div class="sev-header" style="background:{bg};color:{color};border:1px solid {border_color};">
    <span style="font-size:1.1rem;">{icon}</span>
    <span>{sev} — {len(vulns)} finding{'s' if len(vulns)!=1 else ''}</span>
  </div>
  {inner}
</div>"""
        return html

    def _render_vuln_card(self, v: Vulnerability, color: str, bg: str) -> str:
        score_str  = f"{v.cvss_score():.1f}" if v.cvss_score() is not None else "N/A"
        vector_str = v.cvss.vector_string() if v.cvss else ""
        try:
            path = urlparse(v.url).path or "/"
        except Exception:
            path = v.url[:60]

        fields: List[tuple] = []
        fields.append(("Description",
            f'<div class="vuln-field-value" style="font-size:.85rem;">{sanitize_for_html(v.description)}</div>'))
        fields.append(("URL",
            f'<div class="code" title="{sanitize_for_html(v.url)}">{sanitize_for_html(path)}</div>'))

        if v.parameter:
            fields.append(("Parameter", f'<span class="tag">{sanitize_for_html(v.parameter)}</span>'))
        if v.method:
            fields.append(("Method", f'<span class="tag">{sanitize_for_html(v.method)}</span>'))

        # Attack flow visualization
        if v.payload:
            fields.append(("Attack Flow",
                f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:4px;">'
                f'<span class="tag" style="color:#fde047;">param: {sanitize_for_html(str(v.parameter or ""))}</span>'
                f'<span style="color:var(--muted);">→</span>'
                f'<span class="tag" style="color:#f87171;">inject</span>'
                f'<span style="color:var(--muted);">→</span>'
                f'<span class="tag" style="color:#86efac;">{sanitize_for_html(v.vuln_type.value)}</span>'
                f'</div>'))

        # Payload with replay copy button
        if v.payload:
            payload_safe = sanitize_for_html(str(v.payload)[:600])
            fields.append(("Payload / Request",
                f'<div class="code-replay">'
                f'<button class="copy-btn" onclick="copyText(this)" data-text="{sanitize_for_html(str(v.payload)[:600])}">Copy</button>'
                f'<div class="code">{payload_safe}</div>'
                f'</div>'))

        # Curl reproduction command — lets a human tester replay instantly
        if v.url and v.payload and v.method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            try:
                from urllib.parse import urlparse as _up, urlencode as _ue, parse_qs as _pqs, urlunparse as _uu
                _parsed = _up(v.url)
                _params = _pqs(_parsed.query, keep_blank_values=True)
                _pname = (v.parameter or "").replace("Header: ", "").replace("Cookie: ", "")
                if _pname and _pname in _params and v.method == "GET":
                    _params[_pname] = [str(v.payload)]
                    _repro_url = _uu(_parsed._replace(query=_ue(_params, doseq=True)))
                    _curl_cmd = f"curl -sk '{_repro_url}'"
                elif v.method in ("POST", "PUT", "PATCH") and _pname:
                    _curl_cmd = f"curl -sk -X {v.method} '{v.url}' -d '{_pname}={v.payload}'"
                else:
                    _curl_cmd = f"curl -sk '{v.url}'"
                _curl_safe = sanitize_for_html(_curl_cmd)
                fields.append(("Reproduce (curl)",
                    f'<div class="code-replay">'
                    f'<button class="copy-btn" onclick="copyText(this)" data-text="{_curl_safe}">Copy</button>'
                    f'<div class="code" style="color:#86efac;">{_curl_safe}</div>'
                    f'</div>'))
            except Exception:
                pass

        if v.evidence:
            fields.append(("Evidence",
                f'<div class="code">{sanitize_for_html(str(v.evidence)[:500])}</div>'))

        if v.response_snippet:
            fields.append(("Response Snippet",
                f'<div class="code">{sanitize_for_html(v.response_snippet[:400])}</div>'))

        # Screenshot (Phase 4.1)
        if hasattr(self, "_result") and self._result.screenshots:
            shot = self._result.screenshots.get(v.url)
            if shot:
                b64_str = base64.b64encode(shot).decode()
                fields.append(("Screenshot",
                    f'<img src="data:image/png;base64,{b64_str}" '
                    f'alt="Screenshot" loading="lazy" '
                    f'style="max-width:100%;border-radius:4px;border:1px solid var(--border);margin-top:4px;">'))

        fields.append(("Remediation",
            f'<div style="color:#86efac;font-size:.85rem;">{sanitize_for_html(v.remediation)}</div>'))

        if vector_str:
            fields.append(("CVSS v3.1",
                f'<div class="code">{sanitize_for_html(vector_str)}</div>'))

        if v.cwe_id:
            cwe_num = v.cwe_id.replace("CWE-", "")
            fields.append(("CWE",
                f'<span class="tag"><a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html" target="_blank">{sanitize_for_html(v.cwe_id)}</a></span>'))

        if v.owasp_category:
            fields.append(("OWASP", f'<span class="tag">{sanitize_for_html(v.owasp_category)}</span>'))

        if v.references:
            ref_links = "".join(
                f'<li><a href="{sanitize_for_html(r)}" target="_blank">{sanitize_for_html(r[:80])}</a></li>'
                for r in v.references[:5]
            )
            fields.append(("References", f'<ul class="ref-list">{ref_links}</ul>'))

        fields_html = "".join(
            f'<div class="vuln-field"><div class="vuln-field-label">{k}</div>{val}</div>'
            for k, val in fields
        )

        conf_color = {"High": "#86efac", "Medium": "#fde047", "Low": "#fdba74",
                      "Speculative": "#f87171"}.get(v.confidence, "var(--muted)")

        return f"""<div class="vuln-card" style="border-left:3px solid {color};">
  <div class="vuln-header">
    <div class="vuln-title">{sanitize_for_html(v.title)}</div>
    <div class="vuln-meta">
      <span class="badge" style="background:{bg};color:{color};">{v.severity.value}</span>
      <span class="cvss-badge">CVSS {score_str}</span>
      <span class="tag">{sanitize_for_html(v.vuln_type.value)}</span>
      <span class="conf-badge" style="color:{conf_color};">{sanitize_for_html(v.confidence)}</span>
    </div>
  </div>
  <div class="vuln-body">
    {fields_html}
    <div style="margin-top:12px;font-size:.68rem;color:var(--muted);">
      ID: {v.vuln_id} &nbsp;|&nbsp; {v.discovered_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
      &nbsp;|&nbsp; FP Risk: {sanitize_for_html(v.false_positive_risk)}
    </div>
  </div>
</div>"""

    # =========================================================================
    # Tab: Coverage dashboard (Phase 5.4)
    # =========================================================================

    def _render_tab_coverage(self, result: ScanResult) -> str:
        stats = result.stats
        disc  = stats.endpoints_discovered or stats.urls_crawled or 1
        tested = stats.endpoints_tested or stats.urls_scanned or 0
        cov_pct = min((tested / disc * 100) if disc else 0, 100)

        cov_color = "#16a34a" if cov_pct >= 80 else "#ca8a04" if cov_pct >= 50 else "#dc2626"

        scanner_rows = ""
        type_counts: Dict[str, int] = defaultdict(int)
        for v in result.vulnerabilities:
            type_counts[v.vuln_type.value] += 1

        all_scanner_names = [
            "SQL Injection", "NoSQL Injection", "XSS", "Stored XSS",
            "Command Injection", "SSTI", "SSRF", "XXE", "Path Traversal / LFI",
            "CSRF", "IDOR", "Open Redirect", "Security Headers", "SSL/TLS",
            "CORS", "JWT Vulnerabilities", "GraphQL", "Auth Bypass",
            "Race Condition", "File Upload", "Sensitive Files", "HTTP Smuggling",
            "WebSocket Vulnerability", "Secret / Credential Exposure",
            "OAuth / SAML", "Authorization Matrix",
        ]
        for sname in all_scanner_names:
            count = type_counts.get(sname, 0)
            bar_w = min(count * 20, 100) if count > 0 else 0
            bar_color = "#f87171" if count > 0 else "#1e293b"
            status = f'<span style="color:#f87171;font-weight:700;">{count} finding{"s" if count!=1 else ""}</span>' if count else '<span style="color:#86efac;">✓ Clean</span>'
            scanner_rows += f"""<tr>
  <td style="color:var(--muted);">{sanitize_for_html(sname)}</td>
  <td>
    <div style="display:flex;align-items:center;gap:10px;">
      <div class="cov-bar-wrap" style="height:8px;">
        <div class="cov-bar" style="width:{bar_w}%;background:{bar_color};"></div>
      </div>
      {status}
    </div>
  </td>
</tr>"""

        # Untested endpoints
        all_urls = set(result.crawled_urls)
        tested_urls = {v.url for v in result.vulnerabilities}
        untested = all_urls - tested_urls
        untested_html = ""
        if untested:
            items = "".join(
                f'<div class="tree-node"><span class="tree-path">{sanitize_for_html(urlparse(u).path or u[:60])}</span></div>'
                for u in sorted(untested)[:50]
            )
            untested_html = f"""<div class="section">
  <div class="section-title">Untested / Clean Endpoints ({len(untested)})</div>
  <div class="tree">{items}</div>
</div>"""

        return f"""<div id="tab-coverage" class="tab-pane">
  <div class="section">
    <div class="section-title">Scan Coverage</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-bottom:20px;">
      {self._cov_stat("Endpoints Discovered", disc, "#38bdf8")}
      {self._cov_stat("Endpoints Tested", tested, "#86efac")}
      {self._cov_stat("Coverage", f"{cov_pct:.1f}%", cov_color)}
      {self._cov_stat("Parameters Tested", stats.parameters_tested or 0, "#fde047")}
      {self._cov_stat("JS Files Analyzed", stats.js_files_analyzed or 0, "#c084fc")}
      {self._cov_stat("OpenAPI Endpoints", stats.openapi_endpoints_found or 0, "#fb923c")}
    </div>
    <div class="cov-row" style="margin-bottom:20px;">
      <div class="cov-label">Overall Coverage</div>
      <div class="cov-bar-wrap" style="height:18px;">
        <div class="cov-bar" style="width:{cov_pct:.1f}%;background:{cov_color};"></div>
      </div>
      <div class="cov-pct" style="color:{cov_color};font-size:1rem;">{cov_pct:.1f}%</div>
    </div>
  </div>
  <div class="section">
    <div class="section-title">Scanner Results</div>
    <table><tbody>{scanner_rows}</tbody></table>
  </div>
  {untested_html}
</div>"""

    @staticmethod
    def _cov_stat(label: str, value: object, color: str) -> str:
        return f"""<div class="card" style="border-top:3px solid {color};">
  <div class="card-count" style="color:{color};">{value}</div>
  <div class="card-label">{sanitize_for_html(str(label))}</div>
</div>"""

    # =========================================================================
    # Tab: Attack Surface Map (Phase 5.4)
    # =========================================================================

    def _render_tab_surface(self, result: ScanResult) -> str:
        # Build URL tree grouped by path segments
        vuln_urls = {v.url for v in result.vulnerabilities}
        url_vuln_map: Dict[str, List[str]] = defaultdict(list)
        for v in result.vulnerabilities:
            url_vuln_map[v.url].append(v.vuln_type.value)

        # Group by first path segment
        tree_groups: Dict[str, List[str]] = defaultdict(list)
        for url in sorted(result.crawled_urls):
            try:
                parts = urlparse(url).path.strip("/").split("/")
                group = "/" + parts[0] if parts and parts[0] else "/"
            except Exception:
                group = "/"
            tree_groups[group].append(url)

        tree_html = ""
        for group, urls in sorted(tree_groups.items()):
            tree_html += f'<div class="tree-node" style="margin-bottom:8px;"><span style="color:var(--accent);font-weight:700;">{sanitize_for_html(group)}/</span></div>'
            for url in urls:
                try:
                    path = urlparse(url).path
                except Exception:
                    path = url
                has_vuln = url in vuln_urls
                vuln_badge = ""
                if has_vuln:
                    vtypes = ", ".join(sorted(set(url_vuln_map[url]))[:3])
                    vuln_badge = f'<span class="tree-vuln">⚠ {sanitize_for_html(vtypes)}</span>'
                method_badge = '<span class="tree-method">GET</span>'
                tree_html += f'<div class="tree-node" style="padding-left:20px;">{method_badge}<span class="tree-path">{sanitize_for_html(path)}</span>{vuln_badge}</div>'

        # Parameter map
        param_counts: Dict[str, int] = defaultdict(int)
        for v in result.vulnerabilities:
            if v.parameter:
                param_counts[v.parameter] += 1
        param_rows = "".join(
            f'<tr><td><span class="tag">{sanitize_for_html(p)}</span></td><td style="color:#f87171;font-weight:600;">{c}</td></tr>'
            for p, c in sorted(param_counts.items(), key=lambda x: -x[1])[:20]
        )
        param_section = f"""<div class="section">
  <div class="section-title">Vulnerable Parameters</div>
  <table><thead><tr><th>Parameter</th><th>Finding Count</th></tr></thead>
  <tbody>{param_rows}</tbody></table>
</div>""" if param_rows else ""

        return f"""<div id="tab-surface" class="tab-pane">
  <div class="section">
    <div class="section-title">URL Tree ({len(result.crawled_urls)} endpoints)</div>
    <div class="tree">{tree_html if tree_html else '<span style="color:var(--muted);">No URLs recorded</span>'}</div>
  </div>
  {param_section}
</div>"""

    # =========================================================================
    # Tab: Timeline (Phase 5.1)
    # =========================================================================

    def _render_tab_timeline(self, result: ScanResult) -> str:
        vulns = sorted(result.vulnerabilities, key=lambda v: v.discovered_at)
        if not vulns:
            return f'<div id="tab-timeline" class="tab-pane">{self._empty_state()}</div>'

        items = ""
        for v in vulns:
            color, bg, _ = SEVERITY_COLORS.get(v.severity.value, ("#94a3b8", "#1e293b", "#334155"))
            icon = SEVERITY_ICONS.get(v.severity.value, "•")
            try:
                path = urlparse(v.url).path or "/"
            except Exception:
                path = v.url[:40]

            items += f"""<div class="tl-item">
  <div class="tl-dot" style="background:{color};"></div>
  <div class="tl-card">
    <div class="tl-time">{v.discovered_at.strftime("%H:%M:%S")} UTC</div>
    <div class="tl-title">{icon} {sanitize_for_html(v.title)}</div>
    <div class="tl-meta">
      <span class="badge" style="background:{bg};color:{color};">{v.severity.value}</span>
      &nbsp;<span style="color:var(--muted);">{sanitize_for_html(path)}</span>
      {f'&nbsp;| param: <span class="tag">{sanitize_for_html(v.parameter)}</span>' if v.parameter else ""}
    </div>
  </div>
</div>"""

        return f"""<div id="tab-timeline" class="tab-pane">
  <div class="section">
    <div class="section-title">Finding Timeline — {len(vulns)} events</div>
    <div class="timeline">{items}</div>
  </div>
</div>"""

    # =========================================================================
    # Footer
    # =========================================================================

    def _render_footer(self) -> str:
        return """<footer>
  <div>WebShield Security Scanner — For authorized security research and penetration testing only</div>
  <div style="margin-top:4px;">CVSS v3.1 scoring | OWASP Top 10 2021 | Phase 5 Interactive Report</div>
</footer>"""

    # =========================================================================
    # Empty state
    # =========================================================================

    def _empty_state(self) -> str:
        return """<div class="empty">
  <div class="empty-icon">✅</div>
  <div style="font-size:1.1rem;font-weight:600;color:#86efac;">No vulnerabilities found</div>
  <div style="margin-top:8px;">The scan completed without detecting any vulnerabilities.</div>
</div>"""

    # =========================================================================
    # JavaScript
    # =========================================================================

    def _js(self) -> str:
        return """<script>
// Tab switching
function switchTab(btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  var pane = document.getElementById(btn.dataset.tab);
  if (pane) pane.classList.add('active');
}

// Toggle vuln card
document.querySelectorAll('.vuln-header').forEach(function(hdr) {
  hdr.addEventListener('click', function() {
    var body = this.nextElementSibling;
    if (body) body.classList.toggle('open');
  });
});

// Filter findings
function filterFindings() {
  var query = (document.getElementById('wsSearchInput') || {}).value || '';
  query = query.toLowerCase();
  var sev  = (document.getElementById('wsSeverityFilter') || {}).value || 'all';
  var type = (document.getElementById('wsTypeFilter')     || {}).value || 'all';
  var conf = (document.getElementById('wsConfFilter')     || {}).value || 'all';

  var visible = 0;
  document.querySelectorAll('.vuln-card').forEach(function(card) {
    var text    = card.textContent.toLowerCase();
    var badge   = (card.querySelector('.badge') || {}).textContent || '';
    var tagText = '';
    card.querySelectorAll('.tag').forEach(function(t) { tagText += t.textContent + ' '; });
    var confText = (card.querySelector('.conf-badge') || {}).textContent || '';

    var mText = !query  || text.includes(query);
    var mSev  = sev  === 'all' || badge.includes(sev);
    var mType = type === 'all' || tagText.toLowerCase().includes(type.toLowerCase());
    var mConf = conf === 'all' || confText.toLowerCase().includes(conf.toLowerCase());

    var show = mText && mSev && mType && mConf;
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  document.querySelectorAll('.findings-section').forEach(function(sec) {
    var any = sec.querySelectorAll('.vuln-card:not([style*="none"])').length > 0;
    sec.style.display = any ? '' : 'none';
  });

  var el = document.getElementById('wsVisibleCount');
  if (el) el.textContent = visible + ' finding' + (visible !== 1 ? 's' : '');
}

['wsSearchInput','wsSeverityFilter','wsTypeFilter','wsConfFilter'].forEach(function(id) {
  var el = document.getElementById(id);
  if (el) el.addEventListener(el.tagName === 'INPUT' ? 'input' : 'change', filterFindings);
});

// Expand / collapse all
function expandAll() {
  document.querySelectorAll('.vuln-body').forEach(function(b) { b.classList.add('open'); });
}
function collapseAll() {
  document.querySelectorAll('.vuln-body').forEach(function(b) { b.classList.remove('open'); });
}

// Copy to clipboard (Request/Response replay)
function copyText(btn) {
  var text = btn.dataset.text || btn.nextElementSibling.textContent;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(function() {
      btn.textContent = 'Copied!';
      setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
    });
  }
}
</script>"""
