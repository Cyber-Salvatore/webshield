"""
SQL Injection Scanner
Covers: error-based, boolean-based blind, time-based blind, UNION-based,
        stacked queries, out-of-band indicators, JSON/header injection context.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPClient, HTTPResponse
from ..models.vulnerability import Vulnerability, Severity, VulnType
from ..utils.payloads import SQLI_ERROR_BASED, SQLI_BOOLEAN_BASED, SQLI_TIME_BASED
try:
    from ..utils.payloads import SQLI_WAF_BYPASS as _SQLI_WAF_BYPASS
except ImportError:
    _SQLI_WAF_BYPASS: List[str] = []
from ..utils.patterns import SQLI_ERROR_PATTERNS
# Phase 4 — statistical timing + confidence scoring
from ..utils.timing_analyzer import TimingAnalyzer
from ..utils.confidence_engine import ConfidenceEngine, ConfidenceInput, EvidenceQuality
# Fix 2.1 — UNION-based confirmation via the Triple Confirmation Framework
# (repeat / variant / negative-control), instead of trusting a single
# marker-in-response reflection.
from ..core.triple_confirmation import (
    TripleConfirmationFramework,
    ProbeRole,
    ProbeResult,
)

# Time-based threshold
TIME_THRESHOLD_SECONDS = 4.0
SLEEP_DURATION = 5

# UNION-based: probe for the right number of columns (1-10)
_UNION_PROBE_MAX_COLS = 8

# Tautology pairs for boolean-based detection
_BOOL_PAIRS: List[Tuple[str, str]] = [
    ("' AND '1'='1'--",   "' AND '1'='2'--"),
    ("' AND 1=1--",       "' AND 1=2--"),
    (" AND 1=1",          " AND 1=2"),
    ("') AND ('1'='1",    "') AND ('1'='2"),
    ("\" AND \"1\"=\"1",  "\" AND \"1\"=\"2"),
    ("1 AND 1=1",         "1 AND 1=2"),
    ("1' AND 1=1--",      "1' AND 1=2--"),
]

# Time payloads per DB family — all genuine time-based delays only
_TIME_PAYLOADS: List[str] = [
    # MySQL
    f"' AND SLEEP({SLEEP_DURATION})--",
    f"' OR SLEEP({SLEEP_DURATION})--",
    f"1 AND SLEEP({SLEEP_DURATION})",
    f"1 AND (SELECT * FROM (SELECT(SLEEP({SLEEP_DURATION})))a)--",
    f"' AND (SELECT 1 FROM (SELECT(SLEEP({SLEEP_DURATION})))t)--",
    # MSSQL — Fix 1.4: replaced xp_cmdshell (output-based) with WAITFOR DELAY (time-based)
    f"'; WAITFOR DELAY '0:0:{SLEEP_DURATION}'--",
    f"1; WAITFOR DELAY '0:0:{SLEEP_DURATION}'--",
    f"' IF (1=1) WAITFOR DELAY '0:0:{SLEEP_DURATION}'--",
    # PostgreSQL
    f"'; SELECT pg_sleep({SLEEP_DURATION})--",
    f"'; SELECT 1 FROM pg_sleep({SLEEP_DURATION})--",
    # Oracle — Fix 1.4: replaced fragile dbms_pipe (requires permissions) with DBMS_LOCK
    f"' AND 1=1 AND DBMS_LOCK.SLEEP({SLEEP_DURATION}) IS NULL--",
    f"' OR 1=1 AND (SELECT DBMS_LOCK.SLEEP({SLEEP_DURATION}) FROM DUAL) IS NULL--",
    # SQLite
    f"' AND (SELECT RANDOMBLOB(1000000000/1)) AND '1'='1",
]

# Output-based MSSQL payloads (separate — not time-based)
# Fix 1.4: xp_cmdshell moved here where it belongs
_OUTPUT_PAYLOADS_MSSQL: List[str] = [
    f"'; exec master..xp_cmdshell('ping -n {SLEEP_DURATION} 127.0.0.1')--",
]

# UNION probes for data extraction confirmation
_UNION_MARKERS = ["wsqli_union_test", "0x77736c6975"]  # hex of 'wsqli'


class SQLiScanner(_ScannerBase):
    name = "SQL Injection"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        params = self._extract_url_params(url)

        # Test ALL parameters — a human tester never stops at the first param
        seen_params: set = set()
        for param in params:
            if param in seen_params:
                continue
            seen_params.add(param)
            found = await self._test_param(url, param, "GET", response)
            vulns.extend(found)
            # Continue testing remaining params — different params may have
            # different backends or sanitisation logic

        for form in forms:
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                if not name or inp.get("type") in ("submit", "button", "image", "hidden"):
                    continue
                action = form.get("action", url)
                method = form.get("method", "GET")
                found = await self._test_form_sqli(action, method, form, name)
                vulns.extend(found)
                # Do NOT break — test all form fields for completeness

        # ── JSON body injection (REST APIs returning application/json) ──────
        if not vulns:
            ct = (response.content_type or "").lower()
            if "json" in ct:
                found = await self._test_json_body(url, response)
                vulns.extend(found)

        # ── REST path parameter injection (e.g. /api/users/1 → /api/users/1') ─
        path_params = self._extract_path_params(url)
        for seg_idx, seg_val in path_params[:3]:  # test up to 3 path segments
            for payload in SQLI_ERROR_BASED[:5]:
                injected_url = self._inject_path_segment(url, seg_idx, payload)
                resp = await self.client.get(injected_url)
                if resp is None:
                    continue
                for pattern in SQLI_ERROR_PATTERNS:
                    m = pattern.search(resp.text)
                    if m:
                        vulns.append(self._build_vuln(
                            vuln_type=VulnType.SQLI,
                            title="SQL Injection in REST Path Parameter",
                            description=(
                                f"The URL path segment '{seg_val}' at position {seg_idx} "
                                f"is vulnerable to SQL injection. REST path parameters (e.g. "
                                f"/api/users/{{id}}) are frequently used in DB queries without "
                                f"parameterisation."
                            ),
                            url=url,
                            parameter=f"Path segment [{seg_idx}]: {seg_val}",
                            payload=payload,
                            evidence=f"DB error: '{m.group(0)[:120]}'",
                            method="GET",
                            severity=Severity.CRITICAL,
                            remediation="Use parameterized queries for all path parameter lookups.",
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            response_snippet=self._snippet(resp.text),
                            confidence="High",
                        ))
                        break

        # ── Cookie-based injection (session cookies often flow into DB queries) ─
        cookie_findings = await self._test_cookie_injection(url, response)
        vulns.extend(cookie_findings)

        # ── REST API: test PUT/PATCH with same params if URL looks like REST ──
        if not vulns and params and "/api/" in url or "/v1/" in url or "/v2/" in url:
            for param in list(params)[:3]:
                for verb in ("PUT", "PATCH"):
                    for payload in SQLI_ERROR_BASED[:4]:
                        body = {param: payload}
                        resp = await self.client.request(
                            verb, url, json=body,
                            headers={"Content-Type": "application/json"},
                        )
                        if resp is None:
                            continue
                        for pattern in SQLI_ERROR_PATTERNS:
                            m = pattern.search(resp.text)
                            if m:
                                vulns.append(self._build_vuln(
                                    vuln_type=VulnType.SQLI,
                                    title=f"SQL Injection via {verb} Request Body",
                                    description=(
                                        f"The '{param}' field in a {verb} JSON body is vulnerable "
                                        f"to SQL injection. REST API endpoints often share DB queries "
                                        f"with GET handlers but skip input validation."
                                    ),
                                    url=url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=f"DB error: '{m.group(0)[:120]}'",
                                    method=verb,
                                    severity=Severity.CRITICAL,
                                    remediation="Use parameterized queries for all REST API verb handlers.",
                                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                                    cwe_id="CWE-89",
                                    owasp_category="A03:2021 - Injection",
                                    response_snippet=self._snippet(resp.text),
                                    confidence="High",
                                ))
                                break

        return vulns

    # ------------------------------------------------------------------
    # JSON body SQL injection (REST APIs)
    # ------------------------------------------------------------------


    async def _test_cookie_injection(
        self, url: str, response: HTTPResponse
    ) -> List[Vulnerability]:
        """
        Test cookie values for SQL injection.
        Many applications use cookies (session IDs, user prefs) in DB queries
        without parameterisation. A human pentester ALWAYS checks cookies.
        """
        resp_cookies = dict(response.cookies) if hasattr(response, "cookies") else {}
        client_cookies = getattr(self.client, "cookies", {})
        all_cookies = {**client_cookies, **resp_cookies}

        if not all_cookies:
            return []

        findings: List[Vulnerability] = []
        for cookie_name, original_value in list(all_cookies.items())[:5]:
            for payload in SQLI_ERROR_BASED[:6]:
                injected_cookies = dict(all_cookies)
                injected_cookies[cookie_name] = payload
                cookie_header = "; ".join(f"{k}={v}" for k, v in injected_cookies.items())
                resp = await self.client.get(url, headers={"Cookie": cookie_header})
                if resp is None:
                    continue
                for pattern in SQLI_ERROR_PATTERNS:
                    match = pattern.search(resp.text)
                    if match:
                        findings.append(self._build_vuln(
                            vuln_type=VulnType.SQLI,
                            title=f"SQL Injection via Cookie ({cookie_name})",
                            description=(
                                f"The cookie '{cookie_name}' is vulnerable to SQL injection. "
                                f"The application uses this cookie value in a DB query without "
                                f"parameterisation. An attacker can extract the full database."
                            ),
                            url=url,
                            parameter=f"Cookie: {cookie_name}",
                            payload=payload,
                            evidence=f"DB error: '{match.group(0)[:120]}'",
                            method="GET",
                            severity=Severity.CRITICAL,
                            remediation=(
                                "Use parameterized queries for ALL user-controlled data including cookies."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            response_snippet=self._snippet(resp.text),
                            confidence="High",
                        ))
                        break
                if findings:
                    break
        return findings

    async def _test_json_body(
        self, url: str, response: HTTPResponse
    ) -> List[Vulnerability]:
        """Inject SQLi payloads into JSON body fields of REST API endpoints."""
        import json as _json

        try:
            data = _json.loads(response.text)
        except Exception:
            data = {}

        if not isinstance(data, dict):
            data = {}

        # Infer field names: from response body or use common API field names
        field_names = [k for k in data.keys() if isinstance(data[k], (str, int))][:5]
        if not field_names:
            field_names = ["id", "user_id", "search", "query", "filter"]

        # Use fast error-based payloads only for JSON (time-based too slow for all fields)
        for field in field_names:
            for payload in SQLI_ERROR_BASED[:8]:
                test_body = dict(data)
                test_body[field] = payload

                resp = await self.client.post(
                    url,
                    json=test_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue

                for pattern in SQLI_ERROR_PATTERNS:
                    m = pattern.search(resp.text)
                    if m:
                        return [self._build_vuln(
                            vuln_type=VulnType.SQLI,
                            title="SQL Injection via JSON Body (Error-Based)",
                            description=(
                                f"JSON field '{field}' at {url} is vulnerable to error-based "
                                f"SQL injection. The API accepted a raw SQL fragment in a JSON body "
                                f"and reflected a database error in the response."
                            ),
                            url=url,
                            parameter=field,
                            payload=_json.dumps({field: payload}),
                            evidence=f"DB error: '{m.group(0)[:120]}'",
                            method="POST",
                            severity=Severity.CRITICAL,
                            remediation=(
                                "Use parameterized queries / ORM safe methods. "
                                "Never interpolate raw JSON values into SQL strings."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            confidence="High",
                        )]
        return []

    # ------------------------------------------------------------------
    # Dispatcher — tries all techniques per param
    # ------------------------------------------------------------------

    async def _test_param(
        self, url: str, param: str, method: str, original_response: HTTPResponse
    ) -> List[Vulnerability]:
        # 1. Error-based (fastest, highest confidence)
        found = await self._test_error_based(url, param, method)
        if found:
            return found

        # 2. UNION-based
        found = await self._test_union_based(url, param, method)
        if found:
            return found

        # 3. Boolean-based blind
        found = await self._test_boolean_based(url, param, method, original_response)
        if found:
            return found

        # 4. Time-based blind (slowest, run last)
        found = await self._test_time_based(url, param, method)
        return found

    # ------------------------------------------------------------------
    # Error-based
    # ------------------------------------------------------------------

    async def _test_error_based(
        self, url: str, param: str, method: str
    ) -> List[Vulnerability]:
        for payload in SQLI_ERROR_BASED[:12]:
            injected_url = self._inject_param(url, param, payload)
            resp = await self.client.get(injected_url)
            if resp is None:
                continue
            for pattern in SQLI_ERROR_PATTERNS:
                match = pattern.search(resp.text)
                if match:
                    return [self._build_vuln(
                        vuln_type=VulnType.SQLI,
                        title="SQL Injection (Error-Based)",
                        description=(
                            f"Parameter '{param}' is vulnerable to error-based SQL injection. "
                            f"The payload '{payload}' triggered a database error message in the response, "
                            f"confirming unsanitized SQL query construction. "
                            f"An attacker can extract the full database schema and contents."
                        ),
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"DB error: '{match.group(0)[:120]}'",
                        method=method,
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Use parameterized queries (prepared statements) — never concatenate "
                            "user input into SQL strings. Suppress all database error messages "
                            "from HTTP responses. Apply least-privilege DB accounts."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/89.html",
                        ],
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection",
                        response_snippet=self._snippet(resp.text),
                        confidence="High",
                    )]
        # ── WAF bypass fallback: try obfuscated payloads if standard ones failed ──
        if _SQLI_WAF_BYPASS:
            for waf_payload in _SQLI_WAF_BYPASS[:12]:
                injected_url = self._inject_param(url, param, waf_payload)
                resp = await self.client.get(injected_url)
                if resp is None or resp.status_code in (403, 406, 429, 503):
                    continue
                for pattern in SQLI_ERROR_PATTERNS:
                    m = pattern.search(resp.text)
                    if m:
                        return [self._build_vuln(
                            vuln_type=VulnType.SQLI,
                            title="SQL Injection (Error-Based, WAF Bypass)",
                            description=(
                                f"Parameter '{param}' is vulnerable to error-based SQL injection. "
                                f"Standard payloads were likely filtered, but the WAF bypass payload "
                                f"'{waf_payload}' evaded filtering and triggered a database error. "
                                f"A WAF alone cannot prevent SQL injection — parameterized queries are required."
                            ),
                            url=url,
                            parameter=param,
                            payload=waf_payload,
                            evidence=f"DB error: '{m.group(0)[:120]}'",
                            method=method,
                            severity=Severity.CRITICAL,
                            remediation=(
                                "A WAF is NOT a substitute for parameterized queries. "
                                "Fix the underlying injection — WAF rules can always be bypassed."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            response_snippet=self._snippet(resp.text),
                            confidence="High",
                        )]

        return []

    # ------------------------------------------------------------------
    # UNION-based
    # ------------------------------------------------------------------

    async def _test_union_based(
        self, url: str, param: str, method: str
    ) -> List[Vulnerability]:
        """Determine column count then inject a marker string via UNION SELECT.
        Tests both NULL-fill and string-fill variants for broader WAF/DB coverage.

        Fix 2.1: a bare "marker appears in the response" check is not
        sufficient evidence of UNION-based SQL injection — plenty of
        pages (search results, "you searched for X", error pages that
        echo the query string, etc.) reflect ANY input verbatim,
        including a syntactically-broken UNION SELECT string. Relying on
        reflection alone turns every such page into a false positive.

        Instead, a candidate hit is only reported once it survives the
        Triple Confirmation Framework:
          - REPEAT:  the exact same UNION payload, sent again.
          - VARIANT: a different column position / fill / comment style
                     from the same UNION family, with a fresh marker.
          - CONTROL: the marker sent as a *plain, non-SQL* literal value
                     (no UNION SELECT, no quote breakout at all). If the
                     marker still shows up here, the page just reflects
                     whatever it's given and the "hit" was never caused
                     by SQL execution in the first place.
        """
        nonce = uuid.uuid4().hex[:6]
        for num_cols in range(1, _UNION_PROBE_MAX_COLS + 1):
            for col_idx in range(num_cols):
                # Test multiple fill types and comment styles for broader coverage
                for combo_idx, (fill, suffix) in enumerate([
                    ("NULL",  "--"),    # Standard NULL-based
                    ("'x'",   "--"),    # String-fill (MySQL strict mode)
                    ("1",     "--"),    # Integer-fill (PostgreSQL / MSSQL)
                    ("NULL",  "#"),     # MySQL hash comment
                    ("NULL",  "-- -"),  # Alternate comment style
                ]):
                    marker = f"wsqli{nonce}{num_cols}c{col_idx}n{combo_idx}"
                    cols = [fill] * num_cols
                    cols[col_idx] = f"'{marker}'"
                    union_payload = f"' UNION SELECT {','.join(cols)}{suffix}"
                    injected_url = self._inject_param(url, param, union_payload)
                    resp = await self.client.get(injected_url)
                    if not resp:
                        continue
                    if marker in resp.text and resp.status_code == 200:
                        vuln = await self._confirm_union_candidate(
                            url=url, param=param, method=method,
                            num_cols=num_cols, col_idx=col_idx,
                            fill=fill, suffix=suffix, nonce=nonce,
                            combo_idx=combo_idx, marker=marker,
                            union_payload=union_payload, resp=resp,
                        )
                        if vuln is not None:
                            return [vuln]
                        # Candidate did not survive confirmation (most likely
                        # the site reflects arbitrary input regardless of SQL
                        # validity) — keep searching other column positions,
                        # they may hit a genuinely different code path.
        return []

    async def _confirm_union_candidate(
        self,
        *,
        url: str,
        param: str,
        method: str,
        num_cols: int,
        col_idx: int,
        fill: str,
        suffix: str,
        nonce: str,
        combo_idx: int,
        marker: str,
        union_payload: str,
        resp: HTTPResponse,
    ) -> Optional[Vulnerability]:
        """Run repeat / variant / negative-control probes for a candidate
        UNION hit and only build a Vulnerability if the Triple
        Confirmation Framework agrees it's real."""

        # ── Negative control marker: same nonce family, sent as a plain
        # literal value with NO SQL injection syntax whatsoever. If this
        # comes back reflected, the app just echoes any input and the
        # UNION "hit" above was reflection, not execution.
        control_marker = f"wsqlictl{nonce}"
        control_url = self._inject_param(url, param, control_marker)

        # Build a structurally different variant: shift fill/comment combo
        # (and column position if there's more than one column) so it's a
        # genuinely different payload from the same UNION family.
        variant_combos = [
            ("NULL",  "--"), ("'x'", "--"), ("1", "--"),
            ("NULL",  "#"),  ("NULL", "-- -"),
        ]
        variant_combo_idx = (combo_idx + 1) % len(variant_combos)
        variant_fill, variant_suffix = variant_combos[variant_combo_idx]
        variant_col_idx = (col_idx + 1) % num_cols
        variant_marker = f"wsqli{nonce}{num_cols}c{variant_col_idx}n{variant_combo_idx}"
        variant_cols = [variant_fill] * num_cols
        variant_cols[variant_col_idx] = f"'{variant_marker}'"
        variant_payload = f"' UNION SELECT {','.join(variant_cols)}{variant_suffix}"
        variant_url = self._inject_param(url, param, variant_payload)

        # ── Run the three probes directly (marker-presence anomaly, not a
        # generic content diff — the UNION signal IS the marker) ──────────
        repeat_resp = await self.client.get(self._inject_param(url, param, union_payload))
        repeat_anomaly = bool(repeat_resp and marker in repeat_resp.text
                               and repeat_resp.status_code == 200)

        variant_resp = await self.client.get(variant_url)
        variant_anomaly = bool(variant_resp and variant_marker in variant_resp.text
                                and variant_resp.status_code == 200)

        control_resp = await self.client.get(control_url)
        control_fired = bool(control_resp and control_marker in control_resp.text)

        tcf = TripleConfirmationFramework()
        finding_id = f"sqli-union:{param}:{num_cols}:{col_idx}:{nonce}"
        verdict = tcf.evaluate(
            finding_id=finding_id,
            repeat=ProbeResult(
                role=ProbeRole.REPEAT, anomaly_detected=repeat_anomaly,
                response=repeat_resp, payload=union_payload,
                note=f"marker '{marker}' {'reflected' if repeat_anomaly else 'absent'} on repeat",
            ),
            variant=ProbeResult(
                role=ProbeRole.VARIANT, anomaly_detected=variant_anomaly,
                response=variant_resp, payload=variant_payload,
                note=f"variant marker '{variant_marker}' {'reflected' if variant_anomaly else 'absent'}",
            ),
            control=ProbeResult(
                role=ProbeRole.CONTROL, anomaly_detected=control_fired,
                response=control_resp, payload=control_marker,
                note=(
                    "negative control marker reflected with NO SQL syntax at all — "
                    "this page reflects arbitrary input, UNION hit was not caused "
                    "by SQL execution"
                    if control_fired else
                    "negative control marker (no SQL syntax) was NOT reflected"
                ),
            ),
        )

        if not verdict.should_report:
            return None

        confidence_label = verdict.confidence.label.value if verdict.confidence else "Medium"
        return self._build_vuln(
            vuln_type=VulnType.SQLI,
            title="SQL Injection (UNION-Based Data Extraction)",
            description=(
                f"Parameter '{param}' is vulnerable to UNION-based SQL injection. "
                f"A UNION SELECT with {num_cols} column(s) using fill='{fill}' "
                f"was accepted and the marker '{marker}' was reflected in the response. "
                f"This was confirmed via repeat + variant UNION probes, and a "
                f"negative-control request (the same marker with no SQL syntax at all) "
                f"did NOT reflect — ruling out generic input reflection as the cause. "
                f"Verdict: {verdict.label.value} ({'; '.join(verdict.reasoning)})."
            ),
            url=url,
            parameter=param,
            payload=union_payload,
            evidence=(
                f"Marker '{marker}' reflected (col {col_idx+1}/{num_cols}, fill={fill}); "
                f"repeat={repeat_anomaly}, variant={variant_anomaly}, "
                f"negative_control_fired={control_fired}"
            ),
            method=method,
            severity=Severity.CRITICAL,
            remediation=(
                "Use parameterized queries (prepared statements). "
                "A UNION injection allows full database dump — treat as critical."
            ),
            references=[
                "https://portswigger.net/web-security/sql-injection/union-attacks",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            response_snippet=self._snippet(resp.text),
            confidence=confidence_label,
        )

    # ------------------------------------------------------------------
    # Boolean-based blind
    # ------------------------------------------------------------------

    async def _test_boolean_based(
        self,
        url: str,
        param: str,
        method: str,
        original_response: HTTPResponse,
    ) -> List[Vulnerability]:
        """Compare TRUE vs FALSE boolean conditions — detect response differences."""
        orig_len = len(original_response.text)
        orig_status = original_response.status_code

        for true_pl, false_pl in _BOOL_PAIRS:
            url_true = self._inject_param(url, param, true_pl)
            url_false = self._inject_param(url, param, false_pl)

            resp_true, resp_false = await asyncio.gather(
                self.client.get(url_true),
                self.client.get(url_false),
            )

            if not (resp_true and resp_false):
                continue

            len_true = len(resp_true.text)
            len_false = len(resp_false.text)

            # TRUE should look like normal, FALSE should differ
            diff_tf = abs(len_true - len_false)
            # TRUE should be similar to original
            diff_orig_true = abs(len_true - orig_len)

            # Fix 2.4: Adaptive threshold based on page size to reduce FP/FN.
            # Small pages need larger relative difference; large pages use absolute floor.
            min_diff = self._calc_bool_threshold(orig_len)
            false_looks_different = (
                resp_false.status_code != resp_true.status_code
                or diff_tf >= min_diff
            )

            # Also check structural content difference (not just length)
            # Compute word-set overlap to detect meaningful content change
            words_true = set(resp_true.text.split())
            words_false = set(resp_false.text.split())
            words_orig = set(original_response.text.split())
            structural_diff = len(words_true.symmetric_difference(words_false))
            true_similar_to_orig = len(words_true.symmetric_difference(words_orig)) < max(20, len(words_orig) * 0.10)

            # Trigger on: length diff OR structural word diff, both with TRUE ≈ original
            meaningful_diff = (
                (false_looks_different or structural_diff >= 15)
                and (diff_orig_true < max(100, orig_len * 0.05) or true_similar_to_orig)
            )

            if meaningful_diff:
                return [self._build_vuln(
                    vuln_type=VulnType.SQLI,
                    title="SQL Injection (Boolean-Based Blind)",
                    description=(
                        f"Parameter '{param}' is vulnerable to boolean-based blind SQL injection. "
                        f"TRUE condition ('{true_pl}') returned {len_true} bytes (similar to baseline {orig_len}), "
                        f"while FALSE condition ('{false_pl}') returned {len_false} bytes — "
                        f"a {diff_tf}-byte / {structural_diff}-word difference confirming conditional SQL execution. "
                        f"An attacker can extract any data from the database bit-by-bit."
                    ),
                    url=url,
                    parameter=param,
                    payload=f"TRUE: {true_pl} | FALSE: {false_pl}",
                    evidence=(
                        f"Baseline: {orig_len}B | TRUE: {len_true}B | FALSE: {len_false}B "
                        f"(Δ TRUE/FALSE = {diff_tf}B)"
                    ),
                    method=method,
                    severity=Severity.HIGH,
                    remediation=(
                        "Use parameterized queries. Boolean-blind SQLi allows full data extraction "
                        "using automated tools (sqlmap). Treat as high-priority remediation."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ],
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 - Injection",
                    confidence="Medium",
                )]
        return []

    # ------------------------------------------------------------------
    # Time-based blind
    # ------------------------------------------------------------------

    async def _test_time_based(
        self, url: str, param: str, method: str
    ) -> List[Vulnerability]:
        """
        Phase 4.4 upgrade: statistical time-based detection.
        Builds a 3-sample baseline then requires the injected response to
        exceed mean + max(3×std_dev, 2.0s) before reporting.
        Applies ConfidenceEngine scoring to the finding.
        """
        timing = TimingAnalyzer(self.client)
        confidence_engine = ConfidenceEngine()

        # ── Build statistical baseline (3 benign requests) ────────────────
        baseline_url = self._inject_param(url, param, "1")
        baseline_stats = await timing.measure_baseline(baseline_url, samples=3)

        if baseline_stats.count == 0:
            return []

        for payload in _TIME_PAYLOADS:
            injected_url = self._inject_param(url, param, payload)
            elapsed = await timing.measure_single(injected_url)
            if elapsed is None:
                continue

            anomaly = timing.detect_anomaly(
                observed=elapsed,
                baseline=baseline_stats,
                expected_delay=float(SLEEP_DURATION),
            )

            if not anomaly.is_anomaly:
                continue

            # Confirm with a second measurement to reduce false positives
            elapsed2 = await timing.measure_single(injected_url)
            samples = [elapsed]
            if elapsed2 is not None:
                samples.append(elapsed2)

            conf_result = confidence_engine.score_time_based(
                timing_samples=samples,
                expected_delay=float(SLEEP_DURATION),
                confirmations=len(samples),
            )

            vuln = self._build_vuln(
                vuln_type=VulnType.SQLI,
                title="SQL Injection (Time-Based Blind)",
                description=(
                    f"Parameter '{param}' is vulnerable to time-based blind SQL injection. "
                    f"The payload '{payload}' caused a {elapsed:.1f}s response "
                    f"(baseline mean: {baseline_stats.mean:.1f}s ± {baseline_stats.std_dev:.2f}s), "
                    f"exceeding the 3-sigma threshold of {anomaly.threshold:.1f}s ({anomaly.sigma_distance:.1f}σ). "
                    f"An attacker can extract data character-by-character using conditional time delays."
                ),
                url=url,
                parameter=param,
                payload=payload,
                evidence=(
                    f"Observed: {elapsed:.2f}s | Baseline: mean={baseline_stats.mean:.2f}s "
                    f"std={baseline_stats.std_dev:.2f}s | Threshold: {anomaly.threshold:.2f}s "
                    f"({anomaly.sigma_distance:.1f}σ) | Timing confidence: {anomaly.confidence}"
                ),
                method=method,
                severity=Severity.HIGH,
                remediation=(
                    "Use parameterized queries. Implement query timeouts. "
                    "Monitor for anomalously slow DB queries as an IDS signal."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html",
                ],
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                confidence=conf_result.label,
            )
            conf_result.apply_to_vuln(vuln)
            return [vuln]

        return []

    # ------------------------------------------------------------------
    # Form scanning
    # ------------------------------------------------------------------

    async def _test_form_sqli(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
    ) -> List[Vulnerability]:
        # Error-based on forms
        for payload in SQLI_ERROR_BASED[:8]:
            form_data = {
                inp["name"]: (payload if inp["name"] == param_name else inp.get("value", "test"))
                for inp in form.get("inputs", [])
            }
            resp = (
                await self.client.post(action, data=form_data)
                if method == "POST"
                else await self.client.get(action, params=form_data)
            )
            if resp is None:
                continue
            for pattern in SQLI_ERROR_PATTERNS:
                match = pattern.search(resp.text)
                if match:
                    return [self._build_vuln(
                        vuln_type=VulnType.SQLI,
                        title="SQL Injection in Form Field (Error-Based)",
                        description=(
                            f"Form field '{param_name}' at {action} is vulnerable to "
                            f"error-based SQL injection via {method} request."
                        ),
                        url=action,
                        parameter=param_name,
                        payload=payload,
                        evidence=match.group(0)[:120],
                        method=method,
                        severity=Severity.CRITICAL,
                        remediation="Use parameterized queries for all database interactions.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection",
                        response_snippet=self._snippet(resp.text),
                    )]

        # ── Phase 4.4: Statistical time-based detection on forms ──────────────
        # Build 3-sample statistical baseline using benign form data
        import time as _time
        confidence_engine = ConfidenceEngine()

        baseline_data = {
            inp["name"]: inp.get("value", "test")
            for inp in form.get("inputs", [])
            if inp.get("name")
        }

        # Measure baseline timing (3 samples)
        baseline_times: list = []
        for _ in range(3):
            t0 = _time.monotonic()
            if method == "POST":
                resp_b = await self.client.post(action, data=baseline_data)
            else:
                resp_b = await self.client.get(action, params=baseline_data)
            elapsed_b = _time.monotonic() - t0
            if resp_b is not None:
                baseline_times.append(elapsed_b)

        if not baseline_times:
            return []

        import statistics as _stats
        baseline_mean = _stats.mean(baseline_times)
        baseline_std = _stats.stdev(baseline_times) if len(baseline_times) > 1 else 0.5
        # 3-sigma threshold: must exceed mean + max(3*std, 2.0s)
        threshold = baseline_mean + max(3 * baseline_std, 2.0)

        for payload in _TIME_PAYLOADS[:6]:
            form_data = {
                inp["name"]: (payload if inp["name"] == param_name else inp.get("value", "test"))
                for inp in form.get("inputs", [])
            }
            t0 = _time.monotonic()
            if method == "POST":
                resp = await self.client.post(action, data=form_data)
            else:
                resp = await self.client.get(action, params=form_data)
            elapsed = _time.monotonic() - t0

            if resp is None or elapsed < threshold:
                continue

            # Confirm with second measurement to reduce false positives
            t1 = _time.monotonic()
            if method == "POST":
                resp2 = await self.client.post(action, data=form_data)
            else:
                resp2 = await self.client.get(action, params=form_data)
            elapsed2 = _time.monotonic() - t1

            if resp2 is None or elapsed2 < threshold:
                continue  # Second measurement didn't confirm — skip

            samples = [elapsed, elapsed2]
            conf_result = confidence_engine.score_time_based(
                timing_samples=samples,
                expected_delay=float(SLEEP_DURATION),
                confirmations=2,
            )

            sigma_distance = (elapsed - baseline_mean) / max(baseline_std, 0.001)
            vuln = self._build_vuln(
                vuln_type=VulnType.SQLI,
                title="SQL Injection in Form Field (Time-Based Blind)",
                description=(
                    f"Form field '{param_name}' at {action} is vulnerable to "
                    f"time-based blind SQL injection via {method} request. "
                    f"The payload '{payload}' caused a {elapsed:.1f}s delay "
                    f"(baseline mean: {baseline_mean:.1f}s ± {baseline_std:.2f}s, "
                    f"threshold: {threshold:.1f}s, {sigma_distance:.1f}σ). "
                    f"Dual confirmation (2nd: {elapsed2:.1f}s) eliminates false positives."
                ),
                url=action,
                parameter=param_name,
                payload=payload,
                evidence=(
                    f"1st: {elapsed:.2f}s | 2nd: {elapsed2:.2f}s | "
                    f"Baseline mean={baseline_mean:.2f}s std={baseline_std:.2f}s | "
                    f"Threshold: {threshold:.2f}s ({sigma_distance:.1f}σ)"
                ),
                method=method,
                severity=Severity.HIGH,
                remediation="Use parameterized queries. Implement query timeouts.",
                references=[
                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html",
                ],
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                confidence=conf_result.label,
            )
            conf_result.apply_to_vuln(vuln)
            return [vuln]
        return []

    @staticmethod
    def _calc_bool_threshold(orig_len: int) -> int:
        """
        Fix 2.4: Dynamic threshold based on page size to reduce FP/FN.
        Small pages require larger relative difference.
        Large pages: use absolute minimum.
        """
        if orig_len < 200:
            return max(orig_len // 2, 50)     # 50% of small page, min 50B
        elif orig_len < 1000:
            return max(orig_len // 5, 100)    # 20%, min 100B
        elif orig_len < 5000:
            return max(orig_len // 10, 200)   # 10%, min 200B
        else:
            return 500                         # absolute 500B for large pages
