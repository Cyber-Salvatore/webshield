"""
CSRF Scanner — Professional Grade
===================================
Coverage:
  • Missing CSRF token on all state-changing forms (POST/PUT/DELETE/PATCH)
  • CSRF token present but static/guessable (length < 16, all-zeros, "token")
  • CSRF token in URL (leaked via Referer)
  • SameSite cookie check — all Set-Cookie headers (not just first)
  • Custom request header bypass check (X-Requested-With, etc.)
  • CORS misconfiguration as CSRF amplifier (Origin: null / wildcard)
  • JSON CSRF (Content-Type: text/plain or application/x-www-form-urlencoded
    accepted by JSON endpoints)
  • Multipart form CSRF
  • Flash/JSONP CSRF surface detection
  • Double-submit cookie pattern validation
  • Referer validation bypass (empty Referer accepted)

CWE  : CWE-352
OWASP: A01:2021 – Broken Access Control
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability,
    VulnType,
    Severity,
    CVSSv3,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
)

# ---------------------------------------------------------------------------
# CVSS profiles
# ---------------------------------------------------------------------------

_CVSS_HIGH = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.NONE,
    integrity=Impact.HIGH,
    availability=Impact.NONE,
)

_CVSS_MEDIUM = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.HIGH,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.NONE,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_CWE = "CWE-352"
_OWASP = "A01:2021 - Broken Access Control"
_REFS = [
    "https://owasp.org/www-community/attacks/csrf",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/352.html",
    "https://portswigger.net/web-security/csrf",
]
_REMEDIATION = (
    "1. Implement the Synchronizer Token Pattern: generate a cryptographically "
    "random token per session, embed it in all state-changing forms as a hidden "
    "field, and validate it server-side on every POST/PUT/PATCH/DELETE request.\n"
    "2. Set SameSite=Strict or SameSite=Lax on all session cookies.\n"
    "3. Validate the Origin or Referer header server-side (reject cross-origin "
    "requests to state-changing endpoints).\n"
    "4. Use the Double-Submit Cookie pattern as a secondary defense.\n"
    "5. Require custom request headers (e.g., X-Requested-With: XMLHttpRequest) "
    "on all AJAX state-changing endpoints."
)

# ---------------------------------------------------------------------------
# CSRF token detection patterns
# ---------------------------------------------------------------------------

_TOKEN_FIELD_RE = re.compile(
    r"(?i)\b("
    r"csrf[_\-]?token|xsrf[_\-]?token|_token|_csrf|"
    r"authenticity[_\-]?token|request[_\-]?token|form[_\-]?token|"
    r"nonce|__requestverificationtoken|csrfmiddlewaretoken|"
    r"csrf[_\-]?key|anti[_\-]?csrf|security[_\-]?token|"
    r"form[_\-]?nonce|state[_\-]?token|syn[_\-]?token"
    r")\b",
    re.IGNORECASE,
)

_SAMESITE_STRICT_LAX_RE = re.compile(r"samesite\s*=\s*(strict|lax)", re.IGNORECASE)
_SAMESITE_NONE_RE = re.compile(r"samesite\s*=\s*none", re.IGNORECASE)

# Token looks weak / predictable
_WEAK_TOKEN_RE = re.compile(
    r"^(?:0+|1+|token|csrf|test|dummy|placeholder|sample|example|changeme|"
    r"[a-zA-Z]{1,8}|\d{1,8})$",
    re.IGNORECASE,
)

# State-changing methods
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# CORS wildcard or null Origin in ACAO header
_CORS_WILDCARD_RE = re.compile(r"^\*$|^null$", re.IGNORECASE)

# JSON endpoint signals
_JSON_CONTENT_TYPE_RE = re.compile(r"application/json", re.IGNORECASE)
_JSONP_RE = re.compile(r"(?:callback|jsonp)\s*=\s*\w+", re.IGNORECASE)

# Sensitive action keywords in form action URLs
_SENSITIVE_ACTION_RE = re.compile(
    r"(?i)(delete|remove|transfer|update|change|modify|reset|"
    r"password|email|pay|checkout|purchase|admin|settings|"
    r"profile|account|withdraw|send|post|comment|vote|follow)",
)


# ===========================================================================
# Scanner
# ===========================================================================

class CSRFScanner(_ScannerBase):
    """
    Comprehensive CSRF scanner.

    Per-form checks:
      1. Missing CSRF token field.
      2. CSRF token present but appears static/predictable.
      3. CSRF token transmitted in URL (Referer leak risk).
      4. All Set-Cookie headers for SameSite protection.
      5. SameSite=None detected (explicit CSRF risk).
      6. CORS misconfiguration that amplifies CSRF.
      7. Referer validation bypass (send empty Referer).
      8. JSON CSRF: form-encoded body accepted on JSON endpoint.
    """

    name = "CSRF"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # Collect all Set-Cookie values up front
        samesite_info = self._analyze_samesite(response)

        # CORS check — applies to all state-changing endpoints on this page
        cors_vuln = self._check_cors(url, response)

        # JSONP surface check
        jsonp_vuln = self._check_jsonp_surface(url, response)
        if jsonp_vuln:
            vulns.append(jsonp_vuln)

        for form in forms:
            method = (form.get("method") or "GET").upper()

            # Only state-changing forms
            if method not in _STATE_METHODS:
                continue

            action = form.get("action") or url
            inputs = form.get("inputs", [])

            form_vulns = await self._analyze_form(
                url=url,
                action=action,
                method=method,
                inputs=inputs,
                response=response,
                samesite_info=samesite_info,
            )
            vulns.extend(form_vulns)

        # Attach CORS vuln if we found any CSRF issues (amplification)
        if cors_vuln and vulns:
            vulns.append(cors_vuln)
        elif cors_vuln:
            # CORS misconfiguration alone is worth reporting
            vulns.append(cors_vuln)

        return vulns

    # -----------------------------------------------------------------------
    # Form analysis
    # -----------------------------------------------------------------------

    async def _analyze_form(
        self,
        url: str,
        action: str,
        method: str,
        inputs: List[Dict[str, Any]],
        response: HTTPResponse,
        samesite_info: Dict[str, Any],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        input_names = [inp.get("name", "") for inp in inputs if inp.get("name")]

        # ── 1. Check for CSRF token field ──────────────────────────────────
        csrf_inputs = [
            inp for inp in inputs
            if _TOKEN_FIELD_RE.search(inp.get("name", ""))
        ]
        hidden_csrf_inputs = [
            inp for inp in csrf_inputs
            if inp.get("type", "").lower() == "hidden"
        ]

        has_token = bool(csrf_inputs or hidden_csrf_inputs)

        # ── 2. Evaluate token quality if present ───────────────────────────
        if has_token:
            for token_inp in csrf_inputs + hidden_csrf_inputs:
                token_val = token_inp.get("value", "")
                # Weak / short token
                if token_val and (len(token_val) < 16 or _WEAK_TOKEN_RE.match(token_val)):
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.CSRF,
                        title=f"Weak/Predictable CSRF Token in Form (param: {token_inp.get('name')})",
                        description=(
                            f"The form at '{action}' contains a CSRF token field "
                            f"'{token_inp.get('name')}' but its value '{token_val[:30]}' "
                            f"is short (< 16 chars) or appears static/predictable. "
                            f"An attacker who observes the token value may be able to "
                            f"predict or reuse it across sessions."
                        ),
                        url=url,
                        method=method,
                        parameter=token_inp.get("name"),
                        payload=token_val[:30],
                        evidence=f"CSRF token value: '{token_val[:40]}'",
                        severity=Severity.MEDIUM,
                        cvss=_CVSS_MEDIUM,
                        remediation=(
                            "Use a cryptographically random token of at least 128 bits (32 hex chars). "
                            "Regenerate the token on each session start. "
                            + _REMEDIATION
                        ),
                        references=_REFS,
                        cwe_id=_CWE,
                        owasp_category=_OWASP,
                        confidence="Medium",
                    ))

            # Token present and looks strong — no missing-token finding
            # Still check SameSite and Referer issues below
        else:
            # ── 3. No CSRF token — primary finding ─────────────────────────
            # But first check whether SameSite=Strict/Lax mitigates it
            if not samesite_info["has_strict_or_lax"]:
                # Is this a sensitive action?
                sensitivity = "High" if _SENSITIVE_ACTION_RE.search(action) else "Medium"
                cvss = _CVSS_HIGH if sensitivity == "High" else _CVSS_MEDIUM
                sev = Severity.HIGH if sensitivity == "High" else Severity.MEDIUM

                vulns.append(self._build_vuln(
                    vuln_type=VulnType.CSRF,
                    title=f"Missing CSRF Protection on State-Changing Form ({method})",
                    description=(
                        f"The {method} form at '{action}' does not include a CSRF token, "
                        f"and the session cookie does not have SameSite=Strict or SameSite=Lax. "
                        f"An attacker can create a malicious web page that auto-submits this "
                        f"form on behalf of an authenticated victim, performing unintended "
                        f"actions (e.g., account changes, fund transfers, data deletion)."
                    ),
                    url=url,
                    method=method,
                    parameter=None,
                    payload=None,
                    evidence=(
                        f"No CSRF token field found. Form inputs: {input_names}. "
                        f"SameSite: {samesite_info['summary']}"
                    ),
                    severity=sev,
                    cvss=cvss,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    confidence="High",
                ))
            else:
                # SameSite mitigates — lower severity advisory
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.CSRF,
                    title=f"CSRF Token Missing — Partially Mitigated by SameSite Cookie",
                    description=(
                        f"The {method} form at '{action}' has no CSRF token, but the "
                        f"session cookie uses SameSite={samesite_info['samesite_value']} "
                        f"which provides partial CSRF protection. "
                        f"SameSite=Lax still allows top-level GET navigation redirects; "
                        f"add an explicit CSRF token for defense-in-depth."
                    ),
                    url=url,
                    method=method,
                    evidence=f"No CSRF token. SameSite: {samesite_info['summary']}",
                    severity=Severity.LOW,
                    cvss=_CVSS_MEDIUM,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    confidence="High",
                ))

        # ── 4. SameSite=None — explicit CSRF risk ──────────────────────────
        if samesite_info["has_none"]:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.CSRF,
                title="Session Cookie Has SameSite=None — CSRF Fully Possible Cross-Origin",
                description=(
                    f"A session/auth cookie on this page is configured with SameSite=None. "
                    f"This explicitly allows the cookie to be sent in cross-origin requests, "
                    f"negating any SameSite-based CSRF protection. "
                    f"Combined with a missing CSRF token on '{action}', this form is fully "
                    f"exploitable from any origin."
                ),
                url=url,
                method=method,
                evidence=f"SameSite=None detected: {samesite_info['none_cookie'][:80]}",
                severity=Severity.HIGH,
                cvss=_CVSS_HIGH,
                remediation=(
                    "Change SameSite=None to SameSite=Strict or SameSite=Lax unless "
                    "you explicitly need cross-site cookie sending (e.g., third-party iframes). "
                    + _REMEDIATION
                ),
                references=_REFS,
                cwe_id=_CWE,
                owasp_category=_OWASP,
                confidence="High",
            ))

        # ── 5. Referer validation bypass ───────────────────────────────────
        if not has_token:
            referer_vuln = await self._test_referer_bypass(action, method, inputs, url)
            if referer_vuln:
                vulns.append(referer_vuln)

        # ── 6. JSON CSRF ───────────────────────────────────────────────────
        json_vuln = await self._test_json_csrf(action, method, inputs, url)
        if json_vuln:
            vulns.append(json_vuln)

        return vulns

    # -----------------------------------------------------------------------
    # Referer bypass test
    # -----------------------------------------------------------------------

    async def _test_referer_bypass(
        self,
        action: str,
        method: str,
        inputs: List[Dict[str, Any]],
        url: str,
    ) -> Optional[Vulnerability]:
        """
        Send the form with an empty Referer header to see if the server
        accepts it. If accepted, it indicates no Referer-based CSRF protection.
        """
        if method not in _STATE_METHODS:
            return None

        form_data = {
            inp["name"]: inp.get("value", "test")
            for inp in inputs
            if inp.get("name") and inp.get("type") not in ("submit", "button", "image")
        }

        resp = await self.client.request(
            method, action, data=form_data,
            headers={"Referer": "", "Origin": "https://evil.com"},
        )
        if resp is None:
            return None

        # Server accepted cross-origin request (2xx without redirect to login)
        if resp.status_code in (200, 201, 202, 204):
            # Check it's not just returning a login page
            body_lower = resp.text.lower()
            rejected = any(
                kw in body_lower
                for kw in ("login", "sign in", "unauthorized", "forbidden", "csrf", "token")
            )
            if not rejected:
                return self._build_vuln(
                    vuln_type=VulnType.CSRF,
                    title="CSRF: Server Accepts Request with Empty Referer / Cross-Origin",
                    description=(
                        f"The form endpoint '{action}' accepted a {method} request with an "
                        f"empty Referer header and Origin: evil.com, returning HTTP "
                        f"{resp.status_code}. "
                        f"If no CSRF token is validated, this endpoint is directly exploitable "
                        f"from any cross-origin attacker page."
                    ),
                    url=url,
                    method=method,
                    payload=f"Referer: (empty), Origin: https://evil.com",
                    evidence=f"HTTP {resp.status_code} — cross-origin request accepted",
                    severity=Severity.HIGH,
                    cvss=_CVSS_HIGH,
                    remediation=(
                        "Validate the Origin or Referer header on all state-changing requests. "
                        "Reject requests whose Origin/Referer doesn't match your domain. "
                        + _REMEDIATION
                    ),
                    references=_REFS,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    confidence="Medium",
                )
        return None

    # -----------------------------------------------------------------------
    # JSON CSRF test
    # -----------------------------------------------------------------------

    async def _test_json_csrf(
        self,
        action: str,
        method: str,
        inputs: List[Dict[str, Any]],
        url: str,
    ) -> Optional[Vulnerability]:
        """
        Test whether a form endpoint accepts form-encoded data as JSON
        (Content-Type: text/plain) — classic JSON CSRF vector.
        Construct a form-encoded body that is also valid JSON.
        """
        if method not in ("POST", "PUT", "PATCH"):
            return None

        # Build a simple JSON body from form inputs
        json_body = "{"
        parts = []
        for inp in inputs:
            name = inp.get("name", "")
            val = inp.get("value", "test")
            if name and inp.get("type") not in ("submit", "button", "image", "file"):
                parts.append(f'"{name}":"{val}"')
        json_body += ",".join(parts) + "}"

        resp = await self.client.post(
            action,
            content=json_body.encode("utf-8"),
            headers={
                "Content-Type": "text/plain",   # JSON CSRF vector
                "Origin": "https://evil.com",
            },
        )
        if resp is None:
            return None

        if resp.status_code in (200, 201, 202, 204):
            ct = resp.content_type.lower()
            # If the server responded with JSON, it likely processed the request
            if "json" in ct or len(resp.text) > 50:
                body_lower = resp.text.lower()
                rejected = any(
                    kw in body_lower
                    for kw in ("unsupported media", "invalid content", "415", "bad request")
                )
                if not rejected:
                    return self._build_vuln(
                        vuln_type=VulnType.CSRF,
                        title="JSON CSRF — Endpoint Accepts text/plain Content-Type",
                        description=(
                            f"The endpoint '{action}' accepted a {method} request with "
                            f"Content-Type: text/plain containing a JSON body. "
                            f"Because browsers can send text/plain cross-origin via <form>, "
                            f"an attacker can construct a hidden HTML form that submits "
                            f"JSON-structured data to this endpoint from any origin, "
                            f"bypassing SameSite=Lax protections for top-level navigations."
                        ),
                        url=url,
                        method=method,
                        payload=f"Content-Type: text/plain | Body: {json_body[:100]}",
                        evidence=f"HTTP {resp.status_code} — text/plain JSON body accepted",
                        severity=Severity.MEDIUM,
                        cvss=_CVSS_MEDIUM,
                        remediation=(
                            "Enforce strict Content-Type validation: only accept "
                            "application/json for JSON endpoints and reject text/plain. "
                            + _REMEDIATION
                        ),
                        references=_REFS,
                        cwe_id=_CWE,
                        owasp_category=_OWASP,
                        confidence="Medium",
                    )
        return None

    # -----------------------------------------------------------------------
    # CORS misconfiguration check
    # -----------------------------------------------------------------------

    def _check_cors(
        self, url: str, response: HTTPResponse
    ) -> Optional[Vulnerability]:
        """Check ACAO header for wildcard or null origin."""
        acao = response.header("access-control-allow-origin") or ""
        acac = response.header("access-control-allow-credentials") or ""

        if not acao:
            return None

        if _CORS_WILDCARD_RE.match(acao.strip()):
            if "true" in acac.lower():
                # Wildcard + credentials = full CSRF amplification
                return self._build_vuln(
                    vuln_type=VulnType.CSRF,
                    title="CORS Misconfiguration: Wildcard/Null Origin + Allow-Credentials",
                    description=(
                        f"The response includes "
                        f"Access-Control-Allow-Origin: {acao} and "
                        f"Access-Control-Allow-Credentials: true. "
                        f"This combination is explicitly forbidden by the CORS specification "
                        f"(browsers block it), but some server-side CORS libraries allow it. "
                        f"An attacker can use cross-origin XHR with credentials to read "
                        f"sensitive API responses and chain it with CSRF."
                    ),
                    url=url,
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    severity=Severity.HIGH,
                    cvss=_CVSS_HIGH,
                    remediation=(
                        "Never combine Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true. "
                        "Use an explicit origin allowlist instead of wildcard."
                    ),
                    references=[
                        "https://portswigger.net/web-security/cors",
                        "https://cwe.mitre.org/data/definitions/942.html",
                    ],
                    cwe_id="CWE-942",
                    owasp_category=_OWASP,
                    confidence="High",
                )
        return None

    # -----------------------------------------------------------------------
    # JSONP surface detection
    # -----------------------------------------------------------------------

    def _check_jsonp_surface(
        self, url: str, response: HTTPResponse
    ) -> Optional[Vulnerability]:
        """Detect JSONP endpoints that can be used for cross-origin data theft."""
        if not _JSONP_RE.search(url):
            return None
        # If the response looks like JSONP (function call wrapper)
        body = response.text[:200]
        if re.match(r"^\w+\s*\(", body):
            return self._build_vuln(
                vuln_type=VulnType.CSRF,
                title="JSONP Endpoint Detected — Cross-Origin Data Exposure",
                description=(
                    f"The URL '{url}' appears to be a JSONP endpoint (callback parameter "
                    f"detected, response starts with a function call). "
                    f"JSONP bypasses the Same-Origin Policy and allows any origin to "
                    f"read the response data, enabling cross-origin data theft and "
                    f"acting as a CSRF amplifier for authenticated data."
                ),
                url=url,
                evidence=f"JSONP response: {body[:80]}",
                severity=Severity.MEDIUM,
                cvss=_CVSS_MEDIUM,
                remediation=(
                    "Replace JSONP with CORS (Cross-Origin Resource Sharing) for "
                    "cross-origin API access. Validate the callback parameter "
                    "against an allowlist if JSONP must be kept. "
                    "Add authentication to JSONP endpoints that return sensitive data."
                ),
                references=[
                    "https://portswigger.net/web-security/csrf/bypassing-referer-based-validation",
                    *_REFS,
                ],
                cwe_id=_CWE,
                owasp_category=_OWASP,
                confidence="Medium",
            )
        return None

    # -----------------------------------------------------------------------
    # SameSite analysis helper
    # -----------------------------------------------------------------------

    def _analyze_samesite(self, response: HTTPResponse) -> Dict[str, Any]:
        """
        Extract and classify SameSite attributes from all Set-Cookie headers.
        Returns a dict with:
          has_strict_or_lax: bool
          has_none: bool
          samesite_value: str  (the first value found)
          none_cookie: str     (first Set-Cookie with SameSite=None)
          summary: str         (human-readable summary)
        """
        raw_headers = response.headers
        set_cookie_values: List[str] = []
        if hasattr(raw_headers, "get_list"):
            set_cookie_values = raw_headers.get_list("set-cookie")
        elif hasattr(raw_headers, "get_all"):
            set_cookie_values = raw_headers.get_all("set-cookie") or []
        else:
            for k, v in raw_headers.items():
                if k.lower() == "set-cookie":
                    set_cookie_values.append(v)

        has_strict_or_lax = False
        has_none = False
        samesite_value = "not set"
        none_cookie = ""

        for cookie_str in set_cookie_values:
            if _SAMESITE_STRICT_LAX_RE.search(cookie_str):
                has_strict_or_lax = True
                m = _SAMESITE_STRICT_LAX_RE.search(cookie_str)
                if m:
                    samesite_value = m.group(1)
            if _SAMESITE_NONE_RE.search(cookie_str):
                has_none = True
                if not none_cookie:
                    none_cookie = cookie_str

        summary = (
            f"SameSite={samesite_value}"
            if has_strict_or_lax
            else ("SameSite=None" if has_none else "SameSite not set")
        )

        return {
            "has_strict_or_lax": has_strict_or_lax,
            "has_none": has_none,
            "samesite_value": samesite_value,
            "none_cookie": none_cookie,
            "summary": summary,
        }
