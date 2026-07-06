"""
Open Redirect Scanner — Professional Grade
===========================================
Coverage:
  • URL parameter detection (name heuristic + value heuristic)
  • All redirect status codes: 301 / 302 / 303 / 307 / 308
  • Meta-refresh redirect detection (client-side redirect in body)
  • JavaScript-based redirect detection (window.location, document.location)
  • Header-based redirect to external: Location, Refresh
  • 20+ encoding bypass variants: double-slash, protocol-relative, scheme
    bypass (https:evil.com), %0a CRLF, null-byte, unicode homoglyphs
  • Form action redirect detection (form action="//evil.com")
  • Host-header injection for redirect chains
  • Relative-vs-absolute redirect validation
  • Whitelist bypass: subdomain tricks, path confusion, query confusion
  • Confidence: High (Location header match) / Medium (body redirect match)

CWE  : CWE-601 (URL Redirection to Untrusted Site)
OWASP: A01:2021 – Broken Access Control
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs

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
    confidentiality=Impact.LOW,
    integrity=Impact.HIGH,
    availability=Impact.NONE,
)

_CVSS_MEDIUM = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.LOW,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_CWE = "CWE-601"
_OWASP = "A01:2021 - Broken Access Control"
_REFS = [
    "https://cwe.mitre.org/data/definitions/601.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/04-Testing_for_Client-Side_URL_Redirect",
]
_REMEDIATION = (
    "1. Validate redirect destinations against a strict allowlist of "
    "permitted URLs or domains. Use exact hostname matching, not substring.\n"
    "2. For relative redirects, ensure the value starts with '/' and contains "
    "no scheme (reject anything matching ://  or //  prefix).\n"
    "3. Use an indirect reference map: store permitted URLs server-side and "
    "pass an integer token to the redirect parameter.\n"
    "4. If redirecting after authentication, use a default safe destination "
    "and only allow the redirect if it matches the allowlist.\n"
    "5. Set the Referrer-Policy header to limit leakage via redirect chains."
)

# ---------------------------------------------------------------------------
# Redirect parameter name heuristic
# ---------------------------------------------------------------------------

_REDIRECT_PARAM_RE = re.compile(
    r"(?i)\b("
    r"redirect(?:_?url|_?uri|_?to|_?path)?|"
    r"return(?:_?url|_?to|_?uri|_?path)?|"
    r"next|goto|target|dest(?:ination)?|"
    r"url|uri|link|href|ref(?:errer?)?|"
    r"forward(?:_?url)?|continue|back|"
    r"location|from|origin|callback|"
    r"rurl|r|go|jump|out|exit|"
    r"success(?:_?url)?|cancel(?:_?url)?|"
    r"logout(?:_?redirect)?|login(?:_?redirect)?"
    r")\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# External redirect payloads — targeting evil.com as canary
# ---------------------------------------------------------------------------

_TARGET_DOMAIN = "evil.com"  # canary domain — never resolves to anything real in prod

_PAYLOADS: List[str] = [
    # Protocol-relative
    f"//{_TARGET_DOMAIN}",
    f"//{_TARGET_DOMAIN}/",
    f"//{_TARGET_DOMAIN}/path",
    # Absolute HTTPS/HTTP
    f"https://{_TARGET_DOMAIN}",
    f"http://{_TARGET_DOMAIN}",
    # Scheme bypass
    f"https:{_TARGET_DOMAIN}",
    f"HTTPS://{_TARGET_DOMAIN}",
    f"//\\\\ {_TARGET_DOMAIN}",        # backslash trick
    f"/\\{_TARGET_DOMAIN}",
    # Triple slash
    f"///{_TARGET_DOMAIN}",
    f"////{_TARGET_DOMAIN}",
    # Whitespace prefix
    f" https://{_TARGET_DOMAIN}",
    f"\thttps://{_TARGET_DOMAIN}",
    f"\nhttps://{_TARGET_DOMAIN}",
    f"\r\nhttps://{_TARGET_DOMAIN}",
    # CRLF injection
    f"https://{_TARGET_DOMAIN}%0d%0a",
    f"%0d%0aLocation:%20https://{_TARGET_DOMAIN}",
    # URL encoding
    f"%2F%2F{_TARGET_DOMAIN}",
    f"%68%74%74%70%73%3A%2F%2F{_TARGET_DOMAIN}",   # https://evil.com encoded
    # Double-URL encoding
    f"%252F%252F{_TARGET_DOMAIN}",
    # Null byte prefix
    f"\x00https://{_TARGET_DOMAIN}",
    f"/%09//{_TARGET_DOMAIN}",
    # Unicode lookalike (IDN homograph bypass)
    f"https://{_TARGET_DOMAIN}%E3%80%82com",        # ideographic full stop
    # Subdomain trick (legitimate.com.evil.com)
    f"https://legitimate.com.{_TARGET_DOMAIN}",
    # Path confusion (https://evil.com?http://legitimate.com)
    f"https://{_TARGET_DOMAIN}?http://legitimate.com",
    # Data / javascript schemes
    f"data:text/html,<script>window.location='https://{_TARGET_DOMAIN}'</script>",
    f"javascript:window.location='https://{_TARGET_DOMAIN}'",
    # Fragment-based confusion
    f"https://{_TARGET_DOMAIN}#legitimate.com",
    # Login confusion
    f"https://legitimate.com@{_TARGET_DOMAIN}",
    f"https://{_TARGET_DOMAIN}@legitimate.com",
]

# ---------------------------------------------------------------------------
# Body-based redirect detection patterns
# ---------------------------------------------------------------------------

_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+content\s*=\s*["\'][^"\']*url\s*=\s*([^\s"\']+)',
    re.IGNORECASE,
)

_JS_REDIRECT_RE = re.compile(
    r"""(?:window|document|top|self|parent)\.location(?:\.href|\.replace\(|\.assign\()?\s*[=\(]\s*["']([^"']{10,})""",
    re.IGNORECASE,
)

_JS_LOCATION_SIMPLE_RE = re.compile(
    r"""location\s*=\s*["']([^"']{10,})""",
    re.IGNORECASE,
)

# Refresh header (non-standard but used by some frameworks)
_REFRESH_HEADER_RE = re.compile(r"url\s*=\s*(.+)", re.IGNORECASE)


# ===========================================================================
# Scanner
# ===========================================================================

class OpenRedirectScanner(_ScannerBase):
    """
    Comprehensive Open Redirect scanner.

    Detection pipeline:
      1. Identify redirect-type parameters (name + value heuristic).
      2. Test all payloads without following redirects.
         - Check Location header → High confidence.
         - Check Refresh header → High confidence.
      3. Follow one redirect and check body for meta-refresh / JS redirect.
      4. Test form action attributes for redirect targets.
      5. Test Host header injection for redirect chains.
    """

    name = "Open Redirect"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        seen: set = set()

        parsed = urlparse(url)
        params = self._extract_url_params(url)

        # ── URL parameter testing ────────────────────────────────────────────
        redirect_params = [p for p in params if _REDIRECT_PARAM_RE.search(p)]

        # Also check if any current param VALUE already looks like a URL
        raw_params = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in raw_params.items():
            if name not in redirect_params:
                val = values[0] if values else ""
                if val.startswith(("http://", "https://", "//")):
                    redirect_params.append(name)

        for param in redirect_params:
            if param in seen:
                continue
            seen.add(param)
            for v in await self._test_param(url, param):
                vulns.append(v)
                if v.confidence == "High":
                    return vulns  # Stop on confirmed redirect

        # ── Form action redirect ─────────────────────────────────────────────
        for form in forms:
            action = form.get("action") or url
            for v in self._check_form_action_redirect(action, url):
                vulns.append(v)

            # Test redirect params within forms
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                if not name or not _REDIRECT_PARAM_RE.search(name):
                    continue
                form_action = form.get("action") or url
                method = (form.get("method") or "GET").upper()
                for v in await self._test_form_redirect_param(form_action, method, form, name):
                    vulns.append(v)
                    break

        # ── Host header injection ────────────────────────────────────────────
        host_vulns = await self._test_host_header_redirect(url)
        vulns.extend(host_vulns)

        return vulns

    # -----------------------------------------------------------------------
    # URL parameter redirect testing
    # -----------------------------------------------------------------------

    async def _test_param(
        self, url: str, param: str
    ) -> List[Vulnerability]:
        for payload in _PAYLOADS:
            injected = self._inject_param(url, param, payload)

            # ── No-redirect GET: check Location header ───────────────────
            resp = await self.client.get_no_redirect(injected)
            if resp is None:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.header("location") or resp.header("Location") or ""
                if location and self._is_external(location, url):
                    return [self._build_vuln(
                        vuln_type=VulnType.OPEN_REDIRECT,
                        title=f"Open Redirect via Location Header (param: {param})",
                        description=(
                            f"Parameter '{param}' is vulnerable to open redirect. "
                            f"Setting '{param}={payload}' caused the server to issue "
                            f"HTTP {resp.status_code} with Location: {location}. "
                            f"An attacker can craft a URL on your trusted domain that "
                            f"silently redirects victims to a malicious site, enabling "
                            f"credential phishing, OAuth token theft, and drive-by attacks."
                        ),
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"HTTP {resp.status_code} Location: {location}",
                        method="GET",
                        severity=Severity.HIGH,
                        cvss=_CVSS_HIGH,
                        remediation=_REMEDIATION,
                        references=_REFS,
                        cwe_id=_CWE,
                        owasp_category=_OWASP,
                        confidence="High",
                    )]

            # ── Refresh header ───────────────────────────────────────────
            refresh = resp.header("refresh") or resp.header("Refresh") or ""
            if refresh:
                m = _REFRESH_HEADER_RE.search(refresh)
                if m:
                    dest = m.group(1).strip().strip('"\'')
                    if self._is_external(dest, url):
                        return [self._build_vuln(
                            vuln_type=VulnType.OPEN_REDIRECT,
                            title=f"Open Redirect via Refresh Header (param: {param})",
                            description=(
                                f"Parameter '{param}' with payload '{payload}' caused the "
                                f"server to issue a Refresh: header redirecting to '{dest}'. "
                                f"Refresh-header redirects are transparent to users and "
                                f"less likely to be caught by URL validation filters."
                            ),
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Refresh: {refresh[:150]}",
                            method="GET",
                            severity=Severity.HIGH,
                            cvss=_CVSS_HIGH,
                            remediation=_REMEDIATION,
                            references=_REFS,
                            cwe_id=_CWE,
                            owasp_category=_OWASP,
                            confidence="High",
                        )]

            # ── Body: meta-refresh / JavaScript redirect ─────────────────
            if resp.is_text:
                body_vuln = self._check_body_redirect(resp.text, url, param, payload)
                if body_vuln:
                    return [body_vuln]

        return []

    # -----------------------------------------------------------------------
    # Body redirect detection (meta-refresh, JS)
    # -----------------------------------------------------------------------

    def _check_body_redirect(
        self,
        body: str,
        url: str,
        param: str,
        payload: str,
    ) -> Optional[Vulnerability]:
        """Check for client-side redirects in page body."""
        # Meta-refresh
        m = _META_REFRESH_RE.search(body)
        if m:
            dest = m.group(1).strip().strip('"\'')
            if self._is_external(dest, url):
                return self._build_vuln(
                    vuln_type=VulnType.OPEN_REDIRECT,
                    title=f"Open Redirect via Meta-Refresh (param: {param})",
                    description=(
                        f"Parameter '{param}' with payload '{payload}' caused a "
                        f"<meta http-equiv=refresh> tag redirecting to '{dest}'. "
                        f"Client-side meta-refresh redirects bypass HTTP-level WAF "
                        f"redirect detection."
                    ),
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"<meta refresh> to: {dest}",
                    method="GET",
                    severity=Severity.MEDIUM,
                    cvss=_CVSS_MEDIUM,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    confidence="Medium",
                )

        # JavaScript redirect
        for pattern in (_JS_REDIRECT_RE, _JS_LOCATION_SIMPLE_RE):
            for m in pattern.finditer(body):
                dest = m.group(1).strip()
                if self._is_external(dest, url):
                    return self._build_vuln(
                        vuln_type=VulnType.OPEN_REDIRECT,
                        title=f"Open Redirect via JavaScript (param: {param})",
                        description=(
                            f"Parameter '{param}' with payload '{payload}' caused a "
                            f"JavaScript redirect to '{dest}'. JS-based redirects are "
                            f"harder to detect at the network layer and can be combined "
                            f"with DOM XSS chains."
                        ),
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"JS redirect to: {dest}",
                        method="GET",
                        severity=Severity.MEDIUM,
                        cvss=_CVSS_MEDIUM,
                        remediation=_REMEDIATION,
                        references=_REFS,
                        cwe_id=_CWE,
                        owasp_category=_OWASP,
                        confidence="Medium",
                    )
        return None

    # -----------------------------------------------------------------------
    # Form action redirect
    # -----------------------------------------------------------------------

    def _check_form_action_redirect(
        self, action: str, page_url: str
    ) -> List[Vulnerability]:
        """Check if a form's action attribute points to an external domain."""
        if not action:
            return []
        if self._is_external(action, page_url):
            return [self._build_vuln(
                vuln_type=VulnType.OPEN_REDIRECT,
                title="Potential Open Redirect via Form Action to External Domain",
                description=(
                    f"A form on this page has its action attribute pointing to an "
                    f"external domain: '{action}'. Form submissions may redirect "
                    f"users to an unintended external site, enabling credential "
                    f"phishing if the form contains password fields."
                ),
                url=page_url,
                parameter="form action",
                payload=action,
                evidence=f"form action: {action}",
                method="POST",
                severity=Severity.MEDIUM,
                cvss=_CVSS_MEDIUM,
                remediation=_REMEDIATION,
                references=_REFS,
                cwe_id=_CWE,
                owasp_category=_OWASP,
                confidence="Medium",
            )]
        return []

    # -----------------------------------------------------------------------
    # Form redirect parameter testing
    # -----------------------------------------------------------------------

    async def _test_form_redirect_param(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
    ) -> List[Vulnerability]:
        for payload in _PAYLOADS[:10]:
            form_data = {
                inp["name"]: (
                    payload if inp["name"] == param_name
                    else inp.get("value", "test")
                )
                for inp in form.get("inputs", [])
                if inp.get("name")
            }

            if method == "POST":
                resp = await self.client.request(
                    "POST", action, data=form_data, allow_redirects=False
                )
            else:
                resp = await self.client.get_no_redirect(action, params=form_data)

            if resp is None:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.header("location") or ""
                if location and self._is_external(location, action):
                    return [self._build_vuln(
                        vuln_type=VulnType.OPEN_REDIRECT,
                        title=f"Open Redirect in Form Field '{param_name}'",
                        description=(
                            f"Form field '{param_name}' at {action} ({method}) is vulnerable "
                            f"to open redirect. Setting it to '{payload}' caused HTTP "
                            f"{resp.status_code} with Location: {location}."
                        ),
                        url=action,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"HTTP {resp.status_code} Location: {location}",
                        method=method,
                        severity=Severity.HIGH,
                        cvss=_CVSS_HIGH,
                        remediation=_REMEDIATION,
                        references=_REFS,
                        cwe_id=_CWE,
                        owasp_category=_OWASP,
                        confidence="High",
                    )]
        return []

    # -----------------------------------------------------------------------
    # Host header injection redirect
    # -----------------------------------------------------------------------

    async def _test_host_header_redirect(self, url: str) -> List[Vulnerability]:
        """
        Test if injecting a spoofed Host header causes the server to redirect
        to that host. Some frameworks use Host to build absolute redirect URLs.
        """
        parsed = urlparse(url)
        for evil_host in (_TARGET_DOMAIN, f"evil.{parsed.hostname}"):
            resp = await self.client.get_no_redirect(
                url,
                headers={"Host": evil_host},
            )
            if resp is None:
                continue
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.header("location") or ""
                if evil_host in location:
                    return [self._build_vuln(
                        vuln_type=VulnType.OPEN_REDIRECT,
                        title="Open Redirect via Host Header Injection",
                        description=(
                            f"Injecting a spoofed Host header '{evil_host}' caused the "
                            f"server to redirect to Location: {location}. "
                            f"The application uses the Host header to construct absolute "
                            f"redirect URLs, enabling an attacker to craft password-reset "
                            f"or OAuth callback URLs on the victim's behalf."
                        ),
                        url=url,
                        parameter="Host header",
                        payload=evil_host,
                        evidence=f"Host: {evil_host} → Location: {location}",
                        method="GET",
                        severity=Severity.HIGH,
                        cvss=_CVSS_HIGH,
                        remediation=(
                            "Do not use the Host header to build redirect URLs. "
                            "Use a configured application base URL instead. "
                            + _REMEDIATION
                        ),
                        references=_REFS,
                        cwe_id=_CWE,
                        owasp_category=_OWASP,
                        confidence="High",
                    )]
        return []

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _is_external(self, location: str, original_url: str) -> bool:
        """
        Return True if `location` redirects to a different host than `original_url`.
        Handles protocol-relative, relative, and absolute URLs.
        """
        if not location:
            return False
        # Pure relative path (starts with / but not //)
        if location.startswith("/") and not location.startswith("//"):
            return False
        # Relative path with no scheme
        if not re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+\-.]*:|//)", location):
            return False
        try:
            original_host = urlparse(original_url).hostname or ""
            # Handle protocol-relative
            if location.startswith("//"):
                location = "https:" + location
            redirect_host = urlparse(location).hostname or ""
            if not redirect_host:
                return False
            # Case-insensitive exact match
            return redirect_host.lower() != original_host.lower()
        except Exception:
            return False
