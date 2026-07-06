"""
Security Headers Analyzer — Professional Grade
================================================
Coverage:
  • Missing security headers: HSTS, X-Frame-Options, X-Content-Type-Options,
    CSP, Referrer-Policy, Permissions-Policy, COEP, COOP, CORP
  • HSTS quality: max-age too short, missing includeSubDomains / preload
  • CSP deep analysis: unsafe-inline/eval, wildcard, data:, missing default-src,
    object-src not 'none', base-uri unrestricted, form-action unrestricted,
    frame-ancestors absent, nonce without strict-dynamic, report-only only
  • Insecure cookies: HttpOnly, Secure, SameSite, SameSite=None without Secure,
    excessive expiry, overly broad Domain, predictable short value
  • Technology disclosure: Server, X-Powered-By, X-AspNet-Version,
    X-Debug-Token, X-DebugKit-*, X-Environment, internal IPs in Via/headers
  • Sensitive data in body: secrets, keys, tokens, stack traces,
    HTML comments with secrets, internal hostnames
  • CORS misconfiguration: wildcard + credentials, null origin + credentials
  • HTTP request smuggling hints: TE+CL, chunked + CL, CL on 304/204
  • Cache-Control missing no-store on authenticated-looking pages
  • Server-Timing / X-Runtime information leakage
  • Deprecated / dangerous headers: HPKP, X-XSS-Protection: 0
  • ETag format fingerprinting

CWE  : CWE-693, CWE-614, CWE-200, CWE-444
OWASP: A05:2021 – Security Misconfiguration
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability, Severity, VulnType, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)
from ..utils.helpers import parse_cookie_attributes
from ..utils.patterns import SENSITIVE_DATA_COMPILED, TECH_FINGERPRINTS
from ..utils.payloads import INSECURE_RESPONSE_HEADERS

# ---------------------------------------------------------------------------
# CVSS helpers
# ---------------------------------------------------------------------------

def _cvss(av=AttackVector.NETWORK, ac=AttackComplexity.LOW, pr=PrivilegesRequired.NONE,
          ui=UserInteraction.NONE, s=Scope.UNCHANGED,
          c=Impact.LOW, i=Impact.LOW, a=Impact.NONE) -> CVSSv3:
    return CVSSv3(attack_vector=av, attack_complexity=ac, privileges_required=pr,
                  user_interaction=ui, scope=s, confidentiality=c,
                  integrity=i, availability=a)

_CVSS_HIGH   = _cvss(ui=UserInteraction.NONE, c=Impact.HIGH, i=Impact.HIGH)
_CVSS_MEDIUM = _cvss(ui=UserInteraction.REQUIRED, c=Impact.LOW,  i=Impact.LOW)
_CVSS_LOW    = _cvss(ui=UserInteraction.REQUIRED, c=Impact.LOW,  i=Impact.NONE)
_CVSS_INFO   = _cvss(ui=UserInteraction.REQUIRED, c=Impact.NONE, i=Impact.NONE, a=Impact.NONE)

# ---------------------------------------------------------------------------
# Shared references
# ---------------------------------------------------------------------------

_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_OWASP_CRYPTO    = "A02:2021 - Cryptographic Failures"
_REFS_HEADERS    = [
    "https://securityheaders.com",
    "https://owasp.org/www-project-secure-headers/",
]
_REFS_CSP = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "https://csp-evaluator.withgoogle.com/",
]
_REFS_COOKIE = ["https://owasp.org/www-community/controls/SecureCookieAttribute"]

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# HTML comment potentially containing credentials
_HTML_COMMENT_SECRET_RE = re.compile(
    r"<!--.*?(?:password|passwd|secret|key|token|api[_\-]?key|credential|auth)[^>]{0,120}-->",
    re.IGNORECASE | re.DOTALL,
)

# Stack traces
_STACKTRACE_RE = re.compile(
    r"(?:Traceback \(most recent call last\)|"
    r"at [a-zA-Z_$][\w$]*\.[a-zA-Z_$][\w$]*\(|"
    r"Fatal error:|Parse error:|Warning:.*on line \d+|"
    r"System\.Web\.HttpUnhandledException|"
    r"Microsoft\.CSharp\.RuntimeBinder|"
    r"javax\.servlet\.ServletException)",
    re.IGNORECASE,
)

# Internal hostnames / IPs in response body
_INTERNAL_HOST_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"localhost)\b",
)

# Mixed content: http:// resource in HTTPS page
_MIXED_CONTENT_RE = re.compile(
    r'(?:src|href|action|data)\s*=\s*["\']http://[^"\']{8,}',
    re.IGNORECASE,
)

# Authentication indicators in page (to decide if cache-control matters)
_AUTH_PAGE_RE = re.compile(
    r"(?:logout|sign.?out|my.?account|dashboard|profile|settings|"
    r"authorization|bearer|session|csrf)",
    re.IGNORECASE,
)

# Debug / environment headers
_DEBUG_HEADERS = [
    "x-debug-token", "x-debug-token-link", "x-debugkit",
    "x-debug-info", "x-environment", "x-stage", "x-app-env",
    "x-rack-cache", "x-request-id", "x-correlation-id",
]

# Timing / runtime leakage headers
_TIMING_HEADERS = ["server-timing", "x-runtime", "x-response-time", "x-elapsed"]

# HSTS minimum acceptable max-age (1 year)
_HSTS_MIN_MAX_AGE = 31_536_000

# Cookie max acceptable expiry (1 year in seconds)
_COOKIE_MAX_EXPIRY = 365 * 24 * 3600

# Short / predictable cookie value patterns
_WEAK_COOKIE_VALUE_RE = re.compile(
    r"^(?:0+|1+|[a-z]{1,8}|\d{1,8}|admin|test|guest|user|session)$",
    re.IGNORECASE,
)

# CSP directive parsers
_CSP_DIRECTIVE_RE = re.compile(r"(\S+)\s+([^;]+)", re.IGNORECASE)


# ===========================================================================
# SecurityHeadersScanner
# ===========================================================================

class SecurityHeadersScanner(_ScannerBase):
    """
    Comprehensive HTTP security header analyzer.
    Runs once per target (is_target_level=True).
    """

    name = "Security Headers"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        vulns.extend(self._check_missing_headers(url, response))
        vulns.extend(self._check_hsts_quality(url, response))
        vulns.extend(self._check_csp_deep(url, response))
        vulns.extend(self._check_cookies(url, response))
        vulns.extend(self._check_cors(url, response))
        vulns.extend(self._check_technology_disclosure(url, response))
        vulns.extend(self._check_debug_headers(url, response))
        vulns.extend(self._check_timing_leakage(url, response))
        vulns.extend(self._check_sensitive_data_in_body(url, response))
        vulns.extend(self._check_smuggling_hints(url, response))
        vulns.extend(self._check_cache_control(url, response))
        vulns.extend(self._check_mixed_content(url, response))
        vulns.extend(self._check_deprecated_headers(url, response))

        return vulns

    # -----------------------------------------------------------------------
    # 1. Missing security headers
    # -----------------------------------------------------------------------

    def _check_missing_headers(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        present = {k.lower() for k in response.headers.keys()}
        is_https = url.startswith("https://")

        checks = [
            (
                "strict-transport-security",
                "Missing HTTP Strict Transport Security (HSTS)",
                ("HSTS is absent. Browsers may connect over plain HTTP, enabling SSL-strip MITM attacks."),
                Severity.HIGH, "CWE-319",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                _CVSS_HIGH,
            ),
            (
                "x-frame-options",
                "Missing X-Frame-Options Header",
                ("X-Frame-Options is absent and CSP frame-ancestors is not set. "
                 "The page can be embedded in iframes enabling clickjacking attacks."),
                Severity.MEDIUM, "CWE-1021",
                "Add: X-Frame-Options: DENY. Or use CSP: frame-ancestors 'none'.",
                _CVSS_MEDIUM,
            ),
            (
                "x-content-type-options",
                "Missing X-Content-Type-Options Header",
                ("Without nosniff, browsers may MIME-sniff responses, enabling XSS "
                 "via uploaded files with wrong content-type."),
                Severity.LOW, "CWE-693",
                "Add: X-Content-Type-Options: nosniff",
                _CVSS_LOW,
            ),
            (
                "content-security-policy",
                "Missing Content-Security-Policy (CSP)",
                ("No CSP header found. Any XSS vulnerability on this page is fully exploitable "
                 "without restriction — attackers can exfiltrate cookies, keylog, redirect, etc."),
                Severity.MEDIUM, "CWE-693",
                "Implement CSP with at least: default-src 'self'; script-src 'self'; object-src 'none'",
                _CVSS_MEDIUM,
            ),
            (
                "referrer-policy",
                "Missing Referrer-Policy Header",
                ("Without Referrer-Policy, the browser sends the full URL including sensitive "
                 "query parameters in the Referer header to third-party sites."),
                Severity.LOW, "CWE-200",
                "Add: Referrer-Policy: strict-origin-when-cross-origin",
                _CVSS_LOW,
            ),
            (
                "permissions-policy",
                "Missing Permissions-Policy Header",
                ("Without Permissions-Policy, embedded content can access browser features "
                 "(camera, microphone, geolocation, payment) without restriction."),
                Severity.LOW, "CWE-693",
                "Add: Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()",
                _CVSS_LOW,
            ),
            (
                "cross-origin-embedder-policy",
                "Missing Cross-Origin-Embedder-Policy (COEP)",
                ("COEP is absent. Required for cross-origin isolation, which prevents "
                 "Spectre/side-channel attacks against the page's process memory."),
                Severity.LOW, "CWE-693",
                "Add: Cross-Origin-Embedder-Policy: require-corp",
                _CVSS_LOW,
            ),
            (
                "cross-origin-opener-policy",
                "Missing Cross-Origin-Opener-Policy (COOP)",
                ("COOP is absent. Without it, cross-origin pages can access this page's "
                 "window object, enabling XS-Leaks and cross-origin data theft."),
                Severity.LOW, "CWE-693",
                "Add: Cross-Origin-Opener-Policy: same-origin",
                _CVSS_LOW,
            ),
            (
                "cross-origin-resource-policy",
                "Missing Cross-Origin-Resource-Policy (CORP)",
                ("CORP is absent. Any cross-origin site can include this resource, "
                 "potentially leaking its content via side-channels."),
                Severity.LOW, "CWE-693",
                "Add: Cross-Origin-Resource-Policy: same-site",
                _CVSS_LOW,
            ),
        ]

        for header, title, desc, severity, cwe, remediation, cvss in checks:
            # Skip HSTS check on HTTP pages (it can only be set on HTTPS)
            if header == "strict-transport-security" and not is_https:
                continue
            # Skip COEP/COOP/CORP if already missing CSP (noise reduction for non-advanced)
            if header in ("cross-origin-embedder-policy", "cross-origin-opener-policy",
                          "cross-origin-resource-policy") and "content-security-policy" not in present:
                continue
            if header not in present:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SECURITY_HEADERS,
                    title=title, description=desc, url=url,
                    severity=severity, remediation=remediation,
                    references=_REFS_HEADERS, cwe_id=cwe,
                    owasp_category=_OWASP_MISCONFIG, cvss=cvss, confidence="High",
                ))

        return vulns

    # -----------------------------------------------------------------------
    # 2. HSTS quality
    # -----------------------------------------------------------------------

    def _check_hsts_quality(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not url.startswith("https://"):
            return vulns
        hsts = response.header("strict-transport-security") or ""
        if not hsts:
            return vulns  # Already flagged as missing above

        issues: List[str] = []

        # max-age
        ma = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if ma:
            max_age = int(ma.group(1))
            if max_age < _HSTS_MIN_MAX_AGE:
                issues.append(f"max-age={max_age} is below the recommended 31536000 (1 year)")
        else:
            issues.append("max-age directive is missing")

        if "includesubdomains" not in hsts.lower():
            issues.append("includeSubDomains is absent — subdomains not protected")

        if "preload" not in hsts.lower():
            issues.append("preload is absent — not eligible for HSTS preload list")

        if issues:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SECURITY_HEADERS,
                title="Weak HSTS Configuration",
                description=(
                    f"The HSTS header is present but has weaknesses: {'; '.join(issues)}. "
                    f"A short max-age allows downgrade attacks during the window period. "
                    f"Without includeSubDomains, subdomains remain vulnerable to SSL-strip. "
                    f"Without preload, first-visit HTTPS-downgrade attacks are still possible."
                ),
                url=url,
                evidence=f"Strict-Transport-Security: {hsts}",
                severity=Severity.MEDIUM,
                remediation="Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                references=["https://hstspreload.org/", *_REFS_HEADERS],
                cwe_id="CWE-319",
                owasp_category=_OWASP_MISCONFIG,
                cvss=_CVSS_MEDIUM, confidence="High",
            ))
        return vulns

    # -----------------------------------------------------------------------
    # 3. CSP deep analysis
    # -----------------------------------------------------------------------

    def _check_csp_deep(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        csp_header = (
            response.header("content-security-policy") or
            response.header("content-security-policy-report-only") or ""
        )
        if not csp_header:
            return vulns  # Missing CSP flagged elsewhere

        is_report_only = bool(response.header("content-security-policy-report-only")) and \
                         not response.header("content-security-policy")

        directives: Dict[str, str] = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            m = re.match(r"^(\S+)\s*(.*)", part)
            if m:
                directives[m.group(1).lower()] = m.group(2).strip()

        issues: List[str] = []
        severity = Severity.INFO

        # Report-only mode only
        if is_report_only:
            issues.append("CSP is in report-only mode — no enforcement, only logging")
            severity = Severity.MEDIUM

        # Get effective script policy (script-src or fallback to default-src)
        script_src = directives.get("script-src", directives.get("default-src", ""))
        default_src = directives.get("default-src", "")

        # Missing default-src
        if "default-src" not in directives:
            issues.append("Missing default-src — no catch-all fallback for unlisted resource types")
            severity = max(severity, Severity.MEDIUM)

        # unsafe-inline in script-src
        if "'unsafe-inline'" in script_src.lower():
            issues.append("'unsafe-inline' in script-src allows arbitrary inline script execution")
            severity = max(severity, Severity.HIGH)

        # unsafe-eval
        if "'unsafe-eval'" in script_src.lower():
            issues.append("'unsafe-eval' allows eval()/Function() execution — enables XSS via eval")
            severity = max(severity, Severity.HIGH)

        # Wildcard source in script-src
        if re.search(r"(?:^|\s)\*(?:\s|$)", script_src):
            issues.append("Wildcard (*) in script-src allows scripts from any origin")
            severity = max(severity, Severity.HIGH)

        # data: in script-src
        if "data:" in script_src.lower():
            issues.append("data: URI in script-src enables data URI script execution")
            severity = max(severity, Severity.HIGH)

        # blob: in script-src
        if "blob:" in script_src.lower():
            issues.append("blob: in script-src enables blob URL script execution")
            severity = max(severity, Severity.MEDIUM)

        # object-src not 'none'
        obj_src = directives.get("object-src", default_src)
        if obj_src.lower() != "'none'" and "'none'" not in obj_src.lower():
            issues.append("object-src is not 'none' — Flash/plugin-based XSS possible")
            severity = max(severity, Severity.MEDIUM)

        # base-uri not restricted
        base_uri = directives.get("base-uri", "")
        if not base_uri or ("*" in base_uri):
            issues.append("base-uri is unrestricted — base tag injection can redirect all relative URLs")
            severity = max(severity, Severity.MEDIUM)

        # form-action not restricted
        form_action = directives.get("form-action", "")
        if not form_action:
            issues.append("form-action not set — form submissions can be hijacked to any origin")
            severity = max(severity, Severity.MEDIUM)

        # frame-ancestors not set (clickjacking via CSP)
        frame_anc = directives.get("frame-ancestors", "")
        if not frame_anc and "x-frame-options" not in {k.lower() for k in response.headers.keys()}:
            issues.append("frame-ancestors not set in CSP and X-Frame-Options absent — clickjacking possible")
            severity = max(severity, Severity.MEDIUM)

        # Nonce without strict-dynamic
        has_nonce = bool(re.search(r"'nonce-[^']+'\s", csp_header, re.I))
        if has_nonce and "'strict-dynamic'" not in csp_header.lower():
            issues.append("Nonce-based CSP without 'strict-dynamic' — whitelisted script hosts can be abused")
            severity = max(severity, Severity.LOW)

        # Fix 5.2: Additional CSP checks
        # http: scheme in script-src (insecure resource loading)
        if re.search(r"script-src[^;]*\bhttp:", csp_header, re.I):
            issues.append("http: scheme in script-src — scripts can be loaded over plain HTTP (MITM risk)")
            severity = max(severity, Severity.HIGH)

        # Missing object-src entirely (different from "not 'none'" — catch absent directive)
        if "object-src" not in directives and "default-src" not in directives:
            issues.append("object-src absent and no default-src fallback — Flash/plugin XSS unrestricted")
            severity = max(severity, Severity.HIGH)

        # base-uri with wildcard specifically
        if base_uri and "*" in base_uri:
            issues.append("base-uri with wildcard (*) — base tag injection can point to any origin")
            severity = max(severity, Severity.HIGH)

        # Missing frame-ancestors and X-Frame-Options (clickjacking)
        # (already checked above, but add specific note if only CSP route is available)
        if not frame_anc:
            # Already added above, but check if X-Frame-Options is also absent
            xfo = response.header("x-frame-options") or ""
            if not xfo:
                if "frame-ancestors not set" not in " ".join(issues):
                    issues.append("frame-ancestors not set — clickjacking possible without X-Frame-Options either")
                    severity = max(severity, Severity.MEDIUM)

        # Fix 3.8: CDN wildcard subdomain bypass
        # *.cdn.com in script-src allows any CDN subdomain to serve scripts
        cdn_wildcard = re.search(
            r"script-src[^;]*\*\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", csp_header, re.I
        )
        if cdn_wildcard:
            matched = cdn_wildcard.group(0).split()[-1]  # extract the *.domain.com part
            issues.append(
                f"Wildcard CDN subdomain in script-src: '{matched}' — "
                "any subdomain of that CDN can serve malicious scripts"
            )
            severity = max(severity, Severity.HIGH)

        # Fix 3.8: JSONP bypass via known CDN hosts that serve JSONP endpoints
        # These domains have publicly accessible JSONP callbacks that bypass CSP
        _JSONP_BYPASS_DOMAINS = [
            ("ajax.googleapis.com",  "Google AJAX Libraries CDN — has JSONP endpoints"),
            ("cdnjs.cloudflare.com", "Cloudflare cdnjs — some versions serve JSONP"),
            ("cdn.jsdelivr.net",     "jsDelivr CDN — arbitrary package endpoints callable as JSONP"),
            ("code.jquery.com",      "jQuery CDN — older versions have JSONP helpers"),
        ]
        for domain, reason in _JSONP_BYPASS_DOMAINS:
            if domain in csp_header.lower():
                issues.append(
                    f"'{domain}' in script-src — {reason}. "
                    "JSONP endpoints on whitelisted CDNs can bypass CSP."
                )
                severity = max(severity, Severity.MEDIUM)

        if issues:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SECURITY_HEADERS,
                title="Weak / Misconfigured Content Security Policy",
                description=(
                    f"The CSP header is present but has {len(issues)} weakness(es): "
                    f"{'; '.join(issues)}. "
                    f"These weaknesses significantly reduce XSS mitigation effectiveness."
                ),
                url=url,
                evidence=f"CSP: {csp_header[:300]}",
                severity=severity,
                remediation=(
                    "Tighten the CSP:\n"
                    "  script-src 'nonce-{random}' 'strict-dynamic';\n"
                    "  object-src 'none';\n"
                    "  base-uri 'self';\n"
                    "  form-action 'self';\n"
                    "  frame-ancestors 'none';\n"
                    "  default-src 'self';\n"
                    "Evaluate at: https://csp-evaluator.withgoogle.com/"
                ),
                references=_REFS_CSP,
                cwe_id="CWE-693",
                owasp_category=_OWASP_MISCONFIG,
                cvss=_CVSS_MEDIUM if severity == Severity.HIGH else _CVSS_LOW,
                confidence="High",
            ))
        return vulns

    # -----------------------------------------------------------------------
    # 4. Insecure cookies
    # -----------------------------------------------------------------------

    def _check_cookies(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        is_https = url.startswith("https://")

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

        reported_names: set = set()

        for header_val in set_cookie_values:
            cookie = parse_cookie_attributes(header_val)
            attrs = cookie.get("attributes", {})
            name = cookie.get("name", "unknown")
            value = cookie.get("value", "")

            if name in reported_names:
                continue
            reported_names.add(name)

            issues: List[str] = []
            severity = Severity.LOW

            # HttpOnly
            if "httponly" not in attrs:
                issues.append("missing HttpOnly — XSS can steal this cookie via document.cookie")
                severity = max(severity, Severity.MEDIUM)

            # Secure (only relevant on HTTPS pages)
            if is_https and "secure" not in attrs:
                issues.append("missing Secure flag — cookie sent over plain HTTP")
                severity = max(severity, Severity.MEDIUM)

            # SameSite
            samesite = attrs.get("samesite", "").lower()
            if not samesite:
                issues.append("missing SameSite — vulnerable to CSRF")
                severity = max(severity, Severity.MEDIUM)
            elif samesite == "none":
                if "secure" not in attrs:
                    issues.append("SameSite=None without Secure flag — rejected by modern browsers")
                    severity = max(severity, Severity.MEDIUM)
                else:
                    issues.append("SameSite=None — explicitly allows cross-origin cookie sending (CSRF risk)")
                    severity = max(severity, Severity.LOW)

            # Excessive expiry
            max_age = attrs.get("max-age", "")
            expires = attrs.get("expires", "")
            if max_age:
                try:
                    if int(max_age) > _COOKIE_MAX_EXPIRY:
                        issues.append(f"max-age={max_age}s > 1 year — excessively long session lifetime")
                        severity = max(severity, Severity.LOW)
                except ValueError:
                    pass

            # Overly broad Domain
            domain = attrs.get("domain", "")
            if domain.startswith("."):
                issues.append(f"Domain={domain} — cookie shared across all subdomains")
                severity = max(severity, Severity.LOW)

            # Predictable / short value (only flag session-type cookies)
            is_session_cookie = any(
                k in name.lower() for k in ("session", "sid", "auth", "token", "jwt")
            )
            if is_session_cookie and value and (len(value) < 16 or _WEAK_COOKIE_VALUE_RE.match(value)):
                issues.append(f"short/predictable value ('{value[:20]}') — session token may be guessable")
                severity = max(severity, Severity.HIGH)

            if issues:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SECURITY_HEADERS,
                    title=f"Insecure Cookie: {name}",
                    description=(
                        f"Cookie '{name}' has {len(issues)} security issue(s): "
                        f"{', '.join(issues)}."
                    ),
                    url=url,
                    evidence=f"Set-Cookie: {header_val[:150]}",
                    severity=severity,
                    remediation=f"Set '{name}' with: HttpOnly; Secure; SameSite=Strict; Path=/",
                    references=_REFS_COOKIE,
                    cwe_id="CWE-614",
                    owasp_category=_OWASP_CRYPTO,
                    confidence="High",
                ))

        return vulns

    # -----------------------------------------------------------------------
    # 5. CORS misconfiguration
    # -----------------------------------------------------------------------

    def _check_cors(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        acao = response.header("access-control-allow-origin") or ""
        acac = (response.header("access-control-allow-credentials") or "").lower()
        acao_stripped = acao.strip()

        if not acao_stripped:
            return vulns

        credentials_true = acac == "true"

        if acao_stripped in ("*", "null"):
            if credentials_true:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SECURITY_HEADERS,
                    title=f"CORS Misconfiguration: '{acao_stripped}' Origin + Allow-Credentials",
                    description=(
                        f"Access-Control-Allow-Origin: {acao_stripped} combined with "
                        f"Access-Control-Allow-Credentials: true is a critical CORS misconfiguration. "
                        f"An attacker from any origin (or via null-origin sandboxed iframe) can make "
                        f"credentialed cross-origin requests and read the full authenticated response, "
                        f"leading to account takeover and data theft."
                    ),
                    url=url,
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    severity=Severity.CRITICAL,
                    cvss=_CVSS_HIGH,
                    remediation=(
                        "Never combine ACAO: * or null with ACAC: true. "
                        "Maintain an explicit allowlist of trusted origins and reflect only "
                        "validated origins in the ACAO header."
                    ),
                    references=[
                        "https://portswigger.net/web-security/cors",
                        "https://cwe.mitre.org/data/definitions/942.html",
                    ],
                    cwe_id="CWE-942",
                    owasp_category=_OWASP_MISCONFIG,
                    confidence="High",
                ))
            else:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SECURITY_HEADERS,
                    title=f"CORS: Wildcard Origin Allowed ({acao_stripped})",
                    description=(
                        f"Access-Control-Allow-Origin: {acao_stripped} permits any origin to read "
                        f"this response. While credentials are not allowed, any cross-origin script "
                        f"can read public API responses. If this endpoint returns sensitive public data, "
                        f"restrict the allowed origins."
                    ),
                    url=url,
                    evidence=f"ACAO: {acao}",
                    severity=Severity.LOW,
                    remediation="Restrict ACAO to specific trusted origins unless the API is intentionally public.",
                    references=["https://portswigger.net/web-security/cors"],
                    cwe_id="CWE-942",
                    owasp_category=_OWASP_MISCONFIG,
                    confidence="High",
                ))

        return vulns

    # -----------------------------------------------------------------------
    # 6. Technology disclosure
    # -----------------------------------------------------------------------

    def _check_technology_disclosure(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # Version-disclosing headers
        for header_name in INSECURE_RESPONSE_HEADERS:
            val = response.header(header_name)
            if val:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    title=f"Technology Version Disclosed: {header_name}",
                    description=(
                        f"The '{header_name}' header reveals server technology/version: '{val}'. "
                        f"Attackers use version fingerprints to identify known CVEs and target "
                        f"exploit code specifically for the disclosed version."
                    ),
                    url=url,
                    evidence=f"{header_name}: {val}",
                    severity=Severity.LOW,
                    remediation=f"Remove or suppress the '{header_name}' header in server/framework config.",
                    references=_REFS_HEADERS,
                    cwe_id="CWE-200",
                    owasp_category=_OWASP_MISCONFIG,
                    confidence="High",
                ))

        # Internal IPs in Via / Forwarded headers
        for h in ("via", "x-forwarded-for", "x-real-ip", "forwarded"):
            val = response.header(h) or ""
            m = _INTERNAL_HOST_RE.search(val)
            if m:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    title=f"Internal IP Address Disclosed in {h.title()} Header",
                    description=(
                        f"The response header '{h}' discloses the internal IP address "
                        f"'{m.group(0)}'. This reveals internal network topology and can "
                        f"be used to enumerate internal services."
                    ),
                    url=url,
                    evidence=f"{h}: {val[:120]}",
                    severity=Severity.LOW,
                    remediation=f"Strip the '{h}' header before sending to clients, or anonymize IPs.",
                    references=[],
                    cwe_id="CWE-200",
                    owasp_category=_OWASP_MISCONFIG,
                    confidence="High",
                ))

        # Framework fingerprinting in body + headers
        combined = " ".join(f"{k}: {v}" for k, v in response.headers.items())
        if response.is_text:
            combined += " " + response.text[:3000]
        for tech, patterns in TECH_FINGERPRINTS.items():
            for pattern in patterns:
                if pattern.search(combined):
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        title=f"Technology Fingerprint: {tech}",
                        description=f"Detected {tech} usage via response fingerprints.",
                        url=url,
                        severity=Severity.INFO,
                        remediation=f"Suppress {tech} version information from HTTP responses.",
                        references=[],
                        cwe_id="CWE-200",
                        owasp_category=_OWASP_MISCONFIG,
                        confidence="Medium",
                    ))
                    break

        return vulns

    # -----------------------------------------------------------------------
    # 7. Debug headers
    # -----------------------------------------------------------------------

    def _check_debug_headers(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        for h in _DEBUG_HEADERS:
            val = response.header(h)
            if val:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    title=f"Debug / Environment Header Exposed: {h}",
                    description=(
                        f"The response contains the header '{h}: {val[:80]}'. "
                        f"Debug headers expose internal application state, Symfony debug tokens, "
                        f"environment names (production/staging/dev), and request IDs that can "
                        f"be used for further reconnaissance."
                    ),
                    url=url,
                    evidence=f"{h}: {val[:120]}",
                    severity=Severity.LOW,
                    remediation=f"Remove '{h}' header from production responses.",
                    references=[],
                    cwe_id="CWE-200",
                    owasp_category=_OWASP_MISCONFIG,
                    confidence="High",
                ))
        return vulns

    # -----------------------------------------------------------------------
    # 8. Timing / runtime leakage
    # -----------------------------------------------------------------------

    def _check_timing_leakage(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        for h in _TIMING_HEADERS:
            val = response.header(h)
            if val:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    title=f"Server Timing Information Leaked: {h}",
                    description=(
                        f"The '{h}: {val[:80]}' header exposes backend processing time. "
                        f"Timing information can be used to infer server-side operations, "
                        f"database query patterns, and assist in timing-based blind injection attacks."
                    ),
                    url=url,
                    evidence=f"{h}: {val[:120]}",
                    severity=Severity.INFO,
                    remediation=f"Remove or disable the '{h}' header in production.",
                    references=[],
                    cwe_id="CWE-200",
                    owasp_category=_OWASP_MISCONFIG,
                    confidence="High",
                ))
        return vulns

    # -----------------------------------------------------------------------
    # 9. Sensitive data in body
    # -----------------------------------------------------------------------

    def _check_sensitive_data_in_body(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not response.is_text:
            return vulns
        body = response.text

        # Secret patterns
        for data_type, pattern in SENSITIVE_DATA_COMPILED.items():
            if data_type == "Email Address":
                continue
            m = pattern.search(body)
            if m:
                sev = (
                    Severity.CRITICAL if any(k in data_type for k in ("Private Key", "AWS Secret"))
                    else Severity.HIGH if any(k in data_type for k in ("Key", "Token", "Password", "Secret"))
                    else Severity.MEDIUM
                )
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SENSITIVE_DATA,
                    title=f"Sensitive Data Exposure in Response: {data_type}",
                    description=(
                        f"The response body appears to contain {data_type}. "
                        f"Exposing secrets in HTTP responses violates GDPR/PCI-DSS and "
                        f"enables immediate credential theft."
                    ),
                    url=url,
                    evidence=f"Pattern match: '{m.group(0)[:80]}'",
                    severity=sev,
                    remediation=(
                        f"Remove {data_type} from HTTP responses. "
                        "Store secrets in environment variables or vaults."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cwe.mitre.org/data/definitions/200.html",
                    ],
                    cwe_id="CWE-200",
                    owasp_category=_OWASP_CRYPTO,
                    confidence="Medium",
                ))

        # HTML comments with secrets
        m = _HTML_COMMENT_SECRET_RE.search(body)
        if m:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SENSITIVE_DATA,
                title="Sensitive Data in HTML Comment",
                description=(
                    "The page source contains an HTML comment that may include credentials, "
                    "API keys, or other sensitive data. HTML comments are visible to anyone "
                    "who views the page source."
                ),
                url=url,
                evidence=f"HTML comment: '{m.group(0)[:150]}'",
                severity=Severity.MEDIUM,
                remediation="Remove all sensitive information from HTML comments before deployment.",
                references=["https://cwe.mitre.org/data/definitions/615.html"],
                cwe_id="CWE-615",
                owasp_category=_OWASP_CRYPTO,
                confidence="Medium",
            ))

        # Stack traces
        m = _STACKTRACE_RE.search(body)
        if m:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title="Stack Trace / Error Detail Exposed in Response",
                description=(
                    "The response contains what appears to be a stack trace or detailed error message. "
                    "Stack traces reveal file paths, function names, line numbers, and technology stack, "
                    "dramatically assisting attackers in targeting exploits."
                ),
                url=url,
                evidence=f"Stack trace indicator: '{m.group(0)[:120]}'",
                severity=Severity.MEDIUM,
                remediation=(
                    "Disable detailed error output in production. "
                    "Log errors server-side and show only generic error messages to clients."
                ),
                references=["https://cwe.mitre.org/data/definitions/209.html"],
                cwe_id="CWE-209",
                owasp_category=_OWASP_MISCONFIG,
                confidence="High",
            ))

        # Internal IPs in body
        m = _INTERNAL_HOST_RE.search(body)
        if m:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title="Internal IP Address Exposed in Response Body",
                description=(
                    f"The response body contains an internal IP address '{m.group(0)}'. "
                    f"This reveals internal network topology."
                ),
                url=url,
                evidence=f"Internal IP: {m.group(0)}",
                severity=Severity.LOW,
                remediation="Sanitize all server-side responses to remove internal hostnames and IP addresses.",
                references=[],
                cwe_id="CWE-200",
                owasp_category=_OWASP_MISCONFIG,
                confidence="Medium",
            ))

        return vulns

    # -----------------------------------------------------------------------
    # 10. HTTP smuggling hints
    # -----------------------------------------------------------------------

    def _check_smuggling_hints(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        te = response.header("transfer-encoding") or ""
        cl = response.header("content-length") or ""
        sc = response.status_code

        # TE + CL present simultaneously
        if te and cl:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.HTTP_SMUGGLING,
                title="HTTP Request Smuggling Indicator: Transfer-Encoding + Content-Length",
                description=(
                    "Both Transfer-Encoding and Content-Length headers are present in the response. "
                    "Front-end / back-end pipeline desync on TE vs CL can enable HTTP request smuggling, "
                    "allowing attackers to poison the request pipeline, bypass security controls, "
                    "and hijack other users' requests."
                ),
                url=url,
                evidence=f"Transfer-Encoding: {te} | Content-Length: {cl}",
                severity=Severity.HIGH,
                remediation=(
                    "Ensure the reverse proxy and backend agree on body framing. "
                    "Use HTTP/2 end-to-end. Reject requests with both TE and CL at the edge."
                ),
                references=[
                    "https://portswigger.net/web-security/request-smuggling",
                    "https://cwe.mitre.org/data/definitions/444.html",
                ],
                cwe_id="CWE-444",
                owasp_category=_OWASP_MISCONFIG,
                confidence="Low",
            ))

        # Content-Length on a bodyless response (204/304) — CL confusion
        if cl and sc in (204, 304):
            vulns.append(self._build_vuln(
                vuln_type=VulnType.HTTP_SMUGGLING,
                title=f"Content-Length on Bodyless HTTP {sc} Response",
                description=(
                    f"HTTP {sc} responses must not include a body, yet this response has "
                    f"Content-Length: {cl}. Some proxies may interpret this incorrectly, "
                    f"enabling request smuggling."
                ),
                url=url,
                evidence=f"HTTP {sc} + Content-Length: {cl}",
                severity=Severity.LOW,
                remediation=f"Remove Content-Length header from HTTP {sc} responses.",
                references=["https://portswigger.net/web-security/request-smuggling"],
                cwe_id="CWE-444",
                owasp_category=_OWASP_MISCONFIG,
                confidence="Low",
            ))

        return vulns

    # -----------------------------------------------------------------------
    # 11. Cache-Control
    # -----------------------------------------------------------------------

    def _check_cache_control(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        cc = (response.header("cache-control") or "").lower()
        pragma = (response.header("pragma") or "").lower()

        # Only flag on pages that look like authenticated / sensitive content
        if not _AUTH_PAGE_RE.search(response.text or ""):
            return vulns

        has_no_store = "no-store" in cc
        has_no_cache = "no-cache" in cc or "no-cache" in pragma
        has_private = "private" in cc

        if not (has_no_store and (has_no_cache or has_private)):
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SECURITY_HEADERS,
                title="Missing Cache-Control: no-store on Authenticated Page",
                description=(
                    "This page appears to contain authenticated/sensitive content but lacks "
                    "Cache-Control: no-store. Sensitive data may be cached by proxies, CDNs, "
                    "or the browser — leaking it to subsequent users on shared computers or "
                    "through cache poisoning attacks."
                ),
                url=url,
                evidence=f"Cache-Control: {cc or '(absent)'} | Pragma: {pragma or '(absent)'}",
                severity=Severity.MEDIUM,
                remediation="Add: Cache-Control: no-store, no-cache, private to authenticated responses.",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
                    "https://cwe.mitre.org/data/definitions/524.html",
                ],
                cwe_id="CWE-524",
                owasp_category=_OWASP_MISCONFIG,
                confidence="Medium",
            ))
        return vulns

    # -----------------------------------------------------------------------
    # 12. Mixed content
    # -----------------------------------------------------------------------

    def _check_mixed_content(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not url.startswith("https://") or not response.is_text:
            return vulns

        m = _MIXED_CONTENT_RE.search(response.text)
        if m:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SSL_TLS,
                title="Mixed Content: HTTP Resources on HTTPS Page",
                description=(
                    "This HTTPS page loads resources over HTTP. Browsers block active mixed "
                    "content (scripts, iframes) and warn on passive (images, CSS). "
                    "HTTP resources can be intercepted by MITM attackers to inject malicious "
                    "content into the HTTPS page."
                ),
                url=url,
                evidence=f"HTTP resource reference: '{m.group(0)[:120]}'",
                severity=Severity.MEDIUM,
                remediation="Replace all http:// resource URLs with https:// equivalents.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                    "https://cwe.mitre.org/data/definitions/311.html",
                ],
                cwe_id="CWE-311",
                owasp_category=_OWASP_CRYPTO,
                confidence="High",
            ))
        return vulns

    # -----------------------------------------------------------------------
    # 13. Deprecated / dangerous headers
    # -----------------------------------------------------------------------

    def _check_deprecated_headers(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # HPKP — deprecated, pinning failures cause service outage
        pkp = response.header("public-key-pins") or response.header("public-key-pins-report-only") or ""
        if pkp:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SECURITY_HEADERS,
                title="Deprecated HPKP (HTTP Public Key Pinning) Header Present",
                description=(
                    "HTTP Public Key Pinning (HPKP) is deprecated and removed from all major browsers. "
                    "Misconfigured HPKP can render a site permanently inaccessible (key pinning failure). "
                    "Consider using Certificate Transparency (CT) logs instead."
                ),
                url=url,
                evidence=f"Public-Key-Pins: {pkp[:100]}",
                severity=Severity.INFO,
                remediation="Remove the Public-Key-Pins header. Use Certificate Transparency logs instead.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins"],
                cwe_id="CWE-693",
                owasp_category=_OWASP_MISCONFIG,
                confidence="High",
            ))

        # X-XSS-Protection: 0 — disabling browser XSS auditor
        xxp = response.header("x-xss-protection") or ""
        if xxp.strip() == "0":
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SECURITY_HEADERS,
                title="X-XSS-Protection: 0 — Browser XSS Auditor Disabled",
                description=(
                    "The X-XSS-Protection header is set to 0, explicitly disabling the "
                    "legacy browser XSS auditor. While this header is deprecated in modern browsers, "
                    "older IE/Edge versions relied on it. Disabling it may increase XSS risk on "
                    "legacy clients. If intentional, document the reason."
                ),
                url=url,
                evidence="X-XSS-Protection: 0",
                severity=Severity.INFO,
                remediation=(
                    "Remove the header or set X-XSS-Protection: 1; mode=block if legacy browser support "
                    "is needed. Modern protection should come from a strong CSP."
                ),
                references=[],
                cwe_id="CWE-693",
                owasp_category=_OWASP_MISCONFIG,
                confidence="High",
            ))

        return vulns
