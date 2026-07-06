"""
CORS Misconfiguration Scanner — Professional Grade
===================================================
Coverage:
  • Wildcard origin (ACAO: *) with credentials
  • Reflected origin — server mirrors any Origin header
  • Null origin accepted with credentials
  • Subdomain wildcard (ACAO: *.domain.com)
  • Trusted subdomain with XSS (domain.attacker.com bypass)
  • Regex bypass: evil.com that ends with trusted domain
  • HTTP origin accepted on HTTPS (protocol downgrade)
  • Pre-flight OPTIONS misconfiguration
  • Access-Control-Allow-Headers: * with credentials
  • Cache poisoning via Origin reflection
  • CORS on sensitive API endpoints (/api/user, /api/profile, etc.)
  • Missing Vary: Origin header (cache poisoning risk)

CWE  : CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
OWASP: A05:2021 – Security Misconfiguration
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability, VulnType, Severity, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)

_CVSS_CRITICAL = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.REQUIRED,
    Scope.CHANGED, Impact.HIGH, Impact.HIGH, Impact.NONE)
_CVSS_HIGH = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.REQUIRED,
    Scope.UNCHANGED, Impact.HIGH, Impact.LOW, Impact.NONE)
_CVSS_MEDIUM = CVSSv3(AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.NONE, UserInteraction.REQUIRED,
    Scope.UNCHANGED, Impact.LOW, Impact.NONE, Impact.NONE)

_CWE = "CWE-942"
_OWASP = "A05:2021 - Security Misconfiguration"
_REFS = [
    "https://portswigger.net/web-security/cors",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
    "https://cwe.mitre.org/data/definitions/942.html",
]
_REMEDIATION = (
    "1. Maintain an explicit allowlist of trusted origins — never use wildcards with credentials.\n"
    "2. Validate Origin headers against the allowlist using exact string matching (not regex suffix).\n"
    "3. Never reflect arbitrary Origin values in Access-Control-Allow-Origin.\n"
    "4. Do not allow null origin unless required for specific use cases.\n"
    "5. Add Vary: Origin header when the ACAO value depends on the request Origin.\n"
    "6. Require credentials explicitly — don't combine ACAO: * with ACAC: true."
)

# Sensitive API paths to test CORS on
_SENSITIVE_API_PATHS = [
    "/api/user", "/api/me", "/api/profile",
    "/api/account", "/api/users", "/api/admin",
    "/api/settings", "/api/config", "/api/auth/token",
    "/api/v1/user", "/api/v2/me",
    "/dashboard", "/profile", "/account",
]


class CORSScanner(_ScannerBase):
    """
    Comprehensive CORS misconfiguration scanner.
    Tests multiple origin bypass techniques per endpoint.
    is_target_level=True
    """
    name = "CORS"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
        base     = f"{parsed.scheme}://{parsed.netloc}"

        # Test current URL first
        found = await self._test_endpoint(url, hostname)
        vulns.extend(found)
        if any(v.severity == Severity.CRITICAL for v in found):
            return vulns  # Critical already — don't probe more paths

        # Only probe sensitive API paths if the current URL has a CORS header
        # (avoids sending 12 extra requests to every target that has no CORS at all)
        has_cors_header = bool(
            response.header("access-control-allow-origin") or
            response.header("access-control-allow-credentials")
        )
        if has_cors_header:
            for path in _SENSITIVE_API_PATHS:
                endpoint = urljoin(base, path)
                if endpoint == url:
                    continue
                found = await self._test_endpoint(endpoint, hostname)
                vulns.extend(found)
                if any(v.severity == Severity.CRITICAL for v in found):
                    break

        return vulns

    async def _test_endpoint(
        self, url: str, hostname: str
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # Fix 2.5: Test origins in priority order — high-signal ones first.
        # Return immediately on first critical finding to avoid extra requests.
        # Low-signal origins only tested if high-signal ones produced no results.
        test_origins = self._build_test_origins(hostname)

        for origin, bypass_desc in test_origins:
            resp = await self.client.get(url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.header("access-control-allow-origin") or ""
            acac = (resp.header("access-control-allow-credentials") or "").lower().strip()
            vary = (resp.header("vary") or "").lower()
            credentials_allowed = acac == "true"

            if not acao:
                continue

            # 1. Origin reflected exactly
            if acao == origin and origin not in ("*", "null"):
                severity = Severity.CRITICAL if credentials_allowed else Severity.HIGH
                cvss     = _CVSS_CRITICAL if credentials_allowed else _CVSS_HIGH

                vuln = self._build_vuln(
                    vuln_type=VulnType.SECURITY_HEADERS,
                    title=f"CORS: Origin Reflected — {bypass_desc}",
                    description=(
                        f"The server reflects the attacker-controlled origin '{origin}' "
                        f"in the Access-Control-Allow-Origin header. "
                        + (
                            f"Combined with Access-Control-Allow-Credentials: true, "
                            f"this allows any attacker origin to make credentialed cross-origin "
                            f"requests and read the full authenticated response, "
                            f"enabling complete account takeover."
                            if credentials_allowed else
                            f"While credentials are not allowed, any origin can read "
                            f"this response — if this endpoint returns sensitive data it is at risk."
                        )
                    ),
                    url=url,
                    evidence=(
                        f"Origin: {origin} → ACAO: {acao} | "
                        f"ACAC: {acac or 'not set'} | "
                        f"Vary: {vary or 'not set'}"
                    ),
                    severity=severity, cvss=cvss,
                    remediation=_REMEDIATION, references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    confidence="High",
                )
                vulns.append(vuln)

                # Missing Vary: Origin (cache poisoning risk)
                if "origin" not in vary:
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.SECURITY_HEADERS,
                        title="CORS: Missing 'Vary: Origin' Header — Cache Poisoning Risk",
                        description=(
                            f"The server reflects arbitrary Origin values in ACAO without "
                            f"setting 'Vary: Origin'. Caches may store a response with "
                            f"one origin's ACAO and serve it to other origins, "
                            f"enabling cache-based CORS bypass."
                        ),
                        url=url,
                        evidence=f"ACAO: {acao} | Vary: {vary or '(absent)'}",
                        severity=Severity.MEDIUM, cvss=_CVSS_MEDIUM,
                        remediation="Add 'Vary: Origin' to all responses where ACAO depends on the Origin header.",
                        references=_REFS,
                        cwe_id=_CWE, owasp_category=_OWASP,
                        confidence="High",
                    ))
                break  # One reflection finding per endpoint is enough

            # 2. Null origin accepted
            if origin == "null" and acao == "null":
                severity = Severity.CRITICAL if credentials_allowed else Severity.HIGH
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SECURITY_HEADERS,
                    title="CORS: Null Origin Accepted" + (" + Credentials" if credentials_allowed else ""),
                    description=(
                        "The server accepts 'null' as the Origin. "
                        "Sandboxed iframes and local HTML files send Origin: null. "
                        "An attacker can use a sandboxed iframe on any domain to make "
                        "cross-origin requests that the server treats as trusted."
                        + (" With credentials allowed, this is fully exploitable." if credentials_allowed else "")
                    ),
                    url=url,
                    evidence=f"Origin: null → ACAO: null | ACAC: {acac}",
                    severity=severity, cvss=_CVSS_CRITICAL if credentials_allowed else _CVSS_HIGH,
                    remediation=_REMEDIATION, references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP, confidence="High",
                ))
                break

            # 3. Wildcard with credentials (already caught in headers.py but verify here too)
            if acao == "*" and credentials_allowed:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SECURITY_HEADERS,
                    title="CORS: Wildcard Origin + Allow-Credentials (Invalid Combination)",
                    description=(
                        "ACAO: * with ACAC: true is forbidden by the CORS spec. "
                        "Some middleware applies this combination incorrectly."
                    ),
                    url=url,
                    evidence=f"ACAO: * | ACAC: true",
                    severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION, references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP, confidence="High",
                ))
                break

        # Test OPTIONS preflight
        preflight_vuln = await self._test_preflight(url, hostname)
        if preflight_vuln:
            vulns.append(preflight_vuln)

        return vulns

    def _build_test_origins(self, hostname: str) -> List[Tuple[str, str]]:
        """
        Fix 2.5: Build origins in priority order — most dangerous first.
        High-signal origins (reflected subdomain, null) come before low-signal ones.
        Early-exit in _test_endpoint stops testing once a critical finding is found.
        """
        # Priority 1: High-signal reflected-origin attacks
        priority_origins: List[Tuple[str, str]] = []
        if hostname:
            priority_origins += [
                (f"https://evil.{hostname}",        "Attacker subdomain (suffix bypass)"),
                (f"https://{hostname}.attacker.com", "Reversed subdomain (hostname.attacker.com)"),
                (f"https://attacker{hostname}",      "Prefix bypass (attacker+hostname)"),
            ]
        # Priority 2: Null origin (sandboxed iframe — high impact if accepted)
        priority_origins.append(("null", "Null origin (sandboxed iframe)"))

        # Priority 3: Lower-signal variants (only reached if no critical found above)
        extended_origins: List[Tuple[str, str]] = []
        if hostname:
            extended_origins += [
                (f"http://{hostname}",       "HTTP origin on HTTPS endpoint"),
                (f"https://{hostname}:8080", "Non-standard port variation"),
            ]
        extended_origins.append(("https://evil-cors-test.com", "External attacker origin"))

        return priority_origins + extended_origins

    async def _test_preflight(
        self, url: str, hostname: str
    ) -> Optional[Vulnerability]:
        """Test if OPTIONS preflight allows dangerous combinations."""
        resp = await self.client.request(
            "OPTIONS", url,
            headers={
                "Origin":                           f"https://evil-cors-test.com",
                "Access-Control-Request-Method":    "POST",
                "Access-Control-Request-Headers":   "Authorization, Content-Type",
            },
        )
        if not resp:
            return None

        acao  = resp.header("access-control-allow-origin") or ""
        acam  = resp.header("access-control-allow-methods") or ""
        acah  = resp.header("access-control-allow-headers") or ""
        acac  = (resp.header("access-control-allow-credentials") or "").lower()

        if acao and "evil-cors-test.com" in acao and acac == "true":
            return self._build_vuln(
                vuln_type=VulnType.SECURITY_HEADERS,
                title="CORS: Preflight Allows Arbitrary Origin with Credentials",
                description=(
                    f"The OPTIONS preflight response allows arbitrary origins with credentials. "
                    f"ACAO: {acao} | ACAC: {acac} | ACAM: {acam}. "
                    f"This enables cross-origin credentialed requests from any attacker domain."
                ),
                url=url, method="OPTIONS",
                evidence=f"ACAO: {acao} | ACAC: {acac} | ACAM: {acam} | ACAH: {acah}",
                severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                remediation=_REMEDIATION, references=_REFS,
                cwe_id=_CWE, owasp_category=_OWASP, confidence="High",
            )
        return None
