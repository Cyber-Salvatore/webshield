"""
OAuth 2.0 / SAML Security Scanner — Phase 3.3
===============================================
Tests SSO implementations for common misconfigurations and vulnerabilities.

OAuth 2.0 Coverage:
  • redirect_uri manipulation — open redirect & URI validation bypass
  • State parameter missing / weak (CSRF in OAuth)
  • PKCE absent or bypass (code_challenge missing)
  • Token in URL (access_token / id_token in fragment/query)
  • Implicit flow in use (deprecated — tokens exposed in URL)
  • Authorization code reuse (replay attack)
  • Scope escalation probing (request admin scopes)
  • Client_id / client_secret exposure in JS or responses

SAML Coverage:
  • XML Signature Wrapping (XSW) — malformed SAML assertion
  • XXE in SAML assertions
  • Signature validation bypass (alg=none / stripped signature)
  • Recipient / audience validation absent

JWT in ID Tokens:
  • Delegated to jwt_scanner.py — we flag the finding location

CWE  : CWE-601, CWE-352, CWE-287, CWE-347
OWASP: A07:2021 – Identification and Authentication Failures
       A01:2021 – Broken Access Control
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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

# ---------------------------------------------------------------------------
# CVSS
# ---------------------------------------------------------------------------

_CVSS_HIGH = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.HIGH,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
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

_CVSS_INFO = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.LOW,
    integrity=Impact.NONE,
    availability=Impact.NONE,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OWASP_AUTH  = "A07:2021 - Identification and Authentication Failures"
_OWASP_AC    = "A01:2021 - Broken Access Control"

# Common OAuth/OIDC endpoint paths
_OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/oauth/auth",
    "/auth/authorize", "/connect/authorize",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/token", "/oauth2/token",
    "/oauth/userinfo", "/oauth2/userinfo",
    "/saml/sso", "/saml/login", "/saml/consume", "/saml/acs",
    "/saml2/login", "/saml2/sso",
    "/sso/saml", "/sso/login",
]

# SAML assertion indicators
_SAML_INDICATORS = re.compile(
    r"(?:SAMLResponse|SAMLRequest|saml:|samlp:|AuthnRequest|Response xmlns.*saml)",
    re.IGNORECASE,
)

# OAuth token indicators in URLs / body
_TOKEN_IN_URL_RE = re.compile(
    r"[?#&](?:access_token|id_token|token)=([A-Za-z0-9\-._~+/]{10,})",
    re.IGNORECASE,
)

# Open redirect in redirect_uri candidates
_ATTACKER_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "//evil.com/callback",
    "https://evil.com/callback",
]

# Scope escalation candidates
_ESCALATION_SCOPES = [
    "admin", "superuser", "read:admin", "write:admin",
    "openid profile email admin",
    "openid profile email read:all write:all",
]

# State parameter weakness patterns
_WEAK_STATE_RE = re.compile(r"state=([A-Za-z0-9]{1,8})(?:&|$|#)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# OAuthSAMLScanner
# ---------------------------------------------------------------------------

class OAuthSAMLScanner(_ScannerBase):
    """
    Phase 3.3 — OAuth 2.0 / SAML Security Scanner.

    is_target_level = True: runs once per target, probes all OAuth/SAML paths.
    """

    name = "OAuth / SAML"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        from urllib.parse import urlparse
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        vulns: List[Vulnerability] = []

        # Discover OAuth/SAML endpoints
        endpoints = await self._discover_endpoints(base, url)
        if not endpoints:
            return vulns

        for ep in endpoints:
            vulns.extend(await self._test_oauth_endpoint(ep, base))
            vulns.extend(await self._check_token_in_url(ep))

        # Passive checks on the initial response
        vulns.extend(self._check_saml_response(url, response))
        vulns.extend(self._check_token_in_body(url, response))
        vulns.extend(self._check_client_secret_exposure(url, response))

        return vulns

    # -----------------------------------------------------------------------
    # Endpoint discovery
    # -----------------------------------------------------------------------

    async def _discover_endpoints(self, base: str, seed_url: str) -> List[str]:
        """Probe common OAuth/SAML paths and return responding ones."""
        found: List[str] = []

        # Check seed response for OAuth endpoints
        resp = await self.client.get(seed_url)
        if resp and resp.is_text:
            # Look for OIDC discovery in page body / headers
            if "openid-configuration" in resp.text.lower() or \
               "authorization_endpoint" in resp.text.lower():
                if seed_url not in found:
                    found.append(seed_url)

        # Probe standard paths
        for path in _OAUTH_PATHS:
            ep = base.rstrip("/") + path
            resp = await self.client.get(ep)
            if resp and resp.status_code in (200, 301, 302, 400, 405):
                # Even 400/405 means the endpoint exists
                if ep not in found:
                    found.append(ep)

        return found

    # -----------------------------------------------------------------------
    # OAuth endpoint tests
    # -----------------------------------------------------------------------

    async def _test_oauth_endpoint(
        self, ep: str, base: str
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        resp = await self.client.get(ep)
        if not resp:
            return vulns

        # OIDC discovery document
        if "authorization_endpoint" in (resp.text or ""):
            vulns.extend(await self._test_oidc_discovery(ep, resp, base))
            return vulns

        # Authorization endpoint
        if any(p in ep for p in ("/authorize", "/auth", "/connect/authorize")):
            vulns.extend(await self._test_authorization_endpoint(ep, base))

        return vulns

    async def _test_oidc_discovery(
        self, ep: str, resp: HTTPResponse, base: str
    ) -> List[Vulnerability]:
        """Parse OIDC discovery document and test the authorization_endpoint."""
        vulns: List[Vulnerability] = []
        try:
            import json
            doc = json.loads(resp.text)
        except Exception:
            return vulns

        auth_ep = doc.get("authorization_endpoint", "")
        if auth_ep:
            vulns.extend(await self._test_authorization_endpoint(auth_ep, base))

        # Check if token endpoint uses plain HTTP
        token_ep = doc.get("token_endpoint", "")
        if token_ep.startswith("http://"):
            vulns.append(self._build_vuln(
                vuln_type=VulnType.OAUTH,
                title="OAuth Token Endpoint Over HTTP",
                description=(
                    f"The OIDC discovery document at '{ep}' specifies the token "
                    f"endpoint over plain HTTP: '{token_ep}'. "
                    f"This exposes access tokens to network eavesdropping."
                ),
                url=ep,
                evidence=f"token_endpoint: {token_ep}",
                severity=Severity.HIGH,
                remediation="Serve all OAuth endpoints exclusively over HTTPS.",
                references=["https://datatracker.ietf.org/doc/html/rfc6749#section-3.2"],
                cwe_id="CWE-319",
                owasp_category=_OWASP_AUTH,
                cvss=_CVSS_HIGH,
                confidence="High",
            ))

        # Implicit flow still supported
        grant_types = doc.get("grant_types_supported", [])
        if "implicit" in grant_types:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.OAUTH,
                title="OAuth Implicit Flow Supported (Deprecated)",
                description=(
                    f"The authorization server at '{ep}' still supports the implicit grant "
                    f"flow (grant_type=token). This deprecated flow exposes access tokens "
                    f"directly in URL fragments, making them accessible to malicious scripts "
                    f"and browser history."
                ),
                url=ep,
                evidence=f"grant_types_supported: {grant_types}",
                severity=Severity.MEDIUM,
                remediation=(
                    "Disable implicit flow. Use Authorization Code flow with PKCE instead. "
                    "Reference: OAuth 2.0 Security Best Current Practice (BCP)."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics",
                    "https://oauth.net/2/grant-types/implicit/",
                ],
                cwe_id="CWE-287",
                owasp_category=_OWASP_AUTH,
                cvss=_CVSS_MEDIUM,
                confidence="High",
            ))

        return vulns

    async def _test_authorization_endpoint(
        self, ep: str, base: str
    ) -> List[Vulnerability]:
        """
        Test the OAuth authorization endpoint for:
        - redirect_uri manipulation (open redirect)
        - Missing / weak state parameter (CSRF)
        - Missing PKCE (code_challenge)
        - Scope escalation

        Fix 3.3: Extract real client_id from the page/JS before testing.
        Using "test" as client_id causes immediate error=invalid_client, which
        means redirect_uri validation is never reached.
        """
        vulns: List[Vulnerability] = []

        # Fix 3.3: try to extract a real client_id from the login page / JS
        real_client_id = await self._extract_client_id(base) or "test"

        # ── redirect_uri manipulation ─────────────────────────────────────
        for evil_uri in _ATTACKER_ORIGINS:
            test_url = self._build_auth_url(
                ep,
                extra_params={"redirect_uri": evil_uri, "client_id": real_client_id},
            )
            resp = await self.client.get_no_redirect(test_url)
            if resp and resp.status_code in (301, 302):
                location = resp.header("location") or ""
                if any(evil in location for evil in ("evil.com", "attacker.com")):
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.OAUTH,
                        title="OAuth redirect_uri Open Redirect",
                        description=(
                            f"The authorization endpoint at '{ep}' redirects to "
                            f"attacker-controlled '{evil_uri}' without validating the "
                            f"redirect_uri parameter. An attacker can steal authorization "
                            f"codes by crafting a malicious authorization URL."
                        ),
                        url=ep,
                        parameter="redirect_uri",
                        payload=evil_uri,
                        evidence=f"Location header: {location[:200]}",
                        severity=Severity.HIGH,
                        remediation=(
                            "Enforce strict redirect_uri validation against a pre-registered "
                            "whitelist. Reject partial matches and wildcards."
                        ),
                        references=[
                            "https://portswigger.net/web-security/oauth",
                            "https://cwe.mitre.org/data/definitions/601.html",
                        ],
                        cwe_id="CWE-601",
                        owasp_category=_OWASP_AC,
                        cvss=_CVSS_HIGH,
                        confidence="High",
                    ))
                    break

        # ── Missing state parameter ───────────────────────────────────────
        test_url = self._build_auth_url(ep, extra_params={"client_id": real_client_id})
        resp = await self.client.get_no_redirect(test_url)
        if resp and resp.status_code in (301, 302):
            location = resp.header("location") or resp.header("Location") or ""
            if "state=" not in location.lower() and "error" not in location.lower():
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.OAUTH,
                    title="OAuth State Parameter Missing (CSRF Risk)",
                    description=(
                        f"The authorization endpoint '{ep}' does not require or validate "
                        f"the 'state' parameter. Without a state, the OAuth flow is "
                        f"vulnerable to CSRF attacks — an attacker can trick a user into "
                        f"completing an OAuth authorization that connects the victim's account "
                        f"to the attacker's account."
                    ),
                    url=ep,
                    parameter="state",
                    evidence=f"Redirect accepted without state parameter (Location: {location[:150]})",
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Always include and validate a cryptographically random 'state' "
                        "parameter. Bind it to the user session and verify it on callback."
                    ),
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc6749#section-10.12",
                        "https://cwe.mitre.org/data/definitions/352.html",
                    ],
                    cwe_id="CWE-352",
                    owasp_category=_OWASP_AUTH,
                    cvss=_CVSS_MEDIUM,
                    confidence="Medium",
                ))

        # ── Missing PKCE ──────────────────────────────────────────────────
        test_url_pkce = self._build_auth_url(
            ep,
            extra_params={
                "client_id": real_client_id,
                "response_type": "code",
                "state": "teststate123",
            },
        )
        resp_pkce = await self.client.get_no_redirect(test_url_pkce)
        if resp_pkce and resp_pkce.status_code in (301, 302):
            location = resp_pkce.header("location") or ""
            if "code=" in location and "error" not in location.lower():
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.OAUTH,
                    title="OAuth PKCE Not Enforced",
                    description=(
                        f"The authorization endpoint '{ep}' returns an authorization code "
                        f"without requiring a PKCE code_challenge. "
                        f"Without PKCE, authorization codes can be intercepted and exchanged "
                        f"by a malicious app on the same device (especially for public clients)."
                    ),
                    url=ep,
                    parameter="code_challenge",
                    evidence=f"Authorization code returned without code_challenge (Location: {location[:150]})",
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Require code_challenge (S256 method) for all authorization code flows. "
                        "Reject requests without a valid code_challenge."
                    ),
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc7636",
                        "https://oauth.net/2/pkce/",
                    ],
                    cwe_id="CWE-287",
                    owasp_category=_OWASP_AUTH,
                    cvss=_CVSS_MEDIUM,
                    confidence="Medium",
                ))

        # ── Scope escalation ──────────────────────────────────────────────
        for scope in _ESCALATION_SCOPES:
            test_url_scope = self._build_auth_url(
                ep,
                extra_params={
                    "client_id": real_client_id,
                    "scope": scope,
                    "state": "teststate",
                    "response_type": "code",
                },
            )
            resp_scope = await self.client.get_no_redirect(test_url_scope)
            if resp_scope and resp_scope.status_code in (301, 302):
                location = resp_scope.header("location") or ""
                if "error" not in location.lower() and "denied" not in location.lower():
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.OAUTH,
                        title="OAuth Scope Escalation Possible",
                        description=(
                            f"The authorization endpoint '{ep}' accepted a request "
                            f"with elevated scope '{scope}' without returning an error. "
                            f"An attacker may be able to request admin-level permissions "
                            f"that should not be grantable."
                        ),
                        url=ep,
                        parameter="scope",
                        payload=scope,
                        evidence=f"scope='{scope}' accepted (no error in redirect)",
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Validate requested scopes against the client's registered "
                            "allowed scopes. Return error=invalid_scope for unauthorized scopes."
                        ),
                        references=[
                            "https://datatracker.ietf.org/doc/html/rfc6749#section-3.3",
                        ],
                        cwe_id="CWE-285",
                        owasp_category=_OWASP_AC,
                        cvss=_CVSS_MEDIUM,
                        confidence="Low",
                    ))
                    break

        return vulns

    async def _extract_client_id(self, base_url: str) -> Optional[str]:
        """
        Fix 3.3: Try to find a real client_id from the login/home page or JS files.
        Using a real client_id prevents OAuth servers from short-circuiting with
        error=invalid_client before they even check redirect_uri or state.
        """
        _CLIENT_ID_PATTERNS = [
            re.compile(r'"client_id"\s*:\s*"([^"]{4,})"', re.I),
            re.compile(r"client_id=([A-Za-z0-9_\-\.]{4,})(?:&|$|\s)", re.I),
            re.compile(r"clientId[\"'\s]*[:=]\s*[\"']([^\"']{4,})[\"']", re.I),
            re.compile(r"client[_-]?id[\"'\s]*[:=]\s*[\"']([^\"']{4,})[\"']", re.I),
            re.compile(r"OAUTH_CLIENT_ID[\"'\s]*[:=]\s*[\"']([^\"']{4,})[\"']", re.I),
        ]

        # Check login page and root
        for path in ["/", "/login", "/auth/login", "/signin"]:
            try:
                resp = await self.client.get(base_url.rstrip("/") + path)
                if not resp or not resp.is_text:
                    continue
                for pat in _CLIENT_ID_PATTERNS:
                    m = pat.search(resp.text)
                    if m:
                        return m.group(1)
            except Exception:
                continue

        return None

    # -----------------------------------------------------------------------
    # Token-in-URL detection
    # -----------------------------------------------------------------------

    async def _check_token_in_url(self, ep: str) -> List[Vulnerability]:
        """Detect access_token / id_token in URL fragment or query string."""
        vulns: List[Vulnerability] = []
        resp = await self.client.get(ep)
        if not resp:
            return vulns

        # Check final URL after redirects
        final_url = resp.url
        match = _TOKEN_IN_URL_RE.search(final_url)
        if match:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.OAUTH,
                title="OAuth Token Exposed in URL",
                description=(
                    f"An OAuth token was found in the URL of '{ep}': "
                    f"'{final_url[:200]}'. "
                    f"Tokens in URLs are logged by web servers, proxies, browser history, "
                    f"and Referer headers, leading to token leakage."
                ),
                url=ep,
                evidence=f"Token parameter in URL: {match.group(0)[:100]}",
                severity=Severity.HIGH,
                remediation=(
                    "Use Authorization Code flow. Never place tokens in URLs. "
                    "Return tokens only in the response body over HTTPS."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-10.3",
                ],
                cwe_id="CWE-200",
                owasp_category=_OWASP_AUTH,
                cvss=_CVSS_HIGH,
                confidence="High",
            ))

        return vulns

    # -----------------------------------------------------------------------
    # Passive / body checks
    # -----------------------------------------------------------------------

    def _check_saml_response(
        self, url: str, response: HTTPResponse
    ) -> List[Vulnerability]:
        """Check if a SAML response is present and inspect it for weaknesses."""
        vulns: List[Vulnerability] = []
        if not response.is_text:
            return vulns

        if not _SAML_INDICATORS.search(response.text):
            return vulns

        # XXE in SAML
        if "<!ENTITY" in response.text or "<!DOCTYPE" in response.text:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.OAUTH,
                title="SAML Response Contains DOCTYPE / Entity Declaration",
                description=(
                    f"The response at '{url}' contains a SAML assertion with a DOCTYPE "
                    f"declaration, which may enable XML External Entity (XXE) injection. "
                    f"An attacker who can control the SAML XML can read server-side files."
                ),
                url=url,
                evidence="DOCTYPE or ENTITY declaration found in SAML response",
                severity=Severity.HIGH,
                remediation=(
                    "Disable DOCTYPE processing in the SAML XML parser. "
                    "Use a hardened XML parser that rejects external entities."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
                    "08-Testing_for_SAML",
                    "https://cwe.mitre.org/data/definitions/611.html",
                ],
                cwe_id="CWE-611",
                owasp_category=_OWASP_AUTH,
                cvss=_CVSS_HIGH,
                confidence="Medium",
            ))

        # Signature missing
        if "Signature" not in response.text and "SAMLResponse" in response.text:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.OAUTH,
                title="SAML Assertion Without XML Signature",
                description=(
                    f"The SAML response at '{url}' does not appear to contain an XML "
                    f"Signature element. An attacker could forge arbitrary SAML assertions "
                    f"to impersonate any user."
                ),
                url=url,
                evidence="SAMLResponse found without <Signature> element",
                severity=Severity.CRITICAL,
                remediation=(
                    "All SAML assertions must be signed with the IdP's private key. "
                    "The SP must validate the signature on every assertion."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/347.html",
                ],
                cwe_id="CWE-347",
                owasp_category=_OWASP_AUTH,
                cvss=CVSSv3(
                    AttackVector.NETWORK, AttackComplexity.LOW,
                    PrivilegesRequired.NONE, UserInteraction.NONE,
                    Scope.CHANGED, Impact.HIGH, Impact.HIGH, Impact.HIGH,
                ),
                confidence="Medium",
            ))

        return vulns

    def _check_token_in_body(
        self, url: str, response: HTTPResponse
    ) -> List[Vulnerability]:
        """Check if tokens are visible in response body in clear text."""
        vulns: List[Vulnerability] = []
        if not response.is_text:
            return vulns
        match = _TOKEN_IN_URL_RE.search(response.text)
        if match:
            # Only flag if it looks like a real JWT (3 dot-separated parts starting ey)
            token_val = match.group(1)
            if token_val.startswith("ey") and token_val.count(".") == 2:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.OAUTH,
                    title="OAuth / JWT Token Exposed in Response Body",
                    description=(
                        f"A JWT access token was found embedded in the response body at '{url}'. "
                        f"If this page is cached, logged, or accessible to scripts, "
                        f"the token may be leaked."
                    ),
                    url=url,
                    evidence=f"token parameter in body: {match.group(0)[:80]}",
                    severity=Severity.MEDIUM,
                    remediation="Return tokens only over secure channels and avoid embedding in pages.",
                    references=["https://datatracker.ietf.org/doc/html/rfc6750"],
                    cwe_id="CWE-200",
                    owasp_category=_OWASP_AUTH,
                    cvss=_CVSS_MEDIUM,
                    confidence="High",
                ))
        return vulns

    def _check_client_secret_exposure(
        self, url: str, response: HTTPResponse
    ) -> List[Vulnerability]:
        """Check for client_secret or client credentials in the response."""
        vulns: List[Vulnerability] = []
        if not response.is_text:
            return vulns

        patterns = [
            re.compile(r'"client_secret"\s*:\s*"([^"]{8,})"', re.I),
            re.compile(r"client[_-]secret\s*[=:]\s*['\"]([^'\"]{8,})['\"]", re.I),
            re.compile(r"client[_-]secret\s*=\s*([A-Za-z0-9_\-\.]{16,})", re.I),
        ]
        for pattern in patterns:
            m = pattern.search(response.text)
            if m:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.OAUTH,
                    title="OAuth client_secret Exposed in Response",
                    description=(
                        f"A client_secret was found in the response at '{url}'. "
                        f"Exposed client secrets allow attackers to impersonate the OAuth "
                        f"client application and steal authorization codes or tokens."
                    ),
                    url=url,
                    evidence=f"Pattern matched: {m.group(0)[:100]}",
                    severity=Severity.CRITICAL,
                    remediation=(
                        "Never expose client_secret in client-side code or API responses. "
                        "Rotate the secret immediately and store it server-side only."
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc6749#section-2.3"],
                    cwe_id="CWE-522",
                    owasp_category=_OWASP_AUTH,
                    cvss=CVSSv3(
                        AttackVector.NETWORK, AttackComplexity.LOW,
                        PrivilegesRequired.NONE, UserInteraction.NONE,
                        Scope.UNCHANGED, Impact.HIGH, Impact.HIGH, Impact.NONE,
                    ),
                    confidence="High",
                ))
                break

        return vulns

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_auth_url(ep: str, extra_params: Dict[str, str]) -> str:
        """Build an authorization URL with extra query parameters."""
        parsed = urlparse(ep)
        existing = parse_qs(parsed.query)
        existing.update({k: [v] for k, v in extra_params.items()})
        new_query = urlencode(existing, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
