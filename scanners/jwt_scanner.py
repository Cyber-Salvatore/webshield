"""
JWT (JSON Web Token) Vulnerability Scanner
Tests for: algorithm confusion (none), weak secrets, missing validation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Optional

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import Vulnerability, Severity, VulnType
from ..utils.helpers import decode_jwt_header, decode_jwt_payload, forge_jwt_none_alg
from ..utils.payloads import JWT_WEAK_SECRETS
from ..utils.patterns import JWT_PATTERN, JWT_ALG_NONE


class JWTScanner(_ScannerBase):
    name = "JWT Vulnerabilities"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # Collect JWT tokens from response headers and body
        tokens = self._extract_tokens(response)

        for token, location in tokens:
            vulns.extend(await self._analyze_token(token, location, url, response))

        return vulns

    def _extract_tokens(
        self, response: HTTPResponse
    ) -> List[tuple]:
        """Extract JWT tokens from headers and response body."""
        tokens: List[tuple] = []

        # Check Authorization header
        auth = response.header("Authorization") or ""
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            if JWT_PATTERN.match(token):
                tokens.append((token, "Authorization header"))

        # Fix 2.1: Extract all Set-Cookie headers reliably via items() iteration.
        # httpx's Headers.items() yields every header line including duplicates,
        # which is the only guaranteed way to get all Set-Cookie values across
        # all httpx versions (some fold multi-value headers).
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                for match in JWT_PATTERN.finditer(v):
                    tokens.append((match.group(0), "Set-Cookie header"))

        # Check response body
        if response.is_text:
            for match in JWT_PATTERN.finditer(response.text):
                token = match.group(0)
                tokens.append((token, "Response body"))

        # Fix 2.1 (extra): Check URL query parameters for JWT (CWE-598)
        from urllib.parse import urlparse, parse_qs
        try:
            parsed_url = urlparse(response.url if hasattr(response, "url") else "")
            params = parse_qs(parsed_url.query)
            for param_name, values in params.items():
                for val in values:
                    if JWT_PATTERN.match(val):
                        tokens.append((val, f"URL parameter '{param_name}'"))
        except Exception:
            pass

        # Deduplicate
        seen = set()
        unique_tokens = []
        for token, loc in tokens:
            if token not in seen:
                seen.add(token)
                unique_tokens.append((token, loc))

        return unique_tokens

    async def _analyze_token(
        self,
        token: str,
        location: str,
        url: str,
        response: HTTPResponse,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        header = decode_jwt_header(token)
        payload = decode_jwt_payload(token)

        if not header:
            return vulns

        # Fix 1.1: compare lowercase — JWT spec allows "none", "None", "NONE", "nOnE"
        alg = header.get("alg", "")
        token_short = token[:20] + "..."

        # 1. Algorithm "none" attack
        if alg.lower() == "none":
            vulns.append(self._build_vuln(
                vuln_type=VulnType.JWT,
                title="JWT Using Algorithm 'none' (Critical)",
                description=(
                    f"A JWT token at {location} uses algorithm 'none', meaning the signature "
                    f"is completely absent. Any token with this algorithm is accepted without "
                    f"verification, allowing an attacker to forge arbitrary tokens with any claims."
                ),
                url=url,
                evidence=f"Token header: {json.dumps(header)}",
                payload=token_short,
                severity=Severity.CRITICAL,
                remediation=(
                    "Never accept tokens with alg=none. Explicitly reject any token whose "
                    "header specifies alg=none or a blank algorithm. Use allowlisting of "
                    "permitted algorithms in your JWT library configuration."
                ),
                references=[
                    "https://portswigger.net/web-security/jwt#accepting-tokens-with-no-signature",
                    "https://cwe.mitre.org/data/definitions/347.html",
                ],
                cwe_id="CWE-347",
                owasp_category="A02:2021 - Cryptographic Failures",
            ))

        # 2. Test none algorithm bypass (send a forged token)
        elif alg.upper().startswith("HS"):
            forged = forge_jwt_none_alg(token)
            if forged:
                # Test if server accepts the forged token
                test_resp = await self.client.get(
                    url,
                    headers={"Authorization": f"Bearer {forged}"}
                )
                if test_resp and test_resp.status_code == 200:
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.JWT,
                        title="JWT Algorithm Confusion: 'none' Attack Accepted",
                        description=(
                            f"The server accepted a JWT with algorithm changed to 'none' "
                            f"(no signature). Original algorithm: {alg}. "
                            f"This allows complete authentication bypass — anyone can forge "
                            f"any claims (roles, user ID, admin flags) and the server will accept them."
                        ),
                        url=url,
                        evidence=f"Forged 'none' token accepted: HTTP {test_resp.status_code}",
                        payload=forged[:40],
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Fix the JWT validation logic to reject tokens where the algorithm "
                            "differs from the expected value. Hardcode the expected algorithm. "
                            "Never allow the client to choose the algorithm."
                        ),
                        references=[
                            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                            "https://cwe.mitre.org/data/definitions/347.html",
                        ],
                        cwe_id="CWE-347",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    ))

        # 3. Weak secret brute-force (HS256/HS384/HS512 only)
        if alg.upper() in ("HS256", "HS384", "HS512"):
            weak_secret = self._brute_force_secret(token, alg.upper())
            if weak_secret is not None:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.JWT,
                    title="JWT Signed With Weak Secret",
                    description=(
                        f"The JWT uses {alg} and is signed with a weak/common secret: '{weak_secret}'. "
                        f"An attacker can forge arbitrary JWT tokens with any claims, "
                        f"leading to complete authentication bypass."
                    ),
                    url=url,
                    evidence=f"Secret found: '{weak_secret}'",
                    payload=token_short,
                    severity=Severity.CRITICAL,
                    remediation=(
                        "Use a cryptographically random secret of at least 256 bits for HS256. "
                        "Consider switching to RS256 (asymmetric) which does not have this weakness. "
                        "Rotate all existing tokens immediately."
                    ),
                    references=[
                        "https://portswigger.net/web-security/jwt",
                        "https://cwe.mitre.org/data/definitions/521.html",
                    ],
                    cwe_id="CWE-521",
                    owasp_category="A02:2021 - Cryptographic Failures",
                ))

        # 4. Check for sensitive data in payload
        if payload:
            sensitive_claims = ["password", "passwd", "secret", "key", "private"]
            found_sensitive = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_claims)]
            if found_sensitive:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.JWT,
                    title="Sensitive Data in JWT Payload",
                    description=(
                        f"The JWT payload contains potentially sensitive claims: {found_sensitive}. "
                        f"JWT payloads are base64-encoded (not encrypted) and readable by anyone "
                        f"who has the token. Sensitive data should never be stored in JWT payloads "
                        f"unless using JWE (encrypted JWTs)."
                    ),
                    url=url,
                    evidence=f"Sensitive claims: {found_sensitive}",
                    payload=token_short,
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Remove sensitive fields from JWT payloads. "
                        "Store only minimal, non-sensitive claims. "
                        "Use JWE if sensitive data must be included."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/312.html"],
                    cwe_id="CWE-312",
                    owasp_category="A02:2021 - Cryptographic Failures",
                ))

        # 5. Check for missing expiry
        if payload and "exp" not in payload:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.JWT,
                title="JWT Missing Expiration Claim (exp)",
                description=(
                    "The JWT token does not contain an 'exp' (expiration) claim. "
                    "Without expiration, tokens are valid indefinitely. If a token is stolen, "
                    "it can be used forever with no way to invalidate it."
                ),
                url=url,
                evidence=f"JWT payload claims: {list(payload.keys())}",
                payload=token_short,
                severity=Severity.MEDIUM,
                remediation=(
                    "Always include an 'exp' claim with a short lifetime (e.g., 15 minutes for access tokens). "
                    "Implement token refresh flows for longer sessions."
                ),
                references=["https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4"],
                cwe_id="CWE-613",
                owasp_category="A07:2021 - Identification and Authentication Failures",
            ))

        return vulns

    def _brute_force_secret(self, token: str, algorithm: str) -> Optional[str]:
        """Attempt to brute-force the JWT secret from the weak secret list."""
        hash_func_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = hash_func_map.get(algorithm)
        if not hash_func:
            return None

        parts = token.split(".")
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}".encode()
        try:
            provided_sig = base64.urlsafe_b64decode(
                parts[2] + "=" * (-len(parts[2]) % 4)
            )
        except Exception:
            return None

        for secret in JWT_WEAK_SECRETS:
            try:
                computed = hmac.HMAC(
                    secret.encode(),
                    message,
                    hash_func,
                ).digest()
                if hmac.compare_digest(computed, provided_sig):
                    return secret
            except Exception:
                continue

        return None
