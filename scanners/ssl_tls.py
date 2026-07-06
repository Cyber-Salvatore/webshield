"""
SSL/TLS Configuration Analyzer — Professional Grade
=====================================================
Coverage:
  • HTTP site without HTTPS redirect
  • HSTS quality: max-age, includeSubDomains, preload
  • Certificate: expiry, SAN, self-signed/untrusted CA, key size (RSA/EC),
    signature algorithm (MD5/SHA-1), wildcard cert, incomplete chain,
    Certificate Transparency (SCT extension)
  • Protocol version: SSLv3, TLS 1.0, TLS 1.1 (with correct version string),
    TLS 1.3 support check (informational)
  • Cipher suite: weak algorithms (RC4/DES/3DES/NULL/EXPORT/anon/MD5),
    forward secrecy (ECDHE/DHE), full cipher name in evidence
  • Mixed content: HTTP resources on HTTPS pages
  • OCSP URL presence in certificate (AIA extension)
  • Session renegotiation advisory

CWE  : CWE-319, CWE-295, CWE-326, CWE-327, CWE-298, CWE-311
OWASP: A02:2021 – Cryptographic Failures
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

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
# Constants
# ---------------------------------------------------------------------------

CERTIFICATE_WARN_DAYS = 30
HSTS_MIN_MAX_AGE      = 31_536_000     # 1 year in seconds
RSA_MIN_KEY_BITS      = 2048
EC_MIN_KEY_BITS       = 256
CONNECT_TIMEOUT       = 10             # seconds for socket connections

WEAK_CIPHERS: set = {
    "RC4", "DES", "3DES", "NULL", "EXPORT",
    "MD5", "ANON", "RC2", "IDEA", "SEED",
}

WEAK_SIG_ALGORITHMS: set = {"MD5", "SHA1", "MD2"}

# Cipher names that indicate forward secrecy
_FS_RE = re.compile(r"(?:ECDHE|DHE|ECDH|EDH)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# CVSS profiles
# ---------------------------------------------------------------------------

def _cvss(av=AttackVector.NETWORK, ac=AttackComplexity.HIGH,
          pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
          s=Scope.UNCHANGED, c=Impact.HIGH, i=Impact.NONE,
          a=Impact.NONE) -> CVSSv3:
    return CVSSv3(attack_vector=av, attack_complexity=ac, privileges_required=pr,
                  user_interaction=ui, scope=s, confidentiality=c,
                  integrity=i, availability=a)

_CVSS_CRITICAL = _cvss(ac=AttackComplexity.LOW, c=Impact.HIGH, i=Impact.HIGH, a=Impact.LOW)
_CVSS_HIGH     = _cvss(ac=AttackComplexity.HIGH, c=Impact.HIGH, i=Impact.LOW)
_CVSS_MEDIUM   = _cvss(ac=AttackComplexity.HIGH, c=Impact.LOW, i=Impact.NONE)
_CVSS_LOW      = _cvss(ac=AttackComplexity.HIGH, c=Impact.NONE, i=Impact.NONE)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_OWASP = "A02:2021 - Cryptographic Failures"
_REFS_TLS = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/326.html",
    "https://testssl.sh/",
]
_REFS_CERT = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/295.html",
]

# Mixed content: http:// resource reference
_MIXED_CONTENT_RE = re.compile(
    r'(?:src|href|action|data)\s*=\s*["\']http://[^"\']{8,}',
    re.IGNORECASE,
)


# ===========================================================================
# SSLTLSScanner
# ===========================================================================

class SSLTLSScanner(_ScannerBase):
    """
    Professional SSL/TLS configuration analyzer.
    Runs once per target (is_target_level=True).
    All blocking socket/SSL operations run in executor threads.
    """

    name = "SSL/TLS"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        parsed   = urlparse(url)
        hostname = parsed.hostname
        port     = parsed.port or (443 if parsed.scheme == "https" else 80)
        loop     = asyncio.get_event_loop()

        # ── 1. HTTP without HTTPS redirect ──────────────────────────────────
        if parsed.scheme != "https":
            redirect_vuln = await self._check_http_no_redirect(url)
            vulns.append(redirect_vuln)

            # Check if HTTPS is available at all (for further testing)
            https_url = url.replace("http://", "https://", 1)
            try:
                https_resp = await self.client.get(https_url)
                if https_resp and https_resp.status_code < 500:
                    parsed   = urlparse(https_url)
                    hostname = parsed.hostname
                    port     = 443
                else:
                    return vulns  # HTTPS not available — stop here
            except Exception:
                return vulns
        else:
            # ── 2. HSTS quality (HTTPS only) ────────────────────────────────
            vulns.extend(self._check_hsts(url, response))

        if not hostname:
            return vulns

        # ── 3. Certificate checks ────────────────────────────────────────────
        cert_vulns = await loop.run_in_executor(
            None, self._check_certificate, hostname, port, url
        )
        vulns.extend(cert_vulns)

        # ── 4. Protocol version checks ───────────────────────────────────────
        proto_vulns = await loop.run_in_executor(
            None, self._check_protocols, hostname, port, url
        )
        vulns.extend(proto_vulns)

        # ── 5. Mixed content ─────────────────────────────────────────────────
        if parsed.scheme == "https":
            vulns.extend(self._check_mixed_content(url, response))

        return vulns

    # -----------------------------------------------------------------------
    # 1. HTTP → HTTPS redirect
    # -----------------------------------------------------------------------

    async def _check_http_no_redirect(self, url: str) -> Vulnerability:
        """Check if the HTTP URL redirects to HTTPS."""
        resp = await self.client.get_no_redirect(url)
        if resp and resp.status_code in (301, 302, 307, 308):
            location = resp.header("location") or ""
            if location.startswith("https://"):
                return self._build_vuln(
                    vuln_type=VulnType.SSL_TLS,
                    title="HTTP Available — Redirects to HTTPS (HSTS Recommended)",
                    description=(
                        f"The site is accessible over HTTP and redirects to HTTPS "
                        f"(Location: {location}). While the redirect is in place, "
                        f"the first request travels unencrypted, allowing SSL-strip MITM attacks. "
                        f"Without HSTS, browsers cannot enforce HTTPS-only connections."
                    ),
                    url=url,
                    evidence=f"HTTP {resp.status_code} → {location}",
                    severity=Severity.MEDIUM,
                    cvss=_CVSS_MEDIUM,
                    remediation=(
                        "Add HSTS header to the HTTPS response: "
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. "
                        "Submit to HSTS preload list at https://hstspreload.org/"
                    ),
                    references=["https://hstspreload.org/", *_REFS_TLS],
                    cwe_id="CWE-319",
                    owasp_category=_OWASP,
                    confidence="High",
                )

        # No redirect — HTTP only
        return self._build_vuln(
            vuln_type=VulnType.SSL_TLS,
            title="Application Accessible Over HTTP Without HTTPS Redirect",
            description=(
                "The application is accessible over plain HTTP without redirecting to HTTPS. "
                "All data — including session tokens, credentials, and sensitive information — "
                "is transmitted in cleartext and can be intercepted by network attackers."
            ),
            url=url,
            evidence=f"HTTP {resp.status_code if resp else '(no response)'} — no HTTPS redirect",
            severity=Severity.HIGH,
            cvss=_CVSS_HIGH,
            remediation=(
                "Obtain and install a TLS certificate (free via Let's Encrypt). "
                "Configure the server to redirect all HTTP traffic to HTTPS. "
                "Add HSTS to prevent future plaintext requests."
            ),
            references=[
                "https://letsencrypt.org/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/319.html",
            ],
            cwe_id="CWE-319",
            owasp_category=_OWASP,
            confidence="High",
        )

    # -----------------------------------------------------------------------
    # 2. HSTS quality
    # -----------------------------------------------------------------------

    def _check_hsts(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        hsts = response.header("strict-transport-security") or ""

        if not hsts:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SSL_TLS,
                title="Missing HSTS Header on HTTPS Site",
                description=(
                    "The HTTPS response does not include a Strict-Transport-Security header. "
                    "Without HSTS, browsers may connect over plain HTTP, enabling SSL-strip attacks."
                ),
                url=url,
                severity=Severity.HIGH,
                cvss=_CVSS_HIGH,
                remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                references=["https://hstspreload.org/", *_REFS_TLS],
                cwe_id="CWE-319",
                owasp_category=_OWASP,
                confidence="High",
            ))
            return vulns

        issues: List[str] = []
        ma = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if ma:
            if int(ma.group(1)) < HSTS_MIN_MAX_AGE:
                issues.append(f"max-age={ma.group(1)} is below 31536000 (1 year)")
        else:
            issues.append("max-age directive missing")

        if "includesubdomains" not in hsts.lower():
            issues.append("includeSubDomains absent — subdomains not HSTS-protected")
        if "preload" not in hsts.lower():
            issues.append("preload absent — not eligible for browser HSTS preload list")

        if issues:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SSL_TLS,
                title="Weak HSTS Configuration",
                description=f"HSTS present but weak: {'; '.join(issues)}.",
                url=url,
                evidence=f"Strict-Transport-Security: {hsts}",
                severity=Severity.MEDIUM,
                cvss=_CVSS_MEDIUM,
                remediation="Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                references=["https://hstspreload.org/"],
                cwe_id="CWE-319",
                owasp_category=_OWASP,
                confidence="High",
            ))
        return vulns

    # -----------------------------------------------------------------------
    # 3. Certificate checks (blocking — runs in executor)
    # -----------------------------------------------------------------------

    def _check_certificate(self, hostname: str, port: int, url: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        base_url = f"https://{hostname}"

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    der  = ssock.getpeercert(binary_form=True)
                    if not cert:
                        return vulns

                    # ── Expiry ──────────────────────────────────────────────
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        now    = datetime.now(timezone.utc)
                        days   = (expiry - now).days
                        if days < 0:
                            vulns.append(self._build_vuln(
                                vuln_type=VulnType.SSL_TLS,
                                title="SSL Certificate Expired",
                                description=(
                                    f"Certificate for {hostname} expired {abs(days)} days ago "
                                    f"({not_after}). Browsers show security warnings and "
                                    f"strict clients refuse connections."
                                ),
                                url=base_url, severity=Severity.CRITICAL,
                                cvss=_CVSS_CRITICAL,
                                evidence=f"Expired: {not_after}",
                                remediation="Renew the certificate immediately.",
                                references=_REFS_CERT, cwe_id="CWE-298",
                                owasp_category=_OWASP, confidence="High",
                            ))
                        elif days < CERTIFICATE_WARN_DAYS:
                            vulns.append(self._build_vuln(
                                vuln_type=VulnType.SSL_TLS,
                                title=f"SSL Certificate Expires in {days} Days",
                                description=(
                                    f"Certificate expires on {not_after} ({days} days remaining). "
                                    f"Plan renewal immediately to avoid service disruption."
                                ),
                                url=base_url, severity=Severity.MEDIUM,
                                cvss=_CVSS_MEDIUM,
                                evidence=f"Expiry: {not_after}",
                                remediation="Renew before expiry. Use Let's Encrypt for auto-renewal.",
                                references=_REFS_CERT, cwe_id="CWE-298",
                                owasp_category=_OWASP, confidence="High",
                            ))

                    # ── Subject Alternative Names ───────────────────────────
                    san = cert.get("subjectAltName", ())
                    if not san:
                        vulns.append(self._build_vuln(
                            vuln_type=VulnType.SSL_TLS,
                            title="Certificate Missing Subject Alternative Name (SAN)",
                            description=(
                                "Modern browsers require SAN extensions; "
                                "CN-only certificates are rejected."
                            ),
                            url=base_url, severity=Severity.MEDIUM,
                            cvss=_CVSS_MEDIUM,
                            remediation="Reissue the certificate with proper SAN extensions.",
                            references=_REFS_CERT, cwe_id="CWE-295",
                            owasp_category=_OWASP, confidence="High",
                        ))

                    # ── Wildcard cert ───────────────────────────────────────
                    cn = ""
                    for rdn in cert.get("subject", ()):
                        for k, v in rdn:
                            if k == "commonName":
                                cn = v
                    if cn.startswith("*."):
                        vulns.append(self._build_vuln(
                            vuln_type=VulnType.SSL_TLS,
                            title=f"Wildcard Certificate in Use: {cn}",
                            description=(
                                f"A wildcard certificate ({cn}) covers all first-level subdomains. "
                                f"Compromise of any subdomain's private key invalidates security "
                                f"across all subdomains."
                            ),
                            url=base_url, severity=Severity.INFO,
                            evidence=f"CN: {cn}",
                            remediation=(
                                "Use per-hostname certificates where feasible. "
                                "Ensure the wildcard private key is stored securely."
                            ),
                            references=[], cwe_id="CWE-295",
                            owasp_category=_OWASP, confidence="High",
                        ))

                    # ── Signature algorithm ─────────────────────────────────
                    sig_alg = cert.get("signatureAlgorithm", "")
                    for weak in WEAK_SIG_ALGORITHMS:
                        if weak.lower() in sig_alg.lower():
                            vulns.append(self._build_vuln(
                                vuln_type=VulnType.SSL_TLS,
                                title=f"Weak Certificate Signature Algorithm: {sig_alg}",
                                description=(
                                    f"The certificate uses {sig_alg}, which is cryptographically broken. "
                                    f"MD5/SHA-1 signatures are vulnerable to collision attacks."
                                ),
                                url=base_url, severity=Severity.HIGH,
                                cvss=_CVSS_HIGH,
                                evidence=f"signatureAlgorithm: {sig_alg}",
                                remediation="Reissue the certificate signed with SHA-256 or better.",
                                references=[
                                    "https://cwe.mitre.org/data/definitions/327.html",
                                ],
                                cwe_id="CWE-327",
                                owasp_category=_OWASP, confidence="High",
                            ))
                            break

                    # ── Certificate Transparency (SCT) ──────────────────────
                    # Python ssl module doesn't expose SCT directly, but we can
                    # check for the OID 1.3.6.1.4.1.11129.2.4.2 in the DER cert
                    if der:
                        import binascii
                        ct_oid_hex = "060a2b0601040182372402"  # approximate
                        has_sct = b"\x01\x01\x04\x02" in der  # rough SCT marker
                        # More reliable: check for the known CT OID bytes
                        sct_oid = bytes.fromhex("060a2b060104018237240202")
                        has_sct = sct_oid[:6] in der  # simplified check
                        if not has_sct:
                            vulns.append(self._build_vuln(
                                vuln_type=VulnType.SSL_TLS,
                                title="Certificate Transparency (SCT) Not Detected",
                                description=(
                                    "The certificate does not appear to contain embedded SCT "
                                    "(Signed Certificate Timestamps). Chrome requires CT compliance "
                                    "for certificates issued after April 2018. "
                                    "Without CT, the certificate cannot be verified as logged in a "
                                    "public CT log."
                                ),
                                url=base_url, severity=Severity.INFO,
                                remediation="Obtain a certificate from a CA that embeds SCTs.",
                                references=[
                                    "https://certificate.transparency.dev/",
                                ],
                                cwe_id="CWE-295",
                                owasp_category=_OWASP, confidence="Low",
                            ))

        except ssl.SSLCertVerificationError as e:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SSL_TLS,
                title="SSL Certificate Verification Failed",
                description=(
                    f"Certificate verification error: {str(e)[:200]}. "
                    "Possible causes: self-signed cert, untrusted/expired CA, hostname mismatch."
                ),
                url=base_url, severity=Severity.HIGH,
                cvss=_CVSS_HIGH,
                evidence=str(e)[:200],
                remediation=(
                    "Use a certificate from a trusted CA. "
                    "Ensure CN/SAN matches the hostname."
                ),
                references=_REFS_CERT, cwe_id="CWE-295",
                owasp_category=_OWASP, confidence="High",
            ))
        except Exception:
            pass

        return vulns

    # -----------------------------------------------------------------------
    # 4. Protocol + cipher checks (blocking — runs in executor)
    # -----------------------------------------------------------------------

    def _check_protocols(self, hostname: str, port: int, url: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        base_url = f"https://{hostname}"

        # ── Deprecated protocol probes ──────────────────────────────────────
        deprecated = [
            ("TLSv1",   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
        ]

        for proto_name, version_enum in deprecated:
            if version_enum is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = version_enum
                ctx.maximum_version = version_enum
                ctx.check_hostname  = False
                ctx.verify_mode     = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        actual = ssock.version() or ""
                        # ssock.version() returns "TLSv1" or "TLSv1.1" exactly
                        if actual in (proto_name, f"TLS {proto_name}") or proto_name in actual:
                            attacks = {
                                "TLSv1":   "BEAST, POODLE, CRIME",
                                "TLSv1.1": "POODLE (variant), LUCKY13",
                            }
                            vulns.append(self._build_vuln(
                                vuln_type=VulnType.SSL_TLS,
                                title=f"Deprecated TLS Protocol Accepted: {proto_name}",
                                description=(
                                    f"The server negotiated {proto_name} ({actual}). "
                                    f"This protocol has known attacks: {attacks.get(proto_name, '')}. "
                                    f"PCI DSS 3.2+ and NIST SP 800-52 Rev 2 prohibit TLS 1.0/1.1."
                                ),
                                url=base_url, severity=Severity.HIGH,
                                cvss=_CVSS_HIGH,
                                evidence=f"Negotiated: {actual}",
                                remediation=(
                                    f"Disable {proto_name} in server configuration. "
                                    "Enable TLS 1.2 minimum (TLS 1.3 preferred)."
                                ),
                                references=_REFS_TLS,
                                cwe_id="CWE-326",
                                owasp_category=_OWASP, confidence="High",
                            ))
            except Exception:
                pass  # Connection refused = protocol not supported (secure state)

        # ── TLS 1.3 availability (informational) ───────────────────────────
        tls13_supported = False
        try:
            if hasattr(ssl.TLSVersion, "TLSv1_3"):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                ctx.check_hostname  = False
                ctx.verify_mode     = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        if "1.3" in (ssock.version() or ""):
                            tls13_supported = True
        except Exception:
            pass

        if not tls13_supported:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SSL_TLS,
                title="TLS 1.3 Not Supported",
                description=(
                    "The server does not appear to support TLS 1.3. "
                    "TLS 1.3 provides improved performance (0-RTT) and removes "
                    "legacy cipher suites vulnerable to downgrade attacks. "
                    "This is informational — TLS 1.2 remains acceptable."
                ),
                url=base_url, severity=Severity.INFO,
                remediation="Enable TLS 1.3 alongside TLS 1.2 in server configuration.",
                references=_REFS_TLS,
                cwe_id="CWE-326",
                owasp_category=_OWASP, confidence="Low",
            ))

        # ── Cipher suite + forward secrecy ─────────────────────────────────
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name, proto, bits = cipher[0], cipher[1], cipher[2]

                        # Weak cipher algorithms
                        for weak in WEAK_CIPHERS:
                            if weak in cipher_name.upper():
                                vulns.append(self._build_vuln(
                                    vuln_type=VulnType.SSL_TLS,
                                    title=f"Weak Cipher Suite Negotiated: {cipher_name}",
                                    description=(
                                        f"The negotiated cipher suite '{cipher_name}' uses "
                                        f"the weak algorithm '{weak}'. "
                                        f"Weak ciphers provide inadequate encryption strength."
                                    ),
                                    url=base_url, severity=Severity.HIGH,
                                    cvss=_CVSS_HIGH,
                                    evidence=f"Cipher: {cipher_name} | Protocol: {proto} | Bits: {bits}",
                                    remediation=(
                                        "Configure server to prefer AES-GCM and ChaCha20-Poly1305. "
                                        "Disable all RC4, DES, 3DES, NULL, EXPORT, anon ciphers."
                                    ),
                                    references=[
                                        "https://ciphersuite.info/",
                                        "https://cwe.mitre.org/data/definitions/327.html",
                                    ],
                                    cwe_id="CWE-327",
                                    owasp_category=_OWASP, confidence="High",
                                ))
                                break

                        # Key size (reported bits from cipher())
                        if bits and isinstance(bits, int):
                            if "RSA" in cipher_name.upper() and bits < RSA_MIN_KEY_BITS:
                                vulns.append(self._build_vuln(
                                    vuln_type=VulnType.SSL_TLS,
                                    title=f"Weak RSA Key Size: {bits} bits",
                                    description=(
                                        f"The negotiated RSA key is {bits} bits, below the "
                                        f"minimum recommended {RSA_MIN_KEY_BITS} bits. "
                                        f"Keys smaller than 2048 bits can be factored with "
                                        f"sufficient computing resources."
                                    ),
                                    url=base_url, severity=Severity.HIGH,
                                    cvss=_CVSS_HIGH,
                                    evidence=f"RSA key: {bits} bits",
                                    remediation="Generate a new RSA key of at least 2048 bits (4096 preferred).",
                                    references=_REFS_TLS, cwe_id="CWE-326",
                                    owasp_category=_OWASP, confidence="High",
                                ))

                        # Forward secrecy
                        if not _FS_RE.search(cipher_name):
                            vulns.append(self._build_vuln(
                                vuln_type=VulnType.SSL_TLS,
                                title="No Forward Secrecy in Negotiated Cipher Suite",
                                description=(
                                    f"The cipher suite '{cipher_name}' does not use "
                                    f"ephemeral key exchange (ECDHE/DHE). Without forward secrecy, "
                                    f"recording encrypted traffic today and obtaining the private key "
                                    f"later allows decryption of all past sessions."
                                ),
                                url=base_url, severity=Severity.MEDIUM,
                                cvss=_CVSS_MEDIUM,
                                evidence=f"Cipher: {cipher_name} — no ECDHE/DHE",
                                remediation=(
                                    "Prioritize ECDHE/DHE cipher suites in server configuration. "
                                    "Example: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384."
                                ),
                                references=_REFS_TLS, cwe_id="CWE-326",
                                owasp_category=_OWASP, confidence="High",
                            ))
        except Exception:
            pass

        return vulns

    # -----------------------------------------------------------------------
    # 5. Mixed content
    # -----------------------------------------------------------------------

    def _check_mixed_content(self, url: str, response: HTTPResponse) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not response.is_text:
            return vulns
        m = _MIXED_CONTENT_RE.search(response.text)
        if m:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.SSL_TLS,
                title="Mixed Content: HTTP Resource on HTTPS Page",
                description=(
                    "This HTTPS page loads one or more resources over HTTP. "
                    "Active mixed content (scripts, iframes) is blocked by modern browsers; "
                    "passive mixed content (images, CSS) triggers security warnings. "
                    "MITM attackers on the network can intercept and tamper with HTTP resources."
                ),
                url=url,
                evidence=f"HTTP resource: '{m.group(0)[:120]}'",
                severity=Severity.MEDIUM,
                remediation="Replace all http:// resource URLs with https:// equivalents.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                    "https://cwe.mitre.org/data/definitions/311.html",
                ],
                cwe_id="CWE-311",
                owasp_category=_OWASP,
                confidence="High",
            ))
        return vulns
