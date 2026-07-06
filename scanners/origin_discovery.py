# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Origin IP Discovery Scanner
Detects real server IP behind CDN/WAF by analyzing SSL fingerprints,
response body hashes, and HTTP headers.
Inspired by OriginHunter v10 methodology.
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPClient, HTTPResponse
from ..models.vulnerability import Vulnerability, Severity, VulnType


# CDN/WAF detection header keys
_CDN_HDR_EXACT: Set[str] = {
    'cf-ray', 'cf-cache-status',
    'x-amz-cf-id', 'x-amz-rid',
    'x-akamai-transformed', 'x-akamai-ssl', 'x-akamai-request-id',
    'x-fastly-request-id', 'x-served-by', 'x-cache', 'x-cache-hits',
    'x-sucuri-id', 'x-sucuri-cache',
    'x-proxy-cache', 'x-varnish',
    'x-incap-session-id', 'x-iinfo',
    'nel', 'report-to',
}

_CDN_SERVER_PATTERNS = [
    'cloudflare', 'akamai', 'fastly', 'amazon cloudfront',
    'imperva', 'sucuri', 'incapsula', 'stackpath', 'bunnycdn',
    'edgecast', 'limelight', 'azurefd',
]

# Framework fingerprint patterns
_FRAMEWORK_PATTERNS: Dict[str, List[str]] = {
    'Spring Boot':  [r'Whitelabel Error Page', r'"timestamp"\s*:\s*\d+.*"status"\s*:\s*\d+'],
    'Express/Node': [r'Cannot \w+ /', r'X-Powered-By.*[Ee]xpress'],
    'Django':       [r'Django.*CSRF', r'<title>Django</title>', r'DisallowedHost'],
    'Laravel':      [r'laravel_session', r'X-Powered-By.*PHP'],
    'Rails':        [r'X-Runtime.*Ruby', r'ActionDispatch'],
    'Nginx bare':   [r'<title>Welcome to nginx', r'nginx/\d'],
    'Apache bare':  [r'Apache Tomcat|It works!', r'Apache/2\.\d'],
    'Tomcat':       [r'Apache Tomcat', r'HTTP Status \d+ .?[–—]'],
    'IIS bare':     [r'IIS Windows Server', r'Microsoft-IIS'],
}


def _is_cdn(headers: Dict[str, str]) -> Tuple[bool, str]:
    """Detect if response is from a CDN/WAF."""
    h = {k.lower(): v for k, v in headers.items()}

    for key in _CDN_HDR_EXACT:
        if key in h:
            return True, f"CDN header '{key}': {h[key][:40]}"

    server = h.get('server', '').lower()
    for pattern in _CDN_SERVER_PATTERNS:
        if pattern in server:
            return True, f"CDN Server: {h.get('server', '')[:40]}"

    via = h.get('via', '').lower()
    if via and any(k in via for k in ('cdn', 'cache', 'proxy', 'edge', 'akamai')):
        return True, f"CDN Via: {h.get('via', '')[:40]}"

    return False, ""


def _detect_framework(body: str, headers: Dict[str, str]) -> Optional[str]:
    """Detect backend framework from response."""
    blob = body[:3000] + str(headers)
    for fw, patterns in _FRAMEWORK_PATTERNS.items():
        for p in patterns:
            if re.search(p, blob, re.I):
                return fw
    return None


def _body_hash(content: str) -> str:
    """Normalized body hash for comparison (strips dynamic tokens)."""
    t = re.sub(r'csrf[_\-]?token["\']?\s*[:=]\s*["\']?[\w+/=\-]{8,}', '__CSRF__', content, flags=re.I)
    t = re.sub(r'nonce="[^"]{6,}"', '__NONCE__', t)
    t = re.sub(r'\b[0-9a-f]{32,}\b', '__HASH__', t)
    t = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', '__TS__', t)
    return hashlib.md5(t.encode(), usedforsecurity=False).hexdigest()


def _get_ssl_fingerprint(hostname: str, port: int = 443) -> Optional[str]:
    """Get SSL certificate SHA256 fingerprint."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                if der:
                    return hashlib.sha256(der).hexdigest()[:16]
    except Exception:
        pass
    return None


def _resolve_domain(domain: str) -> Set[str]:
    """Resolve domain to IP addresses."""
    ips: Set[str] = set()
    try:
        for result in socket.getaddrinfo(domain, None):
            ip = result[4][0]
            if ':' not in ip:  # IPv4 only
                ips.add(ip)
    except Exception:
        pass
    return ips


class OriginDiscoveryScanner(_ScannerBase):
    """
    Detects real origin IP behind CDN/WAF.
    Uses SSL fingerprint comparison, body hash matching, and header analysis.
    Methodology from OriginHunter v10.
    """
    name = "Origin IP Discovery"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return vulns

        # Check if behind CDN
        headers_dict = dict(response.headers)
        is_cdn, cdn_reason = _is_cdn(headers_dict)

        if not is_cdn:
            return vulns  # Not behind CDN, no need for origin discovery

        # Fingerprint the real domain response
        domain_body_hash = _body_hash(response.text) if response.text else None
        domain_framework = _detect_framework(response.text or "", headers_dict)
        # Run blocking SSL/DNS calls in executor to avoid stalling the event loop
        import asyncio as _asyncio
        loop = _asyncio.get_event_loop()
        domain_ssl_fp = await loop.run_in_executor(None, _get_ssl_fingerprint, hostname)
        domain_title = self._extract_title(response.text or "")

        # Report CDN detection
        vulns.append(self._build_vuln(
            vuln_type=VulnType.INFO_DISCLOSURE,
            title="CDN/WAF Detected — Origin IP May Be Discoverable",
            description=(
                f"The target is behind a CDN/WAF ({cdn_reason}). "
                f"The real origin server IP may be discoverable via historical DNS records, "
                f"SSL certificate transparency logs, or misconfigured subdomains. "
                f"Discovering the origin IP allows attackers to bypass WAF protections and "
                f"attack the server directly."
            ),
            url=url,
            evidence=f"CDN indicator: {cdn_reason}",
            severity=Severity.INFO,
            remediation=(
                "Ensure all traffic is forced through the CDN. "
                "Use CDN origin protection (Cloudflare Authenticated Origin Pulls). "
                "Restrict the origin server's firewall to only allow CDN IP ranges. "
                "Rotate origin IP if it has been previously exposed."
            ),
            references=[
                "https://blog.detectify.com/2019/07/31/bypassing-cloudflare-waf-with-the-origin-server-ip-address/",
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
            cwe_id="CWE-200",
            owasp_category="A05:2021 - Security Misconfiguration",
            confidence="High",
        ))

        # Try to resolve any subdomains that might expose the real IP
        test_subdomains = [
            f"direct.{hostname}",
            f"origin.{hostname}",
            f"backend.{hostname}",
            f"app.{hostname}",
            f"server.{hostname}",
        ]

        for subdomain in test_subdomains:
            ips = await loop.run_in_executor(None, _resolve_domain, subdomain)
            for ip in ips:
                # Check if this IP serves the same content
                test_url = f"https://{ip}"
                try:
                    test_resp = await self.client.get(
                        test_url,
                        headers={"Host": hostname}
                    )
                    if not test_resp:
                        continue

                    score = 0
                    notes = []

                    # SSL fingerprint check
                    ip_ssl_fp = await loop.run_in_executor(None, _get_ssl_fingerprint, ip)
                    if ip_ssl_fp and domain_ssl_fp:
                        if ip_ssl_fp == domain_ssl_fp:
                            score += 55
                            notes.append("SSL fingerprint IDENTICAL")

                    # Body hash check
                    ip_body_hash = _body_hash(test_resp.text) if test_resp.text else None
                    if ip_body_hash and domain_body_hash and ip_body_hash == domain_body_hash:
                        score += 32
                        notes.append("Response body hash IDENTICAL")

                    # Title check
                    ip_title = self._extract_title(test_resp.text or "")
                    if ip_title and domain_title and ip_title.lower() == domain_title.lower():
                        score += 18
                        notes.append(f"Page title identical: {ip_title[:50]}")

                    # Framework check
                    ip_framework = _detect_framework(test_resp.text or "", dict(test_resp.headers))
                    if ip_framework and domain_framework and ip_framework == domain_framework:
                        score += 10
                        notes.append(f"Framework match: {ip_framework}")

                    # HTTP 400 bonus (bare origin)
                    if test_resp.status_code == 400:
                        score += 14
                        notes.append("HTTP 400 — bare origin (needs Host header)")

                    if score >= 50 and (
                        any("SSL fingerprint IDENTICAL" in n for n in notes) or
                        any("body hash IDENTICAL" in n for n in notes)
                    ):
                        vulns.append(self._build_vuln(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            title=f"Potential Origin IP Discovered via Subdomain: {ip}",
                            description=(
                                f"Subdomain '{subdomain}' resolved to {ip} and appears to be "
                                f"the real origin server with score {score}/100. "
                                f"Evidence: {', '.join(notes)}. "
                                f"This IP likely bypasses CDN/WAF protections."
                            ),
                            url=url,
                            evidence=f"Origin IP: {ip} | Score: {score}/100 | {', '.join(notes)}",
                            severity=Severity.HIGH if score >= 60 else Severity.MEDIUM,
                            remediation=(
                                "Restrict origin server firewall to only allow CDN IP ranges. "
                                "Configure CDN Authenticated Origin Pulls. "
                                "Avoid exposing subdomains that resolve directly to origin."
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/200.html",
                            ],
                            cwe_id="CWE-200",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            confidence="Medium" if score < 60 else "High",
                        ))
                except Exception:
                    continue

        return vulns

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title from HTML."""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
        if match:
            return re.sub(r'\s+', ' ', match.group(1)).strip()[:100]
        return None
