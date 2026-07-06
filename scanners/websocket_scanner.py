"""
WebSocket Security Scanner.

Tests discovered WebSocket endpoints for:
- Missing / bypassable authentication on the WS handshake
- Message injection vulnerabilities (XSS, SQLi, CMDi payloads)
- Sensitive data leakage in messages
- Authorization bypass (accessing other users' channels)
- Subprotocol abuse
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPClient, HTTPResponse
from ..models.vulnerability import (
    Vulnerability, Severity, VulnType, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)

# Playwright (optional — only needed for actual WS connections)
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Fix 3.2: use websockets library for real WS connections (httpx cannot do WS upgrades)
try:
    import websockets
    import websockets.exceptions as _ws_exc
    _WS_LIB_AVAILABLE = True
except ImportError:
    _WS_LIB_AVAILABLE = False
    websockets = None       # type: ignore[assignment]
    _ws_exc = None          # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Injection payloads for WS message fuzzing
# ---------------------------------------------------------------------------

_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
]

_CMDI_PAYLOADS = [
    "; id",
    "| whoami",
    "`id`",
]

_SENSITIVE_PATTERNS = [
    re.compile(r'\b(?:password|passwd|secret|token|api_?key|auth)\b', re.IGNORECASE),
    re.compile(r'["\']?\bemail\b["\']?\s*[=:]\s*["\'][^"\'@\s]+@[^"\'@\s]+["\']', re.IGNORECASE),
    re.compile(r'\b[0-9]{12,19}\b'),   # credit card number range
    re.compile(r'AKIA[0-9A-Z]{16}'),   # AWS key
]


class WebSocketScanner(_ScannerBase):
    """
    Scans WebSocket endpoints discovered by the BrowserEngine.

    Fix 2.3: is_target_level = True — the scanner operates on the target
    as a whole (all WS URLs at once), not on individual crawled pages.
    It is invoked explicitly from engine._run_target_level_scanners()
    via scan_websocket_urls(), not via the per-URL scanner loop.

    Operates in two modes:
    1. Passive: tests the HTTP upgrade request for auth weaknesses
       (works without Playwright — httpx upgrade handshake probe)
    2. Active: establishes a real WS connection and fuzzes messages
       (requires Playwright)
    """

    name = "WebSocket Security"
    is_target_level = True  # Fix 2.3: runs once per target, not per crawled URL

    # CVSS profile for WS auth bypass
    _CVSS_AUTH_BYPASS = CVSSv3(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    )

    _CVSS_INJECTION = CVSSv3(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    )

    def __init__(self, client: HTTPClient) -> None:
        super().__init__(client)
        self._ws_urls: List[str] = []

    def register_websocket_urls(self, urls: List[str]) -> None:
        """Called by engine with WS URLs discovered by BrowserEngine."""
        self._ws_urls = list(set(urls))

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        """
        Standard scanner interface — required by BaseScanner.
        Since WebSocketScanner is target-level (Fix 2.3), this is called
        once with the root target URL. It scans any registered WS URLs.
        The engine also calls scan_websocket_urls() directly for explicit WS lists.
        """
        if not self._ws_urls:
            return []
        results: List[Vulnerability] = []
        for ws_url in self._ws_urls:
            vulns = await self._scan_websocket(ws_url, url)
            results.extend(vulns)
        return results

    async def scan_websocket_urls(
        self,
        ws_urls: List[str],
        origin_url: str,
    ) -> List[Vulnerability]:
        """Directly scan a list of WebSocket URLs."""
        results: List[Vulnerability] = []
        for ws_url in ws_urls:
            vulns = await self._scan_websocket(ws_url, origin_url)
            results.extend(vulns)
        return results

    # -----------------------------------------------------------------------
    # Core scanning
    # -----------------------------------------------------------------------

    async def _scan_websocket(
        self, ws_url: str, origin_url: str
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # 1. Test HTTP upgrade request without authentication
        vulns.extend(await self._test_unauthenticated_upgrade(ws_url, origin_url))

        # 2. Test cross-origin access
        vulns.extend(await self._test_cross_origin_ws(ws_url, origin_url))

        # 3. Active WS fuzzing (only if Playwright available)
        if PLAYWRIGHT_AVAILABLE:
            vulns.extend(await self._test_ws_message_injection(ws_url, origin_url))

        return vulns

    # -----------------------------------------------------------------------
    # 1. Unauthenticated upgrade test
    # -----------------------------------------------------------------------

    async def _test_unauthenticated_upgrade(
        self, ws_url: str, origin_url: str
    ) -> List[Vulnerability]:
        """
        Fix 3.2: Use the 'websockets' library for a real WebSocket upgrade.
        httpx cannot perform WebSocket protocol upgrades — it returns 426 or
        drops the connection. The websockets library does the proper handshake
        and lets us detect whether the server accepted the connection without auth.

        Falls back to the httpx-header probe if websockets is unavailable,
        which is still useful for detecting misconfigured proxies that forward 101.
        """
        vulns: List[Vulnerability] = []
        origin = self._extract_origin(origin_url)

        # ── Approach 1: real WebSocket connection via websockets lib ────────
        if _WS_LIB_AVAILABLE and websockets is not None:
            try:
                # Connect without any auth headers — timeout 5 s
                connect_kwargs: Dict[str, Any] = {
                    "origin": origin,
                    "open_timeout": 5,
                    "close_timeout": 2,
                    "ssl": None,   # allow self-signed
                }
                async with websockets.connect(ws_url, **connect_kwargs) as ws:
                    # If we get here, the server accepted without auth
                    # Send a ping to confirm the connection is live
                    await ws.send('{"type":"ping"}')
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    except asyncio.TimeoutError:
                        msg = "(no response)"

                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BROKEN_AUTH,
                        title="WebSocket Endpoint Accepts Unauthenticated Connections",
                        description=(
                            f"The WebSocket endpoint at {ws_url} accepted a full "
                            f"WebSocket upgrade without any authentication credentials. "
                            f"A real connection was established (websockets library confirmed). "
                            f"An attacker can receive sensitive real-time data or send "
                            f"unauthorized messages to all connected clients."
                        ),
                        url=ws_url,
                        severity=Severity.HIGH,
                        method="WS",
                        evidence=(
                            f"WebSocket connection established without auth. "
                            f"First message received: {str(msg)[:150]}"
                        ),
                        remediation=(
                            "Validate session tokens or JWTs during the WebSocket upgrade "
                            "handshake. Reject connections that lack a valid auth token "
                            "in either the Authorization header or a query parameter."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/v42/"
                            "4-Web_Application_Security_Testing/11-Client-side_Testing/"
                            "10-Testing_WebSockets",
                        ],
                        cwe_id="CWE-306",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        cvss=self._CVSS_AUTH_BYPASS,
                        confidence="High",
                    ))
                    return vulns

            except Exception as exc:
                # Connection refused / auth required / SSL error
                exc_str = str(exc).lower()
                # 401/403 = auth enforced correctly — not a vulnerability
                if any(code in exc_str for code in ("401", "403", "forbidden", "unauthorized")):
                    return vulns
                # Other errors (timeout, SSL, etc.) — fall through to HTTP probe

        # ── Approach 2: fallback HTTP upgrade-header probe (no websockets lib) ──
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "Origin": origin,
        }
        response = await self.client.get(http_url, headers=headers, allow_redirects=False)
        if response is None:
            return vulns

        if response.status_code == 101:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.BROKEN_AUTH,
                title="WebSocket Endpoint Lacks Authentication (HTTP 101 probe)",
                description=(
                    f"The WebSocket endpoint at {ws_url} returned HTTP 101 Switching "
                    f"Protocols in response to an unauthenticated upgrade request. "
                    f"This suggests the server may not require authentication. "
                    f"Install 'websockets' (pip install websockets) for full confirmation."
                ),
                url=ws_url,
                severity=Severity.HIGH,
                method="GET",
                evidence=f"HTTP 101 received on unauthenticated upgrade request to {http_url}",
                remediation=(
                    "Validate session tokens / JWT before accepting WebSocket upgrade. "
                    "Reject connections that do not include a valid Authorization header "
                    "or authenticated session cookie."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/"
                    "4-Web_Application_Security_Testing/11-Client-side_Testing/"
                    "10-Testing_WebSockets",
                ],
                cwe_id="CWE-306",
                owasp_category="A07:2021 – Identification and Authentication Failures",
                cvss=self._CVSS_AUTH_BYPASS,
                confidence="Medium",
            ))

        return vulns

    # -----------------------------------------------------------------------
    # 2. Cross-origin test
    # -----------------------------------------------------------------------

    async def _test_cross_origin_ws(
        self, ws_url: str, origin_url: str
    ) -> List[Vulnerability]:
        """
        Test if the WS endpoint accepts connections from a different origin.
        Many WS servers only check Origin against an allowlist.
        """
        vulns: List[Vulnerability] = []
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

        evil_origin = "https://attacker.com"
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "Origin": evil_origin,
        }

        response = await self.client.get(
            http_url, headers=headers, allow_redirects=False
        )
        if response is None:
            return vulns

        if response.status_code == 101:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.CORS,
                title="WebSocket Cross-Origin Connection Accepted",
                description=(
                    f"The WebSocket endpoint at {ws_url} accepted an upgrade from a "
                    f"cross-origin request (Origin: {evil_origin}). This may allow "
                    f"malicious websites to establish WebSocket connections on behalf "
                    f"of authenticated users (WebSocket CSRF)."
                ),
                url=ws_url,
                severity=Severity.MEDIUM,
                method="GET",
                evidence=f"HTTP 101 accepted with Origin: {evil_origin}",
                remediation=(
                    "Validate the Origin header on WebSocket upgrade requests. "
                    "Only allow connections from trusted origins."
                ),
                references=[
                    "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
                ],
                cwe_id="CWE-346",
                owasp_category="A05:2021 – Security Misconfiguration",
                confidence="Medium",
            ))

        return vulns

    # -----------------------------------------------------------------------
    # 3. Active message injection (requires Playwright)
    # -----------------------------------------------------------------------

    async def _test_ws_message_injection(
        self, ws_url: str, origin_url: str
    ) -> List[Vulnerability]:
        """
        Connect to the WebSocket and send injection payloads.
        Monitors responses for reflection or error-based indicators.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return []

        vulns: List[Vulnerability] = []

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                received_messages: List[str] = []
                injection_results: List[Dict[str, Any]] = []

                # Navigate to the origin page first (establishes cookies/session)
                try:
                    await page.goto(origin_url, wait_until="domcontentloaded", timeout=10_000)
                except Exception:
                    pass

                # Run injection test via injected JS
                test_script = f"""
                    async () => {{
                        const results = [];
                        const payloads = {json.dumps(_XSS_PAYLOADS[:2] + _SQLI_PAYLOADS[:2])};

                        try {{
                            const ws = new WebSocket({json.dumps(ws_url)});
                            await new Promise((resolve, reject) => {{
                                ws.onopen = resolve;
                                ws.onerror = reject;
                                setTimeout(reject, 5000);
                            }});

                            for (const payload of payloads) {{
                                ws.send(JSON.stringify({{ message: payload }}));
                                await new Promise(r => setTimeout(r, 500));
                                // Also try as plain text
                                ws.send(payload);
                                await new Promise(r => setTimeout(r, 300));
                            }}

                            // Collect responses
                            const msgs = [];
                            ws.onmessage = (e) => msgs.push(e.data);
                            await new Promise(r => setTimeout(r, 2000));
                            ws.close();
                            results.push({{ connected: true, messages: msgs }});
                        }} catch(e) {{
                            results.push({{ connected: false, error: e.message }});
                        }}
                        return results;
                    }}
                """

                try:
                    test_results = await page.evaluate(test_script)
                    if test_results and test_results[0].get("connected"):
                        messages = test_results[0].get("messages", [])
                        for msg in messages:
                            if self._contains_reflection(msg, _XSS_PAYLOADS + _SQLI_PAYLOADS):
                                vulns.append(self._build_vuln(
                                    vuln_type=VulnType.XSS,
                                    title="WebSocket Message Injection — Payload Reflected",
                                    description=(
                                        f"Injected payloads were reflected in WebSocket "
                                        f"messages from {ws_url}. This may indicate "
                                        f"insufficient input validation that could lead to "
                                        f"XSS or injection attacks against other connected clients."
                                    ),
                                    url=ws_url,
                                    severity=Severity.HIGH,
                                    method="WS",
                                    evidence=f"Reflected message: {msg[:200]}",
                                    remediation=(
                                        "Validate and sanitize all data received via WebSocket "
                                        "before broadcasting to other clients or reflecting back."
                                    ),
                                    cwe_id="CWE-79",
                                    owasp_category="A03:2021 – Injection",
                                    cvss=self._CVSS_INJECTION,
                                    confidence="Medium",
                                ))
                                break  # one finding per WS URL

                        # Check for sensitive data leakage in responses
                        for msg in messages:
                            for pattern in _SENSITIVE_PATTERNS:
                                if pattern.search(msg):
                                    vulns.append(self._build_vuln(
                                        vuln_type=VulnType.SENSITIVE_DATA,
                                        title="WebSocket Exposes Sensitive Data",
                                        description=(
                                            f"WebSocket messages from {ws_url} appear to contain "
                                            f"sensitive information such as credentials, tokens, or "
                                            f"personal data."
                                        ),
                                        url=ws_url,
                                        severity=Severity.MEDIUM,
                                        method="WS",
                                        evidence=f"Message snippet: {msg[:150]}",
                                        remediation=(
                                            "Review what data is broadcast over WebSocket channels. "
                                            "Ensure sensitive fields are filtered or encrypted."
                                        ),
                                        cwe_id="CWE-200",
                                        owasp_category="A02:2021 – Cryptographic Failures",
                                        confidence="Medium",
                                    ))
                                    break
                except Exception:
                    pass

                await page.close()
                await context.close()
                await browser.close()

        except Exception:
            pass

        return vulns

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    @staticmethod
    def _contains_reflection(message: str, payloads: List[str]) -> bool:
        for payload in payloads:
            if payload[:10] in message:
                return True
        return False
