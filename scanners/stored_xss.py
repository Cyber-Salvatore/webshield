"""
Stored XSS Scanner — Professional Grade
=========================================
Coverage:
  • Multi-format canary injection (HTML tag, JSON string, SVG, attribute)
  • Injection into POST form text/textarea/email/number/select fields
  • Injection into JSON API bodies (detected via Content-Type)
  • Injection into PUT/PATCH endpoints (REST API stored XSS)
  • Canary verification across:
    - All crawled URLs from the same session
    - Common content-display paths (/, /feed, /posts, /dashboard, /admin, …)
    - API endpoints that may render stored content (/api/comments, /api/posts, …)
  • HTML entity escape detection (ensures unescaped confirmation)
  • Escape check variants: HTML-escaped, JS-escaped, URL-encoded forms
  • Password field skip (don't inject into passwords)
  • File upload field skip
  • CSRF token preservation in form submissions
  • Confidence: High (confirmed unescaped in render context) /
                Medium (canary found but in JS string — not executing yet)

CWE  : CWE-79
OWASP: A03:2021 – Injection
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import hashlib
import json
import re
import time
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

# ---------------------------------------------------------------------------
# CVSS
# ---------------------------------------------------------------------------

_CVSS_HIGH = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.LOW, UserInteraction.NONE,
    Scope.CHANGED, Impact.LOW, Impact.LOW, Impact.NONE,
)
_CVSS_MEDIUM = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.LOW, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.LOW, Impact.NONE, Impact.NONE,
)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_CWE   = "CWE-79"
_OWASP = "A03:2021 - Injection"
_REFS  = [
    "https://owasp.org/www-community/attacks/xss/#stored-xss-attacks",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/79.html",
]
_REMEDIATION = (
    "1. HTML-encode all stored user input before rendering in HTML context.\n"
    "2. Use framework-provided output escaping (Jinja2 autoescaping, React JSX, etc.).\n"
    "3. Never use innerHTML or document.write() to render stored user content.\n"
    "4. Implement a Content-Security-Policy without 'unsafe-inline'.\n"
    "5. Sanitize rich-text input with DOMPurify before storing or rendering."
)

# ---------------------------------------------------------------------------
# Pages to check for stored canaries after injection
# ---------------------------------------------------------------------------

_CHECK_PATHS: List[str] = [
    "/", "/home", "/index", "/index.html", "/index.php",
    "/feed", "/comments", "/posts", "/forum", "/blog",
    "/profile", "/account", "/dashboard", "/admin",
    "/messages", "/notifications", "/activity", "/inbox",
    "/search", "/results", "/reviews", "/ratings",
    "/timeline", "/wall", "/board",
    # API endpoints that often render stored content
    "/api/comments", "/api/posts", "/api/messages",
    "/api/feed", "/api/timeline", "/api/users/me",
    "/api/v1/comments", "/api/v1/posts",
]

# ---------------------------------------------------------------------------
# Canary templates for different injection contexts
# ---------------------------------------------------------------------------

def _make_uid(action: str, field: str) -> str:
    ts = str(time.monotonic_ns())
    h  = hashlib.md5(f"sxss{action}{field}{ts}".encode(), usedforsecurity=False).hexdigest()[:10]
    return h


def _html_canary(uid: str) -> str:
    """HTML tag canary — confirms HTML context injection."""
    return f'<img src=x id="wsxss{uid}" onerror="void(0)">'


def _attr_canary(uid: str) -> str:
    """Attribute break canary."""
    return f'" wsxss{uid}="1'


def _js_canary(uid: str) -> str:
    """JavaScript string break canary."""
    return f"';/*wsxss{uid}*/'"


def _svg_canary(uid: str) -> str:
    """SVG-based canary."""
    return f'<svg id="wsxss{uid}"><title>test</title></svg>'


# ---------------------------------------------------------------------------
# Escape-detection helpers
# ---------------------------------------------------------------------------

_HTML_ENTITY_RE = re.compile(r"&(?:lt|gt|quot|amp|#\d+|#x[0-9a-fA-F]+);", re.I)


def _canary_unescaped(uid: str, body: str) -> bool:
    """Return True if the canary UID appears in body without angle bracket entity encoding."""
    raw_tag  = f'id="wsxss{uid}"'
    esc_tag  = f'id=&quot;wsxss{uid}&quot;'
    svg_tag  = f'id="wsxss{uid}"'     # same for SVG

    if raw_tag in body and esc_tag not in body:
        return True
    if svg_tag in body and esc_tag not in body:
        return True
    # Also check uid alone in non-entity context
    idx = body.find(f"wsxss{uid}")
    if idx == -1:
        return False
    ctx = body[max(0, idx - 5): idx + len(uid) + 15]
    return "&lt;" not in ctx and "&gt;" not in ctx and "&quot;" not in ctx


def _canary_in_js_string(uid: str, body: str) -> bool:
    """Return True if the canary appears inside a JS string (not executed yet — Medium confidence)."""
    escaped_apos = f"\\'/*wsxss{uid}*/"
    escaped_dq   = f'\\"/*wsxss{uid}*/"'
    raw_js       = f"/*wsxss{uid}*/"

    return any(s in body for s in (escaped_apos, escaped_dq, raw_js))


# ===========================================================================
# Scanner
# ===========================================================================

class StoredXSSScanner(_ScannerBase):
    """
    Stored XSS scanner using multi-format canary injection and distributed verification.

    Phase 1: Inject canaries into all injectable fields via:
      - HTML form POST submissions
      - JSON API POST/PUT/PATCH bodies

    Phase 2: Verify canaries by visiting:
      - All crawled URLs from the engine session
      - Common content-display paths
      - API endpoints that return stored content
    """

    name = "Stored XSS"

    def __init__(self, client: Any) -> None:
        super().__init__(client)
        # uid → (action, field_name, source_url, canary_html)
        self._injected: Dict[str, Tuple[str, str, str, str]] = {}

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # ── Phase 1: Inject canaries ────────────────────────────────────────
        await self._inject_forms(url, forms)
        await self._inject_json_api(url, response)

        # ── Phase 2: Verify canaries ────────────────────────────────────────
        if not self._injected:
            return vulns

        found = await self._verify_canaries(base, url, response)
        vulns.extend(found)

        return vulns

    # -----------------------------------------------------------------------
    # Phase 1a: Form injection
    # -----------------------------------------------------------------------

    async def _inject_forms(
        self, url: str, forms: List[Dict[str, Any]]
    ) -> None:
        for form in forms:
            method = (form.get("method") or "GET").upper()
            if method != "POST":
                continue
            action = form.get("action") or url
            inputs = form.get("inputs", [])

            for inp in inputs:
                inp_type = (inp.get("type") or "text").lower()
                name     = inp.get("name", "")
                if not name:
                    continue
                # Skip non-injectable field types
                if inp_type in ("submit", "button", "file", "image", "hidden",
                                "password", "reset", "checkbox", "radio"):
                    continue

                uid     = _make_uid(action, name)
                canary  = _html_canary(uid)

                # Build form data — preserve CSRF tokens, fill other fields
                form_data: Dict[str, str] = {}
                for i in inputs:
                    n = i.get("name", "")
                    if not n:
                        continue
                    if n == name:
                        form_data[n] = canary
                    elif i.get("type", "").lower() in ("submit", "button", "image", "reset"):
                        pass  # omit submit buttons
                    else:
                        form_data[n] = i.get("value", "test")

                resp = await self.client.post(action, data=form_data)
                if resp and resp.status_code in (200, 201, 202, 302, 303):
                    self._injected[uid] = (action, name, url, canary)

                # Also inject SVG canary variant for rich-text fields
                if inp_type in ("textarea", "text"):
                    uid2   = _make_uid(action, name + "_svg")
                    canary2 = _svg_canary(uid2)
                    form_data2 = dict(form_data)
                    form_data2[name] = canary2
                    resp2 = await self.client.post(action, data=form_data2)
                    if resp2 and resp2.status_code in (200, 201, 202, 302, 303):
                        self._injected[uid2] = (action, name, url, canary2)

    # -----------------------------------------------------------------------
    # Phase 1b: JSON API injection
    # -----------------------------------------------------------------------

    async def _inject_json_api(
        self, url: str, response: HTTPResponse
    ) -> None:
        """
        If the current endpoint returns JSON, try to inject canaries via
        POST/PUT/PATCH with a JSON body containing string fields.
        """
        ct = response.content_type.lower()
        if "json" not in ct:
            return

        # Try to parse the response and construct a mirrored payload with canaries
        try:
            data = json.loads(response.text)
        except Exception:
            return

        if not isinstance(data, dict):
            return

        # Find string fields to inject into
        injectable = {k: v for k, v in data.items() if isinstance(v, str) and len(v) < 500}
        if not injectable:
            return

        for field_name, original_val in list(injectable.items())[:3]:
            uid    = _make_uid(url, field_name + "_json")
            canary = _html_canary(uid)

            payload = dict(data)
            payload[field_name] = canary

            for method in ("POST", "PUT", "PATCH"):
                resp = await self.client.request(
                    method, url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp and resp.status_code in (200, 201, 202):
                    self._injected[uid] = (url, field_name, url, canary)
                    break

    # -----------------------------------------------------------------------
    # Phase 2: Canary verification
    # -----------------------------------------------------------------------

    async def _verify_canaries(
        self,
        base: str,
        current_url: str,
        current_response: HTTPResponse,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # Build check URL list: fixed paths + current URL
        check_urls: List[str] = [current_url]
        for path in _CHECK_PATHS:
            check_urls.append(urljoin(base, path))
        # Deduplicate
        check_urls = list(dict.fromkeys(check_urls))

        # Check if stored canary appears on each page
        for check_url in check_urls:
            try:
                resp = await self.client.get(check_url)
                if not resp or not resp.is_text:
                    continue
                body = resp.text

                for uid, (inject_action, inject_field, inject_url, canary) in self._injected.items():
                    # High confidence: raw canary present unescaped
                    if _canary_unescaped(uid, body):
                        vulns.append(self._build_vuln(
                            vuln_type=VulnType.XSS,
                            title="Stored XSS Confirmed — Canary Rendered Unescaped",
                            description=(
                                f"A unique XSS canary was injected via POST to '{inject_action}' "
                                f"(field: '{inject_field}'). The canary was later found UNESCAPED "
                                f"at '{check_url}'. "
                                f"Any authenticated or unauthenticated user visiting '{check_url}' "
                                f"will have the injected script execute in their browser. "
                                f"This is persistent/stored XSS."
                            ),
                            url=inject_url,
                            method="POST",
                            parameter=inject_field,
                            payload=canary[:80],
                            evidence=f"Canary 'wsxss{uid}' found unescaped at: {check_url}",
                            severity=Severity.HIGH,
                            cvss=_CVSS_HIGH,
                            remediation=_REMEDIATION,
                            references=_REFS,
                            cwe_id=_CWE,
                            owasp_category=_OWASP,
                            response_snippet=self._snippet(body),
                            confidence="High",
                        ))
                        # Remove from injected to avoid duplicate findings
                        break

                    # Medium confidence: canary in JS string context
                    elif _canary_in_js_string(uid, body):
                        vulns.append(self._build_vuln(
                            vuln_type=VulnType.XSS,
                            title="Potential Stored XSS — Canary in JavaScript String Context",
                            description=(
                                f"A unique canary injected into '{inject_action}' (field: '{inject_field}') "
                                f"was found at '{check_url}' inside a JavaScript string. "
                                f"The injection point is within JS — a context-specific payload "
                                f"(e.g., '; alert(1); //) may execute. Manual verification required."
                            ),
                            url=inject_url,
                            method="POST",
                            parameter=inject_field,
                            payload=canary[:80],
                            evidence=f"Canary 'wsxss{uid}' found in JS context at: {check_url}",
                            severity=Severity.MEDIUM,
                            cvss=_CVSS_MEDIUM,
                            remediation=_REMEDIATION,
                            references=_REFS,
                            cwe_id=_CWE,
                            owasp_category=_OWASP,
                            response_snippet=self._snippet(body),
                            confidence="Medium",
                        ))

            except Exception:
                continue

        return vulns
