"""
Reflection Tracking Engine — Phase 4.5
=========================================
Tracks where injected payloads are reflected in responses and how they
are transformed along the way (URL encoding, HTML encoding, Base64, etc.).

Capabilities:
  • Detect if a canary string is reflected in the response
  • Identify the reflection context (HTML tag, attribute, script, style, URL)
  • Detect encoding transformations applied to the payload
  • Detect partial filtering (e.g. <script> stripped but content remains)
  • Generate context-aware follow-up payloads based on the transformation chain
  • Used by XSS, SSTI scanners to make second-stage payloads smarter

Reflection Contexts:
  HTML_TEXT      → inside tag text node     <p>PAYLOAD</p>
  HTML_ATTR      → inside an attribute      <input value="PAYLOAD">
  SCRIPT_STRING  → inside a JS string       var x = "PAYLOAD";
  SCRIPT_BARE    → bare JS expression       var x = PAYLOAD;
  URL            → inside a href/src/action
  STYLE          → inside a CSS value
  COMMENT        → inside an HTML comment
  JSON_VALUE     → inside a JSON string value
  UNKNOWN        → reflected but context unclear
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReflectionContext(str, Enum):
    HTML_TEXT     = "html_text"
    HTML_ATTR     = "html_attribute"
    SCRIPT_STRING = "script_string"
    SCRIPT_BARE   = "script_bare"
    URL           = "url_attribute"
    STYLE         = "css_style"
    COMMENT       = "html_comment"
    JSON_VALUE    = "json_value"
    UNKNOWN       = "unknown"


class Transformation(str, Enum):
    NONE          = "none"
    HTML_ENCODE   = "html_encoded"    # < → &lt;
    URL_ENCODE    = "url_encoded"     # < → %3C
    DOUBLE_ENCODE = "double_encoded"  # %3C → %253C
    BASE64        = "base64"
    STRIPPED      = "stripped"        # payload partially or fully removed
    CASE_CHANGED  = "case_changed"    # e.g. SCRIPT → script
    BACKSLASH_ESC = "backslash_escaped"  # " → \"
    PARTIAL       = "partial"         # part of payload present, part filtered


# ---------------------------------------------------------------------------
# ReflectionResult
# ---------------------------------------------------------------------------

@dataclass
class ReflectionResult:
    """All reflection data collected for one canary/payload in one response."""
    canary: str
    reflected: bool
    contexts: List[ReflectionContext] = field(default_factory=list)
    transformations: List[Transformation] = field(default_factory=list)
    reflection_count: int = 0          # how many times reflected
    partial_reflection: bool = False   # part of canary present

    @property
    def is_html_injectable(self) -> bool:
        return ReflectionContext.HTML_TEXT in self.contexts and \
               Transformation.HTML_ENCODE not in self.transformations

    @property
    def is_attr_injectable(self) -> bool:
        return ReflectionContext.HTML_ATTR in self.contexts and \
               Transformation.HTML_ENCODE not in self.transformations

    @property
    def is_script_injectable(self) -> bool:
        return ReflectionContext.SCRIPT_STRING in self.contexts or \
               ReflectionContext.SCRIPT_BARE in self.contexts

    def to_dict(self) -> Dict:
        return {
            "canary": self.canary,
            "reflected": self.reflected,
            "contexts": [c.value for c in self.contexts],
            "transformations": [t.value for t in self.transformations],
            "reflection_count": self.reflection_count,
            "partial_reflection": self.partial_reflection,
        }


# ---------------------------------------------------------------------------
# Regex patterns for context detection
# ---------------------------------------------------------------------------

# HTML tag attribute: value="CANARY" or value='CANARY' or value=CANARY
_ATTR_PATTERNS = [
    re.compile(r'=\s*"[^"]*{c}[^"]*"', re.IGNORECASE),
    re.compile(r"=\s*'[^']*{c}[^']*'", re.IGNORECASE),
    re.compile(r"=\s*({c})", re.IGNORECASE),
]

# Inside <script> block, in a string
_SCRIPT_STRING_RE = re.compile(
    r'<script[^>]*>.*?(?:"[^"]*{c}[^"]*"|\'[^\']*{c}[^\']*\').*?</script>',
    re.IGNORECASE | re.DOTALL,
)

# Inside <script> block, bare (not in string delimiters)
_SCRIPT_BARE_RE = re.compile(
    r'<script[^>]*>[^<]*{c}[^<]*</script>',
    re.IGNORECASE | re.DOTALL,
)

# Inside HTML comment
_COMMENT_RE = re.compile(r'<!--[^>]*{c}[^>]*-->', re.IGNORECASE)

# Inside href/src/action/data attributes
_URL_ATTR_RE = re.compile(
    r'(?:href|src|action|data|formaction)\s*=\s*["\']?[^"\'> ]*{c}',
    re.IGNORECASE,
)

# Inside <style> tag or style attribute
_STYLE_RE = re.compile(
    r'(?:<style[^>]*>[^<]*{c}[^<]*</style>|style\s*=\s*"[^"]*{c}[^"]*")',
    re.IGNORECASE | re.DOTALL,
)

# Inside JSON string value
_JSON_RE = re.compile(r'"[^"]*{c}[^"]*"', re.IGNORECASE)


# ---------------------------------------------------------------------------
# ReflectionTracker
# ---------------------------------------------------------------------------

class ReflectionTracker:
    """
    Phase 4.5 — Reflection Tracking Engine.

    Usage::

        tracker = ReflectionTracker()

        # Check if canary was reflected and how
        result = tracker.track(canary="wshld_abc123", response_body=html)

        if result.is_html_injectable:
            # Generate a context-aware XSS payload
            payloads = tracker.suggest_payloads(result)
    """

    # -----------------------------------------------------------------------
    # Main API
    # -----------------------------------------------------------------------

    def track(self, canary: str, response_body: str) -> ReflectionResult:
        """
        Analyse *response_body* for all occurrences and transformations of *canary*.
        """
        result = ReflectionResult(canary=canary, reflected=False)

        if not canary or not response_body:
            return result

        # ── Direct reflection ─────────────────────────────────────────────
        direct_count = response_body.count(canary)
        if direct_count > 0:
            result.reflected = True
            result.reflection_count = direct_count
            result.transformations.append(Transformation.NONE)
            result.contexts.extend(self._detect_contexts(canary, response_body))

        # ── HTML-encoded reflection ───────────────────────────────────────
        html_encoded = self._html_encode(canary)
        if html_encoded != canary and html_encoded in response_body:
            result.reflected = True
            result.reflection_count += response_body.count(html_encoded)
            if Transformation.HTML_ENCODE not in result.transformations:
                result.transformations.append(Transformation.HTML_ENCODE)

        # ── URL-encoded reflection ────────────────────────────────────────
        url_encoded = urllib.parse.quote(canary, safe="")
        if url_encoded != canary and url_encoded in response_body:
            result.reflected = True
            result.reflection_count += response_body.count(url_encoded)
            if Transformation.URL_ENCODE not in result.transformations:
                result.transformations.append(Transformation.URL_ENCODE)

        # ── Double URL-encoded ────────────────────────────────────────────
        double_encoded = urllib.parse.quote(url_encoded, safe="")
        if double_encoded != url_encoded and double_encoded in response_body:
            result.reflected = True
            if Transformation.DOUBLE_ENCODE not in result.transformations:
                result.transformations.append(Transformation.DOUBLE_ENCODE)

        # ── Base64 ───────────────────────────────────────────────────────
        b64 = base64.b64encode(canary.encode()).decode()
        if b64 in response_body:
            result.reflected = True
            if Transformation.BASE64 not in result.transformations:
                result.transformations.append(Transformation.BASE64)

        # ── Partial reflection ────────────────────────────────────────────
        if not result.reflected and len(canary) > 4:
            partial = self._detect_partial(canary, response_body)
            if partial:
                result.reflected = True
                result.partial_reflection = True
                if Transformation.PARTIAL not in result.transformations:
                    result.transformations.append(Transformation.PARTIAL)
                if Transformation.STRIPPED not in result.transformations:
                    result.transformations.append(Transformation.STRIPPED)

        # ── Case-changed reflection ───────────────────────────────────────
        if not result.reflected:
            if canary.lower() in response_body.lower() and canary not in response_body:
                result.reflected = True
                result.transformations.append(Transformation.CASE_CHANGED)

        # ── Backslash-escaped ─────────────────────────────────────────────
        escaped = canary.replace('"', '\\"').replace("'", "\\'")
        if escaped != canary and escaped in response_body:
            result.reflected = True
            if Transformation.BACKSLASH_ESC not in result.transformations:
                result.transformations.append(Transformation.BACKSLASH_ESC)

        # De-duplicate contexts
        result.contexts = list(dict.fromkeys(result.contexts))

        return result

    # -----------------------------------------------------------------------

    def suggest_payloads(self, result: ReflectionResult) -> List[str]:
        """
        Return context-aware follow-up payloads based on how the canary
        was reflected and what transformations were applied.
        """
        if not result.reflected:
            return []

        payloads: List[str] = []
        transforms: Set[Transformation] = set(result.transformations)

        for ctx in result.contexts:
            if ctx == ReflectionContext.HTML_TEXT:
                if Transformation.HTML_ENCODE not in transforms:
                    payloads += [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "<svg onload=alert(1)>",
                    ]
                else:
                    # HTML is encoded — try attribute injection instead
                    payloads += ['" onmouseover="alert(1)', "' onmouseover='alert(1)"]

            elif ctx == ReflectionContext.HTML_ATTR:
                if Transformation.HTML_ENCODE not in transforms:
                    payloads += [
                        '" onmouseover="alert(1)" x="',
                        "' onmouseover='alert(1)' x='",
                        '"><script>alert(1)</script>',
                        "'><img src=x onerror=alert(1)>",
                    ]
                else:
                    # HTML-encoded attr — try breaking out differently
                    payloads += [
                        "javascript:alert(1)",
                        "data:text/html,<script>alert(1)</script>",
                    ]

            elif ctx == ReflectionContext.SCRIPT_STRING:
                if Transformation.BACKSLASH_ESC not in transforms:
                    payloads += [
                        '";alert(1)//',
                        "';alert(1)//",
                        '\\";alert(1)//',
                        "</script><script>alert(1)</script>",
                    ]
                else:
                    # Escaping backslashes → try Unicode escapes
                    payloads += [
                        r"\u0022;alert(1)//",
                        r"\x22;alert(1)//",
                    ]

            elif ctx == ReflectionContext.SCRIPT_BARE:
                payloads += [
                    ";alert(1)//",
                    ";alert(1);var x=",
                ]

            elif ctx == ReflectionContext.URL:
                payloads += [
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                ]

            elif ctx == ReflectionContext.JSON_VALUE:
                payloads += [
                    '","__proto__":{"admin":true},"x":"',
                    '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
                ]

        # De-duplicate while preserving order
        seen: Set[str] = set()
        unique: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    # -----------------------------------------------------------------------
    # Canary generation
    # -----------------------------------------------------------------------

    @staticmethod
    def generate_canary(prefix: str = "wshld") -> str:
        """
        Generate a unique canary string that is:
        - Unlikely to appear in real content
        - Short enough to test quickly
        - Contains a numeric suffix for easy grep
        """
        import uuid
        suffix = uuid.uuid4().hex[:8]
        return f"{prefix}_{suffix}"

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _detect_contexts(self, canary: str, body: str) -> List[ReflectionContext]:
        """Detect all reflection contexts for *canary* in *body*."""
        contexts: List[ReflectionContext] = []
        c = re.escape(canary)

        if re.search(_COMMENT_RE.pattern.replace("{c}", c), body, re.IGNORECASE):
            contexts.append(ReflectionContext.COMMENT)

        if re.search(_URL_ATTR_RE.pattern.replace("{c}", c), body, re.IGNORECASE):
            contexts.append(ReflectionContext.URL)

        if re.search(_STYLE_RE.pattern.replace("{c}", c), body, re.IGNORECASE | re.DOTALL):
            contexts.append(ReflectionContext.STYLE)

        if re.search(_SCRIPT_STRING_RE.pattern.replace("{c}", c), body, re.IGNORECASE | re.DOTALL):
            contexts.append(ReflectionContext.SCRIPT_STRING)
        elif re.search(_SCRIPT_BARE_RE.pattern.replace("{c}", c), body, re.IGNORECASE | re.DOTALL):
            contexts.append(ReflectionContext.SCRIPT_BARE)

        # Attribute check (generic)
        for pat in _ATTR_PATTERNS:
            if re.search(pat.pattern.replace("{c}", c), body, re.IGNORECASE):
                if ReflectionContext.HTML_ATTR not in contexts:
                    contexts.append(ReflectionContext.HTML_ATTR)
                break

        # JSON value
        if re.search(_JSON_RE.pattern.replace("{c}", c), body, re.IGNORECASE):
            contexts.append(ReflectionContext.JSON_VALUE)

        if not contexts:
            # Canary is in the body but we couldn't classify the context
            contexts.append(ReflectionContext.HTML_TEXT)

        return contexts

    @staticmethod
    def _html_encode(text: str) -> str:
        """Manually HTML-encode the most important special characters."""
        return (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    @staticmethod
    def _detect_partial(canary: str, body: str) -> bool:
        """
        Check if a meaningful portion (≥50%) of the canary appears in the body.
        Handles cases where filters strip certain characters.
        """
        # Try 4-char sliding windows
        window = max(4, len(canary) // 2)
        for i in range(len(canary) - window + 1):
            chunk = canary[i:i + window]
            if chunk in body:
                return True
        return False
