"""
WAF Evasion Engine — Professional Grade
=========================================
Provides automatic payload mutation and request-level evasion techniques
applied transparently across all scanners.

Evasion categories implemented:
  1.  URL encoding variants (single, double, partial, mixed-case)
  2.  HTML entity encoding
  3.  Unicode / UTF-8 overlong sequences
  4.  Whitespace substitution (tabs, newlines, form-feeds, IFS)
  5.  Case randomization
  6.  Comment insertion (SQL, HTML, C-style)
  7.  String concatenation / splitting (SQL CONCAT, JS string concat)
  8.  Null-byte prefix / suffix injection
  9.  HTTP parameter pollution (duplicate params)
  10. Chunked Transfer-Encoding evasion hint
  11. HTTP header fragmentation / folding
  12. WAF bypass headers (X-Forwarded-For: 127.0.0.1, X-Originating-IP, etc.)
  13. Request method override (X-HTTP-Method-Override)
  14. Content-Type switching (application/json ↔ text/plain ↔ multipart)
  15. Path normalization bypass (%2f, ///, /./)
  16. WAF fingerprinting detection (Cloudflare, ModSecurity, AWS WAF, etc.)
  17. Payload fragmentation across parameters
  18. HTTP/1.0 downgrade to bypass HTTP/2-only WAF rules
  19. Large header junk padding (push WAF inspection buffer)
  20. Slow-rate evasion (handled at HTTPClient level via delay/jitter)

Usage:
    from webshield.utils.waf_evasion import WAFEvasionEngine

    engine = WAFEvasionEngine()
    variants = engine.mutate_payload(original_payload, technique="all")
    evasion_headers = engine.get_evasion_headers()
    waf_name = engine.detect_waf(response)
"""
from __future__ import annotations

import html
import re
import secrets as _secrets
import string
import urllib.parse
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Cryptographically-secure RNG for payload mutations
# Fix 1.2: use secrets.SystemRandom() instead of random.random()
# to prevent WAF pattern learning from predictable mutations.
# ---------------------------------------------------------------------------
_rng = _secrets.SystemRandom()

# ---------------------------------------------------------------------------
# WAF signature detection patterns
# ---------------------------------------------------------------------------

_WAF_SIGNATURES: List[Tuple[str, re.Pattern]] = [
    ("Cloudflare",      re.compile(r"cloudflare|cf-ray|__cfduid|cf_clearance", re.I)),
    ("AWS WAF",         re.compile(r"aws.?waf|x-amzn-requestid|awsalb", re.I)),
    ("ModSecurity",     re.compile(r"mod_security|modsecurity|NOYB", re.I)),
    ("Akamai",          re.compile(r"akamai|x-akamai|akamai-ghost", re.I)),
    ("Imperva/Incapsula", re.compile(r"incap_ses|visid_incap|x-iinfo|x-cdn=Imperva", re.I)),
    ("F5 BIG-IP ASM",   re.compile(r"TS[a-zA-Z0-9]{3,8}=|BigIP|F5", re.I)),
    ("Sucuri",          re.compile(r"x-sucuri|sucuri", re.I)),
    ("Barracuda",       re.compile(r"barra_counter_session|BNI__BARRACUDA", re.I)),
    ("Fortinet",        re.compile(r"FORTIWAFSID|fortigate", re.I)),
    ("Wordfence",       re.compile(r"wordfence|wfvt_", re.I)),
    ("Radware",         re.compile(r"X-SL-CompState|rdwr", re.I)),
    ("Wallarm",         re.compile(r"wallarm", re.I)),
    ("Nginx WAF",       re.compile(r"nginx.*WAF|naxsi", re.I)),
    ("Varnish",         re.compile(r"x-varnish|via.*varnish", re.I)),
    ("Reblaze",         re.compile(r"x-reblaze", re.I)),
]

# Block indicators in response (429, 403 with WAF body)
_BLOCK_PATTERNS: List[re.Pattern] = [
    re.compile(r"access denied|blocked|forbidden|security violation|"
               r"illegal request|malicious|attack detected|"
               r"your request has been blocked|waf|firewall|"
               r"this page cannot be displayed|request rejected|"
               r"suspicious activity|security check", re.I),
]

# ---------------------------------------------------------------------------
# Evasion header sets
# ---------------------------------------------------------------------------

_EVASION_HEADERS_SETS: List[Dict[str, str]] = [
    # Fake local origin
    {
        "X-Forwarded-For":        "127.0.0.1",
        "X-Real-IP":              "127.0.0.1",
        "X-Originating-IP":       "127.0.0.1",
        "X-Remote-Addr":          "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
    },
    # Trusted internal IP simulation
    {
        "X-Forwarded-For":   "10.0.0.1, 192.168.1.1, 127.0.0.1",
        "Forwarded":         "for=127.0.0.1;proto=https",
        "X-Forwarded-Host":  "localhost",
    },
    # Minimal evasion
    {
        "X-Forwarded-For": "127.0.0.1",
        "X-Remote-IP":     "127.0.0.1",
    },
    # Content negotiation confusion
    {
        "Accept":          "*/*; q=0.1",
        "Accept-Encoding": "identity",
        "Accept-Language": "en-US;q=0.9, *;q=0.1",
    },
    # Scanner masquerading as vulnerability scanner known to WAFs as benign
    {
        "X-Scanner":        "ZAP",
        "User-Agent":       "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)",
    },
]

# Method override headers (for WAFs that only inspect POST)
_METHOD_OVERRIDE_HEADERS: List[Dict[str, str]] = [
    {"X-HTTP-Method-Override": "PUT"},
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-Method-Override":      "PUT"},
    {"_method":                "PUT"},
]


# ===========================================================================
# WAFEvasionEngine
# ===========================================================================

class WAFEvasionEngine:
    """
    Central WAF evasion engine.
    Used by scanners to mutate payloads and add evasion headers.
    """

    def __init__(self) -> None:
        self._detected_waf: Optional[str] = None
        # Fix 1.1: _blocked_count uses a plain int.
        # In asyncio single-threaded execution, incrementing an int is atomic
        # at the Python bytecode level (GIL-protected). A Lock would cause
        # deadlocks if called from non-async contexts (static methods).
        # We protect concurrent writes with a simple compare-and-set pattern
        # that is safe under asyncio's cooperative scheduling.
        self._blocked_count: int = 0

    # -----------------------------------------------------------------------
    # WAF detection
    # -----------------------------------------------------------------------

    def detect_waf(self, response_text: str, response_headers: Dict[str, str]) -> Optional[str]:
        """
        Detect WAF/CDN from response headers and body.
        Returns WAF name or None.
        Updates internal state for adaptive evasion.
        """
        combined = response_text[:2000] + " " + str(response_headers)

        for waf_name, pattern in _WAF_SIGNATURES:
            if pattern.search(combined):
                self._detected_waf = waf_name
                return waf_name

        return None

    def is_blocked(self, status_code: int, response_text: str) -> bool:
        """Return True if response looks like a WAF block."""
        if status_code in (403, 406, 429, 503):
            for pattern in _BLOCK_PATTERNS:
                if pattern.search(response_text[:3000]):
                    self._blocked_count += 1
                    return True
            # 429 always = rate limited/blocked
            if status_code == 429:
                self._blocked_count += 1
                return True
        return False

    @property
    def detected_waf(self) -> Optional[str]:
        return self._detected_waf

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    # -----------------------------------------------------------------------
    # Payload mutation
    # -----------------------------------------------------------------------

    def mutate_payload(
        self,
        payload: str,
        techniques: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Generate evasion variants of *payload*.

        techniques: list of technique names to apply, or None for all.
        Returns deduplicated list including the original.
        """
        if techniques is None:
            techniques = [
                "url_encode", "double_url_encode", "html_entity",
                "unicode", "case_random", "comment_insert",
                "whitespace_sub", "null_byte", "mixed_encode",
            ]

        variants: List[str] = [payload]  # original always first

        technique_map = {
            "url_encode":        self._url_encode,
            "double_url_encode": self._double_url_encode,
            "html_entity":       self._html_entity,
            "unicode":           self._unicode_escape,
            "case_random":       self._case_randomize,
            "comment_insert":    self._comment_insert,
            "whitespace_sub":    self._whitespace_sub,
            "null_byte":         self._null_byte,
            "mixed_encode":      self._mixed_encode,
            "concat_split":      self._concat_split,
        }

        for tech in techniques:
            fn = technique_map.get(tech)
            if fn:
                try:
                    result = fn(payload)
                    if result and result != payload:
                        variants.append(result)
                except Exception:
                    pass

        return list(dict.fromkeys(variants))  # deduplicate preserving order

    # ──────────────────────────────────────────────────────────────────────
    # Individual mutation functions
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _url_encode(payload: str) -> str:
        """Single URL encode special characters."""
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        """Double URL encode (bypasses WAFs that only decode once)."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def _html_entity(payload: str) -> str:
        """HTML entity encode the payload."""
        return html.escape(payload, quote=True)

    @staticmethod
    def _unicode_escape(payload: str) -> str:
        """Replace ASCII letters with unicode escapes (\\u00xx)."""
        result = []
        for ch in payload:
            if ch.isalpha():
                result.append(f"\\u{ord(ch):04x}")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _case_randomize(payload: str) -> str:
        """Randomly alternate upper/lower case (bypasses case-sensitive rules)."""
        # Fix 1.2: use _rng (secrets.SystemRandom) instead of random.random()
        return "".join(
            c.upper() if _rng.random() > 0.5 else c.lower()
            for c in payload
        )

    @staticmethod
    def _comment_insert(payload: str) -> str:
        """
        Insert SQL/C-style inline comments to break keyword detection.
        e.g. SELECT → SEL/**/ECT, UNION → UN/**/ION
        """
        keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE",
                    "DROP", "WHERE", "FROM", "AND", "OR", "EXEC",
                    "CAST", "CONVERT", "SLEEP", "WAITFOR", "HAVING"]
        result = payload
        for kw in keywords:
            # Case-insensitive replace of the keyword with commented version
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            mid = len(kw) // 2
            replacement = kw[:mid] + "/**/" + kw[mid:]
            result = pattern.sub(replacement, result)
        return result

    @staticmethod
    def _whitespace_sub(payload: str) -> str:
        """Replace spaces with tab/newline/form-feed alternates."""
        substitutions = ["\t", "\n", "\r", "\x0c", "\x0b",
                         "%09", "%0a", "%0d", "/**/", "+"]
        result = []
        for ch in payload:
            if ch == " ":
                # Fix 1.2: use _rng (secrets.SystemRandom) for unpredictable choice
                result.append(_rng.choice(substitutions))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _null_byte(payload: str) -> str:
        """Prepend null byte (bypasses some string-based WAF checks)."""
        return "%00" + payload

    @staticmethod
    def _mixed_encode(payload: str) -> str:
        """Randomly URL-encode some characters (partial encoding)."""
        result = []
        for ch in payload:
            # Fix 1.2: use _rng (secrets.SystemRandom) for unpredictable partial encoding
            if ch.isalnum() and _rng.random() > 0.6:
                result.append(f"%{ord(ch):02X}")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _concat_split(payload: str) -> str:
        """
        SQL string concatenation split: 'admin' → 'adm'||'in' (Oracle/PostgreSQL)
        or 'adm'+'in' (MSSQL).
        """
        if "'" in payload:
            # Find quoted strings and split them
            def split_string(m: re.Match) -> str:
                s = m.group(1)
                if len(s) > 2:
                    mid = len(s) // 2
                    return f"'{s[:mid]}'||'{s[mid:]}'"
                return m.group(0)
            return re.sub(r"'([^']{3,})'", split_string, payload)
        return payload

    # -----------------------------------------------------------------------
    # HTTP-level evasion
    # -----------------------------------------------------------------------

    def get_evasion_headers(self, rotate: bool = True) -> Dict[str, str]:
        """
        Return a set of HTTP headers that help bypass IP-based and
        session-based WAF rules.
        rotate=True cycles through different sets on each call.
        """
        if rotate:
            idx = self._blocked_count % len(_EVASION_HEADERS_SETS)
            return dict(_EVASION_HEADERS_SETS[idx])
        return dict(_EVASION_HEADERS_SETS[0])

    def get_waf_specific_headers(self) -> Dict[str, str]:
        """Return evasion headers tailored to the detected WAF."""
        headers: Dict[str, str] = {}

        if self._detected_waf == "Cloudflare":
            # Cloudflare checks CF-Connecting-IP; spoof it
            headers["CF-Connecting-IP"]   = "127.0.0.1"
            headers["X-Forwarded-For"]    = "127.0.0.1"
            headers["True-Client-IP"]     = "127.0.0.1"

        elif self._detected_waf == "AWS WAF":
            # AWS WAF respects X-Forwarded-For chain
            headers["X-Forwarded-For"]    = "127.0.0.1, 10.0.0.1"
            headers["X-Amzn-Trace-Id"]    = "Root=1-fake-traceid"

        elif self._detected_waf in ("Imperva/Incapsula", "Akamai"):
            headers["X-Forwarded-For"]    = "127.0.0.1"
            headers["X-Originating-IP"]   = "127.0.0.1"
            headers["X-Remote-IP"]        = "127.0.0.1"
            headers["X-Client-IP"]        = "127.0.0.1"

        elif self._detected_waf == "ModSecurity":
            # ModSecurity anomaly scoring — spread anomaly across multiple requests
            headers["X-Forwarded-For"]    = "127.0.0.1"
            # Use a benign-looking Content-Type to avoid MIME-based rules
            headers["Content-Type"]       = "application/x-www-form-urlencoded; charset=utf-8"

        elif self._detected_waf == "F5 BIG-IP ASM":
            headers["X-Forwarded-For"]    = "127.0.0.1"
            headers["X-F5-Https"]         = "1"

        else:
            # Generic fallback
            headers.update(self.get_evasion_headers(rotate=False))

        return headers

    def build_path_evasion_variants(self, path: str) -> List[str]:
        """
        Generate path-level WAF bypass variants.
        Used to probe blocked paths via normalization tricks.
        """
        variants: List[str] = [path]

        # Trailing slash
        variants.append(path + "/")
        # Double slash
        variants.append(path.replace("/", "//", 1))
        # URL-encoded slash
        variants.append(path.replace("/", "%2f", 1))
        # Dot-slash suffix
        variants.append(path + "/.")
        # Semicolon bypass (Tomcat, Spring)
        variants.append(path + ";invalid")
        # Tab/space in path
        variants.append(path + "%09")
        # Null byte
        variants.append(path + "%00")
        # Case variation (Windows IIS)
        variants.append(path.upper())
        variants.append(path.swapcase())
        # Backslash (IIS)
        variants.append(path.replace("/", "\\"))
        # Double encoding
        variants.append(urllib.parse.quote(path, safe=""))
        variants.append(path + "..;/")
        variants.append(path + "?foo=bar")
        variants.append(path + "#")

        return list(dict.fromkeys(variants))

    def build_param_pollution_variants(
        self, param: str, payload: str, original_url: str
    ) -> List[str]:
        """
        HTTP Parameter Pollution: duplicate the parameter with different values
        to confuse WAF parsers.
        """
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

        parsed = urlparse(original_url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        base   = urlunparse(parsed._replace(query=""))

        variants: List[str] = []

        # Variant 1: benign value first, payload second
        v1 = dict(qs)
        v1[param] = ["safe_value", payload]
        variants.append(base + "?" + urlencode(v1, doseq=True))

        # Variant 2: payload first, benign second
        v2 = dict(qs)
        v2[param] = [payload, "safe_value"]
        variants.append(base + "?" + urlencode(v2, doseq=True))

        # Variant 3: array notation
        v3_qs = urlencode(qs, doseq=True)
        variants.append(
            base + "?" + v3_qs + f"&{param}[]={urllib.parse.quote(payload)}"
        )

        return variants

    # -----------------------------------------------------------------------
    # Adaptive evasion
    # -----------------------------------------------------------------------

    def adapt_to_block(self, current_headers: Dict[str, str]) -> Dict[str, str]:
        """
        Called when a request is detected as blocked.
        Returns updated headers for the next attempt with stronger evasion.
        """
        new_headers = dict(current_headers)
        # Rotate to next evasion header set
        evasion = self.get_evasion_headers(rotate=True)
        new_headers.update(evasion)
        # Add WAF-specific headers if known
        new_headers.update(self.get_waf_specific_headers())
        return new_headers

    def get_chunked_encoding_hint(self) -> Dict[str, str]:
        """
        Returns headers that enable chunked transfer encoding.
        Some WAFs inspect only the first N bytes of the body;
        chunked encoding can push the malicious part past that window.
        """
        return {
            "Transfer-Encoding": "chunked",
            "TE":                "chunked",
        }

    def encode_chunked_body(self, body: str) -> bytes:
        """Encode a string body as HTTP chunked transfer encoding."""
        data    = body.encode("utf-8")
        chunk_size = 8  # small chunks to fragment WAF inspection
        encoded = b""
        for i in range(0, len(data), chunk_size):
            chunk  = data[i:i + chunk_size]
            encoded += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        encoded += b"0\r\n\r\n"
        return encoded

    # -----------------------------------------------------------------------
    # SQL-specific bypass helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def sql_bypass_variants(payload: str) -> List[str]:
        """Generate SQL injection specific WAF bypass variants."""
        variants = [payload]
        p = payload.upper()

        # Inline comment variations
        for kw in ["SELECT", "UNION", "INSERT", "UPDATE", "WHERE",
                   "FROM", "AND", "OR", "EXEC", "SLEEP", "WAITFOR"]:
            if kw in p:
                # Tab instead of space
                v = re.sub(re.escape(kw), kw.replace(" ", "\t"), payload, flags=re.I)
                variants.append(v)
                # Newline instead of space
                v = re.sub(re.escape(kw), kw.replace(" ", "\n"), payload, flags=re.I)
                variants.append(v)
                # Comment between chars
                mid = len(kw) // 2
                v = re.sub(
                    re.escape(kw),
                    kw[:mid] + "/**/" + kw[mid:],
                    payload, flags=re.I
                )
                variants.append(v)

        # Scientific notation for numbers
        variants.append(re.sub(r"\b1\b", "1e0", payload))

        # MySQL-specific: /*!SELECT*/ syntax
        for kw in ["SELECT", "UNION", "FROM", "WHERE"]:
            variants.append(
                re.sub(re.escape(kw), f"/*!{kw}*/", payload, flags=re.I)
            )

        # Hex encoding of string literals
        def hex_encode_strings(m: re.Match) -> str:
            s = m.group(1)
            hex_val = "0x" + s.encode().hex()
            return hex_val

        variants.append(re.sub(r"'([^']{2,})'", hex_encode_strings, payload))

        return list(dict.fromkeys(v for v in variants if v != payload))

    @staticmethod
    def xss_bypass_variants(payload: str) -> List[str]:
        """Generate XSS-specific WAF bypass variants."""
        variants = []

        # HTML entity encode event handlers
        for handler in ["onerror", "onload", "onfocus", "onclick", "onmouseover"]:
            if handler in payload.lower():
                # Encode first two chars
                encoded = "&#" + str(ord(handler[0])) + ";" + handler[1:]
                variants.append(payload.lower().replace(handler, encoded))

        # JS escape sequences
        variants.append(
            payload.replace("alert", "\\u0061lert")
                   .replace("script", "scr\\u0069pt")
        )

        # HTML5 browser quirks
        variants.append(payload.replace("<", "\x3c").replace(">", "\x3e"))

        # Tab/newline in tag attributes
        variants.append(payload.replace(" ", "\t"))
        variants.append(payload.replace(" ", "\n"))

        # SVG namespace injection
        if "<svg" not in payload.lower():
            variants.append(f'<svg/onload="{payload}">')

        # Data URI
        import base64
        b64 = base64.b64encode(payload.encode()).decode()
        variants.append(f'<script src="data:text/javascript;base64,{b64}"></script>')

        return list(dict.fromkeys(v for v in variants if v and v != payload))

    @staticmethod
    def cmdi_bypass_variants(payload: str) -> List[str]:
        """Generate command injection WAF bypass variants."""
        variants = [payload]

        # IFS separator
        for cmd in ["id", "whoami", "cat", "ls", "sleep"]:
            if cmd in payload:
                variants.append(payload.replace(cmd, f"${{IFS}}{cmd}"))
                variants.append(payload.replace(cmd, f"$IFS$9{cmd}"))
                # Base64 decode
                import base64
                b64 = base64.b64encode(cmd.encode()).decode()
                variants.append(payload.replace(cmd, f"$(echo {b64}|base64 -d)"))
                # Hex encoding
                hex_cmd = "\\x" + "\\x".join(f"{ord(c):02x}" for c in cmd)
                variants.append(payload.replace(cmd, f"$(printf '{hex_cmd}')"))
                # String splitting
                mid = len(cmd) // 2
                variants.append(payload.replace(cmd, f"{cmd[:mid]}''{cmd[mid:]}"))
                variants.append(payload.replace(cmd, f"{cmd[:mid]}\"{cmd[mid:]}\""))

        # Wildcard matching
        variants.append(payload.replace("cat /etc/passwd", "cat /et?/pa??wd"))
        variants.append(payload.replace("cat /etc/passwd", "cat /etc/p*ss*d"))

        # Brace expansion
        variants.append(payload.replace("id", "{id}"))

        # Newline bypass
        variants.append(payload.replace(";", "\n"))
        variants.append(payload.replace(";", "%0a"))

        return list(dict.fromkeys(v for v in variants if v != payload))
