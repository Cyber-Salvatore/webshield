# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Encoding Framework — Part 14 of the Intelligence Layer.

Every payload produced by the Context-Aware Payload Framework (Part 13) passes
through this engine before it is inserted into a request.  The engine solves a
single problem that has historically separated mediocre scanners from elite ones:
*the same logical attack can be represented in dozens of byte-level forms*, and
a WAF or input filter blocks a payload not because the attack concept is detected
but because a specific byte sequence is recognised.

The Encoding Framework:

  1.  Produces up to **60+ distinct encoded variants** of any input string,
      organised into named families.

  2.  Selects the *best variant for the current environment* using a multi-signal
      scoring model that considers the detected WAF, the parameter context, the
      content-type of the response, the HTTP library behaviour, and prior
      observations from the Baseline Engine.

  3.  Supports *layered / chained encoding* — applying two or more transforms in
      sequence — to defeat filters that normalise a single pass before inspection.

  4.  Implements *context-sensitive encoding* — the correct encoding for an XSS
      payload inside an HTML attribute differs from the same payload inside a
      JavaScript string, a CSS property, or a JSON value.

  5.  Exposes a *learning API* so that when the Differential Analysis Engine
      notices that a variant produced a different response, the framework
      promotes that variant's weight for future requests to the same target.

  6.  Maintains a *per-session WAF bypass profile* that accumulates successful
      technique observations across all parameters tested in one scan.

Architecture
------------
EncodingFamily          — An enum that names the high-level family of encoding.
EncodingTechnique       — A dataclass describing one specific transform.
EncodedPayload          — The result of applying one or more techniques to a
                          string, including all metadata needed to reproduce it.
EncodingContext         — Enum for injection contexts (HTML attr, JS string, …).
WAFProfile              — Accumulated bypass knowledge for a specific WAF.
EncodingFramework       — The main orchestrating class.
EncodingSelector        — Scoring / selection logic (pure, side-effect free).
LayeredEncoder          — Applies a chain of techniques in order.
ContextAwareEncoder     — Chooses families and techniques by injection context.
SessionEncodingMemory   — Mutable per-scan state (learned bypass weights).
EncodingReporter        — Summarises encoding decisions for the Evidence layer.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import itertools
import math
import random
import re
import secrets
import string
import struct
import unicodedata
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

# ---------------------------------------------------------------------------
# Secure RNG — never use random.random() for security-critical mutations
# ---------------------------------------------------------------------------
_rng = secrets.SystemRandom()


# ═══════════════════════════════════════════════════════════════════════════
# 1.  Enumerations
# ═══════════════════════════════════════════════════════════════════════════

class EncodingFamily(str, Enum):
    """High-level grouping of encoding techniques."""
    URL             = "url"
    UNICODE         = "unicode"
    HTML            = "html"
    BASE64          = "base64"
    HEX             = "hex"
    OCTAL           = "octal"
    CASE            = "case"
    WHITESPACE      = "whitespace"
    COMMENT         = "comment"
    CONCATENATION   = "concatenation"
    OVERLONG        = "overlong"
    NULL            = "null"
    CHARCODE        = "charcode"
    JS              = "js"
    CSS             = "css"
    SQL             = "sql"
    XML             = "xml"
    JSON            = "json"
    MIXED           = "mixed"
    SUBSTITUTION    = "substitution"
    COMPRESSION     = "compression"


class EncodingContext(str, Enum):
    """Injection contexts — the surrounding code/document structure."""
    HTML_TEXT           = "html_text"
    HTML_ATTR_DQ        = "html_attr_dq"        # inside double-quoted attribute
    HTML_ATTR_SQ        = "html_attr_sq"        # inside single-quoted attribute
    HTML_ATTR_UNQUOTED  = "html_attr_unquoted"
    HTML_COMMENT        = "html_comment"
    HTML_TAG_NAME       = "html_tag_name"
    JS_STRING_DQ        = "js_string_dq"
    JS_STRING_SQ        = "js_string_sq"
    JS_STRING_TEMPLATE  = "js_string_template"
    JS_IDENTIFIER       = "js_identifier"
    JS_REGEX            = "js_regex"
    CSS_VALUE           = "css_value"
    CSS_SELECTOR        = "css_selector"
    URL_PATH            = "url_path"
    URL_QUERY           = "url_query"
    URL_FRAGMENT        = "url_fragment"
    SQL_STRING_SQ       = "sql_string_sq"
    SQL_STRING_DQ       = "sql_string_dq"
    SQL_NUMERIC         = "sql_numeric"
    SQL_IDENTIFIER      = "sql_identifier"
    XML_TEXT            = "xml_text"
    XML_ATTR            = "xml_attr"
    JSON_STRING         = "json_string"
    JSON_KEY            = "json_key"
    HTTP_HEADER_VALUE   = "http_header_value"
    HTTP_COOKIE_VALUE   = "http_cookie_value"
    PATH_FILESYSTEM     = "path_filesystem"
    SHELL_ARG           = "shell_arg"
    LDAP_FILTER         = "ldap_filter"
    XPATH_EXPR          = "xpath_expr"
    GRAPHQL_STRING      = "graphql_string"
    UNKNOWN             = "unknown"


class SelectionStrategy(str, Enum):
    """How the selector picks from the candidate variants."""
    ALL         = "all"           # return every variant (for thorough scans)
    TOP_N       = "top_n"         # return the N highest-scored variants
    BEST        = "best"          # return only the single best
    WAF_TUNED   = "waf_tuned"     # prefer variants that historically bypass WAF
    RANDOM_N    = "random_n"      # random subset (for stealth mode)
    LAYERED     = "layered"       # return chained multi-layer variants only


# ═══════════════════════════════════════════════════════════════════════════
# 2.  Core Data-Classes
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EncodingTechnique:
    """
    Metadata for one specific encoding transform.

    Attributes
    ----------
    name        : Unique snake_case identifier.
    family      : High-level group this technique belongs to.
    description : Human-readable one-liner for reports.
    fn          : The actual transform; accepts a str, returns a str.
    layers      : How many normalisation passes an application must perform
                  before this encoding becomes transparent (higher = harder).
    waf_bypass  : Set of WAF names this technique is known to bypass.
    contexts    : Injection contexts where this technique is appropriate.
                  Empty set means applicable in all contexts.
    weight      : Initial selection weight (0.0–1.0).  The SessionEncodingMemory
                  adjusts this at runtime based on observed success.
    """
    name:        str
    family:      EncodingFamily
    description: str
    fn:          Callable[[str], str]
    layers:      int                        = 1
    waf_bypass:  FrozenSet[str]             = field(default_factory=frozenset)
    contexts:    FrozenSet[EncodingContext] = field(default_factory=frozenset)
    weight:      float                      = 0.5

    def apply(self, payload: str) -> str:
        return self.fn(payload)


@dataclass
class EncodedPayload:
    """
    The result of encoding an original payload string.

    All fields are preserved so that the scanner and reporter can reconstruct
    exactly what was sent and why.
    """
    original:         str
    encoded:          str
    technique_names:  List[str]      # ordered list (for chained encoding)
    families:         List[EncodingFamily]
    layers:           int
    context:          EncodingContext
    waf_bypass_tags:  List[str]      # WAF names this variant is expected to bypass
    score:            float          = 0.0
    fingerprint:      str            = ""  # sha256[:16] of encoded string

    def __post_init__(self) -> None:
        self.fingerprint = hashlib.sha256(
            self.encoded.encode("utf-8", errors="replace")
        ).hexdigest()[:16]

    @property
    def changed(self) -> bool:
        return self.encoded != self.original

    def to_dict(self) -> Dict:
        return {
            "original":        self.original,
            "encoded":         self.encoded,
            "techniques":      self.technique_names,
            "families":        [f.value for f in self.families],
            "layers":          self.layers,
            "context":         self.context.value,
            "waf_bypass_tags": self.waf_bypass_tags,
            "score":           round(self.score, 4),
            "fingerprint":     self.fingerprint,
        }


@dataclass
class WAFProfile:
    """
    Per-session accumulation of bypass knowledge for one WAF.

    The EncodingSelector reads this profile to bias selection toward
    techniques that have already succeeded against this target.
    """
    waf_name:             str
    successful_techniques: List[str]   = field(default_factory=list)
    blocked_techniques:    List[str]   = field(default_factory=list)
    bypass_rate:           float       = 0.0   # fraction of variants that bypassed
    total_attempts:        int         = 0
    total_bypasses:        int         = 0

    def record_attempt(self, technique_name: str, bypassed: bool) -> None:
        self.total_attempts += 1
        if bypassed:
            self.total_bypasses += 1
            if technique_name not in self.successful_techniques:
                self.successful_techniques.append(technique_name)
        else:
            if technique_name not in self.blocked_techniques:
                self.blocked_techniques.append(technique_name)
        if self.total_attempts:
            self.bypass_rate = self.total_bypasses / self.total_attempts

    def score_technique(self, technique_name: str) -> float:
        """Return a (0–1) score boost for this technique based on history."""
        if technique_name in self.successful_techniques:
            idx = self.successful_techniques.index(technique_name)
            # Earlier = higher score
            return max(0.9 - idx * 0.05, 0.5)
        if technique_name in self.blocked_techniques:
            return 0.0
        return 0.3  # unknown — neutral-ish


# ═══════════════════════════════════════════════════════════════════════════
# 3.  Low-Level Encoder Functions
#     All functions are pure: str → str.  They never raise — any input that
#     cannot be encoded is returned unchanged.
# ═══════════════════════════════════════════════════════════════════════════

class _Enc:
    """
    Namespace for all atomic encoder functions.
    Each is a staticmethod to avoid accidental state sharing.
    """

    # ── URL family ──────────────────────────────────────────────────────────

    @staticmethod
    def url_full(p: str) -> str:
        """Percent-encode every character (including unreserved)."""
        return "".join(f"%{ord(c):02X}" for c in p)

    @staticmethod
    def url_standard(p: str) -> str:
        """Standard URL encoding — only encode what's necessary."""
        return urllib.parse.quote(p, safe="")

    @staticmethod
    def url_double(p: str) -> str:
        """Double URL encoding: % → %25."""
        return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

    @staticmethod
    def url_partial(p: str) -> str:
        """Encode only the special characters, leave alphanumerics raw."""
        result = []
        for c in p:
            if c.isalnum() or c in "-_.~":
                result.append(c)
            else:
                result.append(f"%{ord(c):02X}")
        return "".join(result)

    @staticmethod
    def url_lowercase(p: str) -> str:
        """Percent-encode using lowercase hex digits (%xx instead of %XX)."""
        return urllib.parse.quote(p, safe="").lower()

    @staticmethod
    def url_mixed_case(p: str) -> str:
        """Random case in percent-encoded hex digits."""
        encoded = urllib.parse.quote(p, safe="")
        result = []
        i = 0
        while i < len(encoded):
            if encoded[i] == "%" and i + 2 < len(encoded):
                h1 = encoded[i+1].upper() if _rng.random() > 0.5 else encoded[i+1].lower()
                h2 = encoded[i+2].upper() if _rng.random() > 0.5 else encoded[i+2].lower()
                result.append(f"%{h1}{h2}")
                i += 3
            else:
                result.append(encoded[i])
                i += 1
        return "".join(result)

    @staticmethod
    def url_plus_space(p: str) -> str:
        """Encode using + for spaces (application/x-www-form-urlencoded)."""
        return urllib.parse.quote_plus(p)

    @staticmethod
    def url_path_traversal_encode(p: str) -> str:
        """%2e%2e%2f style encoding for ../ path traversal."""
        return p.replace("../", "%2e%2e%2f").replace("..\\", "%2e%2e%5c")

    # ── Unicode family ───────────────────────────────────────────────────────

    @staticmethod
    def unicode_escape(p: str) -> str:
        r"""JavaScript \uXXXX for every character."""
        return "".join(f"\\u{ord(c):04x}" for c in p)

    @staticmethod
    def unicode_escape_upper(p: str) -> str:
        r"""JavaScript \uXXXX uppercase hex."""
        return "".join(f"\\u{ord(c):04X}" for c in p)

    @staticmethod
    def unicode_escape_selective(p: str) -> str:
        r"""Escape only special/non-alnum characters with \uXXXX."""
        return "".join(
            f"\\u{ord(c):04x}" if not c.isalnum() else c
            for c in p
        )

    @staticmethod
    def unicode_fullwidth(p: str) -> str:
        """Map ASCII printables to Unicode fullwidth equivalents (！ ＜ ＞ …)."""
        result = []
        for c in p:
            cp = ord(c)
            if 0x21 <= cp <= 0x7E:
                result.append(chr(cp + 0xFEE0))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def unicode_confusable(p: str) -> str:
        """Substitute chars with visually similar Unicode confusables."""
        table: Dict[str, str] = {
            "<":  "\u02c2",   # modifier letter left arrowhead
            ">":  "\u02c3",   # modifier letter right arrowhead
            "'":  "\u2019",   # right single quotation mark
            '"':  "\u201d",   # right double quotation mark
            "/":  "\u2215",   # division slash
            "\\": "\u29f5",   # reverse solidus operator
            " ":  "\u00a0",   # non-breaking space
            "=":  "\uff1d",   # fullwidth equals sign
            ".":  "\u2024",   # one dot leader
            "-":  "\u2010",   # hyphen
        }
        return "".join(table.get(c, c) for c in p)

    @staticmethod
    def utf8_overlong_slash(p: str) -> str:
        """Replace / with 2-byte overlong UTF-8 sequence %c0%af."""
        return p.replace("/", "%c0%af").replace("\\", "%c1%9c")

    @staticmethod
    def utf8_overlong_dot(p: str) -> str:
        """Replace . with %c0%ae (overlong period)."""
        return p.replace(".", "%c0%ae")

    @staticmethod
    def idn_encode(p: str) -> str:
        """
        For hostnames only: convert to Punycode / IDN encoding.
        For generic payloads, normalise to NFC then return.
        """
        try:
            return p.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            return unicodedata.normalize("NFC", p)

    # ── HTML entity family ───────────────────────────────────────────────────

    @staticmethod
    def html_entity_decimal(p: str) -> str:
        """&#DDD; decimal entities for every character."""
        return "".join(f"&#{ord(c)};" for c in p)

    @staticmethod
    def html_entity_hex(p: str) -> str:
        """&#xHH; hex entities for every character."""
        return "".join(f"&#x{ord(c):x};" for c in p)

    @staticmethod
    def html_entity_hex_upper(p: str) -> str:
        """&#xHH; hex entities — uppercase."""
        return "".join(f"&#x{ord(c):X};" for c in p)

    @staticmethod
    def html_entity_named(p: str) -> str:
        """Named HTML entities where available, decimal otherwise."""
        named: Dict[str, str] = {
            "<":  "&lt;",
            ">":  "&gt;",
            "&":  "&amp;",
            '"':  "&quot;",
            "'":  "&apos;",
            " ":  "&nbsp;",
            "/":  "&#47;",
            "=":  "&#61;",
        }
        return "".join(named.get(c, f"&#{ord(c)};") for c in p)

    @staticmethod
    def html_entity_selective(p: str) -> str:
        """Named HTML entities only for <>"&' — leave rest raw."""
        return html.escape(p, quote=True)

    @staticmethod
    def html_entity_padded(p: str) -> str:
        """Decimal entity with leading zeroes — &#0060; — to confuse parsers."""
        return "".join(f"&#{ord(c):05d};" for c in p)

    # ── Base64 family ────────────────────────────────────────────────────────

    @staticmethod
    def base64_standard(p: str) -> str:
        return base64.b64encode(p.encode("utf-8")).decode()

    @staticmethod
    def base64_urlsafe(p: str) -> str:
        return base64.urlsafe_b64encode(p.encode("utf-8")).decode()

    @staticmethod
    def base64_no_padding(p: str) -> str:
        return base64.b64encode(p.encode("utf-8")).decode().rstrip("=")

    @staticmethod
    def base64_double(p: str) -> str:
        """Base64 of base64."""
        inner = base64.b64encode(p.encode("utf-8")).decode()
        return base64.b64encode(inner.encode("ascii")).decode()

    @staticmethod
    def base64_chunked(p: str) -> str:
        """Base64 split with CRLF every 76 chars (MIME-style)."""
        encoded = base64.b64encode(p.encode("utf-8")).decode()
        return "\r\n".join(encoded[i:i+76] for i in range(0, len(encoded), 76))

    @staticmethod
    def base32_standard(p: str) -> str:
        return base64.b32encode(p.encode("utf-8")).decode()

    @staticmethod
    def base32_no_padding(p: str) -> str:
        return base64.b32encode(p.encode("utf-8")).decode().rstrip("=")

    # ── Hex family ───────────────────────────────────────────────────────────

    @staticmethod
    def hex_escape_js(p: str) -> str:
        r"""JavaScript \xHH hex escapes."""
        return "".join(f"\\x{ord(c):02x}" for c in p)

    @staticmethod
    def hex_escape_js_upper(p: str) -> str:
        r"""JavaScript \xHH hex escapes — uppercase."""
        return "".join(f"\\x{ord(c):02X}" for c in p)

    @staticmethod
    def hex_encode_sql(p: str) -> str:
        """SQL hex literal: 0x414243..."""
        return "0x" + binascii.hexlify(p.encode("utf-8")).decode()

    @staticmethod
    def hex_encode_css(p: str) -> str:
        r"""CSS unicode escape \000041 for every char."""
        return "".join(f"\\{ord(c):06x}" for c in p)

    @staticmethod
    def hex_encode_raw(p: str) -> str:
        """Raw hex: 4142... no prefix."""
        return binascii.hexlify(p.encode("utf-8")).decode()

    @staticmethod
    def hex_encode_percent_pairs(p: str) -> str:
        """%HH%HH... (like URL encoding but for every byte of UTF-8)."""
        return "".join(f"%{b:02X}" for b in p.encode("utf-8"))

    # ── Octal family ─────────────────────────────────────────────────────────

    @staticmethod
    def octal_escape_js(p: str) -> str:
        r"""JavaScript deprecated octal \DDD."""
        return "".join(f"\\{ord(c):o}" if ord(c) < 256 else c for c in p)

    @staticmethod
    def octal_escape_bash(p: str) -> str:
        r"""Bash $'\DDD' octal escape string."""
        inner = "".join(f"\\{ord(c):03o}" for c in p)
        return f"$'{inner}'"

    # ── Case manipulation ────────────────────────────────────────────────────

    @staticmethod
    def case_upper(p: str) -> str:
        return p.upper()

    @staticmethod
    def case_lower(p: str) -> str:
        return p.lower()

    @staticmethod
    def case_random(p: str) -> str:
        return "".join(c.upper() if _rng.random() > 0.5 else c.lower() for c in p)

    @staticmethod
    def case_alternate(p: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))

    @staticmethod
    def case_title(p: str) -> str:
        return p.title()

    @staticmethod
    def case_swapped(p: str) -> str:
        return p.swapcase()

    # ── Whitespace substitution ───────────────────────────────────────────────

    @staticmethod
    def ws_tab(p: str) -> str:
        return p.replace(" ", "\t")

    @staticmethod
    def ws_newline(p: str) -> str:
        return p.replace(" ", "\n")

    @staticmethod
    def ws_cr(p: str) -> str:
        return p.replace(" ", "\r")

    @staticmethod
    def ws_crlf(p: str) -> str:
        return p.replace(" ", "\r\n")

    @staticmethod
    def ws_formfeed(p: str) -> str:
        return p.replace(" ", "\x0c")

    @staticmethod
    def ws_vertical_tab(p: str) -> str:
        return p.replace(" ", "\x0b")

    @staticmethod
    def ws_null_byte(p: str) -> str:
        """Inject null bytes before/after spaces."""
        return p.replace(" ", "\x00 ")

    @staticmethod
    def ws_unicode_space(p: str) -> str:
        """Replace ASCII space with various Unicode space characters."""
        spaces = [
            "\u00a0",  # NO-BREAK SPACE
            "\u2000",  # EN QUAD
            "\u2001",  # EM QUAD
            "\u2002",  # EN SPACE
            "\u2003",  # EM SPACE
            "\u2004",  # THREE-PER-EM SPACE
            "\u2005",  # FOUR-PER-EM SPACE
            "\u2006",  # SIX-PER-EM SPACE
            "\u2007",  # FIGURE SPACE
            "\u2008",  # PUNCTUATION SPACE
            "\u2009",  # THIN SPACE
            "\u200a",  # HAIR SPACE
            "\u200b",  # ZERO WIDTH SPACE
            "\u202f",  # NARROW NO-BREAK SPACE
            "\u3000",  # IDEOGRAPHIC SPACE
        ]
        choice = _rng.choice(spaces)
        return p.replace(" ", choice)

    # ── Comment insertion ─────────────────────────────────────────────────────

    @staticmethod
    def comment_sql_inline(p: str) -> str:
        """Insert /**/ between every token to break keyword detection."""
        # Target SQL keywords only
        kws = ["SELECT","FROM","WHERE","UNION","INSERT","UPDATE","DELETE",
               "DROP","TABLE","AND","OR","NOT","NULL","LIKE","IN","ORDER",
               "BY","GROUP","HAVING","LIMIT","OFFSET","JOIN","ON","AS",
               "EXEC","EXECUTE","CAST","CONVERT","CHAR","VARCHAR","SLEEP",
               "BENCHMARK","WAITFOR","DELAY","XP_","SP_","INTO","OUTFILE"]
        result = p
        for kw in kws:
            # Case-insensitive replacement
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            replacement = lambda m: m.group(0)[:2] + "/**/" + m.group(0)[2:]
            result = pattern.sub(replacement, result)
        return result

    @staticmethod
    def comment_sql_c_style(p: str) -> str:
        """Replace spaces with C-style SQL comments /**/."""
        return p.replace(" ", "/**/")

    @staticmethod
    def comment_sql_hash(p: str) -> str:
        """Append # to terminate SQL line."""
        return p + "#"

    @staticmethod
    def comment_sql_double_dash(p: str) -> str:
        """Append -- comment."""
        return p + "--"

    @staticmethod
    def comment_html(p: str) -> str:
        """Insert <!--> fragments to break keyword detection."""
        if len(p) < 3:
            return p
        mid = len(p) // 2
        return p[:mid] + "<!---->" + p[mid:]

    @staticmethod
    def comment_js_line(p: str) -> str:
        """Insert // within JS payload."""
        if len(p) < 4:
            return p
        mid = len(p) // 2
        return p[:mid] + "//\n" + p[mid:]

    @staticmethod
    def comment_js_block(p: str) -> str:
        """Insert /* */ within JS payload."""
        if len(p) < 4:
            return p
        mid = len(p) // 2
        return p[:mid] + "/**/" + p[mid:]

    # ── String concatenation ──────────────────────────────────────────────────

    @staticmethod
    def concat_sql(p: str) -> str:
        """
        Split the payload into two halves joined by CONCAT() to break
        literal string detection.
        """
        if len(p) < 2:
            return p
        mid = len(p) // 2
        a, b = p[:mid], p[mid:]
        return f"CONCAT('{a}','{b}')"

    @staticmethod
    def concat_sql_chr(p: str) -> str:
        """Express payload as CONCAT(CHR(N),CHR(N),…) — no string literals."""
        return "CONCAT(" + ",".join(f"CHR({ord(c)})" for c in p) + ")"

    @staticmethod
    def concat_js_plus(p: str) -> str:
        """JS string addition — split each char: 'a'+'l'+'e'+'r'+'t'."""
        return "+".join(f"'{c}'" for c in p)

    @staticmethod
    def concat_js_fromcharcode(p: str) -> str:
        """String.fromCharCode(72,101,108,…) — avoids all literal chars."""
        codes = ",".join(str(ord(c)) for c in p)
        return f"String.fromCharCode({codes})"

    @staticmethod
    def concat_js_atob(p: str) -> str:
        """atob('base64') to reconstruct the payload at runtime."""
        b64 = base64.b64encode(p.encode()).decode()
        return f"atob('{b64}')"

    @staticmethod
    def concat_js_template_literal(p: str) -> str:
        """Embed payload in a JS template literal with expression split."""
        if len(p) < 2:
            return f"`{p}`"
        mid = len(p) // 2
        a, b = p[:mid], p[mid:]
        return f"`{a}${{\"\"}}{b}`"

    # ── Null-byte and prefix tricks ───────────────────────────────────────────

    @staticmethod
    def null_prefix(p: str) -> str:
        return "%00" + p

    @staticmethod
    def null_suffix(p: str) -> str:
        return p + "%00"

    @staticmethod
    def null_between(p: str) -> str:
        """Null byte between every character."""
        return "\x00".join(p)

    @staticmethod
    def null_truncate(p: str) -> str:
        """Null byte to truncate server-side string processing."""
        return p + "\x00" + "A" * 8

    # ── CharCode / decimal representations ────────────────────────────────────

    @staticmethod
    def charcode_decimal_js(p: str) -> str:
        """eval(String.fromCharCode(…)) wrapping."""
        codes = ",".join(str(ord(c)) for c in p)
        return f"eval(String.fromCharCode({codes}))"

    @staticmethod
    def charcode_css(p: str) -> str:
        r"""CSS \NNNNNN notation."""
        return "".join(f"\\{ord(c):x} " for c in p)

    @staticmethod
    def charcode_python_chr(p: str) -> str:
        """Python chr() concatenation (for SSTI contexts)."""
        return "+".join(f"chr({ord(c)})" for c in p)

    @staticmethod
    def charcode_php_chr(p: str) -> str:
        """PHP chr() dot-concatenation."""
        return ".".join(f"chr({ord(c)})" for c in p)

    # ── SQL-specific ──────────────────────────────────────────────────────────

    @staticmethod
    def sql_hex_literal(p: str) -> str:
        """0x4142… hex literal without quotes."""
        return "0x" + binascii.hexlify(p.encode()).decode()

    @staticmethod
    def sql_char_function(p: str) -> str:
        """CHAR(72,101,…) — works in MySQL, MSSQL, SQLite."""
        return "CHAR(" + ",".join(str(ord(c)) for c in p) + ")"

    @staticmethod
    def sql_nchar(p: str) -> str:
        """NCHAR(N)+NCHAR(N)+… — MSSQL unicode string construction."""
        return "+".join(f"NCHAR({ord(c)})" for c in p)

    @staticmethod
    def sql_case_expression(p: str) -> str:
        """Wrap keyword in CASE expression to confuse parsers."""
        # Only useful for single-keyword payloads like UNION, SELECT
        tokens = p.split()
        result = []
        for t in tokens:
            if t.upper() in ("SELECT","UNION","FROM","WHERE","AND","OR","NOT"):
                result.append(f"CASE WHEN 1=1 THEN {t} ELSE {t} END")
            else:
                result.append(t)
        return " ".join(result)

    @staticmethod
    def sql_whitespace_variant(p: str) -> str:
        """Replace spaces with tab+newline combos."""
        ws = ["\t", "\n", "\r\n", "\t\t", " \t", "\t "]
        return re.sub(r" +", lambda m: _rng.choice(ws), p)

    # ── XML / XPath ───────────────────────────────────────────────────────────

    @staticmethod
    def xml_entity_encode(p: str) -> str:
        """XML entity encoding for <>&'"."""
        table = {"<":"&lt;",">":"&gt;","&":"&amp;","'":"&apos;",'"':"&quot;"}
        return "".join(table.get(c, c) for c in p)

    @staticmethod
    def xml_cdata(p: str) -> str:
        """Wrap in CDATA section to bypass XML text node filters."""
        return f"<![CDATA[{p}]]>"

    @staticmethod
    def xpath_string_concat(p: str) -> str:
        """XPath concat() to avoid quote usage."""
        chars = [f"'{c}'" for c in p]
        return "concat(" + ",".join(chars) + ")"

    # ── CSS ───────────────────────────────────────────────────────────────────

    @staticmethod
    def css_escape(p: str) -> str:
        r"""CSS escape: \XX hex for every non-alnum."""
        return "".join(
            f"\\{ord(c):x} " if not c.isalnum() else c
            for c in p
        )

    @staticmethod
    def css_expression(p: str) -> str:
        """IE-era CSS expression() wrapping."""
        return f"expression({p})"

    # ── JSON ──────────────────────────────────────────────────────────────────

    @staticmethod
    def json_unicode_escape(p: str) -> str:
        r"""JSON \uXXXX escape for every character."""
        return "".join(f"\\u{ord(c):04x}" for c in p)

    @staticmethod
    def json_surrogate_pair(p: str) -> str:
        r"""
        Encode characters using surrogate pairs where possible.
        Useful for bypassing parsers that don't handle surrogates correctly.
        """
        result = []
        for c in p:
            cp = ord(c)
            if cp > 0xFFFF:
                cp -= 0x10000
                high = 0xD800 | (cp >> 10)
                low  = 0xDC00 | (cp & 0x3FF)
                result.append(f"\\u{high:04x}\\u{low:04x}")
            else:
                result.append(f"\\u{cp:04x}")
        return "".join(result)

    # ── Substitution / character-swap ─────────────────────────────────────────

    @staticmethod
    def substitution_leet(p: str) -> str:
        """Leet-speak substitution for a few common chars."""
        table: Dict[str, str] = {
            "a":"@","e":"3","i":"1","o":"0","s":"$",
            "A":"@","E":"3","I":"1","O":"0","S":"$",
        }
        return "".join(table.get(c, c) for c in p)

    @staticmethod
    def substitution_html_equiv(p: str) -> str:
        """
        Replace HTML special chars with visually similar sequences that
        some parsers normalise:  ＜ → U+FF1C  ＞ → U+FF1E
        """
        table: Dict[str, str] = {
            "<":"\uff1c", ">":"\uff1e",
            '"':"\uff02", "'":"\uff07",
            "/":"\uff0f", "\\":"\uff3c",
        }
        return "".join(table.get(c, c) for c in p)

    @staticmethod
    def substitution_dot_notation(p: str) -> str:
        """Replace dots in hostnames / identifiers with %2e."""
        return p.replace(".", "%2e")

    @staticmethod
    def substitution_slash_variants(p: str) -> str:
        """Mix forward and backslash for path traversal."""
        return p.replace("/", _rng.choice(["/", "\\", "%2f", "%5c"]))

    # ── Compression / misc ────────────────────────────────────────────────────

    @staticmethod
    def zlib_base64(p: str) -> str:
        """zlib-compress then base64 — useful for binary protocol injections."""
        import zlib
        compressed = zlib.compress(p.encode("utf-8"))
        return base64.b64encode(compressed).decode()

    @staticmethod
    def rot13(p: str) -> str:
        return p.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))

    @staticmethod
    def caesar_shift(p: str, shift: int = 13) -> str:
        """Generic Caesar cipher (primarily useful for obfuscation tests)."""
        result = []
        for c in p:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def reverse(p: str) -> str:
        return p[::-1]

    @staticmethod
    def chunk_split(p: str, chunk: int = 3) -> str:
        """Split into chunks separated by zero-width non-joiner."""
        zwnj = "\u200c"
        return zwnj.join(p[i:i+chunk] for i in range(0, len(p), chunk))


# ═══════════════════════════════════════════════════════════════════════════
# 4.  Technique Registry
#     Build the canonical list of EncodingTechnique objects once at import
#     time and share them across all EncodingFramework instances.
# ═══════════════════════════════════════════════════════════════════════════

def _build_registry() -> List[EncodingTechnique]:
    """Construct and return the full list of registered techniques."""
    ALL_CTX: FrozenSet[EncodingContext] = frozenset(EncodingContext)

    def t(
        name: str,
        family: EncodingFamily,
        desc: str,
        fn: Callable[[str], str],
        layers: int = 1,
        waf: Iterable[str] = (),
        ctx: Iterable[EncodingContext] = (),
        weight: float = 0.5,
    ) -> EncodingTechnique:
        return EncodingTechnique(
            name=name, family=family, description=desc, fn=fn,
            layers=layers, waf_bypass=frozenset(waf),
            contexts=frozenset(ctx) if ctx else frozenset(),
            weight=weight,
        )

    HTML_CTX = {
        EncodingContext.HTML_TEXT, EncodingContext.HTML_ATTR_DQ,
        EncodingContext.HTML_ATTR_SQ, EncodingContext.HTML_ATTR_UNQUOTED,
    }
    JS_CTX = {
        EncodingContext.JS_STRING_DQ, EncodingContext.JS_STRING_SQ,
        EncodingContext.JS_STRING_TEMPLATE, EncodingContext.JS_IDENTIFIER,
    }
    SQL_CTX = {
        EncodingContext.SQL_STRING_SQ, EncodingContext.SQL_STRING_DQ,
        EncodingContext.SQL_NUMERIC, EncodingContext.SQL_IDENTIFIER,
    }
    URL_CTX = {
        EncodingContext.URL_PATH, EncodingContext.URL_QUERY,
        EncodingContext.URL_FRAGMENT,
    }

    return [
        # ── URL ──
        t("url_full",            EncodingFamily.URL,    "Full percent-encode every char",         _Enc.url_full,            1, ["Cloudflare","AWS WAF","ModSecurity"], URL_CTX, 0.7),
        t("url_standard",        EncodingFamily.URL,    "Standard percent-encode specials",       _Enc.url_standard,        1, ["Cloudflare"], URL_CTX, 0.9),
        t("url_double",          EncodingFamily.URL,    "Double URL encoding (%25XX)",             _Enc.url_double,          2, ["Cloudflare","AWS WAF","F5 BIG-IP ASM","Akamai"], URL_CTX, 0.85),
        t("url_partial",         EncodingFamily.URL,    "Partial URL encode (specials only)",     _Enc.url_partial,         1, [], URL_CTX, 0.6),
        t("url_lowercase",       EncodingFamily.URL,    "Lowercase hex in %xx escapes",           _Enc.url_lowercase,       1, ["ModSecurity"], URL_CTX, 0.55),
        t("url_mixed_case",      EncodingFamily.URL,    "Mixed-case hex in %xX escapes",          _Enc.url_mixed_case,      1, ["ModSecurity","Nginx WAF"], URL_CTX, 0.7),
        t("url_plus_space",      EncodingFamily.URL,    "+ for space (form encoding)",             _Enc.url_plus_space,      1, [], URL_CTX, 0.5),
        t("url_path_dot_encode", EncodingFamily.URL,    "%2e%2e%2f path traversal variant",       _Enc.url_path_traversal_encode, 1, ["AWS WAF","ModSecurity"], {EncodingContext.URL_PATH, EncodingContext.PATH_FILESYSTEM}, 0.8),

        # ── Unicode ──
        t("unicode_escape",      EncodingFamily.UNICODE, r"\uXXXX JS unicode escape (lower)",    _Enc.unicode_escape,      1, ["Cloudflare","Imperva/Incapsula"], JS_CTX, 0.85),
        t("unicode_escape_upper",EncodingFamily.UNICODE, r"\uXXXX JS unicode escape (upper)",    _Enc.unicode_escape_upper,1, ["Cloudflare"], JS_CTX, 0.8),
        t("unicode_escape_sel",  EncodingFamily.UNICODE, r"\uXXXX only for special chars",       _Enc.unicode_escape_selective, 1, ["Cloudflare"], JS_CTX, 0.75),
        t("unicode_fullwidth",   EncodingFamily.UNICODE, "Fullwidth Unicode equivalents",        _Enc.unicode_fullwidth,   1, ["ModSecurity","Wordfence"], HTML_CTX | JS_CTX, 0.7),
        t("unicode_confusable",  EncodingFamily.UNICODE, "Visually similar Unicode chars",       _Enc.unicode_confusable,  1, ["ModSecurity","Sucuri"], HTML_CTX, 0.65),
        t("utf8_overlong_slash", EncodingFamily.OVERLONG,"%c0%af overlong UTF-8 for /",          _Enc.utf8_overlong_slash, 1, ["ModSecurity","Nginx WAF","AWS WAF"], {EncodingContext.URL_PATH, EncodingContext.PATH_FILESYSTEM}, 0.8),
        t("utf8_overlong_dot",   EncodingFamily.OVERLONG,"%c0%ae overlong UTF-8 for .",          _Enc.utf8_overlong_dot,   1, ["ModSecurity"], {EncodingContext.URL_PATH, EncodingContext.PATH_FILESYSTEM}, 0.65),
        t("idn_encode",          EncodingFamily.UNICODE, "IDN / Punycode hostname encoding",     _Enc.idn_encode,          1, [], {EncodingContext.URL_PATH, EncodingContext.URL_QUERY}, 0.4),

        # ── HTML entity ──
        t("html_decimal",        EncodingFamily.HTML, "&#DDD; decimal entities all chars",       _Enc.html_entity_decimal, 1, ["ModSecurity","Sucuri","Wordfence"], HTML_CTX, 0.9),
        t("html_hex",            EncodingFamily.HTML, "&#xHH; hex entities all chars",           _Enc.html_entity_hex,     1, ["ModSecurity","Sucuri"], HTML_CTX, 0.85),
        t("html_hex_upper",      EncodingFamily.HTML, "&#xHH; hex entities uppercase",           _Enc.html_entity_hex_upper, 1, ["ModSecurity"], HTML_CTX, 0.8),
        t("html_named",          EncodingFamily.HTML, "Named + decimal HTML entities",           _Enc.html_entity_named,   1, ["Wordfence","Sucuri"], HTML_CTX, 0.75),
        t("html_selective",      EncodingFamily.HTML, "html.escape() for <>&\"'",               _Enc.html_entity_selective, 1, [], HTML_CTX, 0.6),
        t("html_padded",         EncodingFamily.HTML, "&#00060; zero-padded decimal entities",   _Enc.html_entity_padded,  1, ["ModSecurity","Akamai"], HTML_CTX, 0.7),

        # ── Base64 ──
        t("base64_std",          EncodingFamily.BASE64,"Standard base64",                        _Enc.base64_standard,     1, [], frozenset(), 0.6),
        t("base64_urlsafe",      EncodingFamily.BASE64,"URL-safe base64 (-_ instead of +/)",     _Enc.base64_urlsafe,      1, [], frozenset(), 0.55),
        t("base64_no_pad",       EncodingFamily.BASE64,"Base64 without trailing = padding",      _Enc.base64_no_padding,   1, [], frozenset(), 0.5),
        t("base64_double",       EncodingFamily.BASE64,"Double base64 (b64 of b64)",              _Enc.base64_double,       2, [], frozenset(), 0.45),
        t("base32_std",          EncodingFamily.BASE64,"Base32 standard",                        _Enc.base32_standard,     1, [], frozenset(), 0.4),
        t("base32_no_pad",       EncodingFamily.BASE64,"Base32 without padding",                 _Enc.base32_no_padding,   1, [], frozenset(), 0.35),

        # ── Hex ──
        t("hex_js_lower",        EncodingFamily.HEX,  r"\xhh JS hex escapes (lower)",           _Enc.hex_escape_js,       1, ["Cloudflare","ModSecurity"], JS_CTX, 0.85),
        t("hex_js_upper",        EncodingFamily.HEX,  r"\xHH JS hex escapes (upper)",           _Enc.hex_escape_js_upper, 1, ["Cloudflare"], JS_CTX, 0.8),
        t("hex_sql",             EncodingFamily.HEX,  "SQL 0x... hex literal",                  _Enc.hex_encode_sql,      1, ["ModSecurity","AWS WAF"], SQL_CTX, 0.85),
        t("hex_css",             EncodingFamily.HEX,  r"CSS \NNNNNN hex escapes",               _Enc.hex_encode_css,      1, ["ModSecurity"], {EncodingContext.CSS_VALUE, EncodingContext.CSS_SELECTOR}, 0.75),
        t("hex_raw",             EncodingFamily.HEX,  "Raw hex string 4142...",                 _Enc.hex_encode_raw,      1, [], frozenset(), 0.4),
        t("hex_percent_pairs",   EncodingFamily.HEX,  "%HH%HH per-byte encoding",               _Enc.hex_encode_percent_pairs, 1, ["ModSecurity"], URL_CTX, 0.7),

        # ── Octal ──
        t("octal_js",            EncodingFamily.OCTAL,r"\DDD octal JS escape",                  _Enc.octal_escape_js,     1, ["ModSecurity"], JS_CTX, 0.7),
        t("octal_bash",          EncodingFamily.OCTAL,"Bash $'\\DDD' octal",                    _Enc.octal_escape_bash,   1, ["ModSecurity"], {EncodingContext.SHELL_ARG}, 0.75),

        # ── Case ──
        t("case_upper",          EncodingFamily.CASE, "ALL UPPERCASE",                          _Enc.case_upper,          1, ["ModSecurity","Nginx WAF"], frozenset(), 0.7),
        t("case_lower",          EncodingFamily.CASE, "all lowercase",                          _Enc.case_lower,          1, [], frozenset(), 0.6),
        t("case_random",         EncodingFamily.CASE, "RaNdOm CaSe",                            _Enc.case_random,         1, ["ModSecurity","Wordfence","Sucuri"], frozenset(), 0.75),
        t("case_alternate",      EncodingFamily.CASE, "AlTeRnAtInG cAsE",                       _Enc.case_alternate,      1, ["Wordfence"], frozenset(), 0.65),

        # ── Whitespace ──
        t("ws_tab",              EncodingFamily.WHITESPACE,"Tab instead of space",              _Enc.ws_tab,              1, ["ModSecurity","Nginx WAF"], SQL_CTX | JS_CTX, 0.8),
        t("ws_newline",          EncodingFamily.WHITESPACE,"LF instead of space",               _Enc.ws_newline,          1, ["ModSecurity"], SQL_CTX, 0.75),
        t("ws_crlf",             EncodingFamily.WHITESPACE,"CRLF instead of space",             _Enc.ws_crlf,             1, ["ModSecurity"], SQL_CTX, 0.7),
        t("ws_formfeed",         EncodingFamily.WHITESPACE,"Form-feed instead of space",        _Enc.ws_formfeed,         1, ["ModSecurity"], SQL_CTX, 0.65),
        t("ws_null_byte",        EncodingFamily.NULL,  "Null byte before space",                _Enc.ws_null_byte,        1, ["ModSecurity"], SQL_CTX | URL_CTX, 0.6),
        t("ws_unicode_space",    EncodingFamily.WHITESPACE,"Unicode space variants",            _Enc.ws_unicode_space,    1, ["Cloudflare","AWS WAF"], SQL_CTX | HTML_CTX, 0.7),

        # ── SQL comment insertion ──
        t("comment_sql_inline",  EncodingFamily.COMMENT,"/**/ inside SQL keywords",             _Enc.comment_sql_inline,  1, ["ModSecurity","AWS WAF","F5 BIG-IP ASM"], SQL_CTX, 0.9),
        t("comment_sql_c",       EncodingFamily.COMMENT,"/**/ instead of spaces (SQL)",         _Enc.comment_sql_c_style, 1, ["ModSecurity","Nginx WAF"], SQL_CTX, 0.9),
        t("comment_html",        EncodingFamily.COMMENT,"<!--> fragment inside HTML payload",   _Enc.comment_html,        1, ["ModSecurity","Sucuri"], HTML_CTX, 0.75),
        t("comment_js_line",     EncodingFamily.COMMENT,"// line comment inside JS payload",    _Enc.comment_js_line,     1, ["ModSecurity"], JS_CTX, 0.7),
        t("comment_js_block",    EncodingFamily.COMMENT,"/**/ block comment inside JS",         _Enc.comment_js_block,    1, ["ModSecurity","Wordfence"], JS_CTX, 0.75),

        # ── Concatenation ──
        t("concat_sql",          EncodingFamily.CONCATENATION,"SQL CONCAT() split literal",     _Enc.concat_sql,          1, ["ModSecurity","AWS WAF"], SQL_CTX, 0.85),
        t("concat_sql_chr",      EncodingFamily.CONCATENATION,"SQL CONCAT(CHR(N),…)",           _Enc.concat_sql_chr,      1, ["ModSecurity","F5 BIG-IP ASM","Imperva/Incapsula"], SQL_CTX, 0.9),
        t("concat_js_plus",      EncodingFamily.CONCATENATION,"JS 'a'+'l'+'e'+'r'+'t' split",  _Enc.concat_js_plus,      1, ["ModSecurity","Cloudflare"], JS_CTX, 0.8),
        t("concat_js_fromchar",  EncodingFamily.CONCATENATION,"JS String.fromCharCode(N,…)",    _Enc.concat_js_fromcharcode, 1, ["Cloudflare","ModSecurity","AWS WAF","Akamai"], JS_CTX, 0.95),
        t("concat_js_atob",      EncodingFamily.CONCATENATION,"JS atob(base64) reconstruct",    _Enc.concat_js_atob,      1, ["Cloudflare","AWS WAF","Imperva/Incapsula"], JS_CTX, 0.88),
        t("concat_js_template",  EncodingFamily.CONCATENATION,"JS template literal split",      _Enc.concat_js_template_literal, 1, ["ModSecurity","Sucuri"], JS_CTX, 0.7),

        # ── Null ──
        t("null_prefix",         EncodingFamily.NULL, "%00 prefix before payload",              _Enc.null_prefix,         1, ["ModSecurity"], frozenset(), 0.6),
        t("null_suffix",         EncodingFamily.NULL, "%00 suffix after payload",               _Enc.null_suffix,         1, [], frozenset(), 0.55),
        t("null_truncate",       EncodingFamily.NULL, "Null + junk to truncate server string",  _Enc.null_truncate,       1, [], frozenset(), 0.5),

        # ── CharCode ──
        t("charcode_eval_js",    EncodingFamily.CHARCODE,"eval(String.fromCharCode(…))",        _Enc.charcode_decimal_js, 1, ["Cloudflare","AWS WAF","Akamai","Imperva/Incapsula"], JS_CTX, 0.92),
        t("charcode_css",        EncodingFamily.CHARCODE,r"CSS \NNNNNN per char",               _Enc.charcode_css,        1, ["ModSecurity"], {EncodingContext.CSS_VALUE}, 0.7),
        t("charcode_py_chr",     EncodingFamily.CHARCODE,"Python chr() concat (SSTI)",          _Enc.charcode_python_chr, 1, [], frozenset(), 0.65),
        t("charcode_php_chr",    EncodingFamily.CHARCODE,"PHP chr().chr()… concat",             _Enc.charcode_php_chr,    1, [], frozenset(), 0.65),

        # ── SQL-specific ──
        t("sql_hex",             EncodingFamily.SQL,  "SQL 0x… hex without quotes",             _Enc.sql_hex_literal,     1, ["ModSecurity","AWS WAF"], SQL_CTX, 0.88),
        t("sql_char",            EncodingFamily.SQL,  "SQL CHAR(N,N,…)",                        _Enc.sql_char_function,   1, ["ModSecurity","F5 BIG-IP ASM"], SQL_CTX, 0.88),
        t("sql_nchar",           EncodingFamily.SQL,  "MSSQL NCHAR(N)+NCHAR(N)",                _Enc.sql_nchar,           1, ["ModSecurity"], SQL_CTX, 0.8),
        t("sql_whitespace",      EncodingFamily.SQL,  "Random whitespace in SQL",               _Enc.sql_whitespace_variant, 1, ["ModSecurity","Nginx WAF"], SQL_CTX, 0.78),

        # ── XML ──
        t("xml_entity",          EncodingFamily.XML,  "XML entity encoding <>&'\"",             _Enc.xml_entity_encode,   1, [], {EncodingContext.XML_TEXT, EncodingContext.XML_ATTR}, 0.8),
        t("xml_cdata",           EncodingFamily.XML,  "CDATA section wrapping",                 _Enc.xml_cdata,           1, ["ModSecurity"], {EncodingContext.XML_TEXT}, 0.75),
        t("xpath_concat",        EncodingFamily.XML,  "XPath concat() quoting bypass",          _Enc.xpath_string_concat, 1, ["ModSecurity"], {EncodingContext.XPATH_EXPR}, 0.85),

        # ── CSS ──
        t("css_escape",          EncodingFamily.CSS,  r"CSS \hex unicode escape",               _Enc.css_escape,          1, ["ModSecurity"], {EncodingContext.CSS_VALUE, EncodingContext.CSS_SELECTOR}, 0.75),
        t("css_expression",      EncodingFamily.CSS,  "IE expression() wrapping",               _Enc.css_expression,      1, [], {EncodingContext.CSS_VALUE}, 0.5),

        # ── JSON ──
        t("json_unicode",        EncodingFamily.JSON, r"JSON \uXXXX full escape",               _Enc.json_unicode_escape, 1, ["Cloudflare","AWS WAF"], {EncodingContext.JSON_STRING, EncodingContext.JSON_KEY}, 0.8),
        t("json_surrogate",      EncodingFamily.JSON, "JSON surrogate pair encoding",           _Enc.json_surrogate_pair, 1, ["AWS WAF","Akamai"], {EncodingContext.JSON_STRING}, 0.7),

        # ── Substitution ──
        t("subst_html_equiv",    EncodingFamily.SUBSTITUTION,"Fullwidth Unicode HTML-equiv",    _Enc.substitution_html_equiv, 1, ["ModSecurity","Sucuri","Wordfence"], HTML_CTX | JS_CTX, 0.7),
        t("subst_dot_notation",  EncodingFamily.SUBSTITUTION,"Dot → %2e substitution",         _Enc.substitution_dot_notation, 1, ["ModSecurity"], URL_CTX, 0.65),
        t("subst_slash",         EncodingFamily.SUBSTITUTION,"/ ↔ \\ ↔ %2f ↔ %5c mix",        _Enc.substitution_slash_variants, 1, ["ModSecurity","AWS WAF"], {EncodingContext.URL_PATH, EncodingContext.PATH_FILESYSTEM}, 0.7),

        # ── Misc ──
        t("zlib_b64",            EncodingFamily.COMPRESSION,"zlib + base64 compression",       _Enc.zlib_base64,          1, [], frozenset(), 0.3),
        t("rot13",               EncodingFamily.MIXED, "ROT13 rotation",                        _Enc.rot13,               1, [], frozenset(), 0.3),
        t("reverse",             EncodingFamily.MIXED, "Reversed string",                       _Enc.reverse,             1, [], frozenset(), 0.2),
        t("chunk_split",         EncodingFamily.MIXED, "Zero-width non-joiner chunk split",     _Enc.chunk_split,         1, [], HTML_CTX, 0.35),
    ]


# Module-level registry — built once
TECHNIQUE_REGISTRY: List[EncodingTechnique] = _build_registry()
_REGISTRY_BY_NAME: Dict[str, EncodingTechnique] = {t.name: t for t in TECHNIQUE_REGISTRY}
_REGISTRY_BY_FAMILY: Dict[EncodingFamily, List[EncodingTechnique]] = defaultdict(list)
for _tech in TECHNIQUE_REGISTRY:
    _REGISTRY_BY_FAMILY[_tech.family].append(_tech)


# ═══════════════════════════════════════════════════════════════════════════
# 5.  Session Encoding Memory
#     Mutable per-scan state — tracks what worked and what got blocked.
# ═══════════════════════════════════════════════════════════════════════════

class SessionEncodingMemory:
    """
    Accumulates bypass / block observations across all requests in one scan.

    Thread-safety: not thread-safe by design — the caller (scan pipeline)
    is expected to access this from a single event-loop or to wrap it with
    a lock if concurrency is required.
    """

    def __init__(self) -> None:
        # waf_name → WAFProfile
        self._waf_profiles:  Dict[str, WAFProfile] = {}
        # technique_name → learned weight delta (positive = successful)
        self._weight_deltas: Dict[str, float] = defaultdict(float)
        # Set of technique names that produced a block signal at least once
        self._blocked_once:  Set[str] = set()
        # Total observations
        self.observations:   int = 0

    # -- WAF profile management ----------------------------------------------

    def get_waf_profile(self, waf_name: str) -> WAFProfile:
        if waf_name not in self._waf_profiles:
            self._waf_profiles[waf_name] = WAFProfile(waf_name)
        return self._waf_profiles[waf_name]

    def record_bypass(self, technique_name: str, waf_names: Iterable[str] = ()) -> None:
        """Record that a technique successfully bypassed all observed WAFs."""
        self.observations += 1
        self._weight_deltas[technique_name] += 0.15
        self._weight_deltas[technique_name] = min(
            self._weight_deltas[technique_name], 0.45
        )
        for waf in waf_names:
            self.get_waf_profile(waf).record_attempt(technique_name, True)

    def record_block(self, technique_name: str, waf_names: Iterable[str] = ()) -> None:
        """Record that a technique was blocked."""
        self.observations += 1
        self._blocked_once.add(technique_name)
        self._weight_deltas[technique_name] -= 0.1
        for waf in waf_names:
            self.get_waf_profile(waf).record_attempt(technique_name, False)

    def effective_weight(self, technique_name: str, base_weight: float) -> float:
        """Compute the learned weight for a technique."""
        delta = self._weight_deltas.get(technique_name, 0.0)
        result = base_weight + delta
        return max(0.01, min(1.0, result))

    def is_blocked(self, technique_name: str) -> bool:
        return technique_name in self._blocked_once

    @property
    def active_waf_names(self) -> List[str]:
        return list(self._waf_profiles.keys())

    def summary(self) -> Dict:
        return {
            "observations": self.observations,
            "waf_profiles": {
                k: {
                    "bypass_rate": round(v.bypass_rate, 3),
                    "successful":  v.successful_techniques[:5],
                    "blocked":     v.blocked_techniques[:5],
                }
                for k, v in self._waf_profiles.items()
            },
            "top_techniques": sorted(
                self._weight_deltas.items(),
                key=lambda x: x[1], reverse=True
            )[:10],
        }


# ═══════════════════════════════════════════════════════════════════════════
# 6.  LayeredEncoder
#     Chains multiple techniques in sequence.
# ═══════════════════════════════════════════════════════════════════════════

class LayeredEncoder:
    """
    Applies a sequence of encoding techniques to produce multi-layer variants.

    Example chain:  url_double → case_random
    The output of the first technique becomes the input of the second.
    """

    # Predefined chains known to be effective against specific WAFs
    KNOWN_CHAINS: Dict[str, List[str]] = {
        "cloudflare_xss": ["url_double", "unicode_escape"],
        "modsec_sqli":    ["comment_sql_c", "case_random"],
        "akamai_lfi":     ["url_double", "utf8_overlong_slash"],
        "aws_xss":        ["concat_js_fromchar", "url_standard"],
        "f5_sqli":        ["comment_sql_c", "hex_sql"],
        "imperva_xss":    ["concat_js_atob", "url_standard"],
        "generic_deep":   ["url_double", "comment_sql_c", "case_random"],
        "deep_unicode":   ["unicode_escape", "url_standard"],
        "html_js_chain":  ["html_decimal", "unicode_escape"],
        "triple_encode":  ["url_standard", "url_double", "url_full"],
    }

    def __init__(self) -> None:
        self._registry = _REGISTRY_BY_NAME

    def apply_chain(
        self,
        payload: str,
        technique_names: Sequence[str],
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> Optional[EncodedPayload]:
        """
        Apply a named sequence of techniques in order.
        Returns None if any step fails or produces no change from base.
        """
        result = payload
        applied_names: List[str] = []
        applied_families: List[EncodingFamily] = []
        total_layers = 0
        all_waf_tags: Set[str] = set()

        for name in technique_names:
            tech = self._registry.get(name)
            if tech is None:
                continue
            try:
                result = tech.apply(result)
                applied_names.append(name)
                applied_families.append(tech.family)
                total_layers += tech.layers
                all_waf_tags.update(tech.waf_bypass)
            except Exception:
                continue

        if not applied_names or result == payload:
            return None

        return EncodedPayload(
            original=payload,
            encoded=result,
            technique_names=applied_names,
            families=applied_families,
            layers=total_layers,
            context=context,
            waf_bypass_tags=sorted(all_waf_tags),
        )

    def all_chain_variants(
        self,
        payload: str,
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> List[EncodedPayload]:
        """Apply every predefined chain and return distinct results."""
        seen: Set[str] = set()
        results: List[EncodedPayload] = []
        for chain_name, names in self.KNOWN_CHAINS.items():
            ep = self.apply_chain(payload, names, context)
            if ep and ep.fingerprint not in seen:
                seen.add(ep.fingerprint)
                results.append(ep)
        return results

    def generate_combinatorial_chains(
        self,
        payload: str,
        families: Iterable[EncodingFamily],
        max_depth: int = 2,
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> Iterator[EncodedPayload]:
        """
        Yield EncodedPayloads for every combination of up to max_depth
        techniques drawn from the given families.  Deduplicates by fingerprint.
        """
        candidates: List[EncodingTechnique] = []
        for fam in families:
            candidates.extend(_REGISTRY_BY_FAMILY.get(fam, []))

        seen: Set[str] = set()
        for depth in range(1, max_depth + 1):
            for combo in itertools.combinations(candidates, depth):
                names = [c.name for c in combo]
                ep = self.apply_chain(payload, names, context)
                if ep and ep.fingerprint not in seen:
                    seen.add(ep.fingerprint)
                    yield ep


# ═══════════════════════════════════════════════════════════════════════════
# 7.  EncodingSelector
#     Pure scoring/selection logic — no side effects.
# ═══════════════════════════════════════════════════════════════════════════

class EncodingSelector:
    """
    Scores and selects from a list of EncodedPayload candidates.

    Scoring model (additive, normalised to [0, 1]):
      - Base technique weight                            (30%)
      - WAF profile match bonus                          (25%)
      - Context match bonus                              (20%)
      - Layer depth bonus (more layers = harder to block)(10%)
      - Session memory bonus (learned success)           (15%)
    """

    def __init__(self, memory: Optional[SessionEncodingMemory] = None) -> None:
        self._memory = memory

    def score(
        self,
        ep: EncodedPayload,
        waf_names: Iterable[str] = (),
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> float:
        waf_set = set(w.lower() for w in waf_names)
        total = 0.0

        # 1. Resolve all technique objects involved
        techs = [_REGISTRY_BY_NAME[n] for n in ep.technique_names if n in _REGISTRY_BY_NAME]

        if not techs:
            return 0.0

        # 2. Base weight component (average across chain)
        avg_weight = sum(t.weight for t in techs) / len(techs)
        total += avg_weight * 0.30

        # 3. WAF profile match — does this technique have a known bypass tag?
        if waf_set:
            max_waf_bonus = 0.0
            for tech in techs:
                bypass_lower = {w.lower() for w in tech.waf_bypass}
                overlap = bypass_lower & waf_set
                if overlap:
                    # WAF profile-based bonus from memory
                    if self._memory:
                        for waf in waf_set:
                            profile = self._memory._waf_profiles.get(waf)
                            if profile:
                                max_waf_bonus = max(
                                    max_waf_bonus,
                                    profile.score_technique(tech.name)
                                )
                            else:
                                max_waf_bonus = max(max_waf_bonus, 0.6)
                    else:
                        max_waf_bonus = max(max_waf_bonus, 0.6)
            total += max_waf_bonus * 0.25

        # 4. Context match bonus
        if context != EncodingContext.UNKNOWN:
            ctx_bonus = 0.0
            for tech in techs:
                if not tech.contexts or context in tech.contexts:
                    ctx_bonus = max(ctx_bonus, 0.7)
            total += ctx_bonus * 0.20

        # 5. Layer depth bonus
        layer_bonus = min(ep.layers / 3.0, 1.0)
        total += layer_bonus * 0.10

        # 6. Session memory bonus
        if self._memory:
            for tech in techs:
                if self._memory.is_blocked(tech.name):
                    return 0.0   # hard disqualify
                delta = self._memory._weight_deltas.get(tech.name, 0.0)
                total += delta * 0.15

        return min(total, 1.0)

    def select(
        self,
        candidates: List[EncodedPayload],
        strategy: SelectionStrategy,
        waf_names: Iterable[str] = (),
        context: EncodingContext = EncodingContext.UNKNOWN,
        n: int = 10,
    ) -> List[EncodedPayload]:
        """Score all candidates and return a subset based on strategy."""
        waf_list = list(waf_names)
        scored = [(ep, self.score(ep, waf_list, context)) for ep in candidates]

        # Attach score to each payload
        for ep, s in scored:
            ep.score = s

        if strategy == SelectionStrategy.ALL:
            return [ep for ep, _ in scored]

        if strategy == SelectionStrategy.BEST:
            best = max(scored, key=lambda x: x[1], default=(None, 0.0))
            return [best[0]] if best[0] else []

        if strategy == SelectionStrategy.TOP_N:
            ranked = sorted(scored, key=lambda x: x[1], reverse=True)
            return [ep for ep, _ in ranked[:n]]

        if strategy == SelectionStrategy.WAF_TUNED:
            ranked = sorted(scored, key=lambda x: x[1], reverse=True)
            # Only return those with positive WAF bypass tags
            waf_set = {w.lower() for w in waf_list}
            filtered = [
                ep for ep, s in ranked
                if s > 0.3 and any(
                    w.lower() in waf_set
                    for w in ep.waf_bypass_tags
                )
            ]
            return filtered[:n] if filtered else [ep for ep, _ in ranked[:n // 2]]

        if strategy == SelectionStrategy.RANDOM_N:
            sample = _rng.sample(candidates, min(n, len(candidates)))
            return sample

        if strategy == SelectionStrategy.LAYERED:
            multi = [ep for ep, _ in scored if ep.layers > 1]
            ranked = sorted(((ep, self.score(ep, waf_list, context)) for ep in multi),
                            key=lambda x: x[1], reverse=True)
            return [ep for ep, _ in ranked[:n]]

        return [ep for ep, _ in scored]


# ═══════════════════════════════════════════════════════════════════════════
# 8.  ContextAwareEncoder
#     Chooses which encoding families are appropriate for a given context
#     and then applies them in a context-sensitive order.
# ═══════════════════════════════════════════════════════════════════════════

class ContextAwareEncoder:
    """
    Produces encoding variants optimised for a specific injection context.

    For an XSS payload in an HTML attribute, the relevant families are
    HTML entity encoding, URL encoding, and JavaScript escaping (if the
    attribute is an event handler).  For an SQLi payload in a string
    parameter, the relevant families are SQL-specific, comment insertion,
    whitespace substitution, case manipulation, and hex encoding.

    The encoder is NOT responsible for choosing the payload — that is the
    Context-Aware Payload Framework (Part 13).  It is responsible only for
    the byte-level representation.
    """

    # Context → list of preferred technique names (ordered by priority)
    _CTX_PRIORITY: Dict[EncodingContext, List[str]] = {
        EncodingContext.HTML_TEXT: [
            "html_decimal", "html_hex", "html_named", "html_padded",
            "unicode_fullwidth", "unicode_confusable", "subst_html_equiv",
        ],
        EncodingContext.HTML_ATTR_DQ: [
            "html_decimal", "html_hex", "html_named",
            "url_standard", "url_double", "unicode_fullwidth",
        ],
        EncodingContext.HTML_ATTR_SQ: [
            "html_decimal", "html_hex", "html_padded",
            "unicode_confusable", "subst_html_equiv",
        ],
        EncodingContext.HTML_ATTR_UNQUOTED: [
            "url_full", "html_decimal", "url_mixed_case",
        ],
        EncodingContext.JS_STRING_DQ: [
            "unicode_escape", "hex_js_lower", "hex_js_upper",
            "unicode_escape_upper", "concat_js_fromchar",
            "concat_js_atob", "concat_js_plus", "charcode_eval_js",
        ],
        EncodingContext.JS_STRING_SQ: [
            "unicode_escape", "hex_js_lower", "concat_js_fromchar",
            "charcode_eval_js", "concat_js_atob",
        ],
        EncodingContext.JS_STRING_TEMPLATE: [
            "unicode_escape", "concat_js_template", "hex_js_lower",
            "charcode_eval_js",
        ],
        EncodingContext.CSS_VALUE: [
            "css_escape", "hex_css", "charcode_css", "url_standard",
        ],
        EncodingContext.URL_PATH: [
            "url_standard", "url_double", "url_lowercase", "url_mixed_case",
            "utf8_overlong_slash", "utf8_overlong_dot", "subst_slash",
            "url_path_dot_encode",
        ],
        EncodingContext.URL_QUERY: [
            "url_standard", "url_double", "url_full", "url_partial",
            "url_lowercase", "url_mixed_case", "url_plus_space",
        ],
        EncodingContext.SQL_STRING_SQ: [
            "sql_hex", "sql_char", "concat_sql_chr", "comment_sql_c",
            "comment_sql_inline", "case_random", "ws_tab", "ws_newline",
            "sql_whitespace",
        ],
        EncodingContext.SQL_STRING_DQ: [
            "sql_hex", "sql_char", "concat_sql_chr", "comment_sql_c",
            "case_random", "ws_tab",
        ],
        EncodingContext.SQL_NUMERIC: [
            "sql_hex", "comment_sql_c", "case_random", "ws_tab",
        ],
        EncodingContext.XML_TEXT: [
            "xml_entity", "html_decimal", "xml_cdata",
        ],
        EncodingContext.XML_ATTR: [
            "xml_entity", "html_decimal", "url_standard",
        ],
        EncodingContext.JSON_STRING: [
            "json_unicode", "json_surrogate", "unicode_escape",
        ],
        EncodingContext.HTTP_HEADER_VALUE: [
            "url_standard", "unicode_escape", "base64_std",
        ],
        EncodingContext.HTTP_COOKIE_VALUE: [
            "url_standard", "url_double", "base64_std", "url_plus_space",
        ],
        EncodingContext.PATH_FILESYSTEM: [
            "utf8_overlong_slash", "url_path_dot_encode", "subst_slash",
            "url_double", "unicode_fullwidth",
        ],
        EncodingContext.SHELL_ARG: [
            "octal_bash", "hex_js_lower", "base64_std",
        ],
        EncodingContext.LDAP_FILTER: [
            "url_standard", "hex_percent_pairs",
        ],
        EncodingContext.XPATH_EXPR: [
            "xpath_concat", "unicode_escape",
        ],
    }

    def __init__(self) -> None:
        self._registry = _REGISTRY_BY_NAME

    def variants_for_context(
        self,
        payload: str,
        context: EncodingContext,
        max_variants: int = 15,
    ) -> List[EncodedPayload]:
        """
        Return up to max_variants EncodedPayloads appropriate for context.
        Techniques are applied in priority order for the given context.
        """
        priority = self._CTX_PRIORITY.get(context, [])
        # Fall back to generic techniques if context not specifically mapped
        if not priority:
            priority = [t.name for t in TECHNIQUE_REGISTRY]

        seen: Set[str] = set()
        results: List[EncodedPayload] = []

        for name in priority:
            if len(results) >= max_variants:
                break
            tech = self._registry.get(name)
            if tech is None:
                continue
            try:
                encoded = tech.apply(payload)
                ep = EncodedPayload(
                    original=payload,
                    encoded=encoded,
                    technique_names=[name],
                    families=[tech.family],
                    layers=tech.layers,
                    context=context,
                    waf_bypass_tags=sorted(tech.waf_bypass),
                    score=tech.weight,
                )
                if ep.changed and ep.fingerprint not in seen:
                    seen.add(ep.fingerprint)
                    results.append(ep)
            except Exception:
                continue

        return results

    def all_techniques_for_context(
        self,
        context: EncodingContext,
    ) -> List[EncodingTechnique]:
        """Return every technique applicable to this context."""
        return [
            t for t in TECHNIQUE_REGISTRY
            if not t.contexts or context in t.contexts
        ]


# ═══════════════════════════════════════════════════════════════════════════
# 9.  EncodingReporter
#     Produces structured summaries for the Evidence Collection Framework.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EncodingDecision:
    """Record of which encoding was selected for a specific request."""
    payload_original:   str
    payload_encoded:    str
    techniques_applied: List[str]
    context:            EncodingContext
    waf_names:          List[str]
    strategy_used:      SelectionStrategy
    score:              float
    rationale:          str


class EncodingReporter:
    """
    Accumulates EncodingDecision records and produces structured summaries.
    Consumed by the Evidence Collection Framework.
    """

    def __init__(self) -> None:
        self._decisions: List[EncodingDecision] = []

    def record(self, decision: EncodingDecision) -> None:
        self._decisions.append(decision)

    def summary(self) -> Dict:
        if not self._decisions:
            return {"total": 0, "technique_usage": {}, "context_breakdown": {}}

        technique_counts: Dict[str, int] = defaultdict(int)
        context_counts:   Dict[str, int] = defaultdict(int)

        for d in self._decisions:
            for t in d.techniques_applied:
                technique_counts[t] += 1
            context_counts[d.context.value] += 1

        top_techs = sorted(
            technique_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return {
            "total":            len(self._decisions),
            "top_techniques":   dict(top_techs),
            "context_breakdown": dict(context_counts),
            "avg_score":        round(
                sum(d.score for d in self._decisions) / len(self._decisions), 4
            ),
        }

    def decisions_for_context(self, context: EncodingContext) -> List[EncodingDecision]:
        return [d for d in self._decisions if d.context == context]


# ═══════════════════════════════════════════════════════════════════════════
# 10.  EncodingFramework  (main public API)
# ═══════════════════════════════════════════════════════════════════════════

class EncodingFramework:
    """
    Top-level orchestrator for payload encoding.

    Typical usage
    -------------
    ::

        framework = EncodingFramework()

        # Simple: get all variants of a payload
        variants = framework.all_variants("<script>alert(1)</script>")

        # Context-aware: variants suitable for HTML attribute injection
        attr_variants = framework.variants_for_context(
            "<script>alert(1)</script>",
            EncodingContext.HTML_ATTR_DQ,
        )

        # WAF-tuned: best variants for a Cloudflare-protected target
        best = framework.select_best(
            "<script>alert(1)</script>",
            waf_names=["Cloudflare"],
            context=EncodingContext.JS_STRING_DQ,
        )

        # Learn from scan results
        framework.record_bypass("unicode_escape", waf_names=["Cloudflare"])
        framework.record_block("url_standard", waf_names=["Cloudflare"])

        # Get top-N for a scan request
        top10 = framework.top_n(
            "' OR 1=1--",
            n=10,
            context=EncodingContext.SQL_STRING_SQ,
            waf_names=["ModSecurity"],
        )
    """

    def __init__(
        self,
        memory: Optional[SessionEncodingMemory] = None,
    ) -> None:
        self._memory    = memory or SessionEncodingMemory()
        self._selector  = EncodingSelector(self._memory)
        self._ctx_enc   = ContextAwareEncoder()
        self._layered   = LayeredEncoder()
        self._reporter  = EncodingReporter()

    # -- Public API ----------------------------------------------------------

    def all_variants(
        self,
        payload: str,
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> List[EncodedPayload]:
        """
        Produce every single-technique variant plus all known chain variants.
        Returns a deduplicated list sorted by score descending.
        """
        seen: Set[str] = set()
        results: List[EncodedPayload] = []

        # Single-technique variants
        for tech in TECHNIQUE_REGISTRY:
            try:
                encoded = tech.apply(payload)
                ep = EncodedPayload(
                    original=payload,
                    encoded=encoded,
                    technique_names=[tech.name],
                    families=[tech.family],
                    layers=tech.layers,
                    context=context,
                    waf_bypass_tags=sorted(tech.waf_bypass),
                )
                if ep.changed and ep.fingerprint not in seen:
                    seen.add(ep.fingerprint)
                    results.append(ep)
            except Exception:
                continue

        # Chain variants
        for ep in self._layered.all_chain_variants(payload, context):
            if ep.fingerprint not in seen:
                seen.add(ep.fingerprint)
                results.append(ep)

        return results

    def variants_for_context(
        self,
        payload: str,
        context: EncodingContext,
        max_variants: int = 20,
    ) -> List[EncodedPayload]:
        """Return context-prioritised variants."""
        single = self._ctx_enc.variants_for_context(payload, context, max_variants)
        chain  = self._layered.all_chain_variants(payload, context)

        seen: Set[str] = set()
        combined: List[EncodedPayload] = []
        for ep in single + chain:
            if ep.fingerprint not in seen:
                seen.add(ep.fingerprint)
                combined.append(ep)

        return combined[:max_variants]

    def select_best(
        self,
        payload: str,
        waf_names: Iterable[str] = (),
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> Optional[EncodedPayload]:
        """
        Select the single best encoding variant for the current environment.
        Returns None only if no technique changes the payload at all.
        """
        candidates = self.all_variants(payload, context)
        selected   = self._selector.select(
            candidates, SelectionStrategy.BEST, waf_names, context
        )
        result = selected[0] if selected else None
        if result:
            self._record_decision(payload, result, waf_names, SelectionStrategy.BEST)
        return result

    def top_n(
        self,
        payload: str,
        n: int = 10,
        context: EncodingContext = EncodingContext.UNKNOWN,
        waf_names: Iterable[str] = (),
        strategy: SelectionStrategy = SelectionStrategy.TOP_N,
    ) -> List[EncodedPayload]:
        """Return the top-N scoring variants."""
        if context != EncodingContext.UNKNOWN:
            candidates = self.variants_for_context(payload, context, max_variants=60)
        else:
            candidates = self.all_variants(payload, context)

        selected = self._selector.select(
            candidates, strategy, waf_names, context, n
        )
        for ep in selected:
            self._record_decision(payload, ep, waf_names, strategy)
        return selected

    def waf_tuned_variants(
        self,
        payload: str,
        waf_names: Iterable[str],
        context: EncodingContext = EncodingContext.UNKNOWN,
        n: int = 15,
    ) -> List[EncodedPayload]:
        """
        Return variants specifically tuned to bypass the given WAFs.
        Prefers techniques with known bypass tags matching the detected WAFs,
        weighted further by session memory.
        """
        waf_list = list(waf_names)
        candidates = self.all_variants(payload, context)
        return self._selector.select(
            candidates, SelectionStrategy.WAF_TUNED, waf_list, context, n
        )

    def layered_variants(
        self,
        payload: str,
        context: EncodingContext = EncodingContext.UNKNOWN,
        n: int = 10,
    ) -> List[EncodedPayload]:
        """Return only multi-layer chained variants."""
        chains = self._layered.all_chain_variants(payload, context)
        return self._selector.select(
            chains, SelectionStrategy.TOP_N, [], context, n
        )

    def encode_with_technique(
        self,
        payload: str,
        technique_name: str,
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> Optional[EncodedPayload]:
        """Apply a specific named technique directly."""
        tech = _REGISTRY_BY_NAME.get(technique_name)
        if not tech:
            return None
        try:
            encoded = tech.apply(payload)
            return EncodedPayload(
                original=payload,
                encoded=encoded,
                technique_names=[technique_name],
                families=[tech.family],
                layers=tech.layers,
                context=context,
                waf_bypass_tags=sorted(tech.waf_bypass),
                score=tech.weight,
            )
        except Exception:
            return None

    def encode_chain(
        self,
        payload: str,
        technique_names: Sequence[str],
        context: EncodingContext = EncodingContext.UNKNOWN,
    ) -> Optional[EncodedPayload]:
        """Apply a chain of named techniques in sequence."""
        return self._layered.apply_chain(payload, technique_names, context)

    # -- Learning API --------------------------------------------------------

    def record_bypass(
        self,
        technique_name: str,
        waf_names: Iterable[str] = (),
    ) -> None:
        """Signal that a technique successfully bypassed WAF detection."""
        self._memory.record_bypass(technique_name, waf_names)

    def record_block(
        self,
        technique_name: str,
        waf_names: Iterable[str] = (),
    ) -> None:
        """Signal that a technique was blocked."""
        self._memory.record_block(technique_name, waf_names)

    # -- Introspection -------------------------------------------------------

    @property
    def technique_count(self) -> int:
        return len(TECHNIQUE_REGISTRY)

    @property
    def family_names(self) -> List[str]:
        return [f.value for f in EncodingFamily]

    def techniques_by_family(
        self, family: EncodingFamily
    ) -> List[EncodingTechnique]:
        return list(_REGISTRY_BY_FAMILY.get(family, []))

    def techniques_for_waf(self, waf_name: str) -> List[EncodingTechnique]:
        waf_lower = waf_name.lower()
        return [
            t for t in TECHNIQUE_REGISTRY
            if any(w.lower() == waf_lower for w in t.waf_bypass)
        ]

    def session_summary(self) -> Dict:
        return self._memory.summary()

    def report_summary(self) -> Dict:
        return self._reporter.summary()

    @staticmethod
    def available_techniques() -> List[Dict]:
        """Return all registered techniques as serialisable dicts."""
        return [
            {
                "name":        t.name,
                "family":      t.family.value,
                "description": t.description,
                "layers":      t.layers,
                "waf_bypass":  sorted(t.waf_bypass),
                "weight":      t.weight,
            }
            for t in TECHNIQUE_REGISTRY
        ]

    # -- Private helpers -----------------------------------------------------

    def _record_decision(
        self,
        original: str,
        ep: EncodedPayload,
        waf_names: Iterable[str],
        strategy: SelectionStrategy,
    ) -> None:
        waf_list = list(waf_names)
        rationale = self._build_rationale(ep, waf_list)
        self._reporter.record(EncodingDecision(
            payload_original=original,
            payload_encoded=ep.encoded,
            techniques_applied=ep.technique_names,
            context=ep.context,
            waf_names=waf_list,
            strategy_used=strategy,
            score=ep.score,
            rationale=rationale,
        ))

    @staticmethod
    def _build_rationale(ep: EncodedPayload, waf_names: List[str]) -> str:
        parts = [f"Techniques: {', '.join(ep.technique_names)}"]
        if ep.waf_bypass_tags:
            parts.append(f"Known WAF bypass: {', '.join(ep.waf_bypass_tags)}")
        if waf_names:
            parts.append(f"Detected WAFs: {', '.join(waf_names)}")
        parts.append(f"Layers: {ep.layers}")
        parts.append(f"Score: {ep.score:.3f}")
        return " | ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# 11.  Convenience helpers (module-level)
# ═══════════════════════════════════════════════════════════════════════════

def quick_encode(
    payload: str,
    context: EncodingContext = EncodingContext.UNKNOWN,
    waf_names: Iterable[str] = (),
    n: int = 5,
) -> List[EncodedPayload]:
    """
    Module-level helper for one-shot encoding without managing an instance.

    ::

        from webshield.recon.encoding_framework import quick_encode, EncodingContext
        variants = quick_encode("' OR 1=1--", EncodingContext.SQL_STRING_SQ, ["ModSecurity"])
    """
    fw = EncodingFramework()
    return fw.top_n(payload, n=n, context=context, waf_names=waf_names)


def best_encode(
    payload: str,
    context: EncodingContext = EncodingContext.UNKNOWN,
    waf_names: Iterable[str] = (),
) -> Optional[EncodedPayload]:
    """Return the single best encoding for a payload."""
    return EncodingFramework().select_best(payload, waf_names, context)


def list_techniques() -> None:
    """Print a formatted table of all registered encoding techniques."""
    header = f"{'Name':<30} {'Family':<16} {'Layers':>6}  {'Weight':>6}  Description"
    print(header)
    print("-" * len(header))
    for t in TECHNIQUE_REGISTRY:
        print(
            f"{t.name:<30} {t.family.value:<16} {t.layers:>6}  {t.weight:>6.2f}  {t.description}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 12.  Public re-exports
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Enums
    "EncodingFamily",
    "EncodingContext",
    "SelectionStrategy",
    # Data-classes
    "EncodingTechnique",
    "EncodedPayload",
    "WAFProfile",
    "EncodingDecision",
    # Core classes
    "EncodingFramework",
    "EncodingSelector",
    "LayeredEncoder",
    "ContextAwareEncoder",
    "SessionEncodingMemory",
    "EncodingReporter",
    # Registry access
    "TECHNIQUE_REGISTRY",
    # Convenience
    "quick_encode",
    "best_encode",
    "list_techniques",
]
