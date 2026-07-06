# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Parameter Intelligence Engine — Part 13 of the Intelligence Layer.

Every parameter encountered during the discovery phase — whether sourced from
URL query strings, POST bodies, JSON payloads, XML documents, HTTP headers,
cookies, GraphQL variables, multipart form fields, or WebSocket messages — is
analysed by this engine before any scanner fires a single request.

The engine answers five questions for each parameter:

  1. *What data type does it carry?*
         Number · String · Boolean · JSON · XML · Base64 · UUID · JWT ·
         Path · Date/Time · Email · IP address · URL · Enum · Array ·
         Binary · Unknown

  2. *Where does it live?*
         Query string · Request body (form / JSON / XML / multipart) ·
         HTTP header · Cookie · Path segment · GraphQL variable ·
         WebSocket message field

  3. *How important is it?*
         A numeric importance score (0–100) based on name semantics,
         data type, position, and security-relevant patterns.

  4. *What is its effect on the application?*
         Database query parameter · File path parameter · Template variable ·
         Redirect destination · Authentication token · Authorisation control ·
         Search/filter input · Configuration toggle · Price/quantity ·
         Identifier (user / object) · Callback URL · Format selector

  5. *Which scanners should test it, and with what priority?*
         The engine produces an ordered list of scanner recommendations with
         a rationale for each, so that scanners can target parameters that are
         most likely to be vulnerable.

Analysis pipeline
-----------------
Stage 1 — Name Analysis
    The parameter name is matched against a comprehensive lexicon of
    security-relevant patterns (several hundred regex rules) to classify its
    probable purpose and produce initial type hints.

Stage 2 — Value Analysis
    If a sample value is available it is inspected with format-detection
    heuristics: JWT structure (three base64url segments), UUID format, numeric
    ranges, boolean literals, path separators, XML/JSON structure, encoded
    payloads, dates, and more.

Stage 3 — Context Analysis
    The parameter's position (header, cookie, body, path, GraphQL, WS) and the
    HTTP method used to transmit it produce context-specific risk adjustments.
    Parameters in GET requests that affect database queries are treated
    differently from the same parameter in a DELETE body.

Stage 4 — Cross-Parameter Correlation
    Parameters from the same endpoint are analysed together.  The presence of
    `user_id` and `token` on the same endpoint signals an authentication flow;
    `from` + `to` + `amount` signals a financial transaction; `template` +
    `engine` signals SSTI potential.  These multi-parameter signals are stored
    as ``ParameterGroup`` objects on the report.

Stage 5 — Encoding Detection
    If the raw value appears encoded (URL, double-URL, HTML entity, Base64,
    hex, Unicode escape) the engine records the encoding chain so that scanners
    can wrap their payloads in the same sequence.

Stage 6 — Confidence Scoring
    Every inference is annotated with a confidence level (0.0–1.0) derived
    from the number of corroborating signals.  Low-confidence inferences are
    preserved but flagged so that scanners can tune their aggressiveness
    accordingly.

Output
------
Each ``AnalysedParameter`` carries:

  • The raw parameter specification (name, source, sample value)
  • A ``DataType`` enum value and confidence
  • A ``ParameterSource`` enum value
  • A float ``importance_score`` in [0.0, 100.0]
  • A frozenset of ``ParameterEffect`` values
  • A list of ``EncodingLayer`` values (innermost first)
  • An ordered list of ``ScannerRecommendation`` objects
  • A ``ParameterEvidence`` record with full reasoning

The ``ParameterIntelligenceReport`` aggregates all analysed parameters,
cross-parameter groups, encoding maps, and global statistics for the scan target.
"""

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Imports                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

# ═══════════════════════════════════════════════════════════════════════════
# Public re-exports
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Enumerations
    "DataType",
    "ParameterSource",
    "ParameterEffect",
    "EncodingLayer",
    "ScannerPriority",
    # Data containers
    "RawParameter",
    "AnalysedParameter",
    "ParameterEvidence",
    "EncodingChain",
    "ScannerRecommendation",
    "ParameterGroup",
    "ParameterIntelligenceReport",
    # Engine
    "ParameterIntelligenceEngine",
    # Convenience
    "analyse_parameters",
]

# ═══════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════


class DataType(Enum):
    """Inferred data type of a parameter's value."""

    NUMBER = "number"
    FLOAT = "float"
    BOOLEAN = "boolean"
    STRING = "string"
    JSON = "json"
    XML = "xml"
    BASE64 = "base64"
    UUID = "uuid"
    JWT = "jwt"
    PATH = "path"
    DATE_TIME = "datetime"
    EMAIL = "email"
    IP_ADDRESS = "ip_address"
    URL = "url"
    ENUM = "enum"  # Small set of known constants
    ARRAY = "array"
    BINARY = "binary"
    MULTIPART = "multipart"
    GRAPHQL_VARIABLE = "graphql_variable"
    WEBSOCKET_FIELD = "websocket_field"
    UNKNOWN = "unknown"


class ParameterSource(Enum):
    """Where in the HTTP request the parameter resides."""

    QUERY_STRING = "query_string"
    FORM_BODY = "form_body"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    MULTIPART_BODY = "multipart_body"
    HTTP_HEADER = "http_header"
    COOKIE = "cookie"
    PATH_SEGMENT = "path_segment"
    GRAPHQL_VARIABLE = "graphql_variable"
    GRAPHQL_INLINE = "graphql_inline"
    WEBSOCKET_MESSAGE = "websocket_message"
    UNKNOWN = "unknown"


class ParameterEffect(Enum):
    """Probable application-level effect of the parameter."""

    DATABASE_QUERY = "database_query"          # SQLi, NoSQLi, ORM injection
    FILE_PATH = "file_path"                    # Path traversal, LFI, RFI
    TEMPLATE_VARIABLE = "template_variable"   # SSTI
    REDIRECT_DESTINATION = "redirect_dest"    # Open Redirect
    AUTH_TOKEN = "auth_token"                 # JWT, session token
    AUTH_CREDENTIAL = "auth_credential"       # username, password
    AUTHZ_CONTROL = "authz_control"           # role, permission, admin flag
    OBJECT_IDENTIFIER = "object_id"           # IDOR, BOLA
    USER_IDENTIFIER = "user_id"              # IDOR targeting users
    SEARCH_FILTER = "search_filter"           # SQLi, NoSQLi, search injection
    CONFIG_TOGGLE = "config_toggle"           # Feature flags, modes
    CALLBACK_URL = "callback_url"             # SSRF, open redirect
    PRICE_QUANTITY = "price_quantity"         # Business logic
    FORMAT_SELECTOR = "format_selector"       # XXE, SSTI via template name
    COMMAND_ARGUMENT = "command_argument"     # CMDi
    DESERIALIZATION = "deserialization"       # Java/PHP/Python deser
    REGEX_INPUT = "regex_input"               # ReDoS
    XML_CONTENT = "xml_content"              # XXE
    HTML_CONTENT = "html_content"            # XSS, HTML injection
    EMAIL_ADDRESS = "email_address"           # Email header injection
    LDAP_FILTER = "ldap_filter"              # LDAP injection
    XPATH_QUERY = "xpath_query"              # XPath injection
    GRAPHQL_QUERY = "graphql_query"          # GraphQL injection
    WEBSOCKET_CHANNEL = "ws_channel"         # WebSocket hijacking
    FINANCIAL_DATA = "financial_data"        # Business logic
    TIMING_CONTROL = "timing_control"        # Race condition
    PAGINATION = "pagination"               # Information disclosure
    ORDERING = "ordering"                    # SQLi via ORDER BY
    UNKNOWN = "unknown"


class EncodingLayer(Enum):
    """Single encoding applied to a parameter value (innermost first in chain)."""

    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    HTML_ENTITY = "html_entity"
    BASE64 = "base64"
    BASE64_URL = "base64_url"
    HEX_ENCODE = "hex_encode"
    UNICODE_ESCAPE = "unicode_escape"
    JSON_STRING = "json_string"
    JWT_PAYLOAD = "jwt_payload"
    GZIP_BASE64 = "gzip_base64"
    ROT13 = "rot13"
    NONE = "none"


class ScannerPriority(Enum):
    """Recommended priority for a scanner targeting a specific parameter."""

    CRITICAL = 1   # Near-certain vulnerability class — test first
    HIGH = 2       # Strong signal — very likely relevant
    MEDIUM = 3     # Moderate signal — worth testing
    LOW = 4        # Weak signal — test if time permits
    SKIP = 5       # Not applicable


# ═══════════════════════════════════════════════════════════════════════════
# Core data containers
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class RawParameter:
    """
    Raw parameter as discovered during reconnaissance.

    Attributes
    ----------
    name:
        Parameter name exactly as seen in the request.
    source:
        Where in the request the parameter was found.
    sample_value:
        A representative value observed during reconnaissance (may be None).
    endpoint_url:
        The URL of the endpoint that contains this parameter.
    http_method:
        HTTP method used (GET, POST, PUT, …).
    content_type:
        Content-Type of the request body (if source is a body parameter).
    extra:
        Arbitrary key-value pairs from the discovery engine.
    """

    name: str
    source: ParameterSource
    sample_value: Optional[str] = None
    endpoint_url: str = ""
    http_method: str = "GET"
    content_type: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    # Computed on access
    @property
    def fingerprint(self) -> str:
        """Stable identifier for de-duplication."""
        return hashlib.sha256(
            f"{self.endpoint_url}|{self.http_method}|{self.source.value}|{self.name}".encode()
        ).hexdigest()[:16]


@dataclass
class EncodingChain:
    """
    Ordered sequence of encoding layers detected on a parameter value.

    The layers are listed from *innermost* (applied first) to *outermost*
    (applied last / visible in the raw HTTP request).  To produce a test
    payload for this parameter, apply the same layers in the same order.
    """

    layers: List[EncodingLayer] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def is_encoded(self) -> bool:
        return bool(self.layers) and self.layers != [EncodingLayer.NONE]

    def apply_to(self, payload: str) -> str:
        """Wrap *payload* in the detected encoding chain."""
        result = payload
        for layer in self.layers:
            result = _apply_encoding(result, layer)
        return result


@dataclass
class ScannerRecommendation:
    """Recommendation for a specific scanner to test this parameter."""

    scanner_name: str
    priority: ScannerPriority
    rationale: str
    suggested_payloads: List[str] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class ParameterEvidence:
    """Full reasoning chain for every inference made about a parameter."""

    name_signals: List[str] = field(default_factory=list)
    value_signals: List[str] = field(default_factory=list)
    context_signals: List[str] = field(default_factory=list)
    correlation_signals: List[str] = field(default_factory=list)
    encoding_signals: List[str] = field(default_factory=list)
    data_type_confidence: float = 0.0
    effect_confidences: Dict[str, float] = field(default_factory=dict)
    importance_breakdown: Dict[str, float] = field(default_factory=dict)
    analysis_duration_ms: float = 0.0


@dataclass
class AnalysedParameter:
    """
    Fully analysed parameter ready to be consumed by scanner modules.

    Attributes
    ----------
    raw:
        The original ``RawParameter`` input.
    data_type:
        Inferred data type of the parameter's value.
    data_type_confidence:
        Confidence in the data_type inference (0.0–1.0).
    effects:
        Set of probable application-level effects.
    encoding_chain:
        Detected encoding layers (empty if unencoded).
    importance_score:
        Numeric importance score in [0.0, 100.0].
    scanner_recommendations:
        Priority-ordered scanner recommendations.
    evidence:
        Full reasoning record.
    decoded_sample:
        The sample value after stripping all detected encoding layers.
    inferred_enum_values:
        If data_type is ENUM, the known valid values observed.
    is_reflected:
        True if this parameter's value was observed in prior responses.
    affects_multiple_endpoints:
        True if the same parameter name appears on multiple endpoints
        (e.g., a global ``lang`` or ``format`` parameter).
    """

    raw: RawParameter
    data_type: DataType = DataType.UNKNOWN
    data_type_confidence: float = 0.0
    effects: FrozenSet[ParameterEffect] = field(default_factory=frozenset)
    encoding_chain: EncodingChain = field(default_factory=EncodingChain)
    importance_score: float = 0.0
    scanner_recommendations: List[ScannerRecommendation] = field(default_factory=list)
    evidence: ParameterEvidence = field(default_factory=ParameterEvidence)
    decoded_sample: Optional[str] = None
    inferred_enum_values: List[str] = field(default_factory=list)
    is_reflected: bool = False
    affects_multiple_endpoints: bool = False

    # ── Convenience accessors ──────────────────────────────────────────────

    @property
    def name(self) -> str:
        return self.raw.name

    @property
    def source(self) -> ParameterSource:
        return self.raw.source

    @property
    def sample_value(self) -> Optional[str]:
        return self.raw.sample_value

    @property
    def endpoint_url(self) -> str:
        return self.raw.endpoint_url

    @property
    def top_scanner(self) -> Optional[str]:
        """Name of the highest-priority recommended scanner."""
        if self.scanner_recommendations:
            return self.scanner_recommendations[0].scanner_name
        return None

    def has_effect(self, effect: ParameterEffect) -> bool:
        return effect in self.effects

    def scanner_priority(self, scanner_name: str) -> Optional[ScannerPriority]:
        for rec in self.scanner_recommendations:
            if rec.scanner_name == scanner_name:
                return rec.priority
        return None


@dataclass
class ParameterGroup:
    """
    A semantically coherent group of parameters on the same endpoint that
    collectively point to a specific attack scenario.

    Examples
    --------
    • {user_id, token}          → authentication flow (IDOR + token bypass)
    • {from, to, amount}        → financial transaction (business logic)
    • {template, engine}        → SSTI via template name injection
    • {redirect_url, next}      → open redirect chain
    • {file, path, dir}         → path traversal cluster
    """

    group_name: str
    endpoint_url: str
    parameter_names: List[str]
    scenario: str
    risk_level: str   # "critical" | "high" | "medium" | "low"
    scanner_names: List[str]
    confidence: float
    description: str = ""


@dataclass
class ParameterIntelligenceReport:
    """
    Aggregate result of the Parameter Intelligence Engine for one scan.

    Attributes
    ----------
    parameters:
        All analysed parameters, one per unique (endpoint, source, name).
    groups:
        Cross-parameter groups signalling specific attack scenarios.
    encoding_map:
        Maps parameter fingerprints to their detected encoding chains.
    global_stats:
        Summary statistics (counts by type, source, effect).
    high_value_parameters:
        Subset of parameters with importance_score ≥ 70.
    scan_target_url:
        The root URL of the scan target.
    analysis_duration_seconds:
        Total wall-clock time for the analysis phase.
    """

    parameters: List[AnalysedParameter] = field(default_factory=list)
    groups: List[ParameterGroup] = field(default_factory=list)
    encoding_map: Dict[str, EncodingChain] = field(default_factory=dict)
    global_stats: Dict[str, Any] = field(default_factory=dict)
    high_value_parameters: List[AnalysedParameter] = field(default_factory=list)
    scan_target_url: str = ""
    analysis_duration_seconds: float = 0.0

    # ── Accessors ──────────────────────────────────────────────────────────

    def by_endpoint(self, url: str) -> List[AnalysedParameter]:
        return [p for p in self.parameters if p.endpoint_url == url]

    def by_effect(self, effect: ParameterEffect) -> List[AnalysedParameter]:
        return [p for p in self.parameters if p.has_effect(effect)]

    def for_scanner(
        self, scanner_name: str, min_priority: ScannerPriority = ScannerPriority.LOW
    ) -> List[AnalysedParameter]:
        results = []
        for p in self.parameters:
            prio = p.scanner_priority(scanner_name)
            if prio is not None and prio.value <= min_priority.value:
                results.append(p)
        return sorted(results, key=lambda x: x.importance_score, reverse=True)

    def top_n(self, n: int = 20) -> List[AnalysedParameter]:
        return sorted(self.parameters, key=lambda x: x.importance_score, reverse=True)[:n]


# ═══════════════════════════════════════════════════════════════════════════
# Internal pattern libraries
# ═══════════════════════════════════════════════════════════════════════════

# ── Name → (effect, base_importance) mapping rules ────────────────────────

_NAME_RULES: List[Tuple[re.Pattern, ParameterEffect, float, DataType, str]] = []

def _nr(
    pattern: str,
    effect: ParameterEffect,
    importance: float,
    dtype: DataType = DataType.UNKNOWN,
    rationale: str = "",
) -> None:
    _NAME_RULES.append(
        (re.compile(pattern, re.IGNORECASE), effect, importance, dtype, rationale)
    )

# Database query parameters
_nr(r"\bq\b|^query$|^search$|^find$|^lookup$|^filter$|^where$|^keyword$|^kw$",
    ParameterEffect.DATABASE_QUERY, 80, DataType.STRING,
    "Common search/query parameter — high SQLi/NoSQLi potential")
_nr(r"^(sql|query|statement|stmt|expression|expr)$",
    ParameterEffect.DATABASE_QUERY, 95, DataType.STRING,
    "Explicit SQL/query parameter name — near-certain injection risk")
_nr(r"\bsort\b|\border\b|\border_by\b|\bsortby\b|\bcolumn\b|\bfield\b",
    ParameterEffect.ORDERING, 70, DataType.STRING,
    "Ordering/sorting parameter — ORDER BY injection possible")
_nr(r"\blimit\b|\bcount\b|\bper_page\b|\bpage_size\b|\boffset\b|\bskip\b|\bstart\b",
    ParameterEffect.PAGINATION, 50, DataType.NUMBER,
    "Pagination parameter — integer injection / disclosure risk")
_nr(r"\bcat(egory)?\b|\btype\b|\bkind\b|\bclass\b|\bgroup\b|\bsection\b|\btag\b",
    ParameterEffect.DATABASE_QUERY, 65, DataType.STRING,
    "Category/filter parameter — database query parameter")
_nr(r"\byear\b|\bmonth\b|\bdate\b|\btime\b|\bperiod\b|\brange\b|\bfrom\b|\bto\b",
    ParameterEffect.DATABASE_QUERY, 55, DataType.DATE_TIME,
    "Temporal filter — date-based injection possible")

# File path parameters
_nr(r"^(file|path|filepath|filename|fname|dir|directory|folder|location|src|source)$",
    ParameterEffect.FILE_PATH, 95, DataType.PATH,
    "Explicit file path parameter — path traversal / LFI critical")
_nr(r"\bfile\b|\bpath\b|\bdir\b|\bfolder\b|\blocal\b",
    ParameterEffect.FILE_PATH, 85, DataType.PATH,
    "File/path parameter — path traversal likely")
_nr(r"^(include|require|import|load|read|fetch|get_file)$",
    ParameterEffect.FILE_PATH, 90, DataType.PATH,
    "File inclusion parameter — LFI/RFI critical")
_nr(r"\btemplate\b|\bview\b|\bpartial\b|\blayout\b|\bpage\b|\bmodule\b",
    ParameterEffect.TEMPLATE_VARIABLE, 85, DataType.STRING,
    "Template/view parameter — SSTI and path traversal possible")
_nr(r"\btheme\b|\bskin\b|\bstyle\b|\bcss\b|\bfont\b",
    ParameterEffect.FILE_PATH, 60, DataType.STRING,
    "Theme/skin parameter — path traversal via theme name")

# Open redirect parameters
_nr(r"^(url|redirect|redirect_to|return|returnurl|return_url|next|goto|"
    r"forward|target|dest|destination|redir|continue|back|ref|referer|origin)$",
    ParameterEffect.REDIRECT_DESTINATION, 95, DataType.URL,
    "Explicit redirect/URL parameter — open redirect critical")
_nr(r"\bredirect\b|\breturn\b|\bnext\b|\bgoto\b|\bdest\b",
    ParameterEffect.REDIRECT_DESTINATION, 80, DataType.URL,
    "Redirect-related parameter — open redirect likely")
_nr(r"\bcallback\b|\bhook\b|\bwebhook\b|\bnotify\b|\bping\b",
    ParameterEffect.CALLBACK_URL, 90, DataType.URL,
    "Callback URL parameter — SSRF potential")

# Authentication parameters
_nr(r"^(token|access_token|auth_token|api_key|apikey|secret|bearer|"
    r"session|sessionid|sess_id|auth|authorization|x_auth_token)$",
    ParameterEffect.AUTH_TOKEN, 90, DataType.STRING,
    "Authentication token parameter — session hijacking, token manipulation")
_nr(r"^(password|passwd|pass|pwd|passphrase|pin|secret_key)$",
    ParameterEffect.AUTH_CREDENTIAL, 95, DataType.STRING,
    "Password/credential parameter — credential exposure risk")
_nr(r"^(username|user|login|email|uname|account|handle|nickname)$",
    ParameterEffect.AUTH_CREDENTIAL, 80, DataType.STRING,
    "Username/email parameter — authentication bypass risk")
_nr(r"^(jwt|token|bearer|refresh_token|id_token|access_token)$",
    ParameterEffect.AUTH_TOKEN, 90, DataType.JWT,
    "JWT parameter — algorithm confusion, signature bypass")

# Authorisation parameters
_nr(r"^(role|roles|permission|permissions|admin|is_admin|superuser|"
    r"privilege|scope|access|group|groups|acl)$",
    ParameterEffect.AUTHZ_CONTROL, 95, DataType.BOOLEAN,
    "Role/permission parameter — privilege escalation critical")
_nr(r"\brole\b|\badmin\b|\bprivilege\b|\bscope\b|\baccess\b",
    ParameterEffect.AUTHZ_CONTROL, 75, DataType.STRING,
    "Authorisation control parameter — privilege escalation possible")

# Object identifiers (IDOR)
_nr(r"^(id|_id|object_id|record_id|item_id|resource_id|entity_id|doc_id)$",
    ParameterEffect.OBJECT_IDENTIFIER, 90, DataType.NUMBER,
    "Generic object identifier — IDOR critical")
_nr(r"^(user_id|userid|uid|account_id|customer_id|member_id|profile_id)$",
    ParameterEffect.USER_IDENTIFIER, 95, DataType.NUMBER,
    "User identifier — IDOR critical, privilege escalation")
_nr(r"^(order_id|invoice_id|payment_id|transaction_id|booking_id|"
    r"reservation_id|ticket_id|case_id|document_id|post_id)$",
    ParameterEffect.OBJECT_IDENTIFIER, 90, DataType.NUMBER,
    "Business object identifier — IDOR critical")
_nr(r"(_id|Id|ID|_key|_ref|_uuid|_guid)$",
    ParameterEffect.OBJECT_IDENTIFIER, 70, DataType.NUMBER,
    "Identifier suffix — IDOR likely")

# SSRF parameters
_nr(r"^(url|uri|endpoint|host|hostname|server|domain|proxy|origin|"
    r"image_url|avatar_url|logo_url|download|fetch|load_url|remote)$",
    ParameterEffect.CALLBACK_URL, 90, DataType.URL,
    "URL/host parameter — SSRF high potential")
_nr(r"\burl\b|\buri\b|\bhost\b|\bserver\b|\bdomain\b|\bremote\b",
    ParameterEffect.CALLBACK_URL, 70, DataType.URL,
    "URL-related parameter — SSRF possible")

# Command injection parameters
_nr(r"^(cmd|command|exec|execute|run|shell|system|arg|args|argument|"
    r"param|params|ping|host|ip|addr)$",
    ParameterEffect.COMMAND_ARGUMENT, 95, DataType.STRING,
    "Command/exec parameter — CMDi critical")

# Template injection (SSTI)
_nr(r"^(template|engine|renderer|render|view|layout|format|output|"
    r"expression|eval|compile)$",
    ParameterEffect.TEMPLATE_VARIABLE, 90, DataType.STRING,
    "Template/render parameter — SSTI critical")

# XML/XXE parameters
_nr(r"^(xml|data|payload|body|content|document|feed|rss|soap|wsdl)$",
    ParameterEffect.XML_CONTENT, 80, DataType.XML,
    "XML data parameter — XXE possible")

# Deserialization parameters
_nr(r"^(object|serialized|data|blob|state|session|cookie_value|"
    r"__viewstate|viewstate|csrfmiddlewaretoken)$",
    ParameterEffect.DESERIALIZATION, 80, DataType.BASE64,
    "Serialised object parameter — deserialization attack possible")

# HTML injection / XSS
_nr(r"^(message|msg|text|content|body|description|comment|feedback|"
    r"note|html|markup|code|input|value)$",
    ParameterEffect.HTML_CONTENT, 70, DataType.STRING,
    "Text content parameter — XSS / HTML injection possible")
_nr(r"^(name|title|heading|label|caption|subject|topic|summary)$",
    ParameterEffect.HTML_CONTENT, 60, DataType.STRING,
    "Display text parameter — XSS / stored XSS possible")

# Financial parameters
_nr(r"^(amount|price|cost|total|fee|rate|discount|quantity|qty|"
    r"balance|credit|debit|charge|payment)$",
    ParameterEffect.PRICE_QUANTITY, 90, DataType.FLOAT,
    "Financial parameter — business logic manipulation critical")

# LDAP injection
_nr(r"^(ldap|dn|ou|cn|uid|username|search|filter|directory|query)$",
    ParameterEffect.LDAP_FILTER, 75, DataType.STRING,
    "LDAP-related parameter — LDAP injection possible")

# XPath injection
_nr(r"^(xpath|xml_query|xmlquery|path|node|element|attribute)$",
    ParameterEffect.XPATH_QUERY, 80, DataType.STRING,
    "XPath-related parameter — XPath injection possible")

# Timing / race condition
_nr(r"^(delay|sleep|wait|timeout|retry|interval|throttle|rate)$",
    ParameterEffect.TIMING_CONTROL, 70, DataType.NUMBER,
    "Timing parameter — race condition / DoS possible")

# Format selectors
_nr(r"^(format|output|type|content_type|mime|encoding|charset|lang|"
    r"locale|language|country|region|timezone)$",
    ParameterEffect.FORMAT_SELECTOR, 60, DataType.STRING,
    "Format/locale parameter — content-type confusion, SSTI via format")

# Email injection
_nr(r"^(email|mail|to|from|cc|bcc|reply_to|recipient|sender)$",
    ParameterEffect.EMAIL_ADDRESS, 80, DataType.EMAIL,
    "Email parameter — email header injection possible")

# ── Value detection patterns ──────────────────────────────────────────────

_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_RE_JWT = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")
_RE_EMAIL = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
_RE_URL = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_RE_IP = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$",
    re.IGNORECASE,
)
_RE_PATH = re.compile(r"^(/[^/\0]+)+/?$|^\.\./|^[A-Za-z]:\\")
_RE_DATE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(.*))?$|"
    r"^\d{2}/\d{2}/\d{4}$|"
    r"^\d{10,13}$"   # Unix timestamp
)
_RE_HEX = re.compile(r"^(0x)?[0-9a-f]{8,}$", re.IGNORECASE)
_RE_BASE64 = re.compile(r"^[A-Za-z0-9+/]+=*$")
_RE_BASE64URL = re.compile(r"^[A-Za-z0-9\-_]+=*$")
_RE_INTEGER = re.compile(r"^-?\d+$")
_RE_FLOAT = re.compile(r"^-?\d+\.\d+([eE][+-]?\d+)?$")
_RE_BOOLEAN = re.compile(r"^(true|false|yes|no|1|0|on|off)$", re.IGNORECASE)

# ── Cross-parameter correlation rules ─────────────────────────────────────

_CORRELATION_GROUPS: List[Dict[str, Any]] = [
    {
        "name": "authentication_flow",
        "patterns": [r"(user|username|login|email)", r"(password|pass|pwd|token|pin)"],
        "scenario": "Credential-based authentication",
        "risk": "critical",
        "scanners": ["auth_bypass", "credential_stuffing", "brute_force"],
        "description": "Username + password pair detected — authentication bypass, brute force, credential stuffing",
    },
    {
        "name": "jwt_authentication",
        "patterns": [r"(jwt|token|bearer|access_token|id_token)"],
        "requires_jwt_value": True,
        "scenario": "JWT-based authentication",
        "risk": "critical",
        "scanners": ["jwt_scanner", "auth_bypass"],
        "description": "JWT token parameter — algorithm confusion, none-algorithm, key confusion attacks",
    },
    {
        "name": "financial_transaction",
        "patterns": [r"(amount|price|cost|total|fee|charge)", r"(from|sender|payer)", r"(to|recipient|payee)"],
        "scenario": "Financial transaction",
        "risk": "critical",
        "scanners": ["business_logic", "race_condition", "idor"],
        "description": "Financial transaction parameters — negative amounts, zero amounts, race conditions",
    },
    {
        "name": "idor_cluster",
        "patterns": [r"(user_id|userid|uid|account_id)", r"(id|object_id|record_id)"],
        "scenario": "Object access control",
        "risk": "high",
        "scanners": ["idor", "authz_matrix"],
        "description": "Multiple identifier parameters — IDOR/BOLA horizontal privilege escalation",
    },
    {
        "name": "ssrf_fetch",
        "patterns": [r"(url|uri|href|src|source|remote|endpoint)", r"(fetch|load|import|download|get)"],
        "scenario": "Server-side URL fetch",
        "risk": "critical",
        "scanners": ["ssrf"],
        "description": "URL + action parameters — SSRF via URL parameter manipulation",
    },
    {
        "name": "template_injection",
        "patterns": [r"(template|view|layout|theme|skin)", r"(engine|renderer|format|type)"],
        "scenario": "Template rendering",
        "risk": "critical",
        "scanners": ["ssti"],
        "description": "Template + engine parameters — SSTI via template name and engine type manipulation",
    },
    {
        "name": "file_operation",
        "patterns": [r"(file|path|filename|filepath|dir|folder|location)"],
        "scenario": "File system operation",
        "risk": "critical",
        "scanners": ["path_traversal", "file_upload", "ssrf"],
        "description": "File path parameters — path traversal, LFI, file upload bypass",
    },
    {
        "name": "redirect_chain",
        "patterns": [r"(redirect|return|next|goto|dest|forward)", r"(url|uri|to|target)"],
        "scenario": "Redirect chain",
        "risk": "high",
        "scanners": ["open_redirect", "ssrf"],
        "description": "Multiple redirect parameters — chained open redirect, SSRF via redirect",
    },
    {
        "name": "search_with_order",
        "patterns": [r"(q|query|search|filter|keyword)", r"(sort|order|orderby|column|field)"],
        "scenario": "Search with ordering",
        "risk": "high",
        "scanners": ["sqli", "nosqli"],
        "description": "Search + ordering parameters — SQL injection via ORDER BY clause",
    },
    {
        "name": "privilege_escalation",
        "patterns": [r"(role|admin|permission|privilege|scope)", r"(user_id|userid|uid)"],
        "scenario": "Access control",
        "risk": "critical",
        "scanners": ["authz_matrix", "idor"],
        "description": "Role + user identifier parameters — privilege escalation, horizontal/vertical IDOR",
    },
    {
        "name": "email_with_template",
        "patterns": [r"(email|mail|to|recipient)", r"(template|subject|body|message|content)"],
        "scenario": "Email sending",
        "risk": "high",
        "scanners": ["ssti", "email_injection"],
        "description": "Email + template parameters — email header injection, SSTI via email template",
    },
    {
        "name": "deserialization_blob",
        "patterns": [r"(data|object|serialized|blob|state|payload)"],
        "scenario": "Object deserialization",
        "risk": "critical",
        "scanners": ["deserialization"],
        "description": "Serialised data parameter — Java/PHP/Python deserialization attacks",
    },
]

# ── Scanner recommendation rules ──────────────────────────────────────────

@dataclass
class _ScannerRule:
    scanner_name: str
    effect: ParameterEffect
    priority: ScannerPriority
    rationale: str
    suggested_payloads: List[str] = field(default_factory=list)

_SCANNER_RULES: List[_ScannerRule] = [
    _ScannerRule("sqli", ParameterEffect.DATABASE_QUERY, ScannerPriority.HIGH,
                 "Database query parameter — SQL injection testing required",
                 ["'", "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"]),
    _ScannerRule("sqli", ParameterEffect.ORDERING, ScannerPriority.HIGH,
                 "Ordering parameter — ORDER BY injection possible",
                 ["1", "1 ASC", "1 DESC", "(SELECT 1)", "SLEEP(5)"]),
    _ScannerRule("sqli", ParameterEffect.SEARCH_FILTER, ScannerPriority.MEDIUM,
                 "Search filter — SQL injection possible via filter value",
                 ["'", "' OR 1=1--", "\\", ";"]),
    _ScannerRule("nosqli", ParameterEffect.DATABASE_QUERY, ScannerPriority.MEDIUM,
                 "Database query parameter — NoSQL injection testing",
                 ['{"$gt": ""}', '{"$where": "1==1"}', '{"$regex": ".*"}']),
    _ScannerRule("path_traversal", ParameterEffect.FILE_PATH, ScannerPriority.CRITICAL,
                 "File path parameter — path traversal critical",
                 ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f"]),
    _ScannerRule("ssti", ParameterEffect.TEMPLATE_VARIABLE, ScannerPriority.CRITICAL,
                 "Template variable — SSTI critical",
                 ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}"]),
    _ScannerRule("open_redirect", ParameterEffect.REDIRECT_DESTINATION, ScannerPriority.HIGH,
                 "Redirect parameter — open redirect testing required",
                 ["https://evil.com", "//evil.com", "/\\evil.com", "javascript:alert(1)"]),
    _ScannerRule("ssrf", ParameterEffect.CALLBACK_URL, ScannerPriority.HIGH,
                 "URL/callback parameter — SSRF testing required",
                 ["http://169.254.169.254/latest/meta-data/", "http://localhost/", "http://0.0.0.0/"]),
    _ScannerRule("xss", ParameterEffect.HTML_CONTENT, ScannerPriority.HIGH,
                 "HTML content parameter — XSS testing required",
                 ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "javascript:alert(1)"]),
    _ScannerRule("idor", ParameterEffect.OBJECT_IDENTIFIER, ScannerPriority.HIGH,
                 "Object identifier — IDOR testing required",
                 ["1", "2", "0", "-1", "99999"]),
    _ScannerRule("idor", ParameterEffect.USER_IDENTIFIER, ScannerPriority.CRITICAL,
                 "User identifier — IDOR critical, horizontal privilege escalation",
                 ["1", "2", "admin", "0"]),
    _ScannerRule("authz_matrix", ParameterEffect.AUTHZ_CONTROL, ScannerPriority.CRITICAL,
                 "Authorisation control — privilege escalation critical",
                 ["admin", "true", "1", "superuser", "root"]),
    _ScannerRule("jwt_scanner", ParameterEffect.AUTH_TOKEN, ScannerPriority.HIGH,
                 "Auth token — JWT manipulation, session fixation testing",
                 []),
    _ScannerRule("cmdi", ParameterEffect.COMMAND_ARGUMENT, ScannerPriority.CRITICAL,
                 "Command argument — CMDi critical",
                 ["; id", "| id", "& id", "$(id)", "`id`", "; sleep 5"]),
    _ScannerRule("xxe", ParameterEffect.XML_CONTENT, ScannerPriority.HIGH,
                 "XML content — XXE testing required",
                 ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']),
    _ScannerRule("deserialization", ParameterEffect.DESERIALIZATION, ScannerPriority.HIGH,
                 "Serialised data — deserialization attack testing required",
                 []),
    _ScannerRule("ldap_injection", ParameterEffect.LDAP_FILTER, ScannerPriority.HIGH,
                 "LDAP filter — LDAP injection testing required",
                 ["*", ")(uid=*", "*)(objectClass=*"]),
    _ScannerRule("xpath_injection", ParameterEffect.XPATH_QUERY, ScannerPriority.HIGH,
                 "XPath query — XPath injection testing required",
                 ["' or '1'='1", "' or 1=1 or '", ") or (1=1"]),
    _ScannerRule("race_condition", ParameterEffect.TIMING_CONTROL, ScannerPriority.MEDIUM,
                 "Timing parameter — race condition, DoS possible",
                 []),
    _ScannerRule("business_logic", ParameterEffect.PRICE_QUANTITY, ScannerPriority.CRITICAL,
                 "Financial parameter — business logic manipulation",
                 ["-1", "0", "0.01", "99999999"]),
    _ScannerRule("email_injection", ParameterEffect.EMAIL_ADDRESS, ScannerPriority.HIGH,
                 "Email parameter — email header injection",
                 ["test@test.com%0aCc:attacker@evil.com", "test%0d%0aBcc:attacker@evil.com"]),
]


# ═══════════════════════════════════════════════════════════════════════════
# Encoding helpers
# ═══════════════════════════════════════════════════════════════════════════


def _apply_encoding(value: str, layer: EncodingLayer) -> str:
    """Apply a single encoding layer to *value*."""
    if layer == EncodingLayer.URL_ENCODE:
        return urllib.parse.quote(value, safe="")
    elif layer == EncodingLayer.DOUBLE_URL_ENCODE:
        return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")
    elif layer == EncodingLayer.HTML_ENTITY:
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    elif layer == EncodingLayer.BASE64:
        return base64.b64encode(value.encode()).decode()
    elif layer == EncodingLayer.BASE64_URL:
        return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    elif layer == EncodingLayer.HEX_ENCODE:
        return value.encode().hex()
    elif layer == EncodingLayer.UNICODE_ESCAPE:
        return value.encode("unicode_escape").decode()
    elif layer == EncodingLayer.JSON_STRING:
        return json.dumps(value)
    return value


def _detect_encoding_chain(value: str) -> Tuple[EncodingChain, str]:
    """
    Detect encoding layers applied to *value* and return
    (chain, decoded_value).
    """
    layers: List[EncodingLayer] = []
    decoded = value
    confidence = 0.0

    # JWT detection (takes priority — three dot-separated base64url segments)
    if _RE_JWT.match(value):
        parts = value.split(".")
        if len(parts) == 3:
            try:
                header_json = base64.urlsafe_b64decode(parts[0] + "==")
                json.loads(header_json)
                layers.append(EncodingLayer.JWT_PAYLOAD)
                confidence = 0.97
                try:
                    payload_json = base64.urlsafe_b64decode(parts[1] + "==")
                    decoded = json.loads(payload_json)
                    if isinstance(decoded, dict):
                        decoded = json.dumps(decoded)
                except Exception:
                    pass
                return EncodingChain(layers=layers, confidence=confidence), decoded
            except Exception:
                pass

    # URL-encoded detection
    if "%" in value:
        try:
            unquoted = urllib.parse.unquote(value)
            if unquoted != value:
                if "%" in unquoted:
                    layers.append(EncodingLayer.DOUBLE_URL_ENCODE)
                    decoded = urllib.parse.unquote(unquoted)
                    confidence = 0.9
                else:
                    layers.append(EncodingLayer.URL_ENCODE)
                    decoded = unquoted
                    confidence = 0.85
        except Exception:
            pass

    # Base64 detection (after URL-decode)
    working = decoded if decoded != value else value
    if _RE_BASE64.match(working) and len(working) >= 8 and len(working) % 4 == 0:
        try:
            candidate = base64.b64decode(working).decode("utf-8")
            if all(32 <= ord(c) < 127 for c in candidate[:20]):
                layers.append(EncodingLayer.BASE64)
                decoded = candidate
                confidence = max(confidence, 0.80)
        except Exception:
            pass

    # Hex detection
    if not layers and _RE_HEX.match(working) and len(working) >= 8:
        try:
            hex_str = working.lstrip("0x")
            candidate = bytes.fromhex(hex_str).decode("utf-8")
            layers.append(EncodingLayer.HEX_ENCODE)
            decoded = candidate
            confidence = max(confidence, 0.75)
        except Exception:
            pass

    # HTML entity detection
    if "&amp;" in working or "&lt;" in working or "&#" in working:
        layers.append(EncodingLayer.HTML_ENTITY)
        decoded = (working.replace("&amp;", "&").replace("&lt;", "<")
                   .replace("&gt;", ">").replace("&quot;", '"'))
        confidence = max(confidence, 0.90)

    if not layers:
        return EncodingChain(layers=[EncodingLayer.NONE], confidence=1.0), value

    return EncodingChain(layers=layers, confidence=confidence), decoded


# ═══════════════════════════════════════════════════════════════════════════
# Data type inference
# ═══════════════════════════════════════════════════════════════════════════


def _infer_data_type(
    name: str,
    value: Optional[str],
    source: ParameterSource,
) -> Tuple[DataType, float]:
    """
    Infer the data type of a parameter from its name, value, and source.

    Returns (DataType, confidence).
    """
    if source == ParameterSource.GRAPHQL_VARIABLE:
        return DataType.GRAPHQL_VARIABLE, 1.0
    if source == ParameterSource.WEBSOCKET_MESSAGE:
        return DataType.WEBSOCKET_FIELD, 1.0

    # Value-based inference first (highest confidence)
    if value is not None and value.strip():
        v = value.strip()

        # JWT — check early (before base64)
        if _RE_JWT.match(v):
            parts = v.split(".")
            if len(parts) == 3:
                try:
                    base64.urlsafe_b64decode(parts[0] + "==")
                    return DataType.JWT, 0.97
                except Exception:
                    pass

        if _RE_UUID.match(v):
            return DataType.UUID, 0.99
        if _RE_EMAIL.match(v):
            return DataType.EMAIL, 0.95
        if _RE_URL.match(v):
            return DataType.URL, 0.90
        if _RE_IP.match(v):
            return DataType.IP_ADDRESS, 0.90
        if _RE_PATH.match(v):
            return DataType.PATH, 0.75
        if _RE_BOOLEAN.match(v):
            return DataType.BOOLEAN, 0.90
        if _RE_INTEGER.match(v):
            return DataType.NUMBER, 0.95
        if _RE_FLOAT.match(v):
            return DataType.FLOAT, 0.92
        if _RE_DATE.match(v):
            return DataType.DATE_TIME, 0.80

        # JSON
        if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
            try:
                json.loads(v)
                return DataType.JSON, 0.95
            except Exception:
                pass

        # XML
        if v.startswith("<") and v.endswith(">"):
            return DataType.XML, 0.85

        # Base64 (after JWT check)
        if _RE_BASE64.match(v) and len(v) >= 8 and len(v) % 4 == 0:
            try:
                base64.b64decode(v)
                return DataType.BASE64, 0.70
            except Exception:
                pass

    # Name-based inference (lower confidence)
    name_lower = name.lower()

    if any(t in name_lower for t in ("_id", "id_", "_key", "_uuid", "_guid")):
        return DataType.UUID, 0.55

    if any(t in name_lower for t in ("password", "passwd", "pass", "pwd", "secret")):
        return DataType.STRING, 0.80

    if any(t in name_lower for t in ("token", "jwt", "bearer")):
        return DataType.JWT, 0.60

    if any(t in name_lower for t in ("url", "uri", "href", "link", "endpoint")):
        return DataType.URL, 0.65

    if any(t in name_lower for t in ("file", "path", "dir", "folder")):
        return DataType.PATH, 0.65

    if any(t in name_lower for t in ("email", "mail")):
        return DataType.EMAIL, 0.70

    if any(t in name_lower for t in ("amount", "price", "cost", "fee", "total")):
        return DataType.FLOAT, 0.70

    if any(t in name_lower for t in (
        "count", "limit", "offset", "page", "size", "num", "number",
        "quantity", "qty", "id", "order", "index",
    )):
        return DataType.NUMBER, 0.60

    if any(t in name_lower for t in ("flag", "enabled", "active", "admin", "is_")):
        return DataType.BOOLEAN, 0.60

    if any(t in name_lower for t in ("date", "time", "timestamp", "created", "updated")):
        return DataType.DATE_TIME, 0.65

    if any(t in name_lower for t in ("xml", "soap", "wsdl")):
        return DataType.XML, 0.70

    if any(t in name_lower for t in ("json", "data", "payload", "body")):
        return DataType.JSON, 0.50

    return DataType.STRING, 0.40


# ═══════════════════════════════════════════════════════════════════════════
# Importance scoring
# ═══════════════════════════════════════════════════════════════════════════


def _compute_importance(
    name: str,
    effects: FrozenSet[ParameterEffect],
    data_type: DataType,
    source: ParameterSource,
    http_method: str,
    encoding_chain: EncodingChain,
) -> Tuple[float, Dict[str, float]]:
    """
    Compute importance score in [0, 100].

    Returns (score, breakdown_dict).
    """
    breakdown: Dict[str, float] = {}

    # Base score from name rules
    base = 0.0
    for pattern, effect, imp, _, _ in _NAME_RULES:
        if pattern.search(name):
            base = max(base, imp)
            break
    breakdown["name_match"] = base

    # Effect multipliers
    effect_scores = {
        ParameterEffect.DATABASE_QUERY: 20,
        ParameterEffect.COMMAND_ARGUMENT: 25,
        ParameterEffect.FILE_PATH: 22,
        ParameterEffect.TEMPLATE_VARIABLE: 22,
        ParameterEffect.REDIRECT_DESTINATION: 18,
        ParameterEffect.AUTHZ_CONTROL: 24,
        ParameterEffect.AUTH_TOKEN: 20,
        ParameterEffect.AUTH_CREDENTIAL: 20,
        ParameterEffect.OBJECT_IDENTIFIER: 18,
        ParameterEffect.USER_IDENTIFIER: 22,
        ParameterEffect.CALLBACK_URL: 20,
        ParameterEffect.PRICE_QUANTITY: 20,
        ParameterEffect.DESERIALIZATION: 22,
        ParameterEffect.XML_CONTENT: 16,
        ParameterEffect.HTML_CONTENT: 14,
        ParameterEffect.ORDERING: 12,
        ParameterEffect.LDAP_FILTER: 16,
        ParameterEffect.XPATH_QUERY: 16,
        ParameterEffect.EMAIL_ADDRESS: 14,
        ParameterEffect.FORMAT_SELECTOR: 10,
        ParameterEffect.TIMING_CONTROL: 10,
        ParameterEffect.PAGINATION: 6,
        ParameterEffect.SEARCH_FILTER: 14,
        ParameterEffect.CONFIG_TOGGLE: 12,
        ParameterEffect.FINANCIAL_DATA: 20,
        ParameterEffect.UNKNOWN: 0,
    }
    effect_score = sum(effect_scores.get(e, 0) for e in effects)
    breakdown["effect_score"] = min(effect_score, 40)

    # Data type bonus
    dtype_bonus = {
        DataType.JWT: 15,
        DataType.PATH: 12,
        DataType.URL: 10,
        DataType.XML: 8,
        DataType.BASE64: 6,
        DataType.JSON: 5,
        DataType.NUMBER: 4,
        DataType.FLOAT: 4,
        DataType.EMAIL: 6,
        DataType.UNKNOWN: 0,
    }
    breakdown["dtype_bonus"] = dtype_bonus.get(data_type, 2)

    # Source bonus
    source_bonus = {
        ParameterSource.QUERY_STRING: 5,
        ParameterSource.JSON_BODY: 4,
        ParameterSource.FORM_BODY: 4,
        ParameterSource.XML_BODY: 6,
        ParameterSource.HTTP_HEADER: 3,
        ParameterSource.COOKIE: 5,
        ParameterSource.PATH_SEGMENT: 5,
        ParameterSource.GRAPHQL_VARIABLE: 7,
        ParameterSource.WEBSOCKET_MESSAGE: 6,
        ParameterSource.MULTIPART_BODY: 4,
        ParameterSource.UNKNOWN: 0,
    }
    breakdown["source_bonus"] = source_bonus.get(source, 0)

    # HTTP method bonus
    method_bonus = {"PUT": 5, "DELETE": 6, "PATCH": 5, "POST": 3}.get(
        http_method.upper(), 0
    )
    breakdown["method_bonus"] = method_bonus

    # Encoding bonus (encoded params often carry interesting data)
    if encoding_chain.is_encoded and encoding_chain.layers[0] != EncodingLayer.NONE:
        breakdown["encoding_bonus"] = 5
    else:
        breakdown["encoding_bonus"] = 0

    total = (
        breakdown["name_match"] * 0.40
        + breakdown["effect_score"]
        + breakdown["dtype_bonus"]
        + breakdown["source_bonus"]
        + breakdown["method_bonus"]
        + breakdown["encoding_bonus"]
    )

    return min(total, 100.0), breakdown


# ═══════════════════════════════════════════════════════════════════════════
# Core analysis engine
# ═══════════════════════════════════════════════════════════════════════════


class ParameterIntelligenceEngine:
    """
    Analyses raw parameters and produces enriched ``AnalysedParameter`` objects
    with data-type inference, effect classification, importance scoring,
    encoding detection, and scanner recommendations.

    Usage
    -----
    ::

        engine = ParameterIntelligenceEngine(target_url="https://example.com")
        report = await engine.analyse_all(raw_parameters)

        # Get all parameters relevant to the SQLi scanner
        sqli_params = report.for_scanner("sqli", min_priority=ScannerPriority.MEDIUM)
    """

    def __init__(
        self,
        target_url: str = "",
        concurrency: int = 64,
        min_importance_threshold: float = 0.0,
    ) -> None:
        self._target_url = target_url
        self._concurrency = concurrency
        self._min_importance = min_importance_threshold
        self._semaphore = asyncio.Semaphore(concurrency)
        # Deduplication set
        self._seen: Set[str] = set()

    # ── Public API ─────────────────────────────────────────────────────────

    async def analyse_all(
        self, parameters: Sequence[RawParameter]
    ) -> ParameterIntelligenceReport:
        """
        Analyse *parameters* in parallel and return a
        ``ParameterIntelligenceReport``.
        """
        start = time.monotonic()

        # Deduplicate
        unique: List[RawParameter] = []
        for p in parameters:
            fp = p.fingerprint
            if fp not in self._seen:
                self._seen.add(fp)
                unique.append(p)

        # Parallel analysis
        tasks = [self._analyse_one(p) for p in unique]
        results: List[AnalysedParameter] = await asyncio.gather(*tasks)

        # Cross-parameter correlation
        groups = self._correlate(results)

        # Encoding map
        encoding_map = {r.raw.fingerprint: r.encoding_chain for r in results}

        # High-value subset
        high_value = [r for r in results if r.importance_score >= 70.0]

        # Global stats
        stats = self._compute_stats(results)

        return ParameterIntelligenceReport(
            parameters=results,
            groups=groups,
            encoding_map=encoding_map,
            global_stats=stats,
            high_value_parameters=high_value,
            scan_target_url=self._target_url,
            analysis_duration_seconds=time.monotonic() - start,
        )

    def analyse_sync(
        self, parameters: Sequence[RawParameter]
    ) -> ParameterIntelligenceReport:
        """Synchronous wrapper for environments without a running event loop."""
        return asyncio.get_event_loop().run_until_complete(self.analyse_all(parameters))

    # ── Internal methods ───────────────────────────────────────────────────

    async def _analyse_one(self, raw: RawParameter) -> AnalysedParameter:
        async with self._semaphore:
            return await asyncio.get_event_loop().run_in_executor(
                None, self._analyse_sync, raw
            )

    def _analyse_sync(self, raw: RawParameter) -> AnalysedParameter:
        t0 = time.monotonic()
        evidence = ParameterEvidence()

        # ── Stage 1: Name analysis ──────────────────────────────────────
        effects: Set[ParameterEffect] = set()
        name_importance = 0.0

        for pattern, effect, imp, _, rationale in _NAME_RULES:
            if pattern.search(raw.name):
                effects.add(effect)
                name_importance = max(name_importance, imp)
                evidence.name_signals.append(f"Name matched '{pattern.pattern}' → {effect.value} ({rationale})")

        # ── Stage 2: Value analysis ─────────────────────────────────────
        encoding_chain, decoded_sample = _detect_encoding_chain(raw.sample_value or "")

        if encoding_chain.is_encoded:
            for layer in encoding_chain.layers:
                evidence.encoding_signals.append(f"Detected encoding layer: {layer.value}")

        data_type, dt_confidence = _infer_data_type(raw.name, raw.sample_value, raw.source)
        evidence.data_type_confidence = dt_confidence

        # Refine data type from decoded sample
        if decoded_sample and decoded_sample != (raw.sample_value or ""):
            refined_type, refined_conf = _infer_data_type(raw.name, decoded_sample, raw.source)
            if refined_conf > dt_confidence:
                data_type = refined_type
                dt_confidence = refined_conf
                evidence.value_signals.append(
                    f"Refined type from decoded value: {data_type.value} ({dt_confidence:.2f})"
                )

        evidence.value_signals.append(f"Data type: {data_type.value} (confidence={dt_confidence:.2f})")

        # Add effects based on data type
        dtype_effects = {
            DataType.URL: {ParameterEffect.CALLBACK_URL, ParameterEffect.REDIRECT_DESTINATION},
            DataType.PATH: {ParameterEffect.FILE_PATH},
            DataType.XML: {ParameterEffect.XML_CONTENT},
            DataType.JWT: {ParameterEffect.AUTH_TOKEN},
            DataType.EMAIL: {ParameterEffect.EMAIL_ADDRESS},
            DataType.JSON: set(),
        }
        for dt, dt_effs in dtype_effects.items():
            if data_type == dt:
                effects.update(dt_effs)

        # ── Stage 3: Context analysis ───────────────────────────────────
        if raw.source in (ParameterSource.HTTP_HEADER, ParameterSource.COOKIE):
            if any(kw in raw.name.lower() for kw in ("auth", "token", "session", "bearer")):
                effects.add(ParameterEffect.AUTH_TOKEN)
                evidence.context_signals.append(f"Auth token in {raw.source.value}")

        if raw.source == ParameterSource.PATH_SEGMENT:
            effects.add(ParameterEffect.OBJECT_IDENTIFIER)
            evidence.context_signals.append("Path segment — likely object identifier")

        if raw.http_method in ("PUT", "DELETE", "PATCH") and ParameterEffect.OBJECT_IDENTIFIER in effects:
            evidence.context_signals.append(
                f"HTTP {raw.http_method} + identifier → IDOR on mutating methods"
            )

        if raw.content_type and "xml" in raw.content_type.lower():
            effects.add(ParameterEffect.XML_CONTENT)
            evidence.context_signals.append("Content-Type XML → XXE candidate")

        if raw.content_type and "json" in raw.content_type.lower():
            evidence.context_signals.append("Content-Type JSON → API parameter")

        if not effects:
            effects.add(ParameterEffect.UNKNOWN)

        frozen_effects = frozenset(effects)

        # ── Stage 4: Importance scoring ─────────────────────────────────
        importance, breakdown = _compute_importance(
            raw.name, frozen_effects, data_type,
            raw.source, raw.http_method, encoding_chain,
        )
        evidence.importance_breakdown = breakdown

        # ── Stage 5: Scanner recommendations ────────────────────────────
        recommendations: List[ScannerRecommendation] = []
        seen_scanners: Set[str] = set()

        for rule in _SCANNER_RULES:
            if rule.effect in frozen_effects and rule.scanner_name not in seen_scanners:
                # Boost priority for high-importance parameters
                priority = rule.priority
                if importance >= 85 and priority == ScannerPriority.MEDIUM:
                    priority = ScannerPriority.HIGH
                elif importance >= 95 and priority == ScannerPriority.HIGH:
                    priority = ScannerPriority.CRITICAL

                recommendations.append(ScannerRecommendation(
                    scanner_name=rule.scanner_name,
                    priority=priority,
                    rationale=rule.rationale,
                    suggested_payloads=list(rule.suggested_payloads),
                    confidence=min(importance / 100.0, 1.0),
                ))
                seen_scanners.add(rule.scanner_name)

        # Sort by priority value (lower = more critical)
        recommendations.sort(key=lambda r: r.priority.value)

        evidence.analysis_duration_ms = (time.monotonic() - t0) * 1000

        return AnalysedParameter(
            raw=raw,
            data_type=data_type,
            data_type_confidence=dt_confidence,
            effects=frozen_effects,
            encoding_chain=encoding_chain,
            importance_score=importance,
            scanner_recommendations=recommendations,
            evidence=evidence,
            decoded_sample=decoded_sample if decoded_sample != raw.sample_value else None,
            inferred_enum_values=[],
            is_reflected=False,
            affects_multiple_endpoints=False,
        )

    # ── Cross-parameter correlation ────────────────────────────────────────

    def _correlate(self, params: List[AnalysedParameter]) -> List[ParameterGroup]:
        """Detect semantic parameter groups per endpoint."""
        groups: List[ParameterGroup] = []

        # Group parameters by endpoint
        by_endpoint: Dict[str, List[AnalysedParameter]] = {}
        for p in params:
            by_endpoint.setdefault(p.endpoint_url, []).append(p)

        for endpoint_url, ep_params in by_endpoint.items():
            param_names = [p.name.lower() for p in ep_params]

            for rule in _CORRELATION_GROUPS:
                patterns = rule["patterns"]
                matched_count = 0
                matched_names: List[str] = []

                for pat_str in patterns:
                    pat = re.compile(pat_str, re.IGNORECASE)
                    for pname in param_names:
                        if pat.search(pname):
                            matched_count += 1
                            matched_names.append(pname)
                            break

                min_required = max(1, len(patterns) - 1)
                if matched_count >= min_required:
                    confidence = matched_count / len(patterns)
                    groups.append(ParameterGroup(
                        group_name=rule["name"],
                        endpoint_url=endpoint_url,
                        parameter_names=matched_names,
                        scenario=rule["scenario"],
                        risk_level=rule["risk"],
                        scanner_names=rule["scanners"],
                        confidence=confidence,
                        description=rule["description"],
                    ))

        return groups

    # ── Statistics ─────────────────────────────────────────────────────────

    def _compute_stats(self, params: List[AnalysedParameter]) -> Dict[str, Any]:
        if not params:
            return {}

        effect_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}
        dtype_counts: Dict[str, int] = {}

        for p in params:
            for e in p.effects:
                effect_counts[e.value] = effect_counts.get(e.value, 0) + 1
            source_counts[p.source.value] = source_counts.get(p.source.value, 0) + 1
            dtype_counts[p.data_type.value] = dtype_counts.get(p.data_type.value, 0) + 1

        importance_values = [p.importance_score for p in params]

        return {
            "total_parameters": len(params),
            "high_value_count": sum(1 for p in params if p.importance_score >= 70),
            "critical_count": sum(1 for p in params if p.importance_score >= 90),
            "encoded_count": sum(1 for p in params if p.encoding_chain.is_encoded),
            "avg_importance": sum(importance_values) / len(importance_values),
            "max_importance": max(importance_values),
            "by_effect": effect_counts,
            "by_source": source_counts,
            "by_data_type": dtype_counts,
            "top_scanners": _top_scanner_targets(params),
        }


def _top_scanner_targets(params: List[AnalysedParameter]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p in params:
        for rec in p.scanner_recommendations:
            if rec.priority in (ScannerPriority.CRITICAL, ScannerPriority.HIGH):
                counts[rec.scanner_name] = counts.get(rec.scanner_name, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10])


# ═══════════════════════════════════════════════════════════════════════════
# Convenience factory
# ═══════════════════════════════════════════════════════════════════════════


async def analyse_parameters(
    parameters: Sequence[RawParameter],
    target_url: str = "",
    concurrency: int = 64,
    min_importance_threshold: float = 0.0,
) -> ParameterIntelligenceReport:
    """
    Top-level async helper for analysing a collection of raw parameters.

    Parameters
    ----------
    parameters:
        All ``RawParameter`` objects produced by the discovery phase.
    target_url:
        Root URL of the scan target.
    concurrency:
        Maximum parallel analyses.
    min_importance_threshold:
        Exclude parameters with importance below this value (0 = include all).

    Returns
    -------
    ``ParameterIntelligenceReport`` with all ``AnalysedParameter`` objects.

    Example
    -------
    ::

        from webshield.recon.parameter_intelligence import (
            RawParameter, ParameterSource, analyse_parameters
        )

        params = [
            RawParameter(
                name="user_id",
                source=ParameterSource.QUERY_STRING,
                sample_value="42",
                endpoint_url="https://example.com/api/profile",
                http_method="GET",
            ),
            RawParameter(
                name="redirect",
                source=ParameterSource.QUERY_STRING,
                sample_value="https://example.com/home",
                endpoint_url="https://example.com/login",
                http_method="GET",
            ),
        ]

        report = await analyse_parameters(params, target_url="https://example.com")

        # All parameters relevant to the open redirect scanner
        redirect_params = report.for_scanner("open_redirect")
        for p in redirect_params:
            print(p.name, p.importance_score, p.encoding_chain.layers)
    """
    engine = ParameterIntelligenceEngine(
        target_url=target_url,
        concurrency=concurrency,
        min_importance_threshold=min_importance_threshold,
    )
    return await engine.analyse_all(parameters)
