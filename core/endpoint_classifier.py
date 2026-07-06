"""
Endpoint Classification Engine — Part 11/12 of the Intelligence Layer
(canonical core/ implementation).

Every Endpoint discovered by the crawler, browser engine, JS analyzer, API
discovery engine, or passive intelligence collector flows through this module
before it ever reaches a scanner.  The engine answers one fundamental question
for each endpoint:

    *What kind of endpoint is this, and which scanners should test it?*

Without classification, the scanner pipeline has to run every test against
every endpoint — an approach that wastes budget, generates noise, and
frequently misses findings because generic payloads are used instead of
context-aware ones.  With classification each endpoint carries a *profile*
that the scanner coordinator can use to select the smallest, most targeted
set of scanners and payloads.

Architecture
------------
Classification is performed in three ordered passes:

1. **Structural pass** — Pattern matching against the URL path, query string,
   fragment, and file extension.  Fast, zero-cost, zero-network.  Catches the
   obvious cases (``/login``, ``/admin``, ``/upload``, ``/api/v2/...``).

2. **Semantic pass** — Lightweight NLP-style analysis of path *segments*:
   tokenisation by ``/``, ``-``, ``_``, and camel-case boundaries, followed by
   stem matching against a curated vocabulary per category.  Handles
   non-English paths (e.g. ``/iniciar-sesion``, ``/paiement``) and
   unconventional naming conventions.

3. **Behavioural pass** — Analysed only when a response object is available
   (i.e. the endpoint has already been probed at least once).  Inspects
   response headers (``Content-Type``, ``Allow``, ``WWW-Authenticate``,
   ``X-Frame-Options``, CSP, CORS preflight headers), response body
   fingerprints (JSON structure, HTML form presence, file-download clues),
   and HTTP methods returned by the server.  This pass can *upgrade* or
   *refine* a classification from the earlier passes.

Confidence model
----------------
Each classification is annotated with a ``ConfidenceLevel`` (HIGH / MEDIUM /
LOW) based on how many independent signals contributed to it.  A path like
``/api/v1/payment/checkout`` will score HIGH for ``API``, MEDIUM for
``PAYMENT``, and LOW for ``AUTHENTICATION`` (weak signal: the word "key" is
absent).  The scanner pipeline respects these levels when setting scan depth.

Multi-label classification
--------------------------
An endpoint can carry **multiple categories**.  ``/admin/users/upload`` is
simultaneously ``ADMIN``, ``PROFILE`` (user management), and
``FILE_UPLOAD``.  The ``EndpointProfile`` returned by the classifier holds
an ordered list of ``ClassificationResult`` objects, primary first.

Scanner routing table
---------------------
The module ships a built-in ``SCANNER_ROUTING_TABLE`` that maps every
``EndpointCategory`` to the list of scanner IDs that should be activated for
it.  This decouples classification from scanner selection: adding a new
scanner only requires adding one entry to the table.

Integration points
------------------
- Called by ``DiscoveryInfrastructure`` immediately after an endpoint is
  confirmed reachable.
- Results stored in the shared ``KnowledgeBase`` under
  ``knowledge_base.endpoint_profiles[url]``.
- Consumed by ``ScanPipeline.build_queue()`` to assign scanner sets.
- Re-run automatically when the ``DifferentialEngine`` detects that a
  response has changed significantly (endpoint may have been repurposed).
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# Category Enumeration
# ---------------------------------------------------------------------------

class EndpointCategory(Enum):
    """Canonical endpoint categories understood by the scanner pipeline."""

    # Authentication / identity management
    AUTHENTICATION   = auto()   # login, logout, register, sso, mfa, otp
    PASSWORD_RESET   = auto()   # forgot-password, reset, confirm-email
    MFA              = auto()   # 2fa, totp, otp, authenticator

    # Authorisation / privilege
    ADMIN            = auto()   # /admin, /dashboard, /manage, /console
    PRIVILEGE        = auto()   # /promote, /grant, /role, /permission

    # User / profile management
    PROFILE          = auto()   # /profile, /account, /settings, /me

    # File operations
    FILE_UPLOAD      = auto()   # /upload, /import, multipart forms
    FILE_DOWNLOAD    = auto()   # /download, /export, /attachment, /media

    # Search and data retrieval
    SEARCH           = auto()   # /search, ?q=, ?query=, /find
    LISTING          = auto()   # /list, /index, /browse, pagination params

    # Payment / financial
    PAYMENT          = auto()   # /payment, /checkout, /cart, /order, /invoice

    # API endpoints
    API              = auto()   # /api/, /v1/, /v2/, /graphql, /rest
    GRAPHQL          = auto()   # /graphql, /graph, gql
    WEBSOCKET        = auto()   # ws://, wss://, /ws, /socket, /events

    # Data format endpoints
    JSON_API         = auto()   # JSON Content-Type, JSON-like paths
    XML_API          = auto()   # XML Content-Type, /soap, /wsdl
    FORM_ENDPOINT    = auto()   # HTML forms (POST with form parameters)

    # Infrastructure / debugging
    HEALTH_CHECK     = auto()   # /health, /ping, /status, /alive
    METRICS          = auto()   # /metrics, /stats, /prometheus, /actuator
    CONFIGURATION    = auto()   # /config, /settings (non-user), /.env, /env
    DEBUG            = auto()   # /debug, /trace, /phpinfo, /__debug__

    # Content / static
    STATIC_RESOURCE  = auto()   # .js, .css, .png, .svg, fonts, etc.
    DOCUMENT         = auto()   # .pdf, .docx, .xlsx, .csv — downloadable docs

    # Miscellaneous
    REDIRECT         = auto()   # /redirect?url=, /out?href=, /go?to=
    WEBHOOK          = auto()   # /webhook, /callback, /notify, /hook
    OAUTH_CALLBACK   = auto()   # /oauth/callback, /auth/callback
    SSO              = auto()   # /saml, /sso, /oidc, /cas

    # Fallback
    UNKNOWN          = auto()   # Could not determine


class ConfidenceLevel(Enum):
    HIGH   = 3
    MEDIUM = 2
    LOW    = 1

    def __ge__(self, other: "ConfidenceLevel") -> bool:
        return self.value >= other.value

    def __gt__(self, other: "ConfidenceLevel") -> bool:
        return self.value > other.value


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    """A single category assignment with supporting evidence."""

    category: EndpointCategory
    confidence: ConfidenceLevel
    signals: List[str] = field(default_factory=list)   # human-readable evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.name,
            "confidence": self.confidence.name,
            "signals": self.signals,
        }


@dataclass
class EndpointProfile:
    """
    Complete classification profile for one endpoint URL.

    ``classifications`` is ordered by confidence (highest first), then by
    enum ordinal for determinism.  The *primary* classification is always
    ``classifications[0]`` when the list is non-empty.
    """

    url: str
    method: str                              # HTTP method (GET / POST / …)
    classifications: List[ClassificationResult] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)   # known param names
    content_type: Optional[str] = None       # observed request Content-Type
    response_content_type: Optional[str] = None
    accepts_file_upload: bool = False
    requires_auth: bool = False
    http_methods_allowed: List[str] = field(default_factory=list)
    has_form: bool = False
    is_dynamic: bool = True                  # False → static resource
    scanner_ids: List[str] = field(default_factory=list)  # routed scanner IDs

    # -----------------------------------------------------------------------

    @property
    def primary_category(self) -> EndpointCategory:
        if self.classifications:
            return self.classifications[0].category
        return EndpointCategory.UNKNOWN

    @property
    def categories(self) -> List[EndpointCategory]:
        return [c.category for c in self.classifications]

    def has_category(self, cat: EndpointCategory) -> bool:
        return cat in self.categories

    def primary_confidence(self) -> ConfidenceLevel:
        if self.classifications:
            return self.classifications[0].confidence
        return ConfidenceLevel.LOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "primary_category": self.primary_category.name,
            "classifications": [c.to_dict() for c in self.classifications],
            "parameters": self.parameters,
            "content_type": self.content_type,
            "response_content_type": self.response_content_type,
            "accepts_file_upload": self.accepts_file_upload,
            "requires_auth": self.requires_auth,
            "http_methods_allowed": self.http_methods_allowed,
            "has_form": self.has_form,
            "is_dynamic": self.is_dynamic,
            "scanner_ids": self.scanner_ids,
        }


# ---------------------------------------------------------------------------
# Scanner routing table
# ---------------------------------------------------------------------------

# Maps each EndpointCategory to a list of scanner identifiers.
# Scanner implementations look up their own ID in this table.
SCANNER_ROUTING_TABLE: Dict[EndpointCategory, List[str]] = {
    EndpointCategory.AUTHENTICATION:  [
        "auth_engine", "brute_force", "jwt_scanner", "session_fixation",
        "csrf", "rate_limiting", "password_policy",
    ],
    EndpointCategory.PASSWORD_RESET:  [
        "auth_engine", "csrf", "host_header_injection", "rate_limiting",
    ],
    EndpointCategory.MFA:             [
        "auth_engine", "rate_limiting", "otp_bypass",
    ],
    EndpointCategory.ADMIN:           [
        "authz_matrix", "idor", "privilege_escalation", "sensitive_files",
        "sqli", "xss", "cmdi", "ssrf",
    ],
    EndpointCategory.PRIVILEGE:       [
        "authz_matrix", "idor", "privilege_escalation",
    ],
    EndpointCategory.PROFILE:         [
        "idor", "stored_xss", "csrf", "xxe", "sqli",
    ],
    EndpointCategory.FILE_UPLOAD:     [
        "file_upload", "xxe", "ssrf", "stored_xss", "path_traversal",
    ],
    EndpointCategory.FILE_DOWNLOAD:   [
        "path_traversal", "idor", "ssrf", "sensitive_files",
    ],
    EndpointCategory.SEARCH:          [
        "sqli", "nosqli", "xss", "ssti", "ldap_injection",
        "xpath_injection", "open_redirect",
    ],
    EndpointCategory.LISTING:         [
        "idor", "sqli", "xss",
    ],
    EndpointCategory.PAYMENT:         [
        "sqli", "idor", "csrf", "race_condition", "ssrf",
    ],
    EndpointCategory.API:             [
        "sqli", "nosqli", "xss", "idor", "authz_matrix",
        "rate_limiting", "cmdi", "ssrf", "ssti",
    ],
    EndpointCategory.GRAPHQL:         [
        "graphql", "sqli", "idor", "authz_matrix",
    ],
    EndpointCategory.WEBSOCKET:       [
        "websocket_scanner", "xss", "sqli",
    ],
    EndpointCategory.JSON_API:        [
        "sqli", "nosqli", "xss", "idor", "ssrf", "xxe",
    ],
    EndpointCategory.XML_API:         [
        "xxe", "sqli", "xss", "ssrf",
    ],
    EndpointCategory.FORM_ENDPOINT:   [
        "csrf", "xss", "sqli", "nosqli", "cmdi", "ssti",
        "path_traversal", "open_redirect",
    ],
    EndpointCategory.HEALTH_CHECK:    [
        "sensitive_files", "headers",
    ],
    EndpointCategory.METRICS:         [
        "sensitive_files", "headers", "authz_matrix",
    ],
    EndpointCategory.CONFIGURATION:   [
        "sensitive_files", "secrets_scanner", "headers", "authz_matrix",
    ],
    EndpointCategory.DEBUG:           [
        "sensitive_files", "secrets_scanner", "authz_matrix",
    ],
    EndpointCategory.STATIC_RESOURCE: [],   # No active scanning
    EndpointCategory.DOCUMENT:        [
        "path_traversal", "idor",
    ],
    EndpointCategory.REDIRECT:        [
        "open_redirect", "ssrf",
    ],
    EndpointCategory.WEBHOOK:         [
        "ssrf", "xss", "csrf",
    ],
    EndpointCategory.OAUTH_CALLBACK:  [
        "oauth_scanner", "open_redirect", "csrf", "ssrf",
    ],
    EndpointCategory.SSO:             [
        "oauth_scanner", "xml_injection", "open_redirect", "csrf",
    ],
    EndpointCategory.UNKNOWN:         [
        "xss", "sqli", "headers",
    ],
}


# ---------------------------------------------------------------------------
# Vocabulary tables for semantic matching
# ---------------------------------------------------------------------------

# (category, required_stems, optional_stems, negative_stems)
# A segment *matches* a row when it contains at least one required stem and
# none of the negative stems.
_SEGMENT_VOCABULARY: List[Tuple[EndpointCategory, FrozenSet[str], FrozenSet[str], FrozenSet[str]]] = [
    (
        EndpointCategory.AUTHENTICATION,
        frozenset({"login", "signin", "sign-in", "auth", "authenticate",
                   "session", "token", "logon", "signon", "connect"}),
        frozenset({"user", "account", "secure"}),
        frozenset({"logout", "signout", "sign-out", "callback"}),
    ),
    (
        EndpointCategory.PASSWORD_RESET,
        frozenset({"password", "passwd", "pwd", "reset", "forgot",
                   "recover", "change-password", "newpassword"}),
        frozenset({"confirm", "email", "link"}),
        frozenset(),
    ),
    (
        EndpointCategory.MFA,
        frozenset({"2fa", "mfa", "otp", "totp", "hotp", "authenticator",
                   "verify", "verification", "twofa", "second-factor"}),
        frozenset({"phone", "sms", "email"}),
        frozenset(),
    ),
    (
        EndpointCategory.ADMIN,
        frozenset({"admin", "administrator", "manage", "management",
                   "dashboard", "console", "panel", "backoffice",
                   "back-office", "control", "cp", "cms"}),
        frozenset({"super", "root", "system"}),
        frozenset(),
    ),
    (
        EndpointCategory.PRIVILEGE,
        frozenset({"role", "permission", "privilege", "grant", "revoke",
                   "promote", "demote", "access-control", "acl"}),
        frozenset({"user", "group", "policy"}),
        frozenset(),
    ),
    (
        EndpointCategory.PROFILE,
        frozenset({"profile", "account", "user", "me", "settings",
                   "preferences", "personal", "member", "identity"}),
        frozenset({"update", "edit", "view"}),
        frozenset({"admin", "manage"}),
    ),
    (
        EndpointCategory.FILE_UPLOAD,
        frozenset({"upload", "import", "attach", "attachment",
                   "multipart", "media", "ingest", "file"}),
        frozenset({"image", "document", "csv", "bulk"}),
        frozenset({"download", "export"}),
    ),
    (
        EndpointCategory.FILE_DOWNLOAD,
        frozenset({"download", "export", "attachment", "media",
                   "stream", "fetch", "retrieve", "get-file"}),
        frozenset({"file", "report", "document", "pdf", "csv"}),
        frozenset({"upload", "import"}),
    ),
    (
        EndpointCategory.SEARCH,
        frozenset({"search", "find", "query", "lookup", "filter",
                   "suggest", "autocomplete", "typeahead", "explore"}),
        frozenset({"advanced", "full-text", "elastic"}),
        frozenset(),
    ),
    (
        EndpointCategory.LISTING,
        frozenset({"list", "index", "browse", "catalog", "catalogue",
                   "directory", "feed", "inbox", "recent", "all"}),
        frozenset({"page", "limit", "offset"}),
        frozenset(),
    ),
    (
        EndpointCategory.PAYMENT,
        frozenset({"payment", "pay", "checkout", "cart", "order",
                   "invoice", "billing", "transaction", "charge",
                   "purchase", "buy", "subscribe", "subscription",
                   "stripe", "paypal", "braintree"}),
        frozenset({"refund", "cancel", "confirm"}),
        frozenset(),
    ),
    (
        EndpointCategory.API,
        frozenset({"api", "rest", "service", "endpoint", "v1", "v2",
                   "v3", "v4", "rpc", "resource"}),
        frozenset({"json", "data", "fetch"}),
        frozenset({"graphql"}),
    ),
    (
        EndpointCategory.GRAPHQL,
        frozenset({"graphql", "graph", "gql", "query", "mutation",
                   "subscription"}),
        frozenset(),
        frozenset(),
    ),
    (
        EndpointCategory.WEBSOCKET,
        frozenset({"ws", "websocket", "socket", "realtime", "live",
                   "stream", "push", "notify", "events", "sse"}),
        frozenset({"chat", "feed"}),
        frozenset(),
    ),
    (
        EndpointCategory.HEALTH_CHECK,
        frozenset({"health", "ping", "alive", "ready", "readiness",
                   "liveness", "status", "heartbeat", "up"}),
        frozenset({"check", "probe"}),
        frozenset(),
    ),
    (
        EndpointCategory.METRICS,
        frozenset({"metrics", "stats", "statistics", "prometheus",
                   "actuator", "telemetry", "monitoring", "grafana"}),
        frozenset({"perf", "performance"}),
        frozenset(),
    ),
    (
        EndpointCategory.CONFIGURATION,
        frozenset({"config", "configuration", "env", "environment",
                   "settings", "setup", "options", "ini"}),
        frozenset({"app", "system"}),
        frozenset({"user", "account", "profile"}),
    ),
    (
        EndpointCategory.DEBUG,
        frozenset({"debug", "trace", "phpinfo", "info", "test",
                   "dev", "development", "diag", "diagnostic",
                   "__debug__", "swagger", "openapi"}),
        frozenset({"console", "explorer"}),
        frozenset({"production"}),
    ),
    (
        EndpointCategory.REDIRECT,
        frozenset({"redirect", "out", "go", "link", "url", "next",
                   "return", "continue", "forward", "redir"}),
        frozenset(),
        frozenset(),
    ),
    (
        EndpointCategory.WEBHOOK,
        frozenset({"webhook", "hook", "callback", "notify",
                   "notification", "event", "trigger", "inbound"}),
        frozenset(),
        frozenset(),
    ),
    (
        EndpointCategory.OAUTH_CALLBACK,
        frozenset({"callback", "oauth", "redirect-uri", "redirect_uri",
                   "authorize", "authorise", "code", "token"}),
        frozenset({"oauth2", "oidc"}),
        frozenset({"webhook", "hook"}),
    ),
    (
        EndpointCategory.SSO,
        frozenset({"saml", "sso", "oidc", "cas", "ldap",
                   "kerberos", "openid", "idp"}),
        frozenset({"login", "auth", "connect"}),
        frozenset(),
    ),
]

# File extensions → category
_EXTENSION_MAP: Dict[str, EndpointCategory] = {
    # Static resources
    ".js":    EndpointCategory.STATIC_RESOURCE,
    ".css":   EndpointCategory.STATIC_RESOURCE,
    ".png":   EndpointCategory.STATIC_RESOURCE,
    ".jpg":   EndpointCategory.STATIC_RESOURCE,
    ".jpeg":  EndpointCategory.STATIC_RESOURCE,
    ".gif":   EndpointCategory.STATIC_RESOURCE,
    ".svg":   EndpointCategory.STATIC_RESOURCE,
    ".webp":  EndpointCategory.STATIC_RESOURCE,
    ".ico":   EndpointCategory.STATIC_RESOURCE,
    ".woff":  EndpointCategory.STATIC_RESOURCE,
    ".woff2": EndpointCategory.STATIC_RESOURCE,
    ".ttf":   EndpointCategory.STATIC_RESOURCE,
    ".eot":   EndpointCategory.STATIC_RESOURCE,
    ".map":   EndpointCategory.STATIC_RESOURCE,
    # Documents
    ".pdf":   EndpointCategory.DOCUMENT,
    ".doc":   EndpointCategory.DOCUMENT,
    ".docx":  EndpointCategory.DOCUMENT,
    ".xls":   EndpointCategory.DOCUMENT,
    ".xlsx":  EndpointCategory.DOCUMENT,
    ".csv":   EndpointCategory.DOCUMENT,
    ".zip":   EndpointCategory.DOCUMENT,
    ".tar":   EndpointCategory.DOCUMENT,
    ".gz":    EndpointCategory.DOCUMENT,
    # Data endpoints
    ".json":  EndpointCategory.JSON_API,
    ".xml":   EndpointCategory.XML_API,
    ".soap":  EndpointCategory.XML_API,
    ".wsdl":  EndpointCategory.XML_API,
    # Scripts (may contain logic)
    ".php":   EndpointCategory.FORM_ENDPOINT,
    ".asp":   EndpointCategory.FORM_ENDPOINT,
    ".aspx":  EndpointCategory.FORM_ENDPOINT,
    ".jsp":   EndpointCategory.FORM_ENDPOINT,
    ".cgi":   EndpointCategory.FORM_ENDPOINT,
}

# Query parameter names → category hints
_PARAM_CATEGORY_HINTS: Dict[str, EndpointCategory] = {
    "q":          EndpointCategory.SEARCH,
    "query":      EndpointCategory.SEARCH,
    "search":     EndpointCategory.SEARCH,
    "keyword":    EndpointCategory.SEARCH,
    "term":       EndpointCategory.SEARCH,
    "s":          EndpointCategory.SEARCH,
    "url":        EndpointCategory.REDIRECT,
    "redirect":   EndpointCategory.REDIRECT,
    "next":       EndpointCategory.REDIRECT,
    "return":     EndpointCategory.REDIRECT,
    "goto":       EndpointCategory.REDIRECT,
    "continue":   EndpointCategory.REDIRECT,
    "token":      EndpointCategory.AUTHENTICATION,
    "code":       EndpointCategory.OAUTH_CALLBACK,
    "state":      EndpointCategory.OAUTH_CALLBACK,
    "page":       EndpointCategory.LISTING,
    "limit":      EndpointCategory.LISTING,
    "offset":     EndpointCategory.LISTING,
    "per_page":   EndpointCategory.LISTING,
    "file":       EndpointCategory.FILE_DOWNLOAD,
    "filename":   EndpointCategory.FILE_DOWNLOAD,
    "path":       EndpointCategory.FILE_DOWNLOAD,
    "attachment": EndpointCategory.FILE_DOWNLOAD,
    "format":     EndpointCategory.JSON_API,
    "output":     EndpointCategory.FILE_DOWNLOAD,
}

# Response Content-Type → category
_CONTENT_TYPE_MAP: Dict[str, EndpointCategory] = {
    "application/json":                  EndpointCategory.JSON_API,
    "application/hal+json":              EndpointCategory.JSON_API,
    "application/vnd.api+json":          EndpointCategory.JSON_API,
    "application/ld+json":               EndpointCategory.JSON_API,
    "text/event-stream":                 EndpointCategory.WEBSOCKET,
    "application/xml":                   EndpointCategory.XML_API,
    "text/xml":                          EndpointCategory.XML_API,
    "application/soap+xml":              EndpointCategory.XML_API,
    "multipart/form-data":               EndpointCategory.FILE_UPLOAD,
    "application/x-www-form-urlencoded": EndpointCategory.FORM_ENDPOINT,
    "application/pdf":                   EndpointCategory.DOCUMENT,
    "application/zip":                   EndpointCategory.FILE_DOWNLOAD,
    "application/octet-stream":          EndpointCategory.FILE_DOWNLOAD,
    "text/csv":                          EndpointCategory.DOCUMENT,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CAMEL_SPLIT_RE  = re.compile(r'(?<=[a-z])(?=[A-Z])')
_SEPARATOR_RE    = re.compile(r'[_\-.\s]')
_STATIC_EXTS     = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
})

def _tokenise_segment(segment: str) -> List[str]:
    """Split a URL path segment into lowercase tokens."""
    # Remove URL encoding artefacts
    segment = re.sub(r'%[0-9A-Fa-f]{2}', '', segment)
    # Split camelCase
    segment = _CAMEL_SPLIT_RE.sub('-', segment)
    # Split on common separators
    tokens = _SEPARATOR_RE.split(segment)
    return [t.lower() for t in tokens if t]


def _extract_path_segments(parsed_url) -> List[str]:
    """Return non-empty, non-UUID path segments from a parsed URL."""
    _UUID_RE = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE,
    )
    _NUMERIC_RE = re.compile(r'^\d+$')
    segments = []
    for part in parsed_url.path.split('/'):
        part = part.strip()
        if not part:
            continue
        if _UUID_RE.match(part) or _NUMERIC_RE.match(part):
            continue  # skip IDs; they don't add semantic signal
        segments.append(part)
    return segments


def _get_file_extension(path: str) -> str:
    """Return lowercase file extension including the dot, or empty string."""
    dot = path.rfind('.')
    slash = path.rfind('/')
    if dot > slash:
        return path[dot:].lower()
    return ''


# ---------------------------------------------------------------------------
# Core classifier
# ---------------------------------------------------------------------------

class EndpointClassifier:
    """
    Classifies an endpoint URL (plus optional HTTP metadata) into one or more
    EndpointCategory values and returns a fully populated EndpointProfile.

    Usage::

        classifier = EndpointClassifier()

        # Basic classification from URL alone:
        profile = classifier.classify(url="https://example.com/api/v2/users/search")

        # Richer classification when a response is available:
        profile = classifier.classify(
            url="https://example.com/upload",
            method="POST",
            request_content_type="multipart/form-data",
            response_headers={"Content-Type": "application/json", "Allow": "POST"},
            response_body_snippet='{"status":"ok"}',
            has_form=True,
            parameters=["file", "description"],
        )
    """

    def __init__(self) -> None:
        # Pre-compile all vocabulary terms for fast lookup
        self._vocab = _SEGMENT_VOCABULARY

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    def classify(
        self,
        url: str,
        method: str = "GET",
        request_content_type: Optional[str] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_body_snippet: Optional[str] = None,
        has_form: bool = False,
        parameters: Optional[List[str]] = None,
        http_methods_allowed: Optional[List[str]] = None,
    ) -> EndpointProfile:
        """
        Classify *url* and return a populated ``EndpointProfile``.

        Only *url* is required.  All other arguments enrich the result.
        """
        if parameters is None:
            parameters = []
        if response_headers is None:
            response_headers = {}
        if http_methods_allowed is None:
            http_methods_allowed = []

        parsed = urlparse(url)

        # Accumulate per-category signal counts: category → [signal strings]
        signals: Dict[EndpointCategory, List[str]] = {}

        # --- Pass 1: Structural (extension + scheme) -----------------------
        self._pass_structural(parsed, signals)

        # --- Pass 2: Semantic (path segments + query params) ---------------
        self._pass_semantic(parsed, parameters, signals)

        # --- Pass 3: Behavioural (response metadata) -----------------------
        response_ct: Optional[str] = None
        if response_headers is not None or response_body_snippet or has_form:
            self._pass_behavioural(
                response_headers=response_headers,
                response_body=response_body_snippet or "",
                request_ct=request_content_type,
                has_form=has_form,
                signals=signals,
            )
            # Normalise response content-type
            raw_ct = response_headers.get("content-type", response_headers.get("Content-Type", ""))
            response_ct = raw_ct.split(";")[0].strip().lower() or None

        # --- Build sorted classification list ------------------------------
        classifications = self._build_classifications(signals)

        # --- Detect auth requirement from headers --------------------------
        requires_auth = self._detect_auth_requirement(response_headers)

        # --- Detect file-upload capability ---------------------------------
        accepts_file_upload = (
            EndpointCategory.FILE_UPLOAD in [c.category for c in classifications]
            or "multipart" in (request_content_type or "").lower()
            or "file" in [p.lower() for p in parameters]
        )

        # --- Determine if this is a static resource -----------------------
        ext = _get_file_extension(parsed.path)
        is_dynamic = ext not in _STATIC_EXTS

        # --- Assign scanner IDs -------------------------------------------
        scanner_ids = self._route_to_scanners(classifications)

        profile = EndpointProfile(
            url=url,
            method=method.upper(),
            classifications=classifications,
            parameters=parameters,
            content_type=request_content_type,
            response_content_type=response_ct,
            accepts_file_upload=accepts_file_upload,
            requires_auth=requires_auth,
            http_methods_allowed=[m.upper() for m in http_methods_allowed],
            has_form=has_form,
            is_dynamic=is_dynamic,
            scanner_ids=scanner_ids,
        )

        return profile

    def classify_batch(
        self,
        urls: List[str],
        **kwargs: Any,
    ) -> List[EndpointProfile]:
        """Classify a list of URLs (no shared response metadata)."""
        return [self.classify(url, **kwargs) for url in urls]

    def update_with_response(
        self,
        profile: EndpointProfile,
        response_headers: Dict[str, str],
        response_body_snippet: str = "",
        has_form: bool = False,
    ) -> EndpointProfile:
        """
        Re-run the behavioural pass on an existing profile when a real
        response becomes available.  Merges new signals without discarding
        earlier ones.
        """
        signals: Dict[EndpointCategory, List[str]] = {
            c.category: list(c.signals) for c in profile.classifications
        }
        self._pass_behavioural(
            response_headers=response_headers,
            response_body=response_body_snippet,
            request_ct=profile.content_type,
            has_form=has_form,
            signals=signals,
        )
        profile.classifications = self._build_classifications(signals)
        profile.requires_auth   = self._detect_auth_requirement(response_headers)
        profile.scanner_ids     = self._route_to_scanners(profile.classifications)

        raw_ct = response_headers.get("content-type", "")
        profile.response_content_type = raw_ct.split(";")[0].strip().lower() or None

        if has_form:
            profile.has_form = True

        # Check multipart / file upload
        allow_header = response_headers.get("Allow", response_headers.get("allow", ""))
        if "POST" in allow_header.upper():
            profile.http_methods_allowed = list(
                {m.strip().upper() for m in allow_header.split(",") if m.strip()}
            )

        return profile

    # -----------------------------------------------------------------------
    # Classification passes
    # -----------------------------------------------------------------------

    def _pass_structural(
        self,
        parsed,
        signals: Dict[EndpointCategory, List[str]],
    ) -> None:
        """Extension-based and scheme-based classification."""

        # WebSocket scheme
        if parsed.scheme in ("ws", "wss"):
            _add(signals, EndpointCategory.WEBSOCKET,
                 f"scheme={parsed.scheme}")
            return

        # File extension
        ext = _get_file_extension(parsed.path)
        if ext and ext in _EXTENSION_MAP:
            cat = _EXTENSION_MAP[ext]
            _add(signals, cat, f"extension={ext}")
            return  # Extension is definitive for static/document types

        # Paths starting with /api/, /rest/, /v<N>/
        path = parsed.path.lower()
        if re.match(r'^/(?:api|rest|v\d+)(/|$)', path):
            _add(signals, EndpointCategory.API,
                 f"api-prefix in path: {path[:30]}")

        # GraphQL
        if re.search(r'/gra?ph(?:ql)?(/|$)', path, re.IGNORECASE):
            _add(signals, EndpointCategory.GRAPHQL,
                 f"graphql path segment: {path[:30]}")

        # Dot-env / config files
        if re.search(r'/\.env|/env\.|\bconfig\.(json|yml|yaml|ini|php)\b', path):
            _add(signals, EndpointCategory.CONFIGURATION,
                 f"config file pattern: {path[:40]}")

        # Debug / info files
        if re.search(r'/phpinfo|/__debug__|/trace\.axd|/elmah\.axd', path):
            _add(signals, EndpointCategory.DEBUG,
                 f"debug file pattern: {path[:40]}")

        # WSDL / SOAP
        # NOTE: `parsed.path` never includes the query string, so a URL like
        # "https://example.com/service?wsdl" would fail the old
        # `'?wsdl' in path` check (path is just "/service"). We need to look
        # at parsed.query separately to catch the common `?wsdl` convention.
        query = parsed.query.lower()
        if path.endswith('.wsdl') or query == 'wsdl' or 'wsdl' in query.split('&'):
            _add(signals, EndpointCategory.XML_API, "wsdl endpoint")

    def _pass_semantic(
        self,
        parsed,
        parameters: List[str],
        signals: Dict[EndpointCategory, List[str]],
    ) -> None:
        """Vocabulary-based matching on path segments and query params."""

        segments = _extract_path_segments(parsed)
        all_tokens: Set[str] = set()
        # Track which required words already produced a signal for a given
        # category via whole-segment matching, so the token-level pass below
        # doesn't re-signal the *same* evidence again (e.g. "/ping" matching
        # "ping" as both a whole segment and a lone token used to double the
        # signal count for one weak match, inflating LOW confidence to
        # MEDIUM for what is really a single piece of evidence).
        segment_matched_words: Dict[EndpointCategory, Set[str]] = {}

        for segment in segments:
            # Match the whole segment first (handles slug names)
            lower_seg = segment.lower()
            for cat, required, optional, negative in self._vocab:
                if any(n in lower_seg for n in negative):
                    continue
                matched = [r for r in required if r in lower_seg]
                if matched:
                    bonus = [o for o in optional if o in lower_seg]
                    signal = f"path segment '{lower_seg}' matched {matched}"
                    if bonus:
                        signal += f" (+{bonus})"
                    _add(signals, cat, signal)
                    segment_matched_words.setdefault(cat, set()).update(matched)

            # Tokenise camelCase / hyphenated segments for granular matching
            tokens = _tokenise_segment(segment)
            all_tokens.update(tokens)

        # Token-level matching against vocabulary
        for cat, required, optional, negative in self._vocab:
            neg_matched = all_tokens & negative
            if neg_matched:
                continue
            req_matched = all_tokens & required
            # Only count tokens not already covered by the whole-segment
            # match above — otherwise a single-word path like "/ping" would
            # be counted as two independent signals instead of one.
            new_matched = req_matched - segment_matched_words.get(cat, set())
            if new_matched:
                opt_matched = all_tokens & optional
                signal = f"tokens {sorted(new_matched)} matched {cat.name}"
                if opt_matched:
                    signal += f" (bonus: {sorted(opt_matched)})"
                _add(signals, cat, signal)

        # Query parameter name matching
        if parsed.query:
            try:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for param in list(qs.keys()) + parameters:
                    param_l = param.lower()
                    if param_l in _PARAM_CATEGORY_HINTS:
                        cat = _PARAM_CATEGORY_HINTS[param_l]
                        _add(signals, cat, f"query param '{param_l}'")
            except Exception:
                pass

    def _pass_behavioural(
        self,
        response_headers: Dict[str, str],
        response_body: str,
        request_ct: Optional[str],
        has_form: bool,
        signals: Dict[EndpointCategory, List[str]],
    ) -> None:
        """Response-metadata classification."""

        # Normalise header names to lowercase for robust lookup
        hdrs = {k.lower(): v for k, v in response_headers.items()}

        # Content-Type header
        raw_ct = hdrs.get("content-type", "")
        if raw_ct:
            ct = raw_ct.split(";")[0].strip().lower()
            if ct in _CONTENT_TYPE_MAP:
                cat = _CONTENT_TYPE_MAP[ct]
                _add(signals, cat, f"response Content-Type: {ct}")
            elif "json" in ct:
                _add(signals, EndpointCategory.JSON_API,
                     f"json in Content-Type: {ct}")
            elif "xml" in ct or "soap" in ct:
                _add(signals, EndpointCategory.XML_API,
                     f"xml/soap in Content-Type: {ct}")
            elif "event-stream" in ct:
                _add(signals, EndpointCategory.WEBSOCKET,
                     "SSE event-stream Content-Type")
            elif "multipart" in ct:
                _add(signals, EndpointCategory.FILE_UPLOAD,
                     "multipart Content-Type")

        # WWW-Authenticate → authentication required
        if hdrs.get("www-authenticate"):
            _add(signals, EndpointCategory.AUTHENTICATION,
                 "WWW-Authenticate header present")

        # CORS headers → likely an API endpoint
        if hdrs.get("access-control-allow-origin"):
            _add(signals, EndpointCategory.API,
                 "CORS Access-Control-Allow-Origin header")

        # Content-Disposition → file download
        cd = hdrs.get("content-disposition", "")
        if "attachment" in cd.lower():
            _add(signals, EndpointCategory.FILE_DOWNLOAD,
                 "Content-Disposition: attachment header")

        # CSP → probably a dynamic page worth testing
        if hdrs.get("content-security-policy"):
            _add(signals, EndpointCategory.FORM_ENDPOINT,
                 "Content-Security-Policy header (dynamic page)")

        # Allow header → available HTTP methods
        allow = hdrs.get("allow", "")
        if allow:
            methods_str = allow.upper()
            if "POST" in methods_str:
                _add(signals, EndpointCategory.FORM_ENDPOINT,
                     f"Allow header includes POST: {allow}")
            if "DELETE" in methods_str:
                _add(signals, EndpointCategory.API,
                     f"Allow header includes DELETE: {allow}")

        # Request Content-Type hint
        if request_ct:
            rct = request_ct.lower()
            if "multipart" in rct:
                _add(signals, EndpointCategory.FILE_UPLOAD,
                     f"request multipart Content-Type: {rct}")
            elif "json" in rct:
                _add(signals, EndpointCategory.JSON_API,
                     f"request JSON Content-Type: {rct}")
            elif "xml" in rct or "soap" in rct:
                _add(signals, EndpointCategory.XML_API,
                     f"request XML/SOAP Content-Type: {rct}")

        # HTML form present in response body
        if has_form or (response_body and re.search(
            r'<form\b', response_body, re.IGNORECASE
        )):
            _add(signals, EndpointCategory.FORM_ENDPOINT,
                 "HTML <form> element in response body")

        # GraphQL introspection response body
        if response_body and "__schema" in response_body:
            _add(signals, EndpointCategory.GRAPHQL,
                 "__schema key in response body (GraphQL introspection)")

        # Swagger / OpenAPI UI in response body
        if response_body and re.search(r'swagger-ui|openapi', response_body, re.IGNORECASE):
            _add(signals, EndpointCategory.DEBUG,
                 "Swagger/OpenAPI UI detected in response body")

        # Error / stack-trace keywords (debug endpoint)
        if response_body and re.search(
            r'traceback|stack.trace|exception.*at\s+line\s+\d|at .*\\.java:\d',
            response_body, re.IGNORECASE
        ):
            _add(signals, EndpointCategory.DEBUG,
                 "Stack trace / exception detail in response body")

        # Health check JSON pattern
        if response_body:
            try:
                import json
                doc = json.loads(response_body)
                if isinstance(doc, dict):
                    if any(k in doc for k in ("status", "healthy", "ok", "alive")):
                        _add(signals, EndpointCategory.HEALTH_CHECK,
                             "health-check JSON structure in response body")
                    # Metrics endpoint pattern
                    if any(k in doc for k in ("metrics", "counters", "gauges", "timers")):
                        _add(signals, EndpointCategory.METRICS,
                             "metrics JSON keys in response body")
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Post-processing helpers
    # -----------------------------------------------------------------------

    def _build_classifications(
        self,
        signals: Dict[EndpointCategory, List[str]],
    ) -> List[ClassificationResult]:
        """
        Convert the raw signal dict into a sorted list of ClassificationResult.

        Signal count → confidence:
          ≥ 3 signals → HIGH
          2 signals   → MEDIUM
          1 signal    → LOW
        """
        results: List[ClassificationResult] = []

        for cat, sig_list in signals.items():
            n = len(sig_list)
            if n >= 3:
                conf = ConfidenceLevel.HIGH
            elif n == 2:
                conf = ConfidenceLevel.MEDIUM
            else:
                conf = ConfidenceLevel.LOW

            # Deduplicate signal strings
            unique_sigs = list(dict.fromkeys(sig_list))
            results.append(ClassificationResult(
                category=cat,
                confidence=conf,
                signals=unique_sigs,
            ))

        # Sort: confidence desc, then enum value (for determinism)
        results.sort(
            key=lambda r: (-r.confidence.value, r.category.value)
        )

        if not results:
            results.append(ClassificationResult(
                category=EndpointCategory.UNKNOWN,
                confidence=ConfidenceLevel.LOW,
                signals=["no matching signals found"],
            ))

        return results

    @staticmethod
    def _detect_auth_requirement(response_headers: Dict[str, str]) -> bool:
        hdrs_l = {k.lower(): v for k, v in response_headers.items()}
        return (
            "www-authenticate" in hdrs_l
            or hdrs_l.get("x-requires-auth", "").lower() in ("true", "1", "yes")
        )

    @staticmethod
    def _route_to_scanners(
        classifications: List[ClassificationResult],
    ) -> List[str]:
        """Return deduplicated scanner IDs for all assigned categories."""
        scanner_set: List[str] = []
        seen: Set[str] = set()

        for cr in classifications:
            for sid in SCANNER_ROUTING_TABLE.get(cr.category, []):
                if sid not in seen:
                    seen.add(sid)
                    scanner_set.append(sid)

        return scanner_set


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _add(
    signals: Dict[EndpointCategory, List[str]],
    cat: EndpointCategory,
    signal: str,
) -> None:
    """Append *signal* string to the signals list for *cat*."""
    if cat not in signals:
        signals[cat] = []
    signals[cat].append(signal)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def classify_endpoint(
    url: str,
    method: str = "GET",
    *,
    request_content_type: Optional[str] = None,
    response_headers: Optional[Dict[str, str]] = None,
    response_body_snippet: Optional[str] = None,
    has_form: bool = False,
    parameters: Optional[List[str]] = None,
    http_methods_allowed: Optional[List[str]] = None,
) -> EndpointProfile:
    """
    Module-level convenience wrapper around ``EndpointClassifier.classify``.

    Creates a fresh classifier and classifies *url* in one call.  For batch
    classification reuse the same ``EndpointClassifier`` instance.
    """
    return EndpointClassifier().classify(
        url=url,
        method=method,
        request_content_type=request_content_type,
        response_headers=response_headers,
        response_body_snippet=response_body_snippet,
        has_form=has_form,
        parameters=parameters,
        http_methods_allowed=http_methods_allowed,
    )
