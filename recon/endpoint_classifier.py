# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Endpoint Classification Engine — Part 12 of the Intelligence Layer.

Every endpoint discovered by the Crawling Engine, Browser Automation Layer,
JavaScript Analysis Engine, API Discovery Engine, and WebSocket Framework is
funnelled through this classifier before it reaches any scanner.

The classifier answers three questions for each endpoint:

  1. *What is this endpoint?*  — its primary functional category and zero or
     more secondary tags that describe additional characteristics.
  2. *How risky is it?*       — a numeric risk score (0–100) derived from the
     combination of category, HTTP methods, parameter hints, and contextual
     evidence gathered during reconnaissance.
  3. *Who should test it?*   — the ordered list of scanner classes that are
     most likely to find vulnerabilities at this specific endpoint, avoiding
     wasted requests against irrelevant attack surfaces.

Classification is multi-layered:

  Layer 1 — URL Pattern Matching
      Regex rules against the path, file extension, and query-string keys.
      Fast O(1)-ish triage that eliminates static assets quickly.

  Layer 2 — HTTP Method / Content-Type Analysis
      Endpoints that accept PUT/DELETE/PATCH receive an elevated risk multiplier.
      Endpoints that accept multipart/form-data are flagged for file-upload tests.
      Endpoints that respond with application/json are eligible for API tests.

  Layer 3 — Parameter Fingerprinting
      Parameter names are matched against large name-based rule sets to detect
      ID parameters (→ IDOR), SQL-like parameters (→ SQLi), redirect parameters
      (→ Open Redirect), template parameters (→ SSTI), file parameters
      (→ Path Traversal / LFI), and so on.

  Layer 4 — Response Characteristic Analysis
      Timing variability, body size variance, error-message leakage, and
      technology-specific response patterns are used to refine the classification
      produced by the earlier layers.

  Layer 5 — Knowledge-Base Cross-Reference
      The fingerprinted technology stack (from the Fingerprinting Framework) is
      consulted to add framework-specific tags (e.g., "django-admin-endpoint",
      "wordpress-xmlrpc", "graphql-playground") and to activate specialised
      scanner modules.

Output
------
Each ``ClassifiedEndpoint`` object carries:
  • The original ``RawEndpoint`` input (URL, methods, headers, parameters)
  • A primary ``EndpointCategory`` enum value
  • A frozenset of ``EndpointTag`` values (secondary characteristics)
  • A float ``risk_score`` in [0.0, 100.0]
  • A priority-ordered list of ``ScannerHint`` objects
  • A ``ClassificationEvidence`` record explaining every decision

The engine is fully async and processes endpoints in parallel batches.
It is designed to be called once per scan after the discovery phase completes,
producing a ``ClassificationReport`` that drives the entire testing phase.
"""

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Standard-library & internal imports                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    TYPE_CHECKING,
)
from urllib.parse import urlparse, parse_qs, unquote_plus

from ..core.http_client import HTTPClient, HTTPResponse
from ..core.target import ScanTarget
from ..utils.helpers import normalize_url

if TYPE_CHECKING:
    from .fingerprinter import FingerprintReport
    from .knowledge_base import KnowledgeBase

# ═══════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════


class EndpointCategory(str, Enum):
    """Primary functional classification of an endpoint."""

    # ── Authentication & Identity ────────────────────────────────────────
    AUTHENTICATION = "authentication"
    """Login, logout, token exchange, SSO callback, MFA challenge."""

    REGISTRATION = "registration"
    """Account creation, invite acceptance, email verification."""

    PASSWORD_RESET = "password_reset"
    """Password-reset initiation, token validation, new-password submission."""

    MFA = "mfa"
    """TOTP / HOTP verification, backup-code submission, device enrollment."""

    SSO = "sso"
    """SAML ACS, OAuth callback, OIDC token endpoint, CAS service ticket."""

    # ── Core Application Functions ───────────────────────────────────────
    SEARCH = "search"
    """Free-text or structured search, autocomplete, faceted filtering."""

    FILE_UPLOAD = "file_upload"
    """Any endpoint that accepts file data (multipart, base64-in-JSON, …)."""

    FILE_DOWNLOAD = "file_download"
    """Static or dynamic file serving — PDF, CSV, image, archive, …"""

    ADMIN = "admin"
    """Administrative panel, user management, system configuration."""

    PAYMENT = "payment"
    """Checkout, invoice, subscription, refund, payment method management."""

    PROFILE = "profile"
    """User profile view / update, avatar upload, preference storage."""

    MESSAGING = "messaging"
    """Chat, notification, inbox, comment, feedback submission."""

    EXPORT = "export"
    """Report generation, data export (CSV/Excel/PDF), bulk download."""

    IMPORT = "import"
    """Bulk data import, CSV/XML/JSON upload for processing."""

    WEBHOOK = "webhook"
    """Inbound webhook receiver, event listener, callback endpoint."""

    # ── API Surface ──────────────────────────────────────────────────────
    API_REST = "api_rest"
    """Standard REST endpoint returning JSON/XML."""

    API_GRAPHQL = "api_graphql"
    """GraphQL query / mutation / subscription endpoint."""

    API_GRPC_WEB = "api_grpc_web"
    """gRPC-Web transcoding endpoint."""

    API_SOAP = "api_soap"
    """SOAP/WSDL-based service endpoint."""

    API_WEBSOCKET = "api_websocket"
    """WebSocket upgrade endpoint."""

    API_SSE = "api_sse"
    """Server-Sent Events stream endpoint."""

    # ── Infrastructure & Health ──────────────────────────────────────────
    HEALTH_CHECK = "health_check"
    """Liveness / readiness probes, ping endpoints."""

    CONFIGURATION = "configuration"
    """Exposed configuration endpoints (.env, config.json, settings files)."""

    DEBUG = "debug"
    """Debug consoles, profiler endpoints, stack-trace emitters."""

    METRICS = "metrics"
    """Prometheus /metrics, StatsD, application performance data."""

    DOCUMENTATION = "documentation"
    """Swagger UI, ReDoc, API Blueprint, Javadoc, developer portals."""

    # ── Static Resources ─────────────────────────────────────────────────
    STATIC_RESOURCE = "static_resource"
    """JavaScript, CSS, images, fonts, icons — low attack surface."""

    SOURCE_MAP = "source_map"
    """Browser source maps (.map files) — high intelligence value."""

    # ── Miscellaneous ────────────────────────────────────────────────────
    REDIRECT = "redirect"
    """Endpoints whose primary purpose is URL redirection."""

    ERROR_PAGE = "error_page"
    """Custom 404, 500, maintenance pages."""

    UNKNOWN = "unknown"
    """Endpoint that could not be classified by any rule."""


class EndpointTag(str, Enum):
    """Secondary characteristics that augment the primary category."""

    # Parameter traits
    ACCEPTS_USER_ID = "accepts_user_id"
    ACCEPTS_FILE_PATH = "accepts_file_path"
    ACCEPTS_URL = "accepts_url"
    ACCEPTS_TEMPLATE = "accepts_template"
    ACCEPTS_SQL_LIKE = "accepts_sql_like"
    ACCEPTS_COMMAND = "accepts_command"
    ACCEPTS_XML = "accepts_xml"
    ACCEPTS_JSON_BODY = "accepts_json_body"
    ACCEPTS_MULTIPART = "accepts_multipart"
    ACCEPTS_RAW_BINARY = "accepts_raw_binary"
    ACCEPTS_CALLBACK = "accepts_callback"          # JSONP
    ACCEPTS_REDIRECT_URL = "accepts_redirect_url"
    ACCEPTS_JWT = "accepts_jwt"
    ACCEPTS_CORS_SENSITIVE = "accepts_cors_sensitive"

    # Method traits
    HAS_GET = "has_get"
    HAS_POST = "has_post"
    HAS_PUT = "has_put"
    HAS_PATCH = "has_patch"
    HAS_DELETE = "has_delete"
    HAS_OPTIONS = "has_options"

    # Authentication traits
    REQUIRES_AUTH = "requires_auth"
    AUTH_OPTIONAL = "auth_optional"
    NO_AUTH_REQUIRED = "no_auth_required"
    USES_BEARER = "uses_bearer"
    USES_API_KEY = "uses_api_key"
    USES_BASIC = "uses_basic"
    USES_COOKIE = "uses_cookie"
    USES_OAUTH = "uses_oauth"

    # Response traits
    RETURNS_JSON = "returns_json"
    RETURNS_XML = "returns_xml"
    RETURNS_HTML = "returns_html"
    RETURNS_BINARY = "returns_binary"
    RETURNS_STREAM = "returns_stream"
    REFLECTS_INPUT = "reflects_input"
    TIMING_VARIABLE = "timing_variable"
    SIZE_VARIABLE = "size_variable"

    # Risk amplifiers
    THIRD_PARTY_INTEGRATION = "third_party_integration"
    PROCESSES_EXTERNAL_URL = "processes_external_url"
    PROCESSES_UPLOADED_FILE = "processes_uploaded_file"
    EXECUTES_USER_CODE = "executes_user_code"
    SENDS_EMAIL = "sends_email"
    SENDS_SMS = "sends_sms"
    PRIVILEGED_OPERATION = "privileged_operation"
    BULK_OPERATION = "bulk_operation"
    RATE_LIMITED = "rate_limited"
    NOT_RATE_LIMITED = "not_rate_limited"
    CSRF_TOKEN_PRESENT = "csrf_token_present"
    NO_CSRF_TOKEN = "no_csrf_token"
    CORS_WILDCARD = "cors_wildcard"
    CORS_REFLECTS_ORIGIN = "cors_reflects_origin"

    # Technology-specific
    FRAMEWORK_DJANGO = "framework_django"
    FRAMEWORK_RAILS = "framework_rails"
    FRAMEWORK_LARAVEL = "framework_laravel"
    FRAMEWORK_SPRING = "framework_spring"
    FRAMEWORK_EXPRESS = "framework_express"
    FRAMEWORK_NEXTJS = "framework_nextjs"
    CMS_WORDPRESS = "cms_wordpress"
    CMS_DRUPAL = "cms_drupal"
    CMS_JOOMLA = "cms_joomla"

    # Discovery source
    FOUND_IN_JS = "found_in_js"
    FOUND_BY_CRAWLER = "found_by_crawler"
    FOUND_BY_BROWSER = "found_by_browser"
    FOUND_IN_OPENAPI = "found_in_openapi"
    FOUND_IN_SITEMAP = "found_in_sitemap"

    # Confidence modifiers
    HIGH_CONFIDENCE = "high_confidence"
    LOW_CONFIDENCE = "low_confidence"


class ScannerPriority(int, Enum):
    """Ordering hint for scanner execution."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    SKIP = 5


# ═══════════════════════════════════════════════════════════════════════════
# Data-classes
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class RawEndpoint:
    """
    Minimal normalised representation of a discovered endpoint.

    All upstream discovery engines produce ``RawEndpoint`` objects.
    Any field that could not be determined during discovery is left as the
    appropriate default (empty collection or ``None``).
    """

    url: str
    """Fully-qualified URL including scheme, host, path, and query string."""

    methods: FrozenSet[str] = field(default_factory=frozenset)
    """HTTP verbs observed or inferred for this endpoint.  Upper-cased."""

    parameters: Dict[str, str] = field(default_factory=dict)
    """
    Observed parameter names mapped to a sample value (may be empty string).
    Includes query-string, form-body, and path-template parameters.
    """

    headers: Dict[str, str] = field(default_factory=dict)
    """Request headers that appear necessary or interesting for this endpoint."""

    content_types_accepted: FrozenSet[str] = field(default_factory=frozenset)
    """Content-Type values the endpoint is known to consume."""

    content_types_returned: FrozenSet[str] = field(default_factory=frozenset)
    """Content-Type values observed in responses from this endpoint."""

    status_code: Optional[int] = None
    """Last observed HTTP status code, if any."""

    response_time_ms: Optional[float] = None
    """Last observed round-trip time in milliseconds."""

    response_size_bytes: Optional[int] = None
    """Last observed response body size in bytes."""

    source: str = "unknown"
    """Which discovery mechanism found this endpoint (crawler / js / browser …)."""

    evidence: List[str] = field(default_factory=list)
    """Human-readable strings describing how this endpoint was discovered."""

    @property
    def parsed(self):  # noqa: ANN201
        return urlparse(self.url)

    @property
    def path(self) -> str:
        return self.parsed.path

    @property
    def extension(self) -> str:
        path = self.parsed.path
        dot = path.rfind(".")
        slash = path.rfind("/")
        if dot > slash:
            return path[dot + 1:].lower()
        return ""

    @property
    def query_params(self) -> Dict[str, List[str]]:
        return parse_qs(self.parsed.query, keep_blank_values=True)


@dataclass
class ClassificationEvidence:
    """Audit trail explaining every classification decision."""

    matched_rules: List[str] = field(default_factory=list)
    """Human-readable descriptions of each rule that fired."""

    category_votes: Dict[str, int] = field(default_factory=dict)
    """Votes cast for each category before the winner was selected."""

    tag_reasons: Dict[str, str] = field(default_factory=dict)
    """Maps each applied tag to the rule / observation that triggered it."""

    risk_factors: List[Tuple[str, float]] = field(default_factory=list)
    """(description, delta) pairs explaining the final risk score."""

    scanner_rationale: Dict[str, str] = field(default_factory=dict)
    """Maps scanner name to the reason it was selected."""

    processing_time_ms: float = 0.0
    """Time taken to classify this single endpoint."""


@dataclass
class ScannerHint:
    """Instruction to a downstream scanner."""

    scanner_name: str
    """Canonical name of the scanner class."""

    priority: ScannerPriority
    """How urgently this scanner should test this endpoint."""

    parameter_focus: List[str] = field(default_factory=list)
    """Parameters that the scanner should prioritise."""

    custom_context: Dict[str, Any] = field(default_factory=dict)
    """Arbitrary key/value context to pass to the scanner at runtime."""

    rationale: str = ""
    """Short human-readable explanation of why this scanner was selected."""


@dataclass
class ClassifiedEndpoint:
    """
    Fully classified endpoint ready for the testing phase.

    This is the primary output unit of the Endpoint Classification Engine.
    """

    raw: RawEndpoint
    """Original endpoint data from the discovery phase."""

    category: EndpointCategory
    """Primary functional classification."""

    tags: FrozenSet[EndpointTag]
    """Secondary characteristics."""

    risk_score: float
    """Composite risk score in [0.0, 100.0] — higher means more dangerous."""

    scanner_hints: List[ScannerHint]
    """Priority-ordered list of scanners that should test this endpoint."""

    evidence: ClassificationEvidence
    """Audit trail for the classification decisions."""

    # ── Convenience helpers ──────────────────────────────────────────────

    @property
    def url(self) -> str:
        return self.raw.url

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 70.0

    @property
    def is_authentication_related(self) -> bool:
        return self.category in (
            EndpointCategory.AUTHENTICATION,
            EndpointCategory.REGISTRATION,
            EndpointCategory.PASSWORD_RESET,
            EndpointCategory.MFA,
            EndpointCategory.SSO,
        )

    @property
    def is_file_related(self) -> bool:
        return self.category in (
            EndpointCategory.FILE_UPLOAD,
            EndpointCategory.FILE_DOWNLOAD,
        ) or EndpointTag.ACCEPTS_FILE_PATH in self.tags

    @property
    def is_api(self) -> bool:
        return self.category in (
            EndpointCategory.API_REST,
            EndpointCategory.API_GRAPHQL,
            EndpointCategory.API_GRPC_WEB,
            EndpointCategory.API_SOAP,
            EndpointCategory.API_WEBSOCKET,
            EndpointCategory.API_SSE,
        )

    def scanner_names_at_priority(
        self, max_priority: ScannerPriority = ScannerPriority.MEDIUM
    ) -> List[str]:
        """Return scanner names whose priority is <= max_priority."""
        return [
            h.scanner_name
            for h in self.scanner_hints
            if h.priority <= max_priority
        ]


@dataclass
class ClassificationReport:
    """Aggregated output of the Endpoint Classification Engine for one scan."""

    target: ScanTarget
    classified: List[ClassifiedEndpoint] = field(default_factory=list)
    total_raw: int = 0
    skipped_static: int = 0
    processing_time_ms: float = 0.0

    # ── Grouped views ────────────────────────────────────────────────────

    def by_category(
        self, category: EndpointCategory
    ) -> List[ClassifiedEndpoint]:
        return [e for e in self.classified if e.category == category]

    def by_tag(self, tag: EndpointTag) -> List[ClassifiedEndpoint]:
        return [e for e in self.classified if tag in e.tags]

    def high_risk(self) -> List[ClassifiedEndpoint]:
        return sorted(
            [e for e in self.classified if e.is_high_risk],
            key=lambda e: e.risk_score,
            reverse=True,
        )

    def scannable_by(
        self,
        scanner_name: str,
        max_priority: ScannerPriority = ScannerPriority.MEDIUM,
    ) -> List[ClassifiedEndpoint]:
        """Return endpoints that should be tested by the given scanner."""
        return [
            e
            for e in self.classified
            if any(
                h.scanner_name == scanner_name and h.priority <= max_priority
                for h in e.scanner_hints
            )
        ]

    @property
    def summary(self) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        for e in self.classified:
            cats[e.category.value] = cats.get(e.category.value, 0) + 1
        return {
            "total_classified": len(self.classified),
            "total_raw": self.total_raw,
            "skipped_static": self.skipped_static,
            "high_risk_count": len(self.high_risk()),
            "categories": cats,
            "processing_time_ms": round(self.processing_time_ms, 1),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Classification Rules (compiled once at import time)
# ═══════════════════════════════════════════════════════════════════════════

# ─── Static extensions that we skip or demote immediately ─────────────────

_STATIC_EXTENSIONS: FrozenSet[str] = frozenset({
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "tiff",
    "woff", "woff2", "ttf", "eot", "otf",
    "css", "scss", "less",
    "mp3", "mp4", "webm", "ogg", "wav", "avi", "mov",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "tar", "gz", "bz2", "7z",
    "txt", "xml", "csv",
})

_SOURCE_MAP_EXTENSIONS: FrozenSet[str] = frozenset({"map"})

_JS_EXTENSIONS: FrozenSet[str] = frozenset({"js", "mjs", "cjs", "ts"})


# ─── Path-pattern → (category, confidence, tags) ─────────────────────────

@dataclass
class _PathRule:
    pattern: re.Pattern
    category: EndpointCategory
    confidence: int          # 1-10; higher wins ties
    tags: Tuple[EndpointTag, ...] = ()
    description: str = ""


def _pr(
    regex: str,
    cat: EndpointCategory,
    conf: int,
    tags: Tuple[EndpointTag, ...] = (),
    desc: str = "",
) -> _PathRule:
    return _PathRule(re.compile(regex, re.IGNORECASE), cat, conf, tags, desc)


_PATH_RULES: List[_PathRule] = [
    # ── Authentication ────────────────────────────────────────────────
    _pr(r"/(api/)?auth/(login|signin|sign[_-]in|session|token)(/|$|\?)",
        EndpointCategory.AUTHENTICATION, 9, desc="auth login path"),
    _pr(r"/(api/)?log[_-]?in(/|$|\?)",
        EndpointCategory.AUTHENTICATION, 9, desc="login path"),
    _pr(r"/(api/)?token(/|$|\?)",
        EndpointCategory.AUTHENTICATION, 7, desc="token endpoint"),
    _pr(r"/oauth2?/(authorize|token|callback|redirect)(/|$|\?)",
        EndpointCategory.SSO, 10, (EndpointTag.USES_OAUTH,), "OAuth path"),
    _pr(r"/saml/(acs|sso|callback|response|metadata)(/|$|\?)",
        EndpointCategory.SSO, 10, desc="SAML path"),
    _pr(r"/oidc/(callback|userinfo|token|authorize)(/|$|\?)",
        EndpointCategory.SSO, 10, desc="OIDC path"),
    _pr(r"/(api/)?log[_-]?out(/|$|\?)",
        EndpointCategory.AUTHENTICATION, 8, desc="logout"),
    _pr(r"/(api/)?sign[_-]?out(/|$|\?)",
        EndpointCategory.AUTHENTICATION, 8, desc="signout"),

    # ── Registration ──────────────────────────────────────────────────
    _pr(r"/(api/)?(register|signup|sign[_-]up|create[_-]account|join)(/|$|\?)",
        EndpointCategory.REGISTRATION, 9, desc="registration"),
    _pr(r"/(api/)?verify[_-]?(email|account)(/|$|\?)",
        EndpointCategory.REGISTRATION, 7, desc="email verification"),
    _pr(r"/invite(/|$|\?)",
        EndpointCategory.REGISTRATION, 6, desc="invite"),

    # ── Password Reset ────────────────────────────────────────────────
    _pr(r"/(api/)?(forgot|reset|recover)[_-]?password(/|$|\?)",
        EndpointCategory.PASSWORD_RESET, 9, desc="password reset"),
    _pr(r"/password/?(reset|forgot|recover|change)(/|$|\?)",
        EndpointCategory.PASSWORD_RESET, 9, desc="password reset"),

    # ── MFA ───────────────────────────────────────────────────────────
    _pr(r"/(api/)?(mfa|2fa|otp|totp|authenticator)(/|$|\?)",
        EndpointCategory.MFA, 9, desc="MFA endpoint"),
    _pr(r"/(api/)?(two[_-]?factor|multi[_-]?factor)(/|$|\?)",
        EndpointCategory.MFA, 9, desc="2FA path"),

    # ── File Upload ───────────────────────────────────────────────────
    _pr(r"/(api/)?(upload|attach|file[_-]?upload|media[_-]?upload)(/|$|\?)",
        EndpointCategory.FILE_UPLOAD, 9,
        (EndpointTag.ACCEPTS_MULTIPART, EndpointTag.PROCESSES_UPLOADED_FILE),
        "upload path"),
    _pr(r"/avatar(/|$|\?)",
        EndpointCategory.FILE_UPLOAD, 7,
        (EndpointTag.ACCEPTS_MULTIPART,), "avatar upload"),
    _pr(r"/import(/|$|\?)",
        EndpointCategory.IMPORT, 8,
        (EndpointTag.ACCEPTS_MULTIPART, EndpointTag.BULK_OPERATION),
        "import path"),

    # ── File Download / Export ────────────────────────────────────────
    _pr(r"/(api/)?(download|export|report)(/|$|\?)",
        EndpointCategory.EXPORT, 8,
        (EndpointTag.BULK_OPERATION,), "export/download"),
    _pr(r"/files?/\w",
        EndpointCategory.FILE_DOWNLOAD, 7,
        (EndpointTag.ACCEPTS_FILE_PATH,), "file path"),

    # ── Admin ─────────────────────────────────────────────────────────
    _pr(r"/(admin|administrator|panel|control[_-]?panel|cp|backoffice|mgmt|management|console)(/|$|\?)",
        EndpointCategory.ADMIN, 10,
        (EndpointTag.PRIVILEGED_OPERATION, EndpointTag.REQUIRES_AUTH),
        "admin path"),
    _pr(r"/wp[_-]?admin(/|$|\?)",
        EndpointCategory.ADMIN, 10,
        (EndpointTag.CMS_WORDPRESS, EndpointTag.PRIVILEGED_OPERATION),
        "WordPress admin"),
    _pr(r"/django[_-]?admin(/|$|\?)",
        EndpointCategory.ADMIN, 10,
        (EndpointTag.FRAMEWORK_DJANGO, EndpointTag.PRIVILEGED_OPERATION),
        "Django admin"),
    _pr(r"/rails/conductor(/|$|\?)",
        EndpointCategory.ADMIN, 10,
        (EndpointTag.FRAMEWORK_RAILS, EndpointTag.PRIVILEGED_OPERATION),
        "Rails conductor"),
    _pr(r"/phpmyadmin(/|$|\?)",
        EndpointCategory.ADMIN, 10,
        (EndpointTag.PRIVILEGED_OPERATION,), "phpMyAdmin"),

    # ── Payment ───────────────────────────────────────────────────────
    _pr(r"/(api/)?(checkout|payment|billing|invoice|subscription|stripe|paypal|pay)(/|$|\?)",
        EndpointCategory.PAYMENT, 9,
        (EndpointTag.PRIVILEGED_OPERATION, EndpointTag.REQUIRES_AUTH),
        "payment path"),

    # ── Profile ───────────────────────────────────────────────────────
    _pr(r"/(api/)?(profile|account|me|user[_-]?settings|preferences)(/|$|\?)",
        EndpointCategory.PROFILE, 7, desc="profile path"),

    # ── Search ────────────────────────────────────────────────────────
    _pr(r"/(api/)?(search|find|query|lookup|autocomplete|suggest)(/|$|\?)",
        EndpointCategory.SEARCH, 8, desc="search path"),

    # ── Messaging ─────────────────────────────────────────────────────
    _pr(r"/(api/)?(message[s]?|chat|comment[s]?|notification[s]?|inbox|mail)(/|$|\?)",
        EndpointCategory.MESSAGING, 7, desc="messaging path"),
    _pr(r"/(api/)?feedback(/|$|\?)",
        EndpointCategory.MESSAGING, 6, desc="feedback"),
    _pr(r"/(api/)?contact(/|$|\?)",
        EndpointCategory.MESSAGING, 6,
        (EndpointTag.SENDS_EMAIL,), "contact form"),

    # ── Webhook ───────────────────────────────────────────────────────
    _pr(r"/(api/)?(webhook[s]?|hook[s]?|callback|event[s]?|notify)(/|$|\?)",
        EndpointCategory.WEBHOOK, 8,
        (EndpointTag.THIRD_PARTY_INTEGRATION,), "webhook path"),

    # ── API — GraphQL ─────────────────────────────────────────────────
    _pr(r"/(graphql|gql|graph)(/|$|\?)",
        EndpointCategory.API_GRAPHQL, 10,
        (EndpointTag.ACCEPTS_JSON_BODY,), "GraphQL path"),

    # ── API — gRPC-Web ────────────────────────────────────────────────
    _pr(r"/(grpc|rpc)(/|$|\?)",
        EndpointCategory.API_GRPC_WEB, 8, desc="gRPC path"),

    # ── API — SOAP ────────────────────────────────────────────────────
    _pr(r"/(soap|wsdl|service[s]?\.asmx)(/|$|\?)",
        EndpointCategory.API_SOAP, 8,
        (EndpointTag.ACCEPTS_XML,), "SOAP path"),

    # ── Health Check ──────────────────────────────────────────────────
    _pr(r"/(health|ping|status|alive|ready|live|actuator/health)(/|$|\?)",
        EndpointCategory.HEALTH_CHECK, 9, desc="health check"),

    # ── Configuration ─────────────────────────────────────────────────
    _pr(r"/\.env(/|$|\?)",
        EndpointCategory.CONFIGURATION, 10,
        (EndpointTag.PRIVILEGED_OPERATION,), ".env file"),
    _pr(r"/(config|settings|configuration)\.?(json|yaml|yml|toml|php|ini)?(/|$|\?)",
        EndpointCategory.CONFIGURATION, 9,
        (EndpointTag.PRIVILEGED_OPERATION,), "config file"),
    _pr(r"/application\.properties(/|$|\?)",
        EndpointCategory.CONFIGURATION, 9,
        (EndpointTag.FRAMEWORK_SPRING,), "Spring config"),

    # ── Debug ─────────────────────────────────────────────────────────
    _pr(r"/(debug|console|shell|repl|tracer|profiler|_debug|__debug__)(/|$|\?)",
        EndpointCategory.DEBUG, 10,
        (EndpointTag.PRIVILEGED_OPERATION, EndpointTag.EXECUTES_USER_CODE),
        "debug path"),
    _pr(r"/(phpdebugbar|debugbar|telescope|horizon)(/|$|\?)",
        EndpointCategory.DEBUG, 10,
        (EndpointTag.PRIVILEGED_OPERATION,), "debug toolbar"),
    _pr(r"/actuator(/|$|\?)",
        EndpointCategory.METRICS, 8,
        (EndpointTag.FRAMEWORK_SPRING,), "Spring Actuator"),

    # ── Metrics ───────────────────────────────────────────────────────
    _pr(r"/(metrics|prometheus|stats)(/|$|\?)",
        EndpointCategory.METRICS, 8, desc="metrics endpoint"),

    # ── Documentation ─────────────────────────────────────────────────
    _pr(r"/(swagger|api[_-]?docs|openapi|redoc|api[_-]?explorer)(/|$|\?)",
        EndpointCategory.DOCUMENTATION, 8, desc="API docs"),

    # ── Redirect ──────────────────────────────────────────────────────
    _pr(r"/(redirect|go|out|link|r|click|track)(/|$|\?)",
        EndpointCategory.REDIRECT, 7,
        (EndpointTag.ACCEPTS_REDIRECT_URL,), "redirect path"),

    # ── Broader REST API  ─────────────────────────────────────────────
    _pr(r"^/api(/v\d+)?/",
        EndpointCategory.API_REST, 5,
        (EndpointTag.ACCEPTS_JSON_BODY,), "generic /api/ prefix"),
    _pr(r"^/v\d+/",
        EndpointCategory.API_REST, 5,
        (EndpointTag.ACCEPTS_JSON_BODY,), "versioned API prefix"),
]


# ─── Parameter name → tag mappings ───────────────────────────────────────

@dataclass
class _ParamRule:
    pattern: re.Pattern
    tag: EndpointTag
    category_vote: Optional[EndpointCategory] = None
    confidence: int = 5
    description: str = ""


def _param(
    regex: str,
    tag: EndpointTag,
    cat: Optional[EndpointCategory] = None,
    conf: int = 5,
    desc: str = "",
) -> _ParamRule:
    return _ParamRule(re.compile(regex, re.IGNORECASE), tag, cat, conf, desc)


_PARAM_RULES: List[_ParamRule] = [
    # ID / resource parameters → IDOR signal
    _param(r"^(user[_-]?id|uid|account[_-]?id|customer[_-]?id|member[_-]?id|owner[_-]?id|author[_-]?id|profile[_-]?id)$",
           EndpointTag.ACCEPTS_USER_ID, conf=9, desc="user ID param"),
    _param(r"^(id|oid|object[_-]?id|resource[_-]?id|entity[_-]?id|record[_-]?id)$",
           EndpointTag.ACCEPTS_USER_ID, conf=6, desc="generic ID param"),
    _param(r"^(order[_-]?id|invoice[_-]?id|ticket[_-]?id|doc[_-]?id|document[_-]?id)$",
           EndpointTag.ACCEPTS_USER_ID, conf=7, desc="resource ID param"),

    # File path parameters → path traversal / LFI
    _param(r"^(file|filename|file[_-]?name|path|filepath|file[_-]?path|template|page|include|load|src|source|dir|directory|folder|attachment|doc)$",
           EndpointTag.ACCEPTS_FILE_PATH,
           EndpointCategory.FILE_DOWNLOAD, 8, "file path param"),

    # URL parameters → SSRF / open redirect
    _param(r"^(url|uri|link|href|target|dest|destination|redirect|return|return[_-]?url|next|goto|callback|redir|continue|forward|location|path)$",
           EndpointTag.ACCEPTS_REDIRECT_URL,
           EndpointCategory.REDIRECT, 8, "URL/redirect param"),
    _param(r"^(endpoint|host|server|api[_-]?url|base[_-]?url|remote|origin|fetch|proxy|resource|load[_-]?url)$",
           EndpointTag.ACCEPTS_URL,
           EndpointCategory.WEBHOOK, 7, "SSRF-prone param"),

    # Template parameters → SSTI
    _param(r"^(template|tmpl|tpl|layout|view|render|format|style|theme)$",
           EndpointTag.ACCEPTS_TEMPLATE, conf=7, desc="template param"),

    # SQL-like → SQLi
    _param(r"^(q|query|search|filter|where|condition|order|sort|limit|offset|page|per[_-]?page|group[_-]?by|having)$",
           EndpointTag.ACCEPTS_SQL_LIKE,
           EndpointCategory.SEARCH, 6, "SQL-like param"),

    # Command / eval → CMDi / SSTI
    _param(r"^(cmd|command|exec|execute|run|eval|sh|bash|shell|process|action|operation|method)$",
           EndpointTag.ACCEPTS_COMMAND, conf=9, desc="command param"),

    # XML / SOAP → XXE
    _param(r"^(xml|body|data|payload|input|content|soap|envelope|document)$",
           EndpointTag.ACCEPTS_XML, conf=5, desc="XML param"),

    # JSONP callback → JSONP injection
    _param(r"^(callback|cb|jsonp|jsoncallback|jsonpCallback)$",
           EndpointTag.ACCEPTS_CALLBACK, conf=8, desc="JSONP callback"),

    # JWT
    _param(r"^(token|access[_-]?token|jwt|bearer|auth[_-]?token|id[_-]?token)$",
           EndpointTag.ACCEPTS_JWT, conf=7, desc="JWT param"),

    # Email → SSRF / send-email
    _param(r"^(email|mail[_-]?to|recipient|to|cc|bcc|from[_-]?email)$",
           EndpointTag.SENDS_EMAIL, conf=6, desc="email param"),

    # Phone → SMS
    _param(r"^(phone|mobile|sms[_-]?to|number|msisdn|cell)$",
           EndpointTag.SENDS_SMS, conf=5, desc="phone/SMS param"),
]


# ─── Method → tags ────────────────────────────────────────────────────────

_METHOD_TAG_MAP: Dict[str, EndpointTag] = {
    "GET": EndpointTag.HAS_GET,
    "POST": EndpointTag.HAS_POST,
    "PUT": EndpointTag.HAS_PUT,
    "PATCH": EndpointTag.HAS_PATCH,
    "DELETE": EndpointTag.HAS_DELETE,
    "OPTIONS": EndpointTag.HAS_OPTIONS,
}

# ─── Scanner routing table ────────────────────────────────────────────────

@dataclass
class _ScannerRoutingRule:
    scanner_name: str
    required_category: Optional[EndpointCategory] = None
    required_tags: Tuple[EndpointTag, ...] = ()
    any_of_tags: Tuple[EndpointTag, ...] = ()
    priority: ScannerPriority = ScannerPriority.MEDIUM
    param_focus_tags: Tuple[EndpointTag, ...] = ()
    rationale: str = ""


_SCANNER_ROUTING: List[_ScannerRoutingRule] = [
    # XSS — anything that reflects input or accepts text params
    _ScannerRoutingRule("xss", any_of_tags=(
        EndpointTag.REFLECTS_INPUT,
        EndpointTag.ACCEPTS_SQL_LIKE,
        EndpointTag.ACCEPTS_TEMPLATE,
    ), priority=ScannerPriority.HIGH,
    rationale="endpoint reflects or processes user input"),

    _ScannerRoutingRule("stored_xss",
        required_category=EndpointCategory.MESSAGING,
        priority=ScannerPriority.HIGH,
        rationale="messaging endpoints store user input"),

    _ScannerRoutingRule("stored_xss",
        required_category=EndpointCategory.PROFILE,
        priority=ScannerPriority.MEDIUM,
        rationale="profile fields often persist user HTML"),

    # SQLi — SQL-like params or search / filter endpoints
    _ScannerRoutingRule("sqli", any_of_tags=(
        EndpointTag.ACCEPTS_SQL_LIKE,
        EndpointTag.ACCEPTS_USER_ID,
    ), priority=ScannerPriority.HIGH,
    param_focus_tags=(EndpointTag.ACCEPTS_SQL_LIKE, EndpointTag.ACCEPTS_USER_ID),
    rationale="SQL-pattern parameters detected"),

    _ScannerRoutingRule("sqli",
        required_category=EndpointCategory.SEARCH,
        priority=ScannerPriority.HIGH,
        rationale="search endpoints commonly vulnerable to SQLi"),

    # IDOR — any endpoint with resource ID parameters
    _ScannerRoutingRule("idor", any_of_tags=(
        EndpointTag.ACCEPTS_USER_ID,
    ), priority=ScannerPriority.HIGH,
    param_focus_tags=(EndpointTag.ACCEPTS_USER_ID,),
    rationale="resource ID parameters are classic IDOR targets"),

    # Path Traversal / LFI — file path params
    _ScannerRoutingRule("path_traversal", any_of_tags=(
        EndpointTag.ACCEPTS_FILE_PATH,
    ), priority=ScannerPriority.HIGH,
    param_focus_tags=(EndpointTag.ACCEPTS_FILE_PATH,),
    rationale="file path parameters detected"),

    _ScannerRoutingRule("path_traversal",
        required_category=EndpointCategory.FILE_DOWNLOAD,
        priority=ScannerPriority.HIGH,
        rationale="file download endpoints"),

    # SSRF — URL parameters or webhook / third-party endpoints
    _ScannerRoutingRule("ssrf", any_of_tags=(
        EndpointTag.ACCEPTS_URL,
        EndpointTag.THIRD_PARTY_INTEGRATION,
        EndpointTag.PROCESSES_EXTERNAL_URL,
    ), priority=ScannerPriority.CRITICAL,
    param_focus_tags=(EndpointTag.ACCEPTS_URL, EndpointTag.ACCEPTS_REDIRECT_URL),
    rationale="URL / external-resource parameters detected"),

    _ScannerRoutingRule("ssrf",
        required_category=EndpointCategory.WEBHOOK,
        priority=ScannerPriority.CRITICAL,
        rationale="webhook endpoints receive external URLs"),

    # Open Redirect — redirect-accepting endpoints
    _ScannerRoutingRule("open_redirect",
        required_category=EndpointCategory.REDIRECT,
        priority=ScannerPriority.HIGH,
        rationale="endpoint is a redirector"),

    _ScannerRoutingRule("open_redirect", any_of_tags=(
        EndpointTag.ACCEPTS_REDIRECT_URL,
    ), priority=ScannerPriority.HIGH,
    rationale="redirect parameter detected"),

    # SSTI — template parameters
    _ScannerRoutingRule("ssti", any_of_tags=(
        EndpointTag.ACCEPTS_TEMPLATE,
    ), priority=ScannerPriority.HIGH,
    param_focus_tags=(EndpointTag.ACCEPTS_TEMPLATE,),
    rationale="template parameter detected"),

    # CMDi — command parameters
    _ScannerRoutingRule("cmdi", any_of_tags=(
        EndpointTag.ACCEPTS_COMMAND,
    ), priority=ScannerPriority.CRITICAL,
    param_focus_tags=(EndpointTag.ACCEPTS_COMMAND,),
    rationale="command/exec parameter detected"),

    # XXE — XML-accepting endpoints
    _ScannerRoutingRule("xxe", any_of_tags=(
        EndpointTag.ACCEPTS_XML,
    ), priority=ScannerPriority.HIGH,
    rationale="XML content type or parameter detected"),

    _ScannerRoutingRule("xxe",
        required_category=EndpointCategory.API_SOAP,
        priority=ScannerPriority.CRITICAL,
        rationale="SOAP endpoints always send XML"),

    # File Upload — multipart / upload endpoints
    _ScannerRoutingRule("file_upload",
        required_category=EndpointCategory.FILE_UPLOAD,
        priority=ScannerPriority.CRITICAL,
        rationale="explicit file upload endpoint"),

    _ScannerRoutingRule("file_upload", any_of_tags=(
        EndpointTag.ACCEPTS_MULTIPART,
    ), priority=ScannerPriority.HIGH,
    rationale="multipart/form-data accepted"),

    # CSRF — state-changing endpoints without CSRF token
    _ScannerRoutingRule("csrf", required_tags=(
        EndpointTag.HAS_POST,
        EndpointTag.NO_CSRF_TOKEN,
    ), priority=ScannerPriority.HIGH,
    rationale="POST endpoint with no CSRF protection"),

    # Auth Bypass — authentication / MFA endpoints
    _ScannerRoutingRule("auth_bypass",
        required_category=EndpointCategory.AUTHENTICATION,
        priority=ScannerPriority.CRITICAL,
        rationale="authentication endpoint"),

    _ScannerRoutingRule("auth_bypass",
        required_category=EndpointCategory.MFA,
        priority=ScannerPriority.CRITICAL,
        rationale="MFA endpoint"),

    _ScannerRoutingRule("auth_bypass",
        required_category=EndpointCategory.PASSWORD_RESET,
        priority=ScannerPriority.CRITICAL,
        rationale="password reset endpoint"),

    # JWT Scanner
    _ScannerRoutingRule("jwt_scanner", any_of_tags=(
        EndpointTag.ACCEPTS_JWT,
        EndpointTag.USES_BEARER,
    ), priority=ScannerPriority.HIGH,
    rationale="JWT token usage detected"),

    # OAuth scanner
    _ScannerRoutingRule("oauth_scanner",
        required_category=EndpointCategory.SSO,
        priority=ScannerPriority.CRITICAL,
        rationale="SSO/OAuth endpoint"),

    # GraphQL scanner
    _ScannerRoutingRule("graphql",
        required_category=EndpointCategory.API_GRAPHQL,
        priority=ScannerPriority.CRITICAL,
        rationale="GraphQL endpoint"),

    # WebSocket scanner
    _ScannerRoutingRule("websocket_scanner",
        required_category=EndpointCategory.API_WEBSOCKET,
        priority=ScannerPriority.HIGH,
        rationale="WebSocket endpoint"),

    # CORS scanner
    _ScannerRoutingRule("cors_scanner", any_of_tags=(
        EndpointTag.CORS_WILDCARD,
        EndpointTag.CORS_REFLECTS_ORIGIN,
    ), priority=ScannerPriority.MEDIUM,
    rationale="CORS misconfiguration indicator"),

    # Headers scanner — all endpoints
    _ScannerRoutingRule("headers",
        priority=ScannerPriority.LOW,
        rationale="security headers check"),

    # Secrets scanner — JS files and source maps
    _ScannerRoutingRule("secrets_scanner", any_of_tags=(
        EndpointTag.FOUND_IN_JS,
    ), priority=ScannerPriority.HIGH,
    rationale="JavaScript file may contain secrets"),

    # Sensitive files — config / env / backup endpoints
    _ScannerRoutingRule("sensitive_files", any_of_tags=(
        EndpointTag.PRIVILEGED_OPERATION,
    ), required_category=EndpointCategory.CONFIGURATION,
    priority=ScannerPriority.CRITICAL,
    rationale="configuration endpoint exposed"),

    # Race condition — state-changing + numeric ID
    _ScannerRoutingRule("race_condition", required_tags=(
        EndpointTag.HAS_POST,
    ), any_of_tags=(
        EndpointTag.ACCEPTS_USER_ID,
        EndpointTag.PRIVILEGED_OPERATION,
    ), priority=ScannerPriority.MEDIUM,
    rationale="POST with resource ID — potential race condition"),

    _ScannerRoutingRule("race_condition",
        required_category=EndpointCategory.PAYMENT,
        priority=ScannerPriority.HIGH,
        rationale="payment endpoints are classic race targets"),

    # HTTP Smuggling — any endpoint (tested at HTTP layer)
    _ScannerRoutingRule("http_smuggling",
        priority=ScannerPriority.LOW,
        rationale="HTTP request smuggling applies broadly"),

    # NoSQLi — JSON-body endpoints
    _ScannerRoutingRule("nosqli", any_of_tags=(
        EndpointTag.ACCEPTS_JSON_BODY,
    ), priority=ScannerPriority.MEDIUM,
    param_focus_tags=(EndpointTag.ACCEPTS_SQL_LIKE, EndpointTag.ACCEPTS_USER_ID),
    rationale="JSON body endpoint may hide NoSQL injection"),

    # LDAP Injection — search / filter endpoints
    _ScannerRoutingRule("ldap_injection",
        required_category=EndpointCategory.SEARCH,
        priority=ScannerPriority.LOW,
        rationale="search endpoints may use LDAP"),

    # CRLF — any endpoint
    _ScannerRoutingRule("crlf_injection",
        any_of_tags=(EndpointTag.RETURNS_HTML, EndpointTag.REFLECTS_INPUT),
        priority=ScannerPriority.MEDIUM,
        rationale="response reflects input — CRLF possible"),

    # Admin panel attack surface
    _ScannerRoutingRule("authz_matrix",
        required_category=EndpointCategory.ADMIN,
        priority=ScannerPriority.CRITICAL,
        rationale="admin endpoint — full authz test required"),

    # IDOR on profile
    _ScannerRoutingRule("idor",
        required_category=EndpointCategory.PROFILE,
        priority=ScannerPriority.HIGH,
        rationale="profile endpoint often leaks other users' data"),
]


# ═══════════════════════════════════════════════════════════════════════════
# Risk Scoring Factors
# ═══════════════════════════════════════════════════════════════════════════

_BASE_RISK_BY_CATEGORY: Dict[EndpointCategory, float] = {
    EndpointCategory.ADMIN: 85.0,
    EndpointCategory.AUTHENTICATION: 80.0,
    EndpointCategory.PASSWORD_RESET: 80.0,
    EndpointCategory.SSO: 75.0,
    EndpointCategory.MFA: 75.0,
    EndpointCategory.FILE_UPLOAD: 75.0,
    EndpointCategory.PAYMENT: 70.0,
    EndpointCategory.CONFIGURATION: 70.0,
    EndpointCategory.DEBUG: 90.0,
    EndpointCategory.WEBHOOK: 65.0,
    EndpointCategory.IMPORT: 65.0,
    EndpointCategory.API_GRAPHQL: 60.0,
    EndpointCategory.API_SOAP: 60.0,
    EndpointCategory.API_GRPC_WEB: 55.0,
    EndpointCategory.API_REST: 55.0,
    EndpointCategory.API_WEBSOCKET: 55.0,
    EndpointCategory.EXPORT: 50.0,
    EndpointCategory.SEARCH: 50.0,
    EndpointCategory.REGISTRATION: 50.0,
    EndpointCategory.PROFILE: 45.0,
    EndpointCategory.FILE_DOWNLOAD: 45.0,
    EndpointCategory.MESSAGING: 45.0,
    EndpointCategory.REDIRECT: 40.0,
    EndpointCategory.METRICS: 30.0,
    EndpointCategory.HEALTH_CHECK: 20.0,
    EndpointCategory.DOCUMENTATION: 20.0,
    EndpointCategory.API_SSE: 30.0,
    EndpointCategory.ERROR_PAGE: 10.0,
    EndpointCategory.STATIC_RESOURCE: 5.0,
    EndpointCategory.SOURCE_MAP: 40.0,
    EndpointCategory.UNKNOWN: 35.0,
}

_RISK_MODIFIERS_BY_TAG: Dict[EndpointTag, float] = {
    EndpointTag.ACCEPTS_COMMAND: +20.0,
    EndpointTag.ACCEPTS_FILE_PATH: +15.0,
    EndpointTag.ACCEPTS_URL: +15.0,
    EndpointTag.ACCEPTS_REDIRECT_URL: +12.0,
    EndpointTag.ACCEPTS_XML: +10.0,
    EndpointTag.ACCEPTS_TEMPLATE: +12.0,
    EndpointTag.ACCEPTS_SQL_LIKE: +10.0,
    EndpointTag.ACCEPTS_CALLBACK: +8.0,
    EndpointTag.PROCESSES_EXTERNAL_URL: +15.0,
    EndpointTag.PROCESSES_UPLOADED_FILE: +12.0,
    EndpointTag.EXECUTES_USER_CODE: +25.0,
    EndpointTag.THIRD_PARTY_INTEGRATION: +5.0,
    EndpointTag.BULK_OPERATION: +5.0,
    EndpointTag.PRIVILEGED_OPERATION: +10.0,
    EndpointTag.REFLECTS_INPUT: +8.0,
    EndpointTag.TIMING_VARIABLE: +5.0,
    EndpointTag.NO_AUTH_REQUIRED: +8.0,
    EndpointTag.NO_CSRF_TOKEN: +5.0,
    EndpointTag.CORS_WILDCARD: +8.0,
    EndpointTag.CORS_REFLECTS_ORIGIN: +6.0,
    EndpointTag.NOT_RATE_LIMITED: +5.0,
    EndpointTag.HAS_DELETE: +5.0,
    EndpointTag.HAS_PUT: +3.0,
    EndpointTag.HAS_PATCH: +3.0,
    # Mitigations reduce risk
    EndpointTag.CSRF_TOKEN_PRESENT: -5.0,
    EndpointTag.RATE_LIMITED: -5.0,
    EndpointTag.REQUIRES_AUTH: -3.0,
}

_MAX_RISK = 100.0
_MIN_RISK = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Core Classifier
# ═══════════════════════════════════════════════════════════════════════════


class EndpointClassifier:
    """
    Stateful classifier that transforms ``RawEndpoint`` objects into
    ``ClassifiedEndpoint`` objects using the multi-layer rule system.

    Parameters
    ----------
    target:
        The scan target, used for host-relative path normalisation.
    fingerprint:
        Optional technology fingerprint from the Fingerprinting Framework.
        Enables Layer 5 (Knowledge-Base Cross-Reference) classification.
    knowledge_base:
        Optional knowledge base for framework-specific rule extensions.
    skip_static:
        If ``True`` (default), endpoints with purely static extensions are
        classified as ``STATIC_RESOURCE`` and skipped from scanner routing.
        Set to ``False`` only when you need to scan static files explicitly.
    concurrency:
        Number of endpoints classified in parallel (default: 32).
    """

    def __init__(
        self,
        target: ScanTarget,
        fingerprint: Optional[Any] = None,
        knowledge_base: Optional[Any] = None,
        skip_static: bool = True,
        concurrency: int = 32,
    ) -> None:
        self._target = target
        self._fingerprint = fingerprint
        self._kb = knowledge_base
        self._skip_static = skip_static
        self._sem = asyncio.Semaphore(concurrency)

    # ── Public API ───────────────────────────────────────────────────────

    async def classify_all(
        self, endpoints: Sequence[RawEndpoint]
    ) -> ClassificationReport:
        """
        Classify a batch of raw endpoints and return the full report.

        All endpoints are processed concurrently up to ``self._concurrency``.
        """
        t_start = time.perf_counter()
        report = ClassificationReport(
            target=self._target,
            total_raw=len(endpoints),
        )

        tasks = [self._classify_one_guarded(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for result in results:
            if result is None:
                report.skipped_static += 1
            else:
                report.classified.append(result)

        report.processing_time_ms = (time.perf_counter() - t_start) * 1000
        return report

    async def classify_one(self, endpoint: RawEndpoint) -> ClassifiedEndpoint:
        """Classify a single endpoint synchronously-within-async."""
        async with self._sem:
            return self._classify(endpoint)

    # ── Internal orchestration ───────────────────────────────────────────

    async def _classify_one_guarded(
        self, endpoint: RawEndpoint
    ) -> Optional[ClassifiedEndpoint]:
        """Return None if the endpoint is static and skip_static is True."""
        async with self._sem:
            t0 = time.perf_counter()
            result = self._classify(endpoint)
            result.evidence.processing_time_ms = (time.perf_counter() - t0) * 1000

            if (
                self._skip_static
                and result.category == EndpointCategory.STATIC_RESOURCE
                and not result.tags & {EndpointTag.SOURCE_MAP}
            ):
                return None
            return result

    # ── Master classification pipeline ──────────────────────────────────

    def _classify(self, ep: RawEndpoint) -> ClassifiedEndpoint:
        evidence = ClassificationEvidence()
        tags: Set[EndpointTag] = set()
        category_votes: Dict[EndpointCategory, int] = {}

        # ── Layer 0: quick extension triage ─────────────────────────────
        ext = ep.extension
        if ext in _STATIC_EXTENSIONS:
            evidence.matched_rules.append(f"static extension: .{ext}")
            self._add_method_tags(ep, tags, evidence)
            return ClassifiedEndpoint(
                raw=ep,
                category=EndpointCategory.STATIC_RESOURCE,
                tags=frozenset(tags | {EndpointTag.LOW_CONFIDENCE}),
                risk_score=_BASE_RISK_BY_CATEGORY[EndpointCategory.STATIC_RESOURCE],
                scanner_hints=[],
                evidence=evidence,
            )
        if ext in _SOURCE_MAP_EXTENSIONS:
            evidence.matched_rules.append(f"source-map extension: .{ext}")
            self._add_method_tags(ep, tags, evidence)
            return ClassifiedEndpoint(
                raw=ep,
                category=EndpointCategory.SOURCE_MAP,
                tags=frozenset(tags | {EndpointTag.HIGH_CONFIDENCE}),
                risk_score=_BASE_RISK_BY_CATEGORY[EndpointCategory.SOURCE_MAP],
                scanner_hints=[ScannerHint(
                    scanner_name="secrets_scanner",
                    priority=ScannerPriority.HIGH,
                    rationale="source maps expose original JS source",
                )],
                evidence=evidence,
            )

        # ── Layer 1: URL / path pattern matching ─────────────────────────
        self._apply_path_rules(ep, category_votes, tags, evidence)

        # ── Layer 2: HTTP method / content-type analysis ─────────────────
        self._apply_method_rules(ep, tags, evidence)
        self._apply_content_type_rules(ep, tags, evidence)

        # ── Layer 3: parameter fingerprinting ────────────────────────────
        self._apply_parameter_rules(ep, category_votes, tags, evidence)

        # ── Layer 4: response characteristic analysis ────────────────────
        self._apply_response_rules(ep, tags, evidence)

        # ── Layer 5: knowledge-base / fingerprint cross-reference ─────────
        if self._fingerprint:
            self._apply_fingerprint_rules(ep, category_votes, tags, evidence)

        # ── Category selection ───────────────────────────────────────────
        category = self._pick_category(category_votes, evidence)

        # ── Discovery source tag ─────────────────────────────────────────
        self._apply_source_tag(ep, tags, evidence)

        # ── Risk scoring ─────────────────────────────────────────────────
        risk_score = self._compute_risk(category, tags, evidence)

        # ── Scanner routing ──────────────────────────────────────────────
        scanner_hints = self._build_scanner_hints(
            ep, category, tags, evidence
        )

        # ── Confidence resolution ─────────────────────────────────────────
        if len(category_votes) >= 2:
            tags.add(EndpointTag.HIGH_CONFIDENCE)
        elif not category_votes:
            tags.add(EndpointTag.LOW_CONFIDENCE)

        return ClassifiedEndpoint(
            raw=ep,
            category=category,
            tags=frozenset(tags),
            risk_score=risk_score,
            scanner_hints=scanner_hints,
            evidence=evidence,
        )

    # ── Layer 1 ──────────────────────────────────────────────────────────

    def _apply_path_rules(
        self,
        ep: RawEndpoint,
        votes: Dict[EndpointCategory, int],
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        path = ep.path
        for rule in _PATH_RULES:
            if rule.pattern.search(path):
                votes[rule.category] = (
                    votes.get(rule.category, 0) + rule.confidence
                )
                for tag in rule.tags:
                    tags.add(tag)
                    evidence.tag_reasons[tag.value] = f"path rule: {rule.description}"
                evidence.matched_rules.append(
                    f"path rule [{rule.confidence}]: {rule.description} → {rule.category.value}"
                )
                evidence.category_votes[rule.category.value] = votes[rule.category]

    # ── Layer 2 ──────────────────────────────────────────────────────────

    def _apply_method_rules(
        self,
        ep: RawEndpoint,
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        for method in ep.methods:
            tag = _METHOD_TAG_MAP.get(method.upper())
            if tag:
                tags.add(tag)
                evidence.tag_reasons[tag.value] = f"HTTP method: {method}"

    def _add_method_tags(
        self,
        ep: RawEndpoint,
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        self._apply_method_rules(ep, tags, evidence)

    def _apply_content_type_rules(
        self,
        ep: RawEndpoint,
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        for ct in ep.content_types_accepted:
            ct_lower = ct.lower()
            if "json" in ct_lower:
                tags.add(EndpointTag.ACCEPTS_JSON_BODY)
                evidence.tag_reasons[EndpointTag.ACCEPTS_JSON_BODY.value] = (
                    f"Content-Type accepted: {ct}"
                )
            if "multipart" in ct_lower:
                tags.add(EndpointTag.ACCEPTS_MULTIPART)
                tags.add(EndpointTag.PROCESSES_UPLOADED_FILE)
                evidence.tag_reasons[EndpointTag.ACCEPTS_MULTIPART.value] = (
                    f"Content-Type accepted: {ct}"
                )
            if "xml" in ct_lower or "soap" in ct_lower:
                tags.add(EndpointTag.ACCEPTS_XML)
                evidence.tag_reasons[EndpointTag.ACCEPTS_XML.value] = (
                    f"Content-Type accepted: {ct}"
                )

        for ct in ep.content_types_returned:
            ct_lower = ct.lower()
            if "json" in ct_lower:
                tags.add(EndpointTag.RETURNS_JSON)
                evidence.tag_reasons[EndpointTag.RETURNS_JSON.value] = (
                    f"Content-Type returned: {ct}"
                )
            if "html" in ct_lower:
                tags.add(EndpointTag.RETURNS_HTML)
            if "xml" in ct_lower:
                tags.add(EndpointTag.RETURNS_XML)
            if "stream" in ct_lower or "octet" in ct_lower:
                tags.add(EndpointTag.RETURNS_BINARY)
            if "text/event-stream" in ct_lower:
                tags.add(EndpointTag.RETURNS_STREAM)

    # ── Layer 3 ──────────────────────────────────────────────────────────

    def _apply_parameter_rules(
        self,
        ep: RawEndpoint,
        votes: Dict[EndpointCategory, int],
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        # Merge URL query params + known params from discovery
        all_params: Set[str] = set(ep.parameters.keys())
        all_params.update(ep.query_params.keys())

        for param_name in all_params:
            for rule in _PARAM_RULES:
                if rule.pattern.match(param_name):
                    tags.add(rule.tag)
                    reason = f"param rule: '{param_name}' matched '{rule.description}'"
                    evidence.tag_reasons.setdefault(rule.tag.value, reason)
                    evidence.matched_rules.append(reason)
                    if rule.category_vote:
                        votes[rule.category_vote] = (
                            votes.get(rule.category_vote, 0) + rule.confidence
                        )
                        evidence.category_votes[rule.category_vote.value] = (
                            votes[rule.category_vote]
                        )

    # ── Layer 4 ──────────────────────────────────────────────────────────

    def _apply_response_rules(
        self,
        ep: RawEndpoint,
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        if ep.response_time_ms is not None and ep.response_time_ms > 2000:
            tags.add(EndpointTag.TIMING_VARIABLE)
            evidence.tag_reasons[EndpointTag.TIMING_VARIABLE.value] = (
                f"slow response ({ep.response_time_ms:.0f}ms)"
            )
        if ep.status_code == 401 or ep.status_code == 403:
            tags.add(EndpointTag.REQUIRES_AUTH)
            evidence.tag_reasons[EndpointTag.REQUIRES_AUTH.value] = (
                f"status {ep.status_code} → auth required"
            )
        if ep.status_code in (200, 201, 204):
            if EndpointTag.REQUIRES_AUTH not in tags:
                tags.add(EndpointTag.AUTH_OPTIONAL)

    # ── Layer 5 ──────────────────────────────────────────────────────────

    def _apply_fingerprint_rules(
        self,
        ep: RawEndpoint,
        votes: Dict[EndpointCategory, int],
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        fp = self._fingerprint
        # Map technology identifiers to endpoint tags
        tech_tag_map = {
            "django": EndpointTag.FRAMEWORK_DJANGO,
            "rails": EndpointTag.FRAMEWORK_RAILS,
            "laravel": EndpointTag.FRAMEWORK_LARAVEL,
            "spring": EndpointTag.FRAMEWORK_SPRING,
            "express": EndpointTag.FRAMEWORK_EXPRESS,
            "next.js": EndpointTag.FRAMEWORK_NEXTJS,
            "wordpress": EndpointTag.CMS_WORDPRESS,
            "drupal": EndpointTag.CMS_DRUPAL,
            "joomla": EndpointTag.CMS_JOOMLA,
        }
        detected: List[str] = getattr(fp, "technologies", [])
        for tech in detected:
            tech_lower = tech.lower()
            for key, tag in tech_tag_map.items():
                if key in tech_lower:
                    tags.add(tag)
                    evidence.tag_reasons[tag.value] = (
                        f"fingerprint: {tech}"
                    )
                    evidence.matched_rules.append(
                        f"fingerprint rule: {tech} → {tag.value}"
                    )

    # ── Category selection ────────────────────────────────────────────────

    def _pick_category(
        self,
        votes: Dict[EndpointCategory, int],
        evidence: ClassificationEvidence,
    ) -> EndpointCategory:
        if not votes:
            return EndpointCategory.UNKNOWN
        winner = max(votes, key=lambda c: votes[c])
        evidence.matched_rules.append(
            f"category selected: {winner.value} (score={votes[winner]})"
        )
        return winner

    # ── Discovery source tag ──────────────────────────────────────────────

    def _apply_source_tag(
        self,
        ep: RawEndpoint,
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> None:
        source_map = {
            "js": EndpointTag.FOUND_IN_JS,
            "crawler": EndpointTag.FOUND_BY_CRAWLER,
            "browser": EndpointTag.FOUND_BY_BROWSER,
            "openapi": EndpointTag.FOUND_IN_OPENAPI,
            "sitemap": EndpointTag.FOUND_IN_SITEMAP,
        }
        for key, tag in source_map.items():
            if key in ep.source.lower():
                tags.add(tag)
                evidence.tag_reasons[tag.value] = f"discovery source: {ep.source}"

    # ── Risk scoring ──────────────────────────────────────────────────────

    def _compute_risk(
        self,
        category: EndpointCategory,
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> float:
        base = _BASE_RISK_BY_CATEGORY.get(category, 35.0)
        evidence.risk_factors.append(
            (f"base risk for {category.value}", base)
        )
        score = base
        for tag in tags:
            delta = _RISK_MODIFIERS_BY_TAG.get(tag, 0.0)
            if delta != 0.0:
                evidence.risk_factors.append((f"tag: {tag.value}", delta))
                score += delta
        return max(_MIN_RISK, min(_MAX_RISK, score))

    # ── Scanner routing ───────────────────────────────────────────────────

    def _build_scanner_hints(
        self,
        ep: RawEndpoint,
        category: EndpointCategory,
        tags: Set[EndpointTag],
        evidence: ClassificationEvidence,
    ) -> List[ScannerHint]:
        hints: Dict[str, ScannerHint] = {}

        for rule in _SCANNER_ROUTING:
            # Category check
            if rule.required_category and rule.required_category != category:
                continue
            # Required tags check (ALL must be present)
            if rule.required_tags and not all(t in tags for t in rule.required_tags):
                continue
            # Any-of tags check (at least ONE must be present)
            if rule.any_of_tags and not any(t in tags for t in rule.any_of_tags):
                # If no category requirement either, skip
                if not rule.required_category:
                    continue

            scanner = rule.scanner_name
            # Keep only the highest-priority (lowest enum value) hint per scanner
            if scanner in hints:
                if rule.priority < hints[scanner].priority:
                    hints[scanner].priority = rule.priority
                continue

            # Resolve focus parameters
            focus_params = []
            for pt in rule.param_focus_tags:
                focus_params.extend(
                    [p for p, _ in ep.parameters.items()
                     if any(pr.pattern.match(p) and pr.tag == pt
                            for pr in _PARAM_RULES)]
                )

            hint = ScannerHint(
                scanner_name=scanner,
                priority=rule.priority,
                parameter_focus=focus_params,
                rationale=rule.rationale,
            )
            hints[scanner] = hint
            evidence.scanner_rationale[scanner] = rule.rationale

        # Sort by priority
        return sorted(hints.values(), key=lambda h: h.priority.value)


# ═══════════════════════════════════════════════════════════════════════════
# Convenience factory
# ═══════════════════════════════════════════════════════════════════════════


async def classify_endpoints(
    endpoints: Sequence[RawEndpoint],
    target: ScanTarget,
    fingerprint: Optional[Any] = None,
    knowledge_base: Optional[Any] = None,
    skip_static: bool = True,
    concurrency: int = 32,
) -> ClassificationReport:
    """
    Top-level async helper for classifying a collection of raw endpoints.

    Parameters
    ----------
    endpoints:
        All ``RawEndpoint`` objects produced by the discovery phase.
    target:
        The scan target.
    fingerprint:
        Optional ``FingerprintReport`` from the Fingerprinting Framework.
    knowledge_base:
        Optional ``KnowledgeBase`` instance.
    skip_static:
        Skip static resources (images, fonts, CSS) from classification output.
    concurrency:
        Maximum parallel classifications.

    Returns
    -------
    ``ClassificationReport`` with all ``ClassifiedEndpoint`` objects.
    """
    classifier = EndpointClassifier(
        target=target,
        fingerprint=fingerprint,
        knowledge_base=knowledge_base,
        skip_static=skip_static,
        concurrency=concurrency,
    )
    return await classifier.classify_all(endpoints)
