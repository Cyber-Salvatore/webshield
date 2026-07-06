"""
JavaScript Analysis Engine — Part 7 of the Intelligence Layer.

Provides deep static analysis of JavaScript files to extract:
- REST API endpoints (fetch, axios, XMLHttpRequest, etc.)
- Hidden admin / internal API routes
- GraphQL queries and mutations embedded in JS
- WebSocket connection URLs
- Client-side routing maps (React Router, Vue Router, Angular)
- Hardcoded secrets, API keys, credentials, and tokens
- Feature flags and configuration objects
- Cloud resource references (S3 buckets, Azure blobs, GCP storage)
- Third-party service integrations
- Validation logic and regex patterns (useful for fuzzing)
- Source map recovery for original source structure

The engine is designed to be called after the Crawling Engine and Browser
Automation Layer have collected script URLs, and it feeds its findings
directly into the Knowledge Base and Endpoint Classification Engine.
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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..core.http_client import HTTPClient
from ..utils.helpers import normalize_url, get_base_url


# ===========================================================================
# Enums & Constants
# ===========================================================================

class SecretConfidence(str, Enum):
    HIGH   = "High"
    MEDIUM = "Medium"
    LOW    = "Low"


class EndpointType(str, Enum):
    REST        = "REST"
    GRAPHQL     = "GraphQL"
    WEBSOCKET   = "WebSocket"
    GRPC        = "gRPC"
    ROUTE       = "ClientRoute"
    INTERNAL    = "Internal"
    UNKNOWN     = "Unknown"


# Maximum JS file size to analyse (avoids OOM on huge vendor bundles)
_MAX_JS_BYTES = 8 * 1024 * 1024   # 8 MB
_MIN_JS_BYTES = 64                 # skip trivial/empty scripts


# ===========================================================================
# Data models
# ===========================================================================

@dataclass
class SecretFinding:
    """A leaked secret or credential found in JavaScript."""
    secret_type: str
    raw_value: str
    context_snippet: str       # ±80 chars around the match (for reporting)
    source_url: str
    line_number: int
    confidence: SecretConfidence

    def redacted(self) -> str:
        v = self.raw_value
        if len(v) <= 8:
            return "***REDACTED***"
        return v[:4] + "*" * max(0, len(v) - 8) + v[-4:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":       self.secret_type,
            "value":      self.redacted(),
            "context":    self.context_snippet[:200],
            "source":     self.source_url,
            "line":       self.line_number,
            "confidence": self.confidence.value,
        }


@dataclass
class DiscoveredEndpoint:
    """An API endpoint or WebSocket URL discovered from JavaScript."""
    url: str
    endpoint_type: EndpointType
    http_methods: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    source_url: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":      self.url,
            "type":     self.endpoint_type.value,
            "methods":  self.http_methods,
            "params":   self.parameters,
            "source":   self.source_url,
            "notes":    self.notes,
        }


@dataclass
class GraphQLFinding:
    """A GraphQL operation embedded in JavaScript."""
    operation_type: str    # query | mutation | subscription
    operation_name: str
    fields: List[str]
    raw_query: str
    source_url: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":       self.operation_type,
            "name":       self.operation_name,
            "fields":     self.fields[:20],
            "query":      self.raw_query[:500],
            "source":     self.source_url,
        }


@dataclass
class FeatureFlag:
    """A feature flag or configuration object found in JavaScript."""
    name: str
    value: Any
    source_url: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "value": str(self.value)[:200], "source": self.source_url}


@dataclass
class CloudResource:
    """A cloud storage bucket, CDN URL, or cloud service reference."""
    provider: str       # AWS | Azure | GCP | Cloudflare | Generic
    resource_url: str
    resource_type: str  # S3 bucket | Blob storage | GCS bucket | etc.
    source_url: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "url":      self.resource_url,
            "type":     self.resource_type,
            "source":   self.source_url,
        }


@dataclass
class JSAnalysisReport:
    """Complete findings from analysing one JavaScript file."""
    source_url: str
    size_bytes: int                                  = 0
    is_minified: bool                                = False
    source_map_url: Optional[str]                    = None
    endpoints: List[DiscoveredEndpoint]              = field(default_factory=list)
    routes: List[str]                                = field(default_factory=list)
    graphql_ops: List[GraphQLFinding]                = field(default_factory=list)
    websocket_urls: List[str]                        = field(default_factory=list)
    secrets: List[SecretFinding]                     = field(default_factory=list)
    feature_flags: List[FeatureFlag]                 = field(default_factory=list)
    cloud_resources: List[CloudResource]             = field(default_factory=list)
    third_party_services: List[str]                  = field(default_factory=list)
    validation_regexes: List[str]                    = field(default_factory=list)
    error: Optional[str]                             = None

    @property
    def has_findings(self) -> bool:
        return bool(
            self.endpoints or self.routes or self.graphql_ops
            or self.websocket_urls or self.secrets or self.feature_flags
            or self.cloud_resources
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source":            self.source_url,
            "size_bytes":        self.size_bytes,
            "is_minified":       self.is_minified,
            "source_map":        self.source_map_url,
            "endpoints":         [e.to_dict() for e in self.endpoints],
            "routes":            self.routes,
            "graphql_ops":       [g.to_dict() for g in self.graphql_ops],
            "websocket_urls":    self.websocket_urls,
            "secrets":           [s.to_dict() for s in self.secrets],
            "feature_flags":     [f.to_dict() for f in self.feature_flags],
            "cloud_resources":   [c.to_dict() for c in self.cloud_resources],
            "third_party":       self.third_party_services,
            "validation_regex":  self.validation_regexes[:10],
            "error":             self.error,
        }


# ===========================================================================
# Detection pattern tables
# ===========================================================================

# ---------------------------------------------------------------------------
# Secret / credential patterns  (name, compiled-regex, confidence)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: List[Tuple[str, re.Pattern, SecretConfidence]] = [
    # AWS
    ("AWS Access Key ID",
     re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
     SecretConfidence.HIGH),
    ("AWS Secret Access Key",
     re.compile(r'(?:aws.?secret|secret.?access.?key|AWS_SECRET)[\'"\s:=]+([A-Za-z0-9/+]{40})', re.I),
     SecretConfidence.HIGH),
    # Google
    ("Google API Key",
     re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
     SecretConfidence.HIGH),
    ("Google OAuth Client Secret",
     re.compile(r'client_secret[\'"\s:=]+([A-Za-z0-9\-_]{24,32})', re.I),
     SecretConfidence.MEDIUM),
    # Firebase
    ("Firebase API Key",
     re.compile(r'(?:firebase|FIREBASE)[^{]{0,50}apiKey[\'"\s:=]+([A-Za-z0-9\-_]{35,45})', re.I),
     SecretConfidence.HIGH),
    # Stripe
    ("Stripe Live Secret Key",
     re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'),
     SecretConfidence.HIGH),
    ("Stripe Publishable Key",
     re.compile(r'\b(pk_live_[0-9a-zA-Z]{24,})\b'),
     SecretConfidence.MEDIUM),
    # GitHub
    ("GitHub Personal Access Token",
     re.compile(r'\b(ghp_[A-Za-z0-9]{36})\b'),
     SecretConfidence.HIGH),
    ("GitHub OAuth Token",
     re.compile(r'\b(gho_[A-Za-z0-9]{36})\b'),
     SecretConfidence.HIGH),
    ("GitHub Fine-Grained Token",
     re.compile(r'\b(github_pat_[A-Za-z0-9_]{82})\b'),
     SecretConfidence.HIGH),
    # Slack
    ("Slack Bot Token",
     re.compile(r'\b(xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+)\b'),
     SecretConfidence.HIGH),
    ("Slack App Token",
     re.compile(r'\b(xapp-[A-Za-z0-9\-]+)\b'),
     SecretConfidence.HIGH),
    ("Slack Webhook URL",
     re.compile(r'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
     SecretConfidence.HIGH),
    # Twilio
    ("Twilio Account SID",
     re.compile(r'\b(AC[0-9a-fA-F]{32})\b'),
     SecretConfidence.HIGH),
    ("Twilio API Key",
     re.compile(r'\b(SK[0-9a-fA-F]{32})\b'),
     SecretConfidence.HIGH),
    # SendGrid
    ("SendGrid API Key",
     re.compile(r'\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b'),
     SecretConfidence.HIGH),
    # Mailgun
    ("Mailgun API Key",
     re.compile(r'\b(key-[0-9a-zA-Z]{32})\b'),
     SecretConfidence.MEDIUM),
    # Mailchimp
    ("Mailchimp API Key",
     re.compile(r'\b([0-9a-f]{32}-us[0-9]{1,2})\b'),
     SecretConfidence.HIGH),
    # Private keys
    ("RSA Private Key",
     re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
     SecretConfidence.HIGH),
    ("OpenSSH / EC Private Key",
     re.compile(r'-----BEGIN (?:EC|OPENSSH|DSA) PRIVATE KEY-----'),
     SecretConfidence.HIGH),
    # JWT secrets (hardcoded)
    ("Hardcoded JWT Secret",
     re.compile(r'(?:jwt.?secret|JWT_SECRET|jwtSecret|secret.?key)[\'"\s:=]+([\'"]([\w!@#$%^&*\-_]{8,80})[\'"])', re.I),
     SecretConfidence.HIGH),
    # Shopify
    ("Shopify Private App Token",
     re.compile(r'\b(shppa_[0-9a-fA-F]{32})\b'),
     SecretConfidence.HIGH),
    ("Shopify Access Token",
     re.compile(r'\b(shpat_[0-9a-fA-F]{32})\b'),
     SecretConfidence.HIGH),
    # NPM
    ("NPM Publish Token",
     re.compile(r'\b(npm_[A-Za-z0-9]{36})\b'),
     SecretConfidence.HIGH),
    # Generic
    ("Generic API Key",
     re.compile(r'(?:api.?key|apikey|API_KEY|x-api-key)[\'"\s:=]+[\'"]([A-Za-z0-9\-_]{20,64})[\'"]', re.I),
     SecretConfidence.MEDIUM),
    ("Generic Password / Secret",
     re.compile(r'(?:password|passwd|secret|token)[\'"\s:=]+[\'"]([A-Za-z0-9!@#$%^&*\-_]{8,64})[\'"]', re.I),
     SecretConfidence.LOW),
    # Database connection strings
    ("Database Connection String",
     re.compile(r'(?:mongodb|postgres|mysql|redis|mssql)://[^\'"<>\s]{10,200}', re.I),
     SecretConfidence.HIGH),
    # Internal base URLs
    ("Internal API Base URL",
     re.compile(
         r'(?:api.?base|API_BASE|baseURL|BASE_URL)[\'"\s:=]+'
         r'[\'\"](https?://(?:10\.|172\.|192\.168\.|localhost|127\.)[^\'"]{4,100})[\'"]',
         re.I,
     ),
     SecretConfidence.MEDIUM),
]

# Placeholder/example values to ignore
_PLACEHOLDERS: Set[str] = {
    "your_api_key", "your-api-key", "api_key_here", "xxxxxxxxxxxx",
    "000000000000", "changeme", "placeholder", "your_secret",
    "example", "test", "xxxxxxxx", "your-secret-key", "insert_key_here",
    "abcdefghijklmnop", "1234567890abcdef", "your_token", "none",
    "null", "undefined", "todo", "fixme", "replace_me",
}

# ---------------------------------------------------------------------------
# API endpoint patterns
# ---------------------------------------------------------------------------
_ENDPOINT_PATTERNS: List[Tuple[re.Pattern, str, List[str]]] = [
    # fetch(url, { method: ... })
    (re.compile(r'''fetch\s*\(\s*[`'"](https?://[^`'"]+|/[^`'"]{2,200})[`'"]'''), "REST", []),
    # axios.get/post/put/delete/patch(url)
    (re.compile(r'''axios\.(get|post|put|delete|patch)\s*\(\s*[`'"](/[^`'"]{2,200})[`'"]'''), "REST", []),
    # $http.get/post... (Angular 1.x)
    (re.compile(r'''\$http\.(get|post|put|delete)\s*\(\s*[`'"](/[^`'"]{2,200})[`'"]'''), "REST", []),
    # url: '/api/...'  in config objects
    (re.compile(r'''url\s*:\s*[`'"](/(?:api|v\d+|rest)[^`'"]{1,200})[`'"]'''), "REST", []),
    # endpoint: '/...'
    (re.compile(r'''endpoint\s*:\s*[`'"](/[^`'"]{2,200})[`'"]'''), "REST", []),
    # Template literal: `/api/users/${id}`
    (re.compile(r'''`(/(?:api|v\d+|graphql|rest)/[^`]{1,200})`'''), "REST", []),
    # RTK Query / SWR baseQuery paths
    (re.compile(r'''(?:baseQuery|queryFn)\s*[^)]{0,80}url\s*:\s*[`'"](/[^`'"]{2,150})[`'"]'''), "REST", []),
    # Generic absolute API paths
    (re.compile(r'''[`'"](/(?:api|v\d+|rest|services|internal)[/][^`'"<>\s]{2,100})[`'"]'''), "REST", []),
]

# ---------------------------------------------------------------------------
# GraphQL patterns
# ---------------------------------------------------------------------------
_GQL_OPERATION = re.compile(
    r'(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{([^{}]{0,2000}(?:\{[^{}]{0,500}\}[^{}]{0,500})*)\}',
    re.DOTALL,
)
_GQL_FIELD = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*\{')

# ---------------------------------------------------------------------------
# WebSocket URL patterns
# ---------------------------------------------------------------------------
_WS_PATTERNS: List[re.Pattern] = [
    re.compile(r'''[`'"](wss?://[^`'"<>\s]{4,200})[`'"]'''),
    re.compile(r'''new\s+WebSocket\s*\(\s*[`'"](wss?://[^`'"]{4,200})[`'"]'''),
    re.compile(r'''new\s+WebSocket\s*\(\s*[`'"]([^`'"]+)[`'"]'''),
    re.compile(r'''(?:socketURL|wsURL|ws_url|wsEndpoint)[\'"\s:=]+[\'\"](wss?://[^\'\"<>\s]{4,200})[\'\"]''', re.I),
]

# ---------------------------------------------------------------------------
# Client-side routing patterns
# ---------------------------------------------------------------------------
_ROUTE_PATTERNS: List[re.Pattern] = [
    # React Router v6: <Route path="/..." />  or  { path: "/..." }
    re.compile(r'''path\s*:\s*[`'"]([/][A-Za-z0-9_/:*\-?]{1,100})[`'"]'''),
    # Angular @NgModule routes
    re.compile(r"""path\s*:\s*'([^']{1,100})'"""),
    # Vue Router
    re.compile(r'''path\s*:\s*"([^"]{1,100})"'''),
    # Express-style router
    re.compile(r'''(?:app|router)\.(get|post|put|delete|patch|use)\s*\(\s*[`'"]([/][^`'"]{1,100})[`'"]'''),
    # Next.js page paths from file-system router hints in bundles
    re.compile(r'''[`'"](\/_next\/[^`'"<>\s]{2,100})[`'"]'''),
]

# ---------------------------------------------------------------------------
# Feature flag / config object patterns
# ---------------------------------------------------------------------------
_FEATURE_FLAG_PATTERNS: List[re.Pattern] = [
    re.compile(r'''(?:featureFlag|feature_flag|FEATURE_FLAG|isEnabled|enable_)([A-Za-z0-9_]+)[\'"\s:=]+(true|false|1|0)''', re.I),
    re.compile(r'''(?:flags|features)\s*[=:]\s*\{([^}]{0,500})\}''', re.I),
    re.compile(r'''process\.env\.([A-Z_]{4,60})\s*(?:\|\|)?\s*[\'"]?([^\'";\n]{0,80})[\'"]?'''),
]

# ---------------------------------------------------------------------------
# Cloud resource patterns
# ---------------------------------------------------------------------------
_CLOUD_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    ("AWS", "S3 Bucket",
     "Amazon S3",
     re.compile(r'https?://([a-z0-9\-]+)\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com', re.I)),
    ("AWS", "CloudFront",
     "Amazon CloudFront",
     re.compile(r'https?://[a-z0-9]+\.cloudfront\.net', re.I)),
    ("Azure", "Blob Storage",
     "Azure Blob",
     re.compile(r'https?://[a-z0-9]+\.blob\.core\.windows\.net/[^\'"<>\s]+', re.I)),
    ("GCP", "GCS Bucket",
     "Google Cloud Storage",
     re.compile(r'https?://storage\.googleapis\.com/[a-z0-9\-_\.]+', re.I)),
    ("GCP", "Firebase Storage",
     "Firebase Storage",
     re.compile(r'https?://firebasestorage\.googleapis\.com/[^\'"<>\s]+', re.I)),
    ("Cloudflare", "R2 / Workers",
     "Cloudflare R2",
     re.compile(r'https?://[a-z0-9]+\.r2\.dev/[^\'"<>\s]*', re.I)),
    ("Generic", "CDN URL",
     "CDN",
     re.compile(r'https?://cdn\.[a-z0-9\-]+\.[a-z]{2,6}/[^\'"<>\s]{4,200}', re.I)),
]

# ---------------------------------------------------------------------------
# Third-party service patterns (just URLs / domains)
# ---------------------------------------------------------------------------
_THIRD_PARTY_PATTERNS: List[re.Pattern] = [
    re.compile(r'https?://(?:api\.)?(?:segment|amplitude|mixpanel|intercom|hubspot|zendesk|salesforce|datadog|sentry)\.[a-z]+', re.I),
    re.compile(r'https?://[a-z0-9]+\.(?:auth0|okta|cognito)\.(?:com|aws)', re.I),
    re.compile(r'https?://maps\.googleapis\.com', re.I),
    re.compile(r'https?://api\.stripe\.com', re.I),
    re.compile(r'https?://graph\.facebook\.com', re.I),
    re.compile(r'https?://api\.twitter\.com', re.I),
    re.compile(r'https?://api\.linkedin\.com', re.I),
]

# ---------------------------------------------------------------------------
# Source map reference
# ---------------------------------------------------------------------------
_SOURCE_MAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')

# ---------------------------------------------------------------------------
# Validation regex extraction (regex literals in JS)
# ---------------------------------------------------------------------------
_REGEX_LITERAL_RE = re.compile(r'/(?:[^/\\]|\\.){8,200}/[gimsuy]*')


# ===========================================================================
# JS Analysis Engine
# ===========================================================================

class JSAnalysisEngine:
    """
    Core engine that fetches and performs deep static analysis on
    JavaScript files collected by the Crawling Engine and Browser Layer.

    Designed to be called asynchronously and concurrently (semaphore-limited).
    All findings are returned as structured objects ready for the Knowledge Base.
    """

    def __init__(
        self,
        client: HTTPClient,
        base_url: str,
        max_concurrent: int = 6,
    ) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.max_concurrent = max_concurrent
        self._seen_urls: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyse_scripts(
        self,
        script_urls: List[str],
    ) -> List[JSAnalysisReport]:
        """
        Analyse a list of JS URLs concurrently.
        Returns one JSAnalysisReport per URL (including error reports).
        """
        unique = list(dict.fromkeys(
            u for u in script_urls if u not in self._seen_urls
        ))
        self._seen_urls.update(unique)

        sem = asyncio.Semaphore(self.max_concurrent)

        async def _one(url: str) -> JSAnalysisReport:
            async with sem:
                return await self._analyse_url(url)

        results = await asyncio.gather(*[_one(u) for u in unique], return_exceptions=True)
        output: List[JSAnalysisReport] = []
        for url, r in zip(unique, results):
            if isinstance(r, JSAnalysisReport):
                output.append(r)
            else:
                output.append(JSAnalysisReport(source_url=url, error=str(r)))
        return output

    async def analyse_inline(self, code: str, label: str = "<inline>") -> JSAnalysisReport:
        """Analyse JavaScript code already available as a string."""
        report = JSAnalysisReport(source_url=label, size_bytes=len(code))
        if len(code) >= _MIN_JS_BYTES:
            report.is_minified = _detect_minified(code)
            self._run_all(code, report)
        return report

    def aggregate(self, reports: List[JSAnalysisReport]) -> Dict[str, Any]:
        """
        Merge multiple JSAnalysisReports into a single aggregated view
        suitable for direct ingestion by the Knowledge Base.
        """
        endpoints: List[Dict] = []
        routes: Set[str] = set()
        graphql_ops: List[Dict] = []
        ws_urls: Set[str] = set()
        secrets: List[Dict] = []
        flags: List[Dict] = []
        clouds: List[Dict] = []
        third_party: Set[str] = set()

        for r in reports:
            endpoints.extend(e.to_dict() for e in r.endpoints)
            routes.update(r.routes)
            graphql_ops.extend(g.to_dict() for g in r.graphql_ops)
            ws_urls.update(r.websocket_urls)
            secrets.extend(s.to_dict() for s in r.secrets)
            flags.extend(f.to_dict() for f in r.feature_flags)
            clouds.extend(c.to_dict() for c in r.cloud_resources)
            third_party.update(r.third_party_services)

        # Deduplicate endpoints by url
        seen_ep: Set[str] = set()
        deduped_eps = []
        for ep in endpoints:
            if ep["url"] not in seen_ep:
                seen_ep.add(ep["url"])
                deduped_eps.append(ep)

        return {
            "total_files":    len(reports),
            "endpoints":      deduped_eps,
            "routes":         sorted(routes),
            "graphql_ops":    graphql_ops,
            "websocket_urls": sorted(ws_urls),
            "secrets":        secrets,
            "feature_flags":  flags,
            "cloud_resources": clouds,
            "third_party":    sorted(third_party),
        }

    # ------------------------------------------------------------------
    # Internal: fetch + analyse one URL
    # ------------------------------------------------------------------

    async def _analyse_url(self, url: str) -> JSAnalysisReport:
        report = JSAnalysisReport(source_url=url)

        resp = await self.client.get(url, headers={"Accept": "*/*"})
        if resp is None:
            report.error = "Connection failed"
            return report
        if resp.status_code not in (200, 206):
            report.error = f"HTTP {resp.status_code}"
            return report

        body = resp.content
        report.size_bytes = len(body)

        if report.size_bytes > _MAX_JS_BYTES:
            report.error = f"File too large ({report.size_bytes // 1024} KB) — skipped"
            return report
        if report.size_bytes < _MIN_JS_BYTES:
            return report

        code = resp.text
        report.is_minified = _detect_minified(code)

        # Source map recovery
        sm_url = _extract_source_map_url(code, url)
        if sm_url:
            report.source_map_url = sm_url
            extra = await self._fetch_source_map(sm_url)
            if extra:
                code = code + "\n\n" + extra

        self._run_all(code, report)
        return report

    # ------------------------------------------------------------------
    # Internal: analysis passes
    # ------------------------------------------------------------------

    def _run_all(self, code: str, report: JSAnalysisReport) -> None:
        self._extract_endpoints(code, report)
        self._extract_routes(code, report)
        self._extract_graphql(code, report)
        self._extract_websockets(code, report)
        self._extract_secrets(code, report)
        self._extract_feature_flags(code, report)
        self._extract_cloud_resources(code, report)
        self._extract_third_party(code, report)
        self._extract_validation_regexes(code, report)

    def _extract_endpoints(self, code: str, report: JSAnalysisReport) -> None:
        seen: Set[str] = set()
        for pattern, ep_type, methods in _ENDPOINT_PATTERNS:
            for m in pattern.findall(code):
                # m might be a string or tuple (if capture groups)
                if isinstance(m, tuple):
                    path = m[1] if len(m) > 1 else m[0]
                    found_methods = [m[0].upper()] if m[0] else []
                else:
                    path = m
                    found_methods = []

                path = path.strip()
                if not _valid_api_path(path):
                    continue

                full_url = path if path.startswith("http") else urljoin(self.base_url, path)
                full_url = normalize_url(full_url)
                if full_url in seen:
                    continue
                seen.add(full_url)

                report.endpoints.append(DiscoveredEndpoint(
                    url=full_url,
                    endpoint_type=EndpointType.REST,
                    http_methods=found_methods or methods,
                    source_url=report.source_url,
                ))

    def _extract_routes(self, code: str, report: JSAnalysisReport) -> None:
        seen: Set[str] = set()
        for pattern in _ROUTE_PATTERNS:
            for m in pattern.findall(code):
                path = (m[1] if isinstance(m, tuple) and len(m) > 1 else m).strip()
                if not path or path in seen or len(path) < 2:
                    continue
                # Normalise dynamic segments
                clean = re.sub(r':[A-Za-z_][A-Za-z0-9_]*', ':param', path)
                clean = re.sub(r'\*\*?', '', clean).rstrip("/")
                if clean and clean.startswith("/"):
                    seen.add(clean)
                    report.routes.append(clean)

    def _extract_graphql(self, code: str, report: JSAnalysisReport) -> None:
        for m in _GQL_OPERATION.finditer(code):
            op_type = m.group(1).lower()
            op_name = m.group(2)
            body    = m.group(3)
            fields  = _GQL_FIELD.findall(body)
            raw     = m.group(0)[:800]
            report.graphql_ops.append(GraphQLFinding(
                operation_type=op_type,
                operation_name=op_name,
                fields=list(dict.fromkeys(fields)),
                raw_query=raw,
                source_url=report.source_url,
            ))

    def _extract_websockets(self, code: str, report: JSAnalysisReport) -> None:
        seen: Set[str] = set()
        for pattern in _WS_PATTERNS:
            for m in pattern.findall(code):
                url = m.strip()
                if url and url not in seen and (url.startswith("ws") or "/" in url):
                    seen.add(url)
                    report.websocket_urls.append(url)

    def _extract_secrets(self, code: str, report: JSAnalysisReport) -> None:
        for name, pattern, confidence in _SECRET_PATTERNS:
            for m in pattern.finditer(code):
                try:
                    value = m.group(1)
                except IndexError:
                    value = m.group(0)
                if not value or len(value) < 4:
                    continue
                if _is_placeholder(value):
                    continue
                start = max(0, m.start() - 80)
                end   = min(len(code), m.end() + 80)
                ctx   = code[start:end].replace("\n", " ")
                line  = code[:m.start()].count("\n") + 1
                report.secrets.append(SecretFinding(
                    secret_type=name,
                    raw_value=value,
                    context_snippet=ctx,
                    source_url=report.source_url,
                    line_number=line,
                    confidence=confidence,
                ))

    def _extract_feature_flags(self, code: str, report: JSAnalysisReport) -> None:
        # process.env.XXX captures
        for m in re.finditer(r'process\.env\.([A-Z_][A-Z0-9_]{2,59})', code):
            flag_name = m.group(1)
            report.feature_flags.append(FeatureFlag(
                name=flag_name,
                value="<env>",
                source_url=report.source_url,
            ))
        # Explicit boolean feature flags
        for m in re.finditer(
            r'(?:featureFlag|feature_flag|isEnabled)([A-Za-z0-9_]+)[\'"\s:=]+(true|false|1|0)',
            code, re.I
        ):
            report.feature_flags.append(FeatureFlag(
                name=m.group(1),
                value=m.group(2),
                source_url=report.source_url,
            ))

    def _extract_cloud_resources(self, code: str, report: JSAnalysisReport) -> None:
        seen: Set[str] = set()
        for provider, res_type, label, pattern in _CLOUD_PATTERNS:
            for m in pattern.findall(code):
                url = m if isinstance(m, str) else m[0]
                if url and url not in seen:
                    seen.add(url)
                    report.cloud_resources.append(CloudResource(
                        provider=provider,
                        resource_url=url,
                        resource_type=res_type,
                        source_url=report.source_url,
                    ))

    def _extract_third_party(self, code: str, report: JSAnalysisReport) -> None:
        for pattern in _THIRD_PARTY_PATTERNS:
            for m in pattern.findall(code):
                url = m.strip()
                if url:
                    # Store just the domain for cleanliness
                    parsed = urlparse(url)
                    domain = parsed.netloc or url
                    report.third_party_services.append(domain)

    def _extract_validation_regexes(self, code: str, report: JSAnalysisReport) -> None:
        """Extract regex literals — useful for fuzzing parameter validation."""
        seen: Set[str] = set()
        for m in _REGEX_LITERAL_RE.findall(code):
            if m not in seen and len(m) >= 10:
                seen.add(m)
                report.validation_regexes.append(m)
                if len(report.validation_regexes) >= 30:
                    break

    # ------------------------------------------------------------------
    # Source map support
    # ------------------------------------------------------------------

    async def _fetch_source_map(self, url: str) -> Optional[str]:
        """
        Download a source map and return the 'sourcesContent' merged into
        a single text block for further pattern analysis.
        """
        try:
            resp = await self.client.get(url, headers={"Accept": "*/*"})
            if resp is None or resp.status_code != 200:
                return None
            data = json.loads(resp.text)
            sources_text: List[str] = []
            for i, content in enumerate(data.get("sourcesContent") or []):
                if content:
                    path = (data.get("sources") or [""])[i] if i < len(data.get("sources", [])) else ""
                    sources_text.append(f"// [Source: {path}]\n{content}")
            return "\n\n".join(sources_text)
        except Exception:
            return None


# ===========================================================================
# Module-level helpers
# ===========================================================================

def _detect_minified(code: str) -> bool:
    """Heuristic: average line length > 400 → likely minified."""
    if not code:
        return False
    lines = code.splitlines()
    if len(lines) < 5:
        return True
    return (len(code) / len(lines)) > 400


def _extract_source_map_url(code: str, js_url: str) -> Optional[str]:
    m = _SOURCE_MAP_RE.search(code)
    if not m:
        return None
    ref = m.group(1).strip()
    if ref.startswith("data:"):
        return None
    return urljoin(js_url, ref)


def _valid_api_path(path: str) -> bool:
    if not path or len(path) < 3:
        return False
    if not (path.startswith("/") or path.startswith("http")):
        return False
    skip_ext = {".js", ".css", ".png", ".jpg", ".gif", ".svg",
                ".woff", ".ttf", ".ico", ".html", ".map", ".ts"}
    low = path.lower()
    if any(low.endswith(e) for e in skip_ext):
        return False
    if "${" in path or "{{" in path or path.count("*") > 1:
        return False
    return True


def _is_placeholder(value: str) -> bool:
    clean = value.lower().strip("'\"")
    if clean in _PLACEHOLDERS:
        return True
    if clean.startswith(("your_", "your-", "example_", "<", "insert")):
        return True
    # All same character → e.g. "xxxxxxxxxxxx"
    if len(set(clean)) <= 2 and len(clean) >= 8:
        return True
    return False


# ===========================================================================
# Convenience function
# ===========================================================================

async def analyse_js_files(
    client: HTTPClient,
    base_url: str,
    script_urls: List[str],
    max_concurrent: int = 6,
) -> Dict[str, Any]:
    """
    High-level convenience function.
    Returns an aggregated findings dict ready for the Knowledge Base.
    """
    engine = JSAnalysisEngine(client, base_url, max_concurrent)
    reports = await engine.analyse_scripts(script_urls)
    return engine.aggregate(reports)
