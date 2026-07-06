"""
Passive Intelligence Engine

Collects the maximum possible amount of information about a target
WITHOUT sending any exploit payloads. Every request made here is a
legitimate-looking read of a publicly accessible resource.

Signal sources:
  • robots.txt               — disallowed / allowed paths, sitemaps
  • sitemap.xml / sitemap index — full URL inventory
  • manifest.json / PWA manifest — app name, start URL, icons, scope
  • RSS / Atom feeds         — content endpoints, author info
  • OpenAPI / Swagger specs  — full API surface (paths, methods, params)
  • GraphQL introspection    — schema, types, queries, mutations
  • JavaScript files         — endpoints, secrets, config objects
  • Source maps (.map)       — original source paths, module names
  • HTML comments            — developer notes, hidden paths
  • Backup / swap files      — .bak, ~, .old, .orig, .swp
  • Directory listings       — Apache / Nginx autoindex
  • Security headers         — CSP sources → third-party domains
  • Cookies                  — names, domains, paths, flags
  • CORS headers             — allowed origins
  • Cache / ETag headers     — caching strategy clues
  • Server banners           — version disclosure
  • HTML metadata            — keywords, description, author, generator
  • well-known resources     — security.txt, openid-configuration, …

All findings go into an IntelligenceReport which is shared with
FingerprintEngine and all scanners.
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
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

try:
    import defusedxml.ElementTree as _safe_ET
    _DEFUSED = True
except ImportError:
    _safe_ET = ET          # type: ignore[assignment]
    _DEFUSED = False

from ..core.http_client import HTTPClient, HTTPResponse
from ..utils.helpers import normalize_url, get_base_url


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DiscoveredEndpoint:
    """A URL / path found through passive analysis."""
    url: str
    source: str                          # "robots", "sitemap", "js", "graphql", …
    method: Optional[str] = None         # GET / POST / … when known
    params: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    auth_required: Optional[bool] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "source": self.source,
            "method": self.method,
            "params": self.params,
            "content_type": self.content_type,
            "auth_required": self.auth_required,
            "notes": self.notes,
        }


@dataclass
class SecretFinding:
    """A potential secret / credential found in a passive source."""
    kind: str        # "api_key", "aws_key", "jwt", "password", "token", …
    value: str       # (truncated for safety in report)
    source_url: str
    context: str     # surrounding text snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value[:40] + "…" if len(self.value) > 40 else self.value,
            "source_url": self.source_url,
            "context": self.context[:120],
        }


@dataclass
class ThirdPartyService:
    """An external service / domain referenced by the application."""
    domain: str
    source: str      # "csp", "cors", "js_import", "html_src", …
    purpose: str     # "cdn", "analytics", "payment", "auth", "media", …

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain, "source": self.source, "purpose": self.purpose}


@dataclass
class IntelligenceReport:
    """
    Aggregated passive intelligence about a target.
    Shared across all engine components after collection.
    """
    target_url: str
    base_url: str

    # Discovered attack surface
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    disallowed_paths: List[str] = field(default_factory=list)   # from robots.txt
    allowed_paths: List[str] = field(default_factory=list)

    # Secrets / sensitive data
    secrets: List[SecretFinding] = field(default_factory=list)

    # Third-party services
    third_party_services: List[ThirdPartyService] = field(default_factory=list)

    # API surface
    openapi_spec: Optional[Dict[str, Any]] = None
    graphql_schema: Optional[Dict[str, Any]] = None
    websocket_urls: List[str] = field(default_factory=list)

    # Metadata
    cloud_resources: List[str] = field(default_factory=list)    # S3, GCS, Azure blob URLs
    internal_urls: List[str] = field(default_factory=list)      # non-public URLs
    hidden_paths: List[str] = field(default_factory=list)       # backup/swap files found
    html_comments: List[str] = field(default_factory=list)

    # Security posture signals
    security_txt: Optional[Dict[str, str]] = None
    csp_directives: Dict[str, List[str]] = field(default_factory=dict)
    cors_origins: List[str] = field(default_factory=list)
    exposed_headers: Dict[str, str] = field(default_factory=dict)

    # Dedup set (internal)
    _seen_urls: Set[str] = field(default_factory=set, repr=False)

    def add_endpoint(self, ep: DiscoveredEndpoint) -> None:
        key = f"{ep.method or 'GET'}:{ep.url}"
        if key not in self._seen_urls:
            self._seen_urls.add(key)
            self.endpoints.append(ep)

    def endpoint_urls(self) -> List[str]:
        return [e.url for e in self.endpoints]

    def summary(self) -> Dict[str, int]:
        return {
            "endpoints": len(self.endpoints),
            "secrets": len(self.secrets),
            "third_party_services": len(self.third_party_services),
            "cloud_resources": len(self.cloud_resources),
            "hidden_paths": len(self.hidden_paths),
            "html_comments": len(self.html_comments),
            "disallowed_paths": len(self.disallowed_paths),
            "websocket_urls": len(self.websocket_urls),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "base_url": self.base_url,
            "summary": self.summary(),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "disallowed_paths": self.disallowed_paths,
            "secrets": [s.to_dict() for s in self.secrets],
            "third_party_services": [t.to_dict() for t in self.third_party_services],
            "cloud_resources": self.cloud_resources,
            "internal_urls": self.internal_urls,
            "hidden_paths": self.hidden_paths,
            "html_comments": self.html_comments[:50],   # cap for report size
            "websocket_urls": self.websocket_urls,
            "csp_directives": self.csp_directives,
            "cors_origins": self.cors_origins,
            "exposed_headers": self.exposed_headers,
            "security_txt": self.security_txt,
            "openapi_available": self.openapi_spec is not None,
            "graphql_schema_available": self.graphql_schema is not None,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Secret detection patterns
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("aws_access_key",      re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    ("aws_secret_key",      re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("google_api_key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("google_oauth",        re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
    ("stripe_live_key",     re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("stripe_pub_key",      re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("github_token",        re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("github_oauth",        re.compile(r"gho_[0-9A-Za-z]{36}")),
    ("slack_token",         re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}")),
    ("slack_webhook",       re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+")),
    ("jwt_token",           re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")),
    ("private_key",         re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key",     re.compile(r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9\-_]{16,64})['\"]")),
    ("generic_password",    re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,64})['\"]")),
    ("generic_secret",      re.compile(r"(?i)(?:secret|token)\s*[=:]\s*['\"]([a-zA-Z0-9\-_./+]{8,64})['\"]")),
    ("db_connection",       re.compile(r"(?i)(?:mysql|postgresql|mongodb|redis)://[^\s'\"]+")),
    ("sendgrid_key",        re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}")),
    ("twilio_key",          re.compile(r"SK[0-9a-fA-F]{32}")),
    ("heroku_api_key",      re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")),
    ("firebase_url",        re.compile(r"https://[a-zA-Z0-9\-]+\.firebaseio\.com")),
    ("azure_storage",       re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+")),
    ("mailgun_key",         re.compile(r"key-[0-9a-zA-Z]{32}")),
]

# Third-party domain → purpose mapping
_TP_PURPOSE: Dict[str, str] = {
    "google-analytics.com": "analytics", "googletagmanager.com": "analytics",
    "segment.com": "analytics",          "mixpanel.com": "analytics",
    "hotjar.com": "analytics",           "fullstory.com": "analytics",
    "amplitude.com": "analytics",
    "stripe.com": "payment",             "braintreegateway.com": "payment",
    "paypal.com": "payment",             "adyen.com": "payment",
    "auth0.com": "auth",                 "okta.com": "auth",
    "cognito": "auth",                   "clerk.dev": "auth",
    "firebase.com": "auth",              "googleapis.com": "cdn",
    "cloudflare.com": "cdn",             "fastly.net": "cdn",
    "akamaized.net": "cdn",              "bootstrapcdn.com": "cdn",
    "jsdelivr.net": "cdn",               "unpkg.com": "cdn",
    "cdnjs.cloudflare.com": "cdn",       "sentry.io": "monitoring",
    "bugsnag.com": "monitoring",         "datadog-browser-agent.com": "monitoring",
    "intercom.io": "support",            "zendesk.com": "support",
    "twilio.com": "communication",       "sendgrid.net": "communication",
    "mailchimp.com": "marketing",        "hubspot.com": "marketing",
    "s3.amazonaws.com": "cloud_storage", "storage.googleapis.com": "cloud_storage",
    "blob.core.windows.net": "cloud_storage",
}

# Cloud resource patterns
_CLOUD_PATTERNS: List[re.Pattern] = [
    re.compile(r"https?://[a-zA-Z0-9\-\.]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com[^\s'\">]*"),
    re.compile(r"https?://s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com/[a-zA-Z0-9\-_/\.%]+"),
    re.compile(r"https?://[a-zA-Z0-9\-\.]+\.blob\.core\.windows\.net[^\s'\">]*"),
    re.compile(r"https?://storage\.googleapis\.com/[a-zA-Z0-9\-_/\.%]+"),
    re.compile(r"https?://[a-zA-Z0-9\-]+\.firebaseio\.com[^\s'\">]*"),
    re.compile(r"https?://[a-zA-Z0-9\-]+\.firebasestorage\.app[^\s'\">]*"),
    re.compile(r"https?://[a-zA-Z0-9\-]+\.azurewebsites\.net[^\s'\">]*"),
    re.compile(r"arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:[0-9]*:[^\s'\"]+"),
]

# Backup / swap file suffixes to probe
_BACKUP_SUFFIXES = [
    ".bak", ".old", ".orig", "~", ".swp", ".tmp", ".backup",
    ".copy", ".1", ".2", ".save", ".disabled", ".dist",
]

# Well-known paths to always check
_WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/webfinger",
    "/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/manifest.json",
    "/site.webmanifest",
    "/feed.xml",
    "/feed/",
    "/rss.xml",
    "/atom.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/change-password",
    "/humans.txt",
    "/ads.txt",
]

# GraphQL introspection query
_GRAPHQL_INTROSPECTION = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
      }
    }
    fragment FullType on __Type {
      kind name description
      fields(includeDeprecated: true) {
        name description isDeprecated deprecationReason
        args { ...InputValue }
        type { ...TypeRef }
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description }
      possibleTypes { ...TypeRef }
    }
    fragment InputValue on __InputValue {
      name description type { ...TypeRef } defaultValue
    }
    fragment TypeRef on __Type {
      kind name
      ofType { kind name ofType { kind name ofType { kind name } } }
    }
    """
}


# ─────────────────────────────────────────────────────────────────────────────
# Main engine
# ─────────────────────────────────────────────────────────────────────────────

class PassiveIntelligenceEngine:
    """
    Gathers maximum intelligence about a target with zero exploit payloads.

    Usage::

        engine = PassiveIntelligenceEngine(client)
        report = await engine.collect("https://example.com")
        # report.endpoints  → all discovered URLs
        # report.secrets    → potential credentials found
    """

    def __init__(
        self,
        client: HTTPClient,
        *,
        probe_backups: bool = True,
        try_graphql: bool = True,
        max_sitemap_urls: int = 2000,
        max_js_files: int = 30,
        concurrency: int = 8,
    ) -> None:
        self._client = client
        self._probe_backups = probe_backups
        self._try_graphql = try_graphql
        self._max_sitemap_urls = max_sitemap_urls
        self._max_js_files = max_js_files
        self._concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)

    # ── Public entry point ───────────────────────────────────────────────────

    async def collect(self, url: str) -> IntelligenceReport:
        """
        Run all passive collection routines against *url*.
        Safe to call concurrently with other scans — no side effects.
        """
        url = normalize_url(url)
        report = IntelligenceReport(
            target_url=url,
            base_url=get_base_url(url),
        )

        # Phase A — well-known + robots + sitemap (sequential, fast)
        await self._collect_well_known(report)
        await self._collect_robots(report)
        await self._collect_sitemaps(report)

        # Phase B — root page deep analysis
        await self._analyze_root_page(report)

        # Phase C — API discovery (OpenAPI / GraphQL)
        await self._discover_openapi(report)
        if self._try_graphql:
            await self._discover_graphql(report)

        # Phase D — JS file analysis (concurrent)
        await self._analyze_js_files(report)

        # Phase E — backup file probing
        if self._probe_backups:
            await self._probe_backup_files(report)

        return report

    # ── Well-known resources ─────────────────────────────────────────────────

    async def _collect_well_known(self, report: IntelligenceReport) -> None:
        tasks = [
            self._fetch_well_known(report, path)
            for path in _WELL_KNOWN_PATHS
            if path not in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml")
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_well_known(
        self, report: IntelligenceReport, path: str
    ) -> None:
        url = report.base_url.rstrip("/") + path
        try:
            async with self._sem:
                resp = await self._client.get(url)
        except Exception:
            return

        if resp.status_code != 200 or not resp.is_text:
            return

        text = resp.text

        if "security.txt" in path:
            self._parse_security_txt(report, text, url)
        elif "openid-configuration" in path or "oauth-authorization-server" in path:
            self._parse_oauth_config(report, text, url)
        elif "manifest" in path:
            self._parse_manifest(report, text, url)
        elif "feed" in path or "rss" in path or "atom" in path:
            self._parse_feed(report, text, url)

    def _parse_security_txt(
        self, report: IntelligenceReport, text: str, source: str
    ) -> None:
        data: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                data[key.strip()] = value.strip()
        report.security_txt = data

    def _parse_oauth_config(
        self, report: IntelligenceReport, text: str, source: str
    ) -> None:
        try:
            config = json.loads(text)
            for key in ("authorization_endpoint", "token_endpoint",
                        "userinfo_endpoint", "jwks_uri", "revocation_endpoint"):
                ep_url = config.get(key)
                if ep_url:
                    report.add_endpoint(DiscoveredEndpoint(
                        url=ep_url, source="openid-configuration",
                        method="POST" if "token" in key else "GET",
                        notes=key,
                    ))
        except (json.JSONDecodeError, TypeError):
            pass

    def _parse_manifest(
        self, report: IntelligenceReport, text: str, source: str
    ) -> None:
        try:
            manifest = json.loads(text)
            start = manifest.get("start_url")
            if start:
                report.add_endpoint(DiscoveredEndpoint(
                    url=urljoin(report.base_url, start),
                    source="manifest",
                    notes="PWA start_url",
                ))
            scope = manifest.get("scope")
            if scope:
                report.add_endpoint(DiscoveredEndpoint(
                    url=urljoin(report.base_url, scope),
                    source="manifest",
                    notes="PWA scope",
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    def _parse_feed(
        self, report: IntelligenceReport, text: str, source: str
    ) -> None:
        try:
            root = _safe_ET.fromstring(text)
            for tag in ("link", "{http://www.w3.org/2005/Atom}link"):
                for el in root.iter(tag):
                    href = el.get("href") or el.text
                    if href and href.startswith("http"):
                        report.add_endpoint(DiscoveredEndpoint(
                            url=href, source="rss_feed"
                        ))
        except ET.ParseError:
            pass

    # ── robots.txt ───────────────────────────────────────────────────────────

    async def _collect_robots(self, report: IntelligenceReport) -> None:
        url = report.base_url.rstrip("/") + "/robots.txt"
        try:
            async with self._sem:
                resp = await self._client.get(url)
        except Exception:
            return

        if resp.status_code != 200 or not resp.is_text:
            return

        sitemap_urls: List[str] = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    report.disallowed_paths.append(path)
                    # Disallowed paths are interesting — add as endpoint to probe
                    full = urljoin(report.base_url, path)
                    report.add_endpoint(DiscoveredEndpoint(
                        url=full, source="robots_disallow",
                        notes="disallowed in robots.txt — may be sensitive",
                    ))
            elif low.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    report.allowed_paths.append(path)
                    report.add_endpoint(DiscoveredEndpoint(
                        url=urljoin(report.base_url, path),
                        source="robots_allow",
                    ))
            elif low.startswith("sitemap:"):
                sm_url = line.split(":", 1)[1].strip()
                if sm_url:
                    sitemap_urls.append(sm_url)

        # Parse any sitemaps referenced in robots.txt
        for sm_url in sitemap_urls:
            await self._parse_sitemap_url(report, sm_url)

    # ── Sitemap ──────────────────────────────────────────────────────────────

    async def _collect_sitemaps(self, report: IntelligenceReport) -> None:
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            url = report.base_url.rstrip("/") + path
            await self._parse_sitemap_url(report, url)

    async def _parse_sitemap_url(
        self, report: IntelligenceReport, url: str
    ) -> None:
        if len(report.endpoints) >= self._max_sitemap_urls:
            return
        try:
            async with self._sem:
                resp = await self._client.get(url)
        except Exception:
            return

        if resp.status_code != 200 or not resp.is_text:
            return

        await self._parse_sitemap_xml(report, resp.text, url)

    async def _parse_sitemap_xml(
        self, report: IntelligenceReport, xml_text: str, source_url: str
    ) -> None:
        try:
            root = _safe_ET.fromstring(xml_text)
        except ET.ParseError:
            return

        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

        # Sitemap index — recurse into child sitemaps
        for sitemap_el in root.findall(".//sm:sitemap/sm:loc", ns):
            child_url = (sitemap_el.text or "").strip()
            if child_url:
                await self._parse_sitemap_url(report, child_url)

        # Regular sitemap — extract URLs
        for url_el in root.findall(".//sm:url/sm:loc", ns):
            page_url = (url_el.text or "").strip()
            if page_url and len(report.endpoints) < self._max_sitemap_urls:
                report.add_endpoint(DiscoveredEndpoint(
                    url=page_url, source="sitemap"
                ))

    # ── Root page analysis ───────────────────────────────────────────────────

    async def _analyze_root_page(self, report: IntelligenceReport) -> None:
        try:
            async with self._sem:
                resp = await self._client.get(report.target_url)
        except Exception:
            return

        self._extract_security_headers(report, resp)
        self._extract_cors(report, resp)
        self._extract_csp(report, resp)

        if not resp.is_text:
            return

        html = resp.text
        self._extract_html_comments(report, html, report.target_url)
        self._extract_html_links(report, html, report.target_url)
        self._extract_cloud_resources(report, html, report.target_url)
        self._extract_third_party(report, html, report.target_url)
        self._extract_websocket_urls(report, html)
        self._scan_for_secrets(report, html, report.target_url)

        # Queue JS files for later analysis
        js_urls = self._collect_js_urls(html, report.base_url)
        report._js_queue = getattr(report, "_js_queue", [])
        report._js_queue.extend(js_urls)

    def _extract_security_headers(
        self, report: IntelligenceReport, resp: HTTPResponse
    ) -> None:
        sensitive = [
            "server", "x-powered-by", "x-aspnet-version",
            "x-aspnetmvc-version", "x-generator", "x-runtime",
            "x-version", "x-drupal-cache", "via",
        ]
        for h in sensitive:
            val = resp.header(h) if hasattr(resp, "header") else resp.headers.get(h)
            if val:
                report.exposed_headers[h] = val

    def _extract_cors(
        self, report: IntelligenceReport, resp: HTTPResponse
    ) -> None:
        origin = (
            resp.header("access-control-allow-origin")
            if hasattr(resp, "header")
            else resp.headers.get("access-control-allow-origin")
        )
        if origin and origin not in report.cors_origins:
            report.cors_origins.append(origin)
            if origin == "*":
                report.add_endpoint(DiscoveredEndpoint(
                    url=report.target_url,
                    source="cors",
                    notes="CORS wildcard (*) — open to all origins",
                ))

    def _extract_csp(
        self, report: IntelligenceReport, resp: HTTPResponse
    ) -> None:
        csp = (
            resp.header("content-security-policy")
            if hasattr(resp, "header")
            else resp.headers.get("content-security-policy")
        )
        if not csp:
            return
        for directive_part in csp.split(";"):
            parts = directive_part.strip().split()
            if not parts:
                continue
            directive = parts[0]
            sources = parts[1:]
            report.csp_directives[directive] = sources
            # Extract third-party domains from CSP
            for src in sources:
                if src.startswith("http"):
                    parsed = urlparse(src)
                    if parsed.hostname and parsed.hostname not in report.base_url:
                        purpose = _TP_PURPOSE.get(
                            parsed.hostname,
                            next(
                                (v for k, v in _TP_PURPOSE.items()
                                 if k in parsed.hostname),
                                "unknown"
                            )
                        )
                        report.third_party_services.append(ThirdPartyService(
                            domain=parsed.hostname,
                            source="csp",
                            purpose=purpose,
                        ))

    def _extract_html_comments(
        self, report: IntelligenceReport, html: str, source: str
    ) -> None:
        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        for comment in comments:
            comment = comment.strip()
            if len(comment) < 3 or len(comment) > 2000:
                continue
            if not re.search(r"[a-zA-Z]", comment):
                continue
            report.html_comments.append(comment[:300])
            # Look for paths / URLs in comments
            for m in re.finditer(r"/[\w\-/\.]{3,80}", comment):
                path = m.group(0)
                if any(ext in path for ext in
                       (".php", ".asp", ".jsp", ".py", ".rb", ".js",
                        "/api", "/admin", "/config", "/backup")):
                    report.add_endpoint(DiscoveredEndpoint(
                        url=urljoin(report.base_url, path),
                        source="html_comment",
                        notes=f"found in HTML comment: {comment[:60]}",
                    ))
            self._scan_for_secrets(report, comment, source)

    def _extract_html_links(
        self, report: IntelligenceReport, html: str, source: str
    ) -> None:
        # <a href>, <form action>, <link href>, <script src>, <img src>
        patterns = [
            re.compile(r'<a[^>]+href=["\']([^"\'#]{4,300})["\']', re.I),
            re.compile(r'<form[^>]+action=["\']([^"\']{4,300})["\']', re.I),
            re.compile(r'<link[^>]+href=["\']([^"\']{4,300})["\']', re.I),
            re.compile(r'<script[^>]+src=["\']([^"\']{4,300})["\']', re.I),
        ]
        for pat in patterns:
            for m in pat.finditer(html):
                href = m.group(1).strip()
                if href.startswith("//"):
                    href = "https:" + href
                if not href.startswith("http"):
                    href = urljoin(source, href)
                parsed = urlparse(href)
                if parsed.scheme not in ("http", "https"):
                    continue
                report.add_endpoint(DiscoveredEndpoint(
                    url=href, source="html_link"
                ))

    def _extract_cloud_resources(
        self, report: IntelligenceReport, text: str, source: str
    ) -> None:
        for pat in _CLOUD_PATTERNS:
            for m in pat.finditer(text):
                url = m.group(0).rstrip("\"'>")
                if url not in report.cloud_resources:
                    report.cloud_resources.append(url)

    def _extract_third_party(
        self, report: IntelligenceReport, html: str, source: str
    ) -> None:
        base_host = urlparse(report.base_url).hostname or ""
        for m in re.finditer(r'https?://([a-zA-Z0-9\-\.]+)', html):
            domain = m.group(1).lower()
            if domain == base_host or domain.endswith("." + base_host):
                continue
            purpose = "unknown"
            for key, val in _TP_PURPOSE.items():
                if key in domain:
                    purpose = val
                    break
            already = any(t.domain == domain for t in report.third_party_services)
            if not already:
                report.third_party_services.append(ThirdPartyService(
                    domain=domain, source="html_src", purpose=purpose
                ))

    def _extract_websocket_urls(
        self, report: IntelligenceReport, text: str
    ) -> None:
        for m in re.finditer(r'wss?://[^\s\'">]{4,200}', text):
            ws_url = m.group(0).rstrip("\"',;)}")
            if ws_url not in report.websocket_urls:
                report.websocket_urls.append(ws_url)

    def _collect_js_urls(self, html: str, base: str) -> List[str]:
        urls: List[str] = []
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']{4,300})["\']', html, re.I):
            src = m.group(1).strip()
            if src.startswith("//"):
                src = "https:" + src
            if not src.startswith("http"):
                src = urljoin(base, src)
            if src not in urls:
                urls.append(src)
        return urls

    # ── Secret scanning ──────────────────────────────────────────────────────

    def _scan_for_secrets(
        self, report: IntelligenceReport, text: str, source_url: str
    ) -> None:
        for kind, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(0)
                # Ignore obvious placeholders
                if re.search(r"(?i)example|placeholder|your[-_]?key|xxxx|1234", value):
                    continue
                start = max(0, m.start() - 40)
                end   = min(len(text), m.end() + 40)
                context = text[start:end].replace("\n", " ")
                # Dedup by value prefix
                already = any(
                    s.value[:20] == value[:20] and s.kind == kind
                    for s in report.secrets
                )
                if not already:
                    report.secrets.append(SecretFinding(
                        kind=kind,
                        value=value,
                        source_url=source_url,
                        context=context,
                    ))

    # ── OpenAPI / Swagger discovery ──────────────────────────────────────────

    async def _discover_openapi(self, report: IntelligenceReport) -> None:
        candidate_paths = [
            "/openapi.json", "/openapi.yaml",
            "/swagger.json", "/swagger.yaml",
            "/api-docs", "/api-docs.json",
            "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/swagger-ui.html",
            "/.well-known/openapi.yaml",
            "/api/swagger.json",
        ]
        for path in candidate_paths:
            url = report.base_url.rstrip("/") + path
            try:
                async with self._sem:
                    resp = await self._client.get(url)
            except Exception:
                continue

            if resp.status_code != 200 or not resp.is_text:
                continue

            text = resp.text
            spec: Optional[Dict[str, Any]] = None

            if path.endswith((".json", "-docs")) or "json" in resp.content_type:
                try:
                    spec = json.loads(text)
                except json.JSONDecodeError:
                    continue
            elif path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    spec = yaml.safe_load(text)
                except Exception:
                    continue

            if spec and isinstance(spec, dict) and ("paths" in spec or "openapi" in spec or "swagger" in spec):
                report.openapi_spec = spec
                self._extract_openapi_endpoints(report, spec)
                break  # Found it — no need to check others

    def _extract_openapi_endpoints(
        self, report: IntelligenceReport, spec: Dict[str, Any]
    ) -> None:
        base_path = spec.get("basePath", "")
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            full_url = urljoin(report.base_url, base_path.rstrip("/") + "/" + path.lstrip("/"))
            for method, operation in methods.items():
                if method.startswith("x-") or not isinstance(operation, dict):
                    continue
                params = [
                    p.get("name", "")
                    for p in operation.get("parameters", [])
                    if isinstance(p, dict)
                ]
                auth_required = bool(
                    operation.get("security") or spec.get("security")
                )
                report.add_endpoint(DiscoveredEndpoint(
                    url=full_url,
                    source="openapi",
                    method=method.upper(),
                    params=params,
                    auth_required=auth_required,
                    notes=operation.get("summary", ""),
                ))

    # ── GraphQL discovery ────────────────────────────────────────────────────

    async def _discover_graphql(self, report: IntelligenceReport) -> None:
        candidate_paths = [
            "/graphql", "/api/graphql", "/graphiql",
            "/v1/graphql", "/v2/graphql", "/__graphql",
            "/query", "/gql",
        ]
        for path in candidate_paths:
            url = report.base_url.rstrip("/") + path
            try:
                async with self._sem:
                    resp = await self._client.post_json(url, _GRAPHQL_INTROSPECTION)
            except Exception:
                continue

            if resp.status_code not in (200, 400):
                continue

            try:
                data = json.loads(resp.text)
            except json.JSONDecodeError:
                continue

            if "data" in data or "errors" in data:
                report.add_endpoint(DiscoveredEndpoint(
                    url=url, source="graphql", method="POST",
                    content_type="application/json",
                    notes="GraphQL endpoint confirmed",
                ))
                schema = data.get("data", {}).get("__schema")
                if schema:
                    report.graphql_schema = schema
                    self._extract_graphql_endpoints(report, schema, url)
                break

    def _extract_graphql_endpoints(
        self, report: IntelligenceReport, schema: Dict[str, Any], base_url: str
    ) -> None:
        """Extract Query / Mutation / Subscription fields as virtual endpoints."""
        root_types = {
            "query":        schema.get("queryType", {}).get("name"),
            "mutation":     (schema.get("mutationType") or {}).get("name"),
            "subscription": (schema.get("subscriptionType") or {}).get("name"),
        }
        type_map = {t["name"]: t for t in schema.get("types", []) if isinstance(t, dict)}

        for op_kind, type_name in root_types.items():
            if not type_name:
                continue
            gql_type = type_map.get(type_name, {})
            for field in gql_type.get("fields", []) or []:
                if not isinstance(field, dict):
                    continue
                field_name = field.get("name", "")
                if field_name.startswith("__"):
                    continue
                args = [a.get("name", "") for a in field.get("args", []) if isinstance(a, dict)]
                report.add_endpoint(DiscoveredEndpoint(
                    url=base_url,
                    source="graphql_schema",
                    method="POST",
                    params=args,
                    notes=f"{op_kind}.{field_name}",
                ))

    # ── JavaScript file analysis ─────────────────────────────────────────────

    async def _analyze_js_files(self, report: IntelligenceReport) -> None:
        js_urls: List[str] = getattr(report, "_js_queue", [])
        # Also probe common JS bundle paths
        extra = [
            "/static/js/main.js", "/assets/js/app.js",
            "/js/app.js", "/bundle.js", "/app.bundle.js",
            "/dist/main.js", "/build/static/js/main.chunk.js",
            "/assets/index.js",
        ]
        for p in extra:
            full = report.base_url.rstrip("/") + p
            if full not in js_urls:
                js_urls.append(full)

        tasks = [
            self._analyze_single_js(report, url)
            for url in js_urls[:self._max_js_files]
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _analyze_single_js(
        self, report: IntelligenceReport, url: str
    ) -> None:
        try:
            async with self._sem:
                resp = await self._client.get(url)
        except Exception:
            return

        if resp.status_code != 200 or not resp.is_text:
            return

        js = resp.text
        self._extract_js_endpoints(report, js, url)
        self._extract_cloud_resources(report, js, url)
        self._extract_websocket_urls(report, js)
        self._scan_for_secrets(report, js, url)
        self._extract_graphql_from_js(report, js, url)
        self._extract_feature_flags(report, js, url)

        # Source map
        sm_url = self._find_source_map(js, url)
        if sm_url:
            await self._analyze_source_map(report, sm_url)

    def _extract_js_endpoints(
        self, report: IntelligenceReport, js: str, source: str
    ) -> None:
        patterns = [
            re.compile(r"""(?:url|path|endpoint|href|action|URL)\s*[=:]\s*['"`](/[^'"`\s]{3,200})['"`]"""),
            re.compile(r"""fetch\(['"`](/[^'"`\s]{3,200})['"`]"""),
            re.compile(r"""axios\.(?:get|post|put|delete|patch)\(['"`](/[^'"`\s]{3,200})['"`]"""),
            re.compile(r"""(?:get|post|put|delete|patch)\(['"`](/[^'"`\s]{3,200})['"`]"""),
            re.compile(r"""(?:to|push|replace)\(['"`](/[a-zA-Z0-9_/\-]{3,100})['"`]"""),
            re.compile(r"""/api/[a-zA-Z0-9_/\-\.]{3,80}"""),
            re.compile(r"""/v\d+/[a-zA-Z0-9_/\-\.]{3,80}"""),
            re.compile(r"""route\s*[=:]\s*['"`]([^'"`]{4,100})['"`]"""),
        ]
        base_host = urlparse(report.base_url).hostname or ""
        for pat in patterns:
            for m in pat.finditer(js):
                path = m.group(1) if m.lastindex else m.group(0)
                path = path.strip()
                if path.startswith("http"):
                    parsed = urlparse(path)
                    if parsed.hostname and parsed.hostname != base_host:
                        continue
                full = urljoin(report.base_url, path)
                report.add_endpoint(DiscoveredEndpoint(
                    url=full, source="javascript", notes=f"extracted from {source}"
                ))

    def _extract_graphql_from_js(
        self, report: IntelligenceReport, js: str, source: str
    ) -> None:
        """Find inline GraphQL queries / mutations in JS bundles."""
        gql_patterns = [
            re.compile(r"""gql`(query|mutation|subscription)\s+\w+""", re.S),
            re.compile(r"""graphql`(query|mutation|subscription)\s+\w+""", re.S),
            re.compile(r"""['"`](query|mutation|subscription)\s+\w+\s*\{"""),
        ]
        for pat in gql_patterns:
            for m in pat.finditer(js):
                report.add_endpoint(DiscoveredEndpoint(
                    url=urljoin(report.base_url, "/graphql"),
                    source="js_graphql",
                    method="POST",
                    notes=f"inline GraphQL {m.group(1)} in {source}",
                ))

    def _extract_feature_flags(
        self, report: IntelligenceReport, js: str, source: str
    ) -> None:
        """Extract feature flags and config objects that reveal hidden routes."""
        config_patterns = [
            re.compile(r"""(?:featureFlags?|FEATURES|flags)\s*=\s*\{([^}]{0,500})\}""", re.S),
            re.compile(r"""(?:config|CONFIG|settings|SETTINGS)\s*=\s*\{([^}]{0,500})\}""", re.S),
        ]
        for pat in config_patterns:
            for m in pat.finditer(js):
                block = m.group(1)
                # Extract any paths from the config block
                for pm in re.finditer(r"""['"`](/[a-zA-Z0-9_/\-\.]{3,80})['"`]""", block):
                    path = pm.group(1)
                    report.add_endpoint(DiscoveredEndpoint(
                        url=urljoin(report.base_url, path),
                        source="js_config",
                        notes="extracted from feature flag / config object",
                    ))

    def _find_source_map(self, js: str, js_url: str) -> Optional[str]:
        m = re.search(r"//# sourceMappingURL=(.+)$", js, re.MULTILINE)
        if not m:
            return None
        sm = m.group(1).strip()
        if sm.startswith("data:"):
            return None
        return urljoin(js_url, sm)

    async def _analyze_source_map(
        self, report: IntelligenceReport, url: str
    ) -> None:
        try:
            async with self._sem:
                resp = await self._client.get(url)
        except Exception:
            return

        if resp.status_code != 200 or not resp.is_text:
            return

        try:
            sm = json.loads(resp.text)
        except json.JSONDecodeError:
            return

        # Source map "sources" field reveals original file paths
        for src_path in sm.get("sources", []):
            if src_path:
                report.add_endpoint(DiscoveredEndpoint(
                    url=src_path,
                    source="source_map",
                    notes=f"original source path from {url}",
                ))

    # ── Backup file probing ──────────────────────────────────────────────────

    async def _probe_backup_files(self, report: IntelligenceReport) -> None:
        """
        For every discovered endpoint, probe common backup file suffixes.
        Limits to the most interesting endpoints to avoid flooding.
        """
        candidates = [
            e.url for e in report.endpoints
            if any(e.url.endswith(ext) for ext in (".php", ".asp", ".jsp", ".py", ".rb", ".js", ".conf", ".xml", ".json"))
        ][:50]  # cap

        tasks: List[Any] = []
        for url in candidates:
            for suffix in _BACKUP_SUFFIXES:
                tasks.append(self._probe_single_backup(report, url + suffix))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_single_backup(
        self, report: IntelligenceReport, url: str
    ) -> None:
        try:
            async with self._sem:
                resp = await self._client.head(url)
        except Exception:
            return

        if resp.status_code == 200:
            report.hidden_paths.append(url)
            report.add_endpoint(DiscoveredEndpoint(
                url=url,
                source="backup_probe",
                notes="backup / swap file found — may expose source code",
            ))
