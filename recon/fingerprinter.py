"""
Fingerprinting Framework

Builds a complete identity profile of any web application from the first
request onward. Every piece of technology detected — server, framework,
language, database, CMS, WAF, CDN, cloud provider — is stored in a
structured AppFingerprint and made available to all other engine components.

Detection signals used:
  • HTTP response headers (Server, X-Powered-By, Via, X-Generator, …)
  • Cookie names and attributes
  • HTML meta tags, generator tags, page structure
  • JavaScript globals, bundle names, framework-specific DOM patterns
  • Static asset paths and file naming conventions
  • Error page content and stack traces
  • TLS certificate metadata (CN, SANs, O field)
  • HTTP behaviour (version, compression, redirect patterns)
  • Response timing patterns (distinguishes sync vs async backends)
  • CSP / CORS / Cache / ETag header semantics
  • Default paths (robots.txt, sitemap.xml, wp-login.php, …)

All detections carry a ConfidenceLevel so downstream components know
how much to trust the result.
"""

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import re
import ssl
import socket
import json
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..core.http_client import HTTPClient, HTTPResponse
from ..utils.helpers import normalize_url, get_base_url


# ─────────────────────────────────────────────────────────────────────────────
# Enums & constants
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceLevel(str, Enum):
    """How certain we are about a fingerprint detection."""
    CERTAIN   = "certain"    # 100 % — unique artefact (e.g. wp-login.php 200)
    HIGH      = "high"       # 80–99 % — strong single signal
    MEDIUM    = "medium"     # 50–79 % — multiple weak signals
    LOW       = "low"        # 20–49 % — single weak signal
    SPECULATIVE = "speculative"  # < 20 % — best-guess


class TechCategory(str, Enum):
    WEB_SERVER    = "web_server"
    FRAMEWORK     = "framework"
    LANGUAGE      = "language"
    DATABASE      = "database"
    CMS           = "cms"
    REVERSE_PROXY = "reverse_proxy"
    WAF           = "waf"
    CDN           = "cdn"
    CLOUD         = "cloud"
    AUTH          = "auth"
    CACHE         = "cache"
    ANALYTICS     = "analytics"
    JS_FRAMEWORK  = "js_framework"
    CONTAINER     = "container"
    OTHER         = "other"


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TechDetection:
    """A single technology that was identified."""
    name: str
    category: TechCategory
    confidence: ConfidenceLevel
    version: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    cpe: Optional[str] = None           # CPE 2.3 string when known

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "confidence": self.confidence.value,
            "version": self.version,
            "evidence": self.evidence,
            "cpe": self.cpe,
        }


@dataclass
class TLSInfo:
    """TLS / SSL metadata extracted from the certificate."""
    protocol_version: Optional[str] = None    # TLSv1.2, TLSv1.3
    cipher_suite: Optional[str] = None
    cert_subject_cn: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_organization: Optional[str] = None
    cert_sans: List[str] = field(default_factory=list)
    cert_not_after: Optional[str] = None
    is_self_signed: bool = False
    supports_http2: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "cipher_suite": self.cipher_suite,
            "cert_subject_cn": self.cert_subject_cn,
            "cert_issuer": self.cert_issuer,
            "cert_organization": self.cert_organization,
            "cert_sans": self.cert_sans,
            "cert_not_after": self.cert_not_after,
            "is_self_signed": self.is_self_signed,
            "supports_http2": self.supports_http2,
        }


@dataclass
class HTTPBehavior:
    """Observed HTTP-level behaviour (compression, versions, redirects, …)."""
    http_version: Optional[str] = None          # HTTP/1.1 or HTTP/2
    supports_gzip: bool = False
    supports_brotli: bool = False
    supports_deflate: bool = False
    keep_alive: bool = False
    redirect_chain: List[str] = field(default_factory=list)
    server_timing_present: bool = False
    etag_format: Optional[str] = None           # weak / strong / none
    cache_control_directives: List[str] = field(default_factory=list)
    cors_enabled: bool = False
    cors_origin: Optional[str] = None
    csp_present: bool = False
    hsts_present: bool = False
    hsts_max_age: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class AppFingerprint:
    """
    The complete identity profile of a scanned application.

    Built incrementally during the scan and shared with all components.
    """
    target_url: str
    base_url: str
    hostname: str

    # Detected technologies (may contain multiple per category)
    technologies: List[TechDetection] = field(default_factory=list)

    # Network / protocol layer
    tls_info: Optional[TLSInfo] = None
    http_behavior: Optional[HTTPBehavior] = None

    # Raw signal caches (useful for debugging / reporting)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    raw_cookies: Dict[str, str] = field(default_factory=dict)

    # Paths that responded with 200 (useful for scanner routing)
    confirmed_paths: Set[str] = field(default_factory=set)

    # Fingerprint hash — lets callers detect when profile changed
    _fingerprint_hash: Optional[str] = field(default=None, repr=False)

    # ── convenience lookups ──────────────────────────────────────────────────

    def get_by_category(self, category: TechCategory) -> List[TechDetection]:
        return [t for t in self.technologies if t.category == category]

    def get_primary(self, category: TechCategory) -> Optional[TechDetection]:
        """Return the highest-confidence detection in a category."""
        candidates = self.get_by_category(category)
        if not candidates:
            return None
        order = [ConfidenceLevel.CERTAIN, ConfidenceLevel.HIGH,
                 ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW,
                 ConfidenceLevel.SPECULATIVE]
        candidates.sort(key=lambda t: order.index(t.confidence))
        return candidates[0]

    def has_waf(self) -> bool:
        return bool(self.get_by_category(TechCategory.WAF))

    def has_cdn(self) -> bool:
        return bool(self.get_by_category(TechCategory.CDN))

    def primary_framework(self) -> Optional[str]:
        t = self.get_primary(TechCategory.FRAMEWORK)
        return t.name if t else None

    def primary_cms(self) -> Optional[str]:
        t = self.get_primary(TechCategory.CMS)
        return t.name if t else None

    def primary_language(self) -> Optional[str]:
        t = self.get_primary(TechCategory.LANGUAGE)
        return t.name if t else None

    def compute_hash(self) -> str:
        """Stable hash of current profile (for change detection)."""
        key_data = sorted(
            f"{t.name}:{t.category}:{t.version}" for t in self.technologies
        )
        self._fingerprint_hash = hashlib.sha256(
            "\n".join(key_data).encode()
        ).hexdigest()[:16]
        return self._fingerprint_hash

    def add_technology(self, tech: TechDetection) -> None:
        """Add a detection, deduplicating by (name, category)."""
        for existing in self.technologies:
            if existing.name == tech.name and existing.category == tech.category:
                # Keep the higher-confidence one; merge evidence
                order = [ConfidenceLevel.CERTAIN, ConfidenceLevel.HIGH,
                         ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW,
                         ConfidenceLevel.SPECULATIVE]
                if order.index(tech.confidence) < order.index(existing.confidence):
                    existing.confidence = tech.confidence
                    if tech.version and not existing.version:
                        existing.version = tech.version
                for ev in tech.evidence:
                    if ev not in existing.evidence:
                        existing.evidence.append(ev)
                return
        self.technologies.append(tech)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "base_url": self.base_url,
            "hostname": self.hostname,
            "technologies": [t.to_dict() for t in self.technologies],
            "tls_info": self.tls_info.to_dict() if self.tls_info else None,
            "http_behavior": self.http_behavior.to_dict() if self.http_behavior else None,
            "confirmed_paths": sorted(self.confirmed_paths),
            "fingerprint_hash": self.compute_hash(),
        }

    def summary(self) -> str:
        """Single-line human-readable summary."""
        parts: List[str] = []
        for cat in [TechCategory.WEB_SERVER, TechCategory.FRAMEWORK,
                    TechCategory.CMS, TechCategory.LANGUAGE,
                    TechCategory.WAF, TechCategory.CDN]:
            t = self.get_primary(cat)
            if t:
                ver = f" {t.version}" if t.version else ""
                parts.append(f"{t.name}{ver}")
        return " | ".join(parts) if parts else "Unknown stack"


# ─────────────────────────────────────────────────────────────────────────────
# Detection rule tables
# These are intentionally kept as plain data structures (lists of tuples) so
# they're easy to extend without touching any logic code.
# ─────────────────────────────────────────────────────────────────────────────

# (header_name_lower, regex_pattern, tech_name, category, confidence)
_HEADER_RULES: List[Tuple[str, str, str, TechCategory, ConfidenceLevel]] = [

    # ── Web Servers ──────────────────────────────────────────────────────────
    ("server", r"(?i)Apache(?:/(\S+))?",        "Apache",   TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)nginx(?:/(\S+))?",         "Nginx",    TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)Microsoft-IIS(?:/(\S+))?", "IIS",      TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)LiteSpeed",                "LiteSpeed",TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)Caddy",                    "Caddy",    TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)Gunicorn(?:/(\S+))?",      "Gunicorn", TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)Uvicorn",                  "Uvicorn",  TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)Jetty(?:/(\S+))?",         "Jetty",    TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)Tomcat(?:/(\S+))?",        "Tomcat",   TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)WEBrick(?:/(\S+))?",       "WEBrick",  TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)Kestrel",                  "Kestrel",  TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),
    ("server", r"(?i)cloudflare",               "Cloudflare",TechCategory.CDN,       ConfidenceLevel.CERTAIN),
    ("server", r"(?i)AmazonS3",                 "Amazon S3",TechCategory.CLOUD,      ConfidenceLevel.CERTAIN),
    ("server", r"(?i)AmazonEC2",                "Amazon EC2",TechCategory.CLOUD,     ConfidenceLevel.HIGH),
    ("server", r"(?i)openresty(?:/(\S+))?",     "OpenResty",TechCategory.WEB_SERVER, ConfidenceLevel.CERTAIN),

    # ── Frameworks / Languages via X-Powered-By ──────────────────────────────
    ("x-powered-by", r"(?i)PHP(?:/(\S+))?",        "PHP",         TechCategory.LANGUAGE,   ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)ASP\.NET(?:\s+MVC\s*(\S+))?","ASP.NET",TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Express",               "Express.js",  TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Next\.js",              "Next.js",     TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Django",                "Django",      TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Rails",                 "Ruby on Rails",TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Laravel",               "Laravel",     TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Symfony(?:/(\S+))?",    "Symfony",     TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Nuxt(?:\.js)?(?:/(\S+))?","Nuxt.js",   TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)FastAPI",               "FastAPI",     TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Flask",                 "Flask",       TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),
    ("x-powered-by", r"(?i)Spring",                "Spring",      TechCategory.FRAMEWORK,  ConfidenceLevel.CERTAIN),

    # ── WAF detection via headers ────────────────────────────────────────────
    ("x-sucuri-id",          r".",  "Sucuri WAF",     TechCategory.WAF, ConfidenceLevel.CERTAIN),
    ("x-sucuri-cache",       r".",  "Sucuri WAF",     TechCategory.WAF, ConfidenceLevel.CERTAIN),
    ("x-fw-hash",            r".",  "Wordfence",      TechCategory.WAF, ConfidenceLevel.HIGH),
    ("x-protected-by",       r".",  "Generic WAF",    TechCategory.WAF, ConfidenceLevel.LOW),
    ("x-shield",             r".",  "Generic WAF",    TechCategory.WAF, ConfidenceLevel.LOW),
    ("x-waf-event-info",     r".",  "Generic WAF",    TechCategory.WAF, ConfidenceLevel.MEDIUM),
    ("cf-ray",               r".",  "Cloudflare",     TechCategory.CDN, ConfidenceLevel.CERTAIN),
    ("cf-cache-status",      r".",  "Cloudflare",     TechCategory.CDN, ConfidenceLevel.CERTAIN),
    ("x-amz-cf-id",          r".",  "CloudFront",     TechCategory.CDN, ConfidenceLevel.CERTAIN),
    ("x-amz-request-id",     r".",  "Amazon AWS",     TechCategory.CLOUD, ConfidenceLevel.HIGH),
    ("x-azure-ref",          r".",  "Azure CDN",      TechCategory.CDN, ConfidenceLevel.CERTAIN),
    ("x-azure-requestid",    r".",  "Microsoft Azure",TechCategory.CLOUD, ConfidenceLevel.HIGH),
    ("x-gcp-cdn-pop",        r".",  "Google Cloud CDN",TechCategory.CDN, ConfidenceLevel.CERTAIN),
    ("x-fastly-request-id",  r".",  "Fastly",         TechCategory.CDN, ConfidenceLevel.CERTAIN),
    ("x-cache",              r"(?i)HIT from akamai", "Akamai",    TechCategory.CDN, ConfidenceLevel.CERTAIN),
    ("via",                  r"(?i)akamai",           "Akamai",    TechCategory.CDN, ConfidenceLevel.HIGH),

    # ── Cache / reverse proxy ────────────────────────────────────────────────
    ("x-varnish",            r".",  "Varnish",        TechCategory.CACHE,         ConfidenceLevel.CERTAIN),
    ("x-cache",              r"(?i)squid", "Squid",   TechCategory.REVERSE_PROXY, ConfidenceLevel.CERTAIN),
    ("x-drupal-cache",       r".",  "Drupal",         TechCategory.CMS,           ConfidenceLevel.CERTAIN),
    ("x-generator",          r"(?i)Drupal (\S+)?","Drupal", TechCategory.CMS,     ConfidenceLevel.CERTAIN),
    ("x-generator",          r"(?i)Joomla","Joomla",   TechCategory.CMS,          ConfidenceLevel.CERTAIN),

    # ── Auth headers ─────────────────────────────────────────────────────────
    ("www-authenticate", r"(?i)Bearer", "JWT/OAuth",  TechCategory.AUTH, ConfidenceLevel.MEDIUM),
    ("www-authenticate", r"(?i)Basic",  "HTTP Basic Auth", TechCategory.AUTH, ConfidenceLevel.HIGH),
    ("www-authenticate", r"(?i)Negotiate","Kerberos/NTLM", TechCategory.AUTH, ConfidenceLevel.HIGH),
]


# (cookie_name_regex, tech_name, category, confidence)
_COOKIE_RULES: List[Tuple[str, str, TechCategory, ConfidenceLevel]] = [
    (r"(?i)^PHPSESSID$",         "PHP",            TechCategory.LANGUAGE,  ConfidenceLevel.CERTAIN),
    (r"(?i)^ASP\.NET_SessionId$","ASP.NET",        TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    (r"(?i)^JSESSIONID$",        "Java EE / Spring",TechCategory.FRAMEWORK,ConfidenceLevel.CERTAIN),
    (r"(?i)^wordpress_",         "WordPress",      TechCategory.CMS,       ConfidenceLevel.CERTAIN),
    (r"(?i)^wp-settings",        "WordPress",      TechCategory.CMS,       ConfidenceLevel.CERTAIN),
    (r"(?i)^laravel_session",    "Laravel",        TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    (r"(?i)^django",             "Django",         TechCategory.FRAMEWORK, ConfidenceLevel.HIGH),
    (r"(?i)^csrftoken$",         "Django",         TechCategory.FRAMEWORK, ConfidenceLevel.MEDIUM),
    (r"(?i)^__utma$",            "Google Analytics",TechCategory.ANALYTICS, ConfidenceLevel.CERTAIN),
    (r"(?i)^_ga$",               "Google Analytics",TechCategory.ANALYTICS, ConfidenceLevel.CERTAIN),
    (r"(?i)^Drupal\.visitor",    "Drupal",         TechCategory.CMS,       ConfidenceLevel.CERTAIN),
    (r"(?i)^Joomla",             "Joomla",         TechCategory.CMS,       ConfidenceLevel.HIGH),
    (r"(?i)^magento2?",          "Magento",        TechCategory.CMS,       ConfidenceLevel.CERTAIN),
    (r"(?i)^PrestaShop",         "PrestaShop",     TechCategory.CMS,       ConfidenceLevel.CERTAIN),
    (r"(?i)^shopify_",           "Shopify",        TechCategory.CMS,       ConfidenceLevel.CERTAIN),
    (r"(?i)^connect\.sid$",      "Express.js / Connect",TechCategory.FRAMEWORK,ConfidenceLevel.HIGH),
    (r"(?i)^rack\.session",      "Ruby Rack",      TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    (r"(?i)^__cfduid$",          "Cloudflare",     TechCategory.CDN,       ConfidenceLevel.CERTAIN),
    (r"(?i)^cf_clearance",       "Cloudflare",     TechCategory.CDN,       ConfidenceLevel.CERTAIN),
    (r"(?i)^AWSALB",             "AWS ELB",        TechCategory.CLOUD,     ConfidenceLevel.CERTAIN),
    (r"(?i)^AWSALBCORS",         "AWS ELB",        TechCategory.CLOUD,     ConfidenceLevel.CERTAIN),
]


# (html_regex, tech_name, category, version_group, confidence)
# version_group = index of regex group that captures version (0 = no capture)
_HTML_RULES: List[Tuple[str, str, TechCategory, int, ConfidenceLevel]] = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)',
     "WordPress", TechCategory.CMS, 1, ConfidenceLevel.CERTAIN),
    (r'<meta[^>]+content=["\']WordPress\s*([\d.]*)["\']',
     "WordPress", TechCategory.CMS, 1, ConfidenceLevel.CERTAIN),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla[^"\']*',
     "Joomla", TechCategory.CMS, 0, ConfidenceLevel.CERTAIN),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]*)',
     "Drupal", TechCategory.CMS, 1, ConfidenceLevel.CERTAIN),
    (r'content=["\']Wix\.com Website Builder',
     "Wix", TechCategory.CMS, 0, ConfidenceLevel.CERTAIN),
    (r'content=["\']Squarespace',
     "Squarespace", TechCategory.CMS, 0, ConfidenceLevel.CERTAIN),
    (r'<link[^>]+/wp-content/',
     "WordPress", TechCategory.CMS, 0, ConfidenceLevel.HIGH),
    (r'<script[^>]+/wp-includes/',
     "WordPress", TechCategory.CMS, 0, ConfidenceLevel.HIGH),
    (r'Powered by <a[^>]*>PrestaShop',
     "PrestaShop", TechCategory.CMS, 0, ConfidenceLevel.CERTAIN),
    (r'<script[^>]+magento',
     "Magento", TechCategory.CMS, 0, ConfidenceLevel.HIGH),
    (r'(?i)shopify\.com/s/files',
     "Shopify", TechCategory.CMS, 0, ConfidenceLevel.CERTAIN),
    (r'ng-version=["\'](\S+)["\']',
     "Angular", TechCategory.JS_FRAMEWORK, 1, ConfidenceLevel.CERTAIN),
    (r'data-reactroot',
     "React", TechCategory.JS_FRAMEWORK, 0, ConfidenceLevel.HIGH),
    (r'__NEXT_DATA__',
     "Next.js", TechCategory.FRAMEWORK, 0, ConfidenceLevel.CERTAIN),
    (r'__NUXT__',
     "Nuxt.js", TechCategory.FRAMEWORK, 0, ConfidenceLevel.CERTAIN),
    (r'id=["\']app["\'][^>]+data-v-',
     "Vue.js", TechCategory.JS_FRAMEWORK, 0, ConfidenceLevel.HIGH),
    (r'<script[^>]+svelte',
     "Svelte", TechCategory.JS_FRAMEWORK, 0, ConfidenceLevel.HIGH),
    (r'<script[^>]+gatsby',
     "Gatsby", TechCategory.FRAMEWORK, 0, ConfidenceLevel.HIGH),
    (r'ASP\.NET_SessionId|__VIEWSTATE|__EVENTVALIDATION',
     "ASP.NET WebForms", TechCategory.FRAMEWORK, 0, ConfidenceLevel.CERTAIN),
    (r'laravel_token',
     "Laravel", TechCategory.FRAMEWORK, 0, ConfidenceLevel.HIGH),
    (r'Yii Framework',
     "Yii", TechCategory.FRAMEWORK, 0, ConfidenceLevel.CERTAIN),
    (r'CakePHP',
     "CakePHP", TechCategory.FRAMEWORK, 0, ConfidenceLevel.HIGH),
    (r'<div[^>]+id=["\']main-container["\']',   # weak CodeIgniter pattern
     "CodeIgniter", TechCategory.FRAMEWORK, 0, ConfidenceLevel.LOW),
    (r'(?i)<input[^>]+name=["\']authenticity_token',
     "Ruby on Rails", TechCategory.FRAMEWORK, 0, ConfidenceLevel.HIGH),
]


# (path, tech_name, category, confidence)
_PATH_RULES: List[Tuple[str, str, TechCategory, ConfidenceLevel]] = [
    ("/wp-login.php",             "WordPress",     TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/wp-admin/",                "WordPress",     TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/wp-content/",              "WordPress",     TechCategory.CMS,      ConfidenceLevel.HIGH),
    ("/wp-json/",                 "WordPress",     TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/xmlrpc.php",               "WordPress",     TechCategory.CMS,      ConfidenceLevel.HIGH),
    ("/administrator/",           "Joomla",        TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/components/com_",          "Joomla",        TechCategory.CMS,      ConfidenceLevel.HIGH),
    ("/?q=node/",                 "Drupal",        TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/sites/default/files/",     "Drupal",        TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/skin/frontend/",           "Magento 1",     TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/pub/static/",              "Magento 2",     TechCategory.CMS,      ConfidenceLevel.HIGH),
    ("/index.php/rest/",          "Magento",       TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/PrestaShop/",              "PrestaShop",    TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/typo3/",                   "TYPO3",         TechCategory.CMS,      ConfidenceLevel.CERTAIN),
    ("/fileadmin/",               "TYPO3",         TechCategory.CMS,      ConfidenceLevel.HIGH),
    ("/django-admin/",            "Django",        TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    ("/rails/info/",              "Ruby on Rails", TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    ("/laravel/",                 "Laravel",       TechCategory.FRAMEWORK, ConfidenceLevel.MEDIUM),
    ("/_next/static/",            "Next.js",       TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    ("/__nuxt/",                  "Nuxt.js",       TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    ("/static/admin/",            "Django",        TechCategory.FRAMEWORK, ConfidenceLevel.MEDIUM),
    ("/actuator/health",          "Spring Boot",   TechCategory.FRAMEWORK, ConfidenceLevel.CERTAIN),
    ("/swagger-ui.html",          "Spring Boot",   TechCategory.FRAMEWORK, ConfidenceLevel.HIGH),
    ("/graphql",                  "GraphQL",       TechCategory.FRAMEWORK, ConfidenceLevel.MEDIUM),
    ("/api/graphql",              "GraphQL",       TechCategory.FRAMEWORK, ConfidenceLevel.MEDIUM),
]


# ─────────────────────────────────────────────────────────────────────────────
# Main Fingerprinter class
# ─────────────────────────────────────────────────────────────────────────────

class FingerprintEngine:
    """
    Orchestrates all fingerprinting sub-routines and produces an AppFingerprint.

    Usage::

        async with HTTPClient(...) as client:
            engine = FingerprintEngine(client)
            profile = await engine.fingerprint("https://example.com")
            print(profile.summary())
    """

    def __init__(
        self,
        client: HTTPClient,
        *,
        probe_paths: bool = True,
        collect_tls: bool = True,
        timeout: float = 10.0,
        max_probe_paths: int = 30,
    ) -> None:
        self._client = client
        self._probe_paths = probe_paths
        self._collect_tls = collect_tls
        self._timeout = timeout
        self._max_probe_paths = max_probe_paths

    # ── Public entry point ───────────────────────────────────────────────────

    async def fingerprint(self, url: str) -> AppFingerprint:
        """
        Full fingerprint run against *url*.
        Returns a populated AppFingerprint regardless of errors.
        """
        url = normalize_url(url)
        parsed = urlparse(url)
        profile = AppFingerprint(
            target_url=url,
            base_url=get_base_url(url),
            hostname=parsed.hostname or "",
        )

        # Always run header/cookie/html analysis on the root page
        await self._analyze_root(profile)

        # TLS analysis (HTTPS only)
        if parsed.scheme == "https" and self._collect_tls:
            profile.tls_info = await self._collect_tls_info(
                parsed.hostname or "", parsed.port or 443
            )

        # Path probing
        if self._probe_paths:
            await self._probe_default_paths(profile)

        profile.compute_hash()
        return profile

    async def update(self, profile: AppFingerprint, response: HTTPResponse) -> None:
        """
        Incrementally update an existing profile from a new response.

        Call this after any significant response during the scan so the
        profile stays current without re-fingerprinting from scratch.
        """
        self._analyze_headers(profile, response)
        self._analyze_cookies(profile, response)
        if response.is_text and response.text:
            self._analyze_html(profile, response.text)

    # ── Root-page analysis ───────────────────────────────────────────────────

    async def _analyze_root(self, profile: AppFingerprint) -> None:
        try:
            response = await self._client.get(profile.target_url)
        except Exception:
            return

        # Cache raw signals
        profile.raw_headers = dict(response.headers)
        profile.raw_cookies = {
            k: v for k, v in (response.cookies or {}).items()
        }

        # Run all analyzers
        self._analyze_headers(profile, response)
        self._analyze_cookies(profile, response)
        self._analyze_http_behavior(profile, response)

        if response.is_text and response.text:
            self._analyze_html(profile, response.text)

        # Record redirect chain
        if profile.http_behavior and response.history:
            profile.http_behavior.redirect_chain = [
                str(r.url) for r in response.history
            ]

    # ── Header analysis ──────────────────────────────────────────────────────

    def _analyze_headers(
        self, profile: AppFingerprint, response: HTTPResponse
    ) -> None:
        headers: Dict[str, str] = {
            k.lower(): v for k, v in response.headers.items()
        }

        for header_name, pattern, tech_name, category, confidence in _HEADER_RULES:
            value = headers.get(header_name)
            if value is None:
                continue
            m = re.search(pattern, value)
            if m:
                version = None
                try:
                    version = m.group(1) if m.lastindex and m.group(1) else None
                except IndexError:
                    pass
                profile.add_technology(TechDetection(
                    name=tech_name,
                    category=category,
                    confidence=confidence,
                    version=version,
                    evidence=[f"{header_name}: {value[:120]}"],
                ))

        # Language inference from server hints
        server = headers.get("server", "")
        if "Python" in server or "python" in server:
            profile.add_technology(TechDetection(
                name="Python", category=TechCategory.LANGUAGE,
                confidence=ConfidenceLevel.HIGH,
                evidence=[f"server: {server}"],
            ))
        if "Ruby" in server:
            profile.add_technology(TechDetection(
                name="Ruby", category=TechCategory.LANGUAGE,
                confidence=ConfidenceLevel.HIGH,
                evidence=[f"server: {server}"],
            ))

        # .NET detection from headers
        dotnet_ver = headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version")
        if dotnet_ver:
            profile.add_technology(TechDetection(
                name="ASP.NET", category=TechCategory.FRAMEWORK,
                confidence=ConfidenceLevel.CERTAIN,
                version=dotnet_ver,
                evidence=[f"x-aspnet-version: {dotnet_ver}"],
            ))
            profile.add_technology(TechDetection(
                name="C# / .NET", category=TechCategory.LANGUAGE,
                confidence=ConfidenceLevel.HIGH,
                evidence=[f"x-aspnet-version: {dotnet_ver}"],
            ))

        # Java detection
        if "tomcat" in server.lower() or "jetty" in server.lower():
            profile.add_technology(TechDetection(
                name="Java", category=TechCategory.LANGUAGE,
                confidence=ConfidenceLevel.HIGH,
                evidence=[f"server: {server}"],
            ))

        # Detect WAF via Cloudflare-specific error behaviour
        if headers.get("cf-ray"):
            if headers.get("x-cloudflare-error") or "challenge" in headers.get("cf-chl-bypass", ""):
                profile.add_technology(TechDetection(
                    name="Cloudflare WAF", category=TechCategory.WAF,
                    confidence=ConfidenceLevel.CERTAIN,
                    evidence=["cf-ray present with challenge"],
                ))

    # ── Cookie analysis ──────────────────────────────────────────────────────

    def _analyze_cookies(
        self, profile: AppFingerprint, response: HTTPResponse
    ) -> None:
        try:
            cookies = dict(response.cookies) if response.cookies else {}
        except Exception:
            cookies = {}

        # Also parse from Set-Cookie headers manually
        for header_val in response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []:
            name_part = header_val.split("=")[0].strip()
            cookies.setdefault(name_part, "")

        for cookie_name in cookies:
            for pattern, tech_name, category, confidence in _COOKIE_RULES:
                if re.search(pattern, cookie_name):
                    profile.add_technology(TechDetection(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        evidence=[f"cookie: {cookie_name}"],
                    ))
                    break

    # ── HTML / DOM analysis ──────────────────────────────────────────────────

    def _analyze_html(self, profile: AppFingerprint, html: str) -> None:
        for pattern, tech_name, category, ver_group, confidence in _HTML_RULES:
            m = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            if m:
                version = None
                if ver_group and m.lastindex and m.lastindex >= ver_group:
                    version = m.group(ver_group) or None
                profile.add_technology(TechDetection(
                    name=tech_name,
                    category=category,
                    confidence=confidence,
                    version=version,
                    evidence=[f"html: matched /{pattern[:60]}/"],
                ))

        # Detect language from script types
        if re.search(r'<script[^>]+type=["\']text/coffeescript', html):
            profile.add_technology(TechDetection(
                name="CoffeeScript", category=TechCategory.LANGUAGE,
                confidence=ConfidenceLevel.CERTAIN,
                evidence=["html: text/coffeescript script type"],
            ))

        # Detect JS framework from src paths
        js_frameworks = [
            (r'react(?:\.min)?\.js', "React",   TechCategory.JS_FRAMEWORK),
            (r'vue(?:\.min)?\.js',   "Vue.js",  TechCategory.JS_FRAMEWORK),
            (r'angular(?:\.min)?\.js',"Angular", TechCategory.JS_FRAMEWORK),
            (r'svelte',              "Svelte",   TechCategory.JS_FRAMEWORK),
            (r'ember(?:\.min)?\.js', "Ember.js", TechCategory.JS_FRAMEWORK),
            (r'backbone(?:\.min)?\.js',"Backbone.js",TechCategory.JS_FRAMEWORK),
            (r'jquery(?:\.min)?\.js',"jQuery",   TechCategory.JS_FRAMEWORK),
            (r'bootstrap(?:\.min)?\.js',"Bootstrap",TechCategory.JS_FRAMEWORK),
            (r'tailwind',            "Tailwind CSS",TechCategory.JS_FRAMEWORK),
        ]
        for pat, name, cat in js_frameworks:
            if re.search(pat, html, re.IGNORECASE):
                profile.add_technology(TechDetection(
                    name=name, category=cat,
                    confidence=ConfidenceLevel.MEDIUM,
                    evidence=[f"html: script src matched /{pat}/"],
                ))

    # ── HTTP behaviour analysis ──────────────────────────────────────────────

    def _analyze_http_behavior(
        self, profile: AppFingerprint, response: HTTPResponse
    ) -> None:
        h = {k.lower(): v for k, v in response.headers.items()}
        beh = HTTPBehavior()

        # HTTP version
        try:
            ver = response._response.http_version
            beh.http_version = ver
            if ver == "HTTP/2":
                beh.supports_http2 = True
        except AttributeError:
            pass

        # Compression
        enc = h.get("content-encoding", "")
        beh.supports_gzip    = "gzip" in enc
        beh.supports_brotli  = "br" in enc
        beh.supports_deflate = "deflate" in enc

        # Keep-alive
        beh.keep_alive = "keep-alive" in h.get("connection", "").lower()

        # Timing header
        beh.server_timing_present = "server-timing" in h

        # ETag format
        etag = h.get("etag", "")
        if etag.startswith("W/"):
            beh.etag_format = "weak"
        elif etag:
            beh.etag_format = "strong"

        # Cache-Control
        cc = h.get("cache-control", "")
        beh.cache_control_directives = [
            d.strip() for d in cc.split(",") if d.strip()
        ]

        # CORS
        acao = h.get("access-control-allow-origin")
        if acao:
            beh.cors_enabled = True
            beh.cors_origin = acao

        # Security headers
        beh.csp_present = "content-security-policy" in h
        hsts = h.get("strict-transport-security", "")
        beh.hsts_present = bool(hsts)
        m = re.search(r"max-age=(\d+)", hsts)
        if m:
            beh.hsts_max_age = int(m.group(1))

        profile.http_behavior = beh

    # ── TLS analysis ────────────────────────────────────────────────────────

    async def _collect_tls_info(
        self, hostname: str, port: int
    ) -> Optional[TLSInfo]:
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def _connect() -> ssl.SSLSocket:
                conn = ctx.wrap_socket(
                    socket.create_connection((hostname, port), timeout=self._timeout),
                    server_hostname=hostname,
                )
                return conn

            try:
                conn = await loop.run_in_executor(None, _connect)
            except ssl.SSLCertVerificationError:
                # Retry without verification to still collect cert metadata
                ctx_noverify = ssl.create_default_context()
                ctx_noverify.check_hostname = False
                ctx_noverify.verify_mode = ssl.CERT_NONE

                def _connect_nv() -> ssl.SSLSocket:
                    return ctx_noverify.wrap_socket(
                        socket.create_connection((hostname, port), timeout=self._timeout),
                        server_hostname=hostname,
                    )
                conn = await loop.run_in_executor(None, _connect_nv)

            info = TLSInfo()
            info.protocol_version = conn.version()
            info.cipher_suite = conn.cipher()[0] if conn.cipher() else None

            cert = conn.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                info.cert_subject_cn    = subject.get("commonName")
                info.cert_issuer        = issuer.get("commonName")
                info.cert_organization  = subject.get("organizationName")
                info.cert_not_after     = cert.get("notAfter")
                info.is_self_signed     = (
                    info.cert_subject_cn == info.cert_issuer
                )
                # SANs
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type in ("DNS", "IP Address"):
                        info.cert_sans.append(san_value)

            conn.close()
            return info
        except Exception:
            return None

    # ── Path probing ─────────────────────────────────────────────────────────

    async def _probe_default_paths(self, profile: AppFingerprint) -> None:
        """
        Send HEAD requests to known default paths and use 200 responses to
        confirm technology presence.
        """
        base = profile.base_url
        # Prioritise paths that give high-confidence signals first
        paths_to_probe = _PATH_RULES[:self._max_probe_paths]

        tasks = [
            self._probe_single_path(profile, base, path, tech_name, category, confidence)
            for path, tech_name, category, confidence in paths_to_probe
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_single_path(
        self,
        profile: AppFingerprint,
        base: str,
        path: str,
        tech_name: str,
        category: TechCategory,
        confidence: ConfidenceLevel,
    ) -> None:
        url = base.rstrip("/") + path
        try:
            response = await self._client.head(url)
        except Exception:
            return

        if response.status_code == 200:
            profile.confirmed_paths.add(path)
            profile.add_technology(TechDetection(
                name=tech_name,
                category=category,
                confidence=confidence,
                evidence=[f"path {path} returned 200"],
            ))
            # Update any existing header/cookie info from this response too
            self._analyze_headers(profile, response)
            self._analyze_cookies(profile, response)


# ─────────────────────────────────────────────────────────────────────────────
# Knowledge base (used by scanners to look up tech-specific attack data)
# ─────────────────────────────────────────────────────────────────────────────

class TechKnowledgeBase:
    """
    Static knowledge base that maps detected technologies to scanner hints.

    Scanners call kb.get(tech_name) to get a dict with:
      - default_paths      : extra paths worth scanning for this tech
      - dangerous_headers  : headers that may disclose sensitive data
      - known_vulns        : CVE IDs / common vuln families
      - payload_families   : which payload families to prioritise
      - auth_patterns      : typical auth endpoints
    """

    _DB: Dict[str, Dict[str, Any]] = {
        "WordPress": {
            "default_paths": [
                "/wp-json/wp/v2/users",
                "/wp-login.php",
                "/wp-admin/admin-ajax.php",
                "/?author=1",
                "/xmlrpc.php",
                "/wp-config.php.bak",
                "/wp-content/debug.log",
            ],
            "dangerous_headers": ["x-pingback"],
            "known_vulns": ["CVE-2017-5487", "CVE-2019-8943"],
            "payload_families": ["sqli", "xss", "path_traversal", "ssrf"],
            "auth_patterns": {"login": "/wp-login.php", "api": "/wp-json/"},
        },
        "Drupal": {
            "default_paths": [
                "/user/login",
                "/?q=admin",
                "/admin/config",
                "/CHANGELOG.txt",
                "/core/CHANGELOG.txt",
                "/sites/default/settings.php",
            ],
            "dangerous_headers": ["x-drupal-cache", "x-generator"],
            "known_vulns": ["CVE-2018-7600", "CVE-2019-6340"],
            "payload_families": ["sqli", "xss", "rce", "ssrf"],
            "auth_patterns": {"login": "/user/login"},
        },
        "Joomla": {
            "default_paths": [
                "/administrator/index.php",
                "/configuration.php",
                "/README.txt",
                "/administrator/manifests/files/joomla.xml",
            ],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2015-8562", "CVE-2017-8917"],
            "payload_families": ["sqli", "xss", "rfi"],
            "auth_patterns": {"login": "/administrator/index.php"},
        },
        "Laravel": {
            "default_paths": [
                "/.env",
                "/storage/logs/laravel.log",
                "/public/storage",
                "/api/user",
            ],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2021-3129"],
            "payload_families": ["sqli", "ssti", "mass_assignment"],
            "auth_patterns": {"login": "/login", "api": "/api/"},
        },
        "Django": {
            "default_paths": [
                "/admin/",
                "/api/",
                "/__debug__/",
                "/static/admin/",
            ],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2019-14234"],
            "payload_families": ["sqli", "xss", "ssti"],
            "auth_patterns": {"login": "/admin/login/", "api": "/api/"},
        },
        "Spring Boot": {
            "default_paths": [
                "/actuator",
                "/actuator/env",
                "/actuator/beans",
                "/actuator/mappings",
                "/actuator/heapdump",
                "/actuator/logfile",
                "/swagger-ui.html",
                "/v2/api-docs",
                "/v3/api-docs",
            ],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2022-22965", "CVE-2022-22963"],
            "payload_families": ["rce", "ssrf", "sqli"],
            "auth_patterns": {"login": "/login", "api": "/api/"},
        },
        "IIS": {
            "default_paths": [
                "/iisstart.htm",
                "/web.config",
                "/aspnet_client/",
            ],
            "dangerous_headers": ["x-powered-by", "x-aspnet-version"],
            "known_vulns": ["CVE-2017-7269", "CVE-2015-1635"],
            "payload_families": ["xss", "path_traversal", "ssrf"],
            "auth_patterns": {"login": "/login", "ntlm": "negotiate"},
        },
        "Nginx": {
            "default_paths": ["/nginx_status", "/.well-known/"],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2017-7529", "CVE-2019-20372"],
            "payload_families": ["path_traversal", "ssrf"],
            "auth_patterns": {},
        },
        "Apache": {
            "default_paths": [
                "/server-status",
                "/server-info",
                "/.htaccess",
                "/.htpasswd",
            ],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2021-41773", "CVE-2021-42013"],
            "payload_families": ["path_traversal", "rce", "ssrf"],
            "auth_patterns": {},
        },
        "Ruby on Rails": {
            "default_paths": [
                "/rails/info/properties",
                "/rails/mailers",
                "/cable",
            ],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2019-5418", "CVE-2020-8164"],
            "payload_families": ["ssti", "mass_assignment", "sqli"],
            "auth_patterns": {"login": "/users/sign_in", "api": "/api/"},
        },
        "Magento": {
            "default_paths": [
                "/admin",
                "/index.php/admin",
                "/pub/static/",
                "/skin/frontend/",
                "/downloader/",
            ],
            "dangerous_headers": [],
            "known_vulns": ["CVE-2019-7139", "CVE-2016-4010"],
            "payload_families": ["sqli", "xss", "rce", "path_traversal"],
            "auth_patterns": {"login": "/admin", "api": "/index.php/rest/"},
        },
        "GraphQL": {
            "default_paths": [
                "/graphql",
                "/api/graphql",
                "/graphiql",
                "/__graphql",
                "/v1/graphql",
            ],
            "dangerous_headers": [],
            "known_vulns": [],
            "payload_families": ["graphql_injection", "idor", "sqli"],
            "auth_patterns": {},
        },
    }

    @classmethod
    def get(cls, tech_name: str) -> Dict[str, Any]:
        """Return knowledge entry for a technology, or an empty dict."""
        return cls._DB.get(tech_name, {})

    @classmethod
    def get_extra_paths(cls, tech_name: str) -> List[str]:
        return cls.get(tech_name).get("default_paths", [])

    @classmethod
    def get_payload_families(cls, tech_name: str) -> List[str]:
        return cls.get(tech_name).get("payload_families", [])

    @classmethod
    def get_auth_patterns(cls, tech_name: str) -> Dict[str, str]:
        return cls.get(tech_name).get("auth_patterns", {})

    @classmethod
    def build_scan_hints(cls, profile: AppFingerprint) -> Dict[str, Any]:
        """
        Aggregate scan hints from all detected technologies in a profile.

        Returns::

            {
                "extra_paths": [...],        # deduplicated paths to probe
                "payload_families": [...],   # dedup'd payload families to use
                "auth_patterns": {...},      # merged auth hints
                "dangerous_headers": [...],  # headers to flag if seen
                "known_vulns": [...],        # CVEs to include in report context
            }
        """
        extra_paths:      Set[str] = set()
        payload_families: Set[str] = set()
        auth_patterns:    Dict[str, str] = {}
        dangerous_headers:Set[str] = set()
        known_vulns:      Set[str] = set()

        for tech in profile.technologies:
            if tech.confidence in (ConfidenceLevel.SPECULATIVE, ConfidenceLevel.LOW):
                continue  # Don't act on very weak signals
            entry = cls.get(tech.name)
            extra_paths.update(entry.get("default_paths", []))
            payload_families.update(entry.get("payload_families", []))
            auth_patterns.update(entry.get("auth_patterns", {}))
            dangerous_headers.update(entry.get("dangerous_headers", []))
            known_vulns.update(entry.get("known_vulns", []))

        return {
            "extra_paths":       sorted(extra_paths),
            "payload_families":  sorted(payload_families),
            "auth_patterns":     auth_patterns,
            "dangerous_headers": sorted(dangerous_headers),
            "known_vulns":       sorted(known_vulns),
        }
