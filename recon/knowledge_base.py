"""
Knowledge Base

A structured, queryable knowledge base that maps every known web technology
to its full security profile.  Every Scanner, every Payload engine, and every
analysis component queries this KB instead of hard-coding assumptions.

Design goals:
  • Single source of truth for technology-specific knowledge
  • Rich entries: default paths, common misconfigurations, known behaviours,
    dangerous features, payload families, header/cookie/auth patterns,
    version indicators, fingerprint rules, CVE context
  • Extensible — new entries can be merged at runtime (plugin-contributed KB)
  • Fast lookup by tech name, category, payload family, or CVE id
  • Integrates seamlessly with FingerprintEngine & AppFingerprint

Entry schema (all fields optional except ``name`` and ``category``)::

    {
      "name":              str,          # canonical tech name
      "aliases":           [str, ...],   # alternative names / spellings
      "category":          TechCategory,

      # Discovery & detection
      "default_paths":     [str, ...],   # paths that exist when tech is present
      "default_files":     [str, ...],   # specific files to probe
      "fingerprint_rules": [FingerprintRule, ...],

      # Headers, cookies, auth
      "header_patterns":   {str: str},   # header-name → regex
      "cookie_patterns":   [str, ...],   # cookie-name regexes
      "auth_patterns":     {str: str},   # role → path
      "dangerous_headers": [str, ...],   # headers that disclose info

      # Scanning guidance
      "payload_families":  [str, ...],   # families to prioritise
      "known_misconfigs":  [str, ...],   # human-readable misconfig names
      "known_behaviors":   {str: str},   # behavior-name → description
      "dangerous_features":[str, ...],   # feature names that expand attack surface

      # Vulnerability context
      "cve_context":       [CVEEntry, ...],

      # Version detection helpers
      "version_indicators":[VersionIndicator, ...],
    }
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
from typing import Any, Dict, FrozenSet, List, Optional, Set

# Re-use the TechCategory enum from the fingerprinter so everything speaks
# the same language.
from .fingerprinter import TechCategory, AppFingerprint, ConfidenceLevel


# ─────────────────────────────────────────────────────────────────────────────
# Supporting data-classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FingerprintRule:
    """
    A single detection rule that maps an observable signal to a technology.

    Attributes:
        signal_type : where to look  (``header``, ``body``, ``cookie``,
                      ``path``, ``js_global``, ``meta``, ``url``)
        pattern     : regex or exact string to match against the signal
        weight      : how much confidence this rule adds (0.0–1.0)
        note        : optional human-readable explanation
    """
    signal_type: str
    pattern:     str
    weight:      float = 0.5
    note:        str   = ""


@dataclass
class CVEEntry:
    """Lightweight CVE reference attached to a technology."""
    cve_id:      str
    description: str
    cvss:        float  = 0.0
    affected_versions: List[str] = field(default_factory=list)
    payload_hint: str  = ""   # which payload family is relevant


@dataclass
class VersionIndicator:
    """
    Describes how to detect a specific version (or version range) of a
    technology from a response signal.
    """
    signal_type:  str        # ``header``, ``body``, ``path``, ``cookie``
    pattern:      str        # regex; capture group 1 should yield the version
    version_range: str = ""  # e.g. "< 6.0" or ">= 5.0, < 5.8"


@dataclass
class KBEntry:
    """
    Full knowledge-base entry for a single technology.

    All list/dict fields default to empty so callers can always iterate
    them safely without None checks.
    """
    # Identity
    name:               str
    category:           TechCategory
    aliases:            List[str]             = field(default_factory=list)

    # Discovery
    default_paths:      List[str]             = field(default_factory=list)
    default_files:      List[str]             = field(default_factory=list)
    fingerprint_rules:  List[FingerprintRule] = field(default_factory=list)

    # HTTP signals
    header_patterns:    Dict[str, str]        = field(default_factory=dict)
    cookie_patterns:    List[str]             = field(default_factory=list)
    dangerous_headers:  List[str]             = field(default_factory=list)

    # Auth
    auth_patterns:      Dict[str, str]        = field(default_factory=dict)

    # Scanning guidance
    payload_families:   List[str]             = field(default_factory=list)
    known_misconfigs:   List[str]             = field(default_factory=list)
    known_behaviors:    Dict[str, str]        = field(default_factory=dict)
    dangerous_features: List[str]             = field(default_factory=list)

    # Vulnerability context
    cve_context:        List[CVEEntry]        = field(default_factory=list)

    # Version detection
    version_indicators: List[VersionIndicator] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":               self.name,
            "category":           self.category.value,
            "aliases":            self.aliases,
            "default_paths":      self.default_paths,
            "default_files":      self.default_files,
            "header_patterns":    self.header_patterns,
            "cookie_patterns":    self.cookie_patterns,
            "dangerous_headers":  self.dangerous_headers,
            "auth_patterns":      self.auth_patterns,
            "payload_families":   self.payload_families,
            "known_misconfigs":   self.known_misconfigs,
            "dangerous_features": self.dangerous_features,
            "cve_count":          len(self.cve_context),
        }


# ─────────────────────────────────────────────────────────────────────────────
# The Knowledge Base
# ─────────────────────────────────────────────────────────────────────────────

class KnowledgeBase:
    """
    Central, queryable repository of technology security knowledge.

    Usage::

        kb = KnowledgeBase.get_instance()
        entry  = kb.get("WordPress")
        paths  = kb.get_paths("Laravel")
        hints  = kb.build_scan_hints(fingerprint)
        merged = kb.build_scan_hints(fingerprint, include_low_confidence=True)

    Plugins can contribute additional entries::

        kb.merge_entry(my_custom_entry)
    """

    _instance: Optional["KnowledgeBase"] = None

    def __init__(self) -> None:
        # Primary index: canonical name → KBEntry
        self._db:         Dict[str, KBEntry] = {}
        # Alias index: alias (lowered) → canonical name
        self._aliases:    Dict[str, str]     = {}
        # Category index: category → set of canonical names
        self._by_category: Dict[TechCategory, Set[str]] = {c: set() for c in TechCategory}
        # CVE index: cve_id → list of tech names
        self._by_cve:     Dict[str, List[str]] = {}
        # Payload family index: family → set of tech names
        self._by_family:  Dict[str, Set[str]]  = {}

        self._load_builtin()

    # ── Singleton ─────────────────────────────────────────────────────────────

    @classmethod
    def get_instance(cls) -> "KnowledgeBase":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Public query API ──────────────────────────────────────────────────────

    def get(self, tech_name: str) -> Optional[KBEntry]:
        """Return the KBEntry for *tech_name* (case-insensitive), or None."""
        key = self._resolve(tech_name)
        return self._db.get(key)

    def get_paths(self, tech_name: str) -> List[str]:
        e = self.get(tech_name)
        return (e.default_paths + e.default_files) if e else []

    def get_payload_families(self, tech_name: str) -> List[str]:
        e = self.get(tech_name)
        return e.payload_families if e else []

    def get_auth_patterns(self, tech_name: str) -> Dict[str, str]:
        e = self.get(tech_name)
        return e.auth_patterns if e else {}

    def get_cves(self, tech_name: str) -> List[CVEEntry]:
        e = self.get(tech_name)
        return e.cve_context if e else []

    def list_by_category(self, category: TechCategory) -> List[KBEntry]:
        names = self._by_category.get(category, set())
        return [self._db[n] for n in names if n in self._db]

    def list_by_payload_family(self, family: str) -> List[KBEntry]:
        names = self._by_family.get(family, set())
        return [self._db[n] for n in names if n in self._db]

    def list_by_cve(self, cve_id: str) -> List[KBEntry]:
        names = self._by_cve.get(cve_id.upper(), [])
        return [self._db[n] for n in names if n in self._db]

    def all_entries(self) -> List[KBEntry]:
        return list(self._db.values())

    # ── Scan-hint aggregation ─────────────────────────────────────────────────

    def build_scan_hints(
        self,
        profile: AppFingerprint,
        include_low_confidence: bool = False,
    ) -> Dict[str, Any]:
        """
        Aggregate scan-relevant information from all technologies detected in
        *profile*.

        Returns a dict with:
          ``extra_paths``        – deduplicated paths to probe
          ``extra_files``        – specific files to check
          ``payload_families``   – payload families to prioritise
          ``auth_patterns``      – merged auth endpoint hints
          ``dangerous_headers``  – headers that may disclose info
          ``cve_context``        – relevant CVEEntry objects
          ``known_misconfigs``   – misconfig descriptions
          ``dangerous_features`` – high-risk features to check
          ``known_behaviors``    – behavior hints for scanners
        """
        skip_confidence: FrozenSet[ConfidenceLevel] = (
            frozenset() if include_low_confidence
            else frozenset({ConfidenceLevel.SPECULATIVE})
        )

        extra_paths:      Set[str] = set()
        extra_files:      Set[str] = set()
        payload_families: Set[str] = set()
        auth_patterns:    Dict[str, str] = {}
        dangerous_headers:Set[str] = set()
        cve_context:      List[CVEEntry] = []
        cve_ids_seen:     Set[str] = set()
        known_misconfigs: Set[str] = set()
        dangerous_features: Set[str] = set()
        known_behaviors:  Dict[str, str] = {}

        for tech in profile.technologies:
            if tech.confidence in skip_confidence:
                continue
            entry = self.get(tech.name)
            if entry is None:
                continue
            extra_paths.update(entry.default_paths)
            extra_files.update(entry.default_files)
            payload_families.update(entry.payload_families)
            auth_patterns.update(entry.auth_patterns)
            dangerous_headers.update(entry.dangerous_headers)
            known_misconfigs.update(entry.known_misconfigs)
            dangerous_features.update(entry.dangerous_features)
            known_behaviors.update(entry.known_behaviors)
            for cve in entry.cve_context:
                if cve.cve_id not in cve_ids_seen:
                    cve_context.append(cve)
                    cve_ids_seen.add(cve.cve_id)

        return {
            "extra_paths":        sorted(extra_paths),
            "extra_files":        sorted(extra_files),
            "payload_families":   sorted(payload_families),
            "auth_patterns":      auth_patterns,
            "dangerous_headers":  sorted(dangerous_headers),
            "cve_context":        cve_context,
            "known_misconfigs":   sorted(known_misconfigs),
            "dangerous_features": sorted(dangerous_features),
            "known_behaviors":    known_behaviors,
        }

    # ── Mutation (plugin support) ─────────────────────────────────────────────

    def merge_entry(self, entry: KBEntry) -> None:
        """
        Add or update an entry.  If an entry with the same name already exists,
        lists are merged (deduped) and dicts are updated.
        """
        key = entry.name
        existing = self._db.get(key)
        if existing is None:
            self._register(entry)
            return

        # Merge lists — simple types can use dict.fromkeys dedup; dataclass
        # instances are not hashable so we use a seen-set via id() for those.
        for attr in (
            "aliases", "default_paths", "default_files",
            "cookie_patterns", "dangerous_headers", "payload_families",
            "known_misconfigs", "dangerous_features",
        ):
            current: list = getattr(existing, attr)
            incoming: list = getattr(entry, attr)
            merged = list(dict.fromkeys(current + incoming))
            setattr(existing, attr, merged)

        # Dataclass-list merges (not hashable — deduplicate by repr)
        for attr in ("fingerprint_rules", "cve_context", "version_indicators"):
            current = getattr(existing, attr)
            incoming = getattr(entry, attr)
            seen: Set[str] = {repr(x) for x in current}
            extra = [x for x in incoming if repr(x) not in seen]
            setattr(existing, attr, current + extra)

        # Merge dicts
        for attr in ("header_patterns", "auth_patterns", "known_behaviors"):
            getattr(existing, attr).update(getattr(entry, attr))

        # Re-index aliases, families, CVEs
        self._index_entry(existing)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _resolve(self, name: str) -> str:
        """Return canonical name, resolving aliases (case-insensitive)."""
        lower = name.lower()
        if lower in self._aliases:
            return self._aliases[lower]
        # Try an exact case-insensitive match in _db
        for key in self._db:
            if key.lower() == lower:
                return key
        return name  # unresolved — caller gets None from _db.get()

    def _register(self, entry: KBEntry) -> None:
        self._db[entry.name] = entry
        self._index_entry(entry)

    def _index_entry(self, entry: KBEntry) -> None:
        # Alias index
        self._aliases[entry.name.lower()] = entry.name
        for alias in entry.aliases:
            self._aliases[alias.lower()] = entry.name
        # Category index
        self._by_category.setdefault(entry.category, set()).add(entry.name)
        # Payload family index
        for fam in entry.payload_families:
            self._by_family.setdefault(fam, set()).add(entry.name)
        # CVE index
        for cve in entry.cve_context:
            self._by_cve.setdefault(cve.cve_id.upper(), [])
            if entry.name not in self._by_cve[cve.cve_id.upper()]:
                self._by_cve[cve.cve_id.upper()].append(entry.name)

    # ─────────────────────────────────────────────────────────────────────────
    # Built-in knowledge entries
    # ─────────────────────────────────────────────────────────────────────────

    def _load_builtin(self) -> None:
        for entry in _BUILTIN_ENTRIES:
            self._register(entry)


# ─────────────────────────────────────────────────────────────────────────────
# Built-in KB entries — one per major technology
# ─────────────────────────────────────────────────────────────────────────────

_BUILTIN_ENTRIES: List[KBEntry] = [

    # ── Web Servers ───────────────────────────────────────────────────────────

    KBEntry(
        name="Apache",
        category=TechCategory.WEB_SERVER,
        aliases=["Apache HTTP Server", "Apache httpd"],
        default_paths=[
            "/server-status",
            "/server-info",
            "/.htaccess",
            "/.htpasswd",
            "/cgi-bin/",
        ],
        default_files=["/.htaccess", "/.htpasswd"],
        fingerprint_rules=[
            FingerprintRule("header", r"Apache(?:/[\d.]+)?", 0.9, "Server header"),
            FingerprintRule("body",   r"Apache/[\d.]+ Server", 0.7, "Error page"),
        ],
        header_patterns={"server": r"Apache(?:/[\d.]+)?"},
        dangerous_headers=["server", "x-powered-by"],
        payload_families=["path_traversal", "rce", "ssrf", "lfi"],
        known_misconfigs=[
            "mod_status enabled on /server-status",
            "mod_info enabled on /server-info",
            "Directory listing enabled",
            ".htaccess / .htpasswd world-readable",
        ],
        known_behaviors={
            "multiviews":  "Apache Multiviews can expose hidden files via path manipulation",
            "mod_rewrite": "Misconfigured rewrite rules can lead to open redirect or SSRF",
        },
        dangerous_features=["mod_status", "mod_info", "mod_cgi", "mod_rewrite"],
        cve_context=[
            CVEEntry("CVE-2021-41773", "Path traversal and RCE via mod_cgi on 2.4.49",
                     cvss=9.8, affected_versions=["2.4.49"],
                     payload_hint="path_traversal"),
            CVEEntry("CVE-2021-42013", "Path traversal bypass on 2.4.49/2.4.50",
                     cvss=9.8, affected_versions=["2.4.49", "2.4.50"],
                     payload_hint="path_traversal"),
            CVEEntry("CVE-2017-9798", "OPTIONS * method leaks server info (Optionsbleed)",
                     cvss=7.5, payload_hint="headers"),
        ],
        version_indicators=[
            VersionIndicator("header", r"Apache/([\d.]+)", "any"),
            VersionIndicator("body",   r"Apache/([\d.]+) Server at", "any"),
        ],
    ),

    KBEntry(
        name="Nginx",
        category=TechCategory.WEB_SERVER,
        aliases=["nginx"],
        default_paths=["/nginx_status", "/.well-known/", "/.well-known/security.txt"],
        fingerprint_rules=[
            FingerprintRule("header", r"nginx(?:/[\d.]+)?", 0.95, "Server header"),
            FingerprintRule("body",   r"<center>nginx(?:/[\d.]+)?</center>", 0.85, "Default error"),
        ],
        header_patterns={"server": r"nginx(?:/[\d.]+)?"},
        dangerous_headers=["server"],
        payload_families=["path_traversal", "ssrf", "off_by_slash"],
        known_misconfigs=[
            "nginx_status exposed at /nginx_status",
            "Off-by-slash alias misconfiguration exposing parent directory",
            "merge_slashes off — path traversal possible",
            "Unsafe $uri usage leading to CRLF injection",
        ],
        known_behaviors={
            "alias_traversal": "alias /data/ + location /files → /files../data traversal",
            "merge_slashes":   "merge_slashes off allows //etc/passwd style traversal",
        },
        dangerous_features=["autoindex", "alias", "merge_slashes off"],
        cve_context=[
            CVEEntry("CVE-2017-7529", "Integer overflow in range filter (info disclosure)",
                     cvss=7.5, payload_hint="headers"),
            CVEEntry("CVE-2019-20372", "CRLF injection via invalid URLs with certain configs",
                     cvss=5.3, payload_hint="crlf_injection"),
        ],
        version_indicators=[
            VersionIndicator("header", r"nginx/([\d.]+)", "any"),
        ],
    ),

    KBEntry(
        name="IIS",
        category=TechCategory.WEB_SERVER,
        aliases=["Microsoft IIS", "Internet Information Services"],
        default_paths=[
            "/iisstart.htm",
            "/web.config",
            "/aspnet_client/",
            "/_layouts/",
            "/Trace.axd",
        ],
        default_files=["/web.config", "/Trace.axd"],
        fingerprint_rules=[
            FingerprintRule("header", r"Microsoft-IIS/[\d.]+", 0.95, "Server header"),
            FingerprintRule("header", r"ASP\.NET", 0.8, "X-Powered-By"),
        ],
        header_patterns={
            "server":        r"Microsoft-IIS/[\d.]+",
            "x-powered-by":  r"ASP\.NET",
            "x-aspnet-version": r"[\d.]+",
        },
        dangerous_headers=["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"],
        payload_families=["path_traversal", "xss", "ssrf", "xxe"],
        known_misconfigs=[
            "Trace.axd enabled — exposes request headers and session data",
            "Directory browsing enabled",
            "web.config accessible",
            "Detailed error messages enabled in production",
        ],
        known_behaviors={
            "ntlm_auth":   "NTLM authentication leaks domain/hostname",
            "tilde_enum":  "IIS short filename 8.3 enumeration via tilde (~) character",
        },
        dangerous_features=["Trace.axd", "WebDAV", "ISAPI", "ASP classic"],
        cve_context=[
            CVEEntry("CVE-2017-7269", "Buffer overflow in WebDAV ScStoragePathFromUrl",
                     cvss=9.8, payload_hint="rce"),
            CVEEntry("CVE-2015-1635", "HTTP.sys request parsing RCE (MS15-034)",
                     cvss=10.0, payload_hint="rce"),
            CVEEntry("CVE-2021-31166", "HTTP Protocol Stack RCE",
                     cvss=9.8, payload_hint="rce"),
        ],
        version_indicators=[
            VersionIndicator("header", r"Microsoft-IIS/([\d.]+)", "any"),
        ],
    ),

    KBEntry(
        name="Caddy",
        category=TechCategory.WEB_SERVER,
        aliases=["Caddy Server"],
        default_paths=["/.well-known/", "/debug/vars"],
        fingerprint_rules=[
            FingerprintRule("header", r"Caddy", 0.9, "Server header"),
        ],
        header_patterns={"server": r"[Cc]addy"},
        payload_families=["ssrf", "path_traversal"],
        known_misconfigs=["Caddy Admin API exposed on :2019"],
        dangerous_features=["admin_api", "file_server"],
    ),

    KBEntry(
        name="Tomcat",
        category=TechCategory.WEB_SERVER,
        aliases=["Apache Tomcat"],
        default_paths=[
            "/manager/html",
            "/manager/text",
            "/host-manager/html",
            "/examples/",
            "/docs/",
        ],
        default_files=["/WEB-INF/web.xml"],
        fingerprint_rules=[
            FingerprintRule("header", r"Apache-Coyote|Apache Tomcat", 0.9, "Server header"),
            FingerprintRule("body",   r"Apache Tomcat/[\d.]+", 0.85, "Error page"),
            FingerprintRule("cookie", r"JSESSIONID", 0.6, "Java session cookie"),
        ],
        header_patterns={"server": r"Apache-Coyote"},
        cookie_patterns=["JSESSIONID"],
        dangerous_headers=["server"],
        payload_families=["rce", "path_traversal", "xxe", "ssrf"],
        known_misconfigs=[
            "Manager app accessible with default credentials",
            "AJP connector exposed on port 8009 (Ghostcat)",
            "Default examples deployed",
        ],
        known_behaviors={
            "ajp_connector": "AJP connector on 8009 can be exploited if unprotected (Ghostcat CVE-2020-1938)",
        },
        dangerous_features=["manager_app", "ajp_connector", "examples"],
        cve_context=[
            CVEEntry("CVE-2020-1938", "Ghostcat — AJP file read/include vulnerability",
                     cvss=9.8, payload_hint="lfi"),
            CVEEntry("CVE-2019-0232", "Remote code execution via CGI Servlet on Windows",
                     cvss=8.1, payload_hint="rce"),
            CVEEntry("CVE-2017-12617", "JSP upload via PUT when readonly=false",
                     cvss=8.1, payload_hint="file_upload"),
        ],
        version_indicators=[
            VersionIndicator("body", r"Apache Tomcat/([\d.]+)", "any"),
        ],
    ),

    # ── Frameworks ────────────────────────────────────────────────────────────

    KBEntry(
        name="Laravel",
        category=TechCategory.FRAMEWORK,
        aliases=["Laravel PHP"],
        default_paths=[
            "/.env",
            "/storage/logs/laravel.log",
            "/public/storage",
            "/api/user",
            "/telescope",
            "/telescope/requests",
            "/horizon",
            "/nova",
            "/nova-api/",
        ],
        default_files=["/.env", "/.env.backup", "/.env.production", "/.env.example"],
        fingerprint_rules=[
            FingerprintRule("cookie",  r"laravel_session", 0.9, "Session cookie"),
            FingerprintRule("header",  r"laravel", 0.7, "X-Powered-By"),
            FingerprintRule("body",    r"Whoops!.*laravel|laravel/framework", 0.85, "Debug page"),
            FingerprintRule("path",    r"\.env$", 0.8, ".env accessible"),
        ],
        cookie_patterns=["laravel_session", "XSRF-TOKEN"],
        auth_patterns={
            "login":    "/login",
            "register": "/register",
            "logout":   "/logout",
            "api":      "/api/",
            "sanctum":  "/sanctum/csrf-cookie",
        },
        payload_families=["ssti", "sqli", "mass_assignment", "xxe", "ssrf", "idor"],
        known_misconfigs=[
            ".env file publicly accessible (leaks APP_KEY, DB creds)",
            "APP_DEBUG=true in production (debug page discloses source code)",
            "Telescope dashboard accessible without auth",
            "Laravel log file publicly readable",
            "APP_KEY not rotated — insecure deserialization possible",
        ],
        known_behaviors={
            "debug_mode":    "APP_DEBUG=true renders Ignition debug pages with source code",
            "mass_assign":   "Eloquent $fillable / $guarded misconfiguration",
            "route_signing": "Signed URLs use APP_KEY — exposed key breaks all auth",
        },
        dangerous_features=["Telescope", "Horizon", "Nova", "debug_mode", "mass_assignment"],
        cve_context=[
            CVEEntry("CVE-2021-3129",
                     "Ignition debug mode RCE via deserialization (< 8.4.2)",
                     cvss=9.8,
                     affected_versions=["< 8.4.2"],
                     payload_hint="rce"),
        ],
        version_indicators=[
            VersionIndicator("body",   r'"laravel/framework":"([\d.^~]+)"', "any"),
            VersionIndicator("header", r"Laravel/([\d.]+)", "any"),
        ],
    ),

    KBEntry(
        name="Django",
        category=TechCategory.FRAMEWORK,
        aliases=["Django Python", "Django REST Framework", "DRF"],
        default_paths=[
            "/admin/",
            "/api/",
            "/__debug__/",
            "/static/admin/",
            "/api/schema/",
            "/api/docs/",
            "/.well-known/",
        ],
        fingerprint_rules=[
            FingerprintRule("cookie",  r"csrftoken|sessionid", 0.8, "Django cookies"),
            FingerprintRule("body",    r"Django.*debug|<title>Django", 0.85, "Debug page"),
            FingerprintRule("header",  r"csrftoken", 0.7, "CSRF cookie"),
        ],
        cookie_patterns=["csrftoken", "sessionid"],
        auth_patterns={
            "login":    "/admin/login/",
            "api":      "/api/",
            "logout":   "/admin/logout/",
        },
        dangerous_headers=["x-frame-options", "x-content-type-options"],
        payload_families=["sqli", "ssti", "xss", "ssrf", "idor", "mass_assignment"],
        known_misconfigs=[
            "DEBUG=True in production (leaks full stack trace + settings)",
            "Secret key exposed or weak",
            "Django admin accessible with default path",
            "ALLOWED_HOSTS=[*] — Host header injection possible",
            "CORS_ORIGIN_ALLOW_ALL=True",
        ],
        known_behaviors={
            "debug_page":    "DEBUG=True shows full exception traceback and local variables",
            "host_injection": "Improper ALLOWED_HOSTS allows Host header injection",
        },
        dangerous_features=["DEBUG", "django-debug-toolbar", "admin", "CORS_ALLOW_ALL"],
        cve_context=[
            CVEEntry("CVE-2019-14234",
                     "SQL injection via Key/Value store introspection on JSONField",
                     cvss=9.8, payload_hint="sqli"),
            CVEEntry("CVE-2022-28347",
                     "SQL injection in QuerySet.explain() on PostgreSQL backend",
                     cvss=9.8, payload_hint="sqli"),
            CVEEntry("CVE-2021-28658",
                     "Potential directory traversal via archive extraction",
                     cvss=5.3, payload_hint="path_traversal"),
        ],
        version_indicators=[
            VersionIndicator("body",   r"Django/([\d.]+)", "any"),
            VersionIndicator("header", r"Django/([\d.]+)", "any"),
        ],
    ),

    KBEntry(
        name="Spring Boot",
        category=TechCategory.FRAMEWORK,
        aliases=["Spring", "Spring Framework", "Spring MVC"],
        default_paths=[
            "/actuator",
            "/actuator/env",
            "/actuator/beans",
            "/actuator/mappings",
            "/actuator/heapdump",
            "/actuator/logfile",
            "/actuator/info",
            "/actuator/health",
            "/actuator/metrics",
            "/actuator/httptrace",
            "/actuator/auditevents",
            "/swagger-ui.html",
            "/swagger-ui/index.html",
            "/v2/api-docs",
            "/v3/api-docs",
            "/webjars/springfox-swagger-ui/",
            "/h2-console",
        ],
        fingerprint_rules=[
            FingerprintRule("header", r"X-Application-Context|WhiteLabel", 0.8, "Spring header"),
            FingerprintRule("body",   r"Whitelabel Error Page|This application has no explicit mapping", 0.9, "Spring error"),
            FingerprintRule("cookie", r"JSESSIONID", 0.5, "Java session"),
        ],
        cookie_patterns=["JSESSIONID", "SPRING_SECURITY_REMEMBER_ME_COOKIE"],
        auth_patterns={
            "login":  "/login",
            "logout": "/logout",
            "api":    "/api/",
        },
        payload_families=["rce", "ssrf", "sqli", "ssti", "xxe", "idor"],
        known_misconfigs=[
            "Actuator endpoints exposed without authentication",
            "/actuator/env leaks environment variables and config",
            "/actuator/heapdump allows memory dump extraction",
            "H2 console accessible in production",
            "Swagger UI accessible in production with full API docs",
        ],
        known_behaviors={
            "actuator_rce":  "env POST + logfile actuator can lead to RCE via logback",
            "spel_injection": "SpEL injection in @Value or routing config",
        },
        dangerous_features=["actuator", "h2-console", "SpEL", "devtools"],
        cve_context=[
            CVEEntry("CVE-2022-22965",
                     "Spring4Shell — RCE via ClassLoader manipulation (Spring MVC >= 5.3.0)",
                     cvss=9.8, affected_versions=[">= 5.3.0, < 5.3.18", ">= 5.2.0, < 5.2.20"],
                     payload_hint="rce"),
            CVEEntry("CVE-2022-22963",
                     "RCE via Spring Cloud Function SpEL expression",
                     cvss=9.8, payload_hint="ssti"),
            CVEEntry("CVE-2021-22053",
                     "RCE via Spring Cloud Netflix Hystrix Dashboard",
                     cvss=8.8, payload_hint="ssrf"),
        ],
        version_indicators=[
            VersionIndicator("body",   r"Spring Boot/([\d.]+)", "any"),
            VersionIndicator("header", r"X-Application-Context:.*:([\d.]+)", "any"),
        ],
    ),

    KBEntry(
        name="Ruby on Rails",
        category=TechCategory.FRAMEWORK,
        aliases=["Rails", "RoR"],
        default_paths=[
            "/rails/info/properties",
            "/rails/info/routes",
            "/rails/mailers",
            "/cable",
            "/api/v1/",
        ],
        fingerprint_rules=[
            FingerprintRule("cookie",  r"_[a-zA-Z0-9]+_session", 0.7, "Rails session cookie"),
            FingerprintRule("header",  r"X-Runtime", 0.6, "Rails response timing header"),
            FingerprintRule("body",    r"ActionController|ActionView", 0.8, "Rails exception"),
        ],
        cookie_patterns=[r"_\w+_session"],
        dangerous_headers=["x-runtime", "x-request-id"],
        auth_patterns={
            "login":    "/users/sign_in",
            "logout":   "/users/sign_out",
            "register": "/users/sign_up",
            "api":      "/api/",
        },
        payload_families=["ssti", "mass_assignment", "sqli", "csrf", "idor", "ssrf"],
        known_misconfigs=[
            "rails/info exposed in production",
            "config.force_ssl not set",
            "Secret key base weak or committed to repo",
            "Mass assignment via strong parameters misconfiguration",
        ],
        known_behaviors={
            "routing":        "Rails routing is introspectable via /rails/info/routes",
            "mass_assign":    "permit! or overly broad permit() allows mass assignment",
            "secret_key":     "Exposed secret_key_base breaks session security entirely",
        },
        dangerous_features=["rails/info", "spring", "byebug", "web-console"],
        cve_context=[
            CVEEntry("CVE-2019-5418",
                     "File content disclosure via Content-Type manipulation (< 5.2.2.1)",
                     cvss=7.5, payload_hint="path_traversal"),
            CVEEntry("CVE-2020-8164",
                     "Possible strong parameters bypass in nested params",
                     cvss=7.5, payload_hint="mass_assignment"),
            CVEEntry("CVE-2022-32224",
                     "Possible RCE via YAML deserialization with GlobalID",
                     cvss=9.8, payload_hint="rce"),
        ],
    ),

    KBEntry(
        name="Express",
        category=TechCategory.FRAMEWORK,
        aliases=["Express.js", "ExpressJS"],
        default_paths=["/api/", "/api/v1/", "/health", "/status"],
        fingerprint_rules=[
            FingerprintRule("header", r"Express", 0.9, "X-Powered-By header"),
        ],
        header_patterns={"x-powered-by": r"[Ee]xpress"},
        dangerous_headers=["x-powered-by"],
        payload_families=["sqli", "nosqli", "xss", "ssrf", "ssti", "prototype_pollution"],
        known_misconfigs=[
            "X-Powered-By: Express header not removed",
            "Helmet.js not used — missing security headers",
            "app.use(express.static('.')) exposes source code",
        ],
        known_behaviors={
            "prototype_pollution": "Unsanitized query params can pollute Object prototype",
        },
        dangerous_features=["cors_wildcard", "express.static('.')"],
    ),

    KBEntry(
        name="FastAPI",
        category=TechCategory.FRAMEWORK,
        aliases=["Fast API", "Starlette"],
        default_paths=["/docs", "/redoc", "/openapi.json"],
        fingerprint_rules=[
            FingerprintRule("path", r"/docs|/openapi\.json", 0.7, "FastAPI docs"),
        ],
        auth_patterns={"api": "/api/", "docs": "/docs"},
        payload_families=["sqli", "ssrf", "idor", "mass_assignment"],
        known_misconfigs=[
            "/docs (Swagger UI) accessible in production",
            "/redoc and /openapi.json expose full API schema",
        ],
        dangerous_features=["swagger_ui", "redoc", "openapi_json"],
    ),

    KBEntry(
        name="Flask",
        category=TechCategory.FRAMEWORK,
        aliases=["Werkzeug"],
        default_paths=[
            "/console",
            "/_debug_toolbar/",
        ],
        fingerprint_rules=[
            FingerprintRule("header",  r"Werkzeug", 0.9, "Werkzeug server header"),
            FingerprintRule("cookie",  r"session", 0.5, "Flask session cookie"),
            FingerprintRule("body",    r"werkzeug\.debug|The debugger caught an exception", 0.9, "Debug console"),
        ],
        cookie_patterns=["session"],
        dangerous_headers=["server"],
        payload_families=["ssti", "ssrf", "idor", "xss"],
        known_misconfigs=[
            "FLASK_DEBUG=1 in production — interactive Werkzeug console exposed",
            "SECRET_KEY weak or hard-coded",
            "Server-Side Template Injection via Jinja2 user input",
        ],
        known_behaviors={
            "debug_console": "Werkzeug interactive debugger allows arbitrary Python execution",
            "ssti":          "Jinja2 template injection if user input reaches render_template_string()",
        },
        dangerous_features=["debug_mode", "werkzeug_debugger", "jinja2_unsafe"],
        cve_context=[
            CVEEntry("CVE-2023-25577",
                     "Werkzeug multipart parsing DoS",
                     cvss=7.5, payload_hint="dos"),
        ],
    ),

    KBEntry(
        name="ASP.NET",
        category=TechCategory.FRAMEWORK,
        aliases=["ASP.NET Core", "ASP.NET MVC", ".NET"],
        default_paths=[
            "/elmah.axd",
            "/Trace.axd",
            "/ScriptResource.axd",
            "/WebResource.axd",
            "/signalr/hubs",
            "/api/",
        ],
        default_files=["/web.config", "/Web.config"],
        fingerprint_rules=[
            FingerprintRule("header",  r"ASP\.NET", 0.9, "X-Powered-By"),
            FingerprintRule("cookie",  r"ASP\.NET_SessionId|\.ASPXAUTH", 0.9, "ASP.NET cookies"),
            FingerprintRule("header",  r"X-AspNet-Version", 0.9, "Version header"),
        ],
        cookie_patterns=["ASP.NET_SessionId", ".ASPXAUTH", "__RequestVerificationToken"],
        dangerous_headers=["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"],
        auth_patterns={
            "login":  "/Account/Login",
            "logout": "/Account/Logout",
            "api":    "/api/",
        },
        payload_families=["xxe", "sqli", "xss", "idor", "ssrf"],
        known_misconfigs=[
            "ELMAH error log accessible without authentication",
            "Trace.axd enabled in production",
            "customErrors mode=Off — detailed errors exposed",
            "ViewState MAC disabled — deserialization attack possible",
        ],
        dangerous_features=["ELMAH", "Trace.axd", "ViewState", "ScriptResource.axd"],
        cve_context=[
            CVEEntry("CVE-2021-42574",
                     "ViewState deserialization RCE when machineKey is known",
                     cvss=9.8, payload_hint="rce"),
        ],
    ),

    # ── CMS ───────────────────────────────────────────────────────────────────

    KBEntry(
        name="WordPress",
        category=TechCategory.CMS,
        aliases=["WP"],
        default_paths=[
            "/wp-login.php",
            "/wp-admin/",
            "/wp-admin/admin-ajax.php",
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts",
            "/?author=1",
            "/xmlrpc.php",
            "/wp-content/debug.log",
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/wp-content/uploads/",
            "/readme.html",
            "/.user.ini",
        ],
        default_files=["/wp-config.php.bak", "/wp-config.php~", "/readme.html"],
        fingerprint_rules=[
            FingerprintRule("path",   r"/wp-login\.php|/wp-admin/", 0.95, "WP admin path"),
            FingerprintRule("body",   r"wp-content|wp-includes", 0.9, "WP asset paths in HTML"),
            FingerprintRule("cookie", r"wordpress_|wp-settings-", 0.9, "WP cookies"),
            FingerprintRule("header", r"x-pingback", 0.8, "Pingback header"),
        ],
        cookie_patterns=["wordpress_logged_in_", "wordpress_sec_", "wp-settings-"],
        dangerous_headers=["x-pingback", "link"],
        auth_patterns={
            "login":  "/wp-login.php",
            "xmlrpc": "/xmlrpc.php",
            "api":    "/wp-json/",
        },
        payload_families=["sqli", "xss", "rce", "ssrf", "path_traversal", "idor"],
        known_misconfigs=[
            "XML-RPC enabled — brute force and SSRF amplification via system.multicall",
            "User enumeration via REST API /wp-json/wp/v2/users",
            "wp-config.php backup file accessible",
            "Debug log /wp-content/debug.log publicly readable",
            "Outdated plugins/themes with known CVEs",
            "Default admin username 'admin'",
        ],
        known_behaviors={
            "rest_users":  "REST API exposes usernames at /wp-json/wp/v2/users by default",
            "xmlrpc":      "XML-RPC multicall enables brute-force with thousands of attempts in one request",
            "author_enum": "/?author=N redirects to /author/username leaking all usernames",
        },
        dangerous_features=["xmlrpc", "REST_API", "debug_log", "file_editor"],
        cve_context=[
            CVEEntry("CVE-2017-5487",
                     "REST API user data exposure (< 4.7.2)",
                     cvss=7.5, payload_hint="idor"),
            CVEEntry("CVE-2019-8943",
                     "Path traversal in post meta (< 5.0.1)",
                     cvss=6.5, payload_hint="path_traversal"),
            CVEEntry("CVE-2023-2745",
                     "Directory traversal in wp_get_font_face_src_from_theme()",
                     cvss=5.4, payload_hint="path_traversal"),
        ],
    ),

    KBEntry(
        name="Drupal",
        category=TechCategory.CMS,
        aliases=[],
        default_paths=[
            "/user/login",
            "/?q=admin",
            "/admin/config",
            "/CHANGELOG.txt",
            "/core/CHANGELOG.txt",
            "/sites/default/settings.php",
            "/sites/default/default.settings.php",
            "/update.php",
            "/install.php",
        ],
        default_files=["/CHANGELOG.txt", "/core/CHANGELOG.txt"],
        fingerprint_rules=[
            FingerprintRule("cookie",  r"Drupal\.visitor|SESS[a-f0-9]+", 0.9, "Drupal session"),
            FingerprintRule("header",  r"x-drupal-cache|x-generator.*Drupal", 0.9, "Drupal headers"),
            FingerprintRule("body",    r"/sites/default/files|Drupal\.settings", 0.85, "Drupal JS"),
        ],
        cookie_patterns=[r"SESS[a-f0-9]+", "Drupal.visitor"],
        dangerous_headers=["x-drupal-cache", "x-generator"],
        auth_patterns={"login": "/user/login", "admin": "/admin/"},
        payload_families=["sqli", "rce", "xss", "ssrf", "idor"],
        known_misconfigs=[
            "CHANGELOG.txt exposes exact Drupal version",
            "update.php / install.php accessible",
            "Error reporting set to verbose in production",
        ],
        cve_context=[
            CVEEntry("CVE-2018-7600",
                     "Drupalgeddon2 — RCE via form API (< 7.58, < 8.5.1)",
                     cvss=9.8, payload_hint="rce"),
            CVEEntry("CVE-2019-6340",
                     "RCE via REST API with HAL+JSON (< 8.6.10)",
                     cvss=9.8, payload_hint="rce"),
            CVEEntry("CVE-2014-3704",
                     "Drupalgeddon — SQL injection in user registration (< 7.32)",
                     cvss=10.0, payload_hint="sqli"),
        ],
        version_indicators=[
            VersionIndicator("body", r"Drupal ([\d.]+),", "any"),
            VersionIndicator("body", r"CHANGELOG\.txt.*?Drupal ([\d.]+)", "any"),
        ],
    ),

    KBEntry(
        name="Joomla",
        category=TechCategory.CMS,
        aliases=[],
        default_paths=[
            "/administrator/index.php",
            "/configuration.php",
            "/README.txt",
            "/administrator/manifests/files/joomla.xml",
            "/components/",
            "/plugins/",
            "/modules/",
        ],
        default_files=["/README.txt", "/administrator/manifests/files/joomla.xml"],
        fingerprint_rules=[
            FingerprintRule("cookie",  r"[a-f0-9]{32}",        0.5, "Joomla session"),
            FingerprintRule("body",    r'name="token" value="[a-f0-9]{32}"', 0.8, "Joomla form token"),
            FingerprintRule("body",    r"/media/jui/|/media/system/js/", 0.8, "Joomla assets"),
        ],
        auth_patterns={"login": "/administrator/index.php"},
        payload_families=["sqli", "xss", "rfi", "rce"],
        known_misconfigs=[
            "README.txt exposes Joomla version",
            "com_config component exposes configuration",
        ],
        cve_context=[
            CVEEntry("CVE-2015-8562",
                     "Remote code execution via PHP object injection in session handler",
                     cvss=10.0, payload_hint="rce"),
            CVEEntry("CVE-2017-8917",
                     "SQL injection in com_fields (< 3.7.1)",
                     cvss=9.8, payload_hint="sqli"),
        ],
    ),

    KBEntry(
        name="Magento",
        category=TechCategory.CMS,
        aliases=["Adobe Commerce"],
        default_paths=[
            "/admin",
            "/index.php/admin",
            "/downloader/",
            "/pub/static/",
            "/var/log/system.log",
            "/app/etc/local.xml",
            "/api/rest/",
        ],
        fingerprint_rules=[
            FingerprintRule("cookie", r"frontend|adminhtml", 0.8, "Magento session cookies"),
        ],
        cookie_patterns=["frontend", "adminhtml", "mage-messages"],
        auth_patterns={"login": "/admin", "api": "/index.php/rest/"},
        payload_families=["sqli", "xss", "rce", "path_traversal", "xxe", "ssrf"],
        known_misconfigs=[
            "Admin path not changed from default /admin",
            "Downloader accessible",
            "var/log files publicly readable",
        ],
        cve_context=[
            CVEEntry("CVE-2019-7139",
                     "SQL injection in product listing filter (< 2.1.18)",
                     cvss=9.8, payload_hint="sqli"),
            CVEEntry("CVE-2022-24086",
                     "RCE via improper input validation in checkout",
                     cvss=9.8, payload_hint="rce"),
        ],
    ),

    KBEntry(
        name="Shopify",
        category=TechCategory.CMS,
        aliases=[],
        default_paths=["/admin/", "/cart.js", "/collections.json", "/products.json"],
        fingerprint_rules=[
            FingerprintRule("body",   r"cdn\.shopify\.com|Shopify\.theme", 0.9, "Shopify CDN"),
            FingerprintRule("header", r"x-shopify-stage", 0.9, "Shopify header"),
        ],
        payload_families=["idor", "xss", "ssrf"],
        known_misconfigs=[
            "Liquid template injection via merchant-controlled data",
            "Third-party app permissions over-privileged",
        ],
    ),

    # ── Databases ─────────────────────────────────────────────────────────────

    KBEntry(
        name="MySQL",
        category=TechCategory.DATABASE,
        aliases=["MariaDB", "MySQL/MariaDB"],
        fingerprint_rules=[
            FingerprintRule("body", r"You have an error in your SQL syntax.*MySQL", 0.95, "MySQL error"),
            FingerprintRule("body", r"mysql_fetch_array|mysql_num_rows", 0.8, "PHP MySQL functions"),
        ],
        payload_families=["sqli", "sqli_error", "sqli_union", "sqli_blind", "sqli_time"],
        known_behaviors={
            "information_schema": "INFORMATION_SCHEMA allows DB/table/column enumeration",
            "outfile":            "SELECT INTO OUTFILE can write files if FILE privilege granted",
            "load_infile":        "LOAD DATA INFILE can read files if LOCAL_INFILE enabled",
        },
        dangerous_features=["outfile", "load_infile", "udf"],
    ),

    KBEntry(
        name="PostgreSQL",
        category=TechCategory.DATABASE,
        aliases=["Postgres"],
        fingerprint_rules=[
            FingerprintRule("body", r"pg_query|ERROR:.*syntax error at or near|PostgreSQL.*ERROR", 0.9, "PG error"),
        ],
        payload_families=["sqli", "sqli_stacked", "sqli_time"],
        known_behaviors={
            "copy_to":    "COPY TO/FROM can read/write files",
            "pg_sleep":   "pg_sleep() used for time-based blind injection",
            "extensions": "pg_read_file(), dblink allow advanced attacks if extensions loaded",
        },
        dangerous_features=["copy_to", "pg_read_file", "dblink", "pg_exec"],
    ),

    KBEntry(
        name="MongoDB",
        category=TechCategory.DATABASE,
        aliases=["Mongo"],
        fingerprint_rules=[
            FingerprintRule("body", r"MongoError|mongo\.connect|mongoose", 0.8, "Mongo error/code"),
        ],
        payload_families=["nosqli", "nosqli_operator", "idor"],
        known_behaviors={
            "operator_injection": "$where, $gt, $ne operators usable in injection attacks",
            "aggregation":        "Aggregation pipeline injection via $lookup, $match",
        },
        dangerous_features=["$where", "mapReduce", "allowDiskUse"],
    ),

    KBEntry(
        name="Redis",
        category=TechCategory.DATABASE,
        aliases=[],
        default_paths=[],
        payload_families=["ssrf"],
        known_misconfigs=[
            "Redis port 6379 exposed without auth",
            "requirepass not set",
            "SSRF to Redis — can write files or execute via Lua",
        ],
        dangerous_features=["SLAVEOF", "CONFIG SET", "EVAL"],
    ),

    # ── Authentication & API Technologies ────────────────────────────────────

    KBEntry(
        name="JWT",
        category=TechCategory.AUTH,
        aliases=["JSON Web Token"],
        fingerprint_rules=[
            FingerprintRule("header", r"Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", 0.95, "JWT Bearer token"),
            FingerprintRule("cookie", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", 0.9, "JWT in cookie"),
        ],
        payload_families=["jwt_alg_none", "jwt_weak_secret", "jwt_rs_to_hs"],
        known_misconfigs=[
            "Algorithm set to 'none' accepted",
            "HS256 with weak or empty secret",
            "RS256 → HS256 algorithm confusion",
            "Missing 'exp' claim — tokens never expire",
            "JWT stored in localStorage (XSS-accessible)",
        ],
        known_behaviors={
            "alg_none":     "Some libraries accept alg:none — signature verification bypassed",
            "alg_confusion": "Asymmetric key used as HMAC secret when alg downgraded",
        },
        dangerous_features=["alg_none", "HS256_weak_key", "no_expiry"],
    ),

    KBEntry(
        name="OAuth 2.0",
        category=TechCategory.AUTH,
        aliases=["OAuth", "OAuth2", "OIDC", "OpenID Connect"],
        default_paths=[
            "/oauth/authorize",
            "/oauth/token",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/connect/authorize",
            "/connect/token",
        ],
        payload_families=["oauth_misconfig", "open_redirect", "csrf", "ssrf"],
        known_misconfigs=[
            "Implicit flow used — access tokens in URL fragment",
            "Missing state parameter — CSRF in authorization code flow",
            "Broad redirect_uri validation — open redirect possible",
            "Client secret exposed in JavaScript or mobile app",
            "PKCE not enforced for public clients",
        ],
        known_behaviors={
            "redirect_uri_bypass": "Regex or prefix matching on redirect_uri allows bypass",
            "token_leakage":       "Referrer header leaks token from implicit flow",
        },
        dangerous_features=["implicit_flow", "no_pkce", "wildcard_redirect_uri"],
    ),

    KBEntry(
        name="SAML",
        category=TechCategory.AUTH,
        aliases=["SAML 2.0"],
        default_paths=[
            "/saml/acs",
            "/saml/sso",
            "/saml/metadata",
            "/shibboleth",
            "/auth/saml",
        ],
        payload_families=["xxe", "xml_signature_wrapping", "xss"],
        known_misconfigs=[
            "XML Signature Wrapping (XSW) — signature validates but assertion is replaced",
            "XXE in SAML assertion parsing",
            "Replay attack — no assertion ID/timestamp validation",
            "InResponseTo not validated",
        ],
        known_behaviors={
            "xsw":  "SAMLResponse body can be manipulated while keeping valid signature",
        },
        dangerous_features=["xml_signature_wrapping", "assertion_replay"],
    ),

    KBEntry(
        name="GraphQL",
        category=TechCategory.OTHER,
        aliases=[],
        default_paths=[
            "/graphql",
            "/api/graphql",
            "/graphiql",
            "/__graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/query",
        ],
        fingerprint_rules=[
            FingerprintRule("body",   r'"data":\s*\{|"errors":\s*\[', 0.7, "GraphQL response shape"),
            FingerprintRule("body",   r'"__typename"', 0.8, "GraphQL introspection field"),
            FingerprintRule("path",   r"/graphql|/graphiql", 0.9, "GraphQL path"),
        ],
        payload_families=["graphql_introspection", "graphql_injection", "idor", "sqli", "ssrf", "dos"],
        known_misconfigs=[
            "Introspection enabled in production — full schema exposed",
            "GraphiQL IDE accessible in production",
            "No query depth limit — DoS via nested queries",
            "No query complexity limit",
            "Batch queries enabled — brute force amplification",
            "Field suggestions enabled — schema enumeration without introspection",
        ],
        known_behaviors={
            "introspection":    "__schema query reveals full API surface",
            "batch_brute":      "Batch queries allow many login attempts in a single request",
            "field_suggestion": "Did you mean '...' leaks field names even without introspection",
        },
        dangerous_features=["introspection", "graphiql", "batching", "subscriptions"],
    ),

    # ── WAFs & Reverse Proxies ────────────────────────────────────────────────

    KBEntry(
        name="Cloudflare",
        category=TechCategory.WAF,
        aliases=["CF"],
        fingerprint_rules=[
            FingerprintRule("header", r"cloudflare", 0.95, "CF-Ray or Server header"),
            FingerprintRule("cookie", r"__cfduid|__cf_bm|cf_clearance", 0.9, "CF cookies"),
        ],
        cookie_patterns=["__cfduid", "__cf_bm", "cf_clearance"],
        dangerous_headers=["cf-ray", "cf-cache-status"],
        known_behaviors={
            "bypass":      "CF can be bypassed by finding the origin IP directly",
            "ray_id":      "CF-Ray header can identify specific requests in CF logs",
        },
        payload_families=["waf_bypass", "encoding_bypass"],
    ),

    KBEntry(
        name="AWS WAF",
        category=TechCategory.WAF,
        aliases=["Amazon WAF"],
        fingerprint_rules=[
            FingerprintRule("header", r"x-amzn-requestid|x-amz-cf-id", 0.8, "AWS headers"),
        ],
        dangerous_headers=["x-amzn-requestid"],
        payload_families=["waf_bypass"],
        known_misconfigs=["WAF rules not covering all injection points"],
    ),

    KBEntry(
        name="ModSecurity",
        category=TechCategory.WAF,
        aliases=["OWASP ModSecurity CRS"],
        fingerprint_rules=[
            FingerprintRule("body",   r"Mod_Security|NOYB", 0.8, "ModSec block page"),
            FingerprintRule("header", r"mod_security", 0.9, "ModSec header"),
        ],
        payload_families=["waf_bypass", "encoding_bypass", "case_manipulation"],
    ),

    # ── Cloud Providers ───────────────────────────────────────────────────────

    KBEntry(
        name="AWS",
        category=TechCategory.CLOUD,
        aliases=["Amazon Web Services", "Amazon"],
        default_paths=[
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.170.2/v2/credentials",  # ECS task metadata
        ],
        fingerprint_rules=[
            FingerprintRule("header", r"x-amz-|AmazonS3|AmazonEC2", 0.8, "AWS headers"),
            FingerprintRule("body",   r"\.s3\.amazonaws\.com|\.cloudfront\.net", 0.7, "AWS URLs"),
        ],
        payload_families=["ssrf", "idor"],
        known_misconfigs=[
            "IMDS v1 enabled — SSRF to 169.254.169.254 fetches credentials",
            "S3 bucket public — list, read, or write",
            "Security groups too permissive",
        ],
        known_behaviors={
            "imds_ssrf": "SSRF to 169.254.169.254/latest/meta-data/ yields IAM credentials (IMDSv1)",
        },
        dangerous_features=["IMDSv1", "public_s3_bucket", "overly_permissive_sg"],
    ),

    KBEntry(
        name="GCP",
        category=TechCategory.CLOUD,
        aliases=["Google Cloud Platform", "Google Cloud"],
        default_paths=[
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
        payload_families=["ssrf"],
        known_behaviors={
            "metadata_ssrf": "SSRF to metadata.google.internal with Metadata-Flavor:Google header leaks credentials",
        },
        known_misconfigs=["GCS bucket publicly accessible", "Service account over-privileged"],
    ),

    KBEntry(
        name="Azure",
        category=TechCategory.CLOUD,
        aliases=["Microsoft Azure"],
        default_paths=[
            "http://169.254.169.254/metadata/instance",
        ],
        payload_families=["ssrf"],
        known_behaviors={
            "imds_ssrf": "SSRF to 169.254.169.254/metadata/instance?api-version=2021-02-01 leaks Azure IMDS",
        },
        known_misconfigs=["Blob storage container publicly accessible", "Managed Identity over-privileged"],
    ),

    # ── JavaScript Frameworks ─────────────────────────────────────────────────

    KBEntry(
        name="React",
        category=TechCategory.JS_FRAMEWORK,
        aliases=["React.js", "ReactJS"],
        fingerprint_rules=[
            FingerprintRule("body", r'__reactFiber|react-dom|data-reactroot', 0.9, "React DOM markers"),
            FingerprintRule("path", r'chunk\.js|main\.[a-f0-9]+\.js', 0.6, "React build output"),
        ],
        payload_families=["xss", "prototype_pollution"],
        known_misconfigs=[
            "dangerouslySetInnerHTML used with user input — XSS",
            "Source maps (.map files) deployed to production — exposes source code",
        ],
        known_behaviors={
            "dangerouslySetInnerHTML": "Equivalent of innerHTML — XSS if user-controlled",
        },
        dangerous_features=["dangerouslySetInnerHTML", "source_maps"],
    ),

    KBEntry(
        name="Angular",
        category=TechCategory.JS_FRAMEWORK,
        aliases=["AngularJS", "Angular 2+"],
        fingerprint_rules=[
            FingerprintRule("body", r'ng-version|ng-app|angular\.min\.js', 0.9, "Angular markers"),
        ],
        payload_families=["xss", "ssti"],
        known_misconfigs=[
            "AngularJS (v1) template injection via ng-app sandbox escape",
            "bypassSecurityTrustHtml used — XSS bypass",
        ],
        known_behaviors={
            "ssti_v1": "AngularJS v1 expression injection in ng-app context ({{7*7}})",
        },
    ),

    KBEntry(
        name="Next.js",
        category=TechCategory.JS_FRAMEWORK,
        aliases=["NextJS"],
        default_paths=["/_next/static/", "/_next/data/", "/api/"],
        fingerprint_rules=[
            FingerprintRule("header", r"x-nextjs-page|x-powered-by.*Next\.js", 0.9, "Next.js headers"),
            FingerprintRule("path",   r"/_next/", 0.9, "Next.js static path"),
        ],
        header_patterns={"x-powered-by": r"Next\.js"},
        dangerous_headers=["x-nextjs-page", "x-powered-by"],
        payload_families=["ssrf", "idor", "xss"],
        known_misconfigs=[
            "getServerSideProps fetch() to internal services via SSRF",
            "Unescaped user input in getServerSideProps/getStaticProps",
        ],
    ),

    KBEntry(
        name="Vue.js",
        category=TechCategory.JS_FRAMEWORK,
        aliases=["Vue", "VueJS", "Nuxt.js", "Nuxt"],
        fingerprint_rules=[
            FingerprintRule("body", r'v-bind:|v-on:|data-v-|__vue__', 0.85, "Vue markers"),
        ],
        payload_families=["xss", "ssti"],
        known_misconfigs=[
            "v-html directive used with user input — XSS",
            "Vue template compilation from user input — SSTI",
        ],
    ),

    # ── Caching ───────────────────────────────────────────────────────────────

    KBEntry(
        name="Varnish",
        category=TechCategory.CACHE,
        aliases=["Varnish Cache"],
        fingerprint_rules=[
            FingerprintRule("header", r"varnish", 0.9, "Via/X-Varnish header"),
        ],
        dangerous_headers=["x-varnish", "via"],
        payload_families=["cache_poisoning", "web_cache_deception"],
        known_misconfigs=[
            "Varnish management port (6082) exposed",
            "VCL allows caching authenticated responses",
        ],
    ),

    KBEntry(
        name="Memcached",
        category=TechCategory.CACHE,
        aliases=[],
        payload_families=["ssrf", "injection"],
        known_misconfigs=[
            "Memcached port 11211 exposed without auth",
            "SSRF to Memcached can read/write cache entries",
        ],
    ),

    # ── Container / Infrastructure ────────────────────────────────────────────

    KBEntry(
        name="Docker",
        category=TechCategory.CONTAINER,
        aliases=["Docker Engine"],
        default_paths=[
            "http://localhost:2375/version",
            "http://localhost:2376/version",
            "/info",
            "/containers/json",
        ],
        payload_families=["ssrf", "rce"],
        known_misconfigs=[
            "Docker daemon API exposed on TCP 2375 without TLS",
            "Docker socket mounted inside container",
        ],
        known_behaviors={
            "api_rce": "Unauthenticated Docker API allows creating privileged containers → host RCE",
        },
    ),

    KBEntry(
        name="Kubernetes",
        category=TechCategory.CONTAINER,
        aliases=["k8s"],
        default_paths=[
            "/api/v1/",
            "/apis/",
            "https://kubernetes.default.svc/api/v1/secrets",
        ],
        payload_families=["ssrf", "idor"],
        known_misconfigs=[
            "Kubernetes API server exposed without auth",
            "ServiceAccount token mounted with excessive RBAC permissions",
            "SSRF to kubernetes.default.svc:443/api/v1/secrets",
        ],
    ),

    # ── Analytics & Tracking ──────────────────────────────────────────────────

    KBEntry(
        name="Google Analytics",
        category=TechCategory.ANALYTICS,
        aliases=["GA4", "Universal Analytics"],
        fingerprint_rules=[
            FingerprintRule("body", r'google-analytics\.com/analytics\.js|gtag\(|ga\.js', 0.9, "GA script"),
        ],
        known_behaviors={
            "tracking_ids": "Tracking IDs in source can be used to identify the organization",
        },
    ),

]
