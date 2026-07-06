"""
Intelligence Bridge
========================================
Connects the Phase 2 Intelligence & Discovery Layer to the scan pipeline.

This module provides:
  1. IntelligenceAwareScanner  — enhanced BaseScanner with intelligence context
  2. ScannerIntelligenceContext — per-scan shared intelligence object
  3. IntelligenceBridge        — wires Phase2MasterOrchestrator into ScanEngine
  4. SmartPayloadSelector      — uses KB + fingerprint to choose optimal payloads
  5. AdaptiveScannerRouter     — routes endpoints to the right scanners using
                                 EndpointClassificationEngine output
  6. ScanPlanBuilder           — builds a prioritised, de-duplicated scan plan
                                 from the full intelligence report
  7. PhaseCoordinator          — single entry-point: run intelligence → build plan
                                 → hand off to Phase 3 scanners

After this module the full intelligence pipeline is:

  Intelligence Layer
    └─ Phase2MasterOrchestrator.run()
         └─ Phase2Report
              ├─ fingerprint, intelligence, kb_matches
              ├─ discovery (ClassifiedEndpoints, EvidenceGraph, AttackChains)
              ├─ auth_flow_map, authz_matrix
              └─ rate_stats, session_events

  Phase 6 Bridge (THIS FILE)
    └─ PhaseCoordinator.prepare()
         ├─ ScannerIntelligenceContext  (shared across all scanners)
         ├─ ScanPlanBuilder.build()     (prioritised endpoint list)
         └─ SmartPayloadSelector        (per-endpoint payload selection)

  Phase 3+ Scanners
    └─ IntelligenceAwareScanner.scan_url()
         ├─ self.context (ScannerIntelligenceContext)
         ├─ self.payloads_for(vuln_type)
         └─ self.should_skip(url)
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Type

from ..core.http_client import HTTPClient, HTTPResponse
from ..core.target import ScanTarget
from ..models.vulnerability import Vulnerability, Severity
from ..scanners.base_scanner import BaseScanner


# ---------------------------------------------------------------------------
# 1.  ScannerIntelligenceContext
# ---------------------------------------------------------------------------

@dataclass
class TechProfile:
    """Condensed technology stack extracted from fingerprinting."""
    web_server:    Optional[str] = None    # "nginx", "apache", "iis" …
    framework:     Optional[str] = None    # "django", "rails", "laravel" …
    language:      Optional[str] = None    # "python", "php", "java" …
    database:      Optional[str] = None    # "mysql", "postgresql", "mongodb" …
    cms:           Optional[str] = None    # "wordpress", "drupal" …
    waf:           Optional[str] = None    # "cloudflare", "modsecurity" …
    cloud:         Optional[str] = None    # "aws", "gcp", "azure" …
    all_names:     List[str] = field(default_factory=list)

    @classmethod
    def from_fingerprint(cls, fp: Any) -> "TechProfile":
        """Build from an AppFingerprint object (duck-typed)."""
        profile = cls()
        if fp is None:
            return profile

        techs = getattr(fp, "technologies", []) or []
        profile.all_names = [getattr(t, "name", str(t)).lower() for t in techs]

        def _find(*keywords: str) -> Optional[str]:
            for kw in keywords:
                for name in profile.all_names:
                    if kw in name:
                        return name
            return None

        profile.web_server = _find("nginx", "apache", "iis", "caddy", "lighttpd")
        profile.framework  = _find("django", "flask", "rails", "laravel", "spring",
                                   "express", "fastapi", "symfony", "asp.net")
        profile.language   = _find("python", "php", "java", "ruby", "node",
                                   "golang", "dotnet", "perl")
        profile.database   = _find("mysql", "mariadb", "postgresql", "pgsql",
                                   "mssql", "oracle", "mongodb", "redis", "sqlite")
        profile.cms        = _find("wordpress", "drupal", "joomla", "magento",
                                   "shopify", "strapi")
        profile.waf        = _find("cloudflare", "modsecurity", "akamai", "aws waf",
                                   "f5", "imperva", "sucuri", "wordfence")
        profile.cloud      = _find("aws", "amazon", "gcp", "google cloud",
                                   "azure", "digitalocean", "heroku")
        return profile

    def to_dict(self) -> Dict[str, Any]:
        return {
            "web_server": self.web_server,
            "framework":  self.framework,
            "language":   self.language,
            "database":   self.database,
            "cms":        self.cms,
            "waf":        self.waf,
            "cloud":      self.cloud,
            "all":        self.all_names,
        }


@dataclass
class ScannerIntelligenceContext:
    """
    Shared intelligence object passed to all scanners before scanning starts.

    Scanners use this to:
    - Skip endpoints irrelevant to their vuln type
    - Pick DB-specific SQLi payloads
    - Add extra WAF-evasion encoding when a WAF is detected
    - Focus on high-risk endpoints first
    - Use KB-provided default paths, credentials, and misconfig patterns
    """
    target_url:     str
    tech_profile:   TechProfile
    high_risk_urls: Set[str] = field(default_factory=set)
    owner_only_urls: Set[str] = field(default_factory=set)
    admin_urls:     Set[str] = field(default_factory=set)
    upload_urls:    Set[str] = field(default_factory=set)
    api_urls:       Set[str] = field(default_factory=set)
    graphql_urls:   Set[str] = field(default_factory=set)
    websocket_urls: Set[str] = field(default_factory=set)
    auth_login_url: Optional[str] = None
    kb_default_paths: List[str] = field(default_factory=list)
    kb_default_creds: List[Tuple[str, str]] = field(default_factory=list)
    known_secrets:  List[str] = field(default_factory=list)
    attack_chains:  List[Any] = field(default_factory=list)

    @property
    def waf_detected(self) -> bool:
        return self.tech_profile.waf is not None

    @property
    def tech_stack(self) -> List[str]:
        return self.tech_profile.all_names

    def is_high_risk(self, url: str) -> bool:
        return url in self.high_risk_urls

    def is_owner_only(self, url: str) -> bool:
        return url in self.owner_only_urls

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target":          self.target_url,
            "tech_profile":    self.tech_profile.to_dict(),
            "high_risk_count": len(self.high_risk_urls),
            "waf_detected":    self.waf_detected,
            "auth_login_url":  self.auth_login_url,
            "kb_paths":        len(self.kb_default_paths),
            "attack_chains":   len(self.attack_chains),
        }


# ---------------------------------------------------------------------------
# 2.  IntelligenceAwareScanner  (enhanced BaseScanner)
# ---------------------------------------------------------------------------

class IntelligenceAwareScanner(BaseScanner):
    """
    Drop-in replacement for BaseScanner that adds intelligence context.

    All new scanners (and optionally retrofitted old ones) extend this class.
    The intelligence context is injected once via ``set_context()`` before
    scanning starts and then available as ``self.context`` throughout.

    Key additions over BaseScanner
    --------------------------------
    ``self.context``          — ScannerIntelligenceContext shared across scan
    ``self.payloads_for()``   — returns context-aware payloads via Phase 2 fw
    ``self.should_skip()``    — fast URL filter based on endpoint type
    ``self.encoding_for()``   — returns best WAF-bypass encoding for a payload
    ``self.confidence_ok()``  — True if triple-confirmation passes
    """

    #: Vuln types this scanner handles — used by SmartPayloadSelector
    vuln_types: List[str] = []

    #: Endpoint types this scanner cares about — used by AdaptiveScannerRouter
    relevant_endpoint_types: List[str] = []   # EndpointType values

    def __init__(self, client: HTTPClient) -> None:
        super().__init__(client)
        self._context: Optional[ScannerIntelligenceContext] = None
        self._payload_fw: Optional[Any] = None   # ContextAwarePayloadFramework
        self._encoding_fw: Optional[Any] = None  # EncodingFramework
        self._diff_engine: Optional[Any] = None  # DifferentialAnalysisEngine
        self._triple_fw: Optional[Any] = None    # TripleConfirmationFramework

    def set_context(self, context: ScannerIntelligenceContext) -> None:
        """Inject the shared intelligence context. Called once before scanning."""
        self._context = context
        self._init_phase2_components()

    @property
    def context(self) -> ScannerIntelligenceContext:
        if self._context is None:
            # Return a minimal empty context so scanners don't crash
            return ScannerIntelligenceContext(
                target_url="",
                tech_profile=TechProfile(),
            )
        return self._context

    def _init_phase2_components(self) -> None:
        """Lazily initialise Phase 2 framework objects."""
        try:
            from ..recon.discovery_engine import (
                ContextAwarePayloadFramework,
                EncodingFramework,
            )
            from ..core.differential_engine import DifferentialAnalysisEngine
            self._payload_fw  = ContextAwarePayloadFramework()
            self._encoding_fw = EncodingFramework()
            self._diff_engine = DifferentialAnalysisEngine()
        except Exception:
            pass

    # -- Payload helpers -----------------------------------------------------

    def payloads_for(
        self,
        vuln_type: str,
        context_hint: str = "html_text",
        limit: int = 10,
    ) -> List[str]:
        """
        Return context-aware payload strings for the given vuln type.

        Uses Phase 2 ContextAwarePayloadFramework when available,
        falls back to empty list (scanner uses its own payloads).
        """
        if self._payload_fw is None:
            return []
        try:
            from ..recon.discovery_engine import PayloadContext
            ctx = PayloadContext(context_hint) if context_hint in [
                e.value for e in PayloadContext
            ] else PayloadContext.HTML_TEXT

            payloads = self._payload_fw.get_payloads(
                ctx, vuln_type,
                tech_stack=self.context.tech_stack,
                waf_detected=self.context.waf_detected,
                limit=limit,
            )
            return [p.value for p in payloads]
        except Exception:
            return []

    def encoding_for(self, payload: str) -> str:
        """Return best WAF-bypass encoded variant of ``payload``."""
        if self._encoding_fw is None:
            return payload
        try:
            waf = [self.context.tech_profile.waf] if self.context.tech_profile.waf else []
            ep = self._encoding_fw.select_best(payload, waf_signatures=waf)
            return ep.encoded
        except Exception:
            return payload

    def encoded_variants(self, payload: str, max_variants: int = 5) -> List[str]:
        """Return list of encoded variants for WAF evasion."""
        if self._encoding_fw is None:
            return [payload]
        try:
            variants = self._encoding_fw.variants(payload, max_variants=max_variants)
            return [v.encoded for v in variants] or [payload]
        except Exception:
            return [payload]

    # -- Routing helpers -----------------------------------------------------

    def should_skip(self, url: str) -> bool:
        """
        Return True if this scanner should skip ``url`` entirely.

        Default: never skip. Subclasses can override with domain logic.
        Example: XSSScanner might skip API-only endpoints.
        """
        return False

    def should_prioritise(self, url: str) -> bool:
        """Return True if this URL should be scanned first."""
        return self.context.is_high_risk(url)

    # -- Diff / confirmation -------------------------------------------------

    async def diff_responses(
        self,
        baseline: HTTPResponse,
        test: HTTPResponse,
        baseline_elapsed: float = 0.0,
        test_elapsed: float = 0.0,
    ) -> Any:
        """Compare test response to baseline using DifferentialAnalysisEngine."""
        if self._diff_engine is None:
            return None
        try:
            return self._diff_engine.compare(
                baseline, test, baseline_elapsed, test_elapsed
            )
        except Exception:
            return None

    async def triple_confirm(
        self,
        url: str,
        method: str,
        payload: str,
        baseline: HTTPResponse,
    ) -> bool:
        """
        Run TripleConfirmationFramework to reduce false positives.
        Returns True if the finding is confirmed.
        """
        if self._diff_engine is None:
            return True   # can't confirm → accept finding (conservative)
        try:
            from ..recon.discovery_engine import (
                TripleConfirmationFramework,
                EncodingFramework,
            )
            diff = self._diff_engine
            enc  = self._encoding_fw
            triple = TripleConfirmationFramework(
                self.client, diff, rounds=3, delay_between=0.2
            )
            result = await triple.confirm(
                url, method, payload, baseline,
                encoding_fw=enc,
            )
            return result.confirmed
        except Exception:
            return True


# ---------------------------------------------------------------------------
# 3.  SmartPayloadSelector
# ---------------------------------------------------------------------------

# Mapping: vuln_type → context hints relevant per endpoint type
_VULN_CONTEXT_MAP: Dict[str, Dict[str, str]] = {
    # vuln_type → {endpoint_type_value → context_hint}
    "sqli": {
        "search":         "sql_string",
        "authentication": "sql_string",
        "api":            "sql_numeric",
        "default":        "sql_string",
    },
    "xss": {
        "search":   "html_text",
        "profile":  "html_attr",
        "api":      "json_string",
        "default":  "html_text",
    },
    "ssti": {"default": "template_var"},
    "cmdi": {"default": "shell_arg"},
    "path": {"default": "path_segment"},
}


class SmartPayloadSelector:
    """
    Selects and orders payloads for a given (endpoint, vuln_type) pair
    using Phase 2 intelligence.

    Priority order
    --------------
    1. KB-provided payloads for the detected technology
    2. ContextAwarePayloadFramework payloads tuned for the rendering context
    3. WAF-evasion encoded variants (when WAF detected)
    4. Fallback to base scanner's built-in payload list
    """

    def __init__(self) -> None:
        try:
            from ..recon.discovery_engine import (
                ContextAwarePayloadFramework, EncodingFramework, PayloadContext
            )
            self._payload_fw  = ContextAwarePayloadFramework()
            self._encoding_fw = EncodingFramework()
            self._PayloadContext = PayloadContext
            self._available = True
        except Exception:
            self._available = False

    def select(
        self,
        vuln_type: str,
        endpoint_type: str = "unknown",
        context: Optional[ScannerIntelligenceContext] = None,
        fallback_payloads: Optional[List[str]] = None,
        limit: int = 15,
    ) -> List[str]:
        """
        Return an ordered list of payloads for ``vuln_type``.

        Parameters
        ----------
        vuln_type:          e.g. "sqli", "xss", "cmdi"
        endpoint_type:      EndpointType.value of the target endpoint
        context:            shared intelligence context (optional)
        fallback_payloads:  scanner's own payload list used when Phase 2
                            framework is unavailable
        limit:              max payloads to return
        """
        if not self._available:
            return (fallback_payloads or [])[:limit]

        ctx_hint = (
            _VULN_CONTEXT_MAP
            .get(vuln_type, {})
            .get(endpoint_type, _VULN_CONTEXT_MAP.get(vuln_type, {}).get("default", "html_text"))
        )

        tech_stack: List[str] = []
        waf_detected = False
        if context:
            tech_stack   = context.tech_stack
            waf_detected = context.waf_detected

        try:
            ctx = self._PayloadContext(ctx_hint)
            payloads = self._payload_fw.get_payloads(
                ctx, vuln_type,
                tech_stack=tech_stack,
                waf_detected=waf_detected,
                limit=limit,
            )
            result = [p.value for p in payloads]
        except Exception:
            result = []

        # Add WAF-bypass encoded variants on top
        if waf_detected and result and context and context.tech_profile.waf:
            encoded: List[str] = []
            for payload in result[:3]:
                try:
                    waf_sigs = [context.tech_profile.waf]
                    ep = self._encoding_fw.select_best(payload, waf_signatures=waf_sigs)
                    encoded.append(ep.encoded)
                except Exception:
                    pass
            result = encoded + result

        # Merge with fallback (avoid duplicates)
        seen: Set[str] = set(result)
        for p in (fallback_payloads or []):
            if p not in seen:
                result.append(p)
                seen.add(p)

        return result[:limit]


# ---------------------------------------------------------------------------
# 4.  AdaptiveScannerRouter
# ---------------------------------------------------------------------------

# Maps endpoint type → scanner names that should run on it
_ENDPOINT_SCANNER_MAP: Dict[str, List[str]] = {
    "authentication":  ["SQLiScanner", "XSSScanner", "AuthBypassScanner",
                        "CRLFInjectionScanner", "BruteForceScanner"],
    "file_upload":     ["FileUploadScanner", "XSSScanner", "PathTraversalScanner",
                        "XXEScanner"],
    "search":          ["SQLiScanner", "XSSScanner", "NoSQLiScanner",
                        "LDAPInjectionScanner", "SSTIScanner"],
    "admin":           ["SQLiScanner", "XSSScanner", "AuthBypassScanner",
                        "IDORScanner", "SensitiveFileScanner"],
    "payment":         ["SQLiScanner", "IDORScanner", "RaceConditionScanner",
                        "XSSScanner"],
    "profile":         ["XSSScanner", "StoredXSSScanner", "IDORScanner",
                        "SSTIScanner"],
    "api":             ["SQLiScanner", "NoSQLiScanner", "IDORScanner",
                        "XSSScanner", "XXEScanner", "SSTIScanner"],
    "graphql":         ["GraphQLScanner", "SQLiScanner", "NoSQLiScanner"],
    "websocket":       ["WebSocketScanner", "XSSScanner"],
    "oauth":           ["OAuthScanner", "OpenRedirectScanner", "XSSScanner"],
    "download":        ["PathTraversalScanner", "IDORScanner",
                        "SensitiveFileScanner"],
    "configuration":   ["SensitiveFileScanner", "XSSScanner", "SQLiScanner"],
    "password_reset":  ["XSSScanner", "OpenRedirectScanner",
                        "AuthBypassScanner"],
    "registration":    ["SQLiScanner", "XSSScanner", "NoSQLiScanner"],
    "webhook":         ["SSRFScanner", "XSSScanner", "CmdiScanner"],
    "health_check":    ["SensitiveFileScanner"],
    "static_resource": [],   # skip scanning static files
    "unknown":         ["SQLiScanner", "XSSScanner", "PathTraversalScanner"],
}

# Scanners that always run regardless of endpoint type (target-level)
_ALWAYS_RUN = {"HeadersScanner", "CORSScanner", "SSLTLSScanner",
               "SecretsScanner", "CSRFScanner", "JWTScanner"}


@dataclass
class RoutingDecision:
    """Which scanners should run on a specific endpoint."""
    url:           str
    endpoint_type: str
    scanners:      List[str]          # scanner class names
    priority:      float              # 0.0–1.0; higher = scan sooner
    skip:          bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":           self.url,
            "endpoint_type": self.endpoint_type,
            "scanners":      self.scanners,
            "priority":      round(self.priority, 2),
            "skip":          self.skip,
        }


class AdaptiveScannerRouter:
    """
    Decides which scanners to run on each endpoint based on its
    EndpointType classification from Phase 2.

    Reduces unnecessary scans (e.g. no SQLi on static CSS files) and
    ensures high-risk endpoints get the most relevant scanners.
    """

    def route(
        self,
        classified_endpoints: List[Any],  # ClassifiedEndpoint objects
        context: ScannerIntelligenceContext,
    ) -> List[RoutingDecision]:
        """
        Return a routing decision per endpoint, sorted by priority (desc).
        """
        decisions: List[RoutingDecision] = []

        for ep in classified_endpoints:
            url  = getattr(ep, "url", str(ep))
            etype = getattr(ep, "endpoint_type", None)
            etype_val = getattr(etype, "value", str(etype)) if etype else "unknown"
            risk = getattr(ep, "risk_score", 0.5)

            # Skip static resources entirely
            if etype_val == "static_resource":
                decisions.append(RoutingDecision(
                    url=url, endpoint_type=etype_val,
                    scanners=[], priority=0.0, skip=True,
                ))
                continue

            scanners = list(_ENDPOINT_SCANNER_MAP.get(etype_val, ["SQLiScanner", "XSSScanner"]))

            decisions.append(RoutingDecision(
                url=url,
                endpoint_type=etype_val,
                scanners=scanners,
                priority=risk,
            ))

        decisions.sort(key=lambda d: d.priority, reverse=True)
        return decisions

    def scanners_for_url(
        self,
        url: str,
        classified_endpoints: List[Any],
    ) -> List[str]:
        """Quick lookup: which scanner names should run on this URL."""
        for ep in classified_endpoints:
            if getattr(ep, "url", None) == url:
                etype = getattr(ep, "endpoint_type", None)
                etype_val = getattr(etype, "value", str(etype)) if etype else "unknown"
                return _ENDPOINT_SCANNER_MAP.get(etype_val, [])
        return []


# ---------------------------------------------------------------------------
# 5.  ScanPlanBuilder
# ---------------------------------------------------------------------------

@dataclass
class ScanPlan:
    """
    A prioritised, de-duplicated list of (url, scanner_names) pairs
    ready for the scan pipeline to execute.
    """
    target_url:   str
    items:        List[RoutingDecision]
    total_urls:   int
    skipped_urls: int
    high_priority_count: int
    context:      ScannerIntelligenceContext
    built_at:     float = field(default_factory=time.time)

    @property
    def active_items(self) -> List[RoutingDecision]:
        return [i for i in self.items if not i.skip]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target":              self.target_url,
            "total_urls":          self.total_urls,
            "active_urls":         len(self.active_items),
            "skipped_urls":        self.skipped_urls,
            "high_priority":       self.high_priority_count,
            "tech_profile":        self.context.tech_profile.to_dict(),
            "waf_detected":        self.context.waf_detected,
            "attack_chains":       len(self.context.attack_chains),
        }


class ScanPlanBuilder:
    """
    Builds a ScanPlan from a Phase2Report.

    Steps
    -----
    1. Extract TechProfile from fingerprint.
    2. Build ScannerIntelligenceContext.
    3. Route each classified endpoint to the right scanners.
    4. Inject KB default paths as extra endpoints.
    5. Sort everything by priority.
    6. Return ScanPlan ready for the engine.
    """

    def __init__(self) -> None:
        self._router = AdaptiveScannerRouter()

    def build(
        self,
        phase2_report: Any,     # Phase2Report
        extra_urls: Optional[List[str]] = None,
    ) -> ScanPlan:
        """Build a ScanPlan from a completed Phase2Report."""
        target_url = getattr(phase2_report, "target_url", "")

        # Build TechProfile
        fingerprint = getattr(phase2_report, "fingerprint", None)
        tech_profile = TechProfile.from_fingerprint(fingerprint)

        # Extract classified endpoints
        discovery = getattr(phase2_report, "discovery", None)
        classified = []
        if discovery:
            classified = getattr(discovery, "classified_endpoints", []) or []

        # Build intelligence context
        context = self._build_context(target_url, tech_profile, phase2_report, classified)

        # Route endpoints
        decisions = self._router.route(classified, context)

        # Add any extra URLs (not in classified list)
        classified_urls = {getattr(ep, "url", "") for ep in classified}
        for url in (extra_urls or []):
            if url not in classified_urls:
                decisions.append(RoutingDecision(
                    url=url,
                    endpoint_type="unknown",
                    scanners=["SQLiScanner", "XSSScanner", "PathTraversalScanner"],
                    priority=0.4,
                ))

        # Inject KB default paths as low-priority discovery targets
        for path in context.kb_default_paths[:50]:
            from urllib.parse import urljoin
            url = urljoin(target_url, path)
            if url not in classified_urls:
                decisions.append(RoutingDecision(
                    url=url,
                    endpoint_type="configuration",
                    scanners=["SensitiveFileScanner"],
                    priority=0.3,
                ))

        decisions.sort(key=lambda d: d.priority, reverse=True)

        skipped   = sum(1 for d in decisions if d.skip)
        high_prio = sum(1 for d in decisions if d.priority >= 0.75)

        return ScanPlan(
            target_url=target_url,
            items=decisions,
            total_urls=len(decisions),
            skipped_urls=skipped,
            high_priority_count=high_prio,
            context=context,
        )

    def _build_context(
        self,
        target_url: str,
        tech_profile: TechProfile,
        report: Any,
        classified: List[Any],
    ) -> ScannerIntelligenceContext:
        ctx = ScannerIntelligenceContext(
            target_url=target_url,
            tech_profile=tech_profile,
        )

        # Populate URL sets from classified endpoints
        for ep in classified:
            url   = getattr(ep, "url", "")
            etype = getattr(ep, "endpoint_type", None)
            etype_val = getattr(etype, "value", str(etype)) if etype else "unknown"
            risk  = getattr(ep, "risk_score", 0.0)

            if risk >= 0.75:
                ctx.high_risk_urls.add(url)
            if etype_val == "admin":
                ctx.admin_urls.add(url)
            if etype_val == "file_upload":
                ctx.upload_urls.add(url)
            if etype_val == "api":
                ctx.api_urls.add(url)
            if etype_val == "graphql":
                ctx.graphql_urls.add(url)
            if etype_val == "websocket":
                ctx.websocket_urls.add(url)

        # Owner-only resources from AuthZ matrix
        authz = getattr(report, "authz_matrix", None)
        if authz:
            try:
                for r in getattr(authz, "resources", []):
                    if getattr(r, "resource_owner_only", False):
                        ctx.owner_only_urls.add(r.url)
            except Exception:
                pass

        # Auth flow map
        auth_flow = getattr(report, "auth_flow_map", None)
        if auth_flow:
            ctx.auth_login_url = getattr(auth_flow, "login_url", None)

        # KB data
        kb_matches = getattr(report, "kb_matches", []) or []
        for kb_entry in kb_matches:
            paths = getattr(kb_entry, "default_paths", []) or []
            ctx.kb_default_paths.extend(paths)
            creds = getattr(kb_entry, "default_credentials", []) or []
            ctx.kb_default_creds.extend(
                (c[0], c[1]) if isinstance(c, (list, tuple)) and len(c) >= 2
                else (str(c), "")
                for c in creds
            )

        # Attack chains
        discovery = getattr(report, "discovery", None)
        if discovery:
            ctx.attack_chains = getattr(discovery, "attack_chains", []) or []

        # Known secrets from passive intelligence
        intel = getattr(report, "intelligence", None)
        if intel:
            secrets = getattr(intel, "secrets", []) or []
            ctx.known_secrets = [getattr(s, "value", str(s)) for s in secrets[:20]]

        return ctx


# ---------------------------------------------------------------------------
# 6.  IntelligenceBridge
# ---------------------------------------------------------------------------

class IntelligenceBridge:
    """
    Wires the Phase 2 MasterOrchestrator into the ScanEngine.

    Call ``inject(scanners, context)`` before the engine starts scanning to:
    - Set the ScannerIntelligenceContext on all IntelligenceAwareScanner instances
    - Leave legacy BaseScanner instances untouched (backward-compatible)

    Usage::

        bridge = IntelligenceBridge()
        plan   = await bridge.prepare(client, target, crawled_urls)
        bridge.inject(engine.scanners, plan.context)
        # now run the engine as normal
    """

    def __init__(self) -> None:
        self._builder = ScanPlanBuilder()

    async def prepare(
        self,
        client: HTTPClient,
        target: ScanTarget,
        crawled_urls: Optional[List[str]] = None,
        confirmed_findings: Optional[List[Dict[str, Any]]] = None,
        *,
        skip_fingerprint:    bool = False,
        skip_intelligence:   bool = False,
        skip_knowledge_base: bool = False,
        rate_initial_delay:  float = 0.3,
    ) -> "ScanPlan":
        """
        Run Phase 2 and build a ScanPlan. Returns the plan even if Phase 2
        components fail (graceful degradation).
        """
        try:
            from ..recon.intelligence_layer import Phase2MasterOrchestrator
            orch = Phase2MasterOrchestrator(
                client, target,
                rate_initial_delay=rate_initial_delay,
                rate_min_delay=0.0,
            )
            report = await orch.run(
                skip_fingerprint=skip_fingerprint,
                skip_intelligence=skip_intelligence,
                skip_knowledge_base=skip_knowledge_base,
                crawled_urls=crawled_urls,
                confirmed_findings=confirmed_findings,
            )
            return self._builder.build(report, extra_urls=crawled_urls)
        except Exception:
            # Return minimal plan so scanning continues regardless
            return self._minimal_plan(target.base_url, crawled_urls or [])

    def inject(
        self,
        scanners: List[BaseScanner],
        context: ScannerIntelligenceContext,
    ) -> int:
        """
        Inject intelligence context into all IntelligenceAwareScanner instances.
        Returns the number of scanners successfully upgraded.
        """
        upgraded = 0
        for scanner in scanners:
            if isinstance(scanner, IntelligenceAwareScanner):
                scanner.set_context(context)
                upgraded += 1
        return upgraded

    def _minimal_plan(
        self, target_url: str, urls: List[str]
    ) -> "ScanPlan":
        """Fallback plan when Phase 2 fails completely."""
        context = ScannerIntelligenceContext(
            target_url=target_url,
            tech_profile=TechProfile(),
        )
        items = [
            RoutingDecision(
                url=url,
                endpoint_type="unknown",
                scanners=["SQLiScanner", "XSSScanner", "PathTraversalScanner"],
                priority=0.5,
            )
            for url in urls
        ]
        return ScanPlan(
            target_url=target_url,
            items=items,
            total_urls=len(items),
            skipped_urls=0,
            high_priority_count=0,
            context=context,
        )


# ---------------------------------------------------------------------------
# 7.  PhaseCoordinator  (top-level entry point for the whole bridge)
# ---------------------------------------------------------------------------

class PhaseCoordinator:
    """
    Single entry-point that coordinates Phase 2 → Phase 3 handoff.

    Typical integration with ScanEngine::

        coord = PhaseCoordinator(client, target)

        # Before scan: run intelligence layer, build plan, inject context
        plan = await coord.prepare(
            crawled_urls=all_urls,
            engine_scanners=engine.scanners,
        )

        # Plan is available for the engine to use
        print(plan.to_dict())

        # During scan: engine runs normally, scanners now have Phase 2 context
        result = await engine.run()

        # After scan: attach intelligence context to result metadata
        coord.annotate_result(result, plan)
    """

    def __init__(
        self,
        client: HTTPClient,
        target: ScanTarget,
        *,
        rate_initial_delay: float = 0.3,
        skip_fingerprint:   bool = False,
        skip_intelligence:  bool = False,
        skip_knowledge_base: bool = False,
    ) -> None:
        self._client  = client
        self._target  = target
        self._rate_delay  = rate_initial_delay
        self._skip_fp     = skip_fingerprint
        self._skip_intel  = skip_intelligence
        self._skip_kb     = skip_knowledge_base
        self._bridge  = IntelligenceBridge()
        self._plan: Optional[ScanPlan] = None

    async def prepare(
        self,
        crawled_urls: Optional[List[str]] = None,
        engine_scanners: Optional[List[BaseScanner]] = None,
        confirmed_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> ScanPlan:
        """
        Run Phase 2 and inject intelligence into scanners.
        Returns the ScanPlan for optional inspection.
        """
        self._plan = await self._bridge.prepare(
            self._client,
            self._target,
            crawled_urls=crawled_urls,
            confirmed_findings=confirmed_findings,
            skip_fingerprint=self._skip_fp,
            skip_intelligence=self._skip_intel,
            skip_knowledge_base=self._skip_kb,
            rate_initial_delay=self._rate_delay,
        )

        if engine_scanners:
            upgraded = self._bridge.inject(engine_scanners, self._plan.context)
            if upgraded:
                pass  # n scanners upgraded silently

        return self._plan

    @property
    def plan(self) -> Optional[ScanPlan]:
        return self._plan

    def annotate_result(self, result: Any, plan: Optional[ScanPlan] = None) -> None:
        """
        Attach Phase 2 intelligence summary to a ScanResult's metadata dict.
        Safe to call even if Phase 2 failed (plan may be None).
        """
        p = plan or self._plan
        if p is None or result is None:
            return
        meta = getattr(result, "metadata", None)
        if isinstance(meta, dict):
            meta["phase2_intelligence"] = p.to_dict()

    def prioritised_urls(self) -> List[str]:
        """Return scan URLs sorted by priority (high-risk first)."""
        if self._plan is None:
            return []
        return [d.url for d in self._plan.active_items]

    def scanner_names_for(self, url: str) -> List[str]:
        """Return which scanner names should handle ``url``."""
        if self._plan is None:
            return []
        for d in self._plan.items:
            if d.url == url:
                return d.scanners
        return []
