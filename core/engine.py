"""
Main scanning engine - orchestrates crawling and vulnerability scanning.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .crawler import Crawler, CrawlResult
from .http_client import HTTPClient, HTTPResponse
from .target import ScanTarget
from ..models.scan_result import ScanResult, ScanStats
from ..models.vulnerability import Vulnerability, VulnType, Severity, CVSSv3
from ..models.vulnerability import (
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)
from ..scanners.base_scanner import BaseScanner
from ..utils.helpers import (
    severity_color, normalize_url,
    RESET_COLOR, BOLD, GREEN, CYAN, DIM, YELLOW, MAGENTA,
)

# ── Phase 1 components ───────────────────────────────────────────────────────
from .js_analyzer import JSAnalyzer, JSAnalysisResult, SecretMatch
from .openapi_parser import OpenAPIParser, APISpec, APIEndpoint

try:
    from .browser_engine import BrowserEngine, BrowserCrawlResult, PLAYWRIGHT_AVAILABLE
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    BrowserEngine = None        # type: ignore[assignment,misc]
    BrowserCrawlResult = None   # type: ignore[assignment]

# WebSocket scanner — imported lazily so missing playwright doesn't hard-fail
try:
    from ..scanners.websocket_scanner import WebSocketScanner
    _WS_SCANNER_AVAILABLE = True
except ImportError:
    _WS_SCANNER_AVAILABLE = False
    WebSocketScanner = None     # type: ignore[assignment,misc]

# ── Phase 2 components ───────────────────────────────────────────────────────
from .passive_analyzer import PassiveAnalyzer, ReplayCrawlItem
from .api_fuzzer import APIFuzzer, MutationResult, generate_mutations

try:
    from ..recon.asset_discovery import AssetDiscovery, AssetReport
    _ASSET_DISCOVERY_AVAILABLE = True
except ImportError:
    _ASSET_DISCOVERY_AVAILABLE = False
    AssetDiscovery = None       # type: ignore[assignment,misc]
    AssetReport = None          # type: ignore[assignment]

# ── Phase 2 Intelligence & Discovery Layer (recon/) ──────────────────────────
# Connects FingerprintEngine, PassiveIntelligenceEngine, KnowledgeBase,
# DiscoveryOrchestrator (endpoint classification, parameter intelligence,
# context-aware payloads, encoding, triple confirmation, evidence graph,
# attack chains, multi-account), AuthenticationFramework, AuthorizationFramework,
# AdaptiveRateController and SessionManagementFramework into the live scan.
try:
    from ..recon.intelligence_bridge import PhaseCoordinator
    _INTELLIGENCE_BRIDGE_AVAILABLE = True
except ImportError:
    _INTELLIGENCE_BRIDGE_AVAILABLE = False
    PhaseCoordinator = None     # type: ignore[assignment,misc]

# Standalone Phase 2 engines not covered by Phase2MasterOrchestrator
try:
    from ..recon.api_discovery_engine import APIDiscoveryEngine
    _API_DISCOVERY_AVAILABLE = True
except ImportError:
    _API_DISCOVERY_AVAILABLE = False
    APIDiscoveryEngine = None   # type: ignore[assignment,misc]

try:
    from ..recon.graphql_framework import GraphQLFramework
    _GRAPHQL_FRAMEWORK_AVAILABLE = True
except ImportError:
    _GRAPHQL_FRAMEWORK_AVAILABLE = False
    GraphQLFramework = None     # type: ignore[assignment,misc]

try:
    from ..recon.websocket_framework import run_websocket_framework
    _WS_FRAMEWORK_AVAILABLE = True
except ImportError:
    _WS_FRAMEWORK_AVAILABLE = False
    run_websocket_framework = None  # type: ignore[assignment,misc]

# ── Phase 3 components ───────────────────────────────────────────────────────
try:
    from .auth_engine import AuthEngine, AuthConfig, AuthSession
    _AUTH_ENGINE_AVAILABLE = True
except ImportError:
    _AUTH_ENGINE_AVAILABLE = False
    AuthEngine = None       # type: ignore[assignment,misc]
    AuthConfig = None       # type: ignore[assignment]
    AuthSession = None      # type: ignore[assignment]

# ── Phase 4 components ───────────────────────────────────────────────────────
from ..utils.response_analyzer import ResponseAnalyzer
from .baseline_engine import BaselineEngine
from .differential_engine import DifferentialAnalysisEngine
from ..utils.confidence_engine import ConfidenceEngine
from ..utils.timing_analyzer import TimingAnalyzer
from ..utils.reflection_tracker import ReflectionTracker


def _safe_serialize(obj: Any) -> Any:
    """
    Best-effort conversion of Phase 2 dataclass/enum-heavy result objects
    into JSON-safe primitives for ScanResult.metadata, without assuming
    every recon model implements ``to_dict()``.
    """
    import dataclasses
    import enum

    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, (list, tuple, set)):
        return [_safe_serialize(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items()}
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: _safe_serialize(getattr(obj, f.name))
            for f in dataclasses.fields(obj)
        }
    if hasattr(obj, "to_dict"):
        try:
            return _safe_serialize(obj.to_dict())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        try:
            return {
                k: _safe_serialize(v)
                for k, v in vars(obj).items()
                if not k.startswith("_")
            }
        except Exception:
            pass
    return str(obj)


# ── CVSS profile for secret exposure findings ────────────────────────────────
_CVSS_SECRET = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)


class ScanEngine:
    """
    Orchestrates the full vulnerability scan pipeline.

    Phase 1 (static):   BFS HTML crawl
    Phase 2 (browser):  Headless browser crawl — discovers SPA routes,
                        real API calls, WebSocket endpoints  [optional]
    Phase 3:            JavaScript analysis — API endpoints, secrets, routes
    Phase 4:            OpenAPI / Swagger spec discovery & parsing
    Phase 5:            Probe common API wordlist endpoints
    Phase 6:            HAR / Burp passive import  [Phase 2.2 — optional]
    Phase 7:            Run per-URL vulnerability scanners
    Phase 8:            Run target-level scanners + WebSocket + Asset Discovery

    Phase 4 (Roadmap):  Response Analysis Engine
      - ResponseAnalyzer    → structural similarity for FP reduction
      - BaselineEngine      → adaptive per-endpoint baselines
      - DifferentialAnalysisEngine → vs-baseline / vs-previous response diffing
      - ConfidenceEngine    → multi-signal confidence scoring
      - TimingAnalyzer      → statistical time-based anomaly detection
      - ReflectionTracker   → context-aware payload suggestions
    """

    def __init__(
        self,
        target: ScanTarget,
        client: HTTPClient,
        scanners: List[BaseScanner],
        concurrent_scanners: int = 5,
        probe_api_endpoints: bool = True,
        use_browser: bool = False,
        browser_screenshots: bool = True,
        browser_headless: bool = True,
        analyze_js: bool = True,
        discover_openapi: bool = True,
        # Phase 2 options
        import_har: Optional[str] = None,
        import_burp: Optional[str] = None,
        run_asset_discovery: bool = False,
        # Phase 3 options
        auth_config: Optional[Any] = None,
        run_authz_matrix: bool = False,
        run_intelligence_layer: bool = True,
        run_correlation: bool = True,
        verbose: bool = True,
    ) -> None:
        self.target = target
        self.client = client
        self.scanners = scanners
        self.concurrent_scanners = concurrent_scanners
        self.probe_api_endpoints = probe_api_endpoints
        self.use_browser = use_browser and bool(PLAYWRIGHT_AVAILABLE)
        self.browser_screenshots = browser_screenshots
        self.browser_headless = browser_headless
        self.analyze_js = analyze_js
        self.discover_openapi = discover_openapi
        # Phase 2
        self.import_har = import_har
        self.import_burp = import_burp
        self.run_asset_discovery = run_asset_discovery
        # Phase 3
        self.auth_config = auth_config          # AuthConfig instance or None
        self.run_authz_matrix = run_authz_matrix
        self._auth_sessions: List[Any] = []     # AuthSession list after login
        self.verbose = verbose
        self._scan_result: Optional[ScanResult] = None
        # Screenshots store: url → PNG bytes
        self._screenshots: Dict[str, bytes] = {}
        # Collected JS analysis results
        self._js_results: List[JSAnalysisResult] = []
        # Discovered OpenAPI specs
        self._api_specs: List[APISpec] = []
        # Phase 2 passive import stats
        self._passive_items_loaded: int = 0
        # ── Phase 4 engines (Response Analysis) ──────────────────────────────
        self.response_analyzer = ResponseAnalyzer()
        self.baseline_engine   = BaselineEngine(client, samples=3, analyzer=self.response_analyzer)
        self.differential_engine = DifferentialAnalysisEngine(analyzer=self.response_analyzer)
        self.confidence_engine = ConfidenceEngine()
        self.timing_analyzer   = TimingAnalyzer(client)
        self.reflection_tracker = ReflectionTracker()
        # ── Phase 3 Analysis Layer (correlation + risk) ──────────────────────
        self.run_correlation: bool = run_correlation
        # ── Phase 2 Intelligence & Discovery Layer state ─────────────────────
        self.run_intelligence_layer: bool = run_intelligence_layer
        self._phase_coordinator: Optional[Any] = None
        self._intelligence_plan: Optional[Any] = None
        self._api_discovery_report: Optional[Any] = None
        self._graphql_report: Optional[Any] = None
        self._websocket_report: Optional[Any] = None

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    # =========================================================================
    # Public entry point
    # =========================================================================

    async def run(self, scan_profile: str = "full") -> ScanResult:
        """Execute the full scan pipeline and return a ScanResult."""
        scan_id = str(uuid.uuid4())[:8].upper()
        stats = ScanStats(start_time=datetime.utcnow())
        result = ScanResult(
            target_url=self.target.url,
            scan_id=scan_id,
            stats=stats,
            scan_profile=scan_profile,
            metadata=self.target.to_dict(),
        )
        self._scan_result = result

        self._log(f"\n{BOLD}{CYAN}╔{'═'*60}╗{RESET_COLOR}")
        self._log(f"{BOLD}{CYAN}║  WebShield Security Scanner — Scan ID: {scan_id:<18}║{RESET_COLOR}")
        self._log(f"{BOLD}{CYAN}╚{'═'*60}╝{RESET_COLOR}\n")
        self._log(f"{BOLD}Target:{RESET_COLOR}  {self.target.url}")
        self._log(f"{BOLD}Profile:{RESET_COLOR} {scan_profile}")
        self._log(f"\n{BOLD}[Phase 1]{RESET_COLOR} Static crawl...")
        self._log(f"{BOLD}Browser:{RESET_COLOR} {'✓ Playwright' if self.use_browser else '✗ Static only'}")
        self._log(f"{BOLD}JS Scan:{RESET_COLOR} {'✓ Enabled' if self.analyze_js else '✗ Disabled'}")
        self._log(f"{BOLD}OpenAPI:{RESET_COLOR} {'✓ Enabled' if self.discover_openapi else '✗ Disabled'}")
        if self.import_har:
            self._log(f"{BOLD}HAR    :{RESET_COLOR} {self.import_har}")
        if self.import_burp:
            self._log(f"{BOLD}Burp   :{RESET_COLOR} {self.import_burp}")
        self._log(f"{BOLD}Scanners:{RESET_COLOR} {len(self.scanners)}\n")

        # Shared accumulators across all phases
        all_crawl_items: List[Any] = []
        all_script_urls: List[str] = []     # JS files to analyze
        all_ws_urls: List[str] = []         # WebSocket endpoints found

        # ── Phase 1: Static BFS Crawl ─────────────────────────────────────────
        static_items, static_scripts = await self._run_static_crawl(stats, result)
        all_crawl_items.extend(static_items)
        all_script_urls.extend(static_scripts)

        # ── Phase 2: Browser Crawl ────────────────────────────────────────────
        if self.use_browser:
            self._log(f"\n{BOLD}[Phase 2] Headless browser crawl...{RESET_COLOR}")
            browser_crawl_items, browser_scripts, browser_ws = await self._run_browser_crawl(
                existing_urls={cr.url for cr in all_crawl_items},
                stats=stats,
            )
            all_crawl_items.extend(browser_crawl_items)
            all_script_urls.extend(browser_scripts)
            all_ws_urls.extend(browser_ws)
        else:
            self._log(
                f"\n{BOLD}[Phase 2] Browser crawl{RESET_COLOR} "
                f"{DIM}(skipped — pass --browser to enable){RESET_COLOR}"
            )

        # ── Phase 3: JavaScript Analysis ──────────────────────────────────────
        unique_scripts = list(dict.fromkeys(all_script_urls))
        if self.analyze_js and unique_scripts:
            self._log(
                f"\n{BOLD}[Phase 3] JavaScript analysis "
                f"({len(unique_scripts)} scripts)...{RESET_COLOR}"
            )
            new_js_items = await self._run_js_analysis(
                unique_scripts, result, stats
            )
            all_crawl_items.extend(new_js_items)
        else:
            self._log(
                f"\n{BOLD}[Phase 3] JS analysis{RESET_COLOR} "
                f"{DIM}(skipped — no scripts found or disabled){RESET_COLOR}"
            )

        # ── Phase 4: OpenAPI Discovery ────────────────────────────────────────
        if self.discover_openapi:
            self._log(f"\n{BOLD}[Phase 4] OpenAPI / Swagger discovery...{RESET_COLOR}")
            openapi_items = await self._run_openapi_discovery(
                existing_urls={cr.url for cr in all_crawl_items},
                stats=stats,
            )
            all_crawl_items.extend(openapi_items)
        else:
            self._log(f"\n{BOLD}[Phase 4] OpenAPI discovery{RESET_COLOR} {DIM}(skipped){RESET_COLOR}")

        # ── Phase 5: API Wordlist Probing ─────────────────────────────────────
        if self.probe_api_endpoints:
            self._log(f"\n{BOLD}[Phase 5] Probing API endpoints...{RESET_COLOR}")
            wordlist_items = await self._run_api_wordlist_probe(
                existing_urls={cr.url for cr in all_crawl_items},
                stats=stats,
            )
            all_crawl_items.extend(wordlist_items)

        # ── Phase 6: Passive Import (HAR / Burp) ──────────────────────────────
        if self.import_har or self.import_burp:
            self._log(f"\n{BOLD}[Phase 6] Passive traffic import...{RESET_COLOR}")
            passive_items = await self._run_passive_import(stats)
            all_crawl_items.extend(passive_items)
        else:
            self._log(
                f"\n{BOLD}[Phase 6] Passive import{RESET_COLOR} "
                f"{DIM}(skipped — pass --har-file or --burp-file to enable){RESET_COLOR}"
            )

        # ── Phase 6.5: Authorization Engine (Phase 3) ─────────────────────────
        if self.auth_config and _AUTH_ENGINE_AVAILABLE:
            self._log(f"\n{BOLD}[Phase 6.5] Authorization Engine — login flows...{RESET_COLOR}")
            await self._run_auth_engine(result)
        else:
            self._log(
                f"\n{BOLD}[Phase 6.5] Auth Engine{RESET_COLOR} "
                f"{DIM}(skipped — pass --auth-login-url to enable){RESET_COLOR}"
            )

        # ── Phase 6.7: Intelligence & Discovery Layer (Phase 2 roadmap) ────────
        if self.run_intelligence_layer and _INTELLIGENCE_BRIDGE_AVAILABLE:
            self._log(f"\n{BOLD}[Phase 6.7] Intelligence & Discovery layer...{RESET_COLOR}")
            await self._run_intelligence_layer(all_crawl_items, result)
        else:
            self._log(
                f"\n{BOLD}[Phase 6.7] Intelligence layer{RESET_COLOR} "
                f"{DIM}(skipped — bridge unavailable or disabled){RESET_COLOR}"
            )

        # Deduplicate crawl items by URL (keep first occurrence)
        seen_urls: Set[str] = set()
        deduped: List[Any] = []
        for cr in all_crawl_items:
            if cr.url not in seen_urls:
                seen_urls.add(cr.url)
                deduped.append(cr)
        all_crawl_items = deduped

        result.crawled_urls = [cr.url for cr in all_crawl_items]

        # ── Phase 7: Per-URL Vulnerability Scanning ───────────────────────────
        self._log(
            f"\n{BOLD}[Phase 7] Running vulnerability scanners "
            f"({len(all_crawl_items)} targets)...{RESET_COLOR}"
        )
        semaphore = asyncio.Semaphore(self.concurrent_scanners)
        total_pages = len(all_crawl_items)
        scanned_count = 0

        async def scan_page(cr: Any) -> None:
            nonlocal scanned_count
            async with semaphore:
                await self._scan_crawl_result(cr, result, stats)
                scanned_count += 1
                if self.verbose and total_pages > 1:
                    pct = int(scanned_count / total_pages * 100)
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    vuln_count = len(result.vulnerabilities)
                    print(
                        f"\r  [{bar}] {pct:3d}% "
                        f"({scanned_count}/{total_pages}) "
                        f"Findings: {vuln_count}",
                        end="", flush=True,
                    )

        await asyncio.gather(*[scan_page(cr) for cr in all_crawl_items], return_exceptions=True)
        if self.verbose and total_pages > 1:
            print()  # newline after progress bar

        # Fix 2.2: inject crawled URLs into AuthzMatrix AFTER Phase 7 completes —
        # result.crawled_urls is fully populated here (not in Phase 6.5).
        if self.run_authz_matrix and self._auth_sessions:
            from ..scanners.authz_matrix import AuthorizationMatrixScanner
            for scanner in self.scanners:
                if isinstance(scanner, AuthorizationMatrixScanner):
                    scanner.set_urls(result.crawled_urls)
                    if self.verbose:
                        self._log(
                            f"  {GREEN}✓ AuthzMatrix URLs updated: "
                            f"{len(result.crawled_urls)} endpoints × "
                            f"{len(self._auth_sessions)} role(s){RESET_COLOR}"
                        )
                    break

        # ── Phase 8: Target-level + WebSocket + Asset Discovery scanners ──────
        self._log(f"\n{BOLD}[Phase 8] Running target-level checks...{RESET_COLOR}")
        await self._run_target_level_scanners(result, stats, ws_urls=all_ws_urls)

        # ── Finalise ──────────────────────────────────────────────────────────
        stats.end_time = datetime.utcnow()
        if stats.start_time:
            stats.duration_seconds = (stats.end_time - stats.start_time).total_seconds()
        stats.requests_sent = self.client.request_count
        stats.urls_scanned = len(all_crawl_items)

        # Fix 4.1: wire browser screenshots into the scan result
        if self._screenshots:
            result.screenshots.update(self._screenshots)

        # Fix 4.3: populate coverage metrics in ScanStats
        # endpoints_discovered = total URLs found before dedup (across all phases)
        # endpoints_tested = unique URLs actually scanned (after dedup)
        stats.endpoints_discovered       = stats.urls_crawled   # tracks raw count per phase
        stats.endpoints_tested           = len(all_crawl_items)  # after deduplication
        stats.js_files_analyzed          = len(unique_scripts) if self.analyze_js else 0
        stats.openapi_endpoints_found    = sum(s.endpoint_count for s in self._api_specs)
        stats.websocket_endpoints_found  = len(set(all_ws_urls))
        stats.passive_requests_imported  = self._passive_items_loaded

        result.metadata["js_files_analyzed"]    = stats.js_files_analyzed
        result.metadata["openapi_specs_found"]  = len(self._api_specs)
        result.metadata["websocket_urls_found"] = stats.websocket_endpoints_found
        result.metadata["passive_items_loaded"] = self._passive_items_loaded
        if self._api_specs:
            result.metadata["openapi_specs"] = [s.to_dict() for s in self._api_specs]

        # ── Phase 2 intelligence summary into result.metadata ───────────────
        if self._phase_coordinator is not None and self._intelligence_plan is not None:
            try:
                self._phase_coordinator.annotate_result(result, self._intelligence_plan)
            except Exception:
                pass

        # ── Phase 9: Correlation & Risk Analysis (Phase 3 analysis layer) ────
        if self.run_correlation:
            self._log(f"\n{BOLD}[Phase 9] Correlation & risk analysis...{RESET_COLOR}")
            self._run_correlation_analysis(result)

        self._print_summary(result)
        return result

    def _run_correlation_analysis(self, result: ScanResult) -> None:
        """
        Phase 9 — turn the flat finding list into attack chains and a
        contextual, exploitability-weighted risk model.  Best-effort: any
        failure degrades gracefully to the pre-existing severity-only view.
        """
        try:
            from ..analysis import (
                ComplianceFramework,
                RemediationFramework,
                RiskAnalysisFramework,
                VulnerabilityCorrelationEngine,
            )
        except Exception as exc:  # pragma: no cover - import guard
            self._log(f"  {YELLOW}[!] Analysis layer unavailable: {exc}{RESET_COLOR}")
            return

        try:
            correlation = VulnerabilityCorrelationEngine().correlate(result.vulnerabilities)
            risk = RiskAnalysisFramework().analyze(result.vulnerabilities, correlation.chains)
            result.metadata["correlation"] = correlation.to_dict()
            result.metadata["risk_analysis"] = risk.to_dict()
            confirmed = len(correlation.confirmed_chains)
            self._log(
                f"  {GREEN}✓ Correlation: {len(correlation.chains)} chain(s) "
                f"({confirmed} confirmed), contextual risk "
                f"{risk.aggregate_risk:.1f}/10 ({risk.aggregate_level}){RESET_COLOR}"
            )
        except Exception as exc:
            self._log(f"  {YELLOW}[!] Correlation analysis failed: {exc}{RESET_COLOR}")

        try:
            compliance = ComplianceFramework().map(result.vulnerabilities)
            result.metadata["compliance"] = compliance.to_dict()
            self._log(
                f"  {GREEN}✓ Compliance: mapped to "
                f"{len(compliance.standards_covered())} standard(s){RESET_COLOR}"
            )
        except Exception as exc:
            self._log(f"  {YELLOW}[!] Compliance mapping failed: {exc}{RESET_COLOR}")

        try:
            tech_profile = None
            p2 = result.metadata.get("phase2_intelligence")
            if isinstance(p2, dict):
                tech_profile = p2.get("tech_profile")
            remediation = RemediationFramework().generate(result.vulnerabilities, tech_profile)
            result.metadata["remediation"] = remediation.to_dict()
            self._log(
                f"  {GREEN}✓ Remediation: {len(remediation.guidance)} guidance item(s)"
                + (f" tailored for {remediation.detected_language}" if remediation.detected_language else "")
                + f"{RESET_COLOR}"
            )
        except Exception as exc:
            self._log(f"  {YELLOW}[!] Remediation generation failed: {exc}{RESET_COLOR}")

    # =========================================================================
    # Phase implementations
    # =========================================================================

    async def _run_static_crawl(
        self,
        stats: ScanStats,
        result: ScanResult,
    ) -> Tuple[List[CrawlResult], List[str]]:
        """Phase 1 — BFS static HTML crawl."""
        crawl_items: List[CrawlResult] = []
        script_urls: List[str] = []

        crawler = Crawler(self.client, self.target, max_pages=self.target.max_pages)
        async for crawl_result in crawler.crawl():
            crawl_items.append(crawl_result)
            stats.urls_crawled += 1
            script_urls.extend(crawl_result.scripts)
            self._log(
                f"  {DIM}[Crawl] {crawl_result.url} "
                f"({crawl_result.response.status_code}, "
                f"{len(crawl_result.forms)} forms){RESET_COLOR}"
            )

        self._log(
            f"\n  {GREEN}✓ Static crawl: {stats.urls_crawled} pages, "
            f"{len(crawler.discovered_forms)} forms{RESET_COLOR}"
        )
        return crawl_items, script_urls

    async def _run_browser_crawl(
        self,
        existing_urls: Set[str],
        stats: ScanStats,
    ) -> Tuple[List[CrawlResult], List[str], List[str]]:
        """
        Phase 2 — Headless Playwright crawl.
        Returns (new_crawl_items, new_script_urls, ws_urls).
        """
        if not PLAYWRIGHT_AVAILABLE or BrowserEngine is None:
            self._log(f"  {YELLOW}[!] Playwright not available — skipping browser crawl{RESET_COLOR}")
            return [], [], []

        new_items: List[CrawlResult] = []
        new_scripts: List[str] = []
        ws_urls: List[str] = []

        engine = BrowserEngine(
            target=self.target,
            headless=self.browser_headless,
            screenshots=self.browser_screenshots,
            auth_token=self.client.auth_token,
            cookies=dict(self.client.cookies) if self.client.cookies else {},
            custom_headers=self.client.custom_headers,
            proxy=self.client.proxy,
            max_pages=self.target.max_pages,
            max_depth=self.target.max_depth,
        )

        page_count = 0
        async for browser_result in engine.crawl():
            # Store screenshot if available
            if browser_result.screenshot:
                self._screenshots[browser_result.url] = browser_result.screenshot

            # Convert BrowserCrawlResult → CrawlResult for compatibility
            # Only add URLs the static crawler missed
            if browser_result.url not in existing_urls:
                # We need a real HTTPResponse — re-fetch via our client
                resp = await self.client.get(browser_result.url)
                if resp:
                    new_items.append(CrawlResult(
                        url=browser_result.url,
                        response=resp,
                        depth=browser_result.depth,
                        forms=browser_result.forms,
                        links=browser_result.links,
                    ))
                    stats.urls_crawled += 1
                    existing_urls.add(browser_result.url)

            # Also add API endpoints discovered via network interception
            for api_call in browser_result.api_calls:
                if api_call.is_api_call and api_call.url not in existing_urls:
                    resp = await self.client.get(api_call.url)
                    if resp:
                        new_items.append(CrawlResult(
                            url=api_call.url,
                            response=resp,
                            depth=browser_result.depth,
                            forms=[],
                            links=[],
                        ))
                        stats.urls_crawled += 1
                        existing_urls.add(api_call.url)

            new_scripts.extend(browser_result.script_urls)
            ws_urls.extend(browser_result.websocket_urls)
            page_count += 1

            self._log(
                f"  {DIM}[Browser] {browser_result.url} "
                f"({len(browser_result.api_calls)} API calls, "
                f"{len(browser_result.websocket_urls)} WS){RESET_COLOR}"
            )

        ws_urls.extend(engine.all_websocket_urls)
        unique_ws = list(dict.fromkeys(ws_urls))

        self._log(
            f"\n  {GREEN}✓ Browser crawl: {page_count} pages, "
            f"{len(new_items)} new endpoints, "
            f"{len(unique_ws)} WebSocket URLs{RESET_COLOR}"
        )
        return new_items, new_scripts, unique_ws

    async def _run_js_analysis(
        self,
        script_urls: List[str],
        result: ScanResult,
        stats: ScanStats,
    ) -> List[CrawlResult]:
        """
        Phase 3 — Analyze JS bundles for API endpoints, routes, secrets.
        Returns new CrawlResult items for newly discovered API endpoints.
        """
        analyzer = JSAnalyzer(
            client=self.client,
            base_url=self.target.base_url,
            max_concurrent=5,
        )
        js_results = await analyzer.analyze_scripts(script_urls)
        self._js_results.extend(js_results)

        all_endpoints: Set[str] = set()
        all_secrets: List[SecretMatch] = []

        for r in js_results:
            all_endpoints.update(r.endpoints)
            all_secrets.extend(r.secrets)
            if r.error:
                stats.errors += 1

        # Report secrets as vulnerabilities
        for secret in all_secrets:
            vuln = Vulnerability(
                vuln_type=VulnType.SECRET_EXPOSURE,
                title=f"Leaked Secret in JavaScript: {secret.secret_type}",
                description=(
                    f"A {secret.secret_type} was found hardcoded or exposed in a "
                    f"JavaScript file. Leaked credentials can allow attackers to "
                    f"directly access third-party services, cloud infrastructure, "
                    f"or internal APIs.\n\n"
                    f"File: {secret.source_url}\n"
                    f"Value (redacted): {secret.redacted_value()}"
                ),
                url=secret.source_url,
                method="GET",
                evidence=f"Context: {secret.context[:150]}",
                severity=Severity.HIGH if secret.confidence == "High" else Severity.MEDIUM,
                cvss=_CVSS_SECRET,
                remediation=(
                    "Remove the secret from the source code immediately. "
                    "Rotate the exposed credential. "
                    "Use environment variables or a secrets manager (e.g. AWS Secrets Manager, "
                    "HashiCorp Vault) to inject secrets at runtime, never bundle them in "
                    "client-side JavaScript."
                ),
                references=[
                    "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
                    "https://cwe.mitre.org/data/definitions/798.html",
                ],
                cwe_id="CWE-798",
                owasp_category="A02:2021 – Cryptographic Failures",
                confidence=secret.confidence,
                false_positive_risk="Low" if secret.confidence == "High" else "Medium",
            )
            result.add_vulnerability(vuln)
            self._report_finding(vuln)

        self._log(
            f"\n  {GREEN}✓ JS analysis: {len(js_results)} files, "
            f"{len(all_endpoints)} endpoints, "
            f"{len(all_secrets)} secrets{RESET_COLOR}"
        )

        # Fetch newly discovered endpoints for scanning
        new_items: List[CrawlResult] = []
        for ep_url in list(all_endpoints)[:50]:   # cap to avoid explosion
            resp = await self.client.get(ep_url)
            if resp:
                new_items.append(CrawlResult(
                    url=ep_url, response=resp, depth=0, forms=[], links=[]
                ))
                stats.urls_crawled += 1

        return new_items

    async def _run_openapi_discovery(
        self,
        existing_urls: Set[str],
        stats: ScanStats,
    ) -> List[CrawlResult]:
        """
        Phase 4 — Discover OpenAPI/Swagger specs and convert endpoints
        to scannable CrawlResult items.
        """
        parser = OpenAPIParser(
            client=self.client,
            base_url=self.target.base_url,
        )
        specs = await parser.discover_and_parse()
        self._api_specs.extend(specs)

        if not specs:
            self._log(f"  {DIM}No OpenAPI/Swagger specs found{RESET_COLOR}")
            return []

        for spec in specs:
            self._log(
                f"  {GREEN}✓ Found spec: {spec.title or spec.spec_version} "
                f"({spec.endpoint_count} endpoints) @ {spec.spec_url}{RESET_COLOR}"
            )
            # Log unauthenticated endpoints as informational finding
            unauth = spec.unauthenticated_endpoints
            if unauth:
                self._log(
                    f"    {YELLOW}→ {len(unauth)} endpoints have no auth requirement{RESET_COLOR}"
                )

        # Convert spec endpoints to CrawlResult items
        new_items: List[CrawlResult] = []
        fallback_base = self.target.base_url

        for spec in specs:
            for method, concrete_url in spec.all_concrete_urls(fallback_base):
                norm = normalize_url(concrete_url)
                if norm in existing_urls:
                    continue
                existing_urls.add(norm)

                # Use the method defined in the spec
                if method == "GET":
                    resp = await self.client.get(concrete_url)
                else:
                    resp = await self.client.request(method, concrete_url)

                if resp:
                    new_items.append(CrawlResult(
                        url=norm, response=resp, depth=0, forms=[], links=[]
                    ))
                    stats.urls_crawled += 1

        total_endpoints = sum(s.endpoint_count for s in specs)
        self._log(
            f"\n  {GREEN}✓ OpenAPI: {len(specs)} spec(s), "
            f"{total_endpoints} total endpoints, "
            f"{len(new_items)} new testable URLs{RESET_COLOR}"
        )
        return new_items

    async def _run_api_wordlist_probe(
        self,
        existing_urls: Set[str],
        stats: ScanStats,
    ) -> List[CrawlResult]:
        """Phase 5 — Probe common API paths from the built-in wordlist."""
        # Re-use the Crawler's probe method via a temporary instance
        tmp_crawler = Crawler(self.client, self.target, max_pages=0)
        probe_urls = await tmp_crawler.probe_api_endpoints()

        new_items: List[CrawlResult] = []
        for api_url in probe_urls:
            norm = normalize_url(api_url)
            if norm in existing_urls:
                continue
            existing_urls.add(norm)
            resp = await self.client.get(api_url)
            if resp:
                new_items.append(CrawlResult(
                    url=norm, response=resp, depth=0, forms=[], links=[]
                ))
                stats.urls_crawled += 1

        self._log(
            f"  {GREEN}✓ Wordlist probe: {len(new_items)} new endpoints{RESET_COLOR}"
        )
        return new_items

    # ── Phase 2.2: Passive Import ─────────────────────────────────────────────

    async def _run_passive_import(self, stats: ScanStats) -> List[Any]:
        """
        Phase 6 — Load HAR / Burp XML traffic and return ReplayCrawlItem list.
        These items are compatible with the scanner pipeline.
        """
        scope_host = None
        try:
            from urllib.parse import urlparse
            scope_host = urlparse(self.target.url).netloc
        except Exception:
            pass

        analyzer = PassiveAnalyzer(
            client=self.client,
            scope_host=scope_host,
        )

        items: List[Any] = []

        if self.import_har:
            try:
                har_items = await analyzer.load_har(self.import_har)
                items.extend(har_items)
                self._log(
                    f"  {GREEN}✓ HAR import: {len(har_items)} requests loaded{RESET_COLOR}"
                )
            except Exception as e:
                self._log(f"  {YELLOW}[!] HAR import failed: {e}{RESET_COLOR}")

        if self.import_burp:
            try:
                burp_items = await analyzer.load_burp(self.import_burp)
                items.extend(burp_items)
                self._log(
                    f"  {GREEN}✓ Burp import: {len(burp_items)} requests loaded{RESET_COLOR}"
                )
            except Exception as e:
                self._log(f"  {YELLOW}[!] Burp import failed: {e}{RESET_COLOR}")

        self._passive_items_loaded = len(items)
        if items:
            stats.urls_crawled += len(items)
            self._log(
                f"  {GREEN}✓ Passive import total: {len(items)} items ready for scanning{RESET_COLOR}"
            )

        return items

    # =========================================================================
    # Per-URL & target-level scanning
    # =========================================================================

    async def _scan_crawl_result(
        self,
        cr: Any,
        result: ScanResult,
        stats: ScanStats,
    ) -> None:
        """
        Run all applicable (non-target-level) scanners on one crawled item.
        Compatible with both CrawlResult and ReplayCrawlItem.

        Fix 2.1: increments parameters_tested counter (Fix 2.5).
        Fix 2.1: Phase 4 engines are available via self.baseline_engine,
                 self.confidence_engine, self.timing_analyzer — scanners
                 that need them import and use them directly, OR engine.py
                 pre-warms baselines here for URL params.
        """
        # Fix 2.5: count injectable parameters for coverage metric
        try:
            from urllib.parse import parse_qs, urlparse
            params = parse_qs(urlparse(cr.url).query)
            stats.parameters_tested += len(params)
            # Also count form inputs
            for form in (cr.forms or []):
                stats.parameters_tested += len([
                    i for i in form.get("inputs", [])
                    if i.get("type") not in ("submit", "button", "image", "hidden", "reset")
                ])
        except Exception:
            pass

        for scanner in self.scanners:
            if scanner.is_target_level:
                continue
            try:
                vulns = await scanner.scan_url(cr.url, cr.response, cr.forms)
                for vuln in vulns:
                    result.add_vulnerability(vuln)
                    self._report_finding(vuln)
            except Exception as e:
                stats.errors += 1
                if self.verbose:
                    self._log(
                        f"  {DIM}[!] Scanner {scanner.name} error "
                        f"on {cr.url}: {e}{RESET_COLOR}"
                    )

    async def _run_target_level_scanners(
        self,
        result: ScanResult,
        stats: ScanStats,
        ws_urls: Optional[List[str]] = None,
    ) -> None:
        """
        Run scanners that operate on the target as a whole.
        Also runs the WebSocket scanner if WS endpoints were discovered,
        and Asset Discovery if enabled.
        """
        response = await self.client.get(self.target.url)
        if not response:
            self._log(f"  {YELLOW}[!] Could not fetch root URL for target-level checks{RESET_COLOR}")
            return

        for scanner in self.scanners:
            if not scanner.is_target_level:
                continue
            try:
                vulns = await scanner.scan_url(self.target.url, response, [])
                for vuln in vulns:
                    result.add_vulnerability(vuln)
                    self._report_finding(vuln)
            except Exception as e:
                stats.errors += 1
                if self.verbose:
                    self._log(
                        f"  {DIM}[!] Target scanner {scanner.name} error: {e}{RESET_COLOR}"
                    )

        # WebSocket scanner — runs only if WS URLs were found
        if ws_urls and _WS_SCANNER_AVAILABLE and WebSocketScanner is not None:
            unique_ws = list(dict.fromkeys(ws_urls))
            self._log(
                f"\n  {MAGENTA}[WS] Testing {len(unique_ws)} WebSocket endpoint(s)...{RESET_COLOR}"
            )
            ws_scanner = WebSocketScanner(self.client)
            try:
                ws_vulns = await ws_scanner.scan_websocket_urls(
                    ws_urls=unique_ws,
                    origin_url=self.target.url,
                )
                for vuln in ws_vulns:
                    result.add_vulnerability(vuln)
                    self._report_finding(vuln)
                if ws_vulns:
                    self._log(
                        f"  {YELLOW}→ {len(ws_vulns)} WebSocket finding(s){RESET_COLOR}"
                    )
            except Exception as e:
                stats.errors += 1
                if self.verbose:
                    self._log(f"  {DIM}[!] WebSocket scanner error: {e}{RESET_COLOR}")

        # Asset Discovery — Phase 2.4 (runs when explicitly enabled)
        if self.run_asset_discovery and _ASSET_DISCOVERY_AVAILABLE and AssetDiscovery is not None:
            self._log(f"\n  {CYAN}[Recon] Running asset discovery...{RESET_COLOR}")
            asset_scanner = AssetDiscovery(self.client)
            try:
                asset_vulns = await asset_scanner.scan_url(self.target.url, response, [])
                for vuln in asset_vulns:
                    result.add_vulnerability(vuln)
                    self._report_finding(vuln)

                report = asset_scanner.last_report
                if report:
                    result.metadata["asset_discovery"] = report.to_dict()
                    alive_count = len([s for s in report.subdomains if s.is_alive])
                    self._log(
                        f"  {GREEN}✓ Asset discovery: "
                        f"{alive_count} live subdomains, "
                        f"{len(report.dev_environments)} dev environments, "
                        f"{len(report.takeover_candidates)} takeover candidates"
                        f"{RESET_COLOR}"
                    )
            except Exception as e:
                stats.errors += 1
                if self.verbose:
                    self._log(f"  {DIM}[!] Asset discovery error: {e}{RESET_COLOR}")

    # =========================================================================
    # Output helpers
    # =========================================================================

    async def _run_auth_engine(self, result: ScanResult) -> None:
        """
        Phase 3.1 — Run AuthEngine to obtain authenticated sessions.
        Injects sessions into AuthorizationMatrixScanner if enabled.
        """
        if not _AUTH_ENGINE_AVAILABLE or AuthEngine is None:
            self._log(f"  {DIM}[!] AuthEngine unavailable (playwright not installed){RESET_COLOR}")
            return

        try:
            engine = AuthEngine(self.auth_config)
            self._log(
                f"  Logging in as '{self.auth_config.username}' "
                f"(+ {len(self.auth_config.extra_users)} extra user(s))..."
            )
            sessions = await engine.login_all_users()
            self._auth_sessions = sessions

            successful = [s for s in sessions if s.success]
            failed     = [s for s in sessions if not s.success]

            for s in successful:
                self._log(
                    f"  {GREEN}✓ Login OK{RESET_COLOR} — "
                    f"{s.username} (role={s.role}) "
                    f"{'[JWT extracted]' if s.auth_token else '[cookies only]'}"
                )
            for s in failed:
                self._log(
                    f"  {DIM}[!] Login FAILED for {s.username}: {s.error}{RESET_COLOR}"
                )

            if not successful:
                self._log(f"  {DIM}[!] All logins failed — skipping authz matrix{RESET_COLOR}")
                return

            # ── Inject sessions into AuthorizationMatrixScanner ──────────
            if self.run_authz_matrix:
                from ..scanners.authz_matrix import AuthorizationMatrixScanner
                for scanner in self.scanners:
                    if isinstance(scanner, AuthorizationMatrixScanner):
                        scanner.set_sessions(successful)
                        scanner.set_urls(result.crawled_urls or [self.target.url])
                        self._log(
                            f"  {GREEN}✓ AuthorizationMatrix ready — "
                            f"{len(successful)} role(s) × "
                            f"{len(result.crawled_urls)} endpoints{RESET_COLOR}"
                        )
                        break

            result.metadata["auth_sessions"] = [
                {"username": s.username, "role": s.role, "success": s.success}
                for s in sessions
            ]

        except Exception as e:
            self._log(f"  {DIM}[!] Auth engine error: {e}{RESET_COLOR}")

    async def _run_intelligence_layer(
        self, crawl_items: List[Any], result: ScanResult
    ) -> None:
        """
        Phase 2 roadmap — Intelligence & Discovery Layer.

        Runs Phase2MasterOrchestrator (Fingerprinting → Passive Intelligence
        → Knowledge Base → Discovery Infrastructure [endpoint classification,
        parameter intelligence, context-aware payloads, encoding, triple
        confirmation, evidence collection, evidence graph, attack chains,
        multi-account] → Authentication Framework → Authorization Framework
        → Adaptive Rate Controller → Session Management) via PhaseCoordinator,
        then injects the resulting ScannerIntelligenceContext into every
        IntelligenceAwareScanner instance in ``self.scanners`` *before*
        Phase 7 runs, so payload selection / encoding / skip decisions are
        tech-aware for the rest of the scan.

        Also runs the API Discovery Engine, GraphQL Framework and WebSocket
        Framework, which are not covered by Phase2MasterOrchestrator.
        """
        crawled_urls = [cr.url for cr in crawl_items]
        try:
            self._phase_coordinator = PhaseCoordinator(self.client, self.target)
            self._intelligence_plan = await self._phase_coordinator.prepare(
                crawled_urls=crawled_urls,
                engine_scanners=self.scanners,
            )
            ctx = self._intelligence_plan.context
            tech = getattr(ctx, "tech_profile", None)
            tech_desc = ""
            if tech is not None:
                parts = [
                    getattr(tech, "web_server", None),
                    getattr(tech, "framework", None),
                    getattr(tech, "database", None),
                ]
                tech_desc = ", ".join(p for p in parts if p) or "unknown"
            upgraded = sum(1 for s in self.scanners if hasattr(s, "set_context"))
            self._log(
                f"  {GREEN}✓ Phase 2 intelligence ready{RESET_COLOR} — "
                f"tech: {tech_desc or 'unknown'} | "
                f"{self._intelligence_plan.total_urls} URL(s) planned | "
                f"{upgraded} scanner(s) context-aware"
            )
        except Exception as e:
            self._log(f"  {DIM}[!] Intelligence layer error: {e}{RESET_COLOR}")

        # ── API Discovery Engine (not covered by Phase2MasterOrchestrator) ──
        if _API_DISCOVERY_AVAILABLE and APIDiscoveryEngine is not None:
            try:
                api_engine = APIDiscoveryEngine(
                    self.client, self.target, crawled_urls=crawled_urls,
                )
                self._api_discovery_report = await api_engine.discover()
                if self._api_discovery_report is not None:
                    result.metadata["api_discovery"] = _safe_serialize(
                        self._api_discovery_report
                    )
            except Exception as e:
                self._log(f"  {DIM}[!] API discovery engine error: {e}{RESET_COLOR}")

        # ── GraphQL Framework (only if a GraphQL-looking endpoint exists) ───
        graphql_hint = any("graphql" in u.lower() for u in crawled_urls)
        if _GRAPHQL_FRAMEWORK_AVAILABLE and GraphQLFramework is not None and graphql_hint:
            try:
                gql = GraphQLFramework(self.client, self.target)
                self._graphql_report = await gql.run()
                if self._graphql_report:
                    result.metadata["graphql_framework"] = _safe_serialize(
                        self._graphql_report
                    )
            except Exception as e:
                self._log(f"  {DIM}[!] GraphQL framework error: {e}{RESET_COLOR}")

        # ── WebSocket Framework (only if WS endpoints were discovered) ──────
        ws_candidates = [u for u in crawled_urls if u.startswith(("ws://", "wss://"))]
        if _WS_FRAMEWORK_AVAILABLE and run_websocket_framework is not None and ws_candidates:
            try:
                self._websocket_report = await run_websocket_framework(
                    self.client, self.target, extra_urls=ws_candidates,
                )
                if self._websocket_report is not None:
                    result.metadata["websocket_framework"] = _safe_serialize(
                        self._websocket_report
                    )
            except Exception as e:
                self._log(f"  {DIM}[!] WebSocket framework error: {e}{RESET_COLOR}")

    def _report_finding(self, vuln: Vulnerability) -> None:
        if not self.verbose:
            return
        color = severity_color(vuln.severity.value)
        score = f"CVSS:{vuln.cvss_score():.1f}" if vuln.cvss_score() is not None else ""
        print(
            f"  {color}[{vuln.severity.value:8s}]{RESET_COLOR} "
            f"{BOLD}{vuln.title}{RESET_COLOR} "
            f"{DIM}@ {vuln.url[:60]}{'...' if len(vuln.url) > 60 else ''}"
            f"{' ' + score if score else ''}{RESET_COLOR}"
        )

    def _print_summary(self, result: ScanResult) -> None:
        counts = result.severity_counts()
        total = len(result.vulnerabilities)
        risk = result.risk_score()

        self._log(f"\n{BOLD}{CYAN}{'═'*62}{RESET_COLOR}")
        self._log(f"{BOLD}  Scan Complete — Risk Score: {risk:.1f}/10{RESET_COLOR}")
        self._log(f"{BOLD}{CYAN}{'═'*62}{RESET_COLOR}")
        self._log(f"  Total findings:  {total}")
        for sev, count in counts.items():
            if count:
                color = severity_color(sev)
                self._log(f"    {color}{sev:10s}{RESET_COLOR}: {count}")
        self._log(f"  URLs crawled:    {result.stats.urls_crawled}")
        self._log(f"  Requests sent:   {result.stats.requests_sent}")
        self._log(f"  Duration:        {result.stats.duration_seconds:.1f}s")
        if self._api_specs:
            total_ep = sum(s.endpoint_count for s in self._api_specs)
            self._log(f"  OpenAPI specs:   {len(self._api_specs)} ({total_ep} endpoints)")
        if result.metadata.get("websocket_urls_found"):
            self._log(f"  WebSocket URLs:  {result.metadata['websocket_urls_found']}")
        if result.metadata.get("passive_items_loaded"):
            self._log(f"  Passive import:  {result.metadata['passive_items_loaded']} requests")
        if result.metadata.get("asset_discovery"):
            ad = result.metadata["asset_discovery"]
            self._log(f"  Subdomains:      {ad.get('subdomains_alive', 0)} alive")
        if result.metadata.get("phase2_intelligence"):
            plan = result.metadata["phase2_intelligence"]
            self._log(
                f"  Intelligence:    {plan.get('total_urls', 0)} URL(s) planned, "
                f"{plan.get('high_priority', 0)} high-priority"
            )
        corr = result.metadata.get("correlation")
        if corr and corr.get("chain_count"):
            self._log(
                f"  Attack chains:   {corr['chain_count']} "
                f"({corr.get('confirmed_chain_count', 0)} confirmed)"
            )
        ra = result.metadata.get("risk_analysis")
        if ra:
            self._log(
                f"  Contextual risk: {ra.get('aggregate_risk', 0.0):.1f}/10 "
                f"({ra.get('aggregate_level', 'Info')})"
            )
        comp = result.metadata.get("compliance")
        if comp and comp.get("summary"):
            self._log(f"  Compliance:      {len(comp['summary'])} standard(s) impacted")
        self._log(f"{BOLD}{CYAN}{'═'*62}{RESET_COLOR}\n")
