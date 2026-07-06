"""
Headless Browser Engine — Playwright-based dynamic crawler.

Replaces static HTML parsing for modern SPAs (React, Angular, Vue).
Intercepts all network requests to discover real API endpoints, WebSocket
connections, and JavaScript-rendered routes that a static crawler misses.
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
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from .target import ScanTarget
from ..utils.helpers import normalize_url, get_base_url

# ---------------------------------------------------------------------------
# Playwright is an optional dependency — degrade gracefully if not installed
# ---------------------------------------------------------------------------
try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Request as PlaywrightRequest,
        Response as PlaywrightResponse,
        WebSocket as PlaywrightWebSocket,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class InterceptedRequest:
    """A single network request captured by the browser."""
    url: str
    method: str
    resource_type: str          # "fetch", "xhr", "document", "websocket" …
    headers: Dict[str, str]
    post_data: Optional[str]    # raw POST body if present
    is_websocket: bool = False

    @property
    def is_api_call(self) -> bool:
        return self.resource_type in ("fetch", "xhr")

    @property
    def parsed_post_json(self) -> Optional[Any]:
        if not self.post_data:
            return None
        try:
            return json.loads(self.post_data)
        except Exception:
            return None


@dataclass
class BrowserCrawlResult:
    """
    Everything the browser engine discovered on a single page visit.
    Designed to be compatible with the static CrawlResult interface so the
    engine can treat both uniformly.
    """
    url: str
    html: str
    depth: int
    status_code: int = 200
    # Discovered endpoints from network interception
    api_calls: List[InterceptedRequest] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)
    # Links discovered in the rendered DOM
    links: List[str] = field(default_factory=list)
    # Forms extracted from the rendered DOM
    forms: List[Dict[str, Any]] = field(default_factory=list)
    # Screenshot (PNG bytes) — None if disabled
    screenshot: Optional[bytes] = None
    # All unique endpoints (API + links + WS) for easy iteration
    discovered_endpoints: List[str] = field(default_factory=list)
    # JS files loaded by this page
    script_urls: List[str] = field(default_factory=list)
    # Page title
    title: str = ""
    # Console errors captured
    console_errors: List[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        """Alias so engine code can treat this like an HTTPResponse."""
        return self.html

    def all_unique_api_urls(self) -> List[str]:
        return list({r.url for r in self.api_calls})


# ---------------------------------------------------------------------------
# Browser Engine
# ---------------------------------------------------------------------------

class BrowserEngine:
    """
    Playwright-based headless browser engine.

    - Opens pages with a real Chromium instance
    - Intercepts every network request (XHR, fetch, WebSocket)
    - Waits for JS to finish rendering before extracting DOM
    - Discovers SPA routes by watching pushState/replaceState calls
    - Takes optional screenshots for the HTML report
    """

    # Resource types we care about for API discovery
    _API_RESOURCE_TYPES = {"fetch", "xhr"}
    # Resource types to skip entirely (no value for security testing)
    _SKIP_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}
    # Max milliseconds to wait for page to settle after load
    _NETWORK_IDLE_TIMEOUT = 8_000
    _PAGE_LOAD_TIMEOUT    = 30_000

    def __init__(
        self,
        target: ScanTarget,
        headless: bool = True,
        screenshots: bool = True,
        auth_token: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        max_pages: int = 100,
        max_depth: int = 3,
        viewport_width: int = 1280,
        viewport_height: int = 800,
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
    ) -> None:
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright is not installed.\n"
                "Run: pip install playwright==1.44.0 && playwright install chromium"
            )

        self.target = target
        self.headless = headless
        self.screenshots = screenshots
        self.auth_token = auth_token
        self.cookies = cookies or {}
        self.custom_headers = custom_headers or {}
        self.proxy = proxy
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.user_agent = user_agent

        # Internal state
        self._visited: Set[str] = set()
        self._discovered_urls: Set[str] = set()
        self._all_api_calls: List[InterceptedRequest] = []
        self._all_websockets: List[str] = []
        self._spa_routes: Set[str] = set()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def crawl(self) -> AsyncIterator[BrowserCrawlResult]:
        """
        Crawl the target using a real browser.
        Yields BrowserCrawlResult for each page visited.
        """
        async with async_playwright() as pw:
            browser = await self._launch_browser(pw)
            try:
                context = await self._create_context(browser)
                try:
                    # Inject auth headers globally on the context
                    if self.auth_token or self.custom_headers:
                        extra_headers = dict(self.custom_headers)
                        if self.auth_token:
                            extra_headers["Authorization"] = f"Bearer {self.auth_token}"
                        await context.set_extra_http_headers(extra_headers)

                    # BFS crawl
                    queue: List[Tuple[str, int]] = [(self.target.url, 0)]
                    self._discovered_urls.add(self.target.url)

                    while queue and len(self._visited) < self.max_pages:
                        url, depth = queue.pop(0)

                        if url in self._visited:
                            continue
                        if not self.target.is_in_scope(url):
                            continue
                        if depth > self.max_depth:
                            continue

                        self._visited.add(url)

                        result = await self._visit_page(context, url, depth)
                        if result is None:
                            continue

                        yield result

                        # Enqueue discovered links
                        for link in result.links:
                            norm = normalize_url(link)
                            if (norm not in self._visited and
                                    norm not in self._discovered_urls and
                                    self.target.is_in_scope(norm) and
                                    len(self._discovered_urls) < self.max_pages):
                                self._discovered_urls.add(norm)
                                queue.append((norm, depth + 1))

                        # Enqueue SPA routes discovered via pushState
                        for spa_url in list(self._spa_routes):
                            norm = normalize_url(spa_url)
                            if (norm not in self._visited and
                                    norm not in self._discovered_urls and
                                    self.target.is_in_scope(norm)):
                                self._discovered_urls.add(norm)
                                queue.append((norm, depth + 1))
                        self._spa_routes.clear()

                finally:
                    await context.close()
            finally:
                await browser.close()

    @property
    def all_api_calls(self) -> List[InterceptedRequest]:
        return self._all_api_calls

    @property
    def all_websocket_urls(self) -> List[str]:
        return list(set(self._all_websockets))

    @property
    def all_visited_urls(self) -> List[str]:
        return list(self._visited)

    # -----------------------------------------------------------------------
    # Browser setup
    # -----------------------------------------------------------------------

    async def _launch_browser(self, pw: Any) -> "Browser":
        launch_kwargs: Dict[str, Any] = {
            "headless": self.headless,
            "args": [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {
                "server": self.proxy,
                "bypass": "localhost,127.0.0.1",
            }
        return await pw.chromium.launch(**launch_kwargs)

    async def _create_context(self, browser: "Browser") -> "BrowserContext":
        context = await browser.new_context(
            viewport={"width": self.viewport_width, "height": self.viewport_height},
            user_agent=self.user_agent,
            ignore_https_errors=True,   # same as verify_ssl=False in httpx
            java_script_enabled=True,
            # Prevent detection as headless
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        # Inject session cookies
        if self.cookies:
            playwright_cookies = [
                {
                    "name": k,
                    "value": v,
                    "url": self.target.base_url,
                }
                for k, v in self.cookies.items()
            ]
            await context.add_cookies(playwright_cookies)

        return context

    # -----------------------------------------------------------------------
    # Page visit
    # -----------------------------------------------------------------------

    async def _visit_page(
        self,
        context: "BrowserContext",
        url: str,
        depth: int,
    ) -> Optional[BrowserCrawlResult]:
        """Visit a single URL, intercept requests, extract DOM data."""
        page = await context.new_page()

        # Accumulators for this page
        page_api_calls: List[InterceptedRequest] = []
        page_ws_urls: List[str] = []
        console_errors: List[str] = []
        status_code: int = 200

        # ── Event listeners ─────────────────────────────────────────────────

        # Intercept network requests
        async def on_request(req: "PlaywrightRequest") -> None:
            rtype = req.resource_type
            if rtype in self._SKIP_RESOURCE_TYPES:
                return
            intercepted = InterceptedRequest(
                url=req.url,
                method=req.method,
                resource_type=rtype,
                headers=dict(req.headers),
                post_data=req.post_data,
                is_websocket=(rtype == "websocket"),
            )
            page_api_calls.append(intercepted)
            if intercepted.is_api_call:
                self._all_api_calls.append(intercepted)

        # Capture HTTP response status for the main document
        async def on_response(resp: "PlaywrightResponse") -> None:
            nonlocal status_code
            if resp.url == url or resp.url.rstrip("/") == url.rstrip("/"):
                status_code = resp.status

        # Capture WebSocket connections
        async def on_websocket(ws: "PlaywrightWebSocket") -> None:
            ws_url = ws.url
            page_ws_urls.append(ws_url)
            self._all_websockets.append(ws_url)

        # Capture console errors (can reveal backend info)
        page.on("console", lambda msg: (
            console_errors.append(msg.text)
            if msg.type == "error" else None
        ))
        page.on("request", on_request)
        page.on("response", on_response)
        page.on("websocket", on_websocket)

        # Intercept navigation via pushState to discover SPA routes
        await page.add_init_script("""
            (function() {
                const push = history.pushState.bind(history);
                const replace = history.replaceState.bind(history);
                function notify(url) {
                    window.__webshield_routes = window.__webshield_routes || [];
                    window.__webshield_routes.push(url);
                }
                history.pushState = function(state, title, url) {
                    if (url) notify(String(url));
                    return push(state, title, url);
                };
                history.replaceState = function(state, title, url) {
                    if (url) notify(String(url));
                    return replace(state, title, url);
                };
            })();
        """)

        try:
            # Navigate and wait for network to idle
            await page.goto(
                url,
                wait_until="networkidle",
                timeout=self._PAGE_LOAD_TIMEOUT,
            )
            # Extra settle time for lazy-loaded components
            await asyncio.sleep(1.5)

            # Collect SPA routes discovered via pushState
            spa_routes_raw: List[str] = await page.evaluate(
                "() => window.__webshield_routes || []"
            )
            for route in spa_routes_raw:
                full = urljoin(url, route)
                if self.target.is_in_scope(full):
                    self._spa_routes.add(normalize_url(full))

            # Extract the fully rendered HTML
            html = await page.content()

            # Extract page title
            title = await page.title()

            # Extract links from rendered DOM
            links = await self._extract_links(page, url)

            # Extract forms from rendered DOM
            forms = await self._extract_forms(page, url)

            # Extract script URLs
            script_urls = await self._extract_script_urls(page, url)

            # Screenshot
            screenshot: Optional[bytes] = None
            if self.screenshots:
                try:
                    screenshot = await page.screenshot(
                        type="png",
                        full_page=False,   # viewport only — faster
                        clip={"x": 0, "y": 0, "width": self.viewport_width, "height": self.viewport_height},
                    )
                except Exception:
                    pass

            # Build result
            result = BrowserCrawlResult(
                url=url,
                html=html,
                depth=depth,
                status_code=status_code,
                api_calls=page_api_calls,
                websocket_urls=page_ws_urls,
                links=links,
                forms=forms,
                screenshot=screenshot,
                script_urls=script_urls,
                title=title,
                console_errors=console_errors[:20],   # cap at 20
            )

            # Aggregate unique discovered endpoints
            result.discovered_endpoints = list({
                r.url for r in page_api_calls if r.is_api_call
            } | set(links) | set(page_ws_urls))

            return result

        except Exception:
            return None
        finally:
            await page.close()

    # -----------------------------------------------------------------------
    # DOM extraction helpers
    # -----------------------------------------------------------------------

    async def _extract_links(self, page: "Page", base_url: str) -> List[str]:
        """Extract all href links from the rendered DOM."""
        try:
            raw_hrefs: List[str] = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h && !h.startsWith('javascript:')
                                   && !h.startsWith('mailto:')
                                   && !h.startsWith('tel:'))
            """)
            links: List[str] = []
            for href in raw_hrefs:
                full = urljoin(base_url, href)
                norm = normalize_url(full)
                if self.target.is_in_scope(norm):
                    links.append(norm)
            return list(dict.fromkeys(links))  # deduplicate, preserve order
        except Exception:
            return []

    async def _extract_forms(self, page: "Page", base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from the rendered DOM including dynamically added ones."""
        try:
            raw_forms: List[Dict[str, Any]] = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action || '',
                    method: (form.method || 'GET').toUpperCase(),
                    enctype: form.enctype || 'application/x-www-form-urlencoded',
                    inputs: Array.from(
                        form.querySelectorAll('input, textarea, select')
                    ).map(inp => ({
                        name: inp.name || '',
                        type: inp.type || 'text',
                        value: inp.value || '',
                        required: inp.required || false,
                    })).filter(i => i.name),
                })).filter(f => f.inputs.length > 0)
            """)
            forms: List[Dict[str, Any]] = []
            for form in raw_forms:
                action = form.get("action", "") or base_url
                full_action = urljoin(base_url, action)
                forms.append({
                    "action": normalize_url(full_action),
                    "method": form.get("method", "GET"),
                    "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
                    "inputs": form.get("inputs", []),
                    "source_url": base_url,
                    "_source": "browser",
                })
            return forms
        except Exception:
            return []

    async def _extract_script_urls(self, page: "Page", base_url: str) -> List[str]:
        """Extract all external script URLs loaded by the page."""
        try:
            raw: List[str] = await page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(s => s && s.startsWith('http'))
            """)
            result: List[str] = []
            for src in raw:
                norm = normalize_url(src)
                # Include scripts from same origin or CDN (don't scope-restrict)
                result.append(norm)
            return list(dict.fromkeys(result))
        except Exception:
            return []
