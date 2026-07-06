"""
Advanced web crawler with:
- Form discovery and parameter extraction
- API endpoint discovery
- Sitemap and robots.txt parsing
- JavaScript href/src extraction hints
- Configurable depth and scope control
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from .http_client import HTTPClient, HTTPResponse
from .target import ScanTarget
from ..utils.helpers import (
    is_in_scope, normalize_url, build_url, fingerprint_hash, is_binary_content
)


# Patterns to find URLs in JavaScript
JS_URL_PATTERNS = [
    re.compile(r"""(?:href|src|action|url|URL|endpoint|api)\s*[=:]\s*['"]([^'"]{4,200})['"]"""),
    re.compile(r"""fetch\(['"]([^'"]+)['"]\)"""),
    re.compile(r"""axios\.\w+\(['"]([^'"]+)['"]\)"""),
    re.compile(r"""(?:get|post|put|delete|patch)\(['"]([^'"]{4,200})['"]"""),
    re.compile(r"""/api/[a-zA-Z0-9_/\-]{2,50}"""),
    re.compile(r"""/v\d+/[a-zA-Z0-9_/\-]{2,50}"""),
]

# Common API endpoint wordlist
API_WORDLIST = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/admin",
    "/api/auth", "/api/login", "/api/logout",
    "/api/products", "/api/orders", "/api/items",
    "/api/search", "/api/config", "/api/health",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger-ui.html", "/.well-known/openapi.yaml",
    "/graphql", "/graphiql", "/playground",
    "/rest/v1", "/rest/api",
    "/wp-json/wp/v2",
    "/admin", "/dashboard", "/login", "/register",
    "/forgot-password", "/reset-password",
    "/profile", "/account", "/settings",
    "/upload", "/uploads", "/files", "/download",
    "/backup", "/config", "/debug", "/test",
    "/health", "/status", "/metrics", "/info",
    "/.env", "/.git/config", "/web.config",
    "/phpinfo.php", "/info.php", "/test.php",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/favicon.ico", "/.well-known/security.txt",
]


class CrawlResult:
    """Represents a crawled page with all extracted data."""

    def __init__(
        self,
        url: str,
        response: HTTPResponse,
        depth: int,
        forms: Optional[List[Dict[str, Any]]] = None,
        links: Optional[List[str]] = None,
        scripts: Optional[List[str]] = None,
    ) -> None:
        self.url = url
        self.response = response
        self.depth = depth
        self.forms: List[Dict[str, Any]] = forms or []
        self.links: List[str] = links or []
        self.scripts: List[str] = scripts or []
        self.params: Dict[str, List[str]] = parse_qs(urlparse(url).query)


class Crawler:
    """
    BFS-based web crawler with form extraction, JS analysis,
    and API endpoint probing.
    """

    def __init__(
        self,
        client: HTTPClient,
        target: ScanTarget,
        max_pages: int = 200,
    ) -> None:
        self.client = client
        self.target = target
        self.max_pages = max_pages
        self._visited_hashes: Set[str] = set()
        self._discovered_urls: Set[str] = set()
        self._forms: List[Dict[str, Any]] = []
        self._api_endpoints: List[str] = []

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        """
        Concurrent BFS crawl yielding CrawlResult for each discovered page.
        Uses a semaphore-controlled batch approach for real parallelism.
        """
        queue: deque[Tuple[str, int]] = deque()
        queue.append((self.target.url, 0))
        self._discovered_urls.add(self.target.url)

        # Start with robots/sitemap — run AFTER queue init so base URL isn't pre-marked
        await self._process_robots_txt()
        await self._process_sitemap()

        # Add any URLs discovered from robots/sitemap into the queue
        for extra_url in list(self._discovered_urls):
            if extra_url != self.target.url and not self.target.is_visited(extra_url):
                queue.append((extra_url, 1))

        semaphore = asyncio.Semaphore(10)  # 10 concurrent fetches

        async def fetch_one(url: str, depth: int) -> Optional[CrawlResult]:
            async with semaphore:
                # Fix 1.5: use try_mark_visited for atomic check-and-mark
                # eliminates TOCTOU gap where two coroutines could both pass
                # the is_visited() check before either calls mark_visited().
                if not self.target.try_mark_visited(url):
                    return None
                if not self.target.is_in_scope(url):
                    return None

                response = await self.client.get(url)
                if response is None:
                    return None

                # Accept text responses only — but always yield root page even if odd content type
                if not response.is_text and depth > 0:
                    return None

                forms, links, scripts = await self._parse_page(url, response.text)
                self._forms.extend(forms)
                return CrawlResult(
                    url=url,
                    response=response,
                    depth=depth,
                    forms=forms,
                    links=links,
                    scripts=scripts,
                )

        while queue:
            if len(self._discovered_urls) >= self.max_pages:
                break

            # Pull a batch from the current BFS level
            batch: List[Tuple[str, int]] = []
            current_depth = queue[0][1] if queue else 0

            while queue and queue[0][1] == current_depth and len(batch) < 20:
                url, depth = queue.popleft()
                if depth > self.target.max_depth:
                    continue
                if not self.target.is_visited(url):
                    batch.append((url, depth))

            if not batch:
                # Drain remaining items from deeper levels
                while queue:
                    url, depth = queue.popleft()
                    if depth <= self.target.max_depth and not self.target.is_visited(url):
                        batch.append((url, depth))
                        break
                if not batch:
                    break

            # Fetch batch concurrently
            tasks = [fetch_one(url, depth) for url, depth in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if not isinstance(result, CrawlResult):
                    continue

                yield result

                # Enqueue discovered links for next BFS level
                for link in result.links:
                    if (link not in self._discovered_urls and
                            self.target.is_in_scope(link) and
                            len(self._discovered_urls) < self.max_pages):
                        self._discovered_urls.add(link)
                        queue.append((link, result.depth + 1))

    async def _parse_page(
        self, base_url: str, html: str
    ) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
        """Extract forms, links, and scripts from HTML."""
        forms: List[Dict[str, Any]] = []
        links: List[str] = []
        scripts: List[str] = []

        try:
            soup = BeautifulSoup(html, "html.parser")

            # Extract all <a href>
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    full_url = urljoin(base_url, href)
                    full_url = normalize_url(full_url)
                    links.append(full_url)

            # Extract forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                full_action = urljoin(base_url, action) if action else base_url
                full_action = normalize_url(full_action)

                inputs: List[Dict[str, str]] = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    inp_type = inp.get("type", "text").lower()
                    value = inp.get("value", "")
                    if name:
                        inputs.append({
                            "name": name,
                            "type": inp_type,
                            "value": value,
                        })

                if inputs:  # Only track forms with parameters
                    form_data: Dict[str, Any] = {
                        "action": full_action,
                        "method": method,
                        "inputs": inputs,
                        "source_url": base_url,
                        "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
                    }
                    forms.append(form_data)
                    # Also add form action to link queue
                    if full_action not in links:
                        links.append(full_action)

            # Extract src/href from script, link, img
            for tag in soup.find_all(["script", "link", "img", "iframe"]):
                src = tag.get("src") or tag.get("href")
                if src:
                    full = urljoin(base_url, src)
                    if full.endswith(".js"):
                        scripts.append(full)
                    else:
                        links.append(normalize_url(full))

            # Extract from JavaScript inline code
            for script_tag in soup.find_all("script"):
                js_content = script_tag.string or ""
                if js_content:
                    extracted = self._extract_urls_from_js(js_content, base_url)
                    links.extend(extracted)

            # Extract from data-* attributes (SPA patterns)
            for tag in soup.find_all(True):
                for attr_name, attr_val in tag.attrs.items():
                    if attr_name.startswith("data-url") or attr_name in ("data-href", "data-src"):
                        if isinstance(attr_val, str) and attr_val.startswith("/"):
                            links.append(urljoin(base_url, attr_val))

        except Exception:
            pass

        # Deduplicate
        links = list(dict.fromkeys(links))
        return forms, links, scripts

    def _extract_urls_from_js(self, js_content: str, base_url: str) -> List[str]:
        """Extract URLs from JavaScript code using heuristic patterns."""
        found: List[str] = []
        for pattern in JS_URL_PATTERNS:
            for match in pattern.findall(js_content):
                match = match.strip()
                if match.startswith("/") or match.startswith("http"):
                    full = urljoin(base_url, match)
                    if self.target.is_in_scope(full):
                        found.append(normalize_url(full))
        return found

    async def _process_robots_txt(self) -> None:
        """Parse robots.txt to discover additional paths — does NOT mark any URL as visited."""
        robots_url = f"{self.target.base_url}/robots.txt"
        try:
            response = await self.client.get(robots_url)
            if response and response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("allow:", "disallow:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and path != "/" and "*" not in path:
                                full_url = urljoin(self.target.base_url, path)
                                if self.target.is_in_scope(full_url):
                                    norm = normalize_url(full_url)
                                    # Only add to discovered — never mark_visited here
                                    self._discovered_urls.add(norm)
                    elif line.lower().startswith("sitemap:"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            sitemap_url = parts[1].strip()
                            await self._parse_sitemap_url(sitemap_url)
        except Exception:
            pass

    async def _process_sitemap(self) -> None:
        """Parse sitemap.xml to discover pages."""
        await self._parse_sitemap_url(f"{self.target.base_url}/sitemap.xml")

    async def _parse_sitemap_url(self, sitemap_url: str) -> None:
        """Recursively parse a sitemap or sitemap index."""
        try:
            response = await self.client.get(sitemap_url)
            if not response or response.status_code != 200:
                return
            soup = BeautifulSoup(response.text, "xml")
            # Sitemap index
            for loc in soup.find_all("sitemap"):
                loc_tag = loc.find("loc")
                if loc_tag and loc_tag.string:
                    await self._parse_sitemap_url(loc_tag.string.strip())
            # Regular sitemap
            for loc in soup.find_all("loc"):
                url = loc.string.strip() if loc.string else ""
                if url and self.target.is_in_scope(url):
                    self._discovered_urls.add(normalize_url(url))
        except Exception:
            pass

    async def probe_api_endpoints(self) -> List[str]:
        """Probe common API and admin endpoints."""
        found: List[str] = []
        tasks = []
        semaphore = asyncio.Semaphore(10)

        async def probe(path: str) -> None:
            async with semaphore:
                url = urljoin(self.target.base_url, path)
                response = await self.client.head(url)
                if response and response.status_code not in (404, 403):
                    found.append(url)
                    self._api_endpoints.append(url)

        for path in API_WORDLIST:
            tasks.append(probe(path))

        await asyncio.gather(*tasks, return_exceptions=True)
        return found

    @property
    def discovered_forms(self) -> List[Dict[str, Any]]:
        return self._forms

    @property
    def discovered_endpoints(self) -> List[str]:
        return self._api_endpoints

    @property
    def all_discovered_urls(self) -> List[str]:
        return list(self._discovered_urls)
