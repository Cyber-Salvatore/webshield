"""
Advanced HTTP client with session management, proxy support,
user-agent rotation, rate limiting, and retry logic.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from ..utils.helpers import is_binary_content
from ..utils.waf_evasion import WAFEvasionEngine


USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]


class HTTPResponse:
    """Wrapper around httpx.Response with extra metadata."""

    def __init__(self, response: httpx.Response, elapsed: float = 0.0) -> None:
        self._response = response
        self.elapsed = elapsed
        self._text_cache: Optional[str] = None

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> httpx.Headers:
        return self._response.headers

    @property
    def url(self) -> str:
        return str(self._response.url)

    @property
    def content(self) -> bytes:
        return self._response.content

    @property
    def text(self) -> str:
        if self._text_cache is None:
            try:
                self._text_cache = self._response.text
            except Exception:
                self._text_cache = self._response.content.decode("utf-8", errors="replace")
        return self._text_cache

    @property
    def content_type(self) -> str:
        return self._response.headers.get("content-type", "")

    @property
    def is_text(self) -> bool:
        return not is_binary_content(self.content_type)

    @property
    def redirect_url(self) -> Optional[str]:
        location = self._response.headers.get("location")
        if location:
            return location
        return None

    @property
    def cookies(self) -> httpx.Cookies:
        return self._response.cookies

    @property
    def history(self) -> List[httpx.Response]:
        return list(self._response.history)

    def header(self, name: str) -> Optional[str]:
        return self._response.headers.get(name)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "url": self.url,
            "content_type": self.content_type,
            "elapsed": round(self.elapsed, 3),
            "headers": dict(self._response.headers),
        }


class HTTPClient:
    """
    Advanced async HTTP client with:
    - User-agent rotation
    - Proxy support
    - Rate limiting
    - Retry with exponential backoff
    - Session/cookie management
    - Custom headers injection
    - SSL verification control
    """

    def __init__(
        self,
        timeout: float = 15.0,
        connect_timeout: float = 10.0,
        max_retries: int = 2,
        delay: float = 0.0,
        jitter: float = 0.0,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        rotate_ua: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        max_redirects: int = 10,
    ) -> None:
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.max_retries = max_retries
        self.delay = delay
        self.jitter = jitter
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.rotate_ua = rotate_ua
        self.custom_headers = custom_headers or {}
        self.cookies = cookies or {}
        self.auth_token = auth_token
        self.username = username
        self.password = password
        self.max_redirects = max_redirects
        self.request_count: int = 0
        self._client: Optional[httpx.AsyncClient] = None
        self._last_request_time: float = 0.0
        # WAF evasion engine — shared across all requests from this client
        self.waf: WAFEvasionEngine = WAFEvasionEngine()
        self._waf_evasion_active: bool = False  # True once a WAF block is detected
        # Simple GET response cache: url → HTTPResponse (avoids redundant identical GETs)
        self._get_cache: Dict[str, "HTTPResponse"] = {}
        self.cache_enabled: bool = True

    def _build_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
        }
        if self.rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = USER_AGENTS[0]

        headers.update(self.custom_headers)

        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        if extra:
            headers.update(extra)

        return headers

    def _build_auth(self) -> Optional[Tuple[str, str]]:
        if self.username and self.password:
            return (self.username, self.password)
        return None

    def _build_proxies(self) -> Optional[Dict[str, str]]:
        if self.proxy:
            return {"http://": self.proxy, "https://": self.proxy}
        return None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            proxy = self.proxy if self.proxy else None
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=self.connect_timeout),
                verify=self.verify_ssl,
                follow_redirects=True,
                max_redirects=self.max_redirects,
                proxy=proxy,
                cookies=self.cookies,
                auth=self._build_auth(),
            )
        return self._client

    async def _rate_limit(self) -> None:
        """Enforce delay + jitter between requests."""
        if self.delay > 0 or self.jitter > 0:
            elapsed = time.monotonic() - self._last_request_time
            wait = self.delay + random.uniform(0, self.jitter)
            remaining = wait - elapsed
            if remaining > 0:
                await asyncio.sleep(remaining)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        content: Optional[bytes] = None,
        allow_redirects: bool = True,
    ) -> Optional[HTTPResponse]:
        """
        Send an HTTP request with retry logic and automatic WAF evasion.
        On first block detection the engine switches to evasion mode for
        all subsequent requests in this session.
        Returns HTTPResponse or None on failure.
        """
        await self._rate_limit()
        client = await self._get_client()

        # Merge base headers + caller headers + WAF evasion headers (if active)
        req_headers = self._build_headers(headers)
        if self._waf_evasion_active:
            req_headers.update(self.waf.get_waf_specific_headers())

        last_exc: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                self._last_request_time = time.monotonic()
                start = time.monotonic()
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers,
                    params=params,
                    data=data,
                    json=json,
                    content=content,
                    follow_redirects=allow_redirects,
                )
                elapsed = time.monotonic() - start
                self.request_count += 1
                http_resp = HTTPResponse(response, elapsed)

                # ── WAF detection + adaptive evasion ──────────────────────
                # Detect WAF on first successful response (once per session)
                if self.waf.detected_waf is None:
                    self.waf.detect_waf(
                        http_resp.text[:2000],
                        dict(http_resp.headers),
                    )

                # Handle 429 / 503 rate limiting with Retry-After backoff
                if http_resp.status_code in (429, 503) and attempt < self.max_retries:
                    retry_after = http_resp.header("Retry-After")
                    wait = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** (attempt + 1))
                    wait = min(wait, 60.0)
                    await asyncio.sleep(wait)
                    continue

                # If blocked, activate evasion and retry with bypass headers
                if self.waf.is_blocked(http_resp.status_code, http_resp.text):
                    if not self._waf_evasion_active:
                        self._waf_evasion_active = True
                    # Rebuild headers with evasion for next attempt
                    req_headers = self._build_headers(headers)
                    req_headers.update(self.waf.adapt_to_block(req_headers))
                    if attempt < self.max_retries:
                        await asyncio.sleep(1.0 + attempt)
                        continue  # retry with evasion headers

                return http_resp

            except httpx.TimeoutException as e:
                last_exc = e
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)

            except httpx.TooManyRedirects as e:
                last_exc = e
                break

            except httpx.RequestError as e:
                last_exc = e
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)

        return None

    async def request_with_rate_limit_handling(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        content: Optional[bytes] = None,
        allow_redirects: bool = True,
        max_rate_limit_retries: int = 3,
    ) -> Optional[HTTPResponse]:
        """
        Like request(), but handles 429 / 503 with Retry-After backoff.
        """
        for attempt in range(max_rate_limit_retries):
            resp = await self.request(
                method, url, headers=headers, params=params,
                data=data, json=json, content=content,
                allow_redirects=allow_redirects,
            )
            if resp is None:
                return None
            if resp.status_code in (429, 503):
                retry_after = resp.header("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** (attempt + 1))
                wait = min(wait, 60.0)  # Cap at 60s
                await asyncio.sleep(wait)
                continue
            return resp
        return None

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        use_cache: bool = False,
    ) -> Optional[HTTPResponse]:
        """GET request. Pass use_cache=True to reuse a prior response for the same URL."""
        if use_cache and self.cache_enabled and not params and not headers:
            if url in self._get_cache:
                return self._get_cache[url]
        resp = await self.request("GET", url, headers=headers, params=params,
                                  allow_redirects=allow_redirects)
        if use_cache and self.cache_enabled and resp and not params and not headers:
            self._get_cache[url] = resp
        return resp

    def clear_cache(self) -> None:
        """Clear the GET response cache."""
        self._get_cache.clear()

    async def post(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ) -> Optional[HTTPResponse]:
        # Auto-set Content-Type for raw bytes if not already specified
        if content is not None and headers and "Content-Type" not in headers:
            headers = dict(headers)
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return await self.request("POST", url, headers=headers, data=data,
                                  json=json, content=content)

    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[HTTPResponse]:
        return await self.request("HEAD", url, headers=headers)

    async def post_json(
        self,
        url: str,
        body: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[HTTPResponse]:
        """
        Fix 5.3: POST a JSON body with Content-Type: application/json.
        Shorthand for the common API testing pattern used by api_fuzzer.py
        and any scanner that needs to send structured JSON.
        """
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        return await self.post(url, json=body, headers=req_headers)

    async def post_json_mutation(
        self,
        url: str,
        mutation: Any,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[HTTPResponse]:
        """
        Fix 5.3: Send a mutated JSON body and tag the request so it's
        identifiable in proxy/intercept tools.
        mutation must have .mutated_body (dict) and .category (str).
        """
        headers: Dict[str, str] = {
            "X-WebShield-Mutation": str(getattr(mutation, "category", "unknown")),
        }
        if extra_headers:
            headers.update(extra_headers)
        return await self.post_json(url, mutation.mutated_body, headers=headers)


    async def put(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ) -> Optional[HTTPResponse]:
        """PUT request — used by REST API scanners."""
        return await self.request("PUT", url, headers=headers, data=data,
                                  json=json, content=content)

    async def patch(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ) -> Optional[HTTPResponse]:
        """PATCH request — used by REST API scanners."""
        return await self.request("PATCH", url, headers=headers, data=data,
                                  json=json, content=content)

    async def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[HTTPResponse]:
        """DELETE request — used by REST API scanners."""
        return await self.request("DELETE", url, headers=headers)

    async def options(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[HTTPResponse]:
        """OPTIONS request — used by CORS scanner to check preflight."""
        return await self.request("OPTIONS", url, headers=headers)

    async def get_no_redirect(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[HTTPResponse]:
        """GET without following redirects (for open redirect detection)."""
        return await self.request("GET", url, headers=headers, params=params,
                                  allow_redirects=False)

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "HTTPClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
