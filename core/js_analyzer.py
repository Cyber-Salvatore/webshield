"""
JavaScript Analysis Engine.

Fetches and analyzes JavaScript bundles (webpack, vite, rollup, etc.) to:
- Extract API endpoints that are never visible in HTML
- Discover hidden routes defined in client-side routers
- Find leaked secrets: API keys, AWS credentials, Firebase configs, JWTs
- Parse source maps to recover original source structure
- Detect environment variables exposed in bundles
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
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from .http_client import HTTPClient
from ..utils.helpers import normalize_url, get_base_url


# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

@dataclass
class SecretMatch:
    """A potential secret found in a JS file."""
    secret_type: str
    value: str
    context: str        # surrounding code snippet (redacted for long values)
    source_url: str
    line_hint: int = 0  # approximate line number
    confidence: str = "High"   # High | Medium | Low

    def redacted_value(self) -> str:
        """Return a safely redacted version for display."""
        if len(self.value) <= 8:
            return "***"
        return self.value[:4] + "*" * (len(self.value) - 8) + self.value[-4:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.secret_type,
            "value": self.redacted_value(),
            "context": self.context[:120],
            "source": self.source_url,
            "confidence": self.confidence,
        }


# Pattern: (name, regex, confidence)
_SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # AWS
    (
        "AWS Access Key ID",
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "High",
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r'(?:aws.?secret|secret.?access.?key|AWS_SECRET)[\'"\s:=]+([A-Za-z0-9/+]{40})',
            re.IGNORECASE,
        ),
        "High",
    ),
    # Google
    (
        "Google API Key",
        re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
        "High",
    ),
    (
        "Google OAuth Client Secret",
        re.compile(r'client_secret[\'"\s:=]+([A-Za-z0-9\-_]{24,32})', re.IGNORECASE),
        "Medium",
    ),
    # Firebase
    (
        "Firebase API Key",
        re.compile(
            r'(?:firebase|FIREBASE)[^{]{0,50}apiKey[\'"\s:=]+([A-Za-z0-9\-_]{35,45})',
            re.IGNORECASE,
        ),
        "High",
    ),
    # Stripe
    (
        "Stripe Live Secret Key",
        re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'),
        "High",
    ),
    (
        "Stripe Publishable Key",
        re.compile(r'\b(pk_live_[0-9a-zA-Z]{24,})\b'),
        "Medium",
    ),
    # GitHub
    (
        "GitHub Personal Access Token",
        re.compile(r'\b(ghp_[A-Za-z0-9]{36})\b'),
        "High",
    ),
    (
        "GitHub OAuth Token",
        re.compile(r'\b(gho_[A-Za-z0-9]{36})\b'),
        "High",
    ),
    # Slack
    (
        "Slack Bot Token",
        re.compile(r'\b(xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+)\b'),
        "High",
    ),
    (
        "Slack Webhook URL",
        re.compile(r'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        "High",
    ),
    # Twilio
    (
        "Twilio API Key",
        re.compile(r'\b(SK[0-9a-fA-F]{32})\b'),
        "High",
    ),
    # SendGrid
    (
        "SendGrid API Key",
        re.compile(r'\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b'),
        "High",
    ),
    # Mailgun
    (
        "Mailgun API Key",
        re.compile(r'\b(key-[0-9a-zA-Z]{32})\b'),
        "Medium",
    ),
    # Private keys
    (
        "RSA Private Key",
        re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        "High",
    ),
    (
        "Private Key",
        re.compile(r'-----BEGIN (?:EC|OPENSSH|DSA) PRIVATE KEY-----'),
        "High",
    ),
    # JWT secrets (weak / hardcoded)
    (
        "Hardcoded JWT Secret",
        re.compile(
            r'(?:jwt.?secret|JWT_SECRET|jwtSecret|secret.?key)[\'"\s:=]+([\'"]([^\'\"]{8,80})[\'"])',
            re.IGNORECASE,
        ),
        "High",
    ),
    # Generic high-entropy secrets
    (
        "Generic API Key",
        re.compile(
            r'(?:api.?key|apikey|API_KEY|x-api-key)[\'"\s:=]+[\'"]([A-Za-z0-9\-_]{20,64})[\'"]',
            re.IGNORECASE,
        ),
        "Medium",
    ),
    (
        "Generic Secret / Password",
        re.compile(
            r'(?:password|passwd|secret|token)[\'"\s:=]+[\'"]([A-Za-z0-9!@#$%^&*\-_]{8,64})[\'"]',
            re.IGNORECASE,
        ),
        "Low",
    ),
    # Database connection strings
    (
        "Database Connection String",
        re.compile(
            r'(?:mongodb|postgres|mysql|redis)://[^\'"\s<>]{10,200}',
            re.IGNORECASE,
        ),
        "High",
    ),
    # Internal / private URLs
    (
        "Internal API Base URL",
        re.compile(
            r'(?:api.?base|API_BASE|baseURL|BASE_URL)[\'"\s:=]+[\'"]'
            r'(https?://(?:10\.|172\.|192\.168\.|localhost|127\.)[^\'\"]{4,100})[\'"]',
            re.IGNORECASE,
        ),
        "Medium",
    ),
]

# ---------------------------------------------------------------------------
# API endpoint / route patterns in JS
# ---------------------------------------------------------------------------

_API_ENDPOINT_PATTERNS: List[re.Pattern] = [
    # fetch / axios / http calls
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|http\.(?:get|post))\s*\(\s*[`'"]([^`'"]+)[`'"]"""),
    # url: '/api/...'
    re.compile(r"""url\s*:\s*[`'"]([/][^`'"]{2,150})[`'"]"""),
    # endpoint: '/...'
    re.compile(r"""endpoint\s*:\s*[`'"]([/][^`'"]{2,150})[`'"]"""),
    # baseURL + path concatenation
    re.compile(r"""[`'"]([/]api[/][^`'"\s]{2,100})[`'"]"""),
    re.compile(r"""[`'"]([/]v\d+[/][^`'"\s]{2,100})[`'"]"""),
    # Template literals with API paths
    re.compile(r"""`([/](?:api|v\d+|rest)[/][^`]{2,150})`"""),
    # Redux action / RTK Query endpoints
    re.compile(r"""(?:builder\.query|builder\.mutation)\s*\([^)]{0,50}url\s*:\s*[`'"]([^`'"]+)[`'"]"""),
    # React Router / Vue Router / Angular route paths
    re.compile(r"""(?:path|route)\s*:\s*[`'"]([/][A-Za-z0-9_/:\-*?]{2,100})[`'"]"""),
    # OpenAPI operationId → path mapping
    re.compile(r"""[`'"]([/][a-zA-Z0-9_/\-{}]{4,100})[`'"]"""),
]

# Route-specific patterns (client-side router definitions)
_ROUTE_PATTERNS: List[re.Pattern] = [
    # React Router v6
    re.compile(r"""<Route[^>]+path\s*=\s*[{]?[`'"]([^`'"]+)[`'"]"""),
    # Vue Router
    re.compile(r"""path\s*:\s*[`'"]([/][^`'"]*)[`'"]"""),
    # Angular routing
    re.compile(r"""path\s*:\s*'([^']+)'"""),
    # Express-style
    re.compile(r"""(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\([`'"]([/][^`'"]*)[`'"]"""),
]


# ---------------------------------------------------------------------------
# Analysis result
# ---------------------------------------------------------------------------

@dataclass
class JSAnalysisResult:
    """Aggregated findings from analyzing one JS file."""
    source_url: str
    endpoints: List[str] = field(default_factory=list)
    routes: List[str] = field(default_factory=list)
    secrets: List[SecretMatch] = field(default_factory=list)
    source_map_url: Optional[str] = None
    is_minified: bool = False
    size_bytes: int = 0
    error: Optional[str] = None

    def has_findings(self) -> bool:
        return bool(self.endpoints or self.routes or self.secrets)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_url,
            "endpoints": self.endpoints,
            "routes": self.routes,
            "secrets": [s.to_dict() for s in self.secrets],
            "source_map": self.source_map_url,
            "size_bytes": self.size_bytes,
            "is_minified": self.is_minified,
        }


# ---------------------------------------------------------------------------
# JS Analyzer
# ---------------------------------------------------------------------------

class JSAnalyzer:
    """
    Fetches and analyzes JavaScript files from a target.

    Works in two passes:
    1. Download the JS (or source map if available)
    2. Run all detection patterns over the content

    Designed to be async-safe and called concurrently.
    """

    # Cap JS file size to avoid processing huge vendor bundles
    _MAX_JS_SIZE_BYTES = 5 * 1024 * 1024   # 5 MB
    _MIN_JS_SIZE_BYTES = 100               # skip trivial inline scripts

    def __init__(
        self,
        client: HTTPClient,
        base_url: str,
        max_concurrent: int = 5,
    ) -> None:
        self.client = client
        self.base_url = base_url
        self.max_concurrent = max_concurrent
        self._analyzed_urls: Set[str] = set()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def analyze_scripts(
        self,
        script_urls: List[str],
    ) -> List[JSAnalysisResult]:
        """
        Analyze a list of JS file URLs concurrently.
        Returns one JSAnalysisResult per URL (errors included).
        """
        # Deduplicate
        unique_urls = list(dict.fromkeys(
            u for u in script_urls if u not in self._analyzed_urls
        ))
        self._analyzed_urls.update(unique_urls)

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _analyze_one(url: str) -> JSAnalysisResult:
            async with semaphore:
                return await self._analyze_url(url)

        tasks = [_analyze_one(url) for url in unique_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output: List[JSAnalysisResult] = []
        for url, result in zip(unique_urls, results):
            if isinstance(result, JSAnalysisResult):
                output.append(result)
            else:
                output.append(JSAnalysisResult(source_url=url, error=str(result)))

        return output

    async def analyze_inline(self, js_content: str, source_label: str) -> JSAnalysisResult:
        """Analyze inline JS content (from <script> tags)."""
        result = JSAnalysisResult(source_url=source_label, size_bytes=len(js_content))
        if len(js_content) < self._MIN_JS_SIZE_BYTES:
            return result
        self._run_patterns(js_content, result)
        return result

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    async def _analyze_url(self, url: str) -> JSAnalysisResult:
        """Download and analyze a single JS URL."""
        result = JSAnalysisResult(source_url=url)

        response = await self.client.get(url, headers={"Accept": "*/*"})
        if response is None:
            result.error = "Failed to fetch"
            return result

        if response.status_code not in (200, 206):
            result.error = f"HTTP {response.status_code}"
            return result

        content = response.content
        result.size_bytes = len(content)

        if result.size_bytes > self._MAX_JS_SIZE_BYTES:
            result.error = f"File too large ({result.size_bytes // 1024} KB)"
            return result

        if result.size_bytes < self._MIN_JS_SIZE_BYTES:
            return result  # nothing useful

        js_text = response.text
        result.is_minified = self._detect_minified(js_text)

        # Check for source map reference
        source_map_url = self._extract_source_map_url(js_text, url)
        if source_map_url:
            result.source_map_url = source_map_url
            # Try to fetch and use the source map for better analysis
            sm_content = await self._fetch_source_map(source_map_url)
            if sm_content:
                # Append source map content for pattern analysis
                js_text = js_text + "\n" + sm_content

        self._run_patterns(js_text, result)
        return result

    def _run_patterns(self, content: str, result: JSAnalysisResult) -> None:
        """Run all detection passes over JS content."""
        self._extract_endpoints(content, result)
        self._extract_routes(content, result)
        self._extract_secrets(content, result)

    def _extract_endpoints(self, content: str, result: JSAnalysisResult) -> None:
        """Extract API endpoint paths from JS content."""
        found: Set[str] = set()
        for pattern in _API_ENDPOINT_PATTERNS:
            for match in pattern.findall(content):
                path = match.strip()
                if self._is_valid_api_path(path):
                    full = urljoin(self.base_url, path)
                    found.add(normalize_url(full))
        result.endpoints = list(found)

    def _extract_routes(self, content: str, result: JSAnalysisResult) -> None:
        """Extract client-side route definitions."""
        found: Set[str] = set()
        for pattern in _ROUTE_PATTERNS:
            for match in pattern.findall(content):
                path = match.strip()
                if path and path != "/" and len(path) > 1:
                    # Convert dynamic segments: /users/:id → /users/1
                    clean = re.sub(r':[A-Za-z_]+', '1', path)
                    clean = re.sub(r'\*', '', clean)
                    if clean and clean.startswith("/"):
                        found.add(clean)
        result.routes = list(found)

    def _extract_secrets(self, content: str, result: JSAnalysisResult) -> None:
        """Scan for leaked secrets using predefined patterns."""
        for secret_type, pattern, confidence in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                # Get the matched value — use group(1) if available
                try:
                    value = match.group(1)
                except IndexError:
                    value = match.group(0)

                if not value or len(value) < 4:
                    continue

                # Skip obvious test/example values
                if self._is_placeholder(value):
                    continue

                # Extract surrounding context (±60 chars)
                start = max(0, match.start() - 60)
                end = min(len(content), match.end() + 60)
                context = content[start:end].replace("\n", " ")

                # Approximate line number
                line = content[:match.start()].count("\n") + 1

                result.secrets.append(SecretMatch(
                    secret_type=secret_type,
                    value=value,
                    context=context,
                    source_url=result.source_url,
                    line_hint=line,
                    confidence=confidence,
                ))

    # -----------------------------------------------------------------------
    # Source map support
    # -----------------------------------------------------------------------

    def _extract_source_map_url(self, content: str, js_url: str) -> Optional[str]:
        """Look for //# sourceMappingURL= comment."""
        match = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', content)
        if not match:
            return None
        sm_path = match.group(1).strip()
        if sm_path.startswith("data:"):
            return None   # inline source map — skip
        return urljoin(js_url, sm_path)

    async def _fetch_source_map(self, url: str) -> Optional[str]:
        """Fetch a source map and return the 'sourcesContent' as concatenated text."""
        try:
            response = await self.client.get(url, headers={"Accept": "*/*"})
            if response is None or response.status_code != 200:
                return None
            data = json.loads(response.text)
            # 'sources' contains original file paths
            sources_text: List[str] = []
            for i, src_content in enumerate(data.get("sourcesContent") or []):
                if src_content:
                    sources_text.append(f"// Source: {data.get('sources', [''])[i]}\n{src_content}")
            return "\n\n".join(sources_text)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _detect_minified(content: str) -> bool:
        """Heuristic: check if JS is minified (very long lines, low line count)."""
        if not content:
            return False
        lines = content.split("\n")
        if len(lines) < 5:
            return True
        avg_line_len = len(content) / len(lines)
        return avg_line_len > 500

    @staticmethod
    def _is_valid_api_path(path: str) -> bool:
        """Filter out paths that are clearly not API endpoints."""
        if not path or len(path) < 3:
            return False
        if not path.startswith("/"):
            # Only keep absolute paths
            if not path.startswith("http"):
                return False
        # Skip common non-API paths
        skip_extensions = {".js", ".css", ".png", ".jpg", ".gif", ".svg",
                           ".woff", ".ttf", ".ico", ".html", ".map"}
        low = path.lower()
        for ext in skip_extensions:
            if low.endswith(ext):
                return False
        # Skip paths that are just template placeholders
        if "${" in path or "{{" in path:
            return False
        return True

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """Return True if the value is a well-known placeholder/example."""
        placeholders = {
            "your_api_key", "your-api-key", "api_key_here",
            "xxxxxxxxxxxx", "000000000000", "changeme",
            "placeholder", "your_secret", "example", "test",
            "xxxxxxxx", "your-secret-key", "insert_key_here",
            "abcdefghijklmnop", "1234567890abcdef",
        }
        low = value.lower().strip("'\"")
        return low in placeholders or low.startswith("your_") or low.startswith("your-")


# ---------------------------------------------------------------------------
# Convenience: analyze a batch of URLs and aggregate unique findings
# ---------------------------------------------------------------------------

async def analyze_js_batch(
    client: HTTPClient,
    base_url: str,
    script_urls: List[str],
    max_concurrent: int = 5,
) -> Tuple[List[str], List[str], List[SecretMatch]]:
    """
    Convenience function. Returns (endpoints, routes, secrets) aggregated
    across all JS files in script_urls.
    """
    analyzer = JSAnalyzer(client, base_url, max_concurrent)
    results = await analyzer.analyze_scripts(script_urls)

    all_endpoints: Set[str] = set()
    all_routes: Set[str] = set()
    all_secrets: List[SecretMatch] = []

    for r in results:
        all_endpoints.update(r.endpoints)
        all_routes.update(r.routes)
        all_secrets.extend(r.secrets)

    return list(all_endpoints), list(all_routes), all_secrets
