"""
Target scope and configuration management.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse

from ..utils.helpers import normalize_url, get_base_url


@dataclass
class ScanTarget:
    """Represents the scanning target and scope configuration."""

    url: str
    scope_domains: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    excluded_extensions: List[str] = field(default_factory=list)
    max_depth: int = 3
    max_pages: int = 150
    follow_redirects: bool = True
    include_subdomains: bool = False
    custom_headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    auth_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    # Internal tracking
    _visited: Set[str] = field(default_factory=set, repr=False, compare=False)

    DEFAULT_EXCLUDED_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".pdf", ".zip", ".tar", ".gz", ".rar", ".exe", ".dll", ".bin",
        ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".css", ".map",
    }

    def __post_init__(self) -> None:
        self.url = normalize_url(self.url)
        parsed = urlparse(self.url)
        if not self.scope_domains:
            self.scope_domains = [parsed.hostname or ""]
        # Merge default excluded extensions and sort for deterministic output
        all_excl = set(self.excluded_extensions) | self.DEFAULT_EXCLUDED_EXTENSIONS
        self.excluded_extensions = sorted(all_excl)

    @property
    def base_url(self) -> str:
        return get_base_url(self.url)

    @property
    def hostname(self) -> str:
        return urlparse(self.url).hostname or ""

    def is_in_scope(self, url: str) -> bool:
        """Determine whether a URL is within the defined scan scope."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            # Check domain scope
            in_domain_scope = False
            for domain in self.scope_domains:
                if hostname == domain:
                    in_domain_scope = True
                    break
                if self.include_subdomains and hostname.endswith("." + domain):
                    in_domain_scope = True
                    break

            if not in_domain_scope:
                return False

            # Check excluded paths
            path = parsed.path.lower()
            for excluded in self.excluded_paths:
                if path.startswith(excluded.lower()):
                    return False

            # Check excluded extensions
            for ext in self.excluded_extensions:
                if path.endswith(ext.lower()):
                    return False

            return True
        except Exception:
            return False

    def mark_visited(self, url: str) -> None:
        self._visited.add(url)

    def is_visited(self, url: str) -> bool:
        return url in self._visited

    def try_mark_visited(self, url: str) -> bool:
        """
        Atomically check and mark a URL as visited.

        Fix 1.5: replaces the TOCTOU gap of is_visited() + mark_visited()
        in crawler.py. In asyncio's single-threaded cooperative model this
        is truly atomic — no coroutine can interleave between the check and
        the add. Returns True if the URL was *not* visited (newly marked),
        False if it was already visited.
        """
        if url in self._visited:
            return False
        self._visited.add(url)
        return True

    def visited_count(self) -> int:
        return len(self._visited)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "base_url": self.base_url,
            "hostname": self.hostname,
            "scope_domains": self.scope_domains,
            "excluded_paths": self.excluded_paths,
            "max_depth": self.max_depth,
            "max_pages": self.max_pages,
            "follow_redirects": self.follow_redirects,
            "include_subdomains": self.include_subdomains,
        }
