"""
Scan result aggregation model.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import Counter

from .vulnerability import Vulnerability, Severity


@dataclass
class ScanStats:
    urls_crawled: int = 0
    urls_scanned: int = 0
    requests_sent: int = 0
    errors: int = 0
    duration_seconds: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    # Fix 4.3: Coverage metrics — give the report real context about scan depth
    endpoints_discovered: int = 0         # total URLs found (crawl + JS + OpenAPI + wordlist)
    endpoints_tested: int = 0             # URLs actually scanned by vulnerability scanners
    parameters_tested: int = 0           # injected parameters count
    js_files_analyzed: int = 0           # JS files processed
    openapi_endpoints_found: int = 0     # endpoints from OpenAPI/Swagger specs
    websocket_endpoints_found: int = 0   # WebSocket endpoints discovered
    passive_requests_imported: int = 0   # from HAR/Burp import

    @property
    def coverage_percent(self) -> float:
        """Ratio of tested endpoints vs discovered endpoints (0-100)."""
        if self.endpoints_discovered == 0:
            return 0.0
        return round((self.endpoints_tested / self.endpoints_discovered) * 100, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "urls_crawled": self.urls_crawled,
            "urls_scanned": self.urls_scanned,
            "requests_sent": self.requests_sent,
            "errors": self.errors,
            "duration_seconds": round(self.duration_seconds, 2),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            # Coverage metrics
            "endpoints_discovered": self.endpoints_discovered,
            "endpoints_tested": self.endpoints_tested,
            "parameters_tested": self.parameters_tested,
            "coverage_percent": self.coverage_percent,
            "js_files_analyzed": self.js_files_analyzed,
            "openapi_endpoints_found": self.openapi_endpoints_found,
            "websocket_endpoints_found": self.websocket_endpoints_found,
            "passive_requests_imported": self.passive_requests_imported,
        }


@dataclass
class ScanResult:
    """Aggregated result of a full scan."""
    target_url: str
    scan_id: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    crawled_urls: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_profile: str = "full"
    # Fix 4.1: store screenshots from BrowserEngine (url → PNG bytes)
    screenshots: Dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Deduplication key set — not a dataclass field, initialised here
        self._vuln_keys: set = set()

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        Normalize URL for deduplication — keep scheme+host+path only.
        Strip query params and fragment so the same vuln on
        /product?id=1 and /product?id=2 isn't reported twice.
        """
        from urllib.parse import urlparse, urlunparse
        try:
            p = urlparse(url)
            return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
        except Exception:
            return url

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """
        Add a vulnerability only if it's not a duplicate.

        Deduplication key: (vuln_type, normalized_url, parameter, title_prefix)

        - normalized_url: strips query string so same vuln across paginated
          URLs (/product?id=1 vs /product?id=2) is only reported once.
        - title_prefix: first 60 chars of title groups UNION column variants
          and other sub-technique duplicates.
        """
        # Fix 1.3: defensive init in case _vuln_keys wasn't set via __post_init__
        # (e.g. ScanResult created via copy.copy() or __new__)
        if not hasattr(self, "_vuln_keys"):
            self._vuln_keys = set()
        normalized = self._normalize_url(vuln.url)
        title_prefix = vuln.title[:60]
        key = (
            vuln.vuln_type,
            normalized,
            vuln.parameter or "",
            title_prefix,
        )
        if key not in self._vuln_keys:
            self._vuln_keys.add(key)
            self.vulnerabilities.append(vuln)

    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return counts

    def vulns_by_severity(self) -> Dict[str, List[Vulnerability]]:
        result: Dict[str, List[Vulnerability]] = {s.value: [] for s in Severity}
        for v in self.vulnerabilities:
            result[v.severity.value].append(v)
        # Sort within each group by CVSS score descending
        for key in result:
            result[key].sort(key=lambda x: x.cvss_score() or 0, reverse=True)
        return result

    def unique_vuln_types(self) -> List[str]:
        return list({v.vuln_type.value for v in self.vulnerabilities})

    def risk_score(self) -> float:
        """Compute an aggregate risk score 0-10 based on all findings."""
        if not self.vulnerabilities:
            return 0.0
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.2,
        }
        # Use max severity as floor + volume bonus (capped at 2.0)
        max_weight = max(weights.get(v.severity, 0.0) for v in self.vulnerabilities)
        volume_bonus = min(len(self.vulnerabilities) * 0.1, 2.0)
        return round(min(max_weight + volume_bonus, 10.0), 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "scan_profile": self.scan_profile,
            "risk_score": self.risk_score(),
            "severity_summary": self.severity_counts(),
            "total_vulnerabilities": len(self.vulnerabilities),
            "unique_vuln_types": self.unique_vuln_types(),
            "stats": self.stats.to_dict(),
            "metadata": self.metadata,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }
