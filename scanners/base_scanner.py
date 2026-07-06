"""
Abstract base class for all vulnerability scanners.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..core.http_client import HTTPClient, HTTPResponse
from ..models.vulnerability import Vulnerability, Severity, VulnType, CVSSv3, CVSS_PROFILES
from ..utils.helpers import inject_payload_into_url, extract_params

# Sentinel — signals that the caller did NOT pass an explicit severity
_SEVERITY_UNSET = object()


class BaseScanner(ABC):
    """
    All scanner modules extend this class.
    Provides helpers for parameter injection and result building.
    """

    #: Name shown in logs
    name: str = "BaseScanner"

    #: If True, this scanner runs once against the root target, not per-URL
    is_target_level: bool = False

    def __init__(self, client: HTTPClient) -> None:
        self.client = client

    @abstractmethod
    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        """
        Scan a single URL+response for vulnerabilities.
        May also test all forms discovered at that URL.

        Args:
            url: The URL that was fetched.
            response: The HTTP response for the URL.
            forms: List of form dicts discovered on the page.

        Returns:
            List of Vulnerability instances found.
        """
        ...

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _build_vuln(
        self,
        vuln_type: VulnType,
        title: str,
        description: str,
        url: str,
        severity: Any = _SEVERITY_UNSET,
        parameter: Optional[str] = None,
        payload: Optional[str] = None,
        evidence: Optional[str] = None,
        method: str = "GET",
        remediation: str = "",
        references: Optional[List[str]] = None,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        response_snippet: Optional[str] = None,
        confidence: str = "High",
        cvss: Optional[CVSSv3] = None,
        false_positive_risk: str = "Low",  # accepted but stored on Vulnerability only
    ) -> Vulnerability:
        caller_set_severity = severity is not _SEVERITY_UNSET
        explicit_severity: Severity = severity if caller_set_severity else Severity.MEDIUM

        if cvss is None:
            cvss = CVSS_PROFILES.get(vuln_type)

        # Derive severity from CVSS score only when the caller left it unset
        resolved_severity = (
            explicit_severity
            if (caller_set_severity or cvss is None)
            else cvss.severity_from_score()
        )
        vuln = Vulnerability(
            vuln_type=vuln_type,
            title=title,
            description=description,
            url=url,
            severity=resolved_severity,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            method=method,
            remediation=remediation,
            references=references or [],
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            response_snippet=response_snippet,
            confidence=confidence,
            cvss=cvss,
        )
        vuln.false_positive_risk = false_positive_risk
        return vuln

    def _extract_url_params(self, url: str) -> List[str]:
        """Return list of query parameter names from a URL."""
        params = extract_params(url)
        return list(params.keys())

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        return inject_payload_into_url(url, param, payload)


    def _extract_path_params(self, url: str) -> list:
        """
        Extract REST-style path parameters from a URL.
        e.g. /api/users/123 → ['123']  (numeric segments are likely IDs)
             /api/items/abc-def → ['abc-def']  (slugs)
        Returns list of (url_with_param, segment_value) tuples.
        """
        from urllib.parse import urlparse
        import re
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        results = []
        # Numeric or UUID-like segments are almost always DB IDs
        id_pattern = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-zA-Z0-9_-]{4,64})$")
        for i, part in enumerate(path_parts):
            if id_pattern.match(part) and (part.isdigit() or "-" in part or len(part) >= 8):
                results.append((i, part))
        return results

    def _inject_path_segment(self, url: str, segment_index: int, payload: str) -> str:
        """Replace a path segment at segment_index with payload."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/")]
        # parts[0] is "" for leading slash
        non_empty_idx = 0
        for i, p in enumerate(parts):
            if p:
                if non_empty_idx == segment_index:
                    parts[i] = payload
                    break
                non_empty_idx += 1
        new_path = "/".join(parts)
        return urlunparse(parsed._replace(path=new_path))

    def _snippet(self, text: str, length: int = 300) -> str:
        return text[:length] if text else ""
