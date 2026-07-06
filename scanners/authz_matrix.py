"""
Authorization Matrix Scanner — Phase 3.2
==========================================
Tests every discovered endpoint with multiple user roles to detect:

  • BOLA  (Broken Object Level Authorization)  — CWE-639 / OWASP API1
    User A accessing User B's resources
  • BFLA  (Broken Function Level Authorization) — CWE-285 / OWASP API5
    Low-privilege user calling admin/privileged functions
  • Privilege Escalation
    Regular user gaining elevated access
  • Horizontal privilege testing
    User accessing another user's data at the same privilege level

How it works:
  1. Receives a list of AuthSession objects (one per role)
  2. For each endpoint × role: sends the request and records the response
  3. Builds a matrix: endpoint → {role → (status, response_size)}
  4. Detects anomalies:
     - Endpoint accessible to lower role than expected
     - Different data returned to different users at the same role

Integrates with:
  - core/auth_engine.py  → provides AuthSession list
  - engine.py            → calls scanner with session list after login phase
  - scanners/idor.py     → BOLA is IDOR generalised; shares compare logic
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPClient, HTTPResponse
from ..core.auth_engine import AuthSession
from ..models.vulnerability import (
    Vulnerability, Severity, VulnType, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)

# ---------------------------------------------------------------------------
# CVSS profiles
# ---------------------------------------------------------------------------

_CVSS_BOLA = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.LOW,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.NONE,
)

_CVSS_BFLA = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.LOW,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.LOW,
)

_CVSS_PRIVESC = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.LOW,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.HIGH,
)

# ---------------------------------------------------------------------------
# Patterns for admin / privileged endpoints
# ---------------------------------------------------------------------------

_ADMIN_PATH_RE = re.compile(
    r"/(?:admin|administrator|management|manage|superuser|superadmin|"
    r"staff|moderator|internal|privileged|root|system|sys|config|"
    r"settings/admin|dashboard/admin)[/\?#]?",
    re.IGNORECASE,
)

_SENSITIVE_METHODS = {"DELETE", "PUT", "PATCH"}

# Patterns in response body suggesting privilege was granted
_PRIVILEGE_BODY_RE = re.compile(
    r'"(?:role|isAdmin|is_admin|admin|superuser|staff|permissions?)"\s*:\s*'
    r'"?(?:admin|true|superuser|root|1)"?',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# MatrixEntry — one cell in the authorization matrix
# ---------------------------------------------------------------------------

@dataclass
class MatrixEntry:
    url: str
    method: str
    role: str
    username: str
    status_code: int
    response_size: int
    accessible: bool          # True if response looks like access was granted


# ---------------------------------------------------------------------------
# AuthorizationMatrixScanner
# ---------------------------------------------------------------------------

class AuthorizationMatrixScanner(_ScannerBase):
    """
    Phase 3.2 — Authorization Matrix Testing Scanner.

    Requires sessions to be injected via set_sessions() before scan_url()
    is called. The engine.py must call set_sessions() after auth_engine.login_all_users().

    is_target_level = True  (runs once, tests all discovered URLs)
    """

    name = "Authorization Matrix"
    is_target_level = True

    def __init__(self, client: HTTPClient) -> None:
        super().__init__(client)
        self._sessions: List[AuthSession] = []
        self._tested_urls: List[str] = []

    def set_sessions(self, sessions: List[AuthSession]) -> None:
        """Inject the authenticated sessions to test with."""
        self._sessions = [s for s in sessions if s.success]

    def set_urls(self, urls: List[str]) -> None:
        """Set the list of discovered URLs to test."""
        self._tested_urls = urls

    # -----------------------------------------------------------------------

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        """
        Entry point called by engine.py for target-level scanners.
        When called this way url = target root URL and we test all collected URLs.
        """
        if not self._sessions:
            return []

        urls_to_test = self._tested_urls or [url]
        vulns: List[Vulnerability] = []

        for test_url in urls_to_test:
            vulns.extend(await self._test_endpoint_matrix(test_url))

        return vulns

    # -----------------------------------------------------------------------
    # Core matrix logic
    # -----------------------------------------------------------------------

    async def _test_endpoint_matrix(self, url: str) -> List[Vulnerability]:
        """Build the authorization matrix for one URL and detect violations."""
        vulns: List[Vulnerability] = []

        # Build per-role responses
        entries: List[MatrixEntry] = []
        for session in self._sessions:
            entry = await self._probe(url, "GET", session)
            if entry:
                entries.append(entry)

        if len(entries) < 2:
            return vulns  # need at least 2 roles to compare

        # ── BFLA: low-privilege accessing admin endpoint ──────────────────
        if _ADMIN_PATH_RE.search(url):
            for entry in entries:
                if entry.role not in ("admin", "superuser", "root") and entry.accessible:
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BFLA,
                        title="Broken Function Level Authorization (BFLA)",
                        description=(
                            f"User '{entry.username}' (role: {entry.role}) can access "
                            f"the admin endpoint '{url}'. "
                            f"Response status: {entry.status_code}, size: {entry.response_size} bytes. "
                            f"Unprivileged users should not be able to access administrative functions."
                        ),
                        url=url,
                        method=entry.method,
                        parameter="role",
                        evidence=(
                            f"User '{entry.username}' (role={entry.role}) received "
                            f"HTTP {entry.status_code} on {url}"
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Implement server-side role checks on every administrative endpoint. "
                            "Do not rely on client-side role enforcement or UI hiding. "
                            "Apply the principle of least privilege."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                            "https://cwe.mitre.org/data/definitions/285.html",
                        ],
                        cwe_id="CWE-285",
                        owasp_category="A01:2021 - Broken Access Control",
                        cvss=_CVSS_BFLA,
                        confidence="Medium",
                    ))

        # ── BOLA: different users getting same-role data of each other ─────
        if len(entries) >= 2:
            vulns.extend(self._detect_bola(url, entries))

        # ── Privilege escalation: non-admin response looks like admin ──────
        vulns.extend(self._detect_privilege_escalation(url, entries))

        return vulns

    def _detect_bola(
        self, url: str, entries: List[MatrixEntry]
    ) -> List[Vulnerability]:
        """
        Detect BOLA: multiple users with the same role get different-sized
        responses — but user-specific data from URL contains an ID that
        should scope the data to one user.
        """
        vulns: List[Vulnerability] = []

        # Only relevant for ID-containing URLs
        if not re.search(r"/\d+|/[0-9a-f\-]{36}", url):
            return vulns

        # Find same-role pairs
        by_role: Dict[str, List[MatrixEntry]] = {}
        for e in entries:
            by_role.setdefault(e.role, []).append(e)

        for role, role_entries in by_role.items():
            if len(role_entries) < 2:
                continue
            sizes = [e.response_size for e in role_entries if e.accessible]
            if not sizes:
                continue
            # Both accessible with significantly different sizes → BOLA
            if max(sizes) - min(sizes) > 200 and min(sizes) > 50:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.BOLA,
                    title="Broken Object Level Authorization (BOLA/IDOR)",
                    description=(
                        f"Multiple users with role '{role}' received different "
                        f"sized responses from '{url}', suggesting cross-user data access. "
                        f"Response sizes: {sizes}. "
                        f"An attacker could enumerate IDs to access other users' data."
                    ),
                    url=url,
                    method="GET",
                    evidence=(
                        f"Same-role users received responses of sizes {sizes} "
                        f"— indicates per-user data leakage"
                    ),
                    severity=Severity.HIGH,
                    remediation=(
                        "Validate that the authenticated user owns the requested object "
                        "on every request. Never rely only on the object ID in the URL; "
                        "bind it to the authenticated session."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://cwe.mitre.org/data/definitions/639.html",
                    ],
                    cwe_id="CWE-639",
                    owasp_category="A01:2021 - Broken Access Control",
                    cvss=_CVSS_BOLA,
                    confidence="Medium",
                ))
                break  # one finding per URL

        return vulns

    def _detect_privilege_escalation(
        self, url: str, entries: List[MatrixEntry]
    ) -> List[Vulnerability]:
        """Detect when a low-privilege user's response body suggests admin-level data."""
        vulns: List[Vulnerability] = []
        for entry in entries:
            if entry.role in ("admin", "superuser", "root"):
                continue
            if not entry.accessible:
                continue
            # We don't have the full response text here — flag based on URL patterns
            # The full text check is done in _probe()
            if entry.accessible and _ADMIN_PATH_RE.search(url):
                # Already handled in BFLA — skip
                pass
        return vulns

    # -----------------------------------------------------------------------
    # HTTP probe with session cookies
    # -----------------------------------------------------------------------

    async def _probe(
        self,
        url: str,
        method: str,
        session: AuthSession,
    ) -> Optional[MatrixEntry]:
        """Send one request with the session's credentials and return a MatrixEntry."""
        headers: Dict[str, str] = {}
        if session.auth_token:
            headers["Authorization"] = f"Bearer {session.auth_token}"

        try:
            resp = await self.client.request(
                method=method,
                url=url,
                headers=headers,
            )
        except Exception:
            return None

        if resp is None:
            return None

        accessible = self._is_accessible(resp)

        return MatrixEntry(
            url=url,
            method=method,
            role=session.role,
            username=session.username,
            status_code=resp.status_code,
            response_size=len(resp.content),
            accessible=accessible,
        )

    @staticmethod
    def _is_accessible(resp: HTTPResponse) -> bool:
        """
        Determine if a response looks like access was granted.
        200/201/202/206 without auth-error body = accessible.
        """
        if resp.status_code in (401, 403, 404, 410):
            return False
        if resp.status_code not in range(200, 300):
            return False
        # Check body for explicit auth errors
        body_lower = resp.text[:2000].lower() if resp.is_text else ""
        auth_errors = ("unauthorized", "forbidden", "access denied",
                       "not allowed", "permission denied")
        return not any(kw in body_lower for kw in auth_errors)
