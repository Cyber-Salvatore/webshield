"""
Multi-Account Session Framework — Phase 3.3
=============================================
Manages more than one authenticated session/role at the same time during a
single scan, keeps them alive, synchronises data discovered through one
account into the others, and exposes the primitives the rest of the platform
needs to run cross-account testing (IDOR / BOLA / BFLA / Broken Access
Control) automatically.

Responsibilities:
  • Hold one HTTPClient per AuthSession (role-scoped cookie/token jars)
  • Detect session expiry (401/403/redirect-to-login patterns) and
    transparently re-authenticate via AuthEngine without interrupting a scan
  • Maintain a cross-account Resource Registry: every object/resource id
    observed during crawling or scanning is tagged with the account that
    "owns" it (i.e. the account it was discovered under)
  • Generate ownership-swap candidates: for every owned resource, build the
    requests needed to test whether *another* account can read/modify it
    (the raw material BOLA/IDOR/BFLA scanners consume)
  • Dispatch the same logical request through every registered account in
    parallel and return a normalised matrix of responses
  • Score the matrix with ResponseAnalyzer to highlight responses that are
    suspiciously similar (likely access-control leakage) or suspiciously
    different (likely role-based segregation working correctly)
  • Keep ephemeral per-account state in sync (CSRF tokens, dynamic nonces,
    anti-automation cookies) so that secondary accounts don't fail requests
    purely because of stale tokens

Usage::

    manager = MultiAccountManager(base_client_kwargs={"timeout": 15.0})
    manager.register(session_admin)
    manager.register(session_user_a)
    manager.register(session_user_b)

    await manager.start()

    manager.register_resource("order_id", "4471", owner_role="user_a",
                               source_url="https://target/api/orders/4471")

    matrix = await manager.cross_account_request("GET", "https://target/api/orders/4471")
    report = manager.analyze_matrix(matrix)

    candidates = manager.build_idor_candidates()
    for c in candidates:
        resp = await manager.clients[c.tester_role].get(c.url)
        ...

    await manager.close()
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import itertools
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .http_client import HTTPClient, HTTPResponse
from ..utils.response_analyzer import ResponseAnalyzer, SimilarityResult

try:
    from .auth_engine import AuthSession, AuthEngine, AuthConfig
    _AUTH_ENGINE_AVAILABLE = True
except ImportError:  # pragma: no cover - playwright not installed
    AuthSession = None        # type: ignore[assignment,misc]
    AuthEngine = None         # type: ignore[assignment,misc]
    AuthConfig = None         # type: ignore[assignment,misc]
    _AUTH_ENGINE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Patterns used to detect a session that has silently expired
# ---------------------------------------------------------------------------

_LOGIN_REDIRECT_PATTERNS = (
    "login", "signin", "sign-in", "session-expired", "auth/redirect",
)
_AUTH_FAILURE_BODY_PATTERNS = (
    "session expired", "session has expired", "please log in", "please login",
    "token expired", "invalid token", "unauthenticated", "not authenticated",
    "csrf token mismatch", "csrf token invalid",
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ManagedAccount:
    """A single account/role tracked by the MultiAccountManager."""
    session: Any                      # AuthSession
    client: HTTPClient
    role: str
    username: str
    last_used: float = field(default_factory=time.time)
    last_revalidated: float = field(default_factory=time.time)
    revalidation_failures: int = 0
    healthy: bool = True

    def touch(self) -> None:
        self.last_used = time.time()


@dataclass
class OwnedResource:
    """A resource/object id observed under a particular account."""
    param_name: str
    value: str
    owner_role: str
    source_url: str
    resource_type: str = "generic"     # e.g. order, invoice, user, file, ticket
    first_seen: float = field(default_factory=time.time)


@dataclass
class IDORCandidate:
    """A cross-account access test built from an OwnedResource."""
    resource: OwnedResource
    tester_role: str
    url: str
    method: str = "GET"
    notes: str = ""


@dataclass
class AccessMatrixEntry:
    """One cell of the cross-account response matrix."""
    role: str
    status_code: int
    content_length: int
    elapsed: float
    response: HTTPResponse


@dataclass
class AccessMatrixReport:
    """Result of comparing every account's response to a given request."""
    url: str
    method: str
    entries: Dict[str, AccessMatrixEntry]
    pairwise_similarity: Dict[Tuple[str, str], SimilarityResult]
    suspicious_leak_pairs: List[Tuple[str, str]] = field(default_factory=list)
    expected_segregation_pairs: List[Tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status_by_role": {
                role: e.status_code for role, e in self.entries.items()
            },
            "size_by_role": {
                role: e.content_length for role, e in self.entries.items()
            },
            "pairwise_similarity": {
                f"{a}↔{b}": sim.to_dict()
                for (a, b), sim in self.pairwise_similarity.items()
            },
            "suspicious_leak_pairs": [f"{a}↔{b}" for a, b in self.suspicious_leak_pairs],
        }


# ---------------------------------------------------------------------------
# Resource id extraction heuristics (numbers, UUIDs in URLs / JSON bodies)
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NUMERIC_ID_RE = re.compile(r"/(\d{1,15})(?:/|$|\?)")
_ID_KEY_RE = re.compile(
    r'"(?P<key>[a-zA-Z_]*id|[a-zA-Z_]*Id)"\s*:\s*"?(?P<val>[0-9a-fA-F-]{1,40})"?'
)


def extract_resource_ids(url: str, body: str = "") -> List[Tuple[str, str]]:
    """
    Heuristically pull (param_name, value) candidates for resource ids out
    of a URL path/query and an optional JSON/HTML body.
    Used to populate the Resource Registry automatically while crawling.
    """
    found: List[Tuple[str, str]] = []

    for m in _NUMERIC_ID_RE.finditer(url):
        found.append(("path_id", m.group(1)))

    for m in _UUID_RE.finditer(url):
        found.append(("uuid", m.group(0)))

    if body:
        for m in _ID_KEY_RE.finditer(body):
            found.append((m.group("key"), m.group("val")))

    # de-duplicate while preserving order
    seen: Set[Tuple[str, str]] = set()
    out: List[Tuple[str, str]] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# MultiAccountManager
# ---------------------------------------------------------------------------

class MultiAccountManager:
    """
    Phase 3.3 — Multi-Account Session Framework.

    Owns the lifecycle of every authenticated account used in a scan,
    keeps a shared Resource Registry so other engines can ask "who owns
    resource X" and "can role Y reach it", and provides parallel
    cross-account request dispatch with built-in response comparison.
    """

    def __init__(
        self,
        base_client_kwargs: Optional[Dict[str, Any]] = None,
        auth_config_by_role: Optional[Dict[str, Any]] = None,
        analyzer: Optional[ResponseAnalyzer] = None,
        revalidation_interval: float = 120.0,
        max_revalidation_failures: int = 3,
    ) -> None:
        self.base_client_kwargs = base_client_kwargs or {}
        self.auth_config_by_role = auth_config_by_role or {}
        self.analyzer = analyzer or ResponseAnalyzer()
        self.revalidation_interval = revalidation_interval
        self.max_revalidation_failures = max_revalidation_failures

        self.accounts: Dict[str, ManagedAccount] = {}     # role -> account
        self.clients: Dict[str, HTTPClient] = {}          # role -> client (convenience view)
        self.resources: List[OwnedResource] = []
        self._resource_index: Dict[Tuple[str, str], OwnedResource] = {}
        self._shared_dynamic_values: Dict[str, str] = {}  # e.g. csrf_token -> value
        self._lock = asyncio.Lock()

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def register(self, session: Any, role: Optional[str] = None) -> ManagedAccount:
        """Register an already-authenticated AuthSession under a role label."""
        resolved_role = role or getattr(session, "role", None) or f"role_{len(self.accounts) + 1}"
        client_kwargs = dict(self.base_client_kwargs)
        client_kwargs.update(getattr(session, "to_http_client_kwargs", lambda: {})())
        client = HTTPClient(**client_kwargs)

        account = ManagedAccount(
            session=session,
            client=client,
            role=resolved_role,
            username=getattr(session, "username", resolved_role),
        )
        self.accounts[resolved_role] = account
        self.clients[resolved_role] = client
        return account

    async def start(self) -> None:
        """Warm up underlying HTTP clients (connection pools)."""
        for account in self.accounts.values():
            await account.client._get_client()  # noqa: SLF001 - intentional warmup

    async def close(self) -> None:
        await asyncio.gather(
            *(account.client.close() for account in self.accounts.values()),
            return_exceptions=True,
        )

    # -----------------------------------------------------------------
    # Session health / re-authentication
    # -----------------------------------------------------------------

    def _looks_unauthenticated(self, response: HTTPResponse) -> bool:
        if response.status_code in (401, 403):
            return True
        final_url = (response.url or "").lower()
        if any(p in final_url for p in _LOGIN_REDIRECT_PATTERNS):
            return True
        if response.status_code in (200, 302):
            text = (response.text or "")[:4000].lower()
            if any(p in text for p in _AUTH_FAILURE_BODY_PATTERNS):
                return True
        return False

    async def ensure_healthy(self, role: str) -> bool:
        """
        Check whether an account's session still looks authenticated and,
        if not, attempt a transparent re-login. Returns True if the account
        can be used.
        """
        account = self.accounts.get(role)
        if account is None:
            return False

        now = time.time()
        if now - account.last_revalidated < self.revalidation_interval and account.healthy:
            return True

        account.last_revalidated = now

        if not _AUTH_ENGINE_AVAILABLE:
            return account.healthy

        cfg = self.auth_config_by_role.get(role)
        if cfg is None:
            return account.healthy

        try:
            engine = AuthEngine(cfg)
            new_session = await engine.login()
            if new_session.success:
                account.session = new_session
                kwargs = new_session.to_http_client_kwargs()
                account.client.cookies.update(kwargs.get("cookies", {}))
                if kwargs.get("auth_token"):
                    account.client.auth_token = kwargs["auth_token"]
                account.healthy = True
                account.revalidation_failures = 0
            else:
                account.revalidation_failures += 1
                account.healthy = account.revalidation_failures < self.max_revalidation_failures
        except Exception:
            account.revalidation_failures += 1
            account.healthy = account.revalidation_failures < self.max_revalidation_failures

        return account.healthy

    async def request_as(
        self,
        role: str,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> Optional[HTTPResponse]:
        """Issue a request as a specific account, with auto-reauth on expiry."""
        account = self.accounts.get(role)
        if account is None:
            return None

        await self.ensure_healthy(role)
        self._apply_shared_dynamic_values(account, kwargs)

        response = await account.client.request(method, url, **kwargs)
        account.touch()

        if response is not None and self._looks_unauthenticated(response):
            account.healthy = False
            if await self.ensure_healthy(role):
                response = await account.client.request(method, url, **kwargs)
                account.touch()

        return response

    # -----------------------------------------------------------------
    # Cross-account dynamic value sync (CSRF tokens, nonces, etc.)
    # -----------------------------------------------------------------

    def sync_dynamic_value(self, key: str, value: str) -> None:
        """
        Record a dynamic value (CSRF token, nonce, anti-bot cookie...) so
        every account picks it up on its next request if it shares the
        same client-side mechanism.
        """
        self._shared_dynamic_values[key] = value

    def _apply_shared_dynamic_values(self, account: ManagedAccount, kwargs: Dict[str, Any]) -> None:
        if not self._shared_dynamic_values:
            return
        headers = dict(kwargs.get("headers") or {})
        for key, value in self._shared_dynamic_values.items():
            if key.lower().startswith("header:"):
                headers.setdefault(key.split(":", 1)[1], value)
            else:
                account.client.cookies.setdefault(key, value)
        if headers:
            kwargs["headers"] = headers

    # -----------------------------------------------------------------
    # Resource Registry
    # -----------------------------------------------------------------

    def register_resource(
        self,
        param_name: str,
        value: str,
        owner_role: str,
        source_url: str,
        resource_type: str = "generic",
    ) -> OwnedResource:
        key = (param_name, value)
        existing = self._resource_index.get(key)
        if existing is not None:
            return existing

        resource = OwnedResource(
            param_name=param_name,
            value=value,
            owner_role=owner_role,
            source_url=source_url,
            resource_type=resource_type,
        )
        self.resources.append(resource)
        self._resource_index[key] = resource
        return resource

    def ingest_response(
        self,
        owner_role: str,
        url: str,
        response: HTTPResponse,
        resource_type: str = "generic",
    ) -> List[OwnedResource]:
        """
        Convenience hook: scan a crawl/scan response for resource ids and
        register every one found under the given owner role.
        """
        body = ""
        try:
            body = response.text or ""
        except Exception:
            pass

        out: List[OwnedResource] = []
        for param_name, value in extract_resource_ids(url, body):
            out.append(self.register_resource(param_name, value, owner_role, url, resource_type))
        return out

    def resources_owned_by(self, role: str) -> List[OwnedResource]:
        return [r for r in self.resources if r.owner_role == role]

    # -----------------------------------------------------------------
    # IDOR / BOLA / BFLA candidate generation
    # -----------------------------------------------------------------

    def build_idor_candidates(
        self,
        only_resource_types: Optional[Set[str]] = None,
        max_per_resource: int = 0,
    ) -> List[IDORCandidate]:
        """
        For every known resource, build one access-test candidate per
        *other* registered account ("can role B reach role A's object?").
        Pure data generation — actually sending requests is left to the
        caller / scanner so rate limiting and confirmation logic stay
        centralised in their respective engines.
        """
        candidates: List[IDORCandidate] = []
        roles = list(self.accounts.keys())

        for resource in self.resources:
            if only_resource_types and resource.resource_type not in only_resource_types:
                continue

            testers = [r for r in roles if r != resource.owner_role]
            if max_per_resource:
                testers = testers[:max_per_resource]

            for tester_role in testers:
                candidates.append(
                    IDORCandidate(
                        resource=resource,
                        tester_role=tester_role,
                        url=resource.source_url,
                        notes=(
                            f"Resource '{resource.value}' ({resource.resource_type}) owned by "
                            f"'{resource.owner_role}', testing access as '{tester_role}'"
                        ),
                    )
                )
        return candidates

    # -----------------------------------------------------------------
    # Cross-account parallel dispatch + comparison
    # -----------------------------------------------------------------

    async def cross_account_request(
        self,
        method: str,
        url: str,
        roles: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> Dict[str, Optional[HTTPResponse]]:
        """
        Send the same logical request through every (or a chosen subset
        of) registered account in parallel.
        """
        target_roles = roles or list(self.accounts.keys())

        async def _one(role: str) -> Tuple[str, Optional[HTTPResponse]]:
            resp = await self.request_as(role, method, url, **kwargs)
            return role, resp

        results = await asyncio.gather(*(_one(r) for r in target_roles))
        return dict(results)

    def analyze_matrix(
        self,
        responses: Dict[str, Optional[HTTPResponse]],
        url: str = "",
        method: str = "GET",
        leak_similarity_threshold: float = 0.85,
        segregation_similarity_threshold: float = 0.40,
    ) -> AccessMatrixReport:
        """
        Compare every pair of per-account responses and flag pairs that are
        suspiciously similar between accounts that should NOT see the same
        data (potential BOLA/IDOR leak), as well as pairs that correctly
        diverge (expected role segregation).
        """
        entries: Dict[str, AccessMatrixEntry] = {}
        for role, resp in responses.items():
            if resp is None:
                continue
            entries[role] = AccessMatrixEntry(
                role=role,
                status_code=resp.status_code,
                content_length=len(resp.content) if resp.content else 0,
                elapsed=resp.elapsed,
                response=resp,
            )

        pairwise: Dict[Tuple[str, str], SimilarityResult] = {}
        leak_pairs: List[Tuple[str, str]] = []
        segregation_pairs: List[Tuple[str, str]] = []

        for role_a, role_b in itertools.combinations(entries.keys(), 2):
            sim = self.analyzer.compare(
                entries[role_a].response, entries[role_b].response
            )
            pairwise[(role_a, role_b)] = sim

            both_2xx = entries[role_a].status_code < 300 and entries[role_b].status_code < 300
            if both_2xx and sim.score >= leak_similarity_threshold:
                leak_pairs.append((role_a, role_b))
            elif sim.score <= segregation_similarity_threshold:
                segregation_pairs.append((role_a, role_b))

        return AccessMatrixReport(
            url=url,
            method=method,
            entries=entries,
            pairwise_similarity=pairwise,
            suspicious_leak_pairs=leak_pairs,
            expected_segregation_pairs=segregation_pairs,
        )

    # -----------------------------------------------------------------
    # Introspection
    # -----------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        return {
            "accounts": {
                role: {
                    "username": acc.username,
                    "healthy": acc.healthy,
                    "last_used": acc.last_used,
                    "revalidation_failures": acc.revalidation_failures,
                }
                for role, acc in self.accounts.items()
            },
            "resources_tracked": len(self.resources),
            "resources_by_role": {
                role: len(self.resources_owned_by(role)) for role in self.accounts
            },
        }
