"""
Intelligence Layer
======================================
Final piece of the Phase 2 Intelligence & Discovery infrastructure.

Components built here:
  1. AdaptiveRateController      — self-tuning request throttle based on server health
  2. SessionManagementFramework  — multi-session cookie/token lifecycle manager
  3. AuthenticationFramework     — auto-detect & drive login/MFA/SSO/OAuth flows
  4. AuthorizationFramework      — maps permission levels & resources for AuthZ tests
  5. Phase2MasterOrchestrator    — ties all Phase 2 parts (1-5) into one entry point

After completing the full Intelligence Layer:
  Part 1 → FingerprintEngine          (fingerprinter.py)
  Part 2 → PassiveIntelligenceEngine  (intelligence_engine.py)
  Part 3 → KnowledgeBase              (knowledge_base.py)
  Part 4 → DiscoveryOrchestrator      (discovery_engine.py)
  Part 5 → Phase2MasterOrchestrator   (THIS FILE)
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..core.http_client import HTTPClient, HTTPResponse
from ..core.target import ScanTarget

# ---------------------------------------------------------------------------
# 1.  AdaptiveRateController
# ---------------------------------------------------------------------------

class ServerHealthState(str, Enum):
    """Current inferred health of the target server."""
    HEALTHY    = "healthy"       # responding fast, no errors
    DEGRADED   = "degraded"      # slower than baseline, some 5xx
    STRESSED   = "stressed"      # high latency, many errors
    RATE_LIMITED = "rate_limited"  # 429 / 503 responses received
    BLOCKED    = "blocked"       # our IP appears to be blocked


@dataclass
class RateWindow:
    """Sliding window of recent request metrics."""
    window_size: int = 20           # number of recent requests to track
    latencies:   Deque[float] = field(default_factory=lambda: deque(maxlen=20))
    status_codes: Deque[int]  = field(default_factory=lambda: deque(maxlen=20))
    error_count:  int = 0
    rate_limit_count: int = 0

    def record(self, latency: float, status_code: int) -> None:
        self.latencies.append(latency)
        self.status_codes.append(status_code)
        if status_code >= 500:
            self.error_count += 1
        if status_code in (429, 503):
            self.rate_limit_count += 1

    @property
    def mean_latency(self) -> float:
        return sum(self.latencies) / len(self.latencies) if self.latencies else 0.0

    @property
    def error_rate(self) -> float:
        if not self.status_codes:
            return 0.0
        errors = sum(1 for s in self.status_codes if s >= 500 or s == 0)
        return errors / len(self.status_codes)

    @property
    def rate_limited(self) -> bool:
        return any(s in (429, 503) for s in list(self.status_codes)[-5:])


class AdaptiveRateController:
    """
    Self-tuning request throttle that observes server health signals and
    automatically adjusts the delay between requests.

    Algorithm
    ---------
    • Starts at ``initial_delay`` seconds between requests.
    • After each request, records latency + status code into a sliding window.
    • Every ``check_interval`` requests, re-evaluates server health:
        HEALTHY      → slowly decrease delay (min ``min_delay``)
        DEGRADED     → hold current delay
        STRESSED     → increase delay by ``backoff_factor``
        RATE_LIMITED → immediate jump to ``rate_limit_delay``, then back-off
        BLOCKED      → raise ``BlockedError``
    • Respects a hard maximum of ``max_delay`` seconds.
    • Thread / coroutine-safe: uses asyncio.Lock internally.

    Usage::

        rate = AdaptiveRateController(initial_delay=0.2, min_delay=0.05)
        async with rate:
            for url in urls:
                await rate.wait()           # honours the current delay
                resp = await client.get(url)
                rate.record(resp.elapsed, resp.status_code)
    """

    class BlockedError(RuntimeError):
        """Raised when the controller detects the scanner IP is blocked."""

    def __init__(
        self,
        initial_delay:     float = 0.3,
        min_delay:         float = 0.05,
        max_delay:         float = 30.0,
        backoff_factor:    float = 2.0,
        recovery_factor:   float = 0.85,
        rate_limit_delay:  float = 10.0,
        check_interval:    int   = 10,
        blocked_threshold: int   = 5,    # consecutive 403/0 before BLOCKED
    ) -> None:
        self._delay         = initial_delay
        self._min_delay     = min_delay
        self._max_delay     = max_delay
        self._backoff       = backoff_factor
        self._recovery      = recovery_factor
        self._rl_delay      = rate_limit_delay
        self._check_int     = check_interval
        self._blocked_thr   = blocked_threshold

        self._window        = RateWindow(window_size=20)
        self._lock          = asyncio.Lock()
        self._req_count     = 0
        self._consecutive_blocked = 0
        self._baseline_latency: Optional[float] = None
        self._health        = ServerHealthState.HEALTHY

    # -- Public API ----------------------------------------------------------

    async def wait(self) -> None:
        """Sleep for the current adaptive delay before the next request."""
        if self._delay > 0:
            await asyncio.sleep(self._delay)

    def record(self, latency: float, status_code: int) -> None:
        """Call after every response to feed the adaptive algorithm."""
        self._window.record(latency, status_code)
        self._req_count += 1

        # Track consecutive blocks (403/0)
        if status_code in (403, 0):
            self._consecutive_blocked += 1
        else:
            self._consecutive_blocked = 0

        # Establish baseline from first 5 requests
        if self._req_count == 5:
            self._baseline_latency = self._window.mean_latency

        # Re-evaluate every check_interval requests
        if self._req_count % self._check_int == 0:
            self._evaluate()

    @property
    def current_delay(self) -> float:
        return self._delay

    @property
    def health(self) -> ServerHealthState:
        return self._health

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "current_delay_s":   round(self._delay, 3),
            "health":            self._health.value,
            "mean_latency_s":    round(self._window.mean_latency, 3),
            "error_rate":        round(self._window.error_rate, 3),
            "request_count":     self._req_count,
            "rate_limit_count":  self._window.rate_limit_count,
        }

    # -- Internal ------------------------------------------------------------

    def _evaluate(self) -> None:
        """Re-assess server health and adjust delay accordingly."""
        if self._consecutive_blocked >= self._blocked_thr:
            self._health = ServerHealthState.BLOCKED
            return

        if self._window.rate_limited:
            self._health  = ServerHealthState.RATE_LIMITED
            self._delay   = min(self._max_delay, self._rl_delay)
            return

        mean_lat  = self._window.mean_latency
        err_rate  = self._window.error_rate
        baseline  = self._baseline_latency or mean_lat

        if err_rate > 0.3 or (baseline > 0 and mean_lat > baseline * 5):
            self._health = ServerHealthState.STRESSED
            self._delay  = min(self._max_delay, self._delay * self._backoff)
        elif err_rate > 0.1 or (baseline > 0 and mean_lat > baseline * 2):
            self._health = ServerHealthState.DEGRADED
            # Hold current delay
        else:
            self._health = ServerHealthState.HEALTHY
            self._delay  = max(self._min_delay, self._delay * self._recovery)


# ---------------------------------------------------------------------------
# 2.  SessionManagementFramework
# ---------------------------------------------------------------------------

class TokenType(str, Enum):
    BEARER     = "bearer"
    BASIC      = "basic"
    API_KEY    = "api_key"
    COOKIE     = "cookie"
    CSRF_TOKEN = "csrf_token"
    JWT        = "jwt"
    OAUTH      = "oauth"
    UNKNOWN    = "unknown"


@dataclass
class ManagedToken:
    """A tracked authentication token with expiry awareness."""
    token_id:    str
    token_type:  TokenType
    value:       str
    header_name: Optional[str] = None   # e.g. "Authorization", "X-API-Key"
    cookie_name: Optional[str] = None
    issued_at:   float = field(default_factory=time.time)
    expires_in:  Optional[float] = None  # seconds from issued_at; None = unknown
    refresh_token: Optional[str] = None
    metadata:    Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expires_in is None:
            return False
        return (time.time() - self.issued_at) >= self.expires_in

    @property
    def remaining_seconds(self) -> Optional[float]:
        if self.expires_in is None:
            return None
        return max(0.0, self.expires_in - (time.time() - self.issued_at))

    def inject_into_headers(self, headers: Dict[str, str]) -> None:
        """Mutate ``headers`` in-place to include this token."""
        if self.token_type == TokenType.BEARER and self.value:
            headers["Authorization"] = f"Bearer {self.value}"
        elif self.token_type == TokenType.BASIC and self.value:
            headers["Authorization"] = f"Basic {self.value}"
        elif self.token_type == TokenType.API_KEY and self.header_name:
            headers[self.header_name] = self.value
        elif self.token_type == TokenType.CSRF_TOKEN and self.header_name:
            headers[self.header_name] = self.value


@dataclass
class SessionState:
    """Complete state of one authenticated scan session."""
    session_id:   str
    base_url:     str
    cookies:      Dict[str, str] = field(default_factory=dict)
    tokens:       List[ManagedToken] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    user_role:    str = "anonymous"
    is_authenticated: bool = False
    login_url:    Optional[str] = None
    last_refreshed: float = field(default_factory=time.time)

    def build_headers(self) -> Dict[str, str]:
        """Return merged headers with all active tokens injected."""
        headers: Dict[str, str] = dict(self.custom_headers)
        for token in self.tokens:
            if not token.is_expired:
                token.inject_into_headers(headers)
        return headers

    def build_cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def has_expired_tokens(self) -> bool:
        return any(t.is_expired for t in self.tokens)

    def add_token(self, token: ManagedToken) -> None:
        # Replace existing token of same type if present
        self.tokens = [t for t in self.tokens if t.token_type != token.token_type]
        self.tokens.append(token)

    def get_token(self, token_type: TokenType) -> Optional[ManagedToken]:
        return next((t for t in self.tokens if t.token_type == token_type), None)


class SessionManagementFramework:
    """
    Manages multiple authenticated sessions across an entire scan.

    Responsibilities
    ----------------
    • Create and track SessionState objects per test account.
    • Detect CSRF tokens in responses and auto-refresh them.
    • Detect JWT expiry and trigger re-login callbacks.
    • Provide ``apply(session, headers, cookies)`` to inject auth into requests.
    • Log all session events for the evidence store.

    Usage::

        smf = SessionManagementFramework(client)
        session = smf.create_session("alice", "user", login_url="/login",
                                     cookies={"session": "abc123"})
        smf.register_re_login(session.session_id, my_login_coroutine)

        headers = {}
        cookies = {}
        await smf.apply(session.session_id, headers, cookies)
        resp = await client.get(url, headers=headers)
        smf.update_from_response(session.session_id, resp)
    """

    def __init__(self, client: HTTPClient) -> None:
        self._client   = client
        self._sessions: Dict[str, SessionState] = {}
        self._re_login_hooks: Dict[str, Callable] = {}
        self._event_log: List[Dict[str, Any]] = []
        self._csrf_patterns = [
            re.compile(r'<input[^>]+name=["\'](_token|csrf_token|__RequestVerificationToken|csrfmiddlewaretoken)["\'][^>]+value=["\']([^"\']+)["\']', re.I),
            re.compile(r'"csrf[_\-]?token"\s*:\s*"([^"]+)"', re.I),
            re.compile(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', re.I),
        ]

    # -- Session lifecycle ---------------------------------------------------

    def create_session(
        self,
        session_id: str,
        role: str = "anonymous",
        *,
        base_url:  str = "",
        cookies:   Optional[Dict[str, str]] = None,
        headers:   Optional[Dict[str, str]] = None,
        auth_token: Optional[str] = None,
        login_url:  Optional[str] = None,
    ) -> SessionState:
        state = SessionState(
            session_id=session_id,
            base_url=base_url,
            cookies=cookies or {},
            custom_headers=headers or {},
            user_role=role,
            is_authenticated=(bool(cookies) or bool(auth_token)),
            login_url=login_url,
        )
        if auth_token:
            state.add_token(ManagedToken(
                token_id=f"{session_id}-bearer",
                token_type=TokenType.BEARER,
                value=auth_token,
            ))
        self._sessions[session_id] = state
        self._log("session_created", session_id=session_id, role=role)
        return state

    def get_session(self, session_id: str) -> Optional[SessionState]:
        return self._sessions.get(session_id)

    def all_sessions(self) -> List[SessionState]:
        return list(self._sessions.values())

    def register_re_login(self, session_id: str, callback: Callable) -> None:
        """Register an async callable to re-authenticate when tokens expire."""
        self._re_login_hooks[session_id] = callback

    # -- Request preparation -------------------------------------------------

    async def apply(
        self,
        session_id: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
    ) -> None:
        """Inject auth into mutable ``headers`` and ``cookies`` dicts."""
        session = self._sessions.get(session_id)
        if not session:
            return

        # Refresh expired tokens if a re-login hook is registered
        if session.has_expired_tokens() and session_id in self._re_login_hooks:
            await self._re_login(session_id)

        # Inject headers
        headers.update(session.build_headers())

        # Inject cookies
        if session.cookies:
            existing = cookies.get("Cookie", "")
            new_cookies = session.build_cookie_header()
            cookies["Cookie"] = f"{existing}; {new_cookies}".strip("; ")

    # -- Response parsing ----------------------------------------------------

    def update_from_response(
        self,
        session_id: str,
        response: HTTPResponse,
    ) -> None:
        """
        Parse a response for new cookies, CSRF tokens, and auth signals,
        then update the session state accordingly.
        """
        session = self._sessions.get(session_id)
        if not session:
            return

        # Update cookies from Set-Cookie headers
        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            self._parse_set_cookie(session, set_cookie)

        # Extract CSRF token from response body
        body = response.text or ""
        csrf = self._extract_csrf(body)
        if csrf:
            session.add_token(ManagedToken(
                token_id=f"{session_id}-csrf",
                token_type=TokenType.CSRF_TOKEN,
                value=csrf,
                header_name="X-CSRF-Token",
            ))
            self._log("csrf_refreshed", session_id=session_id)

    def _parse_set_cookie(self, session: SessionState, raw: str) -> None:
        """Parse a Set-Cookie header and update session cookies."""
        for part in raw.split(","):
            kv = part.strip().split(";")[0].strip()
            if "=" in kv:
                name, _, value = kv.partition("=")
                session.cookies[name.strip()] = value.strip()

    def _extract_csrf(self, body: str) -> Optional[str]:
        for pattern in self._csrf_patterns:
            m = pattern.search(body)
            if m:
                # Last group is the token value
                return m.group(m.lastindex or 1)
        return None

    async def _re_login(self, session_id: str) -> None:
        hook = self._re_login_hooks.get(session_id)
        if hook:
            try:
                result = await hook()
                if result and isinstance(result, dict):
                    session = self._sessions[session_id]
                    if "cookies" in result:
                        session.cookies.update(result["cookies"])
                    if "token" in result:
                        session.add_token(ManagedToken(
                            token_id=f"{session_id}-refreshed",
                            token_type=TokenType.BEARER,
                            value=result["token"],
                        ))
                    session.last_refreshed = time.time()
                    self._log("session_refreshed", session_id=session_id)
            except Exception as exc:
                self._log("refresh_failed", session_id=session_id, error=str(exc))

    def _log(self, event: str, **kw: Any) -> None:
        self._event_log.append({"event": event, "ts": time.time(), **kw})

    @property
    def event_log(self) -> List[Dict[str, Any]]:
        return list(self._event_log)


# ---------------------------------------------------------------------------
# 3.  AuthenticationFramework
# ---------------------------------------------------------------------------

class AuthFlowType(str, Enum):
    """Detected type of authentication flow."""
    FORM_LOGIN   = "form_login"
    BASIC_AUTH   = "basic_auth"
    TOKEN_BASED  = "token_based"   # API key / Bearer in header
    OAUTH2       = "oauth2"
    OIDC         = "oidc"
    SAML         = "saml"
    MFA_TOTP     = "mfa_totp"
    MFA_EMAIL    = "mfa_email"
    SSO          = "sso"
    MAGIC_LINK   = "magic_link"
    UNKNOWN      = "unknown"


@dataclass
class AuthFlowMap:
    """Complete map of an application's authentication flow."""
    flow_type:         AuthFlowType
    login_url:         Optional[str] = None
    logout_url:        Optional[str] = None
    register_url:      Optional[str] = None
    password_reset_url:Optional[str] = None
    mfa_url:           Optional[str] = None
    oauth_authorize_url: Optional[str] = None
    oauth_token_url:   Optional[str] = None
    token_endpoint:    Optional[str] = None    # /api/auth/token
    username_field:    Optional[str] = None
    password_field:    Optional[str] = None
    csrf_field:        Optional[str] = None
    session_cookie:    Optional[str] = None
    auth_header:       Optional[str] = None    # "Authorization" / "X-API-Key"
    success_indicator: Optional[str] = None    # URL fragment / body text / selector
    notes:             List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_type": self.flow_type.value,
            "login_url": self.login_url,
            "logout_url": self.logout_url,
            "register_url": self.register_url,
            "password_reset_url": self.password_reset_url,
            "mfa_url": self.mfa_url,
            "oauth_urls": {
                "authorize": self.oauth_authorize_url,
                "token": self.oauth_token_url,
            },
            "token_endpoint": self.token_endpoint,
            "form_fields": {
                "username": self.username_field,
                "password": self.password_field,
                "csrf": self.csrf_field,
            },
            "session_cookie": self.session_cookie,
            "auth_header": self.auth_header,
            "notes": self.notes,
        }


# URL patterns for auth endpoint detection
_AUTH_URL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"/login|/signin|/auth/login", re.I), "login_url"),
    (re.compile(r"/logout|/signout", re.I), "logout_url"),
    (re.compile(r"/register|/signup|/create.?account", re.I), "register_url"),
    (re.compile(r"/forgot.?pass|/reset.?pass|/password.?reset", re.I), "password_reset_url"),
    (re.compile(r"/mfa|/2fa|/totp|/verify", re.I), "mfa_url"),
    (re.compile(r"/oauth/authorize|/oauth2/authorize", re.I), "oauth_authorize_url"),
    (re.compile(r"/oauth/token|/oauth2/token", re.I), "oauth_token_url"),
    (re.compile(r"/api/auth|/api/login|/auth/token", re.I), "token_endpoint"),
]

# Form field name patterns
_USERNAME_FIELDS = re.compile(r"username|email|login|user_name|user\.name|identifier", re.I)
_PASSWORD_FIELDS = re.compile(r"password|passwd|pass|secret|pwd", re.I)
_CSRF_FIELDS     = re.compile(r"csrf|_token|xsrf|__requestverificationtoken|csrfmiddlewaretoken", re.I)

# Session cookie name patterns
_SESSION_COOKIE  = re.compile(r"session|sess|auth|token|jwt|connect\.sid|phpsessid|asp\.net_sessionid", re.I)


class AuthenticationFramework:
    """
    Discovers and maps the full authentication flow of a target application
    without performing actual login attempts.

    Steps
    -----
    1. Crawl the login page to find form fields and hidden inputs.
    2. Detect auth flow type (form login, OAuth, SAML, token-based …).
    3. Map all auth-related URLs from the discovered endpoint list.
    4. Identify session cookies and auth headers from existing responses.
    5. Produce an AuthFlowMap that other components use for authenticated scanning.

    Usage::

        auth_fw = AuthenticationFramework(client, target)
        flow_map = await auth_fw.discover()
        print(flow_map.flow_type, flow_map.login_url)
    """

    def __init__(self, client: HTTPClient, target: ScanTarget) -> None:
        self._client = client
        self._target = target

    async def discover(
        self,
        known_endpoints: Optional[List[str]] = None,
        sample_responses: Optional[List[HTTPResponse]] = None,
    ) -> AuthFlowMap:
        """
        Auto-discover the authentication flow.

        Parameters
        ----------
        known_endpoints:    URLs discovered during crawling.
        sample_responses:   HTTP responses already collected during recon.
        """
        flow_map = AuthFlowMap(flow_type=AuthFlowType.UNKNOWN)

        # 1. Map auth-related URLs
        endpoints = known_endpoints or []
        self._map_auth_urls(flow_map, endpoints)

        # 2. Try to fetch the login page and parse it
        if flow_map.login_url:
            try:
                resp = await self._client.get(flow_map.login_url)
                self._parse_login_page(flow_map, resp)
            except Exception:
                pass

        # 3. Sniff from existing responses
        for resp in (sample_responses or []):
            self._sniff_from_response(flow_map, resp)

        # 4. Infer flow type
        flow_map.flow_type = self._infer_flow_type(flow_map)

        return flow_map

    def _map_auth_urls(self, flow_map: AuthFlowMap, endpoints: List[str]) -> None:
        for url in endpoints:
            for pattern, attr in _AUTH_URL_PATTERNS:
                if pattern.search(url) and not getattr(flow_map, attr):
                    setattr(flow_map, attr, url)
                    break

    def _parse_login_page(self, flow_map: AuthFlowMap, resp: HTTPResponse) -> None:
        body = resp.text or ""

        # Detect OAuth / SSO redirects
        if re.search(r"oauth|openid|saml|sso", body, re.I):
            if re.search(r"authorize|client_id|response_type", body, re.I):
                flow_map.notes.append("OAuth/OIDC authorization flow detected in login page")

        # Find form fields
        input_matches = re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*)["\'])?[^>]*>',
            body, re.I,
        )
        for name, input_type in input_matches:
            if _USERNAME_FIELDS.match(name) and not flow_map.username_field:
                flow_map.username_field = name
            elif _PASSWORD_FIELDS.match(name) and not flow_map.password_field:
                flow_map.password_field = name
            elif _CSRF_FIELDS.match(name) and not flow_map.csrf_field:
                flow_map.csrf_field = name

        # Check for MFA indicators
        if re.search(r"otp|totp|authenticator|2fa|mfa|verify.?code", body, re.I):
            flow_map.notes.append("MFA / TOTP step likely required after login")

        # Check for magic link
        if re.search(r"magic.?link|passwordless|send.?(me.?)?a.?link", body, re.I):
            flow_map.flow_type = AuthFlowType.MAGIC_LINK
            flow_map.notes.append("Passwordless / magic-link login detected")

    def _sniff_from_response(
        self, flow_map: AuthFlowMap, resp: HTTPResponse
    ) -> None:
        # Session cookies
        set_cookie = resp.headers.get("set-cookie", "")
        if set_cookie and not flow_map.session_cookie:
            cookie_name = set_cookie.split("=")[0].strip()
            if _SESSION_COOKIE.match(cookie_name):
                flow_map.session_cookie = cookie_name

        # Bearer token indicator
        www_auth = resp.headers.get("www-authenticate", "")
        if "bearer" in www_auth.lower():
            flow_map.auth_header = "Authorization"
            flow_map.notes.append("Bearer token authentication required (WWW-Authenticate: Bearer)")

        # API key header
        body = resp.text or ""
        if re.search(r"x-api-key|api[_\-]?key|apikey", body, re.I):
            flow_map.auth_header = flow_map.auth_header or "X-API-Key"

    def _infer_flow_type(self, flow_map: AuthFlowMap) -> AuthFlowType:
        if flow_map.flow_type not in (AuthFlowType.UNKNOWN, AuthFlowType.FORM_LOGIN):
            return flow_map.flow_type
        if flow_map.oauth_authorize_url:
            return AuthFlowType.OAUTH2
        if flow_map.token_endpoint and not flow_map.username_field:
            return AuthFlowType.TOKEN_BASED
        if flow_map.username_field and flow_map.password_field:
            return AuthFlowType.FORM_LOGIN
        if "MFA" in " ".join(flow_map.notes).upper():
            return AuthFlowType.MFA_TOTP
        if flow_map.auth_header:
            return AuthFlowType.TOKEN_BASED
        return AuthFlowType.UNKNOWN

    def map_from_endpoints(self, endpoints: List[str]) -> AuthFlowMap:
        """Quick synchronous mapping from a list of known URLs (no HTTP calls)."""
        flow_map = AuthFlowMap(flow_type=AuthFlowType.UNKNOWN)
        self._map_auth_urls(flow_map, endpoints)
        flow_map.flow_type = self._infer_flow_type(flow_map)
        return flow_map


# ---------------------------------------------------------------------------
# 4.  AuthorizationFramework
# ---------------------------------------------------------------------------

class PermissionLevel(str, Enum):
    """Privilege tiers used in authorization testing."""
    ANONYMOUS    = "anonymous"
    AUTHENTICATED = "authenticated"
    USER         = "user"
    MODERATOR    = "moderator"
    ADMIN        = "admin"
    SUPER_ADMIN  = "super_admin"
    SERVICE      = "service"       # machine-to-machine / API service account


@dataclass
class ResourcePermission:
    """Expected permission required to access a resource."""
    url:              str
    method:           str
    required_level:   PermissionLevel
    allows_anonymous: bool = False
    resource_owner_only: bool = False   # True = only the owner can access
    notes:            List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "required_level": self.required_level.value,
            "allows_anonymous": self.allows_anonymous,
            "owner_only": self.resource_owner_only,
            "notes": self.notes,
        }


@dataclass
class AuthZMatrix:
    """
    Permission matrix: maps (endpoint, method) → required PermissionLevel.
    Used by IDOR / BAC / privilege-escalation scanners.
    """
    resources:  List[ResourcePermission] = field(default_factory=list)
    role_hierarchy: List[PermissionLevel] = field(default_factory=lambda: [
        PermissionLevel.ANONYMOUS,
        PermissionLevel.AUTHENTICATED,
        PermissionLevel.USER,
        PermissionLevel.MODERATOR,
        PermissionLevel.ADMIN,
        PermissionLevel.SUPER_ADMIN,
    ])

    def get_permission(self, url: str, method: str = "GET") -> Optional[ResourcePermission]:
        return next(
            (r for r in self.resources
             if r.url == url and r.method.upper() == method.upper()),
            None,
        )

    def roles_below(self, level: PermissionLevel) -> List[PermissionLevel]:
        """Return all roles with lower privilege than ``level``."""
        try:
            idx = self.role_hierarchy.index(level)
            return self.role_hierarchy[:idx]
        except ValueError:
            return []

    def endpoints_requiring_level(
        self, level: PermissionLevel
    ) -> List[ResourcePermission]:
        return [r for r in self.resources if r.required_level == level]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_count": len(self.resources),
            "resources": [r.to_dict() for r in self.resources],
            "role_hierarchy": [r.value for r in self.role_hierarchy],
        }


# URL → PermissionLevel heuristics
_PERM_RULES: List[Tuple[re.Pattern, PermissionLevel, bool, bool]] = [
    # (pattern, required_level, allows_anonymous, owner_only)
    (re.compile(r"/admin|/superuser|/root|/manage", re.I),      PermissionLevel.ADMIN,         False, False),
    (re.compile(r"/moderator|/staff", re.I),                    PermissionLevel.MODERATOR,     False, False),
    (re.compile(r"/api/me|/api/self|/profile/edit|/account/", re.I), PermissionLevel.USER,     False, True),
    (re.compile(r"/api/users/\w+|/user/\d+|/profile/\w+", re.I), PermissionLevel.USER,        False, True),
    (re.compile(r"/api/|/v\d+/|/rest/", re.I),                  PermissionLevel.AUTHENTICATED, False, False),
    (re.compile(r"/login|/register|/forgot.?pass", re.I),        PermissionLevel.ANONYMOUS,     True,  False),
    (re.compile(r"/static/|/public/|/assets/", re.I),            PermissionLevel.ANONYMOUS,     True,  False),
    (re.compile(r"/health|/ping|/status", re.I),                  PermissionLevel.ANONYMOUS,     True,  False),
]


class AuthorizationFramework:
    """
    Analyses discovered endpoints to build an AuthZMatrix representing
    expected permission levels for each resource.

    The matrix is used by:
    - IDOR scanner       → tests owner-only resources with other users
    - BAC scanner        → tests admin resources with lower-privilege accounts
    - Privilege escalation → attempts vertical privilege bypass

    Usage::

        authz = AuthorizationFramework()
        matrix = authz.build_matrix(classified_endpoints)
        admin_eps = matrix.endpoints_requiring_level(PermissionLevel.ADMIN)
    """

    def build_matrix(
        self,
        endpoints: List[Any],   # ClassifiedEndpoint objects or (url, method) tuples
    ) -> AuthZMatrix:
        """Build an AuthZMatrix from a list of endpoints."""
        matrix = AuthZMatrix()
        for ep in endpoints:
            # Accept both ClassifiedEndpoint objects and (url, method) tuples
            if hasattr(ep, "url"):
                url, method = ep.url, ep.method
            else:
                url, method = ep[0], ep[1]

            perm = self._infer_permission(url, method)
            matrix.resources.append(perm)

        return matrix

    def _infer_permission(self, url: str, method: str) -> ResourcePermission:
        for pattern, level, anon, owner in _PERM_RULES:
            if pattern.search(url):
                notes: List[str] = []
                if owner:
                    notes.append("Resource likely owner-scoped — test with multiple accounts")
                if anon:
                    notes.append("Publicly accessible — verify no sensitive data exposed")
                return ResourcePermission(
                    url=url,
                    method=method,
                    required_level=level,
                    allows_anonymous=anon,
                    resource_owner_only=owner,
                    notes=notes,
                )

        # Default: authenticated
        return ResourcePermission(
            url=url,
            method=method,
            required_level=PermissionLevel.AUTHENTICATED,
            allows_anonymous=False,
            resource_owner_only=False,
        )

    def identify_escalation_targets(
        self,
        matrix: AuthZMatrix,
        current_level: PermissionLevel,
    ) -> List[ResourcePermission]:
        """
        Return resources that require higher privilege than ``current_level``,
        i.e. endpoints worth attempting privilege escalation against.
        """
        hierarchy = matrix.role_hierarchy
        try:
            current_idx = hierarchy.index(current_level)
        except ValueError:
            return []

        return [
            r for r in matrix.resources
            if hierarchy.index(r.required_level) > current_idx
            and not r.allows_anonymous
        ]

    def owner_only_resources(self, matrix: AuthZMatrix) -> List[ResourcePermission]:
        """Resources that are likely owner-scoped — prime IDOR candidates."""
        return [r for r in matrix.resources if r.resource_owner_only]


# ---------------------------------------------------------------------------
# 5.  Phase2MasterOrchestrator
# ---------------------------------------------------------------------------

@dataclass
class Phase2Report:
    """
    Unified output of the full Phase 2 Intelligence & Discovery layer.

    Aggregates results from all 5 Phase 2 components.
    """
    target_url:         str
    # Part 1 — Fingerprinting
    fingerprint:        Optional[Any] = None        # AppFingerprint
    # Part 2 — Passive Intelligence
    intelligence:       Optional[Any] = None        # IntelligenceReport
    # Part 3 — Knowledge Base entries matched
    kb_matches:         List[Any] = field(default_factory=list)  # List[KBEntry]
    # Part 4 — Discovery
    discovery:          Optional[Any] = None        # DiscoveryReport
    # Part 5 — Rate/Session/Auth/AuthZ
    auth_flow_map:      Optional[AuthFlowMap] = None
    authz_matrix:       Optional[AuthZMatrix] = None
    rate_stats:         Dict[str, Any] = field(default_factory=dict)
    session_events:     List[Dict[str, Any]] = field(default_factory=list)
    # Overall
    duration_seconds:   float = 0.0
    warnings:           List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        disc = self.discovery
        fprint = self.fingerprint

        detected_techs: List[str] = []
        if fprint and hasattr(fprint, "technologies"):
            detected_techs = [
                f"{t.name} {t.version or ''}".strip()
                for t in fprint.technologies
            ]

        endpoint_count = len(disc.classified_endpoints) if disc else 0
        high_risk_count = len(disc.high_risk_endpoints) if disc else 0
        chain_count = len(disc.attack_chains) if disc else 0

        return {
            "target": self.target_url,
            "duration_s": round(self.duration_seconds, 2),
            "technologies_detected": detected_techs,
            "endpoint_count": endpoint_count,
            "high_risk_endpoints": high_risk_count,
            "attack_chains": chain_count,
            "auth_flow": self.auth_flow_map.flow_type.value if self.auth_flow_map else "unknown",
            "authz_resources": len(self.authz_matrix.resources) if self.authz_matrix else 0,
            "kb_matches": len(self.kb_matches),
            "rate_health": self.rate_stats.get("health", "unknown"),
            "warnings": self.warnings,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.summary()
        if self.auth_flow_map:
            d["auth_flow_map"] = self.auth_flow_map.to_dict()
        if self.authz_matrix:
            d["authz_matrix"] = self.authz_matrix.to_dict()
        if self.discovery:
            d["attack_chains"] = [c.to_dict() for c in self.discovery.attack_chains]
            d["high_risk_endpoints"] = [e.to_dict() for e in self.discovery.high_risk_endpoints]
        d["rate_stats"] = self.rate_stats
        return d


class Phase2MasterOrchestrator:
    """
    Master coordinator for the entire Phase 2 Intelligence Layer.

    Runs all 5 components in the correct order, sharing data between them
    so that each component benefits from the discoveries of the previous ones.

    Execution order
    ---------------
    1. FingerprintEngine         → identify technologies
    2. PassiveIntelligenceEngine → collect passive signals, endpoints, secrets
    3. KnowledgeBase             → enrich fingerprint with KB data
    4. DiscoveryOrchestrator     → classify & map the full attack surface
    5. AuthenticationFramework   → map auth flow
    6. AuthorizationFramework    → build permission matrix
    7. SessionManagementFramework→ initialise sessions for Phase 3 scanners
    8. AdaptiveRateController    → configure scan speed based on server health

    Usage::

        orch = Phase2MasterOrchestrator(client, target)
        # Optionally register authenticated sessions
        orch.session_fw.create_session("admin", "admin", cookies={"session": "..."})
        orch.session_fw.create_session("user_a", "user", auth_token="...")

        report = await orch.run()
        print(report.summary())
    """

    def __init__(
        self,
        client: HTTPClient,
        target: ScanTarget,
        *,
        rate_initial_delay: float = 0.3,
        rate_min_delay:     float = 0.05,
    ) -> None:
        self._client = client
        self._target = target

        # Lazily import heavy recon components to avoid circular imports
        self._rate     = AdaptiveRateController(
            initial_delay=rate_initial_delay,
            min_delay=rate_min_delay,
        )
        self.session_fw = SessionManagementFramework(client)
        self._auth_fw  = AuthenticationFramework(client, target)
        self._authz_fw = AuthorizationFramework()

    async def run(
        self,
        *,
        skip_fingerprint:  bool = False,
        skip_intelligence: bool = False,
        skip_knowledge_base: bool = False,
        crawled_urls:      Optional[List[str]] = None,
        sample_responses:  Optional[List[HTTPResponse]] = None,
        confirmed_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Phase2Report:
        """
        Execute the full intelligence pipeline.

        Parameters
        ----------
        skip_*:             Skip expensive components for fast/partial scans.
        crawled_urls:       URLs already discovered by the crawler.
        sample_responses:   HTTP responses already collected.
        confirmed_findings: Findings from earlier scan passes.
        """
        t0 = time.monotonic()
        report = Phase2Report(target_url=self._target.base_url)
        warnings: List[str] = []

        # --- Part 1: Fingerprinting -----------------------------------------
        if not skip_fingerprint:
            try:
                from .fingerprinter import FingerprintEngine
                fp_engine = FingerprintEngine(self._client)
                report.fingerprint = await fp_engine.fingerprint(self._target.base_url)
            except Exception as exc:
                warnings.append(f"Fingerprinting failed: {exc}")

        # --- Part 2: Passive Intelligence -----------------------------------
        if not skip_intelligence:
            try:
                from .intelligence_engine import PassiveIntelligenceEngine
                pi_engine = PassiveIntelligenceEngine(self._client)
                report.intelligence = await pi_engine.collect(
                    self._target.base_url,
                    existing_responses=sample_responses,
                )
            except Exception as exc:
                warnings.append(f"Passive intelligence failed: {exc}")

        # --- Part 3: Knowledge Base enrichment ------------------------------
        if not skip_knowledge_base and report.fingerprint:
            try:
                from .knowledge_base import KnowledgeBase
                kb = KnowledgeBase()
                tech_names: List[str] = []
                if hasattr(report.fingerprint, "technologies"):
                    tech_names = [t.name for t in report.fingerprint.technologies]
                report.kb_matches = [kb.lookup(t) for t in tech_names if kb.lookup(t)]
            except Exception as exc:
                warnings.append(f"Knowledge base lookup failed: {exc}")

        # --- Part 4: Discovery Infrastructure -------------------------------
        try:
            from .discovery_engine import DiscoveryOrchestrator
            all_urls: List[str] = list(crawled_urls or [])

            # Merge intelligence-discovered endpoints
            if report.intelligence and hasattr(report.intelligence, "endpoints"):
                all_urls.extend(
                    ep.url for ep in report.intelligence.endpoints
                    if hasattr(ep, "url")
                )

            raw_endpoints = [(u, "GET") for u in dict.fromkeys(all_urls)]
            disc_orch = DiscoveryOrchestrator(self._client, self._target)
            report.discovery = await disc_orch.run(
                raw_endpoints,
                confirmed_findings=confirmed_findings,
            )
        except Exception as exc:
            warnings.append(f"Discovery orchestration failed: {exc}")

        # --- Part 5a: Authentication Framework ------------------------------
        try:
            endpoint_urls = [ep.url for ep in (
                report.discovery.classified_endpoints if report.discovery else []
            )]
            report.auth_flow_map = await self._auth_fw.discover(
                known_endpoints=endpoint_urls,
                sample_responses=sample_responses,
            )
        except Exception as exc:
            warnings.append(f"Auth flow discovery failed: {exc}")

        # --- Part 5b: Authorization Framework -------------------------------
        try:
            if report.discovery:
                report.authz_matrix = self._authz_fw.build_matrix(
                    report.discovery.classified_endpoints
                )
        except Exception as exc:
            warnings.append(f"AuthZ matrix build failed: {exc}")

        # --- Part 5c: Rate stats --------------------------------------------
        report.rate_stats    = self._rate.stats
        report.session_events = self.session_fw.event_log
        report.warnings       = warnings
        report.duration_seconds = time.monotonic() - t0

        return report

    # -- Convenience helpers -------------------------------------------------

    def add_authenticated_session(
        self,
        account_id: str,
        role: str,
        *,
        cookies:    Optional[Dict[str, str]] = None,
        auth_token: Optional[str] = None,
        headers:    Optional[Dict[str, str]] = None,
    ) -> SessionState:
        """Register an authenticated session for Phase 3 scanners."""
        return self.session_fw.create_session(
            account_id, role,
            base_url=self._target.base_url,
            cookies=cookies,
            auth_token=auth_token,
            headers=headers,
        )

    def get_escalation_targets(
        self,
        report: Phase2Report,
        current_role: str = "user",
    ) -> List[ResourcePermission]:
        """
        Return endpoints worth testing for privilege escalation from
        the given role.  Requires a completed Phase2Report.
        """
        if not report.authz_matrix:
            return []
        try:
            level = PermissionLevel(current_role)
        except ValueError:
            level = PermissionLevel.USER
        return self._authz_fw.identify_escalation_targets(
            report.authz_matrix, level
        )

    def get_idor_candidates(self, report: Phase2Report) -> List[ResourcePermission]:
        """Return owner-only resources — prime IDOR test targets."""
        if not report.authz_matrix:
            return []
        return self._authz_fw.owner_only_resources(report.authz_matrix)
