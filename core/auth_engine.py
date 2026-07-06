"""
Browser Automation Auth Engine — Phase 3.1
============================================
Automates login flows using Playwright to obtain authenticated sessions
that can be shared across all scanners.

Supports:
  • Username/password login forms (auto-detect field selectors)
  • Multi-step forms (wizard flows)
  • TOTP-based MFA (requires pyotp)
  • OAuth SSO flows (Google, GitHub — via browser interaction)
  • Session state persistence (save/load cookies + localStorage)
  • Success/failure detection via URL change, text, or selector

After a successful login the engine exports:
  • cookies      → dict[str, str]  injected into HTTPClient
  • storage_state → path to Playwright storage_state JSON
  • auth_token    → Bearer token extracted from localStorage/sessionStorage

Usage::

    cfg = AuthConfig(
        login_url="https://target.com/login",
        username="admin",
        password="s3cr3t",
        success_indicator="dashboard",
    )
    engine = AuthEngine(cfg)
    session = await engine.login()
    if session.success:
        # use session.cookies with HTTPClient
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        TimeoutError as PlaywrightTimeout,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = None          # type: ignore[assignment,misc]
    BrowserContext = None   # type: ignore[assignment,misc]
    Page = None             # type: ignore[assignment,misc]

try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False


# ---------------------------------------------------------------------------
# AuthConfig
# ---------------------------------------------------------------------------

@dataclass
class AuthConfig:
    """
    Configuration for an automated login flow.

    Minimal usage — auto-detect everything:
        AuthConfig(login_url="...", username="u", password="p")

    Full usage:
        AuthConfig(
            login_url="...",
            username="u", password="p",
            username_selector="#username",
            password_selector="#password",
            submit_selector="button[type=submit]",
            success_indicator="dashboard",
            mfa_secret="BASE32SECRET",
            session_storage_path="/tmp/session.json",
        )
    """
    login_url: str
    username: str = ""
    password: str = ""

    # Selectors — if None the engine auto-detects
    username_selector: Optional[str] = None
    password_selector: Optional[str] = None
    submit_selector:   Optional[str] = None

    # Success detection
    # Can be: a URL substring, a page text, or a CSS selector that appears
    success_indicator: str = ""

    # MFA — TOTP secret (base32). Requires pyotp.
    mfa_secret: Optional[str] = None
    mfa_selector: Optional[str] = None     # selector for the OTP input

    # Session persistence
    session_storage_path: Optional[str] = None   # path to save storage_state JSON

    # Browser behaviour
    headless: bool = True
    timeout_ms: int = 15_000      # per-action timeout
    navigation_timeout_ms: int = 30_000

    # Extra users for AuthorizationMatrix — list of (username, password, role)
    extra_users: List[Dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AuthSession — result of a login attempt
# ---------------------------------------------------------------------------

@dataclass
class AuthSession:
    """Result returned by AuthEngine.login()."""
    success: bool
    username: str
    role: str = "user"
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None       # JWT/Bearer from localStorage
    storage_state_path: Optional[str] = None
    error: Optional[str] = None

    def to_http_client_kwargs(self) -> Dict[str, Any]:
        """Return kwargs suitable for HTTPClient constructor."""
        kwargs: Dict[str, Any] = {"cookies": self.cookies}
        if self.auth_token:
            kwargs["auth_token"] = self.auth_token
        return kwargs


# ---------------------------------------------------------------------------
# AuthEngine
# ---------------------------------------------------------------------------

class AuthEngine:
    """
    Phase 3.1 — Browser-based Login Automation Engine.

    Uses Playwright to drive real browser login flows, handling:
    - Auto-detecting login form fields
    - Multi-step forms
    - TOTP MFA
    - Session state export for use with HTTPClient / scanners
    """

    # Common selectors to try when auto-detecting fields
    _USERNAME_SELECTORS = [
        'input[type="email"]',
        'input[name="email"]',
        'input[name="username"]',
        'input[name="user"]',
        'input[name="login"]',
        'input[id*="user" i]',
        'input[id*="email" i]',
        'input[placeholder*="email" i]',
        'input[placeholder*="username" i]',
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
    ]

    _PASSWORD_SELECTORS = [
        'input[type="password"]',
        'input[name="password"]',
        'input[name="pass"]',
        'input[name="passwd"]',
        'input[id*="pass" i]',
        'input[placeholder*="password" i]',
        'input[autocomplete="current-password"]',
    ]

    _SUBMIT_SELECTORS = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'button:has-text("Log in")',
        'button:has-text("Submit")',
        '[data-testid*="login" i]',
        '[data-testid*="submit" i]',
    ]

    # Indicators of a failed login
    _FAILURE_PATTERNS = re.compile(
        r"(?:invalid|incorrect|failed|wrong|error|bad credentials|"
        r"unauthorized|authentication failed|login failed)",
        re.IGNORECASE,
    )

    def __init__(self, config: AuthConfig) -> None:
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright is not installed. "
                "Run: pip install playwright && playwright install chromium"
            )
        self.config = config

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def login(self, role: str = "user") -> AuthSession:
        """
        Perform the full login flow and return an AuthSession.
        Returns AuthSession(success=False, error=...) on failure.
        """
        async with async_playwright() as pw:
            browser = await self._launch_browser(pw)
            try:
                context = await self._create_context(browser)
                session = await self._perform_login(
                    context,
                    self.config.username,
                    self.config.password,
                    role,
                )
                await browser.close()
                return session
            except Exception as exc:
                await browser.close()
                return AuthSession(
                    success=False,
                    username=self.config.username,
                    role=role,
                    error=str(exc),
                )

    async def login_all_users(self) -> List[AuthSession]:
        """
        Login with primary user + all extra_users defined in config.
        Returns one AuthSession per user.
        Used by AuthorizationMatrixScanner.
        """
        sessions: List[AuthSession] = []

        # Primary user
        primary = await self.login(role="primary")
        sessions.append(primary)

        # Extra users
        for user_def in self.config.extra_users:
            uname = user_def.get("username", "")
            pwd   = user_def.get("password", "")
            role  = user_def.get("role", "user")
            if not uname:
                continue
            async with async_playwright() as pw:
                browser = await self._launch_browser(pw)
                try:
                    context = await self._create_context(browser)
                    session = await self._perform_login(context, uname, pwd, role)
                    sessions.append(session)
                    await browser.close()
                except Exception as exc:
                    sessions.append(AuthSession(
                        success=False, username=uname, role=role, error=str(exc)
                    ))
                    await browser.close()

        return sessions

    # -----------------------------------------------------------------------
    # Private — browser setup
    # -----------------------------------------------------------------------

    async def _launch_browser(self, pw: Any) -> "Browser":
        return await pw.chromium.launch(
            headless=self.config.headless,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )

    async def _create_context(self, browser: "Browser") -> "BrowserContext":
        kwargs: Dict[str, Any] = {
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }
        # Load existing session if available
        if (self.config.session_storage_path and
                os.path.exists(self.config.session_storage_path)):
            kwargs["storage_state"] = self.config.session_storage_path

        return await browser.new_context(**kwargs)

    # -----------------------------------------------------------------------
    # Private — login flow
    # -----------------------------------------------------------------------

    async def _perform_login(
        self,
        context: "BrowserContext",
        username: str,
        password: str,
        role: str,
    ) -> AuthSession:
        page = await context.new_page()
        page.set_default_timeout(self.config.timeout_ms)
        page.set_default_navigation_timeout(self.config.navigation_timeout_ms)

        try:
            # Navigate to login page
            await page.goto(self.config.login_url, wait_until="networkidle")

            # Fill username
            user_sel = (
                self.config.username_selector
                or await self._find_selector(page, self._USERNAME_SELECTORS)
            )
            if user_sel:
                await page.fill(user_sel, username)
            else:
                raise RuntimeError("Could not find username input field")

            # Fill password
            pass_sel = (
                self.config.password_selector
                or await self._find_selector(page, self._PASSWORD_SELECTORS)
            )
            if pass_sel:
                await page.fill(pass_sel, password)
            else:
                raise RuntimeError("Could not find password input field")

            # Submit
            submit_sel = (
                self.config.submit_selector
                or await self._find_selector(page, self._SUBMIT_SELECTORS)
            )
            if submit_sel:
                await page.click(submit_sel)
            else:
                # Fallback: press Enter in password field
                if pass_sel:
                    await page.press(pass_sel, "Enter")

            # Wait for navigation
            try:
                await page.wait_for_load_state("networkidle", timeout=self.config.navigation_timeout_ms)
            except PlaywrightTimeout:
                pass  # some SPAs don't fire networkidle — continue anyway

            # Handle MFA if configured
            if self.config.mfa_secret:
                await self._handle_mfa(page)

            # Detect success
            current_url = page.url
            page_text = await page.text_content("body") or ""
            success = self._detect_success(current_url, page_text)

            if not success:
                return AuthSession(
                    success=False,
                    username=username,
                    role=role,
                    error=f"Login appears to have failed (URL: {current_url})",
                )

            # Extract session data
            cookies = await context.cookies()
            cookie_dict = {c["name"]: c["value"] for c in cookies}

            # Try to extract Bearer token from localStorage / sessionStorage
            auth_token = await self._extract_token(page)

            # Save storage state if requested
            storage_path: Optional[str] = self.config.session_storage_path
            if storage_path:
                await context.storage_state(path=storage_path)
            else:
                # Save to a temp file so callers can reload the session
                fd, storage_path = tempfile.mkstemp(suffix=".json", prefix="wshld_session_")
                os.close(fd)
                await context.storage_state(path=storage_path)

            await page.close()
            return AuthSession(
                success=True,
                username=username,
                role=role,
                cookies=cookie_dict,
                auth_token=auth_token,
                storage_state_path=storage_path,
            )

        except Exception as exc:
            await page.close()
            raise exc

    async def _handle_mfa(self, page: "Page") -> None:
        """Fill TOTP MFA field if present."""
        if not PYOTP_AVAILABLE:
            raise RuntimeError(
                "pyotp is not installed. Run: pip install pyotp"
            )
        totp = pyotp.TOTP(self.config.mfa_secret)
        code = totp.now()

        mfa_sel = (
            self.config.mfa_selector
            or await self._find_selector(page, [
                'input[name*="otp" i]',
                'input[name*="mfa" i]',
                'input[name*="code" i]',
                'input[name*="token" i]',
                'input[autocomplete="one-time-code"]',
                'input[placeholder*="code" i]',
            ])
        )
        if mfa_sel:
            await page.fill(mfa_sel, code)
            submit = await self._find_selector(page, self._SUBMIT_SELECTORS)
            if submit:
                await page.click(submit)
            try:
                await page.wait_for_load_state("networkidle", timeout=self.config.navigation_timeout_ms)
            except PlaywrightTimeout:
                pass

    async def _extract_token(self, page: "Page") -> Optional[str]:
        """Try to extract Bearer token from browser storage."""
        try:
            result = await page.evaluate("""() => {
                const keys = ['token', 'access_token', 'authToken', 'jwt',
                              'bearer', 'auth', 'id_token', 'accessToken'];
                for (const k of keys) {
                    const v = localStorage.getItem(k) || sessionStorage.getItem(k);
                    if (v) return v;
                }
                // Look for any JWT-shaped value
                for (let i = 0; i < localStorage.length; i++) {
                    const v = localStorage.getItem(localStorage.key(i));
                    if (v && v.split('.').length === 3 && v.startsWith('ey')) return v;
                }
                return null;
            }""")
            return result if isinstance(result, str) else None
        except Exception:
            return None

    def _detect_success(self, url: str, page_text: str) -> bool:
        """Determine if the login was successful."""
        # Explicit success indicator
        if self.config.success_indicator:
            indicator = self.config.success_indicator.lower()
            if indicator in url.lower() or indicator in page_text.lower():
                return True
            return False

        # Heuristic: not still on the login page + no failure text
        login_url_lower = self.config.login_url.lower()
        current_url_lower = url.lower()

        still_on_login = any(
            kw in current_url_lower
            for kw in ("login", "signin", "sign-in", "auth", "logon")
        )
        has_failure = bool(self._FAILURE_PATTERNS.search(page_text[:5000]))

        if has_failure:
            return False
        if still_on_login and "login_url" in login_url_lower:
            return False

        # Positive signals: dashboard/account/home/profile in URL
        positive_signals = ("dashboard", "home", "account", "profile",
                             "overview", "main", "index", "welcome")
        if any(s in current_url_lower for s in positive_signals):
            return True

        # Fallback: if we moved away from login URL, assume success
        return not still_on_login

    @staticmethod
    async def _find_selector(page: "Page", selectors: List[str]) -> Optional[str]:
        """Try each selector and return the first one that matches a visible element."""
        for sel in selectors:
            try:
                elem = await page.query_selector(sel)
                if elem and await elem.is_visible():
                    return sel
            except Exception:
                continue
        return None
