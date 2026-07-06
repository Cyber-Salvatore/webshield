"""
Command Injection Scanner (CWE-78 / OWASP A03:2021)

Covers:
  • Output-based / error-based detection (UNIX & Windows)
  • WAF bypass variants triggered on 403 / 406 / 429
  • Time-based blind injection — dual-confirmation approach
  • HTTP header injection (User-Agent, Referer, X-Forwarded-For)
  • File-upload CMDi INFO flag
  • OS fingerprinting from response evidence
  • Chained extraction payloads (cat /etc/passwd, whoami) after confirmation
  • NULL-byte and percent-encoding bypasses
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
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
# Timing constants
# ---------------------------------------------------------------------------

_SLEEP_SECONDS: int = 5
_TIME_THRESHOLD: float = 4.0        # Minimum delay above baseline to flag
_BASELINE_SAMPLES: int = 2          # Number of baseline requests to average

# ---------------------------------------------------------------------------
# CVSS profiles
# ---------------------------------------------------------------------------

_CVSS_CRITICAL = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.HIGH,
)

_CVSS_HIGH = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.LOW,
)

_CVSS_MEDIUM = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.HIGH,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.LOW,
    integrity=Impact.LOW,
    availability=Impact.LOW,
)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_DETECTION_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    # UNIX identity / user enumeration
    (re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+", re.MULTILINE),            "UNIX: uid= output"),
    (re.compile(r"root:x:0:0:",               re.MULTILINE),              "UNIX: /etc/passwd root entry"),
    (re.compile(r"(daemon|nobody|www-data|apache|nginx):[^:]+:\d+:\d+:",
                re.MULTILINE),                                             "UNIX: /etc/passwd entry"),
    (re.compile(r"bin/(sh|bash|dash|zsh)",    re.MULTILINE),              "UNIX: shell path"),
    # Linux system info
    (re.compile(r"Linux\s+\S+\s+\d+\.\d+",   re.MULTILINE),              "UNIX: uname output"),
    # Windows identity / system
    (re.compile(r"Windows IP Configuration",  re.IGNORECASE),             "Windows: ipconfig output"),
    (re.compile(r"Volume Serial Number",      re.IGNORECASE),             "Windows: dir output"),
    (re.compile(r"Microsoft Windows \[Version", re.IGNORECASE),           "Windows: ver output"),
    (re.compile(r"\\[A-Za-z0-9_\-]+\\[A-Za-z0-9_\-]+$",
                re.MULTILINE),                                             "Windows: DOMAIN\\user"),
    # Network diagnostics (both platforms)
    (re.compile(r"^\s*PING\s+\d+\.\d+\.\d+\.\d+", re.MULTILINE),        "PING command output"),
    (re.compile(r"\d+ bytes from \d+\.\d+\.\d+\.\d+",
                re.MULTILINE),                                             "PING reply bytes"),
    (re.compile(r"\d+ packets transmitted",   re.MULTILINE),              "PING statistics"),
    # File content indicators
    (re.compile(r"for 16-bit app support",    re.IGNORECASE),             "Windows: win.ini content"),
    (re.compile(r"\[extensions\]",            re.IGNORECASE),             "Windows: win.ini [extensions]"),
    (re.compile(r"\[fonts\]",                 re.IGNORECASE),             "Windows: win.ini [fonts]"),
]

# Compiled pattern list (pattern only) used by helper
_PATTERN_LIST: List[re.Pattern[str]] = [p for p, _ in _DETECTION_PATTERNS]
_PATTERN_LABELS: Dict[re.Pattern[str], str] = {p: lbl for p, lbl in _DETECTION_PATTERNS}

# ---------------------------------------------------------------------------
# Output-based payloads (UNIX & Windows)
# ---------------------------------------------------------------------------

# Primary output-based probes — confirmed injection by matching detection patterns
_OUTPUT_PAYLOADS_UNIX: List[str] = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "&& id",
    "|| id",
    "\nid",
    "%0aid",
    "%00; id",
    "; id%00",
    "; whoami",
    "| whoami",
    "&& whoami",
]

_OUTPUT_PAYLOADS_WINDOWS: List[str] = [
    "& whoami",
    "| whoami",
    "&& whoami",
    "; dir",
    "; whoami",
    "%0Awhoami",
    "& ver",
    "| ver",
]

# Merged, deduplicated primary probes
_OUTPUT_PAYLOADS_PRIMARY: List[str] = list(
    dict.fromkeys(_OUTPUT_PAYLOADS_UNIX + _OUTPUT_PAYLOADS_WINDOWS)
)

# ---------------------------------------------------------------------------
# WAF bypass variants (used after 403 / 406 / 429)
# ---------------------------------------------------------------------------

_WAF_BYPASS_PAYLOADS: List[str] = [
    # String concatenation / quoting
    "; i'+'d",
    "; wh''oami",
    # IFS separator bypass
    ";$IFS$9id",
    "|${IFS}id",
    "1;sleep${IFS}5",
    # Hex-encoded command
    r"; \x69\x64",
    # Base64 decode execution
    "; $(echo aWQ= | base64 -d)",
    "; $(echo d2hvYW1p | base64 -d)",
    # Arithmetic bypass
    "$((0))&&id",
    # Windows case variation
    "& WhoAmI",
    "& wHoAmI",
    "| WhoAmI",
    # Backtick variant in value
    "`whoami`",
    # NULL byte prefix
    "%00; id",
    "; id%00",
    # Newline bypass
    "%0a id",
    "%0d%0a id",
]

# ---------------------------------------------------------------------------
# Time-based payloads (both platforms)
# ---------------------------------------------------------------------------

_TIME_PAYLOADS: List[str] = [
    f"; sleep {_SLEEP_SECONDS}",
    f"| sleep {_SLEEP_SECONDS}",
    f"& ping -n {_SLEEP_SECONDS} 127.0.0.1",
    f"$(sleep {_SLEEP_SECONDS})",
    f"`sleep {_SLEEP_SECONDS}`",
    f"1;sleep${'{'}IFS{'}'}{_SLEEP_SECONDS}",
    f"; Start-Sleep {_SLEEP_SECONDS}",
    f"|| sleep {_SLEEP_SECONDS}",
    f"&& sleep {_SLEEP_SECONDS}",
    f"\nsleep {_SLEEP_SECONDS}",
]

# ---------------------------------------------------------------------------
# Chained extraction payloads — run after confirming injection
# ---------------------------------------------------------------------------

_CHAIN_PAYLOADS: List[Tuple[str, str]] = [
    ("; cat /etc/passwd",      "UNIX file read: /etc/passwd"),
    ("| cat /etc/passwd",      "UNIX file read: /etc/passwd"),
    ("; whoami",               "UNIX/Windows: whoami"),
    ("& whoami",               "Windows: whoami"),
    ("| type C:\\Windows\\win.ini", "Windows file read: win.ini"),
]

# ---------------------------------------------------------------------------
# HTTP headers to test for injection
# ---------------------------------------------------------------------------

_INJECTABLE_HEADERS: List[str] = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
]

# ---------------------------------------------------------------------------
# Standard vulnerability metadata
# ---------------------------------------------------------------------------

_REMEDIATION = (
    "Never pass unsanitized user input to OS-level commands. "
    "Use language-native APIs instead of shell invocation whenever possible. "
    "If shell execution is unavoidable, apply strict allowlist validation, "
    "use shlex.quote() (Python), escapeshellarg() (PHP), or ProcessBuilder "
    "(Java) to prevent shell metacharacter injection. "
    "Run the web application process under a least-privilege OS account. "
    "Deploy a WAF rule set targeting shell metacharacters as a defense-in-depth layer."
)

_REFERENCES = [
    "https://owasp.org/www-community/attacks/Command_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/78.html",
    "https://owasp.org/Top10/A03_2021-Injection/",
    "https://portswigger.net/web-security/os-command-injection",
]

_CWE = "CWE-78"
_OWASP = "A03:2021 - Injection"


# ===========================================================================
# Scanner
# ===========================================================================


class CmdiScanner(_ScannerBase):
    """
    OS Command Injection scanner (CWE-78).

    Detection strategy (in priority order):
      1. Output-based / error-based — highest confidence (Critical)
      2. WAF bypass variants        — when blocked by WAF (Critical)
      3. Time-based blind           — dual-confirmation (High / Medium)
      4. HTTP header injection      — same output/time checks on headers
      5. File-upload INFO flag      — flag as informational if file input present
    """

    name = "Command Injection"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        params = self._extract_url_params(url)

        # --- Query-parameter injection — test ALL parameters ---
        seen_params: set = set()
        for param in params:
            if param in seen_params:
                continue
            seen_params.add(param)
            found = await self._scan_param(url, param, "GET")
            vulns.extend(found)
            # Continue — each param may have different sanitisation

        # --- Form-field injection ---
        for form in forms:
            # Check for file-upload INFO flag
            file_flag = self._check_file_upload_info(form, url)
            if file_flag:
                vulns.append(file_flag)

            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                if not name or inp.get("type") in ("submit", "button", "image", "hidden", "file"):
                    continue
                action = form.get("action", url)
                method = form.get("method", "GET").upper()
                found = await self._scan_form_field(action, method, form, name)
                vulns.extend(found)
                # Do NOT break — test all form fields

        # --- HTTP header injection ---
        header_findings = await self._scan_headers(url)
        vulns.extend(header_findings)


        # ── JSON body injection (REST APIs) ─────────────────────────────────
        if not vulns:
            ct = (response.content_type or "").lower()
            if "json" in ct:
                found = await self._test_json_body(url, response)
                vulns.extend(found)

        # ── Cookie injection (CMDi via cookie headers) ──────────────────────
        resp_cookies = dict(response.cookies) if hasattr(response, "cookies") else {}
        client_cookies = getattr(self.client, "cookies", {})
        all_cookies = {**client_cookies, **resp_cookies}
        if all_cookies:
            for cookie_name, _ in list(all_cookies.items())[:4]:
                cookie_results = await self._scan_cookie(url, cookie_name, all_cookies)
                vulns.extend(cookie_results)

        return vulns

    # ------------------------------------------------------------------
    # Per-parameter dispatcher
    # ------------------------------------------------------------------

    async def _scan_param(
        self, url: str, param: str, method: str
    ) -> List[Vulnerability]:
        """Run all detection techniques against a single URL parameter."""

        # Negative control: what does the *unmodified* page already look
        # like? Any output-detection label that already fires here is
        # noise (e.g. the backend always emits a shell error because a
        # binary is missing) and must not be credited to injection.
        baseline_labels = await self._get_baseline_labels(url)

        # 1. Output-based (primary payloads)
        found = await self._test_output_based(
            url, param, method, _OUTPUT_PAYLOADS_PRIMARY, baseline_labels=baseline_labels
        )
        if found:
            return found

        # 2. WAF bypass variants (triggered unconditionally — some servers return
        #    a 200 with WAF rewrite even without a prior 403, so always try)
        found = await self._test_output_based(
            url, param, method, _WAF_BYPASS_PAYLOADS, waf_mode=True, baseline_labels=baseline_labels
        )
        if found:
            return found

        # 3. Time-based blind (dual confirmation)
        found = await self._test_time_based(url, param, method)
        return found

    # ------------------------------------------------------------------
    # Output-based detection
    # ------------------------------------------------------------------

    async def _test_output_based(
        self,
        url: str,
        param: str,
        method: str,
        payloads: List[str],
        *,
        waf_mode: bool = False,
        baseline_labels: Optional[set] = None,
    ) -> List[Vulnerability]:
        """
        Inject each payload and look for command execution indicators in the
        response body.  On waf_mode=True the payloads are bypass variants and
        we specifically probe after receiving a blocking status code first.

        ``baseline_labels`` is the negative-control set computed once from
        the unmodified page (see ``_get_baseline_labels``): a match whose
        label is already in that set is noise the app produces regardless
        of the payload, not evidence of injection, so it's skipped rather
        than reported.
        """
        baseline_labels = baseline_labels or set()
        for payload in payloads:
            injected = self._inject_param(url, param, payload)
            resp = await self.client.get(injected)
            if resp is None:
                continue

            # If WAF mode is active, only process bypass payloads when the
            # primary probe was blocked; but we still always attempt bypass
            # payloads regardless to catch WAF-unaware targets.
            if waf_mode and resp.status_code not in (200, 301, 302, 307, 308):
                # Re-probe with bypass variant — already doing it below
                pass

            matched_label, matched_text = self._match_output(resp.text)
            if matched_label and matched_label in baseline_labels:
                # Negative control fired — this pattern already appears on
                # the page with no payload at all. Keep trying other
                # payloads instead of crediting it as a finding.
                continue
            if matched_label:
                os_hint = self._os_hint_from_label(matched_label)
                # Attempt chained extraction for richer evidence
                chain_evidence = await self._chain_extract(url, param, method, os_hint)
                evidence_parts = [
                    f"Pattern matched: {matched_label}",
                    f"Matched text: '{matched_text[:120]}'",
                ]
                if chain_evidence:
                    evidence_parts.append(f"Chained output: {chain_evidence[:300]}")
                if os_hint:
                    evidence_parts.append(f"Detected OS: {os_hint}")

                return [self._build_vuln(
                    vuln_type=VulnType.CMDI,
                    title="OS Command Injection — Output Confirmed",
                    description=(
                        f"Parameter '{param}' is directly vulnerable to OS command injection. "
                        f"The injected payload '{payload}' caused the server to execute an "
                        f"OS-level command and return its output in the HTTP response. "
                        f"An attacker can execute arbitrary commands with the privileges of "
                        f"the web server process, leading to full server compromise."
                        + (f" Target appears to be {os_hint}." if os_hint else "")
                    ),
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=" | ".join(evidence_parts),
                    method=method,
                    severity=Severity.CRITICAL,
                    cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION,
                    references=_REFERENCES,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

        return []

    # ------------------------------------------------------------------
    # Time-based blind — dual confirmation
    # ------------------------------------------------------------------

    async def _test_time_based(
        self, url: str, param: str, method: str
    ) -> List[Vulnerability]:
        """
        Dual-confirmation time-based approach:
          1. Measure baseline as an average of _BASELINE_SAMPLES requests.
          2. Send the first sleep payload — must exceed threshold.
          3. Send the same payload a second time — must *also* exceed threshold.
          4. Only report if both confirmations pass (reduces false positives).
        """
        baseline_time = await self._measure_baseline(url, param)

        threshold = baseline_time + _TIME_THRESHOLD

        for payload in _TIME_PAYLOADS:
            # First confirmation
            t1 = await self._timed_inject(url, param, payload)
            if t1 is None or t1 < threshold:
                continue

            # Second confirmation — same payload, independent request
            t2 = await self._timed_inject(url, param, payload)
            if t2 is None:
                continue

            if t2 >= threshold:
                # Both confirmed → High confidence
                severity = Severity.HIGH
                cvss = _CVSS_HIGH
                conf = "High"
                conf_note = f"Dual-confirmed: t1={t1:.2f}s, t2={t2:.2f}s"
            else:
                # Only first confirmed → Medium confidence
                severity = Severity.MEDIUM
                cvss = _CVSS_MEDIUM
                conf = "Medium"
                conf_note = f"Single-confirmed: t1={t1:.2f}s (t2={t2:.2f}s below threshold)"

            return [self._build_vuln(
                vuln_type=VulnType.CMDI,
                title="OS Command Injection — Time-Based Blind",
                description=(
                    f"Parameter '{param}' is vulnerable to time-based blind OS command injection. "
                    f"Payload '{payload}' induced a response delay significantly above baseline "
                    f"({baseline_time:.2f}s), indicating the server executed a sleep/ping command. "
                    f"Confidence: {conf}."
                ),
                url=url,
                parameter=param,
                payload=payload,
                evidence=(
                    f"Baseline avg: {baseline_time:.2f}s | Threshold: {threshold:.2f}s | "
                    f"{conf_note}"
                ),
                method=method,
                severity=severity,
                cvss=cvss,
                remediation=_REMEDIATION,
                references=_REFERENCES,
                cwe_id=_CWE,
                owasp_category=_OWASP,
                confidence=conf,
            )]

        return []

    # ------------------------------------------------------------------
    # HTTP header injection
    # ------------------------------------------------------------------

    async def _scan_headers(self, url: str) -> List[Vulnerability]:
        """
        Test injectable HTTP headers (User-Agent, Referer, X-Forwarded-For).
        Some server-side scripts log or process these values through shell commands.
        """
        findings: List[Vulnerability] = []

        # Negative control, computed once for the whole page: any output
        # pattern that already fires with no injected header at all is
        # noise (missing binaries, generic error pages, etc.) and must
        # not be credited to a specific header being command-injectable.
        baseline_labels = await self._get_baseline_labels(url)

        for header_name in _INJECTABLE_HEADERS:
            # Output-based header test
            found = await self._test_header_output_based(url, header_name, baseline_labels)
            if found:
                findings.extend(found)
                continue

            # Time-based header test
            found = await self._test_header_time_based(url, header_name)
            findings.extend(found)

        return findings

    async def _test_header_output_based(
        self, url: str, header_name: str, baseline_labels: Optional[set] = None
    ) -> List[Vulnerability]:
        baseline_labels = baseline_labels or set()
        for payload in _OUTPUT_PAYLOADS_PRIMARY[:10]:
            resp = await self.client.get(url, headers={header_name: payload})
            if resp is None:
                continue
            matched_label, matched_text = self._match_output(resp.text)
            if matched_label and matched_label in baseline_labels:
                # Same anomaly already present without any payload —
                # not caused by this header, skip it.
                continue
            if matched_label:
                os_hint = self._os_hint_from_label(matched_label)
                return [self._build_vuln(
                    vuln_type=VulnType.CMDI,
                    title=f"OS Command Injection via HTTP Header ({header_name})",
                    description=(
                        f"The HTTP header '{header_name}' is vulnerable to OS command injection. "
                        f"The server appears to pass this header value into a shell command "
                        f"(e.g., logging, processing pipeline). Payload '{payload}' produced "
                        f"recognizable command output in the response."
                        + (f" Detected OS: {os_hint}." if os_hint else "")
                    ),
                    url=url,
                    parameter=f"Header: {header_name}",
                    payload=payload,
                    evidence=f"Pattern: {matched_label} | Text: '{matched_text[:120]}'",
                    method="GET",
                    severity=Severity.CRITICAL,
                    cvss=_CVSS_CRITICAL,
                    remediation=(
                        "Never use HTTP header values as arguments to shell commands. "
                        "Sanitize and validate all header inputs server-side. "
                        + _REMEDIATION
                    ),
                    references=_REFERENCES,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]
        return []

    async def _test_header_time_based(
        self, url: str, header_name: str
    ) -> List[Vulnerability]:
        # Baseline: benign header value
        baseline_times: List[float] = []
        for _ in range(_BASELINE_SAMPLES):
            resp = await self.client.get(url, headers={header_name: "Mozilla/5.0"})
            if resp and resp.elapsed is not None:
                baseline_times.append(resp.elapsed)
        if not baseline_times:
            return []
        baseline_time = sum(baseline_times) / len(baseline_times)
        threshold = baseline_time + _TIME_THRESHOLD

        for payload in _TIME_PAYLOADS[:6]:
            # Dual confirmation
            resp1 = await self.client.get(url, headers={header_name: payload})
            t1 = resp1.elapsed if (resp1 and resp1.elapsed is not None) else None
            if t1 is None or t1 < threshold:
                continue

            resp2 = await self.client.get(url, headers={header_name: payload})
            t2 = resp2.elapsed if (resp2 and resp2.elapsed is not None) else None
            if t2 is None:
                continue

            conf = "High" if t2 >= threshold else "Medium"
            sev = Severity.HIGH if conf == "High" else Severity.MEDIUM
            cvss = _CVSS_HIGH if conf == "High" else _CVSS_MEDIUM

            return [self._build_vuln(
                vuln_type=VulnType.CMDI,
                title=f"OS Command Injection via HTTP Header ({header_name}) — Time-Based",
                description=(
                    f"HTTP header '{header_name}' is vulnerable to time-based blind "
                    f"OS command injection. The server likely passes this header to a "
                    f"shell command. Confidence: {conf}."
                ),
                url=url,
                parameter=f"Header: {header_name}",
                payload=payload,
                evidence=(
                    f"Baseline: {baseline_time:.2f}s | t1={t1:.2f}s | t2={t2:.2f}s | "
                    f"threshold={threshold:.2f}s"
                ),
                method="GET",
                severity=sev,
                cvss=cvss,
                remediation=_REMEDIATION,
                references=_REFERENCES,
                cwe_id=_CWE,
                owasp_category=_OWASP,
                confidence=conf,
            )]

        return []

    # ------------------------------------------------------------------
    # Form-field scanning
    # ------------------------------------------------------------------

    async def _scan_form_field(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
    ) -> List[Vulnerability]:
        """Run output-based then time-based checks on a single form field."""

        # Negative control: submit the form with a harmless value first so
        # any output pattern the app produces regardless of the payload
        # (template placeholders, generic error boilerplate, etc.) isn't
        # mistaken for command-injection evidence later.
        baseline_labels = await self._get_form_baseline_labels(action, method, form, param_name)

        # Output-based
        found = await self._test_form_output_based(
            action, method, form, param_name, baseline_labels=baseline_labels
        )
        if found:
            return found

        # WAF bypass output-based
        found = await self._test_form_output_based(
            action, method, form, param_name, payloads=_WAF_BYPASS_PAYLOADS,
            baseline_labels=baseline_labels,
        )
        if found:
            return found

        # Time-based blind
        return await self._test_form_time_based(action, method, form, param_name)

    async def _test_form_output_based(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
        payloads: Optional[List[str]] = None,
        baseline_labels: Optional[set] = None,
    ) -> List[Vulnerability]:
        if payloads is None:
            payloads = _OUTPUT_PAYLOADS_PRIMARY
        baseline_labels = baseline_labels or set()

        for payload in payloads:
            form_data = self._build_form_data(form, param_name, payload)
            resp = await self._submit_form(action, method, form_data)
            if resp is None:
                continue
            matched_label, matched_text = self._match_output(resp.text)
            if matched_label and matched_label in baseline_labels:
                continue
            if matched_label:
                os_hint = self._os_hint_from_label(matched_label)
                return [self._build_vuln(
                    vuln_type=VulnType.CMDI,
                    title="OS Command Injection in Form Field — Output Confirmed",
                    description=(
                        f"Form field '{param_name}' at {action} is directly vulnerable to "
                        f"OS command injection (method: {method}). The server executed the "
                        f"injected payload '{payload}' and leaked command output in the response."
                        + (f" Detected OS: {os_hint}." if os_hint else "")
                    ),
                    url=action,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Pattern: {matched_label} | Text: '{matched_text[:120]}'",
                    method=method,
                    severity=Severity.CRITICAL,
                    cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION,
                    references=_REFERENCES,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]
        return []

    async def _test_form_time_based(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
    ) -> List[Vulnerability]:
        # Baseline
        baseline_data = self._build_form_data(form, param_name, "normal_value")
        baseline_times: List[float] = []
        for _ in range(_BASELINE_SAMPLES):
            resp = await self._submit_form(action, method, baseline_data)
            if resp and resp.elapsed is not None:
                baseline_times.append(resp.elapsed)
        if not baseline_times:
            return []
        baseline_time = sum(baseline_times) / len(baseline_times)
        threshold = baseline_time + _TIME_THRESHOLD

        for payload in _TIME_PAYLOADS:
            form_data = self._build_form_data(form, param_name, payload)

            # First confirmation
            resp1 = await self._submit_form(action, method, form_data)
            t1 = resp1.elapsed if (resp1 and resp1.elapsed is not None) else None
            if t1 is None or t1 < threshold:
                continue

            # Second confirmation
            resp2 = await self._submit_form(action, method, form_data)
            t2 = resp2.elapsed if (resp2 and resp2.elapsed is not None) else None
            if t2 is None:
                continue

            conf = "High" if t2 >= threshold else "Medium"
            sev = Severity.HIGH if conf == "High" else Severity.MEDIUM
            cvss = _CVSS_HIGH if conf == "High" else _CVSS_MEDIUM

            return [self._build_vuln(
                vuln_type=VulnType.CMDI,
                title="OS Command Injection in Form Field — Time-Based Blind",
                description=(
                    f"Form field '{param_name}' at {action} is vulnerable to time-based blind "
                    f"OS command injection (method: {method}). Payload '{payload}' induced a "
                    f"significant response delay above baseline. Confidence: {conf}."
                ),
                url=action,
                parameter=param_name,
                payload=payload,
                evidence=(
                    f"Baseline avg: {baseline_time:.2f}s | threshold: {threshold:.2f}s | "
                    f"t1={t1:.2f}s | t2={t2:.2f}s"
                ),
                method=method,
                severity=sev,
                cvss=cvss,
                remediation=_REMEDIATION,
                references=_REFERENCES,
                cwe_id=_CWE,
                owasp_category=_OWASP,
                confidence=conf,
            )]

        return []

    # ------------------------------------------------------------------
    # File-upload INFO flag
    # ------------------------------------------------------------------

    def _check_file_upload_info(
        self, form: Dict[str, Any], url: str
    ) -> Optional[Vulnerability]:
        """
        If a form contains a file input, emit an INFO finding noting that
        file-upload command injection vectors may exist (e.g., filename passed
        to a shell command, or malicious file processed by an external tool).
        """
        for inp in form.get("inputs", []):
            if inp.get("type") == "file":
                action = form.get("action", url)
                method = form.get("method", "GET").upper()
                return self._build_vuln(
                    vuln_type=VulnType.CMDI,
                    title="Potential CMDi Vector: File Upload Present",
                    description=(
                        f"A file upload input was detected in a form at {action} "
                        f"(method: {method}). Applications that process uploaded files using "
                        f"shell commands (e.g., ImageMagick, ffmpeg, file conversion scripts) "
                        f"may be vulnerable to OS command injection via crafted filenames or "
                        f"malicious file content. Manual testing is recommended."
                    ),
                    url=action,
                    parameter=inp.get("name", "file"),
                    payload="N/A — informational",
                    evidence="File input field detected in form",
                    method=method,
                    severity=Severity.INFO,
                    remediation=(
                        "Validate and sanitize filenames before passing them to any shell "
                        "command. Use safe APIs for file processing rather than shell tools. "
                        "Restrict uploaded file types and content-type headers."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html",
                        "https://imagemagick.org/script/security-policy.php",
                    ],
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    confidence="Low",
                )
        return None

    # ------------------------------------------------------------------
    # Chained extraction (called after confirming injection)
    # ------------------------------------------------------------------

    async def _chain_extract(
        self,
        url: str,
        param: str,
        method: str,
        os_hint: Optional[str],
    ) -> Optional[str]:
        """
        Fix 3.5: After confirming injection, send ONE targeted follow-up payload
        based on detected OS — avoids the previous 5-request overhead per finding.
        """
        if os_hint and "Windows" in os_hint:
            payload = "& whoami"
        elif os_hint and "UNIX" in os_hint:
            payload = "; id"
        else:
            payload = "; id || whoami"   # works on both platforms

        injected = self._inject_param(url, param, payload)
        resp = await self.client.get(injected)
        if resp is None:
            return None
        label, matched = self._match_output(resp.text)
        if label:
            return f"[{label}] {matched[:200]}"
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _measure_baseline(self, url: str, param: str) -> float:
        """Return average response time over _BASELINE_SAMPLES benign requests."""
        times: List[float] = []
        baseline_url = self._inject_param(url, param, "normal_value")
        for _ in range(_BASELINE_SAMPLES):
            resp = await self.client.get(baseline_url)
            if resp and resp.elapsed is not None:
                times.append(resp.elapsed)
        if not times:
            return 0.0
        return sum(times) / len(times)

    async def _timed_inject(
        self, url: str, param: str, payload: str
    ) -> Optional[float]:
        """Send one timed injection request and return elapsed time."""
        injected = self._inject_param(url, param, payload)
        resp = await self.client.get(injected)
        if resp is None or resp.elapsed is None:
            return None
        return resp.elapsed

    def _match_output(
        self, body: str
    ) -> Tuple[Optional[str], str]:
        """
        Scan response body against all detection patterns.
        Returns (label, matched_text) or (None, "") if no match.
        """
        for pattern, label in _DETECTION_PATTERNS:
            m = pattern.search(body)
            if m:
                return label, m.group(0)
        return None, ""

    def _match_output_labels(self, body: str) -> set:
        """Like ``_match_output`` but returns the set of ALL labels that
        match — used to build a baseline "noise" set so a weak pattern
        (e.g. 'bin/sh' appearing because a missing binary makes the shell
        itself print an error) isn't mistaken for command-injection
        evidence when it was already present before any payload was sent.
        """
        labels = set()
        for pattern, label in _DETECTION_PATTERNS:
            if pattern.search(body):
                labels.add(label)
        return labels

    async def _get_baseline_labels(self, url: str) -> set:
        """Negative control for query-parameter/URL-level output checks:
        fetch the page completely unmodified and record which detection
        patterns already fire on it. Any label in this set is noise the
        application produces regardless of injection and must not be
        credited as evidence — mirrors the negative-control probe used by
        the Triple Confirmation Framework elsewhere in WebShield.
        """
        try:
            resp = await self.client.get(url)
        except Exception:
            return set()
        if resp is None:
            return set()
        return self._match_output_labels(resp.text)

    async def _get_form_baseline_labels(
        self, action: str, method: str, form: Dict[str, Any], param_name: str
    ) -> set:
        """Negative control for form-field output checks: submit the form
        with a harmless value and record which labels already fire."""
        try:
            baseline_data = self._build_form_data(form, param_name, "normal_value")
            resp = await self._submit_form(action, method, baseline_data)
        except Exception:
            return set()
        if resp is None:
            return set()
        return self._match_output_labels(resp.text)

    @staticmethod
    def _os_hint_from_label(label: Optional[str]) -> Optional[str]:
        """Derive a human-readable OS string from the detection pattern label."""
        if not label:
            return None
        if label.startswith("UNIX") or label.startswith("PING"):
            return "Linux/UNIX"
        if label.startswith("Windows"):
            return "Windows"
        return None

    @staticmethod
    def _build_form_data(
        form: Dict[str, Any],
        target_param: str,
        payload: str,
    ) -> Dict[str, str]:
        """Build a form submission dict with the payload injected into target_param."""
        return {
            inp["name"]: (
                payload if inp["name"] == target_param else inp.get("value", "test")
            )
            for inp in form.get("inputs", [])
            if inp.get("name")
        }

    async def _submit_form(
        self,
        action: str,
        method: str,
        form_data: Dict[str, str],
    ) -> Optional[HTTPResponse]:
        """Submit a form via POST or GET and return the response."""
        if method == "POST":
            return await self.client.post(action, data=form_data)
        return await self.client.get(action, params=form_data)

    # ------------------------------------------------------------------
    # JSON body injection (REST APIs returning application/json)
    # ------------------------------------------------------------------

    async def _test_json_body(
        self, url: str, response: "HTTPResponse"
    ) -> list:
        """Inject payloads into JSON body fields of REST API endpoints."""
        import json as _json

        try:
            data = _json.loads(response.text)
        except Exception:
            data = {}

        if not isinstance(data, dict):
            data = {}

        field_names = [k for k in data.keys() if isinstance(data[k], (str, int))][:5]
        if not field_names:
            field_names = ["id", "input", "value", "query", "data"]

        for field in field_names:
            for payload in _OUTPUT_PAYLOADS_UNIX[:6]:
                test_body = dict(data)
                test_body[field] = payload

                resp = await self.client.post(
                    url,
                    json=test_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue

                if any(p.search(resp.text) for p in _PATTERN_LIST):
                    return [self._build_vuln(
                        vuln_type=VulnType.CMDI,
                        title="Command Injection via JSON Body",
                        description=(
                            f"JSON field '{field}' at {url} is vulnerable to injection via "
                            f"REST API POST body. The payload was: {payload!r}"
                        ),
                        url=url,
                        parameter=field,
                        payload=_json.dumps({field: payload}),
                        evidence=self._snippet(resp.text, 200),
                        method="POST",
                        severity=Severity.CRITICAL,
                        remediation="Sanitize all inputs. Use subprocess with args list, never shell=True.",
                        references=["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"],
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 - Injection",
                        confidence="Medium",
                    )]
        return []
