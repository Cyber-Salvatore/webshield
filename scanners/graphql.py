"""
GraphQL Security Scanner — Professional Grade
==============================================
Coverage:
  • Endpoint discovery: 15+ common paths + content-type detection
  • Introspection enabled (full schema extraction + type count)
  • Field suggestion leak (schema enumeration without introspection)
  • Query batching abuse (DoS amplification)
  • Query depth bomb (missing depth limiting)
  • Query alias overloading (DoS via alias-amplified resolvers)
  • SQL injection via GraphQL variables (error-based)
  • NoSQL injection via GraphQL variables ($where, $gt)
  • CSRF via GraphQL (application/x-www-form-urlencoded + JSON)
  • Authorization bypass: unauthenticated mutation access
  • Information disclosure via error messages (stack traces, DB errors)
  • GraphiQL / Playground exposed in production
  • Subscription endpoint exposure

CWE  : CWE-200, CWE-89, CWE-400, CWE-352, CWE-285
OWASP: A05:2021 – Security Misconfiguration
       A03:2021 – Injection
       A01:2021 – Broken Access Control
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

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
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.CHANGED, Impact.HIGH, Impact.HIGH, Impact.HIGH)
_CVSS_HIGH = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.HIGH, Impact.LOW, Impact.NONE)
_CVSS_MEDIUM = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.LOW, Impact.NONE, Impact.NONE)
_CVSS_DOS = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.NONE, Impact.NONE, Impact.HIGH)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
_OWASP_INJECT    = "A03:2021 - Injection"
_OWASP_ACCESS    = "A01:2021 - Broken Access Control"
_REFS_GQL = [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
    "https://portswigger.net/web-security/graphql",
    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
]

# ---------------------------------------------------------------------------
# Endpoint paths
# ---------------------------------------------------------------------------

_GQL_PATHS: List[str] = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/v2/graphql", "/v3/graphql",
    "/playground", "/api/v1/graphql", "/api/v2/graphql",
    "/query", "/gql", "/graph",
    "/graphql/v1", "/graphql/v2", "/graphql/console",
    "/graphql/explorer",
]

# GraphiQL / Playground HTML signatures
_GRAPHIQL_RE = re.compile(r"graphiql|GraphQL Playground|apollo-sandbox", re.IGNORECASE)
_GQL_DATA_RE = re.compile(r'"data"\s*:', re.IGNORECASE)
_GQL_ERRORS_RE = re.compile(r'"errors"\s*:', re.IGNORECASE)
_INTROSPECTION_RE = re.compile(r'"__schema"', re.IGNORECASE)
_SUGGESTION_RE = re.compile(
    r'(?:Did you mean[^\?]*\?|"suggestions"\s*:\s*\[|similar.*field)',
    re.IGNORECASE,
)

# SQL error patterns in GraphQL responses
_SQL_ERROR_RE = re.compile(
    r"(?i)(sql syntax|mysql_fetch|ora-\d{4,5}|sqlite_exception|"
    r"pg::syntaxerror|unterminated quoted string|"
    r"division by zero|column.*does not exist|"
    r"table.*doesn't exist|data type mismatch)",
)

# NoSQL error patterns
_NOSQL_ERROR_RE = re.compile(
    r"(?i)(mongodb.*error|bson|castError|MongoServerError|"
    r"ValidationError|ObjectID.*invalid|E11000 duplicate)",
)

# Stack trace patterns
_STACKTRACE_RE = re.compile(
    r"(?i)(Traceback|at [a-zA-Z_]+\.[a-zA-Z_]+\(|"
    r"Exception in thread|java\.lang\.|"
    r"System\.NullReferenceException)",
)

# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind
      fields(includeDeprecated: true) {
        name isDeprecated deprecationReason
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}
"""

_DEPTH_BOMB: str = "{ " + "a { " * 20 + "id" + " }" * 20 + " }"

_SQLI_QUERY = """
query TestSQLi($id: String, $name: String) {
  user(id: $id) { id name email role }
}
"""
_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1 OR 1=1--",
    "' UNION SELECT null, null, null--",
    "'; DROP TABLE users;--",
    "1; SELECT SLEEP(2)--",
]

_NOSQL_QUERY = """
query TestNoSQLi($filter: JSON) {
  users(filter: $filter) { id name email }
}
"""
_NOSQL_PAYLOADS = [
    {"$gt": ""},
    {"$where": "function(){return true}"},
    {"$regex": ".*"},
    {"$ne": "invalid_value_xyz"},
]

# Alias overloading DoS
_ALIAS_COUNT = 100
_ALIAS_QUERY = "{ " + " ".join(f"a{i}: __typename" for i in range(_ALIAS_COUNT)) + " }"

# Batch DoS
_BATCH_QUERY = [{"query": "{ __typename }"} for _ in range(100)]

# Mutation auth bypass probes
_MUTATION_PROBES: List[str] = [
    """mutation { deleteUser(id: "1") { id } }""",
    """mutation { createUser(name:"hack" email:"hack@evil.com" role:"admin") { id } }""",
    """mutation { updateUser(id:"1" role:"admin") { id role } }""",
    """mutation { resetPassword(email:"admin@example.com") { success } }""",
]

# CSRF via form-urlencoded probe
_CSRF_FORM_BODY = "query=%7B+__typename+%7D"  # URL-encoded: query={ __typename }


# ===========================================================================
# Scanner
# ===========================================================================

class GraphQLScanner(_ScannerBase):
    """
    Professional GraphQL security scanner.
    Runs once per target (is_target_level=True).
    """

    name = "GraphQL"
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

        endpoints = await self._discover_endpoints(base, url, response)

        for ep in endpoints:
            vulns.extend(await self._test_endpoint(ep))

        return vulns

    # -----------------------------------------------------------------------
    # Endpoint discovery
    # -----------------------------------------------------------------------

    async def _discover_endpoints(
        self, base: str, current_url: str, response: HTTPResponse
    ) -> List[str]:
        found: List[str] = []

        # Current URL already a GQL endpoint?
        if response.is_text and (
            _GQL_DATA_RE.search(response.text) or
            _GQL_ERRORS_RE.search(response.text) or
            _GRAPHIQL_RE.search(response.text)
        ):
            found.append(current_url)

        for path in _GQL_PATHS:
            ep = urljoin(base, path)
            resp = await self.client.post(
                ep,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"},
            )
            if resp and resp.status_code in (200, 400) and resp.is_text:
                if _GQL_DATA_RE.search(resp.text) or _GQL_ERRORS_RE.search(resp.text):
                    if ep not in found:
                        found.append(ep)

        return found

    # -----------------------------------------------------------------------
    # Per-endpoint testing
    # -----------------------------------------------------------------------

    async def _test_endpoint(self, ep: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # ── Phase 1/2 original checks ─────────────────────────────────────
        vulns.extend(await self._check_graphiql_exposed(ep))
        vulns.extend(await self._check_introspection(ep))
        vulns.extend(await self._check_field_suggestions(ep))
        vulns.extend(await self._check_batch_abuse(ep))
        vulns.extend(await self._check_depth_bomb(ep))
        vulns.extend(await self._check_alias_overloading(ep))
        vulns.extend(await self._check_sqli(ep))
        vulns.extend(await self._check_nosqli(ep))
        vulns.extend(await self._check_mutation_auth_bypass(ep))
        vulns.extend(await self._check_csrf(ep))
        vulns.extend(await self._check_error_disclosure(ep))

        # ── Phase 3.4 — Advanced GraphQL tests ───────────────────────────
        vulns.extend(await self._check_subscription_exposure(ep))
        vulns.extend(await self._check_query_cost_analysis(ep))
        vulns.extend(await self._check_persisted_query_bypass(ep))
        vulns.extend(await self._check_introspection_hardening(ep))
        vulns.extend(await self._check_batch_query_abuse_advanced(ep))

        return vulns

    # -----------------------------------------------------------------------
    # Checks
    # -----------------------------------------------------------------------

    async def _check_graphiql_exposed(self, ep: str) -> List[Vulnerability]:
        """GraphiQL/Playground UI accessible in production."""
        resp = await self.client.get(ep)
        if resp and resp.is_text and _GRAPHIQL_RE.search(resp.text):
            return [self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title="GraphQL IDE (GraphiQL/Playground) Exposed in Production",
                description=(
                    f"The GraphQL interactive IDE is accessible at {ep}. "
                    f"In production, this allows any user to explore the full API schema, "
                    f"send arbitrary queries and mutations, and bypass authorization "
                    f"in some configurations."
                ),
                url=ep, method="GET",
                evidence="GraphiQL/Playground HTML detected",
                severity=Severity.MEDIUM, cvss=_CVSS_MEDIUM,
                remediation="Disable GraphiQL/Playground in production environments.",
                references=_REFS_GQL,
                cwe_id="CWE-200", owasp_category=_OWASP_MISCONFIG,
                confidence="High",
            )]
        return []

    async def _check_introspection(self, ep: str) -> List[Vulnerability]:
        resp = await self.client.post(
            ep,
            json={"query": _INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if not resp or not resp.is_text:
            return []

        if resp.status_code == 200 and _INTROSPECTION_RE.search(resp.text):
            try:
                data        = json.loads(resp.text)
                types       = data.get("data", {}).get("__schema", {}).get("types", [])
                type_count  = len(types)
                type_names  = [t["name"] for t in types if t.get("name") and not t["name"].startswith("__")][:10]
                has_mutation = data.get("data", {}).get("__schema", {}).get("mutationType") is not None
            except Exception:
                type_count, type_names, has_mutation = 0, [], False

            return [self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title=f"GraphQL Introspection Enabled ({type_count} types)",
                description=(
                    f"GraphQL introspection is enabled at {ep}. "
                    f"Discovered {type_count} types including: {type_names}. "
                    f"Mutation types: {'present' if has_mutation else 'absent'}. "
                    f"Introspection exposes the complete API surface for reconnaissance."
                ),
                url=ep, method="POST",
                payload="{__schema{types{name}}}",
                evidence=f"{type_count} types discovered; mutations: {has_mutation}",
                severity=Severity.MEDIUM, cvss=_CVSS_MEDIUM,
                remediation=(
                    "Disable introspection in production. "
                    "Use persisted queries. "
                    "Apollo: introspection:false. graphene-django: GRAPHENE['INTROSPECTION']=False."
                ),
                references=_REFS_GQL,
                cwe_id="CWE-200", owasp_category=_OWASP_MISCONFIG,
                response_snippet=self._snippet(resp.text),
                confidence="High",
            )]
        return []

    async def _check_field_suggestions(self, ep: str) -> List[Vulnerability]:
        resp = await self.client.post(
            ep,
            json={"query": "{ usr { emai } }"},
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.is_text and _SUGGESTION_RE.search(resp.text):
            return [self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title="GraphQL Field Suggestion Leak — Schema Enumeration Without Introspection",
                description=(
                    f"GraphQL at {ep} returns field name suggestions in error messages. "
                    f"Even with introspection disabled, the full schema can be enumerated "
                    f"via typo-based queries exploiting suggestion responses."
                ),
                url=ep, method="POST",
                payload='{ usr { emai } }',
                evidence=resp.text[:200],
                severity=Severity.LOW, cvss=_CVSS_MEDIUM,
                remediation=(
                    "Disable field suggestions in production. "
                    "Apollo: debug:false. Sanitize all error messages."
                ),
                references=_REFS_GQL,
                cwe_id="CWE-209", owasp_category=_OWASP_MISCONFIG,
                confidence="High",
            )]
        return []

    async def _check_batch_abuse(self, ep: str) -> List[Vulnerability]:
        resp = await self.client.post(
            ep,
            json=_BATCH_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.is_text:
            try:
                data = json.loads(resp.text)
                if isinstance(data, list) and len(data) >= 10:
                    return [self._build_vuln(
                        vuln_type=VulnType.MISC,
                        title=f"GraphQL Query Batching: {len(data)}/100 Operations Accepted",
                        description=(
                            f"GraphQL at {ep} accepted a batch of 100 operations in one request "
                            f"and returned {len(data)} responses. "
                            f"Query batching allows rate-limit bypass and DoS amplification."
                        ),
                        url=ep, method="POST",
                        payload=f"[{{query:__typename}} × 100]",
                        evidence=f"Server responded to {len(data)}/100 batched operations",
                        severity=Severity.MEDIUM, cvss=_CVSS_DOS,
                        remediation=(
                            "Limit batch size to ≤10 operations. "
                            "Apply per-operation rate limiting."
                        ),
                        references=_REFS_GQL,
                        cwe_id="CWE-400", owasp_category=_OWASP_MISCONFIG,
                        confidence="High",
                    )]
            except Exception:
                pass
        return []

    async def _check_depth_bomb(self, ep: str) -> List[Vulnerability]:
        resp = await self.client.post(
            ep,
            json={"query": _DEPTH_BOMB},
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.status_code == 200 and _GQL_ERRORS_RE.search(resp.text or "") is None:
            return [self._build_vuln(
                vuln_type=VulnType.MISC,
                title="GraphQL Missing Query Depth Limit (20-Level Nested Query Accepted)",
                description=(
                    f"GraphQL at {ep} accepted a 20-level deeply nested query without error. "
                    f"Missing depth limits enable 'Nested Query' DoS attacks that exhaust "
                    f"server CPU and memory."
                ),
                url=ep, method="POST",
                payload=_DEPTH_BOMB[:80],
                evidence=f"20-deep query: HTTP {resp.status_code}, no depth error",
                severity=Severity.MEDIUM, cvss=_CVSS_DOS,
                remediation=(
                    "Implement query depth limiting (max 5-7). "
                    "Use graphql-depth-limit (Node.js) or graphene complexity validators."
                ),
                references=_REFS_GQL,
                cwe_id="CWE-400", owasp_category=_OWASP_MISCONFIG,
                confidence="Medium",
            )]
        return []

    async def _check_alias_overloading(self, ep: str) -> List[Vulnerability]:
        """Send 100 aliased fields in one query — tests alias-based DoS."""
        resp = await self.client.post(
            ep,
            json={"query": _ALIAS_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.status_code == 200 and not _GQL_ERRORS_RE.search(resp.text or ""):
            try:
                data = json.loads(resp.text)
                alias_count = len(data.get("data", {}))
                if alias_count >= 50:
                    return [self._build_vuln(
                        vuln_type=VulnType.MISC,
                        title=f"GraphQL Alias Overloading: {alias_count} Aliases Accepted",
                        description=(
                            f"GraphQL at {ep} accepted a query with {_ALIAS_COUNT} aliased fields "
                            f"({alias_count} resolved) without restriction. "
                            f"Alias overloading multiplies resolver execution, enabling DoS with "
                            f"a single HTTP request."
                        ),
                        url=ep, method="POST",
                        payload=f"{{a0:__typename a1:__typename ... a{_ALIAS_COUNT-1}:__typename}}",
                        evidence=f"{alias_count}/{_ALIAS_COUNT} aliases resolved",
                        severity=Severity.MEDIUM, cvss=_CVSS_DOS,
                        remediation=(
                            "Implement query complexity analysis. "
                            "Limit the number of unique field aliases per query. "
                            "Use graphql-query-complexity libraries."
                        ),
                        references=_REFS_GQL,
                        cwe_id="CWE-400", owasp_category=_OWASP_MISCONFIG,
                        confidence="High",
                    )]
            except Exception:
                pass
        return []

    async def _check_sqli(self, ep: str) -> List[Vulnerability]:
        for payload in _SQLI_PAYLOADS:
            resp = await self.client.post(
                ep,
                json={"query": _SQLI_QUERY, "variables": {"id": payload, "name": payload}},
                headers={"Content-Type": "application/json"},
            )
            if resp and resp.is_text:
                m = _SQL_ERROR_RE.search(resp.text)
                if m:
                    return [self._build_vuln(
                        vuln_type=VulnType.SQLI,
                        title="SQL Injection via GraphQL Variable",
                        description=(
                            f"GraphQL at {ep} is vulnerable to SQL injection via query variables. "
                            f"Injecting '{payload}' produced a SQL error in the response."
                        ),
                        url=ep, method="POST",
                        parameter="variables.id",
                        payload=payload,
                        evidence=f"SQL error: '{m.group(0)[:100]}'",
                        severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                        remediation=(
                            "Use ORM parameterized queries. "
                            "Never interpolate GraphQL variables into SQL strings."
                        ),
                        references=[*_REFS_GQL, "https://cwe.mitre.org/data/definitions/89.html"],
                        cwe_id="CWE-89", owasp_category=_OWASP_INJECT,
                        response_snippet=self._snippet(resp.text),
                        confidence="High",
                    )]
        return []

    async def _check_nosqli(self, ep: str) -> List[Vulnerability]:
        for payload in _NOSQL_PAYLOADS:
            resp = await self.client.post(
                ep,
                json={"query": _NOSQL_QUERY, "variables": {"filter": payload}},
                headers={"Content-Type": "application/json"},
            )
            if resp and resp.is_text:
                m = _NOSQL_ERROR_RE.search(resp.text)
                if m:
                    return [self._build_vuln(
                        vuln_type=VulnType.SQLI,
                        title="NoSQL Injection via GraphQL Variable",
                        description=(
                            f"GraphQL at {ep} appears vulnerable to NoSQL injection. "
                            f"Injecting '{payload}' produced a NoSQL-related error."
                        ),
                        url=ep, method="POST",
                        parameter="variables.filter",
                        payload=str(payload),
                        evidence=f"NoSQL error: '{m.group(0)[:100]}'",
                        severity=Severity.CRITICAL, cvss=_CVSS_CRITICAL,
                        remediation=(
                            "Validate and sanitize all GraphQL input variables. "
                            "Use typed schemas to prevent operator injection ($where, $gt)."
                        ),
                        references=[*_REFS_GQL, "https://cwe.mitre.org/data/definitions/943.html"],
                        cwe_id="CWE-943", owasp_category=_OWASP_INJECT,
                        response_snippet=self._snippet(resp.text),
                        confidence="High",
                    )]
        return []

    async def _check_mutation_auth_bypass(self, ep: str) -> List[Vulnerability]:
        """Test if sensitive mutations are accessible without authentication."""
        for mutation in _MUTATION_PROBES:
            resp = await self.client.post(
                ep,
                json={"query": mutation},
                headers={"Content-Type": "application/json"},
            )
            if not resp or not resp.is_text:
                continue
            # Fix 2.2: use robust success detection — avoids FP on {"data":null,"errors":[...]}
            if resp.status_code == 200 and self._is_mutation_success(resp.text):
                return [self._build_vuln(
                    vuln_type=VulnType.BROKEN_AUTH,
                    title="GraphQL Mutation Accessible Without Authentication",
                    description=(
                        f"Mutation '{mutation[:60]}...' at {ep} returned a non-auth-error "
                        f"response without credentials. Sensitive mutations (delete, create admin, "
                        f"reset password) may be accessible to unauthenticated attackers."
                    ),
                    url=ep, method="POST",
                    payload=mutation[:100],
                    evidence=f"HTTP 200 with non-null data — no auth error",
                    severity=Severity.HIGH, cvss=_CVSS_HIGH,
                    remediation=(
                        "Implement resolver-level authorization checks for all mutations. "
                        "Require authentication before executing any state-changing operation."
                    ),
                    references=[*_REFS_GQL, "https://cwe.mitre.org/data/definitions/285.html"],
                    cwe_id="CWE-285", owasp_category=_OWASP_ACCESS,
                    response_snippet=self._snippet(resp.text),
                    confidence="Medium",
                )]
        return []

    def _is_mutation_success(self, body: str) -> bool:
        """
        Fix 2.2: True only if mutation returned non-null data without auth errors.
        Avoids FP on {"data": null, "errors": [...]} which is an error response.
        """
        try:
            data = json.loads(body)
        except Exception:
            return False

        # Must have data key
        if "data" not in data:
            return False

        # data must not be null entirely
        if data["data"] is None:
            return False

        # At least one data value must be non-null
        data_values = data["data"]
        if isinstance(data_values, dict):
            if all(v is None for v in data_values.values()):
                return False

        # Must not contain auth error indicators in errors array
        for error in data.get("errors", []):
            msg = str(error.get("message", "")).lower()
            if any(kw in msg for kw in (
                "unauthorized", "unauthenticated", "forbidden",
                "not allowed", "permission", "access denied",
                "must be logged", "authentication required",
            )):
                return False

        return True

    async def _check_csrf(self, ep: str) -> List[Vulnerability]:
        """
        Test if GraphQL accepts application/x-www-form-urlencoded Content-Type.
        Browsers can send this cross-origin without a preflight → CSRF via GraphQL.
        """
        resp = await self.client.post(
            ep,
            content=_CSRF_FORM_BODY.encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin":        "https://evil.com",
            },
        )
        if resp and resp.is_text and resp.status_code == 200:
            if _GQL_DATA_RE.search(resp.text) or _GQL_ERRORS_RE.search(resp.text):
                return [self._build_vuln(
                    vuln_type=VulnType.CSRF,
                    title="GraphQL CSRF: Accepts application/x-www-form-urlencoded",
                    description=(
                        f"GraphQL at {ep} accepts form-urlencoded Content-Type from cross-origin. "
                        f"Browsers can send this content type cross-origin without CORS preflight, "
                        f"enabling CSRF attacks via HTML forms that submit GraphQL mutations."
                    ),
                    url=ep, method="POST",
                    payload=_CSRF_FORM_BODY,
                    evidence=f"HTTP {resp.status_code} with GraphQL response for form-urlencoded",
                    severity=Severity.HIGH, cvss=_CVSS_HIGH,
                    remediation=(
                        "Only accept Content-Type: application/json for GraphQL endpoints. "
                        "Reject form-urlencoded and text/plain content types. "
                        "Implement CSRF tokens or require custom headers (X-Requested-With)."
                    ),
                    references=[*_REFS_GQL, "https://cwe.mitre.org/data/definitions/352.html"],
                    cwe_id="CWE-352", owasp_category="A01:2021 - Broken Access Control",
                    response_snippet=self._snippet(resp.text),
                    confidence="High",
                )]
        return []

    async def _check_error_disclosure(self, ep: str) -> List[Vulnerability]:
        """Check if error responses reveal stack traces or internal details."""
        # Send invalid query to trigger error
        resp = await self.client.post(
            ep,
            json={"query": "{ invalidField999 }"},
            headers={"Content-Type": "application/json"},
        )
        if not resp or not resp.is_text:
            return []

        m = _STACKTRACE_RE.search(resp.text)
        if m:
            return [self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title="GraphQL Error Response Reveals Stack Trace",
                description=(
                    f"GraphQL at {ep} returned a stack trace or internal error detail "
                    f"in the error response. Stack traces reveal file paths, function names, "
                    f"and internal implementation details."
                ),
                url=ep, method="POST",
                payload='{ invalidField999 }',
                evidence=f"Stack trace: '{m.group(0)[:120]}'",
                severity=Severity.MEDIUM, cvss=_CVSS_MEDIUM,
                remediation=(
                    "Sanitize all error messages in production. "
                    "Return generic error messages. Disable debug mode."
                ),
                references=_REFS_GQL,
                cwe_id="CWE-209", owasp_category=_OWASP_MISCONFIG,
                response_snippet=self._snippet(resp.text),
                confidence="High",
            )]
        return []

    # =========================================================================
    # Phase 3.4 — Advanced GraphQL Tests
    # =========================================================================

    async def _check_subscription_exposure(self, ep: str) -> List[Vulnerability]:
        """
        Phase 3.4: Check if GraphQL subscriptions endpoint is exposed
        and accepts unauthenticated WebSocket connections.
        """
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(ep)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_ep = urlunparse(parsed._replace(scheme=ws_scheme))

        # Check via HTTP upgrade hint or subscriptions path
        sub_paths = [
            ep.replace("/graphql", "/graphql/subscriptions"),
            ep + "/subscriptions",
            ep.replace("/graphql", "/subscriptions"),
        ]
        for sub_ep in sub_paths:
            resp = await self.client.get(sub_ep)
            if resp and resp.status_code in (200, 101, 426, 400):
                return [self._build_vuln(
                    vuln_type=VulnType.GRAPHQL,
                    title="GraphQL Subscriptions Endpoint Exposed",
                    description=(
                        f"A GraphQL subscriptions endpoint was found at '{sub_ep}'. "
                        f"Subscriptions operate over WebSocket and may lack the same "
                        f"authentication controls as the HTTP endpoint. "
                        f"An unauthenticated attacker may be able to subscribe to "
                        f"real-time data streams."
                    ),
                    url=sub_ep,
                    evidence=f"Endpoint responded with HTTP {resp.status_code}",
                    severity=Severity.MEDIUM, cvss=_CVSS_MEDIUM,
                    remediation=(
                        "Apply the same authentication and authorization to WebSocket "
                        "subscription connections as to HTTP GraphQL queries. "
                        "Validate auth tokens during the WebSocket handshake."
                    ),
                    references=_REFS_GQL,
                    cwe_id="CWE-284", owasp_category=_OWASP_ACCESS,
                    confidence="Medium",
                )]
        return []

    async def _check_query_cost_analysis(self, ep: str) -> List[Vulnerability]:
        """
        Phase 3.4: Test if expensive queries are rejected.
        High query cost = potential DoS via complex queries.
        """
        import time
        # Build a deeply nested and aliased query (high cost)
        expensive_query = (
            "{ " +
            " ".join(
                f"alias{i}: __schema {{ types {{ name fields {{ name }} }} }}"
                for i in range(10)
            ) +
            " }"
        )
        t0 = time.monotonic()
        resp = await self.client.post(
            ep,
            json={"query": expensive_query},
            headers={"Content-Type": "application/json"},
        )
        elapsed = time.monotonic() - t0

        if not resp:
            return []

        # If server responded successfully with high cost query in reasonable time
        # — no query complexity limit
        body = resp.text or ""
        if resp.status_code == 200 and _GQL_DATA_RE.search(body):
            if elapsed < 30.0:  # server didn't time out → no protection
                return [self._build_vuln(
                    vuln_type=VulnType.GRAPHQL,
                    title="GraphQL Query Complexity / Cost Limit Not Enforced",
                    description=(
                        f"GraphQL at '{ep}' accepted a high-complexity query "
                        f"(10 aliased schema introspections) in {elapsed:.1f}s without rejecting it. "
                        f"Without query cost analysis, an attacker can craft a single "
                        f"deeply nested or alias-heavy query that exhausts server resources "
                        f"(DoS via query complexity)."
                    ),
                    url=ep, method="POST",
                    payload=expensive_query[:200],
                    evidence=f"Expensive query completed in {elapsed:.2f}s with HTTP 200",
                    severity=Severity.MEDIUM, cvss=_CVSS_DOS,
                    remediation=(
                        "Implement query complexity analysis with a maximum cost limit. "
                        "Use libraries like graphql-cost-analysis or graphql-query-complexity. "
                        "Set a maximum query depth and alias count."
                    ),
                    references=[
                        *_REFS_GQL,
                        "https://www.howtographql.com/advanced/4-security/",
                    ],
                    cwe_id="CWE-400", owasp_category=_OWASP_MISCONFIG,
                    confidence="Medium",
                )]
        return []

    async def _check_persisted_query_bypass(self, ep: str) -> List[Vulnerability]:
        """
        Phase 3.4: Test if Automatic Persisted Queries (APQ) can be abused
        to bypass query restrictions.
        """
        import hashlib
        dangerous_query = '{ __schema { types { name } } }'
        query_hash = hashlib.sha256(dangerous_query.encode()).hexdigest()

        # Step 1: register the query hash
        reg_payload = {
            "extensions": {
                "persistedQuery": {"version": 1, "sha256Hash": query_hash}
            },
            "query": dangerous_query,
        }
        resp1 = await self.client.post(
            ep,
            json=reg_payload,
            headers={"Content-Type": "application/json"},
        )

        if not resp1 or not _GQL_DATA_RE.search(resp1.text or ""):
            return []

        # Step 2: replay using only the hash (no query text)
        replay_payload = {
            "extensions": {
                "persistedQuery": {"version": 1, "sha256Hash": query_hash}
            }
        }
        resp2 = await self.client.post(
            ep,
            json=replay_payload,
            headers={"Content-Type": "application/json"},
        )

        if resp2 and _GQL_DATA_RE.search(resp2.text or ""):
            return [self._build_vuln(
                vuln_type=VulnType.GRAPHQL,
                title="GraphQL Automatic Persisted Queries (APQ) Enabled",
                description=(
                    f"GraphQL at '{ep}' supports Automatic Persisted Queries. "
                    f"APQ can be used to register arbitrary queries by hash and replay them, "
                    f"potentially bypassing allowlists or query validation that check "
                    f"the raw query string."
                ),
                url=ep, method="POST",
                evidence="APQ: query registered by hash and successfully replayed without query text",
                severity=Severity.LOW, cvss=_CVSS_MEDIUM,
                remediation=(
                    "If using an operation allowlist (persisted operations), disable APQ "
                    "to prevent clients from registering arbitrary new queries. "
                    "Only allow pre-registered, vetted queries in production."
                ),
                references=[
                    *_REFS_GQL,
                    "https://www.apollographql.com/docs/apollo-server/performance/apq/",
                ],
                cwe_id="CWE-284", owasp_category=_OWASP_ACCESS,
                confidence="High",
            )]
        return []

    async def _check_introspection_hardening(self, ep: str) -> List[Vulnerability]:
        """
        Phase 3.4: Deeper introspection hardening checks:
        - __type queries still work even when full __schema is disabled
        - Field-level introspection via __Field
        """
        # Check __type when __schema is disabled
        type_query = '{ __type(name: "Query") { name fields { name } } }'
        resp = await self.client.post(
            ep,
            json={"query": type_query},
            headers={"Content-Type": "application/json"},
        )
        if not resp:
            return []

        body = resp.text or ""
        if resp.status_code == 200 and '"__type"' in body and _GQL_DATA_RE.search(body):
            return [self._build_vuln(
                vuln_type=VulnType.GRAPHQL,
                title="GraphQL __type Introspection Not Fully Disabled",
                description=(
                    f"GraphQL at '{ep}' blocks __schema introspection but still responds "
                    f"to __type queries. This allows attackers to enumerate schema types "
                    f"one by one, effectively bypassing the introspection restriction."
                ),
                url=ep, method="POST",
                payload=type_query,
                evidence=f"__type query succeeded: {body[:200]}",
                severity=Severity.LOW, cvss=_CVSS_MEDIUM,
                remediation=(
                    "Disable all introspection queries including __type and __Field, "
                    "not only __schema. Use a server-side middleware that blocks all "
                    "meta-field queries in production."
                ),
                references=_REFS_GQL,
                cwe_id="CWE-200", owasp_category=_OWASP_MISCONFIG,
                response_snippet=self._snippet(body),
                confidence="High",
            )]
        return []

    async def _check_batch_query_abuse_advanced(self, ep: str) -> List[Vulnerability]:
        """
        Phase 3.4: Advanced batch abuse — test mixed queries in one batch
        to bypass rate limiting that counts requests not operations.
        """
        # Send one HTTP request with 50 operations
        batch = [
            {"query": '{ __typename }', "operationName": f"op{i}"}
            for i in range(50)
        ]
        resp = await self.client.post(
            ep,
            json=batch,
            headers={"Content-Type": "application/json"},
        )
        if not resp:
            return []

        body = resp.text or ""
        # If we get an array response matching our 50 ops, batching is unlimited
        try:
            import json as _json
            parsed = _json.loads(body)
            if isinstance(parsed, list) and len(parsed) >= 50:
                return [self._build_vuln(
                    vuln_type=VulnType.GRAPHQL,
                    title="GraphQL Unbounded Batch Query Abuse",
                    description=(
                        f"GraphQL at '{ep}' accepted a batch request with 50 operations "
                        f"in a single HTTP request. Unlimited batching allows attackers to "
                        f"amplify requests — 1 HTTP request = N GraphQL operations — "
                        f"which can be used for credential stuffing, rate-limit bypass, or DoS."
                    ),
                    url=ep, method="POST",
                    evidence=f"50-operation batch returned {len(parsed)} responses",
                    severity=Severity.MEDIUM, cvss=_CVSS_DOS,
                    remediation=(
                        "Set a maximum batch size (recommended: 5-10 operations per request). "
                        "Apply rate limiting per operation count, not per HTTP request."
                    ),
                    references=_REFS_GQL,
                    cwe_id="CWE-400", owasp_category=_OWASP_MISCONFIG,
                    confidence="High",
                )]
        except Exception:
            pass
        return []
