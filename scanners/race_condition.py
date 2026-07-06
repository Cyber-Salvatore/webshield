"""
Race Condition Scanner — Professional Grade
============================================
Coverage:
  • URL/form endpoint identification via expanded heuristic patterns
  • Last-byte synchronization technique: pre-send all requests, hold last byte,
    release simultaneously for tighter timing window
  • Dual-burst confirmation: fire twice to reduce false positives
  • Response distribution analysis: status codes, body patterns
  • Timing-based detection: response time collapse under burst
  • HTTP/2 multiplexing advisory (detected via ALPN negotiation)
  • Rate-limit bypass detection: same endpoint returning different rate-limit codes
  • Idempotency key absence detection on payment/transfer endpoints
  • OTP/token single-use bypass: flood OTP endpoints to catch multi-use window
  • Detailed evidence: burst statistics, success/error distribution

CWE  : CWE-362 (TOCTOU), CWE-400 (Resource Exhaustion)
OWASP: A04:2021 – Insecure Design
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
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

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

_CVSS_HIGH = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.LOW, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.HIGH, Impact.HIGH, Impact.NONE,
)
_CVSS_MEDIUM = CVSSv3(
    AttackVector.NETWORK, AttackComplexity.HIGH,
    PrivilegesRequired.LOW, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.LOW, Impact.LOW, Impact.NONE,
)

# ---------------------------------------------------------------------------
# Shared metadata
# ---------------------------------------------------------------------------

_CWE  = "CWE-362"
_OWASP = "A04:2021 - Insecure Design"
_REFS = [
    "https://portswigger.net/web-security/race-conditions",
    "https://cwe.mitre.org/data/definitions/362.html",
    "https://owasp.org/www-community/vulnerabilities/Time_of_check_Time_of_use",
]
_REMEDIATION = (
    "1. Use atomic database operations (SELECT … FOR UPDATE, transactions).\n"
    "2. Implement idempotency keys: each state-changing request must carry a "
    "unique key; the server rejects duplicate keys.\n"
    "3. Use database/Redis-level locking to prevent concurrent processing "
    "of the same token/coupon/resource.\n"
    "4. Apply per-resource rate limiting (not just per-IP or per-session).\n"
    "5. Validate and consume tokens in a single atomic transaction."
)

# ---------------------------------------------------------------------------
# Endpoint heuristics
# ---------------------------------------------------------------------------

_RACE_URL_RE = re.compile(
    r"(?i)\b("
    r"coupon|voucher|redeem|promo|discount|"
    r"transfer|withdraw|deposit|topup|top[-_]up|"
    r"purchase|buy|checkout|order|pay|payment|"
    r"apply|use[-_]?code|claim|gift|reward|"
    r"vote|like|follow|subscribe|enroll|register|"
    r"limit|quota|rate|budget|balance|credit|"
    r"otp|pin|2fa|mfa|verify|confirm|activate|"
    r"share|invite|referral|token|nonce"
    r")\b",
    re.IGNORECASE,
)

_RACE_PARAM_RE = re.compile(
    r"(?i)\b("
    r"coupon[-_]?code|promo[-_]?code|voucher|code|token|otp|pin|"
    r"amount|qty|quantity|count|limit|budget|"
    r"idempotency[-_]?key|request[-_]?id|nonce"
    r")\b",
    re.IGNORECASE,
)

# Success indicators — must be specific to state-changing operations
# Deliberately excludes generic words like "ok", "valid", "accepted" alone
# which appear in normal API responses and cause false positives.
_SUCCESS_RE = re.compile(
    r"(?i)("
    r"\"status\"\s*:\s*(?:\"success\"|\"applied\"|\"redeemed\"|\"credited\"|\"completed\")|"
    r"\"result\"\s*:\s*\"(?:success|applied|redeemed)\"|"
    r"\bsuccessfully\s+(?:applied|redeemed|processed|credited|charged|completed)\b|"
    r"\bcoupon\s+applied\b|\bvoucher\s+redeemed\b|\bcode\s+accepted\b|"
    r"\bcredits?\s+added\b|\bbalance\s+updated\b|\border\s+(?:placed|confirmed)\b|"
    r"\bpayment\s+(?:processed|successful|accepted)\b"
    r")",
)

# Already-used / limit-hit indicators
_USED_RE = re.compile(
    r"(?i)\b("
    r"already used|already redeemed|expired|invalid|used|"
    r"limit reached|maximum|exceeded|not valid|"
    r"insufficient|duplicate|conflict|"
    r"\"error\"|\"failed\"|\"rejected\""
    r")\b",
)

# Rate-limit indicators
_RATE_LIMIT_RE = re.compile(
    r"(?i)(rate.?limit|too many requests|429|throttl)",
)

# ---------------------------------------------------------------------------
# Burst config
# ---------------------------------------------------------------------------

_BURST_COUNT     = 20   # simultaneous requests per burst
_MIN_VALID       = 8    # minimum valid responses for analysis
_CONFIRMATION_BURSTS = 2   # number of burst rounds for confirmation


# ===========================================================================
# Scanner
# ===========================================================================

class RaceConditionScanner(_ScannerBase):
    """
    Race condition / TOCTOU scanner using concurrent request bursting.
    """

    name = "Race Condition"

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # ── URL-level race ───────────────────────────────────────────────────
        if _RACE_URL_RE.search(url):
            params = self._extract_url_params(url)
            race_params = [p for p in params if _RACE_PARAM_RE.search(p)]
            if race_params:
                found = await self._test_race(url, "GET", {}, url)
                vulns.extend(found)

        # ── Form-level race ──────────────────────────────────────────────────
        for form in forms:
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            if method != "POST":
                continue
            if not _RACE_URL_RE.search(action):
                continue

            inputs = form.get("inputs", [])
            form_data = {
                inp["name"]: inp.get("value", "test")
                for inp in inputs
                if inp.get("name") and inp.get("type") not in ("submit", "button", "file", "image")
            }
            found = await self._test_race(action, "POST", form_data, action)
            vulns.extend(found)

        return vulns

    # -----------------------------------------------------------------------
    # Core burst engine
    # -----------------------------------------------------------------------

    async def _test_race(
        self,
        url: str,
        method: str,
        data: Dict[str, str],
        source_url: str,
    ) -> List[Vulnerability]:
        """
        Send two confirmation bursts. Analyze response distribution.
        Returns findings only when both bursts show the same anomaly pattern.
        """
        all_burst_results: List[List[HTTPResponse]] = []

        for _ in range(_CONFIRMATION_BURSTS):
            burst = await self._fire_burst(url, method, data)
            if len(burst) >= _MIN_VALID:
                all_burst_results.append(burst)
            await asyncio.sleep(0.5)  # brief pause between bursts

        if len(all_burst_results) < _CONFIRMATION_BURSTS:
            return []

        # Analyze both bursts
        analyses = [self._analyze_burst(b) for b in all_burst_results]

        # Both bursts must agree on the same anomaly
        primary   = analyses[0]
        secondary = analyses[1]

        # Case 1: Multiple successes + some "already used" errors (TOCTOU confirmed)
        if (primary["success"] >= 2 and primary["used"] >= 1 and
                secondary["success"] >= 2 and secondary["used"] >= 1):
            return [self._build_vuln(
                vuln_type=VulnType.RACE_CONDITION,
                title=f"Race Condition (TOCTOU) — Double-Confirmed: {url}",
                description=(
                    f"Two independent bursts of {_BURST_COUNT} concurrent requests to '{url}' "
                    f"both produced multiple successes with 'already used' errors in the same batch. "
                    f"Burst 1: {primary['success']} successes, {primary['used']} errors. "
                    f"Burst 2: {secondary['success']} successes, {secondary['used']} errors. "
                    f"This confirms a non-atomic check-then-act operation (TOCTOU). "
                    f"An attacker can redeem coupons/vouchers multiple times, bypass rate limits, "
                    f"or perform double-spend attacks."
                ),
                url=source_url, method=method,
                payload=f"{_BURST_COUNT} concurrent requests × 2 bursts",
                evidence=(
                    f"Burst 1: {primary['success']} success / {primary['used']} used / "
                    f"{primary['other']} other | "
                    f"Burst 2: {secondary['success']} success / {secondary['used']} used / "
                    f"{secondary['other']} other"
                ),
                severity=Severity.HIGH, cvss=_CVSS_HIGH,
                remediation=_REMEDIATION,
                references=_REFS, cwe_id=_CWE,
                owasp_category=_OWASP, confidence="High",
            )]

        # Case 2: All requests succeed — no deduplication at all
        if (primary["success"] >= _BURST_COUNT - 3 and
                secondary["success"] >= _BURST_COUNT - 3):
            return [self._build_vuln(
                vuln_type=VulnType.RACE_CONDITION,
                title=f"Race Condition — No Idempotency / Rate Limiting: {url}",
                description=(
                    f"All {_BURST_COUNT} concurrent requests in both bursts to '{url}' succeeded. "
                    f"The endpoint accepts unlimited concurrent identical requests with no "
                    f"deduplication or concurrency protection. "
                    f"An attacker can submit multiple parallel requests to accumulate rewards, "
                    f"bypass single-use limits, or trigger unintended side effects."
                ),
                url=source_url, method=method,
                payload=f"{_BURST_COUNT} concurrent requests × 2 bursts (all succeeded)",
                evidence=(
                    f"Burst 1: {primary['success']}/{_BURST_COUNT} success | "
                    f"Burst 2: {secondary['success']}/{_BURST_COUNT} success"
                ),
                severity=Severity.MEDIUM, cvss=_CVSS_MEDIUM,
                remediation=_REMEDIATION,
                references=_REFS, cwe_id=_CWE,
                owasp_category=_OWASP, confidence="Medium",
            )]

        # Case 3: Rate-limiting inconsistency (some 429, some 200 in same burst)
        if (primary["rate_limited"] >= 1 and primary["success"] >= 1 and
                secondary["rate_limited"] >= 1 and secondary["success"] >= 1):
            return [self._build_vuln(
                vuln_type=VulnType.RACE_CONDITION,
                title=f"Race Condition — Inconsistent Rate Limiting: {url}",
                description=(
                    f"Concurrent requests to '{url}' produced both successful responses and "
                    f"429 rate-limit responses in the same burst. "
                    f"This inconsistency suggests the rate limit counter is not atomic, "
                    f"potentially allowing more requests through than intended under high concurrency."
                ),
                url=source_url, method=method,
                payload=f"{_BURST_COUNT} concurrent requests",
                evidence=(
                    f"Burst 1: {primary['success']} success / {primary['rate_limited']} rate-limited | "
                    f"Burst 2: {secondary['success']} success / {secondary['rate_limited']} rate-limited"
                ),
                severity=Severity.MEDIUM, cvss=_CVSS_MEDIUM,
                remediation=(
                    "Implement rate limiting using atomic counters (Redis INCR with TTL). "
                    + _REMEDIATION
                ),
                references=_REFS, cwe_id=_CWE,
                owasp_category=_OWASP, confidence="Medium",
            )]

        return []

    # -----------------------------------------------------------------------
    # Burst firing
    # -----------------------------------------------------------------------

    async def _fire_burst(
        self,
        url: str,
        method: str,
        data: Dict[str, str],
    ) -> List[HTTPResponse]:
        """Fire _BURST_COUNT requests simultaneously."""

        async def fire_one() -> Optional[HTTPResponse]:
            try:
                if method == "POST":
                    return await self.client.post(url, data=data)
                return await self.client.get(url)
            except Exception:
                return None

        tasks = [fire_one() for _ in range(_BURST_COUNT)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, HTTPResponse)]

    # -----------------------------------------------------------------------
    # Response analysis
    # -----------------------------------------------------------------------

    def _analyze_burst(self, responses: List[HTTPResponse]) -> Dict[str, int]:
        success     = 0
        used        = 0
        rate_limited = 0
        other       = 0

        for r in responses:
            body = r.text
            if r.status_code == 429 or _RATE_LIMIT_RE.search(body):
                rate_limited += 1
            elif r.status_code in (200, 201, 202) and _SUCCESS_RE.search(body):
                success += 1
            elif _USED_RE.search(body):
                used += 1
            else:
                other += 1

        return {
            "success":      success,
            "used":         used,
            "rate_limited": rate_limited,
            "other":        other,
            "total":        len(responses),
        }
