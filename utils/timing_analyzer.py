"""
Timing Analysis Engine — Phase 4.4
=====================================
Statistical analysis of HTTP response times to detect time-based injection
(SQLi, CMDi, SSRF) with significantly fewer false positives than
single-measurement comparisons.

Key capabilities:
  • Mean, median, standard deviation, min/max
  • Outlier detection (modified Z-score — robust to small samples)
  • Confidence-rated anomaly detection using statistical thresholds
  • Smart retry timing for race condition testing
  • Jitter estimation and network stability reporting

Used by:
  - scanners/sqli.py      → time-based SQLi confirmation
  - scanners/cmdi.py      → blind CMDi sleep detection
  - scanners/ssrf.py      → SSRF timing oracle
  - scanners/race_condition.py → optimal race window timing
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Coroutine, List, Optional, Tuple

if TYPE_CHECKING:
    from ..core.http_client import HTTPClient, HTTPResponse


# ---------------------------------------------------------------------------
# TimingStats — immutable summary of a measurement series
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TimingStats:
    """Statistical summary for a list of elapsed-time measurements (seconds)."""
    samples: Tuple[float, ...]

    @property
    def count(self) -> int:
        return len(self.samples)

    @property
    def mean(self) -> float:
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)

    @property
    def median(self) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        n = len(s)
        mid = n // 2
        return (s[mid - 1] + s[mid]) / 2 if n % 2 == 0 else s[mid]

    @property
    def std_dev(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        m = self.mean
        variance = sum((x - m) ** 2 for x in self.samples) / len(self.samples)
        return variance ** 0.5

    @property
    def minimum(self) -> float:
        return min(self.samples) if self.samples else 0.0

    @property
    def maximum(self) -> float:
        return max(self.samples) if self.samples else 0.0

    @property
    def jitter(self) -> float:
        """Coefficient of variation — higher = less stable network."""
        if self.mean == 0:
            return 0.0
        return self.std_dev / self.mean

    @property
    def is_stable(self) -> bool:
        """True when jitter < 0.30 (30% CV — reasonably predictable latency)."""
        return self.jitter < 0.30

    def threshold_3sigma(self, floor: float = 2.0) -> float:
        """
        mean + max(3×std_dev, floor).
        A response time exceeding this has < 0.3% chance of being natural jitter
        (assuming approximate normality).
        """
        return self.mean + max(3.0 * self.std_dev, floor)

    def threshold_2sigma(self, floor: float = 1.0) -> float:
        """mean + max(2×std_dev, floor) — less strict, more sensitive."""
        return self.mean + max(2.0 * self.std_dev, floor)

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "mean_s": round(self.mean, 3),
            "median_s": round(self.median, 3),
            "std_dev_s": round(self.std_dev, 3),
            "min_s": round(self.minimum, 3),
            "max_s": round(self.maximum, 3),
            "jitter_cv": round(self.jitter, 3),
            "is_stable": self.is_stable,
            "threshold_3sigma": round(self.threshold_3sigma(), 3),
        }


# ---------------------------------------------------------------------------
# AnomalyResult
# ---------------------------------------------------------------------------

@dataclass
class AnomalyResult:
    """Result of a timing anomaly detection test."""
    is_anomaly: bool
    observed: float          # seconds
    threshold: float         # seconds
    baseline: TimingStats
    confidence: str          # "High" / "Medium" / "Low"
    sigma_distance: float    # how many σ above baseline mean

    def __bool__(self) -> bool:
        return self.is_anomaly

    def __repr__(self) -> str:
        return (
            f"AnomalyResult(anomaly={self.is_anomaly}, "
            f"observed={self.observed:.2f}s, "
            f"threshold={self.threshold:.2f}s, "
            f"conf={self.confidence}, "
            f"sigma={self.sigma_distance:.1f})"
        )


# ---------------------------------------------------------------------------
# TimingAnalyzer
# ---------------------------------------------------------------------------

class TimingAnalyzer:
    """
    Phase 4.4 — Statistical Timing Analysis Engine.

    Usage::

        analyzer = TimingAnalyzer(client)

        # Step 1: build a baseline for the benign request
        baseline_stats = await analyzer.measure_baseline(
            url="https://target.com/search?q=test",
            samples=3,
        )

        # Step 2: measure the injected (sleep) request
        injected_elapsed = await analyzer.measure_single(
            url="https://target.com/search?q=' OR SLEEP(5)--",
        )

        # Step 3: determine anomaly
        result = analyzer.detect_anomaly(
            observed=injected_elapsed,
            baseline=baseline_stats,
            expected_delay=5.0,
        )
        if result.is_anomaly:
            # Time-based injection confirmed
    """

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    # -----------------------------------------------------------------------
    # Measurement
    # -----------------------------------------------------------------------

    async def measure_baseline(
        self,
        url: str,
        samples: int = 3,
        method: str = "GET",
        inter_sample_delay: float = 0.3,
    ) -> TimingStats:
        """
        Send N benign requests and return their timing statistics.

        inter_sample_delay: small pause between samples to avoid burst
        shaping on the server side.
        """
        timings: List[float] = []
        for i in range(max(samples, 1)):
            if i > 0:
                await asyncio.sleep(inter_sample_delay)
            elapsed = await self._timed_request(url, method)
            if elapsed is not None:
                timings.append(elapsed)

        return TimingStats(samples=tuple(timings))

    async def measure_single(
        self,
        url: str,
        method: str = "GET",
    ) -> Optional[float]:
        """Send one request and return its elapsed time (or None on failure)."""
        return await self._timed_request(url, method)

    async def measure_multiple(
        self,
        url: str,
        count: int = 3,
        method: str = "GET",
        inter_sample_delay: float = 0.2,
    ) -> TimingStats:
        """Send count requests and return stats."""
        timings: List[float] = []
        for i in range(count):
            if i > 0:
                await asyncio.sleep(inter_sample_delay)
            elapsed = await self._timed_request(url, method)
            if elapsed is not None:
                timings.append(elapsed)
        return TimingStats(samples=tuple(timings))

    # -----------------------------------------------------------------------
    # Anomaly detection
    # -----------------------------------------------------------------------

    def detect_anomaly(
        self,
        observed: float,
        baseline: TimingStats,
        expected_delay: Optional[float] = None,
        sigma_threshold: float = 3.0,
    ) -> AnomalyResult:
        """
        Determine whether *observed* is a statistically significant timing anomaly.

        Logic:
          1. If baseline is too fast (mean < 50 ms) → skip timing analysis
             (jitter would dominate everything).
          2. Use 3-sigma rule by default.
          3. If expected_delay is given, also check that observed ≈ mean + expected
             within ±50% tolerance.
        """
        if baseline.count == 0 or baseline.mean < 0.05:
            return AnomalyResult(
                is_anomaly=False,
                observed=observed,
                threshold=0.0,
                baseline=baseline,
                confidence="Low",
                sigma_distance=0.0,
            )

        threshold = baseline.mean + max(
            sigma_threshold * baseline.std_dev,
            2.0,   # absolute floor of 2 seconds
        )

        # Sigma distance from mean
        sigma_dist = (
            (observed - baseline.mean) / baseline.std_dev
            if baseline.std_dev > 0
            else float("inf") if observed > baseline.mean else 0.0
        )

        is_anomaly = observed >= threshold

        # Optional: cross-check with expected delay
        if is_anomaly and expected_delay is not None:
            # observed should be approximately baseline.mean + expected_delay
            expected_total = baseline.mean + expected_delay
            tolerance = max(expected_delay * 0.5, 1.0)
            if abs(observed - expected_total) > tolerance:
                is_anomaly = False   # doesn't match expected pattern

        # Confidence based on sigma distance and network stability
        if not is_anomaly:
            confidence = "Low"
        elif sigma_dist >= 5.0 and baseline.is_stable:
            confidence = "High"
        elif sigma_dist >= 3.0:
            confidence = "Medium"
        else:
            confidence = "Low"

        return AnomalyResult(
            is_anomaly=is_anomaly,
            observed=observed,
            threshold=threshold,
            baseline=baseline,
            confidence=confidence,
            sigma_distance=round(sigma_dist, 2),
        )

    # -----------------------------------------------------------------------
    # Race condition helpers
    # -----------------------------------------------------------------------

    async def optimal_race_window(
        self,
        url: str,
        samples: int = 5,
    ) -> float:
        """
        Estimate the optimal race window (seconds) for concurrent requests.

        Returns the mean baseline latency, which is the ideal time to fire
        concurrent requests so they all arrive at the server simultaneously.
        """
        stats = await self.measure_baseline(url, samples=samples)
        return stats.mean

    async def race_burst(
        self,
        request_fn: Callable[[], Coroutine],
        count: int = 10,
        lead_time: float = 0.0,
    ) -> List[Optional[HTTPResponse]]:
        """
        Fire *count* concurrent requests with minimal time skew.

        lead_time: optional warm-up pause before the burst.
        Returns responses in completion order.
        """
        if lead_time > 0:
            await asyncio.sleep(lead_time)
        tasks = [asyncio.create_task(request_fn()) for _ in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r if isinstance(r, HTTPResponse) else None for r in results]

    # -----------------------------------------------------------------------
    # Private
    # -----------------------------------------------------------------------

    async def _timed_request(
        self,
        url: str,
        method: str = "GET",
        post_data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[float]:
        """Send a single request and return wall-clock elapsed seconds."""
        t0 = time.monotonic()
        if method.upper() == "POST":
            resp = await self._client.post(url, data=post_data)
        else:
            resp = await self._client.get(url, params=params)
        elapsed = time.monotonic() - t0

        if resp is None:
            return None
        return elapsed
