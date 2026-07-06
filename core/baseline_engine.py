# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Baseline Engine — Part 15 of the Intelligence Layer.

Before a single attack payload is dispatched, the Baseline Engine constructs a
comprehensive, multi-dimensional model of the target application's *normal*
behaviour.  Every scanner that follows depends on this model to separate
genuine anomalies from noise.

What the engine captures
------------------------
The baseline is not a single HTTP response — it is a rich behavioural profile
for each (endpoint, parameter) pair that includes:

  Response dimensions
  ~~~~~~~~~~~~~~~~~~~
  • HTTP status code distribution across N benign requests
  • Content-Type and character encoding
  • Response body size (bytes) — mean, std-dev, min, max
  • JSON key-path structure (for JSON responses)
  • HTML tag frequency map (for HTML responses)
  • Structural similarity score between baseline samples
  • Dynamic token pattern map — which parts of the response change between
    requests so the differential engine knows to ignore them
  • Redirect chain length and final destination URL
  • Set-Cookie header presence and cookie names (not values)
  • Cache-Control and ETag behaviour
  • CORS exposure headers

  Timing dimensions
  ~~~~~~~~~~~~~~~~~
  • Response latency — mean, median, standard deviation, 95th percentile
  • Statistical threshold for time-based anomaly detection (3σ with a
    configurable minimum floor, default 2 s)
  • Jitter estimate to determine whether the server is stable enough for
    timing-based tests

  Error-page cataloguing
  ~~~~~~~~~~~~~~~~~~~~~~
  • Deliberate 404 / 400 / 500 probes to learn what *error* looks like for
    this application, so content-based detection does not confuse error pages
    with interesting anomalous responses

  Dynamic value fingerprinting
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  • CSRF tokens, nonces, session IDs, and other values that change on every
    request are identified by comparing multiple baseline responses at the
    word/token level.  Downstream engines receive a *stable content mask* —
    the baseline body with all dynamic tokens replaced by a canonical
    placeholder — so comparison operations are not confused by rotating values.

Analysis pipeline
-----------------
Stage 1  — Probe Collection
    N benign requests are dispatched in sequence (not parallel, to avoid
    polluting timing statistics with queuing effects).  A warm-up request is
    sent first and discarded to prime TCP/TLS connections and caches.

Stage 2  — Timing Analysis
    Mean, median, std-dev, 95th-percentile, and jitter are derived from the
    collected latencies.  If jitter > 40 % of the mean the server is flagged
    as UNSTABLE and timing-based tests are disabled for that endpoint.

Stage 3  — Structural Analysis
    All N body responses are compared pairwise with the ResponseAnalyzer.
    The mean pairwise similarity becomes the *baseline coherence score*.
    A coherence score below 0.70 means the application returns highly variable
    content (search results, feeds, etc.) and structural-diff tests must use
    a looser threshold.

Stage 4  — Dynamic Token Extraction
    The N bodies are tokenised and any token that differs across at least one
    pair of responses is added to the *dynamic token registry*.  A compiled
    regex is built from these tokens so they can be stripped before comparison.

Stage 5  — Error Profile Construction
    Dedicated probes for 404, 400, and 500 responses (using harmless but
    invalid inputs) are captured so that downstream scanners can use
    ``baseline.is_error_response(resp)`` instead of naïvely trusting status
    codes.

Stage 6  — Baseline Snapshot Assembly
    All of the above is assembled into an ``EndpointBaseline`` dataclass that
    is stored in a thread-safe LRU-like cache keyed by
    ``(normalised_url, parameter_name)``.

Public API
----------
``BaselineEngine`` exposes:

  ``async get_baseline(url, param, ...)``
      Build or retrieve a baseline for a specific (url, param) pair.

  ``compare(baseline, response)``
      Full multi-dimensional comparison returning a ``BaselineComparison``.

  ``is_timing_anomaly(baseline, elapsed)``
      True if elapsed time exceeds the statistical threshold.

  ``is_structurally_different(baseline, response, threshold)``
      True if the structural similarity score drops below *threshold*.

  ``is_error_response(baseline, response)``
      True if the response resembles the application's error profile.

  ``is_size_anomaly(baseline, response)``
      True if the body length deviates by more than 3 σ.

  ``is_redirect_anomaly(baseline, response)``
      True if the redirect chain changed in length or destination.

  ``is_header_anomaly(baseline, response)``
      True if a security-relevant header appeared or disappeared.

  ``strip_dynamic_tokens(baseline, text)``
      Return a copy of *text* with all known dynamic tokens replaced by a
      canonical placeholder, enabling clean textual comparisons.

  ``async invalidate(url, param)``
      Remove a cached baseline so it is rebuilt on next access.

  ``export_snapshot() / import_snapshot(data)``
      Serialise / deserialise the full baseline cache to/from a dict for
      persistence across scan phases or debugging.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core.http_client import HTTPClient, HTTPResponse
from ..utils.response_analyzer import ResponseAnalyzer, SimilarityResult
from ..utils.timing_analyzer import TimingStats


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class ServerStability(str, Enum):
    """Characterises the timing stability of the target server."""
    ROCK_SOLID  = "rock_solid"   # jitter < 10 % of mean → timing tests reliable
    STABLE      = "stable"       # jitter 10–25 %       → timing tests reliable
    MODERATE    = "moderate"     # jitter 25–40 %       → timing tests with caution
    UNSTABLE    = "unstable"     # jitter > 40 %        → timing tests disabled
    UNMEASURED  = "unmeasured"   # not enough samples yet


class ResponseContentType(str, Enum):
    """High-level classification of the response body."""
    HTML         = "html"
    JSON         = "json"
    XML          = "xml"
    PLAIN_TEXT   = "plain_text"
    JAVASCRIPT   = "javascript"
    BINARY       = "binary"
    EMPTY        = "empty"
    UNKNOWN      = "unknown"


class BaselineStatus(str, Enum):
    """Outcome of a baseline construction attempt."""
    COMPLETE    = "complete"     # all probes succeeded, full profile built
    PARTIAL     = "partial"      # some probes failed but enough data exists
    MINIMAL     = "minimal"      # only one probe succeeded — limited analysis
    FAILED      = "failed"       # no probes succeeded


# ─────────────────────────────────────────────────────────────────────────────
# Helper: dynamic-token extractor
# ─────────────────────────────────────────────────────────────────────────────

_WORD_SPLIT_RE = re.compile(r'([A-Za-z0-9+/=_\-\.]{8,})')
_HEX_RE        = re.compile(r'^[0-9a-fA-F]{8,}$')
_B64_RE        = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
_UUID_RE       = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)
_TIMESTAMP_RE  = re.compile(r'^\d{10,13}$')


def _tokenise(text: str) -> List[str]:
    """Split response body into word-like tokens for dynamic-value detection."""
    return _WORD_SPLIT_RE.findall(text[:50_000])


def _looks_dynamic(token: str) -> bool:
    """Return True if a token has the signature of a rotating value."""
    return bool(
        _HEX_RE.match(token) or
        _B64_RE.match(token) or
        _UUID_RE.match(token) or
        _TIMESTAMP_RE.match(token)
    )


def _extract_dynamic_tokens(bodies: List[str]) -> FrozenSet[str]:
    """
    Given N baseline response bodies, return the set of tokens that differ
    across at least one pair of responses AND look like rotating values
    (hex, base64, UUID, timestamp).  These are the 'dynamic tokens' that
    should be masked before any textual comparison.
    """
    if len(bodies) < 2:
        return frozenset()

    # Build per-position token sets
    token_lists = [_tokenise(b) for b in bodies]
    reference   = set(token_lists[0])
    dynamic: Set[str] = set()

    for tl in token_lists[1:]:
        current = set(tl)
        # tokens in reference that disappeared, or new tokens that appeared
        diff = reference.symmetric_difference(current)
        for t in diff:
            if _looks_dynamic(t):
                dynamic.add(t)

    return frozenset(dynamic)


def _build_mask_pattern(dynamic_tokens: FrozenSet[str]) -> Optional[re.Pattern]:
    """Compile a regex that matches any of the known dynamic tokens."""
    if not dynamic_tokens:
        return None
    escaped = [re.escape(t) for t in sorted(dynamic_tokens, key=len, reverse=True)]
    return re.compile('|'.join(escaped))


# ─────────────────────────────────────────────────────────────────────────────
# Error profile — what "error" looks like for this application
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ErrorProfile:
    """
    Encapsulates error-page behaviour learned from deliberate bad probes.
    Used by ``EndpointBaseline.is_error_response()`` to avoid misidentifying
    error pages as vulnerability signals.
    """
    # 404 profile
    not_found_status:   int            = 404
    not_found_body_sig: Optional[str]  = None   # first 200 chars of a 404 body
    not_found_size_mean: float         = 0.0

    # 400 profile
    bad_request_status:  int           = 400
    bad_request_body_sig: Optional[str] = None

    # 500 profile (if injectable)
    server_error_status:  int          = 500
    server_error_body_sig: Optional[str] = None

    # Soft-404 detection: some apps return 200 for all URLs
    soft_404_detected:  bool           = False
    soft_404_body_size: float          = 0.0    # expected size of a soft 404
    soft_404_keywords:  List[str]      = field(default_factory=list)

    def matches_not_found(self, resp: HTTPResponse) -> bool:
        """True if *resp* resembles the application's 404 pattern."""
        if resp.status_code == self.not_found_status:
            return True
        if self.soft_404_detected:
            body = resp.text if resp.is_text else ""
            body_lower = body.lower()
            if any(kw in body_lower for kw in self.soft_404_keywords):
                return True
            if self.soft_404_body_size > 0:
                size_delta = abs(len(body) - self.soft_404_body_size)
                if size_delta / max(self.soft_404_body_size, 1) < 0.15:
                    return True
        return False

    def matches_server_error(self, resp: HTTPResponse) -> bool:
        """True if *resp* resembles a server error response."""
        if resp.status_code >= 500:
            return True
        if self.server_error_body_sig:
            body = resp.text[:500] if resp.is_text else ""
            return self.server_error_body_sig[:100] in body
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "not_found_status":      self.not_found_status,
            "not_found_size_mean":   self.not_found_size_mean,
            "soft_404_detected":     self.soft_404_detected,
            "soft_404_keywords":     self.soft_404_keywords,
            "server_error_status":   self.server_error_status,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Header baseline — track security-relevant headers
# ─────────────────────────────────────────────────────────────────────────────

_SECURITY_HEADERS = frozenset({
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "set-cookie",
    "cache-control",
    "etag",
    "vary",
})

_INTERESTING_HEADERS = frozenset({
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wp-cf-super-cache",
    "x-varnish",
    "cf-ray",
    "x-amz-request-id",
    "x-request-id",
    "x-correlation-id",
})


@dataclass
class HeaderBaseline:
    """Tracks which headers are consistently present or absent in normal responses."""
    present_headers:  Dict[str, str]  = field(default_factory=dict)   # name → representative value
    absent_headers:   Set[str]        = field(default_factory=set)     # never present in baseline
    variable_headers: Set[str]        = field(default_factory=set)     # present but value rotates
    redirect_chain:   List[str]       = field(default_factory=list)    # URLs in normal redirect chain

    def detect_anomaly(self, resp: HTTPResponse) -> List[str]:
        """
        Return a list of anomaly descriptions for headers in *resp* that differ
        from the baseline.  Empty list means no header anomaly.
        """
        anomalies: List[str] = []
        resp_lower = {k.lower(): v for k, v in resp.headers.items()}

        for name in _SECURITY_HEADERS | _INTERESTING_HEADERS:
            in_resp     = name in resp_lower
            in_baseline = name in self.present_headers

            if in_baseline and not in_resp and name not in self.variable_headers:
                anomalies.append(f"Header '{name}' disappeared (was always present)")

            if not in_baseline and in_resp and name in _SECURITY_HEADERS:
                anomalies.append(f"New security header '{name}' appeared: {resp_lower[name]!r}")

        return anomalies


# ─────────────────────────────────────────────────────────────────────────────
# Size baseline
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SizeBaseline:
    """Statistical model of normal response body size."""
    sizes:    List[int]  = field(default_factory=list)
    mean:     float      = 0.0
    std_dev:  float      = 0.0
    minimum:  int        = 0
    maximum:  int        = 0

    @classmethod
    def from_sizes(cls, sizes: List[int]) -> "SizeBaseline":
        if not sizes:
            return cls()
        mean   = statistics.mean(sizes)
        std    = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
        return cls(
            sizes=sizes,
            mean=mean,
            std_dev=std,
            minimum=min(sizes),
            maximum=max(sizes),
        )

    def is_anomalous(self, size: int, sigma: float = 3.0) -> bool:
        """True if *size* deviates by more than *sigma* standard deviations."""
        if self.std_dev < 10:
            # Extremely stable size — flag any deviation > 10 %
            return abs(size - self.mean) > max(self.mean * 0.10, 50)
        z_score = abs(size - self.mean) / self.std_dev
        return z_score > sigma

    def size_delta_ratio(self, size: int) -> float:
        """Ratio of deviation to mean — positive means larger, negative means smaller."""
        if self.mean == 0:
            return 0.0
        return (size - self.mean) / self.mean


# ─────────────────────────────────────────────────────────────────────────────
# Redirect baseline
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RedirectBaseline:
    """Models the normal redirect behaviour of an endpoint."""
    chain_length:   int          = 0
    final_url:      Optional[str] = None
    redirect_urls:  List[str]    = field(default_factory=list)

    def is_anomalous(
        self,
        chain_length: int,
        final_url: Optional[str],
    ) -> bool:
        """
        True if the redirect chain changed length or landed on a different URL
        compared to baseline.
        """
        if chain_length != self.chain_length:
            return True
        if self.final_url and final_url and final_url != self.final_url:
            # Allow fragment / query string differences
            a = urlparse(self.final_url)._replace(query="", fragment="")
            b = urlparse(final_url)._replace(query="", fragment="")
            return a != b
        return False


# ─────────────────────────────────────────────────────────────────────────────
# EndpointBaseline — the full profile for one (url, parameter) pair
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EndpointBaseline:
    """
    Complete behavioural profile for a single (url, parameter) pair.

    All downstream scanners and analysis engines consume this object rather
    than raw HTTP responses.
    """

    # Identity
    url:            str
    parameter:      str
    status:         BaselineStatus           = BaselineStatus.FAILED
    content_type:   ResponseContentType      = ResponseContentType.UNKNOWN
    stability:      ServerStability          = ServerStability.UNMEASURED

    # Timing model
    timing:         Optional[TimingStats]    = None

    # Size model
    size:           SizeBaseline             = field(default_factory=SizeBaseline)

    # Structural model
    representative_response: Optional[HTTPResponse] = None
    coherence_score: float                   = 1.0   # mean pairwise structural similarity
    structure_threshold: float               = 0.50  # below this → structurally different

    # Dynamic token model
    dynamic_tokens: FrozenSet[str]           = frozenset()
    _mask_pattern:  Optional[re.Pattern]     = field(default=None, repr=False, compare=False)

    # Header model
    headers:        HeaderBaseline           = field(default_factory=HeaderBaseline)

    # Redirect model
    redirects:      RedirectBaseline         = field(default_factory=RedirectBaseline)

    # Error profile
    errors:         ErrorProfile             = field(default_factory=ErrorProfile)

    # Cache header behaviour
    is_cached:      bool                     = False   # server sends Cache-Control: max-age
    has_etag:       bool                     = False

    # Raw sample bodies (first N, for external introspection)
    sample_bodies:  List[str]                = field(default_factory=list, repr=False)

    # Build metadata
    probe_count:    int                      = 0
    build_duration: float                    = 0.0    # seconds taken to build
    built_at:       float                    = field(default_factory=time.monotonic)

    # ── Post-init ────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        self._mask_pattern = _build_mask_pattern(self.dynamic_tokens)

    # ── Timing helpers ───────────────────────────────────────────────────────

    @property
    def timing_threshold(self) -> float:
        """
        Statistical threshold above which a response is considered a timing
        anomaly: mean + max(3σ, 2 s).
        """
        if self.timing is None:
            return 5.0
        return self.timing.threshold_3sigma(floor=2.0)

    def is_timing_anomaly(self, elapsed: float) -> bool:
        """True if *elapsed* seconds exceeds the statistical timing threshold."""
        if self.timing is None:
            return False
        if self.stability == ServerStability.UNSTABLE:
            # Timing tests are not reliable on unstable servers
            return False
        if self.timing.mean < 0.05:
            return False
        return elapsed >= self.timing_threshold

    def timing_delay_factor(self, elapsed: float) -> float:
        """
        How many times longer than the mean is *elapsed*?
        A factor ≥ 5 is a very strong time-based signal.
        """
        if self.timing is None or self.timing.mean == 0:
            return 0.0
        return elapsed / self.timing.mean

    # ── Size helpers ─────────────────────────────────────────────────────────

    def is_size_anomaly(self, response: HTTPResponse, sigma: float = 3.0) -> bool:
        """True if the response body size deviates significantly from baseline."""
        return self.size.is_anomalous(len(response.content), sigma=sigma)

    def size_delta_ratio(self, response: HTTPResponse) -> float:
        """Positive → response is larger than baseline; negative → smaller."""
        return self.size.size_delta_ratio(len(response.content))

    # ── Structural helpers ───────────────────────────────────────────────────

    def effective_threshold(self) -> float:
        """
        Structural similarity threshold adjusted for baseline coherence.
        If the application itself returns variable content (low coherence),
        we lower the bar for what counts as 'different'.
        """
        if self.coherence_score < 0.70:
            # Highly variable responses — require a bigger shift
            return max(self.structure_threshold - 0.20, 0.10)
        return self.structure_threshold

    # ── Error-response helpers ───────────────────────────────────────────────

    def is_error_response(self, response: HTTPResponse) -> bool:
        """True if *response* resembles the application's error profile."""
        return (
            self.errors.matches_not_found(response) or
            self.errors.matches_server_error(response)
        )

    # ── Redirect helpers ─────────────────────────────────────────────────────

    def is_redirect_anomaly(
        self,
        response: HTTPResponse,
        chain_length: int = 0,
    ) -> bool:
        """True if the redirect behaviour changed from baseline."""
        final_url = response.url if hasattr(response, "url") else None
        return self.redirects.is_anomalous(chain_length, final_url)

    # ── Header helpers ───────────────────────────────────────────────────────

    def is_header_anomaly(self, response: HTTPResponse) -> bool:
        """True if a security-relevant header appeared or disappeared."""
        return bool(self.headers.detect_anomaly(response))

    def header_anomalies(self, response: HTTPResponse) -> List[str]:
        """Return a list of human-readable header anomaly descriptions."""
        return self.headers.detect_anomaly(response)

    # ── Dynamic-token helpers ─────────────────────────────────────────────────

    def strip_dynamic_tokens(self, text: str) -> str:
        """
        Return *text* with all known dynamic tokens replaced by the canonical
        placeholder ``__DYN__``.  Enables clean textual comparisons even when
        the application embeds rotating CSRF tokens, nonces, etc.
        """
        if self._mask_pattern is None:
            return text
        return self._mask_pattern.sub("__DYN__", text)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "url":               self.url,
            "parameter":         self.parameter,
            "status":            self.status.value,
            "content_type":      self.content_type.value,
            "stability":         self.stability.value,
            "coherence_score":   round(self.coherence_score, 4),
            "structure_threshold": round(self.effective_threshold(), 4),
            "probe_count":       self.probe_count,
            "build_duration_s":  round(self.build_duration, 3),
            "dynamic_tokens":    sorted(self.dynamic_tokens),
            "is_cached":         self.is_cached,
            "has_etag":          self.has_etag,
            "size": {
                "mean":    round(self.size.mean, 1),
                "std_dev": round(self.size.std_dev, 1),
                "min":     self.size.minimum,
                "max":     self.size.maximum,
            },
            "errors": self.errors.to_dict(),
        }
        if self.timing is not None:
            d["timing"] = self.timing.to_dict()
        return d


# ─────────────────────────────────────────────────────────────────────────────
# BaselineComparison — result of comparing a test response to a baseline
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BaselineComparison:
    """
    Multi-dimensional comparison result returned by ``BaselineEngine.compare()``.

    Every scanner should inspect this object rather than performing ad-hoc
    comparisons, so that all analysis is consistent and reproducible.
    """

    # Raw structural similarity (0.0 = completely different, 1.0 = identical)
    structural_score:    float    = 1.0

    # Flags
    is_structurally_different: bool = False
    is_timing_anomaly:   bool    = False
    is_size_anomaly:     bool    = False
    is_redirect_anomaly: bool    = False
    is_header_anomaly:   bool    = False
    is_error_response:   bool    = False

    # Magnitude indicators
    timing_delay_factor: float   = 0.0   # elapsed / baseline_mean
    size_delta_ratio:    float   = 0.0   # (test_size - baseline_mean) / baseline_mean

    # Narrative
    anomaly_descriptions: List[str] = field(default_factory=list)
    header_anomalies:     List[str] = field(default_factory=list)

    @property
    def any_anomaly(self) -> bool:
        """True if at least one dimension showed an anomaly."""
        return (
            self.is_structurally_different or
            self.is_timing_anomaly or
            self.is_size_anomaly or
            self.is_redirect_anomaly or
            self.is_header_anomaly
        )

    @property
    def anomaly_count(self) -> int:
        """Number of dimensions that are anomalous."""
        return sum([
            self.is_structurally_different,
            self.is_timing_anomaly,
            self.is_size_anomaly,
            self.is_redirect_anomaly,
            self.is_header_anomaly,
        ])

    @property
    def confidence_boost(self) -> float:
        """
        A 0–1 additive boost for the Confidence Framework.
        More corroborating dimensions → higher boost.
        """
        # Each additional corroborating anomaly adds weight
        weights = {
            "structural": 0.35 if self.is_structurally_different else 0.0,
            "timing":     0.30 if self.is_timing_anomaly else 0.0,
            "size":       0.15 if self.is_size_anomaly else 0.0,
            "redirect":   0.15 if self.is_redirect_anomaly else 0.0,
            "header":     0.05 if self.is_header_anomaly else 0.0,
        }
        return min(sum(weights.values()), 1.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "structural_score":         round(self.structural_score, 4),
            "is_structurally_different": self.is_structurally_different,
            "is_timing_anomaly":        self.is_timing_anomaly,
            "is_size_anomaly":          self.is_size_anomaly,
            "is_redirect_anomaly":      self.is_redirect_anomaly,
            "is_header_anomaly":        self.is_header_anomaly,
            "is_error_response":        self.is_error_response,
            "timing_delay_factor":      round(self.timing_delay_factor, 2),
            "size_delta_ratio":         round(self.size_delta_ratio, 3),
            "anomaly_count":            self.anomaly_count,
            "confidence_boost":         round(self.confidence_boost, 3),
            "anomaly_descriptions":     self.anomaly_descriptions,
            "header_anomalies":         self.header_anomalies,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Internal probe helpers
# ─────────────────────────────────────────────────────────────────────────────

# Benign values used for baseline probing — chosen to exercise parameters
# without triggering any scanner payloads or accidental errors
_BENIGN_VALUES: Dict[str, str] = {
    "default":  "1",
    "string":   "test",
    "numeric":  "42",
    "bool":     "true",
    "id":       "1",
    "uuid":     "00000000-0000-0000-0000-000000000001",
    "date":     "2024-01-01",
    "email":    "test@example.com",
    "path":     "/",
    "query":    "hello",
}

# Deliberately bad inputs used to build the error profile
_BAD_INPUT_404   = "__nonexistent_path_webshield__"
_BAD_INPUT_400   = "\x00\x01"   # null bytes → likely triggers 400
_BAD_PARAM_500   = "' AND 1=1 -- "  # mild SQLi probe for 500 detection only


def _classify_content_type(resp: HTTPResponse) -> ResponseContentType:
    ct = resp.content_type.lower()
    if not resp.content:
        return ResponseContentType.EMPTY
    if "json" in ct:
        return ResponseContentType.JSON
    if "xml" in ct:
        return ResponseContentType.XML
    if "html" in ct:
        return ResponseContentType.HTML
    if "javascript" in ct or "ecmascript" in ct:
        return ResponseContentType.JAVASCRIPT
    if "text" in ct:
        return ResponseContentType.PLAIN_TEXT
    if not resp.is_text:
        return ResponseContentType.BINARY
    return ResponseContentType.UNKNOWN


def _compute_stability(samples: List[float]) -> ServerStability:
    """Map timing jitter ratio to a ServerStability level."""
    if len(samples) < 2:
        return ServerStability.UNMEASURED
    mean = statistics.mean(samples)
    if mean < 1e-6:
        return ServerStability.ROCK_SOLID
    std  = statistics.pstdev(samples)
    jitter_ratio = std / mean
    if jitter_ratio < 0.10:
        return ServerStability.ROCK_SOLID
    if jitter_ratio < 0.25:
        return ServerStability.STABLE
    if jitter_ratio < 0.40:
        return ServerStability.MODERATE
    return ServerStability.UNSTABLE


def _build_timing_stats(samples: List[float]) -> Optional[TimingStats]:
    """Construct a TimingStats from a list of elapsed-second measurements."""
    if not samples:
        return None
    return TimingStats(samples=tuple(samples))


def _build_header_baseline(responses: List[HTTPResponse]) -> HeaderBaseline:
    """
    Derive HeaderBaseline from N response objects.

    A header is 'present' if it appears in all responses.
    A header is 'variable' if it appears in all but with differing values.
    A header is 'absent' if it never appears.
    """
    if not responses:
        return HeaderBaseline()

    target_names = _SECURITY_HEADERS | _INTERESTING_HEADERS
    n = len(responses)

    # Collect per-header: list of values across all responses
    header_values: Dict[str, List[str]] = defaultdict(list)
    for resp in responses:
        resp_lower = {k.lower(): v for k, v in resp.headers.items()}
        for name in target_names:
            if name in resp_lower:
                header_values[name].append(resp_lower[name])

    present:  Dict[str, str] = {}
    absent:   Set[str]       = set()
    variable: Set[str]       = set()

    for name in target_names:
        vals = header_values.get(name, [])
        if len(vals) == n:
            # Present in all responses
            if len(set(vals)) > 1:
                variable.add(name)
            else:
                present[name] = vals[0]
        elif len(vals) == 0:
            absent.add(name)
        # else: inconsistently present — treat as variable
        else:
            variable.add(name)

    return HeaderBaseline(
        present_headers=present,
        absent_headers=absent,
        variable_headers=variable,
    )


def _extract_soft_404_signals(body: str) -> List[str]:
    """Extract keywords that indicate a 'not found' response disguised as 200."""
    candidates = [
        "not found", "page not found", "404", "doesn't exist",
        "does not exist", "no longer available", "been removed",
        "cannot be found", "could not be found", "页面不存在",
    ]
    body_lower = body.lower()
    return [kw for kw in candidates if kw in body_lower]


# ─────────────────────────────────────────────────────────────────────────────
# BaselineEngine
# ─────────────────────────────────────────────────────────────────────────────

class BaselineEngine:
    """
    Part 15 of the Intelligence Layer — Baseline Engine.

    Constructs and caches comprehensive behavioural baselines for every
    (endpoint, parameter) pair encountered during scanning.  All scanners
    call ``get_baseline()`` before firing payloads and use the returned
    ``EndpointBaseline`` to interpret whether a response is truly anomalous.

    Thread / coroutine safety
    -------------------------
    One ``BaselineEngine`` instance is shared across the entire scan.  All
    cache writes are protected by an ``asyncio.Lock``.  Probe requests are
    serialised (not concurrent) within a single baseline build to ensure
    timing measurements are not contaminated by queuing.

    Parameters
    ----------
    client : HTTPClient
        The shared HTTP client for the current scan.
    samples : int
        Number of benign probe requests per baseline (default 5).
        More samples → better timing statistics and more reliable dynamic-token
        detection, at the cost of extra requests.
    structural_threshold : float
        Structural similarity below which a response is considered different
        (default 0.50).
    timing_floor : float
        Minimum extra seconds to add to the timing anomaly threshold
        (default 2.0 s) even if σ is very small.
    analyzer : ResponseAnalyzer, optional
        Override the default ResponseAnalyzer instance.
    build_error_profile : bool
        Whether to fire deliberate bad probes to build the error profile
        (default True).  Disable if you need to minimise request count.
    """

    def __init__(
        self,
        client: HTTPClient,
        samples: int = 5,
        structural_threshold: float = 0.50,
        timing_floor: float = 2.0,
        analyzer: Optional[ResponseAnalyzer] = None,
        build_error_profile: bool = True,
    ) -> None:
        self._client              = client
        self._samples             = max(samples, 1)
        self._structural_threshold = structural_threshold
        self._timing_floor        = timing_floor
        self._analyzer            = analyzer or ResponseAnalyzer()
        self._build_error_profile = build_error_profile

        # (normalised_url, param) → EndpointBaseline
        self._cache: Dict[Tuple[str, str], EndpointBaseline] = {}
        self._lock  = asyncio.Lock()

        # Global stats
        self._total_builds: int   = 0
        self._total_probes: int   = 0
        self._cache_hits:   int   = 0
        self._build_errors: int   = 0

    # ── Public API ────────────────────────────────────────────────────────────

    async def get_baseline(
        self,
        url:          str,
        param:        str,
        benign_value: Optional[str] = None,
        method:       str           = "GET",
        headers:      Optional[Dict[str, str]] = None,
        body:         Optional[Dict[str, str]] = None,
    ) -> EndpointBaseline:
        """
        Return (or build) a full ``EndpointBaseline`` for the given
        (url, param) pair.

        Parameters
        ----------
        url : str
            The endpoint URL.  Query string is preserved so parameters embedded
            in the URL are handled correctly.
        param : str
            The parameter name being targeted.  Used as part of the cache key
            so different parameters on the same URL get independent baselines.
        benign_value : str, optional
            Value to use when probing.  If None the engine selects a sensible
            default based on the parameter name.
        method : str
            HTTP method to use (default "GET").
        headers : dict, optional
            Extra headers to include in probe requests.
        body : dict, optional
            Base body for POST requests (the parameter is injected into this).

        Returns
        -------
        EndpointBaseline
            Always returns an object — never raises.  Check ``.status`` to see
            if the baseline is complete, partial, or failed.
        """
        cache_key = (self._normalise_url(url), param)

        async with self._lock:
            if cache_key in self._cache:
                self._cache_hits += 1
                return self._cache[cache_key]

        # Not cached — build it
        baseline = await self._build_baseline(
            url=url,
            param=param,
            benign_value=benign_value or self._choose_benign_value(param),
            method=method,
            extra_headers=headers or {},
            base_body=body or {},
        )

        async with self._lock:
            self._cache[cache_key] = baseline
            self._total_builds += 1

        return baseline

    def compare(
        self,
        baseline: EndpointBaseline,
        response: HTTPResponse,
        elapsed:  Optional[float] = None,
        redirect_chain_length: int = 0,
    ) -> BaselineComparison:
        """
        Perform a full multi-dimensional comparison of *response* against
        *baseline*.

        Parameters
        ----------
        baseline : EndpointBaseline
        response : HTTPResponse
        elapsed : float, optional
            Response time in seconds.  If not provided timing comparison is
            skipped.
        redirect_chain_length : int
            Number of redirects followed to reach *response*.

        Returns
        -------
        BaselineComparison
            Rich result object describing every dimension of anomaly.
        """
        result = BaselineComparison()

        # ── Structural comparison ─────────────────────────────────────────
        if baseline.representative_response is not None:
            sim: SimilarityResult = self._analyzer.compare(
                baseline.representative_response, response
            )
            result.structural_score = sim.score
            threshold = baseline.effective_threshold()
            result.is_structurally_different = sim.score < threshold
            if result.is_structurally_different:
                result.anomaly_descriptions.append(
                    f"Structural similarity {sim.score:.2f} < threshold {threshold:.2f}"
                )

        # ── Timing comparison ─────────────────────────────────────────────
        if elapsed is not None:
            result.is_timing_anomaly  = baseline.is_timing_anomaly(elapsed)
            result.timing_delay_factor = baseline.timing_delay_factor(elapsed)
            if result.is_timing_anomaly:
                result.anomaly_descriptions.append(
                    f"Response time {elapsed:.2f}s is {result.timing_delay_factor:.1f}× "
                    f"the baseline mean "
                    f"({baseline.timing.mean:.2f}s)"
                    if baseline.timing else f"Response time {elapsed:.2f}s exceeds threshold"
                )

        # ── Size comparison ───────────────────────────────────────────────
        result.is_size_anomaly   = baseline.is_size_anomaly(response)
        result.size_delta_ratio  = baseline.size_delta_ratio(response)
        if result.is_size_anomaly:
            result.anomaly_descriptions.append(
                f"Response size {len(response.content)} bytes deviates from baseline "
                f"mean {baseline.size.mean:.0f}±{baseline.size.std_dev:.0f} "
                f"(ratio {result.size_delta_ratio:+.1%})"
            )

        # ── Redirect comparison ───────────────────────────────────────────
        result.is_redirect_anomaly = baseline.is_redirect_anomaly(
            response, redirect_chain_length
        )
        if result.is_redirect_anomaly:
            result.anomaly_descriptions.append(
                "Redirect chain changed from baseline"
            )

        # ── Header comparison ─────────────────────────────────────────────
        hdr_anomalies = baseline.header_anomalies(response)
        result.header_anomalies = hdr_anomalies
        result.is_header_anomaly = bool(hdr_anomalies)
        if hdr_anomalies:
            result.anomaly_descriptions.extend(hdr_anomalies)

        # ── Error-response flag ───────────────────────────────────────────
        result.is_error_response = baseline.is_error_response(response)

        return result

    # ── Convenience single-dimension methods ──────────────────────────────────

    def is_timing_anomaly(
        self,
        baseline: EndpointBaseline,
        elapsed:  float,
    ) -> bool:
        """True if *elapsed* seconds exceeds the statistical timing threshold."""
        return baseline.is_timing_anomaly(elapsed)

    def is_structurally_different(
        self,
        baseline:  EndpointBaseline,
        response:  HTTPResponse,
        threshold: Optional[float] = None,
    ) -> bool:
        """True if the response body structure differs significantly from baseline."""
        if baseline.representative_response is None:
            return False
        sim = self._analyzer.compare(baseline.representative_response, response)
        t   = threshold if threshold is not None else baseline.effective_threshold()
        return sim.score < t

    def structural_score(
        self,
        baseline: EndpointBaseline,
        response: HTTPResponse,
    ) -> float:
        """Return the raw structural similarity score (0.0–1.0)."""
        if baseline.representative_response is None:
            return 1.0
        return self._analyzer.compare(baseline.representative_response, response).score

    def is_error_response(
        self,
        baseline: EndpointBaseline,
        response: HTTPResponse,
    ) -> bool:
        """True if *response* resembles the application's error profile."""
        return baseline.is_error_response(response)

    def is_size_anomaly(
        self,
        baseline:  EndpointBaseline,
        response:  HTTPResponse,
        sigma:     float = 3.0,
    ) -> bool:
        """True if the response body size deviates by more than *sigma* std-devs."""
        return baseline.is_size_anomaly(response, sigma=sigma)

    def strip_dynamic_tokens(
        self,
        baseline: EndpointBaseline,
        text:     str,
    ) -> str:
        """Return *text* with all known rotating values replaced by ``__DYN__``."""
        return baseline.strip_dynamic_tokens(text)

    async def invalidate(self, url: str, param: str) -> None:
        """Remove a cached baseline so it is rebuilt on next access."""
        cache_key = (self._normalise_url(url), param)
        async with self._lock:
            self._cache.pop(cache_key, None)

    async def invalidate_all(self) -> None:
        """Clear the entire baseline cache."""
        async with self._lock:
            self._cache.clear()

    def export_snapshot(self) -> Dict[str, Any]:
        """
        Export the full cache as a serialisable dict.
        Useful for persisting baselines across scan phases.
        """
        return {
            "total_builds":  self._total_builds,
            "total_probes":  self._total_probes,
            "cache_hits":    self._cache_hits,
            "build_errors":  self._build_errors,
            "baselines": {
                f"{k[0]}::{k[1]}": v.to_dict()
                for k, v in self._cache.items()
            },
        }

    def stats(self) -> Dict[str, Any]:
        """Return engine-level operational statistics."""
        return {
            "cache_size":    len(self._cache),
            "total_builds":  self._total_builds,
            "total_probes":  self._total_probes,
            "cache_hits":    self._cache_hits,
            "build_errors":  self._build_errors,
            "hit_rate":      (
                self._cache_hits / max(self._cache_hits + self._total_builds, 1)
            ),
        }

    # ── Internal: baseline construction ──────────────────────────────────────

    async def _build_baseline(
        self,
        url:           str,
        param:         str,
        benign_value:  str,
        method:        str,
        extra_headers: Dict[str, str],
        base_body:     Dict[str, str],
    ) -> EndpointBaseline:
        """
        Full baseline construction pipeline.

        Stage 1 — Warm-up probe (discarded)
        Stage 2 — N benign probes → timing, size, structure, headers
        Stage 3 — Dynamic token extraction
        Stage 4 — Coherence scoring
        Stage 5 — Error profile construction
        Stage 6 — Assembly
        """
        t_start = time.monotonic()

        # ── Stage 1: warm-up ─────────────────────────────────────────────
        warmup_url = self._inject_param(url, param, benign_value, method, base_body)
        await self._fire(url=warmup_url[0], method=method,
                         headers=extra_headers, body=warmup_url[1])
        await asyncio.sleep(0.05)  # brief pause after warm-up

        # ── Stage 2: N benign probes ─────────────────────────────────────
        timings:   List[float]        = []
        sizes:     List[int]          = []
        responses: List[HTTPResponse] = []
        bodies:    List[str]          = []

        for _ in range(self._samples):
            injected_url, injected_body = self._inject_param(
                url, param, benign_value, method, base_body
            )
            t0   = time.monotonic()
            resp = await self._fire(injected_url, method, extra_headers, injected_body)
            elapsed = time.monotonic() - t0

            if resp is not None:
                resp.elapsed = elapsed
                timings.append(elapsed)
                sizes.append(len(resp.content))
                responses.append(resp)
                if resp.is_text:
                    bodies.append(resp.text)
            self._total_probes += 1

            # Small inter-probe delay to avoid contaminating timing with queuing
            await asyncio.sleep(0.02)

        if not responses:
            self._build_errors += 1
            return EndpointBaseline(
                url=url,
                parameter=param,
                status=BaselineStatus.FAILED,
                build_duration=time.monotonic() - t_start,
            )

        # ── Stage 3: dynamic token extraction ────────────────────────────
        dynamic_tokens = _extract_dynamic_tokens(bodies)

        # ── Stage 4: coherence scoring ────────────────────────────────────
        coherence = self._compute_coherence(responses)

        # ── Stage 5: timing & size models ────────────────────────────────
        timing_stats = _build_timing_stats(timings)
        size_baseline = SizeBaseline.from_sizes(sizes)
        stability     = _compute_stability(timings)

        # ── Stage 6: header baseline ──────────────────────────────────────
        header_baseline = _build_header_baseline(responses)

        # Redirect model from representative response
        rep = responses[-1]
        redirect_baseline = RedirectBaseline(
            chain_length=0,
            final_url=rep.url if hasattr(rep, "url") else None,
        )

        # Cache / ETag behaviour
        cache_ctrl = rep.headers.get("cache-control", "").lower()
        has_etag   = "etag" in rep.headers
        is_cached  = "max-age" in cache_ctrl or "public" in cache_ctrl

        # Content-type classification
        content_type = _classify_content_type(rep)

        # ── Stage 7: error profile ────────────────────────────────────────
        error_profile = ErrorProfile()
        if self._build_error_profile:
            error_profile = await self._build_error_profile_for(
                url=url, param=param, method=method,
                extra_headers=extra_headers, base_body=base_body,
                representative=rep,
            )

        # ── Determine status ──────────────────────────────────────────────
        if len(responses) == self._samples:
            status = BaselineStatus.COMPLETE
        elif len(responses) >= 2:
            status = BaselineStatus.PARTIAL
        else:
            status = BaselineStatus.MINIMAL

        baseline = EndpointBaseline(
            url=url,
            parameter=param,
            status=status,
            content_type=content_type,
            stability=stability,
            timing=timing_stats,
            size=size_baseline,
            representative_response=rep,
            coherence_score=coherence,
            structure_threshold=self._structural_threshold,
            dynamic_tokens=dynamic_tokens,
            headers=header_baseline,
            redirects=redirect_baseline,
            errors=error_profile,
            is_cached=is_cached,
            has_etag=has_etag,
            sample_bodies=bodies[:3],   # keep up to 3 for diagnostics
            probe_count=len(responses),
            build_duration=time.monotonic() - t_start,
        )
        # Re-initialise mask pattern after construction
        baseline._mask_pattern = _build_mask_pattern(dynamic_tokens)
        return baseline

    async def _build_error_profile_for(
        self,
        url:            str,
        param:          str,
        method:         str,
        extra_headers:  Dict[str, str],
        base_body:      Dict[str, str],
        representative: HTTPResponse,
    ) -> ErrorProfile:
        """
        Fire deliberate 404 / 400 probes and build an ErrorProfile.

        Uses a random-suffix strategy for 404 detection that is identical to
        what DirBuster / Feroxbuster uses to detect soft-404 applications.
        """
        profile = ErrorProfile()

        # 404 probe — use a non-existent path suffix
        try:
            nf_url = self._inject_404_url(url)
            resp_404 = await self._fire(nf_url, "GET", extra_headers, {})
            self._total_probes += 1
            if resp_404 is not None:
                profile.not_found_status   = resp_404.status_code
                profile.not_found_size_mean = len(resp_404.content)
                if resp_404.status_code == 200:
                    # Soft-404 application
                    profile.soft_404_detected = True
                    profile.soft_404_body_size = len(resp_404.content)
                    if resp_404.is_text:
                        profile.soft_404_keywords = _extract_soft_404_signals(
                            resp_404.text
                        )
                        # Also compare with representative to find stable 404 signal
                        if not profile.soft_404_keywords:
                            # No obvious keywords — use size as the signal
                            profile.soft_404_body_size = len(resp_404.content)
                if resp_404.is_text:
                    profile.not_found_body_sig = resp_404.text[:200]
        except Exception:
            pass

        # 400 probe — inject a null byte into the parameter
        try:
            bad_url, bad_body = self._inject_param(
                url, param, _BAD_INPUT_400, method, base_body
            )
            resp_400 = await self._fire(bad_url, method, extra_headers, bad_body)
            self._total_probes += 1
            if resp_400 is not None:
                profile.bad_request_status = resp_400.status_code
                if resp_400.is_text:
                    profile.bad_request_body_sig = resp_400.text[:200]
        except Exception:
            pass

        # 500 probe — only if the representative response showed it was injectable
        # (avoid inadvertently triggering real vulnerabilities in error profiling)
        # We use a very mild invalid-type value rather than a real SQLi payload
        try:
            err_url, err_body = self._inject_param(
                url, param, "'''", method, base_body
            )
            resp_500 = await self._fire(err_url, method, extra_headers, err_body)
            self._total_probes += 1
            if resp_500 is not None and resp_500.status_code >= 500:
                profile.server_error_status = resp_500.status_code
                if resp_500.is_text:
                    profile.server_error_body_sig = resp_500.text[:200]
        except Exception:
            pass

        return profile

    # ── Coherence scoring ─────────────────────────────────────────────────────

    def _compute_coherence(self, responses: List[HTTPResponse]) -> float:
        """
        Compute mean pairwise structural similarity across all baseline samples.
        A coherence of 1.0 means the server returns identical structure every time.
        """
        if len(responses) < 2:
            return 1.0

        scores: List[float] = []
        # Compare each response to the first (reference), not all pairs,
        # to keep complexity O(n) instead of O(n²).
        reference = responses[0]
        for other in responses[1:]:
            sim = self._analyzer.compare(reference, other)
            scores.append(sim.score)

        return statistics.mean(scores) if scores else 1.0

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    async def _fire(
        self,
        url:     str,
        method:  str,
        headers: Dict[str, str],
        body:    Dict[str, str],
    ) -> Optional[HTTPResponse]:
        """Dispatch a single HTTP request, swallowing all errors."""
        try:
            m = method.upper()
            if m == "POST":
                return await self._client.post(url, data=body, headers=headers)
            elif m == "PUT":
                return await self._client.put(url, data=body, headers=headers)
            elif m == "PATCH":
                return await self._client.patch(url, data=body, headers=headers)
            else:
                return await self._client.get(url, headers=headers)
        except Exception:
            return None

    # ── Injection helpers ─────────────────────────────────────────────────────

    def _inject_param(
        self,
        url:         str,
        param:       str,
        value:       str,
        method:      str,
        base_body:   Dict[str, str],
    ) -> Tuple[str, Dict[str, str]]:
        """
        Inject *value* for *param* into the URL query string (GET) or body (POST).
        Returns (url, body_dict).
        """
        if method.upper() in ("GET", "HEAD", "DELETE"):
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [value]
            new_query = urlencode(params, doseq=True)
            injected_url = urlunparse(parsed._replace(query=new_query))
            return injected_url, {}
        else:
            new_body = dict(base_body)
            new_body[param] = value
            return url, new_body

    @staticmethod
    def _inject_404_url(url: str) -> str:
        """
        Construct a URL that should return a 404 from any well-behaved server.
        Uses a random-looking but deterministic suffix to avoid false positives.
        """
        parsed = urlparse(url)
        suffix = hashlib.md5(url.encode()).hexdigest()[:8]  # noqa: S324  deterministic
        new_path = parsed.path.rstrip("/") + f"/__ws_nf_{suffix}__"
        return urlunparse(parsed._replace(path=new_path, query="", fragment=""))

    @staticmethod
    def _normalise_url(url: str) -> str:
        """
        Normalise a URL for use as a cache key.
        Strips query string, fragment, and trailing slashes; lowercases scheme/host.
        """
        try:
            p = urlparse(url)
            path = p.path.rstrip("/") or "/"
            return urlunparse((
                p.scheme.lower(),
                p.netloc.lower(),
                path,
                "",   # params
                "",   # query — intentionally stripped
                "",   # fragment
            ))
        except Exception:
            return url

    @staticmethod
    def _choose_benign_value(param: str) -> str:
        """
        Choose a sensible benign probe value based on the parameter name.
        """
        name_lower = param.lower()
        if any(kw in name_lower for kw in ("id", "pk", "num", "count", "page", "limit", "offset", "size")):
            return _BENIGN_VALUES["numeric"]
        if any(kw in name_lower for kw in ("email", "mail")):
            return _BENIGN_VALUES["email"]
        if any(kw in name_lower for kw in ("uuid", "guid")):
            return _BENIGN_VALUES["uuid"]
        if any(kw in name_lower for kw in ("date", "time", "from", "to", "start", "end")):
            return _BENIGN_VALUES["date"]
        if any(kw in name_lower for kw in ("path", "file", "dir", "folder", "url")):
            return _BENIGN_VALUES["path"]
        if any(kw in name_lower for kw in ("q", "query", "search", "keyword", "term", "text", "name")):
            return _BENIGN_VALUES["query"]
        if any(kw in name_lower for kw in ("enable", "active", "flag", "show", "debug", "verbose")):
            return _BENIGN_VALUES["bool"]
        return _BENIGN_VALUES["default"]


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function: build a standalone baseline for one endpoint
# ─────────────────────────────────────────────────────────────────────────────

async def build_endpoint_baseline(
    client:       HTTPClient,
    url:          str,
    param:        str,
    benign_value: Optional[str] = None,
    method:       str           = "GET",
    samples:      int           = 5,
) -> EndpointBaseline:
    """
    One-shot helper — creates a temporary ``BaselineEngine`` and returns an
    ``EndpointBaseline`` for the given endpoint.

    Intended for use by individual scanners that need a quick baseline without
    access to the shared engine.

    Parameters
    ----------
    client : HTTPClient
    url    : str
    param  : str
    benign_value : str, optional
    method : str
    samples : int

    Returns
    -------
    EndpointBaseline
    """
    engine = BaselineEngine(client=client, samples=samples)
    return await engine.get_baseline(
        url=url,
        param=param,
        benign_value=benign_value,
        method=method,
    )
