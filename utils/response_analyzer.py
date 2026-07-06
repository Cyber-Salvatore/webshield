"""
Response Similarity Engine — Phase 4.1
=======================================
Compares HTTP responses structurally to detect meaningful differences
and reduce false positives in blind injection testing.

Algorithm:
  - Status code match       (weight 0.30)
  - Content-Type match      (weight 0.10)
  - JSON structure similarity(weight 0.40) — same keys hierarchy?
  - HTML DOM tag similarity  (weight 0.20)

Returns a float 0.0 (completely different) → 1.0 (identical structure).
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from ..core.http_client import HTTPResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_key_set(obj: Any, prefix: str = "", depth: int = 0) -> Set[str]:
    """
    Recursively collect all key paths from a JSON object.
    E.g. {"user": {"id": 1}} → {"user", "user.id"}
    Capped at depth 6 to avoid exponential explosion on deep objects.
    """
    keys: Set[str] = set()
    if depth > 6:
        return keys
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            keys.add(path)
            keys |= _json_key_set(v, path, depth + 1)
    elif isinstance(obj, list) and obj:
        # Only recurse into the first element — structure probe, not data probe
        keys |= _json_key_set(obj[0], prefix, depth + 1)
    return keys


_HTML_TAG_RE = re.compile(r"<([a-z][a-z0-9]*)", re.IGNORECASE)


def _html_tag_freq(html: str) -> Dict[str, int]:
    """Return a frequency map of HTML tags (lowercased)."""
    freq: Dict[str, int] = {}
    for m in _HTML_TAG_RE.finditer(html[:30_000]):
        tag = m.group(1).lower()
        freq[tag] = freq.get(tag, 0) + 1
    return freq


def _jaccard(set_a: Set[str], set_b: Set[str]) -> float:
    """Jaccard similarity: |A ∩ B| / |A ∪ B|"""
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 1.0


def _cosine_freq(a: Dict[str, int], b: Dict[str, int]) -> float:
    """Cosine similarity between two frequency dicts."""
    if not a and not b:
        return 1.0
    all_keys = set(a) | set(b)
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in all_keys)
    mag_a = sum(v * v for v in a.values()) ** 0.5
    mag_b = sum(v * v for v in b.values()) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# ---------------------------------------------------------------------------
# SimilarityResult
# ---------------------------------------------------------------------------

class SimilarityResult:
    """Structured result from a response comparison."""

    def __init__(
        self,
        score: float,
        status_match: bool,
        content_type_match: bool,
        json_score: float,
        html_score: float,
        size_ratio: float,
    ) -> None:
        self.score = round(score, 4)
        self.status_match = status_match
        self.content_type_match = content_type_match
        self.json_score = round(json_score, 4)
        self.html_score = round(html_score, 4)
        self.size_ratio = round(size_ratio, 4)

    @property
    def is_similar(self) -> bool:
        """True when the two responses are structurally similar (score ≥ 0.75)."""
        return self.score >= 0.75

    @property
    def is_different(self) -> bool:
        """True when responses differ meaningfully (score < 0.50)."""
        return self.score < 0.50

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "is_similar": self.is_similar,
            "status_match": self.status_match,
            "content_type_match": self.content_type_match,
            "json_structure_score": self.json_score,
            "html_tag_score": self.html_score,
            "size_ratio": self.size_ratio,
        }

    def __repr__(self) -> str:
        label = "SIMILAR" if self.is_similar else ("DIFFERENT" if self.is_different else "AMBIGUOUS")
        return f"SimilarityResult({label}, score={self.score})"


# ---------------------------------------------------------------------------
# ResponseAnalyzer
# ---------------------------------------------------------------------------

class ResponseAnalyzer:
    """
    Phase 4.1 — Response Similarity Engine.

    Usage::

        analyzer = ResponseAnalyzer()
        result = analyzer.compare(baseline_response, test_response)
        if result.is_different:
            # Likely a real injection effect
            ...
    """

    # Weights must sum to 1.0
    _W_STATUS       = 0.30
    _W_CONTENT_TYPE = 0.10
    _W_JSON         = 0.40
    _W_HTML         = 0.20

    # ---------------------------------------------------------------------------

    def compare(
        self,
        baseline: HTTPResponse,
        test: HTTPResponse,
    ) -> SimilarityResult:
        """
        Compare two HTTP responses and return a SimilarityResult.

        The composite score reflects structural similarity:
        - 1.0 → responses look identical
        - 0.0 → completely different structure
        """
        # ── Status code (binary) ──────────────────────────────────────────
        status_match = baseline.status_code == test.status_code
        status_score = 1.0 if status_match else 0.0

        # ── Content-Type (partial credit for sub-type mismatch) ──────────
        base_ct = (baseline.content_type or "").split(";")[0].strip().lower()
        test_ct = (test.content_type or "").split(";")[0].strip().lower()
        content_type_match = base_ct == test_ct
        ct_score = 1.0 if content_type_match else 0.0

        # ── Body size ratio (used for context, not directly in score) ─────
        base_len = len(baseline.content) or 1
        test_len = len(test.content) or 1
        size_ratio = min(base_len, test_len) / max(base_len, test_len)

        # ── Structural similarity based on content type ───────────────────
        json_score = 0.0
        html_score = 0.0

        if "json" in base_ct:
            json_score = self._json_similarity(baseline.text, test.text)
            html_score = json_score  # reuse for weight calc
        elif "html" in base_ct or "xml" in base_ct:
            html_score = self._html_similarity(baseline.text, test.text)
            json_score = html_score
        else:
            # Plain text / unknown — use size ratio as structural proxy
            html_score = size_ratio
            json_score = size_ratio

        # ── Composite score ───────────────────────────────────────────────
        # When content types differ, structural scores are meaningless —
        # penalise heavily.
        if not content_type_match:
            structural = 0.2  # default low
        elif "json" in base_ct:
            structural = json_score * (self._W_JSON / (self._W_JSON + self._W_HTML)) + \
                         html_score * (self._W_HTML / (self._W_JSON + self._W_HTML))
        else:
            structural = html_score

        score = (
            status_score * self._W_STATUS
            + ct_score * self._W_CONTENT_TYPE
            + structural * (self._W_JSON + self._W_HTML)
        )

        return SimilarityResult(
            score=min(max(score, 0.0), 1.0),
            status_match=status_match,
            content_type_match=content_type_match,
            json_score=json_score,
            html_score=html_score,
            size_ratio=size_ratio,
        )

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _json_similarity(text_a: str, text_b: str) -> float:
        """
        Jaccard similarity of the key-path sets of two JSON documents.
        Falls back to size ratio on parse error.
        """
        try:
            obj_a = json.loads(text_a)
            obj_b = json.loads(text_b)
            keys_a = _json_key_set(obj_a)
            keys_b = _json_key_set(obj_b)
            # Empty objects → identical structure
            if not keys_a and not keys_b:
                return 1.0
            return _jaccard(keys_a, keys_b)
        except (json.JSONDecodeError, Exception):
            # Not valid JSON — fall back to size ratio
            len_a = len(text_a) or 1
            len_b = len(text_b) or 1
            return min(len_a, len_b) / max(len_a, len_b)

    @staticmethod
    def _html_similarity(text_a: str, text_b: str) -> float:
        """
        Cosine similarity of HTML tag frequency distributions.
        """
        freq_a = _html_tag_freq(text_a)
        freq_b = _html_tag_freq(text_b)
        if not freq_a and not freq_b:
            # Empty pages — treat as identical
            return 1.0
        return _cosine_freq(freq_a, freq_b)

    # -----------------------------------------------------------------------
    # Batch helpers
    # -----------------------------------------------------------------------

    def is_anomalous(
        self,
        baseline: HTTPResponse,
        tests: List[HTTPResponse],
        threshold: float = 0.50,
    ) -> Tuple[bool, float]:
        """
        Check if ANY test response is structurally anomalous vs the baseline.

        Returns (anomaly_detected: bool, min_score: float).
        """
        if not tests:
            return False, 1.0
        scores = [self.compare(baseline, t).score for t in tests]
        min_score = min(scores)
        return min_score < threshold, min_score

    def average_similarity(
        self,
        baseline: HTTPResponse,
        tests: List[HTTPResponse],
    ) -> float:
        """Average similarity score across multiple test responses."""
        if not tests:
            return 1.0
        scores = [self.compare(baseline, t).score for t in tests]
        return sum(scores) / len(scores)
