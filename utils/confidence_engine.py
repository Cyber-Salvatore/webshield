"""
Confidence Scoring Engine — Phase 4.3
=======================================
Calculates a confidence score for a vulnerability finding from multiple
independent signals, then maps it to a human-readable label.

Score factors (weights must sum to 1.0):
  ┌─────────────────────────────────────────────┬────────┐
  │ Factor                                      │ Weight │
  ├─────────────────────────────────────────────┼────────┤
  │ Confirmation count  (1 vs 3+ requests)      │  0.30  │
  │ Response similarity vs baseline             │  0.25  │
  │ Evidence quality    (literal vs timing)     │  0.25  │
  │ Timing consistency  (std-dev of repeats)    │  0.20  │
  └─────────────────────────────────────────────┴────────┘

Labels:
  ≥ 0.75  → "High"           (exploit directly)
  ≥ 0.50  → "Medium"         (likely real, verify first)
  ≥ 0.25  → "Low"            (weak signal, manual review)
  < 0.25  → "Speculative"    (noise / coincidence)

Findings with score < 0.50 are flagged with
  false_positive_risk = "High"
and confidence = "Needs Verification".
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from ..models.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Evidence quality levels (ordered worst → best)
# ---------------------------------------------------------------------------

class EvidenceQuality(float, Enum):
    """
    Numeric value maps directly to the evidence-quality component score.
    Higher = more trustworthy signal.
    """
    TIMING_SINGLE   = 0.20   # single timing measurement (jitter-prone)
    TIMING_MULTIPLE = 0.45   # multiple consistent timing measurements
    SIZE_CHANGE     = 0.50   # response size differed significantly
    STRUCTURAL_DIFF = 0.65   # structural JSON/HTML difference detected
    ERROR_MESSAGE   = 0.75   # recognisable error string in response
    REFLECTION      = 0.85   # payload reflected literally in response
    EXEC_OUTPUT     = 1.00   # command output / file read confirmed


# ---------------------------------------------------------------------------
# ConfidenceInput — all signals for one finding
# ---------------------------------------------------------------------------

@dataclass
class ConfidenceInput:
    """
    Collect all available signals for one vulnerability finding.

    Only ``confirmation_count`` is mandatory; everything else is optional
    and defaults to a conservative (low-confidence) value.
    """
    # How many independent requests confirmed the finding (1 = minimal evidence)
    confirmation_count: int = 1

    # Structural similarity score (0–1) from ResponseAnalyzer.compare()
    # 0.0 = completely different from baseline (strong anomaly)
    # 1.0 = identical to baseline (no anomaly)
    # None = not measured
    response_similarity: Optional[float] = None

    # Evidence quality — use EvidenceQuality enum values
    evidence_quality: EvidenceQuality = EvidenceQuality.TIMING_SINGLE

    # Elapsed times for all confirming requests (seconds)
    # Used to compute timing consistency.  Empty list → not applicable.
    timing_samples: List[float] = field(default_factory=list)

    # Expected delay (seconds) for time-based tests.
    # When set, consistency is measured relative to this value.
    expected_delay: Optional[float] = None


# ---------------------------------------------------------------------------
# ConfidenceResult
# ---------------------------------------------------------------------------

@dataclass
class ConfidenceResult:
    """Output of the confidence engine for one finding."""
    score: float           # raw score 0.0 – 1.0
    label: str             # "High" / "Medium" / "Low" / "Speculative"
    fp_risk: str           # "Low" / "Medium" / "High"
    needs_verification: bool

    # Component scores for debugging / transparency
    confirmation_score: float
    similarity_score: float
    evidence_score: float
    timing_score: float

    def apply_to_vuln(self, vuln: Vulnerability) -> Vulnerability:
        """
        Mutate the Vulnerability in place with the computed confidence/FP risk.
        Returns the same object for chaining convenience.
        """
        vuln.confidence = (
            "Needs Verification" if self.needs_verification else self.label
        )
        vuln.false_positive_risk = self.fp_risk
        return vuln

    def __str__(self) -> str:
        return (
            f"Confidence({self.label}, score={self.score:.2f}, "
            f"fp_risk={self.fp_risk}, "
            f"conf={self.confirmation_score:.2f} "
            f"sim={self.similarity_score:.2f} "
            f"evid={self.evidence_score:.2f} "
            f"time={self.timing_score:.2f})"
        )


# ---------------------------------------------------------------------------
# ConfidenceEngine
# ---------------------------------------------------------------------------

class ConfidenceEngine:
    """
    Phase 4.3 — Confidence Scoring Engine.

    Usage::

        engine = ConfidenceEngine()

        result = engine.score(ConfidenceInput(
            confirmation_count=3,
            response_similarity=0.15,          # very different from baseline
            evidence_quality=EvidenceQuality.REFLECTION,
            timing_samples=[5.02, 5.11, 4.99],
            expected_delay=5.0,
        ))

        result.apply_to_vuln(vuln)
    """

    # Weights (must sum to 1.0)
    _W_CONFIRMATION = 0.30
    _W_SIMILARITY   = 0.25
    _W_EVIDENCE     = 0.25
    _W_TIMING       = 0.20

    # Label thresholds
    _THRESH_HIGH         = 0.75
    _THRESH_MEDIUM       = 0.50
    _THRESH_LOW          = 0.25

    # ---------------------------------------------------------------------------

    def score(self, signals: ConfidenceInput) -> ConfidenceResult:
        """Compute confidence from the provided signals."""

        conf_score = self._confirmation_component(signals.confirmation_count)
        sim_score  = self._similarity_component(signals.response_similarity)
        evid_score = float(signals.evidence_quality)
        time_score = self._timing_component(signals.timing_samples, signals.expected_delay)

        composite = (
            conf_score * self._W_CONFIRMATION
            + sim_score  * self._W_SIMILARITY
            + evid_score * self._W_EVIDENCE
            + time_score * self._W_TIMING
        )
        composite = round(min(max(composite, 0.0), 1.0), 4)

        label, fp_risk, needs_verification = self._classify(composite)

        return ConfidenceResult(
            score=composite,
            label=label,
            fp_risk=fp_risk,
            needs_verification=needs_verification,
            confirmation_score=conf_score,
            similarity_score=sim_score,
            evidence_score=evid_score,
            timing_score=time_score,
        )

    # -----------------------------------------------------------------------
    # Quick-score helpers (convenience wrappers)
    # -----------------------------------------------------------------------

    def score_literal(self, confirmations: int = 1) -> ConfidenceResult:
        """Shortcut for findings with literal payload reflection."""
        return self.score(ConfidenceInput(
            confirmation_count=confirmations,
            response_similarity=0.10,          # response clearly changed
            evidence_quality=EvidenceQuality.REFLECTION,
        ))

    def score_error_based(self, confirmations: int = 1) -> ConfidenceResult:
        """Shortcut for error-based injection findings."""
        return self.score(ConfidenceInput(
            confirmation_count=confirmations,
            response_similarity=0.30,
            evidence_quality=EvidenceQuality.ERROR_MESSAGE,
        ))

    def score_time_based(
        self,
        timing_samples: List[float],
        expected_delay: float,
        confirmations: int = 1,
    ) -> ConfidenceResult:
        """Shortcut for time-based injection findings."""
        return self.score(ConfidenceInput(
            confirmation_count=confirmations,
            response_similarity=None,           # timing-based — no structural diff
            evidence_quality=(
                EvidenceQuality.TIMING_MULTIPLE
                if len(timing_samples) >= 3
                else EvidenceQuality.TIMING_SINGLE
            ),
            timing_samples=timing_samples,
            expected_delay=expected_delay,
        ))

    def score_blind(self, similarity: float, confirmations: int = 1) -> ConfidenceResult:
        """Shortcut for blind structural-difference findings."""
        return self.score(ConfidenceInput(
            confirmation_count=confirmations,
            response_similarity=similarity,
            evidence_quality=EvidenceQuality.STRUCTURAL_DIFF,
        ))

    # -----------------------------------------------------------------------
    # Component scorers
    # -----------------------------------------------------------------------

    @staticmethod
    def _confirmation_component(count: int) -> float:
        """
        Maps confirmation count to a 0–1 score.
          1  → 0.30  (minimum evidence)
          2  → 0.60
          3  → 0.85
          4+ → 1.00
        """
        mapping = {1: 0.30, 2: 0.60, 3: 0.85}
        return mapping.get(count, 1.00 if count >= 4 else 0.30)

    @staticmethod
    def _similarity_component(similarity: Optional[float]) -> float:
        """
        A *lower* structural similarity means the response changed more → higher
        confidence that something happened.

          similarity = 0.0  (totally different) → component score 1.0
          similarity = 0.5  (half different)    → component score 0.5
          similarity = 1.0  (identical)         → component score 0.0
          None              (not measured)      → neutral 0.5
        """
        if similarity is None:
            return 0.50
        # Invert: high similarity = low confidence something changed
        return round(1.0 - min(max(similarity, 0.0), 1.0), 4)

    @staticmethod
    def _timing_component(samples: List[float], expected: Optional[float]) -> float:
        """
        Measures how consistently the timing samples match the expected delay.

        No samples → neutral (0.50)
        High variance → low score
        Samples consistently near expected → high score
        """
        if not samples:
            return 0.50

        if expected is None:
            # No expected delay provided — check internal consistency only
            mean = sum(samples) / len(samples)
            if mean < 0.5:
                return 0.20   # very fast, suspicious timing hit
            variance = sum((t - mean) ** 2 for t in samples) / len(samples)
            std = variance ** 0.5
            cv = std / mean if mean > 0 else 1.0   # coefficient of variation
            # Low CV (consistent) → high timing score
            return round(max(0.0, 1.0 - min(cv, 1.0)), 4)

        # We know the expected delay — check how close samples are
        # Allow ±30% tolerance around expected
        tolerance = max(expected * 0.30, 0.5)
        consistent = sum(
            1 for t in samples
            if abs(t - expected) <= tolerance
        )
        ratio = consistent / len(samples)
        # More consistent = higher score
        return round(ratio, 4)

    # -----------------------------------------------------------------------

    def _classify(self, score: float) -> tuple[str, str, bool]:
        """
        Returns (label, fp_risk, needs_verification).
        """
        if score >= self._THRESH_HIGH:
            return "High", "Low", False
        elif score >= self._THRESH_MEDIUM:
            return "Medium", "Medium", False
        elif score >= self._THRESH_LOW:
            return "Low", "High", True
        else:
            return "Speculative", "High", True
