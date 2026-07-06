# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Confidence Framework — Part 17 of the Intelligence Layer.

Every other engine in the Intelligence Layer produces *signals*, not verdicts:

  • the Baseline Engine            (Part 15) emits ``BaselineComparison``
  • the Differential Analysis Engine (Part 16) emits ``DiffResult``
  • ``ReflectionTracker``           emits reflection / encoding observations
  • ``TimingAnalyzer``              emits statistical timing anomalies
  • scanners themselves             emit raw request/response evidence

None of those signals is, by itself, proof of a vulnerability.  The
Confidence Framework is the single place where all of that evidence is
collected, weighed, cross-checked against itself, and converted into one
precise, reproducible ``ConfidenceScore`` per finding — replacing the
previous pattern of scanners eyeballing "looks reflected, probably XSS"
with a disciplined, auditable scoring pipeline.

Design goals
------------
1.  **Every piece of evidence is typed.**  A reflected payload is not the
    same kind of proof as a 1.2-second timing delay, and the framework
    must never treat them as equal.
2.  **Confirmations matter, with diminishing returns.**  A finding
    confirmed three independent times is much stronger than one seen
    once, but the fourth and fifth confirmation add very little extra —
    the framework models this with a saturating curve instead of a
    linear one.
3.  **Agreement with the Baseline / Differential engines is a first-class
    citizen.**  ``BaselineComparison.confidence_boost`` and
    ``DiffResult.confidence_boost`` were *designed* to feed this module
    (see their docstrings) — both are accepted directly.
4.  **Relationships between evidence change the score.**  Two
    independent, differently-typed pieces of evidence that agree
    ("corroboration") should boost confidence beyond what either would
    earn alone.  Evidence that contradicts another piece (most commonly
    a negative-control probe coming back *positive*, i.e. the "anomaly"
    fires even without the payload) should pull the score down hard —
    this is the project's primary defence against false positives before
    the dedicated Triple-Confirmation Framework (Part 18) and Evidence
    Collection Framework (Part 19) layer additional safeguards on top.
5.  **The relationship ledger this module keeps (``EvidenceRelationship``)
    is intentionally generic** so the forthcoming Evidence Graph
    (Part 20) can adopt it directly as its edge representation rather
    than reinventing one.

Nothing here is a hard gate — scanners decide for themselves whether a
score is high enough to report.  The framework's job is only to make that
decision *informed*.
"""
from __future__ import annotations

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Evidence taxonomy
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceType(str, Enum):
    """
    Every kind of proof the Intelligence Layer is able to produce, ordered
    loosely from weakest to strongest standalone signal.  The numeric base
    quality used by the scorer lives in ``_EVIDENCE_BASE_QUALITY`` below —
    keeping the enum and the weights separate means new evidence types can
    be added without touching scoring call-sites.
    """
    TIMING_ANOMALY        = "timing_anomaly"          # statistical delay vs baseline
    SIZE_ANOMALY          = "size_anomaly"             # response size outlier
    HEADER_ANOMALY        = "header_anomaly"           # appeared/disappeared/changed header
    REDIRECT_ANOMALY      = "redirect_anomaly"         # redirect chain / destination changed
    STATUS_CHANGE         = "status_change"            # HTTP status code differs
    JSON_STRUCTURE        = "json_structure"           # JSON key/type/value diff
    DOM_STRUCTURE         = "dom_structure"             # DOM tag/attribute diff
    STRUCTURAL_DIFF       = "structural_diff"          # generic content-similarity drop
    ERROR_MESSAGE         = "error_message"            # recognisable error string / stack trace
    REFLECTION            = "reflection"               # payload reflected in response
    DOM_INJECTION_SIGNAL  = "dom_injection_signal"      # new <script> / on*= handler appeared
    OUT_OF_BAND           = "out_of_band"               # OOB callback received (DNS/HTTP)
    EXEC_OUTPUT           = "exec_output"               # command output / file content confirmed
    STATIC_SIGNATURE      = "static_signature"          # known vulnerable version / fingerprint match
    NEGATIVE_CONTROL_OK   = "negative_control_ok"       # control probe behaved as expected (supports)
    NEGATIVE_CONTROL_FAIL = "negative_control_fail"      # control probe also fired (contradicts)
    MANUAL                = "manual"                    # human-asserted evidence


# Base quality (0..1) for each evidence type, independent of how strong the
# *instance* of that evidence was.  This is the "type" half of the
# "type of evidence" requirement from the spec; ``Evidence.strength`` is the
# per-instance half.
_EVIDENCE_BASE_QUALITY: Dict[EvidenceType, float] = {
    EvidenceType.TIMING_ANOMALY:        0.40,
    EvidenceType.SIZE_ANOMALY:          0.35,
    EvidenceType.HEADER_ANOMALY:        0.35,
    EvidenceType.REDIRECT_ANOMALY:      0.40,
    EvidenceType.STATUS_CHANGE:         0.45,
    EvidenceType.JSON_STRUCTURE:        0.55,
    EvidenceType.DOM_STRUCTURE:         0.55,
    EvidenceType.STRUCTURAL_DIFF:       0.50,
    EvidenceType.ERROR_MESSAGE:         0.75,
    EvidenceType.REFLECTION:            0.80,
    EvidenceType.DOM_INJECTION_SIGNAL:  0.90,
    EvidenceType.OUT_OF_BAND:           1.00,
    EvidenceType.EXEC_OUTPUT:           1.00,
    EvidenceType.STATIC_SIGNATURE:      0.60,
    EvidenceType.NEGATIVE_CONTROL_OK:   0.50,
    EvidenceType.NEGATIVE_CONTROL_FAIL: 0.50,   # magnitude only — sign is handled separately
    EvidenceType.MANUAL:                0.50,
}

# Evidence types whose presence is a *contradiction* of the finding rather
# than support for it (their strength is subtracted, not added).
_CONTRADICTING_TYPES = frozenset({EvidenceType.NEGATIVE_CONTROL_FAIL})


class RelationshipType(str, Enum):
    """How two pieces of evidence for the same finding relate to each other."""
    CORROBORATES = "corroborates"   # independent evidence agrees → boosts confidence
    CONTRADICTS  = "contradicts"    # evidence conflicts → lowers confidence
    DUPLICATES   = "duplicates"     # same underlying observation seen twice → no extra weight


class ConfidenceLabel(str, Enum):
    HIGH        = "High"
    MEDIUM      = "Medium"
    LOW         = "Low"
    SPECULATIVE = "Speculative"


# ─────────────────────────────────────────────────────────────────────────────
# Evidence + relationship records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """A single, atomic piece of proof collected for one finding."""
    finding_id:  str
    type:        EvidenceType
    description: str
    strength:    float = 1.0     # 0..1 — how strong *this instance* of the evidence is
    source:      str   = ""      # e.g. "differential_engine", "baseline_engine", "reflection_tracker"
    independent: bool  = True    # False if derived from the same raw request/response as another
    request_id:  Optional[str] = None
    raw_ref:     Optional[Any] = None   # optional pointer back to DiffResult / BaselineComparison / etc.
    id:          str   = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp:   float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.strength = max(0.0, min(1.0, self.strength))

    @property
    def base_quality(self) -> float:
        return _EVIDENCE_BASE_QUALITY.get(self.type, 0.5)

    @property
    def is_contradicting(self) -> bool:
        return self.type in _CONTRADICTING_TYPES

    @property
    def weighted_quality(self) -> float:
        """type-quality × instance-strength, the per-evidence contribution unit."""
        return self.base_quality * self.strength

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "type": self.type.value,
            "description": self.description,
            "strength": round(self.strength, 3),
            "source": self.source,
            "independent": self.independent,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
        }


@dataclass
class EvidenceRelationship:
    """
    An edge between two evidence records for the same finding.  Stored in a
    plain, serialisable shape on purpose — the forthcoming Evidence Graph
    (Part 20) is meant to ingest this list directly as its edge set.
    """
    source_id: str
    target_id: str
    relation:  RelationshipType
    note:      str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation.value,
            "note": self.note,
        }


@dataclass
class ConfidenceScore:
    """The final, precise confidence verdict for one finding."""
    finding_id:             str
    value:                  float
    label:                  ConfidenceLabel
    breakdown:              Dict[str, float] = field(default_factory=dict)
    evidence_count:         int = 0
    distinct_evidence_types: int = 0
    corroboration_count:    int = 0
    contradiction_count:    int = 0
    contributing_evidence:  List[str] = field(default_factory=list)
    false_positive_risk:    str = "High"
    needs_verification:     bool = True
    explanation:            List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "value": round(self.value, 4),
            "label": self.label.value,
            "breakdown": {k: round(v, 4) for k, v in self.breakdown.items()},
            "evidence_count": self.evidence_count,
            "distinct_evidence_types": self.distinct_evidence_types,
            "corroboration_count": self.corroboration_count,
            "contradiction_count": self.contradiction_count,
            "contributing_evidence": self.contributing_evidence,
            "false_positive_risk": self.false_positive_risk,
            "needs_verification": self.needs_verification,
            "explanation": self.explanation,
        }


def _label_for(value: float) -> ConfidenceLabel:
    if value >= 0.75:
        return ConfidenceLabel.HIGH
    if value >= 0.50:
        return ConfidenceLabel.MEDIUM
    if value >= 0.25:
        return ConfidenceLabel.LOW
    return ConfidenceLabel.SPECULATIVE


def _fp_risk_for(value: float) -> str:
    if value >= 0.75:
        return "Low"
    if value >= 0.50:
        return "Medium"
    return "High"


# ─────────────────────────────────────────────────────────────────────────────
# The framework itself
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceFramework:
    """
    Central evidence ledger + scorer, shared across an entire scan.

    One instance is normally created per ``ScanEngine`` run and handed to
    every scanner so all findings are scored on the same, consistent scale.

    Usage
    -----
        cf = ConfidenceFramework()
        cf.add_evidence(finding_id, EvidenceType.REFLECTION,
                         "payload reflected unescaped in <script> context",
                         strength=0.9, source="reflection_tracker")
        cf.add_evidence_from_diff(finding_id, diff_result)
        score = cf.compute_confidence(finding_id)
    """

    # Component weights — must sum to 1.0
    _W_CONFIRMATION  = 0.30
    _W_EVIDENCE_TYPE = 0.25
    _W_BASELINE      = 0.25
    _W_RELATIONSHIP  = 0.20

    # Sources that count as "baseline/differential agreement" evidence for
    # the dedicated baseline-agreement scoring component.
    _BASELINE_SOURCES = frozenset({"baseline_engine", "differential_engine"})

    def __init__(self) -> None:
        self._evidence: Dict[str, List[Evidence]] = defaultdict(list)
        self._evidence_index: Dict[str, Evidence] = {}
        self._relationships: List[EvidenceRelationship] = []
        self._scores: Dict[str, ConfidenceScore] = {}

    # ── Ingestion ────────────────────────────────────────────────────────

    def add_evidence(
        self,
        finding_id: str,
        type: EvidenceType,
        description: str,
        *,
        strength: float = 1.0,
        source: str = "",
        independent: bool = True,
        request_id: Optional[str] = None,
        raw_ref: Optional[Any] = None,
    ) -> Evidence:
        """Register one piece of evidence and return the stored record."""
        ev = Evidence(
            finding_id=finding_id, type=type, description=description,
            strength=strength, source=source, independent=independent,
            request_id=request_id, raw_ref=raw_ref,
        )
        self._evidence[finding_id].append(ev)
        self._evidence_index[ev.id] = ev
        self._scores.pop(finding_id, None)   # invalidate cached score
        self._auto_link(finding_id, ev)
        return ev

    def add_evidence_from_baseline(
        self, finding_id: str, comparison: Any, *, source: str = "baseline_engine",
        request_id: Optional[str] = None,
    ) -> List[Evidence]:
        """
        Ingest a ``BaselineComparison`` (Part 15) directly. One Evidence
        record is created per anomalous dimension so each contributes its
        own type/quality rather than being collapsed into a single blob.
        """
        added: List[Evidence] = []
        boost = float(getattr(comparison, "confidence_boost", 0.0))
        if boost <= 0.0:
            return added

        dim_map = [
            ("is_structurally_different", EvidenceType.STRUCTURAL_DIFF, 0.35),
            ("is_timing_anomaly",         EvidenceType.TIMING_ANOMALY,  0.30),
            ("is_size_anomaly",           EvidenceType.SIZE_ANOMALY,    0.15),
            ("is_redirect_anomaly",       EvidenceType.REDIRECT_ANOMALY, 0.15),
            ("is_header_anomaly",         EvidenceType.HEADER_ANOMALY,  0.05),
        ]
        for attr, ev_type, dim_weight in dim_map:
            if getattr(comparison, attr, False):
                # scale instance strength by this dimension's share of the
                # overall boost so a comparison with many firing dimensions
                # doesn't make every single one look maximally strong
                instance_strength = min(1.0, boost) if boost else dim_weight
                added.append(self.add_evidence(
                    finding_id, ev_type,
                    f"baseline comparison anomaly: {attr}",
                    strength=instance_strength, source=source,
                    request_id=request_id, raw_ref=comparison,
                ))
        if not added and boost > 0:
            added.append(self.add_evidence(
                finding_id, EvidenceType.STRUCTURAL_DIFF,
                "baseline comparison anomaly (unspecified dimension)",
                strength=boost, source=source, request_id=request_id,
                raw_ref=comparison,
            ))
        return added

    def add_evidence_from_diff(
        self, finding_id: str, diff_result: Any, *, source: str = "differential_engine",
        request_id: Optional[str] = None,
    ) -> List[Evidence]:
        """
        Ingest a ``DiffResult`` (Part 16) directly — the dedicated
        ``confidence_boost`` property and ``dimensions_triggered`` list on
        that object exist specifically to feed this method.
        """
        added: List[Evidence] = []
        boost = float(getattr(diff_result, "confidence_boost", 0.0))
        if boost <= 0.0:
            return added

        dom_diff = getattr(diff_result, "dom_diff", None)
        if dom_diff is not None and getattr(dom_diff, "has_injection_signal", False):
            added.append(self.add_evidence(
                finding_id, EvidenceType.DOM_INJECTION_SIGNAL,
                "new <script>/event-handler attribute appeared in response DOM",
                strength=max(boost, 0.85), source=source,
                request_id=request_id, raw_ref=diff_result,
            ))

        dims = list(getattr(diff_result, "dimensions_triggered", []) or [])
        dim_to_type = {
            "status":        EvidenceType.STATUS_CHANGE,
            "size":          EvidenceType.SIZE_ANOMALY,
            "content":       EvidenceType.STRUCTURAL_DIFF,
            "json_structure": EvidenceType.JSON_STRUCTURE,
            "dom_structure":  EvidenceType.DOM_STRUCTURE,
            "headers":       EvidenceType.HEADER_ANOMALY,
            "timing":        EvidenceType.TIMING_ANOMALY,
            "redirect":      EvidenceType.REDIRECT_ANOMALY,
        }
        for dim in dims:
            dim_value = getattr(dim, "value", dim)
            ev_type = dim_to_type.get(dim_value)
            if ev_type is None or ev_type == EvidenceType.DOM_STRUCTURE and dom_diff is not None and getattr(dom_diff, "has_injection_signal", False):
                continue   # already recorded as the stronger DOM_INJECTION_SIGNAL above
            added.append(self.add_evidence(
                finding_id, ev_type, f"differential analysis: {dim_value} dimension fired",
                strength=boost, source=source, request_id=request_id, raw_ref=diff_result,
            ))

        for snippet in (getattr(diff_result, "evidence_snippets", None) or [])[:3]:
            added.append(self.add_evidence(
                finding_id, EvidenceType.ERROR_MESSAGE,
                f"interesting content surfaced in diff: {snippet[:120]!r}",
                strength=0.8, source=source, request_id=request_id, raw_ref=diff_result,
            ))

        if not added:
            added.append(self.add_evidence(
                finding_id, EvidenceType.STRUCTURAL_DIFF,
                "differential analysis anomaly (unspecified dimension)",
                strength=boost, source=source, request_id=request_id, raw_ref=diff_result,
            ))
        return added

    def add_reflection(
        self, finding_id: str, context: str, transformations: Optional[List[str]] = None,
        *, source: str = "reflection_tracker", request_id: Optional[str] = None,
    ) -> Evidence:
        """Convenience wrapper for ``ReflectionTracker`` results."""
        transforms = ", ".join(transformations or []) or "none"
        # raw, unencoded reflection in an executable context is the strongest
        # signal; encoded/escaped reflection still counts but more weakly
        strength = 0.95 if (not transformations or "html_encoding" not in transformations) else 0.55
        return self.add_evidence(
            finding_id, EvidenceType.REFLECTION,
            f"payload reflected in {context} context (transformations: {transforms})",
            strength=strength, source=source, request_id=request_id,
        )

    def add_negative_control(
        self, finding_id: str, *, fired: bool, description: str = "",
        source: str = "triple_confirmation", request_id: Optional[str] = None,
    ) -> Evidence:
        """
        Record the result of a negative-control probe (the same request
        sent *without* the payload). If the anomaly fires anyway, that is
        strong evidence the finding is a false positive.
        """
        if fired:
            return self.add_evidence(
                finding_id, EvidenceType.NEGATIVE_CONTROL_FAIL,
                description or "anomaly also observed without the payload (negative control fired)",
                strength=0.9, source=source, request_id=request_id,
            )
        return self.add_evidence(
            finding_id, EvidenceType.NEGATIVE_CONTROL_OK,
            description or "negative control behaved as expected (no anomaly without payload)",
            strength=0.6, source=source, request_id=request_id,
        )

    # ── Relationships ───────────────────────────────────────────────────

    def link(self, source_id: str, target_id: str, relation: RelationshipType, note: str = "") -> EvidenceRelationship:
        """Manually record a relationship between two evidence records."""
        rel = EvidenceRelationship(source_id=source_id, target_id=target_id, relation=relation, note=note)
        self._relationships.append(rel)
        src = self._evidence_index.get(source_id)
        if src:
            self._scores.pop(src.finding_id, None)
        return rel

    def _auto_link(self, finding_id: str, new_ev: Evidence) -> None:
        """
        Automatically wire up obvious relationships as evidence streams in:
          • a contradicting type (failed negative control) CONTRADICTS every
            existing evidence record for the same finding
          • a new, independent evidence record of a *different* type than an
            existing one CORROBORATES it
          • a new record sharing the same ``request_id`` as an existing one
            (i.e. derived from the same probe) DUPLICATES it instead
        """
        existing = [e for e in self._evidence[finding_id] if e.id != new_ev.id]
        for other in existing:
            if new_ev.request_id is not None and new_ev.request_id == other.request_id:
                self._relationships.append(EvidenceRelationship(
                    other.id, new_ev.id, RelationshipType.DUPLICATES,
                    "same underlying request/response pair",
                ))
                continue
            if new_ev.is_contradicting or other.is_contradicting:
                self._relationships.append(EvidenceRelationship(
                    other.id, new_ev.id, RelationshipType.CONTRADICTS,
                    "negative control conflicts with positive evidence",
                ))
                continue
            if new_ev.type != other.type and new_ev.independent and other.independent:
                self._relationships.append(EvidenceRelationship(
                    other.id, new_ev.id, RelationshipType.CORROBORATES,
                    f"independent {other.type.value} + {new_ev.type.value} evidence agree",
                ))

    # ── Scoring ──────────────────────────────────────────────────────────

    def compute_confidence(self, finding_id: str) -> ConfidenceScore:
        """Compute (and cache) the precise ``ConfidenceScore`` for a finding."""
        if finding_id in self._scores:
            return self._scores[finding_id]

        evidences = self._evidence.get(finding_id, [])
        if not evidences:
            score = ConfidenceScore(
                finding_id=finding_id, value=0.0, label=ConfidenceLabel.SPECULATIVE,
                explanation=["no evidence registered for this finding"],
            )
            self._scores[finding_id] = score
            return score

        supporting = [e for e in evidences if not e.is_contradicting]
        contradicting = [e for e in evidences if e.is_contradicting]

        explanation: List[str] = []

        # ── Component 1: confirmation count (saturating curve) ──────────
        confirmations = len(supporting)
        confirmation_score = 1.0 - (0.55 ** confirmations) if confirmations else 0.0
        explanation.append(
            f"{confirmations} supporting confirmation(s) → confirmation component "
            f"{confirmation_score:.2f}"
        )

        # ── Component 2: evidence-type quality ───────────────────────────
        if supporting:
            qualities = sorted((e.weighted_quality for e in supporting), reverse=True)
            # best piece of evidence dominates, the rest contribute a
            # tapering bonus — one EXEC_OUTPUT is worth more than five
            # SIZE_ANOMALYs, but the extra anomalies still help a little
            evidence_type_score = qualities[0]
            for i, q in enumerate(qualities[1:], start=1):
                evidence_type_score += q * (0.5 ** i) * 0.3
            evidence_type_score = min(1.0, evidence_type_score)
        else:
            evidence_type_score = 0.0
        explanation.append(f"strongest evidence quality → evidence-type component {evidence_type_score:.2f}")

        # ── Component 3: baseline/differential agreement ─────────────────
        baseline_evs = [e for e in supporting if e.source in self._BASELINE_SOURCES]
        if baseline_evs:
            baseline_score = min(1.0, sum(e.strength for e in baseline_evs) / max(1, len(baseline_evs)) +
                                  0.1 * (len(baseline_evs) - 1))
        else:
            # no dedicated baseline/differential evidence registered — neutral,
            # not penalised, since not every scanner runs those engines
            baseline_score = 0.5
        explanation.append(f"baseline/differential agreement component {baseline_score:.2f}")

        # ── Component 4: relationship / diversity ────────────────────────
        distinct_types = len({e.type for e in supporting})
        rel_ids = {e.id for e in evidences}
        corroborations = [
            r for r in self._relationships
            if r.relation == RelationshipType.CORROBORATES and r.source_id in rel_ids and r.target_id in rel_ids
        ]
        contradictions = [
            r for r in self._relationships
            if r.relation == RelationshipType.CONTRADICTS and r.source_id in rel_ids and r.target_id in rel_ids
        ]
        diversity_score = min(1.0, (distinct_types - 1) * 0.25) if distinct_types else 0.0
        corroboration_bonus = min(0.4, len(corroborations) * 0.10)
        contradiction_penalty = min(0.9, len(contradictions) * 0.35 + len(contradicting) * 0.35)
        relationship_score = max(0.0, min(1.0, diversity_score + corroboration_bonus - contradiction_penalty))
        explanation.append(
            f"{distinct_types} distinct evidence type(s), {len(corroborations)} corroboration(s), "
            f"{len(contradictions) + len(contradicting)} contradiction(s) → relationship component "
            f"{relationship_score:.2f}"
        )

        breakdown = {
            "confirmation_count":  confirmation_score,
            "evidence_quality":    evidence_type_score,
            "baseline_agreement":  baseline_score,
            "relationship":        relationship_score,
        }
        value = (
            confirmation_score  * self._W_CONFIRMATION +
            evidence_type_score * self._W_EVIDENCE_TYPE +
            baseline_score       * self._W_BASELINE +
            relationship_score   * self._W_RELATIONSHIP
        )
        # a failed negative control is treated as near-disqualifying,
        # regardless of how strong everything else looked
        if contradicting:
            value *= max(0.1, 1.0 - 0.5 * len(contradicting))
            explanation.append(
                f"{len(contradicting)} failed negative-control probe(s) applied a severe penalty"
            )
        value = max(0.0, min(1.0, value))

        score = ConfidenceScore(
            finding_id=finding_id,
            value=value,
            label=_label_for(value),
            breakdown=breakdown,
            evidence_count=len(evidences),
            distinct_evidence_types=distinct_types,
            corroboration_count=len(corroborations),
            contradiction_count=len(contradictions) + len(contradicting),
            contributing_evidence=[e.id for e in evidences],
            false_positive_risk=_fp_risk_for(value),
            needs_verification=value < 0.50,
            explanation=explanation,
        )
        self._scores[finding_id] = score
        return score

    # ── Accessors / utilities ───────────────────────────────────────────

    def evidence_for(self, finding_id: str) -> List[Evidence]:
        return list(self._evidence.get(finding_id, []))

    def relationships_for(self, finding_id: str) -> List[EvidenceRelationship]:
        ids = {e.id for e in self._evidence.get(finding_id, [])}
        return [r for r in self._relationships if r.source_id in ids or r.target_id in ids]

    def all_findings(self) -> List[str]:
        return list(self._evidence.keys())

    def reset(self, finding_id: Optional[str] = None) -> None:
        """Clear all evidence (for one finding, or the whole framework)."""
        if finding_id is None:
            self._evidence.clear()
            self._evidence_index.clear()
            self._relationships.clear()
            self._scores.clear()
            return
        for ev in self._evidence.pop(finding_id, []):
            self._evidence_index.pop(ev.id, None)
        self._relationships = [
            r for r in self._relationships
            if self._evidence_index.get(r.source_id) is not None and self._evidence_index.get(r.target_id) is not None
        ]
        self._scores.pop(finding_id, None)

    def explain(self, finding_id: str) -> str:
        """Human-readable explanation of how a finding's score was reached."""
        score = self.compute_confidence(finding_id)
        lines = [
            f"Finding {finding_id}: confidence={score.value:.3f} ({score.label.value}), "
            f"false_positive_risk={score.false_positive_risk}",
        ]
        lines.extend(f"  • {line}" for line in score.explanation)
        return "\n".join(lines)

    def merge_into_vulnerability(self, finding_id: str, vulnerability: Any) -> Any:
        """
        Attach the computed score onto an existing ``Vulnerability`` /
        finding object using ``setattr`` so this stays decoupled from the
        exact shape of ``models.vulnerability.Vulnerability``.
        """
        score = self.compute_confidence(finding_id)
        try:
            setattr(vulnerability, "confidence", score.label.value)
            setattr(vulnerability, "confidence_score", score.value)
            setattr(vulnerability, "false_positive_risk", score.false_positive_risk)
        except Exception:
            pass
        return vulnerability

    def summary(self) -> Dict[str, Any]:
        """Aggregate view across every finding tracked so far."""
        scores = [self.compute_confidence(fid) for fid in self.all_findings()]
        by_label: Dict[str, int] = defaultdict(int)
        for s in scores:
            by_label[s.label.value] += 1
        return {
            "total_findings": len(scores),
            "by_label": dict(by_label),
            "average_confidence": round(sum(s.value for s in scores) / len(scores), 4) if scores else 0.0,
            "needs_verification": sum(1 for s in scores if s.needs_verification),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Stateless convenience function
# ─────────────────────────────────────────────────────────────────────────────

def confidence_from_evidence(evidence: List[Evidence]) -> ConfidenceScore:
    """
    One-shot scoring helper for callers that already collected a list of
    ``Evidence`` records (e.g. in a unit test) and don't need a persistent
    ``ConfidenceFramework`` instance.
    """
    if not evidence:
        return ConfidenceScore(finding_id="", value=0.0, label=ConfidenceLabel.SPECULATIVE)
    finding_id = evidence[0].finding_id
    cf = ConfidenceFramework()
    for e in evidence:
        cf.add_evidence(
            finding_id, e.type, e.description, strength=e.strength,
            source=e.source, independent=e.independent, request_id=e.request_id,
            raw_ref=e.raw_ref,
        )
    return cf.compute_confidence(finding_id)


__all__ = [
    "EvidenceType", "RelationshipType", "ConfidenceLabel",
    "Evidence", "EvidenceRelationship", "ConfidenceScore",
    "ConfidenceFramework", "confidence_from_evidence",
]
