# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Risk Analysis Framework — Phase 3.

CVSS answers "how bad is this class of bug in the abstract".  It does not
answer "how bad is *this* finding, on *this* target, given everything else
we know".  A high-CVSS finding the scanner is only tentative about, that
needs admin privileges to reach and touches no sensitive data, is not a
9.8.  A medium-CVSS IDOR that sits inside a confirmed data-theft chain is
worth far more than its base score.

This framework recomputes a realistic, exploitability-weighted risk score
per finding from factors the CVSS base score ignores or flattens:

  • **exploitability** — how easy the finding is to actually trigger
    (attack complexity, privileges required, user interaction).
  • **impact** — the confidentiality/integrity/availability damage.
  • **data sensitivity** — does this finding class touch credentials,
    PII or the auth boundary?
  • **confidence** — the scanner's own certainty and false-positive risk;
    an unconfirmed finding is discounted, not trusted blindly.
  • **chain membership** — a finding that participates in a confirmed
    attack chain (from the Correlation Engine) inherits that escalation.

The result is a 0–10 score with a plain-language rationale, plus an
aggregate target risk that reflects the *worst realistic path*, not just a
severity headcount.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..models.vulnerability import (
    AttackComplexity,
    PrivilegesRequired,
    Severity,
    UserInteraction,
    Vulnerability,
    VulnType,
)
from .correlation_engine import AttackChain

# Finding classes whose successful exploitation directly touches credentials,
# PII, or the authentication boundary — these carry outsized real-world risk.
_HIGH_SENSITIVITY_TYPES = frozenset({
    VulnType.SQLI, VulnType.NOSQLI, VulnType.IDOR, VulnType.BOLA, VulnType.BFLA,
    VulnType.BROKEN_AUTH, VulnType.JWT, VulnType.OAUTH, VulnType.SECRET_EXPOSURE,
    VulnType.SENSITIVE_DATA, VulnType.SSRF, VulnType.XXE,
})
_MEDIUM_SENSITIVITY_TYPES = frozenset({
    VulnType.XSS, VulnType.CMDI, VulnType.SSTI, VulnType.PATH_TRAVERSAL,
    VulnType.LFI, VulnType.RFI, VulnType.FILE_UPLOAD, VulnType.CSRF,
    VulnType.HTTP_SMUGGLING, VulnType.LDAP, VulnType.XPATH, VulnType.WEBSOCKET,
})

_SEVERITY_BASE: Dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}


def _level_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


# ─────────────────────────────────────────────────────────────────────────────
# Records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RiskFactors:
    """Normalised 0–1 sub-scores that feed the final risk number."""
    exploitability: float
    impact: float
    data_sensitivity: float
    confidence: float
    chain_multiplier: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exploitability": round(self.exploitability, 3),
            "impact": round(self.impact, 3),
            "data_sensitivity": round(self.data_sensitivity, 3),
            "confidence": round(self.confidence, 3),
            "chain_multiplier": round(self.chain_multiplier, 3),
        }


@dataclass
class RiskScore:
    finding_id: str
    title: str
    vuln_type: str
    cvss_score: Optional[float]
    risk_score: float
    risk_level: str
    factors: RiskFactors
    in_confirmed_chain: bool
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "cvss_score": self.cvss_score,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "factors": self.factors.to_dict(),
            "in_confirmed_chain": self.in_confirmed_chain,
            "rationale": self.rationale,
        }


@dataclass
class RiskReport:
    scores: List[RiskScore]
    aggregate_risk: float
    aggregate_level: str
    method: str = "WebShield Contextual Risk v1"
    notes: List[str] = field(default_factory=list)

    def top(self, n: int = 10) -> List[RiskScore]:
        return sorted(self.scores, key=lambda s: s.risk_score, reverse=True)[:n]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "aggregate_risk": round(self.aggregate_risk, 2),
            "aggregate_level": self.aggregate_level,
            "notes": list(self.notes),
            "scores": [s.to_dict() for s in sorted(self.scores, key=lambda s: s.risk_score, reverse=True)],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Framework
# ─────────────────────────────────────────────────────────────────────────────

class RiskAnalysisFramework:
    """Computes contextual per-finding and aggregate risk."""

    def analyze(
        self,
        vulnerabilities: Sequence[Vulnerability],
        chains: Optional[Sequence[AttackChain]] = None,
    ) -> RiskReport:
        chains = list(chains or [])
        # Map finding id -> best escalation from any chain it belongs to.
        confirmed_ids: Dict[str, float] = {}
        potential_ids: Dict[str, float] = {}
        for chain in chains:
            target = confirmed_ids if not chain.is_potential else potential_ids
            for fid in chain.member_finding_ids:
                prev = target.get(fid, 0.0)
                target[fid] = max(prev, chain.combined_risk)

        scores: List[RiskScore] = []
        for v in vulnerabilities:
            scores.append(self._score_finding(v, confirmed_ids, potential_ids))

        aggregate = self._aggregate(scores)
        notes: List[str] = []
        if confirmed_ids:
            notes.append(
                f"{len(confirmed_ids)} finding(s) participate in a confirmed attack chain and "
                f"were escalated above their CVSS base score."
            )
        if not vulnerabilities:
            notes.append("No findings — aggregate risk is zero.")
        return RiskReport(
            scores=scores,
            aggregate_risk=aggregate,
            aggregate_level=_level_from_score(aggregate),
            notes=notes,
        )

    # -- per-finding ----------------------------------------------------------

    def _score_finding(
        self,
        v: Vulnerability,
        confirmed_ids: Dict[str, float],
        potential_ids: Dict[str, float],
    ) -> RiskScore:
        exploitability = self._exploitability(v)
        impact = self._impact(v)
        data_sensitivity = self._data_sensitivity(v)
        confidence = self._confidence_factor(v)

        in_confirmed = v.vuln_id in confirmed_ids
        chain_multiplier = self._chain_multiplier(v.vuln_id, confirmed_ids, potential_ids)

        # Blend: impact dominates, exploitability and data-sensitivity modulate.
        blended = 10.0 * (0.50 * impact + 0.30 * exploitability + 0.20 * data_sensitivity)
        raw = blended * confidence * chain_multiplier
        risk = round(min(max(raw, 0.0), 10.0), 2)

        factors = RiskFactors(
            exploitability=exploitability,
            impact=impact,
            data_sensitivity=data_sensitivity,
            confidence=confidence,
            chain_multiplier=chain_multiplier,
        )
        rationale = self._rationale(v, factors, in_confirmed, v.vuln_id in potential_ids)
        return RiskScore(
            finding_id=v.vuln_id,
            title=v.title,
            vuln_type=v.vuln_type.value,
            cvss_score=v.cvss_score(),
            risk_score=risk,
            risk_level=_level_from_score(risk),
            factors=factors,
            in_confirmed_chain=in_confirmed,
            rationale=rationale,
        )

    @staticmethod
    def _exploitability(v: Vulnerability) -> float:
        cvss = v.cvss
        if cvss is None:
            # No CVSS vector — infer from severity as a coarse proxy.
            return {
                Severity.CRITICAL: 0.9, Severity.HIGH: 0.8, Severity.MEDIUM: 0.6,
                Severity.LOW: 0.4, Severity.INFO: 0.2,
            }.get(v.severity, 0.5)
        ac = 1.0 if cvss.attack_complexity == AttackComplexity.LOW else 0.6
        pr = {
            PrivilegesRequired.NONE: 1.0,
            PrivilegesRequired.LOW: 0.7,
            PrivilegesRequired.HIGH: 0.4,
        }.get(cvss.privileges_required, 0.8)
        ui = 1.0 if cvss.user_interaction == UserInteraction.NONE else 0.7
        return round(ac * pr * ui, 3)

    @staticmethod
    def _impact(v: Vulnerability) -> float:
        cvss = v.cvss
        if cvss is not None:
            impact_map = {"H": 1.0, "L": 0.5, "N": 0.0}
            c = impact_map.get(cvss.confidentiality.value, 0.0)
            i = impact_map.get(cvss.integrity.value, 0.0)
            a = impact_map.get(cvss.availability.value, 0.0)
            # Worst dimension dominates; the others add diminishing weight.
            ordered = sorted((c, i, a), reverse=True)
            return round(min(ordered[0] + 0.25 * ordered[1] + 0.10 * ordered[2], 1.0), 3)
        return {
            Severity.CRITICAL: 1.0, Severity.HIGH: 0.8, Severity.MEDIUM: 0.55,
            Severity.LOW: 0.3, Severity.INFO: 0.1,
        }.get(v.severity, 0.5)

    @staticmethod
    def _data_sensitivity(v: Vulnerability) -> float:
        if v.vuln_type in _HIGH_SENSITIVITY_TYPES:
            return 1.0
        if v.vuln_type in _MEDIUM_SENSITIVITY_TYPES:
            return 0.55
        return 0.2

    @staticmethod
    def _confidence_factor(v: Vulnerability) -> float:
        conf = (v.confidence or "").strip().lower()
        base = {
            "confirmed": 1.0, "high": 0.95, "firm": 0.85, "medium": 0.75,
            "tentative": 0.6, "low": 0.55,
        }.get(conf, 0.8)
        fpr = (v.false_positive_risk or "").strip().lower()
        penalty = {"low": 0.0, "medium": 0.1, "high": 0.25}.get(fpr, 0.0)
        return round(max(base - penalty, 0.3), 3)

    @staticmethod
    def _chain_multiplier(
        finding_id: str,
        confirmed_ids: Dict[str, float],
        potential_ids: Dict[str, float],
    ) -> float:
        if finding_id in confirmed_ids:
            # Scale escalation with how severe the chain was (combined_risk 0-10).
            return round(1.0 + 0.05 * confirmed_ids[finding_id], 3)  # up to ~1.5
        if finding_id in potential_ids:
            return 1.15
        return 1.0

    @staticmethod
    def _rationale(
        v: Vulnerability,
        f: RiskFactors,
        in_confirmed: bool,
        in_potential: bool,
    ) -> str:
        parts: List[str] = []
        if in_confirmed:
            parts.append("participates in a confirmed attack chain (escalated)")
        elif in_potential:
            parts.append("one step short of a larger chain (mildly escalated)")
        if f.confidence < 0.8:
            parts.append("discounted for lower scanner confidence")
        if f.data_sensitivity >= 1.0:
            parts.append("touches credentials/PII/auth boundary")
        if f.exploitability >= 0.85:
            parts.append("trivially exploitable (no auth/interaction)")
        elif f.exploitability <= 0.5:
            parts.append("harder to exploit (privileges or interaction required)")
        if not parts:
            parts.append("scored from base impact and exploitability")
        return "; ".join(parts) + "."

    # -- aggregate ------------------------------------------------------------

    @staticmethod
    def _aggregate(scores: Sequence[RiskScore]) -> float:
        """
        Aggregate target risk = worst realistic path, not a severity headcount.
        The single highest finding sets the floor; every additional finding
        adds a sharply diminishing increment so a target with many issues
        reads higher than one with a single bug, without ever letting volume
        alone manufacture a Critical.
        """
        if not scores:
            return 0.0
        ordered = sorted((s.risk_score for s in scores), reverse=True)
        floor = ordered[0]
        bonus = 0.0
        for i, s in enumerate(ordered[1:], start=1):
            bonus += s * (0.5 ** i)  # 2nd finding half-weight, 3rd quarter, ...
        return round(min(floor + bonus * 0.15, 10.0), 2)


__all__ = [
    "RiskFactors",
    "RiskScore",
    "RiskReport",
    "RiskAnalysisFramework",
]
