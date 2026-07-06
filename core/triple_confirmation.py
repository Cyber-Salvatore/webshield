# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Triple Confirmation Framework — Part 18 of the Intelligence Layer.

No finding produced anywhere in WebShield is reported off the back of a
single request/response pair. Before a discovery is allowed to graduate
into a reported finding it must survive three independent probes:

  1.  **Repeat** — the exact same payload, sent again. A real,
      deterministic vulnerability reproduces; transient noise (a one-off
      slow response, a flaky 500, a randomly rotated value) usually does
      not.
  2.  **Variant** — a *different* payload from the same family (e.g. a
      different SQLi boolean condition, a different XSS context breaker,
      a different path-traversal depth). A genuine vulnerability is
      sensitive to the payload changing in the expected way; a coincidence
      is not.
  3.  **Negative control** — a syntactically similar but harmless request
      with the payload *removed or neutralised*. If the "anomaly" still
      fires without the payload, the original observation was never
      caused by the payload at all.

This module is the orchestrator that runs those three probes, compares
every result against the others and against the target's normal baseline
(via the Baseline Engine / Differential Analysis Engine, Parts 15–16),
and produces a single ``ConfirmationVerdict``. It also feeds every probe
it runs into the Confidence Framework (Part 17) as typed ``Evidence``, so
the resulting confidence score is a *direct* function of how well the
three probes agreed — closing the loop between Parts 15 through 18.

Scanners are not required to use this module — a single positive
response is sometimes legitimately enough (e.g. an out-of-band callback
already received). But for anything probabilistic — timing, content
diffing, size deltas — running it through ``TripleConfirmationFramework``
is how WebShield keeps its false-positive rate close to zero.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .confidence_framework import (
    ConfidenceFramework,
    ConfidenceScore,
    Evidence,
    EvidenceType,
)
from .differential_engine import DiffResult, diff_responses


# ─────────────────────────────────────────────────────────────────────────────
# Probe outcomes
# ─────────────────────────────────────────────────────────────────────────────

class ProbeRole(str, Enum):
    """Which of the three confirmation probes a result came from."""
    REPEAT  = "repeat"             # same payload, sent again
    VARIANT = "variant"            # a different payload from the same family
    CONTROL = "negative_control"   # payload removed / neutralised


@dataclass
class ProbeResult:
    """
    The outcome of sending one probe. Built either from a raw
    ``HTTPResponse`` (most common — the framework diffs it against the
    original response itself) or from a caller-supplied boolean
    ``anomaly_detected`` for probes whose "anomaly" isn't a simple HTTP
    diff (e.g. an out-of-band callback, a timing measurement already
    processed by ``TimingAnalyzer``).
    """
    role:             ProbeRole
    anomaly_detected: bool
    response:         Optional[Any] = None     # HTTPResponse, if applicable
    elapsed:          float = 0.0
    diff:             Optional[DiffResult] = None
    payload:          str = ""
    note:             str = ""
    error:            Optional[str] = None     # set if the probe itself failed (network error, etc.)

    @property
    def succeeded(self) -> bool:
        return self.error is None


class VerdictLabel(str, Enum):
    CONFIRMED      = "confirmed"        # repeat + variant agree, control does not fire
    LIKELY         = "likely"           # majority of probes agree, but not unanimous
    INCONCLUSIVE   = "inconclusive"     # probes disagree / one or more failed to run
    FALSE_POSITIVE = "false_positive"   # negative control fired — original signal not payload-caused


@dataclass
class ConfirmationVerdict:
    """The final outcome of a triple-confirmation run for one finding."""
    finding_id:   str
    label:        VerdictLabel
    probes:       List[ProbeResult] = field(default_factory=list)
    confidence:   Optional[ConfidenceScore] = None
    reasoning:    List[str] = field(default_factory=list)

    @property
    def should_report(self) -> bool:
        """
        Conservative reporting gate: only ``CONFIRMED`` and ``LIKELY``
        verdicts (with a non-trivial confidence score) should ever reach a
        report. Callers remain free to apply stricter gates on top.
        """
        if self.label in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.INCONCLUSIVE):
            return False
        if self.confidence is not None and self.confidence.value < 0.25:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "label": self.label.value,
            "should_report": self.should_report,
            "probes": [
                {
                    "role": p.role.value,
                    "anomaly_detected": p.anomaly_detected,
                    "succeeded": p.succeeded,
                    "payload": p.payload,
                    "note": p.note,
                    "error": p.error,
                }
                for p in self.probes
            ],
            "confidence": self.confidence.to_dict() if self.confidence else None,
            "reasoning": self.reasoning,
        }


# Type alias for the async probe callback scanners provide. It receives the
# payload to send (empty string for the negative-control probe) and must
# return a raw ``HTTPResponse``-like object plus the elapsed time in
# seconds: ``(response, elapsed_seconds)``.
ProbeSender = Callable[[str], Awaitable[Any]]


# ─────────────────────────────────────────────────────────────────────────────
# The framework itself
# ─────────────────────────────────────────────────────────────────────────────

class TripleConfirmationFramework:
    """
    Orchestrates the repeat / variant / negative-control probe sequence
    for one finding and turns the outcome into a ``ConfirmationVerdict``.

    Two ways to use it:

    1.  **Fully automatic** — give it a ``send`` coroutine and the three
        payload strings; it sends all three probes itself, diffs each
        against the original response, and decides.

            tcf = TripleConfirmationFramework(confidence_framework=cf)
            verdict = await tcf.confirm(
                finding_id="f1",
                original_response=resp,
                original_elapsed=0.8,
                send=lambda payload: client.request("GET", url_with(payload)),
                repeat_payload=payload,
                variant_payload=alt_payload,
                control_payload="",
            )

    2.  **Manual** — the scanner already ran its own probes (e.g. it
        needed ``TimingAnalyzer`` for statistical timing comparison) and
        just wants the framework to combine the three boolean outcomes
        into a verdict and feed the Confidence Framework:

            verdict = tcf.evaluate(
                finding_id="f1",
                repeat=ProbeResult(ProbeRole.REPEAT, anomaly_detected=True),
                variant=ProbeResult(ProbeRole.VARIANT, anomaly_detected=True),
                control=ProbeResult(ProbeRole.CONTROL, anomaly_detected=False),
            )
    """

    def __init__(self, confidence_framework: Optional[ConfidenceFramework] = None) -> None:
        self.confidence_framework = confidence_framework or ConfidenceFramework()

    # ── Automatic mode ──────────────────────────────────────────────────

    async def confirm(
        self,
        finding_id: str,
        *,
        original_response: Any,
        original_elapsed: float,
        send: ProbeSender,
        repeat_payload: str,
        variant_payload: Optional[str] = None,
        control_payload: str = "",
        evidence_type: EvidenceType = EvidenceType.STRUCTURAL_DIFF,
        delay_between_probes: float = 0.0,
    ) -> ConfirmationVerdict:
        """
        Run all three probes against the live target and produce a
        verdict. Any individual probe that raises is captured as a failed
        ``ProbeResult`` rather than propagating, so one network hiccup
        doesn't abort the whole confirmation sequence.
        """
        probes: List[ProbeResult] = []

        async def _run(role: ProbeRole, payload: str) -> ProbeResult:
            try:
                start = time.monotonic()
                result = await send(payload)
                elapsed = time.monotonic() - start
                response = result[0] if isinstance(result, tuple) else result
                if isinstance(result, tuple) and len(result) > 1:
                    elapsed = result[1]
                diff = diff_responses(original_response, response, original_elapsed, elapsed)
                # the negative control "fires" if it STILL shows a
                # difference despite carrying no payload — i.e. its
                # diff confidence_boost is non-trivial
                anomaly = diff.confidence_boost >= 0.25 if role != ProbeRole.CONTROL else diff.confidence_boost >= 0.20
                return ProbeResult(
                    role=role, anomaly_detected=anomaly, response=response,
                    elapsed=elapsed, diff=diff, payload=payload,
                    note=f"diff confidence_boost={diff.confidence_boost:.2f}",
                )
            except Exception as exc:
                return ProbeResult(role=role, anomaly_detected=False, payload=payload, error=str(exc))

        probes.append(await _run(ProbeRole.REPEAT, repeat_payload))
        if delay_between_probes:
            await asyncio.sleep(delay_between_probes)

        if variant_payload is not None:
            probes.append(await _run(ProbeRole.VARIANT, variant_payload))
            if delay_between_probes:
                await asyncio.sleep(delay_between_probes)

        probes.append(await _run(ProbeRole.CONTROL, control_payload))

        return self._build_verdict(finding_id, probes, evidence_type)

    # ── Manual mode ──────────────────────────────────────────────────────

    def evaluate(
        self,
        finding_id: str,
        *,
        repeat: ProbeResult,
        variant: Optional[ProbeResult] = None,
        control: Optional[ProbeResult] = None,
        evidence_type: EvidenceType = EvidenceType.STRUCTURAL_DIFF,
    ) -> ConfirmationVerdict:
        """Combine caller-supplied ``ProbeResult`` objects into a verdict."""
        probes = [repeat]
        if variant is not None:
            probes.append(variant)
        if control is not None:
            probes.append(control)
        return self._build_verdict(finding_id, probes, evidence_type)

    # ── Decision logic ──────────────────────────────────────────────────

    def _build_verdict(
        self, finding_id: str, probes: List[ProbeResult], evidence_type: EvidenceType,
    ) -> ConfirmationVerdict:
        reasoning: List[str] = []

        by_role = {p.role: p for p in probes}
        repeat  = by_role.get(ProbeRole.REPEAT)
        variant = by_role.get(ProbeRole.VARIANT)
        control = by_role.get(ProbeRole.CONTROL)

        # ── Feed the Confidence Framework ────────────────────────────────
        for p in probes:
            if not p.succeeded:
                reasoning.append(f"{p.role.value} probe failed to execute: {p.error}")
                continue
            if p.role == ProbeRole.CONTROL:
                self.confidence_framework.add_negative_control(
                    finding_id, fired=p.anomaly_detected,
                    description=p.note or "negative control probe",
                    source="triple_confirmation",
                )
            elif p.anomaly_detected:
                if p.diff is not None:
                    self.confidence_framework.add_evidence_from_diff(
                        finding_id, p.diff, source="triple_confirmation",
                        request_id=f"{finding_id}:{p.role.value}",
                    )
                else:
                    self.confidence_framework.add_evidence(
                        finding_id, evidence_type,
                        f"{p.role.value} probe anomaly: {p.note or p.payload}",
                        strength=0.8, source="triple_confirmation",
                        request_id=f"{finding_id}:{p.role.value}",
                    )

        # ── Decide the label ────────────────────────────────────────────
        control_fired = bool(control and control.succeeded and control.anomaly_detected)
        if control_fired:
            reasoning.append(
                "negative control still showed the anomaly without the payload — "
                "treating the original observation as a false positive"
            )
            label = VerdictLabel.FALSE_POSITIVE
        else:
            repeat_ok = bool(repeat and repeat.succeeded and repeat.anomaly_detected)
            variant_ran = variant is not None
            control_ran = control is not None
            variant_ok = variant_ran and variant.succeeded and variant.anomaly_detected
            control_ok = control_ran and control.succeeded and not control.anomaly_detected

            failed_probes = [p for p in probes if not p.succeeded]
            if failed_probes:
                reasoning.append(
                    f"{len(failed_probes)} probe(s) failed to execute — verdict downgraded pending retry"
                )

            if not repeat_ok:
                reasoning.append("the repeat probe did not reproduce the original anomaly")
                label = VerdictLabel.INCONCLUSIVE
            elif failed_probes:
                label = VerdictLabel.INCONCLUSIVE
            elif variant_ran and control_ran and variant_ok and control_ok:
                reasoning.append("repeat and variant probes both reproduced the anomaly; control stayed clean")
                label = VerdictLabel.CONFIRMED
            elif (variant_ran and variant_ok) or (control_ran and control_ok):
                reasoning.append(
                    "the repeat probe reproduced the anomaly and at least one supporting probe agrees"
                )
                label = VerdictLabel.LIKELY
            else:
                reasoning.append(
                    "only the repeat probe reproduced the anomaly, with no corroborating variant or "
                    "clean control — treating as inconclusive"
                )
                label = VerdictLabel.INCONCLUSIVE

        confidence = self.confidence_framework.compute_confidence(finding_id)

        # A FALSE_POSITIVE verdict should never be allowed to read as
        # confident, regardless of what the raw score happened to land on —
        # the negative-control penalty inside ConfidenceFramework already
        # pulls this down hard, but we make the relationship explicit here.
        if label == VerdictLabel.FALSE_POSITIVE:
            reasoning.append(f"final confidence after control-failure penalty: {confidence.value:.2f}")

        return ConfirmationVerdict(
            finding_id=finding_id, label=label, probes=probes,
            confidence=confidence, reasoning=reasoning,
        )


__all__ = [
    "ProbeRole", "ProbeResult", "VerdictLabel", "ConfirmationVerdict",
    "TripleConfirmationFramework",
]
