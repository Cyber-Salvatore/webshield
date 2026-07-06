# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Evidence Collection Framework — Part 19 of the Intelligence Layer.

Every other engine produces *signals* (``BaselineComparison``, ``DiffResult``,
timing samples, reflection hits, ...) and the Confidence Framework (Part 17)
turns those signals into a ``ConfidenceScore``.  Neither of those layers,
however, keeps the *raw material* a human (or a report) needs to verify a
finding independently: the exact request that was sent, the exact response
that came back, the screenshot at the moment of impact, the console error,
the stack trace.  That is this module's job.

Responsibilities
-----------------
1.  **Capture** every kind of raw artifact produced during a scan: requests,
    responses, screenshots, header/cookie snapshots, DOM snapshots/diffs,
    timing samples, log lines, stack traces, error messages and arbitrary
    browser network events — each tagged with the ``finding_id`` it supports.
2.  **Redact** secrets (Authorization headers, cookies, bearer/JWT tokens,
    API keys, passwords) before anything is stored or exported, so evidence
    bundles are safe to hand to a client or attach to a report.
3.  **Content-address** every artifact (sha256 of its canonical form) so
    duplicate captures of the same exchange collapse instead of bloating
    the bundle, and so tampering after the fact is detectable.
4.  **Stay reproducible.**  Any captured request can be turned back into a
    ``ReplayPackage`` — a curl command and a Python/httpx snippet — so a
    finding can be reproduced byte-for-byte without re-reading scanner code.
5.  **Bridge into the Confidence Framework.**  An ``EvidenceBundle`` can
    mint ``confidence_framework.Evidence`` objects directly from captured
    artifacts, so scanners record proof once and both systems benefit.
6.  **Export.**  A full scan's evidence can be written to disk as a
    self-contained, content-addressed directory (manifest + redacted raw
    blobs) — the artifact a Triple-Confirmation (Part 18) verdict or an
    Evidence Graph (Part 20) node ultimately points back to.

Nothing here decides whether a finding is real — that is Confidence
Framework / Triple Confirmation territory.  This module's only job is to
make sure that whatever they decide is something a third party can audit
and reproduce.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .confidence_framework import Evidence, EvidenceType


# ─────────────────────────────────────────────────────────────────────────────
# Artifact taxonomy
# ─────────────────────────────────────────────────────────────────────────────

class ArtifactType(str, Enum):
    REQUEST          = "request"
    RESPONSE         = "response"
    SCREENSHOT       = "screenshot"
    HEADER_SNAPSHOT  = "header_snapshot"
    COOKIE_SNAPSHOT  = "cookie_snapshot"
    DOM_SNAPSHOT     = "dom_snapshot"
    DOM_DIFF         = "dom_diff"
    TIMING_SAMPLE    = "timing_sample"
    LOG_ENTRY        = "log_entry"
    STACK_TRACE      = "stack_trace"
    ERROR_MESSAGE    = "error_message"
    NETWORK_EVENT    = "network_event"
    CONSOLE_MESSAGE  = "console_message"
    NOTE             = "note"


# Artifact types that, on their own, can be turned into a ``ReplayPackage``.
_REPLAYABLE_TYPES = frozenset({ArtifactType.REQUEST})


# ─────────────────────────────────────────────────────────────────────────────
# Redaction
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_HEADER_KEYS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-access-token", "x-csrf-token", "proxy-authorization", "x-session-token",
})

# Body/text patterns that look like secrets regardless of context. Applied to
# any free-text artifact content (response bodies, logs, stack traces, notes).
_SECRET_TEXT_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)("?(?:password|passwd|pwd)"?\s*[:=]\s*")([^"]{1,200})(")'), r'\1[REDACTED]\3'),
    (re.compile(r'(?i)("?(?:secret|api[_-]?key|client[_-]?secret|access[_-]?key)"?\s*[:=]\s*")([^"]{1,200})(")'), r'\1[REDACTED]\3'),
    (re.compile(r'(?i)(bearer\s+)([A-Za-z0-9\-_.+/=]{10,})'), r'\1[REDACTED]'),
    (re.compile(r'\b(eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,})\b'), '[REDACTED-JWT]'),
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '[REDACTED-AWS-KEY]'),
    (re.compile(r'(?i)(["\']?(?:token|auth[_-]?token)["\']?\s*[:=]\s*["\'])([A-Za-z0-9\-_.+/=]{8,200})(["\'])'), r'\1[REDACTED]\3'),
    # Unquoted form-encoded values, e.g. `password=hunter2` or
    # `...&api_key=abc123&...` inside an application/x-www-form-urlencoded
    # or querystring-style body. The patterns above only match values
    # wrapped in quotes (JSON-style) and silently let plain key=value pairs
    # through unredacted.
    (re.compile(r'(?i)\b((?:password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|access[_-]?key|token|auth[_-]?token)\s*=\s*)([^&\s"\']{1,200})'), r'\1[REDACTED]'),
]

_MAX_TEXT_BYTES_DEFAULT = 20_000


def _redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not headers:
        return {}
    out: Dict[str, str] = {}
    for k, v in dict(headers).items():
        out[k] = "[REDACTED]" if k.lower() in _SECRET_HEADER_KEYS else str(v)
    return out


def _redact_text(text: Optional[str]) -> str:
    if not text:
        return ""
    redacted = text
    for pattern, repl in _SECRET_TEXT_PATTERNS:
        redacted = pattern.sub(repl, redacted)
    return redacted


def _truncate(text: str, max_bytes: int) -> Tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated + f"\n...[truncated, {len(encoded) - max_bytes} bytes omitted]", True


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)


def _content_hash(data: Any) -> str:
    return hashlib.sha256(_canonical_json(data).encode("utf-8", errors="replace")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Replay
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReplayPackage:
    """Everything needed to re-send an exact, previously captured request."""
    method:  str
    url:     str
    headers: Dict[str, str] = field(default_factory=dict)
    body:    Optional[str] = None
    note:    str = ""   # e.g. warns when headers were redacted and can't be replayed verbatim

    def as_curl(self) -> str:
        parts = ["curl", "-i", "-X", self.method, f"'{self.url}'"]
        for k, v in self.headers.items():
            parts.append(f"-H '{k}: {v}'")
        if self.body:
            parts.append(f"--data-raw '{self.body}'")
        cmd = " \\\n  ".join(parts)
        if self.note:
            cmd += f"\n# NOTE: {self.note}"
        return cmd

    def as_python_httpx(self) -> str:
        lines = [
            "import httpx",
            "",
            f"resp = httpx.request(",
            f"    {self.method!r},",
            f"    {self.url!r},",
            f"    headers={self.headers!r},",
        ]
        if self.body:
            lines.append(f"    content={self.body!r},")
        lines.append(")")
        lines.append("print(resp.status_code, len(resp.content))")
        if self.note:
            lines.insert(0, f"# NOTE: {self.note}")
        return "\n".join(lines)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method, "url": self.url,
            "headers": self.headers, "body": self.body, "note": self.note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Artifact + bundle
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EvidenceArtifact:
    """A single, atomic, content-addressed piece of raw proof."""
    id:           str
    type:         ArtifactType
    finding_id:   Optional[str]
    request_id:   str                    # correlates request/response/timing/screenshot of one exchange
    sequence:     int
    captured_at:  float
    summary:      str
    data:         Dict[str, Any]         # redacted, JSON-serialisable payload
    content_hash: str
    redacted:     bool = False
    truncated:    bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "type": self.type.value, "finding_id": self.finding_id,
            "request_id": self.request_id, "sequence": self.sequence,
            "captured_at": self.captured_at, "summary": self.summary,
            "data": self.data, "content_hash": self.content_hash,
            "redacted": self.redacted, "truncated": self.truncated,
        }


@dataclass
class EvidenceBundle:
    """All artifacts collected in support of a single finding."""
    finding_id: str
    created_at: float = field(default_factory=time.time)
    artifacts:  List[EvidenceArtifact] = field(default_factory=list)
    _seen_hashes: set = field(default_factory=set, repr=False)

    def add(self, artifact: EvidenceArtifact) -> bool:
        """Append an artifact; returns False (no-op) if it's a duplicate."""
        if artifact.content_hash in self._seen_hashes:
            return False
        self._seen_hashes.add(artifact.content_hash)
        self.artifacts.append(artifact)
        return True

    def by_type(self, type_: ArtifactType) -> List[EvidenceArtifact]:
        return [a for a in self.artifacts if a.type == type_]

    def by_request(self, request_id: str) -> List[EvidenceArtifact]:
        return [a for a in self.artifacts if a.request_id == request_id]

    def chain_of_custody(self) -> List[Dict[str, Any]]:
        """Ordered, tamper-evident timeline of every artifact in this bundle."""
        return [
            {"sequence": a.sequence, "id": a.id, "type": a.type.value,
             "captured_at": a.captured_at, "content_hash": a.content_hash}
            for a in sorted(self.artifacts, key=lambda x: x.sequence)
        ]

    def integrity_hash(self) -> str:
        """sha256 over the ordered chain of artifact hashes — changes if any
        artifact is added, removed, reordered, or mutated after capture."""
        chained = "|".join(a.content_hash for a in sorted(self.artifacts, key=lambda x: x.sequence))
        return hashlib.sha256(chained.encode("utf-8")).hexdigest()

    def to_confidence_evidence(
        self,
        type: EvidenceType,
        description: str,
        strength: float = 1.0,
        source: str = "evidence_collection",
        artifact_ids: Optional[Sequence[str]] = None,
    ) -> Evidence:
        """Mint a ``confidence_framework.Evidence`` object backed by one or
        more captured artifacts, via ``raw_ref`` pointing back at this bundle."""
        ref_ids = list(artifact_ids) if artifact_ids else [a.id for a in self.artifacts]
        return Evidence(
            finding_id=self.finding_id,
            type=type,
            description=description,
            strength=strength,
            source=source,
            raw_ref={"bundle_finding_id": self.finding_id, "artifact_ids": ref_ids,
                     "integrity_hash": self.integrity_hash()},
        )

    def summary_stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for a in self.artifacts:
            counts[a.type.value] += 1
        return dict(counts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "created_at": self.created_at,
            "integrity_hash": self.integrity_hash(),
            "artifact_count": len(self.artifacts),
            "summary_stats": self.summary_stats(),
            "chain_of_custody": self.chain_of_custody(),
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Collector
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceCollector:
    """
    Central collection point every scanner/engine writes raw proof into
    during a scan.  One ``EvidenceCollector`` is normally shared across the
    whole ``ScanEngine`` run; ``finding_id`` is the only thing that
    distinguishes which bundle an artifact belongs to (use ``"_unassigned"``
    for exploratory captures that aren't tied to a finding yet — they can be
    reassigned later via ``reassign``).
    """

    def __init__(self, redact: bool = True, max_text_bytes: int = _MAX_TEXT_BYTES_DEFAULT) -> None:
        self.redact = redact
        self.max_text_bytes = max_text_bytes
        self._bundles: Dict[str, EvidenceBundle] = {}
        self._artifact_index: Dict[str, EvidenceArtifact] = {}
        self._sequence = 0

    # -- bundle access ------------------------------------------------------

    def bundle(self, finding_id: str) -> EvidenceBundle:
        if finding_id not in self._bundles:
            self._bundles[finding_id] = EvidenceBundle(finding_id=finding_id)
        return self._bundles[finding_id]

    def get_bundle(self, finding_id: str) -> Optional[EvidenceBundle]:
        return self._bundles.get(finding_id)

    def all_bundles(self) -> Dict[str, EvidenceBundle]:
        return dict(self._bundles)

    def reassign(self, finding_id_from: str, finding_id_to: str) -> None:
        """Move every artifact from one (e.g. provisional) finding id to
        another, used once a Triple-Confirmation verdict assigns a final id."""
        src = self._bundles.pop(finding_id_from, None)
        if not src:
            return
        dst = self.bundle(finding_id_to)
        for artifact in src.artifacts:
            artifact.finding_id = finding_id_to
            dst.add(artifact)

    # -- internal helpers -----------------------------------------------------

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _new_artifact(
        self, finding_id: str, type_: ArtifactType, request_id: Optional[str],
        summary: str, data: Dict[str, Any], redacted: bool, truncated: bool,
    ) -> EvidenceArtifact:
        artifact = EvidenceArtifact(
            id=uuid.uuid4().hex[:12],
            type=type_,
            finding_id=finding_id,
            request_id=request_id or uuid.uuid4().hex[:12],
            sequence=self._next_sequence(),
            captured_at=time.time(),
            summary=summary,
            data=data,
            content_hash=_content_hash({"type": type_.value, "data": data}),
            redacted=redacted,
            truncated=truncated,
        )
        self._artifact_index[artifact.id] = artifact
        self.bundle(finding_id).add(artifact)
        return artifact

    def _process_text(self, text: Optional[str]) -> Tuple[str, bool, bool]:
        was_redacted = False
        out = text or ""
        if self.redact:
            redacted_out = _redact_text(out)
            was_redacted = redacted_out != out
            out = redacted_out
        out, was_truncated = _truncate(out, self.max_text_bytes)
        return out, was_redacted, was_truncated

    def _process_headers(self, headers: Optional[Dict[str, Any]]) -> Tuple[Dict[str, str], bool]:
        if not headers:
            return {}, False
        if self.redact:
            cleaned = _redact_headers(headers)
            return cleaned, cleaned != {k: str(v) for k, v in dict(headers).items()}
        return {k: str(v) for k, v in dict(headers).items()}, False

    # -- capture: request / response -----------------------------------------

    def capture_request(
        self, finding_id: str, method: str, url: str,
        headers: Optional[Dict[str, Any]] = None, body: Optional[Union[str, bytes]] = None,
        request_id: Optional[str] = None, payload_context: Optional[str] = None,
    ) -> EvidenceArtifact:
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        body_clean, body_redacted, body_truncated = self._process_text(body)
        hdrs_clean, hdrs_redacted = self._process_headers(headers)
        data = {"method": method.upper(), "url": url, "headers": hdrs_clean,
                "body": body_clean or None, "payload_context": payload_context}
        return self._new_artifact(
            finding_id, ArtifactType.REQUEST, request_id,
            summary=f"{method.upper()} {url}", data=data,
            redacted=body_redacted or hdrs_redacted, truncated=body_truncated,
        )

    def capture_response(
        self, finding_id: str, response: Any, request_id: Optional[str] = None,
        elapsed: Optional[float] = None,
    ) -> EvidenceArtifact:
        """Accepts anything duck-typed like ``core.http_client.HTTPResponse``
        (``.status_code``, ``.headers``, ``.text``/``.content``, ``.url``)."""
        status_code = getattr(response, "status_code", None)
        url = getattr(response, "url", "")
        try:
            headers = dict(getattr(response, "headers", {}) or {})
        except Exception:
            headers = {}
        try:
            text = response.text if hasattr(response, "text") else str(response)
        except Exception:
            text = ""
        elapsed_val = elapsed if elapsed is not None else getattr(response, "elapsed", None)

        body_clean, body_redacted, body_truncated = self._process_text(text)
        hdrs_clean, hdrs_redacted = self._process_headers(headers)
        data = {
            "status_code": status_code, "url": url, "headers": hdrs_clean,
            "body": body_clean, "elapsed_ms": round(elapsed_val * 1000, 2) if elapsed_val else None,
            "content_length": len(text) if text else 0,
        }
        return self._new_artifact(
            finding_id, ArtifactType.RESPONSE, request_id,
            summary=f"{status_code} {url}", data=data,
            redacted=body_redacted or hdrs_redacted, truncated=body_truncated,
        )

    def capture_exchange(
        self, finding_id: str, method: str, url: str, response: Any,
        request_headers: Optional[Dict[str, Any]] = None,
        request_body: Optional[Union[str, bytes]] = None,
        payload_context: Optional[str] = None, elapsed: Optional[float] = None,
    ) -> Tuple[EvidenceArtifact, EvidenceArtifact]:
        """Convenience wrapper: capture a request and its matching response
        as one correlated pair sharing a single ``request_id``."""
        request_id = uuid.uuid4().hex[:12]
        req = self.capture_request(finding_id, method, url, request_headers,
                                    request_body, request_id, payload_context)
        resp = self.capture_response(finding_id, response, request_id, elapsed)
        return req, resp

    # -- capture: everything else --------------------------------------------

    def capture_header_snapshot(self, finding_id: str, headers: Dict[str, Any],
                                 label: str = "", request_id: Optional[str] = None) -> EvidenceArtifact:
        hdrs_clean, redacted = self._process_headers(headers)
        return self._new_artifact(
            finding_id, ArtifactType.HEADER_SNAPSHOT, request_id,
            summary=label or "header snapshot", data={"label": label, "headers": hdrs_clean},
            redacted=redacted, truncated=False,
        )

    def capture_cookie_snapshot(self, finding_id: str, cookies: Dict[str, Any],
                                 label: str = "", request_id: Optional[str] = None) -> EvidenceArtifact:
        cleaned = {k: "[REDACTED]" for k in dict(cookies)} if self.redact else {k: str(v) for k, v in dict(cookies).items()}
        return self._new_artifact(
            finding_id, ArtifactType.COOKIE_SNAPSHOT, request_id,
            summary=label or f"{len(cleaned)} cookie(s)",
            data={"label": label, "cookie_names": list(cleaned.keys()), "cookies": cleaned},
            redacted=self.redact, truncated=False,
        )

    def capture_dom_snapshot(self, finding_id: str, html: str, label: str = "",
                              request_id: Optional[str] = None) -> EvidenceArtifact:
        clean, redacted, truncated = self._process_text(html)
        return self._new_artifact(
            finding_id, ArtifactType.DOM_SNAPSHOT, request_id,
            summary=label or "DOM snapshot", data={"label": label, "html": clean},
            redacted=redacted, truncated=truncated,
        )

    def capture_dom_diff(self, finding_id: str, before: str, after: str, label: str = "",
                          request_id: Optional[str] = None) -> EvidenceArtifact:
        before_c, b_red, b_trunc = self._process_text(before)
        after_c, a_red, a_trunc = self._process_text(after)
        return self._new_artifact(
            finding_id, ArtifactType.DOM_DIFF, request_id,
            summary=label or "DOM diff",
            data={"label": label, "before": before_c, "after": after_c,
                  "before_len": len(before or ""), "after_len": len(after or "")},
            redacted=b_red or a_red, truncated=b_trunc or a_trunc,
        )

    def capture_screenshot(self, finding_id: str, image_path: Optional[str] = None,
                            image_bytes: Optional[bytes] = None, caption: str = "",
                            request_id: Optional[str] = None) -> EvidenceArtifact:
        """Stores a *reference* (path or hash of the bytes), never the raw
        binary inline, so bundles stay small and JSON-serialisable."""
        if image_bytes is not None:
            digest = hashlib.sha256(image_bytes).hexdigest()
            data = {"caption": caption, "byte_size": len(image_bytes), "sha256": digest, "path": image_path}
        else:
            data = {"caption": caption, "path": image_path, "sha256": None, "byte_size": None}
        return self._new_artifact(
            finding_id, ArtifactType.SCREENSHOT, request_id,
            summary=caption or (image_path or "screenshot"), data=data,
            redacted=False, truncated=False,
        )

    def capture_timing(self, finding_id: str, samples_ms: Sequence[float],
                        baseline_ms: Optional[float] = None, label: str = "",
                        request_id: Optional[str] = None) -> EvidenceArtifact:
        samples = list(samples_ms)
        avg = sum(samples) / len(samples) if samples else 0.0
        data = {
            "label": label, "samples_ms": samples, "avg_ms": round(avg, 2),
            "min_ms": round(min(samples), 2) if samples else None,
            "max_ms": round(max(samples), 2) if samples else None,
            "baseline_ms": baseline_ms,
            "delta_ms": round(avg - baseline_ms, 2) if baseline_ms is not None else None,
        }
        return self._new_artifact(
            finding_id, ArtifactType.TIMING_SAMPLE, request_id,
            summary=label or f"timing: {round(avg, 1)}ms avg over {len(samples)} sample(s)",
            data=data, redacted=False, truncated=False,
        )

    def capture_log(self, finding_id: str, message: str, level: str = "info",
                     source: str = "", request_id: Optional[str] = None) -> EvidenceArtifact:
        clean, redacted, truncated = self._process_text(message)
        return self._new_artifact(
            finding_id, ArtifactType.LOG_ENTRY, request_id,
            summary=f"[{level}] {clean[:120]}", data={"level": level, "source": source, "message": clean},
            redacted=redacted, truncated=truncated,
        )

    def capture_stack_trace(self, finding_id: str, trace_text: str, source: str = "",
                             request_id: Optional[str] = None) -> EvidenceArtifact:
        clean, redacted, truncated = self._process_text(trace_text)
        return self._new_artifact(
            finding_id, ArtifactType.STACK_TRACE, request_id,
            summary=(clean.splitlines()[0] if clean else "stack trace")[:160],
            data={"source": source, "trace": clean},
            redacted=redacted, truncated=truncated,
        )

    def capture_error_message(self, finding_id: str, message: str, status_code: Optional[int] = None,
                               source: str = "", request_id: Optional[str] = None) -> EvidenceArtifact:
        clean, redacted, truncated = self._process_text(message)
        return self._new_artifact(
            finding_id, ArtifactType.ERROR_MESSAGE, request_id,
            summary=clean[:160], data={"status_code": status_code, "source": source, "message": clean},
            redacted=redacted, truncated=truncated,
        )

    def capture_network_event(self, finding_id: str, event: Dict[str, Any],
                               request_id: Optional[str] = None) -> EvidenceArtifact:
        """Browser-automation-layer events (XHR/fetch/websocket frames seen
        outside the main request path) recorded as-is, after redaction."""
        safe_event = json.loads(_redact_text(_canonical_json(event))) if self.redact else event
        return self._new_artifact(
            finding_id, ArtifactType.NETWORK_EVENT, request_id,
            summary=str(event.get("type") or event.get("url") or "network event")[:160],
            data=safe_event, redacted=self.redact, truncated=False,
        )

    def capture_console_message(self, finding_id: str, message: str, level: str = "log",
                                 request_id: Optional[str] = None) -> EvidenceArtifact:
        clean, redacted, truncated = self._process_text(message)
        return self._new_artifact(
            finding_id, ArtifactType.CONSOLE_MESSAGE, request_id,
            summary=f"[console.{level}] {clean[:120]}", data={"level": level, "message": clean},
            redacted=redacted, truncated=truncated,
        )

    def capture_note(self, finding_id: str, text: str, request_id: Optional[str] = None) -> EvidenceArtifact:
        clean, redacted, truncated = self._process_text(text)
        return self._new_artifact(
            finding_id, ArtifactType.NOTE, request_id,
            summary=clean[:160], data={"text": clean}, redacted=redacted, truncated=truncated,
        )

    # -- replay ---------------------------------------------------------------

    def replay_package(self, artifact_id: str) -> Optional[ReplayPackage]:
        artifact = self._artifact_index.get(artifact_id)
        if not artifact or artifact.type not in _REPLAYABLE_TYPES:
            return None
        d = artifact.data
        note = "headers/body were redacted at capture time — replace [REDACTED] before sending" if artifact.redacted else ""
        return ReplayPackage(method=d.get("method", "GET"), url=d.get("url", ""),
                              headers=dict(d.get("headers") or {}), body=d.get("body"), note=note)

    # -- export -----------------------------------------------------------------

    def export_all(self, output_dir: Union[str, Path]) -> Path:
        """Writes a self-contained, content-addressed evidence directory:
        one JSON manifest plus one JSON file per bundle. Safe to hand to a
        third party — every artifact has already passed through redaction."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        manifest = {
            "generated_at": time.time(),
            "bundle_count": len(self._bundles),
            "artifact_count": len(self._artifact_index),
            "bundles": {},
        }
        for finding_id, bundle in self._bundles.items():
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", finding_id)[:80] or uuid.uuid4().hex[:8]
            bundle_path = out / f"bundle_{safe_name}.json"
            bundle_path.write_text(_canonical_json(bundle.to_dict()), encoding="utf-8")
            manifest["bundles"][finding_id] = {
                "file": bundle_path.name, "integrity_hash": bundle.integrity_hash(),
                "artifact_count": len(bundle.artifacts),
            }
        manifest_path = out / "manifest.json"
        manifest_path.write_text(_canonical_json(manifest), encoding="utf-8")
        return manifest_path

    # -- stats --------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = defaultdict(int)
        redacted_count = 0
        for artifact in self._artifact_index.values():
            by_type[artifact.type.value] += 1
            if artifact.redacted:
                redacted_count += 1
        return {
            "bundle_count": len(self._bundles),
            "artifact_count": len(self._artifact_index),
            "by_type": dict(by_type),
            "redacted_artifacts": redacted_count,
        }


__all__ = [
    "ArtifactType", "EvidenceArtifact", "EvidenceBundle", "EvidenceCollector",
    "ReplayPackage",
]
