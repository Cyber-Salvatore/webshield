"""
Differential Analysis Engine — Part 16 of the Intelligence Layer.

Every response produced while a scan is running carries a question: *did
this request actually change anything, or is this just noise?*  The
Differential Analysis Engine is the dedicated answer to that question.  It
sits directly on top of the Baseline Engine (Part 15) and is consumed by
every scanner and by the Triple Confirmation Framework that follows it.

Two comparison modes
---------------------
1.  **Baseline mode** — ``compare_to_baseline()``.  A test response is
    compared against the rich ``EndpointBaseline`` produced by
    ``BaselineEngine``.  Dynamic tokens (CSRF values, nonces, rotating
    session identifiers, …) are stripped from both sides *before* any
    textual comparison, using the baseline's own dynamic-token registry, so
    a response is never flagged as different merely because a nonce
    rotated.

2.  **Sequential mode** — ``record_and_compare()``.  Many real findings
    only reveal themselves across a *sequence* of probes against the same
    (url, parameter) pair: a WAF that engages after N requests, a
    time-based injection chain whose delay grows request over request, a
    paginated response that slowly drifts in size.  The engine keeps a
    bounded rolling history per key and diffs each new response against the
    most recent prior one, in addition to (or instead of) the baseline.

Dimensions inspected
---------------------
Every comparison — in either mode — inspects the same seven dimensions, so
results are uniform regardless of which mode produced them:

  • **Status**     — did the HTTP status code change?
  • **Size**        — did the response body size move outside the normal
                       envelope?
  • **Content**     — composite structural similarity (delegates to
                       ``ResponseAnalyzer`` when comparing real
                       ``HTTPResponse`` objects, falls back to a
                       ``difflib`` ratio when comparing against a
                       lightweight history snapshot).
  • **JSON structure** — key-path level diff: which keys appeared,
                       disappeared, or changed type/value (Jaccard
                       similarity of the key-path sets as an additional
                       structural signal).
  • **DOM structure**  — HTML tag-frequency diff, *plus* detection of
                       newly-appeared inline event-handler attributes
                       (``onerror=``, ``onload=``, …) and newly-appeared
                       ``<script>`` blocks — a strong corroborating signal
                       for reflected-content findings.
  • **Headers**     — structured appeared / disappeared / changed diff
                       across all headers (a fixed allow-list of volatile
                       headers — Date, Age, ETag, request-id, … — is
                       ignored so they never generate noise).
  • **Timing**      — elapsed-time delta against the baseline mean (or the
                       previous probe), plus a rolling linear-regression
                       drift estimate across the recorded history — useful
                       for spotting *progressive* time-based injection
                       chains where each successive probe gets slower.
  • **Redirects**   — chain-length and final-destination changes (baseline
                       mode only, since sequential snapshots do not retain
                       full redirect chains).

Evidence extraction
--------------------
``difflib.SequenceMatcher`` opcodes are used (not naive token-set
subtraction) to locate the actual inserted / replaced spans between two
response bodies, then each span is filtered against an "interesting
content" pattern (error keywords, SQL syntax fragments, stack-trace
markers, …) before being trimmed to a short, readable snippet.  This is
materially more accurate than a token-presence heuristic and is what feeds
``DiffResult.evidence_snippets`` for the (forthcoming) Evidence Collection
Framework.

Backward compatibility
-----------------------
The original Discovery-Infrastructure prototype (``recon.discovery_engine
.DifferentialAnalysisEngine``) exposed a single method::

    compare(baseline_response, test_response, baseline_elapsed=0.0,
            test_elapsed=0.0) -> DiffResult

with a flat result object (``is_different``, ``size_diff_pct``,
``status_changed``, ``header_diffs``, ``content_diff_score``,
``timing_diff_seconds``, ``is_timing_anomaly``, ``evidence_snippets``,
``notes``, ``.significance``).  Every one of those fields and that exact
call signature is preserved here unchanged, so ``TripleConfirmationFramework``
and ``IntelligenceAwareScanner.diff_responses()`` keep working without any
caller-side changes.  ``compare()`` additionally accepts an
``EndpointBaseline`` as its first argument and transparently delegates to
``compare_to_baseline()`` when it sees one — the dedicated, rich code path.

Public API
----------
``DifferentialAnalysisEngine`` exposes:

  ``compare(baseline, test, baseline_elapsed=0.0, test_elapsed=0.0)``
      Polymorphic, backward-compatible entry point.

  ``compare_to_baseline(baseline, response, elapsed=None, ...)``
      Rich comparison against an ``EndpointBaseline``.

  ``record_and_compare(key, response, elapsed=None, baseline=None, ...)``
      Sequential comparison against the rolling history for *key*,
      optionally combined with a baseline comparison.

  ``history_for(key)`` / ``clear_history(key=None)``
      Inspect or reset the rolling history for a given (url, parameter) key.

  ``get_stats()``
      Aggregate comparison / anomaly counters for the running scan.

Module-level convenience: ``diff_responses(base, test, ...)`` — a one-shot
helper that builds a temporary engine and runs ``compare()``.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import difflib
import json
import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .http_client import HTTPResponse
from ..utils.response_analyzer import ResponseAnalyzer, SimilarityResult
from .baseline_engine import EndpointBaseline


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class DiffSignificance(str, Enum):
    """Human-readable severity tier for a DiffResult."""
    NONE     = "none"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"   # structural change + injected markup/script evidence


class DiffDimension(str, Enum):
    """One of the seven comparison dimensions the engine inspects."""
    STATUS   = "status"
    SIZE     = "size"
    CONTENT  = "content"
    JSON     = "json_structure"
    DOM      = "dom_structure"
    HEADERS  = "headers"
    TIMING   = "timing"
    REDIRECT = "redirect"


# ─────────────────────────────────────────────────────────────────────────────
# Helper: header diffing
# ─────────────────────────────────────────────────────────────────────────────

# Headers that rotate on every single request regardless of any application
# behaviour change — comparing them would only generate noise.
_VOLATILE_HEADERS = frozenset({
    "date", "age", "x-request-id", "x-correlation-id", "etag",
    "last-modified", "content-length", "cf-ray", "x-amz-cf-id",
    "x-amz-request-id", "retry-after", "expires", "x-runtime",
    "x-response-time", "x-served-by", "x-cache-hits",
})


@dataclass
class HeaderDiff:
    """Structured appeared / disappeared / changed diff across all headers."""
    appeared:    Dict[str, str] = field(default_factory=dict)
    disappeared: List[str]      = field(default_factory=list)
    changed:     Dict[str, Tuple[str, str]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.appeared or self.disappeared or self.changed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "appeared":    dict(list(self.appeared.items())[:20]),
            "disappeared": self.disappeared[:20],
            "changed":     {k: list(v) for k, v in list(self.changed.items())[:20]},
        }


def _diff_headers(base: Dict[str, str], test: Dict[str, str]) -> HeaderDiff:
    """Diff two header dicts, ignoring the known-volatile set."""
    base_l = {k.lower(): v for k, v in (base or {}).items()}
    test_l = {k.lower(): v for k, v in (test or {}).items()}
    diff = HeaderDiff()

    for name, val in test_l.items():
        if name in _VOLATILE_HEADERS:
            continue
        if name not in base_l:
            diff.appeared[name] = val
        elif base_l[name] != val:
            diff.changed[name] = (base_l[name], val)

    for name in base_l:
        if name in _VOLATILE_HEADERS:
            continue
        if name not in test_l:
            diff.disappeared.append(name)

    return diff


# ─────────────────────────────────────────────────────────────────────────────
# Helper: JSON structural diffing
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class JSONStructureDiff:
    """Key-path level diff between two JSON documents."""
    is_json:               bool                       = False
    added_keys:            Set[str]                   = field(default_factory=set)
    removed_keys:          Set[str]                   = field(default_factory=set)
    type_changed_keys:     Dict[str, Tuple[str, str]]  = field(default_factory=dict)
    value_changed_keys:    List[str]                   = field(default_factory=list)
    structural_similarity: float                       = 1.0

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_keys or self.removed_keys or
            self.type_changed_keys or self.value_changed_keys
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_json":               self.is_json,
            "added_keys":            sorted(self.added_keys)[:20],
            "removed_keys":          sorted(self.removed_keys)[:20],
            "type_changed_keys":     {k: list(v) for k, v in list(self.type_changed_keys.items())[:20]},
            "value_changed_keys":    self.value_changed_keys[:20],
            "structural_similarity": round(self.structural_similarity, 4),
        }


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "unknown"


def _flatten_json(
    obj: Any,
    prefix: str = "",
    out: Optional[Dict[str, Tuple[str, Any]]] = None,
    depth: int = 0,
    budget: Optional[List[int]] = None,
) -> Dict[str, Tuple[str, Any]]:
    """
    Flatten a parsed JSON document into ``{path: (type, value)}`` leaf
    entries.  Depth and leaf-count are bounded so pathological documents
    cannot blow up comparison time.
    """
    if out is None:
        out = {}
    if budget is None:
        budget = [2000]
    if depth > 12 or budget[0] <= 0:
        return out

    if isinstance(obj, dict):
        for k, v in obj.items():
            budget[0] -= 1
            if budget[0] <= 0:
                break
            _flatten_json(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1, budget)
    elif isinstance(obj, list):
        for idx, v in enumerate(obj[:50]):
            budget[0] -= 1
            if budget[0] <= 0:
                break
            _flatten_json(v, f"{prefix}[{idx}]", out, depth + 1, budget)
    else:
        out[prefix or "$"] = (_json_type(obj), obj)

    return out


def _looks_like_json(text: str) -> bool:
    t = text.lstrip()
    return t.startswith("{") or t.startswith("[")


def _diff_json(base_text: str, test_text: str) -> JSONStructureDiff:
    diff = JSONStructureDiff()
    try:
        base_obj = json.loads(base_text) if base_text.strip() else None
        test_obj = json.loads(test_text) if test_text.strip() else None
    except (json.JSONDecodeError, ValueError, TypeError):
        return diff
    if base_obj is None and test_obj is None:
        return diff

    diff.is_json = True
    base_leaves = _flatten_json(base_obj)
    test_leaves = _flatten_json(test_obj)
    base_keys = set(base_leaves)
    test_keys = set(test_leaves)

    diff.added_keys   = test_keys - base_keys
    diff.removed_keys = base_keys - test_keys

    for k in base_keys & test_keys:
        b_type, b_val = base_leaves[k]
        t_type, t_val = test_leaves[k]
        if b_type != t_type:
            diff.type_changed_keys[k] = (b_type, t_type)
        elif b_val != t_val:
            diff.value_changed_keys.append(k)

    union = base_keys | test_keys
    if union:
        diff.structural_similarity = len(base_keys & test_keys) / len(union)

    return diff


# ─────────────────────────────────────────────────────────────────────────────
# Helper: DOM structural diffing
# ─────────────────────────────────────────────────────────────────────────────

_TAG_RE         = re.compile(r"<\s*([a-zA-Z][\w:-]*)", re.I)
_EVENT_ATTR_RE  = re.compile(r"\bon[a-z]{3,20}\s*=", re.I)
_SCRIPT_OPEN_RE = re.compile(r"<\s*script\b", re.I)
_ATTR_RE        = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*["\']')
_HTML_HINT_RE   = re.compile(r"<\s*(html|!doctype|body|div|span|table|form|head)\b", re.I)


@dataclass
class DOMStructureDiff:
    """Tag-frequency and markup-injection diff between two HTML bodies."""
    is_html:               bool            = False
    tag_added:             Dict[str, int]  = field(default_factory=dict)
    tag_removed:           Dict[str, int]  = field(default_factory=dict)
    new_event_handlers:    List[str]       = field(default_factory=list)
    new_script_blocks:     int             = 0
    new_attributes:        Set[str]        = field(default_factory=set)
    structural_similarity: float           = 1.0

    @property
    def has_changes(self) -> bool:
        return bool(
            self.tag_added or self.tag_removed or
            self.new_event_handlers or self.new_script_blocks
        )

    @property
    def has_injection_signal(self) -> bool:
        """True if new inline event handlers or <script> blocks appeared —
        a strong corroborating signal for a markup/script injection finding."""
        return bool(self.new_event_handlers or self.new_script_blocks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_html":               self.is_html,
            "tag_added":             dict(list(self.tag_added.items())[:20]),
            "tag_removed":           dict(list(self.tag_removed.items())[:20]),
            "new_event_handlers":    self.new_event_handlers[:20],
            "new_script_blocks":     self.new_script_blocks,
            "new_attributes":        sorted(self.new_attributes)[:20],
            "structural_similarity": round(self.structural_similarity, 4),
            "has_injection_signal":  self.has_injection_signal,
        }


def _looks_like_html(text: str) -> bool:
    return bool(_HTML_HINT_RE.search(text[:4000]))


def _content_similarity(structural_score: float, base_text: str, test_text: str) -> Tuple[float, float]:
    """
    Blend tag/JSON-structural similarity with a pure textual similarity
    signal (``difflib`` quick-ratio on the raw, dynamic-token-masked body).

    Tag-frequency and JSON key-path similarity are intentionally blind to
    *content* — a page that swaps "Welcome back" for a raw SQL error
    inside the exact same ``<html><body>…</body></html>`` shell looks
    100% structurally identical by tag count alone.  Returning the lower
    of the two scores ensures a content-only change is never missed just
    because the surrounding markup/JSON shape did not move.

    Returns ``(combined_score, text_similarity)``.
    """
    if not base_text and not test_text:
        text_similarity = 1.0
    else:
        text_similarity = difflib.SequenceMatcher(
            None, base_text[:20_000], test_text[:20_000]
        ).quick_ratio()
    return min(structural_score, text_similarity), text_similarity


def _tag_freq(html: str) -> Dict[str, int]:
    freq: Dict[str, int] = {}
    for m in _TAG_RE.finditer(html[:200_000]):
        tag = m.group(1).lower()
        freq[tag] = freq.get(tag, 0) + 1
    return freq


def _cosine(a: Dict[str, int], b: Dict[str, int]) -> float:
    if not a and not b:
        return 1.0
    keys = set(a) | set(b)
    dot   = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _diff_dom(base_html: str, test_html: str) -> DOMStructureDiff:
    diff = DOMStructureDiff(is_html=True)

    base_freq = _tag_freq(base_html)
    test_freq = _tag_freq(test_html)

    for tag, cnt in test_freq.items():
        delta = cnt - base_freq.get(tag, 0)
        if delta > 0:
            diff.tag_added[tag] = delta
    for tag, cnt in base_freq.items():
        delta = cnt - test_freq.get(tag, 0)
        if delta > 0:
            diff.tag_removed[tag] = delta

    base_events = {
        m.group(0).split("=")[0].strip().lower()
        for m in _EVENT_ATTR_RE.finditer(base_html[:200_000])
    }
    test_events = {
        m.group(0).split("=")[0].strip().lower()
        for m in _EVENT_ATTR_RE.finditer(test_html[:200_000])
    }
    diff.new_event_handlers = sorted(test_events - base_events)[:20]

    diff.new_script_blocks = max(
        0,
        len(_SCRIPT_OPEN_RE.findall(test_html[:200_000])) -
        len(_SCRIPT_OPEN_RE.findall(base_html[:200_000])),
    )

    base_attrs = {m.group(1).lower() for m in _ATTR_RE.finditer(base_html[:200_000])}
    test_attrs = {m.group(1).lower() for m in _ATTR_RE.finditer(test_html[:200_000])}
    diff.new_attributes = set(sorted(test_attrs - base_attrs)[:20])

    diff.structural_similarity = _cosine(base_freq, test_freq)
    return diff


# ─────────────────────────────────────────────────────────────────────────────
# Helper: evidence snippet extraction (difflib-based)
# ─────────────────────────────────────────────────────────────────────────────

_INTERESTING_CONTENT_RE = re.compile(
    r"error|exception|warning|traceback|stack\s*trace|fatal|"
    r"syntax\s*error|denied|forbidden|unauthorized|debug|"
    r"root:|admin:|select\s|union\s|sleep\(|waitfor\s|"
    r"0x[0-9a-f]{4,}|undefined|null\s*pointer|segmentation",
    re.I,
)


_WORD_SPLIT_RE = re.compile(r"\S+|\s+")


def _extract_diff_snippets(
    base_text: str,
    test_text: str,
    max_snippets: int = 5,
    context: int = 40,
) -> Tuple[List[str], bool]:
    """
    Locate the actual inserted / replaced spans between two bodies using
    ``difflib.SequenceMatcher`` opcodes, then surface short, readable
    snippets — prioritising spans that match an "interesting content"
    pattern, falling back to any sizeable structural change.

    The comparison runs at *word* granularity (tokens split on whitespace
    boundaries), not raw characters: two short, partially-overlapping words
    (e.g. "welcome" vs "Traceback") can otherwise be fragmented by a
    character-level matcher into several tiny, non-contiguous chunks, each
    too small — and none containing the full keyword — to be recognised as
    interesting on its own.

    Returns ``(snippets, found_interesting_evidence)``. The second value is
    True only when at least one returned snippet matched the
    "interesting content" pattern (error keywords, SQL syntax fragments,
    stack-trace markers, …) rather than merely being a large generic
    change — this is treated as an anomaly signal in its own right,
    independent of the overall similarity ratio, because a single
    diagnostic line can be buried in an otherwise near-identical page.
    """
    if not base_text and not test_text:
        return [], False

    base_c = base_text[:80_000]
    test_c = test_text[:80_000]

    base_tokens = _WORD_SPLIT_RE.findall(base_c)
    test_tokens = _WORD_SPLIT_RE.findall(test_c)

    matcher = difflib.SequenceMatcher(a=base_tokens, b=test_tokens, autojunk=False)
    snippets: List[str] = []
    found_interesting = False

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue

        added   = "".join(test_tokens[j1:j2])
        removed = "".join(base_tokens[i1:i2])
        chunk   = added or removed
        if not chunk.strip():
            continue

        is_interesting = bool(_INTERESTING_CONTENT_RE.search(chunk))
        if not is_interesting and len(chunk) < 30:
            continue
        if is_interesting:
            found_interesting = True

        if added:
            ctx_before = "".join(test_tokens[max(0, j1 - 6):j1])[-context:]
            ctx_after  = "".join(test_tokens[j2:j2 + 6])[:context]
        else:
            ctx_before = "".join(base_tokens[max(0, i1 - 6):i1])[-context:]
            ctx_after  = "".join(base_tokens[i2:i2 + 6])[:context]

        snippet = f"{ctx_before}{chunk}{ctx_after}"
        snippet = re.sub(r"\s+", " ", snippet).strip()[:200]
        if snippet and snippet not in snippets:
            snippets.append(snippet)
        if len(snippets) >= max_snippets:
            break

    return snippets, found_interesting


# ─────────────────────────────────────────────────────────────────────────────
# Timing & redirect diff
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TimingDiff:
    """Elapsed-time comparison, plus a rolling drift estimate across history."""
    baseline_elapsed: float = 0.0
    test_elapsed:     float = 0.0
    delta_seconds:    float = 0.0
    delay_factor:     float = 0.0   # test / baseline
    is_anomaly:       bool  = False
    rolling_drift:    float = 0.0   # seconds/probe slope across recorded history

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_elapsed": round(self.baseline_elapsed, 4),
            "test_elapsed":     round(self.test_elapsed, 4),
            "delta_seconds":    round(self.delta_seconds, 4),
            "delay_factor":     round(self.delay_factor, 2),
            "is_anomaly":       self.is_anomaly,
            "rolling_drift":    round(self.rolling_drift, 4),
        }


@dataclass
class RedirectDiff:
    """Redirect chain-length and final-destination diff (baseline mode only)."""
    chain_length_changed: bool           = False
    base_chain_length:    int            = 0
    test_chain_length:    int            = 0
    final_url_changed:    bool           = False
    base_final_url:       Optional[str]  = None
    test_final_url:       Optional[str]  = None

    @property
    def has_changes(self) -> bool:
        return self.chain_length_changed or self.final_url_changed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_length_changed": self.chain_length_changed,
            "base_chain_length":    self.base_chain_length,
            "test_chain_length":    self.test_chain_length,
            "final_url_changed":    self.final_url_changed,
            "base_final_url":       self.base_final_url,
            "test_final_url":       self.test_final_url,
        }


# ─────────────────────────────────────────────────────────────────────────────
# DiffResult — the master comparison result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DiffResult:
    """
    Master result of a differential comparison.

    The flat fields (``is_different``, ``size_diff_pct``, ``status_changed``,
    ``header_diffs``, ``content_diff_score``, ``timing_diff_seconds``,
    ``is_timing_anomaly``, ``evidence_snippets``, ``notes``,
    ``.significance``) are a strict superset of the original
    ``recon.discovery_engine.DiffResult`` prototype and remain
    source-compatible with every existing caller.  The structured sub-objects
    (``json_diff``, ``dom_diff``, ``header_diff``, ``redirect_diff``,
    ``timing``) are the Part 16 upgrade.
    """

    # ── Legacy flat fields (back-compat) ────────────────────────────────────
    is_different:        bool       = False
    size_diff_pct:        float      = 0.0
    status_changed:       bool       = False
    header_diffs:         List[str]  = field(default_factory=list)
    content_diff_score:   float      = 0.0
    timing_diff_seconds:   float      = 0.0
    is_timing_anomaly:    bool       = False
    evidence_snippets:    List[str]  = field(default_factory=list)
    notes:                List[str]  = field(default_factory=list)

    # ── Additional flat flags (parity with BaselineComparison) ──────────────
    structural_score:          float = 1.0
    text_similarity:           float = 1.0
    is_structurally_different: bool  = False
    is_size_anomaly:           bool  = False
    is_error_response:         bool  = False

    # ── Rich Part-16 sub-results ─────────────────────────────────────────────
    json_diff:     JSONStructureDiff = field(default_factory=JSONStructureDiff)
    dom_diff:      DOMStructureDiff  = field(default_factory=DOMStructureDiff)
    header_diff:   HeaderDiff        = field(default_factory=HeaderDiff)
    redirect_diff: RedirectDiff      = field(default_factory=RedirectDiff)
    timing:        TimingDiff        = field(default_factory=TimingDiff)

    # ── Provenance ────────────────────────────────────────────────────────────
    dynamic_tokens_masked: bool = False
    compared_against:      str  = "raw_pair"   # "baseline" | "previous" | "baseline+previous" | "raw_pair" | "none"

    # ── Derived properties ───────────────────────────────────────────────────

    @property
    def anomaly_count(self) -> int:
        """Number of dimensions that fired."""
        return sum([
            self.status_changed,
            self.is_size_anomaly,
            self.is_structurally_different,
            self.is_timing_anomaly,
            self.header_diff.has_changes,
            self.redirect_diff.has_changes,
            self.json_diff.has_changes,
            self.dom_diff.has_changes,
        ])

    @property
    def dimensions_triggered(self) -> List[DiffDimension]:
        """Which of the seven dimensions are anomalous, in inspection order."""
        dims: List[DiffDimension] = []
        if self.status_changed:
            dims.append(DiffDimension.STATUS)
        if self.is_size_anomaly:
            dims.append(DiffDimension.SIZE)
        if self.is_structurally_different:
            dims.append(DiffDimension.CONTENT)
        if self.json_diff.has_changes:
            dims.append(DiffDimension.JSON)
        if self.dom_diff.has_changes:
            dims.append(DiffDimension.DOM)
        if self.header_diff.has_changes:
            dims.append(DiffDimension.HEADERS)
        if self.is_timing_anomaly:
            dims.append(DiffDimension.TIMING)
        if self.redirect_diff.has_changes:
            dims.append(DiffDimension.REDIRECT)
        return dims

    @property
    def significance(self) -> DiffSignificance:
        """Backward-compatible severity tier, extended with a CRITICAL rung."""
        if not self.is_different:
            return DiffSignificance.NONE
        if self.dom_diff.has_injection_signal and self.is_structurally_different:
            return DiffSignificance.CRITICAL
        if self.status_changed or self.content_diff_score > 0.5:
            return DiffSignificance.HIGH
        if (
            self.content_diff_score > 0.2 or self.is_timing_anomaly or
            self.json_diff.has_changes or self.dom_diff.has_changes
        ):
            return DiffSignificance.MEDIUM
        return DiffSignificance.LOW

    @property
    def confidence_boost(self) -> float:
        """
        0–1 additive boost for the (forthcoming) Confidence Framework,
        mirroring ``BaselineComparison.confidence_boost``'s weighting scheme
        but extended across all seven Part-16 dimensions.
        """
        weights = {
            "structural": 0.25 if self.is_structurally_different else 0.0,
            "timing":     0.20 if self.is_timing_anomaly else 0.0,
            "json":       0.15 if self.json_diff.has_changes else 0.0,
            "dom":        0.15 if self.dom_diff.has_changes else 0.0,
            "size":       0.10 if self.is_size_anomaly else 0.0,
            "redirect":   0.10 if self.redirect_diff.has_changes else 0.0,
            "headers":    0.05 if self.header_diff.has_changes else 0.0,
        }
        return min(sum(weights.values()), 1.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_different":              self.is_different,
            "significance":              self.significance.value,
            "size_diff_pct":              round(self.size_diff_pct, 2),
            "status_changed":             self.status_changed,
            "header_diffs":               self.header_diffs[:20],
            "content_diff_score":         round(self.content_diff_score, 4),
            "structural_score":           round(self.structural_score, 4),
            "text_similarity":            round(self.text_similarity, 4),
            "timing_diff_seconds":         round(self.timing_diff_seconds, 4),
            "is_timing_anomaly":          self.is_timing_anomaly,
            "is_structurally_different":  self.is_structurally_different,
            "is_size_anomaly":            self.is_size_anomaly,
            "is_error_response":          self.is_error_response,
            "anomaly_count":              self.anomaly_count,
            "dimensions_triggered":       [d.value for d in self.dimensions_triggered],
            "confidence_boost":           round(self.confidence_boost, 3),
            "evidence_snippets":          self.evidence_snippets,
            "notes":                      self.notes,
            "json_diff":                  self.json_diff.to_dict(),
            "dom_diff":                   self.dom_diff.to_dict(),
            "header_diff":                self.header_diff.to_dict(),
            "redirect_diff":              self.redirect_diff.to_dict(),
            "timing":                     self.timing.to_dict(),
            "dynamic_tokens_masked":      self.dynamic_tokens_masked,
            "compared_against":           self.compared_against,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Rolling history snapshot (sequential mode)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _ResponseSnapshot:
    """
    Lightweight, bounded-size record of one prior response kept for
    sequential (vs-previous) comparison.  Bodies are truncated so memory
    use stays bounded across long fuzzing loops.
    """
    status_code:  int
    size:         int
    elapsed:      float
    headers:      Dict[str, str]
    text_excerpt: str
    content_type: str
    timestamp:    float = field(default_factory=time.monotonic)


# ─────────────────────────────────────────────────────────────────────────────
# DifferentialAnalysisEngine
# ─────────────────────────────────────────────────────────────────────────────

class DifferentialAnalysisEngine:
    """
    Part 16 of the Intelligence Layer — Differential Analysis Engine.

    Compares every test response against the application's behavioural
    baseline and/or against the immediately preceding probe for the same
    endpoint, across seven independent dimensions, so that genuinely
    anomalous behaviour is detected even when the individual signal is
    very subtle and noise (rotating tokens, volatile headers, natural
    response-size jitter) is suppressed.

    Parameters
    ----------
    analyzer : ResponseAnalyzer, optional
        Shared structural-similarity analyzer. A fresh one is created if
        not supplied — pass the scan's shared instance to avoid redundant
        work and keep similarity scoring consistent with the Baseline
        Engine.
    history_window : int
        Number of prior responses retained per (url, parameter) key for
        sequential comparison (default 5).
    size_change_threshold_pct : float
        Percentage body-size delta, in raw pairwise / sequential mode
        (no baseline std-dev available), above which a response is
        flagged as a size anomaly (default 5.0). Baseline mode instead
        uses the baseline's own 3σ statistical model.
    content_diff_threshold : float
        Structural-difference threshold (1 - similarity) above which a
        response is flagged as structurally different in pairwise /
        sequential mode (default 0.15).
    timing_threshold_seconds : float
        Minimum elapsed-time delta, in pairwise / sequential mode, above
        which a response is flagged as a timing anomaly (default 2.0s).
        Baseline mode instead uses the baseline's own statistical
        threshold (mean + max(3σ, floor)).
    """

    #: Characters of response body retained per history snapshot.
    MAX_TEXT_CAPTURE = 60_000

    def __init__(
        self,
        analyzer: Optional[ResponseAnalyzer] = None,
        history_window: int = 5,
        size_change_threshold_pct: float = 5.0,
        content_diff_threshold: float = 0.15,
        timing_threshold_seconds: float = 2.0,
    ) -> None:
        self._analyzer          = analyzer or ResponseAnalyzer()
        self._history_window    = max(history_window, 1)
        self._size_threshold_pct = size_change_threshold_pct
        self._content_threshold = content_diff_threshold
        self._timing_threshold  = timing_threshold_seconds

        self._history: Dict[Tuple[str, str], Deque[_ResponseSnapshot]] = defaultdict(
            lambda: deque(maxlen=self._history_window)
        )

        self._total_comparisons = 0
        self._anomalies_detected = 0

    # ── Backward-compatible polymorphic entry point ──────────────────────────

    def compare(
        self,
        baseline: Any,
        test: HTTPResponse,
        baseline_elapsed: float = 0.0,
        test_elapsed: float = 0.0,
        *,
        redirect_chain_length: int = 0,
    ) -> DiffResult:
        """
        Backward-compatible comparison entry point.

        ``baseline`` may be either:
          • an ``EndpointBaseline`` — delegates to the rich
            ``compare_to_baseline()`` path (dynamic-token masking, baseline
            statistical thresholds, redirect-chain comparison).
          • a raw ``HTTPResponse`` — legacy pairwise mode, matching the
            exact call signature and result shape of the original
            ``recon.discovery_engine.DifferentialAnalysisEngine.compare()``.
        """
        if isinstance(baseline, EndpointBaseline):
            return self.compare_to_baseline(
                baseline, test,
                elapsed=test_elapsed,
                redirect_chain_length=redirect_chain_length,
            )
        return self._compare_responses(
            baseline, test, baseline_elapsed, test_elapsed,
        )

    # ── Baseline mode ─────────────────────────────────────────────────────────

    def compare_to_baseline(
        self,
        baseline: EndpointBaseline,
        response: HTTPResponse,
        elapsed: Optional[float] = None,
        redirect_chain_length: int = 0,
    ) -> DiffResult:
        """
        Full multi-dimensional comparison of *response* against *baseline*.

        Dynamic tokens registered on the baseline are stripped from both
        the representative baseline body and the test body before any
        textual comparison, so rotating CSRF tokens / nonces / session
        identifiers never trigger a false anomaly.
        """
        anchor = baseline.representative_response

        base_text_raw = self._safe_text(anchor) if anchor is not None else ""
        test_text_raw = self._safe_text(response)
        base_text = baseline.strip_dynamic_tokens(base_text_raw)
        test_text = baseline.strip_dynamic_tokens(test_text_raw)

        # ── Status ────────────────────────────────────────────────────────
        status_changed = (
            anchor is not None and
            getattr(anchor, "status_code", None) != response.status_code
        )

        # ── Size ──────────────────────────────────────────────────────────
        is_size_anomaly = baseline.is_size_anomaly(response)
        size_diff_pct = abs(baseline.size_delta_ratio(response)) * 100

        # ── Structural ────────────────────────────────────────────────────
        if anchor is not None:
            try:
                sim: SimilarityResult = self._analyzer.compare(anchor, response)
                structural_score = sim.score
            except Exception:
                structural_score = difflib.SequenceMatcher(
                    None, base_text[:20_000], test_text[:20_000]
                ).quick_ratio()
        else:
            structural_score = 1.0
        combined_score, text_similarity = _content_similarity(structural_score, base_text, test_text)
        content_diff_score = round(1.0 - combined_score, 4)
        is_structurally_different = combined_score < baseline.effective_threshold()

        # ── Headers ───────────────────────────────────────────────────────
        header_diff = _diff_headers(
            getattr(anchor, "headers", {}) if anchor is not None else {},
            response.headers or {},
        )
        baseline_header_notes = baseline.header_anomalies(response)

        # ── JSON / DOM (on dynamic-token-masked text) ────────────────────
        base_ct = (getattr(anchor, "content_type", "") or "") if anchor is not None else ""
        test_ct = response.content_type or ""

        json_diff = JSONStructureDiff()
        if _looks_like_json(base_text) or _looks_like_json(test_text) or "json" in base_ct.lower() or "json" in test_ct.lower():
            json_diff = _diff_json(base_text, test_text)

        dom_diff = DOMStructureDiff()
        if _looks_like_html(base_text) or _looks_like_html(test_text) or "html" in base_ct.lower() or "html" in test_ct.lower():
            dom_diff = _diff_dom(base_text, test_text)

        evidence_snippets, found_interesting = _extract_diff_snippets(base_text, test_text)
        is_structurally_different = is_structurally_different or found_interesting

        # ── Timing ────────────────────────────────────────────────────────
        history_key = (baseline.url, baseline.parameter)
        is_timing_anomaly = baseline.is_timing_anomaly(elapsed) if elapsed is not None else False
        delay_factor = baseline.timing_delay_factor(elapsed) if elapsed is not None else 0.0
        baseline_mean = baseline.timing.mean if baseline.timing is not None else 0.0
        timing = TimingDiff(
            baseline_elapsed=baseline_mean,
            test_elapsed=elapsed or 0.0,
            delta_seconds=(elapsed - baseline_mean) if elapsed is not None else 0.0,
            delay_factor=delay_factor,
            is_anomaly=is_timing_anomaly,
            rolling_drift=self._rolling_drift_for(history_key, elapsed),
        )

        # ── Redirects ─────────────────────────────────────────────────────
        final_url = getattr(response, "url", None)
        chain_length_changed = redirect_chain_length != baseline.redirects.chain_length
        final_url_changed = False
        if baseline.redirects.final_url and final_url:
            a = urlparse(baseline.redirects.final_url)._replace(query="", fragment="")
            b = urlparse(final_url)._replace(query="", fragment="")
            final_url_changed = a != b
        redirect_diff = RedirectDiff(
            chain_length_changed=chain_length_changed,
            base_chain_length=baseline.redirects.chain_length,
            test_chain_length=redirect_chain_length,
            final_url_changed=final_url_changed,
            base_final_url=baseline.redirects.final_url,
            test_final_url=final_url,
        )

        # ── Error profile ─────────────────────────────────────────────────
        is_error = baseline.is_error_response(response)

        # ── Notes ─────────────────────────────────────────────────────────
        notes: List[str] = list(baseline_header_notes)
        if status_changed:
            notes.append(
                f"Status changed: {getattr(anchor, 'status_code', None)} → {response.status_code}"
            )
        if is_timing_anomaly:
            notes.append(
                f"Response time {elapsed:.2f}s is {delay_factor:.1f}× the baseline mean "
                f"({baseline_mean:.2f}s)"
            )
        if size_diff_pct > 20:
            notes.append(f"Body size deviated from baseline by {size_diff_pct:.0f}%")
        if is_error:
            notes.append("Response matches the application's known error-page profile")
        if dom_diff.new_event_handlers:
            notes.append(
                f"New inline event-handler attribute(s) appeared: "
                f"{', '.join(dom_diff.new_event_handlers[:5])}"
            )
        if dom_diff.new_script_blocks:
            notes.append(f"{dom_diff.new_script_blocks} new <script> block(s) appeared")
        if json_diff.added_keys:
            notes.append(f"{len(json_diff.added_keys)} new JSON key(s) appeared")
        if json_diff.removed_keys:
            notes.append(f"{len(json_diff.removed_keys)} JSON key(s) disappeared")
        if redirect_diff.has_changes:
            notes.append("Redirect chain length or destination changed from baseline")

        legacy_header_diffs = list(baseline_header_notes) + [
            f"{n}: appeared ({v!r})" for n, v in header_diff.appeared.items()
        ] + [
            f"{n}: disappeared" for n in header_diff.disappeared
        ] + [
            f"{n}: '{o}' → '{v}'" for n, (o, v) in header_diff.changed.items()
        ]

        result = DiffResult(
            size_diff_pct=size_diff_pct,
            status_changed=status_changed,
            header_diffs=legacy_header_diffs,
            content_diff_score=content_diff_score,
            timing_diff_seconds=timing.delta_seconds,
            is_timing_anomaly=is_timing_anomaly,
            evidence_snippets=evidence_snippets,
            notes=notes,
            structural_score=round(structural_score, 4),
            text_similarity=round(text_similarity, 4),
            is_structurally_different=is_structurally_different,
            is_size_anomaly=is_size_anomaly,
            is_error_response=is_error,
            json_diff=json_diff,
            dom_diff=dom_diff,
            header_diff=header_diff,
            redirect_diff=redirect_diff,
            timing=timing,
            dynamic_tokens_masked=True,
            compared_against="baseline",
        )
        result.is_different = result.anomaly_count > 0
        self._record_stats(result)
        return result

    # ── Sequential (history) mode ────────────────────────────────────────────

    def record_and_compare(
        self,
        key: Tuple[str, str],
        response: HTTPResponse,
        elapsed: Optional[float] = None,
        baseline: Optional[EndpointBaseline] = None,
        redirect_chain_length: int = 0,
    ) -> DiffResult:
        """
        Compare *response* against the rolling history for *key* (the
        immediately preceding probe, if any) and, when supplied, also
        against *baseline* — then append *response* to that history.

        This is the primary entry point for fuzzing loops: call it once
        per probe against the same (url, parameter) pair and it will
        surface anomalies that only emerge across a sequence (gradual
        drift, a WAF engaging after N requests, a growing time-based
        delay) in addition to whatever a single baseline comparison would
        catch.
        """
        history = self._history[key]

        if baseline is not None:
            result = self.compare_to_baseline(
                baseline, response, elapsed=elapsed,
                redirect_chain_length=redirect_chain_length,
            )
            result.compared_against = "baseline+previous" if history else "baseline"
        elif history:
            result = self._compare_to_snapshot(history[-1], response, elapsed)
            result.compared_against = "previous"
        else:
            result = DiffResult(compared_against="none")
            self._total_comparisons += 1

        if history:
            result.timing.rolling_drift = self._sequential_drift(history, elapsed)

        history.append(self._make_snapshot(response, elapsed))
        return result

    def history_for(self, key: Tuple[str, str]) -> List[_ResponseSnapshot]:
        """Return a copy of the rolling history recorded for *key*."""
        return list(self._history.get(key, ()))

    def clear_history(self, key: Optional[Tuple[str, str]] = None) -> None:
        """Clear the rolling history for *key*, or for every key if *key* is None."""
        if key is None:
            self._history.clear()
        else:
            self._history.pop(key, None)

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate comparison / anomaly counters for the running scan."""
        return {
            "total_comparisons":  self._total_comparisons,
            "anomalies_detected": self._anomalies_detected,
            "anomaly_rate": (
                round(self._anomalies_detected / self._total_comparisons, 4)
                if self._total_comparisons else 0.0
            ),
            "tracked_keys": len(self._history),
        }

    # ── Internal: raw pairwise comparison (legacy-compatible path) ──────────

    def _compare_responses(
        self,
        base_resp: Any,
        test_resp: Any,
        base_elapsed: float,
        test_elapsed: float,
    ) -> DiffResult:
        base_text = self._safe_text(base_resp)
        test_text = self._safe_text(test_resp)

        base_size = len(getattr(base_resp, "content", b"") or base_text.encode("utf-8", "ignore"))
        test_size = len(getattr(test_resp, "content", b"") or test_text.encode("utf-8", "ignore"))
        base_ct = (getattr(base_resp, "content_type", "") or "").lower()
        test_ct = (getattr(test_resp, "content_type", "") or "").lower()

        status_changed = getattr(base_resp, "status_code", None) != getattr(test_resp, "status_code", None)

        size_diff_pct = self._pct_delta(base_size, test_size)
        is_size_anomaly = size_diff_pct > self._size_threshold_pct

        try:
            sim: SimilarityResult = self._analyzer.compare(base_resp, test_resp)
            structural_score = sim.score
        except Exception:
            structural_score = difflib.SequenceMatcher(
                None, base_text[:20_000], test_text[:20_000]
            ).quick_ratio()
        combined_score, text_similarity = _content_similarity(structural_score, base_text, test_text)
        content_diff_score = round(1.0 - combined_score, 4)
        is_structurally_different = content_diff_score > self._content_threshold

        header_diff = _diff_headers(getattr(base_resp, "headers", {}) or {}, getattr(test_resp, "headers", {}) or {})

        json_diff = JSONStructureDiff()
        if _looks_like_json(base_text) or _looks_like_json(test_text) or "json" in base_ct or "json" in test_ct:
            json_diff = _diff_json(base_text, test_text)

        dom_diff = DOMStructureDiff()
        if _looks_like_html(base_text) or _looks_like_html(test_text) or "html" in base_ct or "html" in test_ct:
            dom_diff = _diff_dom(base_text, test_text)

        evidence_snippets, found_interesting = _extract_diff_snippets(base_text, test_text)
        is_structurally_different = is_structurally_different or found_interesting

        timing_delta = (test_elapsed or 0.0) - (base_elapsed or 0.0)
        is_timing_anomaly = timing_delta >= self._timing_threshold
        timing = TimingDiff(
            baseline_elapsed=base_elapsed or 0.0,
            test_elapsed=test_elapsed or 0.0,
            delta_seconds=timing_delta,
            delay_factor=(test_elapsed / base_elapsed) if base_elapsed else 0.0,
            is_anomaly=is_timing_anomaly,
        )

        notes: List[str] = []
        if status_changed:
            notes.append(
                f"Status changed: {getattr(base_resp, 'status_code', None)} → "
                f"{getattr(test_resp, 'status_code', None)}"
            )
        if is_timing_anomaly:
            notes.append(f"Timing anomaly: +{timing_delta:.2f}s above the comparison point")
        if size_diff_pct > 20:
            notes.append(f"Body size changed by {size_diff_pct:.0f}%")
        if dom_diff.new_event_handlers:
            notes.append(
                f"New inline event-handler attribute(s) appeared: "
                f"{', '.join(dom_diff.new_event_handlers[:5])}"
            )
        if dom_diff.new_script_blocks:
            notes.append(f"{dom_diff.new_script_blocks} new <script> block(s) appeared")
        if json_diff.added_keys:
            notes.append(f"{len(json_diff.added_keys)} new JSON key(s) appeared")
        if json_diff.removed_keys:
            notes.append(f"{len(json_diff.removed_keys)} JSON key(s) disappeared")

        legacy_header_diffs = [
            f"{n}: appeared ({v!r})" for n, v in header_diff.appeared.items()
        ] + [
            f"{n}: disappeared" for n in header_diff.disappeared
        ] + [
            f"{n}: '{o}' → '{v}'" for n, (o, v) in header_diff.changed.items()
        ]

        result = DiffResult(
            size_diff_pct=size_diff_pct,
            status_changed=status_changed,
            header_diffs=legacy_header_diffs,
            content_diff_score=content_diff_score,
            timing_diff_seconds=timing_delta,
            is_timing_anomaly=is_timing_anomaly,
            evidence_snippets=evidence_snippets,
            notes=notes,
            structural_score=round(structural_score, 4),
            text_similarity=round(text_similarity, 4),
            is_structurally_different=is_structurally_different,
            is_size_anomaly=is_size_anomaly,
            json_diff=json_diff,
            dom_diff=dom_diff,
            header_diff=header_diff,
            redirect_diff=RedirectDiff(),
            timing=timing,
            dynamic_tokens_masked=False,
            compared_against="raw_pair",
        )
        result.is_different = result.anomaly_count > 0
        self._record_stats(result)
        return result

    # ── Internal: comparison against a rolling-history snapshot ─────────────

    def _compare_to_snapshot(
        self,
        prev: _ResponseSnapshot,
        response: HTTPResponse,
        elapsed: Optional[float],
    ) -> DiffResult:
        test_text = self._safe_text(response)
        base_text = prev.text_excerpt

        status_changed = prev.status_code != response.status_code

        test_size = len(getattr(response, "content", b"") or test_text.encode("utf-8", "ignore"))
        size_diff_pct = self._pct_delta(prev.size, test_size)
        is_size_anomaly = size_diff_pct > self._size_threshold_pct

        structural_score = difflib.SequenceMatcher(
            None, base_text[:20_000], test_text[:20_000]
        ).quick_ratio()
        content_diff_score = round(1.0 - structural_score, 4)
        is_structurally_different = content_diff_score > self._content_threshold

        header_diff = _diff_headers(prev.headers, response.headers or {})

        test_ct = (response.content_type or "").lower()
        json_diff = JSONStructureDiff()
        if _looks_like_json(base_text) or _looks_like_json(test_text) or "json" in prev.content_type.lower() or "json" in test_ct:
            json_diff = _diff_json(base_text, test_text)

        dom_diff = DOMStructureDiff()
        if _looks_like_html(base_text) or _looks_like_html(test_text) or "html" in prev.content_type.lower() or "html" in test_ct:
            dom_diff = _diff_dom(base_text, test_text)

        evidence_snippets, found_interesting = _extract_diff_snippets(base_text, test_text)
        is_structurally_different = is_structurally_different or found_interesting

        timing_delta = (elapsed or 0.0) - prev.elapsed
        is_timing_anomaly = timing_delta >= self._timing_threshold
        timing = TimingDiff(
            baseline_elapsed=prev.elapsed,
            test_elapsed=elapsed or 0.0,
            delta_seconds=timing_delta,
            delay_factor=(elapsed / prev.elapsed) if (elapsed and prev.elapsed) else 0.0,
            is_anomaly=is_timing_anomaly,
        )

        notes: List[str] = []
        if status_changed:
            notes.append(f"Status changed vs previous probe: {prev.status_code} → {response.status_code}")
        if is_timing_anomaly:
            notes.append(f"Timing anomaly vs previous probe: +{timing_delta:.2f}s")
        if size_diff_pct > 20:
            notes.append(f"Body size changed by {size_diff_pct:.0f}% vs previous probe")
        if dom_diff.new_event_handlers:
            notes.append(
                f"New inline event-handler attribute(s) vs previous probe: "
                f"{', '.join(dom_diff.new_event_handlers[:5])}"
            )

        legacy_header_diffs = [
            f"{n}: appeared ({v!r})" for n, v in header_diff.appeared.items()
        ] + [
            f"{n}: disappeared" for n in header_diff.disappeared
        ] + [
            f"{n}: '{o}' → '{v}'" for n, (o, v) in header_diff.changed.items()
        ]

        result = DiffResult(
            size_diff_pct=size_diff_pct,
            status_changed=status_changed,
            header_diffs=legacy_header_diffs,
            content_diff_score=content_diff_score,
            timing_diff_seconds=timing_delta,
            is_timing_anomaly=is_timing_anomaly,
            evidence_snippets=evidence_snippets,
            notes=notes,
            structural_score=round(structural_score, 4),
            text_similarity=round(structural_score, 4),
            is_structurally_different=is_structurally_different,
            is_size_anomaly=is_size_anomaly,
            json_diff=json_diff,
            dom_diff=dom_diff,
            header_diff=header_diff,
            redirect_diff=RedirectDiff(),
            timing=timing,
            dynamic_tokens_masked=False,
            compared_against="previous",
        )
        result.is_different = result.anomaly_count > 0
        self._record_stats(result)
        return result

    # ── Internal: history bookkeeping ────────────────────────────────────────

    def _make_snapshot(self, response: HTTPResponse, elapsed: Optional[float]) -> _ResponseSnapshot:
        text = self._safe_text(response)
        size = len(getattr(response, "content", b"") or text.encode("utf-8", "ignore"))
        return _ResponseSnapshot(
            status_code=getattr(response, "status_code", 0),
            size=size,
            elapsed=elapsed or 0.0,
            headers=dict(getattr(response, "headers", {}) or {}),
            text_excerpt=text[: self.MAX_TEXT_CAPTURE],
            content_type=getattr(response, "content_type", "") or "",
        )

    @staticmethod
    def _sequential_drift(history: Deque[_ResponseSnapshot], elapsed: Optional[float]) -> float:
        """
        Linear-regression slope (seconds per probe) across the recorded
        elapsed-time history plus the current probe. A meaningfully
        positive slope across a fuzzing loop is a strong signal of a
        progressive time-based injection chain rather than ordinary jitter.
        """
        if elapsed is None:
            return 0.0
        series = [s.elapsed for s in history] + [elapsed]
        n = len(series)
        if n < 2:
            return 0.0
        xs = list(range(n))
        mean_x = sum(xs) / n
        mean_y = sum(series) / n
        num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, series))
        den = sum((x - mean_x) ** 2 for x in xs)
        return num / den if den else 0.0

    def _rolling_drift_for(self, key: Tuple[str, str], elapsed: Optional[float]) -> float:
        history = self._history.get(key)
        if not history:
            return 0.0
        return self._sequential_drift(history, elapsed)

    def _record_stats(self, result: DiffResult) -> None:
        self._total_comparisons += 1
        if result.is_different:
            self._anomalies_detected += 1

    # ── Internal: misc helpers ───────────────────────────────────────────────

    @staticmethod
    def _safe_text(resp: Any) -> str:
        try:
            if getattr(resp, "is_text", True) and getattr(resp, "text", None) is not None:
                return resp.text or ""
            return ""
        except Exception:
            return ""

    @staticmethod
    def _pct_delta(a: int, b: int) -> float:
        if a <= 0:
            return 100.0 if b > 0 else 0.0
        return abs(b - a) / a * 100.0


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function: one-shot diff without engine state
# ─────────────────────────────────────────────────────────────────────────────

def diff_responses(
    base: HTTPResponse,
    test: HTTPResponse,
    base_elapsed: float = 0.0,
    test_elapsed: float = 0.0,
) -> DiffResult:
    """
    One-shot helper — diff two raw HTTP responses without maintaining any
    engine state (history, running statistics). Intended for ad-hoc checks
    or unit tests; scanners running a real scan should hold a single
    shared ``DifferentialAnalysisEngine`` instance so sequential mode and
    aggregate statistics work correctly.
    """
    engine = DifferentialAnalysisEngine()
    return engine.compare(base, test, base_elapsed, test_elapsed)
