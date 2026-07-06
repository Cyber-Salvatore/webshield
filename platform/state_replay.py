"""
WebShield State Management & Replay Framework
================================================

STATE MANAGEMENT:
==================
يحفظ حالة الفحص بالكامل أثناء التشغيل (أي Step خلص، أي Phase
وصلنا ليها، وكل بيانات الـ PipelineContext) بحيث لو الفحص وقف
لأي سبب (Crash / Ctrl-C / إيقاف يدوي) يقدر يكمل من نفس النقطة
من غير إعادة كل اللي فات.

    state = ScanState.new(target_url="https://target.com", profile="deep")
    manager = StateManager()
    await manager.save(state)
    ...
    state = manager.load(state.scan_id)          # في تشغيلة تانية
    resumable = manager.list_resumable()          # كل الفحوصات الناقصة

REPLAY FRAMEWORK:
==================
بيخزن كل Request وResponse بكل تفاصيلهم بحيث أي Finding يقدر
يتعاد بنفس الظروف بالظبط — للتأكد، التجربة، توليد PoC، أو
المراجعة بعد انتهاء الفحص.

    replay = ReplayFramework()
    entry = replay.record(
        request=RequestRecord(method="GET", url="...", headers={...}),
        response=ResponseRecord(status_code=200, headers={...}, body_snippet="..."),
        vuln_type="SQL Injection",
    )
    print(replay.generate_curl(entry.request))
    replay.export_poc(entry.entry_id, "poc_001.json")

كل الموديول ده Decoupled عن أي HTTP Client معين (Core ميبقاش فيه
أي Logic خاص بالثغرات أو بمكتبة معينة) — أي حاجة ليها الخصائص
المناسبة (method/url/headers/...) تقدر تتحول لـ RequestRecord.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — State Management & Replay Framework     ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Union

from .logging_system import PlatformLogger
from .error_framework import WebShieldError
from .event_bus import Event, EventBus

try:
    # اختياري — لو موجود الـ WorkflowDefinition نقدر نطبق الـ State عليه مباشرة
    from .workflow_engine import PhaseStatus, ScanPhase, WorkflowDefinition, WorkflowStep
except ImportError:  # pragma: no cover
    PhaseStatus = None       # type: ignore[assignment]
    ScanPhase = None         # type: ignore[assignment]
    WorkflowDefinition = None  # type: ignore[assignment]
    WorkflowStep = None        # type: ignore[assignment]


class StateError(WebShieldError):
    """خطأ في حفظ أو تحميل حالة الفحص."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# PART 8.A — STATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

class ScanStatus:
    """حالة الفحص العامة."""
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"
    ABORTED   = "aborted"


@dataclass
class ScanState:
    """
    لقطة كاملة لحالة فحص واحد في لحظة معينة.
    بتُحفظ على القرص وتُحمّل تاني علشان الفحص يكمل من نفس النقطة.
    """
    scan_id:          str
    target_url:       str
    profile:          str = "balanced"
    status:           str = ScanStatus.RUNNING

    created_at:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    current_phase:    Optional[str] = None
    completed_steps:  List[str]     = field(default_factory=list)
    failed_steps:     List[str]     = field(default_factory=list)
    skipped_steps:    List[str]     = field(default_factory=list)

    # لقطة كاملة من PipelineContext.snapshot() (Part 7) — لو موجودة
    pipeline_snapshot: Dict[str, Any] = field(default_factory=dict)

    # عدّادات سريعة بدون الحاجة لقراءة كل الـ Findings
    findings_count:    int = 0
    progress_pct:      float = 0.0

    # حقل عام لأي بيانات إضافية يحتاجها المستخدم
    extra: Dict[str, Any] = field(default_factory=dict)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @classmethod
    def new(cls, target_url: str, profile: str = "balanced", scan_id: Optional[str] = None) -> "ScanState":
        return cls(scan_id=scan_id or str(uuid.uuid4())[:12], target_url=target_url, profile=profile)

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_step(self, step_id: str, success: bool) -> None:
        bucket = self.completed_steps if success else self.failed_steps
        if step_id not in bucket:
            bucket.append(step_id)
        self.touch()

    @property
    def is_resumable(self) -> bool:
        return self.status in (ScanStatus.RUNNING, ScanStatus.PAUSED)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanState":
        known = {f for f in cls.__dataclass_fields__.keys()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


class StateManager:
    """
    المدير المركزي لحفظ واستعادة حالة الفحوصات.

    - يحفظ كل ScanState في ملف JSON مستقل تحت state_dir/{scan_id}.json
    - الكتابة Atomic (يكتب في ملف مؤقت وبعدين يستبدل) علشان مفيش
      ملف يتلخرب نص كتابة لو الأداة قفلت فجأة.
    - يدعم Auto-save بشكل دوري عن طريق Background Task.
    - يقدر يتصل بـ EventBus ويحدث الـ State تلقائياً مع كل Event
      من الـ Workflow (step completed/failed، phase started...).
    """

    _FILE_SUFFIX = ".json"
    _STATE_VERSION = 1

    def __init__(
        self,
        storage_dir: Union[str, Path] = "./.webshield_state",
        bus:         Optional[EventBus] = None,
        autosave_interval: float = 15.0,
    ) -> None:
        self._dir = Path(storage_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._bus = bus
        self._autosave_interval = autosave_interval
        self._log = PlatformLogger.get("StateManager")

        self._states: Dict[str, ScanState] = {}
        self._autosave_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

        if bus is not None:
            self._attach_bus(bus)

    # ── EventBus integration ─────────────────────────────────────────────────

    def _attach_bus(self, bus: EventBus) -> None:
        bus.on("workflow.step.completed", self._on_step_completed)
        bus.on("workflow.step.failed",    self._on_step_failed)
        bus.on("scan.phase.started",      self._on_phase_started)
        bus.on("workflow.completed",      self._on_workflow_completed)
        bus.on("finding.new",             self._on_finding_new)

    async def _on_step_completed(self, event: Event) -> None:
        state = self._current_state(event)
        if state:
            state.mark_step(event.data.get("step_id", ""), success=True)

    async def _on_step_failed(self, event: Event) -> None:
        state = self._current_state(event)
        if state:
            state.mark_step(event.data.get("step_id", ""), success=False)

    async def _on_phase_started(self, event: Event) -> None:
        state = self._current_state(event)
        if state:
            state.current_phase = event.data.get("phase")
            state.touch()

    async def _on_workflow_completed(self, event: Event) -> None:
        state = self._current_state(event)
        if state:
            summary = event.data or {}
            state.status = ScanStatus.COMPLETED
            state.progress_pct = summary.get("progress_pct", state.progress_pct)
            state.touch()
            await self.save(state)

    async def _on_finding_new(self, event: Event) -> None:
        state = self._current_state(event)
        if state:
            state.findings_count += 1

    def _current_state(self, event: Event) -> Optional[ScanState]:
        scan_id = event.scan_id
        if scan_id and scan_id in self._states:
            return self._states[scan_id]
        # Fallback: لو فيه State واحد بس شغال
        if len(self._states) == 1:
            return next(iter(self._states.values()))
        return None

    # ── Tracking ──────────────────────────────────────────────────────────────

    def track(self, state: ScanState) -> None:
        """يبدأ تتبع ScanState (يخليها متاحة لـ EventBus handlers)."""
        self._states[state.scan_id] = state

    def untrack(self, scan_id: str) -> None:
        self._states.pop(scan_id, None)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _path_for(self, scan_id: str) -> Path:
        safe_id = "".join(c for c in scan_id if c.isalnum() or c in ("-", "_")) or "scan"
        return self._dir / f"{safe_id}{self._FILE_SUFFIX}"

    async def save(self, state: ScanState) -> Path:
        """يحفظ الحالة بشكل Atomic (write-then-replace)."""
        async with self._lock:
            state.touch()
            self._states[state.scan_id] = state
            path = self._path_for(state.scan_id)
            payload = {
                "version": self._STATE_VERSION,
                "state":   state.to_dict(),
            }

            tmp_path = path.with_suffix(path.suffix + ".tmp")
            try:
                tmp_path.write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                    encoding="utf-8",
                )
                os.replace(tmp_path, path)   # Atomic على كل أنظمة التشغيل المدعومة
            except OSError as e:
                raise StateError(f"فشل حفظ State لـ '{state.scan_id}': {e}") from e
            finally:
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass

            self._log.debug(f"State saved: {state.scan_id} → {path}")
            return path

    def load(self, scan_id: str) -> Optional[ScanState]:
        """يحمل حالة فحص محفوظة، أو None لو غير موجودة."""
        path = self._path_for(scan_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            state = ScanState.from_dict(payload.get("state", {}))
            self._states[state.scan_id] = state
            return state
        except (json.JSONDecodeError, OSError, TypeError) as e:
            self._log.error(f"فشل تحميل State لـ '{scan_id}': {e}")
            return None

    def delete(self, scan_id: str) -> bool:
        path = self._path_for(scan_id)
        self._states.pop(scan_id, None)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_resumable(self) -> List[Dict[str, Any]]:
        """يرجع ملخص كل الفحوصات اللي ممكن تُستكمل (RUNNING/PAUSED)."""
        results: List[Dict[str, Any]] = []
        for f in self._dir.glob(f"*{self._FILE_SUFFIX}"):
            try:
                payload = json.loads(f.read_text(encoding="utf-8"))
                state = ScanState.from_dict(payload.get("state", {}))
            except (json.JSONDecodeError, OSError, TypeError):
                continue
            if state.is_resumable:
                results.append({
                    "scan_id":      state.scan_id,
                    "target_url":   state.target_url,
                    "profile":      state.profile,
                    "status":       state.status,
                    "current_phase": state.current_phase,
                    "progress_pct": state.progress_pct,
                    "updated_at":   state.updated_at,
                })
        return sorted(results, key=lambda r: r["updated_at"], reverse=True)

    # ── Auto-save ─────────────────────────────────────────────────────────────

    async def start_autosave(self, state: ScanState) -> None:
        """يبدأ Background Task يحفظ الحالة بشكل دوري لحد ما يتوقف."""
        self.track(state)
        if state.scan_id in self._autosave_tasks:
            return

        async def _loop() -> None:
            try:
                while True:
                    await asyncio.sleep(self._autosave_interval)
                    if state.status not in (ScanStatus.RUNNING, ScanStatus.PAUSED):
                        await self.save(state)
                        break
                    await self.save(state)
            except asyncio.CancelledError:
                await self.save(state)
                raise

        task = asyncio.create_task(_loop(), name=f"autosave-{state.scan_id}")
        self._autosave_tasks[state.scan_id] = task

    async def stop_autosave(self, scan_id: str) -> None:
        task = self._autosave_tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # ── Workflow Resume Helpers ───────────────────────────────────────────────

    def apply_to_workflow(self, state: ScanState, wf: "WorkflowDefinition") -> int:
        """
        يطبق الـ State المحفوظة على WorkflowDefinition جديد قبل إعادة تشغيله:
        أي Step كانت COMPLETED قبل كده بيتعلّم عليها كده تاني، فالـ WorkflowEngine
        مش بيعيد تشغيلها (لأنه بس بيشغل الـ Steps PENDING).

        Returns:
            عدد الـ Steps اللي تم تخطيها (resumed).
        """
        if PhaseStatus is None:
            raise StateError("workflow_engine غير متاح — متأكد إن الموديول متحمّل صح؟")

        completed: Set[str] = set(state.completed_steps)
        resumed = 0
        for step in wf.steps:
            if step.step_id in completed:
                step.status = PhaseStatus.COMPLETED
                resumed += 1
        return resumed


# ══════════════════════════════════════════════════════════════════════════════
# PART 8.B — REPLAY FRAMEWORK
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RequestRecord:
    """تسجيل كامل لـ Request واحد بكل تفاصيله، علشان يقدر يتعاد بالظبط."""
    method:   str
    url:      str
    headers:  Dict[str, str] = field(default_factory=dict)
    cookies:  Dict[str, str] = field(default_factory=dict)
    params:   Dict[str, Any] = field(default_factory=dict)
    body:     Optional[str]  = None   # نص أو JSON-encoded — مش binary
    body_encoding: str       = "text"  # text / json / base64

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RequestRecord":
        known = {f for f in cls.__dataclass_fields__.keys()}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ResponseRecord:
    """تسجيل لـ Response مقابل Request معين (مقتطف بس، مش الجسم كامل لو ضخم)."""
    status_code:   int
    headers:       Dict[str, str] = field(default_factory=dict)
    body_snippet:  str            = ""
    elapsed_ms:    float          = 0.0
    truncated:     bool           = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResponseRecord":
        known = {f for f in cls.__dataclass_fields__.keys()}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ReplayEntry:
    """قيد واحد كامل في الـ Replay Framework: Request + Response + Metadata."""
    entry_id:    str
    request:     RequestRecord
    response:    Optional[ResponseRecord] = None
    finding_id:  Optional[str] = None
    vuln_type:   Optional[str] = None
    tags:        List[str]     = field(default_factory=list)
    notes:       str           = ""
    recorded_at: str           = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id":    self.entry_id,
            "request":     self.request.to_dict(),
            "response":    self.response.to_dict() if self.response else None,
            "finding_id":  self.finding_id,
            "vuln_type":   self.vuln_type,
            "tags":        self.tags,
            "notes":       self.notes,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReplayEntry":
        return cls(
            entry_id    = data["entry_id"],
            request     = RequestRecord.from_dict(data["request"]),
            response    = ResponseRecord.from_dict(data["response"]) if data.get("response") else None,
            finding_id  = data.get("finding_id"),
            vuln_type   = data.get("vuln_type"),
            tags        = list(data.get("tags", [])),
            notes       = data.get("notes", ""),
            recorded_at = data.get("recorded_at", datetime.now(timezone.utc).isoformat()),
        )


SenderFn = Callable[[RequestRecord], Awaitable[Any]]


class ReplayFramework:
    """
    يخزن كل Request/Response مع تفاصيلهم الكاملة بحيث أي Finding يقدر
    يتعاد بنفس الظروف في أي وقت — للتأكد، التجربة، توليد PoC، أو المراجعة.

    الموديول مستقل تماماً عن أي HTTP Client معين؛ المستخدم هو اللي
    بيمرر الـ Request/Response (أو Sender function للـ replay الفعلي).
    """

    def __init__(
        self,
        storage_dir:    Union[str, Path] = "./.webshield_replay",
        max_body_chars: int = 4000,
        scan_id:        Optional[str] = None,
    ) -> None:
        self._dir = Path(storage_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_body = max_body_chars
        self._scan_id  = scan_id or "default"
        self._log      = PlatformLogger.get("ReplayFramework")

        self._entries: Dict[str, ReplayEntry] = {}
        self._lock     = asyncio.Lock()

        self._jsonl_path = self._dir / f"{self._safe_name(self._scan_id)}.jsonl"

    @staticmethod
    def _safe_name(name: str) -> str:
        return "".join(c for c in name if c.isalnum() or c in ("-", "_")) or "default"

    # ── Building Records ──────────────────────────────────────────────────────

    def truncate_body(self, body: Optional[str]) -> tuple:
        """يقص الـ Body لو أطول من الحد الأقصى. يرجع (body, truncated)."""
        if body is None:
            return "", False
        if len(body) > self._max_body:
            return body[: self._max_body], True
        return body, False

    def build_response_record(
        self,
        status_code: int,
        headers:     Optional[Dict[str, str]] = None,
        body:        Optional[str] = None,
        elapsed_ms:  float = 0.0,
    ) -> ResponseRecord:
        """يبني ResponseRecord من بيانات خام (Duck-typed — مش محتاج Response object معين)."""
        snippet, truncated = self.truncate_body(body)
        return ResponseRecord(
            status_code=status_code,
            headers=dict(headers or {}),
            body_snippet=snippet,
            elapsed_ms=elapsed_ms,
            truncated=truncated,
        )

    @staticmethod
    def build_response_from_object(obj: Any, elapsed_ms: float = 0.0, max_body_chars: int = 4000) -> "ResponseRecord":
        """
        يبني ResponseRecord من أي Object فيه status_code/headers/text
        (زي HTTPResponse بتاع core.http_client) بدون أي import مباشر
        — علشان طبقة الـ Platform تفضل مستقلة عن طبقة الـ Core.
        """
        status_code = getattr(obj, "status_code", 0)
        headers = dict(getattr(obj, "headers", {}) or {})
        text = getattr(obj, "text", "") or ""
        truncated = len(text) > max_body_chars
        return ResponseRecord(
            status_code=status_code,
            headers=headers,
            body_snippet=text[:max_body_chars],
            elapsed_ms=elapsed_ms or getattr(obj, "elapsed", 0.0) * 1000,
            truncated=truncated,
        )

    # ── Recording ─────────────────────────────────────────────────────────────

    def record(
        self,
        request:    RequestRecord,
        response:   Optional[ResponseRecord] = None,
        finding_id: Optional[str] = None,
        vuln_type:  Optional[str] = None,
        tags:       Optional[List[str]] = None,
        notes:      str = "",
    ) -> ReplayEntry:
        """يسجل Request/Response جديدة ويخزنها على القرص فوراً (Append-only)."""
        entry = ReplayEntry(
            entry_id=str(uuid.uuid4())[:10],
            request=request,
            response=response,
            finding_id=finding_id,
            vuln_type=vuln_type,
            tags=list(tags or []),
            notes=notes,
        )
        self._entries[entry.entry_id] = entry
        self._append_jsonl(entry)
        self._log.debug(f"Replay entry recorded: {entry.entry_id} ({request.method} {request.url})")
        return entry

    def _append_jsonl(self, entry: ReplayEntry) -> None:
        try:
            with self._jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict(), ensure_ascii=False, default=str))
                fh.write("\n")
        except OSError as e:
            self._log.error(f"فشل تسجيل Replay entry على القرص: {e}")

    def load_all(self) -> List[ReplayEntry]:
        """يحمل كل الـ Entries المخزنة من ملف الـ JSONL (مفيد بعد Resume)."""
        entries: List[ReplayEntry] = []
        if not self._jsonl_path.exists():
            return entries
        with self._jsonl_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = ReplayEntry.from_dict(json.loads(line))
                    entries.append(entry)
                    self._entries[entry.entry_id] = entry
                except (json.JSONDecodeError, KeyError) as e:
                    self._log.warning(f"تخطي سطر Replay تالف: {e}")
        return entries

    # ── Querying ──────────────────────────────────────────────────────────────

    def get(self, entry_id: str) -> Optional[ReplayEntry]:
        return self._entries.get(entry_id)

    def find_by_finding(self, finding_id: str) -> List[ReplayEntry]:
        return [e for e in self._entries.values() if e.finding_id == finding_id]

    def find_by_tag(self, tag: str) -> List[ReplayEntry]:
        return [e for e in self._entries.values() if tag in e.tags]

    def all_entries(self) -> List[ReplayEntry]:
        return list(self._entries.values())

    # ── curl reproduction ─────────────────────────────────────────────────────

    def generate_curl(self, request: RequestRecord) -> str:
        """يبني curl command كامل لإعادة تنفيذ Request معين."""
        parts = ["curl", "-i", "-X", request.method]
        for name, value in request.headers.items():
            parts.append(f"-H {self._shell_quote(f'{name}: {value}')}")
        if request.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in request.cookies.items())
            parts.append(f"-H {self._shell_quote(f'Cookie: {cookie_str}')}")
        if request.body:
            parts.append(f"--data-raw {self._shell_quote(request.body)}")
        parts.append(self._shell_quote(request.url))
        return " ".join(parts)

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\\''") + "'"

    # ── Replay (actual re-execution) ──────────────────────────────────────────

    async def replay(self, entry_id: str, sender: SenderFn) -> Any:
        """
        يعيد تنفيذ Request مسجل عن طريق Sender يحدده المستخدم
        (مثلاً wrapper حول core.http_client.HTTPClient). الموديول
        ده نفسه ميعرفش حاجة عن أي مكتبة HTTP — Decoupling كامل.
        """
        entry = self._entries.get(entry_id)
        if entry is None:
            raise StateError(f"مفيش Replay entry بـ id='{entry_id}'")
        return await sender(entry.request)

    # ── PoC / Bundle Export ───────────────────────────────────────────────────

    def export_poc(self, entry_id: str, path: Union[str, Path]) -> Path:
        """يصدر PoC كامل (Request + Response + curl) لـ Finding واحد."""
        entry = self._entries.get(entry_id)
        if entry is None:
            raise StateError(f"مفيش Replay entry بـ id='{entry_id}'")

        bundle = entry.to_dict()
        bundle["curl_command"] = self.generate_curl(entry.request)

        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return out_path

    def export_bundle(self, entry_ids: List[str], path: Union[str, Path]) -> Path:
        """يصدر مجموعة Entries في ملف واحد (مفيد لتصدير كل أدلة الفحص دفعة واحدة)."""
        bundle = {
            "scan_id": self._scan_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entries": [],
        }
        for entry_id in entry_ids:
            entry = self._entries.get(entry_id)
            if entry is None:
                continue
            item = entry.to_dict()
            item["curl_command"] = self.generate_curl(entry.request)
            bundle["entries"].append(item)

        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return out_path

    # ── EventBus integration (اختياري، للإحصائيات بس) ────────────────────────

    def attach(self, bus: EventBus) -> None:
        """يستمع لـ finding.new بس لإحصائيات (التسجيل الفعلي لازم يكون Explicit)."""
        bus.on("finding.new", self._on_finding_new)

    async def _on_finding_new(self, event: Event) -> None:
        self._log.debug(
            f"Finding جديد ({event.data.get('vuln_type')}) — "
            f"استخدم record() لتسجيل الـ Request/Response المرتبطة بيه لو متاحة"
        )
