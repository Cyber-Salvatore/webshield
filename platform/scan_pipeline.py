"""
WebShield Scan Pipeline
==========================
Pipeline ثابت يمر فيه أي هدف بالترتيب:

    Discovery → Fingerprinting → Baseline → Passive Analysis
    → Active Testing → Confirmation → Evidence Collection
    → Correlation → Reporting

الفرق بين الـ Scan Pipeline والـ Workflow Engine (Part 5):
    - الـ WorkflowEngine مسؤول عن "إمتى" تشغل كل Step (Dependencies،
      Timeouts، Retries، Parallel execution).
    - الـ Scan Pipeline مسؤول عن "البيانات" نفسها: كل Phase بتضيف
      بيانات (Artifacts) في PipelineContext مشترك، والـ Phases اللي
      بعدها تقدر تقرأها بدل ما كل Scanner يشتغل لوحده وميشاركش حاجة.

كل Phase ليها Contract بيحدد:
    - إيه الـ Inputs المطلوبة منها (requires) من الـ Phases اللي قبلها
    - إيه الـ Outputs اللي المفروض تنتجها (produces) للـ Phases اللي بعدها

لو Phase حاولت تشتغل وبيانات الـ requires مش موجودة، الـ Pipeline
يسجل تحذير (أو يفشل الـ Step لو strict=True) بدل ما الأداة تكمل
بعشوائية على بيانات ناقصة.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Scan Pipeline                           ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import inspect
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Union

from .logging_system import PlatformLogger
from .error_framework import ScanError
from .event_bus import Event, EventBus, EventPriority
from .workflow_engine import (
    PhaseStatus,
    ScanPhase,
    WorkflowBuilder,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowStep,
)


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE CONTRACT ERROR
# ══════════════════════════════════════════════════════════════════════════════

class PipelineContractError(ScanError):
    """بيترفع لما Phase تحتاج بيانات من Phase سابقة ومش موجودة (Strict Mode)."""

    def __init__(self, phase: "ScanPhase", missing: List[str], **kw: Any) -> None:
        message = (
            f"Phase '{phase.name}' محتاجة البيانات دي ومش موجودة في "
            f"الـ PipelineContext: {missing}"
        )
        super().__init__(message, **kw)
        self.phase = phase
        self.missing = missing


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE ARTIFACT — وحدة بيانات واحدة متتبعة
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PipelineArtifact:
    """
    سجل لكل قطعة بيانات دخلت الـ Pipeline.
    مفيد للـ Debugging، الـ Replay، وبناء الـ Report النهائي
    (تعرف منين جاءت كل معلومة وإمتى).
    """
    key:        str
    phase:      "ScanPhase"
    producer:   str
    timestamp:  float = field(default_factory=time.monotonic)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key":       self.key,
            "phase":     self.phase.name,
            "producer":  self.producer,
            "timestamp": round(self.timestamp, 3),
        }


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE CONTEXT — البيانات المشتركة بين كل الـ Phases
# ══════════════════════════════════════════════════════════════════════════════

class PipelineContext:
    """
    وعاء البيانات المشترك اللي بيمر عليه الـ Pipeline.

    كل Phase تقدر:
        await ctx.put(ScanPhase.DISCOVERY, "endpoints", [...], producer="crawler")

    وأي Phase بعدها تقدر تقرأ بدون ما تعرف مين أنتجها:
        endpoints = ctx.get("endpoints", [])

    البيانات منظمة كمان حسب الـ Phase (ctx.get_phase_data(phase))
    علشان تقدر تعرف إيه اللي خرج من مرحلة معينة بالذات، وده بيفيد
    في الـ Reporting والـ State Snapshotting (Part 8).
    """

    def __init__(self, target_url: str, scan_id: Optional[str] = None) -> None:
        self.target_url = target_url
        self.scan_id     = scan_id or str(uuid.uuid4())[:8]
        self.created_at  = time.monotonic()

        self._flat:    Dict[str, Any]                       = {}
        self._by_phase: Dict["ScanPhase", Dict[str, Any]]    = {}
        self._history:  List[PipelineArtifact]               = []
        self._lock      = asyncio.Lock()
        self._log       = PlatformLogger.get("PipelineContext")

    # ── Writing ───────────────────────────────────────────────────────────────

    async def put(
        self,
        phase:    "ScanPhase",
        key:      str,
        value:    Any,
        producer: str = "unknown",
    ) -> None:
        """يضيف قطعة بيانات واحدة، متاحة فوراً لأي Phase تالية."""
        async with self._lock:
            self._by_phase.setdefault(phase, {})[key] = value
            self._flat[key] = value
            self._history.append(PipelineArtifact(key=key, phase=phase, producer=producer))
        self._log.debug(f"[{phase.name}] '{key}' ← {producer}")

    async def put_many(
        self,
        phase:    "ScanPhase",
        mapping:  Dict[str, Any],
        producer: str = "unknown",
    ) -> None:
        """يضيف أكتر من قطعة بيانات دفعة واحدة (مثلاً Outputs الـ Step كامل)."""
        for key, value in mapping.items():
            await self.put(phase, key, value, producer=producer)

    # ── Reading ───────────────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """يجيب قيمة بأي اسم، من أي Phase أنتجتها (آخر قيمة تكتب بتربح)."""
        return self._flat.get(key, default)

    def has(self, key: str) -> bool:
        return key in self._flat

    def get_phase_data(self, phase: "ScanPhase") -> Dict[str, Any]:
        """يرجع نسخة من كل البيانات اللي أنتجتها Phase معينة."""
        return dict(self._by_phase.get(phase, {}))

    def get_history(self, key: Optional[str] = None) -> List[PipelineArtifact]:
        if key is None:
            return list(self._history)
        return [a for a in self._history if a.key == key]

    def all(self) -> Dict[str, Any]:
        """نسخة Flat من كل البيانات (للـ Reporting أو الـ Debugging)."""
        return dict(self._flat)

    # ── Snapshot / Restore (للـ State Management — Part 8) ──────────────────

    def snapshot(self) -> Dict[str, Any]:
        """نسخة قابلة للتخزين (JSON-safe بقدر الإمكان) من كل حالة الـ Context."""
        return {
            "target_url": self.target_url,
            "scan_id":    self.scan_id,
            "created_at": self.created_at,
            "flat":       dict(self._flat),
            "by_phase":   {
                phase.name: dict(data) for phase, data in self._by_phase.items()
            },
            "history":    [a.to_dict() for a in self._history],
        }

    @classmethod
    def from_snapshot(cls, data: Dict[str, Any]) -> "PipelineContext":
        """يبني PipelineContext من Snapshot محفوظ (Resume)."""
        ctx = cls(target_url=data.get("target_url", ""), scan_id=data.get("scan_id"))
        ctx.created_at = data.get("created_at", time.monotonic())
        ctx._flat = dict(data.get("flat", {}))
        for phase_name, phase_data in data.get("by_phase", {}).items():
            try:
                phase = ScanPhase[phase_name]
            except KeyError:
                continue
            ctx._by_phase[phase] = dict(phase_data)
        return ctx


# ══════════════════════════════════════════════════════════════════════════════
# STAGE CONTRACT — إيه كل Phase محتاجة وإيه اللي المفروض تنتجه
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class StageContract:
    """تعريف العلاقة بين Phase معينة والبيانات اللي بتتبادلها مع باقي الـ Pipeline."""
    phase:        "ScanPhase"
    requires:     List[str] = field(default_factory=list)
    produces:     List[str] = field(default_factory=list)
    description:  str       = ""

    def missing_from(self, ctx: PipelineContext) -> List[str]:
        return [k for k in self.requires if not ctx.has(k)]


# الـ Contracts الافتراضية اللي تعبر عن الـ Pipeline القياسي في توثيق المشروع
DEFAULT_STAGE_CONTRACTS: Dict["ScanPhase", StageContract] = {
    ScanPhase.DISCOVERY: StageContract(
        phase=ScanPhase.DISCOVERY,
        requires=[],
        produces=["endpoints", "forms", "js_files"],
        description="اكتشاف الـ Assets والـ Endpoints الأولي",
    ),
    ScanPhase.FINGERPRINTING: StageContract(
        phase=ScanPhase.FINGERPRINTING,
        requires=["endpoints"],
        produces=["technologies", "cms", "frameworks"],
        description="تحديد التقنيات بناءً على الـ Endpoints المكتشفة",
    ),
    ScanPhase.BASELINE: StageContract(
        phase=ScanPhase.BASELINE,
        requires=["endpoints"],
        produces=["baseline_responses"],
        description="قياس السلوك الطبيعي قبل أي Active Testing",
    ),
    ScanPhase.PASSIVE_ANALYSIS: StageContract(
        phase=ScanPhase.PASSIVE_ANALYSIS,
        requires=["baseline_responses"],
        produces=["headers_findings", "ssl_findings", "secrets_findings"],
        description="تحليل الـ Responses بدون إرسال Payloads",
    ),
    ScanPhase.ACTIVE_TESTING: StageContract(
        phase=ScanPhase.ACTIVE_TESTING,
        requires=["baseline_responses"],
        produces=["raw_findings"],
        description="الفحص الفعلي بإرسال الـ Payloads",
    ),
    ScanPhase.CONFIRMATION: StageContract(
        phase=ScanPhase.CONFIRMATION,
        requires=["raw_findings"],
        produces=["confirmed_findings"],
        description="التأكد من صحة النتائج وتقليل False Positives",
    ),
    ScanPhase.EVIDENCE: StageContract(
        phase=ScanPhase.EVIDENCE,
        requires=["confirmed_findings"],
        produces=["evidence_bundle"],
        description="جمع الأدلة والتفاصيل لكل نتيجة مؤكدة",
    ),
    ScanPhase.CORRELATION: StageContract(
        phase=ScanPhase.CORRELATION,
        requires=["evidence_bundle"],
        produces=["attack_chains"],
        description="ربط النتائج وتحليل Attack Chains",
    ),
    ScanPhase.REPORTING: StageContract(
        phase=ScanPhase.REPORTING,
        requires=["confirmed_findings"],
        produces=["report_paths"],
        description="توليد التقارير النهائية",
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# STAGE RESULT — ملخص تنفيذ Phase واحدة
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class StageResult:
    phase:        "ScanPhase"
    status:       str                  = "pending"   # pending / running / completed / failed
    started_at:   Optional[float]      = None
    ended_at:     Optional[float]      = None
    step_count:   int                  = 0
    produced_keys: List[str]           = field(default_factory=list)
    warnings:     List[str]            = field(default_factory=list)

    @property
    def duration(self) -> Optional[float]:
        if self.started_at is not None and self.ended_at is not None:
            return round(self.ended_at - self.started_at, 3)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase":         self.phase.name,
            "status":        self.status,
            "duration_s":    self.duration,
            "step_count":    self.step_count,
            "produced_keys": self.produced_keys,
            "warnings":      self.warnings,
        }


@dataclass
class PipelineRunResult:
    """النتيجة النهائية لتشغيل Scan Pipeline كامل."""
    workflow_summary: Dict[str, Any]
    context_snapshot: Dict[str, Any]
    stage_results:     Dict[str, StageResult]
    elapsed_s:         float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_summary": self.workflow_summary,
            "elapsed_s":        round(self.elapsed_s, 2),
            "stages":            {k: v.to_dict() for k, v in self.stage_results.items()},
        }


# ══════════════════════════════════════════════════════════════════════════════
# SCAN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

ExecutorFn = Union[
    Callable[[str, "WorkflowStep"], Optional[Dict[str, Any]]],
    Callable[[str, "WorkflowStep"], Awaitable[Optional[Dict[str, Any]]]],
]


class ScanPipeline:
    """
    الـ Pipeline الثابت اللي يمر فيه أي هدف.

    بيستخدم WorkflowEngine (Part 5) فعلياً لتنفيذ كل Step، لكنه بيلف
    حول الـ Module Executor بتاع المستخدم علشان:
        1. يتأكد إن البيانات المطلوبة (requires) متوفرة قبل تشغيل أي Step
           تابع لـ Phase معينة (Contract Validation).
        2. يجمع الـ Outputs بتاعت كل Step ويحطها في PipelineContext
           مشترك تقدر أي Phase تالية تقرأ منه.
        3. يبني StageResult لكل Phase (مدة التنفيذ، عدد الـ Steps،
           إيه البيانات اللي خرجت منها) — ده اللي يتجمع وقت الـ Reporting.

    الاستخدام:
        bus = EventBus()
        pipeline = ScanPipeline(bus, strict=False)

        async def executor(module_id, step):
            # ... شغل الـ Scanner/Module الحقيقي هنا ...
            return {"endpoints": [...]}     # outputs

        result = await pipeline.run("https://target.com", executor=executor)
        print(result.context_snapshot["endpoints"])
    """

    def __init__(
        self,
        bus:        EventBus,
        contracts:  Optional[Dict["ScanPhase", StageContract]] = None,
        strict:     bool = False,
        max_parallel: int = 5,
    ) -> None:
        self._bus       = bus
        self._contracts = dict(contracts) if contracts else dict(DEFAULT_STAGE_CONTRACTS)
        self._strict    = strict
        self._max_par   = max_parallel
        self._log       = PlatformLogger.get("ScanPipeline")

        self.context: Optional[PipelineContext] = None
        self._wf:     Optional[WorkflowDefinition] = None
        self._stage_results: Dict["ScanPhase", StageResult] = {
            phase: StageResult(phase=phase) for phase in ScanPhase
        }

        bus.on("workflow.step.completed", self._on_step_completed, priority=EventPriority.HIGH)
        bus.on("scan.phase.started",       self._on_phase_started)
        bus.on("scan.phase.completed",     self._on_phase_completed)
        bus.on("scan.phase.failed",        self._on_phase_completed)

    # ── Contracts ─────────────────────────────────────────────────────────────

    def set_contract(self, phase: "ScanPhase", contract: StageContract) -> None:
        """يسمح بتخصيص Contract لـ Phase معينة (مثلاً Profile مختلف)."""
        self._contracts[phase] = contract

    def get_contract(self, phase: "ScanPhase") -> Optional[StageContract]:
        return self._contracts.get(phase)

    async def validate_phase(self, phase: "ScanPhase") -> List[str]:
        """يرجع قائمة بالبيانات الناقصة لـ Phase معينة (فاضية = كل حاجة جاهزة)."""
        if self.context is None:
            return []
        contract = self._contracts.get(phase)
        if not contract:
            return []
        return contract.missing_from(self.context)

    # ── Executor Wrapping ────────────────────────────────────────────────────

    def wrap_executor(self, executor: Optional[ExecutorFn]) -> Callable:
        """
        يلف الـ Executor الحقيقي بمنطق التحقق من الـ Contract وتجميع البيانات.
        بيتمرر للـ WorkflowEngine كـ module_executor.
        """

        async def _wrapped(module_id: str, step: WorkflowStep) -> Dict[str, Any]:
            assert self.context is not None

            missing = await self.validate_phase(step.phase)
            if missing:
                msg = (
                    f"Step '{step.step_id}' (phase={step.phase.name}) "
                    f"ناقصها بيانات: {missing}"
                )
                self._stage_results[step.phase].warnings.append(msg)
                self._log.warning(msg)
                if self._strict:
                    raise PipelineContractError(step.phase, missing)

            outputs: Optional[Dict[str, Any]] = None
            if executor is not None:
                if inspect.iscoroutinefunction(executor):
                    outputs = await executor(module_id, step)
                else:
                    outputs = executor(module_id, step)

            outputs = outputs or {}
            if outputs:
                await self.context.put_many(step.phase, outputs, producer=module_id)

            return outputs

        return _wrapped

    # ── Main Run ──────────────────────────────────────────────────────────────

    async def run(
        self,
        target_url:   str,
        profile:      str = "balanced",
        discovered:   Optional[Dict[str, Any]] = None,
        executor:     Optional[ExecutorFn] = None,
        scan_id:      Optional[str] = None,
        context:      Optional[PipelineContext] = None,
    ) -> PipelineRunResult:
        """
        يبني Workflow مناسب للهدف ويشغله مع PipelineContext مشترك.

        لو context تم تمريره (مثلاً من StateManager.resume — Part 8)،
        بيستخدمه بدل ما يبني واحد جديد فاضي.
        """
        start = time.monotonic()

        self.context = context or PipelineContext(target_url, scan_id=scan_id)
        if discovered:
            await self.context.put_many(ScanPhase.DISCOVERY, discovered, producer="prebuilt")

        self._bus.set_scan_id(self.context.scan_id)

        wf = WorkflowBuilder(profile).build(target_url, discovered)
        self._wf = wf

        wrapped_executor = self.wrap_executor(executor)
        engine = WorkflowEngine(self._bus, wrapped_executor, max_parallel=self._max_par)

        self._log.info(
            f"Starting ScanPipeline for '{target_url}' "
            f"(scan_id={self.context.scan_id}, profile={profile}, strict={self._strict})"
        )

        summary = await engine.run(wf)

        elapsed = time.monotonic() - start
        result = PipelineRunResult(
            workflow_summary=summary,
            context_snapshot=self.context.snapshot(),
            stage_results=dict(self._stage_results),
            elapsed_s=elapsed,
        )

        await self._bus.emit(
            "pipeline.completed",
            {"scan_id": self.context.scan_id, "summary": summary},
            source="ScanPipeline",
        )
        self._log.info(f"ScanPipeline finished in {elapsed:.1f}s")
        return result

    # ── Event Handlers ────────────────────────────────────────────────────────

    async def _on_step_completed(self, event: Event) -> None:
        """يجمع Outputs كل Step المكتمل في الـ StageResult بتاع Phase تبعها."""
        if self._wf is None:
            return
        step_id = event.data.get("step_id")
        step = next((s for s in self._wf.steps if s.step_id == step_id), None)
        if step is None:
            return

        stage = self._stage_results.setdefault(step.phase, StageResult(phase=step.phase))
        stage.step_count += 1
        outputs = event.data.get("outputs") or {}
        for key in outputs:
            if key not in stage.produced_keys:
                stage.produced_keys.append(key)

    async def _on_phase_started(self, event: Event) -> None:
        phase = self._phase_from_event(event)
        if phase is None:
            return
        stage = self._stage_results.setdefault(phase, StageResult(phase=phase))
        stage.status     = "running"
        stage.started_at = time.monotonic()

    async def _on_phase_completed(self, event: Event) -> None:
        phase = self._phase_from_event(event)
        if phase is None:
            return
        stage = self._stage_results.setdefault(phase, StageResult(phase=phase))
        stage.ended_at = time.monotonic()
        stage.status = "failed" if event.name.endswith("failed") else "completed"

    @staticmethod
    def _phase_from_event(event: Event) -> Optional["ScanPhase"]:
        name = (event.data or {}).get("phase")
        if not name:
            return None
        try:
            return ScanPhase[name.upper()]
        except KeyError:
            return None

    # ── Inspection ────────────────────────────────────────────────────────────

    def get_stage_results(self) -> Dict[str, StageResult]:
        return {phase.name: result for phase, result in self._stage_results.items()}

    def get_context(self) -> Optional[PipelineContext]:
        return self.context
