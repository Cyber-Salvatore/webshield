"""
WebShield Workflow Orchestration Layer
=========================================
Workflow Engine مسؤول عن ترتيب كل مراحل الفحص حسب طبيعة الهدف.

الأداة متشتغلش بعشوائية، كل خطوة تبني على اللي قبلها:

    Discovery → Fingerprinting → Baseline → Passive Analysis
    → Active Testing → Confirmation → Evidence Collection
    → Correlation → Reporting

والـ Workflow بيغير نفسه أثناء التشغيل حسب النتائج:
    - اكتشف API → يبدأ API Discovery
    - اكتشف Admin Panel → يبدأ Authorization Testing
    - اكتشف File Upload → يبدأ Upload Security Testing
    - اكتشف GraphQL → يفعّل GraphQL Scanner
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Workflow Orchestration Layer            ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .logging_system import PlatformLogger
from .error_framework import WebShieldError, ScanError
from .event_bus import EventBus, Event, EventPriority


# ══════════════════════════════════════════════════════════════════════════════
# SCAN PHASES
# ══════════════════════════════════════════════════════════════════════════════

class ScanPhase(Enum):
    """
    مراحل الفحص بالترتيب الصحيح.
    كل مرحلة بتبني على نتائج المرحلة اللي قبلها.
    """
    DISCOVERY         = (1,  "اكتشاف الـ Assets والـ Endpoints")
    FINGERPRINTING    = (2,  "تحديد التقنيات المستخدمة")
    BASELINE          = (3,  "قياس السلوك الطبيعي للتطبيق")
    PASSIVE_ANALYSIS  = (4,  "تحليل الـ Responses بدون إرسال Payloads")
    ACTIVE_TESTING    = (5,  "الفحص الفعلي بإرسال الـ Payloads")
    CONFIRMATION      = (6,  "التأكد من صحة النتائج")
    EVIDENCE          = (7,  "جمع الأدلة والتفاصيل")
    CORRELATION       = (8,  "ربط النتائج وتحليل Attack Chains")
    REPORTING         = (9,  "توليد التقارير النهائية")

    def __new__(cls, order: int, description: str):
        obj = object.__new__(cls)
        obj._value_ = order
        obj.description = description
        return obj

    @property
    def order(self) -> int:
        return self._value_

    def __lt__(self, other: "ScanPhase") -> bool:
        return self.order < other.order


class PhaseStatus(Enum):
    PENDING    = auto()
    RUNNING    = auto()
    COMPLETED  = auto()
    SKIPPED    = auto()
    FAILED     = auto()
    PAUSED     = auto()


# ══════════════════════════════════════════════════════════════════════════════
# WORKFLOW STEP
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WorkflowStep:
    """
    خطوة واحدة داخل الـ Workflow.

    كل Step بيحتوي على:
    - اسمه وصفه
    - الـ Module اللي بينفذه
    - الـ Phase اللي بينتمي ليها
    - شروط تشغيله (conditions)
    - نتائجه (outputs)
    """
    step_id:     str
    name:        str
    description: str
    phase:       ScanPhase
    module_id:   str                          # الـ Plugin اللي بينفذه
    priority:    int            = 50          # 0 = أول، 100 = آخر
    conditions:  List[str]     = field(default_factory=list)  # شروط للتشغيل
    depends_on:  List[str]     = field(default_factory=list)  # Step IDs لازم تخلص الأول
    outputs:     Dict[str, Any] = field(default_factory=dict)  # نتائج الـ Step
    timeout:     int            = 300         # ثواني
    retry_count: int            = 0
    optional:    bool           = False       # لو True → الفشل مش بيوقف الـ Workflow

    # Runtime
    status:      PhaseStatus   = PhaseStatus.PENDING
    start_time:  Optional[float] = None
    end_time:    Optional[float] = None
    error:       Optional[str]   = None
    skip_reason: Optional[str]   = None

    @property
    def duration(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None

    @property
    def is_done(self) -> bool:
        return self.status in (
            PhaseStatus.COMPLETED,
            PhaseStatus.SKIPPED,
            PhaseStatus.FAILED,
        )


# ══════════════════════════════════════════════════════════════════════════════
# WORKFLOW DEFINITION
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WorkflowDefinition:
    """
    تعريف Workflow كامل لهدف معين.

    الـ WorkflowEngine بيبني Workflow Definition بناءً على:
    - طبيعة الهدف (API / Web App / CMS / etc.)
    - الـ Profile المختار
    - ما تم اكتشافه أثناء الفحص
    """
    workflow_id:  str
    name:         str
    description:  str
    target_url:   str
    profile:      str            = "balanced"
    steps:        List[WorkflowStep] = field(default_factory=list)
    context:      Dict[str, Any]     = field(default_factory=dict)

    # Stats
    created_at:   float          = field(default_factory=time.monotonic)
    total_steps:  int            = 0
    done_steps:   int            = 0

    def add_step(self, step: WorkflowStep) -> None:
        self.steps.append(step)
        self.total_steps = len(self.steps)

    def get_phase_steps(self, phase: ScanPhase) -> List[WorkflowStep]:
        return [s for s in self.steps if s.phase == phase]

    def get_ready_steps(self, completed_ids: Set[str]) -> List[WorkflowStep]:
        """يرجع الـ Steps اللي جاهزة للتنفيذ (كل Dependencies خلصت)."""
        ready = []
        for step in self.steps:
            if step.status != PhaseStatus.PENDING:
                continue
            if all(dep in completed_ids for dep in step.depends_on):
                ready.append(step)
        return sorted(ready, key=lambda s: (s.phase.order, s.priority))

    @property
    def progress_pct(self) -> float:
        if not self.total_steps:
            return 0.0
        done = sum(1 for s in self.steps if s.is_done)
        return round((done / self.total_steps) * 100, 1)

    @property
    def current_phase(self) -> Optional[ScanPhase]:
        """أحدث Phase شغالة دلوقتي."""
        for step in self.steps:
            if step.status == PhaseStatus.RUNNING:
                return step.phase
        return None


# ══════════════════════════════════════════════════════════════════════════════
# WORKFLOW BUILDER
# ══════════════════════════════════════════════════════════════════════════════

class WorkflowBuilder:
    """
    بيبني Workflow Definition مناسب للهدف.

    الـ Builder بيقرأ:
    - الـ Profile المختار (quick / deep / api / etc.)
    - ما اتكشف من الهدف (تقنيات، endpoints، features)
    وبيولد Workflow مخصوص.
    """

    def __init__(self, profile: str = "balanced") -> None:
        self._profile = profile
        self._log     = PlatformLogger.get("WorkflowBuilder")

    def build(
        self,
        target_url: str,
        discovered: Optional[Dict[str, Any]] = None,
    ) -> WorkflowDefinition:
        """يبني Workflow كامل للهدف."""
        wf = WorkflowDefinition(
            workflow_id = str(uuid.uuid4())[:8],
            name        = f"WebShield Scan — {target_url}",
            description = f"Workflow تلقائي للـ Profile '{self._profile}'",
            target_url  = target_url,
            profile     = self._profile,
            context     = discovered or {},
        )

        # الخطوات الأساسية الموجودة في كل Workflow
        self._add_core_steps(wf)

        # خطوات إضافية بناءً على ما تم اكتشافه
        if discovered:
            self._add_dynamic_steps(wf, discovered)

        self._log.info(
            f"Built workflow '{wf.workflow_id}' with {wf.total_steps} steps "
            f"for profile '{self._profile}'"
        )
        return wf

    def _add_core_steps(self, wf: WorkflowDefinition) -> None:
        """الخطوات الأساسية الموجودة في كل Workflow."""

        # Phase 1: Discovery
        wf.add_step(WorkflowStep(
            step_id     = "discovery_crawler",
            name        = "Web Crawler",
            description = "زحف الموقع واكتشاف كل الـ Endpoints",
            phase       = ScanPhase.DISCOVERY,
            module_id   = "crawler",
            priority    = 10,
            timeout     = 600,
        ))
        wf.add_step(WorkflowStep(
            step_id     = "discovery_js",
            name        = "JS Analyzer",
            description = "تحليل ملفات JavaScript لاكتشاف Endpoints مخفية",
            phase       = ScanPhase.DISCOVERY,
            module_id   = "js_analyzer",
            priority    = 20,
            depends_on  = ["discovery_crawler"],
        ))

        # Phase 2: Fingerprinting
        wf.add_step(WorkflowStep(
            step_id     = "fingerprint_tech",
            name        = "Technology Fingerprinter",
            description = "تحديد التقنيات والـ Frameworks المستخدمة",
            phase       = ScanPhase.FINGERPRINTING,
            module_id   = "fingerprinter",
            priority    = 10,
            depends_on  = ["discovery_crawler"],
        ))

        # Phase 3: Baseline
        wf.add_step(WorkflowStep(
            step_id     = "baseline_responses",
            name        = "Response Baseline",
            description = "قياس السلوك الطبيعي للتطبيق كنقطة مرجعية",
            phase       = ScanPhase.BASELINE,
            module_id   = "baseline_engine",
            priority    = 10,
            depends_on  = ["fingerprint_tech"],
        ))

        # Phase 4: Passive Analysis
        wf.add_step(WorkflowStep(
            step_id     = "passive_headers",
            name        = "Headers Analysis",
            description = "تحليل الـ Security Headers",
            phase       = ScanPhase.PASSIVE_ANALYSIS,
            module_id   = "headers_scanner",
            priority    = 10,
            depends_on  = ["baseline_responses"],
        ))
        wf.add_step(WorkflowStep(
            step_id     = "passive_ssl",
            name        = "SSL/TLS Analysis",
            description = "فحص إعدادات الـ SSL/TLS",
            phase       = ScanPhase.PASSIVE_ANALYSIS,
            module_id   = "ssl_tls_scanner",
            priority    = 20,
            depends_on  = ["baseline_responses"],
        ))
        wf.add_step(WorkflowStep(
            step_id     = "passive_secrets",
            name        = "Secrets Scanner",
            description = "البحث عن API Keys وPasswords في الكود",
            phase       = ScanPhase.PASSIVE_ANALYSIS,
            module_id   = "secrets_scanner",
            priority    = 30,
            depends_on  = ["discovery_js"],
        ))

        # Phase 5: Active Testing (الأساسي)
        core_active = [
            ("active_xss",   "XSS Scanner",         "xss_scanner",   10),
            ("active_sqli",  "SQL Injection",        "sqli_scanner",  20),
            ("active_cmdi",  "Command Injection",    "cmdi_scanner",  30),
            ("active_ssrf",  "SSRF Scanner",         "ssrf_scanner",  40),
            ("active_ssti",  "SSTI Scanner",         "ssti_scanner",  50),
            ("active_xxe",   "XXE Scanner",          "xxe_scanner",   60),
            ("active_cors",  "CORS Scanner",         "cors_scanner",  70),
            ("active_csrf",  "CSRF Scanner",         "csrf_scanner",  80),
        ]
        for sid, name, module, prio in core_active:
            wf.add_step(WorkflowStep(
                step_id     = sid,
                name        = name,
                description = f"فحص {name}",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = module,
                priority    = prio,
                depends_on  = ["baseline_responses"],
            ))

        # Phase 6: Confirmation
        wf.add_step(WorkflowStep(
            step_id     = "confirm_findings",
            name        = "Findings Confirmation",
            description = "إعادة التأكد من صحة كل النتائج",
            phase       = ScanPhase.CONFIRMATION,
            module_id   = "confirmation_engine",
            priority    = 10,
            depends_on  = [s.step_id for s in wf.steps if s.phase == ScanPhase.ACTIVE_TESTING],
        ))

        # Phase 7: Evidence
        wf.add_step(WorkflowStep(
            step_id     = "collect_evidence",
            name        = "Evidence Collector",
            description = "جمع كل الأدلة والـ PoC",
            phase       = ScanPhase.EVIDENCE,
            module_id   = "evidence_collector",
            priority    = 10,
            depends_on  = ["confirm_findings"],
        ))

        # Phase 8: Correlation
        wf.add_step(WorkflowStep(
            step_id     = "correlate_findings",
            name        = "Findings Correlator",
            description = "ربط النتائج واكتشاف Attack Chains",
            phase       = ScanPhase.CORRELATION,
            module_id   = "correlator",
            priority    = 10,
            depends_on  = ["collect_evidence"],
        ))

        # Phase 9: Reporting
        wf.add_step(WorkflowStep(
            step_id     = "generate_report",
            name        = "Report Generator",
            description = "توليد التقرير النهائي",
            phase       = ScanPhase.REPORTING,
            module_id   = "reporter",
            priority    = 10,
            depends_on  = ["correlate_findings"],
        ))

    def _add_dynamic_steps(
        self,
        wf: WorkflowDefinition,
        discovered: Dict[str, Any],
    ) -> None:
        """يضيف خطوات إضافية بناءً على ما اتكشف."""
        techs = {t.lower() for t in discovered.get("technologies", [])}
        features = {f.lower() for f in discovered.get("features", [])}

        # GraphQL
        if "graphql" in techs or "graphql" in features:
            wf.add_step(WorkflowStep(
                step_id     = "graphql_deep",
                name        = "GraphQL Deep Scanner",
                description = "فحص شامل لـ GraphQL API",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = "graphql_scanner",
                priority    = 15,
                depends_on  = ["baseline_responses"],
            ))

        # File Upload
        if "file_upload" in features:
            wf.add_step(WorkflowStep(
                step_id     = "upload_testing",
                name        = "File Upload Security",
                description = "فحص أمان رفع الملفات",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = "file_upload_scanner",
                priority    = 25,
                depends_on  = ["baseline_responses"],
            ))

        # Admin Panel
        if "admin_panel" in features:
            wf.add_step(WorkflowStep(
                step_id     = "admin_authz",
                name        = "Admin Authorization Testing",
                description = "فحص صلاحيات لوحة الإدارة",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = "authz_matrix_scanner",
                priority    = 35,
                depends_on  = ["baseline_responses"],
            ))

        # WebSocket
        if "websocket" in techs or "websocket" in features:
            wf.add_step(WorkflowStep(
                step_id     = "websocket_scan",
                name        = "WebSocket Scanner",
                description = "فحص أمان الـ WebSocket",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = "websocket_scanner",
                priority    = 45,
                depends_on  = ["baseline_responses"],
            ))

        # JWT
        if "jwt" in techs or "jwt" in features:
            wf.add_step(WorkflowStep(
                step_id     = "jwt_testing",
                name        = "JWT Security Testing",
                description = "فحص أمان الـ JWT Tokens",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = "jwt_scanner",
                priority    = 55,
                depends_on  = ["baseline_responses"],
            ))

        # OAuth
        if "oauth" in techs or "oauth" in features:
            wf.add_step(WorkflowStep(
                step_id     = "oauth_testing",
                name        = "OAuth Security Testing",
                description = "فحص أمان الـ OAuth Flow",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = "oauth_scanner",
                priority    = 56,
                depends_on  = ["baseline_responses"],
            ))

        # WordPress
        if "wordpress" in techs:
            wf.add_step(WorkflowStep(
                step_id     = "wp_enum",
                name        = "WordPress Enumeration",
                description = "فحص WordPress plugins/themes/users",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = "wp_scanner",
                priority    = 65,
                depends_on  = ["fingerprint_tech"],
            ))


# ══════════════════════════════════════════════════════════════════════════════
# WORKFLOW ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class WorkflowEngine:
    """
    المحرك الرئيسي للـ Workflow في WebShield.

    المسؤوليات:
    1. تشغيل الـ Workflow Steps بالترتيب الصحيح
    2. التكيف مع النتائج الجديدة أثناء التشغيل
    3. إدارة الـ Dependencies بين الـ Steps
    4. التعامل مع الأخطاء والـ Retries
    5. نشر Events عند كل تغيير في حالة الـ Workflow

    الاستخدام:
        engine = WorkflowEngine(bus, module_executor)
        wf = WorkflowBuilder("deep").build("https://target.com")
        await engine.run(wf)
    """

    def __init__(
        self,
        bus:              EventBus,
        module_executor:  Optional[Callable] = None,
        max_parallel:     int                = 5,
    ) -> None:
        self._bus       = bus
        self._executor  = module_executor
        self._max_par   = max_parallel
        self._log       = PlatformLogger.get("WorkflowEngine")
        self._active:   Dict[str, asyncio.Task] = {}
        self._paused    = False

        # استمع لـ Events اللي بتضيف Steps جديدة أثناء التشغيل
        bus.on("workflow.activate_modules", self._on_activate_modules, priority=EventPriority.HIGH)
        bus.on("workflow.add_step",         self._on_add_step)
        bus.on("workflow.pause",            self._on_pause)
        bus.on("workflow.resume",           self._on_resume)

    # ── Main Execution ────────────────────────────────────────────────────────

    async def run(self, wf: WorkflowDefinition) -> Dict[str, Any]:
        """
        يشغل الـ Workflow كامل.

        Returns:
            Dict يحتوي على ملخص النتائج
        """
        self._wf  = wf
        completed: Set[str] = set()
        failed:    Set[str] = set()

        self._log.info(
            f"Starting workflow '{wf.workflow_id}' — "
            f"{wf.total_steps} steps, profile={wf.profile}"
        )
        await self._bus.emit_scan_phase("workflow", "started", "WorkflowEngine")

        start = time.monotonic()

        # نمر على كل الـ Phases بالترتيب
        for phase in sorted(ScanPhase, key=lambda p: p.order):
            if self._paused:
                await self._wait_for_resume()

            phase_steps = wf.get_phase_steps(phase)
            if not phase_steps:
                continue

            self._log.info(f"Phase: {phase.name} — {len(phase_steps)} steps")
            await self._bus.emit_scan_phase(phase.name.lower(), "started")

            # تنفيذ Steps الـ Phase الحالية
            phase_ok = await self._run_phase_steps(
                phase_steps, completed, failed
            )

            await self._bus.emit_scan_phase(
                phase.name.lower(),
                "completed" if phase_ok else "failed",
            )

            # لو Phase الـ BASELINE فشل → ما فيش فائدة نكمل
            if not phase_ok and phase == ScanPhase.BASELINE:
                self._log.error("Baseline failed — aborting workflow")
                break

        elapsed = time.monotonic() - start
        result  = self._build_summary(wf, elapsed, completed, failed)

        await self._bus.emit("workflow.completed", result, source="WorkflowEngine")
        self._log.info(
            f"Workflow '{wf.workflow_id}' completed in {elapsed:.1f}s — "
            f"{len(completed)}/{wf.total_steps} steps succeeded"
        )
        return result

    async def _run_phase_steps(
        self,
        steps:     List[WorkflowStep],
        completed: Set[str],
        failed:    Set[str],
    ) -> bool:
        """
        يشغل كل Steps المرحلة الحالية بالتوازي (حسب الـ Dependencies).
        """
        remaining = list(steps)
        all_ok    = True

        while remaining:
            # ايه الـ Steps اللي Dependencies بتاعتها خلصت؟
            ready = [
                s for s in remaining
                if all(dep in completed for dep in s.depends_on)
                and s.status == PhaseStatus.PENDING
            ]

            if not ready:
                # لو مفيش Steps جاهزة وفيه Steps لسه → Deadlock
                blocked = [s.step_id for s in remaining if not s.is_done]
                if blocked:
                    self._log.warning(f"Deadlock detected — blocked steps: {blocked}")
                break

            # شغّل الـ Steps الجاهزة بالتوازي (بحد أقصى self._max_par)
            batch = ready[: self._max_par]
            tasks = [
                asyncio.create_task(self._run_step(step), name=step.step_id)
                for step in batch
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for step, res in zip(batch, results):
                remaining.remove(step)
                if isinstance(res, Exception) or step.status == PhaseStatus.FAILED:
                    failed.add(step.step_id)
                    if not step.optional:
                        all_ok = False
                else:
                    completed.add(step.step_id)

        return all_ok

    async def _run_step(self, step: WorkflowStep) -> None:
        """يشغل Step واحد مع timeout وretry."""
        step.status     = PhaseStatus.RUNNING
        step.start_time = time.monotonic()

        self._log.debug(f"Running step '{step.step_id}' ({step.module_id})")
        await self._bus.emit(
            "workflow.step.started",
            {"step_id": step.step_id, "module": step.module_id},
            source="WorkflowEngine",
        )

        last_error: Optional[Exception] = None

        for attempt in range(step.retry_count + 1):
            try:
                async with asyncio.timeout(step.timeout):
                    if self._executor:
                        result = await self._executor(step.module_id, step)
                        step.outputs = result or {}
                    # لو مفيش executor → simulate (لـ testing)
                    else:
                        await asyncio.sleep(0)

                step.status   = PhaseStatus.COMPLETED
                step.end_time = time.monotonic()

                await self._bus.emit(
                    "workflow.step.completed",
                    {
                        "step_id":  step.step_id,
                        "module":   step.module_id,
                        "duration": step.duration,
                        "outputs":  step.outputs,
                    },
                    source="WorkflowEngine",
                )
                return

            except asyncio.TimeoutError:
                last_error = TimeoutError(f"Step '{step.step_id}' timed out after {step.timeout}s")
                self._log.warning(str(last_error))

            except Exception as e:
                last_error = e
                if attempt < step.retry_count:
                    wait = 2 ** attempt  # Exponential backoff
                    self._log.warning(
                        f"Step '{step.step_id}' failed (attempt {attempt+1}), "
                        f"retrying in {wait}s: {e}"
                    )
                    await asyncio.sleep(wait)

        # كل الـ Attempts فشلت
        step.status   = PhaseStatus.FAILED
        step.end_time = time.monotonic()
        step.error    = str(last_error)

        await self._bus.emit(
            "workflow.step.failed",
            {
                "step_id": step.step_id,
                "module":  step.module_id,
                "error":   step.error,
            },
            source="WorkflowEngine",
        )

        if not step.optional:
            raise ScanError(f"Step '{step.step_id}' failed: {last_error}")

    # ── Dynamic Step Addition ─────────────────────────────────────────────────

    async def _on_activate_modules(self, event: Event) -> None:
        """
        يستجيب لـ Event تفعيل Modules جديدة أثناء الفحص.
        مثلاً لما الـ TechRouter يكتشف GraphQL.
        """
        if not hasattr(self, "_wf"):
            return

        modules = event.data.get("modules", [])
        trigger = event.data.get("trigger", "unknown")

        for module_id in modules:
            # تحقق لو الـ Module مش موجود بالفعل
            existing = [s.module_id for s in self._wf.steps]
            if module_id in existing:
                continue

            new_step = WorkflowStep(
                step_id     = f"dynamic_{module_id}_{str(uuid.uuid4())[:4]}",
                name        = f"Dynamic: {module_id}",
                description = f"تم إضافته تلقائياً بسبب اكتشاف '{trigger}'",
                phase       = ScanPhase.ACTIVE_TESTING,
                module_id   = module_id,
                priority    = 90,
                optional    = True,
                depends_on  = ["baseline_responses"],
            )
            self._wf.add_step(new_step)
            self._log.info(
                f"Dynamic step added: '{new_step.step_id}' "
                f"(triggered by '{trigger}')"
            )

    async def _on_add_step(self, event: Event) -> None:
        """يضيف Step جديد للـ Workflow أثناء التشغيل."""
        if not hasattr(self, "_wf"):
            return

        step_data = event.data.get("step", {})
        if not step_data:
            return

        try:
            phase_name = step_data.get("phase", "ACTIVE_TESTING")
            phase      = ScanPhase[phase_name]
            step = WorkflowStep(
                step_id     = step_data.get("step_id", str(uuid.uuid4())[:8]),
                name        = step_data.get("name", "Custom Step"),
                description = step_data.get("description", ""),
                phase       = phase,
                module_id   = step_data.get("module_id", ""),
                priority    = step_data.get("priority", 80),
                optional    = step_data.get("optional", True),
                depends_on  = step_data.get("depends_on", ["baseline_responses"]),
            )
            self._wf.add_step(step)
            self._log.info(f"Custom step added: '{step.step_id}'")
        except (KeyError, ValueError) as e:
            self._log.error(f"Invalid step data: {e}")

    # ── Pause / Resume ────────────────────────────────────────────────────────

    async def _on_pause(self, event: Event) -> None:
        self._paused = True
        self._log.info("Workflow paused")

    async def _on_resume(self, event: Event) -> None:
        self._paused = False
        self._log.info("Workflow resumed")

    async def _wait_for_resume(self) -> None:
        self._log.info("Workflow paused — waiting for resume...")
        while self._paused:
            await asyncio.sleep(0.5)

    # ── Summary ───────────────────────────────────────────────────────────────

    def _build_summary(
        self,
        wf:        WorkflowDefinition,
        elapsed:   float,
        completed: Set[str],
        failed:    Set[str],
    ) -> Dict[str, Any]:
        by_phase: Dict[str, Dict[str, int]] = {}
        for step in wf.steps:
            phase_name = step.phase.name
            if phase_name not in by_phase:
                by_phase[phase_name] = {"completed": 0, "failed": 0, "skipped": 0}
            if step.status == PhaseStatus.COMPLETED:
                by_phase[phase_name]["completed"] += 1
            elif step.status == PhaseStatus.FAILED:
                by_phase[phase_name]["failed"] += 1
            elif step.status == PhaseStatus.SKIPPED:
                by_phase[phase_name]["skipped"] += 1

        return {
            "workflow_id":  wf.workflow_id,
            "target":       wf.target_url,
            "profile":      wf.profile,
            "elapsed_s":    round(elapsed, 2),
            "total_steps":  wf.total_steps,
            "completed":    len(completed),
            "failed":       len(failed),
            "progress_pct": wf.progress_pct,
            "by_phase":     by_phase,
        }
