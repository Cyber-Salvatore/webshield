"""
WebShield Capability System & Scheduler Engine
=================================================

CAPABILITY SYSTEM:
==================
كل Plugin بيعلن احتياجاته قبل التشغيل، والـ Core يشغل بس
الـ Plugins اللي الـ Environment بيدعمها.

مثال:
    class HeadlessXSSScanner(ScannerPlugin):
        required_capabilities = [
            Capability.BROWSER,
            Capability.JAVASCRIPT,
        ]

    # لو مفيش Browser → الـ Scanner ميشتغلش

SCHEDULER ENGINE:
=================
Scheduler ذكي بيوزع المهام على الـ Workers حسب:
- أولوية الـ Task
- خطورة الـ Endpoint
- سرعة السيرفر
- عدد الاتصالات المفتوحة
- موارد الجهاز المتاحة

بيقدر يوقف مهام ويبدأ غيرها أثناء التشغيل.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Capability System & Scheduler Engine   ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import heapq
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any, Callable, Dict, List, Optional, Set, Tuple, Awaitable,
)

from .logging_system import PlatformLogger
from .error_framework import WebShieldError, ResourceError
from .event_bus import EventBus, Event, EventPriority


# ══════════════════════════════════════════════════════════════════════════════
# CAPABILITY SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

class Capability(str, Enum):
    """
    كل الـ Capabilities اللي ممكن Plugin يحتاجها.

    بينقسموا لفئات:
    - Network    : نوع الاتصال اللي محتاجه
    - Browser    : محتاج Browser فعلي
    - Auth       : محتاج صلاحيات/مصادقة
    - Protocol   : بروتوكولات خاصة
    - Out-of-Band: DNS Callbacks وأدوات خارجية
    - Runtime    : متطلبات بيئة التشغيل
    """
    # ── Network ───────────────────────────────────────────────────────────────
    HTTP            = "http"
    HTTP2           = "http2"
    HTTP3           = "http3"
    HTTPS           = "https"
    WEBSOCKET       = "websocket"
    PROXY           = "proxy"

    # ── Browser ───────────────────────────────────────────────────────────────
    BROWSER         = "browser"
    JAVASCRIPT      = "javascript"
    DOM_ACCESS      = "dom_access"

    # ── Authentication ────────────────────────────────────────────────────────
    AUTH_BASIC      = "auth_basic"
    AUTH_SESSION    = "auth_session"
    AUTH_TOKEN      = "auth_token"
    AUTH_OAUTH      = "auth_oauth"
    MULTI_SESSION   = "multi_session"    # أكتر من Session في نفس الوقت

    # ── Protocols ─────────────────────────────────────────────────────────────
    GRAPHQL         = "graphql"
    GRPC            = "grpc"
    SOAP            = "soap"
    DNS             = "dns"

    # ── Out-of-Band ───────────────────────────────────────────────────────────
    DNS_CALLBACK    = "dns_callback"     # لـ Blind XXE / SSRF
    HTTP_CALLBACK   = "http_callback"    # Interactsh / Burp Collaborator
    OOB_TESTING     = "oob_testing"

    # ── Runtime ───────────────────────────────────────────────────────────────
    HIGH_MEMORY     = "high_memory"      # أكتر من 512MB
    HIGH_CPU        = "high_cpu"
    DOCKER          = "docker"
    NETWORK_RAW     = "network_raw"      # Raw Packets (محتاج root)
    FILE_SYSTEM     = "file_system"      # قراءة/كتابة ملفات


@dataclass
class CapabilityInfo:
    """معلومات عن Capability متاحة في البيئة الحالية."""
    name:        Capability
    available:   bool
    version:     Optional[str] = None
    metadata:    Dict[str, Any] = field(default_factory=dict)
    checked_at:  float          = field(default_factory=time.monotonic)


class CapabilityChecker:
    """
    بيفحص إيه الـ Capabilities المتاحة في البيئة الحالية.

    بيشتغل مرة واحدة عند بدء WebShield وبيخزن النتائج.
    """

    def __init__(self) -> None:
        self._cache: Dict[Capability, CapabilityInfo] = {}
        self._log   = PlatformLogger.get("CapabilityChecker")

    async def check_all(self) -> Dict[Capability, CapabilityInfo]:
        """يفحص كل الـ Capabilities ويرجع النتائج."""
        checks = [
            self._check_http(),
            self._check_http2(),
            self._check_websocket(),
            self._check_browser(),
            self._check_dns(),
            self._check_oob(),
            self._check_system(),
        ]
        await asyncio.gather(*checks)
        self._log.info(
            f"Capability check done — "
            f"{sum(1 for c in self._cache.values() if c.available)}"
            f"/{len(self._cache)} available"
        )
        return dict(self._cache)

    def is_available(self, cap: Capability) -> bool:
        """سريع: هل الـ Capability دي متاحة؟"""
        info = self._cache.get(cap)
        return info.available if info else False

    def get_available(self) -> Set[Capability]:
        """يرجع مجموعة كل الـ Capabilities المتاحة."""
        return {cap for cap, info in self._cache.items() if info.available}

    def missing(self, required: List[Capability]) -> List[Capability]:
        """يرجع الـ Capabilities المطلوبة اللي مش متاحة."""
        return [cap for cap in required if not self.is_available(cap)]

    def can_run(self, required: List[Capability]) -> Tuple[bool, List[Capability]]:
        """
        يتحقق لو Plugin ممكن يشتغل.

        Returns:
            (can_run: bool, missing_caps: List[Capability])
        """
        missing = self.missing(required)
        return (len(missing) == 0), missing

    # ── Individual Checks ─────────────────────────────────────────────────────

    async def _check_http(self) -> None:
        """فحص HTTP/HTTPS."""
        self._cache[Capability.HTTP]   = CapabilityInfo(Capability.HTTP,  True)
        self._cache[Capability.HTTPS]  = CapabilityInfo(Capability.HTTPS, True)
        try:
            import httpx
            # HTTP/2 بيحتاج httpx[http2]
            try:
                async with httpx.AsyncClient(http2=True) as c:
                    pass
                self._cache[Capability.HTTP2] = CapabilityInfo(Capability.HTTP2, True)
            except Exception:
                self._cache[Capability.HTTP2] = CapabilityInfo(Capability.HTTP2, False)
        except ImportError:
            self._cache[Capability.HTTP2] = CapabilityInfo(Capability.HTTP2, False)

    async def _check_http2(self) -> None:
        pass  # بيتم في _check_http

    async def _check_websocket(self) -> None:
        try:
            import websockets  # noqa
            self._cache[Capability.WEBSOCKET] = CapabilityInfo(Capability.WEBSOCKET, True)
        except ImportError:
            self._cache[Capability.WEBSOCKET] = CapabilityInfo(Capability.WEBSOCKET, False)

    async def _check_browser(self) -> None:
        """فحص لو Playwright / Selenium متاح."""
        browser_ok = False
        version    = None
        try:
            import playwright  # noqa
            browser_ok = True
            version    = "playwright"
        except ImportError:
            try:
                import selenium  # noqa
                browser_ok = True
                version    = "selenium"
            except ImportError:
                pass

        self._cache[Capability.BROWSER]    = CapabilityInfo(Capability.BROWSER,    browser_ok, version)
        self._cache[Capability.JAVASCRIPT] = CapabilityInfo(Capability.JAVASCRIPT, browser_ok, version)
        self._cache[Capability.DOM_ACCESS] = CapabilityInfo(Capability.DOM_ACCESS, browser_ok, version)

    async def _check_dns(self) -> None:
        try:
            import dns.resolver  # noqa
            self._cache[Capability.DNS] = CapabilityInfo(Capability.DNS, True)
        except ImportError:
            self._cache[Capability.DNS] = CapabilityInfo(Capability.DNS, False)

    async def _check_oob(self) -> None:
        """OOB Testing — محتاج Interactsh أو مزود DNS Callback."""
        # بنفترض إنه مش متاح إلا لو اتحدد في الإعدادات
        self._cache[Capability.DNS_CALLBACK]  = CapabilityInfo(Capability.DNS_CALLBACK, False)
        self._cache[Capability.HTTP_CALLBACK] = CapabilityInfo(Capability.HTTP_CALLBACK, False)
        self._cache[Capability.OOB_TESTING]   = CapabilityInfo(Capability.OOB_TESTING,  False)

    async def _check_system(self) -> None:
        """فحص موارد النظام."""
        import sys
        import os

        # Docker
        docker_ok = os.path.exists("/.dockerenv")
        self._cache[Capability.DOCKER] = CapabilityInfo(Capability.DOCKER, docker_ok)

        # File System
        self._cache[Capability.FILE_SYSTEM] = CapabilityInfo(Capability.FILE_SYSTEM, True)

        # Raw Sockets (يحتاج root على Linux)
        raw_ok = False
        try:
            if sys.platform == "linux" and os.geteuid() == 0:
                raw_ok = True
        except AttributeError:
            pass
        self._cache[Capability.NETWORK_RAW] = CapabilityInfo(Capability.NETWORK_RAW, raw_ok)

    def enable(self, cap: Capability, version: Optional[str] = None, **meta: Any) -> None:
        """يفعّل Capability يدوياً (مثلاً لما المستخدم يحدد OOB provider)."""
        self._cache[cap] = CapabilityInfo(cap, True, version, meta)
        self._log.info(f"Capability '{cap.value}' manually enabled")

    def disable(self, cap: Capability) -> None:
        """يعطّل Capability يدوياً."""
        if cap in self._cache:
            self._cache[cap].available = False
        self._log.info(f"Capability '{cap.value}' manually disabled")

    def get_report(self) -> Dict[str, Any]:
        """تقرير شامل عن كل الـ Capabilities."""
        return {
            cap.value: {
                "available": info.available,
                "version":   info.version,
                "metadata":  info.metadata,
            }
            for cap, info in self._cache.items()
        }


# ══════════════════════════════════════════════════════════════════════════════
# SCHEDULER ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class TaskPriority(Enum):
    """أولوية الـ Task في الـ Scheduler."""
    CRITICAL = 0
    HIGH     = 25
    NORMAL   = 50
    LOW      = 75
    IDLE     = 100


class TaskStatus(Enum):
    QUEUED    = auto()
    RUNNING   = auto()
    COMPLETED = auto()
    FAILED    = auto()
    CANCELLED = auto()
    PAUSED    = auto()


@dataclass
class ScheduledTask:
    """
    مهمة واحدة في الـ Scheduler.
    """
    task_id:      str
    name:         str
    coro_factory: Callable[[], Awaitable[Any]]  # Factory بدل Coroutine مباشر
    priority:     TaskPriority = TaskPriority.NORMAL
    endpoint_url: Optional[str] = None
    severity:     int           = 0      # 0-10، بيأثر على الأولوية
    weight:       int           = 1      # عدد الـ Resources اللي بيستهلكها
    timeout:      int           = 120    # ثواني
    retry_count:  int           = 0
    tags:         Set[str]      = field(default_factory=set)

    # Runtime
    status:      TaskStatus     = TaskStatus.QUEUED
    created_at:  float          = field(default_factory=time.monotonic)
    started_at:  Optional[float] = None
    ended_at:    Optional[float] = None
    result:      Any            = None
    error:       Optional[str]  = None
    asyncio_task: Optional[asyncio.Task] = None

    # للـ Heap — أقل قيمة = أعلى أولوية
    @property
    def heap_key(self) -> Tuple[int, int, float]:
        # أولوية → خطورة معكوسة → وقت الإضافة
        return (self.priority.value, -self.severity, self.created_at)

    def __lt__(self, other: "ScheduledTask") -> bool:
        return self.heap_key < other.heap_key

    @property
    def duration(self) -> Optional[float]:
        if self.started_at and self.ended_at:
            return self.ended_at - self.started_at
        return None


class SchedulerEngine:
    """
    Scheduler ذكي يوزع المهام على الـ Workers.

    Features:
    1. Priority Queue (أعلى أولوية + أخطر Endpoint أول)
    2. Adaptive Concurrency (يزيد/يقلل Workers حسب سرعة السيرفر)
    3. Rate Limiting (لحماية الهدف من الضغط الزائد)
    4. Task Cancellation & Pausing
    5. Resource-aware scheduling (CPU / Memory / Connections)
    6. Real-time stats

    الاستخدام:
        scheduler = SchedulerEngine(bus, max_workers=10, rate_limit=5)
        await scheduler.start()

        task = scheduler.schedule(
            "xss_test",
            lambda: xss_scanner.scan(endpoint),
            priority=TaskPriority.HIGH,
            severity=8,
        )
        await scheduler.wait_all()
    """

    def __init__(
        self,
        bus:          EventBus,
        max_workers:  int   = 10,
        rate_limit:   float = 10.0,  # requests/sec
        adaptive:     bool  = True,
    ) -> None:
        self._bus         = bus
        self._max_workers = max_workers
        self._rate_limit  = rate_limit
        self._adaptive    = adaptive
        self._log         = PlatformLogger.get("SchedulerEngine")

        # Queue & Workers
        self._queue:   List[ScheduledTask] = []  # heap
        self._running: Dict[str, ScheduledTask]  = {}
        self._done:    List[ScheduledTask]        = []

        # Control
        self._running_flag   = False
        self._paused         = False
        self._semaphore:     Optional[asyncio.Semaphore] = None
        self._rate_semaphore: Optional[asyncio.Semaphore] = None
        self._queue_event    = asyncio.Event()

        # Rate limiting state
        self._request_times: List[float] = []

        # Adaptive concurrency
        self._response_times: List[float] = []
        self._current_workers = max_workers

        # Stats
        self._total_scheduled = 0
        self._total_completed = 0
        self._total_failed    = 0
        self._start_time      = 0.0

        # استمع لـ Events التحكم
        bus.on("scheduler.pause",        self._on_pause)
        bus.on("scheduler.resume",       self._on_resume)
        bus.on("scheduler.cancel_tag",   self._on_cancel_tag)
        bus.on("scheduler.set_rate",     self._on_set_rate)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """يشغل الـ Scheduler."""
        self._running_flag   = True
        self._start_time     = time.monotonic()
        self._semaphore      = asyncio.Semaphore(self._max_workers)
        self._log.info(
            f"Scheduler started — max_workers={self._max_workers}, "
            f"rate_limit={self._rate_limit}/s"
        )
        await self._bus.emit("scheduler.started", {}, source="SchedulerEngine")

        # شغّل الـ Dispatcher في الخلفية
        asyncio.create_task(self._dispatch_loop(), name="scheduler-dispatch")

        # لو adaptive → شغّل الـ Monitor
        if self._adaptive:
            asyncio.create_task(self._adaptive_monitor(), name="scheduler-monitor")

    async def stop(self, wait: bool = True) -> None:
        """يوقف الـ Scheduler."""
        self._running_flag = False

        if wait:
            await self.wait_all()

        # إلغاء المهام الشغالة
        for task in self._running.values():
            if task.asyncio_task and not task.asyncio_task.done():
                task.asyncio_task.cancel()

        self._log.info("Scheduler stopped")
        await self._bus.emit(
            "scheduler.stopped",
            self.get_stats(),
            source="SchedulerEngine",
        )

    # ── Task Scheduling ───────────────────────────────────────────────────────

    def schedule(
        self,
        name:         str,
        coro_factory: Callable[[], Awaitable[Any]],
        priority:     TaskPriority  = TaskPriority.NORMAL,
        endpoint_url: Optional[str] = None,
        severity:     int           = 0,
        weight:       int           = 1,
        timeout:      int           = 120,
        retry_count:  int           = 0,
        tags:         Optional[Set[str]] = None,
    ) -> ScheduledTask:
        """
        يضيف Task جديد للـ Queue.

        Returns:
            الـ Task المضاف (بتقدر تتابعه عن طريق status)
        """
        task = ScheduledTask(
            task_id      = str(uuid.uuid4())[:8],
            name         = name,
            coro_factory = coro_factory,
            priority     = priority,
            endpoint_url = endpoint_url,
            severity     = severity,
            weight       = weight,
            timeout      = timeout,
            retry_count  = retry_count,
            tags         = tags or set(),
        )
        heapq.heappush(self._queue, task)
        self._total_scheduled += 1
        self._queue_event.set()

        self._log.debug(
            f"Scheduled task '{name}' (id={task.task_id}, "
            f"priority={priority.name}, severity={severity})"
        )
        return task

    def schedule_batch(
        self,
        tasks: List[Dict[str, Any]],
    ) -> List[ScheduledTask]:
        """يضيف مجموعة Tasks دفعة واحدة."""
        return [self.schedule(**t) for t in tasks]

    def cancel(self, task_id: str) -> bool:
        """يلغي Task محدد."""
        # لو في الـ Queue
        for task in self._queue:
            if task.task_id == task_id:
                task.status = TaskStatus.CANCELLED
                self._queue.remove(task)
                heapq.heapify(self._queue)
                self._log.info(f"Task '{task_id}' cancelled from queue")
                return True

        # لو شغال دلوقتي
        running = self._running.get(task_id)
        if running and running.asyncio_task:
            running.asyncio_task.cancel()
            running.status = TaskStatus.CANCELLED
            self._log.info(f"Task '{task_id}' cancelled (was running)")
            return True

        return False

    def cancel_by_tag(self, tag: str) -> int:
        """يلغي كل الـ Tasks اللي ليها tag معين."""
        cancelled = 0

        # Queue
        to_remove = [t for t in self._queue if tag in t.tags]
        for task in to_remove:
            task.status = TaskStatus.CANCELLED
            self._queue.remove(task)
            cancelled += 1
        if to_remove:
            heapq.heapify(self._queue)

        # Running
        for task in list(self._running.values()):
            if tag in task.tags and task.asyncio_task:
                task.asyncio_task.cancel()
                task.status = TaskStatus.CANCELLED
                cancelled += 1

        self._log.info(f"Cancelled {cancelled} tasks with tag '{tag}'")
        return cancelled

    async def wait_all(self) -> None:
        """ينتظر لحد ما كل الـ Tasks تخلص."""
        while self._queue or self._running:
            await asyncio.sleep(0.1)

    # ── Dispatch Loop ─────────────────────────────────────────────────────────

    async def _dispatch_loop(self) -> None:
        """الحلقة الرئيسية للـ Dispatcher."""
        while self._running_flag:
            if self._paused or not self._queue:
                await asyncio.sleep(0.05)
                continue

            # خد أعلى أولوية من الـ Queue
            task = heapq.heappop(self._queue)

            if task.status == TaskStatus.CANCELLED:
                continue

            # انتظر لو الـ Semaphore ممتلي
            await self._semaphore.acquire()

            # Rate Limiting
            await self._enforce_rate_limit()

            # شغّل الـ Task
            asyncio.create_task(
                self._run_task(task),
                name=f"ws-task-{task.task_id}",
            )

    async def _run_task(self, task: ScheduledTask) -> None:
        """ينفذ Task واحد."""
        task.status     = TaskStatus.RUNNING
        task.started_at = time.monotonic()
        self._running[task.task_id] = task

        await self._bus.emit(
            "scheduler.task.started",
            {"task_id": task.task_id, "name": task.name},
            source="SchedulerEngine",
        )

        last_error: Optional[Exception] = None

        for attempt in range(task.retry_count + 1):
            try:
                async with asyncio.timeout(task.timeout):
                    t0     = time.monotonic()
                    result = await task.coro_factory()
                    elapsed = time.monotonic() - t0

                task.result  = result
                task.status  = TaskStatus.COMPLETED
                task.ended_at = time.monotonic()

                # سجّل وقت الاستجابة للـ Adaptive Monitor
                self._response_times.append(elapsed)
                if len(self._response_times) > 50:
                    self._response_times = self._response_times[-50:]

                self._total_completed += 1
                self._log.debug(
                    f"Task '{task.name}' completed in {elapsed:.2f}s"
                )
                await self._bus.emit(
                    "scheduler.task.completed",
                    {
                        "task_id":  task.task_id,
                        "name":     task.name,
                        "duration": task.duration,
                    },
                    source="SchedulerEngine",
                )
                break

            except asyncio.CancelledError:
                task.status   = TaskStatus.CANCELLED
                task.ended_at = time.monotonic()
                break

            except asyncio.TimeoutError:
                last_error = TimeoutError(
                    f"Task '{task.name}' timed out after {task.timeout}s"
                )
                if attempt < task.retry_count:
                    await asyncio.sleep(2 ** attempt)

            except Exception as e:
                last_error = e
                if attempt < task.retry_count:
                    self._log.warning(
                        f"Task '{task.name}' failed attempt {attempt+1}: {e}"
                    )
                    await asyncio.sleep(2 ** attempt)

        if task.status == TaskStatus.RUNNING:
            task.status   = TaskStatus.FAILED
            task.error    = str(last_error)
            task.ended_at = time.monotonic()
            self._total_failed += 1
            self._log.error(f"Task '{task.name}' failed: {last_error}")
            await self._bus.emit(
                "scheduler.task.failed",
                {"task_id": task.task_id, "name": task.name, "error": task.error},
                source="SchedulerEngine",
            )

        # تنظيف
        self._running.pop(task.task_id, None)
        self._done.append(task)
        self._semaphore.release()

    # ── Rate Limiting ─────────────────────────────────────────────────────────

    async def _enforce_rate_limit(self) -> None:
        """يطبّق Rate Limiting لحماية الهدف."""
        if self._rate_limit <= 0:
            return

        now     = time.monotonic()
        window  = 1.0  # ثانية واحدة

        # إزالة الـ Requests القديمة
        self._request_times = [
            t for t in self._request_times if now - t < window
        ]

        if len(self._request_times) >= self._rate_limit:
            # انتظر لحد ما تفضى مساحة
            oldest  = self._request_times[0]
            wait    = window - (now - oldest)
            if wait > 0:
                await asyncio.sleep(wait)

        self._request_times.append(time.monotonic())

    # ── Adaptive Concurrency ──────────────────────────────────────────────────

    async def _adaptive_monitor(self) -> None:
        """
        يراقب أوقات الاستجابة ويضبط الـ Concurrency تلقائياً.

        - لو السيرفر بطيء → يقلل Workers
        - لو السيرفر سريع → يزيد Workers
        """
        while self._running_flag:
            await asyncio.sleep(10)  # كل 10 ثواني

            if len(self._response_times) < 5:
                continue

            avg_ms = (sum(self._response_times) / len(self._response_times)) * 1000

            old_workers = self._current_workers

            if avg_ms > 3000:
                # السيرفر بطيء جداً → قلّل
                self._current_workers = max(1, self._current_workers - 2)
            elif avg_ms > 1000:
                # بطيء نسبياً → قلّل شوية
                self._current_workers = max(2, self._current_workers - 1)
            elif avg_ms < 200 and self._current_workers < self._max_workers:
                # سريع → زيد
                self._current_workers = min(
                    self._max_workers,
                    self._current_workers + 1,
                )

            if self._current_workers != old_workers:
                # أعد إنشاء الـ Semaphore
                self._semaphore = asyncio.Semaphore(self._current_workers)
                self._log.info(
                    f"Adaptive: workers {old_workers} → {self._current_workers} "
                    f"(avg_response={avg_ms:.0f}ms)"
                )
                await self._bus.emit(
                    "scheduler.workers_adjusted",
                    {
                        "old": old_workers,
                        "new": self._current_workers,
                        "avg_response_ms": round(avg_ms, 1),
                    },
                    source="SchedulerEngine",
                )

    # ── Event Handlers ────────────────────────────────────────────────────────

    async def _on_pause(self, event: Event) -> None:
        self._paused = True
        self._log.info("Scheduler paused")

    async def _on_resume(self, event: Event) -> None:
        self._paused = False
        self._log.info("Scheduler resumed")

    async def _on_cancel_tag(self, event: Event) -> None:
        tag = event.data.get("tag", "")
        if tag:
            self.cancel_by_tag(tag)

    async def _on_set_rate(self, event: Event) -> None:
        new_rate = event.data.get("rate", self._rate_limit)
        old_rate = self._rate_limit
        self._rate_limit = float(new_rate)
        self._log.info(f"Rate limit changed: {old_rate} → {self._rate_limit} req/s")

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """إحصائيات شاملة عن الـ Scheduler."""
        uptime = time.monotonic() - self._start_time if self._start_time else 0
        avg_response = (
            (sum(self._response_times) / len(self._response_times)) * 1000
            if self._response_times else 0
        )
        return {
            "uptime_s":           round(uptime, 2),
            "total_scheduled":    self._total_scheduled,
            "total_completed":    self._total_completed,
            "total_failed":       self._total_failed,
            "queue_size":         len(self._queue),
            "running_count":      len(self._running),
            "done_count":         len(self._done),
            "current_workers":    self._current_workers,
            "max_workers":        self._max_workers,
            "rate_limit":         self._rate_limit,
            "paused":             self._paused,
            "avg_response_ms":    round(avg_response, 1),
            "success_rate_pct":   round(
                (self._total_completed / max(self._total_scheduled, 1)) * 100, 1
            ),
        }

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    @property
    def is_idle(self) -> bool:
        return not self._queue and not self._running
