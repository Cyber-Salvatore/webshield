"""
WebShield Event-Driven Architecture
======================================
Event Bus كامل يخلي كل أجزاء المشروع تتواصل عن طريق Events
بدل الاستدعاءات المباشرة.

كيف بيشتغل:
    - أي Module بيكتشف معلومة → ينشر Event
    - الـ Modules اللي مهتمة بالـ Event → تشتغل تلقائياً
    - مفيش ارتباط مباشر بين الـ Modules

مثال:
    # Fingerprinter اكتشف Laravel
    await bus.emit("tech.detected", {"name": "Laravel", "version": "10.x"})

    # Laravel Scanner بيسمع تلقائياً
    @bus.on("tech.detected")
    async def handle_tech(event: Event):
        if event.data["name"] == "Laravel":
            await laravel_scanner.start()

Event Namespaces:
    scan.*          → أحداث الفحص العامة
    tech.*          → اكتشاف التقنيات
    endpoint.*      → اكتشاف الـ Endpoints
    finding.*       → نتائج الفحص
    auth.*          → أحداث المصادقة
    error.*         → الأخطاء
    workflow.*      → أحداث الـ Workflow
    plugin.*        → أحداث الـ Plugins
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Event-Driven Architecture               ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import re
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any, Awaitable, Callable, Deque, Dict, List,
    Optional, Pattern, Set, Tuple, Union,
)

from .logging_system import PlatformLogger
from .error_framework import WebShieldError


# ══════════════════════════════════════════════════════════════════════════════
# EVENT PRIORITY
# ══════════════════════════════════════════════════════════════════════════════

class EventPriority(Enum):
    """أولوية تنفيذ الـ Event Handlers."""
    CRITICAL = 0    # يتنفذ فوراً قبل أي حاجة
    HIGH     = 25   # مثل: اكتشاف ثغرة خطيرة
    NORMAL   = 50   # الاستخدام الطبيعي
    LOW      = 75   # مثل: تحديثات الـ UI
    IDLE     = 100  # يتنفذ لما مفيش حاجة تانية


# ══════════════════════════════════════════════════════════════════════════════
# EVENT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Event:
    """
    الوحدة الأساسية للتواصل بين أجزاء WebShield.

    كل Event بيحتوي على:
    - name     : اسم الـ Event (مثلاً "tech.detected")
    - data     : البيانات اللي بتتبعت مع الـ Event
    - source   : اسم الـ Module اللي نشره
    - event_id : معرف فريد للـ Event
    - timestamp: وقت النشر
    - scan_id  : معرف الـ Scan الحالي (اختياري)
    - parent_id: معرف الـ Event الأب (للـ Events المتسلسلة)
    """
    name:       str
    data:       Dict[str, Any]
    source:     str                    = "unknown"
    event_id:   str                    = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:  float                  = field(default_factory=time.monotonic)
    scan_id:    Optional[str]          = None
    parent_id:  Optional[str]          = None
    propagate:  bool                   = True   # لو False → ميوصلش للـ wildcard handlers

    def __repr__(self) -> str:
        return f"Event(name={self.name!r}, source={self.source!r}, id={self.event_id})"


# ══════════════════════════════════════════════════════════════════════════════
# HANDLER REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

# نوع الـ Handler: sync أو async
HandlerFn = Union[
    Callable[[Event], None],
    Callable[[Event], Awaitable[None]],
]


@dataclass
class HandlerRegistration:
    """
    تسجيل Handler واحد مع كل معلوماته.
    """
    handler_id: str
    pattern:    str                        # "tech.detected" أو "tech.*" أو "*"
    handler:    HandlerFn
    priority:   EventPriority              = EventPriority.NORMAL
    source:     str                        = "unknown"
    once:       bool                       = False  # يتنفذ مرة واحدة بس
    filter_fn:  Optional[Callable[[Event], bool]] = None  # فلتر إضافي

    # Stats
    call_count:   int   = 0
    total_time_ms: float = 0.0
    error_count:   int   = 0

    @property
    def avg_time_ms(self) -> float:
        if self.call_count == 0:
            return 0.0
        return self.total_time_ms / self.call_count

    def matches(self, event_name: str) -> bool:
        """يتحقق لو الـ Handler مهتم بالـ Event ده."""
        if self.pattern == "*":
            return True
        if self.pattern == event_name:
            return True
        # Wildcard مثلاً "tech.*" يطابق "tech.detected"
        if self.pattern.endswith(".*"):
            namespace = self.pattern[:-2]
            return event_name.startswith(namespace + ".")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# EVENT BUS
# ══════════════════════════════════════════════════════════════════════════════

class EventBus:
    """
    قلب الـ Event-Driven Architecture في WebShield.

    المسؤوليات:
    1. تسجيل وإلغاء تسجيل الـ Handlers
    2. نشر الـ Events لكل الـ Handlers المناسبة
    3. ترتيب الـ Handlers حسب الـ Priority
    4. تسجيل تاريخ كل الـ Events
    5. إدارة الـ Middleware (للـ Events اللي محتاجة معالجة قبل التوزيع)
    6. منع الـ Infinite Loops (لو Event بينشر نفسه)
    7. Dead Letter Queue للـ Events اللي مفيش Handler ليها

    الاستخدام:
        bus = EventBus()

        # تسجيل handler
        @bus.on("tech.detected")
        async def on_tech(event: Event):
            print(f"اكتشفنا: {event.data['name']}")

        # نشر event
        await bus.emit("tech.detected", {"name": "Laravel"}, source="fingerprinter")
    """

    # الـ Events اللي ممنوع تحصل infinite loop فيها
    _LOOP_SAFE_EVENTS: Set[str] = {"error.handler", "bus.stats"}

    def __init__(
        self,
        max_history:    int = 1000,
        max_queue_size: int = 500,
        enable_dlq:     bool = True,
    ) -> None:
        self._handlers:    Dict[str, List[HandlerRegistration]] = defaultdict(list)
        self._middleware:  List[Callable[[Event], Optional[Event]]] = []
        self._history:     Deque[Event] = deque(maxlen=max_history)
        self._dlq:         Deque[Tuple[Event, str]] = deque(maxlen=200)  # Dead Letter Queue
        self._enable_dlq   = enable_dlq
        self._max_queue    = max_queue_size
        self._emitting:    Set[str] = set()  # للـ loop detection
        self._scan_id:     Optional[str] = None
        self._log         = PlatformLogger.get("EventBus")

        # Stats
        self._total_emitted:   int   = 0
        self._total_handled:   int   = 0
        self._total_errors:    int   = 0
        self._start_time:      float = time.monotonic()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def set_scan_id(self, scan_id: str) -> None:
        """يربط الـ Bus بـ Scan معين."""
        self._scan_id = scan_id

    # ── Handler Registration ──────────────────────────────────────────────────

    def on(
        self,
        pattern:  str,
        handler:  Optional[HandlerFn]  = None,
        priority: EventPriority        = EventPriority.NORMAL,
        source:   str                  = "unknown",
        once:     bool                 = False,
        filter_fn: Optional[Callable[[Event], bool]] = None,
    ) -> Callable:
        """
        يسجل Handler لـ Event أو نمط Events.

        الاستخدام كـ decorator:
            @bus.on("tech.detected")
            async def handle(event: Event): ...

        الاستخدام المباشر:
            bus.on("tech.*", my_handler, priority=EventPriority.HIGH)
        """
        def decorator(fn: HandlerFn) -> HandlerFn:
            reg = HandlerRegistration(
                handler_id = str(uuid.uuid4())[:8],
                pattern    = pattern,
                handler    = fn,
                priority   = priority,
                source     = source or getattr(fn, "__module__", "unknown"),
                once       = once,
                filter_fn  = filter_fn,
            )
            # أضف للقاموس وارتب حسب الـ Priority
            self._handlers[pattern].append(reg)
            self._handlers[pattern].sort(key=lambda r: r.priority.value)
            self._log.debug(f"Registered handler for '{pattern}' (id={reg.handler_id})")
            return fn

        if handler is not None:
            # استخدام مباشر (مش decorator)
            decorator(handler)
            return handler

        return decorator

    def once(
        self,
        pattern:  str,
        handler:  Optional[HandlerFn] = None,
        priority: EventPriority       = EventPriority.NORMAL,
    ) -> Callable:
        """يسجل Handler بيتنفذ مرة واحدة بس."""
        return self.on(pattern, handler, priority=priority, once=True)

    def off(self, pattern: str, handler: HandlerFn) -> bool:
        """يلغي تسجيل Handler محدد."""
        regs = self._handlers.get(pattern, [])
        before = len(regs)
        self._handlers[pattern] = [r for r in regs if r.handler is not handler]
        removed = before - len(self._handlers[pattern])
        if removed:
            self._log.debug(f"Removed {removed} handler(s) for '{pattern}'")
        return removed > 0

    def off_all(self, pattern: str) -> int:
        """يشيل كل الـ Handlers لـ Pattern معين."""
        count = len(self._handlers.pop(pattern, []))
        self._log.debug(f"Removed all handlers for '{pattern}' ({count} removed)")
        return count

    def use(self, middleware: Callable[[Event], Optional[Event]]) -> None:
        """
        يضيف Middleware بيشتغل على كل Event قبل توزيعه.

        الـ Middleware ممكن:
        - يعدل الـ Event (مثلاً يضيف بيانات إضافية)
        - يرجع None → الـ Event يتحجب (مش بيوصل لأي Handler)
        """
        self._middleware.append(middleware)

    # ── Event Emission ────────────────────────────────────────────────────────

    async def emit(
        self,
        name:      str,
        data:      Optional[Dict[str, Any]] = None,
        source:    str                       = "unknown",
        parent_id: Optional[str]             = None,
        priority:  EventPriority             = EventPriority.NORMAL,
    ) -> Event:
        """
        ينشر Event لكل الـ Handlers المسجلة.

        Returns:
            الـ Event اللي اتنشر (مع أي تعديلات من الـ Middleware)
        """
        event = Event(
            name      = name,
            data      = data or {},
            source    = source,
            scan_id   = self._scan_id,
            parent_id = parent_id,
        )
        return await self._dispatch(event)

    async def emit_event(self, event: Event) -> Event:
        """ينشر Event object جاهز (للـ re-emit أو الـ chaining)."""
        return await self._dispatch(event)

    def emit_sync(
        self,
        name:   str,
        data:   Optional[Dict[str, Any]] = None,
        source: str                       = "unknown",
    ) -> None:
        """
        نشر Event من كود Sync.
        بيستخدم asyncio.create_task لو في event loop، وإلا بيستخدم run.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.emit(name, data, source))
        except RuntimeError:
            asyncio.run(self.emit(name, data, source))

    # ── Internal Dispatch ─────────────────────────────────────────────────────

    async def _dispatch(self, event: Event) -> Event:
        """المحرك الداخلي لتوزيع الـ Events."""
        # Loop detection
        if event.name in self._emitting and event.name not in self._LOOP_SAFE_EVENTS:
            self._log.warning(f"Loop detected for event '{event.name}' — skipped")
            return event

        self._emitting.add(event.name)
        self._total_emitted += 1
        self._history.append(event)

        try:
            # تشغيل الـ Middleware
            processed = await self._run_middleware(event)
            if processed is None:
                # الـ Middleware حجب الـ Event
                self._log.debug(f"Event '{event.name}' blocked by middleware")
                return event

            event = processed

            # جمع كل الـ Handlers المناسبة مرتبة حسب الـ Priority
            matching = self._get_matching_handlers(event.name)

            if not matching:
                if self._enable_dlq:
                    self._dlq.append((event, "no_handlers"))
                self._log.debug(f"No handlers for event '{event.name}'")
                return event

            # تنفيذ الـ Handlers
            for reg in matching:
                if reg.filter_fn and not reg.filter_fn(event):
                    continue

                await self._invoke_handler(reg, event)

                # لو once → اشيله بعد التنفيذ
                if reg.once:
                    self._handlers[reg.pattern] = [
                        r for r in self._handlers[reg.pattern]
                        if r.handler_id != reg.handler_id
                    ]

        finally:
            self._emitting.discard(event.name)

        return event

    async def _run_middleware(self, event: Event) -> Optional[Event]:
        """يشغل كل الـ Middleware على الـ Event."""
        current = event
        for mw in self._middleware:
            try:
                if asyncio.iscoroutinefunction(mw):
                    result = await mw(current)
                else:
                    result = mw(current)
                if result is None:
                    return None   # حجب
                current = result
            except Exception as e:
                self._log.error(f"Middleware error for '{event.name}': {e}")
        return current

    def _get_matching_handlers(self, event_name: str) -> List[HandlerRegistration]:
        """يجيب كل الـ Handlers المناسبة للـ Event مرتبة حسب Priority."""
        result: List[HandlerRegistration] = []
        seen: Set[str] = set()

        for pattern, regs in self._handlers.items():
            for reg in regs:
                if reg.handler_id not in seen and reg.matches(event_name):
                    result.append(reg)
                    seen.add(reg.handler_id)

        return sorted(result, key=lambda r: r.priority.value)

    async def _invoke_handler(self, reg: HandlerRegistration, event: Event) -> None:
        """يشغل Handler واحد ويسجل الـ Stats."""
        t0 = time.monotonic()
        try:
            if asyncio.iscoroutinefunction(reg.handler):
                await reg.handler(event)
            else:
                reg.handler(event)

            elapsed = (time.monotonic() - t0) * 1000
            reg.call_count    += 1
            reg.total_time_ms += elapsed
            self._total_handled += 1

        except Exception as e:
            reg.error_count   += 1
            self._total_errors += 1
            self._log.error(
                f"Handler error for '{event.name}' "
                f"(handler={reg.handler_id}, source={reg.source}): {e}"
            )
            # نشر error event (بدون loop)
            if event.name != "error.handler":
                await self.emit(
                    "error.handler",
                    {
                        "original_event": event.name,
                        "handler_id":     reg.handler_id,
                        "error":          str(e),
                    },
                    source="EventBus",
                )

    # ── WebShield Built-in Events ─────────────────────────────────────────────

    async def emit_tech_detected(
        self,
        name:    str,
        version: Optional[str] = None,
        source:  str           = "fingerprinter",
        **extra: Any,
    ) -> None:
        """اختصار لـ Event اكتشاف تقنية."""
        await self.emit(
            "tech.detected",
            {"name": name, "version": version, **extra},
            source=source,
        )

    async def emit_endpoint_found(
        self,
        url:    str,
        method: str = "GET",
        source: str = "discovery",
        **extra: Any,
    ) -> None:
        """اختصار لـ Event اكتشاف Endpoint."""
        await self.emit(
            "endpoint.found",
            {"url": url, "method": method, **extra},
            source=source,
        )

    async def emit_finding(
        self,
        vuln_type: str,
        severity:  str,
        url:       str,
        source:    str = "scanner",
        **extra:   Any,
    ) -> None:
        """اختصار لـ Event اكتشاف ثغرة."""
        await self.emit(
            "finding.new",
            {"vuln_type": vuln_type, "severity": severity, "url": url, **extra},
            source=source,
        )

    async def emit_scan_phase(
        self,
        phase:  str,
        status: str = "started",
        source: str = "workflow",
        **extra: Any,
    ) -> None:
        """اختصار لـ Event تغيير مرحلة الفحص."""
        await self.emit(
            f"scan.phase.{status}",
            {"phase": phase, **extra},
            source=source,
        )

    # ── History & DLQ ─────────────────────────────────────────────────────────

    def get_history(
        self,
        name_filter: Optional[str] = None,
        limit:       int            = 100,
    ) -> List[Event]:
        """يرجع تاريخ الـ Events الأخيرة."""
        events = list(self._history)
        if name_filter:
            events = [e for e in events if e.name.startswith(name_filter)]
        return events[-limit:]

    def get_dlq(self) -> List[Tuple[Event, str]]:
        """يرجع الـ Events اللي مفيش Handler ليها."""
        return list(self._dlq)

    def clear_history(self) -> None:
        """يمسح تاريخ الـ Events."""
        self._history.clear()
        self._dlq.clear()

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """إحصائيات شاملة عن الـ Event Bus."""
        uptime = time.monotonic() - self._start_time
        handler_stats = []
        for pattern, regs in self._handlers.items():
            for reg in regs:
                handler_stats.append({
                    "id":          reg.handler_id,
                    "pattern":     reg.pattern,
                    "source":      reg.source,
                    "calls":       reg.call_count,
                    "avg_ms":      round(reg.avg_time_ms, 2),
                    "errors":      reg.error_count,
                    "priority":    reg.priority.name,
                })

        return {
            "uptime_s":          round(uptime, 2),
            "total_emitted":     self._total_emitted,
            "total_handled":     self._total_handled,
            "total_errors":      self._total_errors,
            "registered_patterns": list(self._handlers.keys()),
            "handler_count":     sum(len(v) for v in self._handlers.values()),
            "history_size":      len(self._history),
            "dlq_size":          len(self._dlq),
            "middleware_count":  len(self._middleware),
            "handlers":          handler_stats,
        }


# ══════════════════════════════════════════════════════════════════════════════
# SMART TECH ROUTER
# ══════════════════════════════════════════════════════════════════════════════

class TechRouter:
    """
    يستمع لـ Events اكتشاف التقنيات وينشط الـ Modules المناسبة تلقائياً.

    مثال:
        router = TechRouter(bus)
        router.register("Laravel",    ["laravel_scanner", "php_scanner"])
        router.register("GraphQL",    ["graphql_scanner"])
        router.register("WordPress",  ["wp_scanner", "plugin_enum"])
        router.register("LoginForm",  ["auth_framework"])

    لما الـ Fingerprinter ينشر "tech.detected" مع name="Laravel"،
    الـ TechRouter ينشط Laravel و PHP Scanners تلقائياً.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus      = bus
        self._routes:  Dict[str, List[str]] = {}
        self._log      = PlatformLogger.get("TechRouter")

        # اشترك في اكتشاف التقنيات
        bus.on("tech.detected", self._handle_tech_detected, priority=EventPriority.HIGH)

    def register(self, tech_name: str, module_ids: List[str]) -> None:
        """يربط تقنية معينة بقائمة Modules."""
        self._routes[tech_name.lower()] = module_ids
        self._log.debug(f"Registered route: {tech_name} → {module_ids}")

    def register_many(self, routes: Dict[str, List[str]]) -> None:
        """يسجل عدة Routes دفعة واحدة."""
        for tech, modules in routes.items():
            self.register(tech, modules)

    async def _handle_tech_detected(self, event: Event) -> None:
        tech_name = event.data.get("name", "").lower()
        modules   = self._routes.get(tech_name, [])

        if not modules:
            return

        self._log.info(f"Tech '{tech_name}' detected → activating: {modules}")

        await self._bus.emit(
            "workflow.activate_modules",
            {
                "trigger":    tech_name,
                "modules":    modules,
                "reason":     f"tech.detected:{tech_name}",
                "context":    event.data,
            },
            source="TechRouter",
            parent_id=event.event_id,
        )

    def get_routes(self) -> Dict[str, List[str]]:
        return dict(self._routes)


# ══════════════════════════════════════════════════════════════════════════════
# DEFAULT WEBSHIELD ROUTES
# ══════════════════════════════════════════════════════════════════════════════

WEBSHIELD_DEFAULT_ROUTES: Dict[str, List[str]] = {
    # Frameworks
    "laravel":      ["laravel_scanner", "php_scanner", "debug_mode_check"],
    "django":       ["django_scanner", "python_scanner", "debug_mode_check"],
    "rails":        ["rails_scanner", "ruby_scanner"],
    "spring":       ["spring_scanner", "java_scanner"],
    "express":      ["nodejs_scanner", "js_scanner"],
    "nextjs":       ["nextjs_scanner", "react_scanner", "js_scanner"],
    "wordpress":    ["wp_scanner", "plugin_enum", "cms_scanner"],
    "drupal":       ["drupal_scanner", "cms_scanner"],
    "joomla":       ["joomla_scanner", "cms_scanner"],

    # APIs
    "graphql":      ["graphql_scanner", "introspection_check"],
    "rest_api":     ["api_fuzzer", "rate_limit_check"],
    "soap":         ["soap_scanner", "xxe_scanner"],
    "grpc":         ["grpc_scanner"],

    # Auth & Forms
    "login_form":   ["auth_framework", "brute_force_check", "csrf_scanner"],
    "oauth":        ["oauth_scanner", "token_scanner"],
    "jwt":          ["jwt_scanner"],
    "saml":         ["saml_scanner", "xxe_scanner"],

    # Infrastructure
    "aws_s3":       ["s3_scanner", "cloud_scanner"],
    "cloudflare":   ["waf_detection", "stealth_mode"],
    "nginx":        ["nginx_scanner", "misconfig_check"],
    "apache":       ["apache_scanner", "misconfig_check"],

    # Features
    "file_upload":  ["upload_scanner", "file_type_bypass"],
    "websocket":    ["websocket_scanner"],
    "admin_panel":  ["authz_scanner", "brute_force_check"],
}


def create_default_event_bus(scan_id: Optional[str] = None) -> Tuple[EventBus, TechRouter]:
    """
    ينشئ EventBus مع TechRouter جاهز للاستخدام مع WebShield.

    Returns:
        (bus, router) جاهزين للاستخدام
    """
    bus    = EventBus()
    router = TechRouter(bus)
    router.register_many(WEBSHIELD_DEFAULT_ROUTES)

    if scan_id:
        bus.set_scan_id(scan_id)

    return bus, router
