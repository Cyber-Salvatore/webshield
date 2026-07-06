"""
WebShield Core Platform Manager
================================
قلب الأداة الجديد - مسؤول عن إدارة كل حاجة بتحصل أثناء الـ Scan
بدون أي Logic خاص بالثغرات، فقط إدارة Plugins والـ Workflow والـ Resources.

Architecture:
    CoreManager
    ├── PluginRegistry      (تسجيل وإدارة الـ Plugins)
    ├── WorkflowOrchestrator (ترتيب مراحل الفحص)
    ├── ResourceManager     (إدارة الموارد)
    ├── EventBus            (التواصل بين الأجزاء)
    └── StateManager        (حفظ حالة الفحص)
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Type

from .config_framework import ConfigFramework
from .logging_system import PlatformLogger
from .error_framework import ErrorFramework, WebShieldError
from .dependency_manager import DependencyManager


class CoreState(Enum):
    """حالة الـ Core أثناء دورة حياته."""
    IDLE       = auto()
    STARTING   = auto()
    RUNNING    = auto()
    PAUSED     = auto()
    STOPPING   = auto()
    STOPPED    = auto()
    ERROR      = auto()


@dataclass
class CoreContext:
    """
    السياق العام للفحص - بيتشارك بين كل الـ Plugins.
    
    كل Plugin بيقرأ منه ويكتب فيه بدون استدعاء مباشر لـ Plugins تانية.
    """
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)
    
    # بيانات مكتشفة أثناء الفحص (بتتراكم من كل الـ Plugins)
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_technologies: Dict[str, Any] = field(default_factory=dict)
    discovered_parameters: Dict[str, List[str]] = field(default_factory=dict)
    active_sessions: Dict[str, Any] = field(default_factory=dict)
    
    # نتائج الفحص
    findings: List[Any] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Capabilities المتاحة في البيئة الحالية
    capabilities: Set[str] = field(default_factory=set)
    
    # Metadata إضافية (مفتوحة للـ Plugins)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_endpoint(self, url: str) -> None:
        if url not in self.discovered_endpoints:
            self.discovered_endpoints.append(url)

    def add_technology(self, name: str, info: Any) -> None:
        self.discovered_technologies[name] = info

    def add_finding(self, finding: Any) -> None:
        self.findings.append(finding)

    def has_capability(self, cap: str) -> bool:
        return cap in self.capabilities

    def set_meta(self, key: str, value: Any) -> None:
        self.metadata[key] = value

    def get_meta(self, key: str, default: Any = None) -> Any:
        return self.metadata.get(key, default)


class CoreManager:
    """
    قلب WebShield Platform.
    
    مسؤول عن:
    - تشغيل الـ Plugins وإيقافها بشكل منظم
    - إدارة الـ Workflow ومراحل الفحص
    - توزيع المهام وتجميع النتائج
    - إدارة الـ Resources والـ Configuration
    - التواصل بين أجزاء الأداة عبر EventBus
    
    مش بيعرف حاجة عن الثغرات أو طرق الاختبار -
    كل ده تفاصيل الـ Plugins اللي بتتعامل معاه.
    """

    def __init__(
        self,
        config: Optional[ConfigFramework] = None,
        logger: Optional[PlatformLogger] = None,
    ) -> None:
        self.config = config or ConfigFramework()
        self.logger = logger or PlatformLogger("CoreManager")
        self.errors = ErrorFramework(self.logger)
        
        self._state = CoreState.IDLE
        self._context: Optional[CoreContext] = None
        self._plugins: Dict[str, "PluginInstance"] = {}
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._tasks: List[asyncio.Task] = []
        self._lock = asyncio.Lock()
        self.dependencies = DependencyManager()

    # ── State Management ─────────────────────────────────────────────────────

    @property
    def state(self) -> CoreState:
        return self._state

    @property
    def context(self) -> Optional[CoreContext]:
        return self._context

    async def _set_state(self, new_state: CoreState) -> None:
        old_state = self._state
        self._state = new_state
        self.logger.debug(f"Core state: {old_state.name} → {new_state.name}")
        await self.emit("core.state_changed", {"from": old_state, "to": new_state})

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def start(self, target_url: str, initial_metadata: Optional[Dict[str, Any]] = None) -> CoreContext:
        """يبدأ جلسة فحص جديدة."""
        async with self._lock:
            if self._state not in (CoreState.IDLE, CoreState.STOPPED):
                raise WebShieldError(f"Cannot start: core is {self._state.name}")
            
            await self._set_state(CoreState.STARTING)
            
            # إنشاء السياق الجديد
            self._context = CoreContext(target_url=target_url)
            if initial_metadata:
                self._context.metadata.update(initial_metadata)
            
            # اكتشاف الـ Capabilities المتاحة
            await self._detect_capabilities()
            
            # تشغيل الـ Plugins المسجلة حسب الأولوية
            await self._start_plugins()
            
            await self._set_state(CoreState.RUNNING)
            self.logger.info(f"Core started | scan_id={self._context.scan_id} | target={target_url}")
            
            return self._context

    async def stop(self) -> None:
        """يوقف الفحص بشكل منظم."""
        async with self._lock:
            if self._state not in (CoreState.RUNNING, CoreState.PAUSED):
                return
            
            await self._set_state(CoreState.STOPPING)
            
            # إلغاء كل المهام الجارية
            for task in self._tasks:
                if not task.done():
                    task.cancel()
            
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()
            
            # إيقاف الـ Plugins بشكل معاكس لترتيب التشغيل
            await self._stop_plugins()
            
            await self._set_state(CoreState.STOPPED)
            self.logger.info("Core stopped cleanly")

    async def pause(self) -> None:
        if self._state == CoreState.RUNNING:
            await self._set_state(CoreState.PAUSED)
            await self.emit("core.paused", {})

    async def resume(self) -> None:
        if self._state == CoreState.PAUSED:
            await self._set_state(CoreState.RUNNING)
            await self.emit("core.resumed", {})

    # ── Plugin Management ────────────────────────────────────────────────────

    def register_plugin(self, plugin_instance: "PluginInstance") -> None:
        """يسجل Plugin في الـ Core."""
        pid = plugin_instance.metadata.plugin_id
        if pid in self._plugins:
            self.logger.warning(f"Plugin already registered: {pid}")
            return
        self._plugins[pid] = plugin_instance
        # تسجيل اعتماديات الـ Plugin (لو معلنة) في DependencyManager
        depends_on = getattr(plugin_instance.metadata, "depends_on", None) or []
        self.dependencies.register(pid, depends_on=list(depends_on))
        self.logger.debug(f"Plugin registered: {pid} (priority={plugin_instance.metadata.priority})")

    async def _start_plugins(self) -> None:
        """يشغل الـ Plugins مرتبة حسب الاعتماديات أولاً ثم الـ Priority."""
        try:
            self.dependencies.validate(raise_on_error=True)
            dep_order = self.dependencies.resolution_order()
        except Exception as e:
            # لو فيه مشكلة في الاعتماديات، نرجع لترتيب الـ Priority القديم
            # كـ fallback بدل ما نوقف الفحص بالكامل، لكن نسجل الخطأ بوضوح.
            self.errors.handle(e, context="dependency resolution")
            dep_order = sorted(self._plugins.keys(), key=lambda pid: self._plugins[pid].metadata.priority)

        # استقرار الترتيب: لو فيه أكتر من Plugin بدون اعتماديات بينهم،
        # نفضّل الأولوية المعلنة (priority) كـ tie-breaker.
        sorted_ids = sorted(
            dep_order,
            key=lambda pid: self._plugins[pid].metadata.priority if pid in self._plugins else 50,
        )

        for pid in sorted_ids:
            plugin = self._plugins.get(pid)
            if plugin is None:
                continue
            try:
                # تأكد إن الـ Plugin قادر يشتغل في البيئة الحالية
                if not self._check_plugin_capabilities(plugin):
                    self.logger.debug(
                        f"Plugin skipped (missing capabilities): {plugin.metadata.plugin_id}"
                    )
                    continue
                await plugin.initialize(self._context, self)
                plugin.active = True
                self.dependencies.mark_started(pid)
                self.logger.debug(f"Plugin started: {plugin.metadata.plugin_id}")
            except Exception as e:
                self.errors.handle(e, context=f"starting plugin {plugin.metadata.plugin_id}")

    async def _stop_plugins(self) -> None:
        """يوقف الـ Plugins بالترتيب المعاكس."""
        sorted_plugins = sorted(
            self._plugins.values(),
            key=lambda p: p.metadata.priority,
            reverse=True
        )
        for plugin in sorted_plugins:
            if plugin.active:
                try:
                    await plugin.teardown()
                    plugin.active = False
                except Exception as e:
                    self.errors.handle(e, context=f"stopping plugin {plugin.metadata.plugin_id}")

    def _check_plugin_capabilities(self, plugin: "PluginInstance") -> bool:
        """يتأكد إن كل الـ Capabilities المطلوبة متوفرة."""
        if not self._context:
            return False
        for cap in plugin.metadata.required_capabilities:
            if not self._context.has_capability(cap):
                return False
        return True

    async def _detect_capabilities(self) -> None:
        """يكتشف الـ Capabilities المتاحة في البيئة الحالية."""
        caps = set()
        
        # HTTP دايماً متاح
        caps.add("http")
        
        # Browser (Playwright)
        try:
            import playwright  # type: ignore
            caps.add("browser")
        except ImportError:
            pass
        
        # DNS
        try:
            import aiodns  # type: ignore
            caps.add("dns")
        except ImportError:
            pass
        
        # WebSocket
        try:
            import websockets  # type: ignore
            caps.add("websocket")
        except ImportError:
            pass
        
        if self._context:
            self._context.capabilities = caps
        
        self.logger.info(f"Detected capabilities: {sorted(caps)}")

    # ── Task Management ───────────────────────────────────────────────────────

    def submit_task(self, coro: Any, name: str = "") -> asyncio.Task:
        """يضيف Task جديد تحت إشراف الـ Core."""
        task = asyncio.create_task(coro, name=name or f"ws-task-{len(self._tasks)}")
        self._tasks.append(task)
        # تنظيف تلقائي لما يخلص
        task.add_done_callback(lambda t: self._tasks.remove(t) if t in self._tasks else None)
        return task

    # ── Event Bus ─────────────────────────────────────────────────────────────

    def on(self, event: str, handler: Callable) -> None:
        """يسجل Handler لـ Event معين."""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)

    def off(self, event: str, handler: Callable) -> None:
        """يشيل Handler من الـ Event."""
        if event in self._event_handlers:
            self._event_handlers[event].remove(handler)

    async def emit(self, event: str, data: Dict[str, Any]) -> None:
        """ينشر Event لكل الـ Handlers المسجلة."""
        handlers = self._event_handlers.get(event, [])
        # wildcard handlers
        handlers += self._event_handlers.get("*", [])
        
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event, data)
                else:
                    handler(event, data)
            except Exception as e:
                self.errors.handle(e, context=f"event handler for '{event}'")

    # ── Stats & Diagnostics ───────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """يرجع حالة الـ Core الحالية."""
        return {
            "state": self._state.name,
            "scan_id": self._context.scan_id if self._context else None,
            "active_plugins": [
                pid for pid, p in self._plugins.items() if p.active
            ],
            "active_tasks": len(self._tasks),
            "findings_count": len(self._context.findings) if self._context else 0,
            "endpoints_count": len(self._context.discovered_endpoints) if self._context else 0,
        }


@dataclass
class PluginMetadata:
    """
    Metadata الخاصة بكل Plugin.
    
    الـ Core بيستخدمها لإدارة الـ Plugin بدون ما يعرف تفاصيله الداخلية.
    """
    plugin_id: str
    name: str
    version: str
    description: str
    plugin_type: str                           # scanner / reporter / fingerprinter / etc.
    priority: int = 50                         # 0 = أول، 100 = آخر
    required_capabilities: List[str] = field(default_factory=list)
    input_types: List[str] = field(default_factory=list)
    output_types: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)   # أسماء مكونات لازم تشتغل قبله
    author: str = ""
    tags: List[str] = field(default_factory=list)


class PluginInstance:
    """
    Base class لكل Plugin في WebShield.
    
    كل Plugin لازم يورث منه ويعمل override لـ:
    - initialize() : يتشغل أول مرة
    - execute()    : التنفيذ الفعلي
    - teardown()   : التنظيف عند الإيقاف
    """

    metadata: PluginMetadata
    active: bool = False

    async def initialize(self, context: CoreContext, core: CoreManager) -> None:
        """يتشغل مرة واحدة عند بدء الفحص."""
        self._context = context
        self._core = core

    async def execute(self, **kwargs: Any) -> Any:
        """التنفيذ الفعلي للـ Plugin."""
        raise NotImplementedError

    async def teardown(self) -> None:
        """تنظيف الموارد عند الإيقاف."""
        pass

    def emit(self, event: str, data: Dict[str, Any]) -> None:
        """اختصار لنشر Events من داخل الـ Plugin."""
        if hasattr(self, "_core"):
            asyncio.create_task(self._core.emit(event, data))
