"""
WebShield Plugin Architecture
================================
نظام Plugins كامل يخلي كل وظيفة مستقلة ومتصلة بالـ Core.

كل Plugin:
    - يعلن Metadata خاصة بيه (اسم، نوع، متطلبات)
    - يتسجل في الـ PluginRegistry
    - يتحمل تلقائياً من الـ PluginLoader
    - يتشغل ويتوقف من الـ CoreManager

Types:
    SCANNER       → يبحث عن ثغرات
    FINGERPRINTER → يكتشف التقنيات المستخدمة
    REPORTER      → يولد التقارير
    DISCOVERY     → يكتشف الـ Endpoints
    EXPORTER      → يصدر النتائج
    MIDDLEWARE    → يعدل الـ Requests/Responses
    WORKFLOW      → يدير تسلسل المهام
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Plugin Architecture                                        ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type

from .logging_system import PlatformLogger
from .error_framework import PluginError


# ── Plugin Types ──────────────────────────────────────────────────────────────

class PluginType(Enum):
    SCANNER       = "scanner"
    FINGERPRINTER = "fingerprinter"
    REPORTER      = "reporter"
    DISCOVERY     = "discovery"
    EXPORTER      = "exporter"
    MIDDLEWARE    = "middleware"
    WORKFLOW      = "workflow"
    AUTH          = "auth"
    PAYLOAD       = "payload"


# ── Plugin Metadata ───────────────────────────────────────────────────────────

@dataclass
class PluginInfo:
    """
    معلومات كاملة عن Plugin.
    
    كل Plugin لازم يعرّف ده كـ class attribute:
    
        class MyScanner(ScannerPlugin):
            plugin_info = PluginInfo(
                plugin_id="xss_scanner",
                name="XSS Scanner",
                version="1.0.0",
                description="يكشف ثغرات XSS",
                plugin_type=PluginType.SCANNER,
                priority=50,
                required_capabilities=["http"],
                tags=["xss", "injection"],
            )
    """
    plugin_id: str
    name: str
    version: str
    description: str
    plugin_type: PluginType
    
    # Execution order (0 = أول، 100 = آخر)
    priority: int = 50
    
    # الـ Capabilities اللي الـ Plugin محتاجها عشان تشتغل
    required_capabilities: List[str] = field(default_factory=list)
    
    # أنواع الـ Input اللي بيستقبلها
    input_types: List[str] = field(default_factory=list)
    
    # أنواع الـ Output اللي بيرجعها
    output_types: List[str] = field(default_factory=list)
    
    # Events اللي بيستمع عليها
    subscribed_events: List[str] = field(default_factory=list)
    
    # Events اللي بيصدرها
    emitted_events: List[str] = field(default_factory=list)
    
    author: str = ""
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    
    def __str__(self) -> str:
        return f"{self.name} v{self.version} [{self.plugin_type.value}]"


# ── Base Plugin Classes ───────────────────────────────────────────────────────

class BasePlugin:
    """
    الـ Base Class لكل Plugin في WebShield.
    
    كل Plugin لازم:
    1. يعرف plugin_info
    2. يعمل override لـ execute()
    3. اختياري: initialize() و teardown()
    """

    plugin_info: PluginInfo  # لازم يتعرف في كل subclass

    def __init__(self) -> None:
        self._context: Any = None
        self._core: Any = None
        self._logger = PlatformLogger(
            getattr(self, "plugin_info", type(self)).name
            if hasattr(self, "plugin_info")
            else type(self).__name__
        )
        self.active: bool = False

    async def initialize(self, context: Any, core: Any) -> None:
        """يتشغل مرة واحدة عند بدء الفحص."""
        self._context = context
        self._core = core
        self._logger.debug(f"Plugin initialized: {self.plugin_info.plugin_id}")

    async def execute(self, **kwargs: Any) -> Any:
        """
        التنفيذ الفعلي للـ Plugin.
        كل subclass لازم يعمل override لده.
        """
        raise NotImplementedError(
            f"Plugin {self.plugin_info.plugin_id} must implement execute()"
        )

    async def teardown(self) -> None:
        """تنظيف الموارد - يتشغل عند إيقاف الـ Plugin."""
        pass

    async def emit(self, event: str, data: Dict[str, Any]) -> None:
        """نشر Event عبر الـ EventBus."""
        if self._core:
            await self._core.emit(event, data)

    def on(self, event: str, handler: Callable) -> None:
        """الاشتراك في Event."""
        if self._core:
            self._core.on(event, handler)

    @property
    def context(self) -> Any:
        return self._context


class ScannerPlugin(BasePlugin):
    """
    Base class لكل Scanner Plugins.
    
    كل Scanner لازم يعمل override لـ scan_url()
    """

    plugin_info = PluginInfo(
        plugin_id="base_scanner",
        name="Base Scanner",
        version="1.0.0",
        description="Base class for scanners",
        plugin_type=PluginType.SCANNER,
        required_capabilities=["http"],
    )

    async def scan_url(
        self,
        url: str,
        response: Any,
        forms: List[Any],
    ) -> List[Any]:
        """يفحص URL واحد ويرجع الثغرات اللي اتكشفت."""
        raise NotImplementedError

    async def execute(self, url: str, response: Any, forms: List[Any] = None, **kwargs: Any) -> List[Any]:
        """Wrapper يستدعي scan_url."""
        return await self.scan_url(url, response, forms or [])


class FingerprinterPlugin(BasePlugin):
    """Base class لكل Fingerprinter Plugins."""

    plugin_info = PluginInfo(
        plugin_id="base_fingerprinter",
        name="Base Fingerprinter",
        version="1.0.0",
        description="Base class for fingerprinters",
        plugin_type=PluginType.FINGERPRINTER,
        required_capabilities=["http"],
        emitted_events=["fingerprint.detected"],
    )

    async def fingerprint(self, url: str, response: Any) -> Dict[str, Any]:
        """يكتشف التقنيات المستخدمة في الـ URL ويرجع Dict."""
        raise NotImplementedError

    async def execute(self, url: str, response: Any, **kwargs: Any) -> Dict[str, Any]:
        result = await self.fingerprint(url, response)
        # نشر Event تلقائي عند اكتشاف أي تقنية
        for tech, info in result.items():
            await self.emit("fingerprint.detected", {
                "technology": tech,
                "info": info,
                "url": url,
            })
        return result


class ReporterPlugin(BasePlugin):
    """Base class لكل Reporter Plugins."""

    plugin_info = PluginInfo(
        plugin_id="base_reporter",
        name="Base Reporter",
        version="1.0.0",
        description="Base class for reporters",
        plugin_type=PluginType.REPORTER,
    )

    async def generate_report(self, context: Any, output_path: str) -> str:
        """يولد تقرير ويرجع الـ Path."""
        raise NotImplementedError

    async def execute(self, context: Any = None, output_path: str = "", **kwargs: Any) -> str:
        return await self.generate_report(context or self._context, output_path)


class DiscoveryPlugin(BasePlugin):
    """Base class لكل Discovery Plugins."""

    plugin_info = PluginInfo(
        plugin_id="base_discovery",
        name="Base Discovery",
        version="1.0.0",
        description="Base class for discovery modules",
        plugin_type=PluginType.DISCOVERY,
        emitted_events=["endpoint.discovered"],
    )

    async def discover(self, target_url: str) -> List[str]:
        """يكتشف Endpoints ويرجع قائمة URLs."""
        raise NotImplementedError

    async def execute(self, target_url: str = "", **kwargs: Any) -> List[str]:
        urls = await self.discover(target_url or (self._context.target_url if self._context else ""))
        for url in urls:
            await self.emit("endpoint.discovered", {"url": url, "source": self.plugin_info.plugin_id})
        return urls


# ── Plugin Registry ───────────────────────────────────────────────────────────

class PluginRegistry:
    """
    سجل مركزي لكل الـ Plugins في WebShield.
    
    الاستخدام:
        registry = PluginRegistry()
        registry.register(MyXSSScanner)
        registry.register(MyReporter)
        
        scanners = registry.get_by_type(PluginType.SCANNER)
        xss = registry.get("xss_scanner")
    """

    def __init__(self) -> None:
        self._classes: Dict[str, Type[BasePlugin]] = {}
        self._instances: Dict[str, BasePlugin] = {}
        self._logger = PlatformLogger("PluginRegistry")
        self._event_subscriptions: Dict[str, List[str]] = {}  # event → [plugin_ids]

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, plugin_class: Type[BasePlugin]) -> None:
        """يسجل Plugin Class في الـ Registry."""
        if not hasattr(plugin_class, "plugin_info"):
            raise PluginError(
                f"Plugin {plugin_class.__name__} missing plugin_info attribute"
            )
        
        info = plugin_class.plugin_info
        if not info.enabled:
            self._logger.debug(f"Plugin disabled, skipping: {info.plugin_id}")
            return
        
        if info.plugin_id in self._classes:
            self._logger.warning(f"Overriding existing plugin: {info.plugin_id}")
        
        self._classes[info.plugin_id] = plugin_class
        
        # تسجيل الـ Event subscriptions
        for event in info.subscribed_events:
            if event not in self._event_subscriptions:
                self._event_subscriptions[event] = []
            self._event_subscriptions[event].append(info.plugin_id)
        
        self._logger.debug(f"Registered: {info}")

    def unregister(self, plugin_id: str) -> None:
        self._classes.pop(plugin_id, None)
        self._instances.pop(plugin_id, None)

    def register_many(self, *plugin_classes: Type[BasePlugin]) -> None:
        for cls in plugin_classes:
            self.register(cls)

    # ── Instantiation ─────────────────────────────────────────────────────────

    def get_instance(self, plugin_id: str) -> Optional[BasePlugin]:
        """يرجع instance جاهز من الـ Plugin (Singleton per registry)."""
        if plugin_id not in self._instances:
            cls = self._classes.get(plugin_id)
            if cls is None:
                return None
            self._instances[plugin_id] = cls()
        return self._instances[plugin_id]

    def create_instance(self, plugin_id: str) -> Optional[BasePlugin]:
        """ينشئ instance جديد في كل مرة."""
        cls = self._classes.get(plugin_id)
        return cls() if cls else None

    def get_all_instances(self) -> List[BasePlugin]:
        """يرجع instances لكل الـ Plugins المسجلة."""
        return [self.get_instance(pid) for pid in self._classes if self.get_instance(pid)]

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_by_type(self, plugin_type: PluginType) -> List[Type[BasePlugin]]:
        """يرجع كل الـ Plugins من نوع معين."""
        return [
            cls for cls in self._classes.values()
            if cls.plugin_info.plugin_type == plugin_type
        ]

    def get_by_capability(self, capability: str) -> List[Type[BasePlugin]]:
        """يرجع الـ Plugins اللي بتحتاج Capability معين."""
        return [
            cls for cls in self._classes.values()
            if capability in cls.plugin_info.required_capabilities
        ]

    def get_by_tag(self, tag: str) -> List[Type[BasePlugin]]:
        return [
            cls for cls in self._classes.values()
            if tag in cls.plugin_info.tags
        ]

    def get_subscribers(self, event: str) -> List[str]:
        """يرجع IDs الـ Plugins اللي مشتركة في Event معين."""
        # Exact match + wildcard
        subs = list(self._event_subscriptions.get(event, []))
        event_prefix = event.split(".")[0]
        subs += self._event_subscriptions.get(f"{event_prefix}.*", [])
        return list(set(subs))

    def list_all(self) -> List[PluginInfo]:
        return [cls.plugin_info for cls in self._classes.values()]

    def __contains__(self, plugin_id: str) -> bool:
        return plugin_id in self._classes

    def __len__(self) -> int:
        return len(self._classes)


# ── Plugin Loader ─────────────────────────────────────────────────────────────

class PluginLoader:
    """
    يحمل الـ Plugins تلقائياً من الـ Directories.
    
    بيدور على كل .py file في الـ directories المحددة،
    بيجيب كل Classes اللي بترث من BasePlugin،
    وبيسجلها في الـ PluginRegistry.
    
    الاستخدام:
        loader = PluginLoader(registry)
        loader.load_directory("webshield/scanners")
        loader.load_directory("/custom/plugins")
        loader.load_builtin_plugins()
    """

    def __init__(self, registry: PluginRegistry) -> None:
        self._registry = registry
        self._logger = PlatformLogger("PluginLoader")
        self._loaded_modules: Set[str] = set()

    def load_directory(self, directory: str, recursive: bool = False) -> int:
        """
        يحمل كل Plugins من Directory.
        بيرجع عدد الـ Plugins اللي اتحملت.
        """
        path = Path(directory)
        if not path.exists():
            self._logger.warning(f"Plugin directory not found: {directory}")
            return 0
        
        count = 0
        pattern = "**/*.py" if recursive else "*.py"
        
        for py_file in path.glob(pattern):
            if py_file.name.startswith("_"):
                continue
            count += self._load_file(py_file)
        
        self._logger.info(f"Loaded {count} plugins from {directory}")
        return count

    def _load_file(self, path: Path) -> int:
        """يحمل Plugins من ملف واحد."""
        module_key = str(path.resolve())
        if module_key in self._loaded_modules:
            return 0
        
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if spec is None or spec.loader is None:
                return 0
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore
            
            count = 0
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and obj not in (ScannerPlugin, FingerprinterPlugin, ReporterPlugin, DiscoveryPlugin)
                    and hasattr(obj, "plugin_info")
                    and obj.plugin_info.plugin_id != "base_scanner"
                    and obj.plugin_info.plugin_id != "base_fingerprinter"
                    and obj.plugin_info.plugin_id != "base_reporter"
                    and obj.plugin_info.plugin_id != "base_discovery"
                ):
                    try:
                        self._registry.register(obj)
                        count += 1
                    except Exception as e:
                        self._logger.warning(f"Failed to register {name}: {e}")
            
            self._loaded_modules.add(module_key)
            return count
            
        except Exception as e:
            self._logger.error(f"Failed to load plugin file {path}: {e}")
            return 0

    def load_builtin_plugins(self, package_root: str = "webshield") -> int:
        """يحمل كل الـ Plugins الداخلية في WebShield."""
        count = 0
        builtin_dirs = [
            "scanners",
            "reporters",
            "recon",
        ]
        
        base = Path(package_root)
        for dir_name in builtin_dirs:
            dir_path = base / dir_name
            if dir_path.exists():
                count += self.load_directory(str(dir_path))
        
        return count

    def load_module(self, module_path: str) -> int:
        """يحمل Plugin من module path (e.g. 'myapp.plugins.custom_scanner')."""
        try:
            module = importlib.import_module(module_path)
            count = 0
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BasePlugin) and hasattr(obj, "plugin_info"):
                    try:
                        self._registry.register(obj)
                        count += 1
                    except Exception:
                        pass
            return count
        except ImportError as e:
            self._logger.error(f"Cannot import module {module_path}: {e}")
            return 0


# ── Plugin Adapter (للـ Scanners القديمة) ───────────────────────────────────

class LegacyScannerAdapter(ScannerPlugin):
    """
    يلف الـ Scanners القديمة (اللي بترث من BaseScanner) وبيحولها لـ Plugin.
    
    ده بيضمن التوافق مع الكود الموجود بدون إعادة كتابة.
    
    الاستخدام:
        from webshield.scanners.xss import XSSScanner
        
        # بدل إنك تغير XSSScanner:
        XSSPlugin = LegacyScannerAdapter.wrap(XSSScanner, plugin_id="xss_v2")
        registry.register(XSSPlugin)
    """

    @classmethod
    def wrap(
        cls,
        legacy_scanner_class: Any,
        plugin_id: Optional[str] = None,
        priority: int = 50,
        tags: Optional[List[str]] = None,
    ) -> Type["LegacyScannerAdapter"]:
        """يحول Legacy Scanner لـ Plugin Class."""
        
        scanner_name = legacy_scanner_class.__name__
        pid = plugin_id or scanner_name.lower().replace("scanner", "").strip("_") + "_scanner"
        
        info = PluginInfo(
            plugin_id=pid,
            name=scanner_name,
            version="legacy",
            description=f"Legacy adapter for {scanner_name}",
            plugin_type=PluginType.SCANNER,
            priority=priority,
            required_capabilities=["http"],
            tags=tags or [],
        )

        class WrappedScanner(LegacyScannerAdapter):
            plugin_info = info
            _legacy_class = legacy_scanner_class

            async def initialize(self, context: Any, core: Any) -> None:
                await super().initialize(context, core)
                # ننشئ Legacy Scanner باستخدام الـ HTTP client من الـ Context
                http_client = context.metadata.get("http_client")
                if http_client:
                    self._legacy_instance = self._legacy_class(http_client)
                else:
                    self._legacy_instance = None

            async def scan_url(self, url: str, response: Any, forms: List[Any]) -> List[Any]:
                if self._legacy_instance is None:
                    return []
                return await self._legacy_instance.scan_url(url, response, forms)

        WrappedScanner.__name__ = f"{scanner_name}Plugin"
        return WrappedScanner
