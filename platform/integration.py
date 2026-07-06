"""
WebShield Platform ↔ Legacy Integration Layer
=================================================
الجسر اللي بيوصل بين الـ Platform الجديد (Part 1-13) وبين الأداة الحقيقية
اللي بتشتغل دلوقتي (webshield/core/engine.py + webshield/scanners/*).

ده بيقفل الفجوة اللي ظهرت في تدقيق المرحلة الأولى:
    - LegacyScannerAdapter.wrap() كان معرّف بس مش مستخدم → دلوقتي بيتنادي
      فعلياً على كل الـ 30 Scanner الحقيقيين ويسجلهم في PluginRegistry.
    - main.py كان بيشتغل بمعزل تام عن الـ Platform → دلوقتي main.py بينادي
      bootstrap_platform()/teardown_platform() حوالين كل Scan، فالـ CoreManager
      بيدير الـ Lifecycle الحقيقي للفحص (capabilities, dependency validation,
      plugin start/stop, event emission) حتى لو الـ Engine القديم لسه هو اللي
      بينفذ الفحص نفسه.

ملحوظة: الهدف من المرحلة دي إثبات إن الـ Platform شغال وبيتكامل مع الكود
الحقيقي، مش إعادة كتابة الـ ScanEngine (956 سطر) بالكامل دفعة واحدة —
ده موضوع مرحلة تانية (نقل تنفيذ الفحص نفسه لـ WorkflowEngine/ScanPipeline).
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Platform ↔ Legacy Integration                              ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from .core_manager import CoreManager, CoreContext
from .config_framework import ConfigFramework
from .plugin_architecture import (
    PluginRegistry,
    LegacyScannerAdapter,
    PluginType,
)
from .logging_system import PlatformLogger

_logger = PlatformLogger.get("Integration")


# ── 1. Legacy scanner names → platform plugin ids ───────────────────────────
# نفس الـ 30 Scanner الحقيقيين الموجودين في webshield/scanners/*.
# (الأسماء دي class names حقيقية موجودة فعلاً، اتأكدنا منها مع الـ Audit
#  اللي صلّح أسماء كانت غلط في webshield/scanners/__init__.py)
_LEGACY_SCANNER_CLASS_NAMES = [
    "SQLiScanner", "NoSQLiScanner", "LDAPInjectionScanner", "XPathInjectionScanner",
    "XSSScanner", "StoredXSSScanner", "CmdiScanner", "SSTIScanner", "CRLFInjectionScanner",
    "CSRFScanner", "SSRFScanner", "XXEScanner", "HTTPSmugglingScanner",
    "PathTraversalScanner", "FileUploadScanner", "SensitiveFileScanner",
    "IDORScanner", "OpenRedirectScanner", "AuthBypassScanner", "AuthzMatrixScanner",
    "HeadersScanner", "CORSScanner", "SSLTLSScanner", "JWTScanner", "OAuthScanner",
    "GraphQLScanner", "WebSocketScanner", "RaceConditionScanner", "SecretsScanner",
    "OriginDiscovery",
]


def register_legacy_scanners(registry: Optional[PluginRegistry] = None) -> PluginRegistry:
    """
    يلف كل الـ 30 Scanner الحقيقيين بـ LegacyScannerAdapter.wrap()
    ويسجلهم في PluginRegistry.

    ده أول استخدام فعلي لـ LegacyScannerAdapter.wrap() في المشروع —
    قبل كده كان الكلاس معرّف ومُختبر بس مش مستخدم في أي مكان حقيقي.
    """
    # Import متأخر لتجنب circular import بين platform و scanners
    from webshield import scanners as legacy_scanners_module

    registry = registry or PluginRegistry()
    wrapped_count = 0

    for cls_name in _LEGACY_SCANNER_CLASS_NAMES:
        try:
            legacy_cls = getattr(legacy_scanners_module, cls_name)
        except AttributeError:
            _logger.warning(f"Legacy scanner class not found, skipping: {cls_name}")
            continue

        plugin_id = legacy_cls.__name__.lower().replace("scanner", "").strip("_") + "_scanner"
        wrapped_plugin_cls = LegacyScannerAdapter.wrap(
            legacy_cls,
            plugin_id=plugin_id,
            tags=["legacy", "scanner"],
        )
        registry.register(wrapped_plugin_cls)
        wrapped_count += 1

    _logger.info(
        f"Registered {wrapped_count}/{len(_LEGACY_SCANNER_CLASS_NAMES)} "
        f"legacy scanners as platform plugins"
    )
    return registry


@dataclass
class PlatformSession:
    """نتيجة bootstrap_platform — حزمة الـ Platform الجاهزة لفحص معين."""
    core: CoreManager
    config: ConfigFramework
    registry: PluginRegistry
    context: CoreContext


async def bootstrap_platform(
    target_url: str,
    http_client: Any,
    profile: str = "balanced",
) -> PlatformSession:
    """
    يبدأ جلسة Platform حقيقية حوالين فحص معين:
        1. يبني ConfigFramework ويطبق الـ Profile المطلوب
        2. يسجل كل الـ 30 Scanner كـ Plugins (عبر LegacyScannerAdapter)
        3. يبني CoreManager، يسجل الـ Plugins فيه (وبالتالي في DependencyManager)
        4. يبدأ الـ Core (capability detection + dependency validation +
           plugin lifecycle) فعلياً عبر core.start()

    لو فيه أي خطأ غير متوقع في الـ Platform، بيتسجل في الـ Log
    والفحص الفعلي (اللي بيشتغل بالـ Legacy Engine) يكمل عادي —
    الـ Platform هنا إضافة وليس Single Point of Failure.
    """
    config = ConfigFramework()
    if profile in (config.config.profile, "balanced"):
        pass
    try:
        config.apply_profile(profile)
    except Exception:
        _logger.warning(f"Unknown platform profile '{profile}', falling back to 'balanced'")
        config.apply_profile("balanced")

    registry = register_legacy_scanners()

    core = CoreManager(config=config)

    # نسجل كل الـ Scanner Plugins في الـ CoreManager — ده اللي بيخلي
    # DependencyManager وresolution order يشتغلوا فعلياً على scanners حقيقيين.
    for plugin_id in list(registry._classes.keys()):  # noqa: SLF001 — internal, same package
        instance = registry.get_instance(plugin_id)
        if instance is None:
            continue
        # CoreManager.register_plugin بيتوقع .metadata.plugin_id —
        # الـ BasePlugin الجديد بيستخدم .plugin_info، فبنعمل alias بسيط
        # عشان التوافق من غير ما نلمس الكلاسين التانيين.
        if not hasattr(instance, "metadata"):
            instance.metadata = instance.plugin_info  # type: ignore[attr-defined]
        core.register_plugin(instance)  # type: ignore[arg-type]

    context = await core.start(target_url, initial_metadata={"http_client": http_client})

    await core.emit("scan.started", {"target": target_url, "profile": profile})

    return PlatformSession(core=core, config=config, registry=registry, context=context)


async def teardown_platform(session: PlatformSession) -> None:
    """يقفل جلسة الـ Platform بشكل منظم بعد ما الفحص يخلص."""
    try:
        await session.core.emit("scan.completed", {
            "target": session.context.target_url,
            "scan_id": session.context.scan_id,
        })
        await session.core.stop()
    except Exception as e:
        _logger.error(f"Error during platform teardown: {e}")
