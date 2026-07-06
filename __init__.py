"""
WebShield — Advanced Web Application Vulnerability Scanner & Security Assessment Framework
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

__version__ = "4.0.0"

__author__ = "WebShield Security Research Team"
__description__ = "Professional-grade web application security platform"

# ── Platform Layer ─────────────────────────────────────────────
from .platform import (
    # Part 1: Core Architecture
    CoreManager, CoreContext, CoreState,
    # Part 2: Infrastructure
    ConfigFramework, ScanProfile, PlatformLogger, LogLevel,
    ErrorFramework, WebShieldError, RetryPolicy,
    CacheLayer, ResourceManager,
    # Part 3: Plugin Architecture
    PluginRegistry, PluginLoader,
    ScannerPlugin, FingerprinterPlugin, ReporterPlugin, DiscoveryPlugin,
    PluginInfo, PluginType, LegacyScannerAdapter,
    # Part 4: Event-Driven Architecture
    EventBus, Event, EventPriority, TechRouter,
    # Part 5: Workflow Orchestration Layer
    ScanPhase, PhaseStatus, WorkflowDefinition, WorkflowBuilder, WorkflowEngine,
    # Part 6: Capability System & Scheduler Engine
    Capability, CapabilityChecker, SchedulerEngine,
    # Part 7: Scan Pipeline
    ScanPipeline, PipelineContext, StageContract,
    # Part 8: State Management & Replay Framework
    StateManager, ScanState, ReplayFramework,
    # Part 9: Data Management Layer & Storage Architecture
    DataManagementLayer, StorageManager, StorageKind,
    # Part 10: Security Layer
    SecurityLayer, DataSensitivity, SecretsVault, PermissionManager,
)

# ── Legacy Layer (backward compatible, lazy-loaded) ───────────────────────────
# يتعمل lazy import عشان لو httpx مش متاح، الـ Platform Layer تشتغل بدون مشاكل.
def __getattr__(name: str):  # type: ignore[misc]
    _LEGACY_MAP = {
        "ScanEngine":   ("webshield.core.engine",            "ScanEngine"),
        "Crawler":      ("webshield.core.crawler",           "Crawler"),
        "HTTPClient":   ("webshield.core.http_client",       "HTTPClient"),
        "ScanTarget":   ("webshield.core.target",            "ScanTarget"),
        "ScanResult":   ("webshield.models.scan_result",     "ScanResult"),
        "Vulnerability":("webshield.models.vulnerability",   "Vulnerability"),
        "Severity":     ("webshield.models.vulnerability",   "Severity"),
        "VulnType":     ("webshield.models.vulnerability",   "VulnType"),
        "HTMLReporter": ("webshield.reporters.html_reporter","HTMLReporter"),
        "JSONReporter": ("webshield.reporters.json_reporter","JSONReporter"),
    }
    if name in _LEGACY_MAP:
        import importlib
        module_name, attr = _LEGACY_MAP[name]
        mod = importlib.import_module(module_name)
        return getattr(mod, attr)
    raise AttributeError(f"module 'webshield' has no attribute {name!r}")

__all__ = [
    # Platform - Core
    "CoreManager", "CoreContext", "CoreState",
    # Platform - Infrastructure
    "ConfigFramework", "ScanProfile", "PlatformLogger", "LogLevel",
    "ErrorFramework", "WebShieldError", "RetryPolicy",
    "CacheLayer", "ResourceManager",
    # Platform - Plugins
    "PluginRegistry", "PluginLoader",
    "ScannerPlugin", "FingerprinterPlugin", "ReporterPlugin", "DiscoveryPlugin",
    "PluginInfo", "PluginType", "LegacyScannerAdapter",
    # Platform - Events / Workflow / Capability
    "EventBus", "Event", "EventPriority", "TechRouter",
    "ScanPhase", "PhaseStatus", "WorkflowDefinition", "WorkflowBuilder", "WorkflowEngine",
    "Capability", "CapabilityChecker", "SchedulerEngine",
    # Platform - Scan Pipeline (Part 7)
    "ScanPipeline", "PipelineContext", "StageContract",
    # Platform - State & Replay (Part 8)
    "StateManager", "ScanState", "ReplayFramework",
    # Platform - Data & Storage (Part 9)
    "DataManagementLayer", "StorageManager", "StorageKind",
    # Platform - Security Layer (Part 10)
    "SecurityLayer", "DataSensitivity", "SecretsVault", "PermissionManager",
    # Legacy (backward compatible)
    "ScanEngine", "Crawler", "HTTPClient", "ScanTarget",
    "ScanResult", "Vulnerability", "Severity", "VulnType",
    "HTMLReporter", "JSONReporter",
]
