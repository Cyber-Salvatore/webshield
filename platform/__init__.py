"""
WebShield Platform Layer
=========================
الطبقة الأساسية للـ WebShield Platform — المرحلة الأولى كاملة (10 أجزاء):

    الجزء 1: Core Architecture     → CoreManager, CoreContext, CoreState
    الجزء 2: Infrastructure        → ConfigFramework, PlatformLogger, ErrorFramework,
                                     CacheLayer, ResourceManager
    الجزء 3: Plugin Architecture   → PluginRegistry, PluginLoader, BasePlugin,
                                     ScannerPlugin, FingerprinterPlugin, ...
    الجزء 4: Event-Driven Arch.    → EventBus, Event, TechRouter
    الجزء 5: Workflow Orchestration → WorkflowEngine, WorkflowBuilder, ScanPhase
    الجزء 6: Capability + Scheduler → CapabilityChecker, SchedulerEngine
    الجزء 7: Scan Pipeline          → ScanPipeline, PipelineContext, StageContract
    الجزء 8: State & Replay         → StateManager, ScanState, ReplayFramework
    الجزء 9: Data & Storage         → DataManagementLayer, StorageManager
    الجزء 10: Security Layer        → SecurityLayer, SecretsVault, PermissionManager

الاستخدام:
    from webshield.platform import (
        CoreManager, CoreContext,
        ConfigFramework, ScanProfile,
        PlatformLogger,
        ErrorFramework,
        CacheLayer, ResourceManager,
        PluginRegistry, PluginLoader,
        ScannerPlugin, PluginInfo, PluginType,
        EventBus, WorkflowEngine, SchedulerEngine,
        ScanPipeline, PipelineContext,
        StateManager, ReplayFramework,
        DataManagementLayer, StorageManager,
        SecurityLayer,
    )
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield Platform                                ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# ── Part 2: Infrastructure ────────────────────────────────────────────────────
from .config_framework import (
    ConfigFramework,
    WebShieldConfig,
    ScanProfile,
)

from .logging_system import (
    PlatformLogger,
    LogLevel,
    LogEntry,
    SecretMasker,
)

from .error_framework import (
    ErrorFramework,
    WebShieldError,
    ConfigError,
    PluginError,
    NetworkError,
    TimeoutError,
    ConnectionError,
    SSLError,
    ScanError,
    PayloadError,
    ParserError,
    AuthError,
    ResourceError,
    RetryPolicy,
    ErrorRecord,
)

from .cache_and_resources import (
    CacheLayer,
    CacheEntry,
    ResourceManager,
    ResourceSnapshot,
)

from .dependency_manager import (
    DependencyManager,
    DependencyError,
    CircularDependencyError,
    MissingDependencyError,
    ComponentNode,
)

# ── Part 3: Plugin Architecture ───────────────────────────────────────────────
from .plugin_architecture import (
    PluginType,
    PluginInfo,
    BasePlugin,
    ScannerPlugin,
    FingerprinterPlugin,
    ReporterPlugin,
    DiscoveryPlugin,
    PluginRegistry,
    PluginLoader,
    LegacyScannerAdapter,
)

# ── Part 1: Core Architecture ─────────────────────────────────────────────────
# (يتحمل آخر لأنه بيعتمد على كل حاجة فوق)
from .core_manager import (
    CoreManager,
    CoreContext,
    CoreState,
    PluginMetadata,
    PluginInstance,
)


__all__ = [
    # Core
    "CoreManager", "CoreContext", "CoreState",
    "PluginMetadata", "PluginInstance",
    # Config
    "ConfigFramework", "WebShieldConfig", "ScanProfile",
    # Logging
    "PlatformLogger", "LogLevel", "LogEntry", "SecretMasker",
    # Errors
    "ErrorFramework", "WebShieldError", "ConfigError", "PluginError",
    "NetworkError", "TimeoutError", "ConnectionError", "SSLError",
    "ScanError", "PayloadError", "ParserError", "AuthError",
    "ResourceError", "RetryPolicy", "ErrorRecord",
    # Cache & Resources
    "CacheLayer", "CacheEntry", "ResourceManager", "ResourceSnapshot",
    # Dependency Manager
    "DependencyManager", "DependencyError", "CircularDependencyError",
    "MissingDependencyError", "ComponentNode",
    # Plugins
    "PluginType", "PluginInfo", "BasePlugin",
    "ScannerPlugin", "FingerprinterPlugin", "ReporterPlugin", "DiscoveryPlugin",
    "PluginRegistry", "PluginLoader", "LegacyScannerAdapter",
]

__version__ = "4.0.0"

# ── Part 4: Event-Driven Architecture ────────────────────────────────────────
from .event_bus import (
    Event,
    EventPriority,
    EventBus,
    HandlerRegistration,
    TechRouter,
    WEBSHIELD_DEFAULT_ROUTES,
    create_default_event_bus,
)

# ── Part 5: Workflow Orchestration Layer ──────────────────────────────────────
from .workflow_engine import (
    ScanPhase,
    PhaseStatus,
    WorkflowStep,
    WorkflowDefinition,
    WorkflowBuilder,
    WorkflowEngine,
)

# ── Part 6: Capability System & Scheduler Engine ──────────────────────────────
from .capability_scheduler import (
    Capability,
    CapabilityInfo,
    CapabilityChecker,
    TaskPriority,
    TaskStatus,
    ScheduledTask,
    SchedulerEngine,
)

# ── Part 7: Scan Pipeline ──────────────────────────────────────────────────────
from .scan_pipeline import (
    PipelineArtifact,
    PipelineContext,
    StageContract,
    DEFAULT_STAGE_CONTRACTS,
    StageResult,
    PipelineRunResult,
    PipelineContractError,
    ScanPipeline,
)

# ── Part 8: State Management & Replay Framework ───────────────────────────────
from .state_replay import (
    ScanStatus,
    ScanState,
    StateManager,
    StateError,
    RequestRecord,
    ResponseRecord,
    ReplayEntry,
    ReplayFramework,
)

# ── Part 9: Data Management Layer & Storage Architecture ─────────────────────
from .data_management import (
    DataManagementError,
    STANDARD_COLLECTIONS,
    VersionedRecord,
    DataManagementLayer,
    StorageKind,
    StorageManager,
    compress_bytes,
    decompress_bytes,
)

# ── Part 10: Security Layer ───────────────────────────────────────────────────
from .security_layer import (
    SecurityError,
    DataSensitivity,
    AuditEntry,
    SecurityAuditLog,
    PermissionManager,
    SecretRegistry,
    SecretsVault,
    SecurityLayer,
    SENSITIVE_CONFIG_FIELDS,
)

# ── Part 11: Testing Framework ───────────────────────────────────────────────
from .testing_framework import (
    TestStatus, TestResult, SuiteResult,
    TestRunner, skip, skip_if,
    MockHTTPClient, MockResponse,
    MockEventBus,
    ScanTestHarness, HarnessResult,
    PerformanceProfiler, ProfileEntry,
    RegressionTracker, RegressionBaseline,
    TestFixtureFactory, IntegrationTestBase,
    assert_dict_subset, assert_contains_sensitive,
    assert_event_order, assert_response_redacted,
)

# ── Part 12: Developer SDK ────────────────────────────────────────────────────
from .developer_sdk import (
    SDKError, PluginValidationError,
    SDKSeverity, SDKFinding, SDKResult,
    SDKContext, PluginManifest,
    ScannerSDK, PayloadSDK, ReporterSDK,
    WorkflowSDK, SDKWorkflowStep,
    validate_plugin, SDKBuilder,
)

# ── Part 13: Integration Layer ────────────────────────────────────────────────
from .integration_layer import (
    IntegrationError, WebhookError, ExportError,
    IntegrationStatus, IntegrationResult, BaseIntegration,
    CIExitCode, CIPolicy, CIIntegration,
    DockerIntegration,
    TicketTemplate, TicketIntegration,
    WebhookConfig, WebhookDispatcher,
    ExportFormat, ExportManager,
    IntegrationRegistry, IntegrationConfig,
)

__all__ += [
    # Event-Driven Architecture (Part 4)
    "Event", "EventPriority", "EventBus", "HandlerRegistration",
    "TechRouter", "WEBSHIELD_DEFAULT_ROUTES", "create_default_event_bus",
    # Workflow Orchestration (Part 5)
    "ScanPhase", "PhaseStatus", "WorkflowStep", "WorkflowDefinition",
    "WorkflowBuilder", "WorkflowEngine",
    # Capability System & Scheduler (Part 6)
    "Capability", "CapabilityInfo", "CapabilityChecker",
    "TaskPriority", "TaskStatus", "ScheduledTask", "SchedulerEngine",
    # Scan Pipeline (Part 7)
    "PipelineArtifact", "PipelineContext", "StageContract",
    "DEFAULT_STAGE_CONTRACTS", "StageResult", "PipelineRunResult",
    "PipelineContractError", "ScanPipeline",
    # State Management & Replay (Part 8)
    "ScanStatus", "ScanState", "StateManager", "StateError",
    "RequestRecord", "ResponseRecord", "ReplayEntry", "ReplayFramework",
    # Data Management & Storage (Part 9)
    "DataManagementError", "STANDARD_COLLECTIONS", "VersionedRecord",
    "DataManagementLayer", "StorageKind", "StorageManager",
    "compress_bytes", "decompress_bytes",
    # Security Layer (Part 10)
    "SecurityError", "DataSensitivity", "AuditEntry", "SecurityAuditLog",
    "PermissionManager", "SecretRegistry", "SecretsVault", "SecurityLayer",
    "SENSITIVE_CONFIG_FIELDS",
    # Testing Framework (Part 11)
    "TestStatus", "TestResult", "SuiteResult", "TestRunner",
    "skip", "skip_if",
    "MockHTTPClient", "MockResponse", "MockEventBus",
    "ScanTestHarness", "HarnessResult",
    "PerformanceProfiler", "ProfileEntry",
    "RegressionTracker", "RegressionBaseline",
    "TestFixtureFactory", "IntegrationTestBase",
    "assert_dict_subset", "assert_contains_sensitive",
    "assert_event_order", "assert_response_redacted",
    # Developer SDK (Part 12)
    "SDKError", "PluginValidationError",
    "SDKSeverity", "SDKFinding", "SDKResult",
    "SDKContext", "PluginManifest",
    "ScannerSDK", "PayloadSDK", "ReporterSDK",
    "WorkflowSDK", "SDKWorkflowStep",
    "validate_plugin", "SDKBuilder",
    # Integration Layer (Part 13)
    "IntegrationError", "WebhookError", "ExportError",
    "IntegrationStatus", "IntegrationResult", "BaseIntegration",
    "CIExitCode", "CIPolicy", "CIIntegration",
    "DockerIntegration",
    "TicketTemplate", "TicketIntegration",
    "WebhookConfig", "WebhookDispatcher",
    "ExportFormat", "ExportManager",
    "IntegrationRegistry", "IntegrationConfig",
]
