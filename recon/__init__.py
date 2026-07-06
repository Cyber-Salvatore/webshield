# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""WebShield Recon Modules."""

from .dork_generator import DorkGenerator, DorkResult
from .asset_discovery import AssetDiscovery, AssetReport, SubdomainInfo, DNSRecord
from .fingerprinter import (
    FingerprintEngine,
    AppFingerprint,
    TechDetection,
    TechCategory,
    ConfidenceLevel,
    TLSInfo,
    HTTPBehavior,
    TechKnowledgeBase,
)
from .intelligence_engine import (
    PassiveIntelligenceEngine,
    IntelligenceReport,
    DiscoveredEndpoint,
    SecretFinding,
    ThirdPartyService,
)
from .intelligence_bridge import (
    TechProfile,
    ScannerIntelligenceContext,
    IntelligenceAwareScanner,
    SmartPayloadSelector,
    AdaptiveScannerRouter,
    RoutingDecision,
    ScanPlanBuilder,
    ScanPlan,
    IntelligenceBridge,
    PhaseCoordinator,
)
from .intelligence_layer import (
    # Adaptive Rate Control
    AdaptiveRateController,
    ServerHealthState,
    RateWindow,
    # Session Management
    SessionManagementFramework,
    SessionState,
    ManagedToken,
    TokenType,
    # Authentication Framework
    AuthenticationFramework,
    AuthFlowMap,
    AuthFlowType,
    # Authorization Framework
    AuthorizationFramework,
    AuthZMatrix,
    ResourcePermission,
    PermissionLevel,
    # Master Orchestrator
    Phase2MasterOrchestrator,
    Phase2Report,
)
from .knowledge_base import (
    KnowledgeBase,
    KBEntry,
    CVEEntry,
    FingerprintRule,
    VersionIndicator,
)
from .js_analysis_engine import (
    JSAnalysisEngine,
    JSAnalysisReport,
    SecretFinding as JSSecretFinding,
    DiscoveredEndpoint as JSDiscoveredEndpoint,
    GraphQLFinding,
    FeatureFlag,
    CloudResource,
    SecretConfidence,
    EndpointType as JSEndpointType,
    analyse_js_files,
)
from .graphql_framework import (
    GraphQLFramework,
    GraphQLSchema as GQLSchema,
    GraphQLAttackSurface,
    GQLEndpoint,
    GQLType,
    GQLField,
    GQLArgument,
    GQLOperation,
    GQLDirective,
    GQLTypeRef,
    GQLKind,
    GQLEnumValue,
    OperationType,
    TransportType,
    IntrospectionMode,
    render_sdl,
    extract_attack_surface,
)
from .api_discovery_engine import (
    APIDiscoveryEngine,
    APIDiscoveryResult,
    APIEndpoint,
    APIParameter,
    APIType,
    AuthScheme,
    ParamLocation as APIParamLocation,
    DiscoverySource,
    GraphQLSchema,
    OpenAPIParser,
    GraphQLProbe,
    WebSocketProbe,
    SSEProbe,
    SOAPProbe,
    GRPCProbe,
    RESTProbe,
    run_api_discovery,
)
from .websocket_framework import (
    WebSocketFramework,
    WSFrameworkReport,
    WSEndpoint,
    WSHandshake,
    WSMessageSample,
    WSChannel,
    WSAttackSurface,
    WSStatus,
    WSProtocolFamily,
    WSAuthScheme as WSAuthSchemeEnum,
    WSDataFormat,
    WSDiscoverySource,
    OriginPolicy,
    WSProtocolDetector,
    WSHandshakeAnalyser,
    WSMessageProbe,
    WSSourceMiner,
    WSAuthDetector,
    WSPathProber,
    WSEndpointEnricher,
    build_attack_surface,
    run_websocket_framework,
)
from .discovery_engine import (
    # Endpoint classification
    EndpointClassificationEngine,
    ClassifiedEndpoint,
    EndpointType,
    # Parameter intelligence
    ParameterIntelligenceEngine,
    ClassifiedParameter,
    ParameterType,
    ParameterLocation,
    # Context-aware payloads
    ContextAwarePayloadFramework,
    ContextualPayload,
    PayloadContext,
    # Encoding (basic stub kept for backward compat)
    EncodingFramework as _LegacyEncodingFramework,
    EncodedPayload as _LegacyEncodedPayload,
    # Differential analysis (basic stub kept for backward compat — superseded
    # by the dedicated core.differential_engine module, Part 16)
    DifferentialAnalysisEngine as _LegacyDifferentialAnalysisEngine,
    DiffResult as _LegacyDiffResult,
    # Triple confirmation
    TripleConfirmationFramework,
    ConfirmationResult,
    # Evidence collection
    EvidenceCollectionFramework,
    EvidenceItem,
    EvidenceType,
    # Evidence graph
    EvidenceGraph,
    GraphNode,
    GraphEdge,
    # Attack chain
    AttackChainEngine,
    AttackChain,
    AttackStep,
    # Multi-account
    MultiAccountFramework,
    AccountSession,
    CrossAccountTestResult,
    # Orchestrator
    DiscoveryOrchestrator,
    DiscoveryReport,
)

__all__ = [
    "DorkGenerator",
    "DorkResult",
    "AssetDiscovery",
    "AssetReport",
    "SubdomainInfo",
    "DNSRecord",
    # Fingerprinting Framework
    "FingerprintEngine",
    "AppFingerprint",
    "TechDetection",
    "TechCategory",
    "ConfidenceLevel",
    "TLSInfo",
    "HTTPBehavior",
    "TechKnowledgeBase",
    # Passive Intelligence Engine
    "PassiveIntelligenceEngine",
    "IntelligenceReport",
    "DiscoveredEndpoint",
    "SecretFinding",
    "ThirdPartyService",
    # Knowledge Base
    "KnowledgeBase",
    "KBEntry",
    "CVEEntry",
    "FingerprintRule",
    "VersionIndicator",
    # Intelligence Bridge
    "TechProfile", "ScannerIntelligenceContext", "IntelligenceAwareScanner",
    "SmartPayloadSelector", "AdaptiveScannerRouter", "RoutingDecision",
    "ScanPlanBuilder", "ScanPlan", "IntelligenceBridge", "PhaseCoordinator",
    # Intelligence Layer
    "AdaptiveRateController", "ServerHealthState", "RateWindow",
    "SessionManagementFramework", "SessionState", "ManagedToken", "TokenType",
    "AuthenticationFramework", "AuthFlowMap", "AuthFlowType",
    "AuthorizationFramework", "AuthZMatrix", "ResourcePermission", "PermissionLevel",
    "Phase2MasterOrchestrator", "Phase2Report",
    # JavaScript Analysis Engine (Part 7)
    "JSAnalysisEngine", "JSAnalysisReport", "JSSecretFinding", "JSDiscoveredEndpoint",
    "GraphQLFinding", "FeatureFlag", "CloudResource", "SecretConfidence",
    "JSEndpointType", "analyse_js_files",
    # Discovery Infrastructure
    "EndpointClassificationEngine", "ClassifiedEndpoint", "EndpointType",
    "ParameterIntelligenceEngine", "ClassifiedParameter", "ParameterType", "ParameterLocation",
    "ContextAwarePayloadFramework", "ContextualPayload", "PayloadContext",
    "EncodingFramework", "EncodedPayload",
    "TripleConfirmationFramework", "ConfirmationResult",
    "EvidenceCollectionFramework", "EvidenceItem", "EvidenceType",
    "EvidenceGraph", "GraphNode", "GraphEdge",
    "AttackChainEngine", "AttackChain", "AttackStep",
    "MultiAccountFramework", "AccountSession", "CrossAccountTestResult",
    "DiscoveryOrchestrator", "DiscoveryReport",
    # GraphQL Framework (Part 9)
    "GraphQLFramework", "GQLSchema", "GraphQLAttackSurface",
    "GQLEndpoint", "GQLType", "GQLField", "GQLArgument", "GQLOperation",
    "GQLDirective", "GQLTypeRef", "GQLKind", "GQLEnumValue",
    "OperationType", "TransportType", "IntrospectionMode",
    "render_sdl", "extract_attack_surface",
    # API Discovery Engine (Part 8)
    "APIDiscoveryEngine", "APIDiscoveryResult", "APIEndpoint", "APIParameter",
    "APIType", "AuthScheme", "APIParamLocation", "DiscoverySource", "GraphQLSchema",
    "OpenAPIParser", "GraphQLProbe", "WebSocketProbe", "SSEProbe",
    "SOAPProbe", "GRPCProbe", "RESTProbe", "run_api_discovery",
    # WebSocket Framework (Part 10)
    "WebSocketFramework", "WSFrameworkReport", "WSEndpoint", "WSHandshake",
    "WSMessageSample", "WSChannel", "WSAttackSurface",
    "WSStatus", "WSProtocolFamily", "WSAuthSchemeEnum", "WSDataFormat",
    "WSDiscoverySource", "OriginPolicy",
    "WSProtocolDetector", "WSHandshakeAnalyser", "WSMessageProbe",
    "WSSourceMiner", "WSAuthDetector", "WSPathProber", "WSEndpointEnricher",
    "build_attack_surface", "run_websocket_framework",
]

# Endpoint Classification Engine (Part 12)
from .endpoint_classifier import (
    EndpointClassifier,
    ClassificationReport as ECClassificationReport,
    ClassifiedEndpoint as ECClassifiedEndpoint,
    RawEndpoint,
    EndpointCategory,
    EndpointTag,
    ScannerHint,
    ScannerPriority,
    ClassificationEvidence,
    classify_endpoints,
)

# Encoding Framework (Part 14) — dedicated production-grade module
from .encoding_framework import (
    EncodingFramework,
    EncodingFamily,
    EncodingContext,
    SelectionStrategy,
    EncodingTechnique,
    EncodedPayload,
    WAFProfile,
    EncodingDecision,
    EncodingSelector,
    LayeredEncoder,
    ContextAwareEncoder,
    SessionEncodingMemory,
    EncodingReporter,
    TECHNIQUE_REGISTRY,
    quick_encode,
    best_encode,
    list_techniques,
)

# Differential Analysis Engine (Part 16) — dedicated production-grade module
from ..core.differential_engine import (
    DifferentialAnalysisEngine,
    DiffResult,
    DiffSignificance,
    DiffDimension,
    JSONStructureDiff,
    DOMStructureDiff,
    HeaderDiff,
    RedirectDiff,
    TimingDiff,
    diff_responses,
)

__all__ += [
    "DifferentialAnalysisEngine", "DiffResult", "DiffSignificance", "DiffDimension",
    "JSONStructureDiff", "DOMStructureDiff", "HeaderDiff", "RedirectDiff", "TimingDiff",
    "diff_responses",
]
