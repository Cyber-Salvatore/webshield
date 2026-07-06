"""
WebShield Core Package — lazy imports to break circular dependency chains.
"""
from __future__ import annotations

# HTTPClient + HTTPResponse are needed widely — load them first (no circular deps)
from .http_client import HTTPClient, HTTPResponse
from .target import ScanTarget

def __getattr__(name: str):
    _MAP = {
        "ScanEngine":          ("engine",        "ScanEngine"),
        "Crawler":             ("crawler",       "Crawler"),
        "CrawlResult":         ("crawler",       "CrawlResult"),
        "MultiAccountManager": ("multi_account", "MultiAccountManager"),
        "ManagedAccount":      ("multi_account", "ManagedAccount"),
        "OwnedResource":       ("multi_account", "OwnedResource"),
        "IDORCandidate":       ("multi_account", "IDORCandidate"),
        "AccessMatrixReport":  ("multi_account", "AccessMatrixReport"),
        "BaselineEngine":             ("baseline_engine",     "BaselineEngine"),
        "EndpointBaseline":          ("baseline_engine",     "EndpointBaseline"),
        "BaselineComparison":        ("baseline_engine",     "BaselineComparison"),
        "DifferentialAnalysisEngine": ("differential_engine", "DifferentialAnalysisEngine"),
        "DiffResult":                ("differential_engine", "DiffResult"),
        "DiffSignificance":          ("differential_engine", "DiffSignificance"),
        "DiffDimension":             ("differential_engine", "DiffDimension"),
        "diff_responses":           ("differential_engine", "diff_responses"),
    }
    if name in _MAP:
        import importlib
        mod_name, cls_name = _MAP[name]
        mod = importlib.import_module(f".{mod_name}", package=__name__)
        return getattr(mod, cls_name)
    raise AttributeError(f"module 'webshield.core' has no attribute {name!r}")

__all__ = [
    "HTTPClient", "HTTPResponse", "ScanTarget", "ScanEngine", "Crawler", "CrawlResult",
    "MultiAccountManager", "ManagedAccount", "OwnedResource", "IDORCandidate", "AccessMatrixReport",
    "BaselineEngine", "EndpointBaseline", "BaselineComparison",
    "DifferentialAnalysisEngine", "DiffResult", "DiffSignificance", "DiffDimension", "diff_responses",
]

# Endpoint Classification Engine — canonical core/ copy (see recon.endpoint_classifier
# for the original Part 11/12 module this supersedes; kept here, non-lazily
# imported, to avoid circular-import issues for callers inside webshield.core).
from .endpoint_classifier import (
    EndpointClassifier,
    EndpointProfile,
    EndpointCategory,
    ClassificationResult,
    ConfidenceLevel,
    SCANNER_ROUTING_TABLE,
    classify_endpoint,
)

# Part 17 — Confidence Framework
from .confidence_framework import (
    EvidenceType,
    RelationshipType,
    ConfidenceLabel,
    Evidence,
    EvidenceRelationship,
    ConfidenceScore,
    ConfidenceFramework,
    confidence_from_evidence,
)

# Part 18 — Triple Confirmation Framework
from .triple_confirmation import (
    ProbeRole,
    ProbeResult,
    VerdictLabel,
    ConfirmationVerdict,
    TripleConfirmationFramework,
)

__all__ += [
    "EndpointClassifier", "EndpointProfile", "EndpointCategory",
    "ClassificationResult", "ConfidenceLevel", "SCANNER_ROUTING_TABLE", "classify_endpoint",
    "EvidenceType", "RelationshipType", "ConfidenceLabel",
    "Evidence", "EvidenceRelationship", "ConfidenceScore",
    "ConfidenceFramework", "confidence_from_evidence",
    "ProbeRole", "ProbeResult", "VerdictLabel", "ConfirmationVerdict",
    "TripleConfirmationFramework",
]

# Part 19 — Evidence Collection Framework
from .evidence_collection import (
    ArtifactType,
    EvidenceArtifact,
    EvidenceBundle,
    EvidenceCollector,
    ReplayPackage,
)

__all__ += [
    "ArtifactType", "EvidenceArtifact", "EvidenceBundle",
    "EvidenceCollector", "ReplayPackage",
]

# Part 20 — Evidence Graph
from .evidence_graph import (
    NodeType,
    EdgeType,
    GraphNode,
    GraphEdge,
    GraphPath,
    EvidenceGraph,
)

__all__ += [
    "NodeType", "EdgeType", "GraphNode", "GraphEdge", "GraphPath", "EvidenceGraph",
]
