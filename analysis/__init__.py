# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
WebShield Analysis Layer — Phase 3.

Post-scan reasoning built *on top of* the flat findings the scanners
produce.  Two engines live here:

  • :mod:`correlation_engine` — the Vulnerability Correlation Engine.
    Turns a list of independent findings into attack chains: it knows the
    well-known ways individual weaknesses combine into a single exploit
    path (SSRF → cloud metadata → credential theft, file-upload + path
    traversal → RCE, IDOR + broken-auth → mass data exposure, ...) and
    reports the *chain* impact rather than each finding in isolation.

  • :mod:`risk_analysis` — the Risk Analysis Framework.  Computes a
    realistic, exploitability-weighted risk score per finding — factoring
    confidence, privileges required, data sensitivity and, crucially,
    whether the finding participates in an attack chain — instead of
    leaning on the raw CVSS base score alone.

Both are pure, dependency-light, and JSON-serialisable so the engine can
drop their output straight into ``ScanResult.metadata`` for the reporters.
"""
from __future__ import annotations

from .correlation_engine import (
    AttackChain,
    ChainRule,
    CorrelationGroup,
    CorrelationReport,
    VulnerabilityCorrelationEngine,
)
from .risk_analysis import (
    RiskAnalysisFramework,
    RiskFactors,
    RiskReport,
    RiskScore,
)
from .compliance import (
    ComplianceFramework,
    ComplianceMapping,
    ComplianceReport,
    ControlHit,
    STANDARDS,
)
from .remediation import (
    RemediationFramework,
    RemediationGuidance,
    RemediationReport,
    RemediationTemplate,
)

__all__ = [
    "AttackChain",
    "ChainRule",
    "CorrelationGroup",
    "CorrelationReport",
    "VulnerabilityCorrelationEngine",
    "RiskAnalysisFramework",
    "RiskFactors",
    "RiskReport",
    "RiskScore",
    "ComplianceFramework",
    "ComplianceMapping",
    "ComplianceReport",
    "ControlHit",
    "STANDARDS",
    "RemediationFramework",
    "RemediationGuidance",
    "RemediationReport",
    "RemediationTemplate",
]
