# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Compliance Framework — Phase 3.

A finding on its own tells a developer "you have an SQL injection".  It
does not tell the person who owns the audit that this single bug is a
finding against **PCI DSS 6.2.4**, **OWASP ASVS V5.3**, **GDPR Art. 32**
and **SOC 2 CC6.1** all at once — which is the information that decides
whether a release ships.

This framework maps every finding to the control frameworks WebShield
supports, keyed primarily on the finding's :class:`VulnType` (always set)
and enriched with the finding's own CWE / OWASP category.  It then rolls
those per-finding mappings up per standard, so a report can answer both
"what does *this* bug violate?" and "which **PCI requirements** does this
target currently fail?".

Standards covered
-----------------
* OWASP Top 10 (2021)
* OWASP API Security Top 10 (2023)
* OWASP ASVS (4.0.3 chapters)
* CWE (from the finding, with a canonical fallback per type)
* PCI DSS 4.0
* GDPR (articles)
* SOC 2 (Trust Services Criteria)
* HIPAA Security Rule (§164.312 safeguards)

Everything here is a static, deterministic lookup — no network, no state.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..models.vulnerability import Vulnerability, VulnType

# Standard identifiers (stable keys used across the report and reporters).
STANDARDS: Dict[str, str] = {
    "owasp_top10": "OWASP Top 10 (2021)",
    "owasp_api_top10": "OWASP API Security Top 10 (2023)",
    "owasp_asvs": "OWASP ASVS 4.0",
    "cwe": "CWE",
    "pci_dss": "PCI DSS 4.0",
    "gdpr": "GDPR",
    "soc2": "SOC 2 (Trust Services Criteria)",
    "hipaa": "HIPAA Security Rule",
}

# Reusable control references, composed into the per-type map below.
_GDPR_SECURITY = "Art. 32 — Security of processing"
_GDPR_INTEGRITY = "Art. 5(1)(f) — Integrity and confidentiality"
_GDPR_BY_DESIGN = "Art. 25 — Data protection by design and by default"
_SOC2_ACCESS = "CC6.1 — Logical access controls"
_SOC2_BOUNDARY = "CC6.6 — Boundary protection"
_SOC2_TRANSMISSION = "CC6.7 — Transmission and disposal of data"
_SOC2_DETECT = "CC7.1 — Detection of security events"
_PCI_INJECTION = "6.2.4 — Protect against common application attacks (injection)"
_PCI_CRYPTO_TRANSIT = "4.2.1 — Strong cryptography for data in transit"
_PCI_AUTH = "8.3 — Strong authentication for access"
_PCI_STORED = "3.5 — Protect stored cryptographic keys/secrets"
_HIPAA_ACCESS = "§164.312(a)(1) — Access control"
_HIPAA_INTEGRITY = "§164.312(c)(1) — Integrity"
_HIPAA_AUTH = "§164.312(d) — Person or entity authentication"
_HIPAA_TRANSMISSION = "§164.312(e)(1) — Transmission security"

# Per-VulnType compliance mapping.  Any standard key omitted for a type
# simply means "not directly applicable" and is left out of that finding's
# mapping (rather than padded with a weak match).
_MAP: Dict[VulnType, Dict[str, List[str]]] = {
    VulnType.SQLI: {
        "owasp_top10": ["A03:2021 — Injection"],
        "owasp_asvs": ["V5.3 — Output Encoding & Injection Prevention"],
        "cwe": ["CWE-89"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY, _GDPR_INTEGRITY],
        "soc2": [_SOC2_ACCESS, _SOC2_DETECT],
        "hipaa": [_HIPAA_INTEGRITY, _HIPAA_ACCESS],
    },
    VulnType.NOSQLI: {
        "owasp_top10": ["A03:2021 — Injection"],
        "owasp_asvs": ["V5.3 — Output Encoding & Injection Prevention"],
        "cwe": ["CWE-943"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.LDAP: {
        "owasp_top10": ["A03:2021 — Injection"],
        "owasp_asvs": ["V5.3 — Output Encoding & Injection Prevention"],
        "cwe": ["CWE-90"],
        "pci_dss": [_PCI_INJECTION],
    },
    VulnType.XPATH: {
        "owasp_top10": ["A03:2021 — Injection"],
        "owasp_asvs": ["V5.3 — Output Encoding & Injection Prevention"],
        "cwe": ["CWE-643"],
        "pci_dss": [_PCI_INJECTION],
    },
    VulnType.XSS: {
        "owasp_top10": ["A03:2021 — Injection"],
        "owasp_asvs": ["V5.3.3 — Context-aware output escaping"],
        "cwe": ["CWE-79"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_INTEGRITY],
    },
    VulnType.CMDI: {
        "owasp_top10": ["A03:2021 — Injection"],
        "owasp_asvs": ["V5.3.8 — OS command injection prevention"],
        "cwe": ["CWE-78"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY, _GDPR_INTEGRITY],
        "soc2": [_SOC2_ACCESS, _SOC2_DETECT],
        "hipaa": [_HIPAA_INTEGRITY],
    },
    VulnType.SSTI: {
        "owasp_top10": ["A03:2021 — Injection"],
        "owasp_asvs": ["V5.2.5 — Template injection prevention"],
        "cwe": ["CWE-1336", "CWE-94"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY],
    },
    VulnType.CRLF: {
        "owasp_top10": ["A03:2021 — Injection"],
        "cwe": ["CWE-93", "CWE-113"],
        "owasp_asvs": ["V5.1.5 — Header/URL redirect validation"],
    },
    VulnType.CSRF: {
        "owasp_top10": ["A01:2021 — Broken Access Control"],
        "owasp_asvs": ["V4.2.2 — Anti-CSRF protection"],
        "cwe": ["CWE-352"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.SSRF: {
        "owasp_top10": ["A10:2021 — Server-Side Request Forgery"],
        "owasp_api_top10": ["API7:2023 — Server-Side Request Forgery"],
        "owasp_asvs": ["V12.6 — SSRF protection", "V5.2.6 — URL/redirect validation"],
        "cwe": ["CWE-918"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_BOUNDARY, _SOC2_ACCESS],
    },
    VulnType.XXE: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration"],
        "owasp_asvs": ["V5.5.2 — XML parser hardening (external entities)"],
        "cwe": ["CWE-611"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.HTTP_SMUGGLING: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration"],
        "cwe": ["CWE-444"],
        "soc2": [_SOC2_BOUNDARY],
    },
    VulnType.PATH_TRAVERSAL: {
        "owasp_top10": ["A01:2021 — Broken Access Control"],
        "owasp_asvs": ["V12.3 — File path/traversal protection"],
        "cwe": ["CWE-22"],
        "pci_dss": [_PCI_INJECTION],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_ACCESS],
    },
    VulnType.LFI: {
        "owasp_top10": ["A03:2021 — Injection", "A01:2021 — Broken Access Control"],
        "cwe": ["CWE-98", "CWE-22"],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.RFI: {
        "owasp_top10": ["A03:2021 — Injection"],
        "cwe": ["CWE-98"],
    },
    VulnType.FILE_UPLOAD: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration", "A04:2021 — Insecure Design"],
        "owasp_asvs": ["V12.2 — File upload validation"],
        "cwe": ["CWE-434"],
        "pci_dss": [_PCI_INJECTION],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.IDOR: {
        "owasp_top10": ["A01:2021 — Broken Access Control"],
        "owasp_api_top10": ["API1:2023 — Broken Object Level Authorization"],
        "owasp_asvs": ["V4.2.1 — Object-level access control"],
        "cwe": ["CWE-639"],
        "gdpr": [_GDPR_SECURITY, _GDPR_BY_DESIGN],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_ACCESS],
    },
    VulnType.BOLA: {
        "owasp_top10": ["A01:2021 — Broken Access Control"],
        "owasp_api_top10": ["API1:2023 — Broken Object Level Authorization"],
        "owasp_asvs": ["V4.2.1 — Object-level access control"],
        "cwe": ["CWE-639"],
        "gdpr": [_GDPR_SECURITY, _GDPR_BY_DESIGN],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_ACCESS],
    },
    VulnType.BFLA: {
        "owasp_top10": ["A01:2021 — Broken Access Control"],
        "owasp_api_top10": ["API5:2023 — Broken Function Level Authorization"],
        "owasp_asvs": ["V4.1 — Function-level access control"],
        "cwe": ["CWE-285"],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_ACCESS],
    },
    VulnType.OPEN_REDIRECT: {
        "owasp_top10": ["A01:2021 — Broken Access Control"],
        "owasp_asvs": ["V5.1.5 — Redirect/forward validation"],
        "cwe": ["CWE-601"],
    },
    VulnType.BROKEN_AUTH: {
        "owasp_top10": ["A07:2021 — Identification and Authentication Failures"],
        "owasp_api_top10": ["API2:2023 — Broken Authentication"],
        "owasp_asvs": ["V2 — Authentication"],
        "cwe": ["CWE-287"],
        "pci_dss": [_PCI_AUTH],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_AUTH],
    },
    VulnType.RACE_CONDITION: {
        "owasp_top10": ["A04:2021 — Insecure Design"],
        "cwe": ["CWE-362"],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.SECURITY_HEADERS: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration"],
        "owasp_asvs": ["V14.4 — HTTP security headers"],
        "cwe": ["CWE-693"],
        "soc2": [_SOC2_BOUNDARY],
    },
    VulnType.SSL_TLS: {
        "owasp_top10": ["A02:2021 — Cryptographic Failures"],
        "owasp_asvs": ["V9 — Communications security"],
        "cwe": ["CWE-326", "CWE-327"],
        "pci_dss": [_PCI_CRYPTO_TRANSIT],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_TRANSMISSION],
        "hipaa": [_HIPAA_TRANSMISSION],
    },
    VulnType.CORS: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration"],
        "owasp_api_top10": ["API8:2023 — Security Misconfiguration"],
        "owasp_asvs": ["V14.5 — Cross-origin resource sharing"],
        "cwe": ["CWE-942"],
        "soc2": [_SOC2_BOUNDARY],
    },
    VulnType.JWT: {
        "owasp_top10": ["A02:2021 — Cryptographic Failures", "A07:2021 — Identification and Authentication Failures"],
        "owasp_api_top10": ["API2:2023 — Broken Authentication"],
        "owasp_asvs": ["V3.5 — Token-based session management"],
        "cwe": ["CWE-347"],
        "pci_dss": [_PCI_AUTH],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_AUTH],
    },
    VulnType.GRAPHQL: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration"],
        "owasp_api_top10": ["API8:2023 — Security Misconfiguration"],
        "cwe": ["CWE-400"],
        "soc2": [_SOC2_BOUNDARY],
    },
    VulnType.SENSITIVE_DATA: {
        "owasp_top10": ["A02:2021 — Cryptographic Failures"],
        "cwe": ["CWE-200", "CWE-311"],
        "pci_dss": ["3.4 — Protect stored account data"],
        "gdpr": [_GDPR_SECURITY, _GDPR_INTEGRITY],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_ACCESS],
    },
    VulnType.INFO_DISCLOSURE: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration", "A01:2021 — Broken Access Control"],
        "cwe": ["CWE-200", "CWE-209"],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.WEBSOCKET: {
        "owasp_top10": ["A01:2021 — Broken Access Control", "A05:2021 — Security Misconfiguration"],
        "cwe": ["CWE-346"],
        "soc2": [_SOC2_BOUNDARY],
    },
    VulnType.SECRET_EXPOSURE: {
        "owasp_top10": ["A05:2021 — Security Misconfiguration", "A07:2021 — Identification and Authentication Failures"],
        "cwe": ["CWE-798", "CWE-522"],
        "pci_dss": [_PCI_STORED, _PCI_AUTH],
        "gdpr": [_GDPR_SECURITY],
        "soc2": [_SOC2_ACCESS],
        "hipaa": [_HIPAA_AUTH],
    },
    VulnType.OAUTH: {
        "owasp_top10": ["A07:2021 — Identification and Authentication Failures"],
        "owasp_api_top10": ["API2:2023 — Broken Authentication"],
        "owasp_asvs": ["V2 — Authentication", "V3 — Session Management"],
        "cwe": ["CWE-287"],
        "pci_dss": [_PCI_AUTH],
        "soc2": [_SOC2_ACCESS],
    },
    VulnType.MISC: {
        "owasp_top10": ["A04:2021 — Insecure Design"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ComplianceMapping:
    finding_id: str
    title: str
    vuln_type: str
    severity: str
    standards: Dict[str, List[str]]  # standard key -> control references

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "standards": {k: list(v) for k, v in self.standards.items()},
        }


@dataclass
class ControlHit:
    """One control reference and the findings that violate it."""
    control: str
    finding_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"control": self.control, "count": len(self.finding_ids),
                "finding_ids": list(self.finding_ids)}


@dataclass
class ComplianceReport:
    mappings: List[ComplianceMapping]
    # standard key -> list of ControlHit
    rollups: Dict[str, List[ControlHit]]

    def standards_covered(self) -> List[str]:
        return [STANDARDS.get(k, k) for k, hits in self.rollups.items() if hits]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "standards": STANDARDS,
            "standards_failed": {
                k: [h.to_dict() for h in hits]
                for k, hits in self.rollups.items() if hits
            },
            "summary": {
                STANDARDS.get(k, k): len(hits)
                for k, hits in self.rollups.items() if hits
            },
            "mappings": [m.to_dict() for m in self.mappings],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Framework
# ─────────────────────────────────────────────────────────────────────────────

class ComplianceFramework:
    """Maps findings to compliance controls and rolls them up per standard."""

    def map(self, vulnerabilities: Sequence[Vulnerability]) -> ComplianceReport:
        mappings: List[ComplianceMapping] = []
        # standard -> control -> [finding_ids]
        rollup: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

        for v in vulnerabilities:
            standards = self._standards_for(v)
            mappings.append(ComplianceMapping(
                finding_id=v.vuln_id,
                title=v.title,
                vuln_type=v.vuln_type.value,
                severity=v.severity.value,
                standards=standards,
            ))
            for std_key, controls in standards.items():
                for control in controls:
                    rollup[std_key][control].append(v.vuln_id)

        rollups: Dict[str, List[ControlHit]] = {}
        for std_key in STANDARDS:
            hits = [
                ControlHit(control=ctrl, finding_ids=fids)
                for ctrl, fids in rollup.get(std_key, {}).items()
            ]
            hits.sort(key=lambda h: len(h.finding_ids), reverse=True)
            rollups[std_key] = hits

        return ComplianceReport(mappings=mappings, rollups=rollups)

    @staticmethod
    def _standards_for(v: Vulnerability) -> Dict[str, List[str]]:
        base = _MAP.get(v.vuln_type, {})
        # Copy so we can enrich with the finding's own metadata without
        # mutating the shared table.
        standards: Dict[str, List[str]] = {k: list(vv) for k, vv in base.items()}

        # Enrich CWE with the finding's own value if the scanner set one.
        if v.cwe_id:
            cwe_list = standards.setdefault("cwe", [])
            if v.cwe_id not in cwe_list:
                cwe_list.insert(0, v.cwe_id)

        # Enrich OWASP Top 10 with the finding's own owasp_category, normalising
        # the en-dash the scanners sometimes use so rollups don't split.
        if v.owasp_category:
            normalised = v.owasp_category.replace(" – ", " — ").replace(" - ", " — ")
            top10 = standards.setdefault("owasp_top10", [])
            if normalised not in top10:
                top10.append(normalised)

        return standards


__all__ = [
    "STANDARDS",
    "ComplianceMapping",
    "ControlHit",
    "ComplianceReport",
    "ComplianceFramework",
]
