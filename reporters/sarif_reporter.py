"""
SARIF 2.1.0 Report Generator — Phase 5.3
==========================================
Static Analysis Results Interchange Format — compatible with:
  • GitHub Code Scanning (upload-sarif action)
  • GitLab SAST
  • Azure DevOps
  • VSCode SARIF Viewer extension

Each vulnerability becomes a SARIF `result` with:
  • ruleId   → vuln_type value (e.g. "SQL Injection")
  • level    → error / warning / note  (mapped from severity)
  • message  → title + description
  • locations → URI + logical location (parameter)
  • properties → CVSS score, CWE, OWASP, confidence, evidence

Usage in GitHub Actions::

    - name: WebShield Scan
      run: python main.py https://staging.app.com --no-html --sarif

    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: reports/webshield_*.sarif
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base_reporter import BaseReporter
from ..models.scan_result import ScanResult
from ..models.vulnerability import Severity, Vulnerability

# SARIF 2.1.0 schema URI
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# WebShield tool metadata
_TOOL_NAME     = "WebShield"
_TOOL_VERSION  = "3.0.0"
_TOOL_URI      = "https://github.com/webshield/webshield"

# Severity → SARIF level mapping
_LEVEL_MAP: Dict[str, str] = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
    "Info":     "none",
}

# CWE → SARIF tag prefix
_CWE_BASE = "https://cwe.mitre.org/data/definitions/"


class SARIFReporter(BaseReporter):
    """
    Phase 5.3 — SARIF 2.1.0 Report Generator.

    Produces a .sarif file compatible with GitHub Code Scanning,
    GitLab SAST, and other SARIF consumers.
    """

    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        output_path = self._make_path(result, "sarif", filename)
        sarif = self._build_sarif(result)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, default=str, ensure_ascii=False)
        return str(output_path)

    # -----------------------------------------------------------------------

    def _build_sarif(self, result: ScanResult) -> Dict[str, Any]:
        rules   = self._build_rules(result)
        results = self._build_results(result)

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": _TOOL_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": result.stats.start_time.strftime("%Y-%m-%dT%H:%M:%SZ") if result.stats.start_time else None,
                            "endTimeUtc":   result.stats.end_time.strftime("%Y-%m-%dT%H:%M:%SZ") if result.stats.end_time else None,
                            "toolExecutionNotices": [],
                        }
                    ],
                    "properties": {
                        "scanId":        result.scan_id,
                        "targetUrl":     result.target_url,
                        "scanProfile":   result.scan_profile,
                        "riskScore":     result.risk_score(),
                        "requestsSent":  result.stats.requests_sent,
                        "urlsCrawled":   result.stats.urls_crawled,
                    },
                }
            ],
        }

    # -----------------------------------------------------------------------
    # Rules (one per unique vuln_type)
    # -----------------------------------------------------------------------

    def _build_rules(self, result: ScanResult) -> List[Dict[str, Any]]:
        seen: Dict[str, Dict[str, Any]] = {}
        for v in result.vulnerabilities:
            rule_id = self._rule_id(v)
            if rule_id in seen:
                continue

            tags: List[str] = []
            if v.cwe_id:
                tags.append(v.cwe_id)
            if v.owasp_category:
                tags.append(v.owasp_category[:80])

            relationships = []
            if v.cwe_id:
                cwe_num = v.cwe_id.replace("CWE-", "")
                relationships.append({
                    "target": {
                        "id": v.cwe_id,
                        "guid": None,
                        "toolComponent": {"name": "CWE"},
                    },
                    "kinds": ["superset"],
                })

            seen[rule_id] = {
                "id": rule_id,
                "name": v.vuln_type.value.replace(" ", "").replace("/", "").replace("-", ""),
                "shortDescription": {"text": v.vuln_type.value},
                "fullDescription":  {"text": v.description[:500] if v.description else ""},
                "helpUri": v.references[0] if v.references else _TOOL_URI,
                "properties": {
                    "tags": tags,
                    "precision": "medium",
                    "problem.severity": _LEVEL_MAP.get(v.severity.value, "warning"),
                    "security-severity": str(round(v.cvss_score() or 0.0, 1)),
                },
                "relationships": relationships,
            }
        return list(seen.values())

    # -----------------------------------------------------------------------
    # Results (one per vulnerability)
    # -----------------------------------------------------------------------

    def _build_results(self, result: ScanResult) -> List[Dict[str, Any]]:
        sarif_results: List[Dict[str, Any]] = []

        for v in result.vulnerabilities:
            locations = self._build_locations(v)
            message_text = f"{v.title}\n\n{v.description}"
            if v.evidence:
                message_text += f"\n\nEvidence: {v.evidence}"
            if v.remediation:
                message_text += f"\n\nRemediation: {v.remediation}"

            props: Dict[str, Any] = {
                "vulnId":       v.vuln_id,
                "confidence":   v.confidence,
                "fpRisk":       v.false_positive_risk,
                "discoveredAt": v.discovered_at.isoformat(),
            }
            if v.cvss_score() is not None:
                props["cvssScore"]  = v.cvss_score()
                props["cvssVector"] = v.cvss.vector_string() if v.cvss else ""
            if v.payload:
                props["payload"] = str(v.payload)[:200]
            if v.parameter:
                props["parameter"] = v.parameter

            related_locations: List[Dict[str, Any]] = []
            if v.response_snippet:
                related_locations.append({
                    "id": 1,
                    "message": {"text": "Response snippet"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": v.url},
                    },
                })

            entry: Dict[str, Any] = {
                "ruleId":  self._rule_id(v),
                "level":   _LEVEL_MAP.get(v.severity.value, "warning"),
                "message": {"text": message_text[:2000]},
                "locations": locations,
                "properties": props,
            }
            if related_locations:
                entry["relatedLocations"] = related_locations
            if v.references:
                entry["webRequest"] = {
                    "target": v.url,
                    "method": v.method or "GET",
                }

            sarif_results.append(entry)

        return sarif_results

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _rule_id(v: Vulnerability) -> str:
        """Produce a stable, URL-safe rule ID from vuln_type."""
        return v.vuln_type.value.upper().replace(" ", "_").replace("/", "_").replace("-", "_")[:64]

    @staticmethod
    def _build_locations(v: Vulnerability) -> List[Dict[str, Any]]:
        """Build SARIF locations array from a vulnerability."""
        # SARIF prefers relative URIs — strip scheme/host for web findings
        try:
            from urllib.parse import urlparse
            parsed = urlparse(v.url)
            uri = parsed.path or "/"
            if parsed.query:
                uri += "?" + parsed.query
        except Exception:
            uri = v.url

        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": uri,
                    "uriBaseId": "%SRCROOT%",
                },
            }
        }

        if v.parameter:
            location["logicalLocations"] = [
                {
                    "name": v.parameter,
                    "kind": "parameter",
                    "fullyQualifiedName": f"{uri}#{v.parameter}",
                }
            ]

        return [location]
