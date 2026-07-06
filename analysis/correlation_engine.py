# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Vulnerability Correlation Engine — Phase 3.

The scanners emit *flat* findings: "SQLi on /login", "SSRF on /fetch",
"secret leaked in app.js".  On their own each carries its own severity.
But an attacker never sees the target that way — they see paths.  An SSRF
that reaches the cloud metadata endpoint hands over IAM credentials; a
file-upload combined with a path-traversal becomes remote code execution;
an IDOR next to a broken-authentication finding becomes bulk data theft.

This engine looks at the whole finding set and answers the question the
flat list can't: *which of these combine into a single exploit chain, and
what is the real impact once they do?*  It does this without any network
traffic — it is pure reasoning over already-collected findings, so it is
cheap, deterministic and safe to run at the end of every scan.

Design
------
* :class:`ChainRule` — a declarative rule.  ``all_of`` lists the finding
  types that must all be present (scoped to one host) for the chain to
  fire; ``escalated_severity`` is the impact of the *combination*, which
  is typically higher than any single member.  ``amplifier`` rules fire on
  a single finding to flag a latent, one-more-step chain (e.g. an SSRF is
  always one request away from cloud metadata).
* :class:`AttackChain` — a fired rule bound to the concrete findings that
  satisfied it, with the member finding ids and a combined-impact score.
* :class:`CorrelationGroup` — findings that share an endpoint or root
  cause, so the report can collapse "the same underlying bug reported five
  ways" into one storyline.
* :class:`VulnerabilityCorrelationEngine` — runs the rules, builds the
  groups, and (reusing the Intelligence Layer's
  :class:`~webshield.core.evidence_graph.EvidenceGraph`) exposes a
  structural graph of finding↔endpoint↔host for the reporters.

The engine never mutates the findings it is handed.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import urlparse

from ..models.vulnerability import Severity, Vulnerability, VulnType

# Severity ordering, worst first — used to escalate and to sort.
_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SEVERITY_SCORE: Dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}


def _host_of(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
        return netloc or url
    except Exception:
        return url


# ─────────────────────────────────────────────────────────────────────────────
# Rules
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ChainRule:
    """
    A declarative attack-chain rule.

    ``all_of`` — every :class:`VulnType` in this set must appear among the
    findings on the same host for the chain to fire (a combination rule).

    ``amplifier`` — when ``True``, ``all_of`` holds exactly one type and the
    rule fires on that single finding to surface a *latent* next step that
    the scan couldn't confirm on its own (lower confidence, "potential").
    """
    id: str
    name: str
    all_of: frozenset
    escalated_severity: Severity
    kill_chain_stage: str
    impact: str
    description: str
    confidence: str = "Firm"
    references: Sequence[str] = ()
    amplifier: bool = False


# Combination chains — two or more distinct weaknesses that together form a
# materially worse exploit than any of them alone.
_COMBINATION_RULES: List[ChainRule] = [
    ChainRule(
        id="ssrf-to-metadata-creds",
        name="SSRF → Cloud Metadata → Credential Theft",
        all_of=frozenset({VulnType.SSRF, VulnType.SECRET_EXPOSURE}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Credential Access",
        impact="An attacker pivots the SSRF to the cloud metadata endpoint (169.254.169.254) "
               "and, combined with already-leaked secrets, obtains long-lived IAM/API "
               "credentials — full cloud-account compromise.",
        description="A confirmed SSRF plus exposed secrets means the metadata service and any "
                    "internal credential store are reachable and the keys to use them are already leaking.",
        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    ),
    ChainRule(
        id="upload-traversal-rce",
        name="File Upload + Path Traversal → Remote Code Execution",
        all_of=frozenset({VulnType.FILE_UPLOAD, VulnType.PATH_TRAVERSAL}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Execution",
        impact="An unrestricted upload whose destination path is attacker-controllable via the "
               "traversal lets a webshell be written inside the web root and executed — RCE.",
        description="Upload validation gaps and a path-traversal on the same host combine into "
                    "write-anywhere, turning a file drop into code execution.",
        references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
    ),
    ChainRule(
        id="lfi-logpoison-rce",
        name="Path Traversal/LFI + Injection → Log Poisoning RCE",
        all_of=frozenset({VulnType.LFI, VulnType.CMDI}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Execution",
        impact="Local file inclusion reachable alongside injectable sinks allows log/session "
               "poisoning to be included and executed as code.",
        description="An LFI that can include attacker-influenced files (logs, sessions) next to a "
                    "command sink is a classic path to server-side code execution.",
    ),
    ChainRule(
        id="xss-csrf-takeover",
        name="XSS + CSRF → Session/Account Takeover",
        all_of=frozenset({VulnType.XSS, VulnType.CSRF}),
        escalated_severity=Severity.HIGH,
        kill_chain_stage="Lateral Movement",
        impact="Stored/reflected XSS with no CSRF protection lets a single crafted page run "
               "authenticated state-changing actions and exfiltrate session material — account takeover.",
        description="Client-side script execution plus missing anti-CSRF defences means an attacker "
                    "can act fully as the victim.",
    ),
    ChainRule(
        id="idor-auth-massdata",
        name="IDOR/BOLA + Broken Authentication → Mass Data Exposure",
        all_of=frozenset({VulnType.IDOR, VulnType.BROKEN_AUTH}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Collection",
        impact="Object references that aren't authorization-checked, reachable once weak "
               "authentication is bypassed, allow enumeration of every other user's records.",
        description="Broken object-level authorization behind a weak auth boundary scales a single "
                    "record leak into a full-database exposure.",
    ),
    ChainRule(
        id="bola-auth-massdata",
        name="BOLA + Broken Authentication → Mass Data Exposure",
        all_of=frozenset({VulnType.BOLA, VulnType.BROKEN_AUTH}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Collection",
        impact="API object-level authorization gaps behind weak authentication permit bulk "
               "cross-tenant data extraction.",
        description="BOLA on API objects combined with a bypassable auth layer scales into "
                    "cross-account data theft.",
    ),
    ChainRule(
        id="sqli-auth-fulldb",
        name="SQL Injection + Broken Authentication → Full Database Compromise",
        all_of=frozenset({VulnType.SQLI, VulnType.BROKEN_AUTH}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Collection",
        impact="SQL injection dumps the credential store; the weak authentication layer means the "
               "recovered hashes/tokens are immediately reusable for full takeover.",
        description="Injection-driven data extraction next to a soft auth boundary lets dumped "
                    "credentials be replayed straight back in.",
    ),
    ChainRule(
        id="xxe-ssrf-internal",
        name="XXE + SSRF → Internal Network Access",
        all_of=frozenset({VulnType.XXE, VulnType.SSRF}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Discovery",
        impact="XML external-entity processing and SSRF together give two independent primitives to "
               "read internal files and reach internal-only services.",
        description="Two server-side request primitives on the same target dramatically widen "
                    "internal reach and file disclosure.",
    ),
    ChainRule(
        id="openredirect-oauth-tokentheft",
        name="Open Redirect + OAuth → Authorization-Code / Token Theft",
        all_of=frozenset({VulnType.OPEN_REDIRECT, VulnType.OAUTH}),
        escalated_severity=Severity.HIGH,
        kill_chain_stage="Credential Access",
        impact="An open redirect on a domain trusted by the OAuth flow lets the authorization code "
               "or access token be leaked to an attacker-controlled endpoint.",
        description="Redirect validation gaps in an OAuth/SSO context turn into full token "
                    "interception.",
    ),
    ChainRule(
        id="cors-xss-exfil",
        name="CORS Misconfiguration + XSS → Cross-Origin Data Exfiltration",
        all_of=frozenset({VulnType.CORS, VulnType.XSS}),
        escalated_severity=Severity.HIGH,
        kill_chain_stage="Exfiltration",
        impact="A permissive CORS policy lets injected script read authenticated cross-origin "
               "responses and stream sensitive data off-site.",
        description="Overly-trusting CORS plus script execution removes the same-origin barrier "
                    "protecting user data.",
    ),
    ChainRule(
        id="jwt-bfla-privesc",
        name="JWT Weakness + BFLA → Privilege Escalation",
        all_of=frozenset({VulnType.JWT, VulnType.BFLA}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Privilege Escalation",
        impact="A forgeable/weak JWT lets an attacker mint an elevated identity, and the missing "
               "function-level checks let that identity invoke admin operations.",
        description="Token-integrity weaknesses next to function-level authorization gaps grant "
                    "self-service admin access.",
    ),
]

# Amplifier chains — a single finding that is, by its nature, one confirmed
# step short of a much larger impact.  Emitted as "potential" so they inform
# without being asserted as fact.
_AMPLIFIER_RULES: List[ChainRule] = [
    ChainRule(
        id="ssrf-metadata-potential",
        name="SSRF → Cloud Metadata Credential Access (potential)",
        all_of=frozenset({VulnType.SSRF}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Credential Access",
        impact="If the target runs in a cloud environment, this SSRF likely reaches the instance "
               "metadata endpoint and can extract IAM credentials.",
        description="Any confirmed SSRF is one request away from the 169.254.169.254 metadata "
                    "service on most cloud providers.",
        confidence="Tentative",
        amplifier=True,
    ),
    ChainRule(
        id="sqli-rce-potential",
        name="SQL Injection → OS Command Execution (potential)",
        all_of=frozenset({VulnType.SQLI}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Execution",
        impact="Depending on DB privileges, this injection may reach xp_cmdshell / "
               "INTO OUTFILE / COPY-TO-PROGRAM primitives and pivot to OS command execution.",
        description="High-privilege database contexts turn SQL injection into a code-execution "
                    "primitive.",
        confidence="Tentative",
        amplifier=True,
    ),
    ChainRule(
        id="ssti-rce-potential",
        name="Template Injection → Remote Code Execution (potential)",
        all_of=frozenset({VulnType.SSTI}),
        escalated_severity=Severity.CRITICAL,
        kill_chain_stage="Execution",
        impact="Most server-side template engines expose sandbox escapes that turn template "
               "injection directly into RCE.",
        description="SSTI in a common engine (Jinja2, Twig, Freemarker, Velocity) is routinely "
                    "escalated to code execution.",
        confidence="Tentative",
        amplifier=True,
    ),
    ChainRule(
        id="upload-rce-potential",
        name="Unrestricted Upload → Web Shell (potential)",
        all_of=frozenset({VulnType.FILE_UPLOAD}),
        escalated_severity=Severity.HIGH,
        kill_chain_stage="Execution",
        impact="If the upload lands in a web-servable, executable location, it becomes a webshell.",
        description="An unrestricted upload is a code-execution risk whenever the stored file is "
                    "reachable and interpretable by the server.",
        confidence="Tentative",
        amplifier=True,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Result records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackChain:
    rule_id: str
    name: str
    severity: Severity
    kill_chain_stage: str
    impact: str
    description: str
    confidence: str
    host: str
    member_finding_ids: List[str]
    member_titles: List[str]
    combined_risk: float
    is_potential: bool = False
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value,
            "kill_chain_stage": self.kill_chain_stage,
            "impact": self.impact,
            "description": self.description,
            "confidence": self.confidence,
            "host": self.host,
            "member_finding_ids": self.member_finding_ids,
            "member_titles": self.member_titles,
            "combined_risk": round(self.combined_risk, 2),
            "is_potential": self.is_potential,
            "references": list(self.references),
        }


@dataclass
class CorrelationGroup:
    """Findings sharing an endpoint (normalised url+method) — likely one story."""
    key: str
    url: str
    method: str
    finding_ids: List[str]
    titles: List[str]
    vuln_types: List[str]

    @property
    def count(self) -> int:
        return len(self.finding_ids)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "url": self.url,
            "method": self.method,
            "finding_ids": self.finding_ids,
            "titles": self.titles,
            "vuln_types": self.vuln_types,
            "count": len(self.finding_ids),
        }


@dataclass
class CorrelationReport:
    chains: List[AttackChain]
    groups: List[CorrelationGroup]
    graph: Dict[str, Any]
    total_findings: int

    @property
    def confirmed_chains(self) -> List[AttackChain]:
        return [c for c in self.chains if not c.is_potential]

    @property
    def highest_chain_risk(self) -> float:
        return max((c.combined_risk for c in self.chains), default=0.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "chain_count": len(self.chains),
            "confirmed_chain_count": len(self.confirmed_chains),
            "highest_chain_risk": round(self.highest_chain_risk, 2),
            "chains": [c.to_dict() for c in self.chains],
            "correlation_groups": [g.to_dict() for g in self.groups],
            "graph": self.graph,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityCorrelationEngine:
    """
    Correlates a flat finding list into attack chains and endpoint groups.

    Stateless across calls — pass the full finding list to :meth:`correlate`.
    """

    def __init__(
        self,
        combination_rules: Optional[Sequence[ChainRule]] = None,
        amplifier_rules: Optional[Sequence[ChainRule]] = None,
        include_potential: bool = True,
    ) -> None:
        self._combo_rules = list(combination_rules) if combination_rules is not None else list(_COMBINATION_RULES)
        self._amp_rules = list(amplifier_rules) if amplifier_rules is not None else list(_AMPLIFIER_RULES)
        self._include_potential = include_potential

    # -- public API -----------------------------------------------------------

    def correlate(self, vulnerabilities: Sequence[Vulnerability]) -> CorrelationReport:
        vulns = list(vulnerabilities)
        by_host = self._group_by_host(vulns)

        chains: List[AttackChain] = []
        covered: Set[str] = set()  # finding ids already inside a confirmed combo chain

        for host, host_vulns in by_host.items():
            present = self._types_present(host_vulns)
            for rule in self._combo_rules:
                if rule.all_of.issubset(present):
                    members = [v for v in host_vulns if v.vuln_type in rule.all_of]
                    if len(members) < 2:
                        continue
                    chains.append(self._build_chain(rule, host, members, is_potential=False))
                    covered.update(v.vuln_id for v in members)

        if self._include_potential:
            for host, host_vulns in by_host.items():
                for rule in self._amp_rules:
                    (only_type,) = tuple(rule.all_of)
                    members = [
                        v for v in host_vulns
                        if v.vuln_type == only_type and v.vuln_id not in covered
                    ]
                    if members:
                        chains.append(self._build_chain(rule, host, members, is_potential=True))

        chains.sort(key=lambda c: (_SEVERITY_RANK[c.severity], c.combined_risk, not c.is_potential), reverse=True)

        groups = self._build_groups(vulns)
        graph = self._build_graph(vulns)
        return CorrelationReport(
            chains=chains,
            groups=groups,
            graph=graph,
            total_findings=len(vulns),
        )

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _group_by_host(vulns: Sequence[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        out: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in vulns:
            out[_host_of(v.url)].append(v)
        return out

    @staticmethod
    def _types_present(vulns: Sequence[Vulnerability]) -> Set[VulnType]:
        return {v.vuln_type for v in vulns}

    def _build_chain(
        self,
        rule: ChainRule,
        host: str,
        members: Sequence[Vulnerability],
        is_potential: bool,
    ) -> AttackChain:
        base = _SEVERITY_SCORE[rule.escalated_severity]
        # A confirmed multi-step chain is worth more than the same rule fired
        # speculatively; extra corroborating members nudge it up, capped at 10.
        breadth_bonus = min(0.3 * (len(members) - 1), 1.0)
        combined = base + breadth_bonus
        if is_potential:
            combined *= 0.7
        combined = round(min(combined, 10.0), 2)
        return AttackChain(
            rule_id=rule.id,
            name=rule.name,
            severity=rule.escalated_severity,
            kill_chain_stage=rule.kill_chain_stage,
            impact=rule.impact,
            description=rule.description,
            confidence=rule.confidence,
            host=host,
            member_finding_ids=[v.vuln_id for v in members],
            member_titles=[v.title for v in members],
            combined_risk=combined,
            is_potential=is_potential,
            references=list(rule.references),
        )

    @staticmethod
    def _build_groups(vulns: Sequence[Vulnerability]) -> List[CorrelationGroup]:
        buckets: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in vulns:
            p = urlparse(v.url)
            key = f"{v.method.upper()} {p.scheme}://{p.netloc}{p.path}"
            buckets[key].append(v)
        groups: List[CorrelationGroup] = []
        for key, items in buckets.items():
            if len(items) < 2:
                continue  # a "group" of one isn't a correlation
            first = items[0]
            p = urlparse(first.url)
            groups.append(CorrelationGroup(
                key=key,
                url=f"{p.scheme}://{p.netloc}{p.path}",
                method=first.method.upper(),
                finding_ids=[v.vuln_id for v in items],
                titles=[v.title for v in items],
                vuln_types=sorted({v.vuln_type.value for v in items}),
            ))
        groups.sort(key=lambda g: len(g.finding_ids), reverse=True)
        return groups

    @staticmethod
    def _build_graph(vulns: Sequence[Vulnerability]) -> Dict[str, Any]:
        """
        Reuse the Intelligence Layer's EvidenceGraph to produce a structural
        finding↔endpoint↔host graph for the reporters.  Best-effort: if the
        graph module can't be imported, fall back to a minimal summary.
        """
        try:
            from ..core.evidence_graph import EvidenceGraph
        except Exception:
            return {"node_count": 0, "edge_count": 0, "nodes": [], "edges": []}

        graph = EvidenceGraph()
        for v in vulns:
            graph.add_finding(v.vuln_id, v.title, severity=v.severity.value, vuln_type=v.vuln_type.value)
            graph.add_endpoint(v.url, method=v.method)
            graph.link_finding_to_endpoint(v.vuln_id, v.url, method=v.method)
            host = _host_of(v.url)
            if host:
                graph.add_asset(host)
                graph.link_endpoint_to_asset(v.url, host, method=v.method)
        graph.infer_relationships()
        return graph.to_dict()


__all__ = [
    "ChainRule",
    "AttackChain",
    "CorrelationGroup",
    "CorrelationReport",
    "VulnerabilityCorrelationEngine",
]
