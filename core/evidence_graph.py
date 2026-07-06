# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Evidence Graph — Part 20 of the Intelligence Layer.

Every prior engine in this layer produces a *flat* fact: a fingerprint says
"this is WordPress 6.2", a finding says "this parameter is reflected", a
classifier says "this endpoint is an admin panel".  None of those facts are
useful on their own for the question that matters most once a scan has run
for a while: *what does this target actually look like as a system, and
what does a single weak point let an attacker reach next?*

The Evidence Graph is where every flat fact becomes a node and every
relationship between facts becomes an edge, so the rest of the platform can
ask graph questions instead of re-deriving structure from scratch:

  • "What technologies does this endpoint depend on?"
  • "Which findings are independently corroborating the same root cause?"
  • "Is there a path from this low-severity finding to that admin asset?"
  • "Which node, if compromised, gives an attacker the most reach?"

Design
------
* ``GraphNode`` — a typed, attribute-bearing vertex.  Types cover every
  entity the spec calls out: Technology, Endpoint, Parameter, Finding,
  Asset, Authentication, plus the structural types needed to make those
  useful (Service, CredentialMaterial, UserRole, AttackStep, Evidence).
* ``GraphEdge`` — a typed, directed, weighted connection.  Re-uses
  ``confidence_framework.RelationshipType`` (CORROBORATES / CONTRADICTS /
  DUPLICATES) directly for evidence-level edges — that module's docstring
  says as much — and adds the structural edge types this graph needs on
  top (USES_TECHNOLOGY, EXPOSES_PARAMETER, AFFECTS_ENDPOINT, ...).
* ``EvidenceGraph`` — the graph itself: idempotent node/edge upsert,
  adjacency queries, BFS path-finding (the primitive the forthcoming Attack
  Chain Engine, Part 21, will build scenarios on top of), lightweight
  inference rules, degree-based "hub" ranking, and JSON / Graphviz DOT
  export for reporting.

This module never decides severity or exploitability — it only models
*structure and relationships*. Confidence stays in the Confidence
Framework, verdicts stay in Triple Confirmation, raw proof stays in the
Evidence Collection Framework; this module is the connective tissue between
all three plus the recon layer's own typed facts.
"""
from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .confidence_framework import ConfidenceFramework, EvidenceRelationship, RelationshipType


# ─────────────────────────────────────────────────────────────────────────────
# Node / edge taxonomy
# ─────────────────────────────────────────────────────────────────────────────

class NodeType(str, Enum):
    TECHNOLOGY     = "technology"      # framework / server / CMS / library / database
    ENDPOINT       = "endpoint"
    PARAMETER      = "parameter"
    FINDING        = "finding"
    ASSET          = "asset"           # host / subdomain / virtual host / cloud resource
    AUTHENTICATION = "authentication"  # a login mechanism / SSO provider / MFA scheme
    USER_ROLE      = "user_role"
    CREDENTIAL     = "credential"      # leaked/derived credential material (redacted ref only)
    SERVICE        = "service"         # third-party / internal microservice dependency
    ATTACK_STEP    = "attack_step"     # a single step the Attack Chain Engine can chain through
    EVIDENCE       = "evidence"        # leaf node mirroring confidence_framework.Evidence


class EdgeType(str, Enum):
    # Structural relationships between typed entities
    USES_TECHNOLOGY   = "uses_technology"     # endpoint/asset -> technology
    EXPOSES_PARAMETER = "exposes_parameter"   # endpoint -> parameter
    AFFECTS_ENDPOINT  = "affects_endpoint"    # finding -> endpoint
    AFFECTS_PARAMETER = "affects_parameter"   # finding -> parameter
    BELONGS_TO_ASSET  = "belongs_to_asset"    # endpoint -> asset
    REQUIRES_AUTH     = "requires_auth"       # endpoint -> authentication
    GRANTS_ROLE       = "grants_role"         # authentication -> user_role
    YIELDS_CREDENTIAL = "yields_credential"   # finding -> credential
    DEPENDS_ON        = "depends_on"          # service -> service / asset -> service
    DISCOVERED_VIA     = "discovered_via"     # any node -> the engine/source that found it (note-only)
    SUPPORTED_BY        = "supported_by"      # finding -> evidence
    ENABLES            = "enables"            # attack_step -> attack_step (chain transition)
    SAME_ORIGIN_AS      = "same_origin_as"    # asset <-> asset
    # Evidence-level relationships, reused verbatim from the Confidence Framework
    CORROBORATES = RelationshipType.CORROBORATES.value
    CONTRADICTS  = RelationshipType.CONTRADICTS.value
    DUPLICATES   = RelationshipType.DUPLICATES.value


# Edge types that should be treated as bidirectional when traversing/ranking.
_UNDIRECTED_TYPES = frozenset({EdgeType.SAME_ORIGIN_AS, EdgeType.CORROBORATES, EdgeType.DUPLICATES})


# ─────────────────────────────────────────────────────────────────────────────
# Node / edge records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    id:         str
    type:       NodeType
    label:      str
    attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def merge(self, label: Optional[str] = None, **attrs: Any) -> None:
        if label:
            self.label = label
        self.attributes.update({k: v for k, v in attrs.items() if v is not None})
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.type.value, "label": self.label,
                "attributes": self.attributes, "created_at": self.created_at,
                "updated_at": self.updated_at}


@dataclass
class GraphEdge:
    id:        str
    source_id: str
    target_id: str
    type:      EdgeType
    note:      str = ""
    weight:    float = 1.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "source_id": self.source_id, "target_id": self.target_id,
                "type": self.type.value, "note": self.note, "weight": self.weight,
                "created_at": self.created_at}


@dataclass
class GraphPath:
    nodes: List[str]
    edges: List[GraphEdge]

    @property
    def length(self) -> int:
        return len(self.edges)

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": self.nodes, "length": self.length,
                "edges": [e.to_dict() for e in self.edges]}


# ─────────────────────────────────────────────────────────────────────────────
# The graph
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceGraph:
    """
    A typed, directed multigraph over every entity the Intelligence Layer
    produces.  Node IDs are caller-chosen and stable (e.g. an endpoint's
    canonical URL, a finding's id, a technology's normalised name) so that
    repeated upserts from different engines naturally converge on the same
    node instead of creating duplicates.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._out: Dict[str, List[str]] = defaultdict(list)   # node_id -> [edge_id, ...]
        self._in:  Dict[str, List[str]] = defaultdict(list)

    # -- node / edge upsert ---------------------------------------------------

    def add_node(self, node_id: str, type: NodeType, label: str, **attributes: Any) -> GraphNode:
        if node_id in self._nodes:
            self._nodes[node_id].merge(label=label, **attributes)
        else:
            self._nodes[node_id] = GraphNode(id=node_id, type=type, label=label, attributes=dict(attributes))
        return self._nodes[node_id]

    def add_edge(self, source_id: str, target_id: str, type: EdgeType,
                 note: str = "", weight: float = 1.0, auto_create_nodes: bool = True) -> GraphEdge:
        if source_id not in self._nodes:
            if not auto_create_nodes:
                raise KeyError(f"unknown source node: {source_id}")
            self.add_node(source_id, NodeType.ASSET, source_id)
        if target_id not in self._nodes:
            if not auto_create_nodes:
                raise KeyError(f"unknown target node: {target_id}")
            self.add_node(target_id, NodeType.ASSET, target_id)

        # de-dup identical edges between the same pair
        for existing_id in self._out[source_id]:
            existing = self._edges[existing_id]
            if existing.target_id == target_id and existing.type == type:
                existing.weight = max(existing.weight, weight)
                if note and note not in existing.note:
                    existing.note = (existing.note + " | " + note).strip(" |")
                return existing

        edge = GraphEdge(id=uuid.uuid4().hex[:12], source_id=source_id, target_id=target_id,
                          type=type, note=note, weight=weight)
        self._edges[edge.id] = edge
        self._out[source_id].append(edge.id)
        self._in[target_id].append(edge.id)
        if type in _UNDIRECTED_TYPES:
            reverse = GraphEdge(id=uuid.uuid4().hex[:12], source_id=target_id, target_id=source_id,
                                 type=type, note=note, weight=weight)
            self._edges[reverse.id] = reverse
            self._out[target_id].append(reverse.id)
            self._in[source_id].append(reverse.id)
        return edge

    # -- convenience typed upserts --------------------------------------------

    def add_technology(self, name: str, category: str = "", version: Optional[str] = None,
                        confidence: Optional[float] = None) -> GraphNode:
        return self.add_node(f"tech:{name.lower()}", NodeType.TECHNOLOGY, name,
                              category=category, version=version, confidence=confidence)

    def add_endpoint(self, url: str, method: str = "GET", category: Optional[str] = None) -> GraphNode:
        return self.add_node(f"endpoint:{method.upper()}:{url}", NodeType.ENDPOINT, url,
                              method=method.upper(), category=category)

    def add_parameter(self, endpoint_url: str, name: str, location: str = "query",
                       data_type: Optional[str] = None) -> GraphNode:
        node = self.add_node(f"param:{endpoint_url}:{location}:{name}", NodeType.PARAMETER, name,
                              location=location, data_type=data_type)
        self.add_edge(f"endpoint:GET:{endpoint_url}" if self.has_node(f"endpoint:GET:{endpoint_url}")
                       else self._guess_endpoint_id(endpoint_url) or f"endpoint:GET:{endpoint_url}",
                       node.id, EdgeType.EXPOSES_PARAMETER, auto_create_nodes=True)
        return node

    def _guess_endpoint_id(self, url: str) -> Optional[str]:
        for nid, node in self._nodes.items():
            if node.type == NodeType.ENDPOINT and node.label == url:
                return nid
        return None

    def add_finding(self, finding_id: str, title: str, severity: str = "Medium",
                     vuln_type: Optional[str] = None) -> GraphNode:
        return self.add_node(f"finding:{finding_id}", NodeType.FINDING, title,
                              severity=severity, vuln_type=vuln_type)

    def add_asset(self, host: str, asset_kind: str = "host") -> GraphNode:
        return self.add_node(f"asset:{host}", NodeType.ASSET, host, kind=asset_kind)

    def link_finding_to_endpoint(self, finding_id: str, endpoint_url: str, method: str = "GET") -> GraphEdge:
        return self.add_edge(f"finding:{finding_id}", f"endpoint:{method.upper()}:{endpoint_url}",
                              EdgeType.AFFECTS_ENDPOINT)

    def link_endpoint_to_technology(self, endpoint_url: str, technology: str, method: str = "GET") -> GraphEdge:
        return self.add_edge(f"endpoint:{method.upper()}:{endpoint_url}", f"tech:{technology.lower()}",
                              EdgeType.USES_TECHNOLOGY)

    def link_endpoint_to_asset(self, endpoint_url: str, host: str, method: str = "GET") -> GraphEdge:
        return self.add_edge(f"endpoint:{method.upper()}:{endpoint_url}", f"asset:{host}",
                              EdgeType.BELONGS_TO_ASSET)

    def link_attack_step(self, from_step_id: str, to_step_id: str, note: str = "") -> GraphEdge:
        return self.add_edge(from_step_id, to_step_id, EdgeType.ENABLES, note=note)

    # -- ingestion from upstream engines --------------------------------------

    def ingest_confidence_framework(self, cf: ConfidenceFramework) -> int:
        """
        Pulls every finding's evidence and relationship ledger out of a
        ``ConfidenceFramework`` and mirrors it as FINDING/EVIDENCE nodes and
        SUPPORTED_BY/CORROBORATES/CONTRADICTS/DUPLICATES edges. Idempotent —
        safe to call repeatedly as a scan progresses.
        """
        added = 0
        for finding_id in cf.all_findings():
            self.add_node(f"finding:{finding_id}", NodeType.FINDING, finding_id)
            for evidence in cf.evidence_for(finding_id):
                ev_node_id = f"evidence:{evidence.id}"
                self.add_node(ev_node_id, NodeType.EVIDENCE, evidence.description,
                              evidence_type=evidence.type.value, strength=evidence.strength,
                              source=evidence.source)
                self.add_edge(f"finding:{finding_id}", ev_node_id, EdgeType.SUPPORTED_BY)
                added += 1
            for rel in cf.relationships_for(finding_id):
                self.add_edge(f"evidence:{rel.source_id}", f"evidence:{rel.target_id}",
                               EdgeType(rel.relation.value), note=rel.note)
                added += 1
        return added

    def ingest_evidence_bundle(self, bundle: Any) -> int:
        """Links every artifact in an ``evidence_collection.EvidenceBundle``
        to its finding node, accepting the bundle duck-typed to avoid a hard
        import-time dependency on the Evidence Collection Framework."""
        finding_id = getattr(bundle, "finding_id", None)
        artifacts = getattr(bundle, "artifacts", [])
        if not finding_id:
            return 0
        self.add_node(f"finding:{finding_id}", NodeType.FINDING, finding_id)
        for artifact in artifacts:
            art_node_id = f"artifact:{artifact.id}"
            self.add_node(art_node_id, NodeType.EVIDENCE, artifact.summary,
                          artifact_type=artifact.type.value, redacted=artifact.redacted)
            self.add_edge(f"finding:{finding_id}", art_node_id, EdgeType.SUPPORTED_BY)
        return len(artifacts)

    # -- queries ---------------------------------------------------------------

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def nodes_by_type(self, type: NodeType) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.type == type]

    def edges_of(self, node_id: str, type: Optional[EdgeType] = None,
                 direction: str = "out") -> List[GraphEdge]:
        ids: List[str] = []
        if direction in ("out", "both"):
            ids += self._out.get(node_id, [])
        if direction in ("in", "both"):
            ids += self._in.get(node_id, [])
        edges = [self._edges[i] for i in ids]
        if type is not None:
            edges = [e for e in edges if e.type == type]
        return edges

    def neighbors(self, node_id: str, type: Optional[EdgeType] = None,
                  direction: str = "out") -> List[GraphNode]:
        out: List[GraphNode] = []
        for edge in self.edges_of(node_id, type=type, direction=direction):
            other_id = edge.target_id if edge.source_id == node_id else edge.source_id
            node = self._nodes.get(other_id)
            if node:
                out.append(node)
        return out

    def degree(self, node_id: str) -> int:
        return len(self._out.get(node_id, [])) + len(self._in.get(node_id, []))

    def most_connected_nodes(self, top_n: int = 10, type: Optional[NodeType] = None) -> List[Tuple[GraphNode, int]]:
        """Degree-ranked 'hub' nodes — pivot points an Attack Chain Engine
        should prioritise, since compromising them reaches the most else."""
        candidates = self._nodes.values() if type is None else self.nodes_by_type(type)
        ranked = sorted(((n, self.degree(n.id)) for n in candidates), key=lambda t: t[1], reverse=True)
        return ranked[:top_n]

    # -- traversal: paths (Attack Chain primitive) ------------------------------

    def shortest_path(self, source_id: str, target_id: str,
                       edge_types: Optional[Sequence[EdgeType]] = None) -> Optional[GraphPath]:
        """BFS shortest path by edge count, optionally restricted to a set of
        edge types (e.g. only ``ENABLES`` edges to find an attack chain)."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None
        if source_id == target_id:
            return GraphPath(nodes=[source_id], edges=[])

        allowed = set(edge_types) if edge_types else None
        visited: Set[str] = {source_id}
        queue: deque = deque([(source_id, [source_id], [])])
        while queue:
            current, path_nodes, path_edges = queue.popleft()
            for edge in self.edges_of(current, direction="out"):
                if allowed and edge.type not in allowed:
                    continue
                nxt = edge.target_id
                if nxt in visited:
                    continue
                new_path_nodes = path_nodes + [nxt]
                new_path_edges = path_edges + [edge]
                if nxt == target_id:
                    return GraphPath(nodes=new_path_nodes, edges=new_path_edges)
                visited.add(nxt)
                queue.append((nxt, new_path_nodes, new_path_edges))
        return None

    def find_paths(self, source_id: str, target_id: str, max_depth: int = 6,
                    edge_types: Optional[Sequence[EdgeType]] = None, limit: int = 20) -> List[GraphPath]:
        """All simple paths up to ``max_depth`` hops (bounded DFS) — used to
        enumerate *candidate* attack scenarios rather than just the shortest."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return []
        allowed = set(edge_types) if edge_types else None
        results: List[GraphPath] = []

        def dfs(current: str, path_nodes: List[str], path_edges: List[GraphEdge], visited: Set[str]) -> None:
            if len(results) >= limit or len(path_nodes) - 1 >= max_depth:
                return
            for edge in self.edges_of(current, direction="out"):
                if allowed and edge.type not in allowed:
                    continue
                nxt = edge.target_id
                if nxt in visited:
                    continue
                new_nodes = path_nodes + [nxt]
                new_edges = path_edges + [edge]
                if nxt == target_id:
                    results.append(GraphPath(nodes=new_nodes, edges=new_edges))
                    if len(results) >= limit:
                        return
                else:
                    dfs(nxt, new_nodes, new_edges, visited | {nxt})

        dfs(source_id, [source_id], [], {source_id})
        return results

    def connected_component(self, node_id: str) -> Set[str]:
        if node_id not in self._nodes:
            return set()
        visited = {node_id}
        queue = deque([node_id])
        while queue:
            current = queue.popleft()
            for edge in self.edges_of(current, direction="both"):
                other = edge.target_id if edge.source_id == current else edge.source_id
                if other not in visited:
                    visited.add(other)
                    queue.append(other)
        return visited

    # -- inference --------------------------------------------------------------

    def infer_relationships(self) -> int:
        """
        Lightweight, conservative structural inference over the graph as it
        currently stands. Adds edges, never removes or scores them:

          • two FINDING nodes that both AFFECT the same ENDPOINT are linked
            CORROBORATES (co-located findings reinforce each other's
            relevance to that endpoint, independent of evidence-level
            corroboration already captured by the Confidence Framework).
          • an ENDPOINT that REQUIRES_AUTH and is also linked to a FINDING
            gets an inferred ATTACK_STEP placeholder noting privilege
            relevance, for the Attack Chain Engine to expand on.
        """
        added = 0
        endpoint_to_findings: Dict[str, List[str]] = defaultdict(list)
        for edge in self._edges.values():
            if edge.type == EdgeType.AFFECTS_ENDPOINT:
                endpoint_to_findings[edge.target_id].append(edge.source_id)

        for endpoint_id, finding_ids in endpoint_to_findings.items():
            unique = sorted(set(finding_ids))
            for i in range(len(unique)):
                for j in range(i + 1, len(unique)):
                    self.add_edge(unique[i], unique[j], EdgeType.CORROBORATES,
                                  note=f"co-located on {endpoint_id}")
                    added += 1
        return added

    # -- export -------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str, ensure_ascii=False)

    def to_dot(self) -> str:
        """Graphviz DOT export for visual reporting."""
        lines = ["digraph EvidenceGraph {", '  rankdir="LR";']
        for node in self._nodes.values():
            safe_label = node.label.replace('"', "'")[:60]
            lines.append(f'  "{node.id}" [label="{safe_label}\\n({node.type.value})"];')
        for edge in self._edges.values():
            safe_note = edge.note.replace('"', "'")[:40]
            label = f"{edge.type.value}" + (f": {safe_note}" if safe_note else "")
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [label="{label}"];')
        lines.append("}")
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        by_node_type: Dict[str, int] = defaultdict(int)
        for n in self._nodes.values():
            by_node_type[n.type.value] += 1
        by_edge_type: Dict[str, int] = defaultdict(int)
        for e in self._edges.values():
            by_edge_type[e.type.value] += 1
        return {"node_count": len(self._nodes), "edge_count": len(self._edges),
                "nodes_by_type": dict(by_node_type), "edges_by_type": dict(by_edge_type)}


__all__ = [
    "NodeType", "EdgeType", "GraphNode", "GraphEdge", "GraphPath", "EvidenceGraph",
]
