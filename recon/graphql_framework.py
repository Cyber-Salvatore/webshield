"""
GraphQL Framework — Part 9 of the Intelligence Layer.

A dedicated reconnaissance and mapping framework for GraphQL APIs that
operates *before* any exploitation attempts begin.  Its sole purpose is to
build the most complete picture of the target's GraphQL surface so that all
downstream scanners receive rich, structured context instead of raw URLs.

Capabilities
------------
Schema Discovery (direct & indirect)
  • Full introspection (standard + legacy ``_schema`` endpoints)
  • Partial-introspection when ``__schema`` is disabled but ``__type`` works
  • Field-suggestion extraction (Apollo, Hasura, Strawberry error messages)
  • Schema stitching detection (federated / gateway patterns)
  • SDL recovery from public endpoints and JS bundles

Operation Inventory
  • Query / Mutation / Subscription enumeration with argument trees
  • Directive inventory (``@deprecated``, custom directives, skip/include)
  • Fragment and alias detection in persisted-query stores

Type System Analysis
  • Scalar, Enum, Union, Interface, Input, Object type mapping
  • Nullable vs. required field classification
  • Recursive type resolution (circular reference detection)
  • Custom scalar identification (``Date``, ``JSON``, ``Upload``, ``BigInt``)

Transport & Auth Fingerprinting
  • HTTP and WebSocket transport detection (``graphql-ws``, ``subscriptions-transport-ws``)
  • Persisted query support probing (APQ, Relay)
  • Authentication header extraction from JS analysis context
  • Batching capability detection

Endpoint Enumeration
  • 30+ common GraphQL path variants
  • Content-type sniffing (``application/graphql``, ``application/json``)
  • Playground / GraphiQL / Altair detection

All results are emitted as structured ``GraphQLSchema``, ``GraphQLType``,
``GraphQLField``, and ``GraphQLOperation`` objects that are stored in the
Knowledge Base and consumed by the GraphQL scanner, the Endpoint
Classification Engine, and the Context-Aware Payload Framework.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..core.http_client import HTTPClient, HTTPResponse
from ..core.target import ScanTarget
from ..utils.helpers import normalize_url

logger = logging.getLogger(__name__)


# ===========================================================================
# Constants
# ===========================================================================

#: Common GraphQL endpoint paths to probe (ordered by popularity)
_GQL_PATHS: List[str] = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
    "/graph",
    "/api/graph",
    "/graphql/v1",
    "/graphql/v2",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/hasura/v1/graphql",
    "/console",
    "/playground",
    "/altair",
    "/graphql-playground",
    "/admin/graphql",
    "/internal/graphql",
    "/public/graphql",
    "/data",
    "/data/graphql",
    "/relay",
    "/graphql/ide",
    "/explorer",
    "/graphql/explorer",
    "/__graphql",
]

#: Content-type values that indicate a GraphQL endpoint
_GQL_CONTENT_TYPES: Set[str] = {
    "application/graphql",
    "application/graphql+json",
    "application/json",
}

#: Minimal introspection query — tests whether introspection is enabled
_INTROSPECT_PROBE = '{"query": "{ __schema { queryType { name } } }"}'

#: Full introspection query — retrieves the complete schema
_INTROSPECT_FULL = """{
  "query": "query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        locations
        args { ...InputValue }
      }
    }
  }
  fragment FullType on __Type {
    kind name description
    fields(includeDeprecated: true) {
      name description isDeprecated deprecationReason
      args { ...InputValue }
      type { ...TypeRef }
    }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
    possibleTypes { ...TypeRef }
  }
  fragment InputValue on __InputValue {
    name description
    type { ...TypeRef }
    defaultValue
  }
  fragment TypeRef on __Type {
    kind name
    ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
  }"
}"""

#: Single-type introspection for partial-introspection fallback
_TYPE_PROBE_TMPL = '{{"query": "{{ __type(name: \\"{name}\\") {{ name kind fields {{ name type {{ name kind }} }} }} }}"}}'

#: Probe to detect field suggestion leakage (Apollo-style)
_SUGGESTION_PROBE = '{"query": "{ __suggestionsEnabled }"}'

#: Probe for persisted query (APQ) support
_APQ_PROBE = (
    '{"extensions": {"persistedQuery": {"version": 1,'
    '"sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000"}}}'
)

#: Regex patterns for suggestion-based field leakage (Apollo error messages)
_SUGGESTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"Did you mean ['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]"),
    re.compile(r"Cannot query field ['\"]([^'\"]+)['\"] on type ['\"]([^'\"]+)['\"]"),
    re.compile(r"Unknown argument ['\"]([^'\"]+)['\"] on field"),
    re.compile(r"Field ['\"]([^'\"]+)['\"] of type ['\"]([^'\"]+)['\"] must have"),
]

#: Regex to detect playground HTML payloads
_PLAYGROUND_RE = re.compile(
    r"(GraphiQL|graphql-playground|ApolloPlayground|Altair|"
    r"graphql-ide|graphql explorer|<title>GraphQL)",
    re.I,
)

#: WebSocket GraphQL sub-protocol headers
_WS_SUBPROTOCOLS: List[str] = [
    "graphql-transport-ws",          # graphql-ws (current)
    "graphql-ws",                    # subscriptions-transport-ws (legacy)
]

#: Built-in GraphQL scalar types (excluded from custom-scalar reporting)
_BUILTIN_SCALARS: Set[str] = {"String", "Int", "Float", "Boolean", "ID"}

#: Internal introspection types (filtered from user-visible types)
_INTROSPECTION_TYPES: Set[str] = {
    "__Schema", "__Type", "__Field", "__InputValue",
    "__EnumValue", "__Directive", "__DirectiveLocation",
}


# ===========================================================================
# Data Models
# ===========================================================================

class GQLKind(str, Enum):
    """GraphQL type kinds as returned by introspection."""
    SCALAR       = "SCALAR"
    OBJECT       = "OBJECT"
    INTERFACE    = "INTERFACE"
    UNION        = "UNION"
    ENUM         = "ENUM"
    INPUT_OBJECT = "INPUT_OBJECT"
    LIST         = "LIST"
    NON_NULL     = "NON_NULL"


class OperationType(str, Enum):
    """GraphQL operation types."""
    QUERY        = "query"
    MUTATION     = "mutation"
    SUBSCRIPTION = "subscription"


class TransportType(str, Enum):
    """GraphQL transport protocols detected on the target."""
    HTTP      = "http"
    WEBSOCKET = "websocket"
    SSE       = "sse"


class IntrospectionMode(Enum):
    """How the schema was obtained."""
    FULL         = auto()   # __schema introspection worked
    PARTIAL      = auto()   # __type worked; __schema disabled
    SUGGESTION   = auto()   # Only field suggestions from errors
    UNAVAILABLE  = auto()   # Could not retrieve schema


@dataclass
class GQLTypeRef:
    """A possibly-wrapped type reference (NON_NULL / LIST wrappers)."""
    kind:    GQLKind
    name:    Optional[str]          = None
    of_type: Optional[GQLTypeRef]   = None

    def unwrap(self) -> Optional[str]:
        """Return the innermost named type, stripping all wrappers."""
        if self.name:
            return self.name
        if self.of_type:
            return self.of_type.unwrap()
        return None

    def __str__(self) -> str:
        if self.kind == GQLKind.NON_NULL:
            return f"{self.of_type}!"
        if self.kind == GQLKind.LIST:
            return f"[{self.of_type}]"
        return self.name or "Unknown"


@dataclass
class GQLArgument:
    """An argument on a field or directive."""
    name:          str
    type:          GQLTypeRef
    default_value: Optional[str] = None
    description:   Optional[str] = None

    @property
    def is_required(self) -> bool:
        return self.type.kind == GQLKind.NON_NULL


@dataclass
class GQLField:
    """A single field within a GraphQL Object or Interface type."""
    name:                str
    type:                GQLTypeRef
    args:                List[GQLArgument]   = field(default_factory=list)
    description:         Optional[str]       = None
    is_deprecated:       bool                = False
    deprecation_reason:  Optional[str]       = None

    @property
    def is_mutation_like(self) -> bool:
        """Heuristic: field name suggests a write operation."""
        return bool(re.match(
            r"^(create|update|delete|remove|add|set|patch|upsert|merge|"
            r"insert|put|post|modify|change|replace|reset|toggle)",
            self.name, re.I,
        ))

    @property
    def returns_nullable(self) -> bool:
        return self.type.kind != GQLKind.NON_NULL


@dataclass
class GQLEnumValue:
    """A single value in a GraphQL Enum type."""
    name:               str
    description:        Optional[str] = None
    is_deprecated:      bool          = False
    deprecation_reason: Optional[str] = None


@dataclass
class GQLType:
    """A fully-resolved GraphQL type from introspection."""
    kind:          GQLKind
    name:          str
    description:   Optional[str]       = None
    fields:        List[GQLField]       = field(default_factory=list)
    input_fields:  List[GQLArgument]    = field(default_factory=list)
    interfaces:    List[str]            = field(default_factory=list)
    possible_types: List[str]           = field(default_factory=list)
    enum_values:   List[GQLEnumValue]   = field(default_factory=list)

    @property
    def is_builtin(self) -> bool:
        return self.name.startswith("__") or self.name in _BUILTIN_SCALARS

    @property
    def is_custom_scalar(self) -> bool:
        return (
            self.kind == GQLKind.SCALAR
            and self.name not in _BUILTIN_SCALARS
        )

    @property
    def writable_fields(self) -> List[GQLField]:
        """Fields that accept arguments (potential injection points)."""
        return [f for f in self.fields if f.args]

    @property
    def deprecated_fields(self) -> List[GQLField]:
        return [f for f in self.fields if f.is_deprecated]


@dataclass
class GQLOperation:
    """A top-level operation extracted from the schema root types."""
    operation_type: OperationType
    name:           str
    type:           GQLTypeRef
    args:           List[GQLArgument]  = field(default_factory=list)
    description:    Optional[str]      = None
    is_deprecated:  bool               = False

    @property
    def is_dangerous(self) -> bool:
        """Heuristic: name suggests sensitive capability."""
        return bool(re.search(
            r"(delete|drop|purge|admin|root|sudo|superuser|"
            r"impersonat|bypass|debug|exec|system|command)",
            self.name, re.I,
        ))

    @property
    def requires_auth_heuristic(self) -> bool:
        """Heuristic based on field name patterns."""
        return bool(re.search(
            r"(user|account|profile|admin|token|secret|"
            r"password|billing|payment|order|private)",
            self.name, re.I,
        ))


@dataclass
class GQLDirective:
    """A GraphQL directive (built-in or custom)."""
    name:        str
    locations:   List[str]           = field(default_factory=list)
    args:        List[GQLArgument]   = field(default_factory=list)
    description: Optional[str]       = None

    @property
    def is_builtin(self) -> bool:
        return self.name in {"skip", "include", "deprecated", "specifiedBy"}


@dataclass
class GQLEndpoint:
    """A discovered GraphQL endpoint with transport metadata."""
    url:                  str
    transport:            TransportType               = TransportType.HTTP
    introspection_mode:   IntrospectionMode           = IntrospectionMode.UNAVAILABLE
    playground_exposed:   bool                        = False
    batching_supported:   bool                        = False
    apq_supported:        bool                        = False
    subscriptions_url:    Optional[str]               = None
    ws_subprotocol:       Optional[str]               = None
    auth_required:        bool                        = False
    detected_engine:      Optional[str]               = None  # Apollo, Hasura, etc.
    response_time_ms:     float                       = 0.0
    raw_introspection:    Optional[Dict[str, Any]]    = None

    @property
    def is_fully_mapped(self) -> bool:
        return self.introspection_mode == IntrospectionMode.FULL

    @property
    def risk_level(self) -> str:
        if self.playground_exposed and self.introspection_mode == IntrospectionMode.FULL:
            return "CRITICAL"
        if self.introspection_mode == IntrospectionMode.FULL:
            return "HIGH"
        if self.playground_exposed:
            return "MEDIUM"
        return "LOW"


@dataclass
class GraphQLSchema:
    """Complete reconstructed GraphQL schema for a target."""
    endpoint:        GQLEndpoint
    types:           Dict[str, GQLType]       = field(default_factory=dict)
    queries:         List[GQLOperation]       = field(default_factory=list)
    mutations:       List[GQLOperation]       = field(default_factory=list)
    subscriptions:   List[GQLOperation]       = field(default_factory=list)
    directives:      List[GQLDirective]       = field(default_factory=list)
    discovered_at:   float                    = field(default_factory=time.time)
    # Extra metadata populated during analysis
    custom_scalars:  List[str]                = field(default_factory=list)
    union_types:     List[str]                = field(default_factory=list)
    interface_types: List[str]                = field(default_factory=list)
    suggested_fields: Dict[str, List[str]]   = field(default_factory=dict)

    # -----------------------------------------------------------------------
    # Derived properties
    # -----------------------------------------------------------------------

    @property
    def operation_count(self) -> int:
        return len(self.queries) + len(self.mutations) + len(self.subscriptions)

    @property
    def dangerous_mutations(self) -> List[GQLOperation]:
        return [m for m in self.mutations if m.is_dangerous]

    @property
    def unauthenticated_mutations(self) -> List[GQLOperation]:
        """Mutations that appear NOT to require auth (heuristic)."""
        return [m for m in self.mutations if not m.requires_auth_heuristic]

    @property
    def injection_surface(self) -> List[Tuple[str, GQLField]]:
        """All (type_name, field) pairs that accept arguments."""
        surface: List[Tuple[str, GQLField]] = []
        for type_name, gql_type in self.types.items():
            if gql_type.is_builtin:
                continue
            for f in gql_type.writable_fields:
                surface.append((type_name, f))
        return surface

    @property
    def user_types(self) -> Dict[str, GQLType]:
        """Non-introspection, non-builtin types."""
        return {k: v for k, v in self.types.items() if not v.is_builtin}

    def summary(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint.url,
            "introspection_mode": self.endpoint.introspection_mode.name,
            "playground_exposed": self.endpoint.playground_exposed,
            "batching": self.endpoint.batching_supported,
            "apq": self.endpoint.apq_supported,
            "engine": self.endpoint.detected_engine,
            "queries": len(self.queries),
            "mutations": len(self.mutations),
            "subscriptions": len(self.subscriptions),
            "types": len(self.user_types),
            "custom_scalars": self.custom_scalars,
            "dangerous_mutations": [m.name for m in self.dangerous_mutations],
            "injection_surface_count": len(self.injection_surface),
            "risk_level": self.endpoint.risk_level,
        }


# ===========================================================================
# Type-reference parser
# ===========================================================================

def _parse_type_ref(raw: Optional[Dict[str, Any]]) -> GQLTypeRef:
    """Recursively parse a ``__Type`` dict into a ``GQLTypeRef``."""
    if raw is None:
        return GQLTypeRef(kind=GQLKind.SCALAR, name="Unknown")
    kind = GQLKind(raw.get("kind", "SCALAR"))
    name = raw.get("name")
    of_type_raw = raw.get("ofType")
    of_type = _parse_type_ref(of_type_raw) if of_type_raw else None
    return GQLTypeRef(kind=kind, name=name, of_type=of_type)


def _parse_argument(raw: Dict[str, Any]) -> GQLArgument:
    return GQLArgument(
        name=raw.get("name", ""),
        type=_parse_type_ref(raw.get("type")),
        default_value=raw.get("defaultValue"),
        description=raw.get("description"),
    )


def _parse_field(raw: Dict[str, Any]) -> GQLField:
    return GQLField(
        name=raw.get("name", ""),
        type=_parse_type_ref(raw.get("type")),
        args=[_parse_argument(a) for a in (raw.get("args") or [])],
        description=raw.get("description"),
        is_deprecated=raw.get("isDeprecated", False),
        deprecation_reason=raw.get("deprecationReason"),
    )


def _parse_enum_value(raw: Dict[str, Any]) -> GQLEnumValue:
    return GQLEnumValue(
        name=raw.get("name", ""),
        description=raw.get("description"),
        is_deprecated=raw.get("isDeprecated", False),
        deprecation_reason=raw.get("deprecationReason"),
    )


def _parse_type(raw: Dict[str, Any]) -> Optional[GQLType]:
    """Parse a ``__Type`` object from full introspection into a ``GQLType``."""
    if not raw or not raw.get("name"):
        return None
    try:
        kind = GQLKind(raw.get("kind", "SCALAR"))
    except ValueError:
        return None

    return GQLType(
        kind=kind,
        name=raw["name"],
        description=raw.get("description"),
        fields=[_parse_field(f) for f in (raw.get("fields") or [])],
        input_fields=[_parse_argument(a) for a in (raw.get("inputFields") or [])],
        interfaces=[
            _parse_type_ref(i).unwrap() or ""
            for i in (raw.get("interfaces") or [])
        ],
        possible_types=[
            _parse_type_ref(t).unwrap() or ""
            for t in (raw.get("possibleTypes") or [])
        ],
        enum_values=[_parse_enum_value(e) for e in (raw.get("enumValues") or [])],
    )


def _parse_directive(raw: Dict[str, Any]) -> GQLDirective:
    return GQLDirective(
        name=raw.get("name", ""),
        locations=raw.get("locations") or [],
        args=[_parse_argument(a) for a in (raw.get("args") or [])],
        description=raw.get("description"),
    )


# ===========================================================================
# Engine Detection
# ===========================================================================

_ENGINE_SIGNATURES: List[Tuple[str, re.Pattern]] = [
    ("Apollo Server",       re.compile(r"ApolloServer|x-apollo-trace|QUERY_EXCEEDED", re.I)),
    ("Hasura",              re.compile(r"hasura|x-hasura-|HGE[0-9]+", re.I)),
    ("AWS AppSync",         re.compile(r"appsync|x-amzn-requestid", re.I)),
    ("GraphQL Yoga",        re.compile(r"graphql-yoga|Envelop", re.I)),
    ("Strawberry",          re.compile(r"strawberry", re.I)),
    ("Ariadne",             re.compile(r"ariadne", re.I)),
    ("Lighthouse (PHP)",    re.compile(r"lighthouse", re.I)),
    ("WPGraphQL",           re.compile(r"WPGraphQL|wordpress", re.I)),
    ("Shopify GraphQL",     re.compile(r"X-Shopify", re.I)),
    ("GitHub GraphQL",      re.compile(r"github.com|x-github-", re.I)),
    ("Relay Compiler",      re.compile(r"__relay", re.I)),
    ("DGGraph / Dgraph",    re.compile(r"dgraph", re.I)),
    ("Fauna",               re.compile(r"fauna|faunadb", re.I)),
    ("Prisma",              re.compile(r"prisma", re.I)),
    ("PostGraphile",        re.compile(r"postgraphile|x-graphql-event-stream", re.I)),
]


def _detect_engine(response_text: str, headers: Dict[str, str]) -> Optional[str]:
    """Return the best-guess engine name from response body + headers."""
    combined = response_text + " " + " ".join(headers.values())
    for engine_name, pattern in _ENGINE_SIGNATURES:
        if pattern.search(combined):
            return engine_name
    return None


# ===========================================================================
# GraphQL Framework (main class)
# ===========================================================================

class GraphQLFramework:
    """
    Discover, enumerate, and structurally map every GraphQL API exposed
    by the scan target.

    Usage::

        framework = GraphQLFramework(client, target)
        schemas = await framework.run()
        for schema in schemas:
            print(schema.summary())
    """

    def __init__(
        self,
        client:  HTTPClient,
        target:  ScanTarget,
        *,
        timeout:             float = 15.0,
        max_suggestion_iters: int  = 5,
        concurrency:         int   = 8,
    ) -> None:
        self._client    = client
        self._target    = target
        self._timeout   = timeout
        self._max_sugg  = max_suggestion_iters
        self._semaphore = asyncio.Semaphore(concurrency)
        self._base_url  = target.base_url.rstrip("/")
        self._headers:  Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept":       "application/json, */*",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> List[GraphQLSchema]:
        """
        Full discovery pipeline.  Returns one ``GraphQLSchema`` per
        confirmed GraphQL endpoint found on the target.
        """
        endpoints = await self._discover_endpoints()
        logger.info("[GraphQL] Found %d candidate endpoint(s)", len(endpoints))

        schemas: List[GraphQLSchema] = []
        tasks = [self._analyse_endpoint(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for ep, result in zip(endpoints, results):
            if isinstance(result, Exception):
                logger.debug("[GraphQL] Error analysing %s: %s", ep, result)
                continue
            if result is not None:
                schemas.append(result)

        logger.info("[GraphQL] Mapped %d GraphQL schema(s)", len(schemas))
        return schemas

    # ------------------------------------------------------------------
    # Step 1 — Endpoint discovery
    # ------------------------------------------------------------------

    async def _discover_endpoints(self) -> List[str]:
        """Return a de-duplicated list of confirmed GraphQL endpoint URLs."""
        candidates = [f"{self._base_url}{path}" for path in _GQL_PATHS]

        tasks = [self._probe_endpoint(url) for url in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        confirmed: List[str] = []
        seen: Set[str] = set()
        for url, result in zip(candidates, results):
            if isinstance(result, bool) and result and url not in seen:
                confirmed.append(url)
                seen.add(url)

        return confirmed

    async def _probe_endpoint(self, url: str) -> bool:
        """
        Send a minimal GraphQL probe and return ``True`` if the response
        looks like a GraphQL endpoint.
        """
        async with self._semaphore:
            try:
                resp = await self._client.post(
                    url,
                    data=_INTROSPECT_PROBE,
                    headers=self._headers,
                    timeout=self._timeout,
                )
                return self._is_graphql_response(resp)
            except Exception:
                return False

    @staticmethod
    def _is_graphql_response(resp: HTTPResponse) -> bool:
        """
        Heuristic detection: a response is GraphQL if it carries JSON with
        a ``data`` or ``errors`` key at the root, or if its content-type
        signals GraphQL.
        """
        if resp is None or resp.status_code in (404, 405, 501):
            return False

        ct = resp.headers.get("content-type", "").lower()
        if "application/graphql" in ct:
            return True

        body = resp.text or ""
        if _PLAYGROUND_RE.search(body):
            return True

        try:
            payload = json.loads(body)
            return isinstance(payload, dict) and (
                "data" in payload or "errors" in payload
            )
        except (json.JSONDecodeError, ValueError):
            return False

    # ------------------------------------------------------------------
    # Step 2 — Per-endpoint analysis
    # ------------------------------------------------------------------

    async def _analyse_endpoint(self, url: str) -> Optional[GraphQLSchema]:
        """Full analysis pipeline for a single confirmed GraphQL endpoint."""
        endpoint = GQLEndpoint(url=url)

        # --- Engine detection -------------------------------------------
        try:
            resp = await self._client.post(
                url, data=_INTROSPECT_PROBE,
                headers=self._headers, timeout=self._timeout,
            )
            endpoint.detected_engine = _detect_engine(
                resp.text or "", resp.headers or {}
            )
            endpoint.response_time_ms = getattr(resp, "elapsed_ms", 0.0)
        except Exception as exc:
            logger.debug("[GraphQL] Probe failed for %s: %s", url, exc)
            return None

        # --- Playground detection ----------------------------------------
        endpoint.playground_exposed = self._detect_playground(resp)

        # --- Introspection -----------------------------------------------
        schema = await self._try_introspection(endpoint)

        # --- Capability probing ------------------------------------------
        await self._probe_capabilities(endpoint)

        # --- WebSocket subscription detection ----------------------------
        await self._probe_subscriptions(endpoint)

        if schema is None:
            # Build a minimal schema with just endpoint metadata
            schema = GraphQLSchema(endpoint=endpoint)

        # --- Field suggestion extraction (fallback) ----------------------
        if endpoint.introspection_mode in (
            IntrospectionMode.UNAVAILABLE,
            IntrospectionMode.PARTIAL,
        ):
            await self._extract_suggestions(schema)

        # --- Post-processing -------------------------------------------
        self._postprocess_schema(schema)

        return schema

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    async def _try_introspection(
        self, endpoint: GQLEndpoint
    ) -> Optional[GraphQLSchema]:
        """
        Attempt introspection in three modes:
          1. Full ``__schema`` introspection
          2. Partial ``__type`` introspection
          3. Return ``None`` (caller will use suggestion extraction)
        """
        # --- Full introspection -----------------------------------------
        schema = await self._full_introspection(endpoint)
        if schema is not None:
            endpoint.introspection_mode = IntrospectionMode.FULL
            return schema

        # --- Partial introspection (``__type``) -------------------------
        schema = await self._partial_introspection(endpoint)
        if schema is not None:
            endpoint.introspection_mode = IntrospectionMode.PARTIAL
            return schema

        endpoint.introspection_mode = IntrospectionMode.UNAVAILABLE
        return None

    async def _full_introspection(
        self, endpoint: GQLEndpoint
    ) -> Optional[GraphQLSchema]:
        """Attempt the standard full introspection query."""
        try:
            resp = await self._client.post(
                endpoint.url,
                data=_INTROSPECT_FULL,
                headers=self._headers,
                timeout=self._timeout,
            )
            body = json.loads(resp.text or "{}")
        except Exception as exc:
            logger.debug("[GraphQL] Full introspection failed: %s", exc)
            return None

        if "errors" in body and "data" not in body:
            return None
        if not isinstance(body.get("data"), dict):
            return None

        schema_raw = body["data"].get("__schema", {})
        if not schema_raw:
            return None

        endpoint.raw_introspection = schema_raw
        return self._build_schema_from_introspection(endpoint, schema_raw)

    async def _partial_introspection(
        self, endpoint: GQLEndpoint
    ) -> Optional[GraphQLSchema]:
        """
        Probe ``__type`` for known root types when ``__schema`` is blocked.
        This is useful against Hasura and APIs that disable full introspection
        but leave per-type queries enabled.
        """
        root_type_names = ["Query", "Mutation", "Subscription"]
        found_types: Dict[str, GQLType] = {}

        for type_name in root_type_names:
            probe = _TYPE_PROBE_TMPL.format(name=type_name)
            try:
                resp = await self._client.post(
                    endpoint.url, data=probe,
                    headers=self._headers, timeout=self._timeout,
                )
                body = json.loads(resp.text or "{}")
                type_raw = body.get("data", {}).get("__type")
                if type_raw:
                    parsed = _parse_type(type_raw)
                    if parsed:
                        found_types[parsed.name] = parsed
            except Exception:
                continue

        if not found_types:
            return None

        schema = GraphQLSchema(endpoint=endpoint)
        schema.types.update(found_types)
        self._populate_operations_from_types(schema, found_types)
        return schema

    def _build_schema_from_introspection(
        self,
        endpoint: GQLEndpoint,
        schema_raw: Dict[str, Any],
    ) -> GraphQLSchema:
        """Convert raw introspection data into a ``GraphQLSchema``."""
        schema = GraphQLSchema(endpoint=endpoint)

        # --- Parse types -------------------------------------------------
        for type_raw in schema_raw.get("types") or []:
            parsed = _parse_type(type_raw)
            if parsed:
                schema.types[parsed.name] = parsed

        # --- Parse directives --------------------------------------------
        for dir_raw in schema_raw.get("directives") or []:
            schema.directives.append(_parse_directive(dir_raw))

        # --- Populate operations from root types --------------------------
        self._populate_operations_from_root(schema, schema_raw)

        return schema

    def _populate_operations_from_root(
        self,
        schema:     GraphQLSchema,
        schema_raw: Dict[str, Any],
    ) -> None:
        """Extract Query / Mutation / Subscription operations."""
        query_type_name        = (schema_raw.get("queryType") or {}).get("name")
        mutation_type_name     = (schema_raw.get("mutationType") or {}).get("name")
        subscription_type_name = (schema_raw.get("subscriptionType") or {}).get("name")

        for type_name, op_type, bucket in [
            (query_type_name,        OperationType.QUERY,        schema.queries),
            (mutation_type_name,     OperationType.MUTATION,     schema.mutations),
            (subscription_type_name, OperationType.SUBSCRIPTION, schema.subscriptions),
        ]:
            if not type_name:
                continue
            gql_type = schema.types.get(type_name)
            if not gql_type:
                continue
            for f in gql_type.fields:
                bucket.append(GQLOperation(
                    operation_type=op_type,
                    name=f.name,
                    type=f.type,
                    args=f.args,
                    description=f.description,
                    is_deprecated=f.is_deprecated,
                ))

    def _populate_operations_from_types(
        self,
        schema:      GraphQLSchema,
        found_types: Dict[str, GQLType],
    ) -> None:
        """
        Populate operations when we have root types from partial introspection
        but no ``__schema`` metadata.
        """
        mapping = {
            "Query":        (OperationType.QUERY,        schema.queries),
            "Mutation":     (OperationType.MUTATION,     schema.mutations),
            "Subscription": (OperationType.SUBSCRIPTION, schema.subscriptions),
        }
        for type_name, (op_type, bucket) in mapping.items():
            gql_type = found_types.get(type_name)
            if not gql_type:
                continue
            for f in gql_type.fields:
                bucket.append(GQLOperation(
                    operation_type=op_type,
                    name=f.name,
                    type=f.type,
                    args=f.args,
                    description=f.description,
                ))

    # ------------------------------------------------------------------
    # Capability probing
    # ------------------------------------------------------------------

    async def _probe_capabilities(self, endpoint: GQLEndpoint) -> None:
        """Probe batching and APQ (Automatic Persisted Query) support."""
        await asyncio.gather(
            self._probe_batching(endpoint),
            self._probe_apq(endpoint),
            return_exceptions=True,
        )

    async def _probe_batching(self, endpoint: GQLEndpoint) -> None:
        """
        GraphQL batching: send an array of queries in a single request.
        If the response is also an array, batching is supported.
        """
        batch_payload = json.dumps([
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ])
        try:
            resp = await self._client.post(
                endpoint.url,
                data=batch_payload,
                headers=self._headers,
                timeout=self._timeout,
            )
            body = resp.text or ""
            try:
                parsed = json.loads(body)
                endpoint.batching_supported = isinstance(parsed, list)
            except json.JSONDecodeError:
                pass
        except Exception:
            pass

    async def _probe_apq(self, endpoint: GQLEndpoint) -> None:
        """
        Automatic Persisted Queries: send a query by SHA-256 hash only.
        A ``PersistedQueryNotFound`` error (not a generic error) indicates
        APQ support.
        """
        try:
            resp = await self._client.post(
                endpoint.url,
                data=_APQ_PROBE,
                headers=self._headers,
                timeout=self._timeout,
            )
            body = resp.text or ""
            endpoint.apq_supported = (
                "PersistedQueryNotFound" in body
                or "persistedQuery" in body.lower()
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # WebSocket / Subscription detection
    # ------------------------------------------------------------------

    async def _probe_subscriptions(self, endpoint: GQLEndpoint) -> None:
        """
        Look for a WebSocket subscription endpoint by checking common paths
        and inspecting the base endpoint for upgrade headers.
        """
        sub_paths = ["/subscriptions", "/graphql/subscriptions", "/ws", "/graphql/ws"]
        parsed = urlparse(endpoint.url)
        ws_base = (
            f"ws{'s' if parsed.scheme == 'https' else ''}://{parsed.netloc}"
        )

        for path in sub_paths:
            ws_url = ws_base + path
            try:
                resp = await self._client.get(
                    f"{parsed.scheme}://{parsed.netloc}{path}",
                    headers={"Connection": "Upgrade", "Upgrade": "websocket"},
                    timeout=5.0,
                )
                if resp and resp.status_code in (101, 200, 400, 426):
                    endpoint.subscriptions_url = ws_url
                    # Detect sub-protocol from response header
                    proto = (resp.headers or {}).get(
                        "sec-websocket-protocol", ""
                    ).lower()
                    for sp in _WS_SUBPROTOCOLS:
                        if sp in proto:
                            endpoint.ws_subprotocol = sp
                            break
                    break
            except Exception:
                continue

    # ------------------------------------------------------------------
    # Playground detection
    # ------------------------------------------------------------------

    def _detect_playground(self, resp: HTTPResponse) -> bool:
        """Return True if the response looks like a GraphQL playground UI."""
        if resp is None:
            return False
        body = resp.text or ""
        ct   = (resp.headers or {}).get("content-type", "").lower()
        return bool(_PLAYGROUND_RE.search(body)) or "text/html" in ct

    # ------------------------------------------------------------------
    # Field suggestion extraction
    # ------------------------------------------------------------------

    async def _extract_suggestions(self, schema: GraphQLSchema) -> None:
        """
        When introspection is blocked, fire intentionally-wrong field names
        to trigger Apollo/Hasura suggestion error messages, then extract
        field names from those messages.  Iterates up to
        ``_max_suggestion_iters`` rounds.
        """
        url   = schema.endpoint.url
        known_fields: Dict[str, Set[str]] = {"Query": set(), "Mutation": set()}

        for _ in range(self._max_sugg):
            new_found = False
            for root_type in ("Query", "Mutation"):
                wrong_query = (
                    f'{{"query": "{{ {"xXxWrongFieldxXx"} }}"}}'
                )
                try:
                    resp = await self._client.post(
                        url, data=wrong_query,
                        headers=self._headers, timeout=self._timeout,
                    )
                    body = resp.text or ""
                    for pattern in _SUGGESTION_PATTERNS:
                        for match in pattern.finditer(body):
                            suggested = match.group(1)
                            if suggested not in known_fields[root_type]:
                                known_fields[root_type].add(suggested)
                                new_found = True
                except Exception:
                    break

            if not new_found:
                break

        # Populate schema.suggested_fields
        for root_type, fields in known_fields.items():
            if fields:
                schema.suggested_fields[root_type] = sorted(fields)
                if schema.endpoint.introspection_mode == IntrospectionMode.UNAVAILABLE:
                    schema.endpoint.introspection_mode = IntrospectionMode.SUGGESTION

    # ------------------------------------------------------------------
    # Post-processing
    # ------------------------------------------------------------------

    def _postprocess_schema(self, schema: GraphQLSchema) -> None:
        """
        Walk the parsed type graph and populate convenience lists:
          • custom_scalars
          • union_types
          • interface_types
        Also detect circular references and flag them.
        """
        for name, gql_type in schema.types.items():
            if gql_type.is_builtin or name.startswith("__"):
                continue

            if gql_type.is_custom_scalar:
                schema.custom_scalars.append(name)
            elif gql_type.kind == GQLKind.UNION:
                schema.union_types.append(name)
            elif gql_type.kind == GQLKind.INTERFACE:
                schema.interface_types.append(name)

        # Detect recursive types (circular references)
        self._detect_circular_types(schema)

    def _detect_circular_types(self, schema: GraphQLSchema) -> None:
        """
        DFS-based circular reference detection.  Logs a warning for any
        type that references itself (directly or transitively).
        """
        def refs_of(type_name: str) -> Set[str]:
            gql_type = schema.types.get(type_name)
            if not gql_type:
                return set()
            result: Set[str] = set()
            for f in gql_type.fields:
                inner = f.type.unwrap()
                if inner:
                    result.add(inner)
            return result

        visited:  Set[str] = set()
        in_stack: Set[str] = set()

        def dfs(name: str) -> bool:
            if name in in_stack:
                return True   # cycle detected
            if name in visited:
                return False
            in_stack.add(name)
            for ref in refs_of(name):
                if dfs(ref):
                    logger.debug("[GraphQL] Circular type detected: %s -> %s", name, ref)
            in_stack.discard(name)
            visited.add(name)
            return False

        for type_name in list(schema.types.keys()):
            dfs(type_name)


# ===========================================================================
# SDL (Schema Definition Language) helpers
# ===========================================================================

def render_sdl(schema: GraphQLSchema) -> str:
    """
    Render a ``GraphQLSchema`` back to SDL text for human inspection or
    storage in the Knowledge Base.
    """
    lines: List[str] = []

    def type_ref_str(ref: GQLTypeRef) -> str:
        return str(ref)

    for name, gql_type in schema.user_types.items():
        if gql_type.kind == GQLKind.SCALAR:
            lines.append(f"scalar {name}")
        elif gql_type.kind == GQLKind.ENUM:
            lines.append(f"enum {name} {{")
            for ev in gql_type.enum_values:
                dep = " @deprecated" if ev.is_deprecated else ""
                lines.append(f"  {ev.name}{dep}")
            lines.append("}")
        elif gql_type.kind == GQLKind.INPUT_OBJECT:
            lines.append(f"input {name} {{")
            for inp in gql_type.input_fields:
                lines.append(f"  {inp.name}: {type_ref_str(inp.type)}")
            lines.append("}")
        elif gql_type.kind in (GQLKind.OBJECT, GQLKind.INTERFACE):
            kw = "interface" if gql_type.kind == GQLKind.INTERFACE else "type"
            ifaces = (
                " implements " + " & ".join(gql_type.interfaces)
                if gql_type.interfaces else ""
            )
            lines.append(f"{kw} {name}{ifaces} {{")
            for f in gql_type.fields:
                args_str = ""
                if f.args:
                    arg_parts = [
                        f"{a.name}: {type_ref_str(a.type)}" for a in f.args
                    ]
                    args_str = "(" + ", ".join(arg_parts) + ")"
                dep = " @deprecated" if f.is_deprecated else ""
                lines.append(f"  {f.name}{args_str}: {type_ref_str(f.type)}{dep}")
            lines.append("}")
        elif gql_type.kind == GQLKind.UNION:
            members = " | ".join(gql_type.possible_types)
            lines.append(f"union {name} = {members}")

        lines.append("")

    return "\n".join(lines)


# ===========================================================================
# Attack surface extractor (consumed by downstream scanners)
# ===========================================================================

@dataclass
class GraphQLAttackSurface:
    """
    Distilled attack surface derived from a ``GraphQLSchema``.
    Passed to the Context-Aware Payload Framework and individual scanners.
    """
    endpoint:            str
    introspection_mode:  IntrospectionMode

    # High-value targets
    dangerous_mutations:      List[str]                  = field(default_factory=list)
    auth_sensitive_ops:       List[str]                  = field(default_factory=list)
    injection_points:         List[Dict[str, Any]]       = field(default_factory=list)
    file_upload_ops:          List[str]                  = field(default_factory=list)
    deprecated_ops:           List[str]                  = field(default_factory=list)

    # Transport
    batching_enabled:         bool                       = False
    apq_enabled:              bool                       = False
    subscriptions_url:        Optional[str]              = None

    # Metadata for payload generation
    custom_scalar_names:      List[str]                  = field(default_factory=list)
    engine:                   Optional[str]              = None


def extract_attack_surface(schema: GraphQLSchema) -> GraphQLAttackSurface:
    """Build a ``GraphQLAttackSurface`` from a fully-analysed schema."""
    surface = GraphQLAttackSurface(
        endpoint=schema.endpoint.url,
        introspection_mode=schema.endpoint.introspection_mode,
        dangerous_mutations=[m.name for m in schema.dangerous_mutations],
        auth_sensitive_ops=[
            m.name for m in schema.mutations
            if m.requires_auth_heuristic
        ],
        batching_enabled=schema.endpoint.batching_supported,
        apq_enabled=schema.endpoint.apq_supported,
        subscriptions_url=schema.endpoint.subscriptions_url,
        custom_scalar_names=schema.custom_scalars,
        engine=schema.endpoint.detected_engine,
    )

    # Injection points: all operations + field args
    all_ops = schema.queries + schema.mutations + schema.subscriptions
    for op in all_ops:
        for arg in op.args:
            surface.injection_points.append({
                "operation": op.name,
                "operation_type": op.operation_type.value,
                "argument": arg.name,
                "type": str(arg.type),
                "required": arg.is_required,
            })

    # File upload detection (Upload scalar)
    for op in schema.mutations:
        for arg in op.args:
            if arg.type.unwrap() == "Upload":
                surface.file_upload_ops.append(op.name)

    # Deprecated operations
    all_deprecated = [
        op.name for op in (schema.queries + schema.mutations)
        if op.is_deprecated
    ]
    surface.deprecated_ops = all_deprecated

    return surface
