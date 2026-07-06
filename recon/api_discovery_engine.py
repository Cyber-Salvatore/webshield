"""
API Discovery Engine — Part 8 of the Intelligence Layer.

Dedicated engine for discovering, mapping, and profiling every API surface
exposed by the target application, including:

  - REST APIs  (fetch, axios, OpenAPI, Swagger, raw path patterns)
  - GraphQL    (introspection, field guessing, batching detection)
  - SOAP / WSDL
  - gRPC       (gRPC-Web, reflection endpoint, .proto recovery)
  - WebSocket APIs
  - Server-Sent Events (SSE)

For each discovered endpoint the engine determines:
  • HTTP methods accepted
  • Authentication requirements (Bearer, API-Key, Cookie, Basic, OAuth)
  • Content-Type constraints
  • Parameter inventory (path, query, header, body)
  • Request / response schema (inferred or retrieved)
  • Relationships between endpoints (shared resources, chained flows)
  • Risk rating based on functionality class

All findings are emitted as structured ``APIEndpoint`` objects that feed
directly into the Endpoint Classification Engine and the scanners that follow.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

from ..core.http_client import HTTPClient, HTTPResponse
from ..core.target import ScanTarget
from ..utils.helpers import normalize_url


# ===========================================================================
# Enums & Constants
# ===========================================================================

class APIType(str, Enum):
    REST      = "REST"
    GRAPHQL   = "GraphQL"
    SOAP      = "SOAP"
    GRPC      = "gRPC"
    WEBSOCKET = "WebSocket"
    SSE       = "SSE"
    UNKNOWN   = "Unknown"


class AuthScheme(str, Enum):
    NONE        = "None"
    BEARER      = "Bearer"
    API_KEY     = "API-Key"
    BASIC       = "Basic"
    COOKIE      = "Cookie"
    OAUTH2      = "OAuth2"
    SAML        = "SAML"
    HMAC        = "HMAC"
    CUSTOM      = "Custom"


class ParamLocation(str, Enum):
    PATH    = "path"
    QUERY   = "query"
    HEADER  = "header"
    BODY    = "body"
    COOKIE  = "cookie"


class DiscoverySource(str, Enum):
    CRAWL          = "crawl"
    JS_ANALYSIS    = "js_analysis"
    OPENAPI_SPEC   = "openapi_spec"
    GRAPHQL_INTRO  = "graphql_introspection"
    WSDL           = "wsdl"
    HEADER_HINT    = "header_hint"
    BRUTE_FORCE    = "brute_force"
    LINK_HEADER    = "link_header"
    PASSIVE        = "passive"
    GRPC_REFLECT   = "grpc_reflection"


# Risk levels assigned to endpoint categories
_ENDPOINT_RISK: Dict[str, int] = {
    "auth":          10,
    "admin":         10,
    "payment":       10,
    "password":      10,
    "token":         9,
    "upload":        9,
    "delete":        9,
    "export":        8,
    "import":        8,
    "config":        8,
    "setting":       7,
    "user":          7,
    "account":       7,
    "profile":       6,
    "search":        5,
    "list":          4,
    "health":        2,
    "static":        1,
}

# Common REST API path prefixes tried during brute-force discovery
_COMMON_API_PREFIXES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1",
    "/service", "/services",
    "/internal", "/internal/api",
    "/backend",
    "/graphql", "/gql",
    "/query",
    "/data",
    "/json",
    "/mobile/api", "/mobile/v1",
    "/app/api",
    "/_api", "/_api/v1",
]

# Paths probed specifically for OpenAPI / Swagger documents
_OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api/swagger.json", "/api/openapi.json",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/api-docs", "/api-docs.json", "/api-docs.yaml",
    "/api/docs", "/api/spec",
    "/docs/api", "/doc/api",
    "/.well-known/openapi",
    "/swagger-ui/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/api/swagger-ui.html",
]

# Paths probed for GraphQL endpoints
_GRAPHQL_PATHS = [
    "/graphql", "/gql", "/query",
    "/api/graphql", "/api/gql",
    "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/graphql/v2",
    "/app/graphql",
    "/service/graphql",
    "/data/graphql",
]

# Paths for SOAP/WSDL
_WSDL_PATHS = [
    "/service?wsdl", "/services?wsdl", "/soap?wsdl",
    "/ws?wsdl", "/webservice?wsdl",
    "/api/soap?wsdl",
    "/Service.asmx?wsdl", "/services.asmx?wsdl",
    "/.wsdl",
]

# Paths for gRPC reflection or gRPC-Web
_GRPC_PATHS = [
    "/grpc", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
]

# Paths for SSE
_SSE_PATHS = [
    "/events", "/sse", "/stream", "/feed",
    "/api/events", "/api/stream", "/api/sse",
    "/notifications", "/updates",
]

# GraphQL introspection query (minimal)
_GRAPHQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { kind name ofType { kind name } }
          defaultValue
        }
        type { kind name ofType { kind name } }
      }
      inputFields {
        name
        type { kind name ofType { kind name } }
        defaultValue
      }
      enumValues(includeDeprecated: true) { name description }
    }
    directives {
      name
      description
      locations
      args { name type { kind name } }
    }
  }
}
""".strip()

# Lightweight probe used when full introspection is disabled
_GRAPHQL_FIELD_PROBE = "{ __typename }"

# Content-Type markers for various API types
_SOAP_CONTENT_TYPES  = {"text/xml", "application/soap+xml", "application/xml"}
_GRPC_CONTENT_TYPES  = {"application/grpc", "application/grpc+proto", "application/grpc-web"}
_SSE_CONTENT_TYPES   = {"text/event-stream"}


# ===========================================================================
# Data models
# ===========================================================================

@dataclass
class APIParameter:
    """A single parameter (path variable, query string, header, body field)."""
    name: str
    location: ParamLocation
    data_type: str = "string"      # string, integer, boolean, array, object, file
    required: bool = False
    description: str = ""
    example_value: str = ""
    schema: Optional[Dict[str, Any]] = None


@dataclass
class APIEndpoint:
    """Full representation of a discovered API endpoint."""
    url: str
    api_type: APIType
    methods: List[str] = field(default_factory=list)
    auth_schemes: List[AuthScheme] = field(default_factory=list)
    parameters: List[APIParameter] = field(default_factory=list)
    content_types_accepted: List[str] = field(default_factory=list)
    content_types_returned: List[str] = field(default_factory=list)
    request_schema: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    risk_score: int = 0
    discovery_sources: List[DiscoverySource] = field(default_factory=list)
    related_endpoints: List[str] = field(default_factory=list)
    raw_spec_fragment: Optional[Dict[str, Any]] = None

    # GraphQL-specific
    graphql_type: Optional[str] = None       # Query / Mutation / Subscription
    graphql_fields: List[str] = field(default_factory=list)

    # WebSocket-specific
    ws_protocol: Optional[str] = None
    ws_message_format: Optional[str] = None  # json, msgpack, binary, text

    # SSE-specific
    sse_event_types: List[str] = field(default_factory=list)

    def add_source(self, source: DiscoverySource) -> None:
        if source not in self.discovery_sources:
            self.discovery_sources.append(source)

    def merge(self, other: "APIEndpoint") -> None:
        """Merge information from another APIEndpoint with the same URL."""
        for m in other.methods:
            if m not in self.methods:
                self.methods.append(m)
        for a in other.auth_schemes:
            if a not in self.auth_schemes:
                self.auth_schemes.append(a)
        for p in other.parameters:
            if not any(ep.name == p.name and ep.location == p.location for ep in self.parameters):
                self.parameters.append(p)
        for ct in other.content_types_accepted:
            if ct not in self.content_types_accepted:
                self.content_types_accepted.append(ct)
        for s in other.discovery_sources:
            self.add_source(s)
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)
        self.risk_score = max(self.risk_score, other.risk_score)
        if other.request_schema and not self.request_schema:
            self.request_schema = other.request_schema
        if other.response_schema and not self.response_schema:
            self.response_schema = other.response_schema


@dataclass
class GraphQLSchema:
    """Parsed GraphQL schema information."""
    query_type: Optional[str] = None
    mutation_type: Optional[str] = None
    subscription_type: Optional[str] = None
    types: List[Dict[str, Any]] = field(default_factory=list)
    queries: List[Dict[str, Any]] = field(default_factory=list)
    mutations: List[Dict[str, Any]] = field(default_factory=list)
    subscriptions: List[Dict[str, Any]] = field(default_factory=list)
    introspection_disabled: bool = False
    partial: bool = False          # True when guessed without introspection


@dataclass
class APIDiscoveryResult:
    """Aggregated output from the API Discovery Engine."""
    target_url: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    graphql_schema: Optional[GraphQLSchema] = None
    wsdl_raw: Optional[str] = None
    openapi_spec: Optional[Dict[str, Any]] = None
    api_prefixes_confirmed: List[str] = field(default_factory=list)
    total_endpoints: int = 0
    rest_count: int = 0
    graphql_count: int = 0
    soap_count: int = 0
    grpc_count: int = 0
    websocket_count: int = 0
    sse_count: int = 0
    scan_duration_seconds: float = 0.0

    def add_endpoint(self, ep: APIEndpoint) -> None:
        # Deduplicate by URL + method set
        for existing in self.endpoints:
            if existing.url == ep.url and existing.api_type == ep.api_type:
                existing.merge(ep)
                return
        self.endpoints.append(ep)
        self._update_counts()

    def _update_counts(self) -> None:
        self.total_endpoints  = len(self.endpoints)
        self.rest_count       = sum(1 for e in self.endpoints if e.api_type == APIType.REST)
        self.graphql_count    = sum(1 for e in self.endpoints if e.api_type == APIType.GRAPHQL)
        self.soap_count       = sum(1 for e in self.endpoints if e.api_type == APIType.SOAP)
        self.grpc_count       = sum(1 for e in self.endpoints if e.api_type == APIType.GRPC)
        self.websocket_count  = sum(1 for e in self.endpoints if e.api_type == APIType.WEBSOCKET)
        self.sse_count        = sum(1 for e in self.endpoints if e.api_type == APIType.SSE)


# ===========================================================================
# Internal helpers
# ===========================================================================

def _compute_risk(url: str, tags: List[str]) -> int:
    """Heuristic risk score for an endpoint based on URL path and tags."""
    path = urlparse(url).path.lower()
    score = 1
    for keyword, risk in _ENDPOINT_RISK.items():
        if keyword in path or keyword in " ".join(tags).lower():
            score = max(score, risk)
    return score


def _detect_auth_from_response(response: HTTPResponse) -> List[AuthScheme]:
    """Infer authentication scheme from response headers."""
    schemes: List[AuthScheme] = []
    www_auth = (response.headers.get("www-authenticate", "") +
                response.headers.get("WWW-Authenticate", "")).lower()
    if "bearer" in www_auth:
        schemes.append(AuthScheme.BEARER)
    if "basic" in www_auth:
        schemes.append(AuthScheme.BASIC)
    if "apikey" in www_auth or "api-key" in www_auth or "api_key" in www_auth:
        schemes.append(AuthScheme.API_KEY)
    if response.status_code == 401 and not schemes:
        schemes.append(AuthScheme.CUSTOM)
    return schemes


def _infer_method_from_spec(spec_methods: List[str]) -> List[str]:
    """Normalise HTTP methods to uppercase, filter to well-known ones."""
    known = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
    return [m.upper() for m in spec_methods if m.upper() in known]


def _extract_path_params(path: str) -> List[APIParameter]:
    """Extract {param} and :param style path variables."""
    params: List[APIParameter] = []
    # OpenAPI-style {param}
    for match in re.finditer(r"\{([^}]+)\}", path):
        params.append(APIParameter(
            name=match.group(1),
            location=ParamLocation.PATH,
            required=True,
        ))
    # Express-style :param
    for match in re.finditer(r"/:([a-zA-Z_][a-zA-Z0-9_]*)", path):
        name = match.group(1)
        if not any(p.name == name for p in params):
            params.append(APIParameter(
                name=name,
                location=ParamLocation.PATH,
                required=True,
            ))
    return params


def _openapi_type_to_str(schema: Dict[str, Any]) -> str:
    """Convert an OpenAPI schema snippet to a simple type string."""
    t = schema.get("type", "")
    fmt = schema.get("format", "")
    if t == "array":
        items = schema.get("items", {})
        return f"array[{items.get('type', 'any')}]"
    if fmt:
        return f"{t}({fmt})"
    return t or "any"


# ===========================================================================
# OpenAPI / Swagger parser
# ===========================================================================

class OpenAPIParser:
    """Parses OpenAPI 2.x (Swagger) and 3.x documents into APIEndpoint objects."""

    def __init__(self, base_url: str, spec: Dict[str, Any]) -> None:
        self._base_url = base_url.rstrip("/")
        self._spec = spec
        self._version = "3" if "openapi" in spec else "2"

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    def parse(self) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        paths = self._spec.get("paths", {})
        global_security = self._spec.get("security", [])
        global_auth = self._infer_auth_from_security(global_security) if global_security else []
        base_path = self._resolve_base_path()

        for path_template, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            full_url = self._base_url + base_path + path_template

            for method, operation in path_item.items():
                method = method.upper()
                if method in ("SUMMARY", "DESCRIPTION", "PARAMETERS", "SERVERS",
                              "$REF", "EXTENSIONS"):
                    continue
                if not isinstance(operation, dict):
                    continue

                params = _extract_path_params(path_template)
                params.extend(self._parse_parameters(operation.get("parameters", []) +
                                                     path_item.get("parameters", [])))
                body_params = self._parse_request_body(operation)
                params.extend(body_params)

                op_security = operation.get("security", global_security)
                auth = self._infer_auth_from_security(op_security) or global_auth

                req_ct = self._content_types_from_operation(operation, "requestBody")
                resp_ct = self._content_types_from_responses(operation.get("responses", {}))

                req_schema = self._schema_from_request(operation)
                resp_schema = self._schema_from_responses(operation.get("responses", {}))

                tags: List[str] = operation.get("tags", [])
                description = (operation.get("summary") or operation.get("description") or "")[:200]

                ep = APIEndpoint(
                    url=full_url,
                    api_type=APIType.REST,
                    methods=[method],
                    auth_schemes=auth,
                    parameters=params,
                    content_types_accepted=req_ct,
                    content_types_returned=resp_ct,
                    request_schema=req_schema,
                    response_schema=resp_schema,
                    description=description,
                    tags=tags,
                    risk_score=_compute_risk(full_url, tags),
                    discovery_sources=[DiscoverySource.OPENAPI_SPEC],
                    raw_spec_fragment={path_template: {method.lower(): operation}},
                )
                endpoints.append(ep)

        return endpoints

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _resolve_base_path(self) -> str:
        if self._version == "2":
            return self._spec.get("basePath", "")
        # OAS3: first server URL relative path
        servers = self._spec.get("servers", [])
        if servers:
            parsed = urlparse(servers[0].get("url", ""))
            return parsed.path.rstrip("/")
        return ""

    def _infer_auth_from_security(self, security: Any) -> List[AuthScheme]:
        if not security:
            return []
        schemes: List[AuthScheme] = []
        # Resolve security scheme definitions
        sec_defs: Dict[str, Any] = {}
        if self._version == "2":
            sec_defs = self._spec.get("securityDefinitions", {})
        else:
            sec_defs = self._spec.get("components", {}).get("securitySchemes", {})

        names: Set[str] = set()
        for item in security:
            names.update(item.keys())

        for name in names:
            definition = sec_defs.get(name, {})
            scheme_type = definition.get("type", "").lower()
            scheme_scheme = definition.get("scheme", "").lower()
            if scheme_type == "apikey":
                schemes.append(AuthScheme.API_KEY)
            elif scheme_type == "http":
                if "bearer" in scheme_scheme:
                    schemes.append(AuthScheme.BEARER)
                elif "basic" in scheme_scheme:
                    schemes.append(AuthScheme.BASIC)
            elif scheme_type in ("oauth2", "oauth"):
                schemes.append(AuthScheme.OAUTH2)
            else:
                schemes.append(AuthScheme.CUSTOM)

        return list(set(schemes))

    def _parse_parameters(self, raw: List[Any]) -> List[APIParameter]:
        params: List[APIParameter] = []
        for p in raw:
            if not isinstance(p, dict) or "$ref" in p:
                continue
            loc_str = p.get("in", "query").lower()
            try:
                loc = ParamLocation(loc_str)
            except ValueError:
                loc = ParamLocation.QUERY
            schema = p.get("schema", {}) if self._version == "3" else p
            params.append(APIParameter(
                name=p.get("name", ""),
                location=loc,
                data_type=_openapi_type_to_str(schema),
                required=p.get("required", loc == ParamLocation.PATH),
                description=p.get("description", "")[:120],
                schema=schema,
            ))
        return params

    def _parse_request_body(self, operation: Dict[str, Any]) -> List[APIParameter]:
        """OAS3 requestBody → body parameters."""
        rb = operation.get("requestBody", {})
        if not rb:
            return []
        content = rb.get("content", {})
        params: List[APIParameter] = []
        for ct, ct_obj in content.items():
            schema = ct_obj.get("schema", {})
            props = schema.get("properties", {})
            required_fields = schema.get("required", [])
            for field_name, field_schema in props.items():
                params.append(APIParameter(
                    name=field_name,
                    location=ParamLocation.BODY,
                    data_type=_openapi_type_to_str(field_schema),
                    required=field_name in required_fields,
                    description=field_schema.get("description", "")[:120],
                    schema=field_schema,
                ))
        return params

    def _content_types_from_operation(self, operation: Dict[str, Any], key: str) -> List[str]:
        if self._version == "3":
            return list(operation.get(key, {}).get("content", {}).keys())
        # OAS2: consumes list
        return self._spec.get("consumes", ["application/json"])

    def _content_types_from_responses(self, responses: Dict[str, Any]) -> List[str]:
        cts: Set[str] = set()
        for _, resp in responses.items():
            if not isinstance(resp, dict):
                continue
            if self._version == "3":
                cts.update(resp.get("content", {}).keys())
            else:
                cts.update(self._spec.get("produces", ["application/json"]))
        return list(cts)

    def _schema_from_request(self, operation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        rb = operation.get("requestBody", {})
        content = rb.get("content", {})
        for _, ct_obj in content.items():
            s = ct_obj.get("schema")
            if s:
                return s
        return None

    def _schema_from_responses(self, responses: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for code in ("200", "201", "default"):
            resp = responses.get(code, {})
            if self._version == "3":
                for _, ct_obj in resp.get("content", {}).items():
                    s = ct_obj.get("schema")
                    if s:
                        return s
            else:
                s = resp.get("schema")
                if s:
                    return s
        return None


# ===========================================================================
# GraphQL probe & schema parser
# ===========================================================================

class GraphQLProbe:
    """Detects, probes, and maps GraphQL endpoints."""

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    async def is_graphql(self, url: str) -> bool:
        """Quick check: can we send a minimal GraphQL query and get a valid JSON response?"""
        try:
            resp = await self._client.post(
                url,
                json={"query": _GRAPHQL_FIELD_PROBE},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=10,
            )
            if resp.status_code in (200, 400):
                body = resp.text or ""
                return "data" in body or "errors" in body
        except Exception:
            pass
        return False

    # -----------------------------------------------------------------------
    # Introspection
    # -----------------------------------------------------------------------

    async def introspect(self, url: str) -> GraphQLSchema:
        """
        Attempt full schema introspection. Falls back to field guessing when
        the server has disabled introspection.
        """
        schema = GraphQLSchema()
        try:
            resp = await self._client.post(
                url,
                json={"query": _GRAPHQL_INTROSPECTION},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=20,
            )
            if resp.status_code == 200:
                data = self._safe_json(resp.text)
                raw_schema = data.get("data", {}).get("__schema", {})
                if raw_schema:
                    return self._parse_introspection(raw_schema)
        except Exception:
            pass

        # Introspection disabled or returned errors
        schema.introspection_disabled = True
        schema.partial = True
        await self._guess_fields(url, schema)
        return schema

    def _parse_introspection(self, raw: Dict[str, Any]) -> GraphQLSchema:
        schema = GraphQLSchema(
            query_type=(raw.get("queryType") or {}).get("name"),
            mutation_type=(raw.get("mutationType") or {}).get("name"),
            subscription_type=(raw.get("subscriptionType") or {}).get("name"),
        )
        schema.types = raw.get("types", [])

        q_name = schema.query_type or "Query"
        m_name = schema.mutation_type or "Mutation"
        s_name = schema.subscription_type or "Subscription"

        for t in schema.types:
            name = t.get("name", "")
            fields = t.get("fields") or []
            if name == q_name:
                schema.queries = fields
            elif name == m_name:
                schema.mutations = fields
            elif name == s_name:
                schema.subscriptions = fields

        return schema

    async def _guess_fields(self, url: str, schema: GraphQLSchema) -> None:
        """
        Probe common field names when introspection is disabled.
        Uses a curated wordlist of typical query/mutation names.
        """
        common_queries = [
            "users", "user", "me", "viewer", "profile",
            "posts", "post", "articles", "article",
            "products", "product", "orders", "order",
            "settings", "config", "admin",
            "search", "feed", "notifications",
        ]
        common_mutations = [
            "login", "logout", "register", "signup", "createUser",
            "updateUser", "deleteUser", "createPost", "updatePost", "deletePost",
            "createOrder", "updatePassword", "resetPassword",
            "uploadFile", "createToken",
        ]

        found_queries: List[Dict[str, Any]] = []
        found_mutations: List[Dict[str, Any]] = []

        # Query probes
        for field in common_queries:
            query = f"{{ {field} {{ id }} }}"
            try:
                resp = await self._client.post(
                    url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=8,
                )
                body = resp.text or ""
                # Field exists if we get a data response (even null) rather than
                # "Cannot query field" error
                if resp.status_code == 200 and '"errors"' not in body:
                    found_queries.append({"name": field, "args": [], "type": {"name": "Unknown"}})
                elif '"Cannot query field' not in body and '"errors"' in body:
                    # Might exist but needs args
                    if f'"{field}"' in body and "Cannot query field" not in body:
                        found_queries.append({"name": field, "args": [], "type": {"name": "Unknown"}})
            except Exception:
                pass

        # Mutation probes
        for field in common_mutations:
            query = f"mutation {{ {field} }}"
            try:
                resp = await self._client.post(
                    url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=8,
                )
                body = resp.text or ""
                if "Cannot query field" not in body and '"errors"' in body:
                    found_mutations.append({"name": field, "args": [], "type": {"name": "Unknown"}})
                elif resp.status_code == 200 and '"data"' in body:
                    found_mutations.append({"name": field, "args": [], "type": {"name": "Unknown"}})
            except Exception:
                pass

        schema.queries    = found_queries
        schema.mutations  = found_mutations

    def _safe_json(self, text: Optional[str]) -> Dict[str, Any]:
        try:
            return json.loads(text or "{}")
        except Exception:
            return {}

    # -----------------------------------------------------------------------
    # Convert schema to APIEndpoint list
    # -----------------------------------------------------------------------

    def schema_to_endpoints(self, url: str, schema: GraphQLSchema) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []

        def _make(name: str, gql_type: str, fields: List[Dict[str, Any]]) -> APIEndpoint:
            args_params = []
            for field in fields:
                for arg in (field.get("args") or []):
                    arg_type = (arg.get("type") or {})
                    args_params.append(APIParameter(
                        name=f"{field['name']}.{arg['name']}",
                        location=ParamLocation.BODY,
                        data_type=(arg_type.get("name") or
                                   (arg_type.get("ofType") or {}).get("name") or "any"),
                    ))
            field_names = [f["name"] for f in fields]
            ep = APIEndpoint(
                url=url,
                api_type=APIType.GRAPHQL,
                methods=["POST"],
                parameters=args_params,
                content_types_accepted=["application/json"],
                content_types_returned=["application/json"],
                description=f"GraphQL {gql_type}",
                tags=[gql_type.lower()],
                risk_score=_compute_risk(url, [gql_type]),
                discovery_sources=[DiscoverySource.GRAPHQL_INTRO],
                graphql_type=gql_type,
                graphql_fields=field_names,
            )
            return ep

        if schema.queries:
            endpoints.append(_make("Query", "Query", schema.queries))
        if schema.mutations:
            ep = _make("Mutation", "Mutation", schema.mutations)
            ep.risk_score = min(10, ep.risk_score + 2)   # mutations are higher risk
            endpoints.append(ep)
        if schema.subscriptions:
            endpoints.append(_make("Subscription", "Subscription", schema.subscriptions))

        return endpoints


# ===========================================================================
# WebSocket & SSE detectors
# ===========================================================================

class WebSocketProbe:
    """Checks whether a URL speaks WebSocket."""

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    async def detect(self, url: str) -> Optional[APIEndpoint]:
        """
        Send a WebSocket upgrade request. If the server returns 101 Switching
        Protocols we confirm the endpoint.
        """
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://")
        try:
            resp = await self._client.get(
                url,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                },
                timeout=10,
            )
            if resp.status_code == 101:
                protocol = resp.headers.get("Sec-WebSocket-Protocol", "")
                ep = APIEndpoint(
                    url=ws_url,
                    api_type=APIType.WEBSOCKET,
                    methods=["WS"],
                    description="WebSocket endpoint",
                    risk_score=_compute_risk(url, ["websocket"]),
                    discovery_sources=[DiscoverySource.CRAWL],
                    ws_protocol=protocol or None,
                )
                return ep
        except Exception:
            pass
        return None


class SSEProbe:
    """Checks whether a URL emits Server-Sent Events."""

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    async def detect(self, url: str) -> Optional[APIEndpoint]:
        try:
            resp = await self._client.get(
                url,
                headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
                timeout=8,
            )
            ct = resp.headers.get("content-type", "").lower()
            if "text/event-stream" in ct or resp.status_code == 200 and "data:" in (resp.text or ""):
                # Gather event types from the response snippet
                event_types: List[str] = []
                for match in re.finditer(r"^event:\s*(\S+)", resp.text or "", re.MULTILINE):
                    evt = match.group(1)
                    if evt not in event_types:
                        event_types.append(evt)
                ep = APIEndpoint(
                    url=url,
                    api_type=APIType.SSE,
                    methods=["GET"],
                    content_types_returned=["text/event-stream"],
                    description="Server-Sent Events endpoint",
                    risk_score=_compute_risk(url, ["sse"]),
                    discovery_sources=[DiscoverySource.CRAWL],
                    sse_event_types=event_types,
                )
                return ep
        except Exception:
            pass
        return None


# ===========================================================================
# REST endpoint analyser
# ===========================================================================

class RESTProbe:
    """
    Actively probes a URL to determine whether it is a REST API endpoint,
    what HTTP methods it accepts, and what authentication scheme it uses.
    """

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    async def probe(self, url: str, source: DiscoverySource = DiscoverySource.CRAWL) -> Optional[APIEndpoint]:
        """Return an APIEndpoint if the URL looks like a REST endpoint, else None."""
        try:
            resp = await self._client.get(url, headers={"Accept": "application/json"}, timeout=10)
        except Exception:
            return None

        ct = resp.headers.get("content-type", "").lower()
        # Must return JSON or be an API-like path
        path = urlparse(url).path.lower()
        if not ("json" in ct or "api" in path or
                resp.status_code in (200, 201, 400, 401, 403, 404, 405, 422)):
            return None

        methods   = await self._discover_methods(url)
        auth      = _detect_auth_from_response(resp)
        params    = _extract_path_params(urlparse(url).path)
        query_str = urlparse(url).query
        if query_str:
            for k, _ in parse_qs(query_str).items():
                params.append(APIParameter(name=k, location=ParamLocation.QUERY))

        resp_schema: Optional[Dict[str, Any]] = None
        if "json" in ct:
            try:
                body = json.loads(resp.text or "{}")
                resp_schema = _infer_schema_from_value(body)
            except Exception:
                pass

        tags = _classify_endpoint(url)
        ep = APIEndpoint(
            url=url,
            api_type=APIType.REST,
            methods=methods,
            auth_schemes=auth,
            parameters=params,
            content_types_returned=[ct] if ct else [],
            response_schema=resp_schema,
            tags=tags,
            risk_score=_compute_risk(url, tags),
            discovery_sources=[source],
        )
        return ep

    async def _discover_methods(self, url: str) -> List[str]:
        """Use OPTIONS + a few test requests to build the accepted methods list."""
        methods: Set[str] = set()
        try:
            opt_resp = await self._client.options(url, timeout=8)
            allow = opt_resp.headers.get("Allow", opt_resp.headers.get("allow", ""))
            if allow:
                methods.update(m.strip().upper() for m in allow.split(",") if m.strip())
        except Exception:
            pass

        # If OPTIONS gave nothing, probe individually
        if not methods:
            for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                try:
                    resp = await self._client.request(method, url, timeout=6)
                    if resp.status_code not in (405, 501):
                        methods.add(method)
                except Exception:
                    pass

        return sorted(methods) or ["GET"]


def _classify_endpoint(url: str) -> List[str]:
    """Return coarse-grained category tags for a URL path."""
    path = urlparse(url).path.lower()
    tags: List[str] = []
    if any(k in path for k in ("login", "auth", "token", "session", "signin")):
        tags.append("auth")
    if any(k in path for k in ("admin", "dashboard", "manage", "panel")):
        tags.append("admin")
    if any(k in path for k in ("user", "account", "profile", "member")):
        tags.append("user")
    if any(k in path for k in ("upload", "file", "attachment", "media")):
        tags.append("upload")
    if any(k in path for k in ("pay", "payment", "billing", "invoice", "card")):
        tags.append("payment")
    if any(k in path for k in ("search", "query", "find", "lookup")):
        tags.append("search")
    if any(k in path for k in ("config", "setting", "preference", "option")):
        tags.append("config")
    if any(k in path for k in ("export", "download", "report")):
        tags.append("export")
    return tags


def _infer_schema_from_value(value: Any, depth: int = 0) -> Dict[str, Any]:
    """Heuristically build a JSON Schema from a sample response value."""
    if depth > 3:
        return {"type": "any"}
    if isinstance(value, dict):
        props = {k: _infer_schema_from_value(v, depth + 1) for k, v in list(value.items())[:30]}
        return {"type": "object", "properties": props}
    if isinstance(value, list):
        item_schema = _infer_schema_from_value(value[0], depth + 1) if value else {"type": "any"}
        return {"type": "array", "items": item_schema}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    return {"type": "null"}


# ===========================================================================
# SOAP / WSDL prober
# ===========================================================================

class SOAPProbe:
    """Detects SOAP endpoints and parses WSDL documents."""

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    async def probe(self, base_url: str) -> Tuple[List[APIEndpoint], Optional[str]]:
        """Try common WSDL paths and return any SOAP endpoints found."""
        endpoints: List[APIEndpoint] = []
        wsdl_raw: Optional[str] = None

        for path in _WSDL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await self._client.get(url, timeout=10)
                ct = resp.headers.get("content-type", "").lower()
                text = resp.text or ""
                if resp.status_code == 200 and (
                    "wsdl" in text.lower()[:200] or "definitions" in text.lower()[:200]
                    or any(c in ct for c in ("xml", "wsdl"))
                ):
                    wsdl_raw = text
                    eps = self._parse_wsdl(base_url, text)
                    endpoints.extend(eps)
                    break
            except Exception:
                pass

        return endpoints, wsdl_raw

    def _parse_wsdl(self, base_url: str, wsdl: str) -> List[APIEndpoint]:
        """
        Minimal WSDL parser — extracts service endpoints and operation names
        without pulling in a full XML library.
        """
        endpoints: List[APIEndpoint] = []
        # Extract soap:address location attributes
        for match in re.finditer(r'<soap(?:12)?:address\s+location=["\']([^"\']+)["\']', wsdl, re.I):
            ep_url = match.group(1)
            # Extract operation names from <operation name="...">
            ops = re.findall(r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', wsdl, re.I)
            params = [APIParameter(name=op, location=ParamLocation.BODY, data_type="xml")
                      for op in ops]
            ep = APIEndpoint(
                url=ep_url,
                api_type=APIType.SOAP,
                methods=["POST"],
                auth_schemes=[],
                parameters=params,
                content_types_accepted=["text/xml", "application/soap+xml"],
                content_types_returned=["text/xml"],
                description="SOAP Web Service",
                tags=["soap"],
                risk_score=6,
                discovery_sources=[DiscoverySource.WSDL],
            )
            endpoints.append(ep)
        return endpoints


# ===========================================================================
# gRPC prober
# ===========================================================================

class GRPCProbe:
    """
    Attempts to detect gRPC-Web or gRPC-JSON-Transcoding endpoints.
    Uses the gRPC reflection protocol when available.
    """

    def __init__(self, client: HTTPClient) -> None:
        self._client = client

    async def probe(self, base_url: str) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        for path in _GRPC_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await self._client.post(
                    url,
                    data=b"\x00\x00\x00\x00\x00",   # empty gRPC frame
                    headers={
                        "Content-Type": "application/grpc",
                        "TE": "trailers",
                    },
                    timeout=8,
                )
                ct = resp.headers.get("content-type", "").lower()
                if any(g in ct for g in ("grpc",)) or resp.status_code in (200, 400, 415):
                    ep = APIEndpoint(
                        url=url,
                        api_type=APIType.GRPC,
                        methods=["POST"],
                        content_types_accepted=["application/grpc", "application/grpc+proto"],
                        description="gRPC endpoint",
                        tags=["grpc"],
                        risk_score=7,
                        discovery_sources=[DiscoverySource.GRPC_REFLECT],
                    )
                    endpoints.append(ep)
                    break
            except Exception:
                pass
        return endpoints


# ===========================================================================
# Main API Discovery Engine
# ===========================================================================

class APIDiscoveryEngine:
    """
    Orchestrates the full API discovery process across all protocol families.

    Workflow:
      1.  Probe for OpenAPI / Swagger spec documents.
      2.  Probe for GraphQL endpoints and run introspection.
      3.  Probe for SOAP / WSDL.
      4.  Probe for gRPC / gRPC-Web.
      5.  Probe for Server-Sent Events streams.
      6.  Brute-force common REST API prefixes to confirm which are live.
      7.  Analyse crawled URLs to build REST endpoint inventory.
      8.  Actively probe each discovered URL for methods, auth, schema.
      9.  Detect WebSocket upgrade support on ws:// paths collected from JS.
     10.  Deduplicate, correlate relationships, and produce final report.
    """

    def __init__(
        self,
        client: HTTPClient,
        target: ScanTarget,
        crawled_urls: Optional[List[str]] = None,
        js_discovered_endpoints: Optional[List[str]] = None,
        concurrency: int = 20,
        timeout_per_request: float = 12.0,
    ) -> None:
        self._client = client
        self._target = target
        self._crawled_urls = crawled_urls or []
        self._js_endpoints = js_discovered_endpoints or []
        self._concurrency = concurrency
        self._timeout = timeout_per_request
        self._base_url = target.base_url.rstrip("/")

        # Sub-probes
        self._rest_probe  = RESTProbe(client)
        self._gql_probe   = GraphQLProbe(client)
        self._ws_probe    = WebSocketProbe(client)
        self._sse_probe   = SSEProbe(client)
        self._soap_probe  = SOAPProbe(client)
        self._grpc_probe  = GRPCProbe(client)

        self._semaphore = asyncio.Semaphore(concurrency)
        self._result = APIDiscoveryResult(target_url=self._base_url)

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def discover(self) -> APIDiscoveryResult:
        """Run the full API discovery pipeline and return structured results."""
        start = time.monotonic()

        await asyncio.gather(
            self._discover_openapi(),
            self._discover_graphql(),
            self._discover_soap(),
            self._discover_grpc(),
            self._discover_sse(),
        )

        await self._discover_rest_prefixes()
        await self._analyse_crawled_urls()
        await self._analyse_js_endpoints()
        await self._detect_websockets()

        self._correlate_relationships()

        self._result.scan_duration_seconds = round(time.monotonic() - start, 2)
        return self._result

    # -----------------------------------------------------------------------
    # Step 1 — OpenAPI / Swagger
    # -----------------------------------------------------------------------

    async def _discover_openapi(self) -> None:
        for path in _OPENAPI_PATHS:
            url = self._base_url + path
            try:
                async with self._semaphore:
                    resp = await self._client.get(url, timeout=10)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "").lower()
                text = resp.text or ""
                if "json" in ct:
                    spec = json.loads(text)
                elif "yaml" in ct or url.endswith((".yaml", ".yml")):
                    spec = self._parse_yaml_spec(text)
                else:
                    # Try JSON first then YAML
                    try:
                        spec = json.loads(text)
                    except Exception:
                        spec = self._parse_yaml_spec(text)

                if not isinstance(spec, dict):
                    continue
                # Confirm it is an OpenAPI/Swagger doc
                if not ("openapi" in spec or "swagger" in spec or "paths" in spec):
                    continue

                self._result.openapi_spec = spec
                parser = OpenAPIParser(self._base_url, spec)
                for ep in parser.parse():
                    self._result.add_endpoint(ep)

                # Identify and record confirmed API prefix
                parsed_path = urlparse(url).path
                prefix = "/".join(parsed_path.split("/")[:2])
                if prefix not in self._result.api_prefixes_confirmed:
                    self._result.api_prefixes_confirmed.append(prefix)
                break   # Use the first valid spec found

            except Exception:
                continue

    def _parse_yaml_spec(self, text: str) -> Dict[str, Any]:
        """
        Minimal YAML-to-dict parser for OpenAPI specs without external deps.
        Only handles simple key: value and nested dict/list structures.
        """
        try:
            # Attempt to use PyYAML if available
            import yaml  # type: ignore
            return yaml.safe_load(text) or {}
        except ImportError:
            pass
        # Ultra-minimal fallback: if it looks like JSON-convertible YAML
        # (single-line keys, quoted values) do basic conversion
        return {}

    # -----------------------------------------------------------------------
    # Step 2 — GraphQL
    # -----------------------------------------------------------------------

    async def _discover_graphql(self) -> None:
        candidates = list(_GRAPHQL_PATHS)
        # Also add any GraphQL paths found by the JS analyser
        for url in self._js_endpoints:
            if "graphql" in url.lower() or "gql" in url.lower():
                path = urlparse(url).path
                if path not in candidates:
                    candidates.append(path)

        tasks = [self._probe_graphql_path(p) for p in candidates]
        await asyncio.gather(*tasks)

    async def _probe_graphql_path(self, path: str) -> None:
        url = self._base_url + path if path.startswith("/") else path
        try:
            async with self._semaphore:
                is_gql = await self._gql_probe.is_graphql(url)
            if not is_gql:
                return
            async with self._semaphore:
                schema = await self._gql_probe.introspect(url)
            self._result.graphql_schema = schema
            for ep in self._gql_probe.schema_to_endpoints(url, schema):
                self._result.add_endpoint(ep)
            # Mark confirmed prefix
            prefix = urlparse(url).path
            if prefix not in self._result.api_prefixes_confirmed:
                self._result.api_prefixes_confirmed.append(prefix)
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 3 — SOAP
    # -----------------------------------------------------------------------

    async def _discover_soap(self) -> None:
        try:
            async with self._semaphore:
                endpoints, wsdl = await self._soap_probe.probe(self._base_url)
            if wsdl:
                self._result.wsdl_raw = wsdl
            for ep in endpoints:
                self._result.add_endpoint(ep)
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 4 — gRPC
    # -----------------------------------------------------------------------

    async def _discover_grpc(self) -> None:
        try:
            async with self._semaphore:
                endpoints = await self._grpc_probe.probe(self._base_url)
            for ep in endpoints:
                self._result.add_endpoint(ep)
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 5 — SSE
    # -----------------------------------------------------------------------

    async def _discover_sse(self) -> None:
        tasks = []
        for path in _SSE_PATHS:
            url = self._base_url + path
            tasks.append(self._probe_sse(url))
        await asyncio.gather(*tasks)

    async def _probe_sse(self, url: str) -> None:
        try:
            async with self._semaphore:
                ep = await self._sse_probe.detect(url)
            if ep:
                self._result.add_endpoint(ep)
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 6 — REST prefix brute-force
    # -----------------------------------------------------------------------

    async def _discover_rest_prefixes(self) -> None:
        tasks = [self._probe_rest_prefix(prefix) for prefix in _COMMON_API_PREFIXES]
        await asyncio.gather(*tasks)

    async def _probe_rest_prefix(self, prefix: str) -> None:
        url = self._base_url + prefix
        try:
            async with self._semaphore:
                resp = await self._client.get(
                    url,
                    headers={"Accept": "application/json"},
                    timeout=8,
                )
            ct = resp.headers.get("content-type", "").lower()
            if resp.status_code in (200, 201, 400, 401, 403) and (
                "json" in ct or "html" not in ct
            ):
                if prefix not in self._result.api_prefixes_confirmed:
                    self._result.api_prefixes_confirmed.append(prefix)
                ep = await self._rest_probe.probe(url, source=DiscoverySource.BRUTE_FORCE)
                if ep:
                    self._result.add_endpoint(ep)
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 7 — Analyse crawled URLs
    # -----------------------------------------------------------------------

    async def _analyse_crawled_urls(self) -> None:
        # Partition crawled URLs into groups by normalised path template
        api_urls = [u for u in self._crawled_urls if self._looks_like_api(u)]
        tasks = [self._analyse_single_url(u, DiscoverySource.CRAWL)
                 for u in api_urls[:500]]  # cap to avoid runaway
        await asyncio.gather(*tasks)

    async def _analyse_single_url(self, url: str, source: DiscoverySource) -> None:
        try:
            async with self._semaphore:
                ep = await self._rest_probe.probe(url, source=source)
            if ep:
                self._result.add_endpoint(ep)
        except Exception:
            pass

    def _looks_like_api(self, url: str) -> bool:
        """Heuristic: does this URL look like an API endpoint?"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query
        # Confirmed API prefix
        for prefix in self._result.api_prefixes_confirmed:
            if path.startswith(prefix):
                return True
        # Common API signals
        if any(seg in path for seg in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/json/")):
            return True
        if query and any(k in query for k in ("format=json", "output=json", "type=json")):
            return True
        # Path ends with a numeric ID → likely a resource
        if re.search(r"/\d+(/|$)", path):
            return True
        return False

    # -----------------------------------------------------------------------
    # Step 8 — Analyse JS-discovered endpoints
    # -----------------------------------------------------------------------

    async def _analyse_js_endpoints(self) -> None:
        tasks = []
        for url in self._js_endpoints:
            parsed = urlparse(url)
            if parsed.scheme in ("ws", "wss"):
                # Handled in step 9
                continue
            if parsed.scheme in ("http", "https") or not parsed.scheme:
                tasks.append(self._analyse_single_url(
                    url if parsed.scheme else urljoin(self._base_url, url),
                    DiscoverySource.JS_ANALYSIS,
                ))
        await asyncio.gather(*tasks)

    # -----------------------------------------------------------------------
    # Step 9 — WebSocket detection
    # -----------------------------------------------------------------------

    async def _detect_websockets(self) -> None:
        # Collect ws:// candidates from JS analysis
        ws_candidates: Set[str] = set()
        for url in self._js_endpoints:
            parsed = urlparse(url)
            if parsed.scheme in ("ws", "wss"):
                ws_candidates.add(url)
        # Also try common WS paths as HTTP to see if they respond to Upgrade
        for path in ["/ws", "/socket", "/socket.io", "/cable", "/hub", "/signalr"]:
            ws_candidates.add(self._base_url + path)

        tasks = [self._probe_websocket(url) for url in ws_candidates]
        await asyncio.gather(*tasks)

    async def _probe_websocket(self, url: str) -> None:
        http_url = url.replace("wss://", "https://").replace("ws://", "http://")
        try:
            async with self._semaphore:
                ep = await self._ws_probe.detect(http_url)
            if ep:
                self._result.add_endpoint(ep)
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 10 — Relationship correlation
    # -----------------------------------------------------------------------

    def _correlate_relationships(self) -> None:
        """
        Link endpoints that share a common resource path segment.
        e.g. /api/users and /api/users/{id} are related.
        """
        eps = self._result.endpoints
        for i, ep_a in enumerate(eps):
            path_a = urlparse(ep_a.url).path
            for ep_b in eps[i + 1:]:
                path_b = urlparse(ep_b.url).path
                # They are related if one is a prefix of the other
                shorter = min(path_a, path_b, key=len)
                longer  = max(path_a, path_b, key=len)
                if longer.startswith(shorter.rstrip("/") + "/"):
                    if ep_b.url not in ep_a.related_endpoints:
                        ep_a.related_endpoints.append(ep_b.url)
                    if ep_a.url not in ep_b.related_endpoints:
                        ep_b.related_endpoints.append(ep_a.url)
                # Also link same-base-path siblings
                elif (path_a.rsplit("/", 1)[0] == path_b.rsplit("/", 1)[0]
                      and path_a != path_b):
                    if ep_b.url not in ep_a.related_endpoints:
                        ep_a.related_endpoints.append(ep_b.url)
                    if ep_a.url not in ep_b.related_endpoints:
                        ep_b.related_endpoints.append(ep_a.url)


# ===========================================================================
# Convenience factory
# ===========================================================================

async def run_api_discovery(
    client: HTTPClient,
    target: ScanTarget,
    crawled_urls: Optional[List[str]] = None,
    js_endpoints: Optional[List[str]] = None,
    concurrency: int = 20,
) -> APIDiscoveryResult:
    """
    High-level entry point used by the Phase-2 orchestrator.

    Args:
        client:       Shared HTTP client instance.
        target:       Scan target specification.
        crawled_urls: URLs found by the crawling engine.
        js_endpoints: Endpoints extracted by the JS analysis engine.
        concurrency:  Max parallel probes.

    Returns:
        Fully-populated :class:`APIDiscoveryResult`.
    """
    engine = APIDiscoveryEngine(
        client=client,
        target=target,
        crawled_urls=crawled_urls,
        js_discovered_endpoints=js_endpoints,
        concurrency=concurrency,
    )
    return await engine.discover()
