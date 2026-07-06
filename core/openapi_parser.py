"""
OpenAPI / Swagger Discovery & Parser.

Automatically discovers OpenAPI 3.x and Swagger 2.0 spec files,
parses them, and extracts:
- All endpoints with HTTP methods
- Path & query parameters with types and constraints
- Request body schemas
- Authentication requirements
- Server base URLs
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from .http_client import HTTPClient
from ..utils.helpers import normalize_url, get_base_url

# YAML support is optional
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Well-known spec file locations
# ---------------------------------------------------------------------------

SPEC_PATHS: List[str] = [
    # OpenAPI 3.x
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    # Swagger 2.0
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    # Standard API docs paths
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/docs.json",
    # Versioned
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v1/swagger.json",
    # Common framework defaults
    "/swagger-ui.html",          # Springfox (check for embedded spec)
    "/swagger-ui/index.html",    # Springdoc
    "/redoc",                    # ReDoc
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    # FastAPI
    "/docs",
    "/redoc",
    # Django REST Framework
    "/schema/",
    "/schema.json",
    "/schema.yaml",
    # NestJS
    "/api",
    "/api-json",
    "/api-yaml",
    # Laravel (L5-Swagger)
    "/api/documentation",
    "/docs/api-docs.json",
    # Node/Express
    "/api/swagger",
    "/documentation",
    # WordPress
    "/wp-json",
    "/wp-json/openapi/v1",
    # Misc
    "/api.json",
    "/api.yaml",
    "/endpoints",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class APIParameter:
    """A single parameter for an API endpoint."""
    name: str
    location: str           # "path", "query", "header", "cookie", "body"
    required: bool = False
    param_type: str = "string"   # string, integer, boolean, array, object
    description: str = ""
    enum_values: List[str] = field(default_factory=list)
    example: Optional[Any] = None
    schema: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "in": self.location,
            "required": self.required,
            "type": self.param_type,
            "description": self.description,
        }


@dataclass
class APIEndpoint:
    """A single API endpoint extracted from a spec."""
    path: str               # raw path: /users/{id}
    method: str             # GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
    operation_id: Optional[str] = None
    summary: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    parameters: List[APIParameter] = field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    request_body_content_types: List[str] = field(default_factory=list)
    requires_auth: bool = False
    auth_schemes: List[str] = field(default_factory=list)
    response_codes: List[int] = field(default_factory=list)
    deprecated: bool = False                # marked as deprecated in spec

    @property
    def path_params(self) -> List[APIParameter]:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def query_params(self) -> List[APIParameter]:
        return [p for p in self.parameters if p.location == "query"]

    @property
    def header_params(self) -> List[APIParameter]:
        return [p for p in self.parameters if p.location == "header"]

    def concrete_path(self, base_url: str) -> str:
        """
        Convert /users/{id} to a testable URL like https://api.example.com/users/1.
        Fills path params with type-appropriate test values.
        """
        path = self.path
        for param in self.path_params:
            placeholder = "{" + param.name + "}"
            if placeholder in path:
                path = path.replace(placeholder, self._test_value(param))
        return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    @staticmethod
    def _test_value(param: APIParameter) -> str:
        """Generate a safe test value for a path parameter."""
        if param.enum_values:
            return str(param.enum_values[0])
        if param.example is not None:
            return str(param.example)
        # Use schema-level example if present
        if param.schema:
            schema_example = param.schema.get("example")
            if schema_example is not None:
                return str(schema_example)
            # Use first enum value from schema
            schema_enum = param.schema.get("enum")
            if schema_enum:
                return str(schema_enum[0])
        type_defaults = {
            "integer": "1",
            "number":  "1.0",
            "boolean": "true",
            "string":  "test",
        }
        return type_defaults.get(param.param_type, "1")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "operation_id": self.operation_id,
            "summary": self.summary,
            "tags": self.tags,
            "parameters": [p.to_dict() for p in self.parameters],
            "requires_auth": self.requires_auth,
            "auth_schemes": self.auth_schemes,
            "deprecated": self.deprecated,
        }


@dataclass
class APISpec:
    """Parsed representation of an OpenAPI / Swagger spec."""
    spec_url: str
    spec_version: str       # "openapi-3.0", "openapi-3.1", "swagger-2.0"
    title: str = ""
    description: str = ""
    version: str = ""
    servers: List[str] = field(default_factory=list)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    global_security_schemes: List[str] = field(default_factory=list)
    raw: Optional[Dict[str, Any]] = field(default=None, repr=False)

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    @property
    def authenticated_endpoints(self) -> List[APIEndpoint]:
        return [e for e in self.endpoints if e.requires_auth]

    @property
    def unauthenticated_endpoints(self) -> List[APIEndpoint]:
        return [e for e in self.endpoints if not e.requires_auth]

    def all_concrete_urls(self, fallback_base: str) -> List[Tuple[str, str]]:
        """
        Return list of (method, concrete_url) tuples, ready for scanning.
        Uses the first server from the spec, falling back to fallback_base.
        """
        base = (self.servers[0] if self.servers else fallback_base).rstrip("/")
        return [
            (ep.method, ep.concrete_path(base))
            for ep in self.endpoints
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spec_url": self.spec_url,
            "version": self.spec_version,
            "title": self.title,
            "servers": self.servers,
            "endpoint_count": self.endpoint_count,
            "endpoints": [e.to_dict() for e in self.endpoints],
        }


# ---------------------------------------------------------------------------
# Discovery & Parser
# ---------------------------------------------------------------------------

class OpenAPIParser:
    """
    Discovers and parses OpenAPI / Swagger specs from a target.

    Usage:
        parser = OpenAPIParser(client, base_url="https://api.example.com")
        specs  = await parser.discover_and_parse()
        for spec in specs:
            for method, url in spec.all_concrete_urls(base_url):
                # test the endpoint
    """

    def __init__(
        self,
        client: HTTPClient,
        base_url: str,
        extra_paths: Optional[List[str]] = None,
    ) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.extra_paths = extra_paths or []
        self._discovered_spec_urls: Set[str] = set()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def discover_and_parse(self) -> List[APISpec]:
        """
        Probe all well-known spec paths, parse any found specs.
        Returns list of APISpec objects (one per spec file found).
        """
        spec_urls = await self._discover_spec_urls()
        specs: List[APISpec] = []
        for url in spec_urls:
            spec = await self._fetch_and_parse(url)
            if spec:
                specs.append(spec)
        return specs

    async def parse_from_url(self, url: str) -> Optional[APISpec]:
        """Parse a spec from a known URL directly."""
        return await self._fetch_and_parse(url)

    async def parse_from_content(self, content: str, source_url: str) -> Optional[APISpec]:
        """Parse spec content already in memory."""
        raw = self._parse_content(content)
        if raw is None:
            return None
        return self._build_spec(raw, source_url)

    # -----------------------------------------------------------------------
    # Discovery
    # -----------------------------------------------------------------------

    async def _discover_spec_urls(self) -> List[str]:
        """Probe all candidate paths and return URLs that return a valid spec."""
        all_paths = SPEC_PATHS + self.extra_paths
        found: List[str] = []

        import asyncio
        semaphore = asyncio.Semaphore(10)

        async def probe(path: str) -> Optional[str]:
            async with semaphore:
                url = f"{self.base_url}{path}"
                try:
                    resp = await self.client.get(url)
                    if resp is None or resp.status_code not in (200, 206):
                        return None
                    ct = resp.content_type.lower()
                    body = resp.text.strip()

                    # Must be JSON or YAML and look like a spec
                    if not body:
                        return None

                    # JSON spec check
                    if "json" in ct or body.startswith("{"):
                        try:
                            data = json.loads(body)
                            if self._looks_like_spec(data):
                                return url
                        except json.JSONDecodeError:
                            pass

                    # YAML spec check
                    if YAML_AVAILABLE and ("yaml" in ct or body.startswith("openapi:") or body.startswith("swagger:")):
                        try:
                            data = yaml.safe_load(body)
                            if self._looks_like_spec(data):
                                return url
                        except Exception:
                            pass

                    # HTML page — extract embedded spec URL (Swagger UI)
                    if "html" in ct:
                        embedded = self._extract_spec_url_from_html(body, url)
                        if embedded and embedded not in self._discovered_spec_urls:
                            self._discovered_spec_urls.add(embedded)
                            return embedded

                except Exception:
                    pass
                return None

        results = await asyncio.gather(*[probe(p) for p in all_paths])
        for r in results:
            if r and r not in self._discovered_spec_urls:
                self._discovered_spec_urls.add(r)
                found.append(r)

        return found

    @staticmethod
    def _looks_like_spec(data: Any) -> bool:
        """Quick check if a parsed dict looks like an OpenAPI/Swagger spec."""
        if not isinstance(data, dict):
            return False
        return (
            "openapi" in data
            or "swagger" in data
            or ("paths" in data and "info" in data)
        )

    @staticmethod
    def _extract_spec_url_from_html(html: str, page_url: str) -> Optional[str]:
        """Extract the spec URL embedded in a Swagger UI / ReDoc HTML page."""
        patterns = [
            re.compile(r'url\s*:\s*[\'"]([^\'\"]+\.(?:json|yaml|yml))[\'"]'),
            re.compile(r'spec-url=[\'"]([^\'\"]+)[\'"]'),
            re.compile(r'data-url=[\'"]([^\'\"]+)[\'"]'),
            re.compile(r'"url"\s*:\s*"([^"]+openapi[^"]*)"'),
            re.compile(r'"url"\s*:\s*"([^"]+swagger[^"]*)"'),
            re.compile(r'"url"\s*:\s*"([^"]+api-docs[^"]*)"'),
        ]
        for pattern in patterns:
            match = pattern.search(html)
            if match:
                path = match.group(1)
                return urljoin(page_url, path)
        return None

    # -----------------------------------------------------------------------
    # Fetching & parsing
    # -----------------------------------------------------------------------

    async def _fetch_and_parse(self, url: str) -> Optional[APISpec]:
        """Fetch a spec URL and return a parsed APISpec."""
        try:
            resp = await self.client.get(url)
            if resp is None or resp.status_code not in (200, 206):
                return None
            raw = self._parse_content(resp.text)
            if raw is None:
                return None
            return self._build_spec(raw, url)
        except Exception:
            return None

    def _parse_content(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse JSON or YAML content into a dict."""
        content = content.strip()
        # Try JSON first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        # Try YAML
        if YAML_AVAILABLE:
            try:
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return None

    # -----------------------------------------------------------------------
    # Spec building
    # -----------------------------------------------------------------------

    def _build_spec(self, raw: Dict[str, Any], spec_url: str) -> APISpec:
        """Convert raw spec dict into a structured APISpec."""
        # Detect version
        if "openapi" in raw:
            ver_str = str(raw["openapi"])
            if ver_str.startswith("3.1"):
                version = "openapi-3.1"
            else:
                version = "openapi-3.0"
        elif "swagger" in raw:
            version = "swagger-2.0"
        else:
            version = "unknown"

        info = raw.get("info", {})
        spec = APISpec(
            spec_url=spec_url,
            spec_version=version,
            title=info.get("title", ""),
            description=info.get("description", ""),
            version=info.get("version", ""),
            raw=raw,
        )

        # Extract server base URLs
        spec.servers = self._extract_servers(raw, spec_url)

        # Extract global security schemes
        spec.global_security_schemes = self._extract_security_scheme_names(raw)

        # Extract endpoints
        paths = raw.get("paths", {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            # Resolve $ref at path level
            path_item = self._resolve_ref(path_item, raw)

            # Shared parameters for all operations on this path
            shared_params = self._parse_parameters(
                path_item.get("parameters", []), raw
            )

            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                operation = self._resolve_ref(operation, raw)
                endpoint = self._parse_operation(
                    path=path,
                    method=method.upper(),
                    operation=operation,
                    shared_params=shared_params,
                    spec_version=version,
                    raw_spec=raw,
                    global_security=spec.global_security_schemes,
                )
                spec.endpoints.append(endpoint)

        return spec

    def _parse_operation(
        self,
        path: str,
        method: str,
        operation: Dict[str, Any],
        shared_params: List[APIParameter],
        spec_version: str,
        raw_spec: Dict[str, Any],
        global_security: List[str],
    ) -> APIEndpoint:
        """Build an APIEndpoint from an operation object."""
        # Merge shared + operation-specific parameters
        op_params = self._parse_parameters(operation.get("parameters", []), raw_spec)
        # Operation params override shared params with same name+location
        param_map: Dict[Tuple[str, str], APIParameter] = {}
        for p in shared_params:
            param_map[(p.name, p.location)] = p
        for p in op_params:
            param_map[(p.name, p.location)] = p
        parameters = list(param_map.values())

        # Request body (OpenAPI 3.x)
        body_schema, body_content_types = self._parse_request_body(
            operation.get("requestBody", {}), raw_spec, spec_version
        )
        # Swagger 2.0 body parameter
        if spec_version == "swagger-2.0":
            for p in parameters:
                if p.location == "body" and p.schema:
                    body_schema = p.schema
                    body_content_types = ["application/json"]

        # Security
        op_security = operation.get("security")
        if op_security is None:
            # Inherit global security
            requires_auth = bool(global_security)
            auth_schemes = list(global_security)
        elif op_security == []:
            # Explicitly no security (public endpoint)
            requires_auth = False
            auth_schemes = []
        else:
            requires_auth = True
            auth_schemes = [
                scheme
                for sec_req in op_security
                for scheme in (sec_req.keys() if isinstance(sec_req, dict) else [])
            ]

        # Response codes
        response_codes = [
            int(code)
            for code in operation.get("responses", {}).keys()
            if str(code).isdigit()
        ]

        return APIEndpoint(
            path=path,
            method=method,
            operation_id=operation.get("operationId"),
            summary=operation.get("summary", ""),
            description=operation.get("description", ""),
            tags=operation.get("tags", []),
            parameters=parameters,
            request_body_schema=body_schema,
            request_body_content_types=body_content_types,
            requires_auth=requires_auth,
            auth_schemes=auth_schemes,
            response_codes=response_codes,
            deprecated=bool(operation.get("deprecated", False)),
        )

    def _parse_parameters(
        self, params: List[Any], raw_spec: Dict[str, Any]
    ) -> List[APIParameter]:
        """Parse a list of parameter objects."""
        result: List[APIParameter] = []
        for p in params:
            if not isinstance(p, dict):
                continue
            p = self._resolve_ref(p, raw_spec)
            schema = p.get("schema", {}) or {}

            # Type: OpenAPI 3.x uses schema.type, Swagger 2.0 uses type directly
            param_type = (
                schema.get("type")
                or p.get("type", "string")
            )

            result.append(APIParameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=p.get("required", False),
                param_type=str(param_type),
                description=p.get("description", ""),
                enum_values=[str(v) for v in (schema.get("enum") or p.get("enum") or [])],
                example=schema.get("example") or p.get("example"),
                schema=schema if schema else None,
            ))
        return result

    def _parse_request_body(
        self,
        body: Any,
        raw_spec: Dict[str, Any],
        spec_version: str,
    ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Extract request body schema and content types (OpenAPI 3.x)."""
        if not body or not isinstance(body, dict):
            return None, []

        body = self._resolve_ref(body, raw_spec)
        content = body.get("content", {})
        if not content:
            return None, []

        content_types = list(content.keys())
        # Prefer JSON, fall back to first content type
        preferred = "application/json"
        ct = preferred if preferred in content else (content_types[0] if content_types else None)

        if ct:
            schema = content[ct].get("schema")
            if schema:
                schema = self._resolve_ref(schema, raw_spec)
                return schema, content_types

        return None, content_types

    def _extract_servers(self, raw: Dict[str, Any], spec_url: str) -> List[str]:
        """Extract server base URLs from the spec."""
        servers: List[str] = []

        # OpenAPI 3.x
        for server in raw.get("servers", []):
            url = server.get("url", "")
            if url:
                if url.startswith("/"):
                    url = urljoin(self.base_url, url)
                servers.append(url.rstrip("/"))

        # Swagger 2.0
        if not servers and "host" in raw:
            scheme = (raw.get("schemes") or ["https"])[0]
            base_path = raw.get("basePath", "/")
            servers.append(f"{scheme}://{raw['host']}{base_path}".rstrip("/"))

        # Default: use the URL the spec was fetched from
        if not servers:
            parsed = urlparse(spec_url)
            servers.append(f"{parsed.scheme}://{parsed.netloc}")

        return servers

    @staticmethod
    def _extract_security_scheme_names(raw: Dict[str, Any]) -> List[str]:
        """Extract names of globally required security schemes."""
        security = raw.get("security", [])
        if not security:
            return []
        names: List[str] = []
        for req in security:
            if isinstance(req, dict):
                names.extend(req.keys())
        return names

    # -----------------------------------------------------------------------
    # $ref resolution — handles multi-level chains and allOf/anyOf/oneOf
    # -----------------------------------------------------------------------

    @staticmethod
    def _resolve_ref(
        obj: Dict[str, Any],
        raw_spec: Dict[str, Any],
        _depth: int = 0,
    ) -> Dict[str, Any]:
        """
        Recursively resolve JSON $ref pointers within the same document.

        Handles:
        - Single-level: {"$ref": "#/components/schemas/User"}
        - Chained refs: A → B → C (up to 10 levels deep)
        - allOf / anyOf / oneOf: merges first schema found
        - External refs (http / file) are skipped safely
        """
        if _depth > 10:
            return obj
        if not isinstance(obj, dict):
            return obj

        # Resolve $ref
        if "$ref" in obj:
            ref = obj["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                return obj  # external ref — skip
            parts = ref.lstrip("#/").split("/")
            current: Any = raw_spec
            try:
                for part in parts:
                    part = part.replace("~1", "/").replace("~0", "~")
                    current = current[part]
            except (KeyError, TypeError):
                return obj
            if not isinstance(current, dict):
                return obj
            # Recurse — the resolved object may itself contain a $ref
            return OpenAPIParser._resolve_ref(current, raw_spec, _depth + 1)

        # Flatten allOf / anyOf / oneOf by merging schemas
        for combiner in ("allOf", "anyOf", "oneOf"):
            if combiner in obj:
                schemas = obj[combiner]
                if not isinstance(schemas, list) or not schemas:
                    continue
                merged: Dict[str, Any] = {}
                for sub in schemas:
                    resolved = OpenAPIParser._resolve_ref(
                        sub if isinstance(sub, dict) else {}, raw_spec, _depth + 1
                    )
                    merged.update(resolved)
                # Keep any sibling keys (e.g. description alongside allOf)
                result = {k: v for k, v in obj.items() if k != combiner}
                result.update(merged)
                return result

        return obj
