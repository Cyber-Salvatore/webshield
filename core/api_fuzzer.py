"""
Smart API Fuzzing Engine — Phase 2.1

Schema-aware mutation engine that understands JSON structure and generates
intelligent test cases, rather than blind string injection.

Capabilities:
- JSON schema mutations (type confusion, boundary testing, mass assignment)
- Nested object traversal and deep mutation
- Prototype pollution probes (__proto__, constructor.prototype)
- Array manipulation (empty, oversized, wrong types)
- Numeric boundary testing (negative, overflow, zero, float as int)
- Path traversal in string fields
- Null / undefined injection
- Mass assignment: inject extra undeclared fields
- HTTP verb tampering helpers
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .http_client import HTTPClient, HTTPResponse


# ---------------------------------------------------------------------------
# Mutation categories
# ---------------------------------------------------------------------------

class MutationCategory:
    TYPE_CONFUSION   = "type_confusion"
    BOUNDARY         = "boundary"
    MASS_ASSIGNMENT  = "mass_assignment"
    PROTO_POLLUTION  = "proto_pollution"
    PATH_TRAVERSAL   = "path_traversal"
    INJECTION        = "injection"
    NULL_EMPTY       = "null_empty"
    ARRAY_ABUSE      = "array_abuse"
    OVERFLOW         = "overflow"


@dataclass
class MutationResult:
    """A single mutation with metadata."""
    category: str
    original_body: Dict[str, Any]
    mutated_body: Dict[str, Any]
    mutation_description: str
    target_field: Optional[str] = None  # dotted path e.g. "user.role"

    def to_json(self) -> str:
        return json.dumps(self.mutated_body)


# ---------------------------------------------------------------------------
# Mutation payloads
# ---------------------------------------------------------------------------

# String injection payloads to embed in string fields
_STRING_INJECTION_PAYLOADS: List[str] = [
    # SQLi
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    # XSS
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    # SSTI
    "{{7*7}}",
    "${7*7}",
    # Path traversal
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    # LDAP
    "*)(&",
    # Null byte
    "test\x00admin",
]

# Numeric boundaries
_INT_BOUNDARY_VALUES: List[Any] = [
    0, -1, 1, -999999999, 999999999,
    2**31 - 1,      # INT32_MAX
    2**31,          # INT32_MAX + 1
    -(2**31),       # INT32_MIN
    2**63 - 1,      # INT64_MAX
    0.001, -0.001,  # float as int
    "0", "-1",      # string as int (type confusion)
    None,
    True, False,    # bool as int
]

# Mass assignment: fields an API might accept but shouldn't
_MASS_ASSIGNMENT_FIELDS: Dict[str, Any] = {
    "role": "admin",
    "is_admin": True,
    "admin": True,
    "privilege": "admin",
    "user_role": "superadmin",
    "verified": True,
    "email_verified": True,
    "active": True,
    "enabled": True,
    "paid": True,
    "subscription": "premium",
    "credits": 99999,
    "balance": 99999.99,
    "price": 0,
    "discount": 100,
    "group": "admin",
    "permissions": ["*"],
    "scope": "admin:write",
    "level": 99,
    "__v": 0,
    "_id": "000000000000000000000000",
}

# Prototype pollution payloads
_PROTO_POLLUTION_PAYLOADS: List[Dict[str, Any]] = [
    {"__proto__": {"admin": True}},
    {"__proto__": {"role": "admin"}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"isAdmin": True, "role": "superadmin"}},
    {"prototype": {"polluted": True}},
]


# ---------------------------------------------------------------------------
# Core fuzzer
# ---------------------------------------------------------------------------

class APIFuzzer:
    """
    Schema-aware JSON mutation engine.

    Takes a baseline JSON body and generates a stream of mutated versions,
    each targeting a specific vulnerability class.

    Usage:
        fuzzer = APIFuzzer()
        for mutation in fuzzer.generate(body, schema=schema):
            response = await client.post_json(url, mutation.mutated_body)
            # analyze response
    """

    def __init__(
        self,
        max_mutations_per_field: int = 5,
        include_proto_pollution: bool = True,
        include_mass_assignment: bool = True,
        include_injection: bool = True,
    ) -> None:
        self.max_mutations_per_field = max_mutations_per_field
        self.include_proto_pollution = include_proto_pollution
        self.include_mass_assignment = include_mass_assignment
        self.include_injection = include_injection

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def generate(
        self,
        body: Dict[str, Any],
        schema: Optional[Dict[str, Any]] = None,
    ) -> Iterator[MutationResult]:
        """
        Generate all mutations for a given request body.

        Args:
            body:   The original JSON body (dict).
            schema: Optional JSON schema — used to understand field types.
                    If None, types are inferred from the body values.

        Yields:
            MutationResult for each mutation.
        """
        if not isinstance(body, dict):
            return

        # 1. Null / empty injection per field
        yield from self._null_empty_mutations(body)

        # 2. Type confusion per field
        yield from self._type_confusion_mutations(body, schema)

        # 3. Boundary testing on numeric fields
        yield from self._boundary_mutations(body, schema)

        # 4. String injection payloads in string fields
        if self.include_injection:
            yield from self._injection_mutations(body, schema)

        # 5. Mass assignment: inject extra admin fields
        if self.include_mass_assignment:
            yield from self._mass_assignment_mutations(body)

        # 6. Prototype pollution
        if self.include_proto_pollution:
            yield from self._proto_pollution_mutations(body)

        # 7. Array field abuse
        yield from self._array_abuse_mutations(body, schema)

        # 8. Nested object traversal
        yield from self._nested_mutations(body, schema)

    def generate_from_openapi_endpoint(
        self,
        endpoint_schema: Optional[Dict[str, Any]],
        example_body: Optional[Dict[str, Any]] = None,
    ) -> Iterator[MutationResult]:
        """
        Generate mutations from an OpenAPI request body schema.
        Builds a baseline body from schema defaults/examples first.
        """
        baseline = example_body or {}
        if endpoint_schema:
            baseline = self._schema_to_baseline(endpoint_schema, baseline)

        if not baseline:
            # No schema info — try basic mass assignment + proto pollution
            if self.include_mass_assignment:
                yield from self._mass_assignment_mutations({})
            if self.include_proto_pollution:
                yield from self._proto_pollution_mutations({})
            return

        yield from self.generate(baseline, schema=endpoint_schema)

    # -----------------------------------------------------------------------
    # Mutation generators
    # -----------------------------------------------------------------------

    def _null_empty_mutations(
        self, body: Dict[str, Any]
    ) -> Iterator[MutationResult]:
        """Null / empty string / empty object on each field."""
        null_values: List[Tuple[str, Any]] = [
            ("null", None),
            ("empty_string", ""),
            ("empty_object", {}),
            ("empty_array", []),
        ]
        for field_path, field_value in self._iter_flat_fields(body):
            for val_name, val in null_values[:2]:  # cap to null + empty string
                mutated = self._set_field(body, field_path, val)
                yield MutationResult(
                    category=MutationCategory.NULL_EMPTY,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Set {field_path} = {val_name}",
                    target_field=field_path,
                )

    def _type_confusion_mutations(
        self,
        body: Dict[str, Any],
        schema: Optional[Dict[str, Any]],
    ) -> Iterator[MutationResult]:
        """Send wrong types for each field (string→int, int→string, etc.)."""
        for field_path, field_value in self._iter_flat_fields(body):
            original_type = type(field_value).__name__

            # String → integer
            if isinstance(field_value, str):
                mutated = self._set_field(body, field_path, 1)
                yield MutationResult(
                    category=MutationCategory.TYPE_CONFUSION,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Type confusion: {field_path} string→int",
                    target_field=field_path,
                )
                # String → boolean
                mutated = self._set_field(body, field_path, True)
                yield MutationResult(
                    category=MutationCategory.TYPE_CONFUSION,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Type confusion: {field_path} string→bool",
                    target_field=field_path,
                )
                # String → array
                mutated = self._set_field(body, field_path, [field_value, field_value])
                yield MutationResult(
                    category=MutationCategory.TYPE_CONFUSION,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Type confusion: {field_path} string→array",
                    target_field=field_path,
                )

            # Integer → string
            elif isinstance(field_value, int):
                mutated = self._set_field(body, field_path, str(field_value))
                yield MutationResult(
                    category=MutationCategory.TYPE_CONFUSION,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Type confusion: {field_path} int→string",
                    target_field=field_path,
                )
                # Integer → array
                mutated = self._set_field(body, field_path, [field_value])
                yield MutationResult(
                    category=MutationCategory.TYPE_CONFUSION,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Type confusion: {field_path} int→array",
                    target_field=field_path,
                )

            # Boolean → string
            elif isinstance(field_value, bool):
                mutated = self._set_field(body, field_path, "true" if field_value else "false")
                yield MutationResult(
                    category=MutationCategory.TYPE_CONFUSION,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Type confusion: {field_path} bool→string",
                    target_field=field_path,
                )

    def _boundary_mutations(
        self,
        body: Dict[str, Any],
        schema: Optional[Dict[str, Any]],
    ) -> Iterator[MutationResult]:
        """Test numeric boundary values on integer/number fields."""
        boundary_subset = [0, -1, -999999999, 999999999, 2**31 - 1, 2**31, -(2**31)]
        for field_path, field_value in self._iter_flat_fields(body):
            if not isinstance(field_value, (int, float)):
                continue
            for val in boundary_subset:
                mutated = self._set_field(body, field_path, val)
                yield MutationResult(
                    category=MutationCategory.BOUNDARY,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Boundary: {field_path} = {val}",
                    target_field=field_path,
                )

    def _injection_mutations(
        self,
        body: Dict[str, Any],
        schema: Optional[Dict[str, Any]],
    ) -> Iterator[MutationResult]:
        """Inject attack payloads into string fields."""
        count = 0
        for field_path, field_value in self._iter_flat_fields(body):
            if not isinstance(field_value, str):
                continue
            for payload in _STRING_INJECTION_PAYLOADS[:self.max_mutations_per_field]:
                mutated = self._set_field(body, field_path, payload)
                yield MutationResult(
                    category=MutationCategory.INJECTION,
                    original_body=body,
                    mutated_body=mutated,
                    mutation_description=f"Injection: {field_path} = {payload[:50]}",
                    target_field=field_path,
                )
            count += 1
            if count >= 5:  # limit to first 5 string fields
                break

    def _mass_assignment_mutations(
        self, body: Dict[str, Any]
    ) -> Iterator[MutationResult]:
        """Add undeclared privilege-escalation fields to the body."""
        # Single-field probes
        for extra_field, extra_value in list(_MASS_ASSIGNMENT_FIELDS.items())[:10]:
            if extra_field in body:
                continue  # field already exists — still try to override
            mutated = copy.deepcopy(body)
            mutated[extra_field] = extra_value
            yield MutationResult(
                category=MutationCategory.MASS_ASSIGNMENT,
                original_body=body,
                mutated_body=mutated,
                mutation_description=f"Mass assignment: add {extra_field}={extra_value}",
                target_field=extra_field,
            )

        # Batch probe — send many privilege fields at once
        mutated = copy.deepcopy(body)
        batch_fields = {k: v for k, v in _MASS_ASSIGNMENT_FIELDS.items() if k not in body}
        if batch_fields:
            mutated.update(batch_fields)
            yield MutationResult(
                category=MutationCategory.MASS_ASSIGNMENT,
                original_body=body,
                mutated_body=mutated,
                mutation_description=f"Mass assignment: batch {len(batch_fields)} privilege fields",
                target_field="[batch]",
            )

    def _proto_pollution_mutations(
        self, body: Dict[str, Any]
    ) -> Iterator[MutationResult]:
        """Add __proto__ / constructor.prototype pollution fields."""
        for proto_payload in _PROTO_POLLUTION_PAYLOADS:
            mutated = copy.deepcopy(body)
            mutated.update(proto_payload)
            yield MutationResult(
                category=MutationCategory.PROTO_POLLUTION,
                original_body=body,
                mutated_body=mutated,
                mutation_description=f"Prototype pollution: {list(proto_payload.keys())[0]}",
                target_field=list(proto_payload.keys())[0],
            )

    def _array_abuse_mutations(
        self,
        body: Dict[str, Any],
        schema: Optional[Dict[str, Any]],
    ) -> Iterator[MutationResult]:
        """Abuse array fields: send oversized, wrong-type, or empty arrays."""
        for field_path, field_value in self._iter_flat_fields(body):
            if not isinstance(field_value, list):
                continue

            # Empty array
            mutated = self._set_field(body, field_path, [])
            yield MutationResult(
                category=MutationCategory.ARRAY_ABUSE,
                original_body=body,
                mutated_body=mutated,
                mutation_description=f"Array abuse: {field_path} = []",
                target_field=field_path,
            )

            # Oversized array (500 elements)
            mutated = self._set_field(
                body, field_path,
                (field_value * 500)[:500] if field_value else ["test"] * 500
            )
            yield MutationResult(
                category=MutationCategory.ARRAY_ABUSE,
                original_body=body,
                mutated_body=mutated,
                mutation_description=f"Array abuse: {field_path} oversized (500 items)",
                target_field=field_path,
            )

            # Wrong type in array: inject injection payload as single element
            mutated = self._set_field(body, field_path, ["' OR '1'='1"])
            yield MutationResult(
                category=MutationCategory.INJECTION,
                original_body=body,
                mutated_body=mutated,
                mutation_description=f"Array injection: {field_path}[0] = SQLi payload",
                target_field=field_path,
            )

    def _nested_mutations(
        self,
        body: Dict[str, Any],
        schema: Optional[Dict[str, Any]],
    ) -> Iterator[MutationResult]:
        """Probe nested objects with path traversal payloads."""
        for field_path, field_value in self._iter_flat_fields(body):
            if not isinstance(field_value, dict):
                continue
            # Inject path traversal into nested string values
            for nested_key, nested_val in field_value.items():
                if isinstance(nested_val, str):
                    full_path = f"{field_path}.{nested_key}"
                    mutated = self._set_field(
                        body, full_path, "../../etc/passwd"
                    )
                    yield MutationResult(
                        category=MutationCategory.PATH_TRAVERSAL,
                        original_body=body,
                        mutated_body=mutated,
                        mutation_description=f"Path traversal in nested: {full_path}",
                        target_field=full_path,
                    )
                    break  # one per nested object

    # -----------------------------------------------------------------------
    # Schema → baseline body builder
    # -----------------------------------------------------------------------

    def _schema_to_baseline(
        self,
        schema: Dict[str, Any],
        existing: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build a minimal valid request body from a JSON schema.
        Uses schema examples, defaults, or type-based fallbacks.
        """
        result = copy.deepcopy(existing)
        properties = schema.get("properties", {})

        for prop_name, prop_schema in properties.items():
            if prop_name in result:
                continue  # keep existing value
            result[prop_name] = self._schema_value(prop_schema, prop_name)

        return result

    def _schema_value(self, prop_schema: Dict[str, Any], field_name: str) -> Any:
        """Generate a single test value from a property schema."""
        if not isinstance(prop_schema, dict):
            return "test"

        # Use schema example first
        if "example" in prop_schema:
            return prop_schema["example"]

        # Use default
        if "default" in prop_schema:
            return prop_schema["default"]

        # Use first enum value
        if "enum" in prop_schema and prop_schema["enum"]:
            return prop_schema["enum"][0]

        prop_type = prop_schema.get("type", "string")

        if prop_type == "integer" or prop_type == "number":
            return 1
        elif prop_type == "boolean":
            return True
        elif prop_type == "array":
            items_schema = prop_schema.get("items", {})
            return [self._schema_value(items_schema, field_name + "_item")]
        elif prop_type == "object":
            return self._schema_to_baseline(prop_schema, {})
        else:  # string
            # Use field name as hint
            name_lower = field_name.lower()
            if "email" in name_lower:
                return "test@example.com"
            elif "url" in name_lower or "uri" in name_lower:
                return "https://example.com"
            elif "id" in name_lower:
                return "1"
            elif "date" in name_lower or "time" in name_lower:
                return "2024-01-01T00:00:00Z"
            elif "pass" in name_lower or "secret" in name_lower:
                return "TestPass123!"
            else:
                return "test"

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _iter_flat_fields(
        self,
        obj: Dict[str, Any],
        prefix: str = "",
        max_depth: int = 3,
        _depth: int = 0,
    ) -> Iterator[Tuple[str, Any]]:
        """Iterate over all leaf fields with their dotted paths."""
        if _depth >= max_depth:
            return
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            yield path, value
            if isinstance(value, dict) and _depth < max_depth - 1:
                yield from self._iter_flat_fields(value, path, max_depth, _depth + 1)

    @staticmethod
    def _set_field(
        body: Dict[str, Any],
        field_path: str,
        value: Any,
    ) -> Dict[str, Any]:
        """
        Return a deep copy of body with the field at field_path set to value.
        Handles dotted paths like "user.profile.name".
        """
        result = copy.deepcopy(body)
        parts = field_path.split(".")
        current = result
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value
        return result


# ---------------------------------------------------------------------------
# HTTPClient extension helper
# ---------------------------------------------------------------------------

async def post_json_mutation(
    client: HTTPClient,
    url: str,
    mutation: MutationResult,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Optional[HTTPResponse]:
    """
    Convenience wrapper — sends a mutated JSON body and returns the response.
    Attaches a custom header to identify mutated requests in proxies/logs.
    """
    headers = {"X-WebShield-Mutation": mutation.category}
    if extra_headers:
        headers.update(extra_headers)
    return await client.post(
        url,
        json=mutation.mutated_body,
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Standalone convenience function
# ---------------------------------------------------------------------------

def generate_mutations(
    body: Dict[str, Any],
    schema: Optional[Dict[str, Any]] = None,
    *,
    include_injection: bool = True,
    include_mass_assignment: bool = True,
    include_proto_pollution: bool = True,
) -> List[MutationResult]:
    """
    Generate all mutations for a body dict and return as a list.
    Useful for testing or passing to a scanner.
    """
    fuzzer = APIFuzzer(
        include_injection=include_injection,
        include_mass_assignment=include_mass_assignment,
        include_proto_pollution=include_proto_pollution,
    )
    return list(fuzzer.generate(body, schema))
