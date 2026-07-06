from .helpers import (
    normalize_url, get_base_url, is_same_domain, is_in_scope,
    inject_payload_into_url, extract_params, url_encode, build_url,
    add_scheme, decode_jwt_header, decode_jwt_payload, forge_jwt_none_alg,
    Timer, truncate, sanitize_for_html, extract_forms_from_html,
    fingerprint_hash, is_binary_content, parse_cookie_attributes,
    severity_color, RESET_COLOR, BOLD, GREEN, CYAN, DIM,
)
from .payloads import (
    SQLI_ERROR_BASED, SQLI_UNION_BASED, SQLI_BOOLEAN_BASED, SQLI_TIME_BASED,
    SQLI_ALL, XSS_BASIC, XSS_FILTER_BYPASS, XSS_DOM, XSS_ALL,
    CMDI_UNIX, CMDI_WINDOWS, CMDI_ALL, PATH_TRAVERSAL, SSRF_PAYLOADS,
    XXE_PAYLOADS, OPEN_REDIRECT, JWT_WEAK_SECRETS, JWT_NONE_ALG_HEADER,
    REQUIRED_SECURITY_HEADERS, INSECURE_RESPONSE_HEADERS, SENSITIVE_DATA_PATTERNS,
)
from .patterns import (
    SQLI_ERROR_PATTERNS, XSS_REFLECTION_MARKERS, CMDI_RESPONSE_PATTERNS,
    LFI_RESPONSE_PATTERNS, SSRF_RESPONSE_PATTERNS, SENSITIVE_DATA_COMPILED,
    OPEN_REDIRECT_DOMAINS, JWT_PATTERN, JWT_ALG_NONE, SMUGGLING_PATTERNS,
    BROKEN_AUTH_PATTERNS, AUTH_WEAK_COOKIE_FLAGS, TECH_FINGERPRINTS,
)
# ── Phase 4 — Response Analysis Engine ──────────────────────────────────────
from .response_analyzer import ResponseAnalyzer, SimilarityResult
from .confidence_engine import (
    ConfidenceEngine, ConfidenceInput, ConfidenceResult, EvidenceQuality,
)
from .timing_analyzer import TimingAnalyzer, TimingStats, AnomalyResult
from .reflection_tracker import (
    ReflectionTracker, ReflectionResult, ReflectionContext, Transformation,
)

__all__ = [
    "normalize_url", "get_base_url", "is_same_domain", "is_in_scope",
    "inject_payload_into_url", "extract_params", "url_encode", "build_url",
    "add_scheme", "decode_jwt_header", "decode_jwt_payload", "forge_jwt_none_alg",
    "Timer", "truncate", "sanitize_for_html", "extract_forms_from_html",
    "fingerprint_hash", "is_binary_content", "parse_cookie_attributes",
    "severity_color", "RESET_COLOR", "BOLD", "GREEN", "CYAN", "DIM",
    "SQLI_ERROR_BASED", "SQLI_UNION_BASED", "SQLI_BOOLEAN_BASED", "SQLI_TIME_BASED",
    "SQLI_ALL", "XSS_BASIC", "XSS_FILTER_BYPASS", "XSS_DOM", "XSS_ALL",
    "CMDI_UNIX", "CMDI_WINDOWS", "CMDI_ALL", "PATH_TRAVERSAL", "SSRF_PAYLOADS",
    "XXE_PAYLOADS", "OPEN_REDIRECT", "JWT_WEAK_SECRETS", "JWT_NONE_ALG_HEADER",
    "REQUIRED_SECURITY_HEADERS", "INSECURE_RESPONSE_HEADERS", "SENSITIVE_DATA_PATTERNS",
    "SQLI_ERROR_PATTERNS", "XSS_REFLECTION_MARKERS", "CMDI_RESPONSE_PATTERNS",
    "LFI_RESPONSE_PATTERNS", "SSRF_RESPONSE_PATTERNS", "SENSITIVE_DATA_COMPILED",
    "OPEN_REDIRECT_DOMAINS", "JWT_PATTERN", "JWT_ALG_NONE", "SMUGGLING_PATTERNS",
    "BROKEN_AUTH_PATTERNS", "AUTH_WEAK_COOKIE_FLAGS", "TECH_FINGERPRINTS",
    # Phase 4
    "ResponseAnalyzer", "SimilarityResult",
    "ConfidenceEngine", "ConfidenceInput", "ConfidenceResult", "EvidenceQuality",
    "TimingAnalyzer", "TimingStats", "AnomalyResult",
    "ReflectionTracker", "ReflectionResult", "ReflectionContext", "Transformation",
]
