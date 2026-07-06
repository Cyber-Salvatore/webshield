"""
Utility helper functions for WebShield.
"""

from __future__ import annotations
import base64
import hashlib
import json
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse


# ---------------------------------------------------------------------------
# URL Utilities
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Normalize a URL: ensure scheme, strip fragments."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    # Remove fragments
    return urlunparse(parsed._replace(fragment=""))


def get_base_url(url: str) -> str:
    """Return scheme://host:port from a URL."""
    parsed = urlparse(url)
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs share the same domain."""
    return urlparse(url1).netloc == urlparse(url2).netloc


def is_in_scope(url: str, target: str, scope_domain: Optional[str] = None) -> bool:
    """Check if a URL is within the allowed scanning scope."""
    target_parsed = urlparse(target)
    url_parsed = urlparse(url)
    if scope_domain:
        return url_parsed.hostname == scope_domain or (
            url_parsed.hostname is not None and
            url_parsed.hostname.endswith("." + scope_domain)
        )
    return url_parsed.hostname == target_parsed.hostname


def inject_payload_into_url(url: str, param: str, payload: str) -> str:
    """Replace a parameter value in a URL query string with a payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def extract_params(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from a URL."""
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def build_url(base: str, path: str) -> str:
    return urljoin(base, path)


def add_scheme(url: str, default: str = "https") -> str:
    if "://" not in url:
        return f"{default}://{url}"
    return url


# ---------------------------------------------------------------------------
# JWT Utilities
# ---------------------------------------------------------------------------

def decode_jwt_header(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT header without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header = parts[0]
        # Pad to correct length
        padded = header + "=" * (-len(header) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return None


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        padded = payload + "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return None


def forge_jwt_none_alg(token: str) -> Optional[str]:
    """Attempt to forge a JWT using algorithm=none attack."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        # Replace header with none alg
        new_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        # Keep the original payload, empty signature
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Timing Utilities
# ---------------------------------------------------------------------------

class Timer:
    """Context manager for timing operations."""

    def __init__(self) -> None:
        self.start: float = 0.0
        self.elapsed: float = 0.0

    def __enter__(self) -> "Timer":
        self.start = time.monotonic()
        return self

    def __exit__(self, *args: Any) -> None:
        self.elapsed = time.monotonic() - self.start


def measure_response_time(func: Any) -> Any:
    """Decorator to measure response time of HTTP calls."""
    import functools
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Tuple[Any, float]:
        start = time.monotonic()
        result = func(*args, **kwargs)
        elapsed = time.monotonic() - start
        return result, elapsed
    return wrapper


# ---------------------------------------------------------------------------
# String & Data Utilities
# ---------------------------------------------------------------------------

def truncate(text: str, length: int = 200) -> str:
    """Truncate a string for display."""
    if len(text) <= length:
        return text
    return text[:length] + "..."


def sanitize_for_html(text: str) -> str:
    """
    Fix 5.4: Escape all HTML special characters to prevent XSS in the
    generated HTML report.  Handles non-string input gracefully.

    Order matters: & must be escaped first to avoid double-escaping.
    The / escape is included for extra safety in unquoted attribute contexts.
    """
    if not isinstance(text, str):
        text = str(text)
    return (
        text
        .replace("&",  "&amp;")   # must be first — prevents double-encoding
        .replace("<",  "&lt;")
        .replace(">",  "&gt;")
        .replace('"',  "&quot;")
        .replace("'",  "&#x27;")
        .replace("/",  "&#x2F;")  # extra safety in unquoted attribute context
    )


def extract_forms_from_html(html: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Simple form extractor for cases where BeautifulSoup is not imported.
    Returns a list of form metadata dicts.
    """
    from bs4 import BeautifulSoup
    forms = []
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        full_action = build_url(base_url, action) if action else base_url
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            inp_type = inp.get("type", "text")
            value = inp.get("value", "")
            if name:
                inputs.append({"name": name, "type": inp_type, "value": value})
        forms.append({
            "action": full_action,
            "method": method,
            "inputs": inputs,
        })
    return forms


def fingerprint_hash(content: str) -> str:
    """Generate a short hash for deduplication."""
    return hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:12]


def is_binary_content(content_type: str) -> bool:
    """Check if content type is binary (skip text analysis)."""
    binary_types = [
        "image/", "audio/", "video/", "application/octet-stream",
        "application/pdf", "application/zip", "application/x-gzip",
        "application/x-tar", "font/",
    ]
    return any(content_type.startswith(bt) for bt in binary_types)


def parse_cookie_attributes(cookie_header: str) -> Dict[str, Any]:
    """Parse Set-Cookie header into name/value and attributes."""
    parts = [p.strip() for p in cookie_header.split(";")]
    result: Dict[str, Any] = {"name": "", "value": "", "attributes": {}}
    if parts:
        name_val = parts[0].split("=", 1)
        result["name"] = name_val[0].strip()
        result["value"] = name_val[1].strip() if len(name_val) > 1 else ""
    for attr in parts[1:]:
        if "=" in attr:
            k, v = attr.split("=", 1)
            result["attributes"][k.strip().lower()] = v.strip()
        else:
            result["attributes"][attr.strip().lower()] = True
    return result


def severity_color(severity: str) -> str:
    """Return ANSI color code for severity level."""
    colors = {
        "Critical": "\033[91m",   # bright red
        "High": "\033[31m",       # red
        "Medium": "\033[33m",     # yellow
        "Low": "\033[34m",        # blue
        "Info": "\033[36m",       # cyan
    }
    return colors.get(severity, "\033[0m")


RESET_COLOR = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
DIM = "\033[2m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"


def inject_payload_into_json(body: dict, key: str, payload: str) -> dict:
    """
    Recursively inject payload into a JSON body at key 'key'.
    Handles nested objects and arrays of objects.
    Returns a new dict with the injection applied.
    """
    import copy
    result = copy.deepcopy(body)

    def _inject(obj):
        if isinstance(obj, dict):
            for k in obj:
                if k == key:
                    obj[k] = payload
                else:
                    _inject(obj[k])
        elif isinstance(obj, list):
            for item in obj:
                _inject(item)

    _inject(result)
    return result


def build_graphql_injection(query_template: str, variable: str, payload: str) -> dict:
    """
    Build a GraphQL request body with an injected payload in a variable.
    query_template: a GraphQL query string with {variable} placeholder.
    Returns a dict suitable for JSON POST body.
    """
    return {
        "query": query_template,
        "variables": {variable: payload}
    }


def detect_waf_block(status_code: int, body: str) -> bool:
    """
    Heuristic: returns True if a WAF likely blocked the request.
    Used to trigger WAF bypass logic automatically.
    """
    import re
    if status_code in (403, 406, 429, 503):
        return True
    waf_patterns = [
        r"access denied",
        r"blocked by",
        r"security policy",
        r"cloudflare ray id",
        r"mod_security",
        r"request rejected",
        r"you have been blocked",
        r"incapsula",
        r"akamai.*reference",
    ]
    body_lower = body.lower() if body else ""
    for pat in waf_patterns:
        if re.search(pat, body_lower):
            return True
    return False

