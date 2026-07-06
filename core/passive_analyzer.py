"""
Passive Analysis Engine — Phase 2.2

Imports real traffic from HAR files or Burp Suite XML exports,
builds an attack surface from actual recorded requests, and feeds
them into the scanner pipeline.

This solves the hardest problem in web security testing: authenticated flows
that the crawler can't reach. By importing a HAR file recorded while
manually browsing with an authenticated session, WebShield can test every
endpoint the user visited.

Supported input formats:
- HAR 1.2  (exported by Chrome DevTools, Firefox, Burp Suite, ZAP)
- Burp Suite XML export  (Project → Export → Save selected items)

Usage:
    analyzer = PassiveAnalyzer(client)
    items = await analyzer.load_har("export.har")
    items = await analyzer.load_burp("burp_export.xml")
    # items is a list of CrawlResult — feed directly to engine scanners
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

try:
    import defusedxml.ElementTree as defused_ET
    _DEFUSED_AVAILABLE = True
except ImportError:
    _DEFUSED_AVAILABLE = False

from .http_client import HTTPClient, HTTPResponse
from ..utils.helpers import normalize_url


# ---------------------------------------------------------------------------
# Replay Request / CrawlResult-compatible representation
# ---------------------------------------------------------------------------

@dataclass
class ReplayRequest:
    """
    A captured HTTP request/response pair from HAR or Burp.
    Compatible with the scanner pipeline.
    """
    url: str
    method: str
    request_headers: Dict[str, str]
    request_body: Optional[str]          # raw body string
    request_body_json: Optional[Any]     # parsed if Content-Type is JSON
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    response_content_type: str
    source: str                          # "har" or "burp"
    forms: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def query_params(self) -> Dict[str, List[str]]:
        return parse_qs(urlparse(self.url).query)

    @property
    def has_json_body(self) -> bool:
        ct = self.request_headers.get("content-type", "").lower()
        return "json" in ct

    @property
    def has_form_body(self) -> bool:
        ct = self.request_headers.get("content-type", "").lower()
        return "form" in ct

    def to_form_inputs(self) -> List[Dict[str, str]]:
        """
        Convert POST body (form or JSON) to a list of form inputs,
        compatible with the scanner's form format.
        """
        inputs: List[Dict[str, str]] = []
        if self.has_json_body and isinstance(self.request_body_json, dict):
            for k, v in self.request_body_json.items():
                inputs.append({"name": k, "type": "text", "value": str(v)})
        elif self.has_form_body and self.request_body:
            parsed = parse_qs(self.request_body)
            for k, vals in parsed.items():
                inputs.append({"name": k, "type": "text", "value": vals[0] if vals else ""})
        elif self.query_params:
            for k, vals in self.query_params.items():
                inputs.append({"name": k, "type": "text", "value": vals[0] if vals else ""})
        return inputs


# ---------------------------------------------------------------------------
# CrawlResult adapter
# ---------------------------------------------------------------------------

class ReplayHTTPResponse:
    """
    Wraps a ReplayRequest so it looks like an HTTPResponse to scanners.
    Scanners use: .status_code, .text, .headers, .content_type, .elapsed
    """

    def __init__(self, replay: ReplayRequest) -> None:
        self._replay = replay

    @property
    def status_code(self) -> int:
        return self._replay.response_status

    @property
    def text(self) -> str:
        return self._replay.response_body

    @property
    def content(self) -> bytes:
        return self._replay.response_body.encode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self._replay.response_content_type

    @property
    def headers(self) -> Dict[str, str]:
        return self._replay.response_headers

    @property
    def is_text(self) -> bool:
        ct = self.content_type.lower()
        return any(t in ct for t in ("text", "json", "xml", "html", "javascript"))

    @property
    def elapsed(self) -> float:
        return 0.0

    def header(self, name: str) -> Optional[str]:
        return self._replay.response_headers.get(name.lower())


@dataclass
class ReplayCrawlItem:
    """
    Thin wrapper that mimics CrawlResult for scanner compatibility.
    """
    url: str
    response: ReplayHTTPResponse
    depth: int
    forms: List[Dict[str, Any]]
    links: List[str]
    replay: ReplayRequest   # original request for re-sending if needed

    @property
    def params(self) -> Dict[str, List[str]]:
        return self.replay.query_params

    @property
    def scripts(self) -> List[str]:
        return []


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class PassiveAnalyzer:
    """
    Loads HAR or Burp XML files and produces scanner-ready items.

    The resulting ReplayCrawlItem objects can be fed directly into
    ScanEngine._scan_crawl_result() to run all vulnerability scanners
    on the captured traffic.
    """

    # HTTP methods worth testing (skip OPTIONS, HEAD for injection testing)
    _INTERESTING_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

    def __init__(
        self,
        client: HTTPClient,
        scope_host: Optional[str] = None,
        skip_static_resources: bool = True,
    ) -> None:
        self.client = client
        self.scope_host = scope_host
        self.skip_static_resources = skip_static_resources
        self._seen_urls: Set[str] = set()

    # -----------------------------------------------------------------------
    # HAR loading
    # -----------------------------------------------------------------------

    async def load_har(self, har_path: str) -> List[ReplayCrawlItem]:
        """
        Load a HAR file and return a list of ReplayCrawlItem.

        Args:
            har_path: Path to the .har file.
        """
        path = Path(har_path)
        if not path.exists():
            raise FileNotFoundError(f"HAR file not found: {har_path}")

        raw = path.read_text(encoding="utf-8", errors="replace")
        try:
            har_data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid HAR file: {e}") from e

        return self._parse_har(har_data)

    def _parse_har(self, har_data: Dict[str, Any]) -> List[ReplayCrawlItem]:
        """Parse HAR 1.2 format."""
        items: List[ReplayCrawlItem] = []

        log = har_data.get("log", har_data)
        entries = log.get("entries", [])

        for entry in entries:
            item = self._har_entry_to_item(entry)
            if item is not None:
                items.append(item)

        return items

    def _har_entry_to_item(self, entry: Dict[str, Any]) -> Optional[ReplayCrawlItem]:
        """Convert a single HAR entry to a ReplayCrawlItem."""
        request = entry.get("request", {})
        response = entry.get("response", {})

        url = request.get("url", "")
        method = request.get("method", "GET").upper()

        if not url or method not in self._INTERESTING_METHODS:
            return None

        if self.scope_host and not self._is_in_scope(url):
            return None

        if self.skip_static_resources and self._is_static_resource(url):
            return None

        # Deduplicate by URL+method
        dedup_key = f"{method}:{normalize_url(url)}"
        if dedup_key in self._seen_urls:
            return None
        self._seen_urls.add(dedup_key)

        # Parse request headers
        req_headers = {
            h["name"].lower(): h["value"]
            for h in request.get("headers", [])
            if isinstance(h, dict) and "name" in h
        }

        # Parse request body
        req_body_str: Optional[str] = None
        req_body_json: Optional[Any] = None
        post_data = request.get("postData", {})
        if post_data:
            req_body_str = post_data.get("text", "")
            if "json" in req_headers.get("content-type", "").lower():
                try:
                    req_body_json = json.loads(req_body_str or "")
                except Exception:
                    pass

        # Parse response
        resp_status = response.get("status", 200)
        resp_headers = {
            h["name"].lower(): h["value"]
            for h in response.get("headers", [])
            if isinstance(h, dict) and "name" in h
        }
        resp_content = response.get("content", {})
        resp_body = resp_content.get("text", "")
        resp_ct = resp_content.get("mimeType", "text/html")

        # Handle base64-encoded content
        if resp_content.get("encoding") == "base64" and resp_body:
            try:
                resp_body = base64.b64decode(resp_body).decode("utf-8", errors="replace")
            except Exception:
                resp_body = ""

        replay = ReplayRequest(
            url=url,
            method=method,
            request_headers=req_headers,
            request_body=req_body_str,
            request_body_json=req_body_json,
            response_status=resp_status,
            response_headers=resp_headers,
            response_body=resp_body,
            response_content_type=resp_ct,
            source="har",
        )

        # Build form-like inputs from the request
        forms = []
        form_inputs = replay.to_form_inputs()
        if form_inputs:
            forms = [{
                "action": url,
                "method": method,
                "inputs": form_inputs,
                "source_url": url,
                "enctype": req_headers.get("content-type", "application/x-www-form-urlencoded"),
                "_source": "har_import",
            }]

        return ReplayCrawlItem(
            url=url,
            response=ReplayHTTPResponse(replay),
            depth=0,
            forms=forms,
            links=[],
            replay=replay,
        )

    # -----------------------------------------------------------------------
    # Burp Suite XML loading
    # -----------------------------------------------------------------------

    async def load_burp(self, burp_path: str) -> List[ReplayCrawlItem]:
        """
        Load a Burp Suite XML export and return a list of ReplayCrawlItem.

        Args:
            burp_path: Path to the Burp XML export file.
        """
        path = Path(burp_path)
        if not path.exists():
            raise FileNotFoundError(f"Burp export not found: {burp_path}")

        raw = path.read_bytes()

        # Use defusedxml if available (prevents XXE on untrusted XML)
        if _DEFUSED_AVAILABLE:
            try:
                root = defused_ET.fromstring(raw)
            except Exception as e:
                raise ValueError(f"Invalid Burp XML: {e}") from e
        else:
            try:
                root = ET.fromstring(raw)
            except ET.ParseError as e:
                raise ValueError(f"Invalid Burp XML: {e}") from e

        return self._parse_burp_xml(root)

    def _parse_burp_xml(self, root: ET.Element) -> List[ReplayCrawlItem]:
        """Parse Burp Suite XML export format."""
        items: List[ReplayCrawlItem] = []

        # Burp XML: <items><item>...</item></items>
        item_elements = root.findall(".//item")

        for elem in item_elements:
            item = self._burp_item_to_replay(elem)
            if item is not None:
                items.append(item)

        return items

    def _burp_item_to_replay(self, elem: ET.Element) -> Optional[ReplayCrawlItem]:
        """Convert a Burp <item> XML element to a ReplayCrawlItem."""

        def text(tag: str) -> str:
            el = elem.find(tag)
            return (el.text or "").strip() if el is not None else ""

        def decode_burp(tag: str) -> str:
            """Burp base64-encodes request/response bodies in XML."""
            el = elem.find(tag)
            if el is None:
                return ""
            raw_text = el.text or ""
            is_base64 = el.get("base64", "false").lower() == "true"
            if is_base64:
                try:
                    return base64.b64decode(raw_text).decode("utf-8", errors="replace")
                except Exception:
                    return raw_text
            return raw_text

        url = text("url")
        method_line = text("method")
        method = method_line.split(" ")[0].upper() if method_line else "GET"

        if not url or method not in self._INTERESTING_METHODS:
            return None

        if self.scope_host and not self._is_in_scope(url):
            return None

        if self.skip_static_resources and self._is_static_resource(url):
            return None

        dedup_key = f"{method}:{normalize_url(url)}"
        if dedup_key in self._seen_urls:
            return None
        self._seen_urls.add(dedup_key)

        # Parse raw request (Burp stores the full HTTP message)
        raw_request = decode_burp("request")
        req_headers, req_body_str = self._parse_raw_http_message(raw_request)

        req_body_json: Optional[Any] = None
        if "json" in req_headers.get("content-type", "").lower() and req_body_str:
            try:
                req_body_json = json.loads(req_body_str)
            except Exception:
                pass

        # Parse raw response
        raw_response = decode_burp("response")
        resp_headers_raw, resp_body = self._parse_raw_http_message(raw_response)

        status_str = text("status")
        resp_status = int(status_str) if status_str.isdigit() else 200
        resp_ct = resp_headers_raw.get("content-type", "text/html").split(";")[0].strip()

        replay = ReplayRequest(
            url=url,
            method=method,
            request_headers=req_headers,
            request_body=req_body_str or None,
            request_body_json=req_body_json,
            response_status=resp_status,
            response_headers=resp_headers_raw,
            response_body=resp_body,
            response_content_type=resp_ct,
            source="burp",
        )

        forms = []
        form_inputs = replay.to_form_inputs()
        if form_inputs:
            forms = [{
                "action": url,
                "method": method,
                "inputs": form_inputs,
                "source_url": url,
                "enctype": req_headers.get("content-type", "application/x-www-form-urlencoded"),
                "_source": "burp_import",
            }]

        return ReplayCrawlItem(
            url=url,
            response=ReplayHTTPResponse(replay),
            depth=0,
            forms=forms,
            links=[],
            replay=replay,
        )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_raw_http_message(raw: str) -> Tuple[Dict[str, str], str]:
        """
        Parse a raw HTTP message (headers + body) into a headers dict and body string.
        Works for both requests and responses.
        """
        headers: Dict[str, str] = {}
        if not raw:
            return headers, ""

        # Split headers from body on blank line
        if "\r\n\r\n" in raw:
            header_block, body = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            header_block, body = raw.split("\n\n", 1)
        else:
            return headers, raw

        lines = header_block.splitlines()
        # Skip the first line (request line or status line)
        for line in lines[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()

        return headers, body

    def _is_in_scope(self, url: str) -> bool:
        if not self.scope_host:
            return True
        parsed = urlparse(url)
        return parsed.netloc == self.scope_host or parsed.netloc.endswith("." + self.scope_host)

    @staticmethod
    def _is_static_resource(url: str) -> bool:
        """Return True for static resources that have no security testing value."""
        static_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".woff", ".woff2", ".ttf", ".eot",
            ".css",
            ".mp4", ".mp3", ".ogg", ".wav",
            ".pdf",
            ".zip", ".gz", ".tar",
        }
        parsed_path = urlparse(url).path.lower()
        for ext in static_extensions:
            if parsed_path.endswith(ext):
                return True
        return False

    # -----------------------------------------------------------------------
    # Statistics
    # -----------------------------------------------------------------------

    @staticmethod
    def summarize(items: List[ReplayCrawlItem]) -> Dict[str, Any]:
        """Return a summary dict for reporting."""
        methods: Dict[str, int] = {}
        sources: Dict[str, int] = {}
        status_codes: Dict[int, int] = {}
        has_json_body = 0
        has_form_body = 0

        for item in items:
            replay = item.replay
            methods[replay.method] = methods.get(replay.method, 0) + 1
            sources[replay.source] = sources.get(replay.source, 0) + 1
            status_codes[replay.response_status] = status_codes.get(replay.response_status, 0) + 1
            if replay.has_json_body:
                has_json_body += 1
            if replay.has_form_body:
                has_form_body += 1

        return {
            "total_requests": len(items),
            "methods": methods,
            "sources": sources,
            "status_codes": status_codes,
            "with_json_body": has_json_body,
            "with_form_body": has_form_body,
        }
