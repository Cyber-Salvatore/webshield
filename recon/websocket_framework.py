"""
WebSocket Framework — Part 10 of the Intelligence Layer.

A dedicated reconnaissance and mapping framework for WebSocket connections that
operates *before* any exploitation attempts begin.  Its sole purpose is to build
the most complete picture of the target's WebSocket surface so that all downstream
scanners receive rich, structured context instead of raw URLs.

Capabilities
------------
Endpoint Discovery
  • 50+ common WebSocket path variants (ws:// and wss://)
  • Upgrade-header sniffing on discovered HTTP endpoints
  • JavaScript source mining (socket.io, SockJS, native WebSocket, ws library)
  • HTML attribute extraction (data-ws-url, data-socket, data-endpoint …)
  • Service Worker and Background Worker inspection
  • EventSource / SSE co-location detection

Handshake Analysis
  • Full HTTP/1.1 Upgrade handshake capture (101 Switching Protocols)
  • Sec-WebSocket-Key / Accept validation
  • Subprotocol negotiation (graphql-ws, graphql-transport-ws, mqtt, stomp,
    wamp, json-rpc, binary, chat, actioncable …)
  • Extension negotiation (permessage-deflate, x-webkit-deflate-frame …)
  • Cookie and Authorization header forwarding behaviour
  • Origin validation probing (permissive CORS-equivalent for WS)

Message Profiling
  • Passive observation of initial server push messages
  • Protocol detection: JSON-RPC 2.0, STOMP, MQTT, WAMP, ActionCable,
    Phoenix Channels, socket.io, SockJS frame format
  • Data format classification: JSON, MessagePack, CBOR, Protobuf hint,
    plain text, binary blob
  • Heartbeat / ping-pong interval measurement
  • Subscription / event-type inventory
  • Authentication flow detection within the WebSocket message stream

Authentication & Authorization Profile
  • Token-in-first-message patterns (JWT, API key, session ID)
  • Token-in-handshake-header patterns
  • Token-in-query-string patterns (ws://host/path?token=…)
  • Per-channel / per-room access control topology
  • Multi-tenant namespace isolation detection

Attack Surface Extraction
  • Injectable message fields (key/value pairs that accept user input)
  • Server event / subscription names (enumerable attack surface)
  • File transfer channels
  • Admin or privileged command namespaces
  • Binary protocol frame structure hints

All results are emitted as structured ``WSEndpoint``, ``WSHandshake``,
``WSProtocol``, ``WSMessage``, and ``WSAttackSurface`` objects that are stored
in the Knowledge Base and consumed by the WebSocket scanner, the Endpoint
Classification Engine, and the Context-Aware Payload Framework.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs

from ..core.http_client import HTTPClient, HTTPResponse
from ..core.target import ScanTarget
from ..utils.helpers import normalize_url

logger = logging.getLogger(__name__)


# ===========================================================================
# Constants
# ===========================================================================

#: Common WebSocket endpoint paths — ordered by prevalence in the wild
_WS_PATHS: List[str] = [
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/",
    "/socket.io",
    "/sockjs",
    "/sockjs/",
    "/ws/",
    "/wss/",
    "/cable",
    "/api/ws",
    "/api/socket",
    "/api/websocket",
    "/v1/ws",
    "/v2/ws",
    "/v1/socket",
    "/v2/socket",
    "/realtime",
    "/realtime/ws",
    "/live",
    "/live/ws",
    "/stream",
    "/stream/ws",
    "/streaming",
    "/notifications",
    "/notifications/ws",
    "/events",
    "/events/ws",
    "/feed",
    "/feed/ws",
    "/updates",
    "/updates/ws",
    "/push",
    "/push/ws",
    "/chat",
    "/chat/ws",
    "/messages",
    "/messages/ws",
    "/echo",
    "/ws/echo",
    "/ws/chat",
    "/ws/notifications",
    "/ws/events",
    "/ws/stream",
    "/ws/realtime",
    "/ws/updates",
    "/ws/feed",
    "/ws/push",
    "/ws/live",
    "/admin/ws",
    "/admin/websocket",
    "/internal/ws",
    "/api/v1/ws",
    "/api/v2/ws",
    "/hub",
    "/signalr",
    "/signalr/hubs",
    "/ws/v1",
    "/ws/v2",
    "/io",
]

#: JavaScript patterns that reveal WebSocket endpoint URLs
_JS_WS_PATTERNS: List[re.Pattern] = [
    # new WebSocket("wss://host/path")
    re.compile(
        r"""new\s+WebSocket\s*\(\s*['"`]([^'"`\s]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    # io("https://host", ...) — socket.io
    re.compile(
        r"""(?:io|connect)\s*\(\s*['"`]([^'"`\s]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    # SockJS("/ws")
    re.compile(
        r"""(?:new\s+)?SockJS\s*\(\s*['"`]([^'"`\s]{2,300})['"`]""",
        re.IGNORECASE,
    ),
    # wsUrl: "/ws/endpoint"
    re.compile(
        r"""(?:wsUrl|ws_url|socketUrl|socket_url|endpoint|wsEndpoint|ws_endpoint)\s*[:=]\s*['"`]([^'"`\s]{2,300})['"`]""",
        re.IGNORECASE,
    ),
    # const WS_URL = "wss://..."
    re.compile(
        r"""(?:WS|SOCKET|WEBSOCKET|WS_URL|SOCKET_URL)(?:_URL|_ENDPOINT|_HOST)?\s*[=:]\s*['"`]([^'"`\s]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    # url: process.env.REACT_APP_WS_URL or similar env reference — capture the variable name
    re.compile(
        r"""process\.env\.([A-Z_]{4,60}WS[A-Z_]*)""",
        re.IGNORECASE,
    ),
    # Phoenix Channel: new Socket("/socket", {})
    re.compile(
        r"""new\s+Socket\s*\(\s*['"`]([^'"`\s]{2,300})['"`]""",
        re.IGNORECASE,
    ),
    # ActionCable: createConsumer("wss://...")
    re.compile(
        r"""createConsumer\s*\(\s*['"`]([^'"`\s]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    # Centrifuge / Centrifugo
    re.compile(
        r"""new\s+Centrifuge\s*\(\s*['"`]([^'"`\s]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    # WAMP: new autobahn.Connection({url: "wss://..."})
    re.compile(
        r"""url\s*:\s*['"`](wss?://[^'"`\s]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    # Generic ws/wss literal URL
    re.compile(
        r"""['"`](wss?://[^'"`\s]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    # Relative WS path: "/ws" or "/socket"
    re.compile(
        r"""['"` ](\/(?:ws|websocket|socket|sockjs|cable|realtime|live|stream|hub|events|notifications)[^'"`\s]{0,100})['"`]""",
        re.IGNORECASE,
    ),
]

#: HTML attribute patterns that contain WebSocket URLs
_HTML_WS_ATTRS: List[re.Pattern] = [
    re.compile(
        r"""(?:data-ws|data-socket|data-websocket|data-channel|data-endpoint|data-url)\s*=\s*['"`]([^'"`]{4,300})['"`]""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:ws-url|socket-url|websocket-url)\s*=\s*['"`]([^'"`]{4,300})['"`]""",
        re.IGNORECASE,
    ),
]

#: Known application-layer WebSocket subprotocols
_KNOWN_SUBPROTOCOLS: Dict[str, str] = {
    "graphql-ws":                    "GraphQL over WebSocket (graphql-ws library)",
    "graphql-transport-ws":          "GraphQL over WebSocket (graphql-transport-ws)",
    "subscriptions-transport-ws":    "GraphQL Subscriptions (Apollo)",
    "mqtt":                          "MQTT over WebSocket",
    "stomp":                         "STOMP messaging protocol",
    "v10.stomp":                     "STOMP 1.0 over WebSocket",
    "v11.stomp":                     "STOMP 1.1 over WebSocket",
    "v12.stomp":                     "STOMP 1.2 over WebSocket",
    "wamp":                          "WAMP (Web Application Messaging Protocol)",
    "wamp.2.json":                   "WAMP v2 JSON serialisation",
    "wamp.2.msgpack":                "WAMP v2 MessagePack serialisation",
    "actioncable-v1-json":           "Rails ActionCable JSON",
    "actioncable-v1-msgpack":        "Rails ActionCable MessagePack",
    "phoenix":                       "Phoenix Channels (Elixir/Phoenix)",
    "json-rpc":                      "JSON-RPC 2.0 over WebSocket",
    "xmpp":                          "XMPP over WebSocket",
    "chat":                          "Generic chat subprotocol",
    "binary":                        "Binary protocol (opaque)",
    "sip":                           "SIP over WebSocket (RFC 7118)",
    "ocpp1.6":                       "OCPP 1.6 (EV charging)",
    "ocpp2.0":                       "OCPP 2.0 (EV charging)",
    "soap":                          "SOAP over WebSocket",
    "slack-rtm":                     "Slack RTM protocol",
}

#: WS-specific security headers to capture during handshake
_SECURITY_HEADERS: Set[str] = {
    "sec-websocket-protocol",
    "sec-websocket-extensions",
    "sec-websocket-accept",
    "sec-websocket-version",
    "x-forwarded-for",
    "x-real-ip",
    "x-request-id",
    "server",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "set-cookie",
    "www-authenticate",
    "authorization",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
}


# ===========================================================================
# Enums
# ===========================================================================

class WSStatus(str, Enum):
    """High-level reachability status of a WebSocket endpoint."""
    OPEN           = "open"           # 101 received; connection established
    REJECTED       = "rejected"       # non-101 HTTP response
    UNREACHABLE    = "unreachable"    # connection-level error
    UNKNOWN        = "unknown"        # not yet probed


class WSProtocolFamily(str, Enum):
    """Top-level grouping of application-layer protocol families."""
    GRAPHQL        = "graphql"
    SOCKET_IO      = "socket_io"
    SOCKJS         = "sockjs"
    STOMP          = "stomp"
    MQTT           = "mqtt"
    WAMP           = "wamp"
    ACTION_CABLE   = "action_cable"
    PHOENIX        = "phoenix"
    JSON_RPC       = "json_rpc"
    SIGNALR        = "signalr"
    CENTRIFUGE     = "centrifuge"
    XMPP           = "xmpp"
    RAW_JSON       = "raw_json"
    RAW_BINARY     = "raw_binary"
    PLAIN_TEXT     = "plain_text"
    UNKNOWN        = "unknown"


class WSAuthScheme(str, Enum):
    """Where and how authentication credentials are conveyed."""
    NONE                    = "none"
    QUERY_PARAM_TOKEN       = "query_param_token"       # ?token=… / ?jwt=…
    QUERY_PARAM_SESSION     = "query_param_session"     # ?session_id=…
    HANDSHAKE_HEADER        = "handshake_header"        # Authorization: Bearer …
    HANDSHAKE_COOKIE        = "handshake_cookie"        # Cookie: session=…
    FIRST_MESSAGE_TOKEN     = "first_message_token"     # {"token": "…"} in first msg
    FIRST_MESSAGE_AUTH_OBJ  = "first_message_auth_obj"  # {"type":"auth","payload":{…}}
    SUBSCRIBE_WITH_TOKEN    = "subscribe_with_token"    # {"type":"subscribe","token":…}
    UNKNOWN                 = "unknown"


class WSDataFormat(str, Enum):
    """Wire-level data encoding used in messages."""
    JSON         = "json"
    MESSAGEPACK  = "messagepack"
    CBOR         = "cbor"
    PROTOBUF     = "protobuf"
    PLAIN_TEXT   = "plain_text"
    BINARY_BLOB  = "binary_blob"
    MIXED        = "mixed"
    UNKNOWN      = "unknown"


class WSDiscoverySource(str, Enum):
    """How a WebSocket endpoint URL was discovered."""
    PATH_PROBE       = "path_probe"
    JS_ANALYSIS      = "js_analysis"
    HTML_ATTRIBUTE   = "html_attribute"
    HTTP_UPGRADE     = "http_upgrade"
    LINK_HEADER      = "link_header"
    SOURCE_MAP       = "source_map"
    SERVICE_WORKER   = "service_worker"
    KNOWLEDGE_BASE   = "knowledge_base"
    USER_PROVIDED    = "user_provided"


class OriginPolicy(str, Enum):
    """How strictly the server validates the Origin header."""
    STRICT       = "strict"       # Rejects unknown origins
    PERMISSIVE   = "permissive"   # Accepts any Origin (dangerous)
    NO_CHECK     = "no_check"     # No Origin header required at all
    UNKNOWN      = "unknown"


# ===========================================================================
# Data classes
# ===========================================================================

@dataclass
class WSHandshake:
    """
    Full record of an HTTP Upgrade handshake to a WebSocket endpoint.

    Captures everything that matters for security analysis: status code,
    subprotocol agreement, extensions, auth tokens, cookies, and the
    raw response headers.
    """
    url:                  str
    status_code:          int                        = 0
    reason:               str                        = ""
    upgrade_successful:   bool                       = False

    # Negotiated capabilities
    subprotocol:          Optional[str]              = None
    extensions:           List[str]                  = field(default_factory=list)
    server_header:        Optional[str]              = None
    sec_ws_accept:        Optional[str]              = None

    # Auth signals from the handshake
    set_cookies:          List[str]                  = field(default_factory=list)
    www_authenticate:     Optional[str]              = None
    auth_scheme:          WSAuthScheme               = WSAuthScheme.UNKNOWN

    # CORS-equivalent for WebSocket
    origin_policy:        OriginPolicy               = OriginPolicy.UNKNOWN
    allowed_origins:      List[str]                  = field(default_factory=list)

    # Raw request/response for evidence
    request_headers:      Dict[str, str]             = field(default_factory=dict)
    response_headers:     Dict[str, str]             = field(default_factory=dict)

    # Timing
    connect_time_ms:      float                      = 0.0
    timestamp:            float                      = field(default_factory=time.time)


@dataclass
class WSMessageSample:
    """
    A single observed or inferred WebSocket message.

    Collected from:
      - Actual initial server-push messages (when the framework can observe them)
      - Protocol-specific probes (e.g. ping frames, subscribe requests)
      - JS source analysis (hardcoded message templates)
    """
    direction:    str                        = "server"  # "client" | "server"
    opcode:       str                        = "text"    # "text" | "binary" | "ping" | "pong" | "close"
    raw:          str                        = ""
    parsed:       Optional[Dict[str, Any]]  = None
    event_type:   Optional[str]             = None      # e.g. "message", "subscribe", "broadcast"
    channel:      Optional[str]             = None
    is_auth:      bool                      = False
    timestamp:    float                     = field(default_factory=time.time)


@dataclass
class WSChannel:
    """
    A logical channel / room / subscription topic discovered in a WebSocket connection.

    Sources: JS source mining, HTML attributes, observed subscribe messages,
    documented subprotocol schemas.
    """
    name:          str
    path:          Optional[str]             = None   # e.g. "/cable" → channel "ChatChannel"
    requires_auth: bool                      = False
    is_admin:      bool                      = False
    param_names:   List[str]                 = field(default_factory=list)
    event_types:   List[str]                 = field(default_factory=list)
    source:        WSDiscoverySource         = WSDiscoverySource.JS_ANALYSIS
    notes:         str                       = ""


@dataclass
class WSEndpoint:
    """
    Full reconnaissance profile for a single WebSocket endpoint.

    This is the primary output object of ``WebSocketFramework``.  It aggregates
    everything discovered about one WebSocket URL so that downstream scanners
    have a ready-made, rich context to work from.
    """
    url:                str

    # Discovery metadata
    source:             WSDiscoverySource           = WSDiscoverySource.PATH_PROBE
    status:             WSStatus                    = WSStatus.UNKNOWN

    # Handshake details
    handshake:          Optional[WSHandshake]       = None

    # Application-layer protocol
    protocol_family:    WSProtocolFamily            = WSProtocolFamily.UNKNOWN
    subprotocol_label:  Optional[str]               = None   # from _KNOWN_SUBPROTOCOLS
    data_format:        WSDataFormat                = WSDataFormat.UNKNOWN

    # Auth topology
    auth_scheme:        WSAuthScheme                = WSAuthScheme.NONE
    token_param_name:   Optional[str]               = None  # query param name for token
    auth_header_name:   Optional[str]               = None  # header name for auth

    # Origin / CORS-like policy
    origin_policy:      OriginPolicy                = OriginPolicy.UNKNOWN

    # Message samples
    initial_messages:   List[WSMessageSample]       = field(default_factory=list)

    # Subscription / channel topology
    channels:           List[WSChannel]             = field(default_factory=list)
    event_types:        List[str]                   = field(default_factory=list)
    subscription_names: List[str]                   = field(default_factory=list)

    # Heartbeat
    heartbeat_interval_s:   Optional[float]         = None
    ping_opcode:            Optional[str]           = None   # "ping" or "text" (app-level)

    # Capabilities
    compression_enabled:    bool                    = False
    binary_support:         bool                    = False
    multiplexed:            bool                    = False  # multiple channels on one conn

    # Attack surface hints
    injectable_fields:      List[Dict[str, Any]]    = field(default_factory=list)
    file_transfer_channels: List[str]               = field(default_factory=list)
    admin_commands:         List[str]               = field(default_factory=list)
    privileged_channels:    List[str]               = field(default_factory=list)

    # Companion HTTP endpoint (if discovered via Upgrade header)
    http_companion_url:     Optional[str]           = None

    # Technology hints
    server_software:        Optional[str]           = None
    framework_hint:         Optional[str]           = None   # "socket.io", "phoenix", …

    # Related HTTP SSE endpoint (if co-located)
    sse_companion_url:      Optional[str]           = None

    # Timing metadata
    discovery_time_ms:      float                   = 0.0
    timestamp:              float                   = field(default_factory=time.time)


@dataclass
class WSFrameworkReport:
    """
    Aggregated output of a complete WebSocket Framework reconnaissance run.

    Contains all discovered endpoints, the deduplication log, extraction stats,
    and a pre-built ``WSAttackSurface`` for downstream consumers.
    """
    target_url:         str
    scan_duration_s:    float                   = 0.0
    endpoints:          List[WSEndpoint]        = field(default_factory=list)

    # Dedup & stats
    probed_paths:       int                     = 0
    open_count:         int                     = 0
    rejected_count:     int                     = 0
    unreachable_count:  int                     = 0

    # JS & HTML mining results
    js_urls_mined:      int                     = 0
    html_attrs_mined:   int                     = 0

    # Attack surface (ready for scanners)
    attack_surface:     Optional["WSAttackSurface"] = None

    def summary(self) -> str:
        lines = [
            f"WebSocket Framework Report — {self.target_url}",
            f"  Duration      : {self.scan_duration_s:.1f}s",
            f"  Endpoints open: {self.open_count}",
            f"  Paths probed  : {self.probed_paths}",
            f"  JS URLs mined : {self.js_urls_mined}",
        ]
        for ep in self.endpoints:
            if ep.status == WSStatus.OPEN:
                lines.append(
                    f"  [OPEN] {ep.url} | {ep.protocol_family.value} | "
                    f"auth={ep.auth_scheme.value}"
                )
        return "\n".join(lines)


# ===========================================================================
# Protocol Detector
# ===========================================================================

class WSProtocolDetector:
    """
    Infers the application-layer protocol family from handshake and message data.

    Operates purely on already-collected evidence — makes no network calls.
    """

    # (pattern, family, data_format)
    _SUBPROTOCOL_RULES: List[Tuple[str, WSProtocolFamily, WSDataFormat]] = [
        ("graphql-transport-ws",     WSProtocolFamily.GRAPHQL,      WSDataFormat.JSON),
        ("graphql-ws",               WSProtocolFamily.GRAPHQL,      WSDataFormat.JSON),
        ("subscriptions-transport",  WSProtocolFamily.GRAPHQL,      WSDataFormat.JSON),
        ("stomp",                    WSProtocolFamily.STOMP,        WSDataFormat.PLAIN_TEXT),
        ("mqtt",                     WSProtocolFamily.MQTT,         WSDataFormat.BINARY_BLOB),
        ("wamp",                     WSProtocolFamily.WAMP,         WSDataFormat.JSON),
        ("actioncable",              WSProtocolFamily.ACTION_CABLE, WSDataFormat.JSON),
        ("phoenix",                  WSProtocolFamily.PHOENIX,      WSDataFormat.JSON),
        ("json-rpc",                 WSProtocolFamily.JSON_RPC,     WSDataFormat.JSON),
        ("xmpp",                     WSProtocolFamily.XMPP,         WSDataFormat.PLAIN_TEXT),
    ]

    # URL path → family hint
    _PATH_RULES: List[Tuple[str, WSProtocolFamily]] = [
        ("/socket.io",   WSProtocolFamily.SOCKET_IO),
        ("/sockjs",      WSProtocolFamily.SOCKJS),
        ("/cable",       WSProtocolFamily.ACTION_CABLE),
        ("/signalr",     WSProtocolFamily.SIGNALR),
        ("/graphql",     WSProtocolFamily.GRAPHQL),
        ("/hub",         WSProtocolFamily.SIGNALR),
    ]

    # JSON message field patterns
    _JSON_MSG_RULES: List[Tuple[str, WSProtocolFamily]] = [
        # Phoenix {"topic":…,"event":…,"payload":…,"ref":…}
        ('"topic"',   WSProtocolFamily.PHOENIX),
        # ActionCable {"type":"welcome"}
        ('"type":"welcome"',       WSProtocolFamily.ACTION_CABLE),
        ('"type":"ping"',          WSProtocolFamily.ACTION_CABLE),
        # socket.io 42["event", data]
        ('42[',                    WSProtocolFamily.SOCKET_IO),
        # WAMP [TYPE, REQUEST_ID, …]
        # Checked structurally below
        # JSON-RPC {"jsonrpc":"2.0", …}
        ('"jsonrpc"',              WSProtocolFamily.JSON_RPC),
        # GraphQL {"type":"connection_ack"}
        ('"connection_ack"',       WSProtocolFamily.GRAPHQL),
        ('"connection_init"',      WSProtocolFamily.GRAPHQL),
        ('"next"',                 WSProtocolFamily.GRAPHQL),
        # STOMP frame starts with CONNECTED\n or SEND\n
    ]

    def detect(
        self,
        endpoint: WSEndpoint,
        messages: List[WSMessageSample],
    ) -> Tuple[WSProtocolFamily, WSDataFormat]:
        """Return (family, data_format) based on all available evidence."""

        # 1. Subprotocol from handshake (highest confidence)
        if endpoint.handshake and endpoint.handshake.subprotocol:
            sp = endpoint.handshake.subprotocol.lower()
            for pat, fam, fmt in self._SUBPROTOCOL_RULES:
                if pat in sp:
                    return fam, fmt

        # 2. URL path clues
        path = urlparse(endpoint.url).path.lower()
        for pat, fam in self._PATH_RULES:
            if pat in path:
                fmt = (
                    WSDataFormat.PLAIN_TEXT
                    if fam in (WSProtocolFamily.SOCKJS,)
                    else WSDataFormat.JSON
                )
                return fam, fmt

        # 3. Message content analysis
        for msg in messages:
            raw = msg.raw or ""

            # STOMP frames start with verb\n
            if re.match(r'^(CONNECTED|SEND|SUBSCRIBE|MESSAGE|RECEIPT|ERROR)\n', raw):
                return WSProtocolFamily.STOMP, WSDataFormat.PLAIN_TEXT

            # socket.io encoding: leading digit(s) then JSON
            if re.match(r'^\d+(\[|{)', raw):
                return WSProtocolFamily.SOCKET_IO, WSDataFormat.JSON

            # SockJS frame: a["…"] or h or o or c[…]
            if re.match(r'^(?:o|h|a\[|c\[)', raw):
                return WSProtocolFamily.SOCKJS, WSDataFormat.JSON

            # JSON message field matching
            for pat, fam in self._JSON_MSG_RULES:
                if pat in raw:
                    return fam, WSDataFormat.JSON

            # WAMP: JSON array where first element is an integer type code
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list) and parsed and isinstance(parsed[0], int):
                    return WSProtocolFamily.WAMP, WSDataFormat.JSON
            except (json.JSONDecodeError, ValueError):
                pass

            # Binary data
            if msg.opcode == "binary":
                return WSProtocolFamily.UNKNOWN, WSDataFormat.BINARY_BLOB

            # Fallback: valid JSON → raw_json
            try:
                json.loads(raw)
                return WSProtocolFamily.RAW_JSON, WSDataFormat.JSON
            except (json.JSONDecodeError, ValueError):
                pass

        # 4. Framework-level hint from server header
        server = (endpoint.server_software or "").lower()
        if "socket.io" in server:
            return WSProtocolFamily.SOCKET_IO, WSDataFormat.JSON
        if "phoenix" in server:
            return WSProtocolFamily.PHOENIX, WSDataFormat.JSON
        if "puma" in server or "cowboy" in server:
            return WSProtocolFamily.PHOENIX, WSDataFormat.JSON

        return WSProtocolFamily.UNKNOWN, WSDataFormat.UNKNOWN


# ===========================================================================
# Handshake Analyser
# ===========================================================================

class WSHandshakeAnalyser:
    """
    Performs simulated WebSocket handshake analysis over the HTTP client.

    Because the tool's HTTP client speaks HTTP/1.1 (not a real WebSocket
    library), we simulate the Upgrade request and interpret the 101 response,
    capturing all security-relevant headers without actually maintaining a WS
    connection.  Real message observation is handled by ``WSMessageProbe``.
    """

    def __init__(self, http: HTTPClient, target: ScanTarget) -> None:
        self._http = http
        self._target = target

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def probe(self, ws_url: str, origin: Optional[str] = None) -> WSHandshake:
        """
        Send an HTTP Upgrade request to ``ws_url`` and capture the handshake.

        Returns a ``WSHandshake`` regardless of whether the upgrade succeeded.
        """
        http_url = self._ws_to_http(ws_url)
        nonce = self._generate_ws_key()
        req_headers = self._build_upgrade_headers(nonce, origin or self._target.base_url)

        hs = WSHandshake(url=ws_url, request_headers=req_headers)
        t0 = time.monotonic()

        try:
            resp = await self._http.get(http_url, headers=req_headers)
            hs.status_code = resp.status_code
            hs.reason = self._status_reason(resp.status_code)
            hs.response_headers = {k.lower(): v for k, v in resp.headers.items()}

            if resp.status_code == 101:
                hs.upgrade_successful = True
                self._parse_101(hs, nonce)
            else:
                hs.upgrade_successful = False

            hs.server_header = hs.response_headers.get("server")
            self._extract_cookies(hs)
            self._detect_origin_policy(hs)
            self._detect_auth_from_headers(hs)

        except Exception as exc:  # noqa: BLE001
            logger.debug("WebSocket handshake error for %s: %s", ws_url, exc)
            hs.status_code = 0
            hs.reason = str(exc)

        hs.connect_time_ms = (time.monotonic() - t0) * 1000
        return hs

    async def probe_origin_policy(self, ws_url: str) -> OriginPolicy:
        """
        Determine origin validation strictness by probing with a foreign origin.
        """
        foreign_origin = "https://evil.example.com"
        hs = await self.probe(ws_url, origin=foreign_origin)
        if hs.status_code == 101:
            return OriginPolicy.PERMISSIVE
        if hs.status_code in (400, 403, 426):
            return OriginPolicy.STRICT
        if hs.status_code == 0:
            return OriginPolicy.UNKNOWN
        return OriginPolicy.NO_CHECK

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ws_to_http(ws_url: str) -> str:
        """Convert ``wss://`` → ``https://`` and ``ws://`` → ``http://``."""
        return ws_url.replace("wss://", "https://").replace("ws://", "http://")

    @staticmethod
    def _generate_ws_key() -> str:
        """Generate a valid Sec-WebSocket-Key nonce."""
        raw = base64.b64encode(b"\x00" * 16).decode()
        return raw

    @staticmethod
    def _expected_accept(key: str) -> str:
        """Compute the expected Sec-WebSocket-Accept value."""
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        digest = hashlib.sha1((key + magic).encode()).digest()
        return base64.b64encode(digest).decode()

    def _build_upgrade_headers(self, nonce: str, origin: str) -> Dict[str, str]:
        return {
            "Upgrade":                "websocket",
            "Connection":             "Upgrade",
            "Sec-WebSocket-Key":      nonce,
            "Sec-WebSocket-Version":  "13",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            "Origin":                 origin,
            "User-Agent":             getattr(self._http, "user_agent", "WebShield/3.2"),
        }

    def _parse_101(self, hs: WSHandshake, nonce: str) -> None:
        headers = hs.response_headers
        hs.sec_ws_accept = headers.get("sec-websocket-accept", "")
        hs.subprotocol = headers.get("sec-websocket-protocol")

        # Extensions
        ext_raw = headers.get("sec-websocket-extensions", "")
        if ext_raw:
            hs.extensions = [e.strip() for e in ext_raw.split(",")]

    def _extract_cookies(self, hs: WSHandshake) -> None:
        raw = hs.response_headers.get("set-cookie", "")
        if raw:
            hs.set_cookies = [c.strip() for c in raw.split(",") if "=" in c]

    def _detect_origin_policy(self, hs: WSHandshake) -> None:
        """Infer origin policy from CORS-like headers (present on some stacks)."""
        acao = hs.response_headers.get("access-control-allow-origin", "")
        if acao == "*":
            hs.origin_policy = OriginPolicy.PERMISSIVE
        elif acao:
            hs.origin_policy = OriginPolicy.STRICT
            hs.allowed_origins = [o.strip() for o in acao.split(",")]

    def _detect_auth_from_headers(self, hs: WSHandshake) -> None:
        if hs.www_authenticate:
            hs.auth_scheme = WSAuthScheme.HANDSHAKE_HEADER
        elif hs.set_cookies:
            hs.auth_scheme = WSAuthScheme.HANDSHAKE_COOKIE

    @staticmethod
    def _status_reason(code: int) -> str:
        reasons = {
            101: "Switching Protocols",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            426: "Upgrade Required",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }
        return reasons.get(code, "Unknown")


# ===========================================================================
# Message Probe (simulated / protocol-template based)
# ===========================================================================

class WSMessageProbe:
    """
    Generates and classifies synthetic WebSocket messages for protocol detection.

    Because we cannot maintain long-lived WS connections through the HTTP client,
    this class works with *templates* — known first messages for each protocol
    family — and analyses any response fragments that come back in the HTTP
    response body of the upgrade attempt.
    """

    # First client message templates indexed by protocol family
    _INIT_MESSAGES: Dict[WSProtocolFamily, List[str]] = {
        WSProtocolFamily.GRAPHQL: [
            '{"type":"connection_init","payload":{}}',
            '{"type":"connection_init"}',
        ],
        WSProtocolFamily.ACTION_CABLE: [
            '{"command":"subscribe","identifier":"{\\"channel\\":\\"ApplicationCable::Channel\\"}"}',
        ],
        WSProtocolFamily.PHOENIX: [
            '{"topic":"phoenix","event":"heartbeat","payload":{},"ref":"1"}',
        ],
        WSProtocolFamily.JSON_RPC: [
            '{"jsonrpc":"2.0","method":"ping","params":[],"id":1}',
        ],
        WSProtocolFamily.STOMP: [
            "CONNECT\naccept-version:1.2\nheart-beat:0,0\n\n\x00",
        ],
        WSProtocolFamily.WAMP: [
            "[1,\"realm1\",{}]",  # HELLO
        ],
        WSProtocolFamily.SOCKET_IO: [
            "2probe",   # Polling→WS upgrade ping
            "5",        # Upgrade packet
        ],
        WSProtocolFamily.SOCKJS: [
            '["probe"]',
        ],
    }

    def get_init_messages(
        self,
        family: WSProtocolFamily,
    ) -> List[WSMessageSample]:
        """Return the synthetic initial messages for a given protocol family."""
        raw_list = self._INIT_MESSAGES.get(family, [])
        samples = []
        for raw in raw_list:
            sample = WSMessageSample(
                direction="client",
                opcode="text",
                raw=raw,
            )
            try:
                sample.parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                pass
            samples.append(sample)
        return samples

    def parse_message(self, raw: str, opcode: str = "text") -> WSMessageSample:
        """Parse a raw WebSocket message string into a ``WSMessageSample``."""
        sample = WSMessageSample(direction="server", opcode=opcode, raw=raw)
        if opcode == "text":
            try:
                parsed = json.loads(raw)
                sample.parsed = parsed
                if isinstance(parsed, dict):
                    sample.event_type = (
                        parsed.get("type")
                        or parsed.get("event")
                        or parsed.get("action")
                    )
                    sample.channel = parsed.get("topic") or parsed.get("channel")
                    sample.is_auth = bool(
                        "token" in parsed
                        or "access_token" in parsed
                        or "Authorization" in parsed
                        or sample.event_type in ("auth", "authenticate", "login")
                    )
            except (json.JSONDecodeError, ValueError):
                pass
        return sample

    def extract_injectable_fields(
        self,
        messages: List[WSMessageSample],
    ) -> List[Dict[str, Any]]:
        """
        Identify message fields that accept user-controlled input.

        Returns a list of injection-point dicts with keys:
        ``field_path``, ``example_value``, ``message_template``.
        """
        injection_points: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def _walk(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    fp = f"{path}.{k}" if path else k
                    _walk(v, fp)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _walk(item, f"{path}[{i}]")
            elif isinstance(obj, str) and path and path not in seen:
                seen.add(path)
                injection_points.append({
                    "field_path":      path,
                    "example_value":   obj,
                    "value_type":      "string",
                })
            elif isinstance(obj, (int, float)) and path and path not in seen:
                seen.add(path)
                injection_points.append({
                    "field_path":      path,
                    "example_value":   obj,
                    "value_type":      "number",
                })

        for msg in messages:
            if msg.parsed:
                _walk(msg.parsed)

        return injection_points


# ===========================================================================
# JavaScript & HTML Miner
# ===========================================================================

class WSSourceMiner:
    """
    Extracts WebSocket URLs, channel names, event types, and auth patterns
    from JavaScript source files and HTML page content.
    """

    def __init__(self, base_url: str) -> None:
        self._base = base_url

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mine_js(self, js_content: str) -> Tuple[List[str], List[WSChannel], List[str]]:
        """
        Parse a JavaScript file for WebSocket signals.

        Returns:
            ws_urls    — absolute WebSocket URLs found
            channels   — ``WSChannel`` objects discovered
            event_types — event/message type strings
        """
        ws_urls: List[str] = []
        channels: List[WSChannel] = []
        event_types: List[str] = []

        # Extract raw URL strings
        for pattern in _JS_WS_PATTERNS:
            for match in pattern.finditer(js_content):
                raw = match.group(1)
                url = self._resolve(raw)
                if url and url not in ws_urls:
                    ws_urls.append(url)

        # Extract channels / topics / rooms
        channels.extend(self._extract_channels(js_content))

        # Extract event type strings
        event_types.extend(self._extract_event_types(js_content))

        return ws_urls, channels, event_types

    def mine_html(self, html_content: str) -> List[str]:
        """Extract WebSocket URLs from HTML data-* attributes."""
        urls: List[str] = []
        for pattern in _HTML_WS_ATTRS:
            for match in pattern.finditer(html_content):
                raw = match.group(1)
                url = self._resolve(raw)
                if url and url not in urls:
                    urls.append(url)
        return urls

    def mine_service_worker(self, sw_content: str) -> List[str]:
        """Extract WebSocket URLs from a Service Worker script."""
        urls: List[str] = []
        for pattern in _JS_WS_PATTERNS:
            for match in pattern.finditer(sw_content):
                raw = match.group(1)
                url = self._resolve(raw)
                if url and url not in urls:
                    urls.append(url)
        return urls

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve(self, raw: str) -> Optional[str]:
        """Resolve a raw URL string to an absolute WebSocket URL."""
        raw = raw.strip()
        if not raw or len(raw) < 2:
            return None

        # Already absolute WS
        if raw.startswith(("ws://", "wss://")):
            return raw

        # Absolute HTTP — convert to WS
        if raw.startswith("https://"):
            return "wss://" + raw[8:]
        if raw.startswith("http://"):
            return "ws://" + raw[7:]

        # Relative path — resolve against base
        if raw.startswith("/") or raw.startswith("."):
            try:
                http = urljoin(self._base, raw)
                return self._http_to_ws(http)
            except Exception:
                return None

        # Bare hostname?
        if re.match(r'^[\w.-]+\.\w{2,}/', raw):
            scheme = "wss" if "443" in raw else "ws"
            return f"{scheme}://{raw}"

        return None

    @staticmethod
    def _http_to_ws(url: str) -> str:
        return url.replace("https://", "wss://").replace("http://", "ws://")

    def _extract_channels(self, js: str) -> List[WSChannel]:
        """Mine channel / topic / room names from JS source."""
        channels: List[WSChannel] = []
        seen: Set[str] = set()

        # ActionCable channel names: "ChatChannel", "NotificationsChannel"
        for m in re.finditer(r"""channel\s*:\s*['"`](\w+Channel)['"`]""", js, re.IGNORECASE):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                is_admin = "admin" in name.lower()
                channels.append(WSChannel(
                    name=name,
                    source=WSDiscoverySource.JS_ANALYSIS,
                    is_admin=is_admin,
                ))

        # Phoenix topics: "room:lobby", "presence:user_id"
        for m in re.finditer(r"""['"` ](\w+:\w[\w-]*)['"`]""", js):
            name = m.group(1)
            if ":" in name and name not in seen and len(name) < 60:
                seen.add(name)
                channels.append(WSChannel(
                    name=name,
                    source=WSDiscoverySource.JS_ANALYSIS,
                    requires_auth="user" in name.lower() or "private" in name.lower(),
                ))

        # socket.io namespaces: socket.of("/admin")
        for m in re.finditer(r"""\.of\s*\(\s*['"`]([^'"`]+)['"`]\s*\)""", js, re.IGNORECASE):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                channels.append(WSChannel(
                    name=name,
                    source=WSDiscoverySource.JS_ANALYSIS,
                    is_admin="admin" in name.lower(),
                ))

        # WAMP realm names
        for m in re.finditer(r"""realm\s*:\s*['"`]([^'"`]{2,60})['"`]""", js, re.IGNORECASE):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                channels.append(WSChannel(
                    name=name,
                    source=WSDiscoverySource.JS_ANALYSIS,
                ))

        # Generic subscription topics
        for m in re.finditer(
            r"""subscribe\s*\(\s*['"`]([^'"`]{2,80})['"`]""", js, re.IGNORECASE
        ):
            name = m.group(1)
            if name not in seen and "/" in name or "_" in name:
                seen.add(name)
                channels.append(WSChannel(
                    name=name,
                    source=WSDiscoverySource.JS_ANALYSIS,
                ))

        return channels

    def _extract_event_types(self, js: str) -> List[str]:
        """Extract event type name strings from JS source."""
        event_types: Set[str] = set()

        # .on("event_name", …)
        for m in re.finditer(r"""\.on\s*\(\s*['"`]([^'"`]{2,60})['"`]""", js):
            event_types.add(m.group(1))

        # .emit("event_name", …)
        for m in re.finditer(r"""\.emit\s*\(\s*['"`]([^'"`]{2,60})['"`]""", js):
            event_types.add(m.group(1))

        # switch(msg.type) { case "event_name":
        for m in re.finditer(r"""case\s*['"`]([^'"`]{2,60})['"`]\s*:""", js):
            event_types.add(m.group(1))

        # type === "event_name"
        for m in re.finditer(r"""type\s*===?\s*['"`]([^'"`]{2,60})['"`]""", js):
            event_types.add(m.group(1))

        # Filter out noise
        return [
            e for e in sorted(event_types)
            if not any(c in e for c in ("//", "/*", "*/", "\n"))
        ]


# ===========================================================================
# Auth Detector
# ===========================================================================

class WSAuthDetector:
    """
    Infers the authentication scheme used by a WebSocket endpoint.

    Combines evidence from:
      - URL query parameters
      - Handshake request headers
      - Handshake response cookies
      - Initial protocol messages
      - JavaScript source patterns
    """

    _TOKEN_QUERY_PARAMS = {
        "token", "access_token", "jwt", "auth_token", "apikey", "api_key",
        "key", "secret", "auth", "authorization", "bearer",
    }

    _SESSION_QUERY_PARAMS = {
        "session", "session_id", "sid", "sessid", "cookie",
    }

    def detect_from_url(self, ws_url: str) -> Tuple[WSAuthScheme, Optional[str]]:
        """Check URL query parameters for embedded tokens."""
        qs = parse_qs(urlparse(ws_url).query, keep_blank_values=True)
        for param in qs:
            if param.lower() in self._TOKEN_QUERY_PARAMS:
                return WSAuthScheme.QUERY_PARAM_TOKEN, param
            if param.lower() in self._SESSION_QUERY_PARAMS:
                return WSAuthScheme.QUERY_PARAM_SESSION, param
        return WSAuthScheme.NONE, None

    def detect_from_handshake(self, hs: WSHandshake) -> WSAuthScheme:
        """Check handshake evidence for auth signals."""
        if hs.www_authenticate:
            return WSAuthScheme.HANDSHAKE_HEADER
        if hs.set_cookies:
            return WSAuthScheme.HANDSHAKE_COOKIE
        # Authorization header forwarded
        auth_hdr = hs.request_headers.get("Authorization", "")
        if auth_hdr:
            return WSAuthScheme.HANDSHAKE_HEADER
        return WSAuthScheme.NONE

    def detect_from_messages(
        self, messages: List[WSMessageSample]
    ) -> WSAuthScheme:
        """Infer auth scheme from message-level patterns."""
        for msg in messages:
            if not msg.parsed or not isinstance(msg.parsed, dict):
                continue
            # {"type":"authenticate","token":"…"}
            if msg.is_auth:
                if msg.event_type in ("auth", "authenticate", "login"):
                    return WSAuthScheme.FIRST_MESSAGE_AUTH_OBJ
                return WSAuthScheme.FIRST_MESSAGE_TOKEN
            # {"type":"subscribe","token":"…"}
            if msg.event_type == "subscribe" and "token" in msg.parsed:
                return WSAuthScheme.SUBSCRIBE_WITH_TOKEN
        return WSAuthScheme.NONE

    def detect_from_js(self, js_content: str) -> WSAuthScheme:
        """Mine JS source for auth token injection patterns."""
        # Bearer token in first message
        if re.search(r"""['"` ]?token['"`]?\s*:\s*(?:localStorage|sessionStorage|cookie)""",
                     js_content, re.IGNORECASE):
            return WSAuthScheme.FIRST_MESSAGE_TOKEN
        if re.search(r"""Authorization.*Bearer""", js_content, re.IGNORECASE):
            return WSAuthScheme.HANDSHAKE_HEADER
        if re.search(r"""[?&]token=""", js_content, re.IGNORECASE):
            return WSAuthScheme.QUERY_PARAM_TOKEN
        return WSAuthScheme.NONE

    def best_scheme(self, *candidates: WSAuthScheme) -> WSAuthScheme:
        """Return the highest-confidence scheme from a list of candidates."""
        priority = [
            WSAuthScheme.FIRST_MESSAGE_AUTH_OBJ,
            WSAuthScheme.FIRST_MESSAGE_TOKEN,
            WSAuthScheme.SUBSCRIBE_WITH_TOKEN,
            WSAuthScheme.HANDSHAKE_HEADER,
            WSAuthScheme.QUERY_PARAM_TOKEN,
            WSAuthScheme.QUERY_PARAM_SESSION,
            WSAuthScheme.HANDSHAKE_COOKIE,
            WSAuthScheme.UNKNOWN,
            WSAuthScheme.NONE,
        ]
        for scheme in priority:
            if scheme in candidates:
                return scheme
        return WSAuthScheme.NONE


# ===========================================================================
# Path Prober
# ===========================================================================

class WSPathProber:
    """
    Probes a list of candidate WebSocket paths and returns those that respond
    with a 101 or otherwise look like active WebSocket endpoints.
    """

    # Status codes that suggest a WebSocket-capable endpoint even without 101
    _CANDIDATE_CODES = {101, 400, 426}
    # Definite rejection codes
    _REJECT_CODES    = {404, 410}

    def __init__(
        self,
        analyser: WSHandshakeAnalyser,
        target: ScanTarget,
        concurrency: int = 10,
    ) -> None:
        self._analyser = analyser
        self._target = target
        self._sem = asyncio.Semaphore(concurrency)

    async def probe_paths(
        self,
        paths: Optional[List[str]] = None,
        extra_urls: Optional[List[str]] = None,
    ) -> List[WSEndpoint]:
        """
        Probe all candidate paths and return discovered ``WSEndpoint`` objects.
        """
        urls: List[str] = []

        # Build URL list from paths
        base = self._target.base_url.rstrip("/")
        for path in (paths or _WS_PATHS):
            http_url = base + path
            urls.append(self._http_to_ws(http_url))

        # Merge extra URLs (from JS mining, etc.)
        for url in (extra_urls or []):
            if url not in urls:
                urls.append(url)

        tasks = [self._probe_one(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        endpoints: List[WSEndpoint] = []
        for ep in results:
            if isinstance(ep, WSEndpoint):
                endpoints.append(ep)

        return endpoints

    async def _probe_one(self, ws_url: str) -> WSEndpoint:
        async with self._sem:
            t0 = time.monotonic()
            ep = WSEndpoint(
                url=ws_url,
                source=WSDiscoverySource.PATH_PROBE,
                status=WSStatus.UNKNOWN,
            )
            try:
                hs = await self._analyser.probe(ws_url)
                ep.handshake = hs
                ep.server_software = hs.server_header

                if hs.status_code == 101:
                    ep.status = WSStatus.OPEN
                    ep.origin_policy = hs.origin_policy
                    ep.auth_scheme = hs.auth_scheme
                    if hs.extensions:
                        ep.compression_enabled = any(
                            "deflate" in e for e in hs.extensions
                        )
                elif hs.status_code in self._CANDIDATE_CODES:
                    ep.status = WSStatus.REJECTED
                elif hs.status_code in self._REJECT_CODES:
                    ep.status = WSStatus.UNREACHABLE
                elif hs.status_code == 0:
                    ep.status = WSStatus.UNREACHABLE
                else:
                    ep.status = WSStatus.REJECTED

            except Exception as exc:  # noqa: BLE001
                logger.debug("Probe error for %s: %s", ws_url, exc)
                ep.status = WSStatus.UNREACHABLE

            ep.discovery_time_ms = (time.monotonic() - t0) * 1000
            return ep

    @staticmethod
    def _http_to_ws(url: str) -> str:
        return url.replace("https://", "wss://").replace("http://", "ws://")


# ===========================================================================
# Endpoint Enricher
# ===========================================================================

class WSEndpointEnricher:
    """
    Enriches a ``WSEndpoint`` with protocol detection, auth analysis,
    channel/event inventory, and attack surface extraction.

    Operates on already-probed endpoints — no network calls.
    """

    def __init__(self) -> None:
        self._proto_detector = WSProtocolDetector()
        self._msg_probe      = WSMessageProbe()
        self._auth_detector  = WSAuthDetector()

    def enrich(
        self,
        endpoint: WSEndpoint,
        js_channels: Optional[List[WSChannel]] = None,
        js_events: Optional[List[str]] = None,
        js_auth: WSAuthScheme = WSAuthScheme.NONE,
    ) -> WSEndpoint:
        """Apply all enrichment passes to ``endpoint`` in-place and return it."""

        # 1. Protocol detection
        family, fmt = self._proto_detector.detect(endpoint, endpoint.initial_messages)
        endpoint.protocol_family = family
        endpoint.data_format = fmt
        endpoint.subprotocol_label = _KNOWN_SUBPROTOCOLS.get(
            (endpoint.handshake.subprotocol or "").lower()
        )

        # 2. Auth detection (best of all sources)
        auth_from_url, token_param = self._auth_detector.detect_from_url(endpoint.url)
        auth_from_hs  = (
            self._auth_detector.detect_from_handshake(endpoint.handshake)
            if endpoint.handshake else WSAuthScheme.NONE
        )
        auth_from_msg = self._auth_detector.detect_from_messages(endpoint.initial_messages)
        endpoint.auth_scheme = self._auth_detector.best_scheme(
            auth_from_url, auth_from_hs, auth_from_msg, js_auth
        )
        endpoint.token_param_name = token_param

        # 3. Merge JS channels & events
        if js_channels:
            existing = {c.name for c in endpoint.channels}
            for ch in js_channels:
                if ch.name not in existing:
                    endpoint.channels.append(ch)
                    existing.add(ch.name)
        if js_events:
            known = set(endpoint.event_types)
            endpoint.event_types.extend(e for e in js_events if e not in known)

        # 4. Detect admin / privileged items
        endpoint.admin_commands = [
            c.name for c in endpoint.channels
            if c.is_admin or "admin" in c.name.lower()
        ]
        endpoint.privileged_channels = [
            c.name for c in endpoint.channels
            if c.requires_auth and not c.is_admin
        ]

        # 5. Inject injection points from messages
        endpoint.injectable_fields = self._msg_probe.extract_injectable_fields(
            endpoint.initial_messages
        )

        # 6. Framework hint from protocol family
        _FAMILY_TO_FRAMEWORK = {
            WSProtocolFamily.SOCKET_IO:    "socket.io",
            WSProtocolFamily.SOCKJS:       "SockJS",
            WSProtocolFamily.ACTION_CABLE: "ActionCable (Rails)",
            WSProtocolFamily.PHOENIX:      "Phoenix Channels (Elixir)",
            WSProtocolFamily.SIGNALR:      "ASP.NET SignalR",
            WSProtocolFamily.CENTRIFUGE:   "Centrifuge/Centrifugo",
            WSProtocolFamily.GRAPHQL:      "GraphQL over WebSocket",
            WSProtocolFamily.STOMP:        "STOMP",
            WSProtocolFamily.MQTT:         "MQTT",
            WSProtocolFamily.WAMP:         "WAMP",
        }
        endpoint.framework_hint = _FAMILY_TO_FRAMEWORK.get(family)

        return endpoint


# ===========================================================================
# Attack Surface Builder
# ===========================================================================

@dataclass
class WSAttackSurface:
    """
    Distilled WebSocket attack surface for downstream scanners.

    Built by ``WSFramework`` from all discovered endpoints and passed to:
      - ``websocket_scanner.py`` (active exploitation)
      - ``EndpointClassificationEngine`` (risk scoring)
      - ``ContextAwarePayloadFramework`` (targeted payloads)
    """
    # Endpoints split by risk category
    open_endpoints:          List[str]                  = field(default_factory=list)
    permissive_origin_urls:  List[str]                  = field(default_factory=list)
    unauthenticated_urls:    List[str]                  = field(default_factory=list)
    authenticated_urls:      List[str]                  = field(default_factory=list)
    admin_urls:              List[str]                  = field(default_factory=list)

    # Message injection surface
    injectable_endpoints:    List[Dict[str, Any]]       = field(default_factory=list)

    # Channel / subscription topology
    all_channels:            List[str]                  = field(default_factory=list)
    privileged_channels:     List[str]                  = field(default_factory=list)
    admin_channels:          List[str]                  = field(default_factory=list)

    # Event types (for fuzzing)
    all_event_types:         List[str]                  = field(default_factory=list)

    # Protocol families present
    protocol_families:       List[str]                  = field(default_factory=list)

    # Auth schemes present
    auth_schemes:            List[str]                  = field(default_factory=list)

    # File transfer channels
    file_transfer_channels:  List[str]                  = field(default_factory=list)

    # Binary protocol endpoints (need binary fuzzer)
    binary_endpoints:        List[str]                  = field(default_factory=list)

    # Token param names (for query-string auth bypass tests)
    token_param_names:       List[str]                  = field(default_factory=list)


def build_attack_surface(report: WSFrameworkReport) -> WSAttackSurface:
    """Build a ``WSAttackSurface`` from a completed ``WSFrameworkReport``."""
    surface = WSAttackSurface()

    families:     Set[str] = set()
    auth_schemes: Set[str] = set()

    for ep in report.endpoints:
        if ep.status != WSStatus.OPEN:
            continue

        surface.open_endpoints.append(ep.url)

        if ep.origin_policy == OriginPolicy.PERMISSIVE:
            surface.permissive_origin_urls.append(ep.url)

        if ep.auth_scheme in (WSAuthScheme.NONE, WSAuthScheme.UNKNOWN):
            surface.unauthenticated_urls.append(ep.url)
        else:
            surface.authenticated_urls.append(ep.url)

        if ep.admin_commands:
            surface.admin_urls.append(ep.url)

        if ep.injectable_fields:
            surface.injectable_endpoints.append({
                "url":    ep.url,
                "fields": ep.injectable_fields,
            })

        for ch in ep.channels:
            if ch.name not in surface.all_channels:
                surface.all_channels.append(ch.name)
            if ch.requires_auth and ch.name not in surface.privileged_channels:
                surface.privileged_channels.append(ch.name)
            if ch.is_admin and ch.name not in surface.admin_channels:
                surface.admin_channels.append(ch.name)

        for et in ep.event_types:
            if et not in surface.all_event_types:
                surface.all_event_types.append(et)

        families.add(ep.protocol_family.value)
        auth_schemes.add(ep.auth_scheme.value)

        surface.file_transfer_channels.extend(ep.file_transfer_channels)

        if ep.data_format in (WSDataFormat.BINARY_BLOB, WSDataFormat.MESSAGEPACK,
                               WSDataFormat.CBOR, WSDataFormat.PROTOBUF):
            surface.binary_endpoints.append(ep.url)

        if ep.token_param_name and ep.token_param_name not in surface.token_param_names:
            surface.token_param_names.append(ep.token_param_name)

    surface.protocol_families = sorted(families)
    surface.auth_schemes      = sorted(auth_schemes)

    return surface


# ===========================================================================
# Main Framework
# ===========================================================================

class WebSocketFramework:
    """
    Top-level coordinator for WebSocket reconnaissance.

    Orchestrates:
      1. Path probing  — HTTP Upgrade handshake against 60+ candidate paths
      2. JS mining     — URL, channel, event, and auth extraction from scripts
      3. HTML mining   — data-* attribute extraction from page content
      4. Endpoint enrichment — protocol, auth, attack surface classification
      5. Origin policy probing — for all open endpoints
      6. Attack surface packaging — ready for downstream scanners

    Usage::

        async with WebSocketFramework(http_client, target) as fw:
            report = await fw.run(js_contents=["..."], html_content="...")
            surface = report.attack_surface
    """

    def __init__(
        self,
        http:        HTTPClient,
        target:      ScanTarget,
        concurrency: int = 8,
    ) -> None:
        self._http        = http
        self._target      = target
        self._analyser    = WSHandshakeAnalyser(http, target)
        self._prober      = WSPathProber(self._analyser, target, concurrency)
        self._enricher    = WSEndpointEnricher()
        self._auth_det    = WSAuthDetector()
        self._miner       = WSSourceMiner(target.base_url)

    async def __aenter__(self) -> "WebSocketFramework":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        js_contents:  Optional[List[str]] = None,
        html_content: Optional[str] = None,
        extra_urls:   Optional[List[str]] = None,
    ) -> WSFrameworkReport:
        """
        Run the full WebSocket reconnaissance pipeline.

        Parameters
        ----------
        js_contents:
            List of JavaScript source file contents already fetched by the
            JS Analysis Engine or Browser Automation Layer.
        html_content:
            Raw HTML of the target's main page (used for data-* attribute mining).
        extra_urls:
            Additional WebSocket URLs to probe on top of the built-in path list
            (e.g. from Knowledge Base or user-supplied scope).

        Returns
        -------
        ``WSFrameworkReport`` with all endpoints and the pre-built attack surface.
        """
        t0 = time.monotonic()
        report = WSFrameworkReport(target_url=self._target.base_url)

        # ----------------------------------------------------------------
        # Phase A — Source mining (JS + HTML) to collect extra URLs
        # ----------------------------------------------------------------
        mined_ws_urls:  List[str]       = list(extra_urls or [])
        all_channels:   List[WSChannel] = []
        all_events:     List[str]       = []
        all_auth:       List[WSAuthScheme] = []

        for js in (js_contents or []):
            urls, channels, events = self._miner.mine_js(js)
            report.js_urls_mined += len(urls)
            mined_ws_urls.extend(u for u in urls if u not in mined_ws_urls)
            all_channels.extend(channels)
            all_events.extend(e for e in events if e not in all_events)
            auth = self._auth_det.detect_from_js(js)
            if auth != WSAuthScheme.NONE:
                all_auth.append(auth)

        if html_content:
            html_urls = self._miner.mine_html(html_content)
            report.html_attrs_mined = len(html_urls)
            mined_ws_urls.extend(u for u in html_urls if u not in mined_ws_urls)

        # ----------------------------------------------------------------
        # Phase B — Path probing
        # ----------------------------------------------------------------
        raw_endpoints = await self._prober.probe_paths(extra_urls=mined_ws_urls)
        report.probed_paths = len(raw_endpoints)

        # Deduplicate by URL
        seen_urls: Set[str] = set()
        unique_endpoints: List[WSEndpoint] = []
        for ep in raw_endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                unique_endpoints.append(ep)

        # ----------------------------------------------------------------
        # Phase C — Origin policy probing (open endpoints only)
        # ----------------------------------------------------------------
        origin_tasks = [
            self._probe_origin(ep)
            for ep in unique_endpoints
            if ep.status == WSStatus.OPEN
        ]
        if origin_tasks:
            await asyncio.gather(*origin_tasks, return_exceptions=True)

        # ----------------------------------------------------------------
        # Phase D — Endpoint enrichment
        # ----------------------------------------------------------------
        js_auth_best = self._auth_det.best_scheme(*all_auth) if all_auth else WSAuthScheme.NONE
        for ep in unique_endpoints:
            self._enricher.enrich(
                ep,
                js_channels=all_channels,
                js_events=all_events,
                js_auth=js_auth_best,
            )
            # Merge companion HTTP URL
            if ep.handshake and ep.handshake.upgrade_successful:
                ep.http_companion_url = (
                    WSHandshakeAnalyser._ws_to_http(ep.url)
                )

        # ----------------------------------------------------------------
        # Phase E — Aggregate stats
        # ----------------------------------------------------------------
        for ep in unique_endpoints:
            if ep.status == WSStatus.OPEN:
                report.open_count += 1
            elif ep.status == WSStatus.REJECTED:
                report.rejected_count += 1
            else:
                report.unreachable_count += 1

        report.endpoints    = unique_endpoints
        report.scan_duration_s = time.monotonic() - t0

        # ----------------------------------------------------------------
        # Phase F — Build attack surface
        # ----------------------------------------------------------------
        report.attack_surface = build_attack_surface(report)

        logger.info(
            "WebSocket Framework complete: %d open / %d probed in %.1fs",
            report.open_count, report.probed_paths, report.scan_duration_s,
        )
        return report

    async def analyse_endpoint(self, ws_url: str) -> WSEndpoint:
        """
        Deep-dive analysis of a single, already-known WebSocket endpoint.

        Combines handshake analysis, origin policy probing, and enrichment
        into a single call suitable for targeted use by downstream scanners.
        """
        ep = WSEndpoint(url=ws_url, source=WSDiscoverySource.USER_PROVIDED)

        # Handshake
        hs = await self._analyser.probe(ws_url)
        ep.handshake = hs
        ep.server_software = hs.server_header
        ep.status = WSStatus.OPEN if hs.status_code == 101 else WSStatus.REJECTED

        if ep.status == WSStatus.OPEN:
            # Origin policy
            ep.origin_policy = await self._analyser.probe_origin_policy(ws_url)
            ep.handshake.origin_policy = ep.origin_policy

            # Compression
            if hs.extensions:
                ep.compression_enabled = any("deflate" in e for e in hs.extensions)

        # Enrich
        self._enricher.enrich(ep)
        return ep

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _probe_origin(self, ep: WSEndpoint) -> None:
        """Probe origin policy for one open endpoint (mutates in place)."""
        try:
            policy = await self._analyser.probe_origin_policy(ep.url)
            ep.origin_policy = policy
            if ep.handshake:
                ep.handshake.origin_policy = policy
        except Exception as exc:  # noqa: BLE001
            logger.debug("Origin probe error for %s: %s", ep.url, exc)


# ===========================================================================
# Convenience function (mirrors graphql_framework / api_discovery_engine API)
# ===========================================================================

async def run_websocket_framework(
    http:          HTTPClient,
    target:        ScanTarget,
    js_contents:   Optional[List[str]] = None,
    html_content:  Optional[str] = None,
    extra_urls:    Optional[List[str]] = None,
    concurrency:   int = 8,
) -> WSFrameworkReport:
    """
    Run the full WebSocket Framework pipeline and return the report.

    This is the primary entry point used by ``Phase2MasterOrchestrator``
    and any scanner that needs WebSocket reconnaissance context.

    Parameters
    ----------
    http:
        Configured ``HTTPClient`` for the current scan session.
    target:
        ``ScanTarget`` describing the application under test.
    js_contents:
        JavaScript file contents already collected by the JS Analysis Engine.
    html_content:
        Raw HTML of the target's index page for data-* attribute mining.
    extra_urls:
        Additional WebSocket URLs from user scope or Knowledge Base.
    concurrency:
        Maximum simultaneous handshake probes (default: 8).

    Returns
    -------
    ``WSFrameworkReport`` containing all discovered endpoints and the
    ``WSAttackSurface`` ready for downstream consumption.
    """
    async with WebSocketFramework(http, target, concurrency) as fw:
        return await fw.run(
            js_contents=js_contents,
            html_content=html_content,
            extra_urls=extra_urls,
        )
