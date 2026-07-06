"""
Compiled regex patterns for vulnerability detection.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import re
from typing import Dict, Pattern, List, Tuple

# ---------------------------------------------------------------------------
# SQL Error Detection Patterns
# ---------------------------------------------------------------------------

SQLI_ERROR_PATTERNS: List[Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    # MySQL / MariaDB
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"mysql_fetch_(array|row|object|assoc)\(\)",
    r"mysql_num_rows\(\)",
    r"valid mysql result",
    r"mysqlclient\.queries",
    r"com\.mysql\.jdbc",
    r"org\.hibernate\.QueryException",
    # MSSQL / SQL Server
    r"unclosed quotation mark after the character string",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"warning.*mssql",
    r"\[sql server\]",
    r"sqlserver\.",
    r"sqlexception.*sql server",
    r"incorrect syntax near",
    r"conversion failed when converting",
    r"arithmetic overflow error",
    # PostgreSQL
    r"pg::syntaxerror",
    r"postgresql.*error",
    r"pg_query\(\) expects parameter",
    r"psql.*error",
    r"pgsql.*error",
    r"unrecognized token",
    r"column.*does not exist",
    # Oracle
    r"ora-[0-9]{4,5}",
    r"oracle error",
    r"oracle.*driver",
    r"oracle\.jdbc",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite.*error",
    r"sqlite3\.operationalerror",
    r"near .*syntax error",
    r"unable to open database file",
    # Generic / Framework
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"sqlstate\[",
    r"pdoexception",
    r"java\.sql\.sqlexception",
    r"java\.sql\.syntax",
    r"net\.sourceforge\.jtds",
    r"jdbc.*exception",
    r"hibernate.*exception",
    r"sql command not properly ended",
    r"division by zero",
    r"invalid column name",
    r"\bsqlite_error\b",
    r"data type mismatch",
    r"\bdb2\b.*error",
    r"com\.ibm\.db2",
]]

# ---------------------------------------------------------------------------
# XSS Reflection Patterns
# ---------------------------------------------------------------------------

XSS_REFLECTION_MARKERS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "onerror=alert(1)",
    "onload=alert(1)",
    "alert(1)",
    "alert('XSS')",
    "javascript:alert",
]

# ---------------------------------------------------------------------------
# Command Injection Detection Patterns
# ---------------------------------------------------------------------------

CMDI_RESPONSE_PATTERNS: List[Pattern] = [re.compile(p, re.MULTILINE) for p in [
    r"uid=\d+\(",                   # Unix id output
    r"root:x:0:0:",                 # /etc/passwd
    r"(daemon|nobody|www-data):",   # passwd entries
    r"Windows IP Configuration",    # ipconfig
    r"Volume Serial Number",        # dir output
    r"Microsoft Windows \[",        # Windows ver
    r"Linux .+ \d+\.\d+",           # uname -a
    r"bin/(sh|bash|dash)",          # shell paths
    r"^\s*PING \d+\.\d+",           # ping output
    r"bytes from",                  # ping response
    r"\d+ packets transmitted",     # ping stats
]]

# ---------------------------------------------------------------------------
# Path Traversal Detection Patterns
# ---------------------------------------------------------------------------

LFI_RESPONSE_PATTERNS: List[Pattern] = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in [
    # Fix 3.1: Stricter patterns — each must be highly specific to avoid FP
    # /etc/passwd — highly specific Unix file signatures
    r"root:x:0:0",
    r"daemon:x:\d+:\d+:",
    # Windows boot.ini — require two distinct section markers
    r"\[boot loader\]",
    r"\[operating systems\]",
    # win.ini — require the specific string unique to this file
    r"for 16-bit app support",
    # PHP source — require a realistic opening with actual code (not just <?php)
    r"<\?php\s+(?:require|include|define|echo|session_start|header|class|function)",
    # .env — require key=value with real-looking secret (not docs/examples)
    r"(?:DB_PASSWORD|DATABASE_PASSWORD)\s*=\s*(?!your_|example|changeme|<)[^\s]{3,}",
    r"(?:APP_SECRET|SECRET_KEY)\s*=\s*(?!your_|example|changeme|<)[A-Za-z0-9+/]{16,}",
    # AWS credentials — highly specific format
    r"aws_access_key_id\s*=\s*AKIA[A-Z0-9]{16}",
    r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}",
]]

# ---------------------------------------------------------------------------
# SSRF Detection Patterns (in response body)
# ---------------------------------------------------------------------------

SSRF_RESPONSE_PATTERNS: List[Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"ami-id",
    r"instance-id",
    r"security-credentials",
    r"169\.254\.169\.254",
    r"computeMetadata",
    r"AccessKeyId",
    r"SecretAccessKey",
    r"iam/security-credentials",
    r"local-hostname",
    r"public-keys",
    r"network/interfaces",
    # More specific cloud metadata indicators:
    r'"instanceId"\s*:',             # AWS/GCP JSON metadata
    r'"region"\s*:\s*"[a-z]+-[a-z]+-\d+"',  # AWS region in metadata
    r"latest/meta-data/",            # AWS metadata path in body
    r"computeMetadata/v1/",          # GCP metadata path
    # NOTE: "metadata", "Token", "Expiration" removed — too generic, match normal app responses
]]

# ---------------------------------------------------------------------------
# Sensitive Data Patterns (compiled)
# ---------------------------------------------------------------------------

from .payloads import SENSITIVE_DATA_PATTERNS_EXTENDED as _RAW_SENSITIVE

SENSITIVE_DATA_COMPILED: Dict[str, Pattern] = {
    name: re.compile(pattern, re.MULTILINE)
    for name, pattern in _RAW_SENSITIVE.items()
}

# ---------------------------------------------------------------------------
# Open Redirect Detection
# ---------------------------------------------------------------------------

OPEN_REDIRECT_DOMAINS = ["evil.com", "attacker.com", "example.evil"]

# ---------------------------------------------------------------------------
# JWT Detection
# ---------------------------------------------------------------------------

JWT_PATTERN: Pattern = re.compile(
    r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"
)

JWT_ALG_NONE: Pattern = re.compile(
    r'"alg"\s*:\s*"none"', re.IGNORECASE
)

# ---------------------------------------------------------------------------
# HTTP Smuggling Indicators
# ---------------------------------------------------------------------------

SMUGGLING_PATTERNS: List[Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"transfer-encoding:\s*chunked",
    r"content-length:\s*\d+",
]]

# ---------------------------------------------------------------------------
# Broken Auth Patterns
# ---------------------------------------------------------------------------

BROKEN_AUTH_PATTERNS: List[Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"set-cookie:.*session",
    r"set-cookie:.*token",
    r"set-cookie:.*auth",
    r"set-cookie:.*jwt",
    r"authorization:\s*bearer",
    r"x-auth-token",
    r"x-access-token",
]]

AUTH_WEAK_COOKIE_FLAGS: List[str] = ["httponly", "secure", "samesite"]

# ---------------------------------------------------------------------------
# Technology Fingerprint Patterns
# ---------------------------------------------------------------------------

TECH_FINGERPRINTS: Dict[str, List[Pattern]] = {
    "PHP": [re.compile(r"X-Powered-By: PHP", re.I), re.compile(r"\.php(\?|$|/)", re.I)],
    "ASP.NET": [re.compile(r"X-Powered-By: ASP\.NET", re.I), re.compile(r"\.aspx?(\?|$|/)", re.I)],
    "WordPress": [re.compile(r"wp-content/", re.I), re.compile(r"wp-includes/", re.I)],
    "Drupal": [re.compile(r"Drupal", re.I), re.compile(r"drupal\.js", re.I)],
    "Joomla": [re.compile(r"/components/com_", re.I)],
    "nginx": [re.compile(r"Server: nginx", re.I)],
    "Apache": [re.compile(r"Server: Apache", re.I)],
    "IIS": [re.compile(r"Server: Microsoft-IIS", re.I)],
    "Express.js": [re.compile(r"X-Powered-By: Express", re.I)],
    "Django": [re.compile(r"csrfmiddlewaretoken", re.I)],
    "Laravel": [re.compile(r"laravel_session", re.I)],
    "Spring": [re.compile(r"JSESSIONID", re.I)],
    "Ruby on Rails": [re.compile(r"_rails_", re.I), re.compile(r"X-Request-Id", re.I)],
}
