"""
Secrets Discovery Engine

Dedicated scanner that hunts for exposed credentials across all surfaces:
- JavaScript files and source maps
- HTML page source (comments, inline scripts, meta tags)
- API responses (credentials leaking in JSON responses)
- HTTP response headers (debug headers, server tokens)

Differences from JSAnalyzer:
- JSAnalyzer fetches and analyzes external .js files only
- This scanner runs on every crawled page/response as a BaseScanner,
  integrating with the full scanner pipeline
- Adds more patterns not in JSAnalyzer (JWT tokens in responses,
  database dumps, PEM blocks, etc.)
- Also checks response headers and HTML comments
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPClient, HTTPResponse
from ..models.vulnerability import (
    Vulnerability, Severity, VulnType, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)


# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

@dataclass
class SecretPattern:
    """A single secret pattern with metadata for reporting."""
    name: str
    pattern: re.Pattern
    severity: Severity
    confidence: str           # High | Medium | Low
    description: str
    remediation: str
    cwe_id: str = "CWE-798"
    owasp_category: str = "A02:2021 – Cryptographic Failures"


def _p(flags: int = 0) -> int:
    return re.IGNORECASE | flags


# Comprehensive secret patterns
_SECRET_PATTERNS: List[SecretPattern] = [

    # ── Cloud Providers ─────────────────────────────────────────────────────
    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        severity=Severity.CRITICAL,
        confidence="High",
        description="An AWS Access Key ID was found. This can provide direct access to AWS services.",
        remediation=(
            "Revoke the exposed key immediately via AWS IAM. Rotate all keys in the affected account. "
            "Use IAM roles instead of long-lived credentials. Never embed AWS keys in client-side code."
        ),
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(
            r'(?:aws.?secret|secret.?access.?key|AWS_SECRET_ACCESS_KEY|aws_secret)[\'"\s:=]+([A-Za-z0-9/+]{40})\b',
            _p(),
        ),
        severity=Severity.CRITICAL,
        confidence="High",
        description="An AWS Secret Access Key was found. Combined with an Access Key ID, this grants full AWS API access.",
        remediation="Revoke immediately via AWS IAM. Audit CloudTrail logs for unauthorized usage.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
        severity=Severity.HIGH,
        confidence="High",
        description="A Google API Key was found. May allow unauthorized use of Google Cloud services.",
        remediation="Restrict the key to specific APIs and IPs in Google Cloud Console. Rotate the key.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Google OAuth Client Secret",
        pattern=re.compile(r'client_secret[\'"\s:=]+([A-Za-z0-9\-_]{24,32})', _p()),
        severity=Severity.HIGH,
        confidence="Medium",
        description="A Google OAuth Client Secret was found.",
        remediation="Rotate the OAuth client secret in Google Cloud Console.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Firebase API Key",
        pattern=re.compile(
            r'(?:firebase|FIREBASE)[^{]{0,50}(?:apiKey|api_key)[\'"\s:=]+([A-Za-z0-9\-_]{35,45})',
            _p(),
        ),
        severity=Severity.HIGH,
        confidence="High",
        description="A Firebase API Key was found in client-side code.",
        remediation="Configure Firebase Security Rules. API keys in Firebase are semi-public but rules must be strict.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Azure Connection String",
        pattern=re.compile(
            r'DefaultEndpointsProtocol=https;AccountName=[^;]{1,64};AccountKey=[A-Za-z0-9+/=]{88}',
            _p(),
        ),
        severity=Severity.CRITICAL,
        confidence="High",
        description="An Azure Storage Account connection string was found.",
        remediation="Regenerate the Azure storage account key immediately.",
        cwe_id="CWE-798",
    ),

    # ── Payment / Financial ──────────────────────────────────────────────────
    SecretPattern(
        name="Stripe Live Secret Key",
        pattern=re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'),
        severity=Severity.CRITICAL,
        confidence="High",
        description="A Stripe live secret key was found. Allows full payment API access.",
        remediation="Revoke the key in Stripe Dashboard immediately. Review transaction history for fraud.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Stripe Publishable Key (Live)",
        pattern=re.compile(r'\b(pk_live_[0-9a-zA-Z]{24,})\b'),
        severity=Severity.MEDIUM,
        confidence="High",
        description="A Stripe live publishable key was found. While less sensitive, it confirms live environment.",
        remediation="Ensure the corresponding secret key is not also exposed.",
        cwe_id="CWE-200",
    ),
    SecretPattern(
        name="PayPal Client Secret",
        pattern=re.compile(r'paypal.{0,30}(?:client_secret|secret)[\'"\s:=]+([A-Za-z0-9\-_]{20,64})', _p()),
        severity=Severity.HIGH,
        confidence="Medium",
        description="A PayPal client secret was found.",
        remediation="Rotate the PayPal credentials in the Developer Dashboard.",
        cwe_id="CWE-798",
    ),

    # ── Code Repositories ────────────────────────────────────────────────────
    SecretPattern(
        name="GitHub Personal Access Token",
        pattern=re.compile(r'\b(ghp_[A-Za-z0-9]{36})\b'),
        severity=Severity.CRITICAL,
        confidence="High",
        description="A GitHub Personal Access Token was found.",
        remediation="Revoke the token at github.com/settings/tokens immediately.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        pattern=re.compile(r'\b(gho_[A-Za-z0-9]{36})\b'),
        severity=Severity.HIGH,
        confidence="High",
        description="A GitHub OAuth token was found.",
        remediation="Revoke the token at github.com/settings/tokens.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="GitHub Actions Token",
        pattern=re.compile(r'\b(gha_[A-Za-z0-9]{36})\b'),
        severity=Severity.HIGH,
        confidence="High",
        description="A GitHub Actions token was found.",
        remediation="Rotate the GitHub Actions token.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="GitLab Personal Access Token",
        pattern=re.compile(r'\b(glpat-[A-Za-z0-9\-_]{20})\b'),
        severity=Severity.HIGH,
        confidence="High",
        description="A GitLab Personal Access Token was found.",
        remediation="Revoke the token in GitLab user settings.",
        cwe_id="CWE-798",
    ),

    # ── Communication ────────────────────────────────────────────────────────
    SecretPattern(
        name="Slack Bot Token",
        pattern=re.compile(r'\b(xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+)\b'),
        severity=Severity.HIGH,
        confidence="High",
        description="A Slack Bot Token was found. Allows reading/posting to Slack channels.",
        remediation="Revoke the token in Slack API app settings.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Slack Incoming Webhook",
        pattern=re.compile(r'hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]+'),
        severity=Severity.HIGH,
        confidence="High",
        description="A Slack Incoming Webhook URL was found. Can post messages to Slack.",
        remediation="Revoke the webhook in Slack channel settings.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Discord Bot Token",
        pattern=re.compile(r'\b([A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9\-_]{38})\b'),
        severity=Severity.HIGH,
        confidence="Medium",
        description="A Discord bot token was found.",
        remediation="Regenerate the token in Discord Developer Portal.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r'\b(SK[0-9a-fA-F]{32})\b'),
        severity=Severity.HIGH,
        confidence="High",
        description="A Twilio API Key was found.",
        remediation="Revoke the API key in Twilio Console.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=re.compile(r'\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b'),
        severity=Severity.HIGH,
        confidence="High",
        description="A SendGrid API Key was found.",
        remediation="Revoke the key in SendGrid API Keys settings.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Mailgun API Key",
        pattern=re.compile(r'\b(key-[0-9a-zA-Z]{32})\b'),
        severity=Severity.HIGH,
        confidence="Medium",
        description="A Mailgun API Key was found.",
        remediation="Rotate the key in Mailgun account settings.",
        cwe_id="CWE-798",
    ),

    # ── Cryptographic Keys ───────────────────────────────────────────────────
    SecretPattern(
        name="RSA Private Key",
        pattern=re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        severity=Severity.CRITICAL,
        confidence="High",
        description="An RSA private key was found. This allows impersonation or decryption of sensitive data.",
        remediation=(
            "Revoke the key immediately. Generate a new key pair. "
            "Audit all systems using this certificate."
        ),
        cwe_id="CWE-321",
    ),
    SecretPattern(
        name="Private Key (Generic)",
        pattern=re.compile(r'-----BEGIN (?:EC|OPENSSH|DSA|PGP) PRIVATE KEY-----'),
        severity=Severity.CRITICAL,
        confidence="High",
        description="A private key was found.",
        remediation="Revoke and rotate the key immediately.",
        cwe_id="CWE-321",
    ),
    SecretPattern(
        name="Certificate (PEM)",
        pattern=re.compile(r'-----BEGIN CERTIFICATE-----'),
        severity=Severity.LOW,
        confidence="High",
        description="A PEM certificate was found. Not immediately exploitable but indicates key material nearby.",
        remediation="Verify that no corresponding private key is also exposed.",
        cwe_id="CWE-200",
    ),

    # ── JWT / Session ─────────────────────────────────────────────────────────
    SecretPattern(
        name="Hardcoded JWT Secret",
        pattern=re.compile(
            r'(?:jwt.?secret|JWT_SECRET|jwtSecret|tokenSecret|TOKEN_SECRET|SECRET_KEY|secret_key)'
            r'[\'"\s:=]+[\'"]([^\'\"]{8,128})[\'"]',
            _p(),
        ),
        severity=Severity.HIGH,
        confidence="High",
        description="A hardcoded JWT signing secret was found. Allows forging valid JWT tokens.",
        remediation="Rotate the JWT secret immediately. Use a strong random 256-bit secret via env variable.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="JWT Token in Response",
        pattern=re.compile(r'\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'),
        severity=Severity.MEDIUM,
        confidence="Medium",
        description=(
            "A JWT token was found in the response body. "
            "If this is a long-lived token or contains sensitive claims, it could be abused."
        ),
        remediation=(
            "Ensure tokens have appropriate expiry. "
            "Do not return tokens in API responses unnecessarily. "
            "Use short-lived tokens and refresh token patterns."
        ),
        cwe_id="CWE-200",
    ),

    # ── Database ──────────────────────────────────────────────────────────────
    SecretPattern(
        name="Database Connection String",
        pattern=re.compile(
            r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|mssql|sqlserver)'
            r'://[^\s\'\"<>{}\[\]]{10,300}',
            _p(),
        ),
        severity=Severity.CRITICAL,
        confidence="High",
        description="A database connection string with credentials was found.",
        remediation=(
            "Remove from source/client code immediately. "
            "Rotate database credentials. Use server-side environment variables."
        ),
        cwe_id="CWE-798",
    ),

    # ── Generic High-Entropy Secrets ──────────────────────────────────────────
    SecretPattern(
        name="Generic API Key",
        pattern=re.compile(
            r'(?:api.?key|apikey|API_KEY|x-api-key|APIKEY)[\'"\s:=]+[\'"]([A-Za-z0-9\-_]{20,80})[\'"]',
            _p(),
        ),
        severity=Severity.HIGH,
        confidence="Medium",
        description="A generic API key was found.",
        remediation="Identify the service and rotate this key. Store in server-side environment variables.",
        cwe_id="CWE-798",
    ),
    SecretPattern(
        name="Generic Password / Secret",
        pattern=re.compile(
            r'(?:password|passwd|passcode|secret|SECRET)[\'"\s:=]+[\'"]([A-Za-z0-9!@#$%^&*()\-_+]{8,64})[\'"]',
            _p(),
        ),
        severity=Severity.MEDIUM,
        confidence="Low",
        description="A hardcoded password or secret was found.",
        remediation="Remove from code. Use environment variables or a secrets manager.",
        cwe_id="CWE-798",
    ),

    # ── Internal/Private URLs ─────────────────────────────────────────────────
    SecretPattern(
        name="Internal API Endpoint",
        pattern=re.compile(
            r'(?:api.?base|API_BASE|baseURL|BASE_URL|apiUrl|API_URL)[\'"\s:=]+[\'"]'
            r'(https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|localhost|127\.)[^\'\"]{4,200})[\'"]',
            _p(),
        ),
        severity=Severity.MEDIUM,
        confidence="Medium",
        description="An internal or private API endpoint URL was found in client-side code.",
        remediation="Remove internal URLs from client-side bundles. Use relative paths or API gateway.",
        cwe_id="CWE-200",
    ),

    # ── Debug / Error ─────────────────────────────────────────────────────────
    SecretPattern(
        name="Stack Trace / Internal Path Disclosure",
        pattern=re.compile(
            r'(?:at\s+\w+\.\w+\([\w/\\.]+:\d+:\d+\)|'
            r'File "(?:/[^"]+)"[,\s]|'
            r'in (?:/[\w/\-_.]+\.(?:py|rb|php|java|cs|go))\b)',
        ),
        severity=Severity.LOW,
        confidence="Medium",
        description="A stack trace or internal file path was found in the response.",
        remediation="Disable debug mode in production. Configure proper error handling to hide stack traces.",
        cwe_id="CWE-209",
        owasp_category="A05:2021 – Security Misconfiguration",
    ),
]

# ---------------------------------------------------------------------------
# Response header checks
# ---------------------------------------------------------------------------

_SENSITIVE_HEADERS: List[Tuple[str, str, Severity]] = [
    ("x-powered-by", "Server technology disclosure via X-Powered-By header", Severity.LOW),
    ("server", "Detailed server version disclosure", Severity.LOW),
    ("x-aspnet-version", "ASP.NET version disclosure", Severity.LOW),
    ("x-aspnetmvc-version", "ASP.NET MVC version disclosure", Severity.LOW),
    ("x-generator", "CMS/framework disclosure via X-Generator header", Severity.LOW),
    ("x-debug-token", "Debug token exposed in response headers", Severity.MEDIUM),
    ("x-debug-token-link", "Debug profiler link exposed in response headers", Severity.MEDIUM),
    ("x-php-origin", "PHP origin URL disclosed", Severity.MEDIUM),
]

# Placeholder values to skip (reduce false positives)
_PLACEHOLDER_VALUES = {
    "your_api_key", "your-api-key", "api_key_here",
    "changeme", "placeholder", "example", "test", "demo",
    "xxxxxxxx", "00000000", "insert_key_here", "replace_me",
    "your_secret", "mysecret", "password123", "secret123",
    "test123", "sample", "dummy", "fake",
}

# Fix 3.2: Paths covered by SensitiveFileScanner — skip in SecretsScanner
# to avoid duplicate findings on the same URL.
_SENSITIVE_FILE_PATH_RE = re.compile(
    r"/\.(env|git|svn|hg|aws|ssh)(/|$)|"
    r"/(wp-config|config|appsettings|application)\.(php|json|yml|yaml|properties)|"
    r"/backup\.(zip|tar\.gz|sql)|"
    r"/(db|dump|database)\.sql|"
    r"/credentials\.json|/service-?account\.json|"
    r"/server\.(key|pem)|/private\.key|/ssl\.key|"
    r"/(phpinfo|info|test)\.php|"
    r"/settings\.py|/local_settings\.py|"
    r"/docker-compose\.yml|/Dockerfile|"
    r"/laravel\.log|/storage/logs/",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# CVSS profile for secrets
# ---------------------------------------------------------------------------

_CVSS_SECRET_HIGH = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.HIGH,
)

_CVSS_SECRET_MEDIUM = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.LOW,
    availability=Impact.NONE,
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SecretsScanner(_ScannerBase):
    """
    Scans every crawled page response for exposed secrets, credentials,
    and sensitive information leakage.

    Runs on:
    - Response body (HTML, JSON, JS inline content)
    - HTTP response headers

    Complements JSAnalyzer (which runs on external .js files) by covering
    the full page response surface.
    """

    name = "Secrets & Credentials Exposure"
    is_target_level = False

    def __init__(self, client: HTTPClient) -> None:
        super().__init__(client)
        # Skip patterns that are very noisy on first few findings
        self._reported_patterns: set = set()

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        if not response or not response.is_text:
            return vulns

        # Fix 3.2: Skip URLs that SensitiveFileScanner already covers.
        # These paths are reported as file-exposure findings; scanning them
        # again here would produce duplicate SECRET_EXPOSURE findings.
        if _SENSITIVE_FILE_PATH_RE.search(url):
            return vulns

        content = response.text

        # 1. Scan response body for secret patterns
        vulns.extend(self._scan_body(url, content))

        # 2. Scan response headers for information disclosure
        vulns.extend(self._scan_headers(url, dict(response.headers)))

        # 3. Scan HTML comments for embedded secrets
        vulns.extend(self._scan_html_comments(url, content))

        return vulns

    # -----------------------------------------------------------------------
    # Body scanning
    # -----------------------------------------------------------------------

    def _scan_body(self, url: str, content: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        seen_in_page: set = set()

        for pattern_def in _SECRET_PATTERNS:
            for match in pattern_def.pattern.finditer(content):
                try:
                    value = match.group(1)
                except IndexError:
                    value = match.group(0)

                if not value or len(value) < 4:
                    continue

                value_lower = value.lower().strip("'\"")
                if value_lower in _PLACEHOLDER_VALUES:
                    continue
                if value_lower.startswith("your_") or value_lower.startswith("your-"):
                    continue
                if len(set(value_lower)) <= 2:  # all same chars
                    continue

                # Deduplicate: same pattern + same value on same URL
                dedup_key = f"{pattern_def.name}:{value[:20]}:{url}"
                if dedup_key in seen_in_page:
                    continue
                seen_in_page.add(dedup_key)

                # Extract context
                start = max(0, match.start() - 80)
                end = min(len(content), match.end() + 80)
                context = content[start:end].replace("\n", " ")

                # Redact the value for the report
                redacted = self._redact(value)

                cvss = _CVSS_SECRET_HIGH if pattern_def.severity in (Severity.CRITICAL, Severity.HIGH) else _CVSS_SECRET_MEDIUM

                vuln = self._build_vuln(
                    vuln_type=VulnType.SECRET_EXPOSURE,
                    title=f"Exposed {pattern_def.name}",
                    description=(
                        f"{pattern_def.description}\n\n"
                        f"Found in: {url}\n"
                        f"Value (redacted): {redacted}\n"
                        f"Confidence: {pattern_def.confidence}"
                    ),
                    url=url,
                    severity=pattern_def.severity,
                    method="GET",
                    evidence=f"Matched: {context[:200]}",
                    remediation=pattern_def.remediation,
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
                        "https://cwe.mitre.org/data/definitions/798.html",
                    ],
                    cwe_id=pattern_def.cwe_id,
                    owasp_category=pattern_def.owasp_category,
                    cvss=cvss,
                    confidence=pattern_def.confidence,
                    false_positive_risk="Low" if pattern_def.confidence == "High" else "Medium",
                )
                vulns.append(vuln)

        return vulns

    # -----------------------------------------------------------------------
    # Header scanning
    # -----------------------------------------------------------------------

    def _scan_headers(
        self, url: str, headers: Dict[str, str]
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, description, severity in _SENSITIVE_HEADERS:
            value = headers_lower.get(header_name)
            if not value:
                continue

            # Skip generic/non-informative values
            if value.lower() in ("", "-", "unknown"):
                continue

            vuln = self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title=f"Information Disclosure via {header_name.title()} Header",
                description=(
                    f"{description}.\n\n"
                    f"Header: {header_name}: {value}\n\n"
                    f"Exposing technology stack details helps attackers "
                    f"identify known vulnerabilities for the specific version."
                ),
                url=url,
                severity=severity,
                method="GET",
                evidence=f"Response header: {header_name}: {value}",
                remediation=(
                    f"Remove or suppress the '{header_name}' header. "
                    "Configure your web server/framework to hide version information."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                ],
                cwe_id="CWE-200",
                owasp_category="A05:2021 – Security Misconfiguration",
                confidence="High",
            )
            vulns.append(vuln)

        return vulns

    # -----------------------------------------------------------------------
    # HTML comment scanning
    # -----------------------------------------------------------------------

    def _scan_html_comments(self, url: str, content: str) -> List[Vulnerability]:
        """Scan HTML comments for embedded credentials or debug info."""
        vulns: List[Vulnerability] = []

        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        for match in comment_pattern.finditer(content):
            comment_body = match.group(1).strip()
            if len(comment_body) < 10:
                continue

            # Check for suspicious patterns in comments
            suspicious_patterns = [
                (re.compile(r'(?:password|passwd|secret|api.?key|token|credential)', re.IGNORECASE),
                 "Potential credentials in HTML comment"),
                (re.compile(r'TODO|FIXME|HACK|XXX|TEMP', re.IGNORECASE),
                 "Developer TODO/FIXME comment"),
                (re.compile(r'(?:staging|debug|test|dev).{0,20}(?:password|key|secret)', re.IGNORECASE),
                 "Debug/staging credential in HTML comment"),
            ]

            for sus_pattern, title in suspicious_patterns:
                if sus_pattern.search(comment_body):
                    vuln = self._build_vuln(
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        title=f"Sensitive Data in HTML Comment: {title}",
                        description=(
                            f"An HTML comment may contain sensitive information.\n\n"
                            f"Comment preview: {comment_body[:150]}..."
                        ),
                        url=url,
                        severity=Severity.LOW,
                        method="GET",
                        evidence=f"HTML comment: {comment_body[:200]}",
                        remediation=(
                            "Remove all HTML comments from production code that may contain "
                            "credentials, debug information, or development notes."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                        ],
                        cwe_id="CWE-615",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        confidence="Low",
                        false_positive_risk="High",
                    )
                    vulns.append(vuln)
                    break  # one finding per comment

        return vulns

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _redact(value: str) -> str:
        """Return a safely redacted version for display in reports."""
        if len(value) <= 6:
            return "***"
        keep = min(4, len(value) // 4)
        return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]
