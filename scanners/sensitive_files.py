"""
Sensitive File Exposure Scanner — Professional Grade
=====================================================
Coverage:
  • Source control leakage: /.git/config, /.git/HEAD, /.svn/entries, /.hg/hgrc
  • Environment files: /.env, /.env.local, /.env.production, /.env.staging
  • Configuration files: /config.json, /config.yml, /appsettings.json,
    /application.properties, /application.yml, /web.config, /wp-config.php
  • Backup files: /backup.zip, /backup.tar.gz, /db.sql, /dump.sql, /site.zip
  • Log files: /logs/access.log, /error.log, /app.log, /debug.log
  • CI/CD exposure: /.travis.yml, /.github/workflows/, /Jenkinsfile, /Dockerfile
  • Cloud credentials: /.aws/credentials, /credentials.json, /service-account.json
  • Debug/info endpoints: /phpinfo.php, /info.php, /test.php, /status, /server-info
  • Editor/IDE files: /.idea/workspace.xml, /.vscode/settings.json
  • Package manager files: /package.json, /composer.json, /requirements.txt,
    /Gemfile, /poetry.lock (dependency info leakage)
  • API documentation: /swagger.json, /openapi.json, /api-docs, /postman_collection.json
  • SSL/TLS key files: /server.key, /private.key, /.well-known/acme-challenge/
  • Content validation: detects actual sensitive content in returned files
  • Severity based on content type (keys > credentials > config > info)

CWE  : CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)
       CWE-200 (Exposure of Sensitive Information)
OWASP: A05:2021 – Security Misconfiguration
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner
try:
    from ..recon.intelligence_bridge import IntelligenceAwareScanner as _ScannerBase
except Exception:
    _ScannerBase = BaseScanner
from ..core.http_client import HTTPResponse
from ..models.vulnerability import (
    Vulnerability, VulnType, Severity, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)

_CVSS_CRITICAL = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.HIGH, Impact.HIGH, Impact.NONE)
_CVSS_HIGH = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.HIGH, Impact.NONE, Impact.NONE)
_CVSS_MEDIUM = CVSSv3(AttackVector.NETWORK, AttackComplexity.LOW,
    PrivilegesRequired.NONE, UserInteraction.NONE,
    Scope.UNCHANGED, Impact.LOW, Impact.NONE, Impact.NONE)

_CWE = "CWE-538"
_OWASP = "A05:2021 - Security Misconfiguration"
_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    "https://cwe.mitre.org/data/definitions/538.html",
    "https://cwe.mitre.org/data/definitions/200.html",
]

# ---------------------------------------------------------------------------
# Sensitive files: (path, description, severity, content_validator_key)
# ---------------------------------------------------------------------------
# content_validator_key matches keys in _CONTENT_VALIDATORS below
# severity: C=Critical, H=High, M=Medium, L=Low

_SENSITIVE_FILES: List[Tuple[str, str, str, str]] = [
    # Source control
    ("/.git/config",         "Git config (may contain remote URLs/tokens)",      "H", "git_config"),
    ("/.git/HEAD",           "Git HEAD reference",                                "M", "git_head"),
    ("/.git/COMMIT_EDITMSG", "Git last commit message",                           "M", "any_content"),
    ("/.git/logs/HEAD",      "Git commit log",                                    "M", "any_content"),
    ("/.svn/entries",        "SVN entries (source code structure)",               "H", "svn_entries"),
    ("/.svn/wc.db",          "SVN working copy database",                         "H", "binary_check"),
    ("/.hg/hgrc",            "Mercurial config",                                  "M", "any_content"),
    ("/.DS_Store",           "macOS directory metadata",                           "L", "binary_check"),

    # Environment / secrets
    ("/.env",                ".env file (API keys, DB passwords)",                "C", "env_file"),
    ("/.env.local",          ".env.local file",                                   "C", "env_file"),
    ("/.env.development",    ".env.development file",                             "H", "env_file"),
    ("/.env.production",     ".env.production file",                              "C", "env_file"),
    ("/.env.staging",        ".env.staging file",                                 "H", "env_file"),
    ("/.env.backup",         ".env backup file",                                  "C", "env_file"),

    # Configuration
    ("/config.json",         "config.json (may contain secrets)",                 "H", "config_json"),
    ("/config.yml",          "config.yml",                                        "H", "config_yaml"),
    ("/config.yaml",         "config.yaml",                                       "H", "config_yaml"),
    ("/appsettings.json",    "ASP.NET appsettings.json",                          "H", "config_json"),
    ("/appsettings.Development.json", "ASP.NET dev settings",                     "H", "config_json"),
    ("/application.properties", "Spring Boot properties",                         "H", "spring_props"),
    ("/application.yml",     "Spring Boot YAML config",                           "H", "config_yaml"),
    ("/web.config",          "IIS web.config",                                    "H", "web_config"),
    ("/wp-config.php",       "WordPress database config",                          "C", "wp_config"),
    ("/wp-config.php.bak",   "WordPress config backup",                           "C", "wp_config"),
    ("/configuration.php",   "Joomla config",                                     "H", "any_content"),
    ("/config.php",          "PHP config file",                                   "H", "php_source"),
    ("/database.yml",        "Rails database config",                             "H", "config_yaml"),
    ("/settings.py",         "Django settings",                                   "H", "django_settings"),
    ("/local_settings.py",   "Django local settings",                             "H", "django_settings"),

    # Backup / dumps
    ("/backup.zip",          "Site backup archive",                               "H", "binary_check"),
    ("/backup.tar.gz",       "Site backup tarball",                               "H", "binary_check"),
    ("/backup.sql",          "SQL database backup",                               "C", "sql_dump"),
    ("/db.sql",              "SQL database dump",                                  "C", "sql_dump"),
    ("/dump.sql",            "SQL dump",                                           "C", "sql_dump"),
    ("/database.sql",        "Database SQL export",                               "C", "sql_dump"),
    ("/site.zip",            "Site archive",                                      "H", "binary_check"),
    ("/www.zip",             "Web root archive",                                  "H", "binary_check"),

    # Logs
    ("/logs/access.log",     "Apache/nginx access log",                           "M", "access_log"),
    ("/log/access.log",      "Access log",                                        "M", "access_log"),
    ("/access.log",          "Access log in root",                                "M", "access_log"),
    ("/error.log",           "Error log",                                         "M", "error_log"),
    ("/debug.log",           "Debug log (may contain stack traces)",              "M", "error_log"),
    ("/app.log",             "Application log",                                   "M", "error_log"),
    ("/laravel.log",         "Laravel log",                                       "M", "error_log"),
    ("/storage/logs/laravel.log", "Laravel storage log",                          "M", "error_log"),

    # CI/CD
    ("/.travis.yml",         "Travis CI config",                                  "M", "any_content"),
    ("/Jenkinsfile",         "Jenkins pipeline",                                  "M", "any_content"),
    ("/Dockerfile",          "Docker config",                                     "M", "any_content"),
    ("/docker-compose.yml",  "Docker Compose (may contain secrets)",             "H", "docker_compose"),
    ("/.github/workflows/deploy.yml", "GitHub Actions deploy workflow",          "M", "any_content"),
    ("/.circleci/config.yml","CircleCI config",                                   "M", "any_content"),

    # Cloud credentials
    ("/.aws/credentials",   "AWS credentials file",                              "C", "aws_creds"),
    ("/credentials.json",   "Google service account JSON",                       "C", "gcp_creds"),
    ("/service-account.json","GCP service account",                              "C", "gcp_creds"),
    ("/serviceaccount.json", "Service account JSON",                             "C", "gcp_creds"),

    # SSL/TLS keys
    ("/server.key",          "TLS private key",                                   "C", "private_key"),
    ("/private.key",         "Private key",                                       "C", "private_key"),
    ("/server.pem",          "PEM certificate/key",                               "H", "private_key"),
    ("/ssl.key",             "SSL private key",                                   "C", "private_key"),

    # IDE / editor
    ("/.idea/workspace.xml", "JetBrains IDE workspace",                           "L", "any_content"),
    ("/.vscode/settings.json","VSCode settings",                                  "L", "any_content"),

    # Package manager (dependency info)
    ("/package.json",        "Node.js package.json (dependency list)",            "L", "any_content"),
    ("/package-lock.json",   "package-lock.json",                                "L", "any_content"),
    ("/composer.json",       "PHP Composer dependencies",                         "L", "any_content"),
    ("/requirements.txt",    "Python requirements",                               "L", "any_content"),
    ("/Gemfile",             "Ruby Gemfile",                                      "L", "any_content"),

    # API docs
    ("/swagger.json",        "Swagger API definition",                            "M", "swagger"),
    ("/openapi.json",        "OpenAPI specification",                             "M", "swagger"),
    ("/openapi.yaml",        "OpenAPI YAML spec",                                 "M", "swagger"),
    ("/api-docs",            "API documentation",                                 "M", "any_content"),
    ("/postman_collection.json", "Postman collection (auth tokens/examples)",     "H", "config_json"),
    ("/swagger-ui.html",     "Swagger UI in production",                          "M", "any_content"),

    # PHP info / debug
    ("/phpinfo.php",         "PHP info page",                                     "H", "phpinfo"),
    ("/info.php",            "PHP info page",                                     "H", "phpinfo"),
    ("/test.php",            "PHP test page",                                     "M", "php_source"),
    ("/server-status",       "Apache server-status",                              "H", "server_status"),
    ("/server-info",         "Apache server-info",                                "H", "any_content"),

    # Security.txt
    ("/.well-known/security.txt", "Security.txt (contact info)",                 "L", "any_content"),
]

# ---------------------------------------------------------------------------
# Content validators
# ---------------------------------------------------------------------------

_CONTENT_VALIDATORS: Dict[str, Tuple[re.Pattern, str]] = {
    "git_config":    (re.compile(r"\[core\]|\[remote|url\s*=\s*https?://"), "Git config content"),
    "git_head":      (re.compile(r"ref: refs/heads/|[0-9a-f]{40}"), "Git HEAD reference"),
    "svn_entries":   (re.compile(r"<entry|wc-entries|svn:"), "SVN entries"),
    "env_file":      (re.compile(r"[A-Z_]+=.{1,200}", re.M), "Environment variable assignments"),
    "config_json":   (re.compile(r'"(?:password|secret|key|token|db|database)"\s*:', re.I), "Secret fields in JSON"),
    "config_yaml":   (re.compile(r"(?:password|secret|key|token|db|database)\s*:", re.I), "Secret fields in YAML"),
    "spring_props":  (re.compile(r"(?:password|secret|datasource\.url|spring\.)", re.I), "Spring Boot properties"),
    "web_config":    (re.compile(r"<connectionStrings|<appSettings|password=", re.I), "IIS web.config secrets"),
    "wp_config":     (re.compile(r"DB_PASSWORD|DB_NAME|DB_USER|AUTH_KEY|SECURE_AUTH_KEY", re.I), "WordPress config"),
    "php_source":    (re.compile(r"<\?php"), "PHP source code"),
    "django_settings": (re.compile(r"SECRET_KEY|DATABASES|PASSWORD", re.I), "Django settings"),
    "sql_dump":      (re.compile(r"INSERT INTO|CREATE TABLE|DROP TABLE", re.I), "SQL statements"),
    "access_log":    (re.compile(r'"(?:GET|POST|PUT) /\S+ HTTP/\d\.\d" \d{3}'), "HTTP access log"),
    "error_log":     (re.compile(r"(?:ERROR|Warning|Fatal|Traceback|Exception)", re.I), "Error log entries"),
    "docker_compose": (re.compile(r"(?:password|secret|MYSQL_ROOT_PASSWORD|environment)", re.I), "Docker Compose secrets"),
    "aws_creds":     (re.compile(r"aws_access_key_id|aws_secret_access_key", re.I), "AWS credentials"),
    "gcp_creds":     (re.compile(r'"private_key"|"client_email"|"type": "service_account"', re.I), "GCP service account"),
    "private_key":   (re.compile(r"-----BEGIN.*PRIVATE KEY-----"), "Private key"),
    "phpinfo":       (re.compile(r"PHP Version|phpinfo\(\)|PHP License", re.I), "PHP info page"),
    "server_status": (re.compile(r"Server Version|Apache Server Status", re.I), "Apache server-status"),
    "swagger":       (re.compile(r'"swagger"|"openapi"', re.I), "API specification"),
    "binary_check":  (re.compile(r"."), "File exists"),  # any content = flagged
    "any_content":   (re.compile(r".{10,}"), "Non-empty response"),
}

_SEV_MAP = {"C": Severity.CRITICAL, "H": Severity.HIGH, "M": Severity.MEDIUM, "L": Severity.LOW}
_CVSS_MAP = {"C": _CVSS_CRITICAL, "H": _CVSS_HIGH, "M": _CVSS_MEDIUM, "L": _CVSS_MEDIUM}


class SensitiveFileScanner(_ScannerBase):
    """
    Sensitive file exposure scanner.
    Probes 70+ well-known sensitive paths and validates content.
    is_target_level=True — runs once per target.
    """
    name = "Sensitive Files"
    is_target_level = True

    async def scan_url(
        self,
        url: str,
        response: HTTPResponse,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for path, description, sev_key, validator_key in _SENSITIVE_FILES:
            target_url = urljoin(base, path)
            resp = await self.client.get(target_url)

            if not resp or resp.status_code not in (200, 206):
                continue

            # Must have actual content
            if len(resp.text.strip()) < 10 and resp.status_code != 206:
                continue

            # Validate content matches expected pattern
            validator_pattern, validator_desc = _CONTENT_VALIDATORS.get(
                validator_key, (re.compile(r".{10,}"), "Non-empty content")
            )
            if not validator_pattern.search(resp.text[:5000]):
                continue

            sev  = _SEV_MAP.get(sev_key, Severity.MEDIUM)
            cvss = _CVSS_MAP.get(sev_key, _CVSS_MEDIUM)

            vulns.append(self._build_vuln(
                vuln_type=VulnType.SENSITIVE_DATA,
                title=f"Sensitive File Exposed: {path}",
                description=(
                    f"The file '{path}' is publicly accessible and contains: {description}. "
                    f"Content indicator: {validator_desc}. "
                    f"This file should not be accessible via the web server."
                ),
                url=target_url,
                evidence=(
                    f"HTTP 200 | Content length: {len(resp.text)} bytes | "
                    f"Content indicator: {validator_desc} | "
                    f"Preview: '{resp.text[:120].strip()[:80]}'"
                ),
                severity=sev, cvss=cvss,
                remediation=(
                    f"1. Block access to '{path}' in web server config (nginx deny, Apache Deny from all).\n"
                    "2. Move sensitive files outside the web root.\n"
                    "3. Use .htaccess / nginx location blocks to deny direct access.\n"
                    "4. Audit and remove backup/temp files from production deployments."
                ),
                references=_REFS,
                cwe_id=_CWE, owasp_category=_OWASP,
                response_snippet=self._snippet(resp.text),
                confidence="High",
            ))

        return vulns
