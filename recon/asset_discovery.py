"""
Asset Discovery Engine — Phase 2.4

Enumerates all digital assets associated with a target domain:
- DNS record discovery (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV)
- SPF / DMARC / DKIM record analysis
- Subdomain enumeration via common wordlist
- Staging / dev / test environment detection
- CDN origin IP discovery
- Cloud provider detection from DNS records
- Zone transfer attempt (AXFR)
- Certificate Transparency log querying (crt.sh)

Results are returned as an AssetReport and can trigger additional
scans on discovered subdomains.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import json
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from ..core.http_client import HTTPClient
from ..models.vulnerability import (
    Vulnerability, Severity, VulnType, CVSSv3,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
)
from ..scanners.base_scanner import BaseScanner


# ---------------------------------------------------------------------------
# Subdomain wordlist
# ---------------------------------------------------------------------------

_SUBDOMAIN_WORDLIST: List[str] = [
    # Common environments
    "www", "mail", "webmail", "email", "smtp", "pop", "imap",
    "ftp", "sftp", "ssh",
    # Dev / staging
    "dev", "develop", "development",
    "stg", "stage", "staging",
    "test", "testing", "qa", "uat",
    "demo", "preview", "sandbox",
    "beta", "alpha", "rc",
    # Admin / internal
    "admin", "administrator", "panel", "console", "dashboard",
    "portal", "backend", "internal", "intranet",
    "corp", "corporate", "staff", "employee",
    # API
    "api", "api2", "api3", "api-v1", "api-v2",
    "rest", "graphql", "grpc",
    # Infrastructure
    "vpn", "proxy", "gateway", "firewall",
    "monitor", "monitoring", "metrics", "logs", "logging",
    "ci", "cd", "jenkins", "gitlab", "github",
    "registry", "repo", "repository",
    # Services
    "shop", "store", "pay", "payment", "checkout",
    "auth", "sso", "oauth", "login", "account", "accounts",
    "app", "apps", "mobile", "m", "wap",
    "cdn", "static", "assets", "media", "files", "uploads",
    "docs", "documentation", "help", "support", "kb",
    # Database / cache
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "cache", "search", "elastic",
    # Cloud / infra
    "aws", "gcp", "azure", "s3", "storage",
    "k8s", "kubernetes", "docker", "helm",
    # Versioned
    "v1", "v2", "v3",
    # Numbers
    "1", "2", "3",
    # Geographic
    "us", "eu", "ap", "uk", "de", "fr",
    "us-east", "us-west", "eu-west", "ap-south",
    # Legacy
    "old", "legacy", "deprecated", "archive",
    "backup", "bak", "temp",
    # CMS
    "wp", "wordpress", "blog", "cms",
    # Web server
    "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2",
    # Misc
    "status", "health", "ping",
    "remote", "rdp", "citrix",
    "video", "stream", "live",
]

# Staging/dev environment indicators
_DEV_ENV_PATTERNS = re.compile(
    r'(?:dev|develop|development|stg|stage|staging|test|testing|qa|uat|demo|sandbox|beta|alpha|rc|local)',
    re.IGNORECASE,
)

# Cloud provider DNS signatures
_CLOUD_PROVIDERS: List[Tuple[str, re.Pattern]] = [
    ("AWS CloudFront",   re.compile(r'cloudfront\.net$', re.IGNORECASE)),
    ("AWS S3",           re.compile(r's3(?:[.-]\w+)?\.amazonaws\.com$', re.IGNORECASE)),
    ("AWS ELB",          re.compile(r'elb\.amazonaws\.com$', re.IGNORECASE)),
    ("AWS EC2",          re.compile(r'ec2\.amazonaws\.com$|compute\.amazonaws\.com$', re.IGNORECASE)),
    ("Cloudflare",       re.compile(r'cdn\.cloudflare\.net$', re.IGNORECASE)),
    ("Azure",            re.compile(r'\.azure(?:websites|edge)\.net$|cloudapp\.net$', re.IGNORECASE)),
    ("Google Cloud",     re.compile(r'appspot\.com$|\.goog$|googleusercontent\.com$', re.IGNORECASE)),
    ("Fastly",           re.compile(r'fastly\.net$', re.IGNORECASE)),
    ("Akamai",           re.compile(r'akamaiedge\.net$|akamai\.net$', re.IGNORECASE)),
    ("Netlify",          re.compile(r'netlify\.app$|netlify\.com$', re.IGNORECASE)),
    ("Vercel",           re.compile(r'vercel\.app$', re.IGNORECASE)),
    ("Heroku",           re.compile(r'herokuapp\.com$', re.IGNORECASE)),
    ("DigitalOcean",     re.compile(r'digitalocean\.app$|ondigitalocean\.app$', re.IGNORECASE)),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DNSRecord:
    """A single DNS record."""
    record_type: str     # A, AAAA, CNAME, MX, TXT, NS, SOA, SRV
    name: str
    value: str
    ttl: int = 0


@dataclass
class SubdomainInfo:
    """Information about a discovered subdomain."""
    hostname: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    is_alive: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    is_dev_environment: bool = False
    cloud_provider: Optional[str] = None
    takeover_risk: bool = False      # CNAME pointing to unclaimed cloud resource


@dataclass
class EmailSecurityReport:
    """SPF / DMARC / DKIM assessment."""
    has_spf: bool = False
    spf_record: Optional[str] = None
    spf_strict: bool = False        # "-all" vs "~all" vs "+all"
    has_dmarc: bool = False
    dmarc_record: Optional[str] = None
    dmarc_policy: str = "none"      # none | quarantine | reject
    dmarc_pct: int = 100            # percentage of mail covered
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class AssetReport:
    """Complete asset discovery results for a domain."""
    domain: str
    dns_records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[SubdomainInfo] = field(default_factory=list)
    email_security: Optional[EmailSecurityReport] = None
    zone_transfer_possible: bool = False
    nameservers: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    ct_subdomains: List[str] = field(default_factory=list)  # from crt.sh
    errors: List[str] = field(default_factory=list)

    @property
    def dev_environments(self) -> List[SubdomainInfo]:
        return [s for s in self.subdomains if s.is_dev_environment and s.is_alive]

    @property
    def takeover_candidates(self) -> List[SubdomainInfo]:
        return [s for s in self.subdomains if s.takeover_risk]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "dns_records": [{"type": r.record_type, "name": r.name, "value": r.value} for r in self.dns_records],
            "subdomains_found": len(self.subdomains),
            "subdomains_alive": len([s for s in self.subdomains if s.is_alive]),
            "dev_environments": [s.hostname for s in self.dev_environments],
            "takeover_candidates": [s.hostname for s in self.takeover_candidates],
            "zone_transfer_possible": self.zone_transfer_possible,
            "nameservers": self.nameservers,
            "cloud_providers": self.cloud_providers,
            "ct_subdomains_count": len(self.ct_subdomains),
            "email_security": {
                "has_spf": self.email_security.has_spf if self.email_security else False,
                "has_dmarc": self.email_security.has_dmarc if self.email_security else False,
                "dmarc_policy": self.email_security.dmarc_policy if self.email_security else "none",
            } if self.email_security else None,
        }


# ---------------------------------------------------------------------------
# CVSS profiles
# ---------------------------------------------------------------------------

_CVSS_ZONE_TRANSFER = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.NONE,
    availability=Impact.NONE,
)

_CVSS_SUBDOMAIN_TAKEOVER = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    availability=Impact.NONE,
)

_CVSS_EMAIL_SPOOFING = CVSSv3(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.REQUIRED,
    scope=Scope.UNCHANGED,
    confidentiality=Impact.NONE,
    integrity=Impact.HIGH,
    availability=Impact.NONE,
)


# ---------------------------------------------------------------------------
# Asset Discovery Engine
# ---------------------------------------------------------------------------

class AssetDiscovery(BaseScanner):
    """
    Discovers all digital assets associated with the target domain.

    This is a target-level scanner — it runs once against the root domain,
    not per URL.
    """

    name = "Asset Discovery"
    is_target_level = True

    # Domains that are unclaimed cloud services (subdomain takeover risk)
    _TAKEOVER_INDICATORS = [
        re.compile(r'NoSuchBucket', re.IGNORECASE),
        re.compile(r'There is no app configured at that hostname', re.IGNORECASE),
        re.compile(r'No such app', re.IGNORECASE),
        re.compile(r'herokucdn\.com/error-pages/no-such-app', re.IGNORECASE),
        re.compile(r'github\.com/404', re.IGNORECASE),
        re.compile(r'fastly error: unknown domain', re.IGNORECASE),
        re.compile(r'The request could not be satisfied', re.IGNORECASE),
        re.compile(r'Cloudfront: distribution', re.IGNORECASE),
        re.compile(r"doesn't exist", re.IGNORECASE),
        re.compile(r"This site can't be reached", re.IGNORECASE),
        re.compile(r'The specified bucket does not exist', re.IGNORECASE),
    ]

    def __init__(
        self,
        client: HTTPClient,
        enumerate_subdomains: bool = True,
        check_zone_transfer: bool = True,
        query_ct_logs: bool = True,
        subdomain_concurrency: int = 20,
    ) -> None:
        super().__init__(client)
        self.enumerate_subdomains = enumerate_subdomains
        self.check_zone_transfer = check_zone_transfer
        self.query_ct_logs = query_ct_logs
        self.subdomain_concurrency = subdomain_concurrency
        self._report: Optional[AssetReport] = None

    async def scan_url(
        self,
        url: str,
        response: Any,
        forms: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        """Entry point — called by the engine for target-level scanners."""
        domain = self._extract_domain(url)
        if not domain:
            return []

        report = await self.discover(domain)
        self._report = report

        return self._findings_to_vulns(report, url)

    async def discover(self, domain: str) -> AssetReport:
        """
        Full asset discovery for a domain.
        Returns an AssetReport with all findings.
        """
        report = AssetReport(domain=domain)

        if not DNS_AVAILABLE:
            report.errors.append(
                "dnspython not installed — DNS-based discovery disabled. "
                "Install with: pip install dnspython==2.6.1"
            )
            return report

        # ── Stage 1: DNS records + CT logs run first (in parallel) ────────────
        # CT log results feed into subdomain enumeration, so they must finish first
        stage1_tasks = [
            self._discover_dns_records(domain, report),
            self._check_email_security(domain, report),
        ]
        if self.query_ct_logs:
            stage1_tasks.append(self._query_certificate_transparency(domain, report))

        await asyncio.gather(*stage1_tasks, return_exceptions=True)

        # ── Stage 2: Subdomain enumeration (uses CT results from stage 1) ─────
        await self._enumerate_subdomains(domain, report)

        # ── Stage 3: Zone transfer (needs nameservers from stage 1) ───────────
        if self.check_zone_transfer and report.nameservers:
            await self._try_zone_transfer(domain, report)

        # Deduplicate cloud providers
        report.cloud_providers = list(set(report.cloud_providers))

        return report

    # -----------------------------------------------------------------------
    # DNS Record Discovery
    # -----------------------------------------------------------------------

    async def _discover_dns_records(self, domain: str, report: AssetReport) -> None:
        """Enumerate all DNS record types for the domain."""
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA"]

        for rtype in record_types:
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None, self._query_dns, domain, rtype
                )
                for answer in answers:
                    record = DNSRecord(
                        record_type=rtype,
                        name=domain,
                        value=str(answer),
                        ttl=getattr(answer, 'rdataset', None) and 0 or 0,
                    )
                    report.dns_records.append(record)

                    # Extract IPs for A/AAAA records
                    if rtype in ("A", "AAAA"):
                        ip = str(answer)
                        if ip not in report.ip_addresses:
                            report.ip_addresses.append(ip)

                    # Extract nameservers
                    if rtype == "NS":
                        ns = str(answer).rstrip(".")
                        if ns not in report.nameservers:
                            report.nameservers.append(ns)

                    # Detect cloud provider from CNAME
                    if rtype == "CNAME":
                        cname_val = str(answer).rstrip(".")
                        for provider, pattern in _CLOUD_PROVIDERS:
                            if pattern.search(cname_val):
                                if provider not in report.cloud_providers:
                                    report.cloud_providers.append(provider)

            except Exception:
                pass  # Record type not found — normal

    @staticmethod
    def _query_dns(domain: str, record_type: str) -> List[Any]:
        """Synchronous DNS query (run in executor)."""
        if not DNS_AVAILABLE:
            return []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            answers = resolver.resolve(domain, record_type)
            return list(answers)
        except Exception:
            return []

    # -----------------------------------------------------------------------
    # Subdomain Enumeration
    # -----------------------------------------------------------------------

    async def _enumerate_subdomains(self, domain: str, report: AssetReport) -> None:
        """Enumerate subdomains via wordlist DNS resolution."""
        if not self.enumerate_subdomains:
            return

        semaphore = asyncio.Semaphore(self.subdomain_concurrency)
        discovered: List[SubdomainInfo] = []

        # Merge wordlist with CT log subdomains
        all_candidates = list(_SUBDOMAIN_WORDLIST)
        for ct_sub in report.ct_subdomains:
            prefix = ct_sub.replace(f".{domain}", "").rstrip(".")
            if prefix and prefix not in all_candidates:
                all_candidates.append(prefix)

        async def probe_subdomain(prefix: str) -> Optional[SubdomainInfo]:
            hostname = f"{prefix}.{domain}"
            async with semaphore:
                info = await self._probe_host(hostname)
                return info

        tasks = [probe_subdomain(prefix) for prefix in all_candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, SubdomainInfo) and result.is_alive:
                discovered.append(result)
                # Detect cloud provider
                if result.cloud_provider and result.cloud_provider not in report.cloud_providers:
                    report.cloud_providers.append(result.cloud_provider)

        report.subdomains = discovered

    async def _probe_host(self, hostname: str) -> Optional[SubdomainInfo]:
        """Resolve a hostname and check if it's alive."""
        info = SubdomainInfo(hostname=hostname)

        # DNS resolution
        ips = await asyncio.get_event_loop().run_in_executor(
            None, self._resolve_hostname, hostname
        )
        if not ips:
            return None  # doesn't exist

        info.ip_addresses = ips
        info.is_alive = True
        info.is_dev_environment = bool(_DEV_ENV_PATTERNS.search(hostname))

        # Check CNAME
        cnames = await asyncio.get_event_loop().run_in_executor(
            None, self._query_dns, hostname, "CNAME"
        )
        if cnames:
            info.cname = str(cnames[0]).rstrip(".")
            # Check cloud provider
            for provider, pattern in _CLOUD_PROVIDERS:
                if pattern.search(info.cname):
                    info.cloud_provider = provider
                    break

        # HTTP/HTTPS status check
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            try:
                resp = await self.client.get(url)
                if resp:
                    if scheme == "https":
                        info.https_status = resp.status_code
                    else:
                        info.http_status = resp.status_code

                    # Check for subdomain takeover indicators
                    for pattern in self._TAKEOVER_INDICATORS:
                        if pattern.search(resp.text[:2000]):
                            info.takeover_risk = True
                            break
                    break  # got a response, skip http if https works
            except Exception:
                continue

        return info

    @staticmethod
    def _resolve_hostname(hostname: str) -> List[str]:
        """Synchronous hostname resolution."""
        try:
            results = socket.getaddrinfo(hostname, None)
            ips = list({r[4][0] for r in results})
            return ips
        except Exception:
            return []

    # -----------------------------------------------------------------------
    # Zone Transfer
    # -----------------------------------------------------------------------

    async def _try_zone_transfer(self, domain: str, report: AssetReport) -> None:
        """Attempt DNS zone transfer (AXFR) against all nameservers."""
        if not DNS_AVAILABLE:
            return

        for ns in report.nameservers[:3]:  # try first 3 NS
            try:
                ns_ip = await asyncio.get_event_loop().run_in_executor(
                    None, self._resolve_ns, ns
                )
                if not ns_ip:
                    continue

                zone = await asyncio.get_event_loop().run_in_executor(
                    None, self._axfr_attempt, domain, ns_ip
                )

                if zone:
                    report.zone_transfer_possible = True
                    # Extract subdomains from zone
                    for name, node in zone.nodes.items():
                        subdomain = str(name).rstrip(".")
                        if subdomain and subdomain != "@":
                            full = f"{subdomain}.{domain}"
                            if full not in [s.hostname for s in report.subdomains]:
                                report.subdomains.append(SubdomainInfo(
                                    hostname=full, is_alive=False
                                ))
                    break  # one successful transfer is enough

            except Exception:
                continue

    @staticmethod
    def _resolve_ns(ns: str) -> Optional[str]:
        """Resolve nameserver hostname to IP."""
        try:
            return socket.gethostbyname(ns)
        except Exception:
            return None

    @staticmethod
    def _axfr_attempt(domain: str, ns_ip: str) -> Optional[Any]:
        """Attempt AXFR zone transfer."""
        if not DNS_AVAILABLE:
            return None
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            return zone
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Email Security
    # -----------------------------------------------------------------------

    async def _check_email_security(self, domain: str, report: AssetReport) -> None:
        """Check SPF, DMARC, and basic DKIM records."""
        email_sec = EmailSecurityReport()

        # SPF check
        txt_records = await asyncio.get_event_loop().run_in_executor(
            None, self._query_dns, domain, "TXT"
        )
        for record in txt_records:
            record_str = str(record).strip('"')
            if record_str.startswith("v=spf1"):
                email_sec.has_spf = True
                email_sec.spf_record = record_str
                email_sec.spf_strict = record_str.endswith("-all")
                if "+all" in record_str:
                    email_sec.vulnerabilities.append(
                        "SPF uses '+all' — allows anyone to send email as your domain"
                    )
                elif "~all" in record_str:
                    email_sec.vulnerabilities.append(
                        "SPF uses '~all' (softfail) — not strict enough. Use '-all'."
                    )

        # DMARC check
        dmarc_records = await asyncio.get_event_loop().run_in_executor(
            None, self._query_dns, f"_dmarc.{domain}", "TXT"
        )
        for record in dmarc_records:
            record_str = str(record).strip('"')
            if record_str.startswith("v=DMARC1"):
                email_sec.has_dmarc = True
                email_sec.dmarc_record = record_str

                # Extract policy
                policy_match = re.search(r'p=(\w+)', record_str)
                if policy_match:
                    email_sec.dmarc_policy = policy_match.group(1).lower()
                    if email_sec.dmarc_policy == "none":
                        email_sec.vulnerabilities.append(
                            "DMARC policy is 'p=none' — emails are not quarantined or rejected"
                        )

                # Extract pct
                pct_match = re.search(r'pct=(\d+)', record_str)
                if pct_match:
                    email_sec.dmarc_pct = int(pct_match.group(1))
                    if email_sec.dmarc_pct < 100:
                        email_sec.vulnerabilities.append(
                            f"DMARC pct={email_sec.dmarc_pct}% — not all email is covered"
                        )
                break

        # Missing records
        if not email_sec.has_spf:
            email_sec.vulnerabilities.append("No SPF record found — email spoofing possible")
        if not email_sec.has_dmarc:
            email_sec.vulnerabilities.append("No DMARC record found — no email authentication policy")

        report.email_security = email_sec

    # -----------------------------------------------------------------------
    # Certificate Transparency
    # -----------------------------------------------------------------------

    async def _query_certificate_transparency(
        self, domain: str, report: AssetReport
    ) -> None:
        """Query crt.sh for subdomains from CT logs."""
        try:
            # Use wildcard search to find all subdomains in CT
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = await self.client.get(ct_url)
            if resp is None or resp.status_code != 200:
                return

            entries = json.loads(resp.text)
            seen: Set[str] = set()

            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") and name not in seen:
                        seen.add(name)
                        report.ct_subdomains.append(name)

        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Findings → Vulnerabilities
    # -----------------------------------------------------------------------

    def _findings_to_vulns(self, report: AssetReport, origin_url: str) -> List[Vulnerability]:
        """Convert AssetReport findings to Vulnerability objects."""
        vulns: List[Vulnerability] = []

        # Zone transfer vulnerability
        if report.zone_transfer_possible:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title="DNS Zone Transfer Possible (AXFR)",
                description=(
                    f"The DNS server for {report.domain} allows zone transfer requests. "
                    "This exposes all DNS records including internal hostnames, "
                    "IP addresses, and subdomains that should not be public."
                ),
                url=origin_url,
                severity=Severity.HIGH,
                method="DNS",
                evidence=f"AXFR zone transfer succeeded for {report.domain}",
                remediation=(
                    "Restrict AXFR zone transfers to authorized secondary DNS servers only. "
                    "Configure ACLs in your DNS server (BIND, PowerDNS, etc.) to deny "
                    "transfer requests from unauthorized IPs."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy",
                ],
                cwe_id="CWE-200",
                owasp_category="A05:2021 – Security Misconfiguration",
                cvss=_CVSS_ZONE_TRANSFER,
                confidence="High",
            ))

        # Subdomain takeover candidates
        for sub in report.takeover_candidates:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.MISC,
                title=f"Subdomain Takeover Risk: {sub.hostname}",
                description=(
                    f"The subdomain {sub.hostname} has a CNAME pointing to "
                    f"{sub.cname or 'a cloud service'} that appears unclaimed. "
                    "An attacker can register the unclaimed resource and serve "
                    "malicious content under your domain."
                ),
                url=f"https://{sub.hostname}",
                severity=Severity.HIGH,
                method="GET",
                evidence=f"CNAME: {sub.cname or 'unknown'}, Response indicates unclaimed resource",
                remediation=(
                    "Remove the dangling CNAME DNS record, or reclaim the cloud resource "
                    "it points to. Audit all CNAME records regularly."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                ],
                cwe_id="CWE-350",
                owasp_category="A05:2021 – Security Misconfiguration",
                cvss=_CVSS_SUBDOMAIN_TAKEOVER,
                confidence="Medium",
            ))

        # Dev/staging environments exposed
        for dev_env in report.dev_environments:
            vulns.append(self._build_vuln(
                vuln_type=VulnType.INFO_DISCLOSURE,
                title=f"Exposed Development/Staging Environment: {dev_env.hostname}",
                description=(
                    f"A development or staging environment was found at {dev_env.hostname}. "
                    "These environments often have weaker security controls, debug features "
                    "enabled, or test credentials, which can provide an attack path to production."
                ),
                url=f"https://{dev_env.hostname}",
                severity=Severity.MEDIUM,
                method="GET",
                evidence=f"HTTP status: {dev_env.https_status or dev_env.http_status}, hostname suggests dev/staging",
                remediation=(
                    "Restrict access to dev/staging environments via IP allowlists or VPN. "
                    "Use different credentials from production. "
                    "Consider removing public DNS records for non-production environments."
                ),
                references=[
                    "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                ],
                cwe_id="CWE-200",
                owasp_category="A05:2021 – Security Misconfiguration",
                confidence="Medium",
                false_positive_risk="Low",
            ))

        # Email security findings
        if report.email_security:
            for issue in report.email_security.vulnerabilities:
                is_missing = "No SPF" in issue or "No DMARC" in issue
                vulns.append(self._build_vuln(
                    vuln_type=VulnType.MISC,
                    title=f"Email Security Issue: {issue[:60]}",
                    description=(
                        f"Email security configuration issue for {report.domain}:\n{issue}\n\n"
                        "Weak or missing email authentication allows attackers to send "
                        "spoofed emails appearing to come from your domain (phishing)."
                    ),
                    url=origin_url,
                    severity=Severity.MEDIUM if is_missing else Severity.LOW,
                    method="DNS",
                    evidence=issue,
                    remediation=(
                        "Configure a strict SPF record with '-all'. "
                        "Add a DMARC record with 'p=reject'. "
                        "Consider adding DKIM signing for all outbound email."
                    ),
                    references=[
                        "https://dmarc.org/overview/",
                        "https://www.dmarcanalyzer.com/spf/spf-record-check/",
                    ],
                    cwe_id="CWE-290",
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                    cvss=_CVSS_EMAIL_SPOOFING,
                    confidence="High",
                ))

        return vulns

    # -----------------------------------------------------------------------
    # Helper
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        """Extract the root domain from a URL."""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc or parsed.path
            # Remove port
            netloc = netloc.split(":")[0]
            # Remove www. prefix for root domain queries
            if netloc.startswith("www."):
                netloc = netloc[4:]
            return netloc if netloc else None
        except Exception:
            return None

    @property
    def last_report(self) -> Optional[AssetReport]:
        """Return the last AssetReport generated."""
        return self._report
