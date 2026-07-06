# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Advanced Web Application Security Scanner                  ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Dork Generator — Bug Bounty Reconnaissance Suite
Generates targeted search engine dorks for Shodan, Google, GitHub, Bing, Yandex.
Inspired by DORK MASTER reconnaissance methodology.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DorkResult:
    """Container for generated dorks."""
    domain: str
    org: Optional[str]
    engine: str
    category: str
    dorks: List[str] = field(default_factory=list)


class DorkGenerator:
    """
    Generates comprehensive search engine dorks for bug bounty reconnaissance.
    Supports Shodan, Google, GitHub, Bing, and Yandex.
    """

    def generate(
        self,
        domain: Optional[str] = None,
        org: Optional[str] = None,
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Generate dorks for all engines.

        Args:
            domain: Target domain (e.g. target.com)
            org: Organization name (e.g. Target Inc)

        Returns:
            Dict: {engine: {category: [dorks]}}
        """
        if not domain and not org:
            raise ValueError("At least domain or org must be provided")

        return {
            "shodan": self._shodan_dorks(domain, org),
            "google": self._google_dorks(domain, org),
            "github": self._github_dorks(domain, org),
            "bing": self._bing_dorks(domain, org),
            "yandex": self._yandex_dorks(domain, org),
        }

    def _shodan_dorks(
        self, domain: Optional[str], org: Optional[str]
    ) -> Dict[str, List[str]]:
        d = domain or "target.com"
        sub = f".{d}"
        wc = f"*.{d}"
        o = org or "Target Inc"
        h = bool(domain)
        o2 = bool(org)

        return {
            "TLS Certificate Recon": list(filter(None, [
                h and f'ssl.cert.subject.CN:"{d}"',
                h and f'ssl.cert.subjectAltName:"{d}"',
                h and f'ssl.cert.subjectAltName:"{wc}"',
                h and f'ssl.cert.subjectAltName:"{d}" port:443',
                h and f'ssl.cert.subjectAltName:"{d}" -hostname:"{d}"',
                h and f'ssl.cert.subjectAltName:"{d}" !org:"Cloudflare" !org:"Akamai" !org:"Fastly"',
                h and f'ssl.cert.issuer.CN:"Let\'s Encrypt" ssl.cert.subjectAltName:"{d}"',
                h and f'ssl.cert.expired:true ssl.cert.subjectAltName:"{d}"',
                h and f'ssl.cert.subjectAltName:"{d}" http.status:200',
            ])),
            "Subdomain & IP Enum": list(filter(None, [
                h and f'hostname:{d}',
                h and f'hostname:{sub}',
                h and f'hostname:/dev|staging|test|qa|sandbox|beta/ AND hostname:{sub}',
                h and f'hostname:(dev.{d} OR staging.{d} OR uat.{d} OR qa.{d} OR preprod.{d})',
                h and f'hostname:{sub} !org:"Cloudflare" !org:"Akamai"',
                h and f'hostname:{sub} http.status:200',
                h and f'hostname:{sub} port:8080 OR port:8443 OR port:8888',
                o2 and f'org:"{o}"',
                o2 and f'isp:"{o}"',
            ])),
            "API & GraphQL": list(filter(None, [
                h and f'hostname:{sub} (http.title:"Swagger UI" OR http.html:"openapi" OR http.html:"swagger")',
                h and f'hostname:{sub} http.html:"graphql" port:443',
                h and f'hostname:{sub} http.html:"/api/v" http.status:200',
                h and f'hostname:{sub} http.html:"api_key" OR http.html:"apikey" OR http.html:"access_token"',
                o2 and f'org:"{o}" (http.title:"Swagger" OR http.html:"/swagger.json")',
                o2 and f'org:"{o}" http.html:"__schema" port:443',
            ])),
            "Admin & Auth Panels": list(filter(None, [
                h and f'hostname:{sub} (http.title:"Admin" OR http.title:"Dashboard" OR http.title:"Login")',
                h and f'hostname:{sub} http.title:"phpMyAdmin"',
                h and f'hostname:{sub} (http.title:"Grafana" OR http.title:"Kibana")',
                h and f'hostname:{sub} http.title:"Jenkins"',
                h and f'hostname:{sub} http.html:"wp-admin" OR http.html:"wp-login"',
                h and f'hostname:{sub} http.title:"GitLab" OR http.title:"Jira" OR http.title:"Confluence"',
                h and f'hostname:{sub} http.title:"Portainer"',
                o2 and f'org:"{o}" http.title:"Admin Panel"',
            ])),
            "Secrets & Config Leaks": list(filter(None, [
                h and f'hostname:{sub} (http.html:"DB_PASSWORD" OR http.html:"DATABASE_URL" OR http.html:"SECRET_KEY")',
                h and f'hostname:{sub} (http.html:"AWS_ACCESS_KEY" OR http.html:"AKIA" OR http.html:"aws_secret")',
                h and f'hostname:{sub} (http.html:"traceback" OR http.html:"Traceback (most recent")',
                h and f'hostname:{sub} http.html:"config.php" OR http.html:".env"',
                h and f'hostname:{sub} http.html:"private_key" OR http.html:"BEGIN RSA"',
                o2 and f'org:"{o}" (http.html:"DB_PASSWORD" OR http.html:"SECRET_KEY")',
            ])),
            "Database Exposure": list(filter(None, [
                o2 and f'org:"{o}" port:9200 product:"Elasticsearch"',
                o2 and f'org:"{o}" port:27017 product:"MongoDB"',
                o2 and f'org:"{o}" port:6379 product:"Redis"',
                o2 and f'org:"{o}" port:5432 product:"PostgreSQL"',
                o2 and f'org:"{o}" port:3306 product:"MySQL"',
                o2 and f'org:"{o}" port:5984 product:"CouchDB"',
                o2 and f'org:"{o}" port:8500 product:"Consul"',
                h and f'hostname:{sub} port:9200',
                h and f'hostname:{sub} port:27017',
                h and f'hostname:{sub} port:6379',
            ])),
            "Cloud & Storage": list(filter(None, [
                h and f'hostname:{sub} http.title:"Index of /"',
                h and f'hostname:{sub} (http.html:"s3.amazonaws.com" OR http.html:"firebaseio.com")',
                h and f'hostname:{sub} http.html:"AzureWebJobsStorage"',
                o2 and f'org:"{o}" product:"Minio" port:9000',
            ])),
            "DevOps & CI/CD": list(filter(None, [
                o2 and f'org:"{o}" product:"Jenkins" port:8080',
                o2 and f'org:"{o}" http.title:"GitLab" port:80',
                o2 and f'org:"{o}" http.title:"TeamCity"',
                o2 and f'org:"{o}" product:"Kubernetes Dashboard"',
                o2 and f'org:"{o}" port:2376 product:"Docker"',
                h and f'hostname:{sub} http.title:"Jenkins" OR http.title:"GitLab CI"',
                h and f'hostname:{sub} port:2376',
            ])),
            "SSRF & Proxy Indicators": list(filter(None, [
                h and f'hostname:{sub} http.html:"webhook" OR http.html:"callback"',
                h and f'hostname:{sub} (http.html:"url=" OR http.html:"next=" OR http.html:"return=")',
                h and f'hostname:{sub} http.html:"proxy" OR http.html:"redirect"',
                o2 and f'org:"{o}" http.html:"internal" http.status:200',
            ])),
            "Remote Access": list(filter(None, [
                o2 and f'org:"{o}" port:22 product:"OpenSSH"',
                o2 and f'org:"{o}" port:3389 product:"Remote Desktop"',
                o2 and f'org:"{o}" port:5900 product:"VNC"',
                o2 and f'org:"{o}" port:23',
                h and f'hostname:{sub} port:22',
                h and f'hostname:{sub} port:3389',
            ])),
        }

    def _google_dorks(
        self, domain: Optional[str], org: Optional[str]
    ) -> Dict[str, List[str]]:
        d = domain or "target.com"
        return {
            "Sensitive Files": [
                f"site:{d} ext:env OR ext:log OR ext:conf OR ext:cfg OR ext:bak",
                f"site:{d} ext:php inurl:admin",
                f"site:{d} inurl:/.git/HEAD",
                f"site:{d} ext:sql",
                f"site:{d} ext:xlsx OR ext:csv OR ext:json inurl:export",
                f"site:{d} inurl:/.svn/entries",
                f"site:{d} ext:tar.gz OR ext:zip inurl:backup",
                f"site:{d} inurl:phpinfo.php",
            ],
            "Login & Admin": [
                f"site:{d} inurl:login OR inurl:signin OR inurl:auth",
                f"site:{d} inurl:admin OR inurl:administrator OR inurl:dashboard",
                f"site:{d} inurl:/wp-admin/ OR inurl:/admin/ OR inurl:/cpanel/",
                f'site:{d} intitle:"Admin Panel" OR intitle:"Control Panel"',
                f"site:{d} inurl:reset-password OR inurl:forgot-password",
                f"site:{d} inurl:oauth OR inurl:sso OR inurl:saml",
            ],
            "Errors & Debug": [
                f'site:{d} intext:"Warning: mysql_fetch" OR intext:"SQL syntax"',
                f'site:{d} intext:"Traceback (most recent" OR intext:"SyntaxError"',
                f'site:{d} intext:"debug=true" OR intext:"APP_DEBUG"',
                f'site:{d} intitle:"Error 500" OR intitle:"Internal Server Error"',
                f"site:{d} intext:\"stack trace\" -site:stackoverflow.com",
                f'site:{d} intext:"SQLSTATE[" OR intext:"mysqli_"',
            ],
            "API & Endpoints": [
                f"site:{d} inurl:/api/v1 OR inurl:/api/v2 OR inurl:/api/v3",
                f"site:{d} inurl:swagger.json OR inurl:openapi.json",
                f"site:{d} inurl:graphql",
                f"site:{d} inurl:/rest/ OR inurl:/service/",
                f"site:{d} ext:wsdl OR ext:wadl",
            ],
            "Subdomains": [
                f"site:*.{d} -site:www.{d}",
                f"site:*.{d} inurl:dev OR inurl:staging OR inurl:test",
                f"site:{d} inurl:internal OR inurl:intranet OR inurl:private",
                f'inurl:"{d}" ext:php OR ext:asp OR ext:aspx',
            ],
            "Cloud Leaks": [
                f"site:{d} inurl:s3.amazonaws.com",
                f"site:{d} inurl:blob.core.windows.net",
                f"site:{d} inurl:firebaseio.com",
                f'"{d}" site:pastebin.com',
                f'"{d}" site:jsfiddle.net',
                f'"{d}" site:trello.com',
                f'"{d}" site:docs.google.com',
            ],
            "Injection Parameters": [
                f'site:{d} inurl:"?id=" OR inurl:"?q=" OR inurl:"?search="',
                f'site:{d} inurl:"?redirect=" OR inurl:"?url=" OR inurl:"?next="',
                f'site:{d} inurl:"?page=" OR inurl:"?file=" OR inurl:"?path="',
                f'site:{d} inurl:"?token=" OR inurl:"?key=" OR inurl:"?code="',
            ],
        }

    def _github_dorks(
        self, domain: Optional[str], org: Optional[str]
    ) -> Dict[str, List[str]]:
        d = domain or "target.com"
        org_prefix = d.split('.')[0]
        return {
            "API Keys & Tokens": [
                f'"{d}" password OR passwd OR secret language:python',
                f'"{d}" "AWS_ACCESS_KEY_ID" OR "AKIA"',
                f'"{d}" "private_key" OR "BEGIN RSA PRIVATE KEY"',
                f'"{d}" token OR apikey OR api_key filename:.env',
                f'"{d}" db_password OR database_url OR db_url',
                f'"{d}" "client_secret" OR "client_id" AND "secret"',
                f'"{d}" "Authorization: Bearer" OR "X-API-Key"',
                f'org:{org_prefix} "api_key" OR "api_secret" language:python',
            ],
            "Config & Env Files": [
                f'"{d}" filename:.env',
                f'"{d}" filename:config.yml OR filename:config.json',
                f'"{d}" filename:settings.py OR filename:local_settings.py',
                f'"{d}" filename:wp-config.php',
                f'"{d}" filename:database.yml',
                f'"{d}" filename:.htpasswd OR filename:.htaccess',
                f'"{d}" filename:credentials OR filename:.aws/credentials',
                f'"{d}" filename:docker-compose.yml',
            ],
            "JWT & Auth Secrets": [
                f'"{d}" "jwt_secret" OR "JWT_SECRET"',
                f'"{d}" "HS256" OR "RS256" filename:*.py OR filename:*.js',
                f'"{d}" "SECRET_KEY" filename:*.py',
                f'"{d}" "FLASK_SECRET" OR "DJANGO_SECRET_KEY"',
            ],
            "Infrastructure": [
                f'"{d}" filename:Dockerfile',
                f'"{d}" filename:terraform.tfvars',
                f'"{d}" filename:*.tf "aws_access_key"',
                f'"{d}" filename:ansible.cfg OR filename:*.yml password',
                f'"{d}" filename:kube-config OR filename:kubeconfig',
            ],
            "Leaked Credentials": [
                f'"{d}" "admin" "password" extension:sql',
                f'"{d}" "INSERT INTO users" password',
                f'"{d}" "BEGIN CERTIFICATE"',
                f'"{d}" "ssh-rsa AAAA"',
            ],
            "Source Code Recon": [
                f'"{d}" filename:*.js "fetch(" OR "axios("',
                f'"{d}" "endpoint" OR "baseURL" filename:*.js',
                f'"{d}" "cors" OR "Access-Control-Allow-Origin"',
                f'"{d}" "TODO" OR "FIXME" OR "HACK" filename:*.py',
            ],
        }

    def _bing_dorks(
        self, domain: Optional[str], org: Optional[str]
    ) -> Dict[str, List[str]]:
        d = domain or "target.com"
        return {
            "Bing Recon": [
                f"site:{d} ext:log",
                f"site:{d} ext:env",
                f"site:{d} inurl:admin",
                f'site:{d} "Index of /"',
                f"site:{d} inurl:config",
                f"site:{d} ext:php inurl:id=",
                f"site:{d} inurl:login inurl:admin",
                f"site:{d} ext:bak OR ext:old",
                f"site:{d} inurl:phpinfo.php",
                f"site:*.{d} -site:www.{d}",
                f"site:{d} ext:sql",
                f"site:{d} inurl:backup",
                f'site:{d} intitle:"Server Error"',
                f"site:{d} inurl:wp-content",
            ],
        }

    def _yandex_dorks(
        self, domain: Optional[str], org: Optional[str]
    ) -> Dict[str, List[str]]:
        d = domain or "target.com"
        return {
            "Yandex Recon": [
                f"host:{d} filetype:log",
                f"host:{d} filetype:env",
                f"host:{d} inurl:admin",
                f"host:*.{d} inurl:staging OR inurl:dev",
                f'host:{d} "DB_PASSWORD"',
                f"host:{d} filetype:sql",
                f"host:{d} inurl:config.php",
                f'host:{d} "Index of /"',
                f"host:{d} inurl:backup",
                f"host:{d} inurl:wp-admin",
                f"host:{d} filetype:xml",
                f"host:{d} inurl:api",
            ],
        }

    def export_text(
        self,
        dorks: Dict[str, Dict[str, List[str]]],
        domain: Optional[str] = None,
        org: Optional[str] = None,
    ) -> str:
        """Export all dorks as formatted text."""
        lines = [
            "# WebShield — Dork Generator",
            f"# Target: {domain or 'N/A'} | Org: {org or 'N/A'}",
            f"# Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)",
            "",
        ]
        for engine, categories in dorks.items():
            lines.append(f"{'='*50}")
            lines.append(f"# {engine.upper()}")
            lines.append(f"{'='*50}")
            lines.append("")
            for category, dork_list in categories.items():
                lines.append(f"## {category}")
                for dork in dork_list:
                    lines.append(dork)
                lines.append("")
        return "\n".join(lines)

    def total_count(self, dorks: Dict[str, Dict[str, List[str]]]) -> int:
        """Count total generated dorks."""
        return sum(
            len(dork_list)
            for categories in dorks.values()
            for dork_list in categories.values()
        )
