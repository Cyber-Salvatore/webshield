"""
WebShield Integration Layer
================================================
بيربط WebShield مع أنظمة وأدوات خارجية:

    - CIIntegration      : CI/CD (GitHub Actions, GitLab CI, Jenkins)
    - DockerIntegration  : Docker & Kubernetes deployment helpers
    - TicketIntegration  : Jira, GitHub Issues, GitLab Issues
    - WebhookDispatcher  : إرسال نتائج لـ Webhooks خارجية
    - ExportManager      : تصدير النتائج لـ JSON/CSV/SARIF/JUnit
    - IntegrationRegistry: تسجيل وإدارة كل الـ Integrations
    - IntegrationConfig  : إعدادات الـ Integration من ملف واحد
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Integration Layer                      ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import csv
import io
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .logging_system import PlatformLogger
from .error_framework import WebShieldError
from .developer_sdk import SDKFinding, SDKSeverity


# ══════════════════════════════════════════════════════════════════════════════
# ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class IntegrationError(WebShieldError):
    """خطأ في تشغيل Integration."""

class WebhookError(IntegrationError):
    """خطأ في إرسال Webhook."""

class ExportError(IntegrationError):
    """خطأ في تصدير البيانات."""


# ══════════════════════════════════════════════════════════════════════════════
# BASE INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

class IntegrationStatus(str, Enum):
    ENABLED   = "enabled"
    DISABLED  = "disabled"
    ERROR     = "error"
    UNTESTED  = "untested"


@dataclass
class IntegrationResult:
    """نتيجة تشغيل Integration."""
    integration_id: str
    success:        bool
    message:        str          = ""
    data:           Dict[str, Any] = field(default_factory=dict)
    duration_ms:    float        = 0.0
    error:          Optional[str] = None


class BaseIntegration:
    """
    Base class لكل الـ Integrations.
    كل Integration بتحتاج تعرّف integration_id + name + test() + run().
    """
    integration_id: str = "base"
    name:           str = "Base Integration"
    description:    str = ""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config  = config or {}
        self._log     = PlatformLogger(f"Integration:{self.integration_id}")
        self._status  = IntegrationStatus.UNTESTED

    def get_config(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, os.environ.get(
            f"WS_{self.integration_id.upper()}_{key.upper()}", default
        ))

    def test(self) -> bool:
        """
        تحقق إن الـ Integration شغالة — Override دي.
        بترجع True لو كل حاجة تمام.
        """
        return True

    async def run(self, findings: List[SDKFinding],
                  metadata: Optional[Dict[str, Any]] = None) -> IntegrationResult:
        """
        شغّل الـ Integration على نتائج الـ Scan — Override دي.
        """
        raise NotImplementedError(f"{type(self).__name__} must implement run()")

    @property
    def status(self) -> IntegrationStatus:
        return self._status

    def _result(self, success: bool, message: str = "",
                data: Optional[Dict] = None, error: Optional[str] = None,
                duration_ms: float = 0.0) -> IntegrationResult:
        self._status = IntegrationStatus.ENABLED if success else IntegrationStatus.ERROR
        return IntegrationResult(
            integration_id = self.integration_id,
            success        = success,
            message        = message,
            data           = data or {},
            duration_ms    = duration_ms,
            error          = error,
        )


# ══════════════════════════════════════════════════════════════════════════════
# CI/CD INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

class CIExitCode(int, Enum):
    SUCCESS       = 0
    FINDINGS      = 1   # findings found (within threshold)
    THRESHOLD_MET = 2   # findings exceed threshold → block pipeline
    ERROR         = 3   # scan error


@dataclass
class CIPolicy:
    """سياسة CI/CD — إيه الـ findings اللي بتوقف الـ Pipeline."""
    fail_on_critical:  bool  = True
    fail_on_high:      bool  = False
    max_critical:      int   = 0    # 0 = أي critical يفشل
    max_high:          int   = 5
    max_medium:        int   = 20
    fail_on_new_only:  bool  = False  # فشل بس لو في findings جديدة


class CIIntegration(BaseIntegration):
    """
    دعم CI/CD — بيولّد تقارير وبيحدد exit code يناسب الـ Pipeline.

    يدعم: GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps

    مثال في GitHub Actions:
        - name: WebShield Scan
          run: python -m webshield https://staging.example.com --ci --format github
          env:
            WS_THRESHOLD_CRITICAL: 0
            WS_THRESHOLD_HIGH: 5
    """
    integration_id = "ci_cd"
    name           = "CI/CD Integration"
    description    = "Pipeline integration with exit codes and threshold policies"

    PLATFORM_GITHUB   = "github"
    PLATFORM_GITLAB   = "gitlab"
    PLATFORM_JENKINS  = "jenkins"
    PLATFORM_GENERIC  = "generic"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._policy = CIPolicy(
            fail_on_critical = self.get_config("fail_on_critical", True),
            fail_on_high     = self.get_config("fail_on_high", False),
            max_critical     = int(self.get_config("threshold_critical", 0)),
            max_high         = int(self.get_config("threshold_high", 5)),
            max_medium       = int(self.get_config("threshold_medium", 20)),
        )

    def detect_platform(self) -> str:
        """اكتشاف تلقائي للـ CI platform من Environment Variables."""
        if os.environ.get("GITHUB_ACTIONS"):
            return self.PLATFORM_GITHUB
        if os.environ.get("GITLAB_CI"):
            return self.PLATFORM_GITLAB
        if os.environ.get("JENKINS_URL"):
            return self.PLATFORM_JENKINS
        return self.PLATFORM_GENERIC

    def evaluate_policy(self, findings: List[SDKFinding]) -> Tuple[CIExitCode, str]:
        """بيقيّم الـ findings حسب الـ Policy ويرجع exit code + سبب."""
        critical = sum(1 for f in findings if f.severity == SDKSeverity.CRITICAL)
        high     = sum(1 for f in findings if f.severity == SDKSeverity.HIGH)
        medium   = sum(1 for f in findings if f.severity == SDKSeverity.MEDIUM)

        if self._policy.fail_on_critical and critical > self._policy.max_critical:
            return (CIExitCode.THRESHOLD_MET,
                    f"CRITICAL threshold exceeded: {critical} found, max={self._policy.max_critical}")
        if self._policy.fail_on_high and high > self._policy.max_high:
            return (CIExitCode.THRESHOLD_MET,
                    f"HIGH threshold exceeded: {high} found, max={self._policy.max_high}")
        if medium > self._policy.max_medium:
            return (CIExitCode.THRESHOLD_MET,
                    f"MEDIUM threshold exceeded: {medium} found, max={self._policy.max_medium}")

        if findings:
            return (CIExitCode.FINDINGS,
                    f"Scan complete: {critical}C {high}H {medium}M findings")
        return (CIExitCode.SUCCESS, "Scan complete: no findings")

    def format_output(self, findings: List[SDKFinding],
                      platform: Optional[str] = None) -> str:
        """Format output مناسب لكل CI platform."""
        platform = platform or self.detect_platform()
        lines: List[str] = []

        if platform == self.PLATFORM_GITHUB:
            # GitHub Actions annotations
            for f in findings:
                level = "error" if f.severity in (SDKSeverity.CRITICAL, SDKSeverity.HIGH) else "warning"
                lines.append(f"::{level} title=WebShield - {f.title}::{f.description} [{f.url}]")
            if not findings:
                lines.append("::notice title=WebShield::No security findings detected.")

        elif platform == self.PLATFORM_GITLAB:
            # GitLab CI output
            for f in findings:
                icon = "🔴" if f.severity == SDKSeverity.CRITICAL else "🟡"
                lines.append(f"{icon} [{f.severity.upper()}] {f.title} — {f.url}")

        else:
            # Generic output
            lines.append(f"WebShield Security Scan Results")
            lines.append("=" * 40)
            for f in findings:
                lines.append(f"[{f.severity.upper()}] {f.title}")
                lines.append(f"  URL: {f.url}")
                if f.evidence:
                    lines.append(f"  Evidence: {f.evidence[:100]}")

        return "\n".join(lines)

    async def run(self, findings: List[SDKFinding],
                  metadata: Optional[Dict[str, Any]] = None) -> IntegrationResult:
        start    = time.monotonic()
        code, msg = self.evaluate_policy(findings)
        platform  = self.detect_platform()
        output    = self.format_output(findings, platform)

        return self._result(
            success     = code != CIExitCode.THRESHOLD_MET,
            message     = msg,
            data        = {
                "exit_code":      code.value,
                "platform":       platform,
                "findings_count": len(findings),
                "output":         output,
                "policy": {
                    "max_critical": self._policy.max_critical,
                    "max_high":     self._policy.max_high,
                },
            },
            duration_ms = (time.monotonic() - start) * 1000,
        )


# ══════════════════════════════════════════════════════════════════════════════
# DOCKER INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

class DockerIntegration(BaseIntegration):
    """
    دعم Docker & Kubernetes — بيولّد configs وscripts للنشر.

    مثال:
        docker_int = DockerIntegration()
        compose = docker_int.generate_compose(target="https://app.example.com")
        Path("docker-compose.webshield.yml").write_text(compose)
    """
    integration_id = "docker"
    name           = "Docker/Kubernetes Integration"
    description    = "Container deployment configs for WebShield"

    def generate_compose(self, target: str, profile: str = "balanced",
                         output_dir: str = "./webshield_output") -> str:
        """يولّد docker-compose.yml جاهز لتشغيل WebShield."""
        return f"""version: '3.8'
services:
  webshield:
    image: webshield:latest
    command: python -m webshield {target} --profile {profile} --output /output
    volumes:
      - {output_dir}:/output
    environment:
      - WS_PROFILE={profile}
      - WS_TARGET={target}
    networks:
      - scan_network

networks:
  scan_network:
    driver: bridge
"""

    def generate_kubernetes_job(self, target: str, profile: str = "balanced",
                                namespace: str = "security") -> str:
        """يولّد Kubernetes Job manifest."""
        job_id = str(uuid.uuid4())[:8]
        return f"""apiVersion: batch/v1
kind: Job
metadata:
  name: webshield-scan-{job_id}
  namespace: {namespace}
  labels:
    app: webshield
    scan-target: "{target.replace('https://', '').replace('http://', '').replace('/', '-')}"
spec:
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: webshield
          image: webshield:latest
          command: ["python", "-m", "webshield", "{target}", "--profile", "{profile}"]
          env:
            - name: WS_PROFILE
              value: "{profile}"
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
"""

    def generate_dockerfile(self) -> str:
        """يولّد Dockerfile لـ WebShield."""
        return """FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create output directory
RUN mkdir -p /output

ENTRYPOINT ["python", "-m", "webshield"]
CMD ["--help"]
"""

    async def run(self, findings: List[SDKFinding],
                  metadata: Optional[Dict[str, Any]] = None) -> IntegrationResult:
        meta   = metadata or {}
        target = meta.get("target_url", "https://example.com")
        return self._result(
            success = True,
            message = "Docker configs generated",
            data    = {
                "compose":    self.generate_compose(target),
                "k8s_job":    self.generate_kubernetes_job(target),
                "dockerfile": self.generate_dockerfile(),
            },
        )


# ══════════════════════════════════════════════════════════════════════════════
# TICKET INTEGRATION (Jira / GitHub Issues / GitLab)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TicketTemplate:
    """قالب التذكرة."""
    title:    str
    body:     str
    labels:   List[str]  = field(default_factory=list)
    priority: str        = "medium"
    assignee: str        = ""


class TicketIntegration(BaseIntegration):
    """
    دعم إنشاء تذاكر تلقائياً لكل finding مهم.
    يدعم: Jira, GitHub Issues, GitLab Issues, Linear

    الـ Integration بتولّد الـ Ticket payloads الجاهزة للإرسال.
    الإرسال الفعلي يحتاج اتصال شبكي — بنرجع الـ payloads فقط في هذه البيئة.
    """
    integration_id = "tickets"
    name           = "Ticket Integration"
    description    = "Auto-create tickets for security findings"

    PLATFORM_JIRA   = "jira"
    PLATFORM_GITHUB = "github"
    PLATFORM_GITLAB = "gitlab"
    PLATFORM_LINEAR = "linear"

    def __init__(self, platform: str = PLATFORM_GITHUB,
                 config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._platform = platform

    def build_ticket(self, finding: SDKFinding) -> TicketTemplate:
        """يبني ticket template من finding."""
        severity_emoji = {
            SDKSeverity.CRITICAL: "🔴",
            SDKSeverity.HIGH:     "🟠",
            SDKSeverity.MEDIUM:   "🟡",
            SDKSeverity.LOW:      "🟢",
            SDKSeverity.INFO:     "ℹ️",
        }.get(finding.severity, "⚪")

        title = f"{severity_emoji} [Security] {finding.title}"

        if self._platform == self.PLATFORM_JIRA:
            body = self._jira_body(finding)
        elif self._platform == self.PLATFORM_GITHUB:
            body = self._github_body(finding)
        else:
            body = self._generic_body(finding)

        labels = ["security", f"severity:{finding.severity.value}"]
        labels += finding.tags

        return TicketTemplate(
            title    = title,
            body     = body,
            labels   = labels,
            priority = finding.severity.value,
        )

    def _github_body(self, f: SDKFinding) -> str:
        cwe_line = f"\n**CWE:** [CWE-{f.cwe}](https://cwe.mitre.org/data/definitions/{f.cwe}.html)" if f.cwe else ""
        return f"""## Security Finding: {f.title}

**Severity:** `{f.severity.value.upper()}`
**URL:** `{f.url}`
**Discovered:** {f.discovered_at}{cwe_line}

### Description
{f.description or "No description provided."}

### Evidence
```
{f.evidence or "No evidence captured."}
```

### Remediation
{f.remediation or "Please review and fix this security issue."}

---
*Found by WebShield Security Scanner*
"""

    def _jira_body(self, f: SDKFinding) -> str:
        return f"""h2. Security Finding: {f.title}

*Severity:* {f.severity.value.upper()}
*URL:* {f.url}
*Discovered:* {f.discovered_at}

h3. Description
{f.description or "No description provided."}

h3. Evidence
{{code}}
{f.evidence or "No evidence captured."}
{{code}}

h3. Remediation
{f.remediation or "Please review and fix this security issue."}

_Found by WebShield Security Scanner_
"""

    def _generic_body(self, f: SDKFinding) -> str:
        return f"""Security Finding: {f.title}
Severity: {f.severity.value.upper()}
URL: {f.url}
Description: {f.description}
Evidence: {f.evidence}
Remediation: {f.remediation}
"""

    def build_tickets_for_findings(self, findings: List[SDKFinding],
                                   min_severity: SDKSeverity = SDKSeverity.MEDIUM
                                   ) -> List[TicketTemplate]:
        """يبني tickets لكل الـ findings اللي فوق الـ threshold."""
        severity_order = [SDKSeverity.CRITICAL, SDKSeverity.HIGH,
                          SDKSeverity.MEDIUM, SDKSeverity.LOW, SDKSeverity.INFO]
        min_idx = severity_order.index(min_severity)

        tickets = []
        for f in findings:
            if severity_order.index(f.severity) <= min_idx:
                tickets.append(self.build_ticket(f))
        return tickets

    def test(self) -> bool:
        config_key = "github_token" if self._platform == self.PLATFORM_GITHUB else "api_token"
        return bool(self.get_config(config_key, ""))

    async def run(self, findings: List[SDKFinding],
                  metadata: Optional[Dict[str, Any]] = None) -> IntegrationResult:
        start   = time.monotonic()
        tickets = self.build_tickets_for_findings(findings)
        return self._result(
            success     = True,
            message     = f"Generated {len(tickets)} ticket(s) for {len(findings)} finding(s)",
            data        = {
                "platform":      self._platform,
                "tickets":       [{"title": t.title, "labels": t.labels, "priority": t.priority}
                                  for t in tickets],
                "tickets_count": len(tickets),
            },
            duration_ms = (time.monotonic() - start) * 1000,
        )


# ══════════════════════════════════════════════════════════════════════════════
# WEBHOOK DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WebhookConfig:
    """إعدادات Webhook واحد."""
    url:           str
    webhook_id:    str                  = field(default_factory=lambda: str(uuid.uuid4())[:8])
    secret:        str                  = ""
    format:        str                  = "json"     # json, slack, teams
    min_severity:  SDKSeverity          = SDKSeverity.HIGH
    enabled:       bool                 = True
    headers:       Dict[str, str]       = field(default_factory=dict)
    retry_count:   int                  = 3


class WebhookDispatcher(BaseIntegration):
    """
    بيبعت نتائج الـ Scan لـ Webhooks خارجية (Slack, Teams, custom).

    مثال:
        dispatcher = WebhookDispatcher()
        dispatcher.add_webhook("https://hooks.slack.com/...", format="slack")
        dispatcher.add_webhook("https://your-siem.com/events", min_severity=SDKSeverity.HIGH)
        await dispatcher.run(findings)
    """
    integration_id = "webhook"
    name           = "Webhook Dispatcher"
    description    = "Send scan results to external webhooks"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._webhooks: List[WebhookConfig] = []

    def add_webhook(self, url: str, format: str = "json",
                    min_severity: SDKSeverity = SDKSeverity.HIGH,
                    secret: str = "", **kwargs: Any) -> "WebhookDispatcher":
        self._webhooks.append(WebhookConfig(
            url          = url,
            format       = format,
            min_severity = min_severity,
            secret       = secret,
            **{k: v for k, v in kwargs.items() if k in WebhookConfig.__dataclass_fields__},
        ))
        return self

    def build_payload(self, webhook: WebhookConfig,
                      findings: List[SDKFinding],
                      metadata: Dict[str, Any]) -> Dict[str, Any]:
        """يبني الـ payload المناسب لكل format."""
        relevant = [
            f for f in findings
            if [SDKSeverity.CRITICAL, SDKSeverity.HIGH, SDKSeverity.MEDIUM,
                SDKSeverity.LOW, SDKSeverity.INFO].index(f.severity)
            <= [SDKSeverity.CRITICAL, SDKSeverity.HIGH, SDKSeverity.MEDIUM,
                SDKSeverity.LOW, SDKSeverity.INFO].index(webhook.min_severity)
        ]

        if webhook.format == "slack":
            return self._slack_payload(relevant, metadata)
        elif webhook.format == "teams":
            return self._teams_payload(relevant, metadata)
        else:
            return self._json_payload(relevant, metadata)

    def _slack_payload(self, findings: List[SDKFinding], meta: Dict) -> Dict:
        color = "#FF0000" if any(f.severity == SDKSeverity.CRITICAL for f in findings) else "#FFA500"
        fields = []
        for f in findings[:5]:  # Max 5 in Slack message
            fields.append({
                "title": f"[{f.severity.value.upper()}] {f.title}",
                "value": f.url,
                "short": False,
            })
        return {
            "attachments": [{
                "color":      color,
                "title":      f"WebShield Scan: {meta.get('target_url', 'Unknown')}",
                "text":       f"Found {len(findings)} security issue(s)",
                "fields":     fields,
                "footer":     "WebShield Security Scanner",
                "ts":         int(time.time()),
            }]
        }

    def _teams_payload(self, findings: List[SDKFinding], meta: Dict) -> Dict:
        facts = [{"name": f"[{f.severity.value.upper()}] {f.title}", "value": f.url}
                 for f in findings[:5]]
        return {
            "@type":      "MessageCard",
            "@context":   "http://schema.org/extensions",
            "summary":    f"WebShield Scan Results",
            "themeColor": "FF0000" if findings else "00FF00",
            "title":      f"WebShield: {meta.get('target_url', 'Scan')}",
            "sections": [{
                "activityTitle": f"{len(findings)} finding(s) detected",
                "facts": facts,
            }],
        }

    def _json_payload(self, findings: List[SDKFinding], meta: Dict) -> Dict:
        return {
            "scan_id":     meta.get("scan_id", ""),
            "target":      meta.get("target_url", ""),
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total":       len(findings),
            "findings": [
                {
                    "id":          f.finding_id,
                    "title":       f.title,
                    "severity":    f.severity.value,
                    "url":         f.url,
                    "description": f.description,
                    "evidence":    f.evidence,
                }
                for f in findings
            ],
        }

    async def run(self, findings: List[SDKFinding],
                  metadata: Optional[Dict[str, Any]] = None) -> IntegrationResult:
        start    = time.monotonic()
        meta     = metadata or {}
        payloads = []

        for wh in self._webhooks:
            if not wh.enabled:
                continue
            payload = self.build_payload(wh, findings, meta)
            payloads.append({
                "webhook_id": wh.webhook_id,
                "url":        wh.url,
                "format":     wh.format,
                "payload":    payload,
                "status":     "ready",   # فعلياً محتاج HTTP client للإرسال
            })

        return self._result(
            success     = True,
            message     = f"Prepared {len(payloads)} webhook payload(s)",
            data        = {"webhooks": payloads, "total": len(payloads)},
            duration_ms = (time.monotonic() - start) * 1000,
        )

    @property
    def webhook_count(self) -> int:
        return len(self._webhooks)


# ══════════════════════════════════════════════════════════════════════════════
# EXPORT MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ExportFormat(str, Enum):
    JSON   = "json"
    CSV    = "csv"
    SARIF  = "sarif"
    JUNIT  = "junit"
    HTML   = "html"
    MARKDOWN = "markdown"


class ExportManager(BaseIntegration):
    """
    تصدير نتائج الـ Scan لأي format بطريقة موحدة.

    يدعم: JSON, CSV, SARIF (للـ Security tools), JUnit (للـ CI), HTML, Markdown

    مثال:
        exporter = ExportManager()
        json_path = exporter.export(findings, format="json", output_dir="./reports")
        sarif_path = exporter.export(findings, format="sarif", output_dir="./reports")
    """
    integration_id = "export"
    name           = "Export Manager"
    description    = "Export scan results in multiple formats"

    def export(self, findings: List[SDKFinding],
               format: Union[str, ExportFormat] = ExportFormat.JSON,
               output_dir: Union[str, Path] = ".",
               scan_id: Optional[str] = None,
               metadata: Optional[Dict[str, Any]] = None) -> Path:
        """يصدّر النتائج لـ format محدد ويرجع path الملف."""
        fmt      = ExportFormat(format) if isinstance(format, str) else format
        out_dir  = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        sid      = scan_id or str(uuid.uuid4())[:8]
        meta     = metadata or {}

        ext_map  = {
            ExportFormat.JSON:     ".json",
            ExportFormat.CSV:      ".csv",
            ExportFormat.SARIF:    ".sarif",
            ExportFormat.JUNIT:    ".xml",
            ExportFormat.HTML:     ".html",
            ExportFormat.MARKDOWN: ".md",
        }
        filepath = out_dir / f"webshield_{sid}{ext_map[fmt]}"

        render_fn = {
            ExportFormat.JSON:     self._render_json,
            ExportFormat.CSV:      self._render_csv,
            ExportFormat.SARIF:    self._render_sarif,
            ExportFormat.JUNIT:    self._render_junit,
            ExportFormat.HTML:     self._render_html,
            ExportFormat.MARKDOWN: self._render_markdown,
        }[fmt]

        content = render_fn(findings, meta)
        filepath.write_text(content, encoding="utf-8")
        self._log.info(f"Exported {len(findings)} findings → {filepath}")
        return filepath

    def export_all(self, findings: List[SDKFinding],
                   formats: List[ExportFormat],
                   output_dir: Union[str, Path] = ".",
                   scan_id: Optional[str] = None) -> Dict[str, Path]:
        """يصدّر لكل الـ formats دفعة واحدة."""
        sid     = scan_id or str(uuid.uuid4())[:8]
        results = {}
        for fmt in formats:
            path = self.export(findings, fmt, output_dir, scan_id=sid)
            results[fmt.value] = path
        return results

    # ── Renderers ─────────────────────────────────────────────────────────────

    def _render_json(self, findings: List[SDKFinding], meta: Dict) -> str:
        data = {
            "schema":    "webshield/findings/v1",
            "scan_id":   meta.get("scan_id", ""),
            "target":    meta.get("target_url", ""),
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": {
                "total":    len(findings),
                "critical": sum(1 for f in findings if f.severity == SDKSeverity.CRITICAL),
                "high":     sum(1 for f in findings if f.severity == SDKSeverity.HIGH),
                "medium":   sum(1 for f in findings if f.severity == SDKSeverity.MEDIUM),
                "low":      sum(1 for f in findings if f.severity == SDKSeverity.LOW),
                "info":     sum(1 for f in findings if f.severity == SDKSeverity.INFO),
            },
            "findings": [
                {
                    "id":          f.finding_id,
                    "title":       f.title,
                    "severity":    f.severity.value,
                    "url":         f.url,
                    "description": f.description,
                    "evidence":    f.evidence,
                    "remediation": f.remediation,
                    "cwe":         f.cwe,
                    "cvss":        f.cvss,
                    "tags":        f.tags,
                    "discovered":  f.discovered_at,
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _render_csv(self, findings: List[SDKFinding], meta: Dict) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "id", "title", "severity", "url", "description",
            "evidence", "remediation", "cwe", "cvss", "tags", "discovered"
        ])
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id":          f.finding_id,
                "title":       f.title,
                "severity":    f.severity.value,
                "url":         f.url,
                "description": f.description,
                "evidence":    f.evidence,
                "remediation": f.remediation,
                "cwe":         f.cwe or "",
                "cvss":        f.cvss or "",
                "tags":        ", ".join(f.tags),
                "discovered":  f.discovered_at,
            })
        return output.getvalue()

    def _render_sarif(self, findings: List[SDKFinding], meta: Dict) -> str:
        """SARIF 2.1.0 — متوافق مع GitHub Code Scanning وSecurity tools."""
        rules = {}
        for f in findings:
            rule_id = f"WS-{f.title.upper().replace(' ', '-')[:30]}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id":   rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription":  {"text": f.description or f.title},
                    "defaultConfiguration": {
                        "level": "error" if f.severity in (SDKSeverity.CRITICAL, SDKSeverity.HIGH) else "warning"
                    },
                    "properties": {
                        "tags":     f.tags,
                        "security-severity": {
                            SDKSeverity.CRITICAL: "9.5",
                            SDKSeverity.HIGH:     "7.5",
                            SDKSeverity.MEDIUM:   "5.0",
                            SDKSeverity.LOW:      "2.5",
                            SDKSeverity.INFO:     "0.0",
                        }.get(f.severity, "0.0"),
                    },
                }

        results = []
        for f in findings:
            rule_id = f"WS-{f.title.upper().replace(' ', '-')[:30]}"
            results.append({
                "ruleId":  rule_id,
                "level":   "error" if f.severity in (SDKSeverity.CRITICAL, SDKSeverity.HIGH) else "warning",
                "message": {"text": f"{f.description or f.title}\n\nEvidence: {f.evidence}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.url},
                    }
                }],
                "properties": {
                    "severity": f.severity.value,
                    "cwe":      str(f.cwe) if f.cwe else "",
                },
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":            "WebShield",
                        "version":         "4.0.0",
                        "informationUri":  "https://github.com/webshield",
                        "rules":           list(rules.values()),
                    }
                },
                "results":  results,
                "artifacts": [{"location": {"uri": meta.get("target_url", "")}}],
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _render_junit(self, findings: List[SDKFinding], meta: Dict) -> str:
        """JUnit XML — متوافق مع Jenkins وGitHub Actions Test Reports."""
        failures = "\n".join(
            f'  <testcase name="{f.title}" classname="webshield.{f.severity.value}">\n'
            f'    <failure message="{f.title}" type="{f.severity.value.upper()}">\n'
            f'URL: {f.url}\nEvidence: {f.evidence[:200]}\n'
            f'    </failure>\n  </testcase>'
            for f in findings if f.severity in (SDKSeverity.CRITICAL, SDKSeverity.HIGH)
        )
        warnings = "\n".join(
            f'  <testcase name="{f.title}" classname="webshield.{f.severity.value}"/>'
            for f in findings if f.severity not in (SDKSeverity.CRITICAL, SDKSeverity.HIGH)
        )
        critical_high = sum(1 for f in findings if f.severity in (SDKSeverity.CRITICAL, SDKSeverity.HIGH))
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="WebShield Security Scan"
           tests="{len(findings)}"
           failures="{critical_high}"
           errors="0"
           timestamp="{time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())}">
{failures}
{warnings}
</testsuite>"""

    def _render_html(self, findings: List[SDKFinding], meta: Dict) -> str:
        severity_colors = {
            "critical": "#dc3545",
            "high":     "#fd7e14",
            "medium":   "#ffc107",
            "low":      "#28a745",
            "info":     "#17a2b8",
        }
        rows = "\n".join(
            f"""<tr>
  <td><span style="color:{severity_colors.get(f.severity.value,'#000')};font-weight:bold">
      {f.severity.value.upper()}</span></td>
  <td>{f.title}</td>
  <td><a href="{f.url}">{f.url}</a></td>
  <td>{f.description[:100]}</td>
</tr>"""
            for f in findings
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WebShield Security Report</title>
  <style>
    body{{font-family:Arial,sans-serif;margin:20px;background:#f8f9fa}}
    h1{{color:#343a40}} table{{border-collapse:collapse;width:100%;background:#fff}}
    th,td{{border:1px solid #dee2e6;padding:10px;text-align:left}}
    th{{background:#343a40;color:#fff}}
    tr:nth-child(even){{background:#f2f2f2}}
  </style>
</head>
<body>
<h1>WebShield Security Report</h1>
<p><strong>Target:</strong> {meta.get('target_url','')}</p>
<p><strong>Total Findings:</strong> {len(findings)}</p>
<table>
  <thead><tr><th>Severity</th><th>Title</th><th>URL</th><th>Description</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<footer><p><em>Generated by WebShield Security Scanner</em></p></footer>
</body></html>"""

    def _render_markdown(self, findings: List[SDKFinding], meta: Dict) -> str:
        lines = [
            "# WebShield Security Report",
            "",
            f"**Target:** {meta.get('target_url', 'N/A')}",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"**Total Findings:** {len(findings)}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in findings if f.severity.value == sev)
            if count:
                lines.append(f"| {sev.upper()} | {count} |")

        lines += ["", "## Findings", ""]
        for i, f in enumerate(findings, 1):
            lines += [
                f"### {i}. {f.title}",
                "",
                f"- **Severity:** `{f.severity.value.upper()}`",
                f"- **URL:** `{f.url}`",
                f"- **CWE:** {f'CWE-{f.cwe}' if f.cwe else 'N/A'}",
                "",
                f"**Description:** {f.description or 'N/A'}",
                "",
                "**Evidence:**",
                f"```\n{f.evidence or 'N/A'}\n```",
                "",
                f"**Remediation:** {f.remediation or 'N/A'}",
                "",
                "---",
                "",
            ]
        return "\n".join(lines)

    async def run(self, findings: List[SDKFinding],
                  metadata: Optional[Dict[str, Any]] = None) -> IntegrationResult:
        return self._result(
            success = True,
            message = f"ExportManager ready — {len(findings)} findings to export",
            data    = {"findings_count": len(findings), "supported_formats": [f.value for f in ExportFormat]},
        )


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

class IntegrationRegistry:
    """
    بيدير كل الـ Integrations المتاحة ويشغّلها بشكل منظم.

    مثال:
        registry = IntegrationRegistry()
        registry.register(CIIntegration())
        registry.register(WebhookDispatcher().add_webhook("https://slack.com/..."))

        # شغّل كل الـ Integrations بعد الـ Scan
        results = await registry.run_all(findings, metadata={"target_url": target})
    """

    def __init__(self) -> None:
        self._integrations: Dict[str, BaseIntegration] = {}
        self._log = PlatformLogger("IntegrationRegistry")

    def register(self, integration: BaseIntegration) -> "IntegrationRegistry":
        """سجّل Integration جديدة."""
        self._integrations[integration.integration_id] = integration
        self._log.info(f"Registered integration: {integration.name}")
        return self

    def get(self, integration_id: str) -> Optional[BaseIntegration]:
        return self._integrations.get(integration_id)

    def list_all(self) -> List[str]:
        return list(self._integrations.keys())

    def test_all(self) -> Dict[str, bool]:
        """اختبر كل الـ Integrations."""
        results = {}
        for iid, integration in self._integrations.items():
            try:
                results[iid] = integration.test()
            except Exception as e:
                self._log.warning(f"Integration '{iid}' test failed: {e}")
                results[iid] = False
        return results

    async def run_all(self, findings: List[SDKFinding],
                      metadata: Optional[Dict[str, Any]] = None
                      ) -> Dict[str, IntegrationResult]:
        """شغّل كل الـ Integrations على نتائج الـ Scan."""
        import asyncio
        results: Dict[str, IntegrationResult] = {}

        for iid, integration in self._integrations.items():
            if integration.status == IntegrationStatus.DISABLED:
                continue
            try:
                result = await integration.run(findings, metadata)
                results[iid] = result
                status = "✓" if result.success else "✗"
                self._log.info(f"{status} {integration.name}: {result.message}")
            except Exception as e:
                self._log.error(f"Integration '{iid}' failed: {e}")
                results[iid] = IntegrationResult(
                    integration_id = iid,
                    success        = False,
                    error          = str(e),
                )

        return results

    async def run_one(self, integration_id: str,
                      findings: List[SDKFinding],
                      metadata: Optional[Dict[str, Any]] = None
                      ) -> Optional[IntegrationResult]:
        """شغّل Integration واحدة بالـ ID بتاعها."""
        integration = self._integrations.get(integration_id)
        if not integration:
            return None
        return await integration.run(findings, metadata)

    def disable(self, integration_id: str) -> None:
        if integration_id in self._integrations:
            self._integrations[integration_id]._status = IntegrationStatus.DISABLED

    def enable(self, integration_id: str) -> None:
        if integration_id in self._integrations:
            self._integrations[integration_id]._status = IntegrationStatus.UNTESTED

    @property
    def count(self) -> int:
        return len(self._integrations)


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class IntegrationConfig:
    """
    إعدادات مركزية لكل الـ Integrations — من ملف YAML/JSON أو Environment Variables.

    مثال:
        config = IntegrationConfig.from_env()
        registry = config.build_registry()
    """
    ci_enabled:          bool              = False
    ci_fail_on_critical: bool              = True
    ci_max_high:         int               = 5

    docker_enabled:      bool              = False

    tickets_enabled:     bool              = False
    tickets_platform:    str               = "github"
    tickets_min_severity: str              = "high"

    webhooks:            List[Dict[str, Any]] = field(default_factory=list)

    export_formats:      List[str]         = field(default_factory=lambda: ["json"])
    export_output_dir:   str               = "./webshield_reports"

    @classmethod
    def from_env(cls) -> "IntegrationConfig":
        """يقرأ الإعدادات من Environment Variables."""
        return cls(
            ci_enabled          = os.environ.get("WS_CI_ENABLED", "").lower() in ("1", "true", "yes"),
            ci_fail_on_critical = os.environ.get("WS_CI_FAIL_CRITICAL", "true").lower() != "false",
            ci_max_high         = int(os.environ.get("WS_CI_MAX_HIGH", "5")),
            docker_enabled      = os.environ.get("WS_DOCKER_ENABLED", "").lower() in ("1", "true"),
            tickets_enabled     = os.environ.get("WS_TICKETS_ENABLED", "").lower() in ("1", "true"),
            tickets_platform    = os.environ.get("WS_TICKETS_PLATFORM", "github"),
            export_formats      = os.environ.get("WS_EXPORT_FORMATS", "json").split(","),
            export_output_dir   = os.environ.get("WS_EXPORT_DIR", "./webshield_reports"),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntegrationConfig":
        valid_keys = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in valid_keys})

    def build_registry(self) -> IntegrationRegistry:
        """يبني IntegrationRegistry مكوّن حسب الإعدادات."""
        registry = IntegrationRegistry()

        if self.ci_enabled:
            registry.register(CIIntegration(config={
                "fail_on_critical": self.ci_fail_on_critical,
                "threshold_high":   self.ci_max_high,
            }))

        if self.docker_enabled:
            registry.register(DockerIntegration())

        if self.tickets_enabled:
            registry.register(TicketIntegration(platform=self.tickets_platform))

        if self.webhooks:
            dispatcher = WebhookDispatcher()
            for wh in self.webhooks:
                dispatcher.add_webhook(**wh)
            registry.register(dispatcher)

        # ExportManager دايماً موجود
        registry.register(ExportManager())

        return registry


# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS
# ══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Errors
    "IntegrationError", "WebhookError", "ExportError",
    # Base
    "IntegrationStatus", "IntegrationResult", "BaseIntegration",
    # CI/CD
    "CIExitCode", "CIPolicy", "CIIntegration",
    # Docker
    "DockerIntegration",
    # Tickets
    "TicketTemplate", "TicketIntegration",
    # Webhooks
    "WebhookConfig", "WebhookDispatcher",
    # Export
    "ExportFormat", "ExportManager",
    # Registry & Config
    "IntegrationRegistry", "IntegrationConfig",
]
