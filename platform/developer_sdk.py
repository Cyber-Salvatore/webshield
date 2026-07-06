"""
WebShield Developer SDK
===========================================
بيسمح لأي مطور يبني Scanner جديد أو Plugin أو Reporter أو Workflow
من غير ما يحتاج يفهم تفاصيل الـ Core.

المكونات:
    - ScannerSDK         : بيبني Scanner Plugin بشكل سهل وموحد
    - PayloadSDK         : إدارة وتوليد Payloads مع WAF evasion
    - ReporterSDK        : بيبني Reporter مخصص لأي format
    - WorkflowSDK        : بيبني Workflow جديد من غير معرفة بالـ Engine
    - SDKContext         : بيوفر للـ Plugin كل ما يحتاجه أثناء الـ Scan
    - SDKResult          : نتيجة موحدة تخرج من أي Plugin
    - PluginManifest     : ملف توصيف الـ Plugin الكامل
    - sdk_scanner        : decorator لبناء Scanner بسطر واحد
    - validate_plugin    : بيتحقق من صحة الـ Plugin قبل التسجيل
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Developer SDK                          ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import inspect
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union

from .logging_system import PlatformLogger
from .error_framework import WebShieldError
from .plugin_architecture import (
    BasePlugin, ScannerPlugin, PluginInfo, PluginType, PluginRegistry,
)
from .event_bus import EventBus
from .data_management import DataManagementLayer


# ══════════════════════════════════════════════════════════════════════════════
# SDK ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class SDKError(WebShieldError):
    """خطأ في استخدام الـ SDK."""

class PluginValidationError(SDKError):
    """الـ Plugin مش صحيح."""


# ══════════════════════════════════════════════════════════════════════════════
# SDK RESULT
# ══════════════════════════════════════════════════════════════════════════════

class SDKSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class SDKFinding:
    """
    نتيجة موحدة تخرج من أي Plugin.
    أبسط من Vulnerability الكاملة — SDK تحولها تلقائياً.
    """
    title:       str
    severity:    SDKSeverity          = SDKSeverity.MEDIUM
    url:         str                  = ""
    description: str                  = ""
    evidence:    str                  = ""
    remediation: str                  = ""
    cwe:         Optional[int]        = None
    cvss:        Optional[float]      = None
    tags:        List[str]            = field(default_factory=list)
    extra:       Dict[str, Any]       = field(default_factory=dict)
    finding_id:  str                  = field(default_factory=lambda: str(uuid.uuid4())[:8])
    discovered_at: str                = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


@dataclass
class SDKResult:
    """نتيجة تشغيل Plugin كاملة."""
    plugin_id:    str
    success:      bool               = True
    findings:     List[SDKFinding]   = field(default_factory=list)
    error:        Optional[str]      = None
    duration_ms:  float              = 0.0
    requests_made: int               = 0
    metadata:     Dict[str, Any]     = field(default_factory=dict)

    def add_finding(self, **kwargs: Any) -> SDKFinding:
        f = SDKFinding(**kwargs)
        self.findings.append(f)
        return f

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SDKSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SDKSeverity.HIGH)


# ══════════════════════════════════════════════════════════════════════════════
# SDK CONTEXT  (ما يتوفر للـ Plugin أثناء التشغيل)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SDKContext:
    """
    السياق الكامل اللي بيتوفر لأي Plugin أثناء الـ Scan.
    بدل ما الـ Plugin يعرف عن CoreManager أو EventBus — بيتعامل مع SDKContext فقط.
    """
    scan_id:     str
    target_url:  str
    profile:     str                  = "balanced"
    endpoints:   List[Dict[str, Any]] = field(default_factory=list)
    fingerprints: Dict[str, Any]      = field(default_factory=dict)
    auth_context: Dict[str, Any]      = field(default_factory=dict)
    config:      Dict[str, Any]       = field(default_factory=dict)
    _bus:        Optional[EventBus]   = field(default=None, repr=False)
    _dm:         Optional[DataManagementLayer] = field(default=None, repr=False)
    _log:        Optional[PlatformLogger]      = field(default=None, repr=False)

    def emit(self, event_name: str, data: Any = None) -> None:
        """بعت event للـ Platform بدون تعقيد."""
        if self._bus:
            self._bus.emit_sync(event_name, data=data)

    def store(self, collection: str, record: Dict[str, Any]) -> str:
        """احفظ بيانات في الـ DataLayer."""
        if self._dm:
            return self._dm.add(collection, record, producer=f"sdk:{self.scan_id}")
        return ""

    def log(self, message: str, level: str = "info") -> None:
        if self._log:
            getattr(self._log, level, self._log.info)(message)

    def has_tech(self, tech: str) -> bool:
        """تحقق لو تقنية معينة اتكشفت."""
        detected = self.fingerprints.get("technologies", [])
        return any(tech.lower() in str(t).lower() for t in detected)

    def get_endpoints_by_method(self, method: str) -> List[Dict[str, Any]]:
        return [e for e in self.endpoints if e.get("method", "").upper() == method.upper()]

    def get_config(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)


# ══════════════════════════════════════════════════════════════════════════════
# PLUGIN MANIFEST
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PluginManifest:
    """
    ملف توصيف Plugin كامل — بيُعرَّف مرة وبيُستخدم في كل مكان.

    مثال:
        manifest = PluginManifest(
            plugin_id   = "my_sqli_scanner",
            name        = "My SQLi Scanner",
            version     = "1.0.0",
            description = "Detects SQL injection via error-based techniques",
            author      = "Your Name",
            vuln_types  = ["sqli"],
            severity    = "high",
        )
    """
    plugin_id:    str
    name:         str
    version:      str                 = "1.0.0"
    description:  str                 = ""
    author:       str                 = ""
    vuln_types:   List[str]           = field(default_factory=list)
    severity:     str                 = "medium"
    tags:         List[str]           = field(default_factory=list)
    requires:     List[str]           = field(default_factory=list)   # tech requirements
    min_profile:  str                 = "quick"
    safe_to_run:  bool                = True  # False = destructive test

    def to_plugin_info(self) -> PluginInfo:
        return PluginInfo(
            plugin_id   = self.plugin_id,
            name        = self.name,
            version     = self.version,
            description = self.description,
            plugin_type = PluginType.SCANNER,
            author      = self.author,
            tags        = self.tags,
        )


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER SDK (الأهم — بيبني Scanners بشكل موحد)
# ══════════════════════════════════════════════════════════════════════════════

class ScannerSDK:
    """
    SDK لبناء Scanner Plugins بشكل سريع وموحد.

    الاستخدام البسيط (decorator):
        @ScannerSDK.scanner(
            plugin_id="my_xss", name="My XSS Scanner", version="1.0.0"
        )
        async def scan(ctx: SDKContext, result: SDKResult) -> None:
            for ep in ctx.endpoints:
                resp = await ctx.http_get(ep["url"] + "?q=<script>alert(1)</script>")
                if "<script>alert(1)</script>" in resp.body:
                    result.add_finding(
                        title    = "Reflected XSS",
                        severity = SDKSeverity.HIGH,
                        url      = ep["url"],
                        evidence = resp.body[:200],
                    )

    الاستخدام المتقدم (class):
        class MyScanner(ScannerSDK):
            manifest = PluginManifest(plugin_id="my_scanner", name="My Scanner", ...)

            async def run(self, ctx: SDKContext) -> SDKResult:
                result = SDKResult(plugin_id=self.manifest.plugin_id)
                # ... scan logic ...
                return result
    """

    manifest: PluginManifest = PluginManifest(
        plugin_id="base_sdk_scanner",
        name="Base SDK Scanner",
    )

    def __init__(self) -> None:
        self._log = PlatformLogger(f"SDK:{self.manifest.plugin_id}")

    # ── Abstract interface ──────────────────────────────────────────────────

    async def run(self, ctx: SDKContext) -> SDKResult:
        """
        نقطة الدخول الرئيسية — Override دي في الـ Scanner بتاعك.
        بدل ما تتعامل مع Context المعقد، بتتعامل مع SDKContext بس.
        """
        raise NotImplementedError(f"{type(self).__name__} must implement run()")

    # ── Decorator factory ───────────────────────────────────────────────────

    @classmethod
    def scanner(cls, plugin_id: str, name: str, version: str = "1.0.0",
                description: str = "", author: str = "", **kwargs: Any) -> Callable:
        """
        Decorator يحوّل دالة async عادية لـ Scanner Plugin كامل.

        مثال:
            @ScannerSDK.scanner("headers_check", "Security Headers Check")
            async def scan(ctx, result):
                if "X-Frame-Options" not in ctx.get_config("headers", {}):
                    result.add_finding(title="Missing X-Frame-Options", severity=SDKSeverity.LOW)
        """
        def decorator(fn: Callable) -> Type["ScannerSDK"]:
            manifest = PluginManifest(
                plugin_id   = plugin_id,
                name        = name,
                version     = version,
                description = description or (fn.__doc__ or "").strip(),
                author      = author,
                **{k: v for k, v in kwargs.items() if k in PluginManifest.__dataclass_fields__},
            )

            class _FunctionalScanner(ScannerSDK):
                pass

            _FunctionalScanner.manifest     = manifest
            _FunctionalScanner.__name__     = f"Scanner_{plugin_id}"
            _FunctionalScanner.__qualname__ = f"Scanner_{plugin_id}"

            async def _run(self: "_FunctionalScanner", ctx: SDKContext) -> SDKResult:
                r = SDKResult(plugin_id=plugin_id)
                start = time.monotonic()
                await fn(ctx, r)
                r.duration_ms = (time.monotonic() - start) * 1000
                return r

            _FunctionalScanner.run = _run  # type: ignore[method-assign]
            _FunctionalScanner._original_fn = staticmethod(fn)  # type: ignore[attr-defined]
            return _FunctionalScanner

        return decorator

    # ── Helper: build ScannerPlugin subclass for PluginRegistry ────────────

    def to_plugin_class(self) -> Type[ScannerPlugin]:
        """
        يحوّل الـ ScannerSDK لـ ScannerPlugin متوافق مع PluginRegistry.
        بيُستخدم تلقائياً في register().
        """
        sdk_instance = self
        manifest     = self.manifest

        class _PluginWrapper(ScannerPlugin):
            plugin_info = manifest.to_plugin_info()

            async def scan(self, context: Any) -> List[Any]:
                # context هنا هو ما بيجي من الـ Pipeline
                ctx = _build_context_from_pipeline(context, manifest.plugin_id)
                result = await sdk_instance.run(ctx)
                return result.findings

        _PluginWrapper.__name__     = f"Plugin_{manifest.plugin_id}"
        _PluginWrapper.__qualname__ = f"Plugin_{manifest.plugin_id}"
        return _PluginWrapper

    # ── Register directly ───────────────────────────────────────────────────

    def register(self, registry: PluginRegistry) -> None:
        """سجّل الـ Scanner في الـ PluginRegistry مباشرة."""
        validate_plugin(self)
        plugin_cls = self.to_plugin_class()
        registry.register(plugin_cls)
        self._log.info(f"Registered SDK scanner: {self.manifest.plugin_id}")


def _build_context_from_pipeline(pipeline_context: Any, plugin_id: str) -> SDKContext:
    """بيبني SDKContext من Pipeline Context — bridge بين العالمين."""
    if isinstance(pipeline_context, SDKContext):
        return pipeline_context
    # Try to extract known fields
    ctx = SDKContext(
        scan_id    = getattr(pipeline_context, "scan_id", str(uuid.uuid4())[:8]),
        target_url = getattr(pipeline_context, "target_url", ""),
        profile    = getattr(pipeline_context, "profile", "balanced"),
        endpoints  = getattr(pipeline_context, "endpoints", []),
        config     = getattr(pipeline_context, "config", {}),
        _bus       = getattr(pipeline_context, "bus", None),
        _dm        = getattr(pipeline_context, "dm", None),
        _log       = PlatformLogger(f"SDK:{plugin_id}"),
    )
    return ctx


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD SDK
# ══════════════════════════════════════════════════════════════════════════════

class PayloadSDK:
    """
    SDK لإدارة وتوليد Payloads مع WAF evasion تلقائي.

    مثال:
        sdk = PayloadSDK()
        payloads = sdk.xss(count=10, evasion=True)
        for p in payloads:
            resp = await http.get(url + "?q=" + p)
    """

    # Built-in payload libraries
    _XSS_BASE = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "';alert(1)//",
        '";alert(1)//',
    ]

    _SQLI_BASE = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1; DROP TABLE users--",
        "' UNION SELECT null,null--",
        "1' AND SLEEP(5)--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    ]

    _SSTI_BASE = [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ]

    _CMDI_BASE = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; sleep 5",
        "| whoami",
    ]

    _PATH_TRAVERSAL_BASE = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
    ]

    def __init__(self, enable_evasion: bool = False) -> None:
        self._evasion = enable_evasion

    def xss(self, count: Optional[int] = None, evasion: bool = False) -> List[str]:
        payloads = list(self._XSS_BASE)
        if evasion or self._evasion:
            payloads += self._xss_evasion_variants()
        return payloads[:count] if count else payloads

    def sqli(self, count: Optional[int] = None, technique: str = "all") -> List[str]:
        return list(self._SQLI_BASE[:count] if count else self._SQLI_BASE)

    def ssti(self, count: Optional[int] = None) -> List[str]:
        return list(self._SSTI_BASE[:count] if count else self._SSTI_BASE)

    def cmdi(self, count: Optional[int] = None, os: str = "unix") -> List[str]:
        return list(self._CMDI_BASE[:count] if count else self._CMDI_BASE)

    def path_traversal(self, count: Optional[int] = None) -> List[str]:
        return list(self._PATH_TRAVERSAL_BASE[:count] if count else self._PATH_TRAVERSAL_BASE)

    def custom(self, payloads: List[str], evasion: bool = False) -> List[str]:
        """أضف payloads مخصصة مع evasion اختياري."""
        result = list(payloads)
        if evasion or self._evasion:
            evaded = []
            for p in payloads:
                evaded.extend(self._apply_evasion(p))
            result.extend(evaded)
        return result

    def _xss_evasion_variants(self) -> List[str]:
        return [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script >alert(1)</script >",
            "<scr\x00ipt>alert(1)</scr\x00ipt>",
            "<<script>alert(1)//<</script>",
            "<img src=x onerror=\"alert(1)\">",
        ]

    def _apply_evasion(self, payload: str) -> List[str]:
        """تطبيق تقنيات تجاوز WAF على payload معين."""
        variants = []
        # URL encoding
        import urllib.parse
        variants.append(urllib.parse.quote(payload))
        # Double encoding
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
        # HTML entity encoding
        variants.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
        return variants

    def inject_into_url(self, url: str, payload: str, param: Optional[str] = None) -> str:
        """أدخل payload في URL param محدد أو كل الـ params."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param and param in params:
            params[param] = [payload]
        else:
            params = {k: [payload] for k in (params or {"q": [""]})}
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))


# ══════════════════════════════════════════════════════════════════════════════
# REPORTER SDK
# ══════════════════════════════════════════════════════════════════════════════

class ReporterSDK:
    """
    SDK لبناء Reporters مخصصة لأي format.

    مثال:
        class SlackReporter(ReporterSDK):
            format_name = "slack"

            def render(self, findings: List[SDKFinding], metadata: Dict) -> str:
                blocks = []
                for f in findings:
                    blocks.append({"type": "section", "text": {"type": "mrkdwn",
                        "text": f"*{f.severity.upper()}* — {f.title}"}})
                return json.dumps({"blocks": blocks})
    """

    format_name: str = "custom"
    file_extension: str = ".txt"

    def render(self, findings: List[SDKFinding], metadata: Dict[str, Any]) -> str:
        """Override دي — بتاخد findings وبترجع نص الـ Report."""
        raise NotImplementedError(f"{type(self).__name__} must implement render()")

    def save(self, findings: List[SDKFinding], path: Union[str, Path],
             metadata: Optional[Dict[str, Any]] = None) -> Path:
        """حفظ الـ Report في ملف."""
        output = Path(path)
        if output.is_dir():
            scan_id = (metadata or {}).get("scan_id", "report")
            output  = output / f"webshield_{scan_id}{self.file_extension}"
        content = self.render(findings, metadata or {})
        output.write_text(content, encoding="utf-8")
        return output

    def render_summary(self, findings: List[SDKFinding]) -> str:
        """ملخص سريع — ينفع Override."""
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        lines = [f"Total findings: {len(findings)}"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                lines.append(f"  {sev.upper()}: {counts[sev]}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# WORKFLOW SDK
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SDKWorkflowStep:
    """خطوة في Workflow مخصص."""
    name:         str
    handler:      Callable
    depends_on:   List[str]         = field(default_factory=list)
    condition:    Optional[Callable] = None   # fn(ctx) → bool
    timeout_sec:  int               = 60
    retry_count:  int               = 0


class WorkflowSDK:
    """
    SDK لبناء Workflows مخصصة من غير ما تفهم WorkflowEngine الداخلي.

    مثال:
        wf = WorkflowSDK("api_security_workflow")
        wf.step("discovery",    handler=discover_endpoints)
        wf.step("auth_check",   handler=check_auth,   depends_on=["discovery"])
        wf.step("rate_limit",   handler=test_limits,  depends_on=["auth_check"],
                condition=lambda ctx: ctx.has_tech("api"))
        await wf.run(ctx)
    """

    def __init__(self, workflow_id: str, description: str = "") -> None:
        self.workflow_id  = workflow_id
        self.description  = description
        self._steps:  List[SDKWorkflowStep]   = []
        self._log     = PlatformLogger(f"WorkflowSDK:{workflow_id}")

    def step(self, name: str, handler: Callable,
             depends_on: Optional[List[str]] = None,
             condition: Optional[Callable] = None,
             timeout_sec: int = 60,
             retry_count: int = 0) -> "WorkflowSDK":
        """أضف خطوة للـ Workflow — fluent API."""
        self._steps.append(SDKWorkflowStep(
            name        = name,
            handler     = handler,
            depends_on  = depends_on or [],
            condition   = condition,
            timeout_sec = timeout_sec,
            retry_count = retry_count,
        ))
        return self

    async def run(self, ctx: SDKContext) -> Dict[str, Any]:
        """شغّل الـ Workflow خطوة خطوة حسب الـ dependencies."""
        import asyncio
        completed: Dict[str, Any] = {}
        remaining = list(self._steps)
        max_iterations = len(remaining) * 2

        iterations = 0
        while remaining:
            iterations += 1
            if iterations > max_iterations:
                break

            runnable = [
                s for s in remaining
                if all(dep in completed for dep in s.depends_on)
            ]
            if not runnable:
                skipped = [s.name for s in remaining]
                self._log.warning(f"Workflow stalled — skipping: {skipped}")
                break

            for step in runnable:
                remaining.remove(step)

                # تحقق من الـ condition
                if step.condition and not step.condition(ctx):
                    self._log.debug(f"Step '{step.name}' skipped (condition=False)")
                    completed[step.name] = None
                    continue

                self._log.debug(f"Running step '{step.name}'")
                start = time.monotonic()
                try:
                    if inspect.iscoroutinefunction(step.handler):
                        result = await asyncio.wait_for(
                            step.handler(ctx),
                            timeout=step.timeout_sec,
                        )
                    else:
                        result = step.handler(ctx)
                    completed[step.name] = result
                    ctx.emit(f"workflow.step.complete", data={"step": step.name,
                             "duration_ms": (time.monotonic() - start) * 1000})
                except Exception as exc:
                    self._log.error(f"Step '{step.name}' failed: {exc}")
                    completed[step.name] = {"error": str(exc)}
                    ctx.emit("workflow.step.error", data={"step": step.name, "error": str(exc)})

        return completed

    @property
    def step_count(self) -> int:
        return len(self._steps)

    @property
    def step_names(self) -> List[str]:
        return [s.name for s in self._steps]


# ══════════════════════════════════════════════════════════════════════════════
# PLUGIN VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_plugin(scanner: ScannerSDK) -> None:
    """
    بيتحقق من إن الـ Plugin صحيح قبل التسجيل.
    بيرمي PluginValidationError لو في مشكلة.
    """
    m = scanner.manifest
    errors: List[str] = []

    if not m.plugin_id:
        errors.append("plugin_id is required")
    if not m.name:
        errors.append("name is required")
    if not m.version or not _is_semver(m.version):
        errors.append(f"version must be semver (e.g. '1.0.0'), got: {m.version!r}")
    if not hasattr(scanner, "run"):
        errors.append("run() method is required")
    elif not inspect.iscoroutinefunction(scanner.run):
        errors.append("run() must be async")

    run_sig = inspect.signature(scanner.run)
    if "ctx" not in run_sig.parameters:
        errors.append("run(ctx, ...) must accept 'ctx' as first parameter")

    if errors:
        raise PluginValidationError(
            f"Plugin '{m.plugin_id}' validation failed:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )


def _is_semver(version: str) -> bool:
    """تحقق بسيط من صيغة SemVer."""
    parts = version.split(".")
    if len(parts) != 3:
        return False
    return all(p.isdigit() for p in parts)


# ══════════════════════════════════════════════════════════════════════════════
# SDK BUILDER (Fluent API شاملة)
# ══════════════════════════════════════════════════════════════════════════════

class SDKBuilder:
    """
    Fluent API لبناء Scanner Plugin بشكل كامل في خطوات واضحة.

    مثال:
        scanner = (
            SDKBuilder()
            .plugin_id("my_sqli")
            .name("My SQLi Scanner")
            .version("1.0.0")
            .description("Detects SQL injection")
            .author("Your Name")
            .tags(["sqli", "injection"])
            .scan_logic(my_scan_function)
            .build()
        )
        scanner.register(registry)
    """

    def __init__(self) -> None:
        self._manifest = PluginManifest(plugin_id="", name="")
        self._fn: Optional[Callable] = None

    def plugin_id(self, pid: str) -> "SDKBuilder":
        self._manifest.plugin_id = pid;  return self

    def name(self, n: str) -> "SDKBuilder":
        self._manifest.name = n;  return self

    def version(self, v: str) -> "SDKBuilder":
        self._manifest.version = v;  return self

    def description(self, d: str) -> "SDKBuilder":
        self._manifest.description = d;  return self

    def author(self, a: str) -> "SDKBuilder":
        self._manifest.author = a;  return self

    def tags(self, t: List[str]) -> "SDKBuilder":
        self._manifest.tags = t;  return self

    def requires_tech(self, techs: List[str]) -> "SDKBuilder":
        self._manifest.requires = techs;  return self

    def scan_logic(self, fn: Callable) -> "SDKBuilder":
        """الدالة اللي بتنفذ الـ Scan — async def fn(ctx, result)."""
        self._fn = fn;  return self

    def build(self) -> ScannerSDK:
        if not self._manifest.plugin_id:
            raise SDKError("plugin_id is required")
        if not self._fn:
            raise SDKError("scan_logic is required")

        decorator = ScannerSDK.scanner(
            plugin_id   = self._manifest.plugin_id,
            name        = self._manifest.name,
            version     = self._manifest.version,
            description = self._manifest.description,
            author      = self._manifest.author,
        )
        cls = decorator(self._fn)
        instance = cls()
        validate_plugin(instance)
        return instance


# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS
# ══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Errors
    "SDKError", "PluginValidationError",
    # Result types
    "SDKSeverity", "SDKFinding", "SDKResult",
    # Context
    "SDKContext",
    # Manifest
    "PluginManifest",
    # Scanner SDK
    "ScannerSDK",
    # Payload SDK
    "PayloadSDK",
    # Reporter SDK
    "ReporterSDK",
    # Workflow SDK
    "WorkflowSDK", "SDKWorkflowStep",
    # Validation
    "validate_plugin",
    # Builder
    "SDKBuilder",
]
