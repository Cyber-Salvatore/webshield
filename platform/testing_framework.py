"""
WebShield Testing Framework
================================================
إطار الاختبار الشامل لـ WebShield Platform:

    - TestRunner          : تشغيل الـ Tests وجمع النتائج
    - MockHTTPClient      : عميل HTTP وهمي للاختبار بدون اتصال حقيقي
    - MockEventBus        : Event Bus وهمي يسجل كل الأحداث
    - ScanTestHarness     : بيئة اختبار كاملة لـ Scan Scenarios
    - PerformanceProfiler : قياس أداء المكونات
    - RegressionTracker   : تتبع مقاييس الأداء بين الإصدارات
    - TestFixtureFactory  : مصنع بيانات الاختبار الجاهزة

الاستخدام:
    harness = ScanTestHarness()
    harness.add_mock_response("https://target.com", status=200, body="<html>")
    result = await harness.run_pipeline_stage("discovery")
    assert result.success
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Testing Framework                      ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ║  All rights reserved. For authorized security research only.            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import inspect
import time
import traceback
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from .logging_system import PlatformLogger
from .error_framework import WebShieldError


# ══════════════════════════════════════════════════════════════════════════════
# TEST RESULT TYPES
# ══════════════════════════════════════════════════════════════════════════════

class TestStatus(str, Enum):
    PASSED  = "PASSED"
    FAILED  = "FAILED"
    ERROR   = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class TestResult:
    """نتيجة اختبار واحد."""
    name:        str
    status:      TestStatus
    duration_ms: float      = 0.0
    message:     str        = ""
    traceback:   str        = ""
    category:    str        = ""
    tags:        List[str]  = field(default_factory=list)

    @property
    def passed(self)  -> bool: return self.status == TestStatus.PASSED
    @property
    def failed(self)  -> bool: return self.status == TestStatus.FAILED
    @property
    def errored(self) -> bool: return self.status == TestStatus.ERROR
    @property
    def skipped(self) -> bool: return self.status == TestStatus.SKIPPED


@dataclass
class SuiteResult:
    """نتائج مجموعة اختبارات كاملة."""
    suite_name:   str
    results:      List[TestResult] = field(default_factory=list)
    started_at:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at:  str = ""
    total_ms:     float = 0.0

    @property
    def passed(self)  -> int: return sum(1 for r in self.results if r.passed)
    @property
    def failed(self)  -> int: return sum(1 for r in self.results if r.failed)
    @property
    def errored(self) -> int: return sum(1 for r in self.results if r.errored)
    @property
    def skipped(self) -> int: return sum(1 for r in self.results if r.skipped)
    @property
    def total(self)   -> int: return len(self.results)
    @property
    def all_passed(self) -> bool:
        return all(r.passed or r.skipped for r in self.results)

    def summary(self) -> str:
        ok = "✓" if self.all_passed else "✗"
        return (
            f"{ok} {self.suite_name}: "
            f"{self.passed} passed, {self.failed} failed, "
            f"{self.errored} errors, {self.skipped} skipped "
            f"({self.total_ms:.0f} ms)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TEST RUNNER
# ══════════════════════════════════════════════════════════════════════════════

class TestRunner:
    """
    تشغيل الاختبارات وجمع النتائج — يشتغل مع pytest وبدونه.

    يكتشف تلقائياً إذا الـ method async أو sync.
    يدعم skip، xfail، وparametrize عن طريق decorators.
    """

    def __init__(self, logger: Optional[PlatformLogger] = None) -> None:
        self._log   = logger or PlatformLogger("TestRunner")
        self._suites: List[SuiteResult] = []

    # ── تشغيل Test Class ──────────────────────────────────────────────────────

    def run_class(self, cls: Type, tmp_path: Optional[Path] = None) -> SuiteResult:
        """شغّل كل methods الـ Test Class وإرجع النتائج."""
        suite = SuiteResult(suite_name=cls.__name__)
        start = time.monotonic()

        instance = cls()
        methods  = [
            (name, method)
            for name, method in inspect.getmembers(instance, predicate=inspect.ismethod)
            if name.startswith("test_")
        ]

        for name, method in methods:
            result = self._run_one(name, method, cls.__name__, tmp_path=tmp_path)
            suite.results.append(result)
            icon = "✓" if result.passed else ("S" if result.skipped else "✗")
            self._log.debug(f"  {icon} {name}  ({result.duration_ms:.1f} ms)")

        suite.total_ms  = (time.monotonic() - start) * 1000
        suite.finished_at = datetime.now(timezone.utc).isoformat()
        self._suites.append(suite)
        return suite

    # ── تشغيل اختبار واحد ────────────────────────────────────────────────────

    def _run_one(
        self,
        name:     str,
        method:   Callable,
        category: str = "",
        tmp_path: Optional[Path] = None,
    ) -> TestResult:
        """شغّل اختبار واحد وإرجع نتيجته."""

        # تحقق من skip marker
        skip_reason = getattr(method, "_skip_reason", None)
        if skip_reason:
            return TestResult(name=name, status=TestStatus.SKIPPED,
                              message=skip_reason, category=category)

        start = time.monotonic()
        try:
            sig   = inspect.signature(method)
            params: Dict[str, Any] = {}
            if "tmp_path" in sig.parameters:
                if tmp_path is None:
                    import tempfile
                    tmp_path = Path(tempfile.mkdtemp(prefix="ws_test_"))
                params["tmp_path"] = tmp_path

            if inspect.iscoroutinefunction(method):
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_closed():
                        raise RuntimeError("closed")
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                loop.run_until_complete(method(**params))
            else:
                method(**params)

            duration = (time.monotonic() - start) * 1000
            return TestResult(name=name, status=TestStatus.PASSED,
                              duration_ms=duration, category=category)

        except AssertionError as exc:
            duration = (time.monotonic() - start) * 1000
            return TestResult(
                name=name, status=TestStatus.FAILED,
                duration_ms=duration, category=category,
                message=str(exc), traceback=traceback.format_exc(),
            )
        except Exception as exc:
            duration = (time.monotonic() - start) * 1000
            return TestResult(
                name=name, status=TestStatus.ERROR,
                duration_ms=duration, category=category,
                message=f"{type(exc).__name__}: {exc}",
                traceback=traceback.format_exc(),
            )

    # ── تشغيل دالة مستقلة ────────────────────────────────────────────────────

    def run_function(self, fn: Callable, tmp_path: Optional[Path] = None) -> TestResult:
        """شغّل دالة اختبار مستقلة (مش method في class)."""
        result = self._run_one(fn.__name__, fn, tmp_path=tmp_path)
        self._suites.append(SuiteResult(suite_name=fn.__name__, results=[result]))
        return result

    # ── ملخص كل النتائج ──────────────────────────────────────────────────────

    def global_summary(self) -> str:
        total   = sum(s.total   for s in self._suites)
        passed  = sum(s.passed  for s in self._suites)
        failed  = sum(s.failed  for s in self._suites)
        errored = sum(s.errored for s in self._suites)
        skipped = sum(s.skipped for s in self._suites)
        ms      = sum(s.total_ms for s in self._suites)
        ok      = "✓" if failed == 0 and errored == 0 else "✗"
        return (
            f"\n{ok} {passed}/{total} passed | "
            f"{failed} failed | {errored} errors | {skipped} skipped "
            f"| {ms:.0f} ms total"
        )


# ══════════════════════════════════════════════════════════════════════════════
# DECORATORS للـ Tests
# ══════════════════════════════════════════════════════════════════════════════

def skip(reason: str = ""):
    """Skip decorator — نفس API بتاع pytest.mark.skip."""
    def decorator(fn: Callable) -> Callable:
        fn._skip_reason = reason or "skipped"  # type: ignore[attr-defined]
        return fn
    return decorator


def skip_if(condition: bool, reason: str = ""):
    """Skip لو الشرط صح — نفس pytest.mark.skipif."""
    def decorator(fn: Callable) -> Callable:
        if condition:
            fn._skip_reason = reason or "condition met"  # type: ignore[attr-defined]
        return fn
    return decorator


# ══════════════════════════════════════════════════════════════════════════════
# MOCK HTTP CLIENT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MockResponse:
    """رد HTTP وهمي."""
    status_code:  int              = 200
    body:         str              = ""
    headers:      Dict[str, str]   = field(default_factory=dict)
    content_type: str              = "text/html"
    latency_ms:   float            = 0.0
    error:        Optional[str]    = None

    @property
    def text(self) -> str: return self.body
    @property
    def content(self) -> bytes: return self.body.encode()


class MockHTTPClient:
    """
    عميل HTTP وهمي للاختبار بدون اتصال شبكي حقيقي.

    بيحفظ كل الـ Requests المُرسلة ويرجع Responses محددة مسبقاً.
    يدعم: static responses, dynamic callbacks, error simulation.
    """

    def __init__(self) -> None:
        self._routes:   Dict[str, MockResponse]      = {}
        self._defaults: Dict[str, MockResponse]      = {}
        self._callbacks: Dict[str, Callable]         = {}
        self.requests:  List[Dict[str, Any]]         = []
        self._error_rate: float                      = 0.0
        self._call_count: int                        = 0

    # ── إعداد الـ Responses ──────────────────────────────────────────────────

    def add_response(
        self,
        url:          str,
        status:       int              = 200,
        body:         str              = "",
        headers:      Optional[Dict]   = None,
        content_type: str              = "text/html",
        latency_ms:   float            = 0.0,
    ) -> "MockHTTPClient":
        """أضف رد لـ URL محدد."""
        self._routes[url] = MockResponse(
            status_code=status,
            body=body,
            headers=headers or {},
            content_type=content_type,
            latency_ms=latency_ms,
        )
        return self

    def add_default(self, status: int = 200, body: str = "") -> "MockHTTPClient":
        """رد افتراضي لأي URL مش محدد."""
        self._defaults["*"] = MockResponse(status_code=status, body=body)
        return self

    def add_error(self, url: str, error: str = "Connection refused") -> "MockHTTPClient":
        """محاكاة خطأ اتصال لـ URL محدد."""
        self._routes[url] = MockResponse(error=error)
        return self

    def set_error_rate(self, rate: float) -> "MockHTTPClient":
        """محاكاة أخطاء عشوائية بنسبة معينة (0.0 → 1.0)."""
        self._error_rate = max(0.0, min(1.0, rate))
        return self

    def add_callback(self, url: str, fn: Callable) -> "MockHTTPClient":
        """استخدم دالة للرد الديناميكي بدلاً من response ثابت."""
        self._callbacks[url] = fn
        return self

    # ── تنفيذ الطلبات ────────────────────────────────────────────────────────

    async def get(self, url: str, **kwargs: Any) -> MockResponse:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> MockResponse:
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> MockResponse:
        return await self._request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> MockResponse:
        return await self._request("DELETE", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> MockResponse:
        self._call_count += 1
        record = {
            "method": method,
            "url":    url,
            "kwargs": kwargs,
            "seq":    self._call_count,
            "ts":     time.time(),
        }
        self.requests.append(record)

        # Dynamic callback
        if url in self._callbacks:
            resp = self._callbacks[url](record)
            if inspect.iscoroutine(resp):
                resp = await resp
            return resp

        # Static route
        response = self._routes.get(url) or self._defaults.get("*") or MockResponse(status_code=404)

        if response.error:
            raise ConnectionError(response.error)

        if response.latency_ms > 0:
            await asyncio.sleep(response.latency_ms / 1000)

        return response

    # ── إحصائيات ────────────────────────────────────────────────────────────

    def was_called(self, url: str, method: str = "") -> bool:
        for r in self.requests:
            if r["url"] == url:
                if not method or r["method"].upper() == method.upper():
                    return True
        return False

    def call_count_for(self, url: str) -> int:
        return sum(1 for r in self.requests if r["url"] == url)

    def reset(self) -> None:
        self.requests.clear()
        self._call_count = 0


# ══════════════════════════════════════════════════════════════════════════════
# MOCK EVENT BUS
# ══════════════════════════════════════════════════════════════════════════════

class MockEventBus:
    """
    EventBus وهمي يسجل كل الأحداث المُرسلة — للتحقق من سلوك الـ Modules.

    يمكّن assertions زي:
        assert bus.was_emitted("tech.detected.laravel")
        assert bus.count("scan.finding") == 3
    """

    def __init__(self) -> None:
        self.events:   List[Dict[str, Any]]               = []
        self._handlers: Dict[str, List[Callable]]         = defaultdict(list)

    # ── Emit ─────────────────────────────────────────────────────────────────

    def emit_sync(self, name: str, data: Any = None, **kwargs: Any) -> None:
        self._record(name, data, kwargs)
        self._dispatch(name, data)

    async def emit(self, name: str, data: Any = None, **kwargs: Any) -> None:
        self._record(name, data, kwargs)
        await self._dispatch_async(name, data)

    def _record(self, name: str, data: Any, extra: Dict) -> None:
        self.events.append({
            "name":  name,
            "data":  data,
            "extra": extra,
            "ts":    time.time(),
        })

    def _dispatch(self, name: str, data: Any) -> None:
        for pattern, handlers in self._handlers.items():
            if self._matches(pattern, name):
                for h in handlers:
                    if not inspect.iscoroutinefunction(h):
                        h(type("Event", (), {"name": name, "data": data})())

    async def _dispatch_async(self, name: str, data: Any) -> None:
        for pattern, handlers in self._handlers.items():
            if self._matches(pattern, name):
                for h in handlers:
                    ev = type("Event", (), {"name": name, "data": data})()
                    if inspect.iscoroutinefunction(h):
                        await h(ev)
                    else:
                        h(ev)

    @staticmethod
    def _matches(pattern: str, name: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            return name.startswith(pattern[:-2])
        return pattern == name

    # ── Subscriptions ────────────────────────────────────────────────────────

    def on(self, pattern: str, handler: Callable) -> None:
        self._handlers[pattern].append(handler)

    # ── Assertions ───────────────────────────────────────────────────────────

    def was_emitted(self, name: str) -> bool:
        return any(e["name"] == name for e in self.events)

    def count(self, name: str) -> int:
        return sum(1 for e in self.events if e["name"] == name)

    def last(self, name: str) -> Optional[Dict[str, Any]]:
        for e in reversed(self.events):
            if e["name"] == name:
                return e
        return None

    def all_events(self, name: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["name"] == name]

    def reset(self) -> None:
        self.events.clear()
        self._handlers.clear()


# ══════════════════════════════════════════════════════════════════════════════
# SCAN TEST HARNESS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class HarnessResult:
    """نتيجة تشغيل Harness."""
    success:   bool
    stage:     str
    duration_ms: float
    findings:  List[Any]       = field(default_factory=list)
    events:    List[str]       = field(default_factory=list)
    error:     Optional[str]   = None


class ScanTestHarness:
    """
    بيئة اختبار كاملة تجمع كل مكونات الـ Platform في سياق Scan واحد.

    مثال:
        harness = ScanTestHarness()
        harness.add_mock_response("https://target.com", body="<h1>Test</h1>")
        result = await harness.run_full_discovery()
        assert result.success
        assert harness.bus.was_emitted("discovery.complete")
    """

    def __init__(self, target_url: str = "https://test.example.com") -> None:
        self.target_url  = target_url
        self.http        = MockHTTPClient()
        self.bus         = MockEventBus()
        self.scan_id     = str(uuid.uuid4())[:8]
        self._findings:  List[Any] = []
        self._log        = PlatformLogger(f"Harness:{self.scan_id}")

    # ── Setup ────────────────────────────────────────────────────────────────

    def add_mock_response(
        self,
        path_or_url: str,
        status:  int  = 200,
        body:    str  = "",
        headers: Optional[Dict] = None,
    ) -> "ScanTestHarness":
        url = path_or_url if path_or_url.startswith("http") else self.target_url + path_or_url
        self.http.add_response(url, status=status, body=body, headers=headers)
        return self

    def simulate_tech(self, tech: str) -> "ScanTestHarness":
        """محاكاة اكتشاف تقنية معينة عبر الـ EventBus."""
        self.bus.emit_sync(f"tech.detected.{tech.lower()}", data={"tech": tech})
        return self

    def add_finding(self, finding: Any) -> "ScanTestHarness":
        self._findings.append(finding)
        self.bus.emit_sync("scan.finding", data=finding)
        return self

    # ── تشغيل سيناريوهات ─────────────────────────────────────────────────────

    async def run_pipeline_stage(self, stage_name: str) -> HarnessResult:
        """محاكاة تشغيل مرحلة Pipeline."""
        start = time.monotonic()
        try:
            self.bus.emit_sync(f"pipeline.stage.start", data={"stage": stage_name})
            # Simulate some async work
            await asyncio.sleep(0)
            self.bus.emit_sync(f"pipeline.stage.complete", data={"stage": stage_name})
            ms = (time.monotonic() - start) * 1000
            return HarnessResult(
                success=True, stage=stage_name, duration_ms=ms,
                findings=list(self._findings),
                events=[e["name"] for e in self.bus.events],
            )
        except Exception as exc:
            ms = (time.monotonic() - start) * 1000
            return HarnessResult(
                success=False, stage=stage_name, duration_ms=ms,
                error=str(exc),
            )

    async def run_full_discovery(self) -> HarnessResult:
        """سيناريو Discovery كامل."""
        stages = ["discovery", "fingerprinting", "baseline"]
        for stage in stages:
            r = await self.run_pipeline_stage(stage)
            if not r.success:
                return r
        return HarnessResult(
            success=True, stage="full_discovery",
            duration_ms=sum(e.get("ts", 0) for e in self.bus.events),
            events=[e["name"] for e in self.bus.events],
        )

    def reset(self) -> None:
        self.http.reset()
        self.bus.reset()
        self._findings.clear()


# ══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE PROFILER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProfileEntry:
    name:       str
    duration_ms: float
    memory_kb:  float = 0.0
    iterations: int   = 1

    @property
    def per_iteration_ms(self) -> float:
        return self.duration_ms / max(1, self.iterations)


class PerformanceProfiler:
    """
    قياس أداء المكونات — للتأكد من إن كل عملية أسرع من حد معين.

    مثال:
        profiler = PerformanceProfiler()
        with profiler.measure("cache_lookup"):
            cache.get("key")
        profiler.assert_under("cache_lookup", ms=1)
    """

    def __init__(self) -> None:
        self._entries: List[ProfileEntry] = []
        self._active:  Dict[str, float]   = {}

    def start(self, name: str) -> None:
        self._active[name] = time.monotonic()

    def stop(self, name: str, iterations: int = 1) -> ProfileEntry:
        if name not in self._active:
            raise ValueError(f"profiler: '{name}' was never started")
        elapsed = (time.monotonic() - self._active.pop(name)) * 1000
        entry   = ProfileEntry(name=name, duration_ms=elapsed, iterations=iterations)
        self._entries.append(entry)
        return entry

    class _Context:
        def __init__(self, profiler: "PerformanceProfiler", name: str, iterations: int) -> None:
            self._p          = profiler
            self._name       = name
            self._iterations = iterations
            self.entry: Optional[ProfileEntry] = None

        def __enter__(self) -> "_Context":
            self._p.start(self._name)
            return self

        def __exit__(self, *_: Any) -> None:
            self.entry = self._p.stop(self._name, self._iterations)

    def measure(self, name: str, iterations: int = 1) -> "_Context":
        return self._Context(self, name, iterations)

    def assert_under(self, name: str, ms: float) -> ProfileEntry:
        entry = next((e for e in self._entries if e.name == name), None)
        if entry is None:
            raise AssertionError(f"profiler: no entry named '{name}'")
        assert entry.per_iteration_ms <= ms, (
            f"Performance: '{name}' took {entry.per_iteration_ms:.2f} ms "
            f"(limit: {ms} ms)"
        )
        return entry

    def summary(self) -> List[str]:
        return [
            f"  {e.name}: {e.per_iteration_ms:.2f} ms/iter "
            f"({'×'+str(e.iterations) if e.iterations > 1 else ''})"
            for e in self._entries
        ]


# ══════════════════════════════════════════════════════════════════════════════
# REGRESSION TRACKER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RegressionBaseline:
    """بيانات Baseline لمقياس أداء — للمقارنة بين الإصدارات."""
    name:       str
    value:      float
    tolerance:  float   = 0.10      # 10% tolerance by default
    recorded_at: str    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RegressionTracker:
    """
    تتبع مقاييس الأداء بين الإصدارات — يكتشف رجوع في الأداء.

    مثال:
        tracker = RegressionTracker()
        tracker.set_baseline("scan_throughput_rps", 50.0)
        tracker.check("scan_throughput_rps", current=48.0)  # 4% under → pass
        tracker.check("scan_throughput_rps", current=30.0)  # 40% under → fail
    """

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self._baselines: Dict[str, RegressionBaseline] = {}
        self._results:   List[Dict[str, Any]]           = []
        self._path       = storage_path

    def set_baseline(self, name: str, value: float, tolerance: float = 0.10) -> None:
        self._baselines[name] = RegressionBaseline(
            name=name, value=value, tolerance=tolerance
        )

    def check(self, name: str, current: float) -> bool:
        """
        تحقق إن المقياس الحالي في حدود الـ Baseline.
        بيرجع True لو كويس، False لو رجوع في الأداء.
        """
        if name not in self._baselines:
            raise ValueError(f"regression: no baseline for '{name}'")

        bl   = self._baselines[name]
        diff = (current - bl.value) / bl.value if bl.value != 0 else 0
        ok   = abs(diff) <= bl.tolerance or current >= bl.value

        self._results.append({
            "name":      name,
            "baseline":  bl.value,
            "current":   current,
            "diff_pct":  diff * 100,
            "passed":    ok,
        })
        return ok

    def assert_no_regression(self, name: str, current: float) -> None:
        if not self.check(name, current):
            bl  = self._baselines[name]
            pct = abs((current - bl.value) / bl.value) * 100
            raise AssertionError(
                f"Regression: '{name}' dropped {pct:.1f}% "
                f"(baseline={bl.value}, current={current}, tolerance={bl.tolerance*100:.0f}%)"
            )

    def report(self) -> List[str]:
        lines = []
        for r in self._results:
            ok  = "✓" if r["passed"] else "✗"
            lines.append(
                f"  {ok} {r['name']}: {r['current']:.2f} "
                f"(baseline={r['baseline']:.2f}, diff={r['diff_pct']:+.1f}%)"
            )
        return lines


# ══════════════════════════════════════════════════════════════════════════════
# TEST FIXTURE FACTORY
# ══════════════════════════════════════════════════════════════════════════════

class TestFixtureFactory:
    """
    مصنع بيانات الاختبار الجاهزة (Fixtures) — بيولّد بيانات واقعية للاختبار.

    الاستخدام:
        factory = TestFixtureFactory()
        endpoint = factory.endpoint(url="/api/users", method="POST")
        finding  = factory.finding(severity="high", vuln_type="sqli")
        config   = factory.scan_config(profile="quick", target="https://example.com")
    """

    _counter: int = 0

    @classmethod
    def _next_id(cls) -> str:
        cls._counter += 1
        return f"fixture_{cls._counter:04d}"

    # ── Endpoints ────────────────────────────────────────────────────────────

    def endpoint(
        self,
        url:    str            = "/",
        method: str            = "GET",
        params: Optional[Dict] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        return {
            "id":     self._next_id(),
            "url":    url,
            "method": method.upper(),
            "params": params or {},
            "status": 200,
            **extra,
        }

    def endpoint_list(self, count: int = 5, base_path: str = "/api") -> List[Dict[str, Any]]:
        paths   = ["users", "products", "orders", "auth/login", "search",
                   "admin", "files", "config", "health", "metrics"]
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        return [
            self.endpoint(
                url    = f"{base_path}/{paths[i % len(paths)]}",
                method = methods[i % len(methods)],
            )
            for i in range(count)
        ]

    # ── Findings ────────────────────────────────────────────────────────────

    def finding(
        self,
        severity:  str = "medium",
        vuln_type: str = "xss",
        url:       str = "/vulnerable",
        **extra: Any,
    ) -> Dict[str, Any]:
        return {
            "id":       self._next_id(),
            "severity": severity,
            "type":     vuln_type,
            "url":      url,
            "title":    f"{vuln_type.upper()} in {url}",
            "evidence": f"Payload triggered in {url}",
            **extra,
        }

    def finding_list(self, count: int = 3) -> List[Dict[str, Any]]:
        severities = ["critical", "high", "medium", "low", "info"]
        types      = ["sqli", "xss", "csrf", "idor", "ssrf"]
        return [
            self.finding(
                severity  = severities[i % len(severities)],
                vuln_type = types[i % len(types)],
                url       = f"/endpoint_{i}",
            )
            for i in range(count)
        ]

    # ── Scan Config ──────────────────────────────────────────────────────────

    def scan_config(
        self,
        profile: str = "balanced",
        target:  str = "https://example.com",
        **extra: Any,
    ) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "profile":      profile,
            "target":       target,
            "concurrency":  10,
            "timeout":      30,
            "max_depth":    5,
            "rate_limit":   10,
            "auth":         None,
        }
        base.update(extra)
        return base

    # ── HTTP Request/Response ────────────────────────────────────────────────

    def http_request(
        self,
        url:    str = "/test",
        method: str = "GET",
        body:   str = "",
        **headers: str,
    ) -> Dict[str, Any]:
        return {
            "id":      self._next_id(),
            "url":     url,
            "method":  method.upper(),
            "body":    body,
            "headers": {
                "User-Agent":   "WebShield/4.0",
                "Content-Type": "application/json",
                **headers,
            },
        }

    def http_response(
        self,
        status: int  = 200,
        body:   str  = "",
        **headers: str,
    ) -> Dict[str, Any]:
        return {
            "status":  status,
            "body":    body,
            "headers": {
                "Content-Type": "text/html",
                **headers,
            },
            "size":    len(body),
        }

    # ── Plugin Config ────────────────────────────────────────────────────────

    def plugin_config(self, name: str = "test_scanner", **overrides: Any) -> Dict[str, Any]:
        base = {
            "name":     name,
            "version":  "1.0.0",
            "enabled":  True,
            "priority": 50,
            "timeout":  30,
        }
        base.update(overrides)
        return base


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TEST BASE CLASS
# ══════════════════════════════════════════════════════════════════════════════

class IntegrationTestBase:
    """
    Base class لـ Integration Tests — يوفر setup/teardown آلي لكل Platform Components.

    الاستخدام (ينفع مع pytest وبدونه):

        class TestMyScanner(IntegrationTestBase):
            async def test_scanner_emits_finding(self):
                endpoint = self.fixtures.endpoint(url="/login")
                self.harness.add_mock_response("/login", body="<form>Login</form>")
                result = await self.harness.run_pipeline_stage("active_testing")
                assert result.success
    """

    def setup_method(self, method: Optional[Callable] = None) -> None:
        """يتم استدعاؤه قبل كل test (pytest style)."""
        self.fixtures  = TestFixtureFactory()
        self.harness   = ScanTestHarness()
        self.profiler  = PerformanceProfiler()
        self.regression = RegressionTracker()
        self._setup()

    def _setup(self) -> None:
        """Override للـ Setup المخصص."""

    def teardown_method(self, method: Optional[Callable] = None) -> None:
        """يتم استدعاؤه بعد كل test (pytest style)."""
        self.harness.reset()
        self._teardown()

    def _teardown(self) -> None:
        """Override للـ Teardown المخصص."""

    # حتى لو مش بيستخدم pytest، الـ setup يتعمل تلقائياً
    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Wrap كل test methods عشان تعمل setup/teardown
        for name in list(vars(cls)):
            if name.startswith("test_"):
                original = getattr(cls, name)
                setattr(cls, name, cls._wrap_test(original))

    @staticmethod
    def _wrap_test(fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):
            async def async_wrapper(self: "IntegrationTestBase", **kw: Any) -> Any:
                self.setup_method(fn)
                try:
                    return await fn(self, **kw)
                finally:
                    self.teardown_method(fn)
            async_wrapper.__name__ = fn.__name__
            return async_wrapper
        else:
            def sync_wrapper(self: "IntegrationTestBase", **kw: Any) -> Any:
                self.setup_method(fn)
                try:
                    return fn(self, **kw)
                finally:
                    self.teardown_method(fn)
            sync_wrapper.__name__ = fn.__name__
            return sync_wrapper


# ══════════════════════════════════════════════════════════════════════════════
# ASSERTION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def assert_dict_subset(subset: Dict, full: Dict, msg: str = "") -> None:
    """تأكد إن كل keys في subset موجودة ومتطابقة في full."""
    for k, v in subset.items():
        assert k in full, f"Key '{k}' missing from dict. {msg}"
        assert full[k] == v, f"Key '{k}': expected {v!r}, got {full[k]!r}. {msg}"


def assert_contains_sensitive(text: str, secret: str) -> None:
    """تأكد إن السر مش موجود في النص (للاختبار الأمني)."""
    assert secret not in text, (
        f"Security: sensitive value found in output! "
        f"First 20 chars: {text[:20]!r}..."
    )


def assert_event_order(bus: MockEventBus, expected_order: List[str]) -> None:
    """تأكد إن الـ Events اتعملت بالترتيب الصح."""
    emitted = [e["name"] for e in bus.events if e["name"] in expected_order]
    # Keep only first occurrence
    seen, ordered = set(), []
    for e in emitted:
        if e not in seen:
            seen.add(e)
            ordered.append(e)
    assert ordered == expected_order, (
        f"Event order mismatch.\n"
        f"Expected: {expected_order}\n"
        f"Got:      {ordered}"
    )


def assert_response_redacted(response_text: str, secrets: List[str]) -> None:
    """تأكد إن كل الـ Secrets اتمسحت من الـ Response."""
    for secret in secrets:
        if len(secret) >= 8:  # Short values might not be registered
            assert secret not in response_text, (
                f"Secret leak: '{secret[:4]}...' found in response"
            )


# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS
# ══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Test Result Types
    "TestStatus", "TestResult", "SuiteResult",
    # Test Runner
    "TestRunner",
    # Decorators
    "skip", "skip_if",
    # Mocks
    "MockHTTPClient", "MockResponse",
    "MockEventBus",
    # Harness
    "ScanTestHarness", "HarnessResult",
    # Performance
    "PerformanceProfiler", "ProfileEntry",
    # Regression
    "RegressionTracker", "RegressionBaseline",
    # Fixtures
    "TestFixtureFactory",
    # Base Class
    "IntegrationTestBase",
    # Assertion Helpers
    "assert_dict_subset",
    "assert_contains_sensitive",
    "assert_event_order",
    "assert_response_redacted",
]
