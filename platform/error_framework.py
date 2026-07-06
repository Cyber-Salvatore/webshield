"""
WebShield Error Handling Framework
=====================================
يمنع انهيار الأداة بسبب أي خطأ، ويوفر تتبع واضح لكل مشكلة.

Hierarchy:
    WebShieldError (base)
    ├── ConfigError         (أخطاء الإعدادات)
    ├── PluginError         (أخطاء الـ Plugins)
    ├── NetworkError        (أخطاء الشبكة)
    │   ├── TimeoutError
    │   ├── ConnectionError
    │   └── SSLError
    ├── ScanError           (أخطاء الفحص)
    │   ├── PayloadError
    │   └── ParserError
    ├── AuthError           (أخطاء المصادقة)
    └── ResourceError       (أخطاء الموارد)
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Error Handling Framework                                   ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Type


# ── Error Classes ─────────────────────────────────────────────────────────────

class WebShieldError(Exception):
    """Base exception لكل أخطاء WebShield."""

    def __init__(
        self,
        message: str,
        context: str = "",
        recoverable: bool = True,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context = context
        self.recoverable = recoverable
        self.details = details or {}
        self.timestamp = datetime.utcnow()

    def __str__(self) -> str:
        parts = [self.message]
        if self.context:
            parts.append(f"[Context: {self.context}]")
        return " ".join(parts)


class ConfigError(WebShieldError):
    """خطأ في الإعدادات."""
    def __init__(self, message: str, key: str = "", **kw: Any) -> None:
        super().__init__(message, recoverable=False, **kw)
        self.key = key


class PluginError(WebShieldError):
    """خطأ في Plugin."""
    def __init__(self, message: str, plugin_id: str = "", **kw: Any) -> None:
        super().__init__(message, **kw)
        self.plugin_id = plugin_id


class NetworkError(WebShieldError):
    """أخطاء الشبكة."""
    def __init__(self, message: str, url: str = "", **kw: Any) -> None:
        super().__init__(message, **kw)
        self.url = url


class TimeoutError(NetworkError):
    """انتهاء وقت الاتصال."""
    pass


class ConnectionError(NetworkError):
    """فشل الاتصال."""
    pass


class SSLError(NetworkError):
    """خطأ في شهادة SSL."""
    pass


class ScanError(WebShieldError):
    """خطأ أثناء الفحص."""
    pass


class PayloadError(ScanError):
    """خطأ في بناء أو إرسال الـ Payload."""
    pass


class ParserError(ScanError):
    """خطأ في تحليل الـ Response."""
    pass


class AuthError(WebShieldError):
    """فشل المصادقة."""
    def __init__(self, message: str, recoverable: bool = False, **kw: Any) -> None:
        super().__init__(message, recoverable=recoverable, **kw)


class ResourceError(WebShieldError):
    """نفاد الموارد (ذاكرة، اتصالات، ملفات)."""
    pass


# ── Error Record ──────────────────────────────────────────────────────────────

@dataclass
class ErrorRecord:
    """سجل لكل خطأ حصل أثناء التشغيل."""
    error_type: str
    message: str
    context: str
    timestamp: datetime
    traceback_str: str
    recoverable: bool
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.error_type,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "recoverable": self.recoverable,
            **self.extra,
        }


# ── Retry Policy ──────────────────────────────────────────────────────────────

@dataclass
class RetryPolicy:
    """سياسة إعادة المحاولة عند فشل العمليات."""
    max_attempts: int = 3
    base_delay: float = 1.0       # ثانية
    exponential: bool = True       # تضعيف الوقت مع كل محاولة
    max_delay: float = 30.0
    retryable_errors: tuple = (NetworkError, TimeoutError)

    def delay_for(self, attempt: int) -> float:
        if self.exponential:
            delay = self.base_delay * (2 ** (attempt - 1))
        else:
            delay = self.base_delay
        return min(delay, self.max_delay)


# ── Error Framework ───────────────────────────────────────────────────────────

class ErrorFramework:
    """
    المدير المركزي لمعالجة الأخطاء.
    
    الاستخدام:
        errors = ErrorFramework(logger)
        
        # معالجة آمنة بدون crash
        errors.handle(exception, context="scanning XSS")
        
        # تنفيذ مع إعادة محاولة تلقائية
        result = await errors.with_retry(my_coroutine(), policy=RetryPolicy(max_attempts=3))
        
        # إحصائيات الأخطاء
        stats = errors.get_stats()
    """

    def __init__(self, logger: Any) -> None:
        self._logger = logger
        self._records: List[ErrorRecord] = []
        self._handlers: Dict[Type[Exception], List[Callable]] = {}
        self._fatal_errors: List[ErrorRecord] = []

    # ── Registration ──────────────────────────────────────────────────────────

    def register_handler(
        self,
        error_type: Type[Exception],
        handler: Callable,
    ) -> None:
        """يسجل Handler مخصص لنوع خطأ معين."""
        if error_type not in self._handlers:
            self._handlers[error_type] = []
        self._handlers[error_type].append(handler)

    # ── Core Handle ───────────────────────────────────────────────────────────

    def handle(
        self,
        error: Exception,
        context: str = "",
        reraise: bool = False,
        log_level: str = "error",
    ) -> Optional[ErrorRecord]:
        """
        يتعامل مع أي خطأ بشكل آمن.
        
        - يسجله
        - ينادي الـ Handlers المسجلة
        - لو مش Recoverable يضيفه للـ Fatal list
        - بيرجع ErrorRecord أو None
        """
        tb_str = traceback.format_exc()
        is_recoverable = getattr(error, "recoverable", True)
        
        record = ErrorRecord(
            error_type=type(error).__name__,
            message=str(error),
            context=context,
            timestamp=datetime.utcnow(),
            traceback_str=tb_str,
            recoverable=is_recoverable,
        )
        self._records.append(record)
        
        # Log
        log_fn = getattr(self._logger, log_level, self._logger.error)
        log_fn(
            f"{'⚠' if is_recoverable else '🔴'} {type(error).__name__}: {error}",
            context=context,
        )
        
        if not is_recoverable:
            self._fatal_errors.append(record)
            self._logger.critical(f"Fatal error in: {context}")
        
        # Custom handlers
        for error_type, handlers in self._handlers.items():
            if isinstance(error, error_type):
                for h in handlers:
                    try:
                        h(error, record)
                    except Exception:
                        pass

        if reraise:
            raise error
        
        return record

    # ── Retry ─────────────────────────────────────────────────────────────────

    async def with_retry(
        self,
        coro_func: Callable,
        *args: Any,
        policy: Optional[RetryPolicy] = None,
        context: str = "",
        **kwargs: Any,
    ) -> Any:
        """
        ينفذ coroutine مع إعادة المحاولة التلقائية.
        
        مثال:
            result = await errors.with_retry(
                my_func, url, timeout=10,
                policy=RetryPolicy(max_attempts=3),
                context="fetching target",
            )
        """
        import asyncio

        policy = policy or RetryPolicy()
        last_error: Optional[Exception] = None
        
        for attempt in range(1, policy.max_attempts + 1):
            try:
                return await coro_func(*args, **kwargs)
            except policy.retryable_errors as e:
                last_error = e
                if attempt < policy.max_attempts:
                    delay = policy.delay_for(attempt)
                    self._logger.warning(
                        f"Attempt {attempt}/{policy.max_attempts} failed: {e} "
                        f"— retrying in {delay:.1f}s",
                        context=context,
                    )
                    await asyncio.sleep(delay)
                else:
                    self.handle(e, context=context)
            except Exception as e:
                self.handle(e, context=context)
                raise

        if last_error:
            raise last_error

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """إحصائيات الأخطاء."""
        by_type: Dict[str, int] = {}
        for r in self._records:
            by_type[r.error_type] = by_type.get(r.error_type, 0) + 1
        
        return {
            "total_errors": len(self._records),
            "fatal_errors": len(self._fatal_errors),
            "recoverable_errors": len([r for r in self._records if r.recoverable]),
            "by_type": by_type,
            "has_fatal": len(self._fatal_errors) > 0,
        }

    def has_fatal_errors(self) -> bool:
        return len(self._fatal_errors) > 0

    def get_recent(self, n: int = 10) -> List[ErrorRecord]:
        return self._records[-n:]

    def clear(self) -> None:
        self._records.clear()
        self._fatal_errors.clear()
