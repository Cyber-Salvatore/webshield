"""
WebShield Platform Logging System
===================================
نظام Logging احترافي يسجل كل خطوة بتحصل بشكل منظم وقابل للقراءة.

Features:
    - Log Levels (DEBUG / INFO / WARNING / ERROR / CRITICAL)
    - Structured Logging (كل log بيتخزن كـ dict)
    - Colored Console Output
    - File Rotation
    - Secret Masking (يمنع ظهور Passwords/Tokens في الـ Logs)
    - Context-aware (كل module بيعمل Logger بإسمه)
    - Performance Metrics
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Platform Logging System                                    ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import logging
import re
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


# ── Log Levels ────────────────────────────────────────────────────────────────

class LogLevel(IntEnum):
    DEBUG    = 10
    INFO     = 20
    SUCCESS  = 25      # مستوى مخصوص لنتائج الفحص الإيجابية
    WARNING  = 30
    ERROR    = 40
    CRITICAL = 50


# ── ANSI Colors ──────────────────────────────────────────────────────────────

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    # ألوان خاصة بالـ Log Levels
    LEVEL_COLORS = {
        LogLevel.DEBUG:    "\033[90m",    # Gray
        LogLevel.INFO:     "\033[94m",    # Blue
        LogLevel.SUCCESS:  "\033[92m",    # Green
        LogLevel.WARNING:  "\033[93m",    # Yellow
        LogLevel.ERROR:    "\033[91m",    # Red
        LogLevel.CRITICAL: "\033[95m",    # Magenta
    }

    @classmethod
    def level(cls, lvl: int) -> str:
        return cls.LEVEL_COLORS.get(lvl, cls.RESET)


# ── Log Entry ─────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """كل رسالة Log بتتخزن كـ Structured Entry."""
    timestamp: float
    level: int
    level_name: str
    logger_name: str
    message: str
    scan_id: Optional[str] = None
    module: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": datetime.fromtimestamp(self.timestamp).isoformat(),
            "level": self.level_name,
            "logger": self.logger_name,
            "msg": self.message,
            "scan_id": self.scan_id,
            **self.extra,
        }

    def format_console(self, color: bool = True) -> str:
        ts = datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S")
        level_str = f"[{self.level_name:8s}]"
        name_str = f"{self.logger_name[:20]:20s}"

        if color:
            c = Colors.level(self.level)
            return (
                f"{Colors.DIM}{ts}{Colors.RESET} "
                f"{c}{Colors.BOLD}{level_str}{Colors.RESET} "
                f"{Colors.CYAN}{name_str}{Colors.RESET} "
                f"{self.message}"
            )
        return f"{ts} {level_str} {name_str} {self.message}"


# ── Secret Masker ─────────────────────────────────────────────────────────────

class SecretMasker:
    """
    يمنع ظهور Passwords, Tokens, Keys في الـ Logs.
    بيستبدل القيم الحساسة بـ ***MASKED***.
    """

    _PATTERNS = [
        # API Keys & Tokens
        r'(api[_\-]?key["\s:=]+)[^\s"&,}]+',
        r'(token["\s:=]+)[^\s"&,}]+',
        r'(bearer\s+)[a-zA-Z0-9._\-]+',
        r'(Authorization:\s*(?:Bearer|Basic)\s+)[^\s]+',
        # Passwords
        r'(password["\s:=]+)[^\s"&,}]+',
        r'(passwd["\s:=]+)[^\s"&,}]+',
        r'(pwd["\s:=]+)[^\s"&,}]+',
        # Secrets
        r'(secret["\s:=]+)[^\s"&,}]+',
        r'(private[_\-]?key["\s:=]+)[^\s"&,}]+',
        # Connection strings
        r'(mongodb(?:\+srv)?://[^@]+@)',
        r'(postgres://[^@]+@)',
        r'(mysql://[^@]+@)',
    ]

    def __init__(self) -> None:
        self._compiled = [
            re.compile(p, re.IGNORECASE)
            for p in self._PATTERNS
        ]

    def mask(self, text: str) -> str:
        """يعوض القيم الحساسة في النص."""
        for pattern in self._compiled:
            text = pattern.sub(r'\1***MASKED***', text)
        return text


# ── File Handler ──────────────────────────────────────────────────────────────

class RotatingFileHandler:
    """
    كاتب Logs لملف مع Rotation تلقائي.
    """

    def __init__(
        self,
        log_dir: str,
        max_size_mb: int = 10,
        backup_count: int = 5,
    ) -> None:
        self._dir = Path(log_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_size_mb * 1024 * 1024
        self._backup_count = backup_count
        self._log_file = self._dir / "webshield.log"
        self._file = open(self._log_file, "a", encoding="utf-8")

    def write(self, entry: LogEntry) -> None:
        line = f"{entry.to_dict()}\n"
        self._file.write(line)
        self._file.flush()
        
        # Rotation
        if self._log_file.stat().st_size > self._max_bytes:
            self._rotate()

    def _rotate(self) -> None:
        self._file.close()
        for i in range(self._backup_count - 1, 0, -1):
            old = self._dir / f"webshield.log.{i}"
            new = self._dir / f"webshield.log.{i+1}"
            if old.exists():
                old.rename(new)
        self._log_file.rename(self._dir / "webshield.log.1")
        self._file = open(self._log_file, "a", encoding="utf-8")

    def close(self) -> None:
        self._file.close()


# ── Platform Logger ────────────────────────────────────────────────────────────

class PlatformLogger:
    """
    الـ Logger الأساسي في WebShield.
    
    كل Module بيعمل instance منه بإسمه:
        logger = PlatformLogger("ScanEngine")
        logger.info("Starting scan")
        logger.error("Connection failed", url="http://...")
    """

    # Global settings (shared across all instances)
    _level: int = LogLevel.INFO
    _color: bool = True
    _file_handler: Optional[RotatingFileHandler] = None
    _masker: SecretMasker = SecretMasker()
    _scan_id: Optional[str] = None
    _entries: List[LogEntry] = []          # In-memory buffer
    _max_buffer: int = 10_000
    _instances: Dict[str, "PlatformLogger"] = {}   # Singleton-per-name cache

    @classmethod
    def get(cls, name: str) -> "PlatformLogger":
        """
        يرجع Logger Instance لاسم معين (Singleton per name) بدل إنشاء
        Instance جديد كل مرة. ده الـ Entry Point المستخدم في كل أجزاء
        الـ Platform:

            log = PlatformLogger.get("WorkflowEngine")
        """
        if name not in cls._instances:
            cls._instances[name] = cls(name)
        return cls._instances[name]

    @classmethod
    def configure(
        cls,
        level: int = LogLevel.INFO,
        color: bool = True,
        log_dir: Optional[str] = None,
        mask_secrets: bool = True,
        scan_id: Optional[str] = None,
    ) -> None:
        """يعدل الإعدادات العامة لكل الـ Loggers."""
        cls._level = level
        cls._color = color
        cls._scan_id = scan_id
        
        if not mask_secrets:
            cls._masker = type("NoMask", (), {"mask": staticmethod(lambda t: t)})()
        
        if log_dir:
            cls._file_handler = RotatingFileHandler(log_dir)
        
        # تسجيل SUCCESS level في logging standard library
        logging.addLevelName(LogLevel.SUCCESS, "SUCCESS")

    def __init__(self, name: str) -> None:
        self._name = name

    # ── Core Methods ──────────────────────────────────────────────────────────

    def _log(self, level: int, message: str, **extra: Any) -> None:
        if level < self.__class__._level:
            return

        level_name = LogLevel(level).name if level in LogLevel._value2member_map_ else str(level)
        
        # إخفاء الأسرار
        safe_message = self.__class__._masker.mask(str(message))
        safe_extra = {
            k: self.__class__._masker.mask(str(v))
            for k, v in extra.items()
        }

        entry = LogEntry(
            timestamp=time.time(),
            level=level,
            level_name=level_name,
            logger_name=self._name,
            message=safe_message,
            scan_id=self.__class__._scan_id,
            extra=safe_extra,
        )

        # Console output
        print(entry.format_console(color=self.__class__._color), file=sys.stderr)

        # File output
        if self.__class__._file_handler:
            self.__class__._file_handler.write(entry)

        # Buffer
        buf = self.__class__._entries
        buf.append(entry)
        if len(buf) > self.__class__._max_buffer:
            buf.pop(0)

    def debug(self, message: str, **extra: Any) -> None:
        self._log(LogLevel.DEBUG, message, **extra)

    def info(self, message: str, **extra: Any) -> None:
        self._log(LogLevel.INFO, message, **extra)

    def success(self, message: str, **extra: Any) -> None:
        self._log(LogLevel.SUCCESS, message, **extra)

    def warning(self, message: str, **extra: Any) -> None:
        self._log(LogLevel.WARNING, message, **extra)

    def error(self, message: str, **extra: Any) -> None:
        self._log(LogLevel.ERROR, message, **extra)

    def critical(self, message: str, **extra: Any) -> None:
        self._log(LogLevel.CRITICAL, message, **extra)

    def finding(self, vuln_type: str, url: str, severity: str, **extra: Any) -> None:
        """مخصوص لتسجيل النتائج الأمنية."""
        self._log(
            LogLevel.SUCCESS,
            f"[FINDING] {vuln_type} @ {url} [{severity.upper()}]",
            **extra,
        )

    # ── Performance Tracking ──────────────────────────────────────────────────

    @contextmanager
    def timer(self, operation: str) -> Generator[None, None, None]:
        """يقيس وقت تنفيذ أي عملية."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.debug(f"⏱ {operation} took {elapsed:.3f}s")

    # ── Utility ───────────────────────────────────────────────────────────────

    @classmethod
    def get_entries(
        cls,
        level: int = LogLevel.DEBUG,
        scan_id: Optional[str] = None,
    ) -> List[LogEntry]:
        """يرجع الـ Entries المخزنة في الـ Buffer."""
        entries = [e for e in cls._entries if e.level >= level]
        if scan_id:
            entries = [e for e in entries if e.scan_id == scan_id]
        return entries

    @classmethod
    def close(cls) -> None:
        if cls._file_handler:
            cls._file_handler.close()

    def child(self, sub_name: str) -> "PlatformLogger":
        """ينشئ logger فرعي (e.g. ScanEngine.SQLi)."""
        return PlatformLogger(f"{self._name}.{sub_name}")
