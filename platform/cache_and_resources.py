"""
WebShield Cache Layer & Resource Manager
==========================================
Cache Layer: يقلل العمليات المتكررة ويسرع الفحص.
Resource Manager: يراقب استهلاك CPU والذاكرة والاتصالات.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Cache & Resource Management                                ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
# CACHE LAYER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CacheEntry:
    value: Any
    created_at: float
    ttl: float              # seconds, 0 = never expire
    hits: int = 0

    @property
    def expired(self) -> bool:
        if self.ttl <= 0:
            return False
        return time.monotonic() - self.created_at > self.ttl

    def touch(self) -> None:
        self.hits += 1


class CacheLayer:
    """
    In-Memory LRU Cache مع TTL.
    
    الاستخدام:
        cache = CacheLayer(max_size=1000, default_ttl=3600)
        
        cache.set("response:http://example.com", response_data)
        data = cache.get("response:http://example.com")
        
        # كـ Decorator
        @cache.cached(ttl=300)
        async def fetch_page(url):
            ...
    """

    def __init__(
        self,
        max_size: int = 5000,
        default_ttl: float = 3600,
    ) -> None:
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0
        self._lock = asyncio.Lock()

    # ── Core Operations ───────────────────────────────────────────────────────

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """يخزن قيمة في الـ Cache."""
        if key in self._store:
            self._store.move_to_end(key)
        elif len(self._store) >= self._max_size:
            # LRU eviction
            self._store.popitem(last=False)
        
        self._store[key] = CacheEntry(
            value=value,
            created_at=time.monotonic(),
            ttl=ttl if ttl is not None else self._default_ttl,
        )

    def get(self, key: str) -> Optional[Any]:
        """يرجع قيمة من الـ Cache أو None لو مش موجودة أو منتهية."""
        entry = self._store.get(key)
        
        if entry is None:
            self._misses += 1
            return None
        
        if entry.expired:
            del self._store[key]
            self._misses += 1
            return None
        
        entry.touch()
        self._store.move_to_end(key)
        self._hits += 1
        return entry.value

    def delete(self, key: str) -> bool:
        if key in self._store:
            del self._store[key]
            return True
        return False

    def clear(self) -> None:
        self._store.clear()

    def has(self, key: str) -> bool:
        return self.get(key) is not None

    # ── Namespaced Operations ─────────────────────────────────────────────────

    def set_ns(self, namespace: str, key: str, value: Any, **kwargs: Any) -> None:
        self.set(f"{namespace}:{key}", value, **kwargs)

    def get_ns(self, namespace: str, key: str) -> Optional[Any]:
        return self.get(f"{namespace}:{key}")

    def clear_ns(self, namespace: str) -> int:
        """يمسح كل الـ Keys في Namespace معين."""
        prefix = f"{namespace}:"
        keys_to_delete = [k for k in self._store if k.startswith(prefix)]
        for k in keys_to_delete:
            del self._store[k]
        return len(keys_to_delete)

    # ── URL Cache (common use case) ───────────────────────────────────────────

    def cache_response(self, url: str, response: Any, ttl: float = 300) -> None:
        """يكاش HTTP Response."""
        self.set_ns("resp", self._url_key(url), response, ttl=ttl)

    def get_response(self, url: str) -> Optional[Any]:
        return self.get_ns("resp", self._url_key(url))

    @staticmethod
    def _url_key(url: str) -> str:
        return hashlib.md5(url.encode()).hexdigest()

    # ── Decorator ─────────────────────────────────────────────────────────────

    def cached(self, ttl: Optional[float] = None, key_func: Optional[Callable] = None):
        """Decorator لـ Cache نتائج functions تلقائياً."""
        def decorator(func: Callable) -> Callable:
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
                
                cached_val = self.get(cache_key)
                if cached_val is not None:
                    return cached_val
                
                result = await func(*args, **kwargs)
                if result is not None:
                    self.set(cache_key, result, ttl=ttl)
                return result
            return wrapper
        return decorator

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{self._hits / total * 100:.1f}%" if total else "0%",
        }


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ResourceSnapshot:
    """لقطة من استهلاك الموارد في لحظة معينة."""
    timestamp: float
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    open_connections: int
    active_tasks: int

    def is_overloaded(
        self,
        max_cpu: float = 80.0,
        max_memory: float = 80.0,
    ) -> bool:
        return self.cpu_percent > max_cpu or self.memory_percent > max_memory


class ResourceManager:
    """
    يراقب ويدير استهلاك موارد الجهاز أثناء الفحص.
    
    - يمنع الأداة من استهلاك موارد زيادة عن اللازم
    - يقلل الـ Concurrency تلقائياً لو الموارد مرهقة
    - يوفر metrics دقيقة لأداء الأداة
    """

    def __init__(
        self,
        max_cpu_percent: float = 70.0,
        max_memory_percent: float = 75.0,
        max_connections: int = 500,
        check_interval: float = 5.0,
    ) -> None:
        self._max_cpu = max_cpu_percent
        self._max_memory = max_memory_percent
        self._max_connections = max_connections
        self._check_interval = check_interval
        self._snapshots: list = []
        self._connection_count = 0
        self._task_count = 0
        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._throttle_callbacks: list = []

    # ── Monitoring ────────────────────────────────────────────────────────────

    async def start_monitoring(self) -> None:
        """يبدأ مراقبة الموارد في الخلفية."""
        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())

    async def stop_monitoring(self) -> None:
        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()

    async def _monitor_loop(self) -> None:
        while self._monitoring:
            snapshot = await self._take_snapshot()
            self._snapshots.append(snapshot)
            if len(self._snapshots) > 1000:
                self._snapshots.pop(0)
            
            if snapshot.is_overloaded(self._max_cpu, self._max_memory):
                for cb in self._throttle_callbacks:
                    try:
                        await cb(snapshot) if asyncio.iscoroutinefunction(cb) else cb(snapshot)
                    except Exception:
                        pass
            
            await asyncio.sleep(self._check_interval)

    async def _take_snapshot(self) -> ResourceSnapshot:
        """يأخذ قراءة للموارد الحالية."""
        cpu = 0.0
        mem_mb = 0.0
        mem_pct = 0.0
        
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            mem_mb = mem.used / 1024 / 1024
            mem_pct = mem.percent
        except ImportError:
            # psutil مش متاح - نستخدم بديل بسيط
            try:
                import resource
                usage = resource.getrusage(resource.RUSAGE_SELF)
                mem_mb = usage.ru_maxrss / 1024
            except Exception:
                pass
        
        return ResourceSnapshot(
            timestamp=time.monotonic(),
            cpu_percent=cpu,
            memory_mb=mem_mb,
            memory_percent=mem_pct,
            open_connections=self._connection_count,
            active_tasks=self._task_count,
        )

    # ── Connection Tracking ───────────────────────────────────────────────────

    def connection_opened(self) -> bool:
        """يسجل فتح اتصال. بيرجع False لو وصلنا للحد الأقصى."""
        if self._connection_count >= self._max_connections:
            return False
        self._connection_count += 1
        return True

    def connection_closed(self) -> None:
        self._connection_count = max(0, self._connection_count - 1)

    def task_started(self) -> None:
        self._task_count += 1

    def task_finished(self) -> None:
        self._task_count = max(0, self._task_count - 1)

    # ── Throttle Callbacks ────────────────────────────────────────────────────

    def on_throttle(self, callback: Callable) -> None:
        """يسجل callback يتنادي لما الموارد تكون مرهقة."""
        self._throttle_callbacks.append(callback)

    # ── Checks ────────────────────────────────────────────────────────────────

    async def check_available(self) -> bool:
        """يتحقق إن في موارد كافية للاستمرار."""
        snapshot = await self._take_snapshot()
        return not snapshot.is_overloaded(self._max_cpu, self._max_memory)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        if not self._snapshots:
            return {"status": "no data"}
        
        latest = self._snapshots[-1]
        avg_cpu = sum(s.cpu_percent for s in self._snapshots[-10:]) / min(10, len(self._snapshots))
        avg_mem = sum(s.memory_mb for s in self._snapshots[-10:]) / min(10, len(self._snapshots))
        
        return {
            "current_cpu": f"{latest.cpu_percent:.1f}%",
            "current_memory_mb": f"{latest.memory_mb:.0f}MB",
            "avg_cpu_10": f"{avg_cpu:.1f}%",
            "avg_memory_10": f"{avg_mem:.0f}MB",
            "open_connections": self._connection_count,
            "active_tasks": self._task_count,
            "overloaded": latest.is_overloaded(self._max_cpu, self._max_memory),
        }
