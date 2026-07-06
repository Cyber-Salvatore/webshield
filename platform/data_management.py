"""
WebShield Data Management Layer & Storage Architecture
==========================================================

DATA MANAGEMENT LAYER:
========================
نظام لإدارة كل البيانات اللي بتطلع أثناء الفحص (Assets، Endpoints،
Parameters، Headers، Cookies، Sessions، Findings، Evidence،
Attack Chains، Fingerprints، Baselines، Configurations، History)
مع Indexing وVersioning بحيث البيانات تبقى منظمة وسريعة حتى في
المشاريع الضخمة.

الطبقة دي Generic تماماً — ميعرفش حاجة عن الثغرات نفسها (نفس مبدأ
الـ Core: "ميبقاش فيه أي Logic خاص بالثغرات"). أي Plugin أو Scanner
بيسجل بياناته في Collection باسمها وبس.

    dm = DataManagementLayer()
    dm.register_collection("endpoints")
    dm.add("endpoints", {"url": "/api/users", "method": "GET"})
    dm.create_index("endpoints", "method")
    get_endpoints = dm.find_by_index("endpoints", "method", "GET")

STORAGE ARCHITECTURE:
=======================
بدل تخزين عشوائي — تقسيم واضح بين البيانات المؤقتة، الدائمة،
الـ Cache، الـ Logs، الـ Reports، والـ Evidence. كل نوع بيانات
ليه مكان وطريقة تخزين مناسبة (مع Compression تلقائي للبيانات
الكبيرة) تضمن السرعة وسهولة الوصول وتقليل استهلاك المساحة.

    storage = StorageManager("./.webshield_data")
    storage.write_json(StorageKind.EVIDENCE, "finding_001", evidence_dict)
    data = storage.read_json(StorageKind.EVIDENCE, "finding_001")
    storage.cleanup_temp()
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Data Management Layer & Storage Architecture (Part 9)      ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import asyncio
import gzip
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

from .logging_system import PlatformLogger
from .error_framework import WebShieldError


class DataManagementError(WebShieldError):
    """خطأ في طبقة إدارة البيانات أو التخزين."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# PART 9.A — DATA MANAGEMENT LAYER
# ══════════════════════════════════════════════════════════════════════════════

# أسماء الـ Collections المعيارية المذكورة في توثيق المشروع — مرجع بس،
# مش إلزامي، أي اسم تاني ينفع برضه عن طريق register_collection().
STANDARD_COLLECTIONS = [
    "assets", "endpoints", "parameters", "headers", "cookies", "sessions",
    "findings", "evidence", "attack_chains", "fingerprints", "baselines",
    "configurations", "history",
]


@dataclass
class VersionedRecord:
    """نسخة واحدة من سجل في الـ History (لما الـ Collection بتدعم Versioning)."""
    record_id:  str
    version:    int
    data:       Any
    producer:   str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id":  self.record_id,
            "version":    self.version,
            "data":       self.data,
            "producer":   self.producer,
            "created_at": self.created_at,
        }


class _Collection:
    """تخزين داخلي لـ Collection واحدة — مش للاستخدام المباشر من برا الموديول."""

    def __init__(self, name: str, versioned: bool = True) -> None:
        self.name = name
        self.versioned = versioned
        self.records: Dict[str, Any] = {}
        self.history: Dict[str, List[VersionedRecord]] = {}
        self.indexes: Dict[str, Dict[Any, Set[str]]] = {}
        self.index_extractors: Dict[str, Callable[[Any], Any]] = {}
        self._counter = 0

    def next_id(self) -> str:
        self._counter += 1
        return f"{self.name[:4]}_{self._counter:08d}"

    def _index_value(self, record: Any, field_name: str) -> Any:
        extractor = self.index_extractors.get(field_name)
        if extractor:
            return extractor(record)
        if isinstance(record, dict):
            return record.get(field_name)
        return getattr(record, field_name, None)

    def reindex_record(self, record_id: str, record: Any) -> None:
        for field_name, idx in self.indexes.items():
            value = self._index_value(record, field_name)
            idx.setdefault(value, set()).add(record_id)

    def unindex_record(self, record_id: str, record: Any) -> None:
        for field_name, idx in self.indexes.items():
            value = self._index_value(record, field_name)
            bucket = idx.get(value)
            if bucket and record_id in bucket:
                bucket.discard(record_id)
                if not bucket:
                    del idx[value]


class DataManagementLayer:
    """
    المدير المركزي لكل البيانات اللي تتجمع أثناء الفحص.

    - كل نوع بيانات (Assets, Endpoints, Findings...) ليه Collection مستقلة.
    - Indexing على أي Field لاستعلامات سريعة (O(1) تقريباً) بدل المسح الكامل.
    - Versioning اختياري: كل `update()` يحفظ نسخة قديمة في الـ History.
    - تكامل مباشر مع StorageManager (Part 9.B) للحفظ على القرص مع
      Compression تلقائي للبيانات الكبيرة.
    """

    def __init__(self) -> None:
        self._collections: Dict[str, _Collection] = {}
        self._log = PlatformLogger.get("DataManagementLayer")

    # ── Collection Management ────────────────────────────────────────────────

    def register_collection(self, name: str, *, versioned: bool = True) -> None:
        """يعرّف Collection جديدة لو لسه مش موجودة."""
        if name not in self._collections:
            self._collections[name] = _Collection(name, versioned=versioned)
            self._log.debug(f"Collection registered: '{name}' (versioned={versioned})")

    def _get_or_create(self, name: str) -> _Collection:
        if name not in self._collections:
            self.register_collection(name)
        return self._collections[name]

    def list_collections(self) -> List[str]:
        return list(self._collections.keys())

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def add(
        self,
        collection: str,
        record:     Any,
        record_id:  Optional[str] = None,
        producer:   str = "unknown",
    ) -> str:
        """يضيف سجل جديد للـ Collection ويرجع الـ ID بتاعه."""
        coll = self._get_or_create(collection)
        rid = record_id or coll.next_id()

        coll.records[rid] = record
        coll.reindex_record(rid, record)

        if coll.versioned:
            coll.history.setdefault(rid, []).append(
                VersionedRecord(record_id=rid, version=1, data=record, producer=producer)
            )
        return rid

    def update(
        self,
        collection: str,
        record_id:  str,
        record:     Any,
        producer:   str = "unknown",
    ) -> int:
        """
        يحدّث سجل موجود. لو الـ Collection versioned، النسخة القديمة
        تتحفظ في الـ History والنسخة الجديدة تاخد رقم نسخة أعلى.

        Returns:
            رقم النسخة الجديدة (1 لو الـ Collection غير Versioned).
        """
        coll = self._get_or_create(collection)
        old = coll.records.get(record_id)
        if old is not None:
            coll.unindex_record(record_id, old)

        coll.records[record_id] = record
        coll.reindex_record(record_id, record)

        if not coll.versioned:
            return 1

        history = coll.history.setdefault(record_id, [])
        new_version = len(history) + 1
        history.append(
            VersionedRecord(record_id=record_id, version=new_version, data=record, producer=producer)
        )
        return new_version

    def get(self, collection: str, record_id: str) -> Optional[Any]:
        coll = self._collections.get(collection)
        return coll.records.get(record_id) if coll else None

    def delete(self, collection: str, record_id: str) -> bool:
        coll = self._collections.get(collection)
        if not coll or record_id not in coll.records:
            return False
        record = coll.records.pop(record_id)
        coll.unindex_record(record_id, record)
        return True

    def all(self, collection: str) -> List[Any]:
        coll = self._collections.get(collection)
        return list(coll.records.values()) if coll else []

    def all_with_ids(self, collection: str) -> Dict[str, Any]:
        coll = self._collections.get(collection)
        return dict(coll.records) if coll else {}

    def count(self, collection: str) -> int:
        coll = self._collections.get(collection)
        return len(coll.records) if coll else 0

    def query(self, collection: str, predicate: Callable[[Any], bool]) -> List[Any]:
        """فلترة كاملة (Full scan) — للاستعلامات اللي مش على Field مفهرس."""
        return [r for r in self.all(collection) if predicate(r)]

    # ── Indexing ──────────────────────────────────────────────────────────────

    def create_index(
        self,
        collection: str,
        field_name: str,
        extractor:  Optional[Callable[[Any], Any]] = None,
    ) -> None:
        """
        يبني Index على Field معينة لاستعلامات سريعة.
        لو الـ Records مش Dicts، تقدر تمرر extractor مخصص.
        """
        coll = self._get_or_create(collection)
        if extractor is not None:
            coll.index_extractors[field_name] = extractor
        idx: Dict[Any, Set[str]] = {}
        for rid, record in coll.records.items():
            value = coll._index_value(record, field_name)
            idx.setdefault(value, set()).add(rid)
        coll.indexes[field_name] = idx
        self._log.debug(f"Index built: {collection}.{field_name} ({len(idx)} distinct values)")

    def find_by_index(self, collection: str, field_name: str, value: Any) -> List[Any]:
        coll = self._collections.get(collection)
        if not coll or field_name not in coll.indexes:
            return []
        ids = coll.indexes[field_name].get(value, set())
        return [coll.records[rid] for rid in ids if rid in coll.records]

    # ── Versioning / History ─────────────────────────────────────────────────

    def get_history(self, collection: str, record_id: str) -> List[VersionedRecord]:
        coll = self._collections.get(collection)
        if not coll:
            return []
        return list(coll.history.get(record_id, []))

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            name: {
                "count":      len(coll.records),
                "versioned":  coll.versioned,
                "indexes":    list(coll.indexes.keys()),
            }
            for name, coll in self._collections.items()
        }

    # ── Persistence (تكامل مع StorageManager — Part 9.B) ─────────────────────

    async def flush(
        self,
        collection: str,
        storage:    "StorageManager",
        kind:       Optional["StorageKind"] = None,
    ) -> Path:
        """يحفظ Collection كاملة على القرص (JSON أو Compressed JSON تلقائياً)."""
        kind = kind or StorageKind.PERSISTENT
        coll = self._collections.get(collection)
        if coll is None:
            raise DataManagementError(f"Collection غير موجودة: '{collection}'")

        payload = {
            "collection": collection,
            "versioned":  coll.versioned,
            "records":    coll.records,
        }
        path = storage.write_json(kind, collection, payload)
        self._log.debug(f"Collection '{collection}' flushed → {path}")
        return path

    async def load(self, collection: str, storage: "StorageManager", kind: Optional["StorageKind"] = None) -> int:
        """يحمّل Collection من القرص (لو موجودة) ويرجع عدد السجلات المحمّلة."""
        kind = kind or StorageKind.PERSISTENT
        try:
            payload = storage.read_json(kind, collection)
        except FileNotFoundError:
            return 0

        coll = self._get_or_create(collection)
        coll.versioned = payload.get("versioned", coll.versioned)
        records = payload.get("records", {})
        for rid, record in records.items():
            coll.records[rid] = record
            coll.reindex_record(rid, record)
        return len(records)

    async def flush_all(self, storage: "StorageManager") -> Dict[str, Path]:
        return {name: await self.flush(name, storage) for name in self._collections}

    # ── Pipeline Integration (Decoupled — Part 7) ────────────────────────────

    def ingest_snapshot(self, snapshot: Dict[str, Any], collection: str = "pipeline_context") -> int:
        """
        يستورد PipelineContext.snapshot() (Part 7) — أو أي Dict تاني —
        كسجلات منفصلة في Collection واحدة، بدون أي import مباشر لـ
        scan_pipeline (الموديول ده يفضل مستقل تماماً).
        """
        flat = snapshot.get("flat", snapshot)
        count = 0
        for key, value in flat.items():
            self.add(collection, {"key": key, "value": value}, record_id=key, producer="pipeline")
            count += 1
        return count


# ══════════════════════════════════════════════════════════════════════════════
# PART 9.B — STORAGE ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════

class StorageKind(str, Enum):
    """أنواع التخزين — كل نوع له مجلد مستقل وطريقة تخزين مناسبة."""
    TEMP        = "temp"          # بيانات مؤقتة أثناء الفحص — تُمسح بعده
    PERSISTENT  = "persistent"    # بيانات دائمة (Collections, History)
    CACHE       = "cache"         # نتائج مؤقتة قابلة لإعادة الحساب
    LOGS        = "logs"          # ملفات الـ Logs
    REPORTS     = "reports"       # التقارير النهائية
    EVIDENCE    = "evidence"      # أدلة الثغرات (Raw Requests/Responses, Screenshots)


def compress_bytes(data: bytes) -> bytes:
    return gzip.compress(data)


def decompress_bytes(data: bytes) -> bytes:
    return gzip.decompress(data)


class StorageManager:
    """
    تقسيم واضح للتخزين بدل العشوائية: TEMP / PERSISTENT / CACHE / LOGS /
    REPORTS / EVIDENCE — كل نوع بيانات في مكانه الصحيح.

    البيانات الكبيرة (أكبر من compress_threshold_bytes) بتتخزن مضغوطة
    تلقائياً (.json.gz) لتقليل استهلاك المساحة، والقراءة (read_json)
    بتكتشف الامتداد الصحيح تلقائياً.
    """

    _SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")

    def __init__(
        self,
        base_dir: Union[str, Path] = "./.webshield_data",
        *,
        compress_threshold_bytes: int = 65_536,   # 64KB
    ) -> None:
        self._base = Path(base_dir)
        self._compress_threshold = compress_threshold_bytes
        self._log = PlatformLogger.get("StorageManager")

        self._dirs: Dict[StorageKind, Path] = {}
        for kind in StorageKind:
            d = self._base / kind.value
            d.mkdir(parents=True, exist_ok=True)
            self._dirs[kind] = d

    # ── Path Resolution ───────────────────────────────────────────────────────

    def _safe_name(self, name: str) -> str:
        cleaned = "".join(c if c in self._SAFE_CHARS else "_" for c in name)
        return cleaned or "unnamed"

    def path_for(self, kind: StorageKind, name: str, suffix: str = "") -> Path:
        return self._dirs[kind] / f"{self._safe_name(name)}{suffix}"

    def dir_for(self, kind: StorageKind) -> Path:
        return self._dirs[kind]

    # ── JSON I/O (مع Compression تلقائي) ──────────────────────────────────────

    def write_json(
        self,
        kind:    StorageKind,
        name:    str,
        data:    Any,
        *,
        compress: Optional[bool] = None,
    ) -> Path:
        """يكتب JSON بشكل Atomic، ويضغط تلقائياً لو البيانات كبيرة."""
        raw = json.dumps(data, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        should_compress = compress if compress is not None else len(raw) > self._compress_threshold

        suffix = ".json.gz" if should_compress else ".json"
        path = self.path_for(kind, name, suffix)
        payload = compress_bytes(raw) if should_compress else raw

        tmp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp_path.write_bytes(payload)
            os.replace(tmp_path, path)
        except OSError as e:
            raise DataManagementError(f"فشل الكتابة في '{path}': {e}") from e
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        # لو كان فيه نسخة بالامتداد التاني (مضغوطة/غير مضغوطة) من تخزين سابق، نشيلها
        other_suffix = ".json" if should_compress else ".json.gz"
        other_path = self.path_for(kind, name, other_suffix)
        if other_path.exists():
            try:
                other_path.unlink()
            except OSError:
                pass

        return path

    def read_json(self, kind: StorageKind, name: str) -> Any:
        """يقرأ JSON (مضغوط أو لأ — بيكتشف تلقائياً)."""
        gz_path = self.path_for(kind, name, ".json.gz")
        plain_path = self.path_for(kind, name, ".json")

        if gz_path.exists():
            raw = decompress_bytes(gz_path.read_bytes())
        elif plain_path.exists():
            raw = plain_path.read_bytes()
        else:
            raise FileNotFoundError(f"مفيش ملف JSON بالاسم '{name}' في {kind.value}")

        return json.loads(raw.decode("utf-8"))

    def exists(self, kind: StorageKind, name: str) -> bool:
        return (
            self.path_for(kind, name, ".json").exists()
            or self.path_for(kind, name, ".json.gz").exists()
        )

    # ── Raw Bytes I/O (للـ Evidence — Screenshots, Raw Bodies) ────────────────

    def write_bytes(self, kind: StorageKind, name: str, data: bytes, suffix: str = ".bin") -> Path:
        path = self.path_for(kind, name, suffix)
        path.write_bytes(data)
        return path

    def read_bytes(self, kind: StorageKind, name: str, suffix: str = ".bin") -> bytes:
        path = self.path_for(kind, name, suffix)
        return path.read_bytes()

    # ── Evidence Helper ───────────────────────────────────────────────────────

    def evidence_path_for(self, finding_id: str, ext: str = ".json") -> Path:
        """مسار جاهز لتخزين دليل Finding معينة تحت مجلد Evidence."""
        return self.path_for(StorageKind.EVIDENCE, finding_id, ext)

    # ── Cleanup & Usage ───────────────────────────────────────────────────────

    def cleanup_temp(self) -> int:
        """يمسح كل البيانات المؤقتة (بعد انتهاء الفحص مثلاً). يرجع عدد الملفات."""
        removed = 0
        temp_dir = self._dirs[StorageKind.TEMP]
        for f in temp_dir.rglob("*"):
            if f.is_file():
                try:
                    f.unlink()
                    removed += 1
                except OSError:
                    pass
        self._log.debug(f"Cleaned up {removed} temp file(s)")
        return removed

    def disk_usage(self) -> Dict[str, int]:
        """حجم كل نوع تخزين بالـ Bytes — مفيد لمراقبة استهلاك المساحة."""
        usage: Dict[str, int] = {}
        for kind, d in self._dirs.items():
            total = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            usage[kind.value] = total
        usage["total"] = sum(usage.values())
        return usage

    def disk_usage_human(self) -> Dict[str, str]:
        def _fmt(n: int) -> str:
            for unit in ("B", "KB", "MB", "GB"):
                if n < 1024:
                    return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
                n /= 1024
            return f"{n:.1f}TB"

        return {k: _fmt(v) for k, v in self.disk_usage().items()}
