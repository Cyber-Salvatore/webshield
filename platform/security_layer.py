"""
WebShield Security Layer
===========================
الأداة نفسها لازم تبقى مؤمنة: أي Secrets أو Credentials أو Sessions
أو Tokens تتخزن بشكل آمن، ويتمنع تسريبها في الـ Logs أو الـ Reports،
وفيه Permission System داخلي يحمي البيانات الحساسة أثناء التشغيل.

المكونات:
    - DataSensitivity   : تصنيف حساسية البيانات (PUBLIC → SECRET)
    - SecurityAuditLog   : سجل كل محاولة وصول لبيانات حساسة (مسموحة أو مرفوضة)
    - PermissionManager  : مين يقدر يوصل لإيه (Capability-based access control)
    - SecretRegistry     : يمنع تسريب أي قيمة حساسة معروفة في أي نص (Logs/Reports)
    - SecretsVault       : تخزين مشفّر للـ Secrets (Fernet لو متاح، وإلا
                            Fallback غير مشفّر مع تحذير واضح)
    - SecurityLayer      : Facade يجمعهم كلهم في نقطة دخول واحدة

ملحوظة مهمة عن التشفير:
    التشفير الحقيقي بيحتاج مكتبة `cryptography` (اختيارية، زي PyYAML
    في Configuration Framework). لو غير متاحة، الـ Vault يعمل في
    "Fallback Mode" — تخزين Base64 بس (Obfuscation وليس Encryption)
    مع تحذير واضح في الـ Logs، بدل ما يدّعي حماية مش موجودة فعلاً.
    لتفعيل التشفير الحقيقي: pip install cryptography
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Security Layer                         ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .logging_system import PlatformLogger, SecretMasker
from .error_framework import WebShieldError

try:
    from cryptography.fernet import Fernet  # type: ignore
    _CRYPTO_AVAILABLE = True
except ImportError:
    Fernet = None  # type: ignore[assignment]
    _CRYPTO_AVAILABLE = False


class SecurityError(WebShieldError):
    """خطأ أمني: محاولة وصول غير مصرّح بيها لبيانات حساسة."""
    def __init__(self, message: str, actor: str = "", resource: str = "", **kw: Any) -> None:
        super().__init__(message, recoverable=False, **kw)
        self.actor = actor
        self.resource = resource


# ══════════════════════════════════════════════════════════════════════════════
# DATA SENSITIVITY
# ══════════════════════════════════════════════════════════════════════════════

class DataSensitivity(IntEnum):
    """تصنيف حساسية البيانات — كل مستوى أعلى من اللي قبله."""
    PUBLIC    = 0   # أي حاجة ممكن تظهر في التقرير من غير قلق
    INTERNAL  = 1   # تفاصيل تشغيلية (مسارات، إحصائيات) — ليست سرية لكن مش لازم تتنشر
    SENSITIVE = 2   # بيانات شخصية أو تفاصيل تقنية حساسة (Endpoints داخلية، IPs)
    SECRET    = 3   # Credentials, Tokens, Sessions, Passwords — أعلى مستوى حماية


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuditEntry:
    """سجل واحد لمحاولة وصول لبيانات حساسة — للمراجعة الأمنية للأداة نفسها."""
    actor:     str
    action:    str
    resource:  str
    allowed:   bool
    reason:    str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor": self.actor, "action": self.action, "resource": self.resource,
            "allowed": self.allowed, "reason": self.reason, "timestamp": self.timestamp,
        }


class SecurityAuditLog:
    """
    سجل كل محاولات الوصول للبيانات الحساسة (Vault، Permission checks).
    بيخزن أسماء الموارد فقط (مثلاً 'session_token') مش قيمتها الفعلية،
    حتى الـ Audit Log نفسه ميصبحش مصدر تسريب.
    """

    def __init__(self, max_entries: int = 5000) -> None:
        self._entries: List[AuditEntry] = []
        self._max_entries = max_entries
        self._log = PlatformLogger.get("SecurityAudit")

    def record(self, actor: str, action: str, resource: str, allowed: bool, reason: str = "") -> AuditEntry:
        entry = AuditEntry(actor=actor, action=action, resource=resource, allowed=allowed, reason=reason)
        self._entries.append(entry)
        if len(self._entries) > self._max_entries:
            self._entries.pop(0)

        if not allowed:
            self._log.warning(f"🔒 Access DENIED: actor='{actor}' action='{action}' resource='{resource}' ({reason})")
        else:
            self._log.debug(f"Access granted: actor='{actor}' action='{action}' resource='{resource}'")
        return entry

    def recent(self, limit: int = 50) -> List[AuditEntry]:
        return self._entries[-limit:]

    def denied(self, limit: int = 50) -> List[AuditEntry]:
        return [e for e in self._entries if not e.allowed][-limit:]

    def to_list(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._entries]


# ══════════════════════════════════════════════════════════════════════════════
# PERMISSION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class PermissionManager:
    """
    Capability-based Access Control داخلي: مين (أي Plugin/Module) يقدر
    يوصل لمستوى حساسية معين من البيانات.

    افتراضياً، أي Actor غير معروف ليه مستوى PUBLIC بس. لازم يتم منحه
    صلاحية أعلى صريحاً عن طريق grant().

        perms = PermissionManager()
        perms.grant("auth_engine", DataSensitivity.SECRET)
        perms.require("auth_engine", DataSensitivity.SECRET, resource="session_token")  # OK
        perms.require("html_reporter", DataSensitivity.SECRET, resource="session_token")  # SecurityError
    """

    def __init__(self, audit: Optional[SecurityAuditLog] = None) -> None:
        self._grants: Dict[str, DataSensitivity] = {}
        self._audit = audit
        self._log = PlatformLogger.get("PermissionManager")

    def grant(self, actor: str, level: DataSensitivity) -> None:
        self._grants[actor] = level
        self._log.info(f"Permission granted: '{actor}' → {level.name}")

    def revoke(self, actor: str) -> None:
        self._grants.pop(actor, None)

    def level_of(self, actor: str) -> DataSensitivity:
        return self._grants.get(actor, DataSensitivity.PUBLIC)

    def check(self, actor: str, required: DataSensitivity) -> bool:
        return self.level_of(actor) >= required

    def require(self, actor: str, required: DataSensitivity, resource: str = "") -> None:
        """يرفع SecurityError لو الـ Actor مالوش صلاحية كافية."""
        allowed = self.check(actor, required)
        if self._audit:
            reason = "" if allowed else f"needs {required.name}, has {self.level_of(actor).name}"
            self._audit.record(actor, "access", resource, allowed, reason)

        if not allowed:
            raise SecurityError(
                f"الـ Actor '{actor}' مالوش صلاحية كافية للوصول لـ '{resource}' "
                f"(محتاج {required.name}، عنده {self.level_of(actor).name})",
                actor=actor, resource=resource,
            )


# ══════════════════════════════════════════════════════════════════════════════
# SECRET REGISTRY — منع تسريب القيم الحساسة في أي نص (Logs / Reports)
# ══════════════════════════════════════════════════════════════════════════════

class SecretRegistry:
    """
    بيكمّل SecretMasker (Part 2) اللي بيشتغل بـ Regex Patterns بس.
    هنا بنسجل القيم الحساسة الفعلية (Tokens, Passwords) بمجرد ما
    تُنشأ أو تُحمّل، فبعد كده أي نص فيه القيمة دي — حتى لو الـ Pattern
    مش متعرف عليها أصلاً (مثلاً Token مخصص أو Reflected في Response) —
    يتم استبدالها تلقائياً.
    """

    _MIN_SECRET_LEN = 4   # تجاهل قيم قصيرة جداً (تقلل False Positives في الإخفاء)

    def __init__(self, masker: Optional[SecretMasker] = None) -> None:
        self._values: Dict[str, str] = {}     # value → label
        self._masker = masker or SecretMasker()

    def register(self, value: Optional[str], label: str = "secret") -> None:
        if not value or len(value) < self._MIN_SECRET_LEN:
            return
        self._values[value] = label

    def register_many(self, values: Dict[str, Optional[str]]) -> int:
        """يسجل أكتر من قيمة دفعة واحدة (مثلاً كل حقول config حساسة). يرجع العدد المسجل."""
        count = 0
        for label, value in values.items():
            if value:
                self.register(value, label)
                count += 1
        return count

    def unregister(self, value: str) -> None:
        self._values.pop(value, None)

    def is_registered(self, value: str) -> bool:
        return value in self._values

    def redact(self, text: str) -> str:
        """يستبدل كل القيم الحساسة المسجلة + الـ Patterns المعروفة في نص."""
        if not text:
            return text
        # الأطول الأول علشان نتجنب استبدال جزئي يسيب جزء من السر ظاهر
        for value in sorted(self._values, key=len, reverse=True):
            if value in text:
                label = self._values[value]
                text = text.replace(value, f"***{label.upper()}_MASKED***")
        return self._masker.mask(text)

    def stats(self) -> Dict[str, Any]:
        return {"registered_values": len(self._values)}


# ══════════════════════════════════════════════════════════════════════════════
# SECRETS VAULT — تخزين آمن للـ Credentials/Tokens/Sessions
# ══════════════════════════════════════════════════════════════════════════════

class SecretsVault:
    """
    تخزين الـ Secrets (Credentials, Sessions, Tokens) بشكل مشفّر.

    - لو `cryptography` متاحة: تشفير حقيقي بـ Fernet (AES128-CBC + HMAC).
    - لو غير متاحة: Fallback Mode (Base64 Obfuscation بس) + تحذير واضح
      إن دي مش حماية حقيقية.

    أي `get()` بيتطلب Permission كافية لو فيه PermissionManager متصل،
    وكل عملية (نجحت أو فشلت) بتتسجل في الـ Audit Log — لكن القيمة
    الفعلية للسر نفسه ميتسجلش في أي Log أبداً.
    """

    def __init__(
        self,
        key_path:   Optional[Union[str, Path]] = None,
        *,
        permissions: Optional[PermissionManager] = None,
        registry:    Optional[SecretRegistry] = None,
        audit:       Optional[SecurityAuditLog] = None,
    ) -> None:
        self._permissions = permissions
        self._registry = registry
        self._audit = audit
        self._log = PlatformLogger.get("SecretsVault")
        self._store: Dict[str, str] = {}    # name → encrypted/obfuscated token

        self.encrypted = _CRYPTO_AVAILABLE
        self._fernet: Optional[Any] = None

        if _CRYPTO_AVAILABLE:
            key = self._load_or_create_key(key_path)
            self._fernet = Fernet(key)
        else:
            self._log.warning(
                "⚠️ مكتبة 'cryptography' غير مثبتة — SecretsVault شغال في "
                "Fallback Mode (Base64 Obfuscation فقط، ده مش تشفير حقيقي). "
                "لتفعيل التشفير الحقيقي: pip install cryptography"
            )

    # ── Key Management ───────────────────────────────────────────────────────

    def _load_or_create_key(self, key_path: Optional[Union[str, Path]]) -> bytes:
        if key_path is None:
            return Fernet.generate_key()

        path = Path(key_path)
        if path.exists():
            return path.read_bytes()

        key = Fernet.generate_key()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(key)
        try:
            os.chmod(path, 0o600)   # المفتاح يبقى مقروء بس من المالك (POSIX)
        except OSError:
            pass
        return key

    # ── Encrypt / Decrypt ─────────────────────────────────────────────────────

    def _encrypt(self, value: str) -> str:
        if self._fernet is not None:
            return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return "OBFUSCATED:" + base64.b64encode(value.encode("utf-8")).decode("ascii")

    def _decrypt(self, token: str) -> str:
        if self._fernet is not None:
            try:
                return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
            except Exception as e:
                raise SecurityError(
                    "فشل فك تشفير الـ Secret — غالباً الـ Vault ده بمفتاح مختلف عن "
                    "اللي تم التشفير بيه (لازم نفس key_path بين الـ Vaults اللي "
                    "تتشارك بيانات مُصدّرة عن طريق export_to_file/load_from_file)."
                ) from e
        if token.startswith("OBFUSCATED:"):
            return base64.b64decode(token[len("OBFUSCATED:"):].encode("ascii")).decode("utf-8")
        raise SecurityError("صيغة Token غير معروفة في الـ Vault")

    # ── Public API ────────────────────────────────────────────────────────────

    def set(self, name: str, value: str, *, actor: str = "system") -> None:
        """يخزن Secret جديد (Credential/Token/Session) — مشفّر."""
        self._store[name] = self._encrypt(value)
        if self._registry:
            self._registry.register(value, label=name)
        if self._audit:
            self._audit.record(actor, "vault.set", name, allowed=True)

    def get(self, name: str, *, actor: str = "system") -> Optional[str]:
        """يرجع Secret بعد التحقق من الصلاحيات (لو فيه PermissionManager متصل)."""
        if self._permissions is not None:
            self._permissions.require(actor, DataSensitivity.SECRET, resource=name)
        elif self._audit:
            self._audit.record(actor, "vault.get", name, allowed=True, reason="no permission manager attached")

        token = self._store.get(name)
        if token is None:
            return None
        return self._decrypt(token)

    def delete(self, name: str) -> bool:
        return self._store.pop(name, None) is not None

    def list_names(self) -> List[str]:
        """أسماء الـ Secrets المخزنة فقط — أبداً قيمتها."""
        return list(self._store.keys())

    def has(self, name: str) -> bool:
        return name in self._store

    # ── Persistence (التوكنز مشفرة بالفعل — تخزينها كـ JSON آمن) ─────────────

    def export_to_file(self, path: Union[str, Path]) -> Path:
        """
        يصدّر الـ Store المشفّرة لملف. ملحوظة مهمة: القيم متشفرة بمفتاح
        هذا الـ Vault بس — أي Vault تاني عايز يقرأ الملف ده لازم يكون
        مبني بنفس `key_path` (نفس المفتاح)، وإلا الـ load_from_file
        هيرجع القيم لكن get() هيفشل بـ SecurityError عند فك التشفير.
        """
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps({"encrypted": self.encrypted, "store": self._store}, indent=2),
            encoding="utf-8",
        )
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        return out_path

    def load_from_file(self, path: Union[str, Path]) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        payload = json.loads(p.read_text(encoding="utf-8"))
        store = payload.get("store", {})
        self._store.update(store)
        return len(store)


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY LAYER — Facade
# ══════════════════════════════════════════════════════════════════════════════

# الحقول المعروفة في WebShieldConfig (Part 2) اللي محتاجة حماية —
# Duck-typed عن طريق getattr علشان الـ Security Layer يفضل مستقل عن
# config_framework (نفس مبدأ الـ Decoupling المستخدم في باقي الـ Platform).
SENSITIVE_CONFIG_FIELDS = (
    "session_token", "auth_credentials", "proxy_auth", "cookies", "login_form_fields",
)


class SecurityLayer:
    """
    نقطة الدخول الموحدة للأمان الداخلي للأداة.

        security = SecurityLayer()
        security.permissions.grant("auth_engine", DataSensitivity.SECRET)

        security.protect_config(config)         # يسجل كل القيم الحساسة فيه
        security.vault.set("session", token, actor="auth_engine")
        clean_log_line = security.redact(raw_log_line)
    """

    def __init__(self, key_path: Optional[Union[str, Path]] = None) -> None:
        self.audit       = SecurityAuditLog()
        self.permissions = PermissionManager(audit=self.audit)
        self.registry    = SecretRegistry()
        self.vault       = SecretsVault(
            key_path=key_path,
            permissions=self.permissions,
            registry=self.registry,
            audit=self.audit,
        )
        self._log = PlatformLogger.get("SecurityLayer")

    # ── Redaction (للـ Logs والـ Reports) ─────────────────────────────────────

    def redact(self, text: str) -> str:
        """نقطة الدخول الموحدة لإخفاء أي بيانات حساسة في نص (Log line / Report snippet)."""
        return self.registry.redact(text)

    # ── Config Protection ─────────────────────────────────────────────────────

    def protect_config(self, config: Any) -> int:
        """
        يفحص أي Config Object (مثلاً WebShieldConfig) ويسجل قيم الحقول
        الحساسة المعروفة (session_token, auth_credentials, ...) في
        الـ SecretRegistry تلقائياً — بدون أي import مباشر لـ
        config_framework (Duck-typing كامل).

        Returns:
            عدد القيم اللي تم تسجيلها.
        """
        count = 0
        for field_name in SENSITIVE_CONFIG_FIELDS:
            value = getattr(config, field_name, None)
            if not value:
                continue
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, str):
                        self.registry.register(sub_value, label=f"{field_name}.{sub_key}")
                        count += 1
            elif isinstance(value, str):
                self.registry.register(value, label=field_name)
                count += 1

        self._log.info(f"protect_config(): تم تسجيل {count} قيمة حساسة من الإعدادات")
        return count

    def status(self) -> Dict[str, Any]:
        return {
            "vault_encrypted":     self.vault.encrypted,
            "vault_secrets_count": len(self.vault.list_names()),
            "registry":            self.registry.stats(),
            "recent_denied":       [e.to_dict() for e in self.audit.denied(limit=10)],
        }
