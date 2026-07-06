"""
WebShield Configuration Framework
===================================
نظام إعدادات مرن يتحكم في كل إعدادات المشروع من مكان واحد.
يدعم: YAML، JSON، Environment Variables، CLI args، Runtime overrides.
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Configuration Framework                                    ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


# ── Scan Profiles ────────────────────────────────────────────────────────────

class ScanProfile:
    """Profiles جاهزة بتغير عشرات الإعدادات تلقائياً."""

    QUICK = "quick"
    BALANCED = "balanced"
    DEEP = "deep"
    STEALTH = "stealth"
    AUTHENTICATED = "authenticated"
    API = "api"
    CLOUD = "cloud"
    RED_TEAM = "red_team"

    _PROFILES: Dict[str, Dict[str, Any]] = {
        QUICK: {
            "concurrency": 10,
            "request_timeout": 5,
            "max_depth": 2,
            "confirmation_rounds": 1,
            "passive_only": False,
            "follow_redirects": True,
            "max_endpoints": 100,
            "rate_limit": 20,
            "enabled_scanners": ["xss", "sqli", "headers", "cors"],
        },
        BALANCED: {
            "concurrency": 20,
            "request_timeout": 10,
            "max_depth": 5,
            "confirmation_rounds": 2,
            "passive_only": False,
            "follow_redirects": True,
            "max_endpoints": 500,
            "rate_limit": 10,
            "enabled_scanners": "__all__",
        },
        DEEP: {
            "concurrency": 5,
            "request_timeout": 30,
            "max_depth": 20,
            "confirmation_rounds": 3,
            "passive_only": False,
            "follow_redirects": True,
            "max_endpoints": 5000,
            "rate_limit": 3,
            "enabled_scanners": "__all__",
            "fuzzing_depth": "deep",
        },
        STEALTH: {
            "concurrency": 2,
            "request_timeout": 15,
            "max_depth": 3,
            "confirmation_rounds": 1,
            "passive_only": True,
            "follow_redirects": False,
            "max_endpoints": 200,
            "rate_limit": 1,
            "randomize_headers": True,
            "rotate_user_agents": True,
            "jitter_ms": 2000,
        },
        API: {
            "concurrency": 30,
            "request_timeout": 10,
            "max_depth": 1,
            "confirmation_rounds": 2,
            "passive_only": False,
            "follow_redirects": True,
            "max_endpoints": 1000,
            "rate_limit": 15,
            "api_mode": True,
            "enabled_scanners": [
                "sqli", "xss", "idor", "authz_matrix", "graphql",
                "jwt_scanner", "oauth_scanner", "nosqli", "xxe",
            ],
        },
        AUTHENTICATED: {
            "concurrency": 15,
            "request_timeout": 15,
            "max_depth": 10,
            "confirmation_rounds": 2,
            "passive_only": False,
            "follow_redirects": True,
            "max_endpoints": 2000,
            "rate_limit": 8,
            "auth_required": True,
            "enabled_scanners": "__all__",
            # متطلبات هذا الـ Profile: لازم session/login صالح قبل البدء
            "required_capabilities": ["http", "auth"],
            "session_revalidation_interval": 300,   # ثواني، يتأكد إن الـ Session لسه صالحة
        },
        CLOUD: {
            "concurrency": 12,
            "request_timeout": 20,
            "max_depth": 5,
            "confirmation_rounds": 2,
            "passive_only": False,
            "follow_redirects": True,
            "max_endpoints": 1500,
            "rate_limit": 6,
            "cloud_mode": True,
            "enabled_scanners": [
                "ssrf", "idor", "auth_bypass", "authz_matrix", "headers",
                "cors_scanner", "jwt_scanner", "oauth_scanner", "secrets_scanner",
                "origin_discovery", "open_redirect",
            ],
            # فحوصات خاصة بالبيئات السحابية: Metadata endpoints وIAM misconfig
            "check_cloud_metadata_endpoints": True,
            "cloud_metadata_targets": [
                "169.254.169.254",            # AWS/Azure/GCP instance metadata
                "metadata.google.internal",   # GCP
            ],
        },
        RED_TEAM: {
            "concurrency": 3,
            "request_timeout": 30,
            "max_depth": 50,
            "confirmation_rounds": 3,
            "passive_only": False,
            "follow_redirects": True,
            "max_endpoints": 10000,
            "rate_limit": 2,
            "enabled_scanners": "__all__",
            "fuzzing_depth": "extreme",
            "use_browser": True,
            "brute_force": True,
        },
    }

    @classmethod
    def get(cls, profile_name: str) -> Dict[str, Any]:
        return deepcopy(cls._PROFILES.get(profile_name, cls._PROFILES[cls.BALANCED]))

    @classmethod
    def list_profiles(cls) -> List[str]:
        return list(cls._PROFILES.keys())


# ── Main Config Dataclass ─────────────────────────────────────────────────────

@dataclass
class WebShieldConfig:
    """
    الإعدادات الكاملة لـ WebShield.
    كل إعداد ليه قيمة افتراضية منطقية.
    """

    # ── Target ───────────────────────────────────────────────────────────────
    target_url: str = ""
    scope_domains: List[str] = field(default_factory=list)    # نطاق الفحص
    exclude_patterns: List[str] = field(default_factory=list) # مسارات مستثناة

    # ── Performance ──────────────────────────────────────────────────────────
    concurrency: int = 20
    request_timeout: int = 10
    connect_timeout: int = 5
    max_depth: int = 5
    max_endpoints: int = 500
    rate_limit: float = 10.0        # requests per second
    jitter_ms: int = 0              # عشوائية في التوقيت (Stealth)

    # ── HTTP Settings ─────────────────────────────────────────────────────────
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = True
    http2: bool = False
    custom_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    user_agent: str = "WebShield/3.2 Security Scanner"
    rotate_user_agents: bool = False
    randomize_headers: bool = False

    # ── Authentication ────────────────────────────────────────────────────────
    auth_type: Optional[str] = None    # basic / bearer / form / cookie / oauth2
    auth_credentials: Dict[str, str] = field(default_factory=dict)
    login_url: Optional[str] = None
    login_form_fields: Dict[str, str] = field(default_factory=dict)
    session_token: Optional[str] = None

    # ── Proxy ─────────────────────────────────────────────────────────────────
    proxy_url: Optional[str] = None
    proxy_auth: Optional[Dict[str, str]] = None

    # ── Scanning ─────────────────────────────────────────────────────────────
    profile: str = ScanProfile.BALANCED
    enabled_scanners: Union[str, List[str]] = "__all__"
    passive_only: bool = False
    api_mode: bool = False
    use_browser: bool = False
    fuzzing_depth: str = "normal"     # normal / deep / extreme
    confirmation_rounds: int = 2
    retry_failed: int = 2
    brute_force: bool = False
    # ── Profile-specific (Authenticated / Cloud) ────────────────────────────
    auth_required: bool = False
    required_capabilities: List[str] = field(default_factory=list)
    session_revalidation_interval: int = 300
    cloud_mode: bool = False
    check_cloud_metadata_endpoints: bool = False
    cloud_metadata_targets: List[str] = field(default_factory=list)

    # ── Output ───────────────────────────────────────────────────────────────
    output_dir: str = "./webshield_reports"
    output_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    report_name: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    color_output: bool = True

    # ── Cache ─────────────────────────────────────────────────────────────────
    cache_enabled: bool = True
    cache_ttl: int = 3600           # seconds
    cache_dir: str = "./.webshield_cache"

    # ── State & Resume ────────────────────────────────────────────────────────
    state_file: Optional[str] = None
    resume: bool = False
    state_dir: str = "./.webshield_state"
    autosave_interval: float = 15.0     # ثواني بين كل Auto-save للـ State

    # ── Replay ───────────────────────────────────────────────────────────────
    replay_dir: str = "./.webshield_replay"
    replay_max_body_chars: int = 4000   # أقصى عدد حروف يتخزن من الـ Body

    # ── Plugins ──────────────────────────────────────────────────────────────
    plugin_dirs: List[str] = field(default_factory=list)
    disabled_plugins: List[str] = field(default_factory=list)

    # ── Security (internal) ───────────────────────────────────────────────────
    mask_secrets_in_logs: bool = True
    safe_mode: bool = False          # يمنع أي Payload مدمر
    security_key_path: Optional[str] = None    # مفتاح تشفير SecretsVault (Part 10)

    # ── Data & Storage ───────────────────────────────────────────────────────
    data_dir: str = "./.webshield_data"          # الجذر لـ StorageManager (Part 9)
    storage_compress_threshold_kb: int = 64       # حد ضغط البيانات الكبيرة (KB)


# ── Config Framework ──────────────────────────────────────────────────────────

class ConfigFramework:
    """
    مدير الإعدادات المركزي.
    
    الأولوية (من الأعلى للأدنى):
    1. Runtime overrides (set() في الكود)
    2. Environment variables  (WEBSHIELD_*)
    3. CLI arguments
    4. Config file (YAML/JSON)
    5. Profile defaults
    6. Built-in defaults (WebShieldConfig)
    """

    def __init__(self, config_file: Optional[str] = None) -> None:
        self._config = WebShieldConfig()
        self._overrides: Dict[str, Any] = {}
        
        # تطبيق الـ Profile الافتراضي
        self.apply_profile(ScanProfile.BALANCED)
        
        # تحميل ملف الإعدادات لو موجود
        if config_file:
            self.load_file(config_file)
        
        # تطبيق متغيرات البيئة
        self._load_env_vars()

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_file(self, path: str) -> None:
        """يحمل إعدادات من ملف JSON أو YAML."""
        p = Path(path)
        if not p.exists():
            return
        
        content = p.read_text(encoding="utf-8")
        
        if p.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(content)
            except ImportError:
                raise RuntimeError("PyYAML مش مثبت. اعمل: pip install pyyaml")
        else:
            data = json.loads(content)
        
        if isinstance(data, dict):
            self._apply_dict(data)

    def _load_env_vars(self) -> None:
        """يحمل الإعدادات من متغيرات البيئة (WEBSHIELD_KEY=value)."""
        prefix = "WEBSHIELD_"
        for key, value in os.environ.items():
            if key.startswith(prefix):
                attr = key[len(prefix):].lower()
                if hasattr(self._config, attr):
                    current = getattr(self._config, attr)
                    try:
                        if isinstance(current, bool):
                            setattr(self._config, attr, value.lower() in ("1", "true", "yes"))
                        elif isinstance(current, int):
                            setattr(self._config, attr, int(value))
                        elif isinstance(current, float):
                            setattr(self._config, attr, float(value))
                        elif isinstance(current, list):
                            setattr(self._config, attr, value.split(","))
                        else:
                            setattr(self._config, attr, value)
                    except (ValueError, TypeError):
                        pass

    def _apply_dict(self, data: Dict[str, Any]) -> None:
        for key, value in data.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)

    # ── Profile ───────────────────────────────────────────────────────────────

    def apply_profile(self, profile_name: str) -> None:
        """يطبق Profile ويغير الإعدادات المناسبة تلقائياً."""
        profile_data = ScanProfile.get(profile_name)
        self._apply_dict(profile_data)
        self._config.profile = profile_name

    # ── Get / Set ─────────────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """يرجع قيمة إعداد معين."""
        # Runtime overrides أعلى أولوية
        if key in self._overrides:
            return self._overrides[key]
        return getattr(self._config, key, default)

    def set(self, key: str, value: Any) -> None:
        """يعدل إعداد في Runtime (أعلى أولوية من كل حاجة)."""
        self._overrides[key] = value
        if hasattr(self._config, key):
            setattr(self._config, key, value)

    def set_many(self, updates: Dict[str, Any]) -> None:
        for key, value in updates.items():
            self.set(key, value)

    @property
    def config(self) -> WebShieldConfig:
        return self._config

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self._config)
        # إخفاء البيانات الحساسة
        sensitive = {"session_token", "auth_credentials", "proxy_auth"}
        for key in sensitive:
            if key in d and d[key]:
                d[key] = "***"
        return d

    def __repr__(self) -> str:
        return f"ConfigFramework(profile={self._config.profile}, target={self._config.target_url!r})"
