"""
WebShield Dependency Manager
================================
يدير اعتماديات المكونات الداخلية (Plugins / Services) جوه الـ Platform.

كل مكون يقدر يعلن إنه محتاج مكونات تانية تشتغل قبله، والـ DependencyManager
مسؤول عن:
    - تسجيل كل مكون واعتمادياته
    - حساب ترتيب التشغيل الصحيح (Topological Order)
    - اكتشاف الاعتماديات الدائرية (Circular Dependencies)
    - اكتشاف الاعتماديات الناقصة (Missing Dependencies) قبل التشغيل
    - منع تشغيل أي مكون قبل ما اعتمادياته تخلص تشغيل بنجاح

ده مختلف عن الـ Capability System (اللي بيتحقق من إمكانيات البيئة زي
Browser/DNS/WebSocket) — الـ DependencyManager بيتحقق من العلاقة بين
المكونات الداخلية لبعضها (مثال: WorkflowEngine محتاج EventBus يشتغل الأول،
أو Scanner X محتاج Fingerprinter يشتغل قبله عشان يعرف التقنية المستخدمة).
"""
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WebShield — Dependency Manager                                         ║
# ║  Copyright (c) 2026 علاء محمود البدوي (Alaa Mahmoud El-Badawi)         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .logging_system import PlatformLogger
from .error_framework import WebShieldError


class DependencyError(WebShieldError):
    """خطأ عام في نظام الاعتماديات."""


class CircularDependencyError(DependencyError):
    """اعتمادية دائرية بين مكونين أو أكتر."""

    def __init__(self, cycle: List[str]) -> None:
        self.cycle = cycle
        super().__init__(
            "Circular dependency detected: " + " → ".join(cycle + [cycle[0]])
        )


class MissingDependencyError(DependencyError):
    """مكون بيعتمد على مكون تاني مش مسجل أصلاً."""

    def __init__(self, component: str, missing: str) -> None:
        self.component = component
        self.missing = missing
        super().__init__(
            f"Component '{component}' depends on unregistered component '{missing}'"
        )


@dataclass
class ComponentNode:
    """مكون مسجل في الـ DependencyManager."""

    name: str
    depends_on: Set[str] = field(default_factory=set)
    optional_depends_on: Set[str] = field(default_factory=set)
    started: bool = False
    metadata: Dict[str, object] = field(default_factory=dict)


class DependencyManager:
    """
    مدير اعتماديات المكونات الداخلية في WebShield Platform.

    الاستخدام:
        deps = DependencyManager()
        deps.register("event_bus")
        deps.register("workflow_engine", depends_on=["event_bus"])
        deps.register("xss_scanner", depends_on=["fingerprinter"],
                       optional_depends_on=["auth_session"])

        deps.validate()                  # يتأكد إن كل حاجة سليمة
        order = deps.resolution_order()  # ترتيب التشغيل الصحيح

        for name in order:
            ... start component ...
            deps.mark_started(name)
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, ComponentNode] = {}
        self._logger = PlatformLogger.get("DependencyManager")

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        name: str,
        depends_on: Optional[List[str]] = None,
        optional_depends_on: Optional[List[str]] = None,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        """يسجل مكون جديد مع اعتمادياته."""
        if name in self._nodes:
            # Re-registration: merge dependencies instead of failing,
            # since plugins may be registered incrementally.
            node = self._nodes[name]
            node.depends_on.update(depends_on or [])
            node.optional_depends_on.update(optional_depends_on or [])
            if metadata:
                node.metadata.update(metadata)
            return

        self._nodes[name] = ComponentNode(
            name=name,
            depends_on=set(depends_on or []),
            optional_depends_on=set(optional_depends_on or []),
            metadata=metadata or {},
        )
        self._logger.debug(
            f"Component registered: {name} "
            f"(depends_on={sorted(depends_on or [])})"
        )

    def unregister(self, name: str) -> None:
        self._nodes.pop(name, None)

    def is_registered(self, name: str) -> bool:
        return name in self._nodes

    # ── Validation ────────────────────────────────────────────────────────────

    def missing_dependencies(self) -> Dict[str, List[str]]:
        """يرجع dict: اسم المكون → اعتماديات إجبارية مش متسجلة."""
        missing: Dict[str, List[str]] = {}
        for name, node in self._nodes.items():
            gaps = sorted(d for d in node.depends_on if d not in self._nodes)
            if gaps:
                missing[name] = gaps
        return missing

    def find_cycle(self) -> Optional[List[str]]:
        """يدور على أي Circular Dependency. يرجع المسار لو لقى، أو None."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {name: WHITE for name in self._nodes}
        path: List[str] = []

        def visit(name: str) -> Optional[List[str]]:
            color[name] = GRAY
            path.append(name)
            for dep in self._nodes[name].depends_on:
                if dep not in self._nodes:
                    continue  # missing deps handled separately
                if color.get(dep) == GRAY:
                    cycle_start = path.index(dep)
                    return path[cycle_start:]
                if color.get(dep) == WHITE:
                    result = visit(dep)
                    if result:
                        return result
            path.pop()
            color[name] = BLACK
            return None

        for name in self._nodes:
            if color[name] == WHITE:
                result = visit(name)
                if result:
                    return result
        return None

    def validate(self, raise_on_error: bool = True) -> bool:
        """
        يتحقق من سلامة كل الاعتماديات:
        - مفيش اعتماديات ناقصة (Missing)
        - مفيش اعتماديات دائرية (Circular)

        لو raise_on_error=True (الافتراضي) بيرفع Exception أول مشكلة يلاقيها.
        لو False بيرجع True/False من غير ما يرفع حاجة.
        """
        missing = self.missing_dependencies()
        if missing:
            if raise_on_error:
                component, gaps = next(iter(missing.items()))
                raise MissingDependencyError(component, gaps[0])
            self._logger.error(f"Missing dependencies detected: {missing}")
            return False

        cycle = self.find_cycle()
        if cycle:
            if raise_on_error:
                raise CircularDependencyError(cycle)
            self._logger.error(f"Circular dependency detected: {cycle}")
            return False

        return True

    # ── Resolution ────────────────────────────────────────────────────────────

    def resolution_order(self) -> List[str]:
        """
        يرجع ترتيب التشغيل الصحيح (Topological Sort) بحيث أي مكون
        يتشغل بعد كل اعتمادياته الإجبارية والاختيارية المتاحة.
        """
        self.validate(raise_on_error=True)

        visited: Set[str] = set()
        order: List[str] = []

        def visit(name: str) -> None:
            if name in visited:
                return
            visited.add(name)
            node = self._nodes[name]
            all_deps = sorted(node.depends_on | (node.optional_depends_on & self._nodes.keys()))
            for dep in all_deps:
                visit(dep)
            order.append(name)

        for name in sorted(self._nodes.keys()):
            visit(name)

        return order

    # ── Runtime tracking ──────────────────────────────────────────────────────

    def mark_started(self, name: str) -> None:
        if name in self._nodes:
            self._nodes[name].started = True

    def can_start(self, name: str) -> bool:
        """يتأكد إن كل الاعتماديات الإجبارية لمكون معين خلصت تشغيل."""
        node = self._nodes.get(name)
        if node is None:
            return False
        return all(
            self._nodes[dep].started
            for dep in node.depends_on
            if dep in self._nodes
        )

    def startable_components(self) -> List[str]:
        """يرجع كل المكونات الجاهزة تشتغل دلوقتي (اعتمادياتها كلها خلصت)."""
        return [
            name for name, node in self._nodes.items()
            if not node.started and self.can_start(name)
        ]

    # ── Introspection ─────────────────────────────────────────────────────────

    def get_dependents(self, name: str) -> List[str]:
        """يرجع كل المكونات اللي بتعتمد على المكون ده."""
        return sorted(
            other for other, node in self._nodes.items()
            if name in node.depends_on or name in node.optional_depends_on
        )

    def get_dependencies(self, name: str) -> Set[str]:
        node = self._nodes.get(name)
        return set(node.depends_on) if node else set()

    def status(self) -> Dict[str, Dict[str, object]]:
        return {
            name: {
                "depends_on": sorted(node.depends_on),
                "optional_depends_on": sorted(node.optional_depends_on),
                "started": node.started,
            }
            for name, node in self._nodes.items()
        }

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, name: str) -> bool:
        return name in self._nodes

    def __repr__(self) -> str:
        return f"DependencyManager({len(self._nodes)} components)"
