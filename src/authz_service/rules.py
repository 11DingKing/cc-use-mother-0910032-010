"""提交时与替代时运行的完整性规则。

每条规则返回 ``RuleViolation``；全部通过才允许冻结修订。规则是纯函数，
输入为包草案、固定结果与依赖索引，便于独立测试与复用。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .models import (
    CATEGORIES,
    AuthorizationPackage,
    Dependency,
    Pin,
)


@dataclass
class RuleViolation:
    code: str
    message: str
    dep_id: Optional[str] = None
    category: Optional[str] = None


Rule = Callable[..., list[RuleViolation]]


def rule_categories_present(pins: list[Pin], **_: object) -> list[RuleViolation]:
    """四类条件（场地/设备/药械/人员）必须齐备且不得重复成类级冲突。"""
    violations: list[RuleViolation] = []
    by_category: dict[str, list[Pin]] = {}
    for pin in pins:
        by_category.setdefault(pin.category, []).append(pin)
    for category in CATEGORIES:
        present = [p for p in by_category.get(category, []) if p.required]
        if not present:
            violations.append(
                RuleViolation(
                    code="CATEGORY_MISSING",
                    message=f"缺少必备条件类别：{category}",
                    category=category,
                )
            )
    unknown = set(by_category) - set(CATEGORIES)
    for category in sorted(unknown):
        violations.append(
            RuleViolation(
                code="CATEGORY_UNKNOWN",
                message=f"未知条件类别：{category}",
                category=category,
            )
        )
    return violations


def rule_dependencies_resolve(
    pins: list[Pin], deps: dict[str, Dependency], **_: object
) -> list[RuleViolation]:
    """固定引用的依赖与版本必须存在。"""
    violations: list[RuleViolation] = []
    for pin in pins:
        dep = deps.get(pin.dep_id)
        if dep is None:
            violations.append(
                RuleViolation(
                    code="DEP_NOT_FOUND",
                    message=f"依赖不存在：{pin.dep_id}",
                    dep_id=pin.dep_id,
                    category=pin.category,
                )
            )
            continue
        if dep.version_at(pin.version or 0) is None:
            violations.append(
                RuleViolation(
                    code="VERSION_NOT_FOUND",
                    message=f"依赖 {pin.dep_id} 不存在版本 {pin.version}",
                    dep_id=pin.dep_id,
                    category=pin.category,
                )
            )
    return violations


def rule_evidence_digest_matches(
    pins: list[Pin], deps: dict[str, Dependency], **_: object
) -> list[RuleViolation]:
    """证据摘要必须与依赖版本登记时冻结的摘要一致，防篡改。"""
    violations: list[RuleViolation] = []
    for pin in pins:
        dep = deps.get(pin.dep_id)
        if dep is None:
            continue
        version = dep.version_at(pin.version or 0)
        if version is None:
            continue
        if pin.evidence_digest != version.evidence_digest:
            violations.append(
                RuleViolation(
                    code="EVIDENCE_DIGEST_MISMATCH",
                    message=(
                        f"依赖 {pin.dep_id} 证据摘要不一致："
                        f"提交 {pin.evidence_digest}，登记 {version.evidence_digest}"
                    ),
                    dep_id=pin.dep_id,
                    category=pin.category,
                )
            )
    return violations


def rule_same_org(
    package: AuthorizationPackage,
    pins: list[Pin],
    deps: dict[str, Dependency],
    **_: object,
) -> list[RuleViolation]:
    """所有依赖必须属于申请机构，禁止把他人条件装进自己的包。"""
    violations: list[RuleViolation] = []
    for pin in pins:
        dep = deps.get(pin.dep_id)
        if dep is not None and dep.org_id != package.org_id:
            violations.append(
                RuleViolation(
                    code="CROSS_ORG_DEPENDENCY",
                    message=(
                        f"依赖 {pin.dep_id} 属于机构 {dep.org_id}，"
                        f"不能用于机构 {package.org_id} 的申请"
                    ),
                    dep_id=pin.dep_id,
                    category=pin.category,
                )
            )
    return violations


def rule_requires_closure(
    pins: list[Pin], deps: dict[str, Dependency], **_: object
) -> list[RuleViolation]:
    """依赖自身声明的前置依赖（requires）必须在包内全部固定。"""
    violations: list[RuleViolation] = []
    pinned = {pin.dep_id for pin in pins}
    for pin in pins:
        dep = deps.get(pin.dep_id)
        if dep is None:
            continue
        version = dep.version_at(pin.version or 0)
        if version is None:
            continue
        for required_id in version.requires:
            if required_id not in pinned:
                violations.append(
                    RuleViolation(
                        code="REQUIRES_MISSING",
                        message=(
                            f"依赖 {pin.dep_id} 需要 {required_id}，"
                            "但该前置依赖未包含在包内"
                        ),
                        dep_id=pin.dep_id,
                        category=pin.category,
                    )
                )
    return violations


def rule_no_cycle(
    pins: list[Pin], deps: dict[str, Dependency], **_: object
) -> list[RuleViolation]:
    """requires 关系不得成环（含间接环）。"""
    graph: dict[str, list[str]] = {}
    for pin in pins:
        dep = deps.get(pin.dep_id)
        if dep is None:
            continue
        version = dep.version_at(pin.version or 0)
        graph[pin.dep_id] = list(version.requires) if version else []

    color: dict[str, int] = {}  # 0 未访问 1 在栈中 2 完成

    def visit(node: str) -> bool:
        state = color.get(node, 0)
        if state == 1:
            return True
        if state == 2:
            return False
        color[node] = 1
        for nxt in graph.get(node, []):
            if nxt in graph and visit(nxt):
                return True
        color[node] = 2
        return False

    violations: list[RuleViolation] = []
    for node in graph:
        if visit(node):
            violations.append(
                RuleViolation(
                    code="REQUIRES_CYCLE",
                    message="前置依赖关系中存在环",
                    dep_id=node,
                )
            )
            break
    return violations


SUBMIT_RULES: tuple[Rule, ...] = (
    rule_categories_present,
    rule_dependencies_resolve,
    rule_evidence_digest_matches,
    rule_same_org,
    rule_requires_closure,
    rule_no_cycle,
)


def run_rules(
    rules: tuple[Rule, ...],
    *,
    package: AuthorizationPackage,
    pins: list[Pin],
    deps: dict[str, Dependency],
) -> list[RuleViolation]:
    context = {"package": package, "pins": pins, "deps": deps}
    violations: list[RuleViolation] = []
    for rule in rules:
        violations.extend(rule(**context))
    return violations
