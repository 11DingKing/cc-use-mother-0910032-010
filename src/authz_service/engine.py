"""授权领域引擎：依赖登记、包冻结、只追加决定、时间点有效性与图谱传播。

核心语义
========
授权在时刻 *t* 对某服务范围有效，当且仅当：

1. *t* 之前存在生效的批准类决定（批准 / 部分批准 / 替代设备），确定了
   基线修订与已批准范围；
2. 该范围在 *t* 未被条件暂停（且之后未恢复则持续暂停）；
3. 基线修订固定的**全部**依赖在 *t* 均为有效状态，且固定版本已生效。

任一项不成立则授权在该时刻无效——单个依赖撤销会立即（就未来而言）
使整体授权失效，而不需要逐项审批开关。
"""
from __future__ import annotations

import functools
import threading
from datetime import datetime
from typing import Any, Optional

from .hashing import digest
from .models import (
    CATEGORIES,
    DEC_APPROVE,
    DEC_DENY,
    DEC_PARTIAL,
    DEC_RESUME,
    DEC_SUBSTITUTE,
    DEC_SUSPEND,
    DEP_ACTIVE,
    DEP_EXPIRED,
    DEP_REVOKED,
    DEP_SUSPENDED,
    PKG_ARCHIVED,
    PKG_DECIDED,
    PKG_DRAFT,
    PKG_SUBMITTED,
    VALID_STATUSES,
    AuthorizationPackage,
    Decision,
    Dependency,
    DependencyEvent,
    DependencyVersion,
    PackageRevision,
    Pin,
    ServiceRecord,
    new_id,
    now_iso,
    parse_time,
)
from .repository import Repository
from .rules import SUBMIT_RULES, RuleViolation, run_rules


class DomainError(Exception):
    """领域规则冲突（状态机、时间线、范围等）。"""

    def __init__(self, message: str, code: str = "DOMAIN_ERROR") -> None:
        super().__init__(message)
        self.code = code


class IntegrityError(DomainError):
    """提交/替代时完整性校验未通过。"""

    def __init__(self, violations: list[RuleViolation]) -> None:
        super().__init__("完整性校验未通过", "INTEGRITY_VIOLATION")
        self.violations = violations


# 状态机允许的依赖状态迁移（依据当前生效状态）
_DEP_TRANSITIONS: dict[str, frozenset[str]] = {
    DEP_ACTIVE: frozenset({DEP_SUSPENDED, DEP_REVOKED, DEP_EXPIRED}),
    DEP_SUSPENDED: frozenset({DEP_ACTIVE, DEP_REVOKED, DEP_EXPIRED}),
    DEP_REVOKED: frozenset(),
    DEP_EXPIRED: frozenset(),
}

_APPROVAL_DECISIONS = frozenset({DEC_APPROVE, DEC_PARTIAL, DEC_SUBSTITUTE})


def _locked(method):  # 引擎级串行化，保证多步读写与决定序号的原子性
    @functools.wraps(method)
    def wrapper(self: "AuthorizationEngine", *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class AuthorizationEngine:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # 依赖登记与版本
    # ------------------------------------------------------------------ #
    @_locked
    def register_dependency(
        self,
        *,
        org_id: str,
        category: str,
        name: str,
        evidence: dict[str, Any],
        requires: Optional[list[str]] = None,
        valid_from: Optional[str] = None,
        actor: str = "机构合规员",
    ) -> Dependency:
        if category not in CATEGORIES:
            raise DomainError(f"条件类别必须是 {CATEGORIES} 之一", "BAD_CATEGORY")
        if not name or not str(name).strip():
            raise DomainError("依赖名称不能为空", "BAD_NAME")
        if not isinstance(evidence, dict) or not evidence:
            raise DomainError("证据必须是非空对象", "BAD_EVIDENCE")
        effective = parse_time(valid_from)
        dep = Dependency(
            dep_id=new_id("dep"),
            org_id=org_id,
            category=category,
            name=name,
        )
        dep.versions.append(
            DependencyVersion(
                version=1,
                evidence=evidence,
                evidence_digest=digest(evidence),
                valid_from=effective.isoformat(),
                requires=list(requires or []),
            )
        )
        # 登记即产生首个生效事件，时间线从此开始
        dep.events.append(
            DependencyEvent(
                seq=1,
                status=DEP_ACTIVE,
                effective_at=effective.isoformat(),
                reason="登记生效",
                actor=actor,
            )
        )
        self.repo.save_dependency(dep)
        return dep

    @_locked
    def new_evidence_version(
        self,
        *,
        dep_id: str,
        org_id: str,
        evidence: dict[str, Any],
        requires: Optional[list[str]] = None,
        actor: str = "机构合规员",
    ) -> Dependency:
        """补充证据（如许可换证）形成新版本；已固定的旧修订不受影响。"""
        dep = self.repo.get_dependency(dep_id, org_id)
        if not isinstance(evidence, dict) or not evidence:
            raise DomainError("证据必须是非空对象", "BAD_EVIDENCE")
        latest = dep.latest_version()
        dep.versions.append(
            DependencyVersion(
                version=latest.version + 1,
                evidence=evidence,
                evidence_digest=digest(evidence),
                valid_from=now_iso(),
                requires=list(requires if requires is not None else latest.requires),
            )
        )
        self.repo.save_dependency(dep)
        return dep

    @_locked
    def change_dependency_status(
        self,
        *,
        dep_id: str,
        org_id: str,
        status: str,
        effective_at: Optional[str] = None,
        reason: str = "",
        actor: str = "监管人员",
    ) -> Dependency:
        """追加暂停/恢复/撤销/到期事件；事件时间只许不前移，保证历史不可变。"""
        dep = self.repo.get_dependency(dep_id, org_id)
        if status not in VALID_STATUSES:
            raise DomainError(f"未知依赖状态：{status}", "BAD_STATUS")
        effective = parse_time(effective_at)
        last_event = dep.events[-1]
        last_time = parse_time(last_event.effective_at)
        if effective < last_time:
            raise DomainError(
                f"事件生效时间 {effective.isoformat()} 早于上一事件 "
                f"{last_event.effective_at}；已成形的历史不得改写",
                "BACKDATED_EVENT",
            )
        current = dep.status_at(effective)
        # 同一时刻重复设置同一状态视为幂等无操作
        if current == status:
            return dep
        if status not in _DEP_TRANSITIONS.get(current, frozenset()):
            raise DomainError(
                f"依赖不能从 {current} 迁移到 {status}", "BAD_TRANSITION"
            )
        dep.events.append(
            DependencyEvent(
                seq=last_event.seq + 1,
                status=status,
                effective_at=effective.isoformat(),
                reason=reason or ("恢复生效" if status == DEP_ACTIVE else ""),
                actor=actor,
            )
        )
        self.repo.save_dependency(dep)
        return dep

    # ------------------------------------------------------------------ #
    # 授权包登记与提交冻结
    # ------------------------------------------------------------------ #
    @_locked
    def create_package(
        self,
        *,
        org_id: str,
        project_code: str,
        scopes: list[str],
        pin_specs: list[dict[str, Any]],
    ) -> AuthorizationPackage:
        if not project_code or not str(project_code).strip():
            raise DomainError("治疗项目编码不能为空", "BAD_PROJECT")
        clean_scopes = self._clean_scopes(scopes)
        if not pin_specs:
            raise DomainError("授权包至少包含一项条件", "EMPTY_PACKAGE")
        pins: list[Pin] = []
        seen: set[str] = set()
        for spec in pin_specs:
            dep_id = spec.get("dep_id")
            if not dep_id:
                raise DomainError("固定项缺少 dep_id", "BAD_PIN")
            if dep_id in seen:
                raise DomainError(f"依赖 {dep_id} 在包内重复固定", "DUPLICATE_PIN")
            seen.add(dep_id)
            dep = self.repo.get_dependency(dep_id, org_id)  # 同机构隔离
            pins.append(
                Pin(
                    dep_id=dep.dep_id,
                    category=dep.category,
                    label=str(spec.get("label") or dep.name),
                    required=bool(spec.get("required", True)),
                )
            )
        package = AuthorizationPackage(
            package_id=new_id("pkg"),
            org_id=org_id,
            project_code=project_code,
            scopes=clean_scopes,
            pins_draft=pins,
            created_at=now_iso(),
        )
        self.repo.save_package(package)
        return package

    @_locked
    def submit_package(
        self, *, package_id: str, org_id: str, actor: str = "机构合规员"
    ) -> AuthorizationPackage:
        """固定证据摘要并运行完整性规则，通过后冻结为修订 v1。"""
        package = self.repo.get_package(package_id, org_id)
        if package.state != PKG_DRAFT:
            raise DomainError(
                f"当前状态 {package.state} 不能提交（仅 登记 状态可提交）",
                "BAD_STATE",
            )
        frozen = self._freeze_pins(package, package.pins_draft)
        deps = self._dep_index(package.org_id)
        violations = run_rules(
            SUBMIT_RULES, package=package, pins=frozen, deps=deps
        )
        if violations:
            raise IntegrityError(violations)
        manifest = self._manifest_digest(package, frozen)
        package.revisions.append(
            PackageRevision(
                version=1,
                pins=frozen,
                manifest_digest=manifest,
                created_at=now_iso(),
                note=f"{actor} 提交冻结",
            )
        )
        package.state = PKG_SUBMITTED
        self.repo.save_package(package)
        return package

    # ------------------------------------------------------------------ #
    # 只追加的授权决定
    # ------------------------------------------------------------------ #
    @_locked
    def decide(
        self,
        *,
        package_id: str,
        org_id: str,
        decision: str,
        scopes: Optional[list[str]] = None,
        replacements: Optional[list[dict[str, str]]] = None,
        reason: str = "",
        effective_at: Optional[str] = None,
        actor: str = "复核专家",
    ) -> AuthorizationPackage:
        package = self.repo.get_package(package_id, org_id)
        effective = self._check_decision_time(package, parse_time(effective_at))

        if decision == DEC_APPROVE:
            self._do_approve(package, effective, actor, reason, partial_scopes=None)
        elif decision == DEC_PARTIAL:
            subset = self._clean_scopes(scopes or [])
            if not subset or not set(subset) <= set(package.scopes):
                raise DomainError(
                    "部分批准的范围必须是申请范围的非空子集", "BAD_SCOPES"
                )
            self._do_approve(
                package, effective, actor, reason, partial_scopes=subset
            )
        elif decision == DEC_DENY:
            if package.state != PKG_SUBMITTED:
                raise DomainError("仅 待核验 的申请可不予批准", "BAD_STATE")
            self._append_decision(
                package,
                Decision(
                    seq=len(package.decisions) + 1,
                    type=DEC_DENY,
                    effective_at=effective.isoformat(),
                    actor=actor,
                    reason=reason,
                ),
            )
            package.state = PKG_DECIDED
        elif decision == DEC_SUBSTITUTE:
            self._do_substitute(
                package, effective, actor, reason, replacements or []
            )
        elif decision == DEC_SUSPEND:
            self._do_suspend_resume(
                package,
                effective,
                actor,
                reason,
                scopes,
                suspend=True,
            )
        elif decision == DEC_RESUME:
            self._do_suspend_resume(
                package,
                effective,
                actor,
                reason,
                scopes,
                suspend=False,
            )
        else:
            raise DomainError(f"未知决定类型：{decision}", "BAD_DECISION")

        self.repo.save_package(package)
        return package

    @_locked
    def archive_package(
        self, *, package_id: str, org_id: str, actor: str = "机构合规员"
    ) -> AuthorizationPackage:
        package = self.repo.get_package(package_id, org_id)
        if package.state == PKG_ARCHIVED:
            return package
        if package.state != PKG_DECIDED:
            raise DomainError("仅 已决定 的授权可归档", "BAD_STATE")
        package.state = PKG_ARCHIVED
        self.repo.save_package(package)
        return package

    def _do_approve(
        self,
        package: AuthorizationPackage,
        effective: datetime,
        actor: str,
        reason: str,
        partial_scopes: Optional[list[str]],
    ) -> None:
        if package.state != PKG_SUBMITTED:
            raise DomainError("仅 待核验 的申请可批准", "BAD_STATE")
        revision = package.latest_revision
        assert revision is not None
        decision_type = DEC_PARTIAL if partial_scopes is not None else DEC_APPROVE
        approved_scopes = (
            partial_scopes if partial_scopes is not None else package.scopes
        )
        self._append_decision(
            package,
            Decision(
                seq=len(package.decisions) + 1,
                type=decision_type,
                effective_at=effective.isoformat(),
                actor=actor,
                reason=reason,
                new_version=revision.version,
                scopes=list(approved_scopes),
            ),
        )
        package.state = PKG_DECIDED

    def _do_substitute(
        self,
        package: AuthorizationPackage,
        effective: datetime,
        actor: str,
        reason: str,
        replacements: list[dict[str, str]],
    ) -> None:
        """替代设备：以替代依赖生成新修订，旧修订保留服务于历史判定。"""
        if package.state != PKG_DECIDED:
            raise DomainError("替代设备只适用于已决定的授权", "BAD_STATE")
        baseline = self._baseline_at(package, effective)
        if baseline is None:
            raise DomainError("授权当前无生效批准，不能替代设备", "NO_BASELINE")
        if not replacements:
            raise DomainError("替代设备必须给出替换项", "NO_REPLACEMENT")

        old_pins = list(baseline.revision.pins)
        replace_records: list[dict[str, str]] = []
        remove_ids: set[str] = set()
        add_specs: list[dict[str, str]] = []
        for item in replacements:
            remove_id = item.get("remove")
            add_id = item.get("add")
            if not remove_id or not add_id:
                raise DomainError(
                    "每个替换项需要 remove 与 add 两个依赖标识", "BAD_REPLACEMENT"
                )
            if remove_id == add_id:
                raise DomainError(
                    f"替代依赖不能与被替代依赖相同：{remove_id}", "BAD_REPLACEMENT"
                )
            if not any(p.dep_id == remove_id for p in old_pins):
                raise DomainError(
                    f"被替代依赖 {remove_id} 不在当前基线修订中", "PIN_NOT_FOUND"
                )
            old_dep = self.repo.internal_get_dependency(remove_id)
            new_dep = self.repo.get_dependency(add_id, package.org_id)
            if old_dep is not None and new_dep.category != old_dep.category:
                raise DomainError(
                    f"替代依赖类别必须一致：{old_dep.category} → {new_dep.category}",
                    "CATEGORY_MISMATCH",
                )
            remove_ids.add(remove_id)
            add_specs.append(
                {"dep_id": add_id, "label": item.get("label") or new_dep.name}
            )
            replace_records.append(
                {
                    "remove": remove_id,
                    "add": add_id,
                    "category": new_dep.category,
                }
            )

        surviving = [p for p in old_pins if p.dep_id not in remove_ids]
        added = self._freeze_pins(
            package,
            [
                Pin(
                    dep_id=spec["dep_id"],
                    category=self.repo.get_dependency(
                        spec["dep_id"], package.org_id
                    ).category,
                    label=spec["label"],
                )
                for spec in add_specs
            ],
        )
        new_pins = surviving + added
        deps = self._dep_index(package.org_id)
        violations = run_rules(
            SUBMIT_RULES, package=package, pins=new_pins, deps=deps
        )
        if violations:
            raise IntegrityError(violations)

        new_number = package.latest_revision.version + 1  # type: ignore[union-attr]
        package.revisions.append(
            PackageRevision(
                version=new_number,
                pins=new_pins,
                manifest_digest=self._manifest_digest(package, new_pins),
                created_at=now_iso(),
                note=f"{actor} 替代设备",
            )
        )
        # 新的批准类决定：基线切到新修订；历史时点仍按旧修订判定
        self._append_decision(
            package,
            Decision(
                seq=len(package.decisions) + 1,
                type=DEC_SUBSTITUTE,
                effective_at=effective.isoformat(),
                actor=actor,
                reason=reason,
                new_version=new_number,
                scopes=list(baseline.scopes),
                replaces=replace_records,
            ),
        )

    def _do_suspend_resume(
        self,
        package: AuthorizationPackage,
        effective: datetime,
        actor: str,
        reason: str,
        scopes: Optional[list[str]],
        *,
        suspend: bool,
    ) -> None:
        if package.state != PKG_DECIDED:
            raise DomainError(
                "仅 已决定 的授权可条件暂停或恢复", "BAD_STATE"
            )
        baseline = self._baseline_at(package, effective)
        if baseline is None:
            raise DomainError("授权当前无生效批准", "NO_BASELINE")
        targets = set(self._clean_scopes(scopes or []))
        if not targets or not targets <= set(baseline.scopes):
            raise DomainError(
                "暂停/恢复范围必须是当前已批准范围的非空子集", "BAD_SCOPES"
            )
        suspended = self._suspended_at(package, effective)
        if suspend:
            if targets <= suspended:
                raise DomainError("所列范围均已暂停", "ALREADY_SUSPENDED")
            decision_type = DEC_SUSPEND
        else:
            if not (targets & suspended):
                raise DomainError("所列范围均未暂停，无可恢复项", "NOT_SUSPENDED")
            decision_type = DEC_RESUME
        self._append_decision(
            package,
            Decision(
                seq=len(package.decisions) + 1,
                type=decision_type,
                effective_at=effective.isoformat(),
                actor=actor,
                reason=reason,
                scopes=sorted(targets),
            ),
        )

    # ------------------------------------------------------------------ #
    # 时间点有效性
    # ------------------------------------------------------------------ #
    @_locked
    def evaluate(
        self, package: AuthorizationPackage, at: Optional[datetime] = None
    ) -> dict[str, Any]:
        """计算授权在某时刻对各服务范围的有效性（合取式）。"""
        moment = at or parse_time(None)
        baseline = self._baseline_at(package, moment)
        suspended = self._suspended_at(package, moment)
        result: dict[str, Any] = {
            "at": moment.isoformat(),
            "approved": baseline is not None,
            "baseline_revision": baseline.revision.version if baseline else None,
            "approved_scopes": sorted(baseline.scopes) if baseline else [],
            "suspended_scopes": sorted(suspended),
            "conditions": [],
            "scopes": {},
        }
        if baseline is None:
            result["conditions"].append("无生效的批准决定")
            for scope in package.scopes:
                result["scopes"][scope] = {
                    "authorized": False,
                    "reasons": ["无生效的批准决定"],
                }
            return result

        pin_states: list[dict[str, Any]] = []
        broken: list[str] = []
        for pin in baseline.revision.pins:
            status, detail = self._pin_status_at(pin, moment)
            pin_states.append(
                {
                    "dep_id": pin.dep_id,
                    "category": pin.category,
                    "label": pin.label,
                    "version": pin.version,
                    "evidence_digest": pin.evidence_digest,
                    "status": status,
                    "detail": detail,
                }
            )
            if status != DEP_ACTIVE:
                broken.append(f"{pin.category}·{pin.label}（{detail}）")
        result["conditions"] = pin_states
        for scope in package.scopes:
            reasons: list[str] = []
            if scope not in baseline.scopes:
                reasons.append("该范围不在批准决定内（部分授权）")
            if scope in suspended:
                reasons.append("该范围处于条件暂停中")
            reasons.extend(broken)
            result["scopes"][scope] = {
                "authorized": not reasons,
                "reasons": reasons,
            }
        result["authorized"] = all(
            item["authorized"] for item in result["scopes"].values()
        )
        return result

    @_locked
    def record_service(
        self,
        *,
        package_id: str,
        org_id: str,
        scope: str,
        service_at: Optional[str] = None,
    ) -> ServiceRecord:
        """登记一次服务：按**服务发生时点**判定并冻结结论，事后依赖变化不改写。"""
        package = self.repo.get_package(package_id, org_id)
        if scope not in package.scopes:
            raise DomainError(
                f"范围 {scope} 不属于该授权申请", "BAD_SCOPE"
            )
        moment = parse_time(service_at)
        verdict = self.evaluate(package, moment)
        scope_result = verdict["scopes"][scope]
        record = ServiceRecord(
            service_id=new_id("svc"),
            org_id=org_id,
            package_id=package_id,
            scope=scope,
            service_at=moment.isoformat(),
            recorded_at=now_iso(),
            authorized=bool(scope_result["authorized"]),
            reasons=list(scope_result["reasons"]),
            manifest_digest=(
                package.revision(verdict["baseline_revision"]).manifest_digest
                if verdict["baseline_revision"]
                else ""
            ),
        )
        self.repo.save_service(record)
        return record

    # ------------------------------------------------------------------ #
    # 依赖图谱：失效影响传播
    # ------------------------------------------------------------------ #
    @_locked
    def impact_of_dependency(self, *, dep_id: str, org_id: str) -> dict[str, Any]:
        """沿 requires 反向边与包固定边，列出受影响授权（限本机构）。"""
        root = self.repo.get_dependency(dep_id, org_id)  # 跨机构直接 NotFound

        # 由本机构各授权的“当前基线修订”构造反向边：被需要者 -> 需要者
        reverse: dict[str, set[str]] = {}
        packages = self.repo.list_packages(org_id)
        baselines: dict[str, tuple[AuthorizationPackage, "_Baseline"]] = {}
        for package in packages:
            baseline = self._baseline_at(package, parse_time(None))
            if baseline is None:
                continue
            baselines[package.package_id] = (package, baseline)
            for pin in baseline.revision.pins:
                dep = self.repo.internal_get_dependency(pin.dep_id)
                if dep is None or dep.org_id != org_id:
                    continue
                version = dep.version_at(pin.version or 0)
                if version is None:
                    continue
                for required_id in version.requires:
                    required = self.repo.internal_get_dependency(required_id)
                    if required is not None and required.org_id == org_id:
                        reverse.setdefault(required_id, set()).add(pin.dep_id)

        # BFS：root 失效会沿“需要它的依赖”向上传播
        parents: dict[str, Optional[str]] = {root.dep_id: None}
        queue = [root.dep_id]
        while queue:
            current = queue.pop(0)
            for dependent in reverse.get(current, ()):  # noqa: SIM113
                if dependent not in parents:
                    parents[dependent] = current
                    queue.append(dependent)
        reached = set(parents)

        affected: list[dict[str, Any]] = []
        affected_package_ids: set[str] = set()
        for package, baseline in baselines.values():
            pinned_now = {pin.dep_id: pin for pin in baseline.revision.pins}
            matched = sorted(set(pinned_now) & reached)
            if not matched:
                continue
            affected_package_ids.add(package.package_id)
            verdict = self.evaluate(package)
            affected.append(
                {
                    "package_id": package.package_id,
                    "project_code": package.project_code,
                    "matched_pins": [
                        {
                            "dep_id": dep_id2,
                            "category": pinned_now[dep_id2].category,
                            "label": pinned_now[dep_id2].label,
                            "path": self._path_to(parents, dep_id2),
                        }
                        for dep_id2 in matched
                    ],
                    "currently_authorized": verdict["authorized"],
                    "scope_verdict": verdict["scopes"],
                }
            )

        # 受影响授权已登记的历史服务结论已冻结，依赖失效不改写它们
        frozen_services = sum(
            1
            for record in self.repo.list_services(org_id)
            if record.package_id in affected_package_ids
            and record.manifest_digest
        )
        return {
            "dep_id": root.dep_id,
            "category": root.category,
            "name": root.name,
            "current_status": root.status_at(parse_time(None)),
            "propagated_dependencies": sorted(reached - {root.dep_id}),
            "affected_authorizations": affected,
            "future_only": True,
            "historical_services_frozen": frozen_services,
        }

    # ------------------------------------------------------------------ #
    # 内部辅助
    # ------------------------------------------------------------------ #
    def _freeze_pins(
        self, package: AuthorizationPackage, pins: list[Pin]
    ) -> list[Pin]:
        """把草案固定项解析为依赖当前最新版本并冻结证据摘要。"""
        frozen: list[Pin] = []
        for pin in pins:
            dep = self.repo.get_dependency(pin.dep_id, package.org_id)
            version = dep.latest_version()
            frozen.append(
                Pin(
                    dep_id=dep.dep_id,
                    category=dep.category,
                    label=pin.label,
                    version=version.version,
                    evidence_digest=version.evidence_digest,
                    required=pin.required,
                )
            )
        return frozen

    def _dep_index(self, org_id: str) -> dict[str, Dependency]:
        return {dep.dep_id: dep for dep in self.repo.list_dependencies(org_id)}

    @staticmethod
    def _clean_scopes(scopes: list[str]) -> list[str]:
        if not isinstance(scopes, list) or not scopes:
            raise DomainError("服务范围不能为空", "BAD_SCOPES")
        clean = [str(item).strip() for item in scopes if str(item).strip()]
        if len(clean) != len(set(clean)):
            raise DomainError("服务范围不能重复", "BAD_SCOPES")
        return clean

    @staticmethod
    def _manifest_digest(
        package: AuthorizationPackage, pins: list[Pin]
    ) -> str:
        return digest(
            {
                "package_id": package.package_id,
                "project_code": package.project_code,
                "scopes": package.scopes,
                "pins": [
                    {
                        "dep_id": p.dep_id,
                        "category": p.category,
                        "version": p.version,
                        "evidence_digest": p.evidence_digest,
                        "required": p.required,
                    }
                    for p in pins
                ],
            }
        )

    @staticmethod
    def _append_decision(package: AuthorizationPackage, decision: Decision) -> None:
        if package.decisions and decision.seq != package.decisions[-1].seq + 1:
            raise DomainError("决定序号必须连续递增", "BAD_SEQUENCE")
        package.decisions.append(decision)

    @staticmethod
    def _check_decision_time(
        package: AuthorizationPackage, effective: datetime
    ) -> datetime:
        if package.decisions:
            last = parse_time(package.decisions[-1].effective_at)
            if effective < last:
                raise DomainError(
                    "决定生效时间不能早于已有决定（历史决定不可改写）",
                    "BACKDATED_DECISION",
                )
        return effective

    def _pin_status_at(
        self, pin: Pin, moment: datetime
    ) -> tuple[str, str]:
        """返回 (状态, 说明)；active 表示该固定项在该时刻有效。"""
        dep = self.repo.internal_get_dependency(pin.dep_id)
        if dep is None:
            return "missing", "依赖不存在"
        version = dep.version_at(pin.version or 0)
        if version is None:
            return "missing", f"版本 {pin.version} 不存在"
        if parse_time(version.valid_from) > moment:
            return "future", f"版本 {pin.version} 尚未生效"
        if pin.evidence_digest != version.evidence_digest:
            return "tampered", "证据摘要与固定值不一致"
        status = dep.status_at(moment)
        labels = {
            DEP_ACTIVE: "有效",
            DEP_SUSPENDED: "已暂停",
            DEP_REVOKED: "已撤销",
            DEP_EXPIRED: "已到期",
            "pending": "尚未生效",
        }
        return status, labels.get(status, status)

    class _Baseline:  # pragma: no cover - 轻量值对象
        __slots__ = ("decision", "revision", "scopes")

        def __init__(
            self, decision: Decision, revision: PackageRevision, scopes: set[str]
        ) -> None:
            self.decision = decision
            self.revision = revision
            self.scopes = scopes

    def _baseline_at(
        self, package: AuthorizationPackage, moment: datetime
    ) -> Optional["_Baseline"]:
        """截止某时刻最新的批准类决定及其修订；暂停集合另行计算。"""
        baseline: Optional[AuthorizationEngine._Baseline] = None
        for decision in package.decisions:
            if parse_time(decision.effective_at) > moment:
                break
            if decision.type == DEC_DENY:
                return None
            if decision.type in _APPROVAL_DECISIONS:
                revision = (
                    package.revision(decision.new_version)
                    if decision.new_version is not None
                    else None
                )
                if revision is None:
                    return None
                # 新的批准类决定重建条件状态（旧暂停由新决定重新声明）
                baseline = AuthorizationEngine._Baseline(
                    decision, revision, set(decision.scopes)
                )
        return baseline

    def _suspended_at(
        self, package: AuthorizationPackage, moment: datetime
    ) -> set[str]:
        """重放到某时刻的条件暂停/恢复决定，得出暂停范围集合。"""
        suspended: set[str] = set()
        saw_approval = False
        for decision in package.decisions:
            if parse_time(decision.effective_at) > moment:
                break
            if decision.type in _APPROVAL_DECISIONS:
                saw_approval = True
                suspended = set()  # 新基线重置条件暂停
            elif decision.type == DEC_SUSPEND:
                suspended.update(decision.scopes)
            elif decision.type == DEC_RESUME:
                suspended.difference_update(decision.scopes)
        return suspended if saw_approval else set()

    @staticmethod
    def _path_to(
        parents: dict[str, Optional[str]], target: str
    ) -> list[str]:
        if target not in parents:
            return [target]
        path = [target]
        current: Optional[str] = target
        while parents.get(current) is not None:
            current = parents[current]
            path.append(current)  # type: ignore[arg-type]
        path.reverse()
        return path
