"""核心领域服务：授权包生命周期、完整性规则、决定状态机与失效传播。

所有方法都假定调用方已通过身份与机构隔离校验（见 api.deps），
并在 STORE.lock 保护下执行；决定一旦写入即不可变。
"""
from __future__ import annotations

from typing import Any

from .digest import digest_of
from .errors import conflict, not_found, unprocessable
from .models import (
    CaseState,
    DecisionType,
    DepStatus,
    Kind,
    Role,
    make_decision,
    make_package_version,
    new_id,
    now_iso,
)
from .store import STORE


# 可作出“管理类决定”的角色
DECISION_ROLES = {Role.REGULATOR.value, Role.REVIEWER.value}


# ---------------------------------------------------------------- 读取辅助


def get_dep(dep_id: str) -> dict[str, Any]:
    dep = STORE.deps.get(dep_id)
    if dep is None:
        raise not_found(f"依赖 {dep_id} 不存在")
    return dep


def get_package(package_id: str) -> dict[str, Any]:
    pkg = STORE.packages.get(package_id)
    if pkg is None:
        raise not_found(f"授权包 {package_id} 不存在")
    return pkg


def pin_view(pin: dict[str, Any]) -> dict[str, Any]:
    return {
        "slot": pin["slot"],
        "dep_id": pin["dep_id"],
        "version": pin["version"],
        "key": pin["key"],
        "required": pin["required"],
    }


# ---------------------------------------------------------------- 依赖管理


def register_dep(principal: dict[str, Any], kind: str, name: str, evidence: list[dict],
                 requires: list[dict] | None = None) -> dict[str, Any]:
    if kind not in {k.value for k in Kind}:
        raise unprocessable("INVALID_KIND", f"依赖类别必须是 {[k.value for k in Kind]}")
    dep_id = new_id(kind[:3].upper())
    at = now_iso()
    version = {
        "version": 1,
        "status": DepStatus.ACTIVE.value,
        "created_at": at,
        "evidence": list(evidence),
        "requires": [dict(r) for r in (requires or [])],
        "status_history": [
            {"at": at, "from": None, "to": DepStatus.ACTIVE.value, "reason": "登记即生效", "by": principal["id"]}
        ],
    }
    dep = {
        "id": dep_id,
        "org_id": principal["org_id"],
        "kind": kind,
        "name": name,
        "current_version": 1,
        "versions": {1: version},
    }
    STORE.deps[dep_id] = dep
    return dep


def _new_dep_version(dep: dict[str, Any], evidence: list[dict], requires: list[dict] | None,
                     actor: str, reason: str) -> int:
    """依赖证据/要求变更 → 新版本；状态沿用最新版本（撤销不会被“洗白”）。"""
    last = dep["versions"][dep["current_version"]]
    nxt = dep["current_version"] + 1
    at = now_iso()
    dep["versions"][nxt] = {
        "version": nxt,
        "status": last["status"],
        "created_at": at,
        "evidence": list(evidence),
        "requires": [dict(r) for r in (requires if requires is not None else last["requires"])],
        "status_history": list(last["status_history"]) + [
            {"at": at, "from": last["status"], "to": last["status"], "reason": reason, "by": actor}
        ],
    }
    dep["current_version"] = nxt
    return nxt


def update_dep_evidence(principal: dict[str, Any], dep_id: str, evidence: list[dict],
                        requires: list[dict] | None = None) -> dict[str, Any]:
    dep = get_dep(dep_id)
    _new_dep_version(dep, evidence, requires, principal["id"], "证据/要求更新，产生新版本")
    return dep


def _set_dep_status(principal: dict[str, Any], dep_id: str, to_status: str, reason: str,
                    publish: bool = True) -> dict[str, Any]:
    dep = get_dep(dep_id)
    ver = dep["versions"][dep["current_version"]]
    at = now_iso()
    frm = ver["status"]
    if frm == to_status:
        raise conflict("STATUS_UNCHANGED", f"依赖 {dep_id} 当前已是 {to_status}")
    if frm == DepStatus.REVOKED.value and to_status != DepStatus.REVOKED.value:
        raise conflict("REVOKED_IS_TERMINAL", "已撤销的依赖不能恢复，请以新版本或替代依赖重新登记")
    ver["status"] = to_status
    ver["status_history"].append({"at": at, "from": frm, "to": to_status, "reason": reason, "by": principal["id"]})
    if publish:
        _publish_status_event(dep, ver["version"], to_status, principal, reason, at)
    return dep


def suspend_dep(principal: dict[str, Any], dep_id: str, reason: str) -> dict[str, Any]:
    return _set_dep_status(principal, dep_id, DepStatus.SUSPENDED.value, reason)


def resume_dep(principal: dict[str, Any], dep_id: str, reason: str) -> dict[str, Any]:
    return _set_dep_status(principal, dep_id, DepStatus.ACTIVE.value, reason)


def revoke_dep(principal: dict[str, Any], dep_id: str, reason: str) -> dict[str, Any]:
    return _set_dep_status(principal, dep_id, DepStatus.REVOKED.value, reason)


# ---------------------------------------------------------------- 授权包提交


def _validate_manifest(project: dict[str, Any], org_id: str, pins: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """完整性规则：槽位完备、类别匹配、机构归属、证据摘要齐备、引用版本存在且有效。

    返回规范化后的 pins（含 slot 元数据）。校验失败收集全部问题后一次性抛出。
    """
    problems: list[dict[str, str]] = []
    by_slot = {p["slot"]: p for p in pins}
    slots = {s["slot"]: s for s in project["slots"]}

    unknown = set(by_slot) - set(slots)
    for slot in sorted(unknown):
        problems.append({"rule": "UNKNOWN_SLOT", "slot": slot, "message": "治疗项目目录中不存在该槽位"})

    normalized: list[dict[str, Any]] = []
    for slot_def in project["slots"]:
        slot = slot_def["slot"]
        pin = by_slot.get(slot)
        if pin is None:
            if slot_def["required"]:
                problems.append({"rule": "MISSING_REQUIRED", "slot": slot, "message": "缺少必填条件槽位"})
            continue
        dep = STORE.deps.get(pin["dep_id"])
        if dep is None:
            problems.append({"rule": "DEP_NOT_FOUND", "slot": slot, "dep_id": pin["dep_id"],
                             "message": "依赖不存在"})
            continue
        if dep["org_id"] != org_id:
            # 跨机构引用：与“资源不存在”同样的报错口径，避免存在性泄露
            problems.append({"rule": "DEP_NOT_FOUND", "slot": slot, "dep_id": pin["dep_id"],
                             "message": "依赖不存在"})
            continue
        if dep["kind"] not in slot_def["kinds"]:
            problems.append({"rule": "KIND_MISMATCH", "slot": slot, "dep_id": dep["id"],
                             "message": f"依赖类别 {dep['kind']} 不能填入该槽位（允许 {slot_def['kinds']}）"})
        ver = dep["versions"].get(pin["version"])
        if ver is None:
            problems.append({"rule": "VERSION_NOT_FOUND", "slot": slot, "dep_id": dep["id"],
                             "version": pin["version"], "message": "引用的依赖版本不存在"})
        else:
            if not ver["evidence"] or any(not e.get("sha256") for e in ver["evidence"]):
                problems.append({"rule": "EVIDENCE_DIGEST_MISSING", "slot": slot, "dep_id": dep["id"],
                                 "message": "依赖证据缺少固定摘要"})
            if ver["status"] != DepStatus.ACTIVE.value:
                problems.append({"rule": "DEP_NOT_ACTIVE", "slot": slot, "dep_id": dep["id"],
                                 "message": f"依赖版本当前状态为 {ver['status']}"})
        normalized.append({
            "slot": slot,
            "dep_id": dep["id"],
            "version": pin["version"],
            "required": slot_def["required"],
            "key": slot_def.get("key", True),
        })

    if problems:
        raise unprocessable("INTEGRITY_FAILED", "授权包完整性规则校验未通过", problems)
    return normalized


def _freeze_manifest(project_code: str, org_id: str, pins: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """固定证据摘要：把每个钉住版本的证据拷贝进清单并计算总摘要。

    返回 (manifest_digest, 冻结 pins)。冻结后即使依赖端证据变化，
    已提交清单的证据快照也不再改变。
    """
    frozen = []
    for pin in pins:
        dep = STORE.deps[pin["dep_id"]]
        ver = dep["versions"][pin["version"]]
        frozen.append({
            **pin_view(pin),
            "evidence_frozen": [dict(e) for e in ver["evidence"]],
            "requires_frozen": [dict(r) for r in ver["requires"]],
        })
    manifest = {"project_code": project_code, "org_id": org_id, "pins": frozen}
    return digest_of(manifest), frozen


def submit_package(principal: dict[str, Any], project_code: str, pins: list[dict[str, Any]],
                   package_id: str | None = None) -> dict[str, Any]:
    project = STORE.projects.get(project_code)
    if project is None:
        raise not_found(f"治疗项目 {project_code} 不存在")

    normalized = _validate_manifest(project, principal["org_id"], pins)
    manifest_digest, frozen_pins = _freeze_manifest(project_code, principal["org_id"], normalized)

    at = now_iso()
    if package_id is None:
        package_id = new_id("PKG")
        pkg = {
            "id": package_id,
            "org_id": principal["org_id"],
            "project_code": project_code,
            "latest_version": 1,
            "created_at": at,
            "versions": {},
            "decisions": [],
        }
        STORE.packages[package_id] = pkg
        version_no = 1
    else:
        pkg = get_package(package_id)
        if pkg["org_id"] != principal["org_id"]:
            raise not_found()
        version_no = pkg["latest_version"] + 1
        # 冻结摘要相同的重复提交直接拒绝，防止用“新版本”绕过决定链
        prev = pkg["versions"][pkg["latest_version"]]
        if prev["manifest_digest"] == manifest_digest:
            raise conflict("MANIFEST_UNCHANGED", "清单与证据摘要与上一版本完全相同，无需重新提交")

    integrity = {
        "status": "passed",
        "rules_run": [
            "MISSING_REQUIRED", "UNKNOWN_SLOT", "KIND_MISMATCH", "DEP_OWNERSHIP",
            "VERSION_EXISTS", "EVIDENCE_DIGEST_PRESENT", "DEP_ACTIVE",
        ],
        "checked_at": at,
        "problems": [],
    }
    pkg["versions"][version_no] = make_package_version(
        version_no, at, principal["id"], frozen_pins, manifest_digest, integrity,
        CaseState.PENDING.value,
    )
    pkg["latest_version"] = version_no
    return pkg


# ---------------------------------------------------------------- 决定状态机


def _decision_body(ver: dict[str, Any], approved_slots: list[str] | None = None,
                   suspended_slots: list[str] | None = None,
                   replacements: dict[str, str] | None = None) -> dict[str, Any]:
    """生成决定时的槽位状态快照。"""
    slots: dict[str, Any] = {}
    for pin in ver["pins"]:
        slot = pin["slot"]
        suspended = slot in (suspended_slots or [])
        approved = approved_slots is None or slot in approved_slots or suspended
        dep_id = (replacements or {}).get(slot, pin["dep_id"])
        slots[slot] = {
            "dep_id": dep_id,
            "version": pin["version"] if slot not in (replacements or {}) else None,
            "status": "suspended" if suspended else ("approved" if approved else "denied"),
        }
    return {
        "slots": slots,
        "approved_slots": sorted(approved_slots) if approved_slots is not None
        else sorted(slots),
        "suspended_slots": sorted(suspended_slots or []),
    }


def _current_authorization(pkg: dict[str, Any]) -> dict[str, Any]:
    """依据不可变决定链回放，计算当前授权状态。

    状态语义：
    * approved   槽位有效；
    * suspended  条件暂停（恢复决定可解除）；
    * denied     部分授权中被拒；
    * replaced   已被替代依赖接管（原槽位以替代项为准）；
    授权整体 active 当且仅当所有必填关键槽位均 approved。
    """
    slots: dict[str, dict[str, Any]] = {}
    last_dec: dict[str, Any] | None = None
    # 只回放“当前清单版本”上作出的决定：重提交产生新版本后必须重新审批，
    # 旧版本上的批准/暂停不会自动沿用，防止借新版本洗白证据。
    for dec in pkg["decisions"]:
        if dec["package_version"] != pkg["latest_version"]:
            continue
        last_dec = dec
        t = dec["type"]
        body = dec["body"]
        if t == DecisionType.GRANT.value:
            for slot, st in body["slots"].items():
                slots[slot] = {**st, "type": t, "decision_id": dec["id"]}
        elif t == DecisionType.PARTIAL_GRANT.value:
            for slot, st in body["slots"].items():
                slots[slot] = {**st, "type": t, "decision_id": dec["id"]}
        elif t == DecisionType.SUSPEND.value:
            for slot in body.get("suspended_slots", []):
                if slot in slots and slots[slot]["status"] == "approved":
                    slots[slot] = {**slots[slot], "status": "suspended", "type": t, "decision_id": dec["id"]}
        elif t == DecisionType.RESUME.value:
            for slot in body.get("resumed_slots", []):
                if slot in slots and slots[slot]["status"] == "suspended":
                    slots[slot] = {**slots[slot], "status": "approved", "type": t, "decision_id": dec["id"]}
        elif t == DecisionType.REPLACE.value:
            for slot, info in body["slots"].items():
                if info["status"] == "replaced":
                    slots[slot] = {**info, "type": t, "decision_id": dec["id"]}
        elif t == DecisionType.REVOKE.value:
            for slot in body.get("revoked_slots", list(slots)):
                if slot in slots:
                    slots[slot] = {**slots[slot], "status": "revoked", "type": t, "decision_id": dec["id"]}

    active_required: list[str] = []
    blocked: list[dict[str, str]] = []
    for pin in pkg["versions"][pkg["latest_version"]]["pins"]:
        slot = pin["slot"]
        cur = slots.get(slot)
        if not pin["required"]:
            continue
        if cur is None:
            blocked.append({"slot": slot, "reason": "never_decided"})
        elif cur["status"] == "approved":
            active_required.append(slot)
        elif cur["status"] == "suspended":
            blocked.append({"slot": slot, "reason": "condition_suspended"})
        elif cur["status"] == "denied":
            blocked.append({"slot": slot, "reason": "denied"})
        elif cur["status"] == "revoked":
            blocked.append({"slot": slot, "reason": "revoked"})
        elif cur["status"] == "replaced":
            # 替代项的有效性由实时依赖状态决定
            dep = STORE.deps.get(cur["dep_id"])
            if dep is None or dep["versions"][cur["version"]]["status"] != DepStatus.ACTIVE.value:
                blocked.append({"slot": slot, "reason": "replacement_invalid"})
            else:
                active_required.append(slot)
    return {
        "slots": slots,
        "active": not blocked,
        "active_required_slots": sorted(active_required),
        "blocked": blocked,
        "last_decision_id": last_dec["id"] if last_dec else None,
    }


def _decide(principal: dict[str, Any], package_id: str, dtype: DecisionType, reason: str,
            build_body) -> dict[str, Any]:
    if principal["role"] not in DECISION_ROLES:
        from .errors import forbidden
        raise forbidden("只有监管人员或复核专家可以作出审批决定")
    pkg = get_package(package_id)
    if pkg["org_id"] != principal["org_id"]:
        # 复核专家同样受机构边界约束：不存在“跨机构可见”的身份。
        raise not_found()
    ver = pkg["versions"][pkg["latest_version"]]
    seq = len(pkg["decisions"]) + 1
    at = now_iso()
    body = build_body(pkg, ver, at)
    dec = make_decision(seq, dtype.value, ver["version"], principal["id"], at, reason, body)
    pkg["decisions"].append(dec)
    ver["case_state"] = CaseState.DECIDED.value
    return dec


def grant(principal: dict[str, Any], package_id: str, reason: str) -> dict[str, Any]:
    def body(pkg, ver, at):
        return _decision_body(ver)
    return _decide(principal, package_id, DecisionType.GRANT, reason, body)


def partial_grant(principal: dict[str, Any], package_id: str, reason: str, approved_slots: list[str]) -> dict[str, Any]:
    def body(pkg, ver, at):
        pins = {p["slot"]: p for p in ver["pins"]}
        unknown = [s for s in approved_slots if s not in pins]
        if unknown:
            raise unprocessable("UNKNOWN_SLOT", "批准槽位不存在", unknown)
        missing_required = [p["slot"] for p in ver["pins"] if p["required"] and p["slot"] not in approved_slots]
        b = _decision_body(ver, approved_slots=approved_slots)
        b["note"] = "部分授权：未批准的必填槽位不得开展服务"
        b["denied_required_slots"] = missing_required
        return b
    return _decide(principal, package_id, DecisionType.PARTIAL_GRANT, reason, body)


def suspend_authorization(principal: dict[str, Any], package_id: str, reason: str, slots: list[str]) -> dict[str, Any]:
    def body(pkg, ver, at):
        pins = {p["slot"]: p for p in ver["pins"]}
        unknown = [s for s in slots if s not in pins]
        if unknown:
            raise unprocessable("UNKNOWN_SLOT", "暂停槽位不存在", unknown)
        return {"suspended_slots": sorted(slots), "slots": _decision_body(ver, suspended_slots=slots)["slots"]}
    return _decide(principal, package_id, DecisionType.SUSPEND, reason, body)


def resume_authorization(principal: dict[str, Any], package_id: str, reason: str, slots: list[str]) -> dict[str, Any]:
    def body(pkg, ver, at):
        return {"resumed_slots": sorted(slots)}
    return _decide(principal, package_id, DecisionType.RESUME, reason, body)


def replace_dependency(principal: dict[str, Any], package_id: str, reason: str,
                       slot: str, replacement_dep_id: str) -> dict[str, Any]:
    def body(pkg, ver, at):
        pins = {p["slot"]: p for p in ver["pins"]}
        if slot not in pins:
            raise unprocessable("UNKNOWN_SLOT", f"槽位 {slot} 不存在")
        repl = STORE.deps.get(replacement_dep_id)
        if repl is None or repl["org_id"] != pkg["org_id"]:
            raise unprocessable("DEP_NOT_FOUND", "替代依赖不存在或不属于本机构")
        project = STORE.projects[pkg["project_code"]]
        slot_def = next(s for s in project["slots"] if s["slot"] == slot)
        if repl["kind"] not in slot_def["kinds"]:
            raise unprocessable("KIND_MISMATCH",
                                f"替代依赖类别 {repl['kind']} 不能用于槽位 {slot}")
        repl_ver = repl["versions"][repl["current_version"]]
        if repl_ver["status"] != DepStatus.ACTIVE.value:
            raise unprocessable("DEP_NOT_ACTIVE", "替代依赖当前不是有效状态")
        if not repl_ver["evidence"] or any(not e.get("sha256") for e in repl_ver["evidence"]):
            raise unprocessable("EVIDENCE_DIGEST_MISSING", "替代依赖缺少固定证据摘要")
        slots = _decision_body(ver)["slots"]
        slots[slot] = {
            "dep_id": repl["id"],
            "version": repl["current_version"],
            "status": "replaced",
            "replaces": pins[slot]["dep_id"],
            "evidence_frozen": [dict(e) for e in repl_ver["evidence"]],
        }
        return {"slots": slots, "replacement_evidence_digest": digest_of(
            [dict(e) for e in repl_ver["evidence"]])}
    return _decide(principal, package_id, DecisionType.REPLACE, reason, body)


def revoke_authorization(principal: dict[str, Any], package_id: str, reason: str,
                         slots: list[str] | None = None) -> dict[str, Any]:
    def body(pkg, ver, at):
        target = sorted(slots) if slots else sorted(p["slot"] for p in ver["pins"])
        unknown = [s for s in target if s not in {p["slot"] for p in ver["pins"]}]
        if unknown:
            raise unprocessable("UNKNOWN_SLOT", "撤销槽位不存在", unknown)
        return {"revoked_slots": target}
    return _decide(principal, package_id, DecisionType.REVOKE, reason, body)


# ---------------------------------------------------------------- 失效传播（图谱）


def _pinned_packages(dep_id: str, *, version: int | None = None, org_id: str | None = None):
    """沿“依赖 → 授权包版本钉选”的图谱边查找。"""
    out = []
    for pkg in STORE.packages.values():
        if org_id is not None and pkg["org_id"] != org_id:
            continue
        for ver_no, ver in pkg["versions"].items():
            for pin in ver["pins"]:
                if pin["dep_id"] == dep_id and (version is None or pin["version"] == version):
                    out.append((pkg, ver_no, pin))
    return out


_EVECT_BY_STATUS = {
    DepStatus.REVOKED.value: ("DEPENDENCY_REVOKED", "future_services_blocked"),
    DepStatus.SUSPENDED.value: ("DEPENDENCY_SUSPENDED", "future_services_blocked"),
    DepStatus.ACTIVE.value: ("DEPENDENCY_RESUMED", "future_services_restored"),
}


def _publish_status_event(dep: dict[str, Any], version: int, to_status: str, principal: dict[str, Any],
                          reason: str, at: str) -> None:
    """依赖状态变更事件：批准后持续跟踪关键依赖；只影响未来服务，不重写历史。"""
    event_type, effect_key = _EVECT_BY_STATUS[to_status]
    impacted = _pinned_packages(dep["id"], version=version)
    event = {
        "type": event_type,
        "dep_id": dep["id"],
        "dep_version": version,
        "to_status": to_status,
        "org_id": dep["org_id"],
        "at": at,
        "by": principal["id"],
        "reason": reason,
        "impact": [
            {
                "package_id": pkg["id"],
                "package_version": ver_no,
                "slot": pin["slot"],
                "key": pin["key"],
                "effect": effect_key if pin["key"] else "advisory",
            }
            for pkg, ver_no, pin in impacted
        ],
    }
    STORE.append_event(event)


def impact_graph(dep_id: str, version: int | None = None) -> dict[str, Any]:
    """沿授权依赖图列出受影响授权（任意状态可见性由调用方做机构过滤）。"""
    dep = get_dep(dep_id)
    hits = _pinned_packages(dep["id"], version=version)
    edges = []
    package_ids = set()
    for pkg, ver_no, pin in hits:
        package_ids.add(pkg["id"])
        edges.append({
            "package_id": pkg["id"],
            "org_id": pkg["org_id"],
            "project_code": pkg["project_code"],
            "package_version": ver_no,
            "slot": pin["slot"],
            "required": pin["required"],
            "key": pin["key"],
            "is_latest": ver_no == pkg["latest_version"],
        })
    return {
        "dep_id": dep["id"],
        "org_id": dep["org_id"],
        "kind": dep["kind"],
        "current_version": dep["current_version"],
        "queried_version": version,
        "edges": edges,
        "impacted_packages": sorted(package_ids),
    }


def list_events(org_id: str) -> list[dict[str, Any]]:
    """事件按机构隔离：机构只能看到本机构依赖的传播事件。"""
    return [e for e in STORE.events if e["org_id"] == org_id]


# ---------------------------------------------------------------- 服务准入


def _slot_live_dep(pkg: dict[str, Any], slot_state: dict[str, Any], pin: dict[str, Any]) -> dict[str, Any] | None:
    """决定槽位当前实际指向的依赖（替代决定会改写指向）。"""
    if slot_state.get("status") == "replaced":
        return STORE.deps.get(slot_state["dep_id"])
    return STORE.deps.get(pin["dep_id"])


def service_eligibility(principal: dict[str, Any], package_id: str, slot: str | None = None) -> dict[str, Any]:
    """未来服务准入：实时校验授权 + 关键依赖当前状态。

    历史服务不受影响（服务发生时记录快照）；本方法只回答“现在/未来能不能做”。
    """
    pkg = get_package(package_id)
    if pkg["org_id"] != principal["org_id"]:
        raise not_found()
    auth = _current_authorization(pkg)
    ver = pkg["versions"][pkg["latest_version"]]
    slot_states = auth["slots"]

    checks = []
    for pin in ver["pins"]:
        if slot is not None and pin["slot"] != slot:
            continue
        st = slot_states.get(pin["slot"], {"status": "never_decided"})
        dep = _slot_live_dep(pkg, st, pin)
        dep_status = dep["versions"][st.get("version") or pin["version"]]["status"] if dep else "missing"
        ok = False
        if not pin["required"]:
            # 可选（非关键）槽位无论依赖状态如何都不阻断服务，仅在检查项中如实呈现
            ok = True
        elif st["status"] in ("approved", "replaced") and dep is not None \
                and dep_status == DepStatus.ACTIVE.value:
            ok = True
        checks.append({
            "slot": pin["slot"],
            "required": pin["required"],
            "authorization": st["status"],
            "dep_id": dep["id"] if dep else (st.get("dep_id") or pin["dep_id"]),
            "dep_status": dep_status,
            "eligible": ok,
        })
    eligible = all(c["eligible"] for c in checks) and (slot is not None or auth["active"])
    return {
        "package_id": pkg["id"],
        "project_code": pkg["project_code"],
        "authorization_active": auth["active"],
        "eligible": eligible,
        "checks": checks,
        "at": now_iso(),
        "note": "依赖失效仅阻断未来服务；已完成服务的当时快照不被改写",
    }


def register_service(principal: dict[str, Any], package_id: str, slot: str) -> dict[str, Any]:
    """执业人员登记一次实际服务：通过准入后冻结当时快照。"""
    if principal["role"] != Role.PRACTITIONER.value:
        from .errors import forbidden
        raise forbidden("只有执业人员可以登记服务")
    # 任一关键条件失效都会让项目级授权失效，此时即使被请求槽位自身正常，
    # 也不得开展任何未来服务（失效传播的边界在“未来”，不在“某个槽位”）。
    elig = service_eligibility(principal, package_id)
    target = next((c for c in elig["checks"] if c["slot"] == slot), None)
    if target is None:
        raise unprocessable("UNKNOWN_SLOT", f"槽位 {slot} 不存在")
    if not elig["eligible"]:
        raise conflict("SERVICE_BLOCKED",
                       f"授权当前不具备服务条件（槽位 {slot}："
                       f"授权={target['authorization']}，依赖={target['dep_status']}）",
                       {"authorization_active": elig["authorization_active"],
                        "blocked": elig["checks"]})
    pkg = get_package(package_id)
    record = {
        "id": new_id("SVC"),
        "package_id": pkg["id"],
        "org_id": pkg["org_id"],
        "slot": slot,
        "at": now_iso(),
        "principal_id": principal["id"],
        "eligible": True,
        "manifest_digest": pkg["versions"][pkg["latest_version"]]["manifest_digest"],
        "snapshot": target,
    }
    STORE.services.setdefault(package_id, []).append(record)
    return record


def list_services(org_id: str, package_id: str | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for pid, records in STORE.services.items():
        if package_id is not None and pid != package_id:
            continue
        pkg = STORE.packages.get(pid)
        if pkg and pkg["org_id"] == org_id:
            out.extend(records)
    return sorted(out, key=lambda r: r["at"])


def package_detail(pkg: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": pkg["id"],
        "org_id": pkg["org_id"],
        "project_code": pkg["project_code"],
        "latest_version": pkg["latest_version"],
        "created_at": pkg["created_at"],
        "versions": [_version_view(pkg, n) for n in sorted(pkg["versions"])],
        "decisions": list(pkg["decisions"]),
        "current_authorization": _current_authorization(pkg),
    }


def _version_view(pkg: dict[str, Any], n: int) -> dict[str, Any]:
    ver = pkg["versions"][n]
    return {
        "version": ver["version"],
        "submitted_at": ver["submitted_at"],
        "submitted_by": ver["submitted_by"],
        "manifest_digest": ver["manifest_digest"],
        "case_state": ver["case_state"],
        "integrity": ver["integrity"],
        "pins": ver["pins"],
    }
