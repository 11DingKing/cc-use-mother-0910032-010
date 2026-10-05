"""项目授权依赖包 —— 服务端领域模型。

核心对象（对应领域契约的四个不变量）：

* 依赖（Dependency）：场地 / 设备 / 药械 / 人员，带显式版本与状态历史；
* 授权包（Package）：机构就某治疗项目提交的版本化清单，提交时冻结证据摘要；
* 决定（Decision）：批准、部分授权、条件暂停、恢复、替代、撤销全部是不可变新决定；
* 传播事件（PropagationEvent）：依赖失效沿授权依赖图向未来服务传播。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Kind(str, Enum):
    FACILITY = "facility"   # 场地
    DEVICE = "device"       # 设备
    DRUG = "drug"           # 药械
    PERSONNEL = "personnel"  # 人员


class DepStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class DecisionType(str, Enum):
    GRANT = "grant"                # 批准
    PARTIAL_GRANT = "partial_grant"  # 部分授权
    SUSPEND = "suspend"            # 条件暂停
    RESUME = "resume"              # 恢复
    REPLACE = "replace"            # 替代设备/药械
    REVOKE = "revoke"              # 撤销授权


class CaseState(str, Enum):
    REGISTERED = "登记"        # 登记
    PENDING = "待核验"         # 待核验
    PROCESSING = "处置中"      # 处置中
    DECIDED = "已决定"         # 已决定
    ARCHIVED = "已归档"        # 已归档


class Role(str, Enum):
    COMPLIANCE = "机构合规员"
    PRACTITIONER = "执业人员"
    REGULATOR = "监管人员"
    REVIEWER = "复核专家"


def make_principal(principal_id: str, name: str, role: Role, org_id: str) -> dict[str, Any]:
    return {"id": principal_id, "name": name, "role": role.value, "org_id": org_id}


def make_evidence(evidence_id: str, sha256: str) -> dict[str, Any]:
    return {"evidence_id": evidence_id, "sha256": sha256}


def make_dep(dep_id: str, org_id: str, kind: str, name: str, version: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": dep_id,
        "org_id": org_id,
        "kind": kind,
        "name": name,
        "current_version": version["version"],
        "versions": {version["version"]: version},
    }


def make_dep_version(
    version: int,
    evidence: list[dict[str, Any]],
    requires: list[dict[str, Any]],
    created_at: str,
) -> dict[str, Any]:
    return {
        "version": version,
        "status": DepStatus.ACTIVE.value,
        "created_at": created_at,
        "evidence": list(evidence),
        "requires": [dict(item) for item in requires],
        "status_history": [
            {"at": created_at, "from": None, "to": DepStatus.ACTIVE.value, "reason": "登记即生效", "by": None}
        ],
    }


def make_project(project_code: str, name: str, slots: list[dict[str, Any]]) -> dict[str, Any]:
    return {"project_code": project_code, "name": name, "slots": [dict(s) for s in slots]}


def make_slot(slot: str, kinds: list[str], required: bool = True, key: bool = True) -> dict[str, Any]:
    return {"slot": slot, "kinds": list(kinds), "required": required, "key": key}


def make_package_version(
    version: int,
    submitted_at: str,
    submitted_by: str,
    pins: list[dict[str, Any]],
    manifest_digest: str,
    integrity: dict[str, Any],
    case_state: str,
) -> dict[str, Any]:
    return {
        "version": version,
        "submitted_at": submitted_at,
        "submitted_by": submitted_by,
        "pins": pins,
        "manifest_digest": manifest_digest,
        "integrity": integrity,
        "case_state": case_state,
    }


def make_decision(
    seq: int,
    decision_type: str,
    package_version: int,
    actor: str,
    at: str,
    reason: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": f"DEC-{seq:04d}",
        "seq": seq,
        "type": decision_type,
        "package_version": package_version,
        "at": at,
        "by": actor,
        "reason": reason,
        "body": body,
    }


def make_service_record(
    service_id: str, slot: str, at: str, principal_id: str, manifest_digest: str, snapshot: dict[str, Any]
) -> dict[str, Any]:
    return {
        "id": service_id,
        "slot": slot,
        "at": at,
        "principal_id": principal_id,
        "eligible": True,
        "manifest_digest": manifest_digest,
        "snapshot": snapshot,
    }
