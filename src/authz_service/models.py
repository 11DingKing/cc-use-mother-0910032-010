"""领域模型：带版本依赖、授权包修订、只追加决定与服务记录。"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# 授权必须同时满足的四类条件（合取，缺一不可）
CATEGORIES: tuple[str, ...] = ("场地", "设备", "药械", "人员")

# 依赖生命周期状态
DEP_ACTIVE = "active"        # 有效
DEP_SUSPENDED = "suspended"  # 暂停（可恢复）
DEP_REVOKED = "revoked"      # 撤销（终态）
DEP_EXPIRED = "expired"      # 到期（终态）
TERMINAL_STATUSES = frozenset({DEP_REVOKED, DEP_EXPIRED})
VALID_STATUSES = frozenset({DEP_ACTIVE, DEP_SUSPENDED, DEP_REVOKED, DEP_EXPIRED})

# 授权包状态
PKG_DRAFT = "登记"
PKG_SUBMITTED = "待核验"
PKG_DECIDED = "已决定"
PKG_ARCHIVED = "已归档"

# 决定类型
DEC_APPROVE = "批准"
DEC_DENY = "不予批准"
DEC_PARTIAL = "部分批准"
DEC_SUBSTITUTE = "替代设备"
DEC_SUSPEND = "条件暂停"
DEC_RESUME = "恢复"

ALL_SCOPE = "*"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: Optional[str]) -> datetime:
    """解析 ISO8601；缺省取当前 UTC；朴素时间按 UTC 处理。"""
    if value is None:
        return datetime.now(timezone.utc)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class DependencyVersion:
    """依赖的一个不可变版本（证据摘要在创建时固定）。"""

    version: int
    evidence: dict[str, Any]
    evidence_digest: str
    valid_from: str
    requires: list[str] = field(default_factory=list)


@dataclass
class DependencyEvent:
    """依赖状态事件（暂停/恢复/撤销/到期）。"""

    seq: int
    status: str
    effective_at: str
    reason: str
    actor: str


@dataclass
class Dependency:
    dep_id: str
    org_id: str
    category: str
    name: str
    versions: list[DependencyVersion] = field(default_factory=list)
    events: list[DependencyEvent] = field(default_factory=list)

    def latest_version(self) -> DependencyVersion:
        return self.versions[-1]

    def status_at(self, at: datetime) -> str:
        """依赖在指定时刻的状态；首个事件之前视为未生效。"""
        status: Optional[str] = None
        for event in self.events:
            if parse_time(event.effective_at) <= at:
                status = event.status
            else:
                break
        return status or "pending"

    def version_at(self, number: int) -> Optional[DependencyVersion]:
        for item in self.versions:
            if item.version == number:
                return item
        return None


@dataclass
class Pin:
    """授权包对某个依赖版本的固定引用（提交后证据摘要不可变）。"""

    dep_id: str
    category: str
    label: str
    version: Optional[int] = None
    evidence_digest: Optional[str] = None
    required: bool = True


@dataclass
class PackageRevision:
    """授权包的一个冻结修订（每次替代设备产生新修订）。"""

    version: int
    pins: list[Pin]
    manifest_digest: str
    created_at: str
    note: str = ""


@dataclass
class Decision:
    """只追加的授权决定。"""

    seq: int
    type: str
    effective_at: str
    actor: str
    reason: str = ""
    new_version: Optional[int] = None
    scopes: list[str] = field(default_factory=list)
    condition: Optional[dict[str, Any]] = None
    replaces: list[dict[str, str]] = field(default_factory=list)


@dataclass
class AuthorizationPackage:
    package_id: str
    org_id: str
    project_code: str
    scopes: list[str]
    state: str = PKG_DRAFT
    pins_draft: list[Pin] = field(default_factory=list)
    revisions: list[PackageRevision] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    created_at: str = ""

    def revision(self, number: int) -> Optional[PackageRevision]:
        for item in self.revisions:
            if item.version == number:
                return item
        return None

    @property
    def latest_revision(self) -> Optional[PackageRevision]:
        return self.revisions[-1] if self.revisions else None


@dataclass
class ServiceRecord:
    """一次服务提供记录；授权结论在登记时按服务时点冻结。"""

    service_id: str
    org_id: str
    package_id: str
    scope: str
    service_at: str
    recorded_at: str
    authorized: bool
    reasons: list[str]
    manifest_digest: str


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


def _dependency_from_dict(data: dict[str, Any]) -> Dependency:
    return Dependency(
        dep_id=data["dep_id"],
        org_id=data["org_id"],
        category=data["category"],
        name=data["name"],
        versions=[DependencyVersion(**item) for item in data.get("versions", [])],
        events=[DependencyEvent(**item) for item in data.get("events", [])],
    )


def _package_from_dict(data: dict[str, Any]) -> AuthorizationPackage:
    return AuthorizationPackage(
        package_id=data["package_id"],
        org_id=data["org_id"],
        project_code=data["project_code"],
        scopes=list(data["scopes"]),
        state=data["state"],
        pins_draft=[Pin(**item) for item in data.get("pins_draft", [])],
        revisions=[
            PackageRevision(
                version=rev["version"],
                pins=[Pin(**pin) for pin in rev["pins"]],
                manifest_digest=rev["manifest_digest"],
                created_at=rev["created_at"],
                note=rev.get("note", ""),
            )
            for rev in data.get("revisions", [])
        ],
        decisions=[Decision(**item) for item in data.get("decisions", [])],
        created_at=data.get("created_at", ""),
    )


def _service_from_dict(data: dict[str, Any]) -> ServiceRecord:
    return ServiceRecord(**data)
