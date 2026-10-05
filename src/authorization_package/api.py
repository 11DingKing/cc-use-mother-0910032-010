"""HTTP 接口：身份解析、机构隔离与请求/响应模型。

认证模型（演示）：调用方在 ``X-Principal-Id`` 头中携带已认证主体编号，
服务端解析其角色与所属机构；所有数据访问强制按 org_id 过滤，
跨机构访问一律返回 404，既不给数据也不泄露资源是否存在。
"""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Header, Query
from pydantic import BaseModel, Field

from . import service
from .errors import DomainError, forbidden, unprocessable
from .models import Kind, Role
from .seed import seed
from .store import STORE


# ---------------------------------------------------------------- 请求模型


class EvidenceIn(BaseModel):
    evidence_id: str = Field(min_length=1)
    sha256: str = Field(min_length=1)


class DepIn(BaseModel):
    kind: str
    name: str = Field(min_length=1)
    evidence: list[EvidenceIn] = Field(min_length=1)
    requires: list[dict[str, Any]] = Field(default_factory=list)


class DepEvidenceIn(BaseModel):
    evidence: list[EvidenceIn] = Field(min_length=1)
    requires: list[dict[str, Any]] | None = None


class ReasonIn(BaseModel):
    reason: str = Field(min_length=1)


class PinIn(BaseModel):
    slot: str = Field(min_length=1)
    dep_id: str = Field(min_length=1)
    version: int = Field(ge=1)


class SubmitIn(BaseModel):
    project_code: str = Field(min_length=1)
    pins: list[PinIn] = Field(min_length=1)


class ResubmitIn(BaseModel):
    pins: list[PinIn] = Field(min_length=1)


class PartialGrantIn(BaseModel):
    reason: str = Field(min_length=1)
    approved_slots: list[str] = Field(min_length=1)


class SlotsIn(BaseModel):
    reason: str = Field(min_length=1)
    slots: list[str] = Field(min_length=1)


class ReplaceIn(BaseModel):
    reason: str = Field(min_length=1)
    slot: str = Field(min_length=1)
    replacement_dep_id: str = Field(min_length=1)


class ServiceIn(BaseModel):
    slot: str = Field(min_length=1)


# ---------------------------------------------------------------- 身份与隔离


async def current_principal(x_principal_id: str | None = Header(default=None)) -> dict[str, Any]:
    if not x_principal_id:
        raise DomainError(401, "UNAUTHENTICATED", "缺少 X-Principal-Id 头")
    principal = STORE.principals.get(x_principal_id)
    if principal is None:
        raise DomainError(401, "UNAUTHENTICATED", "主体不存在或未认证")
    return principal


def require_roles(*roles: Role):
    async def checker(principal: dict[str, Any] = Depends(current_principal)) -> dict[str, Any]:
        if principal["role"] not in {r.value for r in roles}:
            raise forbidden(f"当前角色 {principal['role']} 无权执行该操作")
        return principal
    return checker


def dep_in_org(dep_id: str, principal: dict[str, Any]) -> dict[str, Any]:
    dep = service.get_dep(dep_id)  # 不存在 → 404
    if dep["org_id"] != principal["org_id"]:
        # 关键隔离点：其他机构的资源对调用方表现为“不存在”。
        from .errors import not_found
        raise not_found()
    return dep


def package_in_org(package_id: str, principal: dict[str, Any]) -> dict[str, Any]:
    pkg = service.get_package(package_id)
    if pkg["org_id"] != principal["org_id"]:
        from .errors import not_found
        raise not_found()
    return pkg


# ---------------------------------------------------------------- 应用工厂


def create_app() -> FastAPI:
    seed()
    app = FastAPI(
        title="项目授权依赖包服务",
        version="1.0.0",
        description="授权条件版本化、证据摘要冻结、完整性规则、决定链与依赖失效传播",
    )

    @app.middleware("http")
    async def serialize_state(request, call_next):
        # 内存存储的每个请求都在同一把可重入锁内完成读改写。
        # 所有端点均为 async def，与中间件处于同一事件循环线程，可安全重入。
        with STORE.lock:
            return await call_next(request)

    @app.exception_handler(DomainError)
    async def domain_error_handler(request, exc: DomainError):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=exc.status, content=exc.to_response())

    # ------------------------------------------------------------ 基础

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/me")
    async def me(principal: dict = Depends(current_principal)) -> dict:
        return principal

    # ------------------------------------------------------------ 治疗项目目录

    @app.get("/projects")
    async def list_projects(principal: dict = Depends(current_principal)) -> list[dict]:
        return list(STORE.projects.values())

    @app.get("/projects/{project_code}")
    async def get_project(project_code: str, principal: dict = Depends(current_principal)) -> dict:
        project = STORE.projects.get(project_code)
        if project is None:
            from .errors import not_found
            raise not_found(f"治疗项目 {project_code} 不存在")
        return project

    # ------------------------------------------------------------ 依赖

    @app.post("/deps", status_code=201)
    async def create_dep(body: DepIn,
                   principal: dict = Depends(require_roles(
                       Role.COMPLIANCE, Role.REGULATOR, Role.REVIEWER))) -> dict:
        if body.kind not in {k.value for k in Kind}:
            raise unprocessable("INVALID_KIND", f"依赖类别必须是 {[k.value for k in Kind]}")
        return service.register_dep(
            principal, body.kind, body.name,
            [e.model_dump() for e in body.evidence],
            [dict(r) for r in body.requires],
        )

    @app.get("/deps")
    async def list_deps(kind: str | None = Query(default=None),
                  principal: dict = Depends(current_principal)) -> list[dict]:
        out = [d for d in STORE.deps.values() if d["org_id"] == principal["org_id"]]
        if kind:
            out = [d for d in out if d["kind"] == kind]
        return out

    @app.get("/deps/{dep_id}")
    async def get_dep(dep_id: str, principal: dict = Depends(current_principal)) -> dict:
        return dep_in_org(dep_id, principal)

    @app.post("/deps/{dep_id}/evidence", status_code=201)
    async def new_evidence(dep_id: str, body: DepEvidenceIn,
                     principal: dict = Depends(require_roles(
                         Role.COMPLIANCE, Role.REGULATOR, Role.REVIEWER))) -> dict:
        dep_in_org(dep_id, principal)
        return service.update_dep_evidence(
            principal, dep_id, [e.model_dump() for e in body.evidence],
            [dict(r) for r in body.requires] if body.requires is not None else None,
        )

    @app.post("/deps/{dep_id}/suspend")
    async def suspend(dep_id: str, body: ReasonIn,
                principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        dep_in_org(dep_id, principal)
        return service.suspend_dep(principal, dep_id, body.reason)

    @app.post("/deps/{dep_id}/resume")
    async def resume(dep_id: str, body: ReasonIn,
               principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        dep_in_org(dep_id, principal)
        return service.resume_dep(principal, dep_id, body.reason)

    @app.post("/deps/{dep_id}/revoke")
    async def revoke(dep_id: str, body: ReasonIn,
               principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        dep_in_org(dep_id, principal)
        return service.revoke_dep(principal, dep_id, body.reason)

    # ------------------------------------------------------------ 授权包

    @app.post("/packages", status_code=201)
    async def submit(body: SubmitIn,
               principal: dict = Depends(require_roles(Role.COMPLIANCE, Role.REGULATOR))) -> dict:
        pkg = service.submit_package(
            principal, body.project_code, [p.model_dump() for p in body.pins]
        )
        return service.package_detail(pkg)

    @app.get("/packages")
    async def list_packages(principal: dict = Depends(current_principal)) -> list[dict]:
        out = []
        for pkg in STORE.packages.values():
            if pkg["org_id"] == principal["org_id"]:
                d = service.package_detail(pkg)
                out.append({
                    "id": d["id"], "org_id": d["org_id"], "project_code": d["project_code"],
                    "latest_version": d["latest_version"],
                    "active": d["current_authorization"]["active"],
                    "blocked": d["current_authorization"]["blocked"],
                    "last_decision_id": d["current_authorization"]["last_decision_id"],
                })
        return out

    @app.get("/packages/{package_id}")
    async def get_package(package_id: str, principal: dict = Depends(current_principal)) -> dict:
        pkg = package_in_org(package_id, principal)
        return service.package_detail(pkg)

    @app.post("/packages/{package_id}/resubmit", status_code=201)
    async def resubmit(package_id: str, body: ResubmitIn,
                 principal: dict = Depends(require_roles(Role.COMPLIANCE, Role.REGULATOR))) -> dict:
        package_in_org(package_id, principal)
        pkg = service.submit_package(
            principal,
            STORE.packages[package_id]["project_code"],
            [p.model_dump() for p in body.pins],
            package_id=package_id,
        )
        return service.package_detail(pkg)

    # ------------------------------------------------------------ 审批决定（均为新决定）

    @app.post("/packages/{package_id}/decisions/grant", status_code=201)
    async def dec_grant(package_id: str, body: ReasonIn,
                  principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        package_in_org(package_id, principal)
        dec = service.grant(principal, package_id, body.reason)
        return {"decision": dec, "authorization": service._current_authorization(
            STORE.packages[package_id])}

    @app.post("/packages/{package_id}/decisions/partial-grant", status_code=201)
    async def dec_partial(package_id: str, body: PartialGrantIn,
                    principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        package_in_org(package_id, principal)
        dec = service.partial_grant(principal, package_id, body.reason, body.approved_slots)
        return {"decision": dec, "authorization": service._current_authorization(
            STORE.packages[package_id])}

    @app.post("/packages/{package_id}/decisions/suspend", status_code=201)
    async def dec_suspend(package_id: str, body: SlotsIn,
                    principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        package_in_org(package_id, principal)
        dec = service.suspend_authorization(principal, package_id, body.reason, body.slots)
        return {"decision": dec, "authorization": service._current_authorization(
            STORE.packages[package_id])}

    @app.post("/packages/{package_id}/decisions/resume", status_code=201)
    async def dec_resume(package_id: str, body: SlotsIn,
                   principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        package_in_org(package_id, principal)
        dec = service.resume_authorization(principal, package_id, body.reason, body.slots)
        return {"decision": dec, "authorization": service._current_authorization(
            STORE.packages[package_id])}

    @app.post("/packages/{package_id}/decisions/replace", status_code=201)
    async def dec_replace(package_id: str, body: ReplaceIn,
                    principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        package_in_org(package_id, principal)
        dec = service.replace_dependency(
            principal, package_id, body.reason, body.slot, body.replacement_dep_id)
        return {"decision": dec, "authorization": service._current_authorization(
            STORE.packages[package_id])}

    @app.post("/packages/{package_id}/decisions/revoke", status_code=201)
    async def dec_revoke(package_id: str, body: ReasonIn,
                   principal: dict = Depends(require_roles(Role.REGULATOR, Role.REVIEWER))) -> dict:
        package_in_org(package_id, principal)
        dec = service.revoke_authorization(principal, package_id, body.reason)
        return {"decision": dec, "authorization": service._current_authorization(
            STORE.packages[package_id])}

    # ------------------------------------------------------------ 服务准入与登记

    @app.get("/packages/{package_id}/eligibility")
    async def eligibility(package_id: str, slot: str | None = Query(default=None),
                    principal: dict = Depends(current_principal)) -> dict:
        package_in_org(package_id, principal)
        return service.service_eligibility(principal, package_id, slot)

    @app.post("/packages/{package_id}/services", status_code=201)
    async def add_service(package_id: str, body: ServiceIn,
                    principal: dict = Depends(require_roles(Role.PRACTITIONER))) -> dict:
        package_in_org(package_id, principal)
        return service.register_service(principal, package_id, body.slot)

    @app.get("/packages/{package_id}/services")
    async def package_services(package_id: str, principal: dict = Depends(current_principal)) -> list[dict]:
        package_in_org(package_id, principal)
        return service.list_services(principal["org_id"], package_id)

    @app.get("/services")
    async def all_services(principal: dict = Depends(current_principal)) -> list[dict]:
        return service.list_services(principal["org_id"])

    # ------------------------------------------------------------ 图谱与传播

    @app.get("/deps/{dep_id}/impact")
    async def impact(dep_id: str, version: int | None = Query(default=None),
               principal: dict = Depends(current_principal)) -> dict:
        dep_in_org(dep_id, principal)  # 跨机构探测图谱 → 404
        graph = service.impact_graph(dep_id, version)
        # 双保险：即使存储层出现串机构数据，出口仍按机构裁剪。
        graph["edges"] = [e for e in graph["edges"] if e["org_id"] == principal["org_id"]]
        graph["impacted_packages"] = sorted({e["package_id"] for e in graph["edges"]})
        return graph

    @app.get("/events")
    async def events(principal: dict = Depends(current_principal)) -> list[dict]:
        return service.list_events(principal["org_id"])

    return app


app = create_app()
