"""HTTP API：基于标准库，零第三方依赖。

机构隔离
========
所有业务接口必须携带 ``X-Org-Id`` 头；资源查询严格限定在该机构内，
跨机构访问与资源不存在同样返回 404，避免通过状态码差异探测他机构数据。
"""
from __future__ import annotations

import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

from .engine import AuthorizationEngine, DomainError, IntegrityError
from .models import (
    DEP_ACTIVE,
    DEP_EXPIRED,
    DEP_REVOKED,
    DEP_SUSPENDED,
    DEC_APPROVE,
    DEC_DENY,
    DEC_PARTIAL,
    DEC_RESUME,
    DEC_SUBSTITUTE,
    DEC_SUSPEND,
    to_jsonable,
)
from .repository import NotFound, Repository

ORG_HEADER = "X-Org-Id"
ACTOR_HEADER = "X-Actor"

VALID_DECISIONS = frozenset(
    {DEC_APPROVE, DEC_DENY, DEC_PARTIAL, DEC_SUBSTITUTE, DEC_SUSPEND, DEC_RESUME}
)
VALID_DEP_STATUSES = frozenset(
    {DEP_ACTIVE, DEP_SUSPENDED, DEP_REVOKED, DEP_EXPIRED}
)


def create_app(repo: Optional[Repository] = None) -> "AuthzHandler":
    """返回绑定了仓储的处理器类（供 HTTPServer 使用）。"""
    repository = repo or Repository()
    engine = AuthorizationEngine(repository)

    class BoundHandler(AuthzHandler):
        pass

    BoundHandler.engine = engine
    BoundHandler.repository = repository
    return BoundHandler  # type: ignore[return-value]


def serve(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), create_app())
    return server


Route = tuple[str, re.Pattern[str], Callable[..., Any]]


class AuthzHandler(BaseHTTPRequestHandler):
    engine: AuthorizationEngine
    repository: Repository

    server_version = "AuthzPackageService/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # 安静日志
        return

    # ---- 基础读写 -------------------------------------------------------
    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise _HttpError(HTTPStatus.BAD_REQUEST, "请求体不是合法 JSON", f"BAD_JSON:{exc}")
        if not isinstance(value, dict):
            raise _HttpError(HTTPStatus.BAD_REQUEST, "请求体必须是 JSON 对象", "BAD_BODY")
        return value

    def _org_id(self) -> str:
        org_id = self.headers.get(ORG_HEADER, "").strip()
        if not org_id:
            raise _HttpError(
                HTTPStatus.UNAUTHORIZED,
                f"缺少 {ORG_HEADER} 头",
                "MISSING_ORG",
            )
        return org_id

    def _actor(self, body: dict[str, Any]) -> str:
        return str(body.pop("actor", None) or self.headers.get(ACTOR_HEADER, "机构合规员"))

    def _send(self, status: int, payload: Any) -> None:
        data = json.dumps(to_jsonable(payload), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, message: str, code: str) -> None:
        self._send(status, {"error": {"code": code, "message": message}})

    # ---- 路由 -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)
            for verb, pattern, handler in self._routes():
                if verb != method:
                    continue
                match = pattern.fullmatch(path)
                if match:
                    handler(query=query, **match.groupdict())
                    return
            self._error(HTTPStatus.NOT_FOUND, "接口不存在", "NOT_FOUND")
        except _HttpError as exc:
            self._error(exc.status, exc.message, exc.code)
        except NotFound:
            # 不存在与跨机构不可区分，杜绝通过 403/404 差异探测
            self._error(HTTPStatus.NOT_FOUND, "资源不存在", "NOT_FOUND")
        except IntegrityError as exc:
            self._send(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {
                    "error": {
                        "code": "INTEGRITY_VIOLATION",
                        "message": "完整性校验未通过",
                    },
                    "violations": [
                        {
                            "code": item.code,
                            "message": item.message,
                            "dep_id": item.dep_id,
                            "category": item.category,
                        }
                        for item in exc.violations
                    ],
                },
            )
        except DomainError as exc:
            self._error(HTTPStatus.CONFLICT, str(exc), exc.code)
        except Exception as exc:  # 最后防线，避免连接挂起
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"服务器内部错误：{type(exc).__name__}",
                "INTERNAL",
            )

    def _routes(self) -> list[Route]:
        return [
            ("GET", re.compile(r"/health$"), self._health),
            ("POST", re.compile(r"/dependencies$"), self._register_dep),
            ("GET", re.compile(r"/dependencies$"), self._list_deps),
            ("POST", re.compile(r"/dependencies/(?P<dep_id>[^/]+)/versions$"),
             self._new_dep_version),
            ("POST", re.compile(r"/dependencies/(?P<dep_id>[^/]+)/status$"),
             self._change_dep_status),
            ("GET", re.compile(r"/dependencies/(?P<dep_id>[^/]+)/impact$"),
             self._impact),
            ("POST", re.compile(r"/packages$"), self._create_package),
            ("GET", re.compile(r"/packages$"), self._list_packages),
            ("POST", re.compile(r"/packages/(?P<package_id>[^/]+)/submit$"),
             self._submit_package),
            ("POST", re.compile(r"/packages/(?P<package_id>[^/]+)/decisions$"),
             self._decide),
            ("POST", re.compile(r"/packages/(?P<package_id>[^/]+)/archive$"),
             self._archive),
            ("GET", re.compile(r"/packages/(?P<package_id>[^/]+)$"),
             self._get_package),
            ("GET", re.compile(r"/packages/(?P<package_id>[^/]+)/effective$"),
             self._effective),
            ("POST", re.compile(r"/packages/(?P<package_id>[^/]+)/services$"),
             self._record_service),
            ("GET", re.compile(r"/services$"), self._list_services),
        ]

    # ---- 处理器 ---------------------------------------------------------
    def _health(self, **_: Any) -> None:
        self._send(HTTPStatus.OK, {"status": "ok"})

    def _register_dep(self, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        actor = self._actor(body)
        dep = self.engine.register_dependency(
            org_id=org_id,
            category=str(body.get("category", "")),
            name=str(body.get("name", "")),
            evidence=body.get("evidence") or {},
            requires=body.get("requires"),
            valid_from=body.get("valid_from"),
            actor=actor,
        )
        self._send(HTTPStatus.CREATED, to_jsonable(dep))

    def _list_deps(self, **_: Any) -> None:
        org_id = self._org_id()
        self._send(HTTPStatus.OK, to_jsonable(self.repository.list_dependencies(org_id)))

    def _new_dep_version(self, dep_id: str, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        actor = self._actor(body)
        dep = self.engine.new_evidence_version(
            dep_id=dep_id,
            org_id=org_id,
            evidence=body.get("evidence") or {},
            requires=body.get("requires"),
            actor=actor,
        )
        self._send(HTTPStatus.OK, to_jsonable(dep))

    def _change_dep_status(self, dep_id: str, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        actor = self._actor(body)
        status = str(body.get("status", ""))
        if status not in VALID_DEP_STATUSES:
            raise _HttpError(
                HTTPStatus.BAD_REQUEST,
                f"status 必须是 {sorted(VALID_DEP_STATUSES)} 之一",
                "BAD_STATUS",
            )
        dep = self.engine.change_dependency_status(
            dep_id=dep_id,
            org_id=org_id,
            status=status,
            effective_at=body.get("effective_at"),
            reason=str(body.get("reason", "")),
            actor=actor,
        )
        self._send(HTTPStatus.OK, to_jsonable(dep))

    def _impact(self, dep_id: str, query: dict[str, list[str]], **_: Any) -> None:
        org_id = self._org_id()
        result = self.engine.impact_of_dependency(dep_id=dep_id, org_id=org_id)
        self._send(HTTPStatus.OK, result)

    def _create_package(self, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        package = self.engine.create_package(
            org_id=org_id,
            project_code=str(body.get("project_code", "")),
            scopes=list(body.get("scopes") or []),
            pin_specs=list(body.get("pins") or []),
        )
        self._send(HTTPStatus.CREATED, to_jsonable(package))

    def _list_packages(self, **_: Any) -> None:
        org_id = self._org_id()
        self._send(HTTPStatus.OK, to_jsonable(self.repository.list_packages(org_id)))

    def _submit_package(self, package_id: str, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        actor = self._actor(body)
        package = self.engine.submit_package(
            package_id=package_id, org_id=org_id, actor=actor
        )
        self._send(HTTPStatus.OK, to_jsonable(package))

    def _decide(self, package_id: str, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        actor = self._actor(body)
        decision = str(body.get("decision", ""))
        if decision not in VALID_DECISIONS:
            raise _HttpError(
                HTTPStatus.BAD_REQUEST,
                f"decision 必须是 {sorted(VALID_DECISIONS)} 之一",
                "BAD_DECISION",
            )
        package = self.engine.decide(
            package_id=package_id,
            org_id=org_id,
            decision=decision,
            scopes=body.get("scopes"),
            replacements=body.get("replacements"),
            reason=str(body.get("reason", "")),
            effective_at=body.get("effective_at"),
            actor=actor,
        )
        self._send(HTTPStatus.OK, to_jsonable(package))

    def _archive(self, package_id: str, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        actor = self._actor(body)
        package = self.engine.archive_package(
            package_id=package_id, org_id=org_id, actor=actor
        )
        self._send(HTTPStatus.OK, to_jsonable(package))

    def _get_package(self, package_id: str, **_: Any) -> None:
        org_id = self._org_id()
        package = self.repository.get_package(package_id, org_id)
        self._send(HTTPStatus.OK, to_jsonable(package))

    def _effective(self, package_id: str, query: dict[str, list[str]], **_: Any) -> None:
        org_id = self._org_id()
        package = self.repository.get_package(package_id, org_id)
        from .models import parse_time

        at = parse_time(query["at"][0]) if query.get("at") else None
        self._send(HTTPStatus.OK, self.engine.evaluate(package, at))

    def _record_service(self, package_id: str, **_: Any) -> None:
        org_id = self._org_id()
        body = self._read_json()
        scope = str(body.get("scope", ""))
        record = self.engine.record_service(
            package_id=package_id,
            org_id=org_id,
            scope=scope,
            service_at=body.get("service_at"),
        )
        self._send(HTTPStatus.CREATED, to_jsonable(record))

    def _list_services(self, **_: Any) -> None:
        org_id = self._org_id()
        self._send(HTTPStatus.OK, to_jsonable(self.repository.list_services(org_id)))


class _HttpError(Exception):
    def __init__(self, status: HTTPStatus, message: str, code: str) -> None:
        super().__init__(message)
        self.status = int(status)
        self.message = message
        self.code = code
