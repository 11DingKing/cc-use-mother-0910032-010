"""存储层：线程安全的内存仓储，所有读取按机构隔离。

真实部署可替换为数据库实现；接口刻意保持最小，领域逻辑不依赖具体存储。
"""
from __future__ import annotations

import threading
from typing import Optional

from .models import (
    AuthorizationPackage,
    Dependency,
    ServiceRecord,
    _dependency_from_dict,
    _package_from_dict,
    _service_from_dict,
    to_jsonable,
)


class NotFound(KeyError):
    """资源不存在，或存在但属于其他机构（不区分以防探测）。"""


class Repository:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._deps: dict[str, Dependency] = {}
        self._packages: dict[str, AuthorizationPackage] = {}
        self._services: dict[str, ServiceRecord] = {}

    # ---- 依赖 -----------------------------------------------------------
    def save_dependency(self, dep: Dependency) -> None:
        with self._lock:
            self._deps[dep.dep_id] = dep

    def get_dependency(self, dep_id: str, org_id: str) -> Dependency:
        """按机构读取依赖；不属于该机构时与不存在同样抛 NotFound。"""
        with self._lock:
            dep = self._deps.get(dep_id)
            if dep is None or dep.org_id != org_id:
                raise NotFound(dep_id)
            return dep

    def internal_get_dependency(self, dep_id: str) -> Optional[Dependency]:
        """引擎内部使用：不带机构过滤（包内依赖已由同机构规则保证）。"""
        with self._lock:
            return self._deps.get(dep_id)

    def list_dependencies(self, org_id: str) -> list[Dependency]:
        with self._lock:
            return [dep for dep in self._deps.values() if dep.org_id == org_id]

    # ---- 授权包 ---------------------------------------------------------
    def save_package(self, package: AuthorizationPackage) -> None:
        with self._lock:
            self._packages[package.package_id] = package

    def get_package(self, package_id: str, org_id: str) -> AuthorizationPackage:
        with self._lock:
            package = self._packages.get(package_id)
            if package is None or package.org_id != org_id:
                raise NotFound(package_id)
            return package

    def list_packages(self, org_id: str) -> list[AuthorizationPackage]:
        with self._lock:
            return [p for p in self._packages.values() if p.org_id == org_id]

    # ---- 服务记录 -------------------------------------------------------
    def save_service(self, record: ServiceRecord) -> None:
        with self._lock:
            self._services[record.service_id] = record

    def get_service(self, service_id: str, org_id: str) -> ServiceRecord:
        with self._lock:
            record = self._services.get(service_id)
            if record is None or record.org_id != org_id:
                raise NotFound(service_id)
            return record

    def list_services(self, org_id: str) -> list[ServiceRecord]:
        with self._lock:
            return [s for s in self._services.values() if s.org_id == org_id]

    # ---- 快照（调试/持久化） --------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "dependencies": [to_jsonable(d) for d in self._deps.values()],
                "packages": [to_jsonable(p) for p in self._packages.values()],
                "services": [to_jsonable(s) for s in self._services.values()],
            }

    def load_snapshot(self, data: dict) -> None:
        with self._lock:
            self._deps = {
                item["dep_id"]: _dependency_from_dict(item)
                for item in data.get("dependencies", [])
            }
            self._packages = {
                item["package_id"]: _package_from_dict(item)
                for item in data.get("packages", [])
            }
            self._services = {
                item["service_id"]: _service_from_dict(item)
                for item in data.get("services", [])
            }
