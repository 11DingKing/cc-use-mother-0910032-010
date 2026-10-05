"""线程安全的内存存储。

生产环境可替换为数据库实现：所有状态访问都经过 Store，
图谱查询、隔离与传播逻辑不依赖具体存储介质。
"""
from __future__ import annotations

import threading
from typing import Any


class Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.principals: dict[str, dict[str, Any]] = {}
        self.deps: dict[str, dict[str, Any]] = {}
        self.projects: dict[str, dict[str, Any]] = {}
        self.packages: dict[str, dict[str, Any]] = {}
        # package_id -> list[service]
        self.services: dict[str, list[dict[str, Any]]] = {}
        self.events: list[dict[str, Any]] = []
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.principals.clear()
            self.deps.clear()
            self.projects.clear()
            self.packages.clear()
            self.services.clear()
            self.events.clear()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def append_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            event["seq"] = len(self.events) + 1
            self.events.append(event)


STORE = Store()
