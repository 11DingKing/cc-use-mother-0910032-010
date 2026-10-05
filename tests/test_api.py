"""HTTP API 端到端测试：完整业务流、机构隔离与错误形态。"""
from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authz_service.api import create_app
from authz_service.repository import Repository

ORG_A = "org-A-hospital"
ORG_B = "org-B-clinic"


class ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        handler = create_app(self.repo)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def call(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        org: str | None = ORG_A,
        actor: str | None = None,
    ) -> tuple[int, object]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if org is not None:
            headers["X-Org-Id"] = org
        payload = None
        if body is not None:
            # 角色随 JSON 体传递，避免 HTTP 头的 latin-1 编码限制
            if actor is not None:
                body = {**body, "actor": actor}
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        conn.close()
        return response.status, json.loads(raw) if raw else None

    def _four_deps(self, org: str = ORG_A) -> list[str]:
        specs = [
            ("场地", "手术室A", {"addr": "3F"}),
            ("设备", "加速器", {"sn": "SN1"}),
            ("药械", "对比剂", {"batch": "B1"}),
            ("人员", "医师", {"license": "D1"}),
        ]
        ids = []
        for category, name, evidence in specs:
            status, dep = self.call(
                "POST", "/dependencies",
                {"category": category, "name": name, "evidence": evidence,
                 "valid_from": "2026-01-01T00:00:00+00:00"},
                org=org,
            )
            self.assertEqual(status, 201, dep)
            ids.append(dep["dep_id"])
        return ids

    def _approved(self, org: str = ORG_A, scopes: list[str] | None = None) -> str:
        ids = self._four_deps(org)
        status, pkg = self.call(
            "POST", "/packages",
            {"project_code": "TX-1", "scopes": scopes or ["门诊", "住院"],
             "pins": [{"dep_id": i} for i in ids]},
            org=org,
        )
        self.assertEqual(status, 201, pkg)
        status, submitted = self.call(
            "POST", f"/packages/{pkg['package_id']}/submit", {}, org=org,
            actor="机构合规员",
        )
        self.assertEqual(status, 200, submitted)
        status, decided = self.call(
            "POST", f"/packages/{pkg['package_id']}/decisions",
            {"decision": "批准", "effective_at": "2026-02-01T00:00:00+00:00"},
            org=org, actor="复核专家",
        )
        self.assertEqual(status, 200, decided)
        return pkg["package_id"]

    # ------------------------------------------------------------------ #
    def test_health_and_auth_header(self) -> None:
        status, body = self.call("GET", "/health", org=None)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})
        status, body = self.call("GET", "/packages", org=None)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "MISSING_ORG")

    def test_full_flow_over_http(self) -> None:
        pkg_id = self._approved()
        status, verdict = self.call(
            "GET", f"/packages/{pkg_id}/effective?at=2026-02-10T00:00:00%2B00:00",
        )
        self.assertEqual(status, 200)
        self.assertTrue(verdict["authorized"])
        self.assertEqual(verdict["baseline_revision"], 1)
        self.assertEqual(len(verdict["conditions"]), 4)

        # 撤销设备：未来服务失效
        _, deps = self.call("GET", "/dependencies")
        equipment = next(d for d in deps if d["category"] == "设备")
        status, _ = self.call(
            "POST", f"/dependencies/{equipment['dep_id']}/status",
            {"status": "revoked", "reason": "年检不合格",
             "effective_at": "2026-03-01T00:00:00+00:00"},
            actor="监管人员",
        )
        self.assertEqual(status, 200)
        status, broken = self.call(
            "GET", f"/packages/{pkg_id}/effective?at=2026-03-02T00:00:00%2B00:00",
        )
        self.assertEqual(status, 200)
        self.assertFalse(broken["authorized"])

        # 服务登记：撤销前成立、撤销后被拒
        for when, expected in (
            ("2026-02-20T00:00:00+00:00", True),
            ("2026-03-20T00:00:00+00:00", False),
        ):
            status, record = self.call(
                "POST", f"/packages/{pkg_id}/services",
                {"scope": "门诊", "service_at": when},
            )
            self.assertEqual(status, 201, record)
            self.assertIs(record["authorized"], expected)

    def test_integrity_failure_returns_422(self) -> None:
        ids = self._four_deps()
        status, pkg = self.call(
            "POST", "/packages",
            {"project_code": "TX-2", "scopes": ["门诊"],
             "pins": [{"dep_id": i} for i in ids[:3]]},  # 缺药械（第4个）
        )
        self.assertEqual(status, 201)
        status, body = self.call(
            "POST", f"/packages/{pkg['package_id']}/submit", {}
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "INTEGRITY_VIOLATION")
        codes = {v["code"] for v in body["violations"]}
        self.assertIn("CATEGORY_MISSING", codes)

    def test_cross_org_access_is_indistinguishable_404(self) -> None:
        pkg_id = self._approved(ORG_A)
        # B 机构无法读取 A 的包
        status, body = self.call("GET", f"/packages/{pkg_id}", org=ORG_B)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "NOT_FOUND")
        # 列表也不泄露
        status, listing = self.call("GET", "/packages", org=ORG_B)
        self.assertEqual(status, 200)
        self.assertEqual(listing, [])
        # 影响面同样不可见
        _, deps_a = self.call("GET", "/dependencies", org=ORG_A)
        dep_id = deps_a[0]["dep_id"]
        status, body = self.call(
            "GET", f"/dependencies/{dep_id}/impact", org=ORG_B
        )
        self.assertEqual(status, 404)
        # 服务记录也不跨机构
        status, services = self.call("GET", "/services", org=ORG_B)
        self.assertEqual(services, [])

    def test_partial_suspend_resume_substitute_decisions(self) -> None:
        ids = self._four_deps()
        status, pkg = self.call(
            "POST", "/packages",
            {"project_code": "TX-3", "scopes": ["门诊", "住院"],
             "pins": [{"dep_id": i} for i in ids]},
        )
        pkg_id = pkg["package_id"]
        self.call("POST", f"/packages/{pkg_id}/submit", {})
        status, _ = self.call(
            "POST", f"/packages/{pkg_id}/decisions",
            {"decision": "部分批准", "scopes": ["门诊"],
             "effective_at": "2026-02-01T00:00:00+00:00"},
        )
        self.assertEqual(status, 200)
        _, verdict = self.call(
            "GET", f"/packages/{pkg_id}/effective?at=2026-02-05T00:00:00%2B00:00"
        )
        self.assertIs(verdict["scopes"]["门诊"]["authorized"], True)
        self.assertIs(verdict["scopes"]["住院"]["authorized"], False)

        # 暂停门诊 -> 恢复，均形成新决定
        for decision, when in (
            ("条件暂停", "2026-03-01T00:00:00+00:00"),
            ("恢复", "2026-04-01T00:00:00+00:00"),
        ):
            status, body = self.call(
                "POST", f"/packages/{pkg_id}/decisions",
                {"decision": decision, "scopes": ["门诊"],
                 "effective_at": when},
            )
            self.assertEqual(status, 200, body)
        _, full = self.call("GET", f"/packages/{pkg_id}")
        self.assertEqual(
            [d["type"] for d in full["decisions"]],
            ["部分批准", "条件暂停", "恢复"],
        )

        # 替代设备 -> 新修订 v2
        equipment = next(
            d for d in self.repo.list_dependencies(ORG_A)
            if d.category == "设备"
        )
        _, replacement = self.call(
            "POST", "/dependencies",
            {"category": "设备", "name": "新设备", "evidence": {"sn": "SN2"},
             "valid_from": "2026-04-05T00:00:00+00:00"},
        )
        status, body = self.call(
            "POST", f"/packages/{pkg_id}/decisions",
            {"decision": "替代设备",
             "replacements": [
                 {"remove": equipment.dep_id, "add": replacement["dep_id"]}],
             "effective_at": "2026-04-10T00:00:00+00:00"},
        )
        self.assertEqual(status, 200, body)
        _, after = self.call("GET", f"/packages/{pkg_id}")
        self.assertEqual([r["version"] for r in after["revisions"]], [1, 2])
        _, verdict = self.call(
            "GET", f"/packages/{pkg_id}/effective?at=2026-04-20T00:00:00%2B00:00"
        )
        self.assertIs(verdict["scopes"]["门诊"]["authorized"], True)
        self.assertIs(verdict["scopes"]["住院"]["authorized"], False)

    def test_impact_endpoint_lists_affected(self) -> None:
        pkg_id = self._approved()
        _, deps = self.call("GET", "/dependencies")
        drug = next(d for d in deps if d["category"] == "药械")
        status, impact = self.call(
            "GET", f"/dependencies/{drug['dep_id']}/impact"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(impact["affected_authorizations"]), 1)
        self.assertEqual(
            impact["affected_authorizations"][0]["package_id"], pkg_id
        )
        self.assertTrue(impact["future_only"])

    def test_bad_decisions_are_conflicts(self) -> None:
        pkg_id = self._approved()
        # 重复暂停不存在的范围
        status, body = self.call(
            "POST", f"/packages/{pkg_id}/decisions",
            {"decision": "条件暂停", "scopes": ["不存在的范围"],
             "effective_at": "2026-03-01T00:00:00+00:00"},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "BAD_SCOPES")
        # 非法决定类型 400
        status, body = self.call(
            "POST", f"/packages/{pkg_id}/decisions", {"decision": "随便"}
        )
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
