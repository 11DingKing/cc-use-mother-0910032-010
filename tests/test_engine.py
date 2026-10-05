"""领域引擎回归测试：合取授权、证据冻结、只追加决定、时间有效性与图谱传播。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authz_service.engine import AuthorizationEngine, DomainError, IntegrityError
from authz_service.models import (
    DEP_ACTIVE,
    DEP_REVOKED,
    DEP_SUSPENDED,
    parse_time,
)
from authz_service.repository import NotFound, Repository
from authz_service.rules import rule_evidence_digest_matches


ORG_A = "org-A-医院"
ORG_B = "org-B-诊所"
T_EARLY = "2026-01-01T00:00:00+00:00"


class EngineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.engine = AuthorizationEngine(self.repo)

    def _register_four(self, org_id: str = ORG_A) -> dict[str, str]:
        """登记场地/设备/药械/人员四类条件，返回类别->dep_id。"""
        specs = {
            "场地": ("手术室A", {"addr": "主楼3层", "area_m2": 60}),
            "设备": ("直线加速器", {"model": "LX-2026", "sn": "SN001"}),
            "药械": ("对比剂", {"batch": "B2026-01", "permit": "YP-09"}),
            "人员": ("放疗医师", {"license": "DOC-1001", "name": "张医生"}),
        }
        ids: dict[str, str] = {}
        for category, (name, evidence) in specs.items():
            dep = self.engine.register_dependency(
                org_id=org_id,
                category=category,
                name=name,
                evidence=evidence,
                valid_from=T_EARLY,
            )
            ids[category] = dep.dep_id
        return ids

    def _approved_package(
        self, org_id: str = ORG_A, scopes: list[str] | None = None
    ) -> str:
        ids = self._register_four(org_id)
        pkg = self.engine.create_package(
            org_id=org_id,
            project_code="TX-放射治疗",
            scopes=scopes or ["门诊", "住院"],
            pin_specs=[{"dep_id": dep_id} for dep_id in ids.values()],
        )
        self.engine.submit_package(package_id=pkg.package_id, org_id=org_id)
        self.engine.decide(
            package_id=pkg.package_id,
            org_id=org_id,
            decision="批准",
            effective_at="2026-02-01T00:00:00+00:00",
        )
        return pkg.package_id

    # ------------------------------------------------------------------ #
    def test_full_flow_authorization_is_conjunctive(self) -> None:
        pkg_id = self._approved_package()
        pkg = self.repo.get_package(pkg_id, ORG_A)

        ok = self.engine.evaluate(pkg, parse_time("2026-02-10T00:00:00+00:00"))
        self.assertTrue(ok["authorized"])
        self.assertEqual(ok["baseline_revision"], 1)

        # 单项（设备）撤销 -> 整体授权立即对未来失效
        ids = self._registered_ids(ORG_A)
        self.engine.change_dependency_status(
            dep_id=ids["设备"],
            org_id=ORG_A,
            status=DEP_REVOKED,
            effective_at="2026-03-01T00:00:00+00:00",
            reason="设备年检不合格",
        )
        broken = self.engine.evaluate(pkg, parse_time("2026-03-02T00:00:00+00:00"))
        self.assertFalse(broken["authorized"])
        for scope in ("门诊", "住院"):
            reasons = broken["scopes"][scope]["reasons"]
            self.assertTrue(any("设备" in r for r in reasons), reasons)
        # 撤销之前的历史时点授权仍然成立
        past = self.engine.evaluate(pkg, parse_time("2026-02-15T00:00:00+00:00"))
        self.assertTrue(past["authorized"])

    def _registered_ids(self, org_id: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for dep in self.repo.list_dependencies(org_id):
            result[dep.category] = dep.dep_id
        return result

    def test_evidence_digest_frozen_at_submit(self) -> None:
        ids = self._register_four()
        pkg = self.engine.create_package(
            org_id=ORG_A,
            project_code="TX-X",
            scopes=["门诊"],
            pin_specs=[{"dep_id": dep_id} for dep_id in ids.values()],
        )
        submitted = self.engine.submit_package(
            package_id=pkg.package_id, org_id=ORG_A
        )
        rev = submitted.latest_revision
        self.assertEqual(len(rev.pins), 4)
        # 每个固定项都有冻结版本号与 64 位摘要
        for pin in rev.pins:
            self.assertEqual(pin.version, 1)
            self.assertRegex(pin.evidence_digest, r"^[0-9a-f]{64}$")
        digest_at_submit = rev.manifest_digest

        # 依赖换新证据版本：已冻结修订不变
        self.engine.new_evidence_version(
            dep_id=ids["人员"],
            org_id=ORG_A,
            evidence={"license": "DOC-1001", "name": "张医生", "renewed": True},
        )
        pkg2 = self.repo.get_package(pkg.package_id, ORG_A)
        self.assertEqual(pkg2.latest_revision.manifest_digest, digest_at_submit)
        self.assertEqual(
            pkg2.latest_revision.pins[3].evidence_digest, rev.pins[3].evidence_digest
        )

    def test_tampered_evidence_is_detected(self) -> None:
        pkg_id = self._approved_package()
        pkg = self.repo.get_package(pkg_id, ORG_A)
        ids = self._registered_ids(ORG_A)
        # 模拟存储层被篡改：改动已固定版本的证据摘要
        self.repo.internal_get_dependency(ids["药械"]).versions[0].evidence_digest = (
            "0" * 64
        )
        verdict = self.engine.evaluate(pkg, parse_time("2026-02-10T00:00:00+00:00"))
        self.assertFalse(verdict["authorized"])
        self.assertIn("证据摘要", verdict["scopes"]["门诊"]["reasons"][0])

        # 完整性规则本身也能识别摘要不一致
        dep = self.repo.internal_get_dependency(ids["药械"])
        from authz_service.models import Pin

        violations = rule_evidence_digest_matches(
            pins=[Pin(dep.dep_id, "药械", "x", 1, "deadbeef")],
            deps={dep.dep_id: dep},
        )
        self.assertEqual(violations[0].code, "EVIDENCE_DIGEST_MISMATCH")

    def test_integrity_missing_category(self) -> None:
        # 只登记三类，缺“药械”
        ids = self._register_four()
        pkg = self.engine.create_package(
            org_id=ORG_A,
            project_code="TX-Y",
            scopes=["门诊"],
            pin_specs=[
                {"dep_id": ids["场地"]},
                {"dep_id": ids["设备"]},
                {"dep_id": ids["人员"]},
            ],
        )
        with self.assertRaises(IntegrityError) as ctx:
            self.engine.submit_package(package_id=pkg.package_id, org_id=ORG_A)
        codes = {v.code for v in ctx.exception.violations}
        self.assertIn("CATEGORY_MISSING", codes)

    def test_cross_org_dependency_rejected(self) -> None:
        ids_a = self._register_four(ORG_A)
        # B 机构尝试把 A 的依赖装进自己的包：创建时即不可见
        with self.assertRaises(NotFound):
            self.engine.create_package(
                org_id=ORG_B,
                project_code="TX-Z",
                scopes=["门诊"],
                pin_specs=[{"dep_id": ids_a["场地"]}],
            )
        # 直接读取也不可见（不区分 404，防探测）
        with self.assertRaises(NotFound):
            self.repo.get_dependency(ids_a["场地"], ORG_B)

    def test_requires_closure_and_cycle(self) -> None:
        a = self.engine.register_dependency(
            org_id=ORG_A, category="设备", name="主机",
            evidence={"sn": "A"}, valid_from=T_EARLY,
        )
        b = self.engine.register_dependency(
            org_id=ORG_A, category="设备", name="配套探头",
            evidence={"sn": "B"}, valid_from=T_EARLY, requires=[a.dep_id],
        )
        # 包含 b 但缺少其 requires 的 a -> 闭包违规
        others = self._register_four()
        pkg = self.engine.create_package(
            org_id=ORG_A,
            project_code="TX-R",
            scopes=["门诊"],
            # 用 b 顶替普通设备
            pin_specs=[
                {"dep_id": others["场地"]},
                {"dep_id": b.dep_id},
                {"dep_id": others["药械"]},
                {"dep_id": others["人员"]},
            ],
        )
        with self.assertRaises(IntegrityError) as ctx:
            self.engine.submit_package(package_id=pkg.package_id, org_id=ORG_A)
        self.assertIn("REQUIRES_MISSING", {v.code for v in ctx.exception.violations})

        # 成环：让 a 反过来要求 b，并把两者同时装入新包
        self.engine.new_evidence_version(
            dep_id=a.dep_id, org_id=ORG_A,
            evidence={"sn": "A", "rev": 2}, requires=[b.dep_id],
        )
        cyclic_pkg = self.engine.create_package(
            org_id=ORG_A,
            project_code="TX-R2",
            scopes=["门诊"],
            pin_specs=[
                {"dep_id": others["场地"]},
                {"dep_id": a.dep_id},
                {"dep_id": b.dep_id},
                {"dep_id": others["药械"]},
                {"dep_id": others["人员"]},
            ],
        )
        with self.assertRaises(IntegrityError) as ctx:
            self.engine.submit_package(
                package_id=cyclic_pkg.package_id, org_id=ORG_A
            )
        self.assertIn("REQUIRES_CYCLE", {v.code for v in ctx.exception.violations})

    def test_decisions_are_append_only_and_backdated_rejected(self) -> None:
        pkg_id = self._approved_package()
        pkg = self.repo.get_package(pkg_id, ORG_A)
        # 早于已有决定的时间被拒绝
        with self.assertRaises(DomainError) as ctx:
            self.engine.decide(
                package_id=pkg_id, org_id=ORG_A, decision="条件暂停",
                scopes=["门诊"], effective_at="2026-01-01T00:00:00+00:00",
            )
        self.assertEqual(ctx.exception.code, "BACKDATED_DECISION")
        # 撤销是终态，不能恢复
        ids = self._registered_ids(ORG_A)
        self.engine.change_dependency_status(
            dep_id=ids["场地"], org_id=ORG_A, status=DEP_REVOKED,
            effective_at="2026-03-01T00:00:00+00:00",
        )
        with self.assertRaises(DomainError) as ctx:
            self.engine.change_dependency_status(
                dep_id=ids["场地"], org_id=ORG_A, status=DEP_ACTIVE,
                effective_at="2026-03-02T00:00:00+00:00",
            )
        self.assertEqual(ctx.exception.code, "BAD_TRANSITION")

    def test_partial_authorization(self) -> None:
        ids = self._register_four()
        pkg = self.engine.create_package(
            org_id=ORG_A, project_code="TX-P",
            scopes=["门诊", "住院", "体检"],
            pin_specs=[{"dep_id": d} for d in ids.values()],
        )
        self.engine.submit_package(package_id=pkg.package_id, org_id=ORG_A)
        self.engine.decide(
            package_id=pkg.package_id, org_id=ORG_A,
            decision="部分批准", scopes=["门诊"],
            effective_at="2026-02-01T00:00:00+00:00",
        )
        verdict = self.engine.evaluate(
            self.repo.get_package(pkg.package_id, ORG_A),
            parse_time("2026-02-10T00:00:00+00:00"),
        )
        self.assertTrue(verdict["scopes"]["门诊"]["authorized"])
        self.assertFalse(verdict["scopes"]["住院"]["authorized"])
        self.assertFalse(verdict["scopes"]["体检"]["authorized"])
        self.assertIn("部分授权", verdict["scopes"]["住院"]["reasons"][0])

    def test_suspend_and_resume_are_new_decisions(self) -> None:
        pkg_id = self._approved_package()
        self.engine.decide(
            package_id=pkg_id, org_id=ORG_A, decision="条件暂停",
            scopes=["住院"], reason="住院流程整改",
            effective_at="2026-03-01T00:00:00+00:00",
        )
        pkg = self.repo.get_package(pkg_id, ORG_A)
        suspended = self.engine.evaluate(pkg, parse_time("2026-03-02T00:00:00+00:00"))
        self.assertFalse(suspended["scopes"]["住院"]["authorized"])
        self.assertTrue(suspended["scopes"]["门诊"]["authorized"])  # 其他范围不受影响
        self.assertIn("暂停", suspended["scopes"]["住院"]["reasons"][0])

        # 恢复是另一个新决定
        self.engine.decide(
            package_id=pkg_id, org_id=ORG_A, decision="恢复",
            scopes=["住院"],
            effective_at="2026-04-01T00:00:00+00:00",
        )
        resumed = self.engine.evaluate(
            self.repo.get_package(pkg_id, ORG_A),
            parse_time("2026-04-02T00:00:00+00:00"),
        )
        self.assertTrue(resumed["scopes"]["住院"]["authorized"])
        # 暂停期内的历史判定保持“无效”
        during = self.engine.evaluate(
            self.repo.get_package(pkg_id, ORG_A),
            parse_time("2026-03-15T00:00:00+00:00"),
        )
        self.assertFalse(during["scopes"]["住院"]["authorized"])
        # 决定只追加：时间线上留有三条决定
        self.assertEqual([d.type for d in pkg.decisions], ["批准", "条件暂停", "恢复"])

    def test_equipment_substitution_creates_new_revision(self) -> None:
        pkg_id = self._approved_package()
        ids = self._registered_ids(ORG_A)
        # 旧设备撤销
        self.engine.change_dependency_status(
            dep_id=ids["设备"], org_id=ORG_A, status=DEP_REVOKED,
            effective_at="2026-03-01T00:00:00+00:00",
        )
        # 登记替代设备并形成替代决定
        new_dep = self.engine.register_dependency(
            org_id=ORG_A, category="设备", name="新型加速器",
            evidence={"model": "LX-2027", "sn": "SN999"},
            valid_from="2026-03-05T00:00:00+00:00",
        )
        self.engine.decide(
            package_id=pkg_id, org_id=ORG_A, decision="替代设备",
            replacements=[{"remove": ids["设备"], "add": new_dep.dep_id}],
            effective_at="2026-03-10T00:00:00+00:00",
        )
        pkg = self.repo.get_package(pkg_id, ORG_A)
        self.assertEqual([r.version for r in pkg.revisions], [1, 2])
        pinned_v2 = {p.dep_id for p in pkg.latest_revision.pins}
        self.assertIn(new_dep.dep_id, pinned_v2)
        self.assertNotIn(ids["设备"], pinned_v2)

        # 替代后未来有效；旧设备撤销与替代之间的空档期无效；更早的历史有效
        self.assertTrue(
            self.engine.evaluate(pkg, parse_time("2026-03-20T00:00:00+00:00"))[
                "authorized"
            ]
        )
        self.assertFalse(
            self.engine.evaluate(pkg, parse_time("2026-03-05T00:00:00+00:00"))[
                "authorized"
            ]
        )
        self.assertTrue(
            self.engine.evaluate(pkg, parse_time("2026-02-20T00:00:00+00:00"))[
                "authorized"
            ]
        )

    def test_substitution_must_same_category(self) -> None:
        pkg_id = self._approved_package()
        ids = self._registered_ids(ORG_A)
        wrong = self.engine.register_dependency(
            org_id=ORG_A, category="药械", name="别的药械",
            evidence={"batch": "X"}, valid_from=T_EARLY,
        )
        with self.assertRaises(DomainError) as ctx:
            self.engine.decide(
                package_id=pkg_id, org_id=ORG_A, decision="替代设备",
                replacements=[{"remove": ids["设备"], "add": wrong.dep_id}],
                effective_at="2026-03-10T00:00:00+00:00",
            )
        self.assertEqual(ctx.exception.code, "CATEGORY_MISMATCH")

    def test_service_records_freeze_historical_verdict(self) -> None:
        pkg_id = self._approved_package()
        # 撤销前发生的服务：授权成立，结论冻结
        before = self.engine.record_service(
            package_id=pkg_id, org_id=ORG_A, scope="门诊",
            service_at="2026-02-20T00:00:00+00:00",
        )
        self.assertTrue(before.authorized)
        self.assertNotEqual(before.manifest_digest, "")

        ids = self._registered_ids(ORG_A)
        self.engine.change_dependency_status(
            dep_id=ids["设备"], org_id=ORG_A, status=DEP_REVOKED,
            effective_at="2026-03-01T00:00:00+00:00",
        )
        # 撤销后的服务：被拒
        after = self.engine.record_service(
            package_id=pkg_id, org_id=ORG_A, scope="门诊",
            service_at="2026-03-20T00:00:00+00:00",
        )
        self.assertFalse(after.authorized)

        # 事后再补登撤销前的服务，依然按历史时点判定为成立——失效只影响未来
        backfill = self.engine.record_service(
            package_id=pkg_id, org_id=ORG_A, scope="住院",
            service_at="2026-02-25T00:00:00+00:00",
        )
        self.assertTrue(backfill.authorized)
        # 已存的历史记录不被改写
        stored = self.repo.get_service(before.service_id, ORG_A)
        self.assertTrue(stored.authorized)

    def test_impact_traverses_graph_and_is_org_scoped(self) -> None:
        # 设备主机被配套探头 requires；两者都固定在包内
        host_dep = self.engine.register_dependency(
            org_id=ORG_A, category="设备", name="主机",
            evidence={"sn": "HOST"}, valid_from=T_EARLY,
        )
        probe = self.engine.register_dependency(
            org_id=ORG_A, category="设备", name="探头",
            evidence={"sn": "PROBE"}, valid_from=T_EARLY,
            requires=[host_dep.dep_id],
        )
        others = self._register_four()
        pkg = self.engine.create_package(
            org_id=ORG_A, project_code="TX-G",
            scopes=["门诊"],
            pin_specs=[
                {"dep_id": others["场地"]},
                {"dep_id": host_dep.dep_id},
                {"dep_id": probe.dep_id},
                {"dep_id": others["药械"]},
                {"dep_id": others["人员"]},
            ],
        )
        self.engine.submit_package(package_id=pkg.package_id, org_id=ORG_A)
        self.engine.decide(
            package_id=pkg.package_id, org_id=ORG_A, decision="批准",
            effective_at="2026-02-01T00:00:00+00:00",
        )
        # 另一个机构有自己的同名资源与授权，不应出现在影响面里
        self._approved_package(ORG_B)

        impact = self.engine.impact_of_dependency(
            dep_id=host_dep.dep_id, org_id=ORG_A
        )
        self.assertIn(probe.dep_id, impact["propagated_dependencies"])
        self.assertEqual(len(impact["affected_authorizations"]), 1)
        hit = impact["affected_authorizations"][0]
        self.assertEqual(hit["package_id"], pkg.package_id)
        matched = {m["dep_id"]: m for m in hit["matched_pins"]}
        self.assertIn(host_dep.dep_id, matched)
        self.assertIn(probe.dep_id, matched)
        self.assertEqual(matched[probe.dep_id]["path"], [host_dep.dep_id, probe.dep_id])
        self.assertTrue(impact["future_only"])

        # 跨机构查询影响面：资源不可见
        with self.assertRaises(NotFound):
            self.engine.impact_of_dependency(dep_id=host_dep.dep_id, org_id=ORG_B)

    def test_impact_after_revocation_marks_authorization_invalid(self) -> None:
        pkg_id = self._approved_package()
        ids = self._registered_ids(ORG_A)
        self.engine.change_dependency_status(
            dep_id=ids["药械"], org_id=ORG_A, status=DEP_SUSPENDED,
            effective_at="2026-03-01T00:00:00+00:00",
        )
        impact = self.engine.impact_of_dependency(
            dep_id=ids["药械"], org_id=ORG_A
        )
        self.assertEqual(impact["current_status"], DEP_SUSPENDED)
        self.assertEqual(len(impact["affected_authorizations"]), 1)
        self.assertFalse(
            impact["affected_authorizations"][0]["currently_authorized"]
        )


    def test_concurrent_decisions_keep_atomic_sequence(self) -> None:
        import threading

        pkg_id = self._approved_package()
        errors: list[Exception] = []

        def suspend(scope: str) -> None:
            try:
                self.engine.decide(
                    package_id=pkg_id, org_id=ORG_A, decision="条件暂停",
                    scopes=[scope], effective_at="2026-03-01T00:00:00+00:00",
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=suspend, args=("门诊",)),
            threading.Thread(target=suspend, args=("住院",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        pkg = self.repo.get_package(pkg_id, ORG_A)
        seqs = [d.seq for d in pkg.decisions]
        self.assertEqual(seqs, [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
