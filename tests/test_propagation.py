"""依赖失效传播：沿授权依赖图影响未来服务，历史服务快照不被改写。"""
from __future__ import annotations

try:
    from tests._helpers import *
except ImportError:  # unittest discover -s tests 时 tests 不是包前缀
    from _helpers import *


def _granted_package(client):
    pkg = submit_full_a(client).json()
    grant_a(client, pkg["id"])
    return pkg


def test_service_registered_before_revocation_keeps_snapshot(client):
    pkg = _granted_package(client)
    # 失效前完成一次服务
    r = client.post(f"/packages/{pkg['id']}/services", json={"slot": "machine"}, headers=A_DOC)
    assert r.status_code == 201, r.text
    svc = r.json()
    assert svc["snapshot"]["dep_status"] == "active"
    assert svc["eligible"] is True

    # 关键人员依赖撤销
    r2 = client.post("/deps/PER-A1/revoke", json={"reason": "执业资格注销"}, headers=A_REG)
    assert r2.status_code == 200

    # 历史服务记录仍在，快照仍是当时结论
    past = client.get(f"/packages/{pkg['id']}/services", headers=A_DOC).json()
    assert len(past) == 1
    assert past[0]["id"] == svc["id"]
    assert past[0]["snapshot"]["dep_status"] == "active"

    # 未来服务被阻断
    elig = client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()
    assert elig["eligible"] is False
    op = next(c for c in elig["checks"] if c["slot"] == "operator")
    assert op["dep_status"] == "revoked"

    r3 = client.post(f"/packages/{pkg['id']}/services", json={"slot": "machine"}, headers=A_DOC)
    # 整体授权失效，任一服务登记都应被阻断
    assert r3.status_code == 409


def test_revocation_publishes_impact_event_with_graph_edges(client):
    pkg = _granted_package(client)
    client.post("/deps/DEV-A1/revoke", json={"reason": "设备故障报废"}, headers=A_REG)

    events = client.get("/events", headers=A_REG).json()
    assert len(events) == 1
    ev = events[0]
    assert ev["type"] == "DEPENDENCY_REVOKED"
    assert ev["dep_id"] == "DEV-A1"
    impact0 = ev["impact"][0]
    assert impact0["package_id"] == pkg["id"]
    assert impact0["slot"] == "machine"
    assert impact0["effect"] == "future_services_blocked"

    # 图谱查询沿边列出受影响授权
    graph = client.get("/deps/DEV-A1/impact", headers=A_COMP).json()
    assert graph["impacted_packages"] == [pkg["id"]]
    edge = graph["edges"][0]
    assert edge["slot"] == "machine" and edge["is_latest"] is True


def test_impact_follows_pinned_versions_not_just_current(client):
    pkg = submit_full_a(client).json()
    grant_a(client, pkg["id"])
    # 依赖出 v2；授权包仍钉在 v1
    client.post("/deps/DEV-A1/evidence",
                json={"evidence": [{"evidence_id": "EV2", "sha256": "d" * 64}]},
                headers=A_COMP)

    g_v1 = client.get("/deps/DEV-A1/impact?version=1", headers=A_COMP).json()
    assert g_v1["impacted_packages"] == [pkg["id"]]
    g_v2 = client.get("/deps/DEV-A1/impact?version=2", headers=A_COMP).json()
    assert g_v2["impacted_packages"] == []


def test_suspension_blocks_future_services_and_resume_restores(client):
    pkg = _granted_package(client)
    client.post("/deps/FAC-A1/suspend", json={"reason": "消防整改"}, headers=A_REG)
    assert client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()["eligible"] is False

    client.post("/deps/FAC-A1/resume", json={"reason": "整改通过"}, headers=A_REG)
    elig = client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()
    assert elig["eligible"] is True


def test_replacement_after_revocation_reenables_future_services(client):
    pkg = _granted_package(client)
    client.post("/deps/DEV-A1/revoke", json={"reason": "报废"}, headers=A_REG)
    assert client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()["eligible"] is False

    r = client.post(f"/packages/{pkg['id']}/decisions/replace",
                    json={"reason": "改用备用机", "slot": "machine",
                          "replacement_dep_id": "DEV-A2"}, headers=A_REG)
    assert r.status_code == 201
    assert client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()["eligible"] is True

    # 备用机再失效，未来服务再次被阻断
    client.post("/deps/DEV-A2/revoke", json={"reason": "备用机也故障"}, headers=A_REG)
    assert client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()["eligible"] is False


def test_optional_slot_failure_does_not_block_service(client):
    pkg = _granted_package(client)
    client.post("/deps/DRG-A1/revoke", json={"reason": "造影剂批次召回"}, headers=A_REG)
    elig = client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()
    assert elig["eligible"] is True
    contrast = next(c for c in elig["checks"] if c["slot"] == "contrast")
    assert contrast["eligible"] is True  # 非关键槽位仅提示，不阻断
