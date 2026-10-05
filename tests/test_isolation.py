"""机构数据隔离：任何途径都不能读到或影响其他机构的授权数据。"""
from __future__ import annotations

try:
    from tests._helpers import *
except ImportError:  # unittest discover -s tests 时 tests 不是包前缀
    from _helpers import *


def test_dep_list_scoped_to_org(client):
    a = client.get("/deps", headers=A_COMP).json()
    b = client.get("/deps", headers=B_COMP).json()
    assert {d["id"] for d in a} >= {"FAC-A1", "DEV-A1", "PER-A1"}
    assert {d["id"] for d in b} == {"FAC-B1", "DEV-B1", "PER-B1"}


def test_cross_org_dep_read_is_404(client):
    r = client.get("/deps/DEV-A1", headers=B_COMP)
    assert r.status_code == 404
    r = client.get("/deps/DEV-B1", headers=A_COMP)
    assert r.status_code == 404


def test_cross_org_package_read_is_404(client):
    pkg = submit_full_a(client).json()
    r = client.get(f"/packages/{pkg['id']}", headers=B_COMP)
    assert r.status_code == 404


def test_cross_org_decision_is_404(client):
    pkg = submit_full_a(client).json()
    r = client.post(f"/packages/{pkg['id']}/decisions/grant",
                    json={"reason": "越机构审批"}, headers=B_REG)
    assert r.status_code == 404
    # A 的授权包未受影响
    detail = client.get(f"/packages/{pkg['id']}", headers=A_REG).json()
    assert detail["decisions"] == []


def test_cross_org_suspend_revoke_is_404_and_no_effect(client):
    r = client.post("/deps/DEV-A1/suspend", json={"reason": "越机构操作"}, headers=B_REG)
    assert r.status_code == 404
    dep = client.get("/deps/DEV-A1", headers=A_REG).json()
    assert dep["versions"]["1"]["status"] == "active"


def test_impact_graph_does_not_leak_other_org(client):
    submit_full_a(client)
    # B 用自己的同槽位依赖构包并批准
    payload = {
        "project_code": "PROJ-RT",
        "pins": [
            {"slot": "site", "dep_id": "FAC-B1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-B1", "version": 1},
            {"slot": "operator", "dep_id": "PER-B1", "version": 1},
        ],
    }
    bpkg = client.post("/packages", json=payload, headers=B_COMP).json()
    client.post(f"/packages/{bpkg['id']}/decisions/grant",
                json={"reason": "ok"}, headers=B_REG)

    client.post("/deps/DEV-A1/revoke", json={"reason": "A 设备失效"}, headers=A_REG)
    g = client.get("/deps/DEV-A1/impact", headers=A_COMP).json()
    assert all(e["org_id"] == "ORG-A" for e in g["edges"])

    # B 无法通过 A 的 dep_id 探测图谱
    assert client.get("/deps/DEV-A1/impact", headers=B_COMP).status_code == 404

    # 事件流同样按机构隔离
    a_events = client.get("/events", headers=A_REG).json()
    b_events = client.get("/events", headers=B_REG).json()
    assert {e["dep_id"] for e in a_events} == {"DEV-A1"}
    assert b_events == []


def test_service_records_are_org_scoped(client):
    pkg = submit_full_a(client).json()
    grant_a(client, pkg["id"])
    client.post(f"/packages/{pkg['id']}/services", json={"slot": "machine"}, headers=A_DOC)

    assert client.get(f"/packages/{pkg['id']}/services", headers=B_DOC).status_code == 404
    assert client.get("/services", headers=B_DOC).json() == []
    assert len(client.get("/services", headers=A_DOC).json()) == 1


def test_unauthenticated_and_unknown_principal_rejected(client):
    assert client.get("/deps").status_code == 401
    assert client.get("/deps", headers={"X-Principal-Id": "NOBODY"}).status_code == 401


def test_practitioner_cannot_submit_or_decide(client):
    r = client.post("/packages", json={
        "project_code": "PROJ-RT",
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
        ],
    }, headers=A_DOC)
    assert r.status_code == 403
