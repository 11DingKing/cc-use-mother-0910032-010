"""决定链：批准、部分授权、条件暂停/恢复、替代、撤销均为不可变新决定。"""
from __future__ import annotations

try:
    from tests._helpers import *
except ImportError:  # unittest discover -s tests 时 tests 不是包前缀
    from _helpers import *


def _submit_and_grant(client):
    pkg = submit_full_a(client).json()
    r = grant_a(client, pkg["id"])
    assert r.status_code == 201, r.text
    assert r.json()["authorization"]["active"] is True
    return pkg


def test_grant_is_recorded_as_immutable_decision(client):
    pkg = _submit_and_grant(client)
    detail = client.get(f"/packages/{pkg['id']}", headers=A_REG).json()
    assert len(detail["decisions"]) == 1
    assert detail["decisions"][0]["type"] == "grant"
    assert detail["decisions"][0]["package_version"] == 1


def test_partial_grant_blocks_unapproved_required_slots(client):
    pkg = submit_full_a(client).json()
    r = client.post(f"/packages/{pkg['id']}/decisions/partial-grant",
                    json={"reason": "操作人员资质待复核", "approved_slots": ["site", "machine", "contrast"]},
                    headers=A_REG)
    assert r.status_code == 201
    auth = r.json()["authorization"]
    assert auth["active"] is False
    assert {"slot": "operator", "reason": "denied"} in auth["blocked"]

    # 未来服务在未授权槽位被阻断
    elig = client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()
    assert elig["eligible"] is False
    op = next(c for c in elig["checks"] if c["slot"] == "operator")
    assert op["eligible"] is False

    # 决定链不可变：后来的整体批准是第 2 条决定，而不是覆盖第 1 条
    r2 = grant_a(client, pkg["id"])
    assert r2.status_code == 201
    detail = client.get(f"/packages/{pkg['id']}", headers=A_REG).json()
    assert [d["type"] for d in detail["decisions"]] == ["partial_grant", "grant"]


def test_suspend_and_resume_are_separate_decisions(client):
    pkg = _submit_and_grant(client)
    r = client.post(f"/packages/{pkg['id']}/decisions/suspend",
                    json={"reason": "机房安全检查", "slots": ["site"]}, headers=A_REG)
    assert r.status_code == 201
    assert r.json()["authorization"]["active"] is False

    # 暂停期间服务被阻断
    elig = client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()
    assert elig["eligible"] is False

    r2 = client.post(f"/packages/{pkg['id']}/decisions/resume",
                     json={"reason": "检查完成恢复", "slots": ["site"]}, headers=A_REG)
    assert r2.status_code == 201
    assert r2.json()["authorization"]["active"] is True

    detail = client.get(f"/packages/{pkg['id']}", headers=A_REG).json()
    assert [d["type"] for d in detail["decisions"]] == ["grant", "suspend", "resume"]


def test_resume_only_affects_suspended_slots(client):
    pkg = _submit_and_grant(client)
    client.post(f"/packages/{pkg['id']}/decisions/suspend",
                json={"reason": "x", "slots": ["site", "machine"]}, headers=A_REG)
    r = client.post(f"/packages/{pkg['id']}/decisions/resume",
                    json={"reason": "x", "slots": ["site"]}, headers=A_REG)
    blocked = {b["slot"] for b in r.json()["authorization"]["blocked"]}
    assert blocked == {"machine"}


def test_replace_device_is_new_decision_and_old_pin_preserved(client):
    pkg = _submit_and_grant(client)
    # 原设备撤销
    client.post("/deps/DEV-A1/revoke", json={"reason": "设备报废"}, headers=A_REG)
    # 以备用机替代 —— 形成新决定
    r = client.post(f"/packages/{pkg['id']}/decisions/replace",
                    json={"reason": "启用备用直线加速器", "slot": "machine",
                          "replacement_dep_id": "DEV-A2"}, headers=A_REG)
    assert r.status_code == 201, r.text
    dec = r.json()["decision"]
    assert dec["type"] == "replace"
    assert dec["body"]["slots"]["machine"]["replaces"] == "DEV-A1"
    assert dec["body"]["slots"]["machine"]["dep_id"] == "DEV-A2"
    assert r.json()["authorization"]["active"] is True

    # 原清单钉选仍冻结在 v1，没有被改写
    detail = client.get(f"/packages/{pkg['id']}", headers=A_REG).json()
    machine_pin = next(p for p in detail["versions"][0]["pins"] if p["slot"] == "machine")
    assert machine_pin["dep_id"] == "DEV-A1"
    assert [d["type"] for d in detail["decisions"]] == ["grant", "replace"]


def test_replace_rejects_cross_kind_and_inactive(client):
    pkg = _submit_and_grant(client)
    r = client.post(f"/packages/{pkg['id']}/decisions/replace",
                    json={"reason": "错", "slot": "machine",
                          "replacement_dep_id": "FAC-A1"}, headers=A_REG)
    assert r.status_code == 422
    assert r.json()["error"] == "KIND_MISMATCH"

    client.post("/deps/DEV-A2/suspend", json={"reason": "维修"}, headers=A_REG)
    r2 = client.post(f"/packages/{pkg['id']}/decisions/replace",
                     json={"reason": "错", "slot": "machine",
                           "replacement_dep_id": "DEV-A2"}, headers=A_REG)
    assert r2.status_code == 422
    assert r2.json()["error"] == "DEP_NOT_ACTIVE"


def test_revoke_authorization_is_decision_and_terminal_for_slots(client):
    pkg = _submit_and_grant(client)
    r = client.post(f"/packages/{pkg['id']}/decisions/revoke",
                    json={"reason": "机构不再开展该项目"}, headers=A_REG)
    assert r.status_code == 201
    assert r.json()["authorization"]["active"] is False
    elig = client.get(f"/packages/{pkg['id']}/eligibility", headers=A_DOC).json()
    assert elig["eligible"] is False


def test_reviewer_may_decide_within_same_org(client):
    pkg = submit_full_a(client).json()
    r = grant_a(client, pkg["id"], headers=A_REV)
    assert r.status_code == 201


def test_compliance_cannot_decide(client):
    pkg = submit_full_a(client).json()
    r = client.post(f"/packages/{pkg['id']}/decisions/grant",
                    json={"reason": "越权"}, headers=A_COMP)
    assert r.status_code == 403


def test_dep_revoke_is_terminal_but_new_version_can_be_registered(client):
    client.post("/deps/DEV-A1/revoke", json={"reason": "报废"}, headers=A_REG)
    # 已撤销不能 resume
    r = client.post("/deps/DEV-A1/resume", json={"reason": "想恢复"}, headers=A_REG)
    assert r.status_code == 409
    # 可以重新登记替代资产
    r2 = client.post("/deps", json={
        "kind": "device", "name": "新加速器",
        "evidence": [{"evidence_id": "EV-NEW", "sha256": "c" * 64}],
    }, headers=A_COMP)
    assert r2.status_code == 201
