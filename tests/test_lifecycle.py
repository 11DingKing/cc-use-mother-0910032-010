"""端到端业务场景：新增治疗项目申请 → 审批 → 依赖撤销 → 替代恢复 → 历史可溯。"""
from __future__ import annotations

try:
    from tests._helpers import *
except ImportError:  # unittest discover -s tests 时 tests 不是包前缀
    from _helpers import *


def test_full_lifecycle_journey(client):
    # 1) 机构合规员就“放射治疗”提交授权包：场地/设备/药械/人员四条件同时钉版本
    pkg = submit_full_a(client).json()
    pid = pkg["id"]

    # 2) 监管人员逐项核验后整体批准（一条决定）
    r = client.post(f"/packages/{pid}/decisions/grant",
                    json={"reason": "四条件均核验通过"}, headers=A_REG)
    assert r.status_code == 201

    # 3) 执业人员开展服务并留痕（快照冻结）
    svc = client.post(f"/packages/{pid}/services", json={"slot": "operator"}, headers=A_DOC)
    assert svc.status_code == 201

    # 4) 单项依赖（人员）撤销：整体授权不能保持有效
    client.post("/deps/PER-A1/revoke", json={"reason": "人员执业资格被注销"}, headers=A_REG)
    elig = client.get(f"/packages/{pid}/eligibility", headers=A_DOC).json()
    assert elig["eligible"] is False
    op = next(c for c in elig["checks"] if c["slot"] == "operator")
    assert op["dep_status"] == "revoked"

    # 5) 重新提交新人员版本的授权包（新版本，旧版本与旧决定保留）
    new_pkg = client.post(f"/packages/{pid}/resubmit", json={
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 1},
            {"slot": "contrast", "dep_id": "DRG-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A2", "version": 1},
        ]
    }, headers=A_COMP)
    assert new_pkg.status_code == 201
    assert new_pkg.json()["latest_version"] == 2

    # 6) 新版本再批准，服务恢复；历史服务仍挂在 v1 的事实链上
    client.post(f"/packages/{pid}/decisions/grant",
                json={"reason": "人员条件补齐"}, headers=A_REG)
    elig2 = client.get(f"/packages/{pid}/eligibility", headers=A_DOC).json()
    assert elig2["eligible"] is True

    history = client.get(f"/packages/{pid}/services", headers=A_DOC).json()
    assert len(history) == 1
    assert history[0]["manifest_digest"]  # 历史服务可回溯到当时清单摘要

    detail = client.get(f"/packages/{pid}", headers=A_REG).json()
    assert [v["version"] for v in detail["versions"]] == [1, 2]
    assert [d["type"] for d in detail["decisions"]] == ["grant", "grant"]
    assert [d["package_version"] for d in detail["decisions"]] == [1, 2]


def test_replace_device_journey(client):
    pkg = submit_full_a(client).json()
    pid = pkg["id"]
    client.post(f"/packages/{pid}/decisions/grant", json={"reason": "通过"}, headers=A_REG)

    # 设备撤销 → 服务阻断 → 替代决定 → 服务恢复，全程决定可回放
    client.post("/deps/DEV-A1/revoke", json={"reason": "加速器报废"}, headers=A_REG)
    assert client.get(f"/packages/{pid}/eligibility", headers=A_DOC).json()["eligible"] is False

    r = client.post(f"/packages/{pid}/decisions/replace",
                    json={"reason": "更换为备用机 DEV-A2", "slot": "machine",
                          "replacement_dep_id": "DEV-A2"}, headers=A_REG)
    assert r.status_code == 201
    assert client.get(f"/packages/{pid}/eligibility", headers=A_DOC).json()["eligible"] is True

    events = client.get("/events", headers=A_REG).json()
    assert events[0]["impact"][0]["package_id"] == pid


def test_resubmit_requires_reapproval_old_decision_does_not_carry(client):
    pkg = submit_full_a(client).json()
    pid = pkg["id"]
    client.post(f"/packages/{pid}/decisions/grant", json={"reason": "v1 通过"}, headers=A_REG)
    assert client.get(f"/packages/{pid}/eligibility", headers=A_DOC).json()["eligible"] is True

    # 同一包重提交 v2（换人员证据）：v1 的批准不自动沿用，未来服务立即阻断
    r = client.post(f"/packages/{pid}/resubmit", json={
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 1},
            {"slot": "contrast", "dep_id": "DRG-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A2", "version": 1},
        ]
    }, headers=A_COMP)
    assert r.status_code == 201
    assert client.get(f"/packages/{pid}/eligibility", headers=A_DOC).json()["eligible"] is False

    # 重新批准后恢复；v1 决定仍完整保留
    client.post(f"/packages/{pid}/decisions/grant", json={"reason": "v2 通过"}, headers=A_REG)
    assert client.get(f"/packages/{pid}/eligibility", headers=A_DOC).json()["eligible"] is True
    detail = client.get(f"/packages/{pid}", headers=A_REG).json()
    assert [d["package_version"] for d in detail["decisions"]] == [1, 2]
