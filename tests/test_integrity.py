"""完整性规则与证据摘要冻结。"""
from __future__ import annotations

try:
    from tests._helpers import *
except ImportError:  # unittest discover -s tests 时 tests 不是包前缀
    from _helpers import *


def test_submit_full_package_passes_integrity(client):
    r = submit_full_a(client)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["latest_version"] == 1
    ver = body["versions"][0]
    assert ver["integrity"]["status"] == "passed"
    assert len(ver["manifest_digest"]) == 64
    # 证据在提交时拷贝进清单
    machine = next(p for p in ver["pins"] if p["slot"] == "machine")
    assert machine["evidence_frozen"][0]["sha256"] == "a" * 64


def test_missing_required_slot_fails_collecting_all_problems(client):
    payload = {
        "project_code": "PROJ-RT",
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
        ],
    }
    r = client.post("/packages", json=payload, headers=A_COMP)
    assert r.status_code == 422
    details = r.json()["details"]
    rules = {d["rule"] for d in details}
    assert "MISSING_REQUIRED" in rules
    blocked = {d["slot"] for d in details if d["rule"] == "MISSING_REQUIRED"}
    assert blocked == {"machine", "operator"}


def test_kind_mismatch_and_unknown_slot(client):
    payload = {
        "project_code": "PROJ-RT",
        "pins": [
            {"slot": "site", "dep_id": "DEV-A1", "version": 1},       # 设备不能放进场地槽
            {"slot": "machine", "dep_id": "DEV-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
            {"slot": "ghost", "dep_id": "DEV-A1", "version": 1},      # 目录里没有的槽位
        ],
    }
    r = client.post("/packages", json=payload, headers=A_COMP)
    assert r.status_code == 422
    rules = {d["rule"] for d in r.json()["details"]}
    assert "KIND_MISMATCH" in rules
    assert "UNKNOWN_SLOT" in rules


def test_cross_org_dependency_reference_is_rejected_as_not_found(client):
    # 机构 A 的授权包不能钉选机构 B 的设备；报错口径与“不存在”一致
    payload = {
        "project_code": "PROJ-RT",
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-B1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
        ],
    }
    r = client.post("/packages", json=payload, headers=A_COMP)
    assert r.status_code == 422
    prob = next(d for d in r.json()["details"] if d["dep_id"] == "DEV-B1")
    assert prob["rule"] == "DEP_NOT_FOUND"


def test_nonexistent_dep_version_rejected(client):
    payload = {
        "project_code": "PROJ-RT",
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 99},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
        ],
    }
    r = client.post("/packages", json=payload, headers=A_COMP)
    assert r.status_code == 422
    assert any(d["rule"] == "VERSION_NOT_FOUND" for d in r.json()["details"])


def test_pinned_inactive_dep_rejected_at_submission(client):
    r = client.post("/deps/DEV-A1/suspend", json={"reason": "故障待修"}, headers=A_REG)
    assert r.status_code == 200
    r = submit_full_a(client)
    assert r.status_code == 422
    assert any(d["rule"] == "DEP_NOT_ACTIVE" and d["dep_id"] == "DEV-A1"
               for d in r.json()["details"])


def test_evidence_freeze_is_immutable_after_dep_change(client):
    r = submit_full_a(client)
    pkg = r.json()
    digest_before = pkg["versions"][0]["manifest_digest"]

    # 依赖侧更新证据 → 产生新版本
    r2 = client.post("/deps/DEV-A1/evidence",
                     json={"evidence": [{"evidence_id": "EV-DEV-A1-NEW", "sha256": "f" * 64}]},
                     headers=A_COMP)
    assert r2.status_code == 201
    assert r2.json()["current_version"] == 2

    # 已提交清单的冻结摘要与证据快照不变
    again = client.get(f"/packages/{pkg['id']}", headers=A_COMP).json()
    assert again["versions"][0]["manifest_digest"] == digest_before
    machine = next(p for p in again["versions"][0]["pins"] if p["slot"] == "machine")
    assert machine["evidence_frozen"][0]["sha256"] == "a" * 64

    # 重新钉选新版本 → 清单摘要变化（新包版本）
    r3 = client.post(f"/packages/{pkg['id']}/resubmit", json={
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 2},
            {"slot": "contrast", "dep_id": "DRG-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
        ]
    }, headers=A_COMP)
    assert r3.status_code == 201
    assert r3.json()["latest_version"] == 2
    assert r3.json()["versions"][-1]["manifest_digest"] != digest_before


def test_identical_resubmit_is_rejected(client):
    pkg = submit_full_a(client).json()
    r = client.post(f"/packages/{pkg['id']}/resubmit", json={
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 1},
            {"slot": "contrast", "dep_id": "DRG-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
        ]
    }, headers=A_COMP)
    assert r.status_code == 409
    assert r.json()["error"] == "MANIFEST_UNCHANGED"


def test_optional_slot_missing_is_ok(client):
    payload = {
        "project_code": "PROJ-RT",
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
        ],
    }
    r = client.post("/packages", json=payload, headers=A_COMP)
    assert r.status_code == 201
    assert r.json()["versions"][0]["integrity"]["status"] == "passed"


def test_dep_requires_evidence_digest(client):
    r = client.post("/deps", json={
        "kind": "device", "name": "无证据设备",
        "evidence": [{"evidence_id": "EV-X", "sha256": ""}],
    }, headers=A_COMP)
    # pydantic 层拒绝空摘要
    assert r.status_code == 422
