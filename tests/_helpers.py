"""测试共享常量与请求辅助（不依赖 pytest/fastapi，可被 unittest 安全导入）。"""
from __future__ import annotations

# 常用身份头
A_COMP = {"X-Principal-Id": "U-COMP-A"}
A_REG = {"X-Principal-Id": "U-REG-A"}
A_REV = {"X-Principal-Id": "U-REV"}
A_DOC = {"X-Principal-Id": "U-DOC-A"}
B_COMP = {"X-Principal-Id": "U-COMP-B"}
B_REG = {"X-Principal-Id": "U-REG-B"}
B_DOC = {"X-Principal-Id": "U-DOC-B"}


def submit_full_a(client, headers=A_COMP, project="PROJ-RT"):
    """机构 A 提交完整四槽位授权包。"""
    payload = {
        "project_code": project,
        "pins": [
            {"slot": "site", "dep_id": "FAC-A1", "version": 1},
            {"slot": "machine", "dep_id": "DEV-A1", "version": 1},
            {"slot": "contrast", "dep_id": "DRG-A1", "version": 1},
            {"slot": "operator", "dep_id": "PER-A1", "version": 1},
        ],
    }
    return client.post("/packages", json=payload, headers=headers)


def grant_a(client, package_id, headers=A_REG):
    return client.post(f"/packages/{package_id}/decisions/grant",
                       json={"reason": "现场核验通过"}, headers=headers)
