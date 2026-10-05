"""演示种子数据：两家机构、治疗项目目录、初始依赖。

机构 A（ORG-A，第一医院）与机构 B（ORG-B，第二医院）互相隔离；
设备 DEV-A2 是 DEV-A1 的可替代型号（在治疗项目目录的槽位中并列）。
"""
from __future__ import annotations

from .models import (
    Kind,
    Role,
    make_dep,
    make_dep_version,
    make_principal,
    make_project,
    make_slot,
    now_iso,
)
from .store import STORE


def seed() -> None:
    with STORE.lock:
        if STORE.projects:
            return
        t0 = now_iso()

        # 角色账号（演示用；X-Principal-Id 头即“已认证身份”）
        STORE.principals["U-COMP-A"] = make_principal(
            "U-COMP-A", "甲机构合规员", Role.COMPLIANCE, "ORG-A"
        )
        STORE.principals["U-REG-A"] = make_principal(
            "U-REG-A", "甲机构监管员", Role.REGULATOR, "ORG-A"
        )
        STORE.principals["U-REV"] = make_principal(
            "U-REV", "跨机构复核专家", Role.REVIEWER, "ORG-A"
        )
        STORE.principals["U-DOC-A"] = make_principal(
            "U-DOC-A", "甲机构执业人员", Role.PRACTITIONER, "ORG-A"
        )
        STORE.principals["U-COMP-B"] = make_principal(
            "U-COMP-B", "乙机构合规员", Role.COMPLIANCE, "ORG-B"
        )
        STORE.principals["U-REG-B"] = make_principal(
            "U-REG-B", "乙机构监管员", Role.REGULATOR, "ORG-B"
        )
        STORE.principals["U-DOC-B"] = make_principal(
            "U-DOC-B", "乙机构执业人员", Role.PRACTITIONER, "ORG-B"
        )

        # 治疗项目目录：放射治疗
        STORE.projects["PROJ-RT"] = make_project(
            "PROJ-RT",
            "放射治疗",
            [
                make_slot("site", [Kind.FACILITY.value]),
                make_slot("machine", [Kind.DEVICE.value]),
                make_slot("contrast", [Kind.DRUG.value], required=False, key=False),
                make_slot("operator", [Kind.PERSONNEL.value]),
            ],
        )

        # 机构 A 的依赖
        def dep(dep_id: str, kind: str, name: str, requires=None) -> str:
            STORE.deps[dep_id] = make_dep(
                dep_id,
                "ORG-A",
                kind,
                name,
                make_dep_version(1, [{"evidence_id": f"EV-{dep_id}", "sha256": "a" * 64}], requires or [], t0),
            )
            return dep_id

        dep("FAC-A1", Kind.FACILITY.value, "甲机构放疗机房")
        dep("DEV-A1", Kind.DEVICE.value, "甲机构直线加速器-01")
        dep("DEV-A2", Kind.DEVICE.value, "甲机构直线加速器-02（备用机）")
        dep("DRG-A1", Kind.DRUG.value, "甲机构造影剂")
        dep("PER-A1", Kind.PERSONNEL.value, "物理师 张某某")
        dep("PER-A2", Kind.PERSONNEL.value, "技师 李某某")

        # 机构 B 的依赖（编号独立，证明跨机构隔离）
        for dep_id, kind, name in [
            ("FAC-B1", Kind.FACILITY.value, "乙机构放疗机房"),
            ("DEV-B1", Kind.DEVICE.value, "乙机构直线加速器-01"),
            ("PER-B1", Kind.PERSONNEL.value, "物理师 王某某"),
        ]:
            STORE.deps[dep_id] = make_dep(
                dep_id,
                "ORG-B",
                kind,
                name,
                make_dep_version(1, [{"evidence_id": f"EV-{dep_id}", "sha256": "b" * 64}], [], t0),
            )
