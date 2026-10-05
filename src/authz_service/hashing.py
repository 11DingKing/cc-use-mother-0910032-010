"""确定性摘要：规范化 JSON 后计算 SHA-256，用于证据冻结。"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """排序键、无空白的规范化 UTF-8 字节，保证跨进程一致。"""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
