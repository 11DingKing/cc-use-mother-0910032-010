"""确定性摘要工具：授权包清单与证据均使用规范 JSON 的 SHA-256 摘要。"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """排序键、紧凑分隔、UTF-8，保证跨进程字节一致。"""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha256_hex(value: Any) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def digest_of(value: Any) -> str:
    """对任意可 JSON 化结构计算摘要。"""
    return sha256_hex(canonical_json(value))
