"""授权依赖包服务端。

把机构开展治疗项目所需的场地、设备、药械、人员条件建模为带版本的
依赖；授权申请是固定证据摘要的依赖包；批准后的每次替代、部分授权、
条件暂停与恢复都形成只追加的新决定。依赖状态沿依赖图传播，且只影响
生效时点之后的服务。
"""
from __future__ import annotations

from .engine import AuthorizationEngine, DomainError
from .repository import Repository

__all__ = ["AuthorizationEngine", "DomainError", "Repository"]
