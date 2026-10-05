"""开发启动：python -m uvicorn authorization_package.api:app。"""
from __future__ import annotations

import uvicorn  # type: ignore

if __name__ == "__main__":
    uvicorn.run("authorization_package.api:app", host="0.0.0.0", port=8000, reload=False)
