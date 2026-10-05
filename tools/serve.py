"""便捷启动脚本：python3 tools/serve.py [port]"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authz_service.api import serve  # noqa: E402


if __name__ == "__main__":
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = serve(host, port)
    print(f"授权依赖包服务监听 http://{host}:{port}（需携带 X-Org-Id 头）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
