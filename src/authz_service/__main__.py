"""命令行启动：PYTHONPATH=src python3 -m authz_service [host] [port]"""
from __future__ import annotations

import sys

from .api import serve


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    server = serve(host, port)
    print(f"授权依赖包服务监听 http://{host}:{port}（需携带 X-Org-Id 头）")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
