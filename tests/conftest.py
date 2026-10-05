import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tests._helpers import A_COMP, A_REG, A_REV, A_DOC, B_COMP, B_REG, B_DOC  # noqa: E402,F401


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from authorization_package.api import create_app
    from authorization_package.store import STORE

    STORE.reset()
    app = create_app()
    with TestClient(app) as c:
        yield c
