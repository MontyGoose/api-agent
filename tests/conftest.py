import os
import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture(scope="session", autouse=True)
def test_env_vars():
    os.environ.setdefault("SECRET_KEY", "test-secret-key")
    os.environ.setdefault("ENV", "test")
    os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
    yield


@pytest.fixture(scope="session")
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def user_token(client: TestClient) -> str:
    r = client.post("/api/v1/auth/token", data={"username": "user", "password": "x"})
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture()
def admin_token(client: TestClient) -> str:
    r = client.post("/api/v1/auth/token", data={"username": "admin", "password": "x"})
    assert r.status_code == 200
    return r.json()["access_token"]

@pytest.fixture()
def auth_header():
    def _make(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}
    return _make
