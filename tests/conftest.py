import pytest
import httpx
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from qsuite.api import create_app
from qsuite.config import Settings

PASSWORD = "test-only-correct-password-2026"


@pytest.fixture
def settings(tmp_path):
    return Settings(
        mode="development",
        origin="http://testserver",
        data_dir=str(tmp_path / "app"),
        security_dir=str(tmp_path / "security"),
        secret_dir=str(tmp_path / "secrets"),
        security={
            "trusted_cidrs": ["127.0.0.0/8"],
            "trusted_countries": ["RO"],
            "trusted_continents": ["EU"],
        },
    )


@pytest.fixture
def app(settings):
    def broker(settings, operation, target="", **kwargs):
        if operation == "packages.inventory":
            from qsuite.packages import inventory

            return {"packages": inventory(settings)}
        if operation == "status":
            return {"hostname": "isolated-test-fixture", "access": "lan"}
        if operation == "access.trust":
            return {"require_trusted_tls": target == "required", "https_required": True}
        return {"operation": operation, "target": target, "exit_code": 0, "output": "fixture operation"}

    app = create_app(settings, Fernet.generate_key(), broker=broker, news_transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    app.state.auth.create_user("owner", PASSWORD, "owner")
    return app


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


def login(client, username="owner", password=PASSWORD, otp=None):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password, "otp": otp},
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200, response.text
    return {"Origin": "http://testserver", "X-CSRF-Token": client.cookies.get("qsuite-dev-csrf")}
