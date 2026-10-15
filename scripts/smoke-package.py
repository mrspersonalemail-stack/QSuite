#!/usr/bin/env python3
"""Run with the built wheel installed in a clean venv, never against production."""

import tempfile

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from qsuite import __version__
from qsuite.api import create_app
from qsuite.config import Settings
from qsuite.packages import inventory


def main():
    with tempfile.TemporaryDirectory(prefix="qsuite-installed-smoke-") as root:
        settings = Settings(mode="development", origin="http://testserver", data_dir=root + "/app", security_dir=root + "/security", secret_dir=root + "/secrets", package_dir=root + "/packages")

        def broker(s, operation, target="", **kwargs):
            if operation == "packages.inventory":
                return {"packages": inventory(s)}
            return {}

        app = create_app(settings, Fernet.generate_key(), broker=broker)
        app.state.auth.create_user("fixture_owner", "test-only-wheel-smoke-passphrase", "owner")
        with TestClient(app) as client:
            assert client.get("/login").headers["content-type"].startswith("text/html")
            assert client.get("/api/v1/status").status_code == 401
            assert client.get("/panel/dashboard", follow_redirects=False).status_code == 303
            assert client.post("/api/v1/auth/login", json={"username": "fixture_owner", "password": "test-only-wheel-smoke-passphrase"}, headers={"Origin": "http://testserver"}).status_code == 200
            assert client.get("/api/v1/settings").json()["version"] == __version__
            assert len(client.get("/api/v1/packages").json()["packages"]) == 13
            assert client.post("/api/v1/auth/logout", json={}, headers={"Origin": "http://testserver"}).status_code == 403
        with app.state.db.connect() as db:
            assert db.execute("PRAGMA user_version").fetchone()[0] == 3
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    print("Installed-wheel HTML/login/CSRF/registry/schema smoke PASS: " + __version__)


if __name__ == "__main__":
    main()
