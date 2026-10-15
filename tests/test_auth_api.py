import time

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pyotp
import pytest

from qsuite.api import create_app
from qsuite.auth import digest
from qsuite.config import Settings
from .conftest import login, PASSWORD


def test_no_anonymous_administration(client):
    for path in (
        "status",
        "services",
        "backups",
        "security",
        "security/events",
        "audit",
        "users",
        "settings",
        "incidents",
    ):
        assert client.get("/api/v1/" + path).status_code == 401


def test_login_and_opaque_cookie(client, app):
    headers = login(client)
    raw = client.cookies["qsuite-dev"]
    assert len(raw) >= 40
    assert client.get("/api/v1/auth/me").json()["role"] == "owner"
    with app.state.db.connect() as c:
        row = c.execute("SELECT * FROM sessions").fetchone()
        assert row["token_hash"] == digest(raw)
        assert raw not in str(dict(row))
    assert client.post("/api/v1/auth/logout", json={}, headers=headers).status_code == 200
    assert client.get("/api/v1/status").status_code == 401


def test_login_rotates_existing_session(client):
    login(client)
    before = client.cookies["qsuite-dev"]
    login(client)
    assert client.cookies["qsuite-dev"] != before


def test_password_hash_is_argon2id(app):
    with app.state.db.connect() as c:
        row = c.execute("SELECT password FROM users").fetchone()
        assert row[0].startswith("$argon2id$")
        assert PASSWORD not in row[0]


@pytest.mark.parametrize(
    "body", [{"username": "owner", "password": "bad"}, {"username": "absent", "password": "bad"}]
)
def test_indistinguishable_login_failure(client, body):
    result = client.post("/api/v1/auth/login", json=body, headers={"Origin": "http://testserver"})
    assert result.status_code == 401
    assert result.json() == {"detail": "invalid credentials"}


def test_rate_limit_does_not_lock_account_globally(app):
    for _ in range(10):
        app.state.auth.allow_attempt("source-one")
    with pytest.raises(Exception, match="rate limited"):
        app.state.auth.allow_attempt("source-one")
    app.state.auth.allow_attempt("source-two")
    with app.state.db.connect() as c:
        assert c.execute("SELECT enabled FROM users WHERE username='owner'").fetchone()[0] == 1


def test_idle_expiry(client, app):
    login(client)
    with app.state.db.connect() as c:
        c.execute("UPDATE sessions SET last_seen=?", (int(time.time()) - 2000,))
    assert client.get("/api/v1/status").status_code == 401


def test_absolute_expiry(client, app):
    login(client)
    with app.state.db.connect() as c:
        c.execute("UPDATE sessions SET expires=?", (int(time.time()) - 1,))
    assert client.get("/api/v1/status").status_code == 401


def test_csrf_and_origin_required(client):
    headers = login(client)
    assert (
        client.post("/api/v1/maintenance/on", json={}, headers={"Origin": "http://testserver"}).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/maintenance/on", json={}, headers={**headers, "Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/maintenance/on", json={}, headers={**headers, "X-CSRF-Token": "incorrect"}
        ).status_code
        == 403
    )


def test_host_and_proxy_headers(client):
    login(client)
    assert client.get("/api/v1/status", headers={"Host": "evil.example"}).status_code == 400
    result = client.get(
        "/api/v1/status", headers={"X-Forwarded-Host": "evil.example", "X-Forwarded-For": "127.0.0.1"}
    )
    assert result.status_code == 200


def test_viewer_cannot_mutate_or_open_terminal(client, app):
    app.state.auth.create_user("viewer", PASSWORD, "viewer")
    headers = login(client, "viewer")
    for path in (
        "maintenance/on",
        "backups/validate",
        "services/restart",
        "security/scan",
        "terminal/ticket",
    ):
        assert client.post("/api/v1/" + path, json={}, headers=headers).status_code == 403
    assert client.get("/api/v1/users").status_code == 403
    assert client.get("/api/v1/status").status_code == 200


def test_operator_cannot_manage_users(client, app):
    app.state.auth.create_user("operator", PASSWORD, "operator")
    headers = login(client, "operator")
    assert (
        client.post(
            "/api/v1/users", json={"username": "new", "password": PASSWORD, "role": "owner"}, headers=headers
        ).status_code
        == 403
    )


def test_stale_reauthentication_rejected(client, app):
    headers = login(client)
    with app.state.db.connect() as c:
        c.execute("UPDATE sessions SET fresh_until=0")
    assert client.post("/api/v1/restore/verify", json={}, headers=headers).status_code == 403
    assert (
        client.post("/api/v1/auth/reauthenticate", json={"password": PASSWORD}, headers=headers).status_code
        == 200
    )
    assert client.post("/api/v1/restore/verify", json={}, headers=headers).status_code == 202


def test_totp_enrollment_replay_and_recovery(client, app):
    headers = login(client)
    result = client.post("/api/v1/auth/totp/enroll", json={}, headers=headers)
    assert result.status_code == 200
    uri = result.json()["uri"]
    totp = pyotp.parse_uri(uri)
    result = client.post("/api/v1/auth/totp/confirm", json={"otp": totp.now()}, headers=headers)
    assert result.status_code == 200
    codes = result.json()["recovery_codes"]
    assert len(codes) == 10
    with app.state.db.connect() as c:
        stored = c.execute("SELECT totp FROM users").fetchone()[0]
        assert totp.secret not in stored
        assert codes[0] not in str(c.execute("SELECT * FROM recovery").fetchall())
    # Current code was consumed by enrollment. A replay cannot create a new login.
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "owner", "password": PASSWORD, "otp": totp.now()},
            headers={"Origin": "http://testserver"},
        ).status_code
        == 401
    )
    login(client, otp=codes[0])
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "owner", "password": PASSWORD, "otp": codes[0]},
            headers={"Origin": "http://testserver"},
        ).status_code
        == 401
    )


def test_last_owner_protected(client, app):
    headers = login(client)
    user = client.get("/api/v1/users").json()["users"][0]
    assert (
        client.patch(f"/api/v1/users/{user['id']}", json={"enabled": False}, headers=headers).status_code
        == 409
    )
    assert (
        client.patch(f"/api/v1/users/{user['id']}", json={"role": "viewer"}, headers=headers).status_code
        == 409
    )


def test_account_change_revokes_sessions(client, app):
    headers = login(client)
    app.state.auth.create_user("second", PASSWORD, "viewer")
    with TestClient(app) as other:
        login(other, "second")
        second = [u for u in client.get("/api/v1/users").json()["users"] if u["username"] == "second"][0]
        assert (
            client.patch(
                f"/api/v1/users/{second['id']}", json={"enabled": False}, headers=headers
            ).status_code
            == 200
        )
        assert other.get("/api/v1/status").status_code == 401


def test_audit_never_contains_authentication_secrets(client, app):
    login(client)
    audit = client.get("/api/v1/audit").text
    assert PASSWORD not in audit
    assert client.cookies["qsuite-dev"] not in audit
    assert client.cookies["qsuite-dev-csrf"] not in audit


def test_production_secure_cookie_and_headers(tmp_path):
    settings = Settings(origin="https://testserver", data_dir=str(tmp_path / "production"))
    app = create_app(settings, Fernet.generate_key())
    app.state.auth.create_user("owner", PASSWORD, "owner")
    with TestClient(app, base_url="https://testserver") as client:
        r = client.post(
            "/api/v1/auth/login",
            json={"username": "owner", "password": PASSWORD},
            headers={"Origin": "https://testserver"},
        )
        assert r.status_code == 200
        cookies = r.headers.get_list("set-cookie")
        assert all("Secure" in c and "SameSite=strict" in c and "Path=/" in c for c in cookies)
        assert "HttpOnly" in cookies[0]
        assert "__Host-qsuite=" in cookies[0]
        assert r.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert "strict-transport-security" in r.headers
        assert client.get("/openapi.json").status_code == 404


def test_production_rejects_plaintext_http(tmp_path):
    app = create_app(
        Settings(data_dir=str(tmp_path / "prod"), origin="https://testserver"), Fernet.generate_key()
    )
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 400


def test_body_limits_and_extra_fields(client):
    h = login(client)
    assert client.post("/api/v1/maintenance/on", json={"command": "rm -rf /"}, headers=h).status_code == 422
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "x", "password": "x" * 9000}, headers=h
        ).status_code
        == 413
    )


def test_no_arbitrary_execution_endpoint(client):
    login(client)
    assert (
        client.post(
            "/execute", json={"command": "whoami"}, headers={"Origin": "http://testserver"}
        ).status_code
        == 404
    )
