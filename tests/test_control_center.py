import json
import time

from fastapi.testclient import TestClient
import pytest

from qsuite.packages import inventory
from .conftest import PASSWORD, login


PRIVATE = [
    "status",
    "services",
    "security",
    "security/events",
    "security/protocols",
    "backups",
    "incidents",
    "audit",
    "users",
    "roles",
    "performance/1h",
    "news/admin",
    "news-routing",
    "packages/qsecurity",
    "packages/qbackup",
    "logs/qsecurity",
    "logs/fail2ban",
]


@pytest.mark.parametrize("role", ["mod", "helper", "log_viewer"])
def test_player_presets_deny_private_apis(client, app, role):
    app.state.auth.create_user(role, PASSWORD, role)
    login(client, role)
    # A fake broker traps any forbidden data collection, not just hidden HTML.
    for path in PRIVATE:
        result = client.get("/api/v1/" + path)
        assert result.status_code in {403, 404}, (path, result.text)
        assert "isolated-test-fixture" not in result.text
    assert client.get("/api/v1/settings").json() == {"version": "1.1.0"}


@pytest.mark.parametrize("role", ["owner", "admin", "mod", "helper", "log_viewer"])
def test_role_permissions_return_only_catalogue_not_hashes(client, app, role):
    if role != "owner":
        app.state.auth.create_user(role, PASSWORD, role)
    login(client, role)
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 200
    assert "$argon2" not in response.text and PASSWORD not in response.text
    values = response.json()["permissions"]
    if role in {"mod", "helper", "log_viewer"}:
        assert not {
            "security.view",
            "admin_news.view",
            "terminal.open",
            "users.manage",
            "logs.system.read",
        } & set(values)


def test_custom_role_sessions_and_permissions(client, app):
    headers = login(client)
    body = {
        "name": "senior_mod",
        "label": "Senior Moderator",
        "permissions": ["minecraft.view", "logs.minecraft.read"],
    }
    assert client.put("/api/v1/roles/senior_mod", json=body, headers=headers).status_code == 200
    app.state.auth.create_user("senior", PASSWORD, "senior_mod")
    with TestClient(app) as other:
        login(other, "senior")
        assert other.get("/api/v1/minecraft").status_code == 200
        assert other.get("/api/v1/security").status_code == 403
        assert other.get("/api/v1/log-sources").json()["sources"] == [
            {"id": "minecraft", "label": "Minecraft · player activity", "permission": "logs.minecraft.read"}
        ]
        body["permissions"] = []
        assert client.put("/api/v1/roles/senior_mod", json=body, headers=headers).status_code == 200
        assert other.get("/api/v1/auth/me").status_code == 401


def test_admin_cannot_manage_owner_or_create_escalating_role(client, app):
    app.state.auth.create_user("admin", PASSWORD, "admin")
    h = login(client, "admin")
    owner = app.state.db.rows("SELECT id FROM users WHERE username='owner'")[0]["id"]
    assert (
        client.post(f"/api/v1/users/{owner}/password", json={"password": PASSWORD}, headers=h).status_code
        == 403
    )
    assert client.patch(f"/api/v1/users/{owner}", json={"enabled": False}, headers=h).status_code == 403
    assert (
        client.post(
            "/api/v1/users", json={"username": "escalate", "password": PASSWORD, "role": "owner"}, headers=h
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/api/v1/roles/rootlike",
            json={"name": "rootlike", "label": "Bad", "permissions": ["roles.manage"]},
            headers=h,
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/users", json={"username": "newhelper", "password": PASSWORD, "role": "helper"}, headers=h
        ).status_code
        == 200
    )


def test_builtin_role_cannot_be_replaced(client):
    h = login(client)
    assert (
        client.put(
            "/api/v1/roles/helper",
            json={"name": "helper", "label": "Evil", "permissions": ["security.view"]},
            headers=h,
        ).status_code
        == 409
    )


def test_final_owner_expiration_protected(client, app):
    h = login(client)
    identifier = app.state.db.rows("SELECT id FROM users WHERE username='owner'")[0]["id"]
    assert (
        client.patch(
            f"/api/v1/users/{identifier}", json={"expires": int(time.time()) - 1}, headers=h
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/v1/users/{identifier}", json={"expires": int(time.time()) + 86400}, headers=h
        ).status_code
        == 409
    )


def test_password_reset_requires_change_and_revokes_all_sessions(client, app):
    h = login(client)
    app.state.auth.create_user("member", PASSWORD, "helper")
    identifier = app.state.db.rows("SELECT id FROM users WHERE username='member'")[0]["id"]
    with TestClient(app) as other:
        login(other, "member")
        assert (
            client.post(
                f"/api/v1/users/{identifier}/password",
                json={"password": "a-new-private-password-2026"},
                headers=h,
            ).status_code
            == 200
        )
        assert other.get("/api/v1/auth/me").status_code == 401
        headers = login(other, "member", "a-new-private-password-2026")
        assert other.get("/api/v1/auth/me").json()["must_change"]
        assert other.get("/api/v1/minecraft").status_code == 403
        assert (
            other.post(
                "/api/v1/auth/password",
                json={"current_password": "wrong", "new_password": PASSWORD},
                headers=headers,
            ).status_code
            == 401
        )
        assert (
            other.post(
                "/api/v1/auth/password",
                json={"current_password": "a-new-private-password-2026", "new_password": PASSWORD},
                headers=headers,
            ).status_code
            == 200
        )
        assert other.get("/api/v1/auth/me").status_code == 401
        login(other, "member")
        assert not other.get("/api/v1/auth/me").json()["must_change"]
        assert other.get("/api/v1/minecraft").status_code == 200
    audit = client.get("/api/v1/audit").text
    assert PASSWORD not in audit and "a-new-private-password-2026" not in audit


def test_expired_accounts_cannot_login(client, app):
    app.state.auth.create_user("expired", PASSWORD, "helper", expires=int(time.time()) - 1)
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "expired", "password": PASSWORD},
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 401


def test_privileged_mfa_policy_enforces_setup_without_lockout(client, app):
    h = login(client)
    assert (
        client.put(
            "/api/v1/authentication-policy", json={"require_privileged_mfa": True}, headers=h
        ).status_code
        == 200
    )
    assert client.get("/api/v1/auth/me").json()["mfa_required"]
    assert client.get("/api/v1/status").status_code == 403
    assert client.get("/api/v1/settings").status_code == 200
    assert client.post("/api/v1/auth/totp/enroll", json={}, headers=h).status_code == 200
    app.state.auth.create_user("helper", PASSWORD, "helper")
    login(client, "helper")
    assert not client.get("/api/v1/auth/me").json()["mfa_required"]


def test_individual_session_revocation_is_account_scoped(client, app):
    h = login(client)
    identifier = client.get("/api/v1/auth/sessions").json()["sessions"][0]["identifier"]
    app.state.auth.create_user("helper", PASSWORD, "helper")
    with TestClient(app) as other:
        oh = login(other, "helper")
        assert (
            other.post(f"/api/v1/auth/sessions/{identifier}/revoke", json={}, headers=oh).status_code == 404
        )
    assert client.post(f"/api/v1/auth/sessions/{identifier}/revoke", json={}, headers=h).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_new_validation_errors_never_echo_credentials(client):
    h = login(client)
    secret = "private-value-that-must-not-be-echoed"
    r = client.post(
        "/api/v1/users",
        json={"username": "bad name", "password": secret, "role": "owner", "extra": secret},
        headers=h,
    )
    assert r.status_code == 422 and secret not in r.text


def test_news_classifications_api_and_secret_projection(client, app):
    h = login(client)
    secret = "https://discord.com/api/webhooks/123456789012345678/" + "test-secret-" * 5
    assert (
        client.put("/api/v1/news/admin/configuration", json={"webhook": secret}, headers=h).status_code == 200
    )
    assert (
        client.put(
            "/api/v1/news-routing",
            json={"routes": {"security.event": {"member": True, "admin": True}}},
            headers=h,
        ).status_code
        == 422
    )
    app.state.news.emit(
        "security.event", "SSH alert", "Private source 192.0.2.4 /etc/ssh", level=2, package="qsecurity"
    )
    assert secret not in client.get("/api/v1/news/admin").text
    app.state.auth.create_user("mod", PASSWORD, "mod")
    mh = login(client, "mod")
    assert client.get("/api/v1/news/admin").status_code == 403
    assert "192.0.2.4" not in client.get("/api/v1/news/member").text
    assert (
        client.post(
            "/api/v1/news/member",
            json={"title": "Event", "message": "Let's build!", "evidence": "SSH"},
            headers=mh,
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/news/member",
            json={"title": "Event", "message": "Let's build!", "style": "EVENT"},
            headers=mh,
        ).status_code
        == 200
    )
    assert (
        client.put("/api/v1/news/admin/configuration", json={"webhook": secret}, headers=mh).status_code
        == 403
    )
    assert secret not in json.dumps(app.state.db.rows("SELECT * FROM configuration"))


def test_package_actions_and_settings_require_capability_permissions(settings, tmp_path):
    from cryptography.fernet import Fernet
    from qsuite.api import create_app

    calls = []
    configured = settings.model_copy(update={"services": {"qsecurity": "qsecurity.service"}})

    def broker(s, operation, target="", **kw):
        calls.append((operation, target))
        if operation == "packages.inventory":
            return {"packages": inventory(s)}
        return {"events": [], "configured": False, "operation": operation, "output": ""}

    application = create_app(configured, Fernet.generate_key(), broker=broker)
    for name in ("owner", "mod", "helper"):
        application.state.auth.create_user(name, PASSWORD, name)
    with TestClient(application) as c:
        h = login(c, "mod")
        names = [p["name"] for p in c.get("/api/v1/packages").json()["packages"]]
        assert "qsecurity" not in names
        assert c.get("/api/v1/packages/qsecurity").status_code == 403
        assert c.post("/api/v1/packages/qsecurity/actions/scan_quick", json={}, headers=h).status_code == 403
        calls.clear()
        response = c.get("/api/v1/dashboard")
        assert response.status_code == 200
        assert set(response.json()["widgets"]) == {"minecraft", "crafty", "member_news"}
        assert not {"status", "security.status", "backups", "services"} & {o for o, t in calls}
        h = login(c)
        with application.state.db.connect() as db:
            db.execute("UPDATE sessions SET fresh_until=0")
        assert (
            c.post(
                "/api/v1/packages/qsecurity/configuration/apply", json={"values": {}}, headers=h
            ).status_code
            == 403
        )
        assert c.post("/api/v1/packages/qsecurity/actions/baseline", json={}, headers=h).status_code == 403


def test_control_permission_does_not_grant_private_job_output(client, app):
    h = login(client)
    app.state.auth.create_user("trigger", PASSWORD, "helper")
    assert (
        client.put(
            "/api/v1/roles/trigger",
            json={"name": "trigger", "label": "Trigger", "permissions": ["backup.run"]},
            headers=h,
        ).status_code
        == 200
    )
    identifier = app.state.db.rows("SELECT id FROM users WHERE username='trigger'")[0]["id"]
    assert client.patch(f"/api/v1/users/{identifier}", json={"role": "trigger"}, headers=h).status_code == 200
    login(client, "trigger")
    with app.state.db.connect() as c:
        c.execute(
            "INSERT INTO jobs(id,user_id,operation,status,created,result,permission) VALUES('private-result',?,'backup_validate','succeeded',?,?, 'backup.run')",
            (
                identifier,
                int(time.time()),
                json.dumps({"exit_code": 0, "output": "/srv/private/backup", "secret": "private"}),
            ),
        )
    r = client.get("/api/v1/jobs/private-result")
    assert r.status_code == 200 and "/srv/private" not in r.text and '"secret"' not in r.text


def test_account_setup_blocks_preexisting_terminal_ticket(settings):
    from cryptography.fernet import Fernet
    from qsuite.api import create_app
    from starlette.websockets import WebSocketDisconnect

    app = create_app(
        settings.model_copy(update={"terminal_enabled": True}),
        Fernet.generate_key(),
        broker=lambda *a, **k: {},
    )
    app.state.auth.create_user("owner", PASSWORD, "owner")
    with TestClient(app) as c:
        h = login(c)
        assert c.post("/api/v1/terminal/ticket", json={}, headers=h).status_code == 200
        assert (
            c.put(
                "/api/v1/authentication-policy", json={"require_privileged_mfa": True}, headers=h
            ).status_code
            == 200
        )
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect("/api/v1/terminal", headers={"Origin": "http://testserver"}):
                pass
