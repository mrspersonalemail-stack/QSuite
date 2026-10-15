from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from qsuite.config import Settings
from qsuite.db import Database, redact
from qsuite.helper import Broker, OperationError, decode_request, run
from qsuite.permissions import ROLES, permitted
from .conftest import login


@pytest.mark.parametrize(
    "fields",
    [b'{"command":"id"}', b'{"operation":"status","extra":1}', b'{"operation":1}', b"[]", b'"status"'],
)
def test_helper_closed_schema(fields):
    with pytest.raises((OperationError, ValueError)):
        decode_request(fields)


@pytest.mark.parametrize(
    "operation,target",
    [
        ("execute", "id"),
        ("service.restart", "../../ssh"),
        ("service.start", "ssh.service;id"),
        ("history", "365d"),
        ("status", "unexpected"),
        ("restore_verify", "../../etc/shadow"),
        ("terminal.close", "123;id"),
    ],
)
def test_helper_rejects_unlisted_operations(settings, operation, target):
    with pytest.raises(OperationError):
        Broker(settings).execute(operation, target)


def test_no_critical_service_control(settings):
    settings = settings.model_copy(update={"services": {"ssh": "ssh.service"}})
    with pytest.raises(OperationError, match="critical"):
        Broker(settings).execute("service.stop", "ssh")


def test_bounded_process_timeout():
    with pytest.raises(OperationError, match="timed out"):
        run(["/usr/bin/sleep", "5"], timeout=0.1)


def test_bounded_process_output():
    with pytest.raises(OperationError, match="output limit"):
        run(["/usr/bin/yes"], timeout=2)


def test_command_arguments_are_not_shell_evaluated():
    result = run(["/usr/bin/printf", "%s", "$(id); touch /tmp/qsuite-never-created"])
    assert result["output"] == "$(id); touch /tmp/qsuite-never-created"
    assert not Path("/tmp/qsuite-never-created").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"bind": "0.0.0.0"},
        {"mode": "production", "origin": "http://example.test"},
        {"access": "wan"},
        {"services": {"bad": "ssh.service;id"}},
        {"security": {"trusted_cidrs": ["192.0.2.9/24"]}},
        {"terminal_user": "qsuite"},
    ],
)
def test_config_rejects_unsafe_defaults(change):
    with pytest.raises(ValueError):
        Settings.model_validate(change)


def test_public_defaults_do_not_assume_minecraft():
    s = Settings()
    assert s.access == "lan" and s.bind == "127.0.0.1"
    assert s.integration.minecraft_root is None
    assert not s.security.trusted_countries
    assert not s.security.enforce


def test_redaction_and_log_injection():
    raw = "password=secret-value\nAuthorization: Bearer abcdef\nhttps://discord.com/api/webhooks/123/fake-value\n\x1bInjected\x00"
    result = redact(raw)
    for value in ("secret-value", "abcdef", "fake-value", "\x1b", "\x00"):
        assert value not in result


def test_schema_snapshot_and_version_guard(tmp_path):
    db = Database(tmp_path / "state.db")
    db.initialize()
    db.audit("operator", "LOCAL", "test", "success")
    db.snapshot(tmp_path / "copy.db")
    assert Database(tmp_path / "copy.db").rows("SELECT * FROM audit")[0]["action"] == "test"
    with db.connect() as c:
        c.execute("PRAGMA user_version=999")
    with pytest.raises(ValueError, match="newer"):
        db.initialize()


def test_roles_are_monotonic():
    assert ROLES["viewer"] <= ROLES["operator"] <= ROLES["administrator"] <= ROLES["owner"]
    assert not permitted("invented", "terminal.open")
    assert not permitted("operator", "users.manage")


def test_api_service_target_validation(client, app):
    h = login(client)
    assert client.post("/api/v1/services/restart", json={"target": "ssh;id"}, headers=h).status_code == 422


def test_job_owner_visibility(client, app):
    h = login(client)
    result = client.post("/api/v1/backups/validate", json={}, headers=h)
    assert result.status_code == 202
    job = result.json()["job"]
    assert client.get("/api/v1/jobs/" + job).status_code == 200
    app.state.auth.create_user("viewer", "test-only-correct-password-2026", "viewer")
    with TestClient(app) as other:
        login(other, "viewer")
        assert other.get("/api/v1/jobs/" + job).status_code == 404


def test_asset_path_traversal(client):
    assert client.get("/assets/..%2f..%2fetc%2fshadow").status_code in {400, 404}
    assert client.get("/assets/config.toml").status_code == 404
    assert client.get("/assets/app.js").status_code == 200


def test_websocket_origin_and_anonymous_rejection(client):
    from starlette.websockets import WebSocketDisconnect

    for origin in ("http://testserver", "https://evil.example"):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/api/v1/terminal", headers={"Origin": origin}):
                pass


def test_websocket_viewer_rejection(client, app):
    from starlette.websockets import WebSocketDisconnect

    app.state.auth.create_user("viewer", "test-only-correct-password-2026", "viewer")
    login(client, "viewer")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/v1/terminal", headers={"Origin": "http://testserver"}):
            pass
