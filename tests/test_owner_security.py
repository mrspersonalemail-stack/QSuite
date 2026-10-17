import json

import pytest

from qsuite.permissions import ADMIN_ONLY, OWNER_ONLY, permitted
from .conftest import PASSWORD, login


@pytest.mark.parametrize("role", ["admin", "administrator", "operator", "viewer", "mod", "helper", "log_viewer", "custom"])
def test_security_cannot_be_granted_to_non_owner_even_in_saved_roles(client, app, role):
    with app.state.db.connect() as c:
        if role == "custom":
            c.execute("INSERT INTO roles VALUES(?,?,?,0)", (role, role, "[]"))
        # Simulate pre-1.1.0 or malicious grants; the request boundary must clamp them.
        c.execute("UPDATE roles SET permissions=? WHERE name=?", (json.dumps(sorted(OWNER_ONLY | ADMIN_ONLY | {"packages.view"})), role))
    app.state.auth.create_user("restricted", PASSWORD, role)
    login(client, "restricted")
    me = client.get("/api/v1/auth/me").json()
    assert not OWNER_ONLY & set(me["permissions"])
    for path in ["security", "security/events", "security/protocols", "security/network-protection", "packages/qsecurity", "packages/qsecurity/configuration", "logs/qsecurity"]:
        assert client.get("/api/v1/" + path).status_code in {403, 404}, path
    expected = 200 if role in {"admin", "administrator"} else 403
    for path in ["incidents", "news/admin"]:
        assert client.get("/api/v1/" + path).status_code == expected
    widgets = client.get("/api/v1/dashboard").json()["widgets"]
    assert "security" not in widgets
    assert ("admin_news" in widgets) == (expected == 200)
    assert ("incidents" in widgets) == (expected == 200)


def test_owner_keeps_security_and_administrative_pages(client):
    login(client)
    for path in ["security", "security/network-protection", "incidents", "news/admin", "packages/qsecurity"]:
        assert client.get("/api/v1/" + path).status_code == 200


@pytest.mark.parametrize("permission", ["security.view", "security.configure", "logs.security.read", "incident.view", "admin_news.view"])
def test_reserved_role_grants_cannot_be_added_to_custom_role(client, permission):
    headers = login(client)
    response = client.put("/api/v1/roles/custom", headers=headers,
                          json={"name": "custom", "label": "Custom", "permissions": [permission]})
    assert response.status_code == 422
    assert permission not in client.get("/api/v1/roles").json()["catalogue"]


def test_permitted_clamps_forged_cached_actor_permissions():
    assert not permitted({"role": "admin", "permissions": ["security.view"]}, "security.read")
    assert permitted({"role": "owner", "permissions": ["security.view"]}, "security.read")
