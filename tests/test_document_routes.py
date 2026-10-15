"""Document routes stay HTML; API errors stay JSON regardless of browser headers."""

import time

import pytest

from .conftest import login

FIREFOX = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "Mozilla/5.0 Firefox/144.0",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Referer": "http://testserver/",
}
LIBREWOLF = {
    **FIREFOX,
    "User-Agent": "Mozilla/5.0 Firefox/144.0 LibreWolf/144.0",
    "Sec-Fetch-Site": "none",
    "DNT": "1",
    "Sec-GPC": "1",
    "Accept-Language": "en-US,en;q=0.5",
    "Upgrade-Insecure-Requests": "1",
}
LIBREWOLF.pop("Referer")


@pytest.mark.parametrize("headers", [FIREFOX, LIBREWOLF, {}, {"Accept": "application/json"}])
def test_direct_login_always_returns_html_without_session(client, headers):
    response = client.get("/login?next=%2Fpanel%2Fdashboard", headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert '<form id="login-form"' in response.text
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert "unsafe-inline" not in response.headers["content-security-policy"]


@pytest.mark.parametrize("cookie_state", ["missing", "invalid", "expired"])
@pytest.mark.parametrize("path", ["/", "/panel/dashboard", "/panel/settings"])
def test_missing_invalid_expired_session_redirects_documents_to_html(client, app, cookie_state, path):
    if cookie_state == "invalid":
        client.cookies.set("qsuite-dev", "invalid-session")
    elif cookie_state == "expired":
        login(client)
        with app.state.db.connect() as db:
            db.execute("UPDATE sessions SET expires=?", (int(time.time()) - 1,))
    redirect = client.get(path, headers=LIBREWOLF, follow_redirects=False)
    assert redirect.status_code == 303
    assert redirect.headers["location"].startswith("/login?next=%")
    response = client.get(path, headers=LIBREWOLF)
    assert len(response.history) == 1
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    direct = client.get("/login", headers=LIBREWOLF)
    assert direct.status_code == 200
    assert direct.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("headers", [FIREFOX, LIBREWOLF])
def test_authenticated_document_reads_ignore_privacy_header_differences(client, headers):
    login(client)
    for path in ["/", "/panel/dashboard", "/login"]:
        result = client.get(path, headers=headers, follow_redirects=False)
        assert result.status_code == 200
        assert result.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("headers", [FIREFOX, LIBREWOLF, {"Accept": "application/json"}])
def test_unauthenticated_api_stays_json_even_for_document_accept(client, headers):
    response = client.get("/api/v1/status", headers=headers)
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/json")
    assert response.history == []


def test_login_document_does_not_bypass_host_or_mutation_origin_validation(client):
    assert client.get("/login", headers={"Host": "evil.example"}).status_code == 400
    assert (
        client.post("/api/v1/auth/login", json={}, headers={"Origin": "https://evil.example"}).status_code
        == 403
    )
    assert client.get("/login?next=https://evil.example").status_code == 200
    assert client.get("/panel/not-a-page").status_code == 404
    assert client.head("/login").status_code == 200
