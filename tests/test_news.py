import json

from cryptography.fernet import Fernet
import httpx
import pytest

from qsuite.db import Database
from qsuite.news import EVENTS, NewsStore


@pytest.fixture
def news(tmp_path):
    db = Database(tmp_path / "app.db")
    db.initialize()
    return NewsStore(db, Fernet(Fernet.generate_key()))


@pytest.mark.parametrize(
    "level,target,content,mentions",
    [
        (0, None, "", []),
        (1, None, "", []),
        (2, "123456789012345678", "<@123456789012345678>", []),
        (3, None, "@everyone", ["everyone"]),
        (4, None, "@everyone", ["everyone"]),
        (5, None, "@everyone", ["everyone"]),
    ],
)
def test_exact_central_mention_policy(news, level, target, content, mentions):
    news.configure("admin", policy={"level_2_admin_user_id": target})
    identifier = news.emit(
        "security.event", "Alert @everyone", "<@987654321098765432> @everyone @here", level=level
    )
    row = news.db.rows("SELECT * FROM news_events WHERE id=?", (identifier,))[0]
    payload = news.payload(row, "admin")
    assert payload["content"] == content
    assert payload["allowed_mentions"]["parse"] == mentions
    if level == 2:
        assert payload["allowed_mentions"]["users"] == [target]
    assert "@everyone" not in payload["embeds"][0]["description"]
    if level == 0:
        assert not news.db.rows("SELECT * FROM news_delivery")


def test_snowflake_not_raw_mention_and_separate_secrets(news):
    with pytest.raises(ValueError):
        news.configure("admin", policy={"level_2_admin_user_id": "@everyone"})
    with pytest.raises(ValueError):
        news.configure("member", secret="http://127.0.0.1/admin")  # noqa: S106 -- deliberately invalid non-credential URL
    secret = "https://discord.com/api/webhooks/123456789012345678/" + "fixture-secret-" * 5
    news.configure("admin", secret=secret)
    with pytest.raises(ValueError):
        news.configure("member", secret=secret)
    with pytest.raises(ValueError):
        news.configure("member", secret=secret.replace("/api/", "/api/v10/"))
    assert secret not in json.dumps(news.health("admin"))


@pytest.mark.parametrize(
    "message",
    [
        "SSH login successful",
        "Source 192.0.2.4",
        "Read /etc/ssh/sshd_config",
        "SMART is failing",
        "CVE-2026-12345",
        "User connected from 2001:db8::1",
    ],
)
def test_composer_rejects_recognizable_private_operational_information(news, message):
    with pytest.raises(ValueError):
        news.emit("community.announcement", "Notice", message, package="qwebhook")


@pytest.mark.parametrize("event", [name for name, e in EVENTS.items() if e.classification != "PUBLIC_SAFE"])
def test_hard_classification_survives_corrupted_route_row(news, event):
    with news.db.connect() as c:
        c.execute("UPDATE news_routes SET member=1 WHERE event=?", (event,))
    news.emit(event, "Private", "192.0.2.1 /etc/ssh username", level=3)
    assert news.history("member") == []
    assert not news.db.rows("SELECT * FROM news_delivery WHERE channel='member'")


def test_public_crash_projection_cannot_include_private_diagnostic(news):
    news.set_routes({"minecraft.crash": {"member": True, "admin": True}})
    identifier = news.emit("minecraft.crash", "Secret title", "IP 192.0.2.1 private /srv/path", level=2, package="qmc")
    row = news.db.rows("SELECT * FROM news_events WHERE id=?", (identifier,))[0]
    public = json.dumps(news.payload(row, "member"))
    assert "192.0.2.1" not in public and "/srv/path" not in public and "Secret title" not in public
    assert news.payload(row, "member")["allowed_mentions"]["parse"] == []


def test_discord_outage_preserves_event_and_bounded_retries(news):
    secret = "https://discord.com/api/webhooks/123456789012345678/" + "fixture-secret-" * 5
    news.configure("admin", secret=secret)
    identifier = news.emit("security.event", "Important", "Security remains independent", level=3)

    def unavailable(request):
        raise httpx.ConnectError("private URL " + secret, request=request)

    transport = httpx.MockTransport(unavailable)
    now = news.db.rows("SELECT next_attempt FROM news_delivery")[0]["next_attempt"]
    for _ in range(5):
        news.deliver(transport=transport, now=now)
        state = news.db.rows("SELECT * FROM news_delivery")[0]
        assert secret not in state["error"]
        now = state["next_attempt"]
    assert state["state"] == "failed" and state["attempts"] == 5
    assert news.db.rows("SELECT id FROM news_events")[0]["id"] == identifier
    assert news.health("admin")["health"] == "degraded"


def test_rate_limit_and_success_delivery(news):
    news.configure(
        "admin", secret="https://discord.com/api/webhooks/123456789012345678/" + "fixture-secret-" * 5
    )
    news.emit("security.event", "TEST", "Bounded rate limiting", level=2, test=True)
    transport = httpx.MockTransport(lambda r: httpx.Response(429, headers={"Retry-After": "999999"}))
    now = news.db.rows("SELECT next_attempt FROM news_delivery")[0]["next_attempt"]
    news.deliver(transport=transport, now=now)
    assert news.db.rows("SELECT next_attempt FROM news_delivery")[0]["next_attempt"] == now + 600
    seen = []

    def delivered(request):
        seen.append(json.loads(request.content))
        assert request.url.params.get("wait") == "true"
        return httpx.Response(200, json={"id": "fixture"})

    news.deliver(transport=httpx.MockTransport(delivered), now=now + 600)
    assert "🧪 TEST" in seen[0]["embeds"][0]["title"]
    assert news.db.rows("SELECT state FROM news_delivery")[0]["state"] == "delivered"


def test_foreign_redirect_not_followed(news):
    news.configure(
        "admin", secret="https://discord.com/api/webhooks/123456789012345678/" + "fixture-secret-" * 5
    )
    news.emit("admin.test", "Test", "No SSRF", test=True)
    seen = []

    def redirect(request):
        seen.append(str(request.url.host))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/root"})

    news.deliver(transport=httpx.MockTransport(redirect))
    assert seen == ["discord.com"]


def test_unconfigured_event_later_delivers_and_deduplicates(news):
    news.emit("security.event", "Important", "Retain evidence", identifier="source-1")
    news.emit("security.event", "Important", "Retain evidence", identifier="source-1")
    news.deliver()
    assert news.db.rows("SELECT state FROM news_delivery")[0]["state"] == "unconfigured"
    assert len(news.db.rows("SELECT * FROM news_events")) == 1
    news.configure(
        "admin", secret="https://discord.com/api/webhooks/123456789012345678/" + "fixture-secret-" * 5
    )
    news.deliver(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    assert news.db.rows("SELECT state FROM news_delivery")[0]["state"] == "delivered"


def test_private_package_cannot_relabel_its_events_as_community(news):
    with pytest.raises(ValueError, match="producer"):
        news.emit("community.announcement", "Generic heading", "Private internal account activity", package="qsecurity")
