import json
from pathlib import Path
from cryptography.fernet import Fernet
import httpx
from qsuite import watchdog_news, watchdog
from qsuite.news import NewsStore
from qsuite.db import Database
from .test_watchdog import prepare


def test_private_watchdog_policy_is_encrypted_and_independent_of_api_database(
    tmp_path, settings, monkeypatch
):
    monkeypatch.setattr(watchdog_news, "check_root_file", lambda p: None)
    secret_dir = Path(settings.secret_dir)
    secret_dir.mkdir()
    key = Fernet.generate_key()
    (secret_dir / "auth-key").write_bytes(key)
    db = Database(tmp_path / "independent.db")
    db.initialize()
    news = NewsStore(db, Fernet(key))
    url = "https://discord.com/api/webhooks/123456789012345678/" + "fixture-secret-" * 5
    news.configure("admin", secret=url)
    snapshot = news.watchdog_snapshot()
    assert url not in json.dumps(snapshot)
    assert watchdog_news.configure(settings, snapshot)["synchronized"]
    assert url not in watchdog_news.location(settings).read_text()
    assert watchdog_news.location(settings).stat().st_mode & 0o777 == 0o600
    db.path.rename(tmp_path / "offline.db")
    assert watchdog_news.channel(settings)[0] == url
    assert watchdog_news.configure(settings, snapshot | {"generation": 0, "encrypted_url": None})[
        "configured"
    ]


def test_cerberus_private_transport_works_without_api_and_uses_mention_policy(
    settings, tmp_path, monkeypatch
):
    from qsuite.news import NewsPolicy

    directory = prepare(settings, tmp_path, monkeypatch, state="inactive", heartbeat=False)
    monkeypatch.setattr(
        watchdog_news,
        "channel",
        lambda s: (
            "https://discord.com/api/webhooks/123456789012345678/" + "fixture-secret-" * 5,
            NewsPolicy(l3_plus_mentions_everyone=False),
        ),
    )
    seen = []

    def delivered(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200)

    client_class = httpx.Client
    monkeypatch.setattr(
        watchdog.httpx, "Client", lambda **kw: client_class(**kw, transport=httpx.MockTransport(delivered))
    )
    result = watchdog.check(settings, state_dir=directory)
    assert result["delivered"]
    assert seen[0]["content"] == "" and seen[0]["allowed_mentions"] == {"parse": []}
    assert "CERBERUS" in seen[0]["embeds"][0]["title"]
