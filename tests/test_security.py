import json

import pytest

from qsuite.config import SecurityPolicy
from qsuite.protocols import PROTOCOLS, classify_login, correlate, notification
from qsuite.security import SecurityStore, baseline, ingest_ssh, scan


def test_named_protocols_exist():
    assert len(PROTOCOLS) == 22
    assert PROTOCOLS["CERBERUS"].level == 4
    assert PROTOCOLS["LOCKDOWN"].level == 5


def test_geography_is_not_hostility():
    p = SecurityPolicy(trusted_cidrs=["192.0.2.0/24"], trusted_countries=["RO"], trusted_continents=["EU"])
    assert classify_login("192.0.2.7", "US", "NA", p).name == "HOMEGUARD"
    assert classify_login("8.8.8.8", "RO", "EU", p).level == 0
    assert classify_login("8.8.8.8", "FR", "EU", p).level == 1
    assert classify_login("8.8.8.8", "US", "NA", p).level == 2
    assert "UNKNOWN" in classify_login("8.8.8.8", None, None, p).description
    result = correlate([{"protocol": "EXILE", "source": "8.8.8.8", "session": "known", "attributed": True}])
    assert result["level"] == 2 and not result["containment_eligible"]


def test_unattributed_malware_never_bans_current_admin():
    events = [
        {"protocol": "PLAGUE", "source": None, "attributed": False},
        {"protocol": "EXILE", "source": "8.8.8.8", "session": "admin", "attributed": True},
    ]
    assert not correlate(events)["containment_eligible"]


def test_mixed_attribution_never_bans_wrong_source():
    events = [
        {
            "protocol": "CROWN",
            "source": "8.8.8.8",
            "session": "a",
            "attributed": True,
            "confirmed_hostile": True,
        },
        {
            "protocol": "SABRE",
            "source": "1.1.1.1",
            "session": "b",
            "attributed": True,
            "confirmed_hostile": True,
        },
    ]
    assert not correlate(events)["containment_eligible"]


@pytest.mark.parametrize("level", range(6))
def test_central_mentions(level):
    owner = "123456789012345678"
    result = notification(level, owner)
    assert result["send"] == (level > 0)
    if level <= 1:
        assert result["allowed_mentions"] == {"parse": []}
    elif level == 2:
        assert result["allowed_mentions"] == {"parse": [], "users": [owner]}
    else:
        assert result["allowed_mentions"] == {"parse": ["everyone"]}


def test_security_storage_is_private_and_redacted(settings):
    store = SecurityStore(settings)
    store.initialize()
    event = store.record(
        "EXILE", "token=secret", source="8.8.8.8", evidence={"secret": "hidden", "country": "US"}
    )
    assert store.path.stat().st_mode & 0o777 == 0o600
    data = store.events()
    assert "secret" not in data["events"][0]["summary"]
    assert "hidden" not in json.dumps(data)
    assert event["incident"] is not None
    assert store.summary()["automatic_bans"] is False


def test_unconfigured_webhook_does_not_send(settings, monkeypatch):
    store = SecurityStore(settings)
    store.initialize()
    store.record("CERBERUS", "Test fixture only")
    monkeypatch.setattr("httpx.post", lambda *a, **k: pytest.fail("no webhook configured"))
    store.deliver()
    assert store.summary()["webhook_configured"] is False


def test_ssh_collector_uses_sender_and_reliable_source(settings):
    store = SecurityStore(settings)
    store.initialize()
    entry = {
        "MESSAGE": "Accepted publickey for admin from 8.8.8.8 port 2323 ssh2: ED25519 SHA256:abc123",
        "_PID": "888",
        "_BOOT_ID": "boot",
        "__REALTIME_TIMESTAMP": "123",
    }
    ingest_ssh(store, entry)
    assert not store.events()["events"]
    entry["SYSLOG_IDENTIFIER"] = "sshd-session"
    entry["_UID"] = "0"
    entry["_COMM"] = "sshd-session"
    ingest_ssh(store, entry)
    event = store.events()["events"][0]
    assert event["source"] == "8.8.8.8"
    assert event["username"] == "admin"
    assert event["fingerprint"] == "SHA256:abc123"
    assert event["attributed"] == 1


def test_siege_requires_correlated_failures(settings):
    store = SecurityStore(settings)
    store.initialize()
    entry = {
        "SYSLOG_IDENTIFIER": "sshd",
        "_UID": "0",
        "_COMM": "sshd",
        "MESSAGE": "Failed password for invalid user test from 8.8.8.8 port 1234 ssh2",
    }
    for _ in range(9):
        ingest_ssh(store, entry)
    assert not store.events()["events"]
    ingest_ssh(store, entry)
    assert store.events()["events"][0]["protocol"] == "SIEGE"
    for _ in range(3):
        ingest_ssh(store, entry)
    assert len(store.events()["events"]) == 1


def test_logger_tag_cannot_forge_ssh_attribution(settings):
    store = SecurityStore(settings)
    store.initialize()
    entry = {
        "SYSLOG_IDENTIFIER": "sshd",
        "_UID": "1000",
        "_COMM": "logger",
        "MESSAGE": "Accepted publickey for admin from 8.8.8.8 port 2222",
    }
    ingest_ssh(store, entry)
    assert not store.events()["events"]
    entry["_UID"] = "0"
    ingest_ssh(store, entry)
    assert not store.events()["events"]


def test_integrity_needs_approval_and_deduplicates(settings, tmp_path):
    root = tmp_path / "protected"
    root.mkdir()
    file = root / "test.conf"
    file.write_text("initial")
    settings = settings.model_copy(
        update={"security": settings.security.model_copy(update={"protected_roots": [str(root)]})}
    )
    store = SecurityStore(settings)
    store.initialize()
    assert baseline(settings)["state"] == "baseline approval required"
    assert baseline(settings, True)["approved_files"] == 1
    assert baseline(settings)["state"] == "matches"
    file.write_text("changed")
    assert baseline(settings)["state"] == "changed"
    first = len(store.events()["events"])
    baseline(settings)
    assert len(store.events()["events"]) == first
    assert all(e["attributed"] == 0 for e in store.events()["events"])


def test_missing_scanner_is_degraded(settings, monkeypatch):
    store = SecurityStore(settings)
    store.initialize()
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert scan(settings, "quick")["status"] == "unavailable"
    assert store.events()["events"][0]["protocol"] == "BLINDSPOT"


def test_security_delivery_streams_without_proxy_inheritance(settings, monkeypatch):
    import httpx
    from types import SimpleNamespace

    store = SecurityStore(settings)
    store.initialize()
    store.record("BLINDSPOT", "Isolated delivery fixture")

    class Secret:
        def is_file(self):
            return True

        def is_symlink(self):
            return False

        def stat(self):
            return SimpleNamespace(st_uid=0, st_mode=0o100600)

        def read_text(self):
            return "https://discord.com/api/webhooks/123456789012345678/isolated-fixture-only"

    class UnreadBody(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("response body must not be buffered")

    original = httpx.Client
    options = []

    def client(**kwargs):
        options.append(kwargs)
        return original(**kwargs, transport=httpx.MockTransport(lambda r: httpx.Response(204, stream=UnreadBody())))

    monkeypatch.setattr(store, "webhook_path", lambda: Secret())
    monkeypatch.setattr(httpx, "Client", client)
    store.deliver()
    assert options == [{"timeout": 5, "follow_redirects": False, "trust_env": False}]
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM outbox").fetchone()[0] == 0
