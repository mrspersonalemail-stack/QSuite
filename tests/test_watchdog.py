import json
from pathlib import Path
from types import SimpleNamespace
import time

from qsuite import watchdog


def prepare(settings, tmp_path, monkeypatch, state="active", enabled="enabled", heartbeat=True):
    directory = tmp_path / "watchdog"
    directory.mkdir()
    code = {"security.py": {"sha256": "approved-test-code", "uid": 0, "mode": 0o644}}
    watchdog.atomic(directory / "baseline.json", code)
    monkeypatch.setattr(watchdog, "fingerprints", lambda: code)
    monkeypatch.setattr(watchdog, "trusted_heartbeat", lambda path: True)
    output = f"ActiveState={state}\nUnitFileState={enabled}\nActiveEnterTimestampMonotonic=1\n"
    monkeypatch.setattr(
        watchdog.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=output, returncode=0)
    )
    if heartbeat:
        Path(settings.security_dir).mkdir(parents=True, exist_ok=True)
        watchdog.atomic(Path(settings.security_dir) / "heartbeat.json", {"timestamp": int(time.time())})
    return directory


def test_watchdog_healthy_with_independent_baseline(settings, tmp_path, monkeypatch):
    directory = prepare(settings, tmp_path, monkeypatch)
    assert watchdog.check(settings, state_dir=directory)["state"] == "healthy"


def test_watchdog_reports_dead_engine_without_its_database(settings, tmp_path, monkeypatch, capsys):
    directory = prepare(settings, tmp_path, monkeypatch, state="inactive", heartbeat=False)
    result = watchdog.check(settings, state_dir=directory)
    assert "inactive" in result["state"]
    assert result["configured"] is False
    assert "CERBERUS" in capsys.readouterr().out


def test_watchdog_detects_stalled_active_engine(settings, tmp_path, monkeypatch):
    directory = prepare(settings, tmp_path, monkeypatch)
    watchdog.atomic(Path(settings.security_dir) / "heartbeat.json", {"timestamp": int(time.time()) - 1000})
    assert "stalled" in watchdog.check(settings, state_dir=directory)["state"]


def test_watchdog_works_without_security_database(settings, tmp_path, monkeypatch):
    directory = prepare(settings, tmp_path, monkeypatch)
    assert not settings.security_database.exists()
    assert watchdog.check(settings, state_dir=directory)["state"] == "healthy"


def test_watchdog_rejects_untrusted_heartbeat(settings, tmp_path, monkeypatch):
    directory = prepare(settings, tmp_path, monkeypatch)
    monkeypatch.setattr(watchdog, "trusted_heartbeat", lambda path: False)
    assert "unreadable" in watchdog.check(settings, state_dir=directory)["state"]


def test_watchdog_missing_heartbeat_is_not_healthy(settings, tmp_path, monkeypatch):
    directory = prepare(settings, tmp_path, monkeypatch, heartbeat=False)
    assert "unreadable" in watchdog.check(settings, state_dir=directory)["state"]


def test_watchdog_detects_code_change(settings, tmp_path, monkeypatch):
    directory = prepare(settings, tmp_path, monkeypatch)
    monkeypatch.setattr(
        watchdog, "fingerprints", lambda: {"security.py": {"sha256": "changed", "uid": 0, "mode": 0o644}}
    )
    assert "differs" in watchdog.check(settings, state_dir=directory)["state"]


def test_watchdog_detects_disabled_engine(settings, tmp_path, monkeypatch):
    directory = prepare(settings, tmp_path, monkeypatch, enabled="disabled")
    assert "disabled" in watchdog.check(settings, state_dir=directory)["state"]


def test_watchdog_deduplicates_unchanged_alert(settings, tmp_path, monkeypatch, capsys):
    directory = prepare(settings, tmp_path, monkeypatch, state="inactive")
    watchdog.check(settings, state_dir=directory)
    capsys.readouterr()
    watchdog.check(settings, state_dir=directory)
    assert capsys.readouterr().out == ""
    saved = json.loads((directory / "state.json").read_text())
    assert saved["condition"].startswith("qsecurity inactive")
