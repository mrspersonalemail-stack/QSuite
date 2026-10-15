import json
import time

from qsuite.auth import HASHER
from qsuite.db import redact
from qsuite.telemetry import history


def test_log_redaction_covers_quoted_json_keys_and_password_hashes():
    hashed = HASHER.hash("fixture-not-live-password-2026")
    text = '{"password":"private password value", "token":"private-token"} ' + hashed
    clean = redact(text)
    assert "private password value" not in clean and "private-token" not in clean and hashed not in clean


def test_performance_permission_does_not_include_host_inventory(app, settings):
    payload = {
        "ts": int(time.time()),
        "cpu_percent": 12,
        "load": [1, 2, 3],
        "memory": {"total": 400, "available": 200},
        "addresses": [{"address": "192.0.2.1"}],
        "hostname": "private-host",
        "minecraft": {"processes": [{"pid": 1234}]},
    }
    with app.state.db.connect() as c:
        c.execute("INSERT INTO samples VALUES(?,?)", (payload["ts"], json.dumps(payload)))
    result = history(settings, 3600)
    assert result["samples"][0]["cpu_pct"] == 12
    assert "192.0.2.1" not in str(result) and "private-host" not in str(result) and "pid" not in str(result)


def test_long_history_fits_broker_and_chart_budget(app, settings):
    now = int(time.time())
    with app.state.db.connect() as c:
        c.executemany(
            "INSERT INTO samples VALUES(?,?)",
            [
                (now - i, json.dumps({"ts": now - i, "cpu_percent": i % 100, "load": [0], "memory": {}}))
                for i in range(8000)
            ],
        )
    result = history(settings, 30000)
    assert result["recorded_samples"] == 8000 and len(result["samples"]) <= 720
    assert len(json.dumps(result).encode()) < 524288
