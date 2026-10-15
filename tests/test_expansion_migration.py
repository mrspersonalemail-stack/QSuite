import json
import sqlite3
import time

import pytest

from qsuite.auth import HASHER, digest
from qsuite.db import Database, SCHEMA


def old_database(path):
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        c.execute(
            "INSERT INTO users(id,username,password,role,created) VALUES(1,'owner',?,'owner',?)",
            (HASHER.hash("old-private-password-2026"), int(time.time())),
        )
        c.execute(
            "INSERT INTO sessions VALUES(?,1,?,?,?,?,?,?)",
            (
                digest("opaque-old-session"),
                digest("old-csrf"),
                int(time.time()),
                int(time.time()),
                int(time.time()) + 3600,
                int(time.time()) + 300,
                "LOCAL",
            ),
        )
        c.execute("PRAGMA user_version=1")


def test_migration_preserves_accounts_sessions_and_verified_v1_snapshot(tmp_path):
    path = tmp_path / "app.db"
    old_database(path)
    with sqlite3.connect(path) as c:
        original = c.execute("SELECT password FROM users").fetchone()[0]
    db = Database(path)
    db.initialize()
    with db.connect() as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == 3
        assert c.execute("PRAGMA foreign_key_check").fetchall() == []
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    user = db.rows("SELECT * FROM users")[0]
    assert user["password"] == original and user["role"] == "owner" and user["enabled"]
    assert len(db.rows("SELECT identifier FROM sessions")[0]["identifier"]) == 32
    with sqlite3.connect(path.with_name(path.name + ".v1.rollback")) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == 1
        assert c.execute("SELECT password FROM users").fetchone()[0] == original
    db.initialize()  # Idempotence does not overwrite the rollback snapshot.
    assert len(db.rows("SELECT * FROM roles WHERE name='owner'")) == 1


def test_failed_migration_rolls_back_whole_transaction(tmp_path, monkeypatch):
    from qsuite import permissions

    path = tmp_path / "app.db"
    old_database(path)
    monkeypatch.setattr(permissions, "PRESETS", {"helper": {"minecraft.view"}})
    with pytest.raises(ValueError, match="foreign key"):
        Database(path).initialize()
    with sqlite3.connect(path) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == 1
        assert c.execute("SELECT username FROM users").fetchone()[0] == "owner"
        assert not c.execute("SELECT name FROM sqlite_master WHERE name='roles'").fetchall()


def test_foreign_key_user_role_and_separate_secret_rows(app):
    with app.state.db.connect() as c:
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("UPDATE users SET role='invented'")
    permissions = json.loads(
        app.state.db.rows("SELECT permissions FROM roles WHERE name='helper'")[0]["permissions"]
    )
    assert "security.view" not in permissions
