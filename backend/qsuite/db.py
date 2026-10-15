"""Transactional SQLite schema and bounded, redacted audit data."""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS migrations(version INTEGER PRIMARY KEY, applied INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('owner','administrator','operator','viewer')),
 enabled INTEGER NOT NULL DEFAULT 1, totp TEXT, totp_pending TEXT, totp_last INTEGER NOT NULL DEFAULT -1,
 created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS recovery(user_id INTEGER NOT NULL REFERENCES users(id),
 code_hash TEXT PRIMARY KEY, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), csrf_hash TEXT NOT NULL,
 created INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires INTEGER NOT NULL,
 fresh_until INTEGER NOT NULL, source TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS session_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS login_limits(bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, reset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user TEXT NOT NULL, source TEXT NOT NULL,
 action TEXT NOT NULL, result TEXT NOT NULL, object TEXT NOT NULL DEFAULT '', incident TEXT);
CREATE INDEX IF NOT EXISTS audit_time ON audit(ts);
CREATE TABLE IF NOT EXISTS jobs(
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, operation TEXT NOT NULL, status TEXT NOT NULL,
 created INTEGER NOT NULL, finished INTEGER, result TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS samples(ts INTEGER PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS terminal_tickets(
 token_hash TEXT PRIMARY KEY, session_hash TEXT NOT NULL, expires INTEGER NOT NULL);
"""

EXPANSION = """
CREATE TABLE roles(name TEXT PRIMARY KEY,label TEXT NOT NULL,permissions TEXT NOT NULL,builtin INTEGER NOT NULL);
CREATE TABLE users_v2(
 id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,
 role TEXT NOT NULL REFERENCES roles(name),enabled INTEGER NOT NULL DEFAULT 1,
 totp TEXT,totp_pending TEXT,totp_last INTEGER NOT NULL DEFAULT -1,created INTEGER NOT NULL,
 must_change INTEGER NOT NULL DEFAULT 0,mfa_required INTEGER NOT NULL DEFAULT 0,
 expires INTEGER,last_login INTEGER);
CREATE TABLE configuration(key TEXT PRIMARY KEY,value TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
CREATE TABLE news_events(
 id TEXT PRIMARY KEY,ts INTEGER NOT NULL,event TEXT NOT NULL,classification TEXT NOT NULL,
 level INTEGER NOT NULL,package TEXT NOT NULL,protocol TEXT NOT NULL,title TEXT NOT NULL,
 message TEXT NOT NULL,incident TEXT,test INTEGER NOT NULL DEFAULT 0);
CREATE INDEX news_time ON news_events(ts);
CREATE TABLE news_routes(event TEXT PRIMARY KEY,member INTEGER NOT NULL,admin INTEGER NOT NULL);
CREATE TABLE news_delivery(
 id TEXT PRIMARY KEY,event_id TEXT NOT NULL REFERENCES news_events(id),channel TEXT NOT NULL,
 state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL,
 delivered INTEGER,error TEXT,UNIQUE(event_id,channel));
CREATE TABLE package_settings(package TEXT PRIMARY KEY,values_json TEXT NOT NULL,revision INTEGER NOT NULL);
"""

SECRET_PATTERNS = [
    (re.compile(r"\$argon2(?:id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"), "[REDACTED password hash]"),
    (
        re.compile(r"https?://(?:discord|discordapp)\.com/api/webhooks/[^\s\"'<>]+", re.I),
        "[REDACTED webhook]",
    ),
    (re.compile(r"\bBearer\s+[\w.~+/=-]+", re.I), "Bearer [REDACTED]"),
    (
        re.compile(
            r"(?i)(\b(?:password|passwd|token|secret|authorization|cookie|api[_-]?key|webhook[_-]?url)\b[\"']?\s*[:=]\s*)([^\r\n,;]+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"-----BEGIN (?:\w+ )?PRIVATE KEY-----.*?-----END (?:\w+ )?PRIVATE KEY-----", re.S),
        "[REDACTED private key]",
    ),
]


def redact(value: str, limit: int = 32768) -> str:
    for pattern, replacement in SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return "".join(c for c in value[:limit] if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)


class Database:
    def __init__(self, path: Path):
        self.path = path

    @contextlib.contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("database cannot be a symlink")
        with self.connect() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            if version > 3:
                raise ValueError("database schema is newer than this application")
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)
            c.execute("INSERT OR IGNORE INTO migrations VALUES(1,?)", (int(time.time()),))
            c.commit()
            if version < 2:
                if version == 1:
                    # Online SQLite backup, never copy a live WAL-backed database file.
                    destination = self.path.with_name(self.path.name + ".v1.rollback")
                    if destination.exists():
                        raise ValueError("unreviewed v1 migration snapshot already exists")
                    self.snapshot(destination)
                self._expand(c)
            if version < 3:
                if version == 2:
                    destination = self.path.with_name(self.path.name + ".v2.rollback")
                    if destination.exists():
                        raise ValueError("unreviewed v2 migration snapshot already exists")
                    self.snapshot(destination)
                c.execute("BEGIN IMMEDIATE")
                for name in ("owner", "admin", "administrator"):
                    row = c.execute("SELECT permissions FROM roles WHERE name=? AND builtin=1", (name,)).fetchone()
                    if row:
                        values = set(json.loads(row[0])) | {"backup.download"}
                        c.execute("UPDATE roles SET permissions=? WHERE name=? AND builtin=1", (json.dumps(sorted(values)), name))
                c.execute("INSERT INTO migrations VALUES(3,?)", (int(time.time()),))
                c.execute("PRAGMA user_version=3")
                c.commit()
        os.chmod(self.path, 0o600)

    def _expand(self, c):
        from .permissions import PRESETS, LEGACY_OPERATIONS

        c.execute("PRAGMA foreign_keys=OFF")
        try:
            c.execute("BEGIN IMMEDIATE")
            for statement in EXPANSION.split(";"):
                if statement.strip():
                    c.execute(statement)
            c.executemany("INSERT INTO roles VALUES(?,?,?,1)", [
                (name, ("Legacy " if name in {"administrator", "operator", "viewer"} else "") + name.replace("_", " ").title(), json.dumps(sorted(values)))
                for name, values in PRESETS.items()
            ])
            c.execute("INSERT INTO users_v2(id,username,password,role,enabled,totp,totp_pending,totp_last,created) SELECT * FROM users")
            c.execute("DROP TABLE users")
            c.execute("ALTER TABLE users_v2 RENAME TO users")
            c.execute("ALTER TABLE sessions ADD COLUMN identifier TEXT")
            for row in c.execute("SELECT token_hash FROM sessions").fetchall():
                c.execute("UPDATE sessions SET identifier=? WHERE token_hash=?", (uuid.uuid4().hex, row[0]))
            c.execute("CREATE UNIQUE INDEX session_identifier ON sessions(identifier)")
            c.execute("ALTER TABLE jobs ADD COLUMN permission TEXT NOT NULL DEFAULT ''")
            c.executemany("UPDATE jobs SET permission=? WHERE operation=?", [(p, o) for o, p in LEGACY_OPERATIONS.items()])
            c.execute("INSERT INTO migrations VALUES(2,?)", (int(time.time()),))
            c.execute("PRAGMA user_version=2")
            if c.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("migration foreign key verification failed")
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.execute("PRAGMA foreign_keys=ON")

    def audit(self, user: str, source: str, action: str, result: str, obj: str = "", incident=None):
        # Objects are identifiers, never request bodies, credentials or terminal output.
        with self.connect() as c:
            c.execute(
                "INSERT INTO audit(ts,user,source,action,result,object,incident) VALUES(?,?,?,?,?,?,?)",
                (
                    int(time.time()),
                    redact(user, 64),
                    redact(source, 64),
                    action[:80],
                    result[:64],
                    redact(obj, 200),
                    incident,
                ),
            )

    def prune(self, audit_days: int, history_days: int):
        now = int(time.time())
        with self.connect() as c:
            c.execute("DELETE FROM sessions WHERE expires<? OR last_seen<?", (now, now - 3600))
            c.execute("DELETE FROM terminal_tickets WHERE expires<?", (now,))
            c.execute("DELETE FROM login_limits WHERE reset<?", (now,))
            c.execute("DELETE FROM audit WHERE ts<?", (now - audit_days * 86400,))
            c.execute(
                "DELETE FROM audit WHERE id < (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 49999)"
            )
            c.execute(
                "DELETE FROM login_limits WHERE bucket NOT IN (SELECT bucket FROM login_limits ORDER BY reset DESC LIMIT 20000)"
            )
            c.execute("DELETE FROM samples WHERE ts<?", (now - history_days * 86400,))
            c.execute(
                "DELETE FROM jobs WHERE status NOT IN ('queued','running') AND created<?", (now - 30 * 86400,)
            )
            c.execute("DELETE FROM news_delivery WHERE event_id IN (SELECT id FROM news_events WHERE ts<?)", (now - audit_days * 86400,))
            c.execute("DELETE FROM news_events WHERE ts<?", (now - audit_days * 86400,))

    def snapshot(self, destination: Path):
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with self.connect() as source, sqlite3.connect(destination) as target:
                source.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("snapshot integrity check failed")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    def rows(self, query: str, params=()):
        with self.connect() as c:
            return [dict(row) for row in c.execute(query, params)]

    def result(self, value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
