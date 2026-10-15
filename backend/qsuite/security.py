"""Independent security observation, durable state and load-aware scanning."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import time
import uuid

from .config import Settings, load
from .db import redact
from .protocols import PROTOCOLS, classify_login, correlate, notification

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
 id TEXT PRIMARY KEY,ts INTEGER NOT NULL,protocol TEXT NOT NULL,level INTEGER NOT NULL,
 source TEXT,username TEXT,session TEXT,fingerprint TEXT,attributed INTEGER NOT NULL DEFAULT 0,
 confirmed_hostile INTEGER NOT NULL DEFAULT 0,summary TEXT NOT NULL,evidence TEXT NOT NULL,incident TEXT);
CREATE INDEX IF NOT EXISTS event_time ON events(ts);
CREATE INDEX IF NOT EXISTS event_session ON events(session,ts);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,ts INTEGER NOT NULL,level INTEGER NOT NULL,
 protocol TEXT NOT NULL,summary TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open');
CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,ts INTEGER NOT NULL,kind TEXT NOT NULL,
 status TEXT NOT NULL,detections INTEGER NOT NULL DEFAULT 0,summary TEXT);
CREATE TABLE IF NOT EXISTS baseline(path TEXT PRIMARY KEY,sha256 TEXT NOT NULL,mode INTEGER NOT NULL,uid INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,level INTEGER NOT NULL,payload TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS risk(session TEXT PRIMARY KEY,updated INTEGER NOT NULL,score INTEGER NOT NULL,
 level INTEGER NOT NULL,containment_eligible INTEGER NOT NULL,source TEXT);
"""


class SecurityStore:
    def __init__(self, settings: Settings):
        self.settings, self.path = settings, settings.security_database

    @contextlib.contextmanager
    def connect(self, read_only=False):
        c = sqlite3.connect(f"file:{self.path}?mode=ro" if read_only else self.path, uri=read_only, timeout=5)
        c.row_factory = sqlite3.Row
        if not read_only:
            c.execute("PRAGMA synchronous=FULL")
        try:
            yield c
            if not read_only:
                c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("security database cannot be a symlink")
        with self.connect() as c:
            if c.execute("PRAGMA user_version").fetchone()[0] > 1:
                raise ValueError("unsupported security schema")
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)
            c.execute("PRAGMA user_version=1")
        os.chmod(self.path, 0o600)

    def get(self, key, default=None):
        with self.connect() as c:
            row = c.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.connect() as c:
            c.execute(
                "INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )

    def record(
        self,
        protocol: str,
        summary: str,
        *,
        source=None,
        username=None,
        session=None,
        fingerprint=None,
        attributed=False,
        confirmed_hostile=False,
        evidence=None,
        level=None,
    ):
        if protocol not in PROTOCOLS:
            raise ValueError("unknown protocol")
        if source:
            source = str(ipaddress.ip_address(source))
        now, identifier = int(time.time()), uuid.uuid4().hex
        level = PROTOCOLS[protocol].level if level is None else level
        if not 0 <= level <= 5:
            raise ValueError("invalid severity")
        clean_summary = redact(summary, 1000)
        # Structured evidence uses a small explicit vocabulary. Never attach journal bodies or arbitrary fields.
        allowed = {
            "country",
            "continent",
            "lookup",
            "path",
            "sha256",
            "scanner",
            "detection",
            "pid",
            "source_port",
            "failures",
            "condition",
        }
        safe_evidence = {k: redact(str(v), 256) for k, v in (evidence or {}).items() if k in allowed}
        incident = uuid.uuid4().hex if level >= 2 else None
        with self.connect() as c:
            c.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    now,
                    protocol,
                    level,
                    source,
                    username,
                    session,
                    fingerprint,
                    int(attributed),
                    int(confirmed_hostile),
                    clean_summary,
                    json.dumps(safe_evidence),
                    incident,
                ),
            )
            if incident:
                c.execute(
                    "INSERT INTO incidents(id,ts,level,protocol,summary) VALUES(?,?,?,?,?)",
                    (incident, now, level, protocol, clean_summary),
                )
            if session:
                related = [
                    dict(row)
                    for row in c.execute(
                        "SELECT protocol,source,session,attributed,confirmed_hostile FROM events WHERE session=? AND ts>=?",
                        (session, now - 900),
                    )
                ]
                risk = correlate(related, self.settings.security.risk_weights)
                c.execute(
                    "INSERT INTO risk VALUES(?,?,?,?,?,?) ON CONFLICT(session) DO UPDATE SET updated=excluded.updated,score=excluded.score,level=excluded.level,containment_eligible=excluded.containment_eligible,source=excluded.source",
                    (
                        session,
                        now,
                        risk["score"],
                        risk["level"],
                        int(risk["containment_eligible"]),
                        risk["source"],
                    ),
                )
            policy = notification(level, self.settings.security.owner_mention)
            if policy.pop("send"):
                payload = {
                    **policy,
                    "embeds": [
                        {
                            "title": f"QSecurity · {protocol} · L{level}",
                            "description": clean_summary,
                            "color": [0x45BA87, 0x6EB7FF, 0xF4BF55, 0xF17A47, 0xEC4B65, 0xBD68F5][level],
                            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                            "footer": {
                                "text": f"Incident {incident or 'none'} · Evidence, not geography, determines response"
                            },
                        }
                    ],
                }
                c.execute(
                    "INSERT INTO outbox(id,level,payload,next_attempt) VALUES(?,?,?,?)",
                    (identifier, level, json.dumps(payload), now),
                )
        return {"id": identifier, "incident": incident, "level": level}

    def events(self, read_only=False):
        if not self.path.exists():
            return {"events": [], "state": "not installed"}
        with self.connect(read_only) as c:
            rows = c.execute(
                "SELECT id,ts,protocol,level,source,username,session,fingerprint,attributed,summary,evidence,incident FROM events ORDER BY ts DESC,rowid DESC LIMIT 100"
            ).fetchall()
        return {"events": [dict(row) for row in rows]}

    def incidents(self, read_only=False):
        if not self.path.exists():
            return {"incidents": [], "state": "not installed"}
        with self.connect(read_only) as c:
            rows = c.execute("SELECT * FROM incidents ORDER BY ts DESC LIMIT 100").fetchall()
        return {"incidents": [dict(row) for row in rows]}

    def summary(self, read_only=False):
        if not self.path.exists():
            return {
                "state": "not installed",
                "level": None,
                "webhook_configured": False,
                "scanner": "unknown",
            }
        with self.connect(read_only) as c:
            level = (
                c.execute(
                    "SELECT max(level) FROM incidents WHERE status IN ('open','investigating')"
                ).fetchone()[0]
                or 0
            )
            scans = c.execute(
                "SELECT id,ts,kind,status,detections,summary FROM scans ORDER BY ts DESC LIMIT 10"
            ).fetchall()
            count = c.execute("SELECT count(*) FROM baseline").fetchone()[0]
            risk = [dict(row) for row in c.execute("SELECT * FROM risk ORDER BY updated DESC LIMIT 50")]
        return {
            "state": "observing",
            "level": level,
            "enforcement": "disabled",
            "webhook_configured": self.webhook_path().is_file(),
            "scanner": "installed"
            if shutil.which("clamdscan") or shutil.which("clamscan")
            else "unavailable",
            "scans": [dict(r) for r in scans],
            "baseline_files": count,
            "geography": "UNKNOWN: no lookup dataset configured",
            "automatic_bans": False,
            "lockdown_available": False,
            "risk": risk,
        }

    def webhook_path(self):
        return Path(self.settings.secret_dir) / "security-webhook"

    def deliver(self):
        path = self.webhook_path()
        if not path.is_file():
            # Do not accumulate hundreds of unsendable notifications in unconfigured installations.
            with self.connect() as c:
                c.execute("DELETE FROM outbox WHERE next_attempt<?", (int(time.time()) - 86400,))
            return
        metadata = path.stat()
        if path.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError("security webhook must be root-owned 0600")
        url = path.read_text().strip()
        if not re.fullmatch(r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", url):
            raise ValueError("invalid webhook provider URL")
        import httpx

        with self.connect() as c:
            rows = c.execute(
                "SELECT id,payload,attempts FROM outbox WHERE next_attempt<=? ORDER BY next_attempt LIMIT 5",
                (int(time.time()),),
            ).fetchall()
        for row in rows:
            try:
                with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
                    with client.stream("POST", url, json=json.loads(row["payload"])) as response:
                        delivered = response.status_code in {200, 204}
            except httpx.HTTPError:
                delivered = False
            with self.connect() as c:
                if delivered:
                    c.execute("DELETE FROM outbox WHERE id=?", (row["id"],))
                elif row["attempts"] >= 7:
                    c.execute("DELETE FROM outbox WHERE id=?", (row["id"],))
                else:
                    c.execute(
                        "UPDATE outbox SET attempts=attempts+1,next_attempt=? WHERE id=?",
                        (int(time.time()) + min(3600, 30 * 2 ** row["attempts"]), row["id"]),
                    )

    def prune(self):
        now = int(time.time())
        with self.connect() as c:
            c.execute("DELETE FROM events WHERE ts<?", (now - 90 * 86400,))
            c.execute(
                "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY ts DESC LIMIT 20000)"
            )
            c.execute("DELETE FROM scans WHERE ts<?", (now - 90 * 86400,))
            c.execute(
                "DELETE FROM incidents WHERE ts<? AND status IN ('resolved','false_positive')",
                (now - 180 * 86400,),
            )
            c.execute("DELETE FROM outbox WHERE next_attempt<?", (now - 86400,))
            c.execute("DELETE FROM risk WHERE updated<?", (now - 86400,))
            c.execute(
                "DELETE FROM outbox WHERE id NOT IN (SELECT id FROM outbox ORDER BY next_attempt DESC LIMIT 500)"
            )


def baseline(settings: Settings, update=False):
    store, files = SecurityStore(settings), {}
    for value in settings.security.protected_roots:
        root = Path(value)
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else root.rglob("*")
        for path in candidates:
            if len(files) >= 5000:
                raise ValueError("protected baseline exceeds file limit")
            if path.is_symlink() or not path.is_file():
                continue
            info = path.stat()
            if info.st_size > 8 * 1024 * 1024:
                continue
            files[str(path)] = (
                hashlib.sha256(path.read_bytes()).hexdigest(),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
            )
    if update:
        with store.connect() as c:
            c.execute("DELETE FROM baseline")
            c.executemany("INSERT INTO baseline VALUES(?,?,?,?)", [(p, *v) for p, v in files.items()])
        store.record(
            "ALLCLEAR", "Operator approved integrity baseline", evidence={"condition": f"{len(files)} files"}
        )
        store.set("integrity_changes", {})
        return {"approved_files": len(files)}
    with store.connect() as c:
        previous = {
            row["path"]: (row["sha256"], row["mode"], row["uid"])
            for row in c.execute("SELECT * FROM baseline")
        }
    if not previous:
        return {"state": "baseline approval required", "changes": []}
    changes = [p for p in previous.keys() | files.keys() if previous.get(p) != files.get(p)]
    already = store.get("integrity_changes", {})
    current = {}
    for p in changes:
        signature = str(files.get(p, "missing"))
        current[p] = signature
        if already.get(p) != signature:
            name = "ANCHOR" if "/ssh/" in p or "sudoers" in p else "RAVEN" if "/systemd/" in p else "FORGE"
            store.record(
                name,
                "Protected configuration differs from approved baseline; legitimacy unconfirmed",
                evidence={"path": p, "sha256": files.get(p, ("missing",))[0]},
            )
    store.set("integrity_changes", current)
    return {"state": "changed" if changes else "matches", "changes": changes[:100]}


SUCCESS = re.compile(
    r"Accepted (?:publickey|password) for ([a-zA-Z0-9_.-]+) from ([0-9a-fA-F:.]+) port ([0-9]+)(?:.*?(SHA256:[A-Za-z0-9+/]+))?"
)
FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?([a-zA-Z0-9_.-]+) from ([0-9a-fA-F:.]+) port ([0-9]+)"
)


def ingest_ssh(store: SecurityStore, entry: dict):
    message = entry.get("MESSAGE", "")
    # Avoid accepting unrelated application's messages as SSH evidence.
    # SYSLOG_IDENTIFIER alone is forgeable with logger -t. Journald's trusted UID/comm are required.
    if str(entry.get("_UID")) != "0" or entry.get("_COMM") not in {"sshd", "sshd-session"}:
        return
    match = SUCCESS.search(message)
    if match:
        username, source, port, fingerprint = match.groups()
        protocol = classify_login(source, None, None, store.settings.security)
        session = f"ssh:{entry.get('_BOOT_ID', 'unknown')}:{entry.get('_PID', 'unknown')}:{entry.get('__REALTIME_TIMESTAMP', 'unknown')}"
        store.record(
            protocol.name,
            protocol.description,
            source=source,
            username=username,
            fingerprint=fingerprint,
            session=session,
            attributed=True,
            evidence={"lookup": "UNKNOWN", "source_port": port, "pid": entry.get("_PID", "UNKNOWN")},
        )
        return
    match = FAILED.search(message)
    if match:
        username, source, _ = match.groups()
        ipaddress.ip_address(source)
        state = store.get("failures", {})
        now = int(time.time())
        state = {key: item for key, item in state.items() if item["start"] > now - 300}
        value = state.setdefault(source, {"start": now, "count": 0})
        value["count"] += 1
        if value["count"] == 10:
            store.record(
                "SIEGE",
                "Ten authentication failures from one source in five minutes; Fail2ban owns network enforcement",
                source=source,
                evidence={"failures": value["count"]},
            )
        store.set("failures", dict(list(state.items())[-1000:]))


def observe_once(settings: Settings):
    store = SecurityStore(settings)
    cursor = store.get("journal_cursor")
    argv = [
        "/usr/bin/journalctl",
        "-t",
        "sshd",
        "-t",
        "sshd-session",
        "-o",
        "json",
        "--no-pager",
        "-n",
        "1000",
    ]
    argv += ["--after-cursor", cursor] if cursor else ["--since", "5 minutes ago"]
    result = subprocess.run(argv, capture_output=True, timeout=10, check=False)  # noqa: S603
    if result.returncode != 0:
        if not store.get("journal_degraded", False):
            store.record("BLINDSPOT", "SSH journal collection unavailable")
        store.set("journal_degraded", True)
    else:
        store.set("journal_degraded", False)
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
                ingest_ssh(store, entry)
                if entry.get("__CURSOR"):
                    store.set("journal_cursor", entry["__CURSOR"])
            except (ValueError, TypeError):
                continue
    baseline(settings)
    store.set("heartbeat", int(time.time()))
    # A separate atomic file lets the read-only watchdog avoid SQLite WAL side effects.
    heartbeat = Path(settings.security_dir) / "heartbeat.json"
    temporary = heartbeat.with_suffix(".new")
    with temporary.open("w") as handle:
        json.dump({"timestamp": int(time.time())}, handle)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(heartbeat)
    store.deliver()
    store.prune()


def scan(settings: Settings, kind: str):
    if kind not in {"quick", "full"}:
        raise ValueError("invalid scan kind")
    store = SecurityStore(settings)
    scanner = shutil.which("clamdscan") or shutil.which("clamscan")
    if not scanner:
        store.record("BLINDSPOT", "ClamAV unavailable; malware coverage degraded")
        return {"status": "unavailable", "detections": None}
    roots = settings.security.scan_roots
    if not roots:
        return {"status": "not configured", "detections": None}
    if os.getloadavg()[0] > (os.cpu_count() or 1) * 0.75:
        return {"status": "postponed", "reason": "host load above scan budget"}
    lock = Path(settings.security_dir) / "scan.lock"
    with lock.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "already running"}
        identifier, now = uuid.uuid4().hex, int(time.time())
        with store.connect() as c:
            c.execute("INSERT INTO scans(id,ts,kind,status) VALUES(?,?,?,'running')", (identifier, now, kind))
        from .helper import run

        argv = [
            "/usr/bin/nice",
            "-n",
            "19",
            "/usr/bin/ionice",
            "-c",
            "3",
            scanner,
            "--infected",
            "--no-summary",
        ]
        if Path(scanner).name == "clamscan":
            argv += ["--recursive", "--max-filesize=100M", "--max-scansize=400M", "--max-recursion=32"]
        argv += roots
        try:
            result = run(argv, 1800 if kind == "quick" else 7200)
            detections = sum(1 for line in result["output"].splitlines() if line.endswith(" FOUND"))
            status = (
                "detections"
                if result["exit_code"] == 1
                else "clean"
                if result["exit_code"] == 0
                else "failed"
            )
            # Detection output is not sufficient to safely move a racing live file. Preserve file and record evidence.
            # Quarantine requires a separately implemented, tested openat/O_NOFOLLOW workflow.
            if detections:
                store.record(
                    "PLAGUE",
                    "ClamAV detected malware; source preserved pending protected quarantine review",
                    evidence={"scanner": Path(scanner).name, "detection": str(detections)},
                )
            elif status == "failed":
                store.record("BLINDSPOT", "Malware scan failed; coverage incomplete")
            summary = "Detection requires quarantine review" if detections else status
        except Exception:
            status, detections, summary = "failed", 0, "Scan interrupted or unavailable"
        with store.connect() as c:
            c.execute(
                "UPDATE scans SET status=?,detections=?,summary=? WHERE id=?",
                (status, detections, summary, identifier),
            )
        return {"id": identifier, "status": status, "detections": detections, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="QSecurity observation and explicit integrity approval")
    parser.add_argument("--config")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "protocols", "events", "incidents", "observe", "daemon"):
        sub.add_parser(name)
    p = sub.add_parser("baseline")
    p.add_argument("action", choices=["status", "update"])
    p = sub.add_parser("scan")
    p.add_argument("kind", choices=["quick", "full"])
    args = parser.parse_args()
    settings = load(args.config, privileged=os.geteuid() == 0)
    store = SecurityStore(settings)
    if args.command == "protocols":
        from dataclasses import asdict

        result = [asdict(p) for p in PROTOCOLS.values()]
    elif args.command in {"status", "events", "incidents"}:
        result = getattr(store, "summary" if args.command == "status" else args.command)(read_only=True)
    else:
        if os.geteuid() != 0:
            raise SystemExit("observer, scans and baseline approval require root")
        store.initialize()
        if args.command == "baseline":
            result = baseline(settings, args.action == "update")
        elif args.command == "scan":
            result = scan(settings, args.kind)
        elif args.command == "observe":
            observe_once(settings)
            result = {"observed": True}
        else:
            while True:
                try:
                    settings = load(args.config, privileged=True)
                    observe_once(settings)
                except Exception as exc:
                    print(
                        json.dumps(
                            {"component": "qsecurity", "event": "degraded", "error_type": type(exc).__name__}
                        ),
                        flush=True,
                    )
                time.sleep(60)
    print(json.dumps(result, indent=2))
