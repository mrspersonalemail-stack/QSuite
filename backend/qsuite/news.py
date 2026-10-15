"""Classified events and an independent, encrypted, bounded Discord outbox."""

from dataclasses import dataclass
import datetime as dt
import json
import ipaddress
import re
import time
import uuid

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .db import redact
from .notifications import notification

PUBLIC_SAFE, ADMIN_ONLY, SECURITY_SENSITIVE = "PUBLIC_SAFE", "ADMIN_ONLY", "SECURITY_SENSITIVE"
LEVELS = ["NORMAL", "NOTICE", "SUSPICIOUS", "HOSTILE", "CRITICAL", "LOCKDOWN"]
COLORS = [0x45BA87, 0x6EB7FF, 0xF4BF55, 0xF17A47, 0xEC4B65, 0xBD68F5]
PUBLIC_PRODUCERS = frozenset({"qwebhook", "qmc", "qmaintenance", "crafty"})


@dataclass(frozen=True)
class EventType:
    label: str
    classification: str
    member: bool = False
    admin: bool = True
    member_text: str = ""


EVENTS = {
    "community.announcement": EventType("Community announcement", PUBLIC_SAFE, True, False),
    "community.event": EventType("SMP event", PUBLIC_SAFE, True, False),
    "community.update": EventType("Community update", PUBLIC_SAFE, True, False),
    "community.online": EventType("Community reopening", PUBLIC_SAFE, True, False),
    "minecraft.online": EventType(
        "Minecraft online", PUBLIC_SAFE, True, False, "Minecraft is online. See you in game!"
    ),
    "minecraft.planned_stop": EventType(
        "Minecraft planned downtime",
        PUBLIC_SAFE,
        True,
        True,
        "Minecraft is stopping for scheduled maintenance.",
    ),
    "minecraft.planned_restart": EventType(
        "Minecraft planned restart",
        PUBLIC_SAFE,
        True,
        True,
        "Minecraft is restarting for scheduled maintenance.",
    ),
    "minecraft.crash": EventType(
        "Minecraft unavailable",
        PUBLIC_SAFE,
        False,
        True,
        "Minecraft is temporarily unavailable. The team is investigating.",
    ),
    "maintenance.announcement": EventType("Maintenance announcement", PUBLIC_SAFE, True, True),
    "security.event": EventType("QSecurity event", SECURITY_SENSITIVE),
    "ssh.login": EventType("SSH login", SECURITY_SENSITIVE),
    "malware.detection": EventType("Malware detection", SECURITY_SENSITIVE),
    "backup.failure": EventType("Backup failure", ADMIN_ONLY),
    "smart.warning": EventType("Storage warning", ADMIN_ONLY),
    "performance.warning": EventType("Performance threshold exceeded", ADMIN_ONLY),
    "doctor.failure": EventType("Diagnostic failure", ADMIN_ONLY),
    "service.failure": EventType("Service failure", ADMIN_ONLY),
    "configuration.change": EventType("Configuration change", ADMIN_ONLY),
    "qsuite.failure": EventType("QSuite operation failure", ADMIN_ONLY),
    "admin.test": EventType("Admin News test", ADMIN_ONLY),
}


class NewsPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    level_2_admin_user_id: str | None = Field(default=None, pattern=r"^[0-9]{15,22}$")
    l2_mentions_admin: bool = True
    l3_plus_mentions_everyone: bool = True


def webhook_url(value):
    match = (
        re.fullmatch(
            r"https://discord\.com/api/(?:v[0-9]{1,2}/)?webhooks/([0-9]{15,22})/([A-Za-z0-9_-]{30,200})",
            value,
        )
        if isinstance(value, str)
        else None
    )
    if not match:
        raise ValueError("expected an HTTPS Discord webhook URL")
    return "https://discord.com/api/webhooks/" + match[1] + "/" + match[2]


def clean(value, limit=1500):
    # Mentions originate exclusively from the central policy, never message text.
    return re.sub(r"@(?!\u200b)", "@\u200b", redact(value, limit)).replace("<", "‹").replace(">", "›")


def announcement_event(style):
    return {
        "MAINTENANCE": "maintenance.announcement",
        "DOWNTIME": "maintenance.announcement",
        "EVENT": "community.event",
        "UPDATE": "community.update",
        "ONLINE": "community.online",
    }.get(style, "community.announcement")


def validate_public(title, message):
    text = title + "\n" + message
    if re.search(
        r"\b(?:SSH|sudo|qsecurity|fail2ban|malware|quarantine|authorized_keys|CERBERUS|LOCKDOWN|SMART|CVE-[0-9-]+)\b|security incident|audit logs?|authentication fail",
        text,
        re.I,
    ):
        raise ValueError("private operational/security information is not a public announcement")
    if re.search(
        r"(?<![\w:/])/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)+|https?://(?:discord|discordapp)\.com/api/webhooks/",
        text,
    ):
        raise ValueError("paths and webhook credentials cannot be public announcements")
    candidates = re.findall(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?<!\w)(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]+", text
    )
    for value in candidates:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        raise ValueError("IP addresses cannot be public announcements; use the public game hostname")


class NewsStore:
    def __init__(self, db, cipher):
        self.db, self.cipher = db, cipher
        with db.connect() as c:
            c.executemany(
                "INSERT OR IGNORE INTO news_routes VALUES(?,?,?)",
                [(name, int(e.member), int(e.admin)) for name, e in EVENTS.items()],
            )

    def policy(self):
        rows = self.db.rows("SELECT value FROM configuration WHERE key='news.policy'")
        return NewsPolicy.model_validate(json.loads(rows[0]["value"]) if rows else {})

    def configure(self, channel, *, secret=None, policy=None):
        if channel not in {"member", "admin"}:
            raise ValueError("unknown channel")
        if secret is not None:
            secret = webhook_url(secret)
        if policy is not None and channel != "admin":
            raise ValueError("mention policy belongs to Admin News")
        validated = NewsPolicy.model_validate(policy) if policy is not None else None
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if secret is not None:
                other = c.execute(
                    "SELECT value FROM configuration WHERE key=?",
                    ("news.secret." + ("admin" if channel == "member" else "member"),),
                ).fetchone()
                if other and webhook_url(self.cipher.decrypt(other[0].encode()).decode()) == secret:
                    raise ValueError("Member and Admin News require separate webhooks")
                encrypted = self.cipher.encrypt(secret.encode()).decode()
                c.execute(
                    "INSERT INTO configuration VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET value=excluded.value,revision=revision+1",
                    ("news.secret." + channel, encrypted),
                )
                c.execute(
                    "UPDATE news_delivery SET state='queued',next_attempt=? WHERE channel=? AND state='unconfigured'",
                    (int(time.time()), channel),
                )
            if validated:
                c.execute(
                    "INSERT INTO configuration VALUES('news.policy',?,1) ON CONFLICT(key) DO UPDATE SET value=excluded.value,revision=revision+1",
                    (validated.model_dump_json(),),
                )

            if channel == "admin":
                c.execute(
                    "INSERT INTO configuration VALUES('news.watchdog-generation','1',1) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1,revision=revision+1"
                )

    def watchdog_snapshot(self):
        with self.db.connect() as c:
            c.execute("BEGIN")
            secret = c.execute("SELECT value FROM configuration WHERE key='news.secret.admin'").fetchone()
            policy = c.execute("SELECT value FROM configuration WHERE key='news.policy'").fetchone()
            generation = c.execute(
                "SELECT value FROM configuration WHERE key='news.watchdog-generation'"
            ).fetchone()
            return {
                "encrypted_url": secret[0] if secret else None,
                "policy": NewsPolicy.model_validate(json.loads(policy[0]) if policy else {}).model_dump(),
                "generation": int(generation[0]) if generation else 0,
            }

    def secret(self, channel):
        rows = self.db.rows("SELECT value FROM configuration WHERE key=?", ("news.secret." + channel,))
        return self.cipher.decrypt(rows[0]["value"].encode()).decode() if rows else None

    def routes(self):
        rows = self.db.rows("SELECT * FROM news_routes ORDER BY event")
        return [
            r
            | {
                "label": EVENTS[r["event"]].label,
                "classification": EVENTS[r["event"]].classification,
                "member_allowed": EVENTS[r["event"]].classification == PUBLIC_SAFE,
            }
            for r in rows
            if r["event"] in EVENTS
        ]

    def set_routes(self, values):
        if len(values) > len(EVENTS):
            raise ValueError("too many routes")
        for name, route in values.items():
            if (
                name not in EVENTS
                or set(route) != {"member", "admin"}
                or any(type(v) is not bool for v in route.values())
            ):
                raise ValueError("invalid event route")
            if route["member"] and EVENTS[name].classification != PUBLIC_SAFE:
                raise ValueError("private events can never enter Member News")
        with self.db.connect() as c:
            c.executemany(
                "UPDATE news_routes SET member=?,admin=? WHERE event=?",
                [(r["member"], r["admin"], name) for name, r in values.items()],
            )

    def emit(
        self,
        event,
        title,
        message,
        *,
        level=1,
        package="qsuite",
        protocol="",
        incident=None,
        test=False,
        test_channel=None,
        identifier=None,
    ):
        if event not in EVENTS or type(level) is not int or not 0 <= level <= 5:
            raise ValueError("invalid event type or level")
        definition = EVENTS[event]
        if test_channel and (
            not test
            or test_channel not in {"member", "admin"}
            or test_channel == "member"
            and definition.classification != PUBLIC_SAFE
        ):
            raise ValueError("invalid test notification channel")
        if definition.classification == PUBLIC_SAFE and package not in PUBLIC_PRODUCERS:
            raise ValueError("producer is not approved for public announcements")
        if definition.classification == PUBLIC_SAFE and not definition.member_text:
            validate_public(title, message)
        identifier = identifier or uuid.uuid4().hex
        now = int(time.time())
        with self.db.connect() as c:
            inserted = c.execute(
                "INSERT OR IGNORE INTO news_events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    now,
                    event,
                    definition.classification,
                    level,
                    clean(package, 48),
                    clean(protocol, 64),
                    clean(title, 120),
                    clean(message),
                    clean(incident, 64) if incident else None,
                    int(test),
                ),
            )
            if not inserted.rowcount:
                return identifier
            route = c.execute("SELECT member,admin FROM news_routes WHERE event=?", (event,)).fetchone()
            for channel in ("member", "admin"):
                enabled = bool(route[channel])
                if test_channel:
                    enabled = channel == test_channel
                # Enforced at ingress, route update, history projection AND delivery.
                if channel == "member" and definition.classification != PUBLIC_SAFE:
                    enabled = False
                if enabled and (channel == "member" or level > 0):
                    c.execute(
                        "INSERT INTO news_delivery(id,event_id,channel,state,next_attempt) VALUES(?,?,?,'queued',?)",
                        (uuid.uuid4().hex, identifier, channel, now),
                    )
        return identifier

    def history(self, channel, *, level=None, package=None, protocol=None, delivery=None, since=None):
        params, clauses = [channel], ["d.channel=?"]
        if channel == "member":
            clauses.append("e.classification='PUBLIC_SAFE'")
        for column, value in (
            ("e.level", level),
            ("e.package", package),
            ("e.protocol", protocol),
            ("d.state", delivery),
        ):
            if value is not None:
                clauses.append(column + "=?")
                params.append(value)
        if since is not None:
            clauses.append("e.ts>=?")
            params.append(since)
        rows = self.db.rows(
            "SELECT e.*,d.state AS delivery_status,d.attempts,d.delivered,d.error FROM news_events e LEFT JOIN news_delivery d ON e.id=d.event_id WHERE "  # noqa: S608 -- closed local clauses; all user values are bound
            + " AND ".join(clauses)
            + " ORDER BY e.ts DESC,e.rowid DESC LIMIT 100",
            params,
        )
        if channel == "member":
            return [self.member_projection(row) | {"delivery_status": row["delivery_status"]} for row in rows]
        # Include dashboard-only L0 events even though they have no delivery.
        if level in (None, 0) and delivery in (None, "dashboard"):
            zero = self.db.rows(
                "SELECT *,'dashboard' AS delivery_status FROM news_events WHERE level=0 AND classification!='PUBLIC_SAFE' ORDER BY ts DESC LIMIT 30"
            )
            rows.extend(
                r
                for r in zero
                if (not package or r["package"] == package)
                and (not protocol or r["protocol"] == protocol)
                and (not since or r["ts"] >= since)
            )
        return sorted(rows, key=lambda r: r["ts"], reverse=True)[:100]

    @staticmethod
    def member_projection(row):
        definition = EVENTS.get(row["event"])
        if (
            not definition
            or definition.classification != PUBLIC_SAFE
            or row["classification"] != PUBLIC_SAFE
            or row.get("package") not in PUBLIC_PRODUCERS
        ):
            raise ValueError("private event cannot be projected publicly")
        return {
            "id": row["id"],
            "ts": row["ts"],
            "event": row["event"],
            "test": row["test"],
            "title": definition.label if definition.member_text else row["title"],
            "message": definition.member_text or row["message"],
        }

    def payload(self, row, channel):
        if channel == "member":
            public = self.member_projection(row)
            policy = {"content": "", "allowed_mentions": {"parse": [], "users": [], "roles": []}}
            title, text = public["title"], public["message"]
            footer = "Member News · Community announcement"
        else:
            p = self.policy()
            target = p.level_2_admin_user_id if p.l2_mentions_admin else None
            policy = notification(row["level"], target)
            if row["level"] >= 3 and not p.l3_plus_mentions_everyone:
                policy = {"content": "", "allowed_mentions": {"parse": []}}
            title, text = row["title"], row["message"]
            footer = (
                f"Admin News · {row['package']} · {row['protocol']} · Incident {row['incident'] or 'none'}"
            )
        policy.pop("send", None)
        marker = "🧪 TEST · " if row["test"] else ""
        return {
            "username": "QSuite · " + ("Member News" if channel == "member" else "Admin News"),
            **policy,
            "embeds": [
                {
                    "title": marker
                    + ("📣 " if channel == "member" else f"🛡️ L{row['level']} {LEVELS[row['level']]} · ")
                    + clean(title, 120),
                    "description": clean(text),
                    "color": (
                        {
                            "maintenance.announcement": COLORS[2],
                            "community.online": COLORS[0],
                            "community.event": 0xBD68F5,
                        }.get(row["event"], COLORS[1])
                        if channel == "member"
                        else COLORS[row["level"]]
                    ),
                    "timestamp": dt.datetime.fromtimestamp(row["ts"], dt.timezone.utc).isoformat(),
                    "footer": {"text": footer},
                }
            ],
        }

    def health(self, channel):
        configured = bool(
            self.db.rows("SELECT key FROM configuration WHERE key=?", ("news.secret." + channel,))
        )
        latest = self.db.rows(
            "SELECT state,attempts,delivered,error,next_attempt FROM news_delivery WHERE channel=? ORDER BY rowid DESC LIMIT 1",
            (channel,),
        )
        bad = self.db.rows(
            "SELECT count(*) AS n FROM news_delivery WHERE channel=? AND state IN ('retry','failed','unconfigured')",
            (channel,),
        )[0]["n"]
        return {
            "configured": configured,
            "health": "unconfigured" if not configured else "degraded" if bad else "healthy",
            "last_delivery": latest[0] if latest else None,
            "policy": self.policy().model_dump() if channel == "admin" else None,
        }

    def deliver(self, *, transport=None, now=None):
        now = int(time.time()) if now is None else now
        # One bounded worker; crash after send may cause duplicate delivery (at-least-once).
        rows = self.db.rows(
            "SELECT d.id AS delivery_id,d.channel,d.attempts,e.* FROM news_delivery d JOIN news_events e ON e.id=d.event_id WHERE d.state IN ('queued','retry') AND d.next_attempt<=? ORDER BY d.rowid LIMIT 4",
            (now,),
        )
        for row in rows:
            row["attempts"] = max(0, min(5, row["attempts"]))
            state, error, delivered, delay = "retry", None, None, min(600, 15 * 2 ** row["attempts"])
            try:
                url = self.secret(row["channel"])
                payload = self.payload(row, row["channel"])
                if not url:
                    state, error = "unconfigured", "Webhook not configured"
                else:
                    webhook_url(url)
                    with httpx.Client(
                        timeout=8, follow_redirects=False, transport=transport, trust_env=False
                    ) as client:
                        with client.stream("POST", url + "?wait=true", json=payload) as result:
                            status, headers = result.status_code, dict(result.headers)
                    if status in (200, 204):
                        state, delivered = "delivered", now
                    else:
                        error = "Discord HTTP " + str(status)
                        if status == 429:
                            try:
                                delay = max(
                                    delay,
                                    min(600, max(1, int(float(headers.get("retry-after", delay))))),
                                )
                            except (ValueError, OverflowError):
                                pass
                        if 400 <= status < 500 and status != 429:
                            state = "failed"
            except Exception:
                error = "Delivery unavailable"
            attempts = row["attempts"] + 1
            if state == "retry" and attempts >= 5:
                state = "failed"
            with self.db.connect() as c:
                c.execute(
                    "UPDATE news_delivery SET state=?,attempts=?,next_attempt=?,delivered=?,error=? WHERE id=?",
                    (state, attempts, now + delay, delivered, error, row["delivery_id"]),
                )
