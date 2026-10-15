"""Opaque sessions, Argon2id, replay-resistant TOTP and one-use recovery."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
import uuid

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError
from cryptography.fernet import Fernet
import pyotp

from .config import Settings
from .db import Database
from .permissions import resolve

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, type=Type.ID)
DUMMY = HASHER.hash(secrets.token_urlsafe(32))
HASH_SLOTS = threading.BoundedSemaphore(2)
PASSWORD_MIN_LENGTH = 10


class AuthError(Exception):
    pass


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_password(value: str):
    if not PASSWORD_MIN_LENGTH <= len(value) <= 256:
        raise ValueError(f"password must be {PASSWORD_MIN_LENGTH}–256 characters")


def hash_password(value):
    if not HASH_SLOTS.acquire(timeout=0.5):
        raise AuthError("rate limited")
    try:
        return HASHER.hash(value)
    finally:
        HASH_SLOTS.release()


class Auth:
    def __init__(self, db: Database, settings: Settings, key: bytes):
        self.db, self.settings, self.cipher = db, settings, Fernet(key)

    def create_user(self, username: str, password: str, role: str, *, must_change=False, mfa_required=False, expires=None):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,32}", username) or not self.db.rows("SELECT name FROM roles WHERE name=?", (role,)):
            raise ValueError("invalid username or role")
        validate_password(password)
        with self.db.connect() as c:
            c.execute(
                "INSERT INTO users(username,password,role,created,must_change,mfa_required,expires) VALUES(?,?,?,?,?,?,?)",
                (username, hash_password(password), role, int(time.time()), must_change, mfa_required, expires),
            )

    def allow_attempt(self, source: str):
        # Source only, not username: a remote attacker cannot globally lock an owner account.
        now = int(time.time())
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT count,reset FROM login_limits WHERE bucket=?", (source,)).fetchone()
            if row and row["reset"] > now and row["count"] >= 10:
                raise AuthError("rate limited")
            count, reset = (row["count"] + 1, row["reset"]) if row and row["reset"] > now else (1, now + 300)
            c.execute(
                "INSERT INTO login_limits VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET count=?,reset=?",
                (source, count, reset, count, reset),
            )

    def verify(self, username: str, password: str, otp: str | None, source: str):
        self.allow_attempt(source)
        with self.db.connect() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        hashed = row["password"] if row else DUMMY
        if not HASH_SLOTS.acquire(timeout=0.5):
            raise AuthError("rate limited")
        try:
            try:
                valid = HASHER.verify(hashed, password)
            except (VerificationError, InvalidHashError):
                valid = False
        finally:
            HASH_SLOTS.release()
        if not valid or not row or not row["enabled"] or row["expires"] and row["expires"] <= int(time.time()):
            self.db.audit(username, source, "login", "failed")
            raise AuthError("invalid credentials")
        if row["totp"]:
            if not otp or not self._second_factor(dict(row), otp):
                self.db.audit(username, source, "login", "failed")
                raise AuthError("invalid credentials")
        if HASHER.check_needs_rehash(hashed):
            new_hash = hash_password(password)
            with self.db.connect() as c:
                updated = c.execute("UPDATE users SET password=? WHERE id=? AND password=?", (new_hash, row["id"], hashed))
                if updated.rowcount != 1:
                    raise AuthError("credentials changed; sign in again")
            return dict(row) | {"password": new_hash}
        return dict(row)

    def _second_factor(self, user: dict, value: str):
        if len(value) > 128:
            return False
        totp = pyotp.TOTP(self.cipher.decrypt(user["totp"].encode()).decode())
        current = int(time.time()) // 30
        for counter in range(current - 1, current + 2):
            if hmac.compare_digest(totp.at(counter * 30), value):
                with self.db.connect() as c:
                    update = c.execute(
                        "UPDATE users SET totp_last=? WHERE id=? AND totp_last<?",
                        (counter, user["id"], counter),
                    )
                    return update.rowcount == 1
        with self.db.connect() as c:
            update = c.execute(
                "UPDATE recovery SET used=1 WHERE user_id=? AND code_hash=? AND used=0",
                (user["id"], digest(value)),
            )
            return update.rowcount == 1

    def login(self, username: str, password: str, otp: str | None, source: str):
        user = self.verify(username, password, otp, source)
        token, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(32), int(time.time())
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            current = c.execute("SELECT password,enabled,expires FROM users WHERE id=?", (user["id"],)).fetchone()
            if not current or current["password"] != user["password"] or not current["enabled"] or current["expires"] and current["expires"] <= now:
                raise AuthError("credentials changed; sign in again")
            # Bound session count; session ID is never derived from a client-provided cookie.
            c.execute(
                "DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created DESC LIMIT 4)",
                (user["id"], user["id"]),
            )
            c.execute(
                "INSERT INTO sessions(token_hash,user_id,csrf_hash,created,last_seen,expires,fresh_until,source,identifier) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    digest(token),
                    user["id"],
                    digest(csrf),
                    now,
                    now,
                    now + self.settings.session_seconds,
                    now + self.settings.reauth_seconds,
                    source,
                    uuid.uuid4().hex,
                ),
            )
            c.execute("UPDATE users SET last_login=? WHERE id=?", (now, user["id"]))
        self.db.audit(username, source, "login", "success")
        return token, csrf

    def session(self, token: str | None, *, touch=True):
        if not token or len(token) > 128:
            raise AuthError("authentication required")
        return self.session_by_hash(digest(token), touch=touch)

    def session_by_hash(self, token_hash: str, *, touch=False):
        """Internal revalidation for queued work; hashes are never accepted as browser cookies."""
        now = int(time.time())
        with self.db.connect() as c:
            row = c.execute(
                "SELECT s.*,u.username,u.role,u.enabled,u.totp,u.must_change,u.mfa_required,u.expires AS account_expires FROM sessions s JOIN users u ON s.user_id=u.id WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
            if (
                not row
                or not row["enabled"]
                or row["expires"] <= now
                or row["account_expires"] and row["account_expires"] <= now
                or row["last_seen"] + self.settings.idle_seconds <= now
            ):
                raise AuthError("session expired")
            if touch and row["last_seen"] + 30 < now:
                c.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, token_hash))
            result = dict(row)
            result["mfa"] = bool(result.pop("totp"))
            result["permissions"] = sorted(resolve(self.db, result["role"]))
            policy = c.execute("SELECT value FROM configuration WHERE key='auth.privileged-mfa'").fetchone()
            privileged = bool({"services.control", "security.configure", "users.manage", "terminal.open"} & set(result["permissions"]))
            result["mfa_required"] = bool(result["mfa_required"] or policy and policy[0] == "true" and privileged)
            return result

    def password_change(self, actor, current_password, new_password, otp, source):
        validate_password(new_password)
        user = self.verify(actor["username"], current_password, otp, source)
        new_hash = hash_password(new_password)
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            # Prevent a concurrent administrator reset from being overwritten.
            updated = c.execute("UPDATE users SET password=?,must_change=0 WHERE id=? AND password=? AND enabled=1",
                                (new_hash, user["id"], user["password"]))
            if updated.rowcount != 1:
                raise AuthError("credentials changed; sign in again")
            self.revoke_user(c, user["id"])
        self.db.audit(actor["username"], source, "password.change", "success", actor["username"])

    @staticmethod
    def revoke_user(c, identifier):
        c.execute("DELETE FROM terminal_tickets WHERE session_hash IN (SELECT token_hash FROM sessions WHERE user_id=?)", (identifier,))
        c.execute("DELETE FROM sessions WHERE user_id=?", (identifier,))

    def check_csrf(self, session: dict, token: str | None):
        if not token or len(token) > 128 or not hmac.compare_digest(digest(token), session["csrf_hash"]):
            raise AuthError("invalid CSRF token")

    def fresh(self, session: dict):
        if session["fresh_until"] <= int(time.time()):
            raise AuthError("reauthentication required")

    def reauthenticate(self, session: dict, password: str, otp: str | None, source: str):
        self.verify(session["username"], password, otp, source)
        with self.db.connect() as c:
            c.execute(
                "UPDATE sessions SET fresh_until=? WHERE token_hash=?",
                (int(time.time()) + self.settings.reauth_seconds, session["token_hash"]),
            )
        self.db.audit(session["username"], source, "reauthenticate", "success")

    def enroll(self, session: dict):
        self.fresh(session)
        if session["mfa"]:
            raise AuthError("2FA already enabled")
        secret = pyotp.random_base32()
        with self.db.connect() as c:
            c.execute(
                "UPDATE users SET totp_pending=? WHERE id=?",
                (self.cipher.encrypt(secret.encode()).decode(), session["user_id"]),
            )
        return pyotp.TOTP(secret).provisioning_uri(session["username"], issuer_name="QSuite")

    def confirm_enrollment(self, session: dict, otp: str):
        self.fresh(session)
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            user = c.execute(
                "SELECT totp_pending,totp FROM users WHERE id=?", (session["user_id"],)
            ).fetchone()
            if not user or not user["totp_pending"] or user["totp"]:
                raise AuthError("no pending enrollment")
            secret = self.cipher.decrypt(user["totp_pending"].encode()).decode()
            if not pyotp.TOTP(secret).verify(otp, valid_window=0):
                raise AuthError("invalid code")
            codes = [secrets.token_hex(12) for _ in range(10)]
            c.execute(
                "UPDATE users SET totp=totp_pending,totp_pending=NULL,totp_last=? WHERE id=?",
                (int(time.time()) // 30, session["user_id"]),
            )
            c.executemany(
                "INSERT INTO recovery(user_id,code_hash) VALUES(?,?)",
                [(session["user_id"], digest(code)) for code in codes],
            )
            c.execute(
                "DELETE FROM sessions WHERE user_id=? AND token_hash!=?",
                (session["user_id"], session["token_hash"]),
            )
        self.db.audit(session["username"], session["source"], "2fa.enable", "success")
        return codes
