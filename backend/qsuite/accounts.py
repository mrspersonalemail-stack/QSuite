"""Account administration extends the existing Auth/session/audit implementation."""

import json
import re
import sqlite3
import time

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .auth import PASSWORD_MIN_LENGTH, hash_password, validate_password
from .permissions import ADMIN_ONLY, CATALOGUE, OWNER_ONLY, resolve


class AccountBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class NewAccount(AccountBody):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{1,32}$")
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=256)
    role: str = Field(min_length=1, max_length=48)
    must_change: bool = True
    mfa_required: bool = False
    expires: int | None = Field(default=None, ge=1)


class AccountChange(AccountBody):
    role: str | None = Field(default=None, min_length=1, max_length=48)
    enabled: bool | None = None
    must_change: bool | None = None
    mfa_required: bool | None = None
    expires: int | None = Field(default=None, ge=1)


class PasswordReset(AccountBody):
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=256)
    must_change: bool = True


class PasswordChange(AccountBody):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=256)
    otp: str | None = Field(default=None, max_length=128)


class RoleBody(AccountBody):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,47}$")
    label: str = Field(min_length=1, max_length=64)
    permissions: list[str] = Field(max_length=64)


class AuthenticationPolicy(AccountBody):
    require_privileged_mfa: bool


USER_FIELDS = (
    "id,username,role,enabled,(totp IS NOT NULL) AS mfa,created,must_change,mfa_required,expires,last_login"
)


def routes(app, db, auth, session, permission, source):
    def grant(actor, role):
        rows = db.rows("SELECT name FROM roles WHERE name=?", (role,))
        if not rows:
            raise HTTPException(422, "unknown role")
        if actor["role"] != "owner" and (
            role == "owner" or not resolve(db, role) <= set(actor["permissions"])
        ):
            raise HTTPException(403, "cannot grant this role")

    def manageable(actor, user):
        if actor["role"] != "owner" and (
            user["role"] == "owner" or not resolve(db, user["role"]) <= set(actor["permissions"])
        ):
            raise HTTPException(403, "account requires Owner management")

    @app.get("/api/v1/users")
    def users(actor=Depends(permission("users.view"))):
        return {"users": db.rows("SELECT " + USER_FIELDS + " FROM users ORDER BY id")}  # noqa: S608 -- static column list, no user input

    @app.post("/api/v1/users")
    def create(body: NewAccount, request: Request, actor=Depends(permission("users.manage", fresh=True))):
        grant(actor, body.role)
        try:
            auth.create_user(
                body.username,
                body.password,
                body.role,
                must_change=body.must_change,
                mfa_required=body.mfa_required,
                expires=body.expires,
            )
        except (ValueError, sqlite3.IntegrityError):
            raise HTTPException(400, "invalid or existing account") from None
        db.audit(actor["username"], source(request), "user.create", "success", body.username)
        return {"created": True}

    @app.patch("/api/v1/users/{identifier}")
    def change(
        identifier: int,
        body: AccountChange,
        request: Request,
        actor=Depends(permission("users.manage", fresh=True)),
    ):
        if body.role:
            grant(actor, body.role)
        with db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            user = c.execute("SELECT * FROM users WHERE id=?", (identifier,)).fetchone()
            if not user:
                raise HTTPException(404, "account not found")
            manageable(actor, user)
            values = dict(user) | body.model_dump(exclude_unset=True)
            if (
                values["role"] is None
                or values["enabled"] is None
                or values["must_change"] is None
                or values["mfa_required"] is None
            ):
                raise HTTPException(422, "account flags cannot be null")
            now = int(time.time())
            active = values["enabled"] and (values["expires"] is None or values["expires"] > now)
            if user["role"] == "owner" and (
                values["role"] != "owner" or not active or values["expires"] is not None
            ):
                others = c.execute(
                    "SELECT count(*) FROM users WHERE role='owner' AND enabled=1 AND id!=? AND expires IS NULL",
                    (identifier,),
                ).fetchone()[0]
                if not others:
                    raise HTTPException(409, "cannot remove the last active owner")
            c.execute(
                "UPDATE users SET role=?,enabled=?,must_change=?,mfa_required=?,expires=? WHERE id=?",
                tuple(values[k] for k in ("role", "enabled", "must_change", "mfa_required", "expires"))
                + (identifier,),
            )
            auth.revoke_user(c, identifier)
        db.audit(actor["username"], source(request), "user.change", "success", user["username"])
        return {"updated": True}

    @app.post("/api/v1/users/{identifier}/password")
    def reset(
        identifier: int,
        body: PasswordReset,
        request: Request,
        actor=Depends(permission("users.manage", fresh=True)),
    ):
        validate_password(body.password)
        hashed = hash_password(body.password)
        with db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            user = c.execute("SELECT username,role FROM users WHERE id=?", (identifier,)).fetchone()
            if not user:
                raise HTTPException(404, "account not found")
            manageable(actor, user)
            c.execute(
                "UPDATE users SET password=?,must_change=? WHERE id=?", (hashed, body.must_change, identifier)
            )
            auth.revoke_user(c, identifier)
        db.audit(actor["username"], source(request), "password.reset", "success", user["username"])
        return {"reset": True, "sessions_revoked": True}

    @app.post("/api/v1/auth/password")
    def password(body: PasswordChange, request: Request, actor=Depends(session)):
        auth.password_change(actor, body.current_password, body.new_password, body.otp, source(request))
        return {"changed": True, "sessions_revoked": True}

    @app.get("/api/v1/roles")
    def roles(actor=Depends(permission("users.view"))):
        rows = db.rows("SELECT * FROM roles ORDER BY builtin DESC,name")
        for row in rows:
            row["permissions"] = sorted(resolve(db, row["name"]) & CATALOGUE)
        return {"roles": rows, "catalogue": sorted(CATALOGUE - OWNER_ONLY - ADMIN_ONLY)}

    @app.put("/api/v1/roles/{name}")
    def put_role(
        name: str, body: RoleBody, request: Request, actor=Depends(permission("roles.manage", fresh=True))
    ):
        if actor["role"] != "owner":
            raise HTTPException(403, "Owner required")
        if (
            name != body.name
            or set(body.permissions) - CATALOGUE
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", name)
        ):
            raise HTTPException(422, "invalid role or permissions")
        with db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            old = c.execute("SELECT builtin FROM roles WHERE name=?", (name,)).fetchone()
            if old and old[0]:
                raise HTTPException(409, "preset roles are immutable; create a custom role")
            if set(body.permissions) & (OWNER_ONLY | ADMIN_ONLY):
                raise HTTPException(422, "QSecurity is Owner-only; incidents and Admin News require an Admin preset")
            c.execute(
                "INSERT INTO roles VALUES(?,?,?,0) ON CONFLICT(name) DO UPDATE SET label=excluded.label,permissions=excluded.permissions",
                (name, body.label, json.dumps(sorted(set(body.permissions)))),
            )
            for row in c.execute("SELECT id FROM users WHERE role=?", (name,)).fetchall():
                auth.revoke_user(c, row[0])
        db.audit(actor["username"], source(request), "role.change", "success", name)
        return {"saved": True}

    @app.get("/api/v1/users/{identifier}/sessions")
    def account_sessions(identifier: int, actor=Depends(permission("users.view"))):
        return {
            "sessions": db.rows(
                "SELECT identifier,created,last_seen,expires,source FROM sessions WHERE user_id=? ORDER BY created DESC",
                (identifier,),
            )
        }

    @app.post("/api/v1/users/{identifier}/sessions/revoke")
    def revoke_all(identifier: int, request: Request, actor=Depends(permission("users.manage", fresh=True))):
        rows = db.rows("SELECT username,role FROM users WHERE id=?", (identifier,))
        if not rows:
            raise HTTPException(404, "account not found")
        manageable(actor, rows[0])
        with db.connect() as c:
            auth.revoke_user(c, identifier)
        db.audit(actor["username"], source(request), "sessions.revoke", "success", rows[0]["username"])
        return {"revoked": True}

    @app.post("/api/v1/auth/sessions/{identifier}/revoke")
    def revoke_one(identifier: str, request: Request, actor=Depends(session)):
        auth.fresh(actor)
        with db.connect() as c:
            row = c.execute(
                "SELECT token_hash FROM sessions WHERE identifier=? AND user_id=?",
                (identifier, actor["user_id"]),
            ).fetchone()
            if not row:
                raise HTTPException(404, "session not found")
            c.execute("DELETE FROM terminal_tickets WHERE session_hash=?", (row[0],))
            c.execute("DELETE FROM sessions WHERE token_hash=?", (row[0],))
        db.audit(actor["username"], source(request), "session.revoke", "success", identifier)
        return {"revoked": True}

    @app.post("/api/v1/users/{user_id}/sessions/{identifier}/revoke")
    def admin_revoke_one(
        user_id: int, identifier: str, request: Request, actor=Depends(permission("users.manage", fresh=True))
    ):
        rows = db.rows("SELECT username,role FROM users WHERE id=?", (user_id,))
        if not rows:
            raise HTTPException(404, "account not found")
        manageable(actor, rows[0])
        with db.connect() as c:
            row = c.execute(
                "SELECT token_hash FROM sessions WHERE identifier=? AND user_id=?", (identifier, user_id)
            ).fetchone()
            if not row:
                raise HTTPException(404, "session not found")
            c.execute("DELETE FROM terminal_tickets WHERE session_hash=?", (row[0],))
            c.execute("DELETE FROM sessions WHERE token_hash=?", (row[0],))
        db.audit(actor["username"], source(request), "session.revoke", "success", rows[0]["username"])
        return {"revoked": True}

    @app.get("/api/v1/users/{identifier}/history")
    def history(identifier: int, actor=Depends(permission("users.view"))):
        rows = db.rows("SELECT username FROM users WHERE id=?", (identifier,))
        if not rows:
            raise HTTPException(404, "account not found")
        return {
            "history": db.rows(
                "SELECT ts,source,action,result FROM audit WHERE user=? AND action IN ('login','logout','reauthenticate') ORDER BY id DESC LIMIT 100",
                (rows[0]["username"],),
            )
        }

    @app.get("/api/v1/authentication-policy")
    def policy(actor=Depends(permission("users.view"))):
        rows = db.rows("SELECT value FROM configuration WHERE key='auth.privileged-mfa'")
        return {"require_privileged_mfa": bool(rows and rows[0]["value"] == "true")}

    @app.put("/api/v1/authentication-policy")
    def set_policy(
        body: AuthenticationPolicy,
        request: Request,
        actor=Depends(permission("qsuite.configure", fresh=True)),
    ):
        if actor["role"] != "owner":
            raise HTTPException(403, "Owner required")
        with db.connect() as c:
            c.execute(
                "INSERT INTO configuration VALUES('auth.privileged-mfa',?,1) ON CONFLICT(key) DO UPDATE SET value=excluded.value,revision=revision+1",
                ("true" if body.require_privileged_mfa else "false",),
            )
        db.audit(actor["username"], source(request), "authentication.policy", "success")
        return body.model_dump()
