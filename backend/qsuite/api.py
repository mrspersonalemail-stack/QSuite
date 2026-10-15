"""Production API, authoritative authorization and authenticated PTY transport."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import termios
import time
from urllib.parse import quote, urlsplit
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
import uvicorn

from . import __version__
from .auth import Auth, AuthError, digest
from .config import Settings, load
from .db import Database
from .helper import OperationError, request as helper_request
from .permissions import permitted
from .news import NewsStore
from .protocols import PROTOCOLS
from .telemetry import status

WEB = Path(__file__).parent / "web"
OPERATIONS = {
    "backups/validate": ("backup_validate", "backups.validate", False),
    "restore/verify": ("restore_verify", "restore.verify", True),
    "incidents/capture": ("incident", "incident.capture", False),
    "maintenance/on": ("maintenance_on", "maintenance.change", False),
    "maintenance/off": ("maintenance_off", "maintenance.change", False),
    "security/scan": ("security.scan", "security.scan", False),
    "security/baseline": ("security.baseline", "security.baseline", True),
    "services/start": ("service.start", "services.operate", True),
    "services/stop": ("service.stop", "services.operate", True),
    "services/restart": ("service.restart", "services.operate", True),
}


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Credentials(Body):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=256)
    otp: str | None = Field(default=None, max_length=128)


class Reauthentication(Body):
    password: str = Field(min_length=1, max_length=256)
    otp: str | None = Field(default=None, max_length=128)


class Code(Body):
    otp: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class Operation(Body):
    target: str = Field(default="", max_length=80)


class NewUser(Credentials):
    role: str = Field(pattern=r"^(owner|administrator|operator|viewer)$")


class UserChange(Body):
    role: str | None = Field(default=None, pattern=r"^(owner|administrator|operator|viewer)$")
    enabled: bool | None = None


def create_app(settings: Settings, key: bytes, *, broker=helper_request, news_transport=None):
    db = Database(settings.database)
    db.initialize()
    auth = Auth(db, settings, key)
    news = NewsStore(db, auth.cipher)
    production = settings.mode == "production"
    cookie = "__Host-qsuite" if production else "qsuite-dev"
    csrf_cookie = "__Host-qsuite-csrf" if production else "qsuite-dev-csrf"
    tasks = set()
    job_slots = asyncio.Semaphore(2)
    request_slots = asyncio.Semaphore(20)

    async def sampler():
        while True:
            interval = settings.sample_seconds
            try:
                dynamic = load() if settings.mode == "production" else settings
                interval = dynamic.sample_seconds
                # Legacy collector remains authoritative on migrated installations.
                if not settings.integration.performance_db:
                    measurement = await run_in_threadpool(status, settings)
                    with db.connect() as c:
                        c.execute(
                            "INSERT OR REPLACE INTO samples VALUES(?,?)",
                            (measurement["ts"], json.dumps(measurement)),
                        )
                db.prune(dynamic.audit_days, dynamic.history_days)
            except (OSError, ValueError, sqlite3.Error):
                pass  # Telemetry failure must not kill management or managed workloads.
            await asyncio.sleep(interval)

    async def news_worker():
        with db.connect() as c:
            c.execute("INSERT OR IGNORE INTO configuration VALUES('news.bridge-start',?,1)", (str(int(time.time())),))
            bridge_start = int(c.execute("SELECT value FROM configuration WHERE key='news.bridge-start'").fetchone()[0])
        previous_game = None
        last_smart = 0
        smart_warning = False
        performance_warning = False
        service_states = {}
        previous_watchdog = None
        while True:
            try:
                result = await read("security.events")
                for event in result.get("events", []):
                    if event.get("ts", 0) < bridge_start:
                        continue
                    kind = "malware.detection" if event.get("protocol") in {"PLAGUE", "OUTBREAK"} else "ssh.login" if event.get("protocol") in {"HOMEGUARD", "FOREIGN", "EUROPA", "EXILE"} else "security.event"
                    news.emit(kind, event["protocol"], event["summary"], level=event["level"], package="qsecurity", protocol=event["protocol"], incident=event.get("incident"), identifier="security-" + event["id"])
                game = await read("minecraft.status")
                online = game.get("online") if game.get("configured") else None
                if previous_game is not None and online is not None and online != previous_game:
                    kind = "minecraft.online" if online else "minecraft.crash"
                    news.emit(kind, "Minecraft online" if online else "Minecraft unavailable", "Game status changed", level=1 if online else 2, package="qmc")
                previous_game = online
                watch = await read("news.watchdog.status")
                assessment = watch.get("assessment") or {}
                condition = assessment.get("condition")
                if condition and condition != "healthy" and condition != previous_watchdog:
                    news.emit("security.event", "CERBERUS", condition, level=4, package="qsecurity", protocol="CERBERUS", identifier="watchdog-" + str(assessment.get("event_id") or assessment.get("updated")))
                previous_watchdog = condition
                services = await read("services")
                for unit in services.get("services", []):
                    name, state = unit["id"], unit.get("ActiveState")
                    before = service_states.get(name)
                    if state == "failed" and before != state or before == "active" and state == "inactive" and name in {"qsuite", "qsecurity", "crafty", "fail2ban", "smart"}:
                        news.emit("service.failure", "Service unavailable", name + " changed to " + state, level=4 if name == "qsecurity" else 3, package=name)
                    service_states[name] = state
                dynamic = load() if settings.mode == "production" else settings
                host = await read("status")
                hot = host.get("cpu_percent", 0) >= dynamic.cpu_warning_percent or host.get("memory", {}).get("percent", 0) >= dynamic.memory_warning_percent
                if hot and not performance_warning:
                    news.emit("performance.warning", "Performance threshold exceeded", "CPU or memory crossed the configured warning threshold", level=1, package="qperf")
                performance_warning = hot
                if int(time.time()) - last_smart >= dynamic.smart_monitor_seconds:
                    smart = await read("smart.status")
                    warning = smart.get("health") == "warning" or (smart.get("temperature") or 0) >= dynamic.smart_temperature_warning or dynamic.smart_failed_tests_warning and smart.get("failed_self_test", False)
                    if warning and not smart_warning:
                        news.emit("smart.warning", "Storage health warning", "SMART health, temperature or self-test crossed the configured warning policy", level=3, package="qsmart")
                    smart_warning = warning
                    last_smart = int(time.time())
            except Exception:
                app.state.news_bridge_health = "degraded"
            else:
                app.state.news_bridge_health = "healthy"
            try:
                await run_in_threadpool(news.deliver, transport=news_transport)
            except Exception:
                app.state.news_delivery_health = "degraded"
            else:
                app.state.news_delivery_health = "healthy"
            await asyncio.sleep(15)

    @asynccontextmanager
    async def lifespan(app):
        with db.connect() as c:
            c.execute(
                "UPDATE jobs SET status='interrupted',finished=?,error='Agent restarted; work was not automatically replayed' WHERE status IN ('queued','running')",
                (int(time.time()),),
            )
        task = asyncio.create_task(sampler())
        news_task = asyncio.create_task(news_worker())
        try:
            yield
        finally:
            task.cancel()
            news_task.cancel()
            for running in list(tasks):
                running.cancel()
            await asyncio.gather(task, news_task, *list(tasks), return_exceptions=True)

    app = FastAPI(
        title="QSuite",
        version=__version__,
        lifespan=lifespan,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )
    app.state.db, app.state.auth, app.state.settings = db, auth, settings
    app.state.cookie, app.state.csrf_cookie = cookie, csrf_cookie
    app.state.news = news
    app.state.require_trusted_tls = settings.require_trusted_tls

    def origin_ok(value):
        return value == settings.origin.rstrip("/")

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        # Do not trust X-Forwarded-* at all. TLS is terminated by this service in production.
        expected = urlsplit(settings.origin).netloc
        if request.headers.get("host", "") != expected:
            return JSONResponse({"detail": "invalid host"}, status_code=400)
        if production and request.url.scheme != "https":
            return JSONResponse({"detail": "HTTPS required"}, status_code=400)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not origin_ok(request.headers.get("origin")):
                return JSONResponse({"detail": "invalid origin"}, status_code=403)
            if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
                return JSONResponse({"detail": "JSON required"}, status_code=415)
        if request.headers.get("content-length"):
            try:
                if int(request.headers["content-length"]) > 8192:
                    return JSONResponse({"detail": "request too large"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "invalid content length"}, status_code=400)
        # Validate streamed bodies too, including chunked requests without Content-Length.
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 8192:
                    return JSONResponse({"detail": "request too large"}, status_code=413)
            request._body = bytes(body)
        async with request_slots:
            response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        if production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic input values may contain submitted passwords/webhook secrets.
        return JSONResponse({"detail": "invalid request fields"}, status_code=422)

    @app.exception_handler(AuthError)
    async def authentication_error(request, exc):
        code = 429 if str(exc) == "rate limited" else 401
        if str(exc) in {
            "invalid CSRF token",
            "reauthentication required",
            "2FA already enabled",
            "no pending enrollment",
            "invalid code",
        }:
            code = 403
        return JSONResponse({"detail": str(exc)}, status_code=code)

    @app.exception_handler(OperationError)
    async def broker_error(request, exc):
        return JSONResponse({"detail": "operation unavailable or rejected"}, status_code=503)

    @app.exception_handler(Exception)
    async def unexpected(request, exc):
        return JSONResponse({"detail": "internal service error"}, status_code=500)

    def source(request: Request):
        return request.client.host if request.client else "UNKNOWN"

    def session(request: Request):
        actor = auth.session(request.cookies.get(cookie))
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            auth.check_csrf(actor, request.headers.get("x-csrf-token"))
        allowed = request.url.path.startswith("/api/v1/auth/") or request.url.path == "/api/v1/settings"
        if not allowed and (actor["must_change"] or actor["mfa_required"] and not actor["mfa"]):
            raise HTTPException(403, "change password or enroll required 2FA in Account settings")
        return actor

    def permission(name: str, fresh=False):
        def check(request: Request, actor=Depends(session)):
            if not permitted(actor, name):
                db.audit(actor["username"], source(request), name, "denied")
                raise HTTPException(403, "permission denied")
            if fresh:
                auth.fresh(actor)
                if settings.access == "wan" and not actor["mfa"]:
                    raise HTTPException(403, "enable 2FA before sensitive WAN operations")
            return actor

        return check

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post("/api/v1/auth/login")
    def login(body: Credentials, request: Request, response: Response):
        token, csrf = auth.login(body.username, body.password, body.otp, source(request))
        response.set_cookie(
            cookie,
            token,
            secure=production,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=settings.session_seconds,
        )
        response.set_cookie(
            csrf_cookie,
            csrf,
            secure=production,
            httponly=False,
            samesite="strict",
            path="/",
            max_age=settings.session_seconds,
        )
        return {"authenticated": True}

    @app.get("/api/v1/auth/me")
    def me(actor=Depends(session)):
        return {
            "username": actor["username"],
            "role": actor["role"],
            "mfa": actor["mfa"],
            "fresh_until": actor["fresh_until"],
            "permissions": actor["permissions"],
            "must_change": bool(actor["must_change"]),
            "mfa_required": bool(actor["mfa_required"]),
        }

    @app.post("/api/v1/auth/logout")
    def logout(request: Request, response: Response, actor=Depends(session)):
        with db.connect() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (actor["token_hash"],))
        db.audit(actor["username"], source(request), "logout", "success")
        for name in (cookie, csrf_cookie):
            response.delete_cookie(
                name, path="/", secure=production, httponly=name == cookie, samesite="strict"
            )
        return {"logged_out": True}

    @app.post("/api/v1/auth/reauthenticate")
    def reauthenticate(body: Reauthentication, request: Request, actor=Depends(session)):
        auth.reauthenticate(actor, body.password, body.otp, source(request))
        return {"fresh_until": int(time.time()) + settings.reauth_seconds}

    @app.post("/api/v1/auth/totp/enroll")
    def enroll(actor=Depends(session)):
        return {"uri": auth.enroll(actor)}

    @app.post("/api/v1/auth/totp/confirm")
    def confirm(body: Code, actor=Depends(session)):
        return {"recovery_codes": auth.confirm_enrollment(actor, body.otp)}

    @app.get("/api/v1/auth/sessions")
    def sessions(actor=Depends(session)):
        return {
            "sessions": db.rows(
                "SELECT identifier,created,last_seen,expires,source FROM sessions WHERE user_id=?", (actor["user_id"],)
            )
        }

    @app.post("/api/v1/auth/sessions/revoke")
    def revoke(request: Request, actor=Depends(session)):
        auth.fresh(actor)
        with db.connect() as c:
            auth.revoke_user(c, actor["user_id"])
        db.audit(actor["username"], source(request), "sessions.revoke", "success")
        return {"revoked": True}

    async def read(operation, target=""):
        try:
            return await run_in_threadpool(broker, settings, operation, target)
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise OperationError("helper unavailable") from exc

    @app.get("/api/v1/status")
    async def system_status(actor=Depends(permission("status.read"))):
        return await read("status")

    @app.get("/api/v1/services")
    async def services(actor=Depends(permission("services.view"))):
        return await read("services")

    @app.get("/api/v1/logs/{target}")
    async def logs(target: str, request: Request, actor=Depends(session)):
        if target == "minecraft":
            permission("logs.minecraft.read")(request, actor)
            return await read("minecraft.logs")
        units = settings.services | ({"crafty": settings.integration.crafty_unit} if settings.integration.crafty_unit else {})
        unit = units.get(target)
        if not unit:
            raise HTTPException(404, "log source not found")
        required = "logs.crafty.read" if target == "crafty" else "logs.security.read" if unit in {"qsecurity.service", "fail2ban.service", "ssh.service", "sshd.service"} else "logs.system.read"
        permission(required)(request, actor)
        return await read("logs", target)

    @app.get("/api/v1/performance/{window}")
    async def performance(window: str, actor=Depends(permission("perf.read"))):
        return await read("history", window)

    @app.get("/api/v1/backups")
    async def backup_list(actor=Depends(permission("backups.read"))):
        return await read("backups") | {"download_requires_mfa": settings.access == "wan"}

    from .downloads import routes as download_routes

    download_routes(app, db, auth, permission, source, settings, broker)

    @app.get("/api/v1/security")
    async def security_status(actor=Depends(permission("security.read"))):
        return await read("security.status")

    @app.get("/api/v1/security/protocols")
    def protocols(actor=Depends(permission("security.read"))):
        return {"protocols": [asdict(p) for p in PROTOCOLS.values()]}

    @app.get("/api/v1/security/events")
    async def events(actor=Depends(permission("security.read"))):
        return await read("security.events")

    @app.get("/api/v1/incidents")
    async def incidents(actor=Depends(permission("incidents.read"))):
        return await read("security.incidents")

    @app.get("/api/v1/audit")
    def audit(actor=Depends(permission("audit.read"))):
        return {"audit": db.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 100")}

    @app.get("/api/v1/settings")
    def public_settings(actor=Depends(session)):
        if not permitted(actor, "system.view") and not permitted(actor, "qsuite.configure"):
            return {"version": __version__}
        return {
            "access": settings.access,
            "origin": settings.origin,
            "mode": settings.mode,
            "terminal_enabled": settings.terminal_enabled,
            "version": __version__,
            "require_trusted_tls": app.state.require_trusted_tls,
            "capabilities": {
                "backup_creation": False,
                "production_restore": False,
                "root_terminal": False,
                "automatic_bans": False,
                "lockdown": False,
                "access_change": "local CLI only",
            },
        }

    @app.post("/api/v1/access/tls-policy")
    async def tls_policy(
        body: Operation, request: Request, actor=Depends(permission("access.change", fresh=True))
    ):
        if actor["role"] != "owner":
            raise HTTPException(403, "Owner required")
        if body.target not in {"required", "optional"}:
            raise HTTPException(422, "TLS policy must be required or optional")
        result = await read("access.trust", body.target)
        app.state.require_trusted_tls = result["require_trusted_tls"]
        db.audit(actor["username"], source(request), "access.tls-policy", "success", body.target)
        return result

    async def execute_job(identifier, operation, target, actor, address, fresh=False):
        try:
            async with job_slots:
                with db.connect() as c:
                    c.execute("UPDATE jobs SET status='running' WHERE id=?", (identifier,))
                live = auth.session_by_hash(actor["token_hash"])
                required = db.rows("SELECT permission FROM jobs WHERE id=?", (identifier,))[0]["permission"]
                if live["must_change"] or live["mfa_required"] and not live["mfa"] or not permitted(live, required):
                    raise AuthError("authorization revoked before execution")
                if fresh:
                    auth.fresh(live)
                    if settings.access == "wan" and not live["mfa"]:
                        raise AuthError("2FA required")
                result = await read(operation, target)
                if required == "crafty.control" and not permitted(actor, "system.view"):
                    result = {k: result[k] for k in ("exit_code", "observed", "verified") if k in result}
                ok = (
                    result.get("exit_code", 0) == 0
                    and result.get("verified", True)
                    and result.get("status") not in {"failed", "unavailable"}
                )
                with db.connect() as c:
                    c.execute(
                        "UPDATE jobs SET status=?,finished=?,result=? WHERE id=?",
                        ("succeeded" if ok else "failed", int(time.time()), json.dumps(result), identifier),
                    )
                db.audit(actor["username"], address, operation, "success" if ok else "failed", target)
                try:
                    if ok and operation in {"maintenance_on", "maintenance_off"}:
                        dynamic = load() if settings.mode == "production" else settings
                        message = dynamic.maintenance_message if operation == "maintenance_on" else "Maintenance has ended. Check the game status before joining."
                        news.emit("maintenance.announcement", "Maintenance update", message, package="qmaintenance")
                    if not ok:
                        event = "backup.failure" if operation == "backup_validate" else "doctor.failure" if operation.startswith("doctor") else "qsuite.failure"
                        news.emit(event, "Operation failed", operation + " failed; inspect the private job record", level=2, package="qsuite")
                except Exception:
                    app.state.news_bridge_health = "degraded"  # The durable job/audit remain authoritative.
        except asyncio.CancelledError:
            with db.connect() as c:
                c.execute(
                    "UPDATE jobs SET status='interrupted',finished=? WHERE id=?",
                    (int(time.time()), identifier),
                )
            raise
        except Exception:
            with db.connect() as c:
                c.execute(
                    "UPDATE jobs SET status='failed',finished=?,error='Operation unavailable; inspect service journal' WHERE id=?",
                    (int(time.time()), identifier),
                )
            db.audit(actor["username"], address, operation, "failed", target)

    def queue(operation, target, required, fresh, actor, address):
        with db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            count = c.execute(
                "SELECT count(*) FROM jobs WHERE status IN ('queued','running')"
            ).fetchone()[0]
            if count >= 4:
                raise HTTPException(429, "job queue full")
            if c.execute(
                "SELECT 1 FROM jobs WHERE operation=? AND status IN ('queued','running')", (operation,)
            ).fetchone():
                raise HTTPException(409, "operation already queued or running")
            identifier = uuid.uuid4().hex
            c.execute(
                "INSERT INTO jobs(id,user_id,operation,status,created,permission) VALUES(?,?,?,'queued',?,?)",
                (identifier, actor["user_id"], operation, int(time.time()), required),
            )
        db.audit(actor["username"], address, operation, "queued", target)
        task = asyncio.create_task(
            execute_job(identifier, operation, target, actor, address, fresh)
        )
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return {"job": identifier}


    def add_operation(path, operation, required, fresh):
        async def handler(
            body: Operation, request: Request, actor=Depends(permission(required, fresh=fresh))
        ):
            if operation == "security.scan" and body.target not in {"quick", "full"}:
                raise HTTPException(422, "scan target must be quick or full")
            if operation == "security.baseline" and body.target != "update":
                raise HTTPException(422, "baseline target must be update")
            if operation.startswith("service."):
                units = settings.services | (
                    {"crafty": settings.integration.crafty_unit} if settings.integration.crafty_unit else {}
                )
                if body.target not in units:
                    raise HTTPException(422, "service not allowlisted")
            elif operation not in {"security.scan", "security.baseline"} and body.target:
                raise HTTPException(422, "operation does not accept parameters")
            return queue(operation, body.target, required, fresh, actor, source(request))

        app.add_api_route("/api/v1/" + path, handler, methods=["POST"], status_code=202, name=operation)

    for path, (operation, required, fresh) in OPERATIONS.items():
        add_operation(path, operation, required, fresh)

    @app.get("/api/v1/jobs/{identifier}")
    def get_job(identifier: str, actor=Depends(session)):
        rows = db.rows("SELECT * FROM jobs WHERE id=?", (identifier,))
        if not rows or rows[0]["user_id"] != actor["user_id"] and actor["role"] != "owner":
            raise HTTPException(404, "job not found")
        row = rows[0]
        if actor["role"] != "owner" and (not row["permission"] or not permitted(actor, row["permission"])):
            raise HTTPException(403, "permission denied")
        if row["result"]:
            row["result"] = json.loads(row["result"])
            result_permissions = {"backup_validate": "backup.view", "restore_verify": "backup.view", "incident": "incident.view", "doctor": "doctor.view", "doctor_full": "doctor.view", "security.scan": "security.view", "security.baseline": "security.view", "maintenance_on": "maintenance.view", "maintenance_off": "maintenance.view"}
            required = result_permissions.get(row["operation"], "crafty.view" if row["permission"] == "crafty.control" else "services.view")
            if not permitted(actor, required):
                row["result"] = {k: row["result"][k] for k in ("exit_code", "verified", "status") if k in row["result"]}
        return row

    @app.post("/api/v1/terminal/ticket")
    def terminal_ticket(actor=Depends(permission("terminal.open", fresh=True))):
        if not settings.terminal_enabled:
            raise HTTPException(409, "terminal disabled")
        token = secrets.token_urlsafe(32)
        with db.connect() as c:
            c.execute(
                "INSERT INTO terminal_tickets VALUES(?,?,?)",
                (digest(token), actor["token_hash"], int(time.time()) + 30),
            )
        return {"ticket": token, "expires_in": 30}

    @app.websocket("/api/v1/terminal")
    async def terminal(websocket: WebSocket):
        master, identifier, actor = None, None, None
        try:
            if (
                not origin_ok(websocket.headers.get("origin"))
                or websocket.headers.get("host") != urlsplit(settings.origin).netloc
            ):
                await websocket.close(code=1008)
                return
            if production and websocket.url.scheme != "wss":
                await websocket.close(code=1008)
                return
            actor = auth.session(websocket.cookies.get(cookie))
            auth.fresh(actor)
            if actor["must_change"] or actor["mfa_required"] and not actor["mfa"]:
                await websocket.close(code=1008)
                return
            if not settings.terminal_enabled or not permitted(actor, "terminal.open"):
                await websocket.close(code=1008)
                return
            if settings.access == "wan" and not actor["mfa"]:
                await websocket.close(code=1008)
                return
            await websocket.accept()
            # Ticket is the first frame, never a URL parameter that access logs would record.
            ticket = await asyncio.wait_for(websocket.receive_text(), timeout=5)
            if len(ticket) > 128:
                raise AuthError("invalid ticket")
            with db.connect() as c:
                cursor = c.execute(
                    "DELETE FROM terminal_tickets WHERE token_hash=? AND session_hash=? AND expires>? RETURNING token_hash",
                    (digest(ticket), actor["token_hash"], int(time.time())),
                )
                if cursor.fetchone() is None:
                    raise AuthError("invalid ticket")
            result, master = await run_in_threadpool(broker, settings, "terminal.open", "", receive_fd=True)
            identifier = result["id"]
            os.set_blocking(master, False)
            started = last_input = time.monotonic()
            loop = asyncio.get_running_loop()
            queue = asyncio.Queue(maxsize=16)

            def ready():
                try:
                    data = os.read(master, 8192)
                    if not data:
                        data = b""
                except (BlockingIOError, OSError):
                    data = b""
                if queue.full():
                    loop.remove_reader(master)
                else:
                    queue.put_nowait(data)

            loop.add_reader(master, ready)
            db.audit(actor["username"], websocket.client.host, "terminal.open", "success", identifier)

            async def output():
                while True:
                    data = await queue.get()
                    if not data:
                        return
                    await websocket.send_bytes(data)
                    loop.add_reader(master, ready)

            async def input_stream():
                nonlocal last_input
                while True:
                    data = await websocket.receive_text()
                    if len(data.encode()) > 4096:
                        raise AuthError("terminal frame too large")
                    # Resize controls are structured. All other data goes only to the unprivileged PTY.
                    if data.startswith('{"resize":'):
                        resize = json.loads(data)
                        if set(resize) != {"resize"} or len(resize["resize"]) != 2:
                            raise AuthError("invalid resize")
                        rows, cols = resize["resize"]
                        if (
                            type(rows) is not int
                            or type(cols) is not int
                            or not 1 <= rows <= 200
                            or not 1 <= cols <= 400
                        ):
                            raise AuthError("invalid terminal dimensions")
                        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                    else:
                        os.write(master, data.encode())
                    last_input = time.monotonic()

            async def limits():
                while True:
                    await asyncio.sleep(5)
                    live = auth.session(websocket.cookies.get(cookie), touch=False)
                    if live["must_change"] or live["mfa_required"] and not live["mfa"]:
                        raise AuthError("account setup required")
                    if time.monotonic() - started >= 3600 or time.monotonic() - last_input >= 300:
                        return

            pending = [
                asyncio.create_task(output()),
                asyncio.create_task(input_stream()),
                asyncio.create_task(limits()),
            ]
            try:
                await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                loop.remove_reader(master)
        except (AuthError, OSError, ValueError, WebSocketDisconnect, asyncio.TimeoutError, OperationError):
            pass
        finally:
            if master is not None:
                os.close(master)
            if identifier:
                try:
                    await run_in_threadpool(broker, settings, "terminal.close", identifier)
                except Exception:  # noqa: S110 -- cleanup failure is bounded by independent broker lifetime
                    pass
                db.audit(actor["username"], websocket.client.host, "terminal.close", "success", identifier)
            try:
                await websocket.close(code=1000)
            except RuntimeError:
                pass

    from .accounts import routes as account_routes
    from .control_center import routes as control_routes

    account_routes(app, db, auth, session, permission, source)
    control_routes(app, db, news, session, permission, source, read, queue)

    @app.api_route("/login", methods=["GET", "HEAD"], include_in_schema=False)
    def login_document():
        # Public application shell, never dependent on cookies, Referer or browser identity.
        return FileResponse(WEB / "index.html")

    def protected_document(request: Request):
        try:
            auth.session(request.cookies.get(cookie))
        except AuthError:
            return RedirectResponse("/login?next=" + quote(request.url.path, safe=""), status_code=303)
        return FileResponse(WEB / "index.html")

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    def index(request: Request):
        return protected_document(request)

    @app.api_route("/panel/{page}", methods=["GET", "HEAD"], include_in_schema=False)
    def panel_document(page: str, request: Request):
        if page not in {
            "dashboard",
            "server",
            "security",
            "performance",
            "backups",
            "logs",
            "incidents",
            "terminal",
            "services",
            "settings", "packages", "minecraft", "crafty", "membernews", "adminnews", "notifications", "users", "audit",
        }:
            raise HTTPException(404)
        return protected_document(request)

    @app.get("/assets/{name}")
    def asset(name: str):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+\.(?:js|css|svg)", name):
            raise HTTPException(404)
        path = WEB / name
        if not path.is_file() or path.is_symlink():
            raise HTTPException(404)
        return FileResponse(path)

    return app


def main():
    settings = load()
    if os.geteuid() == 0:
        raise SystemExit("agent must not run as root")
    credentials = Path(os.environ.get("CREDENTIALS_DIRECTORY", settings.secret_dir))
    key = (credentials / "auth-key").read_bytes().strip()
    cert, tls_key = settings.tls_cert, settings.tls_key
    if tls_key and (credentials / "tls-key").is_file():
        tls_key = str(credentials / "tls-key")
    if settings.mode == "production" and (not cert or not tls_key):
        raise SystemExit("production agent requires TLS certificate and key")
    if settings.mode == "production":
        from .tls import validate

        validate(
            cert,
            tls_key,
            urlsplit(settings.origin).hostname,
            settings.access == "wan" and settings.require_trusted_tls,
        )
    uvicorn.run(
        create_app(settings, key),
        host=settings.bind,
        port=settings.port,
        ssl_certfile=cert,
        ssl_keyfile=tls_key,
        proxy_headers=False,
        server_header=False,
        access_log=False,
        ws_max_size=8192,
        limit_concurrency=32,
        timeout_keep_alive=5,
    )
