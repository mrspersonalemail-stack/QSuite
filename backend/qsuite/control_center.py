"""Permission-filtered control center APIs and typed classified news routes."""

import json
import time

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .news import PUBLIC_SAFE, announcement_event, validate_public
from .permissions import permitted
from .packages import BUILTINS
from .packages import CONFIG_MODELS


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Configuration(Body):
    values: dict = Field(max_length=32)
    expected: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class NewsConfiguration(Body):
    webhook: str | None = Field(default=None, max_length=350)
    policy: dict | None = Field(default=None, max_length=3)


class Routing(Body):
    routes: dict[str, dict[str, bool]] = Field(max_length=32)


class Announcement(Body):
    title: str = Field(min_length=1, max_length=120)
    message: str = Field(min_length=1, max_length=1500)
    style: str = Field(default="INFO", pattern=r"^(INFO|MAINTENANCE|EVENT|UPDATE|DOWNTIME|ONLINE)$")


class TestAlert(Body):
    level: int = Field(default=1, ge=1, le=5)


def routes(app, db, news, session, permission, source, read, queue):
    async def package(name, actor):
        if name in BUILTINS and not permitted(actor, BUILTINS[name].permission):
            raise HTTPException(403, "permission denied")
        rows = (await read("packages.inventory"))["packages"]
        item = next((p for p in rows if p["name"] == name), None)
        if not item:
            raise HTTPException(404, "package not found")
        if not permitted(actor, item["permission"]):
            raise HTTPException(403, "permission denied")
        return item

    def filtered(item, actor):
        # Operations/targets are internal dispatch data, never browser command fields.
        actions = {
            k: {field: v[field] for field in ("label", "permission", "fresh_auth", "confirmation")}
            for k, v in item["actions"].items()
            if permitted(actor, v["permission"])
        }
        result = {
            key: item[key]
            for key in ("name", "label", "version", "installed", "enabled", "health", "service_state", "help")
        }
        result["actions"] = actions
        result["configure"] = (
            item["configure"] if item["configure"] and permitted(actor, item["configure"]) else None
        )
        return result

    async def package_state(item, actor):
        if not item["installed"]:
            return {"health": "not installed"}
        operation = item["status"]
        if item["name"] == "qlogs":
            return log_sources(actor)
        if operation == "news":
            return {
                channel: news.health(channel)
                for channel in ("member", "admin")
                if permitted(actor, channel + "_news.view")
            }
        if operation == "doctor.status":
            return {
                "recent": db.rows(
                    "SELECT id,status,created,finished FROM jobs WHERE operation IN ('doctor','doctor_full') ORDER BY created DESC LIMIT 5"
                )
            }
        return await read(operation, "24h" if operation == "history" else "")

    @app.get("/api/v1/packages")
    async def packages(actor=Depends(permission("packages.view"))):
        rows = (await read("packages.inventory"))["packages"]
        return {"packages": [filtered(p, actor) for p in rows if permitted(actor, p["permission"])]}

    @app.get("/api/v1/packages/{name}")
    async def details(name: str, actor=Depends(permission("packages.view"))):
        item = await package(name, actor)
        result = filtered(item, actor)
        result["status"] = await package_state(item, actor)
        result["recent_events"] = (
            db.rows(
                "SELECT ts,action,result,object FROM audit WHERE action LIKE 'package.%' AND object=? ORDER BY id DESC LIMIT 10",
                (name,),
            )
            if permitted(actor, "audit.read")
            else []
        )
        return result

    @app.post("/api/v1/packages/{name}/actions/{action}")
    async def action(name: str, action: str, request: Request, actor=Depends(permission("packages.view"))):
        item = await package(name, actor)
        capability = item["actions"].get(action)
        if not capability:
            raise HTTPException(404, "action not found")
        permission(capability["permission"], fresh=capability["fresh_auth"])(request, actor)
        if not item["installed"]:
            raise HTTPException(409, "package not installed")
        # Refuse even unused arbitrary browser parameters.
        if await request.json() != {}:
            raise HTTPException(422, "package actions accept no command parameters")
        return queue(
            capability["operation"],
            capability["target"],
            capability["permission"],
            capability["fresh_auth"],
            actor,
            source(request),
        )

    @app.get("/api/v1/packages/{name}/configuration")
    async def configuration(name: str, request: Request, actor=Depends(permission("packages.view"))):
        item = await package(name, actor)
        if not item["configure"]:
            raise HTTPException(409, "no implemented configuration adapter")
        permission(item["configure"])(request, actor)
        return await read("package.config.get", name)

    @app.post("/api/v1/packages/{name}/configuration/{stage}")
    async def configure(
        name: str,
        stage: str,
        body: Configuration,
        request: Request,
        actor=Depends(permission("packages.view")),
    ):
        if stage not in {"preview", "apply"}:
            raise HTTPException(404)
        item = await package(name, actor)
        if not item["configure"]:
            raise HTTPException(409, "no implemented configuration adapter")
        permission(item["configure"], fresh=stage == "apply")(request, actor)
        if name not in CONFIG_MODELS:
            raise HTTPException(409, "configuration adapter unavailable")
        try:
            CONFIG_MODELS[name].model_validate(body.values)
        except ValueError:
            raise HTTPException(422, "invalid typed package configuration") from None
        result = await read("package.config." + stage, json.dumps({"package": name, **body.model_dump()}))
        db.audit(actor["username"], source(request), "package.configuration." + stage, "success", name)
        if stage == "apply" and result.get("applied"):
            news.emit(
                "configuration.change",
                "Package configuration changed",
                name + " configuration was updated",
                package=name,
            )
        return result

    @app.get("/api/v1/dashboard")
    async def dashboard(actor=Depends(session)):
        widgets = {}
        for name, required, operation in (
            ("system", "system.view", "status"),
            ("services", "services.view", "services"),
            ("security", "security.view", "security.status"),
            ("backups", "backup.view", "backups"),
            ("minecraft", "minecraft.view", "minecraft.status"),
            ("crafty", "crafty.view", "crafty.status"),
            ("smart", "smart.view", "smart.status"),
            ("incidents", "incident.view", "security.incidents"),
        ):
            if permitted(actor, required):
                try:
                    widgets[name] = await read(operation)
                except Exception:
                    widgets[name] = {"state": "unavailable"}
        if permitted(actor, "member_news.view"):
            widgets["member_news"] = news.history("member")[:5]
        if permitted(actor, "admin_news.view"):
            widgets["admin_news"] = news.history("admin")[:5]
        return {"widgets": widgets}

    @app.get("/api/v1/minecraft")
    async def minecraft(actor=Depends(permission("minecraft.view"))):
        return await read("minecraft.status")

    @app.get("/api/v1/crafty")
    async def crafty(actor=Depends(permission("crafty.view"))):
        return await read("crafty.status")

    @app.get("/api/v1/log-sources")
    def log_sources(actor=Depends(session)):
        rows = []
        if permitted(actor, "logs.minecraft.read"):
            rows.append(
                {
                    "id": "minecraft",
                    "label": "Minecraft · player activity",
                    "permission": "logs.minecraft.read",
                }
            )
        for name, unit in (
            app.state.settings.services
            | (
                {"crafty": app.state.settings.integration.crafty_unit}
                if app.state.settings.integration.crafty_unit
                else {}
            )
        ).items():
            required = (
                "logs.crafty.read"
                if name == "crafty"
                else "logs.security.read"
                if unit in {"qsecurity.service", "fail2ban.service", "ssh.service", "sshd.service"}
                else "logs.system.read"
            )
            if permitted(actor, required):
                rows.append({"id": name, "label": name, "permission": required})
        return {"sources": rows}

    @app.get("/api/v1/news/{channel}")
    async def history(
        channel: str,
        request: Request,
        level: int | None = None,
        package: str | None = None,
        protocol: str | None = None,
        delivery: str | None = None,
        since: int | None = None,
        actor=Depends(session),
    ):
        if channel not in {"member", "admin"}:
            raise HTTPException(404)
        permission(channel + "_news.view")(request, actor)
        health = news.health(channel)
        if channel == "admin":
            try:
                health["watchdog"] = await read("news.watchdog.status")
            except Exception:
                health["watchdog"] = {"configured": False, "health": "degraded"}
        return {
            "events": news.history(
                channel, level=level, package=package, protocol=protocol, delivery=delivery, since=since
            ),
            "health": health,
        }

    @app.put("/api/v1/news/{channel}/configuration")
    async def news_configuration(
        channel: str, body: NewsConfiguration, request: Request, actor=Depends(session)
    ):
        if channel not in {"member", "admin"}:
            raise HTTPException(404)
        permission(channel + "_news.configure", fresh=True)(request, actor)
        if actor["role"] != "owner":
            raise HTTPException(403, "Owner required")
        try:
            news.configure(channel, secret=body.webhook, policy=body.policy)
        except ValueError:
            raise HTTPException(
                422, "invalid webhook or mention policy; channels must use separate webhooks"
            ) from None
        if channel == "admin":
            await read("news.watchdog.configure", json.dumps(news.watchdog_snapshot()))
        db.audit(actor["username"], source(request), "news.configuration", "success", channel)
        return news.health(channel)

    @app.get("/api/v1/news-routing")
    def routing(actor=Depends(permission("admin_news.configure"))):
        return {"routes": news.routes()}

    @app.put("/api/v1/news-routing")
    def set_routing(
        body: Routing, request: Request, actor=Depends(permission("admin_news.configure", fresh=True))
    ):
        if actor["role"] != "owner":
            raise HTTPException(403, "Owner required")
        try:
            news.set_routes(body.routes)
        except ValueError:
            raise HTTPException(422, "invalid routing; private events can never enter Member News") from None
        db.audit(actor["username"], source(request), "news.routing", "success")
        return {"routes": news.routes()}

    @app.post("/api/v1/news/member/preview")
    def preview(body: Announcement, actor=Depends(permission("member_news.send"))):
        try:
            validate_public(body.title, body.message)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return news.payload(
            {
                "id": "preview",
                "package": "qwebhook",
                "event": announcement_event(body.style),
                "classification": PUBLIC_SAFE,
                "title": body.title,
                "message": body.message,
                "level": 1,
                "test": False,
                "ts": int(time.time()),
            },
            "member",
        )

    @app.post("/api/v1/news/member")
    def announce(body: Announcement, request: Request, actor=Depends(permission("member_news.send"))):
        try:
            validate_public(body.title, body.message)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        recent = db.rows(
            "SELECT count(*) AS n FROM audit WHERE user=? AND action='news.member.send' AND ts>?",
            (actor["username"], int(time.time()) - 60),
        )[0]["n"]
        if recent >= 5:
            raise HTTPException(429, "announcement limit; try again later")
        event = announcement_event(body.style)
        identifier = news.emit(event, body.title, body.message, package="qwebhook")
        db.audit(actor["username"], source(request), "news.member.send", "queued", identifier)
        queued = bool(db.rows("SELECT id FROM news_delivery WHERE event_id=?", (identifier,)))
        return {"event": identifier, "queued": queued}

    @app.post("/api/v1/news/{channel}/test")
    def test(
        channel: str,
        body: TestAlert,
        request: Request,
        actor=Depends(permission("admin_news.test", fresh=True)),
    ):
        if actor["role"] != "owner" or channel not in {"member", "admin"}:
            raise HTTPException(403, "Owner required")
        if not news.health(channel)["configured"]:
            raise HTTPException(409, "configure this webhook before testing")
        if channel == "admin" and body.level == 2 and not news.policy().level_2_admin_user_id:
            raise HTTPException(409, "configure a Level 2 administrator target before testing")
        event = "community.announcement" if channel == "member" else "admin.test"
        identifier = news.emit(
            event,
            "TEST alert",
            "This is a TEST notification. No incident or containment action occurred.",
            level=1 if channel == "member" else body.level,
            test=True,
            test_channel=channel,
            package="qwebhook",
        )
        db.audit(actor["username"], source(request), "news.test", "queued", channel)
        return {"event": identifier, "queued": True}

    @app.post("/api/v1/news/{channel}/{identifier}/retry")
    def retry(channel: str, identifier: str, request: Request, actor=Depends(session)):
        if channel not in {"member", "admin"}:
            raise HTTPException(404)
        permission(channel + "_news.configure", fresh=True)(request, actor)
        if actor["role"] != "owner":
            raise HTTPException(403, "Owner required")
        with db.connect() as c:
            changed = c.execute(
                "UPDATE news_delivery SET state='queued',attempts=0,next_attempt=?,error=NULL WHERE channel=? AND event_id=? AND state IN ('failed','unconfigured')",
                (int(time.time()), channel, identifier),
            )
        if not changed.rowcount:
            raise HTTPException(409, "delivery is not eligible for manual retry")
        db.audit(actor["username"], source(request), "news.retry", "queued", channel)
        return {"queued": True}
