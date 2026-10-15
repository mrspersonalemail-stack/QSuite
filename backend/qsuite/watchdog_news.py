"""Protected private news policy independent of the API and its SQLite database."""

import fcntl
import json
from pathlib import Path

from cryptography.fernet import Fernet

from .config import check_root_file
from .news import NewsPolicy, webhook_url
from .package_config import atomic


def location(settings):
    return Path(settings.secret_dir) / "admin-news-watchdog.json"


def read(settings):
    path = location(settings)
    if not path.exists():
        return None
    check_root_file(path)
    if path.stat().st_mode & 0o077 or path.stat().st_size > 4096:
        raise ValueError("untrusted private news policy")
    value = json.loads(path.read_text())
    if set(value) != {"encrypted_url", "policy", "generation"}:
        raise ValueError("invalid private news policy")
    NewsPolicy.model_validate(value["policy"])
    return value


def configure(settings, value):
    if not isinstance(value, dict) or set(value) != {"encrypted_url", "policy", "generation"}:
        raise ValueError("invalid watchdog news fields")
    if type(value["generation"]) is not int or not 0 <= value["generation"] <= 2**63 - 1:
        raise ValueError("invalid watchdog news generation")
    policy = NewsPolicy.model_validate(value["policy"])
    key = Path(settings.secret_dir) / "auth-key"
    check_root_file(key)
    if value["encrypted_url"]:
        if not isinstance(value["encrypted_url"], str) or len(value["encrypted_url"]) > 1024:
            raise ValueError("invalid encrypted webhook")
        webhook_url(Fernet(key.read_bytes().strip()).decrypt(value["encrypted_url"].encode()).decode())
    path = location(settings)
    check_root_file(path.parent)
    with (path.parent / ".watchdog-news.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = read(settings)
        if old and old["generation"] >= value["generation"]:
            return {"configured": bool(old["encrypted_url"]), "synchronized": True}
        atomic(path, json.dumps(value | {"policy": policy.model_dump()}), 0o600)
    return {"configured": bool(value["encrypted_url"]), "synchronized": True}


def channel(settings):
    value = read(settings)
    if not value or not value["encrypted_url"]:
        return None
    key = Path(settings.secret_dir) / "auth-key"
    check_root_file(key)
    return (
        webhook_url(Fernet(key.read_bytes().strip()).decrypt(value["encrypted_url"].encode()).decode()),
        NewsPolicy.model_validate(value["policy"]),
    )


def status(settings):
    try:
        value = read(settings)
        result = {
            "configured": bool(value and value["encrypted_url"]),
            "health": "healthy" if value and value["encrypted_url"] else "unconfigured",
        }
        state = Path("/var/lib/qsuite-watchdog/state.json")
        if state.exists():
            check_root_file(state)
            if state.stat().st_size <= 4096:
                assessment = json.loads(state.read_text())
                result["assessment"] = {
                    k: assessment.get(k) for k in ("condition", "updated", "delivered", "event_id")
                }
        return result
    except Exception:
        return {"configured": False, "health": "degraded"}
