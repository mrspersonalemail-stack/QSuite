"""Independent CERBERUS availability, heartbeat and code integrity checks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

import httpx

from .config import load
from .notifications import notification

STATE_DIR = Path("/var/lib/qsuite-watchdog")
MODULES = (
    "security.py",
    "protocols.py",
    "notifications.py",
    "config.py",
    "watchdog.py",
    "helper.py",
    "auth.py",
    "permissions.py",
    "api.py",
    "cli.py",
    "db.py",
    "installer.py",
    "tls.py",
    "terminal_child.py",
    "accounts.py",
    "control_center.py",
    "packages.py",
    "package_config.py",
    "news.py",
    "watchdog_news.py",
    "game.py",
    "downloads.py",
    "telemetry.py",
    "__init__.py",
)


def atomic(path: Path, value):
    temporary = path.with_suffix(".new")
    with temporary.open("w") as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def fingerprints():
    root, output = Path(__file__).parent, {}
    for name in MODULES:
        path = root / name
        metadata = path.stat()
        output[name] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "uid": metadata.st_uid,
            "mode": metadata.st_mode & 0o777,
        }
    return output


def approve_code(state_dir=STATE_DIR):
    if os.geteuid() != 0:
        raise ValueError("code baseline requires local root authorization")
    current = fingerprints()
    if any(value["uid"] != 0 or value["mode"] & 0o022 for value in current.values()):
        raise ValueError("security code must be root-owned and immutable to unprivileged users")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic(state_dir / "baseline.json", current)


def trusted_heartbeat(path):
    metadata = path.lstat()
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and not metadata.st_mode & 0o022
        and metadata.st_size <= 1024
    )


def check(settings, *, state_dir=STATE_DIR):
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    previous_path = state_dir / "state.json"
    try:
        previous = json.loads(previous_path.read_text())
    except (ValueError, OSError):
        previous = {}
    maintenance = state_dir / "maintenance.json"
    if maintenance.is_file() and not maintenance.is_symlink():
        info = maintenance.stat()
        if info.st_uid == 0 and not info.st_mode & 0o077:
            try:
                until = json.loads(maintenance.read_text())["until"]
                if time.time() < until <= time.time() + 900:
                    return {"state": "maintenance", "until": until}
            except (ValueError, KeyError, TypeError):
                pass
    condition = "healthy"
    try:
        result = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "qsecurity.service",
                "--property=ActiveState,UnitFileState,SubState,ActiveEnterTimestampMonotonic",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if (
            result.returncode
            or fields.get("ActiveState") != "active"
            or fields.get("UnitFileState") != "enabled"
        ):
            condition = "qsecurity inactive, disabled, masked or unavailable"
        else:
            elapsed = time.monotonic() - int(fields.get("ActiveEnterTimestampMonotonic", 0)) / 1000000
            if elapsed > 120:
                try:
                    heartbeat = Path(settings.security_dir) / "heartbeat.json"
                    if not trusted_heartbeat(heartbeat):
                        raise ValueError("untrusted heartbeat")
                    timestamp = json.loads(heartbeat.read_text())["timestamp"]
                    age = time.time() - int(timestamp)
                    if age < -30 or age > 240:
                        condition = "qsecurity heartbeat missing or stalled"
                except (OSError, ValueError, KeyError, TypeError):
                    condition = "qsecurity heartbeat unreadable; observer coverage unproven"
            current = fingerprints()
            if any(value["uid"] != 0 or value["mode"] & 0o022 for value in current.values()):
                condition = "qsecurity code ownership or permissions changed"
            else:
                try:
                    expected = json.loads((state_dir / "baseline.json").read_text())
                except (OSError, ValueError):
                    expected = None
                if expected is None:
                    condition = "qsecurity independent code baseline approval required"
                elif current != expected:
                    condition = "qsecurity code differs from approved independent baseline"
    except (OSError, ValueError, subprocess.SubprocessError):
        condition = "qsecurity watchdog assessment unavailable"
    healthy = condition == "healthy"
    changed = condition != previous.get("condition")
    attempts = 0 if changed else previous.get("attempts", 0)
    delivered = False if changed else previous.get("delivered", False)
    next_attempt = 0 if changed else previous.get("next_attempt", 0)
    secret = Path(settings.secret_dir) / "security-webhook"
    private_channel = None
    try:
        from .watchdog_news import channel

        private_channel = channel(settings)
    except Exception:
        private_channel = (
            None  # Legacy independent delivery remains available if protected news config is corrupt.
        )
    configured = secret.is_file() and not secret.is_symlink()
    configured = configured or bool(private_channel)
    attempted = False
    if not healthy and not delivered and configured and attempts < 8 and time.time() >= next_attempt:
        info = secret.stat() if secret.exists() else None
        if private_channel or info and info.st_uid == 0 and not info.st_mode & 0o077 and info.st_size <= 1024:
            url = private_channel[0] if private_channel else secret.read_text().strip()
            if re.fullmatch(r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", url):
                policy = notification(4, settings.security.owner_mention)
                policy.pop("send")
                if private_channel and not private_channel[1].l3_plus_mentions_everyone:
                    policy = {"content": "", "allowed_mentions": {"parse": []}}
                payload = {
                    **policy,
                    "embeds": [{"title": "CERBERUS · L4", "description": condition, "color": 0xEC4B65}],
                }
                attempted = True
                try:
                    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
                        with client.stream("POST", url + "?wait=true", json=payload) as response:
                            delivered = response.status_code in {200, 204}
                except httpx.HTTPError:
                    delivered = False
                attempts += 1
                next_attempt = int(time.time()) + min(3600, 30 * 2**attempts)
    if changed or attempted:
        print(
            json.dumps(
                {
                    "component": "qsuite-watchdog",
                    "protocol": "ALLCLEAR" if healthy else "CERBERUS",
                    "level": 0 if healthy else 4,
                    "condition": condition,
                    "delivered": delivered,
                }
            ),
            flush=True,
        )
    atomic(
        previous_path,
        {
            "condition": condition,
            "updated": int(time.time()),
            "delivered": delivered,
            "attempts": attempts,
            "next_attempt": next_attempt,
            "event_id": uuid.uuid4().hex if changed else previous.get("event_id", uuid.uuid4().hex),
        },
    )
    return {"state": condition, "delivered": delivered, "configured": configured}


def main():
    if os.geteuid() != 0:
        raise SystemExit("watchdog requires root")
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-update", action="store_true")
    args = parser.parse_args()
    if args.baseline_update:
        approve_code()
    else:
        check(load(privileged=True))
