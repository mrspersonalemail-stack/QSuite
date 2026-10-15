"""Unified CLI; local account provisioning never sends passwords through an API or argv."""

import argparse
import getpass
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile

from . import __version__
from .auth import Auth
from .config import load
from .db import Database
from .helper import Broker, request
from .telemetry import status
from .permissions import PRESETS


def bootstrap_password(secret_dir: str, username: str):
    """Publish only encrypted credentials, with an atomic no-overwrite operation."""
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,32}", username):
        raise ValueError("invalid username")
    destination = Path(secret_dir) / f"bootstrap-{username}.cred"
    if destination.exists():
        raise ValueError("bootstrap credential already exists; refusing overwrite")
    password = secrets.token_urlsafe(24)
    descriptor, temporary = tempfile.mkstemp(prefix=".bootstrap-", dir=secret_dir)
    os.close(descriptor)
    try:
        subprocess.run(  # noqa: S603 -- fixed executable; secret travels only over stdin
            [
                "/usr/bin/systemd-creds",
                "encrypt",
                "--name=qsuite-bootstrap",
                "--with-key=host",
                "-",
                temporary,
            ],
            input=password.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
        )
        os.chmod(temporary, 0o600)
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return password, destination


def main():
    parser = argparse.ArgumentParser(prog="qsuite", description="QSuite explicit server operations")
    parser.add_argument("--config")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "doctor", "backup", "incidents", "version"):
        sub.add_parser(name)
    p = sub.add_parser("perf")
    p.add_argument("window", nargs="?", default="24h", choices=["1h", "6h", "24h", "7d", "30d"])
    p = sub.add_parser("restore")
    p.add_argument("action", choices=["verify"])
    p.add_argument("archive", choices=["latest"])
    p = sub.add_parser("logs")
    p.add_argument("service")
    p = sub.add_parser("maintenance")
    p.add_argument("state", choices=["on", "off"])
    p = sub.add_parser("security")
    p.add_argument("action", choices=["status", "protocols", "events", "incidents"])
    p = sub.add_parser("user")
    p.add_argument("action", choices=["add"])
    p.add_argument("--username")
    p.add_argument("--role", default="owner", help="preset or existing custom role identifier")
    p.add_argument(
        "--random",
        action="store_true",
        help="generate password and store an encrypted root-only bootstrap credential",
    )
    p = sub.add_parser("install")
    p.add_argument("component", nargs="?", choices=["qsuite", "qsecurity"], default="qsuite")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--units", default="/usr/lib/qsuite/systemd")
    p = sub.add_parser("access")
    p.add_argument("mode", choices=["lan", "wan"])
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--bind")
    p.add_argument("--origin")
    p.add_argument("--cert")
    p.add_argument("--key")
    p = sub.add_parser("update")
    p.add_argument("package", help="local verified Debian package")
    p.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if args.command == "version":
        print(__version__)
        return
    if args.command == "install":
        from .installer import install

        print(json.dumps(install(args.units, args.dry_run, args.component), indent=2))
        return
    settings = load(args.config, privileged=os.geteuid() == 0)
    if args.command == "user":
        if os.geteuid() != 0 or not args.random and not sys.stdin.isatty():
            raise SystemExit(
                "Use a local root terminal to provision accounts; password input must be interactive"
            )
        username = args.username or input("Username: ").strip()
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,32}", username):
            raise SystemExit("invalid username")
        if Path(settings.database).exists():
            with sqlite3.connect(Path(settings.database).as_uri() + "?mode=ro", uri=True) as connection:
                if connection.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                    raise SystemExit("account already exists; refusing to replace credentials")
                if args.role not in PRESETS and (not connection.execute("SELECT 1 FROM sqlite_master WHERE name='roles'").fetchone() or not connection.execute("SELECT 1 FROM roles WHERE name=?", (args.role,)).fetchone()):
                    raise SystemExit("unknown role")
        elif args.role not in PRESETS:
            raise SystemExit("unknown role")
        if args.random:
            if not args.username:
                raise SystemExit("random provisioning requires --username")
            password, bootstrap = bootstrap_password(settings.secret_dir, username)
        else:
            password = getpass.getpass("New QSuite password (10–256 characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise SystemExit("passwords differ")
        key = (Path(settings.secret_dir) / "auth-key").read_bytes().strip()
        user = pwd.getpwnam(settings.agent_user)
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
        db = Database(settings.database)
        db.initialize()
        Auth(db, settings, key).create_user(username, password, args.role)
        db.audit("local-root", "LOCAL", "user.create", "success", username)
        print("Account created. Enable TOTP in Settings before sensitive WAN operations.")
        if args.random:
            print("Encrypted bootstrap credential:", bootstrap)
            print(
                "Retrieve privately with sudo systemd-creds decrypt --name=qsuite-bootstrap CREDENTIAL_FILE -"
            )
        return
    if args.command == "access":
        from .installer import change_access

        print(
            json.dumps(
                change_access(
                    args.config or "/etc/qsuite/config.toml",
                    args.mode,
                    args.dry_run,
                    bind=args.bind,
                    origin=args.origin,
                    cert=args.cert,
                    key=args.key,
                ),
                indent=2,
            )
        )
        return
    if args.command == "update":
        from .installer import update

        print(json.dumps(update(settings, Path(args.package), args.sha256), indent=2))
        return
    operations = {
        "doctor": "doctor",
        "backup": "backup_validate",
        "incidents": "incident",
        "restore": "restore_verify",
    }
    if args.command == "status" and not Path(settings.helper_socket).exists():
        result = status(settings)
    elif args.command == "security":
        if args.action == "protocols":
            from dataclasses import asdict
            from .protocols import PROTOCOLS

            result = {"protocols": [asdict(p) for p in PROTOCOLS.values()]}
        else:
            operation = "security." + args.action
            result = (
                Broker(settings).execute(operation) if os.geteuid() == 0 else request(settings, operation)
            )
    else:
        operation, target = operations.get(args.command, args.command), ""
        if args.command == "perf":
            operation, target = "history", args.window
        elif args.command == "logs":
            target = args.service
        elif args.command == "maintenance":
            operation = "maintenance_" + args.state
        result = (
            Broker(settings).execute(operation, target)
            if os.geteuid() == 0
            else request(settings, operation, target)
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
