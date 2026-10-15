"""Additive provisioning and locally authorized, validated access changes."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import time

from cryptography.fernet import Fernet

from .config import Settings, check_root_file, load
from .db import Database


def command(argv):
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL)  # noqa: S603


def install(units: str, dry_run=False, component="qsuite"):
    import platform

    os_release = platform.freedesktop_os_release()
    if os_release.get("ID") not in {"debian", "ubuntu"}:
        raise ValueError("QSuite targets Debian and Ubuntu; installation refused on another distribution")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("systemd is required")
    plan = {
        "component": component,
        "users": ["qsuite", "qsuite-terminal"],
        "config": "/etc/qsuite/config.toml",
        "state": ["/var/lib/qsuite", "/var/lib/qsecurity"],
        "starts_services": False,
        "changes_firewall": False,
        "next": "configure TLS, audited adapters and owner account; then explicitly start units",
    }
    if dry_run:
        return plan
    if os.geteuid() != 0:
        raise ValueError("installation requires root")
    check_root_file(Path(__file__).resolve())
    check_root_file(Path(units))
    for name, home in [("qsuite", "/var/lib/qsuite"), ("qsuite-terminal", "/var/lib/qsuite-terminal")]:
        try:
            user = pwd.getpwnam(name)
            if user.pw_uid == 0:
                raise ValueError("existing service identity is root")
        except KeyError:
            command(
                [
                    "/usr/sbin/useradd",
                    "--system",
                    "--user-group",
                    "--home-dir",
                    home,
                    "--shell",
                    "/usr/sbin/nologin",
                    name,
                ]
            )
            user = pwd.getpwnam(name)
        Path(home).mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(home, user.pw_uid, user.pw_gid)
        os.chmod(home, 0o700)
    for directory in ("/etc/qsuite", "/etc/qsuite/secrets", "/var/lib/qsecurity", "/var/lib/qsuite-watchdog"):
        Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod("/etc/qsuite", 0o755)  # noqa: S103 -- non-secret config; secrets subdirectory is 0700
    config = Path("/etc/qsuite/config.toml")
    if not config.exists():
        shutil.copyfile(Path(__file__).parent / "defaults/config.toml", config)
        os.chmod(config, 0o644)
    key = Path("/etc/qsuite/secrets/auth-key")
    if not key.exists():
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(Fernet.generate_key() + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    for path in Path(units).glob("*.service"):
        shutil.copyfile(path, Path("/etc/systemd/system") / path.name)
    for path in Path(units).glob("*.timer"):
        shutil.copyfile(path, Path("/etc/systemd/system") / path.name)
    # Only installation-approved timer drop-ins can become writable in the broker sandbox.
    settings = load(config, privileged=True)
    dropin = Path("/etc/systemd/system/qsuite-helper.service.d")
    dropin.mkdir(mode=0o755, exist_ok=True)
    writable = ["/etc/qsuite"]
    if settings.integration.performance_config:
        directory = Path(settings.integration.performance_config).parent
        check_root_file(directory)
        writable.append(str(directory))
    for timer in settings.integration.package_timers.values():
        directory = Path("/etc/systemd/system") / (timer + ".d")
        directory.mkdir(mode=0o755, exist_ok=True)
        check_root_file(directory)
        writable.append(str(directory))
    sandbox = dropin / "package-configuration.conf"
    sandbox.write_text("[Service]\nReadWritePaths=" + " ".join(writable) + "\n")
    os.chmod(sandbox, 0o644)
    command(["/usr/bin/systemctl", "daemon-reload"])
    return plan


def change_access(config_path: str, mode: str, dry_run=False, *, bind=None, origin=None, cert=None, key=None):
    if os.geteuid() != 0:
        raise ValueError("access changes require local root authentication")
    path = Path(config_path)
    settings = load(path, privileged=True)
    changes = {"access": mode, "bind": "127.0.0.1" if mode == "lan" else bind or settings.bind}
    changes.update(
        {name: value for name, value in {"origin": origin, "tls_cert": cert, "tls_key": key}.items() if value}
    )
    proposed = Settings.model_validate(settings.model_dump() | changes)
    if mode == "wan":
        if proposed.bind == "127.0.0.1":
            raise ValueError("configure an explicit WAN bind address before enabling WAN")
        from urllib.parse import urlsplit

        hostname = urlsplit(proposed.origin).hostname
        command(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                proposed.tls_cert,
                "-noout",
                "-checkhost",
                hostname,
                "-checkend",
                "604800",
            ]
        )
        # Full chain file validation is handled during certificate provisioning, not assumed from a file path.
        if proposed.require_trusted_tls:
            command(
                [
                    "/usr/bin/openssl",
                    "verify",
                    "-CAfile",
                    "/etc/ssl/certs/ca-certificates.crt",
                    "-untrusted",
                    proposed.tls_cert,
                    proposed.tls_cert,
                ]
            )
    if dry_run:
        return {"access": mode, "bind": proposed.bind, "origin": proposed.origin, "firewall_changes": False}
    before = path.read_text()
    after = before
    for name, value in changes.items():
        line = f"{name} = {json.dumps(value)}"
        if re.search(rf"^{name}\s*=", after, flags=re.M):
            after = re.sub(rf"^{name}\s*=.*$", lambda match, line=line: line, after, count=1, flags=re.M)
        else:
            after = line + "\n" + after
    backup = path.with_name(f"config.pre-access-{int(time.time())}.toml")
    shutil.copyfile(path, backup)
    temporary = path.with_name("config.toml.new")
    temporary.write_text(after)
    os.chmod(temporary, 0o644)
    temporary.replace(path)
    try:
        command(["/usr/bin/systemctl", "restart", "qsuite-agent.service"])
        command(["/usr/bin/systemctl", "is-active", "--quiet", "qsuite-agent.service"])
    except BaseException:
        shutil.copyfile(backup, path)
        command(["/usr/bin/systemctl", "restart", "qsuite-agent.service"])
        raise
    return {"access": mode, "rollback": str(backup), "firewall_changes": False}


def change_trust(config_path: str, required: bool):
    if os.geteuid() != 0:
        raise ValueError("TLS policy changes require privileged helper")
    path = Path(config_path)
    settings = load(path, privileged=True)
    if required and settings.access == "wan":
        if not settings.tls_cert:
            raise ValueError("configure trusted certificate before requiring it")
        command(
            [
                "/usr/bin/openssl",
                "verify",
                "-CAfile",
                "/etc/ssl/certs/ca-certificates.crt",
                "-untrusted",
                settings.tls_cert,
                settings.tls_cert,
            ]
        )
        from urllib.parse import urlsplit
        from .tls import validate

        validate(settings.tls_cert, settings.tls_key, urlsplit(settings.origin).hostname, True)
    before = path.read_text()
    line = f"require_trusted_tls = {'true' if required else 'false'}"
    if re.search(r"^require_trusted_tls\s*=", before, flags=re.M):
        after = re.sub(r"^require_trusted_tls\s*=.*$", line, before, count=1, flags=re.M)
    else:
        after = line + "\n" + before
    shutil.copyfile(path, path.with_name("config.pre-tls-policy.toml"))
    temporary = path.with_name("config.tls-policy.new")
    with temporary.open("w") as handle:
        handle.write(after)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o644)
    temporary.replace(path)
    return {"require_trusted_tls": required, "https_required": True}


def update(settings: Settings, package: Path, checksum: str):
    if os.geteuid() != 0:
        raise ValueError("updates require root")
    if package.is_symlink() or not package.is_file() or package.suffix != ".deb":
        raise ValueError("supply a local Debian package")
    if not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise ValueError("invalid checksum")
    if hashlib.sha256(package.read_bytes()).hexdigest() != checksum:
        raise ValueError("package checksum mismatch")
    metadata = subprocess.run(  # noqa: S603 -- a verified package path, never shell input
        ["/usr/bin/dpkg-deb", "-f", str(package), "Package"], capture_output=True, text=True, check=True
    )  # noqa: S603
    if metadata.stdout.strip() != "qsuite":
        raise ValueError("not a QSuite package")
    backup_dir = Path("/var/backups/qsuite")
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    snapshot = backup_dir / f"qsuite-pre-update-{int(time.time())}.db"
    Database(settings.database).snapshot(snapshot)
    shutil.copyfile("/etc/qsuite/config.toml", snapshot.with_suffix(".toml"))
    os.chmod(snapshot.with_suffix(".toml"), 0o600)
    maintenance = Path("/var/lib/qsuite-watchdog/maintenance.json")
    maintenance.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    maintenance.write_text(json.dumps({"until": int(time.time()) + 600, "reason": "verified package update"}))
    os.chmod(maintenance, 0o600)
    try:
        command(["/usr/bin/dpkg", "--install", str(package)])
    finally:
        maintenance.unlink(missing_ok=True)
    return {
        "package": package.name,
        "schema_snapshot": str(snapshot),
        "verification": "run acceptance checks before declaring upgrade successful",
    }
