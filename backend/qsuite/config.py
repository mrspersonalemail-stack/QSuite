"""Strict, non-secret installation configuration."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Integration(StrictModel):
    crafty_unit: str | None = None
    minecraft_root: str | None = None
    game_port: int | None = Field(default=None, ge=1, le=65535)
    backup_root: str | None = None
    backup_mount: str | None = None
    corruption_marker: str | None = None
    performance_db: str | None = None
    performance_config: str | None = None
    offsite_status: str | None = None
    legacy_commands: dict[str, str] = Field(default_factory=dict)
    package_timers: dict[str, str] = Field(default_factory=dict)


class SecurityPolicy(StrictModel):
    trusted_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])
    trusted_countries: list[str] = Field(default_factory=list)
    trusted_continents: list[str] = Field(default_factory=list)
    owner_mention: str | None = None
    enforce: bool = False
    risk_weights: dict[str, int] = Field(
        default_factory=lambda: {
            "FOREIGN": 5,
            "EUROPA": 10,
            "EXILE": 20,
            "SIEGE": 20,
            "GHOST": 25,
            "ANCHOR": 25,
            "RAVEN": 25,
            "FORGE": 25,
            "THRONE": 25,
            "PLAGUE": 60,
            "OUTBREAK": 85,
            "CROWN": 70,
            "SABRE": 90,
            "BLACKOUT": 90,
        }
    )
    scan_roots: list[str] = Field(default_factory=list)
    protected_roots: list[str] = Field(
        default_factory=lambda: ["/etc/ssh", "/etc/sudoers.d", "/etc/systemd/system"]
    )


class Settings(StrictModel):
    mode: str = "production"
    access: str = "lan"
    bind: str = "127.0.0.1"
    port: int = Field(default=9080, ge=1024, le=65535)
    origin: str = "https://localhost:9443"
    data_dir: str = "/var/lib/qsuite"
    security_dir: str = "/var/lib/qsecurity"
    helper_socket: str = "/run/qsuite-helper/control.sock"
    agent_user: str = "qsuite"
    terminal_user: str = "qsuite-terminal"
    terminal_enabled: bool = False
    require_trusted_tls: bool = True
    tls_cert: str | None = None
    tls_key: str | None = None
    secret_dir: str = "/etc/qsuite/secrets"  # noqa: S105 -- directory, not a credential
    session_seconds: int = Field(default=28800, ge=300, le=86400)
    idle_seconds: int = Field(default=1800, ge=60, le=3600)
    reauth_seconds: int = Field(default=300, ge=30, le=600)
    audit_days: int = Field(default=180, ge=7, le=730)
    history_days: int = Field(default=30, ge=1, le=90)
    sample_seconds: int = Field(default=300, ge=60, le=3600)
    package_dir: str = "/etc/qsuite/packages.d"
    cpu_warning_percent: int = Field(default=90, ge=50, le=100)
    memory_warning_percent: int = Field(default=90, ge=50, le=100)
    smart_monitor_seconds: int = Field(default=1800, ge=300, le=86400)
    smart_temperature_warning: int = Field(default=60, ge=30, le=90)
    smart_failed_tests_warning: bool = True
    maintenance_message: str = Field(default="Service maintenance is in progress. Please check back soon.", min_length=1, max_length=1000)
    services: dict[str, str] = Field(default_factory=dict)
    integration: Integration = Field(default_factory=Integration)
    security: SecurityPolicy = Field(default_factory=SecurityPolicy)

    @model_validator(mode="after")
    def validate_boundary(self):
        if self.mode not in {"production", "development"} or self.access not in {"lan", "wan"}:
            raise ValueError("invalid runtime/access mode")
        address = ipaddress.ip_address(self.bind)
        if self.access == "lan" and not address.is_loopback:
            raise ValueError("LAN binds to loopback; use an SSH tunnel or explicit WAN mode")
        parsed = urlsplit(self.origin)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.path not in {"", "/"}:
            raise ValueError("origin must contain only scheme, hostname and optional port")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("invalid origin")
        if self.mode == "production" and parsed.scheme != "https":
            raise ValueError("production requires an HTTPS origin")
        if self.access == "wan" and (not self.tls_cert or not self.tls_key or self.mode != "production"):
            raise ValueError("WAN requires production and explicit TLS files")
        for cidr in self.security.trusted_cidrs:
            ipaddress.ip_network(cidr, strict=True)
        if len(self.security.trusted_cidrs) > 32 or any(not re.fullmatch(r"[A-Z]{2}", c) for c in self.security.trusted_countries):
            raise ValueError("invalid trusted networks or country codes")
        if any(c not in {"AF", "AN", "AS", "EU", "NA", "OC", "SA"} for c in self.security.trusted_continents):
            raise ValueError("invalid continent code")
        if any(
            type(weight) is not int or not 0 <= weight <= 100
            for weight in self.security.risk_weights.values()
        ):
            raise ValueError("risk weights must be integers between 0 and 100")
        if self.security.owner_mention and not re.fullmatch(r"[0-9]{15,22}", self.security.owner_mention):
            raise ValueError("owner mention must be a Discord user ID")
        for name in (self.agent_user, self.terminal_user):
            if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name):
                raise ValueError("invalid service account")
        if self.agent_user == self.terminal_user:
            raise ValueError("terminal and agent identities must differ")
        units = list(self.services.values()) + (
            [self.integration.crafty_unit] if self.integration.crafty_unit else []
        )
        for unit in units:
            if not re.fullmatch(r"[a-zA-Z0-9_.@-]+\.service", unit):
                raise ValueError("invalid service unit")
        if set(self.integration.package_timers) - {"qbackup", "qperf"} or any(not re.fullmatch(r"[a-zA-Z0-9_.@-]+\.timer", u) for u in self.integration.package_timers.values()):
            raise ValueError("invalid audited package timer")
        allowed = {
            "doctor",
            "doctor_full",
            "smart",
            "maintenance_status",
            "backup_validate",
            "restore_verify",
            "incident",
            "maintenance_on",
            "maintenance_off",
        }
        if set(self.integration.legacy_commands) - allowed:
            raise ValueError("unknown legacy operation")
        paths = [self.data_dir, self.security_dir, self.secret_dir, self.helper_socket, self.package_dir]
        paths += list(self.integration.legacy_commands.values())
        paths += self.security.scan_roots + self.security.protected_roots
        paths += [
            v for k, v in self.integration.model_dump().items() if isinstance(v, str) and k != "crafty_unit"
        ]
        paths += [v for v in (self.tls_cert, self.tls_key) if v]
        for value in paths:
            if not Path(value).is_absolute() or ".." in Path(value).parts or "\x00" in value:
                raise ValueError("paths must be absolute and canonical")
        return self

    @property
    def database(self) -> Path:
        return Path(self.data_dir) / "qsuite.db"

    @property
    def security_database(self) -> Path:
        return Path(self.security_dir) / "qsecurity.db"


def load(path: str | Path | None = None, *, privileged: bool = False) -> Settings:
    path = Path(path or os.environ.get("QSUITE_CONFIG", "/etc/qsuite/config.toml"))
    if privileged:
        check_root_file(path)
    return Settings.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))


def check_root_file(path: Path) -> None:
    """Reject writable ancestors too; a root-owned leaf alone is insufficient."""
    if path.is_symlink():
        raise ValueError("privileged configuration cannot be a symlink")
    for part in [path, *path.parents]:
        info = part.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(
                "privileged configuration and ancestors must be root-owned, not group/world writable"
            )
