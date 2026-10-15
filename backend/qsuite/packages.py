"""Declarative capability registry. Metadata never adds executable shell vocabulary."""

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re

from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .config import check_root_file
from .permissions import CATALOGUE


@dataclass(frozen=True)
class Capability:
    label: str
    permission: str
    operation: str
    target: str = ""
    fresh_auth: bool = False
    confirmation: str = ""


@dataclass(frozen=True)
class Package:
    name: str
    label: str
    permission: str
    status: str
    command: str | None = None
    service: str | None = None
    configure: str | None = None
    help: str = ""
    version: str | None = None
    actions: dict[str, Capability] = field(default_factory=dict)


BUILTINS = {
    "qsecurity": Package(
        "qsecurity",
        "QSecurity",
        "security.view",
        "security.status",
        service="qsecurity",
        configure="security.configure",
        help="Observation, integrity and explicit scans. Automatic containment and protected quarantine are not implemented.",
        actions={
            "scan_quick": Capability("Quick scan", "security.scan", "security.scan", "quick"),
            "scan_full": Capability("Full scan", "security.scan", "security.scan", "full"),
            "baseline": Capability(
                "Approve integrity baseline",
                "security.baseline",
                "security.baseline",
                "update",
                True,
                "Approve current protected files only after reviewing their changes.",
            ),
        },
    ),
    "qbackup": Package(
        "qbackup",
        "QBackup",
        "backup.view",
        "backups",
        "backup_validate",
        configure="backup.configure",
        help="Existing Crafty backups and validation. Backup creation requires a supported Crafty API credential.",
        actions={"validate": Capability("Validate latest", "backup.run", "backup_validate")},
    ),
    "qrestore": Package(
        "qrestore",
        "QRestore",
        "backup.view",
        "backups",
        "restore_verify",
        help="Verify the latest archive in an isolated extraction. Live world replacement is not exposed.",
        actions={
            "verify": Capability(
                "Verify isolated restore",
                "backup.restore",
                "restore_verify",
                "",
                True,
                "Extract and verify an isolated copy of the latest backup?",
            )
        },
    ),
    "qstatus": Package(
        "qstatus", "QStatus", "system.view", "status", help="Read-only host inventory and health."
    ),
    "qdoctor": Package(
        "qdoctor",
        "QDoctor",
        "doctor.view",
        "doctor.status",
        "doctor",
        help="Bounded diagnostics using the installed qdoctor adapter.",
        actions={
            "quick": Capability("Run quick", "doctor.run", "doctor"),
            "full": Capability("Run full", "doctor.run", "doctor_full"),
        },
    ),
    "qperf": Package(
        "qperf",
        "QPerf",
        "performance.view",
        "history",
        configure="performance.configure",
        help="Historical metrics. Native sample/retention controls or an explicitly configured legacy sample timer.",
    ),
    "qincident": Package(
        "qincident",
        "QIncident",
        "incident.view",
        "security.incidents",
        "incident",
        help="Private incidents and sanitized capture.",
        actions={"capture": Capability("Capture incident", "incident.create", "incident")},
    ),
    "qlogs": Package(
        "qlogs",
        "QLogs",
        "logs.system.read",
        "services",
        help="Sources are authorized individually; log access does not grant service control.",
    ),
    "qsmart": Package(
        "qsmart",
        "QSmart",
        "smart.view",
        "smart.status",
        "smart",
        configure="smart.configure",
        help="Read-only SSD health via an audited root-owned SMART adapter. Settings control QSuite's private news monitor; the existing host watchdog remains independent.",
    ),
    "qmaintenance": Package(
        "qmaintenance",
        "QMaintenance",
        "maintenance.view",
        "maintenance.status",
        "maintenance_on",
        configure="maintenance.configure",
        help="The existing maintenance guard and an approved public maintenance message. Members receive only the enabled state.",
        actions={
            "on": Capability(
                "Enable maintenance",
                "maintenance.configure",
                "maintenance_on",
                "",
                True,
                "Enable maintenance mode?",
            ),
            "off": Capability(
                "End maintenance",
                "maintenance.configure",
                "maintenance_off",
                "",
                True,
                "End maintenance mode?",
            ),
        },
    ),
    "qmc": Package(
        "qmc",
        "QMC",
        "minecraft.view",
        "minecraft.status",
        help="Minecraft status and safe player log feed. Native game lifecycle controls require an authenticated manager integration.",
    ),
    "crafty": Package(
        "crafty",
        "Crafty",
        "crafty.view",
        "crafty.status",
        service="crafty",
        help="These operations control Crafty itself and may interrupt managed Minecraft worlds.",
        actions={
            verb: Capability(
                verb.title() + " Crafty",
                "crafty.control",
                "service." + verb,
                "crafty",
                True,
                verb.title() + " Crafty and potentially interrupt managed worlds?",
            )
            for verb in ("start", "stop", "restart")
        },
    ),
    "qwebhook": Package(
        "qwebhook",
        "QWebhook / News",
        "member_news.view",
        "news",
        help="Member and Admin News use independent encrypted secrets. Existing qwebhook/qalert/CERBERUS remain independent.",
    ),
}
# Extensible metadata must refer to a reviewed operation already implemented in the broker.
READ_OPERATIONS = {p.status for p in BUILTINS.values()}
READ_PERMISSIONS = {
    operation: {p.permission for p in BUILTINS.values() if p.status == operation}
    for operation in READ_OPERATIONS
}
ACTION_OPERATIONS = {c.operation for p in BUILTINS.values() for c in p.actions.values()}


def registry(directory=None):
    packages = dict(BUILTINS)
    if directory:
        root = Path(directory)
        if root.exists():
            check_root_file(root)
            for path in sorted(root.glob("*.json"))[:64]:
                check_root_file(path)
                if path.stat().st_size > 16384:
                    raise ValueError("package manifest too large")
                value = json.loads(path.read_text())
                if set(value) - {"name", "label", "permission", "status", "help", "actions", "version"}:
                    raise ValueError("unsupported package manifest fields")
                actions = {k: Capability(**v) for k, v in value.pop("actions", {}).items()}
                package = Package(**value, actions=actions)
                if package.version is not None and (
                    not isinstance(package.version, str) or len(package.version) > 64
                ):
                    raise ValueError("invalid package version")
                if not re.fullmatch(r"q[a-z0-9_-]{1,47}", package.name) or package.name in packages:
                    raise ValueError("invalid or duplicate package name")
                if (
                    package.status not in READ_OPERATIONS
                    or package.permission not in READ_PERMISSIONS[package.status]
                ):
                    raise ValueError("unreviewed package status capability")
                if len(package.label) > 80 or len(package.help) > 2000 or len(actions) > 12:
                    raise ValueError("package metadata too large")
                for name, capability in actions.items():
                    if (
                        not re.fullmatch(r"[a-z_]{1,40}", name)
                        or capability.permission not in CATALOGUE
                        or capability.operation not in ACTION_OPERATIONS
                    ):
                        raise ValueError("unreviewed action capability")
                    # Do not let metadata weaken the reviewed operation's permission/freshness/target.
                    choices = [
                        c
                        for p in BUILTINS.values()
                        for c in p.actions.values()
                        if c.operation == capability.operation
                    ]
                    if not any(
                        (c.permission, c.target, c.fresh_auth)
                        == (capability.permission, capability.target, capability.fresh_auth)
                        for c in choices
                    ):
                        raise ValueError("action must retain the reviewed authorization contract")
                packages[package.name] = package
    return packages


def inventory(settings, runner=None):
    packages = registry(Path(settings.package_dir))
    rows = []
    for package in packages.values():
        installed = True
        if package.command:
            path = settings.integration.legacy_commands.get(package.command)
            installed = bool(path and Path(path).is_file())
        elif package.service:
            installed = bool(
                settings.integration.crafty_unit
                if package.service == "crafty"
                else settings.services.get(package.service)
            )
        if package.name == "qmc":
            installed = bool(settings.integration.minecraft_root and settings.integration.game_port)
        item = asdict(package)
        item.pop("command", None)
        item["installed"] = installed
        item["enabled"] = installed
        item["health"] = "not assessed" if installed else "not installed"
        item["service_state"] = None
        if installed and package.service and runner:
            unit = (
                settings.integration.crafty_unit
                if package.service == "crafty"
                else settings.services[package.service]
            )
            observed = runner(
                ["/usr/bin/systemctl", "show", unit, "--property=ActiveState,UnitFileState", "--no-pager"]
            )
            fields = dict(line.split("=", 1) for line in observed["output"].splitlines() if "=" in line)
            item["service_state"] = fields.get("ActiveState", "unknown")
            item["enabled"] = fields.get("UnitFileState") in {"enabled", "enabled-runtime", "static"}
            item["health"] = "active" if item["service_state"] == "active" else "degraded"
        item["version"] = package.version or (
            __version__
            if package.name in {"qsecurity", "qstatus", "qperf", "qwebhook"}
            else "installed adapter (version not reported)"
        )
        rows.append(item)
    return rows


class PackageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PerfConfig(PackageConfig):
    sample_seconds: int = Field(default=300, ge=60, le=3600)
    history_days: int = Field(default=30, ge=1, le=90)
    cpu_warning_percent: int = Field(default=90, ge=50, le=100)
    memory_warning_percent: int = Field(default=90, ge=50, le=100)


class BackupConfig(PackageConfig):
    validation_schedule: str = Field(
        default="*-*-* 06:00:00", pattern=r"^\*-\*-\* (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$"
    )


class SecurityConfig(PackageConfig):
    trusted_cidrs: list[str] = Field(max_length=32)
    trusted_countries: list[str] = Field(max_length=32)
    trusted_continents: list[str] = Field(max_length=8)
    risk_weights: dict[str, int] = Field(max_length=32)


class SmartConfig(PackageConfig):
    smart_monitor_seconds: int = Field(default=1800, ge=300, le=86400)
    smart_temperature_warning: int = Field(default=60, ge=30, le=90)
    smart_failed_tests_warning: bool = True


class MaintenanceConfig(PackageConfig):
    maintenance_message: str = Field(min_length=1, max_length=1000)


CONFIG_MODELS = {
    "qperf": PerfConfig,
    "qbackup": BackupConfig,
    "qsecurity": SecurityConfig,
    "qsmart": SmartConfig,
    "qmaintenance": MaintenanceConfig,
}
