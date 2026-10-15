"""Permission catalogue, presets and compatibility names. Never a frontend boundary."""

import json

CATALOGUE = {
    "minecraft.view",
    "minecraft.control",
    "minecraft.configure",
    "crafty.view",
    "crafty.control",
    "member_news.view",
    "member_news.send",
    "member_news.configure",
    "admin_news.view",
    "admin_news.configure",
    "admin_news.test",
    "security.view",
    "security.configure",
    "security.bans",
    "security.scan",
    "security.quarantine",
    "security.lockdown",
    "security.baseline",
    "backup.view",
    "backup.download",
    "backup.run",
    "backup.configure",
    "backup.restore",
    "logs.minecraft.read",
    "logs.crafty.read",
    "logs.system.read",
    "logs.security.read",
    "logs.audit.read",
    "performance.view",
    "performance.configure",
    "smart.view",
    "smart.configure",
    "doctor.run",
    "doctor.view",
    "incident.view",
    "incident.create",
    "services.view",
    "services.control",
    "terminal.open",
    "terminal.privileged",
    "users.view",
    "users.manage",
    "roles.manage",
    "system.view",
    "system.control",
    "system.power",
    "qsuite.configure",
    "qsuite.update",
    "access.configure",
    "tls.configure",
    "audit.read",
    "packages.view",
    "maintenance.view",
    "maintenance.configure",
}
ALIASES = {
    "status.read": "system.view",
    "logs.read": "logs.system.read",
    "perf.read": "performance.view",
    "security.read": "security.view",
    "backups.read": "backup.view",
    "incidents.read": "incident.view",
    "backups.validate": "backup.run",
    "restore.verify": "backup.restore",
    "incident.capture": "incident.create",
    "maintenance.change": "maintenance.configure",
    "services.operate": "services.control",
    "access.change": "access.configure",
    "host.power": "system.power",
    "security.policy": "security.configure",
}


def expanded(permissions):
    values = set(permissions)
    return values | {old for old, new in ALIASES.items() if new in values}


READ = {
    "system.view",
    "services.view",
    "logs.system.read",
    "logs.security.read",
    "logs.crafty.read",
    "logs.minecraft.read",
    "performance.view",
    "security.view",
    "backup.view",
    "incident.view",
    "minecraft.view",
    "crafty.view",
    "packages.view",
    "smart.view",
    "doctor.view",
    "maintenance.view",
    "member_news.view",
    "admin_news.view",
}
OPERATE = READ | {
    "backup.run",
    "backup.restore",
    "incident.create",
    "maintenance.configure",
    "services.control",
    "doctor.run",
    "member_news.send",
    "crafty.control",
}
ADMIN = OPERATE | {
    "backup.download",
    "terminal.open",
    "security.scan",
    "security.baseline",
    "security.bans",
    "security.configure",
    "backup.configure",
    "performance.configure",
    "smart.configure",
    "minecraft.configure",
    "minecraft.control",
    "users.view",
    "users.manage",
    "audit.read",
    "logs.audit.read",
}
PRESETS = {
    "owner": CATALOGUE,
    "admin": ADMIN,
    "mod": {
        "minecraft.view",
        "crafty.view",
        "member_news.view",
        "member_news.send",
        "logs.minecraft.read",
        "packages.view",
        "maintenance.view",
    },
    "helper": {"minecraft.view", "crafty.view", "member_news.view", "packages.view"},
    "log_viewer": {"logs.minecraft.read"},
    # Preserve privileges of previously provisioned legacy accounts.
    "administrator": ADMIN | {"security.lockdown"},
    "operator": OPERATE,
    "viewer": READ,
}
ROLES = {name: expanded(values) for name, values in PRESETS.items()}
LEGACY_OPERATIONS = {
    "backup_validate": "backup.run", "restore_verify": "backup.restore", "incident": "incident.create",
    "maintenance_on": "maintenance.configure", "maintenance_off": "maintenance.configure",
    "security.scan": "security.scan", "security.baseline": "security.baseline",
    "service.start": "services.control", "service.stop": "services.control", "service.restart": "services.control",
}


def resolve(db, name):
    rows = db.rows("SELECT permissions FROM roles WHERE name=?", (name,))
    return expanded(json.loads(rows[0]["permissions"])) if rows else set()


def permitted(actor_or_role, permission: str) -> bool:
    values = (
        actor_or_role.get("permissions", [])
        if isinstance(actor_or_role, dict)
        else ROLES.get(actor_or_role, set())
    )
    return ALIASES.get(permission, permission) in values
