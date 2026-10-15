# Users and permissions

Frontend visibility is convenience. Every API operation checks backend permissions;
direct requests remain forbidden when their navigation/card is hidden. Sessions
resolve current role/account state, and role/account changes revoke sessions.

| Preset | Intended scope |
| --- | --- |
| Owner | Full catalogue and Owner-only policy/role/news controls |
| Admin | Host operations, private information, downloads, scans, users within their grant scope and unprivileged terminal |
| Mod | Game/Crafty status, player activity, public news sending, package and maintenance visibility |
| Helper | Game/Crafty status, public news and permitted package visibility |
| Log Viewer | Filtered Minecraft player activity only |

Mod/Helper/Log Viewer do not receive security/SSH, system inventory, private logs,
backups, incidents, terminal, webhook settings or Admin News. Log Viewer does not
mean unrestricted system-log access. Legacy `administrator`, `operator`, `viewer`
are retained for compatibility and are broader than member presets; inspect them
before assigning. New backup download permission is granted only to Owner/Admin
and the legacy administrator preset, not legacy operator/viewer.

The authoritative catalogue and preset sets are in
[`permissions.py`](../backend/qsuite/permissions.py). Groups include `system.*`,
`services.*`, `security.*`, `backup.*`, `logs.*`, `performance.*`, `smart.*`,
`doctor.*`, `incident.*`, `maintenance.*`, `minecraft.*`, `crafty.*`, `users.*`,
`roles.manage`, `packages.view`, `terminal.*`, `member_news.*`, `admin_news.*`,
`qsuite.*`, `access.configure`, `tls.configure` and `audit.read`.
Some reserved permissions (root terminal, lockdown, quarantine, system power) have
no implemented action; granting them does not create one.

Owners can create custom roles in **Users & permissions**. Presets are immutable;
copy only the permissions needed into a named custom role. Example: a community
announcer needs `member_news.view` and `member_news.send`; a recovery reviewer
needs `backup.view`, with `backup.download` separately granted if required.

An Admin cannot manage an Owner or grant privileges outside their own set. Only
Owner manages custom roles and routing. The last permanent enabled Owner cannot
be disabled, demoted or given an expiry. Fresh authentication protects sensitive
changes; WAN sensitive actions also require TOTP. Expired/disabled accounts cannot
sign in; password reset revokes sessions and normally requires a password change.
See [API](api.md) and [security](security.md).
