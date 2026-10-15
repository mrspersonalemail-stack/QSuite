# QSuite v1.0.0

**Draft: do not publish until the release checklist passes.**

QSuite brings Linux server management into a responsive self-hosted control center.
Inspect host health, manage explicitly approved services, review security observations,
configure modules and provide community users with a narrow, separate view.

Highlights include backend RBAC/custom roles, TOTP and recovery codes, typed settings
previews, separate encrypted Member/Admin News, a closed privileged broker, optional
unprivileged PTY, independent CERBERUS checks and resumable backup downloads.

The target is systemd Debian/Ubuntu. Each downloadable Debian artifact must match
its qualified OS/Python minor/architecture; no platform is declared stable until
its recorded clean lifecycle drill passes. Install from a verified local `.deb`,
configure HTTPS and create an Owner before starting services. Read
[installation](installation.md) and [getting started](getting-started.md).

Security is based on explicit capabilities and least privilege, not browser-hidden
controls. Sensitive WAN actions require fresh authentication and TOTP. This project
has not been independently audited or certified. Report vulnerabilities privately
once the repository's private reporting channel is enabled.

Minecraft/Crafty is optional. Crafty remains the game supervisor. Diagnostic,
SMART, maintenance and recovery actions can depend on separately installed adapters.
Backup creation, production restore, automatic lockdown/bans, protected quarantine,
geolocation lookup and root terminal are unavailable. Automated complete rollback
is not provided; retain independent snapshots and SSH/console recovery access.

Before upgrading, review [upgrading](upgrading.md); application schema is 3 and
security schema is 1. Removal preserves private configuration and state.
See the [documentation index](README.md), [permissions](permissions.md),
[QSecurity](qsecurity.md), [backups](backups.md) and [security policy](../SECURITY.md).
