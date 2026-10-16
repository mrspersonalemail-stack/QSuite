# Implementation status

This document describes QSuite v1.0.0. It is not an independent certification.
The [validation record](release-readiness.md) defines the tested platform scope
and remaining qualification limits.

## Implemented

Authenticated HTTPS API and static UI, Argon2id sessions/CSRF/TOTP/recovery,
backend RBAC/custom roles, typed package configuration, filtered dashboards/logs,
Member/Admin News separation and encrypted outbox, host telemetry/history,
closed root broker, optional separate-identity PTY, archive downloads and explicit
security observation/baselines/scans/watchdog. Application schema 3 supports
migration snapshots. Offline Python-minor-specific Debian packaging preserves data.

## Adapter-dependent

Diagnostic/SMART/maintenance executables, incident bundle capture, backup validation,
isolated restore verification, optional legacy metric databases/timers and Crafty
service operations need reviewed installation configuration. They are not installed
as independent q* binaries by the QSuite package. Empty integration is supported.

## Unavailable / not qualified

Backup creation, native Crafty backup API/token integration, production restore,
root terminal, automatic permanent bans, hostile-session termination, recovery-safe
lockdown, geolocation lookup dataset, full sudo/transfer attribution, protected
malware quarantine, scheduled full-device scanning, passkeys, encrypted offsite
replication and fully automated software/database rollback are unavailable.

Fresh install, real service startup, same-version reinstall/resume and removal/purge
are qualified on Ubuntu 24.04/26.04 amd64. Application schema migration/recovery
paths have automated tests. Cross-version binary upgrades, reboot/power-loss and
real mobile/separate-terminal acceptance remain qualification work. GUI access-mode
changes remain local CLI only; TLS trust policy can be changed by an authorized Owner.
