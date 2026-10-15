# QSuite 1.0.0

Prepared first public release; publication remains subject to the release checklist.

## Added

- Responsive web control center, permission-filtered dashboard and 13 module entries.
- Linux status/history, explicit service operations, unified CLI and optional game status.
- Typed configuration preview/apply, revision checks, verification and rollback copies.

## Authentication and security

- Argon2id, opaque sessions, CSRF, TOTP, one-use recovery, expiry and revocation.
- Owner/Admin/Mod/Helper/Log Viewer/custom roles and per-source backend authorization.
- Exact origin/Host and production HTTPS; optional WAN CA policy preserves all other checks.
- Closed root broker, separate unprivileged terminal identity and independent CERBERUS.
- SSH/integrity observations, explicit ClamAV integration and private incidents.

## Notifications

- Classified Member/Admin News, independent encrypted webhook secrets, bounded delivery,
  safe mention policy, explicit test messages and private watchdog policy synchronization.

## Backups and recovery

- Authenticated ZIP downloads with resume ranges, bounded transfers and descriptor cleanup.
- Adapter-based validation/isolated verification; backup creation/production restore absent.

## Packaging and documentation

- Canonical version metadata, offline ABI-specific Debian payload and verified wheel manifest.
- Data-preserving removal with a self-contained post-removal script; active QSuite unit resume.
- Public examples, complete guide index, contributor/issue templates and release checks.

## Known limitations

No stable platform qualification is claimed until clean systemd lifecycle drills pass.
Automatic containment, protected quarantine, geolocation provider, root terminal,
native backup creation and automated full rollback remain unavailable. Minecraft/Crafty
is optional; manager service controls are not per-server game lifecycle controls.
