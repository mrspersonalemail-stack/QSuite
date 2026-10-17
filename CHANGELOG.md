# QSuite 1.1.0 — 17 October 2026

- Optional QSecurity VPN/proxy firewall add-on, disabled by default. Reviewed
  settings toggle, IPv4/IPv6 UFW sets, fixed HTTPS feeds, offline cache restore,
  narrow exceptions and a separate network-privileged service. See
  [scope and limitations](docs/vpn-protection.md).
- QSecurity and security logs are Owner-only, including VPN controls and direct
  API/package access. Saved legacy/custom grants cannot bypass the role ceiling.
  Incidents and Admin News remain available to Owner/Admin; lower roles cannot
  obtain those reserved views through custom grants.
- Regression tests for role ceilings, firewall configuration preservation, cached
  feed failures and set rollback; disposable VM native IPv4/IPv6 packet qualification.

# QSuite 1.0.0

Initial public release — 16 October 2026. See the [validation record](docs/release-readiness.md).

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
- Safe runtime creation under permissive umasks/inherited ACLs; untrusted existing code is rejected before execution.
- Real installed-service qualification on disposable Ubuntu 24.04/26.04 VMs.
- Public examples, complete guide index, contributor/issue templates and release checks.

## Known limitations

Ubuntu 24.04/26.04 amd64 clean installation and same-version reinstall/removal are qualified.
Debian systemd lifecycle, reboot/power-loss and real mobile/terminal acceptance remain unqualified.
Automatic containment, protected quarantine, geolocation provider, root terminal,
native backup creation and automated full rollback remain unavailable. Minecraft/Crafty
is optional; manager service controls are not per-server game lifecycle controls.
