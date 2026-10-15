# QSuite

## Linux Server Management Made Simple

A self-hosted web control panel for Linux server administration, monitoring,
security observation, service operations and recovery workflows. QSuite brings
common tasks into a responsive interface while keeping permissions and privileged
operations on the server.

**Release status:** v1.0.0 is being prepared. Stable publication is gated by the
[release checklist](docs/release-readiness.md). No public package download is
available until those gates pass. This project has not received an independent
security audit or certification.

Screenshots await an isolated browser review. Production screenshots are excluded
to protect private host and account information.

## What it does

| Area | Available functionality |
| --- | --- |
| Dashboard | Host health, storage, permitted service status and news |
| Package Control Center | Capability discovery, explicit actions, typed settings previews and rollback copies |
| QSecurity | SSH journal observation, reviewed file baselines, incident records, explicit ClamAV integration and independent CERBERUS checks |
| Performance | Current CPU/memory/storage measurements and bounded historical samples |
| Backups & recovery | List and download completed ZIP archives; installed adapters can validate and verify isolated restores |
| Users & permissions | Owner, Admin, Mod, Helper, Log Viewer and custom roles; backend enforcement |
| Notifications | Separate Member News and private Admin News, encrypted webhook settings, severity and mention policies |
| Service management | Root-configured allowlist, observed results, confirmation and fresh authentication |
| Browser terminal | Optional PTY under a separate unprivileged Linux identity |
| Minecraft / Crafty | Optional local game status, filtered player activity and manager service operations |

QSuite is a general Linux management application. Minecraft and Crafty are
optional; they are neither installed nor required by QSuite.

### Boundaries you should know

Backup **creation** and production restore are unavailable. Diagnostic, SMART,
maintenance, backup-validation and restore-verification actions depend on separately
installed, audited adapters. Merely configuring a Crafty token does not enable a
producer in this version. No root terminal, automatic bans, automatic lockdown,
geolocation dataset or protected malware quarantine is provided. A registered
permission or named security protocol is not proof of an implemented capability.

## Platform status

QSuite targets systemd-based Debian and Ubuntu with Python 3.11 or newer.
The predecessor build had an Ubuntu 26.04 amd64 / Python 3.14 pilot installation.
That is not a clean-install qualification of v1.0.0. Debian 12/13 and Ubuntu 24.04
are CI candidates, not claimed as validated platforms until those jobs pass.
See [installation](docs/installation.md) for the exact qualification status.

## Quick start

Start with [installation](docs/installation.md), then [first-run setup](docs/getting-started.md).
Packages are built for one Python minor and architecture. Check that match before
installing a locally downloaded package:

```sh
sha256sum -c SHA256SUMS
sudo apt install ./qsuite_1.0.0_py314_amd64.deb
qsuite version
```

These commands describe the prepared artifact, not a published download. Installation
creates isolated accounts and preserves managed workloads. Configure HTTPS and an
Owner before explicitly starting the units. There is no default password and no
remote shell installer. Keep an independent SSH or console recovery path.

## Documentation

[Documentation index](docs/README.md) · [Architecture](docs/architecture.md) ·
[Packages](docs/packages.md) · [QSecurity](docs/qsecurity.md) ·
[Permissions](docs/permissions.md) · [Notifications](docs/notifications.md) ·
[Access & TLS](docs/access-modes.md) · [Backups](docs/backups.md)

## Security and contributing

Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities. Do not post
credentials or private logs in public issues. Contributions should include
failure-path tests and documentation; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Bundled xterm assets retain their [upstream license](frontend/XTERM-LICENSE).
