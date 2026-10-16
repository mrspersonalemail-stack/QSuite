# QSuite v1.0.0

QSuite is a self-hosted Linux server control center with explicit permissions,
local accounts and a closed privileged operation broker.

## Highlights

- Responsive dashboard, host monitoring and bounded performance history.
- Package Control Center with capability discovery, typed configuration previews,
  verification and rollback copies.
- QSecurity SSH/integrity observation and independent CERBERUS watchdog checks.
- Owner, Admin, Mod, Helper, Log Viewer and custom roles, enforced by the backend.
- Argon2id passwords, opaque sessions, CSRF, TOTP, recovery codes and fresh authentication.
- Separate Member News and private Admin News; encrypted Discord webhook settings,
  severity routing and restricted mentions.
- HTTPS with explicit LAN/WAN access and optional additional WAN CA trust policy.
- Allowlisted service operations, optional separate-user terminal, and optional
  Minecraft/Crafty status integration.
- Authenticated, resumable ZIP backup downloads; adapter-based diagnostics,
  backup validation and isolated restore verification.

## Installation

Download the Debian package matching your **system Python minor and amd64 architecture**,
plus `SHA256SUMS`. Verify the download before installation:

```sh
python3 --version
dpkg --print-architecture
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./qsuite_1.0.0_py312_amd64.deb
qsuite version
```

The example is for Ubuntu 24.04 / Python 3.12. Use `py314` on Ubuntu 26.04 /
Python 3.14. Runtime dependencies are bundled and hash-verified for offline Python
installation; apt may need to obtain the listed OS dependencies. A fresh install
leaves services stopped. Configure HTTPS and create an Owner before enabling them.
There is no default password, signed APT repository or remote shell installer.

Read [Installation](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.0.0/docs/installation.md)
and [Getting started](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.0.0/docs/getting-started.md).
The wheel is also supplied for maintainers; the Debian package is the recommended
service deployment path.

## Documentation

[Documentation index](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.0.0/docs/README.md)
includes architecture, packages, permissions, QSecurity, notifications, access/TLS,
backups, CLI/API, configuration, upgrading, removal and troubleshooting.

## Security

Read [SECURITY.md](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.0.0/SECURITY.md).
Report vulnerabilities privately to **qsuite-reports@proton.me**; do not include
credentials or production logs in public issues. QSuite has not received an
independent security audit or certification. Keep independent SSH/console access
and backups. Sensitive WAN operations require fresh authentication and TOTP.

## Supported Systems

- **Ubuntu 24.04 amd64 / Python 3.12** — installed systemd lifecycle qualified.
- **Ubuntu 26.04 amd64 / Python 3.14** — installed systemd lifecycle qualified.
- Debian 12/13 pass container tests/builds but lack installed lifecycle qualification;
  no Debian-specific or ARM64 binary is attached to this release.

The release evidence and precise platform scope are recorded in the
[release validation record](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.0.0/docs/release-readiness.md).

## Known Limitations

- Backup creation and production restore are not implemented. Validation, SMART,
  maintenance and some diagnostics require separately installed, audited adapters.
- No automatic bans/lockdown, protected quarantine, geolocation provider or root terminal.
- Crafty remains the game supervisor; manager service control is not per-server lifecycle control.
- Removal/purge deliberately preserves accounts, configuration, runtime and private data.
  Complete automated rollback is unavailable; retain independent recovery copies.
- Reboot/power-loss drills and real mobile/browser terminal acceptance are not part
  of this release qualification. The terminal is disabled by default.
- One non-failing upstream Starlette TestClient deprecation warning remains.

## Checksums

`SHA256SUMS` covers every attached wheel and Debian package. GitHub also supplies
source archives for the immutable `v1.0.0` tag. Checksums detect changed downloads;
obtain publisher identity through a trusted channel.

License: MIT. Bundled xterm assets retain their upstream MIT license.
