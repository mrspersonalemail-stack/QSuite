# Installation

## Qualification and requirements

QSuite v1.1.0 release packages are qualified on:

| System | Architecture | System Python | Package |
| --- | --- | --- | --- |
| Ubuntu 24.04 | amd64 | 3.12 | `qsuite_1.1.0_py312_amd64.deb` |
| Ubuntu 26.04 | amd64 | 3.14 | `qsuite_1.1.0_py314_amd64.deb` |

Both ran fresh installation, real systemd services, HTTPS/Owner login, package discovery,
same-version reinstall/resume and data-preserving removal/purge on disposable hosted VMs.
Debian 12 (3.11) and Debian 13 (3.13) pass container tests and package builds; their
installed systemd lifecycle has not been qualified, so Debian-specific binaries are
not attached to this stable release. ARM64, Arch and RHEL are not qualified release targets.
See the [validation record](release-readiness.md) for limitations, including reboot,
real mobile/terminal acceptance and older-version binary upgrades.

Requirements: Debian/Ubuntu, systemd as the service manager, Python 3.11+, a matching
architecture/minor-specific package, root for installation, `python3-venv`, OpenSSL
and CA certificates. Optional tools depend on enabled adapters. No measured minimum
RAM/disk sizing is promised; allow headroom for two 64 MiB password hash workers,
private state, archives and optional scans. There is no signed APT repository.

## Install a verified package

Obtain the matching package and `SHA256SUMS` from the
[QSuite v1.1.0 release](https://github.com/mrspersonalemail-stack/QSuite/releases/tag/v1.1.0).
Compare provenance through a trusted channel: a checksum downloaded from the same
compromised source does not authenticate its publisher.

```sh
python3 --version
dpkg --print-architecture
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./qsuite_1.1.0_py314_amd64.deb
qsuite version
```

The example filename is specifically for Python 3.14 amd64. Do not install it on a
different Python minor. Apt installs system dependencies; Python runtime wheels
inside the package are hash-verified and installed offline.

The runtime prefix `/opt` and existing QSuite code/ancestors must be root-owned
and not group/world writable. Existing runtime directories with inheritable ACLs
require local review. The installer rejects untrusted existing paths before executing
runtime code; it never approves an untrusted tree by changing its modes. New runtime
directories start private and clear their own inherited ACLs before becoming readable.

Installation creates `qsuite` and `qsuite-terminal`, protected state/configuration,
an authentication encryption key, versioned `/opt/qsuite` runtime and systemd units.
It never overwrites an existing key or Owner and does not configure your firewall,
SSH, router, Crafty or Minecraft. A fresh installation leaves services stopped.
Follow [getting started](getting-started.md) before enabling them.

For maintainers building locally, see [development](development.md). If installation
fails, preserve state and logs, inspect `sudo journalctl -u qsuite-agent -n 100`, and
use [troubleshooting](troubleshooting.md). Removal preserves data; see
[uninstall](uninstall.md).
