# Installation

## Qualification and requirements

Stable v1.0.0 has **not yet passed a clean systemd installation/upgrade/removal
qualification**. Do not treat the prepared package as a supported stable download.
The preceding pilot ran on Ubuntu 26.04 amd64 with Python 3.14. Configured CI
candidates are Debian 12 (3.11), Debian 13 (3.13), Ubuntu 24.04 (3.12) and Ubuntu
26.04 (3.14); each needs its own ABI-compatible wheel bundle and actual checks.
Arch Linux is a development host, not a supported installer target. No RHEL support.

Requirements: Debian/Ubuntu, systemd as the service manager, Python 3.11+, a matching
architecture/minor-specific package, root for installation, `python3-venv`, OpenSSL
and CA certificates. Optional tools depend on enabled adapters. No measured minimum
RAM/disk sizing is promised; allow headroom for two 64 MiB password hash workers,
private state, archives and optional scans. There is no signed APT repository.

## Install a verified package

Obtain the matching package and `SHA256SUMS` from the release when it is published.
Compare provenance through a trusted channel: a checksum downloaded from the same
compromised source does not authenticate its publisher.

```sh
python3 --version
dpkg --print-architecture
sha256sum -c SHA256SUMS
sudo apt install ./qsuite_1.0.0_py314_amd64.deb
qsuite version
```

The example filename is specifically for Python 3.14 amd64. Do not install it on a
different Python minor. Apt installs system dependencies; Python runtime wheels
inside the package are hash-verified and installed offline.

Installation creates `qsuite` and `qsuite-terminal`, protected state/configuration,
an authentication encryption key, versioned `/opt/qsuite` runtime and systemd units.
It never overwrites an existing key or Owner and does not configure your firewall,
SSH, router, Crafty or Minecraft. A fresh installation leaves services stopped.
Follow [getting started](getting-started.md) before enabling them.

For maintainers building locally, see [development](development.md). If installation
fails, preserve state and logs, inspect `sudo journalctl -u qsuite-agent -n 100`, and
use [troubleshooting](troubleshooting.md). Removal preserves data; see
[uninstall](uninstall.md).
