# QSuite v1.1.0

QSecurity gains optional host VPN/proxy protection and clearer role boundaries.

## Highlights

- **QSecurity is Owner-only**: dashboard data, security APIs, package controls,
  VPN settings, scans and security logs. The backend clamps saved legacy/custom
  grants on each request; hiding navigation is not the authorization boundary.
- **Incidents and Admin News remain available to Owner/Admin**. Existing view and
  action permissions remain distinct; this does not grant Admins webhook secrets
  or Owner-only routing controls. Lower/custom roles cannot acquire reserved grants.
- **VPN/proxy protection is disabled by default**. The Owner can enable it from
  QSecurity with configuration preview, fresh authentication and existing WAN TOTP.
- Active UFW installations can drop listed VPN, open-proxy and Tor exit sources
  across IPv4/IPv6, on all inbound ports, before traffic reaches applications.
- Fixed HTTPS feeds, narrow false-positive exceptions, six-hour updates and
  offline cache restoration. Failed downloads retain previous valid lists.
- Separate firewall service; web/API/broker/observer capability limits are unchanged.
  Existing UFW service rules and manual bans are preserved. Minecraft remains optional
  and this add-on neither installs nor modifies its plugins.

## Installation and upgrading

Download the package matching your system's Python and amd64 architecture, plus
`SHA256SUMS`. Ubuntu 24.04 uses `py312`; Ubuntu 26.04 uses `py314`.

```sh
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./qsuite_1.1.0_py312_amd64.deb
qsuite version
```

The VPN add-on additionally needs an **already configured, active UFW** and `ipset`:
`sudo apt install ufw ipset`. QSuite does not enable/reset UFW for you. Installing
QSuite does not enable the VPN policy or start its refresh timer by default.
Preserve independent SSH/console access and snapshots before upgrading.

[Installation](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.1.0/docs/installation.md)
· [VPN guide](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.1.0/docs/vpn-protection.md)
· [Permissions](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.1.0/docs/permissions.md)
· [Documentation](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.1.0/docs/README.md)

## Supported systems and validation

Ubuntu 24.04 amd64/Python 3.12 and Ubuntu 26.04 amd64/Python 3.14 are the binary
targets. CI covers Debian 12/13 and both Ubuntu versions, with installed Ubuntu
systemd lifecycle qualification and synthetic IPv4/IPv6 firewall packet checks.
See the [release record](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.1.0/docs/release-readiness-v1.1.0.md).
No Debian-specific or ARM64 binary is supplied.

## Security and limits

IP lists cannot identify every VPN or residential proxy and can produce false
positives. Host filtering cannot prevent packets consuming the internet link;
upstream DDoS protection and account bans remain separate controls. QSuite has not
received an independent security audit/certification. Real reboot/power-loss,
mobile/terminal identity and cross-version binary upgrade drills remain outside
this qualification. Backup creation and production restore remain unavailable;
some diagnostic/recovery operations require audited adapters.

Report vulnerabilities privately using
[SECURITY.md](https://github.com/mrspersonalemail-stack/QSuite/blob/v1.1.0/SECURITY.md).
License remains MIT; bundled upstream notices are retained.

## Checksums

`SHA256SUMS` covers every attached wheel and Debian package. The release and
annotated tag are immutable after publication; GitHub supplies tagged source archives.
