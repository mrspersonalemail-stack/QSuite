# QSuite v1.1.0 release validation

The release must be tagged only after the exact final commit passes the existing
CI matrix and installed lifecycle checks. This record describes the gate scope;
the immutable tag, GitHub Actions run and attached checksums identify its evidence.
The v1.0.0 validation record remains historical and unchanged.

## Required gates

- Backend regression suite, including Owner-only API/package/log access, legacy
  and custom-role ceilings, retained Admin Incidents/Admin News, and existing
  authentication, CSRF, session, notification isolation and migration checks.
- VPN unit checks for default-off, strict/narrow configuration, public feed
  validation, set-swap rollback, failed-download preservation, UFW framework
  rollback/idempotency, management-peer protection and lost-cache boot fallback.
- Ruff, scoped mypy, JavaScript syntax/frontend tests, dependency checks/advisory
  audit, public-source/version/vendor/link inspection and source/history secret scans.
- Four isolated container targets: Debian 12/13 and Ubuntu 24.04/26.04.
- Ubuntu 24.04/26.04 hosted systemd VMs: clean installation, HTTPS/Owner/session/
  CSRF/package discovery, same-version reinstall and removal/purge preservation.
- On those disposable VMs only: synthetic veth/network-namespace IPv4/IPv6
  reachability before activation, actual DROP counters after activation, explicit
  exceptions, UFW reload, disable and offline cache restoration. No external VPN
  traffic, production world or real notification webhook is used in these checks.
- Inspect wheel/source/DEB paths, ownership/modes, notices, scripts and wheel hashes;
  match published packages to successful installed qualification hashes. Download
  public assets back and verify the published SHA256SUMS and release attestation.

## Boundaries and deployment

QSecurity and security logs are Owner-only, while Incidents/Admin News require
Owner/Admin. Role ceilings apply to saved grants without requiring a destructive
database migration. Existing sessions resolve current effective permissions.

VPN protection defaults off. Only an explicitly enabled installation modifies its
UFW-owned framework blocks and enables the feed timer. The optional network service
has CAP_NET_ADMIN/CAP_NET_RAW; existing web/helper/observer bounds are not widened.
UFW/ipset remain optional prerequisites. The default fresh install stays stopped.

The qserver pilot enabled the policy explicitly, preserved existing bans/rules and
verified SSH/HTTPS access. Minecraft/Crafty were not modified or restarted. Native
packet and install/remove drills run only on disposable CI hosts.

## Limits

List coverage is incomplete; residential/unlisted proxies can evade it and
legitimate IPs can be misclassified. Host filtering is not upstream bandwidth
protection. Actual reboot/power-loss, mobile/terminal identity acceptance,
cross-version binary upgrade and Debian installed/ARM64 qualification are not
claimed. Type coverage remains scoped. One upstream non-failing TestClient
deprecation warning remains. No independent audit or certification is claimed.
