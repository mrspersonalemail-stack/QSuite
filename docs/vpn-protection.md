# Optional VPN and proxy protection

This QSecurity add-on is **disabled by default**. It is independent of the security
observer's `enforce` setting and does not install or configure Minecraft plugins.
It currently supports an already active UFW firewall on Debian/Ubuntu with `ipset`.

## Enable or disable

1. Install the optional OS prerequisites: `sudo apt install ufw ipset`. Configure
   and enable UFW separately, preserving management access. QSuite never enables,
   resets or replaces your firewall policy.
2. Install the updated QSuite wheel/package and the bundled network guard units.
3. Open **QSecurity → VPN & proxy protection settings** (also in the QSecurity
   package settings). Enable the switch, preview, reauthenticate and apply.
4. Check the observed firewall state and feed timestamps in QSecurity. Disable
   through the same reviewed workflow. Disable before uninstalling this add-on.

QSecurity is **Owner-only** in v1.1.0. This uses `security.configure` and `packages.view`, existing CSRF, fresh
authentication and WAN TOTP requirements. `security.view` permits the Owner to view status.
Restricted roles do not acquire firewall controls or source-IP list access.
The privileged broker requests only a fixed systemd service, and retains its
existing capability boundary. The dedicated network service has `CAP_NET_ADMIN`
and `CAP_NET_RAW` (the iptables/ipset compatibility query opens a raw socket).

For local root administration, set `[security].vpn_protection_enabled` in
`/etc/qsuite/config.toml` and run:

```sh
sudo systemctl start qsuite-network-guard.service
sudo /opt/qsuite/current/venv/bin/qsuite-network-guard status
sudo journalctl -u qsuite-network-guard.service -u qsuite-network-guard-refresh.service
```

## What is blocked

Known VPN IPv4/IPv6 networks from [X4BNet's VPN-only feeds](https://github.com/X4BNet/lists_vpn),
verified open-proxy exit IPs from [monosans](https://github.com/monosans/proxy-list),
and running Tor exits' advertised exit addresses from [Tor Onionoo](https://metrics.torproject.org/onionoo.html).
Lists are downloaded over verified HTTPS; no downloaded code is executed and no
player IPs or credentials are sent to classification services. URLs are fixed.
The general datacenter feed is deliberately not used.

UFW-owned framework chains check both address families before normal inbound
allow/established rules, and silently **DROP** matches on every inbound port and
protocol. Loopback and replies to host-initiated connections are preserved.
An allow exception returns to normal UFW processing; it does not override other
bans or grant access to otherwise closed ports. Existing UFW rules stay intact.
An established SSH management peer matching the lists prevents activation until
an administrator supplies an explicit narrow exception.

## Updates and recovery

The enabled add-on enables its refresh timer, normally every six hours with up to
15 minutes jitter. An offline UFW boot hook restores the last validated cache.
Updates validate address families, public networks, prefix breadth, sizes and
unexpected VPN feed growth/shrinkage. Per-family kernel set swaps avoid empty
list windows; failed downloads keep the prior valid lists. Cache and status are
root-only under `/var/lib/qsecurity/network-guard`. Cache loss retains ordinary
UFW protection and reports degradation until refresh; it cannot claim VPN coverage.

`vpn_allow_cidrs = []` supplies explicit false-positive exceptions. Use exact IP
CIDRs where possible; exceptions cannot be broader than IPv4 /24 or IPv6 /48.
No exception is created automatically for an administrator's changing WAN IP.
Config application retains a rollback copy and replays the previous policy if
service application fails. UFW syntax validation precedes reload, and a failed
reload restores the previous framework files. Disabling removes only QSuite's
marked blocks and stops/disables its refresh timer.

The dashboard reports the **last observed** firewall state and successful feed
timestamp, not an assurance that unrelated root changes cannot alter netfilter.
Feeds older than 12 hours are reported stale. Inspect the dedicated unit journals
if updates fail; there is no real webhook transmission during activation.

## Limits

IP reputation is incomplete and can misclassify legitimate users. New/private VPNs,
residential proxies and changing exits can evade it. This does not bind a ban to a
person or replace account bans/authentication. Packets still reach the host/network
interface before the host firewall drops them; upstream filtering is required to
stop traffic consuming the internet link. No router changes or Minecraft changes
are made by this add-on.
