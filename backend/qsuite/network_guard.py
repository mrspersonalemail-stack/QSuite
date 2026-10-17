"""Optional UFW VPN/proxy sets. Only the dedicated root service changes netfilter.

No downloaded code, per-player queries, arbitrary URLs or arbitrary firewall argv.
The observer and web broker keep their existing capability bounds.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit

from .config import check_root_file, load
from .package_config import atomic

ROOT = Path("/var/lib/qsecurity/network-guard")
UFW = Path("/etc/ufw")
BEGIN = "# BEGIN QSUITE VPN PROTECTION\n"
END = "# END QSUITE VPN PROTECTION\n"
ENTRY = "/opt/qsuite/current/venv/bin/qsuite-network-guard"
TIMER = "qsuite-network-guard-refresh.timer"
SOURCES = {
    "vpn4": ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", 1000),
    "vpn6": ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt", 50),
    "proxies": ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json", 10),
    "tor": ("https://onionoo.torproject.org/details?type=relay&running=true&flag=Exit&fields=exit_addresses", 100),
}


class GuardError(ValueError):
    """Only reviewed, non-secret operator diagnostics may use this exception."""


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        before, after = urlsplit(req.full_url), urlsplit(newurl)
        if after.scheme != "https" or after.netloc != before.netloc:
            raise GuardError("feed redirect to a different origin refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def run(argv, *, data=None, required=True):
    result = subprocess.run(  # noqa: S603 -- only fixed commands, validated IP literals and local paths
        argv, input=data, text=True, capture_output=True, timeout=90,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if required and result.returncode:
        print(Path(argv[0]).name + " diagnostic: " + result.stderr[-1500:], file=sys.stderr)
        raise GuardError(Path(argv[0]).name + " failed; inspect the dedicated service journal")
    return result


def network(value, family=None):
    item = ipaddress.ip_network(value, strict=True)
    if not item.is_global or item.prefixlen < (12 if item.version == 4 else 24):
        raise GuardError("non-public or excessively broad network in feed")
    if family and item.version != family:
        raise GuardError("feed address family mismatch")
    return item


def cache():
    path = ROOT / "cache.json"
    check_root_file(path)
    if path.stat().st_size > 8_000_000:
        raise GuardError("oversized cached feeds")
    value = json.loads(path.read_text())
    if set(value.get("feeds", {})) != set(SOURCES):
        raise GuardError("incomplete cached feeds")
    for name, rows in value["feeds"].items():
        if not SOURCES[name][1] <= len(rows) <= 100_000:
            raise GuardError("invalid cached feed size")
        for row in rows:
            network(row, 4 if name == "vpn4" else 6 if name == "vpn6" else None)
    return value


def download(previous=None):
    feeds, digests = {}, {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SameOriginRedirect())
    for name, (url, minimum) in SOURCES.items():
        req = urllib.request.Request(url, headers={"User-Agent": "QSuite-NetworkGuard/1"})  # noqa: S310 -- constant HTTPS sources
        with opener.open(req, timeout=25) as response:  # noqa: S310 -- fixed HTTPS source allowlist
            if response.geturl().split("/", 3)[:3] != url.split("/", 3)[:3]:
                raise GuardError("unexpected feed redirect")
            raw = response.read(6_000_001)
        if len(raw) > 6_000_000:
            raise GuardError("oversized feed")
        if name == "proxies":
            records = json.loads(raw)
            # Exit addresses are what the destination observes, even behind chained proxies.
            rows = [str(ipaddress.ip_address(row["exit_ip"])) for row in records]
        elif name == "tor":
            rows = [ip for relay in json.loads(raw)["relays"] for ip in relay.get("exit_addresses", [])]
        else:
            rows = [s.strip() for s in raw.decode("ascii").splitlines() if s.strip() and not s.startswith("#")]
        family = 4 if name == "vpn4" else 6 if name == "vpn6" else None
        nets = {network(row, family) for row in rows}
        if not minimum <= len(nets) <= 100_000:
            raise GuardError("feed size outside safety bounds")
        if previous and name.startswith("vpn"):
            old = len(previous["feeds"][name])
            if len(nets) < old / 2 or len(nets) > old * 2:
                raise GuardError("abrupt VPN feed size change; previous lists retained")
        feeds[name] = [str(n) for n in sorted(nets, key=lambda n: (n.version, int(n.network_address), n.prefixlen))]
        digests[name] = hashlib.sha256(raw).hexdigest()
    return {"updated": time.time(), "feeds": feeds, "sha256": digests}


def sets(value, exceptions):
    result = {"qng_deny4": [], "qng_deny6": [], "qng_allow4": [], "qng_allow6": []}
    for rows in value["feeds"].values():
        for row in rows:
            n = network(row)
            result["qng_deny" + str(n.version)].append(n)
    for row in exceptions:
        n = ipaddress.ip_network(row, strict=True)
        result["qng_allow" + str(n.version)].append(n)
    return {name: list(ipaddress.collapse_addresses(rows)) for name, rows in result.items()}


def apply_sets(values):
    names, swapped = list(values), []
    try:
        for name, rows in values.items():
            family = "inet6" if name.endswith("6") else "inet"
            for target in (name, name + "_next"):
                run(["/usr/sbin/ipset", "create", target, "hash:net", "family", family, "maxelem", "262144", "-exist"])
            text = "flush " + name + "_next\n"
            text += "".join("add " + name + "_next " + str(n) + "\n" for n in rows)
            run(["/usr/sbin/ipset", "restore"], data=text)
        for name in names:
            run(["/usr/sbin/ipset", "swap", name, name + "_next"])
            swapped.append(name)
    except BaseException:
        for name in reversed(swapped):
            run(["/usr/sbin/ipset", "swap", name, name + "_next"], required=False)
        raise
    finally:
        for name in names:
            run(["/usr/sbin/ipset", "destroy", name + "_next"], required=False)


def remove_block(text):
    if BEGIN not in text and END not in text:
        return text
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise GuardError("ambiguous managed UFW block")
    before, rest = text.split(BEGIN)
    _, after = rest.split(END)
    return before + after


def rule_block(v6=False):
    prefix, suffix = ("ufw6", "6") if v6 else ("ufw", "4")
    chain = prefix + "-qnetguard"
    return BEGIN + f""":{chain} - [0:0]
-A {prefix}-before-input -j {chain}
-A {chain} -i lo -j RETURN
-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j RETURN
-A {chain} -m set --match-set qng_allow{suffix} src -j RETURN
-A {chain} -m set --match-set qng_deny{suffix} src -m comment --comment qsecurity-vpn-proxy -j DROP
-A {chain} -j RETURN
""" + END


def firewall(enabled):
    """Modify only tagged UFW framework blocks, retaining unrelated rules and bans."""
    old = {}
    try:
        names = ("before.init", "before.rules", "before6.rules") if enabled else ("before.rules", "before6.rules", "before.init")
        for name in names:
            path = UFW / name
            check_root_file(path)
            text, mode = path.read_text(), path.stat().st_mode & 0o777
            clean = remove_block(text)
            after = clean
            if enabled:
                if name.endswith(".rules"):
                    marker = "# End required lines\n"
                    if clean.count(marker) != 1:
                        raise GuardError("unrecognized UFW framework layout")
                    after = clean.replace(marker, marker + rule_block(name == "before6.rules"), 1)
                else:
                    marker = 'case "$1" in'
                    if clean.count(marker) != 1:
                        raise GuardError("unrecognized UFW init hook")
                    fallback = "".join(
                        f"        /usr/sbin/ipset create {n} hash:net family {family} maxelem 262144 -exist\n"
                        for n, family in (("qng_deny4", "inet"), ("qng_deny6", "inet6"),
                                          ("qng_allow4", "inet"), ("qng_allow6", "inet6"))
                    )
                    hook = BEGIN + f'if [ "$1" = start ]; then\n    if ! {ENTRY} restore; then\n' + fallback + '        echo "QSecurity: offline restore unavailable; baseline UFW retained" >&2\n    fi\nfi\n' + END
                    after = clean.replace(marker, hook + marker, 1)
            if after != text:
                old[path] = (text, mode)
                # before.init is a supported UFW hook, not an independent nftables controller.
                atomic(path, after, 0o750 if name == "before.init" else mode)
        if old or observed() != enabled:
            for program, name in (("iptables-restore", "before.rules"), ("ip6tables-restore", "before6.rules")):
                run(["/usr/sbin/" + program, "--test", "--noflush"], data=(UFW / name).read_text())
            run(["/usr/sbin/ufw", "reload"])
            if observed() != enabled:
                raise GuardError("effective UFW VPN policy failed verification")
    except BaseException:
        for path, (text, mode) in old.items():
            atomic(path, text, mode)
        if old:
            run(["/usr/sbin/ufw", "reload"], required=False)
        raise


def observed():
    if not all(shutil.which(p) for p in ("iptables", "ip6tables")):
        return False
    return all(run(["/usr/sbin/" + program, "-C", chain, "-j", guard], required=False).returncode == 0
               for program, chain, guard in (("iptables", "ufw-before-input", "ufw-qnetguard"),
                                             ("ip6tables", "ufw6-before-input", "ufw6-qnetguard")))


def save_status(settings, value=None, *, phase="ready"):
    data = {"enabled": settings.security.vpn_protection_enabled, "active": observed(),
            "observed": time.time(), "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "phase": phase, "updated": value.get("updated") if value else None,
            "feed_counts": {k: len(v) for k, v in value["feeds"].items()} if value else {}}
    atomic(ROOT / "status.json", json.dumps(data), 0o600)
    return data


def status(settings):
    result = {"enabled": settings.security.vpn_protection_enabled, "active": False,
              "available": bool(shutil.which("ufw") and shutil.which("ipset") and Path(ENTRY).is_file()),
              "phase": "disabled", "updated": None, "observed": None, "feed_counts": {},
              "limitations": "Known exits only. Unlisted/residential proxies may evade IP lists; false positives are possible."}
    path = ROOT / "status.json"
    if path.exists():
        check_root_file(path)
        if path.stat().st_size > 16384:
            raise GuardError("network protection status too large")
        saved = json.loads(path.read_text())
        if saved.get("boot_id") == Path("/proc/sys/kernel/random/boot_id").read_text().strip():
            result.update({k: saved[k] for k in ("active", "phase", "updated", "observed", "feed_counts")})
    if result["enabled"] and not result["active"]:
        result["phase"] = "pending or degraded"
    elif result["enabled"] and (not result["updated"] or time.time() - result["updated"] > 43200):
        result["phase"] = "stale feeds; last valid lists retained"
    return result


def check_management(values):
    # Never activate a feed that would cut off an established SSH management peer.
    output = run(["/usr/bin/ss", "-Hnt", "state", "established", "( sport = :22 or sport = :2222 )"]).stdout
    for line in output.splitlines():
        peer = line.split()[3].rsplit(":", 1)[0].strip("[]")
        address = ipaddress.ip_address(peer)
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        denied = any(address in n for n in values["qng_deny" + str(address.version)])
        allowed = any(address in n for n in values["qng_allow" + str(address.version)])
        if denied and not allowed:
            raise GuardError("current SSH peer is listed; add a narrow VPN exception before enabling")


def execute(action):
    settings = load(privileged=True)
    if action == "status":
        return status(settings)
    if os.geteuid() != 0:
        raise GuardError("network operations require local root or the dedicated service")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_root_file(ROOT)
    with (ROOT / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        settings = load(privileged=True)
        enabled = settings.security.vpn_protection_enabled
        if not enabled:
            if (UFW / "before.rules").exists() and BEGIN in (UFW / "before.rules").read_text():
                firewall(False)
            if action == "reconcile":
                run(["/usr/bin/systemctl", "disable", "--now", TIMER])
            return save_status(settings)
        if not all(shutil.which(p) for p in ("ufw", "ipset", "iptables", "ip6tables")):
            raise GuardError("install UFW and ipset before enabling protection")
        if "Status: active" not in run(["/usr/sbin/ufw", "status"]).stdout:
            raise GuardError("UFW must already be active; QSuite will not enable/reset it")
        try:
            previous = cache() if (ROOT / "cache.json").exists() else None
        except (ValueError, OSError):
            # A corrupt cache must not permanently prevent recovery. Keep its
            # bytes/kernel sets until a wholly validated replacement is ready.
            previous = None
        if action == "restore":
            # UFW's own boot/reload hook cannot recursively take this lock. See main().
            raise GuardError("restore must run through the dedicated offline path")
        value = download(previous) if action == "refresh" or previous is None or time.time() - previous["updated"] > 21600 else previous
        values = sets(value, settings.security.vpn_allow_cidrs)
        check_management(values)
        apply_sets(values)
        atomic(ROOT / "cache.json", json.dumps(value), 0o600)
        if action == "reconcile":
            firewall(True)
            run(["/usr/bin/systemctl", "enable", "--now", TIMER])
        elif not observed():
            firewall(True)
        return save_status(settings, value)


def restore():
    """Offline, idempotent UFW hook; no lock/reload/download or service recursion.

    During a managed reload the outer service owns the lock and sets already exist.
    A lost cache must not prevent the rest of UFW from protecting the host.
    """
    if os.geteuid() != 0:
        raise GuardError("offline restoration requires root")
    settings = load(privileged=True)
    if not settings.security.vpn_protection_enabled:
        apply_sets({n: [] for n in ("qng_deny4", "qng_deny6", "qng_allow4", "qng_allow6")})
        return
    if all(run(["/usr/sbin/ipset", "list", name, "-terse"], required=False).returncode == 0
           for name in ("qng_deny4", "qng_deny6", "qng_allow4", "qng_allow6")):
        return
    try:
        apply_sets(sets(cache(), settings.security.vpn_allow_cidrs))
    except (ValueError, OSError):
        # Empty sets keep the baseline firewall bootable; the refresh timer will
        # fetch a valid cache. Report degraded rather than claiming protection.
        apply_sets({n: [] for n in ("qng_deny4", "qng_deny6", "qng_allow4", "qng_allow6")})
        print("QSecurity: VPN cache unavailable; UFW baseline retained, refresh required", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="QSecurity optional host VPN/proxy protection")
    parser.add_argument("action", choices=("status", "reconcile", "refresh", "restore"))
    args = parser.parse_args()
    try:
        if args.action == "restore":
            restore()
        else:
            print(json.dumps(execute(args.action)))
    except Exception as exc:
        # Do not dump provider response bodies or tracebacks into public jobs.
        if args.action == "refresh":
            try:
                save_status(load(privileged=True), cache(), phase="refresh failed; last valid lists retained")
            except (ValueError, OSError):
                pass
        diagnostic = str(exc) if isinstance(exc, GuardError) else type(exc).__name__
        print("QSecurity network protection failed: " + diagnostic, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
