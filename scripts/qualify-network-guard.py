#!/usr/bin/env python3
"""Native packet qualification, exclusively on disposable GitHub-hosted VMs."""

import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time

from qsuite import network_guard as guard
from qsuite.config import load
from qsuite.package_config import current, operation, atomic


def run(*argv, required=True):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=90)  # noqa: S603 -- fixed fixture commands
    if required and result.returncode:
        raise RuntimeError("native network qualification command failed: " + argv[0] + ": " + result.stderr[-2000:])
    return result


def main():
    if os.geteuid() != 0 or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.environ.get("QSUITE_DISPOSABLE_QUALIFICATION") != "yes":
        raise RuntimeError("refusing network qualification outside a disposable hosted VM")
    config = Path("/etc/qsuite/config.toml")
    original = config.read_text()
    assert not load(privileged=True).security.vpn_protection_enabled
    assert "Status: inactive" in run("ufw", "status").stdout
    root = guard.ROOT
    root.mkdir(mode=0o700, exist_ok=True)
    # No external lookups: use only synthetic public-address fixtures on a veth pair.
    feeds = {
        "vpn4": [str(ipaddress.ip_network(str(ipaddress.ip_address("8.0.0.0") + i))) for i in range(1000)],
        "vpn6": [str(ipaddress.ip_network(str(ipaddress.ip_address("2001:4860:ffff::") + i))) for i in range(50)],
        "proxies": [f"9.0.0.{i}/32" for i in range(1, 11)],
        "tor": [f"11.0.0.{i}/32" for i in range(1, 101)],
    }
    atomic(root / "cache.json", json.dumps({"updated": time.time(), "feeds": feeds, "sha256": {}}), 0o600)
    dropin = Path("/etc/systemd/system/qsuite-network-guard-refresh.timer.d")
    dropin.mkdir(mode=0o755, exist_ok=True)
    atomic(dropin / "qualification.conf", "[Timer]\nOnBootSec=\nOnBootSec=1h\nRandomizedDelaySec=0\n")
    run("systemctl", "daemon-reload")

    def policy(enabled, exceptions=None):
        values = current(load(privileged=True), "qsecurity")
        values |= {"vpn_protection_enabled": enabled, "vpn_allow_cidrs": exceptions or []}
        request = {"package": "qsecurity", "values": values}
        preview = operation(config, request)
        operation(config, request | {"expected": preview["expected"]}, apply=True)

    def ping(v6=False):
        args = ["ip", "netns", "exec", "qng-qualification", "ping", "-6" if v6 else "-4", "-n", "-c", "1", "-W", "2", "2001:4860:ffff::1" if v6 else "8.0.0.1"]
        return run(*args, required=False).returncode == 0

    try:
        run("ufw", "allow", "22/tcp")
        run("ufw", "--force", "enable")
        run("ip", "netns", "add", "qng-qualification")
        run("ip", "link", "add", "qng-host", "type", "veth", "peer", "name", "qng-peer")
        run("ip", "link", "set", "qng-peer", "netns", "qng-qualification")
        run("ip", "link", "set", "qng-host", "up")
        run("ip", "netns", "exec", "qng-qualification", "ip", "link", "set", "lo", "up")
        run("ip", "netns", "exec", "qng-qualification", "ip", "link", "set", "qng-peer", "up")
        run("ip", "address", "add", "8.0.0.1/30", "dev", "qng-host")
        run("ip", "-6", "address", "add", "2001:4860:ffff::1/126", "dev", "qng-host", "nodad")
        run("ip", "netns", "exec", "qng-qualification", "ip", "address", "add", "8.0.0.2/30", "dev", "qng-peer")
        run("ip", "netns", "exec", "qng-qualification", "ip", "-6", "address", "add", "2001:4860:ffff::2/126", "dev", "qng-peer", "nodad")
        assert ping() and ping(True), "baseline veth reachability failed"
        policy(True)
        assert guard.observed()
        assert not ping() and not ping(True), "listed source reached host despite DROP policy"
        for binary, chain in [("iptables", "ufw-qnetguard"), ("ip6tables", "ufw6-qnetguard")]:
            rows = run(binary, "-nvxL", chain).stdout.splitlines()
            drop = next(row for row in rows if "qsecurity-vpn-proxy" in row)
            assert int(drop.split()[0]) > 0, "native DROP counter did not increase"
        policy(True, ["8.0.0.2/32", "2001:4860:ffff::2/128"])
        assert ping() and ping(True), "explicit exceptions failed"
        run("ufw", "reload")
        assert guard.observed() and ping() and ping(True), "UFW reload lost policy or exceptions"
        policy(False)
        assert not guard.observed() and ping() and ping(True), "disable failed to restore baseline reachability"
        assert run("systemctl", "is-enabled", guard.TIMER, required=False).returncode != 0
        # Empty kernel sets simulate a fresh boot without touching the host's ruleset.
        for name in ("qng_deny4", "qng_deny6", "qng_allow4", "qng_allow6"):
            run("ipset", "destroy", name)
        values = load(privileged=True).model_dump()
        values["security"]["vpn_protection_enabled"] = True
        from qsuite.package_config import toml

        atomic(config, toml(values))
        run(guard.ENTRY, "restore")
        assert run("ipset", "test", "qng_deny4", "8.0.0.2", required=False).returncode == 0
        assert run("ipset", "test", "qng_deny6", "2001:4860:ffff::2", required=False).returncode == 0
        print("Native VPN qualification PASS: default-off, IPv4/IPv6 DROP counters, exceptions, reload, disable, offline cache restore")
    finally:
        atomic(config, original)
        run("systemctl", "start", "qsuite-network-guard.service", required=False)
        run("ufw", "--force", "disable", required=False)
        run("ip", "link", "delete", "qng-host", required=False)
        run("ip", "netns", "delete", "qng-qualification", required=False)
        (dropin / "qualification.conf").unlink(missing_ok=True)
        run("systemctl", "daemon-reload", required=False)


if __name__ == "__main__":
    main()
