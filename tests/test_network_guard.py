import ipaddress
import json
from types import SimpleNamespace

import pytest

from qsuite import network_guard as ng
from qsuite.config import Settings
from qsuite.packages import SecurityConfig


@pytest.fixture
def feeds(monkeypatch):
    monkeypatch.setattr(ng, "SOURCES", {k: (v[0], 1) for k, v in ng.SOURCES.items()})
    return {"updated": 100, "feeds": {"vpn4": ["8.8.8.0/24"], "vpn6": ["2001:4860::/32"],
                                      "proxies": ["9.9.9.9/32"], "tor": ["11.1.1.1/32"]}}


def test_defaults_off_and_exceptions_are_narrow():
    assert Settings().security.vpn_protection_enabled is False
    assert SecurityConfig(trusted_cidrs=[], trusted_countries=[], trusted_continents=[], risk_weights={}).vpn_protection_enabled is False
    for value in ["true", 1]:
        with pytest.raises(ValueError):
            Settings(security={"vpn_protection_enabled": value})
    for value in ["0.0.0.0/0", "8.8.0.0/16", "::/0", "2001:4860::/32", "$(id)"]:
        with pytest.raises(ValueError):
            Settings(security={"vpn_allow_cidrs": [value]})


@pytest.mark.parametrize("value", ["0.0.0.0/0", "10.0.0.0/8", "127.0.0.1", "::1", "192.168.1.1", "8.8.8.0/7", "$(id)"])
def test_feed_cannot_include_private_or_broad_networks(value):
    with pytest.raises(ValueError):
        ng.network(value)


def test_rule_order_drops_all_inbound_protocols_without_bypassing_other_bans():
    for v6 in [False, True]:
        text = ng.rule_block(v6)
        assert text.index("ctdir REPLY") < text.index("-j DROP")
        assert "--match-set qng_allow" in text and "-j RETURN" in text
        assert "ACCEPT" not in text and "--dport" not in text


def test_set_update_failure_swaps_back_already_changed_sets(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[1:3] == ["swap", "qng_deny6"]:
            raise ValueError("fixture swap failure")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(ng, "run", run)
    with pytest.raises(ValueError):
        ng.apply_sets({"qng_deny4": [ipaddress.ip_network("8.8.8.8")], "qng_deny6": []})
    assert sum(a[1:3] == ["swap", "qng_deny4"] for a in calls) == 2
    assert any(a[1:3] == ["destroy", "qng_deny4_next"] for a in calls)


@pytest.fixture
def firewall_files(tmp_path, monkeypatch):
    monkeypatch.setattr(ng, "UFW", tmp_path)
    monkeypatch.setattr(ng, "check_root_file", lambda p: None)
    originals = {"before.rules": "*filter\n:ufw-before-input - [0:0]\n# End required lines\n-A ufw-before-input -s 8.8.4.4 -j DROP\nCOMMIT\n",
                 "before6.rules": "*filter\n:ufw6-before-input - [0:0]\n# End required lines\nCOMMIT\n",
                 "before.init": '#!/bin/sh\ncase "$1" in\nstart) ;;\nesac\n'}
    for name, text in originals.items():
        (tmp_path / name).write_text(text)
        (tmp_path / name).chmod(0o640)
    monkeypatch.setattr(ng, "observed", lambda: ng.BEGIN in (tmp_path / "before.rules").read_text())
    return tmp_path, originals


def test_firewall_enable_disable_preserves_other_rules_and_is_idempotent(firewall_files, monkeypatch):
    root, originals = firewall_files
    calls = []
    monkeypatch.setattr(ng, "run", lambda argv, **kw: calls.append(argv))
    ng.firewall(True)
    assert "-s 8.8.4.4 -j DROP" in (root / "before.rules").read_text()
    first = len(calls)
    ng.firewall(True)
    assert len(calls) == first
    ng.firewall(False)
    assert all((root / name).read_text() == text for name, text in originals.items())


def test_firewall_native_validation_failure_restores_files(firewall_files, monkeypatch):
    root, originals = firewall_files

    def fail(argv, **kw):
        if "--test" in argv:
            raise ValueError("fixture syntax failure")

    monkeypatch.setattr(ng, "run", fail)
    with pytest.raises(ValueError):
        ng.firewall(True)
    assert all((root / name).read_text() == text for name, text in originals.items())


def test_failed_download_keeps_cached_lists_and_kernel_sets(tmp_path, monkeypatch, feeds):
    monkeypatch.setattr(ng, "ROOT", tmp_path)
    monkeypatch.setattr(ng, "check_root_file", lambda p: None)
    monkeypatch.setattr(ng, "load", lambda **kw: Settings(security={"vpn_protection_enabled": True}))
    monkeypatch.setattr(ng.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ng.shutil, "which", lambda p: "/usr/sbin/" + p)
    monkeypatch.setattr(ng, "run", lambda *a, **k: SimpleNamespace(stdout="Status: active", returncode=0))
    monkeypatch.setattr(ng, "download", lambda previous: (_ for _ in ()).throw(ValueError("feed unavailable")))
    monkeypatch.setattr(ng, "apply_sets", lambda values: pytest.fail("sets must not change"))
    path = tmp_path / "cache.json"
    path.write_text(json.dumps(feeds))
    before = path.read_bytes()
    with pytest.raises(ValueError, match="feed unavailable"):
        ng.execute("refresh")
    assert path.read_bytes() == before


def test_ssh_management_peer_cannot_be_silently_blocked(monkeypatch):
    monkeypatch.setattr(ng, "run", lambda *a, **k: SimpleNamespace(stdout="0 0 192.0.2.1:2222 8.8.8.8:54321\n"))
    values = {"qng_deny4": [ipaddress.ip_network("8.8.8.8")], "qng_allow4": []}
    with pytest.raises(ValueError, match="SSH peer"):
        ng.check_management(values)
    values["qng_allow4"] = values["qng_deny4"]
    ng.check_management(values)


def test_offline_restore_lost_cache_keeps_ufw_bootable(monkeypatch):
    monkeypatch.setattr(ng.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ng, "load", lambda **kw: Settings(security={"vpn_protection_enabled": True}))
    monkeypatch.setattr(ng, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    monkeypatch.setattr(ng, "cache", lambda: (_ for _ in ()).throw(ValueError("lost cache")))
    applied = []
    monkeypatch.setattr(ng, "apply_sets", applied.append)
    ng.restore()
    assert len(applied) == 1 and len(applied[0]) == 4 and not any(applied[0].values())


def test_corrupt_cache_recovers_only_after_validated_download(tmp_path, monkeypatch, feeds):
    monkeypatch.setattr(ng, "ROOT", tmp_path)
    monkeypatch.setattr(ng, "check_root_file", lambda p: None)
    monkeypatch.setattr(ng, "load", lambda **kw: Settings(security={"vpn_protection_enabled": True}))
    monkeypatch.setattr(ng.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ng.shutil, "which", lambda p: "/usr/sbin/" + p)
    monkeypatch.setattr(ng, "run", lambda *a, **k: SimpleNamespace(stdout="Status: active", returncode=0))
    monkeypatch.setattr(ng, "check_management", lambda values: None)
    monkeypatch.setattr(ng, "observed", lambda: True)
    monkeypatch.setattr(ng, "save_status", lambda settings, value: value)
    monkeypatch.setattr(ng, "download", lambda previous: feeds if previous is None else pytest.fail("corrupt cache trusted"))
    applied = []
    monkeypatch.setattr(ng, "apply_sets", applied.append)
    path = tmp_path / "cache.json"
    path.write_text("not-json")
    assert ng.execute("refresh") == feeds
    assert applied and json.loads(path.read_text()) == feeds


def test_download_uses_actual_proxy_exit_addresses_and_fixed_sources(monkeypatch, feeds):
    bodies = {"vpn4": b"8.8.8.0/24\n", "vpn6": b"2001:4860::/32\n",
              "proxies": b'[{"host":"8.8.4.4","exit_ip":"9.9.9.9"}]',
              "tor": b'{"relays":[{"exit_addresses":["11.1.1.1"]}]}'}

    class Response:
        def __init__(self, url):
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def geturl(self):
            return self.url

        def read(self, limit):
            assert limit <= 6_000_001
            return next(bodies[name] for name, (url, _) in ng.SOURCES.items() if url == self.url)

    monkeypatch.setattr(ng.urllib.request, "build_opener", lambda *handlers: SimpleNamespace(open=lambda req, timeout: Response(req.full_url)))
    result = ng.download()
    assert result["feeds"]["proxies"] == ["9.9.9.9/32"]
    assert result["feeds"]["vpn6"] == ["2001:4860::/32"]
    assert len(result["sha256"]) == 4
    before = feeds | {"feeds": feeds["feeds"] | {"vpn4": ["8.8.8.0/24"] * 4}}
    with pytest.raises(ValueError, match="abrupt VPN"):
        ng.download(before)


def test_redirects_cannot_contact_another_origin_or_plain_http():
    request = ng.urllib.request.Request(ng.SOURCES["vpn4"][0])
    for target in ["http://raw.githubusercontent.com/list", "https://evil.invalid/", "https://127.0.0.1/"]:
        with pytest.raises(ValueError, match="different origin"):
            ng.SameOriginRedirect().redirect_request(request, None, 302, "redirect", {}, target)
