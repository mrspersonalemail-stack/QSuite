import json
from pathlib import Path

import pytest

from qsuite import package_config
from qsuite.config import load
from qsuite.packages import registry


@pytest.fixture
def config_path(tmp_path, settings, monkeypatch):
    monkeypatch.setattr(package_config, "check_root_file", lambda p: None)
    monkeypatch.setattr("qsuite.config.check_root_file", lambda p: None)
    path = tmp_path / "config.toml"
    settings = settings.model_copy(update={"package_dir": str(tmp_path / "packages.d")})
    path.write_text(package_config.toml(settings.model_dump()))
    return path


def test_preview_apply_and_stale_revision(config_path):
    values = package_config.current(load(config_path), "qperf") | {"sample_seconds": 600}
    request = {"package": "qperf", "values": values}
    preview = package_config.operation(config_path, request)
    assert load(config_path).sample_seconds == 300
    result = package_config.operation(config_path, request | {"expected": preview["expected"]}, apply=True)
    assert result["verified"] and load(config_path).sample_seconds == 600
    assert Path(config_path.parent / result["rollback"]).read_text()
    assert (config_path.parent / result["rollback_bundle"] / "manifest.json").is_file()
    # Existing renewal/trust helpers edit bare top-level TOML keys by anchored regex.
    import re

    assert re.search(r"^origin\s*=", config_path.read_text(), re.M)
    assert re.search(r"^require_trusted_tls\s*=", config_path.read_text(), re.M)
    with pytest.raises(ValueError, match="preview again"):
        package_config.operation(config_path, request | {"expected": preview["expected"]}, apply=True)


@pytest.mark.parametrize(
    "values", [{"sample_seconds": 0}, {"sample_seconds": "$(reboot)"}, {"command": "sudo reboot"}]
)
def test_typed_package_config_rejects_commands_and_malformed_values(config_path, values):
    original = config_path.read_bytes()
    with pytest.raises(ValueError):
        package_config.operation(config_path, {"package": "qperf", "values": values})
    assert config_path.read_bytes() == original


def test_qsecurity_validation_refuses_unsafe_network_and_protocol(config_path):
    values = package_config.current(load(config_path), "qsecurity")
    with pytest.raises(ValueError):
        package_config.operation(
            config_path, {"package": "qsecurity", "values": values | {"trusted_cidrs": ["0.0.0.0/$(reboot)"]}}
        )
    with pytest.raises(ValueError, match="unknown risk"):
        package_config.operation(
            config_path, {"package": "qsecurity", "values": values | {"risk_weights": {"SHELL": 100}}}
        )


def test_timer_verification_failure_restores_all_config_and_dropin(config_path, tmp_path):
    settings = load(config_path)
    data = settings.model_dump()
    data["integration"]["package_timers"] = {"qbackup": "fixture-validation.timer"}
    config_path.write_text(package_config.toml(data))
    original = config_path.read_bytes()
    root = tmp_path / "units"
    root.mkdir()
    dropin = root / "fixture-validation.timer.d"
    dropin.mkdir()
    (dropin / "qsuite.conf").write_text("[Timer]\nOnCalendar=*-*-* 06:00:00\n")
    before = (dropin / "qsuite.conf").read_text()
    request = {"package": "qbackup", "values": {"validation_schedule": "*-*-* 07:00:00"}}
    preview = package_config.operation(config_path, request, timer_root=root)
    calls = []

    def runner(argv):
        calls.append(argv)
        if "is-active" in argv:
            raise RuntimeError("fixture timer failed validation")

    with pytest.raises(RuntimeError):
        package_config.operation(
            config_path, request | {"expected": preview["expected"]}, True, runner=runner, timer_root=root
        )
    assert config_path.read_bytes() == original
    assert (dropin / "qsuite.conf").read_text() == before
    assert not (config_path.parent / "package-config.json").exists()
    assert sum("daemon-reload" in a for a in calls) == 2


def test_manifest_cannot_weaken_status_or_action_authorization(tmp_path, monkeypatch):
    monkeypatch.setattr("qsuite.packages.check_root_file", lambda p: None)
    path = tmp_path / "qextra.json"
    manifest = {
        "name": "qextra",
        "label": "Extra",
        "permission": "minecraft.view",
        "status": "security.status",
    }
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="status capability"):
        registry(tmp_path)
    manifest |= {
        "permission": "security.view",
        "actions": {
            "bad": {
                "label": "Bypass",
                "permission": "minecraft.view",
                "operation": "security.baseline",
                "target": "update",
                "fresh_auth": False,
            }
        },
    }
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="authorization contract"):
        registry(tmp_path)


def test_manifest_adds_reviewed_capability_without_browser_shell(tmp_path, monkeypatch):
    monkeypatch.setattr("qsuite.packages.check_root_file", lambda p: None)
    manifest = {
        "name": "qextra",
        "label": "Extra",
        "permission": "security.view",
        "status": "security.status",
        "actions": {
            "quick": {
                "label": "Quick",
                "permission": "security.scan",
                "operation": "security.scan",
                "target": "quick",
            }
        },
    }
    (tmp_path / "qextra.json").write_text(json.dumps(manifest))
    assert registry(tmp_path)["qextra"].actions["quick"].target == "quick"


def test_legacy_retention_config_applies_and_is_in_rollback_bundle(config_path, tmp_path):
    data = load(config_path).model_dump()
    path = tmp_path / "performance.conf"
    path.write_text('{"history_days": 30}')
    data["integration"]["performance_config"] = str(path)
    config_path.write_text(package_config.toml(data))
    values = package_config.current(load(config_path), "qperf") | {"history_days": 60}
    request = {"package": "qperf", "values": values}
    preview = package_config.operation(config_path, request)
    result = package_config.operation(config_path, request | {"expected": preview["expected"]}, True)
    assert json.loads(path.read_text()) == {"history_days": 60}
    bundle = config_path.parent / result["rollback_bundle"]
    entries = json.loads((bundle / "manifest.json").read_text())
    before = next(e for e in entries if e["destination"] == str(path))
    assert json.loads((bundle / before["file"]).read_text()) == {"history_days": 30}


def test_public_maintenance_configuration_rejects_diagnostics(config_path):
    with pytest.raises(ValueError, match="public announcement"):
        package_config.operation(
            config_path,
            {"package": "qmaintenance", "values": {"maintenance_message": "SSH compromised 192.0.2.4"}},
        )
