"""Root-owned typed configuration, optimistic preview and rollback on verification failure."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import re

from .config import Settings, check_root_file, load
from .packages import CONFIG_MODELS


def toml(values):
    lines = []

    def section(value, prefix=""):
        scalar = {k: v for k, v in value.items() if not isinstance(v, dict) and v is not None}
        nested = {k: v for k, v in value.items() if isinstance(v, dict)}
        if prefix:
            lines.append("\n[" + prefix + "]")
        for k, v in scalar.items():
            key = k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k)
            lines.append(key + " = " + json.dumps(v, ensure_ascii=False))
        for k, v in nested.items():
            key = k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k)
            section(v, (prefix + "." if prefix else "") + key)

    section(values)
    return "\n".join(lines) + "\n"


def atomic(path, data, mode=0o644):
    fd, name = tempfile.mkstemp(prefix=".qsuite-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(name).unlink(missing_ok=True)


def current(settings, package):
    if package == "qsecurity":
        return (
            CONFIG_MODELS[package]
            .model_validate({k: getattr(settings.security, k) for k in CONFIG_MODELS[package].model_fields})
            .model_dump()
        )
    if package in {"qperf", "qsmart", "qmaintenance"}:
        values = {name: getattr(settings, name) for name in CONFIG_MODELS[package].model_fields}
        if package == "qperf" and settings.integration.performance_config:
            path = Path(settings.integration.performance_config)
            if path.exists():
                check_root_file(path)
                content = json.loads(path.read_text())
                if (
                    set(content) != {"history_days"}
                    or type(content["history_days"]) is not int
                    or not 1 <= content["history_days"] <= 90
                ):
                    raise ValueError("invalid legacy retention configuration")
                values["history_days"] = content["history_days"]
        return values
    if package == "qbackup":
        state = Path(settings.package_dir).parent / "package-config.json"
        if state.exists():
            check_root_file(state)
            if state.stat().st_size > 16384:
                raise ValueError("package state too large")
            return (
                CONFIG_MODELS[package]
                .model_validate(json.loads(state.read_text()).get(package, {}))
                .model_dump()
            )
        return CONFIG_MODELS[package]().model_dump()
    raise ValueError("package has no implemented configuration adapter")


def proposal(settings, package, values):
    model = CONFIG_MODELS.get(package)
    if not model:
        raise ValueError("configuration unavailable")
    validated = model.model_validate(values).model_dump()
    before = current(settings, package)
    root = settings.model_dump()
    if package == "qsecurity":
        import ipaddress
        from .protocols import PROTOCOLS

        if set(validated["risk_weights"]) - set(PROTOCOLS):
            raise ValueError("unknown risk protocol")
        if any(ipaddress.ip_network(value, strict=True).prefixlen == 0 for value in validated["trusted_cidrs"]):
            raise ValueError("trusting every network is not permitted")
        root["security"] |= validated
    elif package in {"qperf", "qsmart", "qmaintenance"}:
        if package == "qmaintenance":
            from .news import validate_public

            validate_public("Maintenance announcement", validated["maintenance_message"])
        root |= validated
    elif package == "qbackup" and package not in settings.integration.package_timers:
        raise ValueError("no audited backup validation timer configured")
    proposed = Settings.model_validate(root)
    return before, validated, proposed


def operation(config_path, request, apply=False, *, runner=None, timer_root=Path("/etc/systemd/system")):
    path = Path(config_path)
    settings = load(path, privileged=True)
    if not isinstance(request, dict) or set(request) - {"package", "values", "expected"}:
        raise ValueError("invalid configuration request")
    package = request["package"]
    before, after, proposed = proposal(settings, package, request["values"])
    config_before = path.read_text()
    state_path = path.parent / "package-config.json"
    state_before = state_path.read_text() if state_path.exists() else None
    if state_path.exists():
        check_root_file(state_path)
    perf_path = (
        Path(settings.integration.performance_config)
        if package == "qperf" and settings.integration.performance_config
        else None
    )
    if perf_path and perf_path.exists():
        check_root_file(perf_path)
    perf_before = perf_path.read_text() if perf_path and perf_path.exists() else None
    timer = settings.integration.package_timers.get(package)
    dropin = timer_root / (timer + ".d") / "qsuite.conf" if timer else None
    dropin_before = None
    if dropin and dropin.exists():
        check_root_file(dropin)
        dropin_before = dropin.read_text()
    revision = hashlib.sha256(
        (config_before + (state_before or "") + (dropin_before or "") + (perf_before or "")).encode()
    ).hexdigest()
    result = {
        "package": package,
        "before": before,
        "after": after,
        "expected": revision,
        "changes": [k for k in after if before.get(k) != after[k]],
        "applies_to": timer or "native QSuite configuration",
    }
    if not apply:
        return result
    if request.get("expected") != revision:
        raise ValueError("configuration changed; preview again")
    if not result["changes"]:
        return result | {"applied": False, "verified": True}
    if runner is None:
        from .installer import command

        runner = command
    lockpath = path.parent / ".package-config.lock"
    if lockpath.exists():
        check_root_file(lockpath)
    with lockpath.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Recheck under lock; never overwrite concurrent owner edits.
        if (
            path.read_text() != config_before
            or (state_path.read_text() if state_path.exists() else None) != state_before
            or (dropin.read_text() if dropin and dropin.exists() else None) != dropin_before
            or (perf_path.read_text() if perf_path and perf_path.exists() else None) != perf_before
        ):
            raise ValueError("configuration changed; preview again")
        backup = path.parent / ("config.pre-package-" + str(time.time_ns()) + ".toml")
        atomic(backup, config_before, 0o600)
        bundle = backup.with_suffix(".bundle")
        bundle.mkdir(mode=0o700)
        saved = []
        for n, (target, contents) in enumerate(
            (
                (path, config_before),
                (state_path, state_before),
                (dropin, dropin_before),
                (perf_path, perf_before),
            )
        ):
            if target:
                saved.append({"destination": str(target), "file": str(n) if contents is not None else None})
                if contents is not None:
                    atomic(bundle / str(n), contents, 0o600)
        atomic(bundle / "manifest.json", json.dumps(saved, indent=2), 0o600)
        try:
            atomic(path, toml(proposed.model_dump()))
            if perf_path:
                check_root_file(perf_path.parent)
                atomic(perf_path, json.dumps({"history_days": after["history_days"]}), 0o600)
            if package == "qbackup":
                state = json.loads(state_before or "{}")
                state[package] = after
                atomic(state_path, json.dumps(state))
            if timer:
                dropin.parent.mkdir(mode=0o755, exist_ok=True)
                check_root_file(dropin.parent)
                text = "[Timer]\n"
                text += (
                    ("OnCalendar=\nOnCalendar=" + after["validation_schedule"] + "\n")
                    if package == "qbackup"
                    else ("OnUnitActiveSec=\nOnUnitActiveSec=" + str(after["sample_seconds"]) + "s\n")
                )
                atomic(dropin, text)
                runner(["/usr/bin/systemctl", "daemon-reload"])
                runner(["/usr/bin/systemctl", "restart", timer])
                runner(["/usr/bin/systemctl", "is-active", "--quiet", timer])
            validated = load(path, privileged=True)
            if current(validated, package) != after:
                raise ValueError("persisted configuration failed verification")
        except BaseException:
            atomic(path, config_before)
            if perf_path:
                if perf_before is not None:
                    atomic(perf_path, perf_before, 0o600)
                else:
                    perf_path.unlink(missing_ok=True)
            if state_before is not None:
                atomic(state_path, state_before)
            elif state_path.exists():
                state_path.unlink()
            if dropin:
                if dropin_before is not None:
                    atomic(dropin, dropin_before)
                else:
                    dropin.unlink(missing_ok=True)
                runner(["/usr/bin/systemctl", "daemon-reload"])
                runner(["/usr/bin/systemctl", "restart", timer])
            raise
    return result | {
        "applied": True,
        "verified": True,
        "rollback": backup.name,
        "rollback_bundle": bundle.name,
    }
