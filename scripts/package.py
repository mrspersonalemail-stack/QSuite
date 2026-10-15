#!/usr/bin/env python3
"""Data-preserving Debian package lifecycle. Runs under dpkg's root context."""

import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

UNITS = ["qsuite-agent.service", "qsuite-helper.service", "qsecurity.service", "qsuite-watchdog.timer"]
STATE = Path("/var/lib/qsuite-watchdog")


def active_units():
    return [unit for unit in UNITS if subprocess.run(  # noqa: S603 -- fixed allowlist
        ["/usr/bin/systemctl", "is-active", "--quiet", unit], check=False
    ).returncode == 0]


def resume_units(state=STATE):
    resume = state / "package-services.json"
    if not resume.exists():
        return
    units = json.loads(resume.read_text())
    if not isinstance(units, list) or any(not isinstance(unit, str) or unit not in UNITS for unit in units):
        raise ValueError("invalid service resume state")
    if units:
        subprocess.run(["/usr/bin/systemctl", "start", *units], check=True)  # noqa: S603
        for unit in units:
            subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], check=True)  # noqa: S603
    resume.unlink()


def main():
    action = sys.argv[1]
    if action == "preserve":
        # Explicitly preserve accounts, configuration, databases, quarantine and backups, even on purge.
        return
    if action == "stop":
        if Path("/run/systemd/system").exists():
            operation = "disable" if len(sys.argv) > 2 and sys.argv[2] == "remove" else "stop"
            STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
            resume = STATE / "package-services.json"
            if operation == "stop":
                if not resume.exists():
                    resume.write_text(json.dumps(active_units()))
                    resume.chmod(0o600)
                marker = STATE / "maintenance.json"
                marker.write_text(
                    json.dumps({"until": int(time.time()) + 600, "reason": "verified package lifecycle"})
                )
                marker.chmod(0o600)
            else:
                resume.unlink(missing_ok=True)
            argv = ["/usr/bin/systemctl", operation]
            if operation == "disable":
                argv.append("--now")
            subprocess.run([*argv, *UNITS], check=False)  # noqa: S603
        return
    if action != "install":
        raise ValueError("invalid package lifecycle action")
    if len(sys.argv) > 2 and sys.argv[2] != "configure":
        return
    if platform.freedesktop_os_release().get("ID") not in {"debian", "ubuntu"}:
        raise ValueError("installation requires Debian or Ubuntu")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("installation requires a running systemd service manager")
    base = Path("/usr/lib/qsuite")
    version = (base / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid package version")
    manifest = json.loads((base / "wheels.json").read_text())
    actual = {p.name for p in (base / "wheelhouse").iterdir() if p.is_file() and not p.is_symlink()}
    if not manifest or set(manifest) != actual or len(list((base / "wheelhouse").iterdir())) != len(actual):
        raise ValueError("wheel manifest must cover every payload file")
    if [name for name in manifest if name.startswith("qsuite-")] != [f"qsuite-{version}-py3-none-any.whl"]:
        raise ValueError("package version and wheel differ")
    for name, expected in manifest.items():
        if Path(name).name != name or not name.endswith(".whl"):
            raise ValueError("invalid wheel manifest")
        if hashlib.sha256((base / "wheelhouse" / name).read_bytes()).hexdigest() != expected:
            raise ValueError("wheel hash mismatch")
    destination = Path("/opt/qsuite") / version
    destination.mkdir(parents=True, exist_ok=True, mode=0o755)
    venv = destination / "venv"
    if not (venv / "bin/python").exists():
        subprocess.run(["/usr/bin/python3", "-m", "venv", str(venv)], check=True)  # noqa: S603
    subprocess.run(  # noqa: S603 -- offline verified package installation
        [
            str(venv / "bin/python"),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(base / "wheelhouse"),
            f"qsuite=={version}",
        ],
        check=True,
    )  # noqa: S603
    wheel = next((base / "wheelhouse").glob("qsuite-*.whl"))
    subprocess.run(  # noqa: S603 -- verified offline installation argv
        [
            str(venv / "bin/python"),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            str(wheel),
        ],
        check=True,
    )  # noqa: S603
    current = destination.parent / "current"
    pending = destination.parent / "current.new"
    pending.unlink(missing_ok=True)
    pending.symlink_to(destination)
    pending.replace(current)
    if Path("/run/systemd/system").exists():
        subprocess.run([str(venv / "bin/qsuite"), "install"], check=True)  # noqa: S603
        subprocess.run([str(venv / "bin/qsuite-watchdog"), "--baseline-update"], check=True)  # noqa: S603
        resume_units()
        (STATE / "maintenance.json").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
