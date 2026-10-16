import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "scripts" / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def test_package_builder_normalizes_writable_umask(tmp_path, monkeypatch):
    builder = module("qsuite_deb_builder", "build-deb.py")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / "qsuite-1.0.0-py3-none-any.whl").write_bytes(b"isolated fixture, not an installable wheel")

    def fake_build(argv, **kwargs):
        staging = Path(argv[-2])
        for path in staging.rglob("*"):
            assert not path.stat().st_mode & 0o022, path
        Path(argv[-1]).write_bytes(b"isolated package fixture")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(builder.subprocess, "run", fake_build)
    before = os.umask(0o002)
    try:
        output = builder.build(wheels, tmp_path / "out", "amd64", 14, "1.0.0")
    finally:
        os.umask(before)
    assert output.with_suffix(".deb.sha256").is_file()


def test_purge_preserves_all_data_without_commands(monkeypatch):
    package = module("qsuite_package_lifecycle", "package.py")
    monkeypatch.setattr(package.sys, "argv", ["package.py", "preserve", "purge"])
    monkeypatch.setattr(
        package.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("purge must preserve data")),
    )
    package.main()


def test_package_unknown_action_fails_before_mutation(monkeypatch):
    import pytest

    package = module("qsuite_package_lifecycle_invalid", "package.py")
    monkeypatch.setattr(package.sys, "argv", ["package.py", "unexpected"])
    with pytest.raises(ValueError, match="lifecycle"):
        package.main()


def test_builder_refuses_unrelated_payload_and_old_version(tmp_path):
    import pytest
    from qsuite import __version__

    builder = module("release_builder", "build-deb.py")
    assert builder.source_version(Path(__file__).parents[1]) == __version__
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / f"qsuite-{__version__}-py3-none-any.whl").write_bytes(b"fixture")
    (wheels / "unrelated.txt").write_text("must never be bundled")
    with pytest.raises(ValueError, match="only regular wheel"):
        builder.build(wheels, tmp_path / "out", "amd64", 14, __version__)
    with pytest.raises(ValueError, match="version"):
        builder.build(wheels, tmp_path / "out", "amd64", 14, "0.0.0")


def test_postrm_is_self_contained_after_payload_removal(tmp_path, monkeypatch):
    from qsuite import __version__

    builder = module("release_removal_builder", "build-deb.py")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / f"qsuite-{__version__}-py3-none-any.whl").write_bytes(b"fixture")

    def inspect(argv, **kwargs):
        text = (Path(argv[-2]) / "DEBIAN/postrm").read_text()
        assert "/usr/lib/qsuite" not in text
        assert "exit 0" in text
        Path(argv[-1]).write_bytes(b"fixture")

    monkeypatch.setattr(builder.subprocess, "run", inspect)
    builder.build(wheels, tmp_path / "out", "amd64", 14, __version__)


def test_record_only_allowlisted_active_units(monkeypatch):
    package = module("release_service_resume", "package.py")
    seen = []

    def run(argv, **kwargs):
        seen.append(argv)
        return SimpleNamespace(returncode=0 if argv[-1] == "qsuite-helper.service" else 3)

    monkeypatch.setattr(package.subprocess, "run", run)
    assert package.active_units() == ["qsuite-helper.service"]
    assert len(seen) == len(package.UNITS)
    assert all(argv[-1] in package.UNITS for argv in seen)


def test_install_refuses_unsupported_host_before_payload_access(monkeypatch):
    import pytest

    package = module("release_host_guard", "package.py")
    monkeypatch.setattr(package.sys, "argv", ["package.py", "install", "configure"])
    monkeypatch.setattr(package.platform, "freedesktop_os_release", lambda: {"ID": "unsupported"})
    with pytest.raises(ValueError, match="Debian or Ubuntu"):
        package.main()


def test_upgrade_resumes_and_verifies_each_saved_unit(tmp_path, monkeypatch):
    import json

    package = module("release_resume_verify", "package.py")
    state = tmp_path / "package-services.json"
    state.write_text(json.dumps(["qsuite-helper.service", "qsuite-agent.service"]))
    calls = []
    monkeypatch.setattr(package.subprocess, "run", lambda argv, **kw: calls.append(argv))
    package.resume_units(tmp_path)
    assert calls == [
        ["/usr/bin/systemctl", "start", "qsuite-helper.service", "qsuite-agent.service"],
        ["/usr/bin/systemctl", "is-active", "--quiet", "qsuite-helper.service"],
        ["/usr/bin/systemctl", "is-active", "--quiet", "qsuite-agent.service"],
    ]
    assert not state.exists()


def test_failed_resume_preserves_recovery_state(tmp_path, monkeypatch):
    import json
    import subprocess
    import pytest

    package = module("release_resume_failure", "package.py")
    state = tmp_path / "package-services.json"
    state.write_text(json.dumps(["qsuite-agent.service"]))

    def fail(argv, **kw):
        raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(package.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        package.resume_units(tmp_path)
    assert state.exists()
    state.write_text(json.dumps(["ssh.service"]))
    with pytest.raises(ValueError, match="resume state"):
        package.resume_units(tmp_path)


def test_vm_qualification_refuses_non_hosted_environment_before_commands(tmp_path, monkeypatch):
    import pytest

    qualification = module("release_vm_qualification", "qualify-deb.py")
    monkeypatch.setattr(qualification.os, "geteuid", lambda: 0)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    monkeypatch.setenv("QSUITE_DISPOSABLE_QUALIFICATION", "yes")
    monkeypatch.setattr(qualification, "run", lambda *a: (_ for _ in ()).throw(AssertionError("no mutation")))
    with pytest.raises(RuntimeError, match="disposable VM"):
        qualification.qualify(tmp_path / "unused.deb", tmp_path / "report.json")
