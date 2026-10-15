import os
from pathlib import Path
import subprocess

import pytest

from qsuite.cli import bootstrap_password


def test_bootstrap_is_encrypted_and_secret_is_not_an_argument(tmp_path, monkeypatch):
    def encrypt(argv, **kwargs):
        assert len(kwargs["input"]) == 32
        assert kwargs["input"].decode() not in argv
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        Path(argv[-1]).write_bytes(b"encrypted-fixture")

    monkeypatch.setattr("qsuite.cli.subprocess.run", encrypt)
    password, path = bootstrap_password(str(tmp_path), "fixture_owner")
    assert len(password) == 32
    assert path.read_bytes() == b"encrypted-fixture"
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [path]
    with pytest.raises(ValueError, match="refusing overwrite"):
        bootstrap_password(str(tmp_path), "fixture_owner")


@pytest.mark.parametrize("username", ["../root", "a/b", "", "a" * 33, "a\n"])
def test_bootstrap_rejects_unsafe_name(tmp_path, username):
    with pytest.raises(ValueError, match="invalid username"):
        bootstrap_password(str(tmp_path), username)
    assert not list(tmp_path.iterdir())


def test_encryption_failure_leaves_no_credential(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "systemd-creds")

    monkeypatch.setattr("qsuite.cli.subprocess.run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        bootstrap_password(str(tmp_path), "owner")
    assert not list(tmp_path.iterdir())
