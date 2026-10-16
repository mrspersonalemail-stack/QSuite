#!/usr/bin/env python3
"""Inspect prepared source, wheel and Debian payloads without installing services."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile


def unsafe_wheel_modes(archive, version):
    # WheelFile writes its generated RECORD hash index with mode 0664.
    # That upstream metadata convention is not an executable/code payload;
    # pip's install umask controls the installed file's actual permissions.
    # Keep the exception exact and reject writable code/data or world write.
    return any((item.external_attr >> 16) & 0o022
               and not (item.filename == f"qsuite-{version}.dist-info/RECORD"
                        and ((item.external_attr >> 16) & 0o777) == 0o664)
               for item in archive.infolist())


def inspect(directory, dpkg_deb="dpkg-deb"):
    wheels = list(directory.glob("qsuite-*-py3-none-any.whl"))
    sources = list(directory.glob("qsuite-*.tar.gz"))
    packages = list(directory.glob("qsuite_*.deb"))
    if len(wheels) != 1 or len(sources) != 1 or not packages:
        raise ValueError("expected one wheel/source and at least one Debian target")
    wheel = wheels[0]
    version = wheel.name.split("-")[1]
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            raise ValueError("wheel CRC failure")
        names = archive.namelist()
        if unsafe_wheel_modes(archive, version):
            raise ValueError("writable application wheel member")
        if any(n.startswith("/") or ".." in Path(n).parts or not n.startswith(("qsuite/", f"qsuite-{version}.dist-info/")) for n in names):
            raise ValueError("unexpected wheel payload")
        if f"qsuite-{version}.dist-info/licenses/LICENSE" not in names or "qsuite/web/XTERM-LICENSE" not in names:
            raise ValueError("wheel license missing")
    with tarfile.open(sources[0]) as archive:
        for member in archive.getmembers():
            if member.mode & 0o022:
                raise ValueError("writable source distribution member")
            parts = Path(member.name).parts
            if member.issym() or member.islnk() or member.name.startswith("/") or ".." in parts:
                raise ValueError("unsafe source member")
            if any(p in {".local", ".git", ".venv", "deployments", "node_modules", "__pycache__"} for p in parts):
                raise ValueError("private/generated source member")
        names = {n.name for n in archive.getmembers()}
        for required in ["LICENSE", "README.md", "SECURITY.md", "CHANGELOG.md", "scripts/build-deb.py", "tests/test_downloads.py", "docs/README.md", "docs/release-readiness.md"]:
            if f"qsuite-{version}/{required}" not in names:
                raise ValueError("incomplete source distribution: " + required)
    for package in packages:
        metadata = subprocess.check_output([dpkg_deb, "--field", str(package), "Package", "Version", "Architecture"], text=True)  # noqa: S603
        if "Package: qsuite\n" not in metadata or f"Version: {version}\n" not in metadata:
            raise ValueError("Debian metadata mismatch")
        payload = subprocess.check_output([dpkg_deb, "--fsys-tarfile", str(package)])  # noqa: S603
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            if any(m.uid != 0 or m.gid != 0 or m.isdev() or m.issym() or m.islnk() for m in archive.getmembers()):
                raise ValueError("Debian owner or member type mismatch")
        with tempfile.TemporaryDirectory(prefix="qsuite-payload-review-") as tmp:
            root = Path(tmp)
            subprocess.run([dpkg_deb, "--raw-extract", str(package), str(root)], check=True)  # noqa: S603
            for p in root.rglob("*"):
                if p.is_symlink() or p.stat().st_mode & 0o022:
                    raise ValueError("writable/symlink package member")
                if p.is_file() and not (str(p.relative_to(root)).startswith(("usr/lib/qsuite/", "DEBIAN/")) or str(p.relative_to(root)) in {"usr/bin/qsuite", "usr/bin/qsecurity"}):
                    raise ValueError("unexpected Debian payload")
            base = root / "usr/lib/qsuite"
            if (base / "VERSION").read_text().strip() != version:
                raise ValueError("Debian runtime version mismatch")
            manifest = json.loads((base / "wheels.json").read_text())
            if set(manifest) != {p.name for p in (base / "wheelhouse").iterdir()}:
                raise ValueError("incomplete wheel manifest")
            for name, expected in manifest.items():
                if hashlib.sha256((base / "wheelhouse" / name).read_bytes()).hexdigest() != expected:
                    raise ValueError("wheel digest mismatch")
            if (base / "wheelhouse" / wheel.name).read_bytes() != wheel.read_bytes():
                raise ValueError("outer/embedded QSuite wheels differ")
            if "/usr/lib/qsuite" in (root / "DEBIAN/postrm").read_text():
                raise ValueError("postrm depends on removed payload")
        print(package.name + ": metadata, allowlisted payload, permissions and manifest PASS")
    print("Python wheel/source contents and licenses PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--dpkg-deb", default="dpkg-deb")
    args = parser.parse_args()
    inspect(args.directory, args.dpkg_deb)
