#!/usr/bin/env python3
"""Build an offline-installable, Python-minor-specific Debian package.

Resolve and hash-lock wheels before invoking this script. Build separately for
each Python minor/architecture; do not label ABI-specific wheels architecture-all.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def source_version(root):
    """Read the canonical literal without importing application dependencies."""
    module = ast.parse((root / "backend/qsuite/__init__.py").read_text())
    for node in module.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError("canonical source version missing")


def build(wheelhouse: Path, destination: Path, architecture: str, minor: int, version: str):
    root = Path(__file__).resolve().parent.parent
    if not wheelhouse.is_dir() or not list(wheelhouse.glob("qsuite-*.whl")):
        raise ValueError("wheelhouse must include the built QSuite wheel and all locked dependencies")
    if architecture not in {"amd64", "arm64"} or minor not in {11, 12, 13, 14}:
        raise ValueError("unsupported build target")
    if version != source_version(root):
        raise ValueError("build version must match the current source version")
    wheels = sorted(wheelhouse.iterdir())
    if any(p.is_symlink() or not p.is_file() or p.suffix != ".whl" for p in wheels):
        raise ValueError("wheelhouse must contain only regular wheel files")
    if [p.name for p in wheels if p.name.startswith("qsuite-")] != [f"qsuite-{version}-py3-none-any.whl"]:
        raise ValueError("wheelhouse must contain exactly the current QSuite wheel")
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"qsuite_{version}_py3{minor}_{architecture}.deb"
    with tempfile.TemporaryDirectory(prefix="qsuite-deb-") as directory:
        staging = Path(directory)
        debian = staging / "DEBIAN"
        debian.mkdir()
        control = (root / "packaging/debian/control.in").read_text()
        for name, value in {
            "VERSION": version,
            "ARCH": architecture,
            "PYMIN": f">= 3.{minor}",
            "PYMAX": f"<< 3.{minor + 1}",
        }.items():
            control = control.replace(f"@{name}@", value)
        (debian / "control").write_text(control)
        files = staging / "usr/lib/qsuite"
        files.mkdir(parents=True)
        (files / "wheelhouse").mkdir()
        for wheel in wheels:
            shutil.copyfile(wheel, files / "wheelhouse" / wheel.name)
        (files / "VERSION").write_text(version + "\n")
        shutil.copytree(root / "packaging/systemd", files / "systemd")
        manifest = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((files / "wheelhouse").glob("*.whl"))
        }
        (files / "wheels.json").write_text(json.dumps(manifest, indent=2))
        # Maintainer shell only invokes the bundled Python provisioner; no network installer.
        for name, action in [("postinst", "install"), ("prerm", "stop")]:
            script = debian / name
            script.write_text(
                f'#!/bin/sh\nset -eu\nexec /usr/bin/python3 /usr/lib/qsuite/package.py {action} "$@"\n'
            )
            script.chmod(0o755)
        # dpkg removes the payload before postrm. Preservation cannot invoke a
        # Python file that no longer exists, including during purge.
        postrm = debian / "postrm"
        postrm.write_text("#!/bin/sh\nset -eu\n# Preserve all configuration and state, including on purge.\nexit 0\n")
        postrm.chmod(0o755)
        shutil.copyfile(root / "scripts/package.py", files / "package.py")
        bin_dir = staging / "usr/bin"
        bin_dir.mkdir(parents=True)
        for name in ("qsuite", "qsecurity"):
            wrapper = bin_dir / name
            wrapper.write_text(f'#!/bin/sh\nexec /opt/qsuite/current/venv/bin/{name} "$@"\n')
            wrapper.chmod(0o755)
        # A builder umask must never create writable privileged package directories.
        staging.chmod(0o755)
        for item in staging.rglob("*"):
            if item.is_dir():
                item.chmod(0o755)
            elif item.is_file():
                item.chmod(0o755 if item.stat().st_mode & 0o111 else 0o644)
        if "SOURCE_DATE_EPOCH" in os.environ:
            epoch = int(os.environ["SOURCE_DATE_EPOCH"])
            if epoch < 0:
                raise ValueError("invalid source date epoch")
            for item in [*staging.rglob("*"), staging]:
                os.utime(item, (epoch, epoch))
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(staging), str(output)], check=True)  # noqa: S603,S607
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".deb.sha256").write_text(f"{checksum}  {output.name}\n")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--python-minor", type=int, required=True)
    args = parser.parse_args()
    print(build(args.wheelhouse, args.output, args.architecture, args.python_minor, source_version(Path(__file__).resolve().parent.parent)))
