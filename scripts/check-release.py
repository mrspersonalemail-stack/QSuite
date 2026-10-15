#!/usr/bin/env python3
"""Offline public-source boundary, documentation, version and vendor checks.

This complements an independent secret scanner; it does not replace one.
Only file names and rule names are reported, never matched private values.
"""

import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ["backend", "frontend", "tests", "scripts", "docs", "packaging", ".github"]
EXCLUDED = {"__pycache__", "node_modules", ".pytest_cache"}


def files():
    for directory in PUBLIC:
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and not EXCLUDED.intersection(path.parts) and not any(part.endswith(".egg-info") for part in path.parts) and not path.name.endswith(".pyc"):
                yield path
    for name in ["README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md", "LICENSE", "config.example.toml", "pyproject.toml", "requirements.lock", ".gitignore", ".gitleaks.toml", "MANIFEST.in"]:
        yield ROOT / name


def check():
    errors = []
    paths = list(files())
    for path in paths:
        if path.is_symlink():
            errors.append((path, "public symlink"))
        if path.suffix in {".db", ".sqlite", ".key", ".pem", ".cred", ".zip", ".deb", ".whl", ".log"}:
            errors.append((path, "runtime/archive/secret file"))
        if path.stat().st_size > 2 * 1024 * 1024:
            errors.append((path, "oversized public file"))
        if path.suffix == ".png":
            continue  # Screenshots need separate visual review.
        text = path.read_text(encoding="utf-8")
        # Credential patterns are intentionally structural, not copied live secrets.
        patterns = {
            "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "provider token": r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{25,}",
            "deployment path": r"/home/[^/\s]+/(?:ChatGPT|\.ssh)/",
        }
        for label, pattern in patterns.items():
            if re.search(pattern, text):
                errors.append((path, label))
        if path.suffix == ".md":
            for target in re.findall(r"!?\[[^\]]*\]\(([^\s)]+)\)", text):
                if target.startswith(("https://", "http://", "mailto:", "#")):
                    continue
                target = unquote(target.split("#")[0])
                if not (path.parent / target).exists():
                    errors.append((path, "broken relative link: " + target))
    version_module = ast.parse((ROOT / "backend/qsuite/__init__.py").read_text())
    version = next(ast.literal_eval(n.value) for n in version_module.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in n.targets))
    if version != "1.0.0":
        errors.append((ROOT / "backend/qsuite/__init__.py", "release version mismatch"))
    manifest = json.loads((ROOT / "frontend/vendor-manifest.json").read_text())
    for name, expected in manifest["files"].items():
        if hashlib.sha256((ROOT / "backend/qsuite/web" / name).read_bytes()).hexdigest() != expected:
            errors.append((ROOT / "backend/qsuite/web" / name, "vendor digest mismatch"))
    if (ROOT / "frontend/XTERM-LICENSE").read_bytes() != (ROOT / "backend/qsuite/web/XTERM-LICENSE").read_bytes():
        errors.append((ROOT / "frontend/XTERM-LICENSE", "vendor license mismatch"))
    # Never let a manually staged private file bypass the explicit public inventory.
    staged = subprocess.check_output(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"], cwd=ROOT, text=True).splitlines()  # noqa: S603,S607
    allowed = {str(p.relative_to(ROOT)) for p in paths}
    for name in staged:
        if name not in allowed:
            errors.append((ROOT / name, "outside public inventory"))
    for path, error in errors:
        print(f"{path.relative_to(ROOT)}: {error}")
    print(f"Checked {len(paths)} public files; {len(errors)} errors. Independent secret scan and visual review still required.")
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(check())
