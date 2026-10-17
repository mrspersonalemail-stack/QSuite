# Development

Use an isolated Python 3.11+ virtual environment. Installation targets Debian/Ubuntu;
unit development on another Linux host does not qualify its service packaging.

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/ruff check backend tests scripts
.venv/bin/mypy --follow-imports=skip --ignore-missing-imports \
  backend/qsuite/config.py backend/qsuite/permissions.py backend/qsuite/notifications.py
node --check backend/qsuite/web/app.js
node --check backend/qsuite/web/ui.js
node --check backend/qsuite/web/center.js
node --test tests/frontend.test.cjs
.venv/bin/python scripts/check-release.py
```

Mypy currently covers those three boundary modules; this is not a claim of complete
backend type checking. The frontend is plain JavaScript, without TypeScript or a
transpilation build. Node syntax/tests and asset inspection are its checks.

## Source ownership

See [architecture](architecture.md). Reuse canonical permissions, closed request
models and explicit broker operations. No `shell=True`, arbitrary root command,
frontend-only authorization, unsafe HTML or production test fixtures. Public/private
news must remain isolated at every stage. Add negative and failure-path tests for
boundary changes. Keep vendor version/hash/license metadata synchronized.

`backend/qsuite/__init__.py` is the authoritative version; setuptools reads its
attribute. The Debian builder reads the same literal and emits a VERSION payload
for the package lifecycle. API/CLI/frontend settings consume the runtime version.

## Build offline packages

On the exact target Python minor/architecture with `dpkg-deb` available:

```sh
.venv/bin/pip install build
.venv/bin/python -m build
mkdir -p dist/wheelhouse
.venv/bin/pip download --require-hashes --only-binary=:all: \
  -r requirements.lock -d dist/wheelhouse
cp dist/qsuite-1.1.0-py3-none-any.whl dist/wheelhouse/
.venv/bin/python scripts/build-deb.py --wheelhouse dist/wheelhouse \
  --architecture amd64 --python-minor 14 --output dist
```

Use an empty wheelhouse per version/target; only regular wheel files are accepted.
Run `python scripts/inspect-artifacts.py dist` and run
`scripts/smoke-package.py` with the wheel installed in a clean virtual environment.
Audit dependencies, generate SHA256SUMS, then qualify
install, service start, Owner/login, registry, migration/upgrade, failure recovery
and removal in a disposable systemd VM. Never run those drills on a production host.
CI container tests do not prove PID-1 service behavior, reboot or hardware isolation.

Public exports exclude deployment files, `.local`, environments, databases, logs,
secrets and build output. Run the release checker plus Gitleaks directory/history
scans before committing/pushing; inspect false positives without logging values.
A secret in any commit requires rotation and reviewed history remediation.

[Contributing](../CONTRIBUTING.md) · [Release checklist](release-readiness.md)
