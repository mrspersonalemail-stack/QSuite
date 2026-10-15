# Contributing to QSuite

Start with [development](docs/development.md) and [architecture](docs/architecture.md).
Use an isolated environment and run backend, frontend, release-boundary and migration
tests. Runtime dependencies are hash-locked; do not introduce unreviewed major upgrades.

For bugs include version, OS/Python, reproduction, expected/actual behavior and
sanitized evidence. Use feature requests to describe the problem and permission
boundary. Never post credentials, host inventories or private security incidents.
Use [private reporting](SECURITY.md) for vulnerabilities.

Pull requests should explain motivation, scope, tests, failure recovery, security
impact and compatibility. Add documentation for changed CLI/API/configuration.
Security-sensitive changes need negative authorization, injection, secret redaction
and rollback tests. Keep commits focused and reviewable. Do not remove safety checks
to make tests pass. No broad reformatting or arbitrary command execution endpoints.

Python uses Ruff conventions and closed Pydantic models. JavaScript uses local
assets and DOM text APIs rather than untrusted HTML. Frontend controls never replace
backend checks. Preserve vendor licenses/hashes and the existing MIT license.
See our [Code of Conduct](CODE_OF_CONDUCT.md).
