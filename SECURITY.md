# Security policy

## Release support

QSuite v1.1.0 is the current stable release. Fixes target the latest 1.1.x release.
Older development snapshots have no maintenance guarantee.
No independent security audit or certification is
claimed. Monitor releases and review changes before installing administrative tools.

## Responsible disclosure

Report vulnerabilities privately to
[qsuite-reports@proton.me](mailto:qsuite-reports@proton.me). Do not post exploitable
security details in public issues. If GitHub private vulnerability reporting is
enabled, **Security → Report a vulnerability** is another supported channel. If
that form is absent, use the dedicated inbox. This is a project reporting address,
not a personal account recovered from metadata.

Include affected version/OS, threat assumptions, impact, a minimal isolated
reproduction and sanitized evidence. Never include passwords, tokens, webhooks,
sessions, TOTP/recovery codes, private keys or raw production databases/logs. Use a
disposable environment; do not probe systems you do not own. Coordinate disclosure
before public discussion. Maintainers will make reasonable efforts to acknowledge
and investigate reports, without promising a fixed response time or bounty.

## Scope and trust

Authentication/session/CSRF/RBAC, Member/Admin separation, root broker/PTY boundaries,
configuration validation, archive downloads, package provenance and private state
handling are in scope. The browser has no generic root execution API. A compromised
agent can still invoke its closed privileged allowlist. Root or compromised kernel
can access local secrets; local audit storage is not independently tamper-proof.

WAN uses HTTPS, exact Host/Origin, secure cookies and fresh authentication/TOTP for
sensitive actions. Optional CA trust never permits HTTP or bypasses identity/key
checks. No root terminal, production restore or automatic containment is exposed.
Read the [security model](docs/security.md), [QSecurity limitations](docs/qsecurity.md)
and [implementation status](docs/implementation-status.md).
