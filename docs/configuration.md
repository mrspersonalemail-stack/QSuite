# Configuration

The root-owned example is [config.example.toml](../config.example.toml).
`/etc/qsuite/config.toml` contains non-secret policy. `/etc/qsuite/secrets/` is
root-only and contains the authentication encryption key and optional encrypted
bootstrap/independent notification credentials. Never put credentials into TOML.
No `.env` file is used by the application.

Precedence: CLI `--config` where supported, then `QSUITE_CONFIG`, then
`/etc/qsuite/config.toml`. Settings are strict: unknown keys, unsafe paths, invalid
unit names, shared API/terminal identities and invalid origins are rejected.
Privileged readers also require root ownership and non-writable ancestors.

| Section / keys | Meaning |
| --- | --- |
| `mode`, `access`, `bind`, `port`, `origin` | Production/development, LAN/WAN, listen address and exact browser origin |
| `tls_cert`, `tls_key`, `require_trusted_tls` | Local certificate paths and WAN CA policy |
| `terminal_enabled` | Explicit opt-in for separate-identity PTY |
| `session_seconds`, `idle_seconds`, `reauth_seconds` | Bounded session policies |
| `sample_seconds`, `history_days`, `audit_days` | Native telemetry and retention |
| `[services]` | Arbitrary IDs mapped to locally approved systemd units |
| `[integration]` | Optional archive/game/metrics paths and Crafty unit |
| `[integration.legacy_commands]` | Fixed reviewed executable adapters, not shell strings |
| `[integration.package_timers]` | Audited qbackup/qperf timers only |
| `[security]` | Explicit trust lists, risk weights, scan roots and protected files |

Defaults have no game root/port, geographic trust region, DDNS credential, webhook,
server UUID or personal account. `security.enforce` is reserved; it does not activate
bans or lockdown. The optional integration fields and limits are defined in
[`config.py`](../backend/qsuite/config.py).

**Packages → module → settings** uses typed preview/apply and retains rollback
copies. Native sampling/threshold policy is reread by workers. Root access-mode
CLI changes restart the API; manual edits to startup settings require an explicit
restart. Service maps and integration paths are startup configuration: restart the
helper/API after review. A Settings TLS-trust toggle persists policy for subsequent
startup checks; it does not replace certificate files or enable plaintext HTTP.

`CREDENTIALS_DIRECTORY` is supplied by systemd for private runtime credentials.
Never replace it with a world-readable secret directory. Webhook configuration and
custom roles live in private application SQLite. The watchdog's private copy is
root-owned and encrypted. Make protected backups before major edits.

[Access modes](access-modes.md) · [Packages](packages.md) · [Upgrading](upgrading.md)
