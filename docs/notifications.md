# Notifications

**Member News** is for reviewed community announcements: events, maintenance and
safe game status. **Admin News** is private: security/SSH/malware evidence, backup,
SMART, diagnostics, service failures and administrative incidents. Access and
routing are enforced in the backend, including ingress, history and delivery.
Security-sensitive and Admin-only event classes can never be routed to Member News.

In **Account & settings / notification controls**, the Owner configures independent
Discord webhooks for each channel. The same canonical endpoint cannot serve both.
Secrets are encrypted with the independent authentication key, write-only in the
UI/API and never included in health/status responses. Back up the database and
that key separately with appropriate protection.

Admin policy fields are `level_2_admin_user_id`, `l2_mentions_admin` and
`l3_plus_mentions_everyone`. Enter your own Discord numeric user ID locally; no
real target is included in examples or defaults. L0 remains local; L1 has no
mention; L2 can mention only the configured user; L3+ can allow `@everyone`.
Disabling those toggles suppresses the corresponding mentions. Member News never
permits role/user/everyone mentions. Body text cannot expand the mention allowlist.

Preview a public message, inspect its text, then send. Public filtering rejects
common credentials, IP addresses and private paths; this is not complete data-loss
prevention. Moderators remain responsible for reviewing human-authored text.
Tests are explicitly labelled TEST and do not create real containment actions.
L2 testing requires a configured administrator target.

The native outbox makes bounded attempts, uses exponential delays and honors
bounded rate-limit delays. Delivery is at-least-once: a crash after Discord accepts
a message can cause a duplicate. Health exposes queued/retry/failed/unconfigured
states without credentials. Configure first, then use the Owner's test/retry tools.
Network tests should use fake transports, never a production webhook.

CERBERUS receives a protected encrypted private policy snapshot; generation checks
prevent stale overwrite. It can fall back to a separately configured root-only
`security-webhook` legacy file. Ordinary legacy `qwebhook`/`qalert` binaries are
not shipped or replaced; see [packages](packages.md).
