# Migration and compatibility

QSuite is additive: preserve existing workload supervisors, legacy q* tools, timers,
credentials and independent recovery access. Introduce only reviewed read/status
adapters first. Validate their ownership, output, arguments and sandbox paths before
enabling mutation. Do not run a second Java supervisor or replace a backup producer.

Application schema migrations are separate from release versions. Schema 1 expands
accounts/roles/news/configuration in schema 2; schema 3 adds `backup.download` only
to built-in administrative roles. Legacy privileges remain explicit; custom roles
do not silently gain the download permission. Existing sessions and account hashes
are preserved subject to normal expiry and authorization.

Before a production migration, independently snapshot configuration/keys and both
SQLite stores, record service state, rehearse on isolated copies, and retain old
runtime/package artifacts. Never assume an old binary can read a new schema. See
[upgrading](upgrading.md) and [implementation status](implementation-status.md).
