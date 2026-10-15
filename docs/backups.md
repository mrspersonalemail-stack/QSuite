# Backups and recovery

QSuite can list and download existing completed ZIP archives from an explicitly
configured `integration.backup_root`. It does **not** create them. A producer such
as Crafty remains responsible for consistent snapshots, schedule, destination and
retention. No native Crafty backup API/token workflow is implemented in v1.0.0.

## Download to your computer

Open **Backups & restore**, choose **Download**, and reauthenticate. The browser
streams the archive to its Downloads location without buffering it all in JavaScript.
`backup.view` and `backup.download` are separate permissions. Downloads require fresh
authentication and, in WAN mode, TOTP. Secure same-origin sessions apply.

Two concurrent transfers are allowed. GET/HEAD, single byte ranges, suffix resume,
ETag/If-Range and bounded streaming are supported. Changing archives abort the
transfer. Authorization is rechecked periodically; expiry/revocation terminates it.
Use the browser's resume function only while the archive still has the same identity.
The configured directory and all ancestors reject symlinks; only regular,
single-link ZIP basenames with a completed trailer are opened. A download is not
CRC, world or database validation. Audit “sent” means bytes sent, not proof saved.

## Validation and isolated restore checks

`sudo qsuite backup` invokes an installed fixed `backup_validate` adapter with
`validate`. `sudo qsuite restore verify latest` invokes `restore_verify --verify latest`.
Neither adapter is bundled. Install/review them separately and provide the minimum
helper sandbox write paths they require. GUI controls do not turn an absent adapter
into a working feature. Backup package settings change an audited **validation**
timer, not the producer's schedule or retention.

**Production restore is unavailable.** Never extract untrusted backups over live
services. Verify in an isolated directory/machine, inspect expected files, CRC and
application/database integrity, then plan a separate operator-controlled cutover.
Keep original damaged data and recovery evidence. Retain corruption warnings until
logical recovery is independently demonstrated.

## Recovery confidence

Age, archive CRC, application consistency, offsite copy and recoverability are
separate facts. Same-disk archives do not protect against loss of the disk. Maintain
independent copies and recovery keys, test restores, monitor capacity and reserve
space. No automatic pruning is performed by QSuite to solve low storage.

For QSuite itself, snapshot SQLite through its online backup API, check integrity,
protect snapshots mode 0600 and preserve `/etc/qsuite` secrets independently. Package
updates snapshot the application database/configuration; this is not a complete
backup of QSecurity or workload data. WAL/FULL sync and fsynced writes reduce some
power-loss risks; use a UPS and separately stored copies. They cannot repair faulty
hardware or guarantee world integrity.

[Recovery concepts](disaster-recovery.md) · [Upgrading](upgrading.md)
