# Upgrading

Ubuntu 24.04/26.04 amd64 clean installation and same-version reinstall/resume are
qualified for v1.0.0. Schema migration and failed-migration recovery are covered by
automated tests. Older-version binary upgrades, reboot and full software/database
rollback have not been qualified; preserve independent recovery copies.

1. Read release notes, verify provenance, Python minor, architecture and checksum.
2. Keep SSH/console access. Record active QSuite and managed-workload services.
3. Independently back up configuration, authentication encryption key, both databases
   through SQLite's online backup API, and workload data. Protect snapshots and keys.
4. Use the local verified package:

```sh
sudo qsuite update ./qsuite_1.0.0_py314_amd64.deb --sha256 VERIFIED_SHA256
```

The update command checks package identity/hash and snapshots the application DB and
configuration under `/var/backups/qsuite`. It sets finite watchdog maintenance. This
is not a complete backup of QSecurity, TLS material, other credentials or workloads.
The package records active QSuite units before stopping them and resumes those units
after a successful install. A new install stays stopped for onboarding. No Crafty
or game unit is restarted by the package itself.

Application migrations are transactional and reject schemas newer than supported.
Known schema 1/2 upgrades preserve an online rollback snapshot and refuse to overwrite
an existing one. Schema is not the application release number. Never delete an
unreviewed rollback snapshot simply to force a migration.

After upgrade, check `qsuite version`, `systemctl --failed`, HTTPS login, roles/CSRF,
news isolation, QSecurity heartbeat and watchdog; compare managed workload state
with the inventory. A successful dpkg exit alone does not prove readiness.

## Failure and rollback

Keep old versioned runtimes and verified packages. A failed package step can leave
QSuite stopped or dpkg unconfigured. Preserve journals and snapshots; use SSH for
recovery. Do not merely repoint `/opt/qsuite/current` if schema has changed.
Validate the old runtime with the matching database snapshot in isolation before
an operator-controlled switch. Full automated transactional software/database
rollback is not implemented. Preserve current failed state as evidence and never
overwrite workload data as part of a panel repair.

[Recovery](disaster-recovery.md) · [Uninstall](uninstall.md)
