# Uninstall

First preserve QSuite configuration, both databases and recovery keys independently.
Removing the panel does not replace a backup of the workloads it observed.

```sh
sudo apt remove qsuite
```

Removal disables/stops **QSuite's** API, helper, QSecurity observer and watchdog timer.
It does not remove Crafty, Minecraft, their data, independent backup timers or SSH.
Check any external automation that relied on the panel before removing it.

Even `sudo apt purge qsuite` deliberately preserves service accounts, `/etc/qsuite`,
`/var/lib/qsuite`, `/var/lib/qsecurity`, `/var/lib/qsuite-watchdog`, terminal home,
versioned `/opt/qsuite` runtimes and independent snapshots/backups. That avoids silent
loss of encrypted secrets, audit evidence and recovery state. Package payload under
`/usr/lib/qsuite` and wrappers are removed by dpkg.

## Full cleanup

There is no automatic destructive purge command. Inventory the preserved QSuite-only
paths, verify an independently recoverable copy, check process/account ownership
and remove only the specifically reviewed resources through local administration.
Never recursively delete a parent backup directory, workload directory or generic
`/srv`, `/var/lib`, `/etc` path. Do not remove shared service accounts or external
adapters without checking their other consumers. Preserve incident evidence when
required. Reinstallation reuses protected configuration and credentials.
