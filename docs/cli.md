# CLI reference

`qsuite --help` and subcommand `--help` show actual arguments. Global `--config FILE`
comes **before** the command. Most host operations require `sudo`; ordinary Linux
users are not given the API account's helper-socket privileges. Web roles do not
authorize local root operations.

```text
qsuite [--config FILE] status
qsuite version
qsuite [--config FILE] doctor
qsuite [--config FILE] backup
qsuite [--config FILE] restore verify latest
qsuite [--config FILE] incidents
qsuite [--config FILE] perf [1h|6h|24h|7d|30d]
qsuite [--config FILE] logs SERVICE_ID
qsuite [--config FILE] maintenance on|off
qsuite [--config FILE] security status|protocols|events|incidents
qsuite [--config FILE] user add [--username NAME] [--role ROLE] [--random]
qsuite install [qsuite|qsecurity] [--dry-run] [--units DIRECTORY]
qsuite [--config FILE] access lan|wan [--dry-run] [--bind IP] [--origin URL] [--cert FILE] [--key FILE]
qsuite [--config FILE] update PACKAGE.deb --sha256 VERIFIED_HASH
```

`backup` validates through an external adapter; it does not create an archive.
`incidents` captures a legacy bundle when configured; `security incidents` lists
native private incidents. Logs use an allowlisted configuration ID, not arbitrary
paths or unit names. `doctor` and maintenance need installed adapters. `install`
provisions both units/state foundations; its component label does not install an
independent package or workload. Dry-run does not start services or change firewall.

`user add` prompts on a local root terminal and refuses account replacement. With
explicit `--username --random`, a generated password is stored in a root-only
systemd-encrypted bootstrap credential; only its hash is stored in the account DB.
Retrieve that credential privately using the path printed by the command. Do not
paste decrypted credentials into logs/chat/issues. There is no CLI password-reset
subcommand; use authenticated account management and keep a separate Owner.

The native `qsecurity` executable supports:

```text
qsecurity [--config FILE] status|protocols|events|incidents
qsecurity [--config FILE] observe|daemon
qsecurity [--config FILE] baseline status|update
qsecurity [--config FILE] scan quick|full
```

Observation, scan and baseline approval need root. Scans require a separately
installed scanner and configured roots. `qsuite-agent`, `qsuite-helper`,
`qsuite-watchdog` are service entry points, not unrestricted user commands.

Legacy `qbackup`, `qdoctor`, `qperf`, `qwebhook`, `qalert` and other q* executables
may exist on migrated hosts but **are not shipped by QSuite**. Their interfaces and
privileges belong to that installation. See [packages](packages.md) for the fixed
adapter contract rather than assuming arbitrary legacy command syntax works.
