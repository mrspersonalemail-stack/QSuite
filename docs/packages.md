# Packages and compatibility adapters

QSuite ships one Python/Debian distribution. The 13 package-center entries are
modules/capabilities, not 13 separately published Debian packages. All share the
installed QSuite version unless a separately installed adapter reports otherwise.

| Module | Purpose / GUI | Actual CLI | View / action permissions | Dependency and configuration |
| --- | --- | --- | --- | --- |
| qsecurity | Security observer / QSecurity | `qsuite security status`; `qsecurity` | `security.view`, `security.scan`, `security.baseline` | Native observer; optional ClamAV; `[security]` |
| qbackup | Existing ZIP archives / Backups | `qsuite backup` validates | `backup.view`, `backup.download`, `backup.run` | Optional backup root; validation executable/timer adapter |
| qrestore | Isolated restore verification / Backups | `qsuite restore verify latest` | `backup.view`, `backup.restore` | Separately installed restore-verification adapter |
| qstatus | Host inventory / Dashboard, Server | `qsuite status` | `system.view` | Native psutil collectors |
| qdoctor | Diagnostics / Packages | `qsuite doctor` | `doctor.view`, `doctor.run` | Installed diagnostic adapter, fixed quick/full arguments |
| qperf | Metrics / Performance | `qsuite perf 24h` | `performance.view`, `performance.configure` | Native sampler or audited legacy DB/timer |
| qincident | Private incident records / Incidents | `qsuite incidents` captures | `incident.view`, `incident.create` | Native security records; capture uses external adapter |
| qlogs | Bounded journals / Logs | `qsuite logs SERVICE_ID` | Per-source `logs.*.read` | Root-configured service map; journald |
| qsmart | Storage health / Packages | No native standalone SMART subcommand | `smart.view`, `smart.configure` | Installed SMART adapter; monitor policy |
| qmaintenance | Maintenance state / Packages | `qsuite maintenance on` or `off` | `maintenance.view`, `maintenance.configure` | Installed maintenance guard; approved public message |
| qmc | Game status / Minecraft | No native game lifecycle subcommand | `minecraft.view`, `logs.minecraft.read` | Optional local port/root; filtered activity |
| crafty | Manager service / Crafty | Service actions are web capabilities | `crafty.view`, `crafty.control` | Explicit configured Crafty unit; systemd |
| qwebhook | Member/Admin News | No native `qsuite webhook` command | `member_news.*`, `admin_news.*` | Native classified outbox; separate encrypted webhook configuration |

Native daemons are `qsuite-agent.service`, `qsuite-helper.service`,
`qsecurity.service` and `qsuite-watchdog.timer` (runs its oneshot service).
Inspect their logs through `sudo journalctl -u UNIT -n 100 --no-pager`.
Action results also appear in private jobs/audit. Root-configured legacy tools
retain their own logs and schedules; QSuite does not install or overwrite them.

## Configure and operate

1. An administrator installs and audits any external tool first.
2. Root configures its fixed executable under `[integration.legacy_commands]`.
3. Review required helper sandbox write paths locally; no broad filesystem access.
4. In **Packages**, inspect status, open the module and choose a permitted action.
5. For settings, **Preview changes**, review the exact diff, reauthenticate and apply.
   Optimistic revisions reject stale previews; failed verification attempts rollback.

Typed settings currently cover performance, backup **validation** schedule,
security trust/risk policy, SMART monitor policy and maintenance text. Configuration
permissions are separate from view/action permissions. No arbitrary shell command
can be supplied by a manifest. Manifests may only reuse reviewed capabilities.

Unavailable module: inspect configured paths/units and permissions. A module shown
as installed is not proof every adapter action has passed an operational drill.
See [configuration](configuration.md), [CLI](cli.md), [troubleshooting](troubleshooting.md).
