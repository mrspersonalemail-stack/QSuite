# Optional Minecraft / Crafty integration

QSuite works without Minecraft. It neither installs Crafty nor launches Java.
Crafty or your existing supervisor remains the authoritative game lifecycle manager.

Root may set `integration.crafty_unit`, `minecraft_root` and `game_port` for one local
server. Paths and ports have no deployment-specific defaults. Status uses the local
Minecraft status protocol with bounded reads/timeouts; player counts/version are
reported only when available. TPS/MSPT remain unavailable without a trusted metrics
interface. Crafty status observes the configured systemd unit.

`qmc` exposes status and filtered player activity. **Native start/stop/restart of an
individual Minecraft server is not implemented.** Crafty service controls start,
stop or restart the manager itself and may interrupt all managed worlds. They
require `crafty.control`, fresh authentication, confirmation and WAN TOTP. Status
needs `minecraft.view` / `crafty.view`. Do not use a Crafty restart as a harmless
status refresh.

Mods/Helpers receive limited game/community permissions, not Linux administration.
`logs.minecraft.read` includes only approved join/leave/chat patterns, with common
addresses/credentials/private paths filtered. It excludes raw server errors and
system journals. Review chat confidentiality before granting player-log access.

Member News can announce safe status/maintenance. Private failures and security
records stay in Admin News unless an explicitly public-safe fixed projection exists.
No Crafty admin password or private server UUID belongs in public configuration.
Backup creation remains in the producer UI; see [backups](backups.md).
