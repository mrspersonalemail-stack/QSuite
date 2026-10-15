# Recovery

API, UI, security DB and Discord failures must leave workload managers and
backup timers running. No Crafty unit depends on QSuite.

Verify package/configuration provenance, snapshot checksum and SQLite integrity
in isolation before switching state. Reject newer incompatible schemas. Preserve
old DB/WAL as evidence. Never overwrite Crafty/world data as part of a management
repair. Keep SSH and console recovery independent of panel availability.

TOTP recovery requires the protected credential key or an independent recovery
code. Store both appropriately outside this failure domain. Optional certificate
trust still requires host identity verification through trusted SSH.

Synchronous FULL SQLite and fsynced atomic files reduce some power-loss risks.
They cannot guarantee durability against hardware defects or abrupt power loss.
Use a UPS, separately stored copies and a tested restore. A dashboard's healthy
service status does not certify a recovered Minecraft world.
