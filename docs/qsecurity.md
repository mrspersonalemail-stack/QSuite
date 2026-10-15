# QSecurity

QSecurity is an independent observer, not a complete intrusion prevention or malware
containment system. It stores structured, redacted evidence and private incidents.
Severity is separate from attribution and enforcement eligibility.

| Level | Name | Delivery policy |
| --- | --- | --- |
| L0 | NORMAL | Dashboard/log; no private webhook delivery |
| L1 | NOTICE | Private alert, no mention |
| L2 | SUSPICIOUS | Configured administrator mention, if enabled |
| L3 | HOSTILE | Private alert; everyone mention if enabled |
| L4 | CRITICAL | Private alert; everyone mention if enabled |
| L5 | LOCKDOWN | Named severity; automatic lockdown is unavailable |

**Geography alone must never cause a permanent ban.** The classification functions
accept configured trust regions, but no live geolocation provider/dataset is
shipped: missing lookup is UNKNOWN. LAN trust bypasses geographic escalation only.
Fail2ban retains its own enforcement policy. QSuite does not create permanent bans,
terminate hostile sessions or apply automatic lockdown, even if `security.enforce`
is set; that field is reserved and does not activate an enforcement engine.

## Implemented observation

Trusted root `sshd`/`sshd-session` journal records supply login source/user/key data.
A cursor avoids ordinary replay. Ten failures from a source within five minutes
produce SIEGE. Missing journal access reports BLINDSPOT. Session identifiers bind
correlation to observed records; complete sudo, transfer and process attribution
are unavailable. Configurable risk weights are summed once per recent protocol,
capped at 100; severity and confirmed attributed evidence are evaluated separately.

An operator-approved baseline compares hashes, modes and owners of bounded
protected files. SSH/sudo changes emit ANCHOR; systemd changes RAVEN; other protected
changes FORGE. A legitimate update also changes hashes: investigate before approval.

```sh
sudo qsecurity baseline status
sudo qsecurity baseline update
sudo qsuite security events
```

ClamAV must be installed and maintained separately. Explicit quick/full scans use
configured roots, load deferral, single-flight locking, low priority and time/output
limits. Both modes scan configured roots with different time budgets; they are not
a guarantee of full-device coverage or current signatures. PLAGUE records detected
malware while preserving the source. **Protected quarantine and scheduled scanning
are not implemented.** Missing/failed scanning reports degraded coverage.

CERBERUS is an independent systemd timer checking observer state, heartbeat and a
separately approved code fingerprint baseline. It can deliver private alerts without
the API or security database. Finite upgrade maintenance suppresses expected stops.
Review code provenance before `sudo /opt/qsuite/current/venv/bin/qsuite-watchdog --baseline-update`.

## Protocol availability

| Protocols | Availability |
| --- | --- |
| HOMEGUARD, FOREIGN | Live SSH classification; FOREIGN records UNKNOWN lookup |
| CARPATHIAN, EUROPA, EXILE | Classification functions implemented; live geographic lookup absent |
| SIEGE | SSH failure collector implemented |
| ANCHOR, RAVEN, FORGE | Protected-file comparison implemented |
| PLAGUE, BLINDSPOT | Explicit scanner/coverage and collection failure paths implemented |
| CERBERUS | Independent service, heartbeat and code checks implemented |
| ALLCLEAR | Baseline approval / watchdog recovery vocabulary |
| TRANSFERWATCH, SENTINEL, OUTBREAK, GHOST, THRONE, CROWN, SABRE, BLACKOUT, LOCKDOWN | Reserved vocabulary; no complete autonomous collector/containment workflow |

The full [protocol vocabulary](qsecurity-protocols.md) describes intended meanings;
response labels such as “quarantine” do not mean those responses execute.

Configure private news through [notifications](notifications.md). Legacy independent
security-webhook delivery is separate from Member News. Never route raw security,
SSH, malware, audit or private incident evidence to a community channel.

[Security model](security.md) · [Implementation status](implementation-status.md)
