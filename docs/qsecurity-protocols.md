# Named QSecurity protocols

Severity names: L0 NORMAL, L1 NOTICE, L2 SUSPICIOUS, L3 HOSTILE, L4 CRITICAL, L5 LOCKDOWN.

Individual protocols declare evidence and response. Mention behavior is centralized: L0 log; L1 no mention; L2 configured owner only; L3+ @everyone. Geography alone never proves hostility.

| Protocol | Default level | Trigger/meaning | Response |
| --- | --- | --- | --- |
| HOMEGUARD | 0 | Trusted LAN activity; audit without geography enforcement. | audit |
| CARPATHIAN | 0 | Successful authentication from a configured trusted country. | audit |
| FOREIGN | 1 | Unusual foreign authentication with low confidence. | observe |
| EUROPA | 1 | Authentication outside trusted countries but within configured continent. | observe |
| EXILE | 2 | Successful authentication outside trusted geographic region. | investigate |
| SIEGE | 2 | Correlated authentication failures or password spray. | investigate |
| TRANSFERWATCH | 2 | Sensitive transfer signal requiring targeted inspection. | inspect |
| SENTINEL | 0 | Scheduled or targeted malware scan. | scan |
| PLAGUE | 3 | Confirmed scanner detection; preserve evidence and quarantine. | quarantine |
| OUTBREAK | 4 | Multiple confirmed malware detections or critical compromise indicators. | investigate |
| BLINDSPOT | 1 | Monitoring or scanner/signature coverage is degraded. | investigate |
| RAVEN | 2 | Unexpected persistence definition change; legitimacy unconfirmed. | investigate |
| GHOST | 2 | Unexpected identity or authorized-key change; legitimacy unconfirmed. | investigate |
| ANCHOR | 2 | SSH/PAM/sudo policy changed outside an approved baseline. | investigate |
| THRONE | 2 | Management component changed outside an approved baseline. | investigate |
| FORGE | 2 | Protected file differs from approved baseline. | investigate |
| CROWN | 3 | Strong evidence of unauthorized privilege escalation. | contain if attributable |
| SABRE | 4 | Strong evidence of unauthorized destructive behavior. | contain if attributable |
| BLACKOUT | 4 | Confirmed security evidence destruction or tampering. | investigate |
| CERBERUS | 4 | Independent observer reports unexpected security engine failure. | investigate |
| LOCKDOWN | 5 | Operator-declared emergency containment request. | require recovery-safe enforcement |
| ALLCLEAR | 0 | Previously active condition has been resolved. | audit recovery |

These are the initial vocabulary and conservative defaults. Collector/enforcement availability is listed in [implementation status](implementation-status.md). A named protocol does not imply a complete live trigger/enforcement implementation.

HOMEGUARD bypasses geographic escalation only. LAN activity is still audited. EXILE remains L2 for geography without stronger evidence. Confirmed malware has no IP attribution unless its introduction is proven. Uncertain attribution remains UNKNOWN.
