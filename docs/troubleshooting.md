# Troubleshooting

Keep SSH/console access independent of the panel. Read logs locally and redact before
sharing; never attach a raw database, config directory or incident bundle publicly.

```sh
qsuite version
sudo qsuite status
sudo systemctl status qsuite-agent.service qsuite-helper.service qsecurity.service
sudo journalctl -u qsuite-agent.service -n 100 --no-pager
```

| Symptom | Check / action |
| --- | --- |
| API will not start | Production requires TLS files, readable systemd credentials, valid hostname/expiry/key pair, and correct root-owned configuration |
| Website unreachable | Fresh installs stay stopped; check unit state, loopback bind, tunnel and intended browser origin before changing firewall |
| Invalid Host | Browser hostname and port must exactly match configured origin; forwarded headers are not trusted |
| TLS error | Verify hostname, validity, key and chain. Optional CA policy still requires HTTPS; browsers may independently refuse self-signed certificates |
| LAN/WAN confusion | LAN is loopback through a tunnel. WAN is explicit HTTPS; changing trust does not open ports |
| Login JSON / missing page | `/login` must return HTML. API unauthenticated responses remain JSON. Use the configured HTTPS origin and current application assets |
| Login / session failure | Check time, account enabled/expiry, password/OTP and source rate window; Strict cookies need matching HTTPS origin |
| 403 | Check granted permissions, CSRF/Origin, password-change flag, MFA requirement and fresh authentication; do not weaken controls |
| Discord failed | Check channel-specific configured state, permitted route, test result and bounded retry state; replace a revoked secret locally |
| QSecurity degraded | Check journal/scanner access, protected baseline, heartbeat and independent watchdog code baseline; unavailable is not clean |
| ClamAV unavailable | Install/maintain scanner/signatures separately and configure scan roots; no protected quarantine is implemented |
| Backup action fails | Producer and audited validation/restore adapters are separate. Check free space, mount, archive completion and adapter sandbox paths |
| Download unavailable | Check download permission, fresh login, WAN TOTP, two-transfer limit and whether archive changed or is unsafe |
| SMART unavailable | Install/review the root-owned SMART adapter; some virtual disks do not expose hardware SMART |
| Crafty/game unavailable | Optional unit/root/local port must be configured; QSuite does not install Crafty or manage individual game lifecycle |
| Migration error | Preserve database/WAL and rollback snapshots, check version and disk space; never force a downgrade or delete recovery evidence |

`sudo qsuite doctor` uses an installed diagnostic adapter; it is unavailable on a
clean host without that tool. `sudo qsuite logs SERVICE_ID` uses configured service
IDs and bounded redacted output. Root journald remains an independent recovery path.
See [upgrading](upgrading.md) for package failures and [backups](backups.md) for
recovery confidence.
