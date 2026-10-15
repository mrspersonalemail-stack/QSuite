# Access and certificate policy

LAN is the public default and binds loopback. WAN is explicit and always uses
production HTTPS, exact origin/Host checks, secure cookies, CSRF, authentication
and rate limits. QSuite does not silently alter unrelated firewall/router rules.

**Require trusted TLS for WAN** defaults on. It requires a certificate chaining
to the system CA store. When off, a valid hostname-matching self-signed
certificate with the correct private key is allowed. HTTP remains rejected.
Browsers still enforce their own trust policies; this toggle cannot bypass a
device restriction. Verify the fingerprint over trusted SSH before trusting
a self-signed certificate. Install a CA-issued certificate before turning
the requirement on.

The Settings toggle is owner-only, requires fresh authentication and enrolled
2FA for sensitive WAN actions, and records an audit event. Enabling it without
a trusted certificate fails unchanged.

```sh
sudo qsuite access wan --bind 0.0.0.0 --origin https://panel.example:9443 \
  --cert /etc/qsuite/tls/fullchain.pem --key /etc/qsuite/tls/key.pem --dry-run
sudo qsuite access lan --dry-run
```

Review origin, bind, TLS, recovery access and rollback before removing dry run.
CLI authorization is local root authentication. Access changes restart only
QSuite. Certificate rotation needs validated deployment and a real HTTPS probe.
