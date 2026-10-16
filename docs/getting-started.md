# Getting started

QSuite web accounts are independent of SSH accounts. Keep your existing SSH/console
access while configuring the panel. Begin in loopback LAN mode.

## 1. Configure local HTTPS

After [installing](installation.md), edit `/etc/qsuite/config.toml` with
`sudoedit`. The bundled example defaults to loopback port 9080 and browser origin
`https://localhost:9443`. Production always requires HTTPS.

For an isolated LAN evaluation, create a localhost certificate on the server:

```sh
sudo install -d -m 755 /etc/qsuite/tls
sudo openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes \
  -keyout /etc/qsuite/tls/key.pem -out /etc/qsuite/tls/cert.pem \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost
sudo chmod 600 /etc/qsuite/tls/key.pem
```

Set these **top-level** TOML keys, before any `[section]`:

```toml
tls_cert = "/etc/qsuite/tls/cert.pem"
tls_key = "/etc/qsuite/tls/key.pem"
```

Use `sudo systemctl edit qsuite-agent.service` to add:

```ini
[Service]
LoadCredential=tls-key:/etc/qsuite/tls/key.pem
```

This gives the API a private runtime credential without making the original key
world-readable. QSuite validates hostname, expiry and key matching even for LAN.
Inspect the certificate fingerprint through your trusted SSH connection before
trusting it in your browser. Self-signed HTTPS may be disallowed on managed devices;
use a CA-issued certificate and matching hostname in that case.

## 2. Create the Owner and start services

```sh
sudo qsuite user add --username panelowner --role owner
sudo systemctl daemon-reload
sudo systemctl enable --now qsuite-helper.service qsuite-agent.service
sudo qsecurity baseline update
sudo systemctl enable --now qsecurity.service qsuite-watchdog.timer
```

Enter a unique password locally (10–256 characters; a long passphrase is preferable).
No default credential exists. Review the protected files before approving a baseline.
Do not approve unexpected changes merely to clear an alert.

## 3. Connect from your computer

```sh
ssh -L 9443:127.0.0.1:9080 YOUR_SSH_USER@YOUR_SERVER
```

Open `https://localhost:9443/login` while the SSH tunnel stays connected. Sign in,
open **Account & settings**, enroll TOTP and save the one-use recovery codes away
from the server. Never paste the enrollment URI or recovery codes into an issue.

## 4. Configure only what you need

Use **Packages** to see available capabilities. Uninstalled adapters remain
unavailable; adding a path does not install the tool. See [packages](packages.md).
Keep the terminal disabled until its identity boundary is checked. Configure
independent Member/Admin News webhooks under [notifications](notifications.md).

Use [backups](backups.md) to configure a producer directory, validation and offsite
recovery. QSuite does not create backups itself. Add optional
[Minecraft/Crafty](minecraft.md) integration only when wanted.

Create additional accounts in **Users & permissions**. Start with the narrowest
role and verify their direct API access. Review [access modes](access-modes.md)
before exposing WAN. Review the [validation scope](release-readiness.md) and check
your own installation in isolation before relying on it for production.
