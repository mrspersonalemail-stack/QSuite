# Application security

Backend permissions are authoritative. The broker checks Linux peer identity,
closed request fields, operation names and root-configured service/path lists.
It never accepts a root command string. The terminal account cannot use the
helper socket. Installed code and configuration are root-owned and must not
be writable by API/terminal identities.

Argon2id uses 64 MiB, time cost 3, parallelism 2. Concurrent verification is
capped at two operations. Per-source rate windows avoid remotely locking a
whole owner account. Forwarded client headers are not trusted. Bodies, API
concurrency, job queues, helper output and process lifetime are bounded.

Random session and CSRF tokens are stored as hashes. Default session lifetime
is eight hours, idle expiry 30 minutes. Roles/account changes revoke sessions.
Fresh authentication protects sensitive operations; sensitive WAN actions
also require enrolled 2FA. TOTP secrets use a separate protected encryption
key delivered through systemd credentials. Successful TOTP steps cannot be
replayed. Recovery codes are one-use hashes, shown only once. Provision owners
through interactive local input; never reuse the SSH password automatically.

Production session cookies are Secure, HttpOnly, SameSite=Strict, host-only
and Path=/. CSRF cookies are readable for the matching header. Changes require
exact Origin and JSON. CSP, framing, nosniff, no-cache and referrer controls
apply to responses. Audit objects are identifiers, never request bodies,
passwords or terminal keystrokes. Log output is bounded and redacted.

Audit retains 180 days and at most 50,000 records. Login buckets, samples,
jobs, security events and notification queues have separate bounds. A local
DB writable by its process is not an independently tamper-proof audit trail.
Off-host audit export remains a hardening gate.

Optional CA trust does not remove certificate identity/expiry/key checks or
HTTPS requirements. Enabling trusted policy with a self-signed certificate
fails without modifying policy. See the tests and release checklist for verified controls and remaining qualification work.
