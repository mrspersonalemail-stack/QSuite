# API v1

The same-origin `/api/v1` API uses opaque cookie sessions, not JWTs or bearer API
keys. Authenticate with `POST /api/v1/auth/login` using JSON username/password and
an OTP/recovery code when enrolled. Browser cookies are Secure, HttpOnly (session),
host-only, SameSite Strict, Path `/`. CSRF cookies are readable for the matching
`X-CSRF-Token` header; server stores only token hashes.

All mutations require exact `Origin`, JSON and (after login) valid CSRF. Protected
routes enforce permissions server-side. Fresh authentication and WAN TOTP apply
where required. Do not pass cookies or passwords in URL parameters. No arbitrary
root command endpoint exists.

| Route group | Purpose |
| --- | --- |
| `/health` | Minimal unauthenticated health/version |
| `/auth/*` | Login/logout/me, reauthentication, password, TOTP, own sessions |
| `/status`, `/dashboard`, `/performance/{window}` | Authorized inventory and metrics |
| `/packages`, `/packages/{name}/*` | Filtered capability registry, typed configuration and actions |
| `/users`, `/roles`, `/authentication-policy` | Scoped account/role administration |
| `/news/{member,admin}`, `/news-routing` | Classified news and Owner policy |
| `/backups`, `/backups/{archive}/download` | Authorized archive listing/download |
| `/backups/validate`, `/restore/verify` | Installed validation/verification adapters as jobs |
| `/security*`, `/incidents`, `/audit` | Private security/evidence/audit |
| `/minecraft`, `/crafty`, `/log-sources`, `/logs/{service}` | Optional projections and per-source logs |
| `/services`, `/services/{start,stop,restart}` | Explicit allowlisted operations |
| `/jobs/{identifier}` | Account-scoped job results and current permission checks |
| `/access/tls-policy`, `/settings` | Access policy and safe capability state |
| `/terminal/ticket`, WebSocket `/terminal` | One-use ticket and separate-identity PTY |

The generated [OpenAPI snapshot](api-v1.openapi.json) is the exact HTTP route/schema
reference. Production disables `/docs` and `/openapi.json`; an isolated development
instance exposes them. The WebSocket protocol is described in [terminal](terminal.md).
API version is independent of QSuite's release version. No compatibility beyond
this documented v1 surface is promised for internal helper messages.

Errors are JSON `detail`: 400 invalid Host/config input, 401 missing/expired session,
403 permission/CSRF/fresh-auth/MFA/origin, 404 absent item, 409 conflicts/unavailable
capability, 413 body limit, 415 non-JSON mutation, 416 invalid byte range, 422 fields,
429 rate/concurrency limit, 503 rejected/unavailable broker operation. Unexpected
errors return a generic 500 without request secrets.

Login/reauthentication share a source-based 10-attempt/5-minute limit. Hash workers,
request concurrency, job queue and download slots are bounded. Browser document
navigation is separate: unauthenticated protected pages redirect to `/login`, and
`/login` always serves HTML regardless of missing/invalid cookies or privacy headers.
An unauthenticated API request remains JSON even with `Accept: text/html`.
