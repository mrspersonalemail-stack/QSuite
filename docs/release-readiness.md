# v1.0.0 release readiness

**Stable release decision: HOLD — qualification remains incomplete.**
The owner subsequently requested publication of the audited source repository.
Source publication must retain candidate status; no stable tag or GitHub Release
is created while these qualification gates remain open.
Production services were not contacted or changed during this preparation.

## Evidence, 15 October 2026

| Gate | Result |
| --- | --- |
| Initial repository / history inventory | PASS: no commits or remote; all 169 existing blob objects also inspected |
| Secret scan before publication | PASS on candidate source and existing objects; two vendored xterm class assignments reviewed, narrowly allowlisted and vendor hashes checked |
| Private deployment boundary | PASS: private reports/scripts preserved locally outside public source; no runtime state selected |
| License | PASS: original MIT text preserved; xterm license retained |
| Canonical application version | PASS: runtime literal 1.0.0 drives package metadata, API/CLI and Debian builder |
| Backend / auth / RBAC / isolation / migration / package tests | PASS: 237 backend tests; six frontend tests; Ruff and scoped mypy passed |
| Frontend checks | Six Node tests and syntax checks; no transpilation build applies |
| Type checks | Scoped mypy checks for configuration, permissions, notifications; not whole-program coverage |
| Dependency security | PASS: only cryptography changed, 47.0.0 → 50.0.2; 30 pinned packages, zero known advisory matches in the final scan |
| Encryption compatibility | PASS: synthetic Fernet ciphertext created on 47.0.0 decrypted on 50.0.2 |
| Python wheel / source build | PASS: wheel/source built and inspected, licenses checked; installed-wheel smoke passed |
| Debian artifact | PASS: offline Python 3.14 amd64 candidate built; payload/ownership/modes/manifest inspected without host installation |
| Documentation | PASS: complete guide index, actual CLI/API surface, explicit limitations; relative links checked |
| GitHub CI matrix | Configured; remote qualification pending source publication |
| Clean target systemd lifecycle | NOT ASSESSED: no disposable Debian/Ubuntu systemd VM available; container/unit checks are insufficient |
| Real terminal peer/identity / reboot qualification | NOT ASSESSED for this release; previous deployment evidence is not inherited |
| Screenshots and mobile browser acceptance | NOT ASSESSED: browser tool blocked isolated preview; private production screenshots excluded |
| Public security reporting | PASS: dedicated project inbox confirmed and listed in SECURITY.md; GitHub private reporting remains optional to enable |
| Community conduct reporting | PASS: dedicated project inbox confirmed and listed in CODE_OF_CONDUCT.md |
| Source repository publication | Public repository created as mrspersonalemail-stack/QSuite; audited candidate source publication authorized by owner |
| Stable tag / Release publication | HOLD: qualification gates remain open; source publication does not declare a stable release |

## Build and qualification distinction

Candidate artifacts and checksums live in the local `dist/release-1.0.0/` directory.
The wheel is exercised in a new offline virtual environment with no development
dependencies: HTML/login/CSRF/package registry/schema smoke and pip checks. This
is application packaging evidence, not a full operating-system/systemd install.
The known TestClient deprecation warning does not fail the suite.

## Security review changes

- Debian payload now rejects unrelated wheelhouse files, symlinks and multiple or
  mismatched application wheels. Installer requires a complete verified manifest.
- Post-removal preservation script no longer depends on an already removed payload.
- Upgrades save and resume only previously active allowlisted QSuite units; each
  unit is verified separately, and failure retains the resume record.
- Unsupported OS / missing systemd is rejected before runtime creation.
- Legacy security notification delivery streams responses, disables environment
  proxy inheritance, and retains fixed provider and mention policy.
- Backup GET and HEAD have distinct OpenAPI operation IDs. Unknown HTTP range units
  are ignored. Negative archive/HTTP/permission/descriptor/transport tests added.
- Security dependency remediation was reviewed against the
  [upstream advisory](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf)
  and [upstream changelog](https://cryptography.io/en/latest/changelog/).
  No other locked runtime package changed. Production keys/state were not used in tests.

## Required before stable publication

1. Run CI on each claimed target, then perform disposable PID-1 systemd install,
   Owner/login, registry/diagnostic, upgrade/migration, failed-upgrade recovery,
   removal/purge preservation and reboot drills. Record exact OS/Python/architecture.
2. Complete browser/mobile and separate-terminal identity/lifecycle acceptance on
   isolated data. Capture actual sanitized screenshots only after visual review.
3. Keep the dedicated reporting inbox monitored; optionally enable GitHub private
   vulnerability reporting as an additional channel.
4. Provide repository/tag/Release/asset publication capabilities for the exact
   repository identity QSuite. Do not substitute an unrelated repository or name.
5. Repeat final scan of staged source/reachable history, artifact inspection, docs
   links, checksums and clean Git status. Only then tag/publish v1.0.0.

## Next release candidates

For v1.0.1: broaden type coverage and improve qualification automation, cancellation
and transport tests. For v1.1.0: design a least-privilege producer API for backups,
protected quarantine and more reliable attribution, with separate security review.
Do not advertise these planned features as present.
