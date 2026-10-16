# v1.0.0 release readiness

**Release decision: READY within the validated Ubuntu amd64 scope below.**
The final release commit must pass its CI checks before the annotated `v1.0.0`
tag and immutable GitHub Release are published. The tag identifies that exact commit;
GitHub Release assets and `SHA256SUMS` identify its downloadable packages.
Production services were not contacted or changed during release finalization.

## Evidence, 16 October 2026

| Gate | Result |
| --- | --- |
| Repository / history inventory | PASS: public main fetched and inspected; no prior v1.0.0 tag or Release existed at finalization start |
| Secret scan before publication | PASS: tracked source, relevant reachable history and artifact contents; narrow reviewed xterm false-positive exceptions and vendor hashes retained |
| Private deployment boundary | PASS: private reports/scripts preserved locally outside public source; no runtime state selected |
| License | PASS: original MIT text preserved; xterm license retained |
| Canonical application version | PASS: runtime literal 1.0.0 drives package metadata, API/CLI and Debian builder |
| Backend / auth / RBAC / isolation / migration / package tests | PASS: 245 backend tests; six frontend tests; Ruff and scoped mypy passed |
| Frontend checks | Six Node tests and syntax checks; no transpilation build applies |
| Type checks | Scoped mypy checks for configuration, permissions, notifications; not whole-program coverage |
| Dependency security | PASS: 30 hash-locked runtime packages; zero known advisory matches; no runtime dependency upgrades in this finalization pass |
| Encryption compatibility | PASS: synthetic Fernet ciphertext created on 47.0.0 decrypted on 50.0.2 |
| Python wheel / source build | PASS: wheel/source built and inspected, licenses checked; installed-wheel smoke passed |
| Debian artifact | PASS: four ABI-specific amd64 builds inspected; Ubuntu Python 3.12/3.14 packages additionally exercised through real installed services |
| Documentation | PASS: complete guide index, actual CLI/API surface, explicit limitations; relative links checked |
| GitHub CI matrix | PASS: Debian 12/13 and Ubuntu 24.04/26.04 container tests/builds/audits; [qualification run](https://github.com/mrspersonalemail-stack/QSuite/actions/runs/38932705491) |
| Clean target systemd lifecycle | PASS: Ubuntu 24.04/26.04 hosted VMs; clean install, stopped-on-install policy, TLS/Owner/CSRF/registry, real services, same-version reinstall/resume and removal/purge preservation |
| Real terminal peer/identity / reboot qualification | NOT ASSESSED: actual reboot/power-loss and separate-terminal peer/identity drills; terminal remains disabled by default |
| Screenshots and mobile browser acceptance | NOT ASSESSED: fresh real mobile/browser acceptance; six frontend tests and document-route regression tests pass; private production screenshots excluded |
| Public security reporting | PASS: dedicated project inbox confirmed and listed in SECURITY.md; GitHub private reporting remains optional to enable |
| Community conduct reporting | PASS: dedicated project inbox confirmed and listed in CODE_OF_CONDUCT.md |
| Source repository publication | PASS: public mrspersonalemail-stack/QSuite, default main; release changes preserve unrelated branches and private deployment material |
| Stable tag / Release publication | READY after final-commit CI, annotated tag verification, asset inspection and checksum verification; public tags are never moved |

## Build and qualification distinction

Artifacts are built from the release source in isolated CI. Python wheel/source and
Debian payload contents, licenses, ownership/modes and wheel hashes are inspected.
The wheel also runs HTML/login/CSRF/registry/schema smoke checks in a clean offline
virtual environment. The Ubuntu lifecycle jobs use real PID-1 systemd VMs, generate
only disposable local credentials and never configure a real notification webhook.
Their reports include the exact package hash, OS, Python and test outcomes.

Hosted VMs supply a writable `/opt` with a default ACL. The test fixture tightens
only that disposable VM's `/opt` access permissions. Package installation is then
intentionally called under umask 000. New QSuite runtime directories start private,
clear inherited ACLs and acquire safe final modes. Existing untrusted code or
inheritable ACLs require review before execution. The default-ACL regression is
also reproduced in an isolated filesystem unit test.

These checks do not establish hardware/power-loss resilience, real reboot behavior,
mobile visual acceptance or a cross-version binary upgrade. Schema 1/2 migration
and failed-migration recovery have automated tests. Same-version reinstall is the
installed upgrade-path exercise for this first stable release. One upstream
TestClient deprecation warning is non-failing. No independent certification is claimed.

## Security review changes

- Debian payload now rejects unrelated wheelhouse files, symlinks and multiple or
  mismatched application wheels. Installer requires a complete verified manifest.
- Post-removal preservation script no longer depends on an already removed payload.
- Upgrades save and resume only previously active allowlisted QSuite units; each
  unit is verified separately, and failure retains the resume record.
- Unsupported OS / missing systemd is rejected before runtime creation.
- Runtime creation is safe under permissive umasks/default ACLs. Existing runtime
  files, ancestors and interpreter symlink targets are checked before execution.
- Artifact checksums use portable flat names; source/wheel code and Debian members
  reject writable payload permissions. Only the upstream wheel RECORD metadata
  convention (exact path, 0664) is permitted; installed files remain protected.
- Legacy security notification delivery streams responses, disables environment
  proxy inheritance, and retains fixed provider and mention policy.
- Backup GET and HEAD have distinct OpenAPI operation IDs. Unknown HTTP range units
  are ignored. Negative archive/HTTP/permission/descriptor/transport tests added.
- Security dependency remediation was reviewed against the
  [upstream advisory](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf)
  and [upstream changelog](https://cryptography.io/en/latest/changelog/).
  No other locked runtime package changed. Production keys/state were not used in tests.

## Publication controls and remaining limits

1. The exact final release commit must pass CI. Fetch and compare remote main before
   creating an annotated `v1.0.0`; verify the remote tag's peeled commit. Never replace it.
2. Attach only inspected Ubuntu Python 3.12/3.14 amd64 packages, the maintainer wheel
   and SHA-256 checksums. Debian 12/13 have container build/test evidence only; no
   Debian-specific or ARM64 binary is attached. GitHub provides tagged source archives.
3. Upload assets to a draft before publishing an immutable stable Release. Download
   the public assets back and verify their hashes against the published `SHA256SUMS`.
4. Keep the dedicated reporting inbox monitored. Private GitHub reporting is optional.
5. Reboot/power-loss, older-version binary upgrade, real mobile and terminal identity
   acceptance remain unqualified. These limits must remain in release notes and
   installation guidance. Optional adapters are not installed by this package.

## Next release candidates

For v1.0.1: broaden type coverage and improve qualification automation, cancellation
and transport tests. For v1.1.0: design a least-privilege producer API for backups,
protected quarantine and more reliable attribution, with separate security review.
Do not advertise these planned features as present.
