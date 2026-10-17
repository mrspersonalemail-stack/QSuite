#!/usr/bin/env python3
"""Exercise a real package lifecycle ONLY on a fresh GitHub-hosted runner VM.

No real credentials, webhooks or workload integrations are configured. Never run
this on an existing QSuite installation. The runner is discarded after the job;
the removal checks deliberately verify that private state survives package purge.
"""

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

UNITS = ["qsuite-helper.service", "qsuite-agent.service", "qsecurity.service", "qsuite-watchdog.timer"]


def run(*argv):
    try:
        return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT)  # noqa: S603
    except subprocess.CalledProcessError as exc:
        # dpkg runs only our public package lifecycle on this fresh VM. Keep its
        # bounded install diagnostics; never print captured credential decrypts.
        if argv[0] == "dpkg":
            print(exc.stdout[-8000:], flush=True)
            installed = Path(f"/opt/qsuite/current/venv/lib/python3.{sys.version_info.minor}/site-packages/qsuite/installer.py").resolve()
            for path in [installed, *installed.parents]:
                if path.exists():
                    info = path.stat()
                    print(f"runtime trust diagnostic: {path}: uid={info.st_uid} mode={info.st_mode & 0o777:o}")
        raise


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def active(unit):
    return subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], check=False).returncode == 0  # noqa: S603


def qualify(package, report):
    require(os.geteuid() == 0, "disposable qualification requires root")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("QSUITE_DISPOSABLE_QUALIFICATION") == "yes",
            "refusing outside an explicitly authorized GitHub-hosted disposable VM")
    require(platform.freedesktop_os_release().get("ID") == "ubuntu", "Ubuntu runner required")
    require(Path("/run/systemd/system").is_dir(), "real systemd is required")
    require(not any(Path(p).exists() for p in ("/etc/qsuite", "/opt/qsuite", "/var/lib/qsuite")),
            "refusing an existing installation")
    os.umask(0o022)
    # Hosted build images deliberately grant write access to /opt. Tighten only
    # this fresh disposable VM to the trusted runtime-prefix requirement.
    opt = Path("/opt")
    require(not opt.is_symlink() and opt.stat().st_uid == 0, "unexpected runner /opt identity")
    original_opt_mode = opt.stat().st_mode & 0o777
    inherited_opt_acl = "system.posix_acl_default" in os.listxattr(opt)
    opt.chmod(0o755)
    package = package.resolve(strict=True)
    require(sys.version_info.minor in {12, 14}
            and package.name == f"qsuite_1.1.0_py3{sys.version_info.minor}_amd64.deb",
            "wrong qualification target")
    evidence = {"os": platform.freedesktop_os_release()["PRETTY_NAME"],
                "python": platform.python_version(), "architecture": platform.machine(),
                "package": package.name, "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                "runner_opt_mode_before_hardening": oct(original_opt_mode),
                "runner_opt_has_default_acl": inherited_opt_acl}

    def install_package():
        # Exercise the actual regression: the package must impose its own safe
        # runtime umask even when its caller supplies the most permissive one.
        before = os.umask(0)
        try:
            run("dpkg", "--install", str(package))
        finally:
            os.umask(before)

    install_package()
    require(run("qsuite", "version").strip() == "1.1.0", "CLI version mismatch")
    for name in [*UNITS, "qsuite-watchdog.service"]:
        info = (Path("/etc/systemd/system") / name).stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "installed systemd unit is writable/unowned")
    key_info = Path("/etc/qsuite/secrets/auth-key").stat()
    require(key_info.st_uid == 0 and not key_info.st_mode & 0o077, "authentication key permissions are unsafe")
    for unit in UNITS:
        require(not active(unit), "fresh install unexpectedly started services")
    evidence["clean_install"] = "pass; services initially stopped"
    config = Path("/etc/qsuite/config.toml")
    tls = Path("/etc/qsuite/tls")
    tls.mkdir(mode=0o755)
    run("openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-days", "2", "-nodes",
        "-keyout", str(tls / "key.pem"), "-out", str(tls / "cert.pem"), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost")
    (tls / "key.pem").chmod(0o600)
    config.write_text('tls_cert = "/etc/qsuite/tls/cert.pem"\ntls_key = "/etc/qsuite/tls/key.pem"\n'
                      + config.read_text().replace('origin = "https://localhost:9443"',
                                                   'origin = "https://localhost:9080"'))
    dropin = Path("/etc/systemd/system/qsuite-agent.service.d")
    dropin.mkdir(mode=0o755)
    (dropin / "qualification-tls.conf").write_text("[Service]\nLoadCredential=tls-key:/etc/qsuite/tls/key.pem\n")
    run("qsuite", "user", "add", "--username", "releaseowner", "--role", "owner", "--random")
    password = run("systemd-creds", "decrypt", "--name=qsuite-bootstrap",
                   "/etc/qsuite/secrets/bootstrap-releaseowner.cred", "-").strip()
    run("systemctl", "daemon-reload")
    run("qsecurity", "baseline", "update")
    run("systemctl", "enable", "--now", *UNITS)
    context = ssl.create_default_context(cafile=str(tls / "cert.pem"))
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context),
                                        urllib.request.HTTPCookieProcessor(jar))

    def request(path, body=None, csrf=False):
        headers = {"Origin": "https://localhost:9080", "Accept": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = next(c.value for c in jar if c.name == "__Host-qsuite-csrf")
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request("https://localhost:9080" + path, data=data, headers=headers)
        try:
            with opener.open(req, timeout=10) as response:  # noqa: S310 -- fixed loopback HTTPS origin
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as response:
            return response.code, response.headers, response.read()

    def ready():
        for _attempt in range(30):
            try:
                if request("/api/v1/health")[0] == 200:
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1)
        raise RuntimeError("installed HTTPS service did not become healthy")

    ready()
    require(json.loads(request("/api/v1/health")[2])["version"] == "1.1.0", "API version mismatch")
    status, headers, body = request("/login")
    require(status == 200 and "text/html" in headers["Content-Type"] and b"QSuite" in body,
            "installed login document unavailable")
    require(request("/api/v1/packages")[0] == 401, "anonymous API was not rejected")
    require(request("/api/v1/auth/login", {"username": "releaseowner", "password": password})[0] == 200,
            "provisioned Owner cannot sign in")
    require(json.loads(request("/api/v1/auth/me")[2])["role"] == "owner", "Owner role mismatch")
    require(all(c.secure for c in jar), "production cookies are not Secure")
    inventory = request("/api/v1/packages")
    require(inventory[0] == 200 and len(json.loads(inventory[2])["packages"]) >= 10,
            "installed package discovery failed")
    require(request("/api/v1/auth/logout", {})[0] == 403, "CSRF protection was not enforced")
    evidence["installed_https_owner_registry_csrf"] = "pass"
    for unit in UNITS:
        run("systemctl", "is-active", "--quiet", unit)
    evidence["systemd_services"] = "pass"
    saved_config = config.read_bytes()
    key = Path("/etc/qsuite/secrets/auth-key")
    saved_key = key.read_bytes()
    install_package()
    for unit in UNITS:
        run("systemctl", "is-active", "--quiet", unit)
    require(config.read_bytes() == saved_config and key.read_bytes() == saved_key,
            "package reinstall changed configuration or authentication key")
    ready()
    require(json.loads(request("/api/v1/auth/me")[2])["role"] == "owner", "reinstall lost account/session")
    require(request("/api/v1/auth/logout", {}, csrf=True)[0] == 200, "authenticated logout failed")
    evidence["same_version_reinstall_resume_preservation"] = "pass"
    # This child uses only synthetic network fixtures, never the Owner password.
    # Preserve its bounded diagnostics instead of hiding them in check_output.
    subprocess.run(["/opt/qsuite/current/venv/bin/python", str(Path(__file__).with_name("qualify-network-guard.py").resolve())], check=True)  # noqa: S603
    evidence["vpn_native_ipv4_ipv6_lifecycle"] = "pass; synthetic veth packets, exceptions, reload, disable, offline restore"
    run("dpkg", "--remove", "qsuite")
    run("dpkg", "--purge", "qsuite")
    require(config.read_bytes() == saved_config and key.read_bytes() == saved_key,
            "removal/purge lost protected configuration")
    require(Path("/var/lib/qsuite/qsuite.db").is_file(), "removal/purge lost application database")
    require(not Path("/usr/bin/qsuite").exists(), "package removal left installed CLI wrapper")
    for unit in UNITS:
        require(not active(unit), "package removal left services running")
    evidence["remove_purge_preserves_state_and_stops_services"] = "pass"
    report.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    qualify(args.package, args.report)
