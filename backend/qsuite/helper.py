"""A closed Unix-socket operation broker. No arbitrary root shell vocabulary."""

from __future__ import annotations

import array
import concurrent.futures
import grp
import json
import os
from pathlib import Path
import pty
import pwd
import re
import selectors
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import uuid

from .config import Settings, check_root_file, load
from .db import redact
from .telemetry import status, history

MAX_REQUEST = 8192
MAX_RESPONSE = 524288
WINDOWS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
CRITICAL = {
    "qsuite-agent.service",
    "qsuite-helper.service",
    "qsecurity.service",
    "ssh.service",
    "sshd.service",
    "fail2ban.service",
}


class OperationError(Exception):
    pass


def decode_request(raw: bytes):
    if len(raw) > MAX_REQUEST:
        raise OperationError("request too large")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) - {"operation", "target"}:
        raise OperationError("invalid request fields")
    if not isinstance(value.get("operation"), str) or not isinstance(value.get("target", ""), str):
        raise OperationError("invalid request types")
    return value["operation"], value.get("target", "")


def run(argv: list[str], timeout=10):
    """Drain bounded pipe output; no preexec_fn/fork callbacks in the threaded root broker."""
    child = subprocess.Popen(  # noqa: S603 -- argv comes only from closed operation dispatch
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # noqa: S603 -- closed broker argv
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        start_new_session=True,
    )  # noqa: S603
    deadline, retained, total = time.monotonic() + timeout, bytearray(), 0
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout, selectors.EVENT_READ)
            while poll.get_map():
                if time.monotonic() >= deadline:
                    raise OperationError("operation timed out")
                for selected, _ in poll.select(min(1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(selected.fileobj.fileno(), 8192)
                    if not chunk:
                        poll.unregister(selected.fileobj)
                        continue
                    total += len(chunk)
                    if total > 1048576:
                        raise OperationError("operation output limit reached")
                    retained.extend(chunk[: max(0, 32768 - len(retained))])
            result = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        return {"exit_code": result, "output": redact(retained.decode("utf-8", "replace"))}
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        raise
    finally:
        child.stdout.close()


def backups(settings: Settings):
    root = settings.integration.backup_root
    if not root:
        return {"configured": False, "creation_available": False, "archives": []}
    directory = Path(root)
    archives = []
    for p in directory.glob("*.zip"):
        if not p.is_symlink() and p.is_file():
            info = p.stat()
            available = False
            try:
                from .downloads import archive_descriptor

                _, descriptor = archive_descriptor(settings, p.name)
                os.close(descriptor)
                available = True
            except (OSError, OperationError):
                pass
            archives.append({"id": p.name, "size": info.st_size, "modified": int(info.st_mtime), "downloadable": available})
    archives.sort(key=lambda row: row["modified"], reverse=True)
    marker = settings.integration.corruption_marker
    offsite = {"state": "unknown"}
    if settings.integration.offsite_status:
        try:
            raw = Path(settings.integration.offsite_status).read_text()[:128].strip().split("\t")
            if len(raw) == 2 and raw[1] in {"PASS", "FAIL", "RUNNING"}:
                offsite = {"state": raw[1], "timestamp": raw[0]}
        except OSError:
            pass
    return {
        "configured": True,
        "creation_available": False,
        "archives": archives[:100],
        "logical_integrity": "unproven",
        "world_warning": bool(marker and Path(marker).exists()),
        "offsite": offsite,
    }


class Broker:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.terminals: dict[str, tuple[subprocess.Popen, float]] = {}
        self.lock = threading.Lock()

    def execute(self, operation: str, target: str = ""):
        s = self.settings
        if operation == "security.network.status" and not target:
            from .network_guard import status as network_status

            return network_status(load(privileged=True))
        if operation in {"news.watchdog.configure", "news.watchdog.status"}:
            from .watchdog_news import configure, status as news_status

            return configure(s, json.loads(target)) if operation == "news.watchdog.configure" else news_status(s)
        if operation == "packages.inventory" and not target:
            from .packages import inventory

            return {"packages": inventory(s, runner=run)}
        if operation in {"package.config.get", "package.config.preview", "package.config.apply"}:
            from .package_config import current, operation as configure
            from .packages import CONFIG_MODELS

            path = os.environ.get("QSUITE_CONFIG", "/etc/qsuite/config.toml")
            fresh_settings = load(path, privileged=True)
            if operation == "package.config.get":
                if target not in CONFIG_MODELS:
                    raise OperationError("configuration adapter unavailable")
                if target == "qbackup" and target not in fresh_settings.integration.package_timers:
                    return {"available": False, "reason": "No audited validation timer configured"}
                return {"available": True, "values": current(fresh_settings, target), "schema": CONFIG_MODELS[target].model_json_schema(),
                        "scope": ("Legacy sample interval and retention" if fresh_settings.integration.performance_config else "Legacy sampling interval; history retention applies to native QSuite samples") if target == "qperf" and target in fresh_settings.integration.package_timers else "Installed adapter configuration"}
            result = configure(path, json.loads(target), operation == "package.config.apply")
            if operation == "package.config.apply":
                self.settings = load(path, privileged=True)
            return result
        if operation in {"minecraft.status", "minecraft.logs"} and not target:
            from .game import minecraft_logs, minecraft_status

            return minecraft_status(s) if operation == "minecraft.status" else minecraft_logs(s)
        if operation == "crafty.status" and not target:
            if not s.integration.crafty_unit:
                return {"configured": False, "state": "unavailable"}
            result = run(["/usr/bin/systemctl", "is-active", s.integration.crafty_unit])
            state = result["output"].strip()
            return {"configured": True, "state": state if state in {"active", "inactive", "failed", "activating", "deactivating"} else "unknown"}
        if operation == "maintenance.status" and not target:
            legacy = s.integration.legacy_commands.get("maintenance_status")
            if legacy:
                check_root_file(Path(legacy).resolve())
                result = run([legacy, "status"])
                return {"configured": True, "enabled": bool(re.search(r'"active"\s*:\s*true|"enabled"\s*:\s*true|maintenance.*(?:ON|active)', result["output"], re.I))}
            return {"configured": False, "enabled": None}
        if operation == "smart.status" and not target:
            path = s.integration.legacy_commands.get("smart")
            if not path:
                return {"configured": False, "health": "unavailable"}
            check_root_file(Path(path).resolve())
            result = run([path], 30)
            temp = re.search(r"^\s*194\s+\S+\s+.+?\s+([0-9]+)(?:\s+\(.*)?$", result["output"], re.M)
            return result | {"configured": True, "health": "healthy" if re.search(r"(?:overall-health.*PASSED|Health Status: OK)", result["output"]) else "warning" if re.search(r"(?:overall-health.*FAILED|Health Status: (?!OK))", result["output"]) else "unknown",
                             "temperature": int(temp[1]) if temp else None,
                             "failed_self_test": bool(re.search(r"^#\s+\d+.*(?:failure|error)", result["output"], re.I | re.M))}
        if operation == "status" and not target:
            return status(s)
        if operation == "backups" and not target:
            return backups(s)
        if operation == "history" and target in WINDOWS:
            return history(s, WINDOWS[target])
        if operation == "services" and not target:
            units = s.services | ({"crafty": s.integration.crafty_unit} if s.integration.crafty_unit else {})
            output = []
            for name, unit in units.items():
                result = run(
                    [
                        "/usr/bin/systemctl",
                        "show",
                        unit,
                        "--property=ActiveState,SubState,UnitFileState",
                        "--no-pager",
                    ]
                )
                fields = dict(line.split("=", 1) for line in result["output"].splitlines() if "=" in line)
                output.append(
                    {
                        "id": name,
                        "unit": unit,
                        "controllable": unit not in CRITICAL and not unit.startswith("qsuite-"),
                        **fields,
                    }
                )
            return {"services": output}
        if operation in {"service.start", "service.stop", "service.restart", "logs"}:
            units = s.services | ({"crafty": s.integration.crafty_unit} if s.integration.crafty_unit else {})
            unit = units.get(target)
            if not unit:
                raise OperationError("service is not allowlisted")
            if operation == "logs":
                return run(
                    ["/usr/bin/journalctl", "-u", unit, "-n", "150", "--no-pager", "-o", "short-iso"], 15
                )
            if unit in CRITICAL or unit.startswith("qsuite-"):
                raise OperationError("critical service control is not exposed")
            result = run(
                ["/usr/bin/systemctl", operation.split(".")[1], unit], 400 if target == "crafty" else 60
            )
            observed = run(["/usr/bin/systemctl", "is-active", unit])
            expected = "inactive" if operation == "service.stop" else "active"
            result["observed"] = observed["output"].strip()
            result["verified"] = result["exit_code"] == 0 and result["observed"] == expected
            return result
        legacy = s.integration.legacy_commands
        if operation == "doctor_full" and operation not in legacy and "doctor" in legacy:
            legacy = legacy | {"doctor_full": legacy["doctor"]}
        if operation in legacy:
            path = Path(legacy[operation])
            check_root_file(path.resolve())
            arguments = {
                "doctor": ["--quick"],
                "doctor_full": ["--full"],
                "smart": [],
                "maintenance_status": ["status"],
                "backup_validate": ["validate"],
                "restore_verify": ["--verify", "latest"],
                "incident": ["--hours", "1"],
                "maintenance_on": ["on"],
                "maintenance_off": ["off"],
            }[operation]
            if target:
                raise OperationError("legacy parameters are not accepted")
            if operation == "maintenance_on":
                arguments.append(s.maintenance_message)
            return run([str(path), *arguments], 900 if operation == "restore_verify" else 120)
        if operation == "security.status" and not target:
            from .security import SecurityStore

            return SecurityStore(s).summary(read_only=True)
        if operation == "security.scan" and target in {"quick", "full"}:
            from .security import scan

            return scan(s, target)
        if operation == "security.baseline" and target == "update":
            from .security import baseline

            return baseline(s, update=True)
        if operation == "security.events" and not target:
            from .security import SecurityStore

            return SecurityStore(s).events(read_only=True)
        if operation == "security.incidents" and not target:
            from .security import SecurityStore

            return SecurityStore(s).incidents(read_only=True)
        if operation == "access.trust" and target in {"required", "optional"}:
            from .installer import change_trust

            return change_trust(
                os.environ.get("QSUITE_CONFIG", "/etc/qsuite/config.toml"), target == "required"
            )
        if operation == "terminal.close" and re.fullmatch(r"[0-9a-f]{32}", target):
            with self.lock:
                child = self.terminals.pop(target, None)
            if child:
                self._kill(child[0])
            return {"closed": True}
        raise OperationError("operation or parameter is not allowed")

    def open_terminal(self):
        if not self.settings.terminal_enabled:
            raise OperationError("terminal disabled")
        user = pwd.getpwnam(self.settings.terminal_user)
        if user.pw_uid == 0 or user.pw_gid in {0, grp.getgrnam("sudo").gr_gid}:
            raise OperationError("terminal identity is privileged")
        groups = os.getgrouplist(user.pw_name, user.pw_gid)
        forbidden = {
            grp.getgrnam(name).gr_gid
            for name in (self.settings.agent_user, "sudo", "adm")
            if self._group_exists(name)
        }
        if forbidden.intersection(groups):
            raise OperationError("terminal identity has privileged groups")
        with self.lock:
            if len(self.terminals) >= 4:
                raise OperationError("terminal session limit reached")
            master, slave = pty.openpty()
            try:
                child = subprocess.Popen(
                    [sys.executable, "-m", "qsuite.terminal_child"],
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    cwd=user.pw_dir,
                    user=user.pw_uid,
                    group=user.pw_gid,
                    extra_groups=(),
                    start_new_session=True,
                    env={
                        "HOME": user.pw_dir,
                        "USER": user.pw_name,
                        "PATH": "/usr/bin:/bin",
                        "TERM": "xterm-256color",
                        "LANG": "C.UTF-8",
                    },
                )  # noqa: S603
            except BaseException:
                os.close(master)
                raise
            finally:
                os.close(slave)
            identifier = uuid.uuid4().hex
            self.terminals[identifier] = (child, time.monotonic())
        return identifier, master

    @staticmethod
    def _group_exists(name):
        try:
            grp.getgrnam(name)
            return True
        except KeyError:
            return False

    @staticmethod
    def _kill(child):
        try:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        except (ProcessLookupError, ChildProcessError, subprocess.TimeoutExpired):
            pass

    def reap(self):
        with self.lock:
            for identifier, (child, started) in list(self.terminals.items()):
                exited = child.poll() is not None
                if exited or time.monotonic() - started > 3600:
                    if not exited:
                        self._kill(child)
                    self.terminals.pop(identifier, None)


def request(settings: Settings, operation: str, target: str = "", *, receive_fd=False):
    """Agent-side client. Fail closed if helper is unavailable."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(
            7500 if operation == "security.scan" else 920 if operation == "restore_verify" else 420
        )
        connection.connect(settings.helper_socket)
        connection.sendall(json.dumps({"operation": operation, "target": target}).encode() + b"\n")
        descriptors = []
        try:
            if receive_fd:
                chunk, ancillary, flags, _ = connection.recvmsg(
                    MAX_RESPONSE, socket.CMSG_SPACE(4 * array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC
                )
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        received = array.array("i")
                        received.frombytes(data[:len(data) - len(data) % received.itemsize])
                        descriptors.extend(received)
                if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or len(descriptors) > 1:
                    raise OperationError("invalid helper descriptors")
            else:
                chunk = b""
            while not chunk.endswith(b"\n"):
                block = connection.recv(min(65536, MAX_RESPONSE + 1 - len(chunk)))
                if not block:
                    break
                chunk += block
                if len(chunk) > MAX_RESPONSE:
                    raise OperationError("helper response too large")
            response = json.loads(chunk)
            if "error" in response:
                raise OperationError(response["error"])
            if receive_fd:
                if len(descriptors) != 1:
                    raise OperationError("helper descriptor missing")
                data = response["data"]
                return data, descriptors.pop()
            return response["data"]
        finally:
            for descriptor in descriptors:
                os.close(descriptor)


def serve(settings: Settings):
    uid = pwd.getpwnam(settings.agent_user).pw_uid
    if uid == 0:
        raise ValueError("agent must be unprivileged")
    broker = Broker(settings)
    path = Path(settings.helper_socket)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(path.parent, 0, pwd.getpwnam(settings.agent_user).pw_gid)
    os.chmod(path.parent, 0o750)  # noqa: S103 -- group traversal is needed; only root can write
    path.unlink(missing_ok=True)

    def handle(connection):
        with connection:
            master = None
            try:
                _, peer_uid, _ = struct.unpack(
                    "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if peer_uid != uid:
                    raise OperationError("unauthorized peer")
                connection.settimeout(5)
                raw = b""
                while b"\n" not in raw:
                    chunk = connection.recv(1024)
                    if not chunk:
                        raise OperationError("incomplete request")
                    raw += chunk
                    if len(raw) > MAX_REQUEST:
                        raise OperationError("request too large")
                if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
                    raise OperationError("one request per connection required")
                operation, target = decode_request(raw)
                if operation == "terminal.open" and not target:
                    identifier, master = broker.open_terminal()
                    connection.sendmsg(
                        [json.dumps({"data": {"id": identifier}}).encode() + b"\n"],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [master]))],
                    )
                elif operation == "backup.open":
                    from .downloads import archive_descriptor

                    metadata, master = archive_descriptor(broker.settings, target)
                    connection.sendmsg(
                        [json.dumps({"data": metadata}).encode() + b"\n"],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [master]))],
                    )
                else:
                    response = json.dumps(
                        {"data": broker.execute(operation, target)}, ensure_ascii=False
                    ).encode()
                    if len(response) > MAX_RESPONSE - 1:
                        raise OperationError("response too large")
                    connection.sendall(response + b"\n")
            except (OperationError, ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
                print(
                    json.dumps(
                        {
                            "component": "qsuite-helper",
                            "event": "request_rejected",
                            "error_type": type(exc).__name__,
                            "errno": getattr(exc, "errno", None),
                        }
                    ),
                    flush=True,
                )
                # Do not return exception text: it can contain paths or provider secrets.
                try:
                    connection.sendall(b'{"error":"operation unavailable or rejected"}\n')
                except OSError:
                    pass
            finally:
                if master is not None:
                    os.close(master)

    # Bound concurrent requests, including queued work.
    semaphore = threading.BoundedSemaphore(4)

    def bounded(connection):
        try:
            handle(connection)
        finally:
            semaphore.release()

    with (
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server,
        concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor,
    ):
        server.bind(str(path))
        os.chmod(path, 0o660)
        os.chown(path, 0, pwd.getpwnam(settings.agent_user).pw_gid)
        server.listen(8)
        server.settimeout(5)
        try:
            while True:
                broker.reap()
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                if semaphore.acquire(blocking=False):
                    executor.submit(bounded, connection)
                else:
                    connection.close()
        finally:
            for child, _ in broker.terminals.values():
                broker._kill(child)
            path.unlink(missing_ok=True)


def main():
    if os.geteuid() != 0:
        raise SystemExit("helper requires root")
    os.umask(0o077)
    serve(load(privileged=True))
