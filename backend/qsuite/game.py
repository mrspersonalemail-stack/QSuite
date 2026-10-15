"""Member-safe game projections; never return host collectors or raw server journals."""

import json
import os
import re
import socket
import stat
import struct
import time

import psutil

from .db import redact


def varint(n):
    n &= 0xFFFFFFFF
    output = bytearray()
    while True:
        byte = n & 127
        n >>= 7
        output.append(byte | (128 if n else 0))
        if not n:
            return bytes(output)


def read_varint(connection, deadline=None):
    n = 0
    for i in range(5):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("game status deadline reached")
            connection.settimeout(remaining)
        raw = connection.recv(1)
        if not raw:
            raise ValueError("incomplete game response")
        n |= (raw[0] & 127) << (i * 7)
        if not raw[0] & 128:
            return n
    raise ValueError("invalid game response")


def minecraft_status(settings):
    integration = settings.integration
    result = {
        "configured": bool(integration.game_port and integration.minecraft_root),
        "online": False,
        "players": None,
        "max_players": None,
        "version": None,
        "uptime": None,
        "tps": None,
        "mspt": None,
    }
    if not result["configured"]:
        return result
    try:
        with socket.create_connection(("127.0.0.1", integration.game_port), timeout=3) as connection:
            deadline = time.monotonic() + 3
            handshake = (
                b"\x00" + varint(-1) + b"\x09localhost" + struct.pack(">H", integration.game_port) + b"\x01"
            )
            connection.sendall(varint(len(handshake)) + handshake + b"\x01\x00")
            size = read_varint(connection, deadline)
            if not 3 <= size <= 65536 or read_varint(connection, deadline) != 0:
                raise ValueError("invalid game status")
            length = read_varint(connection, deadline)
            if not 2 <= length <= size or length > 65530:
                raise ValueError("invalid status length")
            body = bytearray()
            while len(body) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("game status deadline reached")
                connection.settimeout(remaining)
                chunk = connection.recv(length - len(body))
                if not chunk:
                    raise ValueError("incomplete status")
                body.extend(chunk)
            data = json.loads(body)
        players = data.get("players", {})
        for source, dest in (("online", "players"), ("max", "max_players")):
            value = players.get(source)
            result[dest] = value if type(value) is int and 0 <= value <= 100000 else None
        version = data.get("version", {}).get("name")
        result["version"] = redact(version, 100) if isinstance(version, str) else None
        result["online"] = True
        for p in psutil.process_iter(["name", "create_time"]):
            try:
                if p.info["name"] == "java" and p.cwd() == integration.minecraft_root:
                    result["uptime"] = max(0, int(time.time() - p.info["create_time"]))
                    break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except (OSError, ValueError, TypeError):
        pass
    return result


def minecraft_logs(settings):
    root = settings.integration.minecraft_root
    if not root:
        return {"lines": [], "scope": "player activity only"}
    descriptors = []
    try:
        # Walk every ancestor with openat/O_NOFOLLOW, not only the final game directory.
        from pathlib import Path

        descriptors.append(os.open("/", os.O_RDONLY | os.O_DIRECTORY))
        for component in Path(root).parts[1:]:
            if component in {".", ".."}:
                raise ValueError("non-canonical game root")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1])
            os.close(descriptors.pop())
            descriptors.append(child)
        descriptors.append(
            os.open("logs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1])
        )
        descriptors.append(
            os.open("latest.log", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptors[-1])
        )
        info = os.fstat(descriptors[-1])
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("game log must be a regular file")
        os.lseek(descriptors[-1], max(0, info.st_size - 65536), os.SEEK_SET)
        raw = os.read(descriptors[-1], 65536).decode("utf-8", "replace")
    except (OSError, ValueError):
        return {"lines": [], "scope": "player activity only", "state": "unavailable"}
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
    lines = []
    for line in raw.splitlines():
        match = re.fullmatch(r"\[([0-9:]{8})\] \[Server thread/INFO\](?: \[.*?\])?: (.+)", line)
        if not match:
            continue
        message = match[2]
        if not (
            re.fullmatch(r"[A-Za-z0-9_]{1,16} (?:joined|left) the game", message)
            or re.fullmatch(r"<[A-Za-z0-9_]{1,16}> .{1,400}", message)
        ):
            continue
        safe = redact(message, 500)
        safe = re.sub(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?\b", "[address]", safe)
        safe = re.sub(r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]+\b", "[address]", safe)
        safe = re.sub(r"(?:/[A-Za-z0-9_.-]+){2,}", "[path]", safe)
        lines.append({"time": match[1], "message": safe})
    return {"lines": lines[-100:], "scope": "player activity only; internal errors and diagnostics excluded"}
