"""Portable host collectors. Missing measurements are null, never invented."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import socket
import sqlite3
import time
import math

import psutil

from .config import Settings


def status(settings: Settings):
    memory, swap = psutil.virtual_memory(), psutil.swap_memory()
    disks = []
    for mount in sorted(
        {"/", *([settings.integration.backup_mount] if settings.integration.backup_mount else [])}
    ):
        try:
            usage = psutil.disk_usage(mount)
            disks.append(
                {
                    "mount": mount,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                }
            )
        except OSError:
            disks.append({"mount": mount, "state": "unavailable"})
    addresses = []
    for name, entries in psutil.net_if_addrs().items():
        for item in entries:
            if item.family in (socket.AF_INET, socket.AF_INET6):
                addresses.append({"interface": name, "address": item.address})
    temps = psutil.sensors_temperatures()
    temperature = next(
        (row.current for name, rows in temps.items() if name in {"coretemp", "k10temp"} for row in rows), None
    )
    java = []
    # Match process cwd to configured server, not every Java process on the host.
    root = settings.integration.minecraft_root
    if root:
        for process in psutil.process_iter(["pid", "name", "memory_info", "cpu_times", "create_time"]):
            try:
                if process.info["name"] == "java" and process.cwd() == root:
                    java.append(
                        {
                            "pid": process.pid,
                            "rss": process.info["memory_info"].rss,
                            "uptime": time.time() - process.info["create_time"],
                            "cpu_percent": None,
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return {
        "ts": int(time.time()),
        "hostname": socket.gethostname(),
        "os": platform.freedesktop_os_release().get("PRETTY_NAME", platform.system()),
        "kernel": platform.release(),
        "uptime": int(time.time() - psutil.boot_time()),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "cpu_temperature": temperature,
        "load": list(os.getloadavg()),
        "memory": {
            "total": memory.total,
            "used": memory.used,
            "available": memory.available,
            "percent": memory.percent,
        },
        "swap": {"total": swap.total, "used": swap.used},
        "disks": disks,
        "addresses": addresses,
        "minecraft": {
            "configured": bool(root),
            "processes": java,
            "players": None,
            "tps": None,
            "mspt": None,
        },
        "access": settings.access,
    }


def history(settings: Settings, seconds: int):
    path = settings.integration.performance_db
    if path and Path(path).is_file():
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT ts,cpu_pct,load1,mem_total_bytes,mem_available_bytes,mc_rss_bytes,net_rx_bps,net_tx_bps FROM samples WHERE ts>? ORDER BY ts LIMIT 9000",
                (int(time.time()) - seconds,),
            ).fetchall()
        stride = max(1, math.ceil(len(rows) / 720))
        return {"source": "legacy", "samples": [dict(row) for row in rows[::stride]], "recorded_samples": len(rows)}
    with sqlite3.connect(f"file:{settings.database}?mode=ro", uri=True, timeout=2) as connection:
        rows = connection.execute(
            "SELECT payload FROM samples WHERE ts>? ORDER BY ts LIMIT 9000", (int(time.time()) - seconds,)
        ).fetchall()
    stride = max(1, math.ceil(len(rows) / 720))
    samples = []
    for row in rows[::stride]:
        data = json.loads(row[0])
        samples.append({"ts": data.get("ts"), "cpu_pct": data.get("cpu_percent"),
                        "load1": data.get("load", [None])[0],
                        "mem_total_bytes": data.get("memory", {}).get("total"),
                        "mem_available_bytes": data.get("memory", {}).get("available")})
    return {"source": "qsuite", "samples": samples, "recorded_samples": len(rows)}
