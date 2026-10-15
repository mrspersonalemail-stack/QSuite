"""Read-only archive descriptors and bounded, authenticated browser downloads."""

import asyncio
from email.utils import formatdate
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sqlite3
import threading
import time
import weakref

from fastapi import Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from .helper import OperationError
from .permissions import permitted

ARCHIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\.zip", re.ASCII)
CHUNK = 262144


def directory_descriptor(root):
    """Open every ancestor without following symlinks, holding the chosen directory."""
    if not root or not Path(root).is_absolute() or ".." in Path(root).parts:
        raise OperationError("backup directory unavailable")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in Path(root).parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def revision(metadata):
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
    return hashlib.sha256(repr(identity).encode()).hexdigest()


def archive_descriptor(settings, name):
    """Only completed ZIPs directly in the configured root; never a supplied path."""
    if not ARCHIVE_NAME.fullmatch(name) or ".." in name:
        raise OperationError("invalid archive identifier")
    directory = directory_descriptor(settings.integration.backup_root)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size < 22:
            raise OperationError("archive unavailable")
        if os.pread(fd, 4, 0) not in {b"PK\x03\x04", b"PK\x05\x06"}:
            raise OperationError("archive is not a ZIP")
        # Read a bounded ZIP trailer, including the maximum possible comment.
        # This confirms finalization, not CRC/world integrity.
        tail = os.pread(fd, min(65557, before.st_size), max(0, before.st_size - 65557))
        index = tail.rfind(b"PK\x05\x06")
        while index >= 0:
            if index + 22 <= len(tail):
                fields = struct.unpack_from("<4s4H2LH", tail, index)
                if index + 22 + fields[-1] == len(tail) and fields[1] == fields[2] == 0:
                    break
            index = tail.rfind(b"PK\x05\x06", 0, index)
        if index < 0 or revision(os.fstat(fd)) != revision(before):
            raise OperationError("archive is incomplete or changing")
        return {"id": name, "size": before.st_size, "modified": int(before.st_mtime), "revision": revision(before)}, fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        os.close(directory)


def selected_range(header, size):
    match = re.fullmatch(r"bytes=([0-9]{0,20})-([0-9]{0,20})", header)
    if not match or not any(match.groups()):
        raise ValueError("unsupported byte range")
    first, last = match.groups()
    if first:
        start, end = int(first), min(int(last), size - 1) if last else size - 1
    else:
        length = int(last)
        if length == 0:
            raise ValueError("empty suffix range")
        start, end = max(0, size - length), size - 1
    if not 0 <= start <= end < size:
        raise ValueError("unsatisfiable range")
    return start, end


class ArchiveResponse(StreamingResponse):
    """Own the descriptor and slot even on disconnect, timeout or task cancellation."""

    def __init__(self, stream, release, **kwargs):
        super().__init__(stream, **kwargs)
        self.cleanup = weakref.finalize(self, release)

    async def __call__(self, scope, receive, send):
        async def bounded_send(message):
            await asyncio.wait_for(send(message), timeout=60)

        try:
            await super().__call__(scope, receive, bounded_send)
        finally:
            self.cleanup()


def routes(app, db, auth, permission, source, settings, broker):
    slots = threading.BoundedSemaphore(2)

    @app.get("/api/v1/backups/{archive}/download", operation_id="download_backup")
    @app.head("/api/v1/backups/{archive}/download", operation_id="head_backup")
    def download(archive: str, request: Request, actor=Depends(permission("backup.download", fresh=True))):
        if not slots.acquire(blocking=False):
            raise HTTPException(429, "two backup downloads are already active", headers={"Retry-After": "10"})
        fd = None
        transferred = False

        def release():
            if fd is not None:
                os.close(fd)
            slots.release()

        try:
            try:
                info, fd = broker(settings, "backup.open", archive, receive_fd=True)
            except (OperationError, OSError, ValueError) as exc:
                raise HTTPException(404, "completed backup archive unavailable") from exc
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or revision(metadata) != info["revision"]:
                raise HTTPException(409, "backup changed; refresh the list")
            size = metadata.st_size
            etag = '"' + info["revision"] + '"'
            modified = formatdate(info["modified"], usegmt=True)
            headers = {"Content-Disposition": f'attachment; filename="{archive}"',
                       "Accept-Ranges": "bytes", "ETag": etag, "Last-Modified": modified,
                       "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
            start, end, code = 0, size - 1, 200
            header = request.headers.get("range")
            if request.method == "GET" and header and header.startswith("bytes=") and request.headers.get("if-range", etag) in {etag, modified}:
                try:
                    start, end = selected_range(header, size)
                except ValueError as exc:
                    raise HTTPException(416, "requested range unavailable", headers={"Content-Range": f"bytes */{size}"}) from exc
                code = 206
                headers["Content-Range"] = f"bytes {start}-{end}/{size}"
            headers["Content-Length"] = str(end - start + 1)
            if request.method == "HEAD":
                return Response(status_code=200, headers=headers, media_type="application/zip")
            db.audit(actor["username"], source(request), "backup.download", "started", archive)

            async def stream():
                offset, checked, began = start, 0, time.monotonic()
                complete = False
                try:
                    while offset <= end:
                        now = time.monotonic()
                        if now - began > 21600:
                            raise OSError("download time limit reached")
                        if now - checked >= 10:
                            live = await run_in_threadpool(auth.session_by_hash, actor["token_hash"])
                            if (not permitted(live, "backup.download") or live["must_change"] or
                                live["mfa_required"] and not live["mfa"] or settings.access == "wan" and not live["mfa"]):
                                raise OSError("download access revoked")
                            checked = now
                        if revision(os.fstat(fd)) != info["revision"]:
                            raise OSError("archive changed during transfer")
                        chunk = await run_in_threadpool(os.pread, fd, min(CHUNK, end - offset + 1), offset)
                        if not chunk:
                            raise OSError("archive truncated during transfer")
                        offset += len(chunk)
                        yield chunk
                    complete = True
                finally:
                    # Failure to write an audit event must not prevent descriptor cleanup.
                    try:
                        db.audit(actor["username"], source(request), "backup.download", "sent" if complete else "interrupted", archive)
                    except (sqlite3.Error, OSError):
                        pass

            response = ArchiveResponse(stream(), release, status_code=code, headers=headers, media_type="application/zip")
            transferred = True
            return response
        finally:
            if not transferred:
                release()
