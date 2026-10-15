"""Backup downloads exercise real archive descriptors, HTTP and rejection paths."""

import asyncio
import os
import zipfile

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pytest

from qsuite.api import create_app
from qsuite.downloads import ArchiveResponse, archive_descriptor, selected_range
from qsuite.helper import OperationError
from .conftest import PASSWORD, login


@pytest.fixture
def archive(settings, tmp_path):
    root = tmp_path / "archives"
    root.mkdir()
    path = root / "snapshot.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("fixture.txt", "Isolated recovery fixture")
    configured = settings.model_copy(update={"integration": settings.integration.model_copy(update={"backup_root": str(root)})})
    return configured, path


@pytest.fixture
def download_app(archive):
    settings, path = archive
    opened = []

    def broker(s, operation, target="", **kwargs):
        if operation == "backup.open":
            result, fd = archive_descriptor(s, target)
            opened.append(fd)
            return result, fd
        return {}

    application = create_app(settings, Fernet.generate_key(), broker=broker)
    for role in ["owner", "admin", "mod", "helper", "log_viewer", "operator", "viewer"]:
        application.state.auth.create_user(role, PASSWORD, role)
    return application, path, opened


def assert_closed(descriptors):
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("header,expected", [("bytes=0-3", (0, 3)), ("bytes=8-", (8, 9)), ("bytes=-3", (7, 9)), ("bytes=-99", (0, 9)), ("bytes=0-99", (0, 9))])
def test_ranges(header, expected):
    assert selected_range(header, 10) == expected


@pytest.mark.parametrize("header", ["bytes=", "bytes=-0", "bytes=10-", "bytes=4-1", "bytes=0-1,3-4", "bytes=one-two", "bytes=" + "9" * 100 + "-"])
def test_bad_ranges(header):
    with pytest.raises(ValueError):
        selected_range(header, 10)


def test_descriptor_validates_zip_and_closes_directory(archive):
    settings, path = archive
    info, fd = archive_descriptor(settings, path.name)
    try:
        assert info["size"] == path.stat().st_size
        assert os.pread(fd, 2, 0) == b"PK"
        assert not os.get_inheritable(fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize("name", ["../snapshot.zip", "/snapshot.zip", "a..zip", "a\n.zip", "a;id.zip", "a.exe", ".hidden.zip", "a" * 220 + ".zip"])
def test_descriptor_rejects_identifiers(archive, name):
    with pytest.raises(OperationError):
        archive_descriptor(archive[0], name)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "incomplete", "garbage"])
def test_descriptor_rejects_unsafe_files(archive, kind):
    settings, original = archive
    path = original.parent / "unsafe.zip"
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, path)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "incomplete":
        path.write_bytes(original.read_bytes()[:-22])
    else:
        path.write_bytes(b"x" * 100)
    with pytest.raises((OSError, OperationError)):
        archive_descriptor(settings, path.name)


def test_descriptor_rejects_symlink_ancestor(archive, tmp_path):
    settings, path = archive
    alias = tmp_path / "alias"
    alias.symlink_to(path.parent, target_is_directory=True)
    settings = settings.model_copy(update={"integration": settings.integration.model_copy(update={"backup_root": str(alias)})})
    with pytest.raises(OSError):
        archive_descriptor(settings, path.name)


def test_http_full_head_resume_if_range_and_cleanup(download_app):
    app, path, opened = download_app
    with TestClient(app) as client:
        login(client)
        response = client.get("/api/v1/backups/snapshot.zip/download")
        assert response.status_code == 200 and response.content == path.read_bytes()
        assert response.headers["content-type"] == "application/zip"
        assert response.headers["content-disposition"] == 'attachment; filename="snapshot.zip"'
        assert response.headers["cache-control"] == "no-store"
        assert_closed(opened)
        etag = response.headers["etag"]
        for header, start, end in [("bytes=0-3", 0, 4), ("bytes=-7", -7, None)]:
            response = client.get("/api/v1/backups/snapshot.zip/download", headers={"Range": header, "If-Range": etag})
            assert response.status_code == 206 and response.content == path.read_bytes()[start:end]
            assert_closed(opened)
        for header in [{"Range": "bytes=0-1", "If-Range": '"stale"'}, {"Range": "unknown=0-1"}]:
            response = client.get("/api/v1/backups/snapshot.zip/download", headers=header)
            assert response.status_code == 200 and response.content == path.read_bytes()
        for _ in range(3):
            response = client.head("/api/v1/backups/snapshot.zip/download", headers={"Range": "bytes=0-1"})
            assert response.status_code == 200 and response.content == b""
            assert int(response.headers["content-length"]) == path.stat().st_size
        assert_closed(opened)
        audits = app.state.db.rows("SELECT result FROM audit WHERE action='backup.download'")
        assert {r["result"] for r in audits} == {"started", "sent"}


@pytest.mark.parametrize("role", ["mod", "helper", "log_viewer", "operator", "viewer"])
def test_download_permission_is_backend_enforced(download_app, role):
    app, _, opened = download_app
    with TestClient(app) as client:
        assert client.get("/api/v1/backups/snapshot.zip/download").status_code == 401
        login(client, role)
        for method in [client.get, client.head]:
            assert method("/api/v1/backups/snapshot.zip/download").status_code == 403
        assert not opened


def test_download_requires_fresh_session_and_releases_on_errors(download_app):
    app, _, opened = download_app
    with TestClient(app) as client:
        login(client)
        for _ in range(3):
            assert client.get("/api/v1/backups/snapshot.zip/download", headers={"Range": "bytes=999999-"}).status_code == 416
            assert client.get("/api/v1/backups/missing.zip/download").status_code == 404
        assert_closed(opened)
        with app.state.db.connect() as db:
            db.execute("UPDATE sessions SET fresh_until=0")
        assert client.get("/api/v1/backups/snapshot.zip/download").status_code == 403


def test_wan_download_requires_mfa(archive):
    settings, _ = archive
    settings = settings.model_copy(update={"mode": "production", "access": "wan", "origin": "https://testserver"})
    app = create_app(settings, Fernet.generate_key(), broker=lambda *a, **k: (_ for _ in ()).throw(AssertionError("broker must not be reached")))
    app.state.auth.create_user("owner", PASSWORD, "owner")
    with TestClient(app, base_url="https://testserver") as client:
        assert client.post("/api/v1/auth/login", json={"username": "owner", "password": PASSWORD}, headers={"Origin": "https://testserver"}).status_code == 200
        assert client.get("/api/v1/backups/snapshot.zip/download").status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["disconnect", "cancel", "send_error"])
async def test_response_releases_descriptor_and_slot_on_transport_failure(tmp_path, failure):
    fd = os.open(tmp_path / "fixture", os.O_CREAT | os.O_RDWR, 0o600)
    released = []

    def release():
        released.append(True)
        os.close(fd)

    async def stream():
        yield b"fixture"
        await asyncio.sleep(10)

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        if failure == "cancel":
            raise asyncio.CancelledError
        if failure == "send_error":
            raise OSError("disconnected")

    response = ArchiveResponse(stream(), release)
    try:
        await response({"type": "http", "asgi": {"spec_version": "2.0"}}, receive, send)
    except (asyncio.CancelledError, OSError, BaseExceptionGroup):
        pass
    assert released == [True]
    assert_closed([fd])


def test_archive_mutation_aborts_stream_and_closes_descriptor(download_app, monkeypatch):
    import qsuite.downloads as downloads

    app, path, opened = download_app
    original = downloads.os.pread
    reads = []
    monkeypatch.setattr(downloads, "CHUNK", 8)

    def pread(fd, count, offset):
        result = original(fd, count, offset)
        if count == 8:
            reads.append(offset)
            if len(reads) == 1:
                with path.open("ab") as handle:
                    handle.write(b"changed")
        return result

    monkeypatch.setattr(downloads.os, "pread", pread)
    with TestClient(app) as client:
        login(client)
        with pytest.raises(Exception, match="archive changed|errors in a TaskGroup"):
            client.get("/api/v1/backups/snapshot.zip/download")
        assert reads == [0]
        assert_closed(opened)
        assert app.state.db.rows("SELECT result FROM audit WHERE action='backup.download' ORDER BY id DESC")[0]["result"] == "interrupted"


def test_open_revision_mismatch_rejected_before_stream(archive):
    settings, path = archive
    descriptors = []

    def broker(s, operation, target="", **kwargs):
        if operation == "backup.open":
            info, fd = archive_descriptor(s, target)
            descriptors.append(fd)
            path.write_bytes(path.read_bytes() + b"changed")
            return info, fd
        return {}

    app = create_app(settings, Fernet.generate_key(), broker=broker)
    app.state.auth.create_user("owner", PASSWORD, "owner")
    with TestClient(app) as client:
        login(client)
        assert client.get("/api/v1/backups/snapshot.zip/download").status_code == 409
        assert_closed(descriptors)
