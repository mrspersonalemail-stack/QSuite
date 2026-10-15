import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from qsuite.config import Settings
from qsuite.tls import validate
from .conftest import login, PASSWORD


@pytest.fixture
def certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "panel.example.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("panel.example.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return str(cert_path), str(key_path)


def test_public_default_requires_trusted_certificate():
    assert Settings().require_trusted_tls is True


def test_optional_trust_still_requires_https():
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(
            access="wan",
            origin="http://example.test",
            bind="0.0.0.0",
            tls_cert="/cert.pem",
            tls_key="/key.pem",
            require_trusted_tls=False,
        )


def test_self_signed_allowed_only_when_trust_optional(certificate):
    cert, key = certificate
    validate(cert, key, "panel.example.test", False)
    with pytest.raises(ValueError, match="trusted CA"):
        validate(cert, key, "panel.example.test", True)


def test_optional_trust_does_not_bypass_hostname(certificate):
    with pytest.raises(ValueError, match="hostname"):
        validate(*certificate, "wrong.example.test", False)


def test_optional_trust_does_not_bypass_key_match(certificate, tmp_path):
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = tmp_path / "wrong.pem"
    key.write_bytes(
        wrong.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    with pytest.raises(ValueError, match="differ"):
        validate(certificate[0], str(key), "panel.example.test", False)


def test_owner_toggle_requires_fresh_authentication(client, app):
    headers = login(client)
    with app.state.db.connect() as c:
        c.execute("UPDATE sessions SET fresh_until=0")
    assert (
        client.post("/api/v1/access/tls-policy", json={"target": "optional"}, headers=headers).status_code
        == 403
    )
    assert (
        client.post("/api/v1/auth/reauthenticate", json={"password": PASSWORD}, headers=headers).status_code
        == 200
    )
    result = client.post("/api/v1/access/tls-policy", json={"target": "optional"}, headers=headers)
    assert result.status_code == 200
    assert result.json()["https_required"] is True
    assert client.get("/api/v1/settings").json()["require_trusted_tls"] is False


def test_viewer_cannot_change_trust_policy(client, app):
    app.state.auth.create_user("viewer", PASSWORD, "viewer")
    headers = login(client, "viewer")
    assert (
        client.post("/api/v1/access/tls-policy", json={"target": "optional"}, headers=headers).status_code
        == 403
    )
