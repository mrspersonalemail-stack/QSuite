"""Certificate validity, identity and key matching, independent of optional CA trust."""

import datetime as dt
import ipaddress
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def validate(cert_path: str, key_path: str, hostname: str, require_trusted: bool):
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    now = dt.datetime.now(dt.timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("TLS certificate is not currently valid")
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        address = ipaddress.ip_address(hostname)
        matches = address in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        hostname = hostname.lower()
        matches = any(
            name.lower() == hostname
            or name.startswith("*.")
            and hostname.endswith(name[1:].lower())
            and hostname.count(".") == name.count(".")
            for name in san.get_values_for_type(x509.DNSName)
        )
    if not matches:
        raise ValueError("TLS certificate does not match configured hostname")
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(encoding, form) != key.public_key().public_bytes(encoding, form):
        raise ValueError("TLS certificate and private key differ")
    if require_trusted:
        # argv comes from validated configuration; no shell or secrets in arguments/output.
        result = subprocess.run(  # noqa: S603 -- validated configuration argv, no shell
            [
                "/usr/bin/openssl",
                "verify",
                "-purpose",
                "sslserver",
                "-CAfile",
                "/etc/ssl/certs/ca-certificates.crt",
                "-untrusted",
                cert_path,
                cert_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )  # noqa: S603
        if result.returncode != 0:
            raise ValueError("trusted WAN requires a certificate chaining to a trusted CA")
