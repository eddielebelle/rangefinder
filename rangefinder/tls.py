"""Self-signed TLS material for facades that serve over TLS (HTTPS, LDAPS).

Uses ``cryptography`` (already present transitively via impacket) to mint a self-signed
certificate at startup and returns a server ``ssl.SSLContext``. Certs are cached per
common name so multiple TLS facades on a host reuse one cert. nmap's ssl-cert script and
any client will see a real (if untrusted) certificate.
"""

from __future__ import annotations

import atexit
import datetime
import hashlib
import ipaddress
import os
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_CACHE: dict[str, ssl.SSLContext] = {}
_TMPFILES: list[str] = []


def _san_entry(name: str):
    try:
        return x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        return x509.DNSName(name)


def _make_cert(common_name: str, sans: list[str]) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt_names = [_san_entry(n) for n in dict.fromkeys([common_name, *sans])]
    # Backdate issuance to a stable-per-host point 3-15 months ago so the cert reads as a
    # mid-life internal cert, not one minted at range boot (a freshly-dated cert is a tell) —
    # and skew the time-of-day per host so certs don't all share one batch-minted timestamp.
    h = int(hashlib.sha256(common_name.encode()).hexdigest(), 16)
    not_before = now - datetime.timedelta(days=90 + h % 360, seconds=(h // 360) % 86_400)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def server_context(common_name: str, sans: list[str] | None = None) -> ssl.SSLContext:
    """Return a server SSLContext with a self-signed cert for *common_name*."""
    sans = sans or []
    cache_key = common_name + "|" + ",".join(sorted(sans))
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    cert_pem, key_pem = _make_cert(common_name, sans)
    # SSLContext.load_cert_chain needs file paths; write to temp files kept for process life.
    cert_file = tempfile.NamedTemporaryFile(prefix="rf-cert-", suffix=".pem", delete=False)
    key_file = tempfile.NamedTemporaryFile(prefix="rf-key-", suffix=".pem", delete=False)
    cert_file.write(cert_pem)
    key_file.write(key_pem)
    cert_file.close()
    key_file.close()
    _TMPFILES.extend([cert_file.name, key_file.name])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file.name, key_file.name)
    _CACHE[cache_key] = ctx
    return ctx


@atexit.register
def _cleanup() -> None:
    for path in _TMPFILES:
        try:
            os.unlink(path)
        except OSError:
            pass
