"""A real TLS server on loopback, for testing the client against TLS itself.

Why this exists rather than mocking `urllib`. The properties under test are
"the agent refuses a certificate signed by the wrong CA", "the agent refuses a
certificate for the wrong hostname" and "the agent presents its client
certificate". A mock cannot fail any of those, because a mock has no TLS in it:
patching `urlopen` would assert that the code calls a function, not that the
connection is verified. The one test that matters most here is the one that
only a real handshake can fail.

This does NOT make these integration tests. Nothing outside the process is
needed: no server to start, no database, no root, no DNS and no route off the
machine. The harness binds 127.0.0.1 on an ephemeral port, generates every
certificate in memory, and tears the listener down with the context manager.
A developer with no network at all can run it.

Certificates are generated per fixture rather than committed. Committed test
key material is key material in a repository, and it expires.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import http.server
import ipaddress
import json
import os
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.timezone.utc


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


@dataclasses.dataclass(frozen=True)
class Authority:
    """A CA that can issue leaf certificates for the harness."""

    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


def make_authority(common_name: str) -> Authority:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    subject = _name(common_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return Authority(key=key, certificate=certificate)


def issue_leaf(
    authority: Authority,
    *,
    common_name: str,
    hostnames: tuple[str, ...] = (),
    ip_addresses: tuple[str, ...] = (),
    server_auth: bool = False,
    client_auth: bool = False,
    not_before: dt.datetime | None = None,
    valid_for: dt.timedelta = dt.timedelta(days=1),
    public_key: ec.EllipticCurvePublicKey | None = None,
) -> tuple[ec.EllipticCurvePrivateKey | None, x509.Certificate]:
    """Issue a leaf certificate. Returns (key, certificate).

    `public_key` lets a caller certify a key it already holds, which is how the
    tests build a certificate for the agent's own generated keypair. The
    returned key is None in that case, because the harness never had it.
    """
    key: ec.EllipticCurvePrivateKey | None = None
    if public_key is None:
        key = ec.generate_private_key(ec.SECP256R1())
        public_key = key.public_key()

    now = not_before or dt.datetime.now(UTC) - dt.timedelta(minutes=5)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(authority.certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + valid_for)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    alternative: list[x509.GeneralName] = [x509.DNSName(host) for host in hostnames]
    alternative += [x509.IPAddress(ipaddress.ip_address(value)) for value in ip_addresses]
    if alternative:
        builder = builder.add_extension(x509.SubjectAlternativeName(alternative), critical=False)

    usages = []
    if server_auth:
        usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if client_auth:
        usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if usages:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)

    return key, builder.sign(authority.key, hashes.SHA256())


def write_pem(path: Path, data: bytes, *, mode: int = 0o644) -> Path:
    """Write PEM bytes at an exact mode, created restrictively."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    return path


def write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> Path:
    return write_pem(
        path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        mode=0o600,
    )


@dataclasses.dataclass
class RecordedRequest:
    """What the server saw. Used to assert on what the client actually sent."""

    path: str
    headers: dict[str, str]
    body: bytes
    peer_certificate: dict[str, Any] | None

    def json(self) -> Any:
        return json.loads(self.body)


@dataclasses.dataclass
class CannedResponse:
    status: int = 200
    body: bytes = b"{}"
    content_type: str = "application/json"
    #: Written in chunks with a pause between them, to exercise the client's
    #: total-deadline bound against a slow-drip response.
    chunk_delay_seconds: float = 0.0
    location: str | None = None


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Set by the server factory below.
    recorded: list[RecordedRequest]
    canned: list[CannedResponse]

    def log_message(self, fmt: str, *args: Any) -> None:
        """Silence. The default writes every request to stderr."""

    def _record(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        peer: dict[str, Any] | None = None
        connection = self.connection
        if isinstance(connection, ssl.SSLSocket):
            raw = connection.getpeercert()
            peer = dict(raw) if raw else None
        self.recorded.append(
            RecordedRequest(
                path=self.path,
                headers={key.lower(): value for key, value in self.headers.items()},
                body=body,
                peer_certificate=peer,
            )
        )
        return body

    def _respond(self) -> None:
        self._record()
        canned = self.canned.pop(0) if len(self.canned) > 1 else self.canned[0]

        self.send_response(canned.status)
        self.send_header("Content-Type", canned.content_type)
        self.send_header("Content-Length", str(len(canned.body)))
        if canned.location:
            self.send_header("Location", canned.location)
        self.end_headers()

        if canned.chunk_delay_seconds and canned.body:
            import time

            for index in range(len(canned.body)):
                self.wfile.write(canned.body[index : index + 1])
                self.wfile.flush()
                time.sleep(canned.chunk_delay_seconds)
        else:
            self.wfile.write(canned.body)

    # BaseHTTPRequestHandler dispatches on `do_<METHOD>`, so the casing is
    # imposed by the standard library rather than chosen.
    do_POST = _respond  # noqa: N815
    do_GET = _respond  # noqa: N815


@contextlib.contextmanager
def tls_server(
    *,
    server_certificate: Path,
    server_key: Path,
    client_ca: Path | None = None,
    responses: list[CannedResponse] | None = None,
    host: str = "127.0.0.1",
) -> Iterator[tuple[str, list[RecordedRequest]]]:
    """Run an HTTPS server on an ephemeral loopback port.

    Yields `(base_url, recorded)`. `base_url` uses `localhost` so the client's
    hostname verification has something real to check against the certificate's
    SAN - connecting to an IP literal would exercise a different and weaker
    code path in `ssl`.

    `client_ca` turns on mutual TLS with `CERT_REQUIRED`, which is what the
    nginx device listener does. A client that presents no certificate fails the
    handshake, exactly as it would in deployment.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(server_certificate), keyfile=str(server_key))
    if client_ca is not None:
        context.load_verify_locations(cafile=str(client_ca))
        context.verify_mode = ssl.CERT_REQUIRED

    recorded: list[RecordedRequest] = []
    handler = type(
        "_BoundHandler",
        (_Handler,),
        {"recorded": recorded, "canned": responses or [CannedResponse()]},
    )

    server = http.server.ThreadingHTTPServer((host, 0), handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"https://localhost:{port}", recorded
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
