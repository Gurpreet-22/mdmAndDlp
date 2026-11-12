#!/usr/bin/env python3
"""A reference mTLS terminator, for verification only. NOT for production.

Read this paragraph before using this file for anything.

This is a small TLS-terminating reverse proxy that implements the same contract
as `deploy/nginx/ubuntuguard-dev.conf`: two listeners, one requiring a verified
client certificate and one not, both overwriting the four `X-Client-*` identity
headers from what TLS actually verified. It exists because the mTLS properties
the system depends on cannot be demonstrated without a real handshake, and
nginx cannot always be installed on a development machine.

**It is not a substitute for nginx.** Running this proves that the server's
header-trust path, the agent's client-certificate handling and the device plane
agree with each other. It proves nothing whatsoever about
`ubuntuguard-dev.conf`, which is a separate artefact that only nginx can
exercise. Anything claiming "mTLS is verified" on the strength of this script
alone is overclaiming, and `deploy/nginx/README.md` carries the commands that
close the gap.

It is also deliberately not production-grade: single-threaded per connection,
no connection reuse upstream, no timeouts worth the name, no request-size
limits beyond the backend's own. Use nginx.

Usage:
    python3 tools/mtls_reference_proxy.py \\
        --server-cert /etc/ubuntuguard/dev-tls/server.crt \\
        --server-key  /etc/ubuntuguard/dev-tls/server.key \\
        --device-ca   /etc/ubuntuguard/dev-tls/device-ca.crt
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import http.server
import ssl
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

#: The headers the application derives device identity from. All four are
#: overwritten on every request, which is what makes a client-supplied one
#: unforgeable. See deploy/nginx/client-cert-headers.conf.
IDENTITY_HEADERS = ("x-client-verify", "x-client-cert", "x-client-dn", "x-client-serial")

#: Also overwritten, for the same reason: if the proxy did not set it, a
#: client's own X-Forwarded-For would pass straight through.
FORWARDED_HEADERS = ("x-forwarded-for", "x-forwarded-proto")

#: Headers that must never be copied upstream from the client.
_STRIPPED = frozenset(IDENTITY_HEADERS) | frozenset(FORWARDED_HEADERS) | {"connection"}

DEVICE_PLANE_PREFIX = "/api/v1/devices/me/"
ENROLL_PATH = "/api/v1/enroll"


def der_to_pem(der: bytes) -> str:
    """DER -> PEM, the form nginx forwards in `$ssl_client_escaped_cert`."""
    import base64
    import textwrap

    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def _subject_dn(der: bytes) -> str:
    """RFC 4514 subject, approximating nginx's `$ssl_client_s_dn`."""
    try:
        from cryptography import x509

        return x509.load_der_x509_certificate(der).subject.rfc4514_string()
    except Exception:  # noqa: BLE001 - informational header only
        return ""


def _serial(der: bytes) -> str:
    try:
        from cryptography import x509

        return format(x509.load_der_x509_certificate(der).serial_number, "X")
    except Exception:  # noqa: BLE001 - informational header only
        return ""


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Bound by the server factory.
    backend: tuple[str, int]
    require_client_certificate: bool
    quiet: bool

    def log_message(self, fmt: str, *args: Any) -> None:
        if not self.quiet:
            super().log_message(fmt, *args)

    # --- the identity headers ------------------------------------------- #

    def _identity(self) -> dict[str, str]:
        """What TLS actually verified, as the four headers.

        On a listener with no client certificate requested, this is
        `("NONE", "", "", "")` - which is exactly what nginx forwards, and
        exactly what the application needs to see in order to refuse.
        """
        connection = self.connection
        der: bytes | None = None
        if isinstance(connection, ssl.SSLSocket):
            raw = connection.getpeercert(binary_form=True)
            der = raw if raw else None

        if der is None:
            return {
                "X-Client-Verify": "NONE",
                "X-Client-Cert": "",
                "X-Client-DN": "",
                "X-Client-Serial": "",
            }

        # SUCCESS only because the socket is CERT_REQUIRED against the device
        # CA, so a certificate being present at all means the chain verified.
        return {
            "X-Client-Verify": "SUCCESS",
            # Percent-encoded, newlines included, as $ssl_client_escaped_cert.
            "X-Client-Cert": quote(der_to_pem(der), safe=""),
            "X-Client-DN": _subject_dn(der),
            "X-Client-Serial": _serial(der),
        }

    # --- routing --------------------------------------------------------- #

    def _misdirected(self) -> bool:
        """Mirror the nginx config's 421 responses for the wrong plane."""
        path = self.path.split("?", 1)[0]
        if self.require_client_certificate and path == ENROLL_PATH:
            return True
        return bool(not self.require_client_certificate and path.startswith(DEVICE_PLANE_PREFIX))

    def _proxy(self) -> None:
        if self._misdirected():
            self.send_response(421)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""

        # Client headers are copied EXCEPT the ones that assert identity.
        # Those are then set from the TLS layer, so a client that sent its own
        # has them replaced rather than merged.
        forwarded = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _STRIPPED
        }
        forwarded.update(self._identity())
        forwarded["X-Forwarded-For"] = self.client_address[0]
        forwarded["X-Forwarded-Proto"] = "https"
        forwarded["Connection"] = "close"

        host, port = self.backend
        upstream = http.client.HTTPConnection(host, port, timeout=30)
        try:
            upstream.request(self.command, self.path, body=body, headers=forwarded)
            response = upstream.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() in {"transfer-encoding", "connection", "content-length"}:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except OSError as exc:
            self.send_response(502)
            message = f"upstream unreachable: {exc}".encode()
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)
        finally:
            upstream.close()

    do_GET = _proxy  # noqa: N815 - BaseHTTPRequestHandler dispatches on do_<METHOD>
    do_POST = _proxy  # noqa: N815
    do_PUT = _proxy  # noqa: N815


def make_server(
    *,
    port: int,
    server_certificate: Path,
    server_key: Path,
    device_ca: Path | None,
    backend: tuple[str, int] = ("127.0.0.1", 8000),
    host: str = "127.0.0.1",
    quiet: bool = True,
) -> http.server.ThreadingHTTPServer:
    """One listener. `device_ca` set means mutual TLS is mandatory.

    `CERT_REQUIRED` with a loaded CA is the equivalent of nginx's
    `ssl_verify_client on`: the handshake fails when no valid certificate is
    presented, so nothing downstream is reachable without one. There is no
    equivalent here of `optional_no_ca`, deliberately - a mode that forwards an
    unverified certificate while reporting SUCCESS has no legitimate use.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(server_certificate), keyfile=str(server_key))
    if device_ca is not None:
        context.load_verify_locations(cafile=str(device_ca))
        context.verify_mode = ssl.CERT_REQUIRED

    handler = type(
        "_BoundHandler",
        (_Handler,),
        {
            "backend": backend,
            "require_client_certificate": device_ca is not None,
            "quiet": quiet,
        },
    )
    server = http.server.ThreadingHTTPServer((host, port), handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


@contextlib.contextmanager
def run_both_planes(
    *,
    server_certificate: Path,
    server_key: Path,
    device_ca: Path,
    enroll_port: int = 0,
    device_port: int = 0,
    backend: tuple[str, int] = ("127.0.0.1", 8000),
) -> Iterator[tuple[str, str]]:
    """Both listeners, yielding `(enroll_base_url, device_base_url)`.

    Ports default to 0 so a test gets ephemeral ones and cannot collide with a
    real nginx or another run.
    """
    enroll = make_server(
        port=enroll_port,
        server_certificate=server_certificate,
        server_key=server_key,
        device_ca=None,
        backend=backend,
    )
    device = make_server(
        port=device_port,
        server_certificate=server_certificate,
        server_key=server_key,
        device_ca=device_ca,
        backend=backend,
    )
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (enroll, device)
    ]
    for thread in threads:
        thread.start()
    try:
        yield (
            f"https://localhost:{enroll.server_address[1]}",
            f"https://localhost:{device.server_address[1]}",
        )
    finally:
        for server in (enroll, device):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-cert", type=Path, required=True)
    parser.add_argument("--server-key", type=Path, required=True)
    parser.add_argument("--device-ca", type=Path, required=True)
    parser.add_argument("--enroll-port", type=int, default=8443)
    parser.add_argument("--device-port", type=int, default=8444)
    parser.add_argument("--backend-port", type=int, default=8000)
    arguments = parser.parse_args()

    print(
        "WARNING: this is a verification tool, not a production proxy. It proves\n"
        "         the mTLS contract, NOT the nginx configuration. Use nginx.\n",
        file=sys.stderr,
    )
    with run_both_planes(
        server_certificate=arguments.server_cert,
        server_key=arguments.server_key,
        device_ca=arguments.device_ca,
        enroll_port=arguments.enroll_port,
        device_port=arguments.device_port,
        backend=("127.0.0.1", arguments.backend_port),
    ) as (enroll_url, device_url):
        print(f"enrollment plane (no client certificate) : {enroll_url}")
        print(f"device plane     (client certificate req): {device_url}")
        print("Ctrl-C to stop.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
