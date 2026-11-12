"""Device identity from an nginx-terminated mTLS connection.

How the device plane establishes identity
-----------------------------------------
nginx terminates TLS, verifies the client certificate against the internal CA,
and forwards the result in headers. The application re-derives everything it
needs from the forwarded certificate rather than trusting a summary.

The headers are therefore as powerful as the client certificate itself: anyone
who can set `X-Client-Cert` can impersonate any device. Two things keep that
from being a hole:

1. The headers are believed only when the request arrives from a trusted peer.
   A request from anywhere else is REFUSED outright rather than having its
   headers ignored, so a misconfigured deployment fails loudly instead of
   quietly authenticating strangers.
2. nginx must overwrite all four headers unconditionally on every request, so a
   client cannot smuggle its own through. That belongs in the nginx config, and
   the sample config carries a comment saying so.

Why the whole certificate and not a fingerprint header
------------------------------------------------------
nginx's `$ssl_client_fingerprint` is SHA-1. Rather than pin device identity to
a SHA-1 digest, the proxy forwards `$ssl_client_escaped_cert` and this module
computes SHA-256 itself. It also means expiry and subject are read from the
certificate, not from whatever the proxy chose to summarise.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from ubuntuguard.constants import (
    CLIENT_CERT_PEM_HEADER,
    CLIENT_CERT_VERIFY_HEADER,
    CLOCK_SKEW_TOLERANCE_SECONDS,
)

#: The value nginx sets for `$ssl_client_verify` when the chain checks out.
#: Anything else ("NONE", "FAILED:...") means the proxy did not verify it.
NGINX_VERIFY_SUCCESS = "SUCCESS"

#: Upper bound on the forwarded certificate header. A PEM-encoded P-256
#: certificate is around 800 bytes; percent-encoded, comfortably under 8 KiB.
#: Bounded so a huge header cannot be turned into parser work.
MAX_CERT_HEADER_BYTES = 16 * 1024


class DeviceAuthError(Exception):
    """Device authentication failed. `code` is the stable reason code.

    The code goes to the audit log. The HTTP response says only that a valid
    client certificate is required, because telling a caller which check failed
    helps them work out what to forge next.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ClientCertificate:
    """What the application derived from the forwarded certificate."""

    fingerprint: str
    """`sha256:<hex>`, computed here, matched against the value stored at enrollment."""

    subject_common_name: str
    """The device UUID the server allocated. The client never chooses this."""

    serial_number: int
    not_before: dt.datetime
    not_after: dt.datetime
    certificate: x509.Certificate


def is_trusted_proxy(client_ip: str | None, trusted_proxy_ips: frozenset[str]) -> bool:
    """Whether to believe the X-Client-* headers on this connection."""
    return client_ip is not None and client_ip in trusted_proxy_ips


def extract_client_certificate(
    headers: Mapping[str, str],
    *,
    client_ip: str | None,
    trusted_proxy_ips: frozenset[str],
    now: dt.datetime | None = None,
) -> ClientCertificate:
    """Derive device identity from forwarded headers, or raise `DeviceAuthError`.

    Pure apart from the default clock, so every refusal path is cheap to test -
    including the one that matters most, a spoofed header from an untrusted peer.
    """
    now = now or dt.datetime.now(dt.UTC)

    # Checked first, before any header is even read. A request that is not from
    # the proxy has no business asserting a client certificate.
    if not is_trusted_proxy(client_ip, trusted_proxy_ips):
        raise DeviceAuthError(
            "untrusted_proxy",
            f"client certificate headers refused from untrusted peer {client_ip!r}",
        )

    lowered = {key.lower(): value for key, value in headers.items()}

    verify = lowered.get(CLIENT_CERT_VERIFY_HEADER, "").strip()
    if not verify:
        raise DeviceAuthError(
            "client_cert_missing",
            f"{CLIENT_CERT_VERIFY_HEADER} header absent; is nginx configured to "
            "forward the client certificate?",
        )
    if verify != NGINX_VERIFY_SUCCESS:
        # nginx reports FAILED:<reason> or NONE. The reason is useful in the
        # audit log and useless to the caller.
        raise DeviceAuthError(
            "client_cert_not_verified",
            f"proxy did not verify the client certificate: {verify}",
        )

    escaped = lowered.get(CLIENT_CERT_PEM_HEADER, "")
    if not escaped:
        raise DeviceAuthError(
            "client_cert_missing",
            f"{CLIENT_CERT_PEM_HEADER} header absent despite "
            f"{CLIENT_CERT_VERIFY_HEADER}={NGINX_VERIFY_SUCCESS}",
        )
    if len(escaped) > MAX_CERT_HEADER_BYTES:
        raise DeviceAuthError(
            "client_cert_malformed",
            f"forwarded certificate header is {len(escaped)} bytes, over the limit",
        )

    # nginx percent-encodes the PEM, newlines included.
    pem = unquote(escaped)
    try:
        certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except ValueError as exc:
        raise DeviceAuthError(
            "client_cert_malformed", f"could not parse the forwarded certificate: {exc}"
        ) from exc

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise DeviceAuthError(
            "client_cert_subject_invalid",
            f"expected exactly one common name, found {len(common_names)}",
        )
    common_name = common_names[0].value
    if not isinstance(common_name, str) or not common_name:
        raise DeviceAuthError("client_cert_subject_invalid", "common name is empty")

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    skew = dt.timedelta(seconds=CLOCK_SKEW_TOLERANCE_SECONDS)

    # nginx has already checked validity; this is a second, independent check so
    # the guarantee does not rest solely on the proxy's configuration.
    if now > not_after + skew:
        raise DeviceAuthError(
            "client_cert_expired", f"certificate expired at {not_after.isoformat()}"
        )
    if now < not_before - skew:
        raise DeviceAuthError(
            "client_cert_not_yet_valid", f"certificate not valid until {not_before.isoformat()}"
        )

    return ClientCertificate(
        fingerprint="sha256:" + certificate.fingerprint(hashes.SHA256()).hex(),
        subject_common_name=common_name,
        serial_number=certificate.serial_number,
        not_before=not_before,
        not_after=not_after,
        certificate=certificate,
    )
