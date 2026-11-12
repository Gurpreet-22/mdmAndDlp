"""Test helpers shared between modules.

A module rather than a conftest fixture because `issue_certificate` is a
factory with several keyword arguments, and a fixture returning a closure reads
worse at every call site than a plain import.

No key material is committed anywhere. Certificates are generated in-process,
which is the same discipline decision D11 applies to the policy signing vector.
"""

from __future__ import annotations

import datetime as dt
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ubuntuguard_agent.constants import DEVICE_CERT_VALIDITY_DAYS

UTC = dt.timezone.utc


def issue_certificate(
    *,
    device_id: str | None = None,
    not_before: dt.datetime | None = None,
    valid_days: int = DEVICE_CERT_VALIDITY_DAYS,
    common_names: int = 1,
) -> bytes:
    """A certificate shaped like the one the server's CA issues.

    Matches `services/ca.issue_device_certificate` in the parts the agent
    reasons about: EC P-256, subject `O=UbuntuGuard, OU=devices, CN=<uuid>`, and
    a 30-day life. Self-signed, because nothing under test here validates a
    chain - the agent reads its own certificate for expiry and identity, and
    nginx is what verifies the chain on the server side.
    """
    device_id = device_id or str(uuid.uuid4())
    not_before = not_before or dt.datetime.now(UTC) - dt.timedelta(minutes=5)
    key = ec.generate_private_key(ec.SECP256R1())

    attributes = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UbuntuGuard"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "devices"),
    ]
    attributes += [x509.NameAttribute(NameOID.COMMON_NAME, device_id) for _ in range(common_names)]

    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(attributes))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "UbuntuGuard Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + dt.timedelta(days=valid_days))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)
