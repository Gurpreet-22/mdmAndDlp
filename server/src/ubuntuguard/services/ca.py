"""Internal certificate authority for device identities.

Scope: this CA exists only to issue client certificates to enrolled agents, so
that mTLS proves "this request comes from device X". It is not a general PKI and
issues nothing else.

The three decisions that matter most are all about what we refuse to trust from
a CSR:

1. The CSR's signature is verified first. Without that check, anyone could
   submit a CSR containing someone else's public key, and the CA would cheerfully
   issue a certificate for a key the requester does not hold.
2. The CSR's subject is ignored. The common name is set from the device UUID the
   server allocated, so a client cannot choose its own identity.
3. The CSR's extensions are ignored. Copying requested extensions is a classic
   CA vulnerability - a CSR asking for basicConstraints CA:TRUE would otherwise
   be handed a certificate that can sign other certificates.
"""

from __future__ import annotations

import datetime as dt
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ubuntuguard.constants import (
    CERT_RENEW_AT_PCT,
    CLOCK_SKEW_TOLERANCE_SECONDS,
    DEVICE_CERT_VALIDITY_DAYS,
)

#: Device keys we accept. EC P-256 is the default the agent generates; P-384 and
#: Ed25519 are permitted for flexibility. RSA below this size is refused rather
#: than quietly accepted.
MIN_RSA_BITS = 3072
ALLOWED_EC_CURVES = frozenset({"secp256r1", "secp384r1"})

#: The internal CA root's own lifetime. Long, because rotating it means
#: re-enrolling the whole fleet.
CA_VALIDITY_DAYS = 3650

ORGANISATION_NAME = "UbuntuGuard"


class CsrRejectedError(ValueError):
    """Raised when a CSR cannot be trusted enough to issue against."""


class KeyFilePermissionError(RuntimeError):
    """Raised when a private key file is readable by group or others."""


@dataclass(frozen=True, slots=True)
class CertificateAuthority:
    """A loaded CA keypair and certificate."""

    private_key: CertificateIssuerPrivateKeyTypes
    certificate: x509.Certificate


def assert_key_file_private(path: Path) -> None:
    """Refuse to load a private key that is not mode 0600 or tighter.

    A world-readable CA key is the single worst failure available to this
    system, so it fails loudly at load time instead of being noticed in a
    review later.
    """
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise KeyFilePermissionError(
            f"{path} is accessible to group or others (mode {stat.S_IMODE(mode):04o}); "
            "expected 0600"
        )


def generate_ca(
    common_name: str = "UbuntuGuard Internal Device CA",
    *,
    now: dt.datetime | None = None,
    valid_days: int = CA_VALIDITY_DAYS,
) -> CertificateAuthority:
    """Create a self-signed CA on EC P-256."""
    now = now or dt.datetime.now(dt.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANISATION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    public_key = key.public_key()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(seconds=CLOCK_SKEW_TOLERANCE_SECONDS))
        .not_valid_after(now + dt.timedelta(days=valid_days))
        # path_length=0: this CA may sign end-entity certificates and nothing
        # else, so a stolen device certificate cannot become a sub-CA.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .sign(key, hashes.SHA256())
    )
    return CertificateAuthority(private_key=key, certificate=certificate)


def save_ca(ca: CertificateAuthority, key_path: Path, cert_path: Path) -> None:
    """Write the CA key at mode 0600 and the certificate at 0644.

    The key is created with restrictive permissions via `os.open`, not chmod'ed
    afterwards: a chmod leaves a window in which the file exists and is readable.
    """
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_bytes = ca.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key_bytes)
    finally:
        os.close(fd)

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(ca.certificate.public_bytes(serialization.Encoding.PEM))


def load_ca(key_path: Path, cert_path: Path) -> CertificateAuthority:
    """Load a CA, refusing a key file that others can read."""
    assert_key_file_private(key_path)
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    if not isinstance(private_key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey):
        raise CsrRejectedError(f"unsupported CA key type: {type(private_key).__name__}")
    return CertificateAuthority(private_key=private_key, certificate=certificate)


def _assert_public_key_acceptable(public_key: object) -> None:
    """Reject weak or unexpected device keys."""
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve.name
        if curve not in ALLOWED_EC_CURVES:
            raise CsrRejectedError(f"EC curve {curve} is not permitted")
        return
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < MIN_RSA_BITS:
            raise CsrRejectedError(f"RSA key of {public_key.key_size} bits is below {MIN_RSA_BITS}")
        return
    raise CsrRejectedError(f"unsupported key type: {type(public_key).__name__}")


def requested_extensions(csr: x509.CertificateSigningRequest) -> list[str]:
    """Names of extensions the CSR asked for, all of which are ignored.

    Returned so enrollment can audit the request. A CSR asking for
    basicConstraints or keyCertSign is not necessarily an attack - some tooling
    adds them by default - but it is worth a record.
    """
    # `_name` is friendlier in an audit entry but is private API, so fall back
    # to the dotted OID rather than crashing if it ever disappears.
    return sorted(
        getattr(ext.oid, "_name", None) or ext.oid.dotted_string for ext in csr.extensions
    )


def verify_csr(csr: x509.CertificateSigningRequest) -> None:
    """Check that the CSR is self-consistent and its key acceptable.

    The signature check is the part that proves the requester holds the private
    key for the public key being certified.
    """
    if not csr.is_signature_valid:
        raise CsrRejectedError("CSR signature is invalid")
    _assert_public_key_acceptable(csr.public_key())


def issue_device_certificate(
    ca: CertificateAuthority,
    csr: x509.CertificateSigningRequest,
    device_id: str,
    *,
    now: dt.datetime | None = None,
    valid_days: int = DEVICE_CERT_VALIDITY_DAYS,
) -> x509.Certificate:
    """Issue a client certificate binding `device_id` to the CSR's public key.

    Only the public key is taken from the CSR. The subject comes from
    `device_id`, and no extension from the CSR is carried over.
    """
    verify_csr(csr)
    now = now or dt.datetime.now(dt.UTC)
    public_key = csr.public_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANISATION_NAME),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "devices"),
            # The server's own identifier for this device, not anything the
            # client asked to be called.
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ]
    )

    ca_ski = ca.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        # Backdated by the clock-skew tolerance so a device whose clock runs
        # slightly fast does not reject its own brand-new certificate.
        .not_valid_before(now - dt.timedelta(seconds=CLOCK_SKEW_TOLERANCE_SECONDS))
        .not_valid_after(now + dt.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Client authentication only. This certificate cannot be used to stand
        # up a server that other agents would trust.
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    """`sha256:<hex>` over the DER encoding.

    SHA-256 rather than SHA-1 deliberately. nginx's `$ssl_client_fingerprint`
    is SHA-1, which is why the proxy forwards the whole certificate and the
    application computes this itself - see `security/device_auth.py`.
    """
    return "sha256:" + certificate.fingerprint(hashes.SHA256()).hex()


def renewal_due_at(certificate: x509.Certificate) -> dt.datetime:
    """When the agent should start trying to renew: 50% through the lifetime.

    Renewing at half-life leaves the whole second half as the window to recover
    from a failed renewal, rather than discovering the problem on the last day.
    """
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    lifetime = not_after - not_before
    return not_before + lifetime * (CERT_RENEW_AT_PCT / 100)


def load_csr_pem(pem: bytes) -> x509.CertificateSigningRequest:
    """Parse a PEM CSR, raising `CsrRejectedError` on anything unparseable."""
    try:
        return x509.load_pem_x509_csr(pem)
    except ValueError as exc:
        raise CsrRejectedError(f"could not parse CSR: {exc}") from exc
