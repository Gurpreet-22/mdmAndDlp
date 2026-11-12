"""Internal CA tests.

Most of these are about what the CA refuses to take from a CSR. A CA that trusts
its input is the problem; the public key is the only thing worth copying out of a
certificate request.
"""

from __future__ import annotations

import datetime as dt
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ubuntuguard.constants import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    DEVICE_CERT_VALIDITY_DAYS,
)
from ubuntuguard.services.ca import (
    CertificateAuthority,
    CsrRejectedError,
    KeyFilePermissionError,
    assert_key_file_private,
    certificate_fingerprint,
    generate_ca,
    issue_device_certificate,
    load_ca,
    load_csr_pem,
    renewal_due_at,
    requested_extensions,
    save_ca,
    verify_csr,
)

NOW = dt.datetime(2026, 10, 29, 12, 0, 0, tzinfo=dt.UTC)
DEVICE_ID = "9a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d"


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    return generate_ca(now=NOW)


def make_csr(
    key: object | None = None,
    *,
    common_name: str = "whatever-the-client-wants",
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
) -> x509.CertificateSigningRequest:
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The CA itself
# --------------------------------------------------------------------------- #


def test_ca_is_a_ca_limited_to_end_entity_certificates(ca: CertificateAuthority) -> None:
    """path_length=0 means a stolen device cert cannot become a sub-CA."""
    constraints = ca.certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    assert constraints.critical is True
    assert constraints.value.ca is True
    assert constraints.value.path_length == 0


def test_ca_key_usage_signs_certificates_not_data(ca: CertificateAuthority) -> None:
    usage = ca.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_cert_sign is True
    assert usage.crl_sign is True
    assert usage.digital_signature is False


def test_ca_is_self_signed(ca: CertificateAuthority) -> None:
    assert ca.certificate.subject == ca.certificate.issuer


def test_ca_uses_p256(ca: CertificateAuthority) -> None:
    public_key = ca.certificate.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert public_key.curve.name == "secp256r1"


# --------------------------------------------------------------------------- #
# Issuing device certificates
# --------------------------------------------------------------------------- #


def test_issued_certificate_uses_the_server_allocated_identity(ca: CertificateAuthority) -> None:
    """The CSR's requested subject is ignored.

    A client that could choose its own common name could impersonate another
    device, since the common name IS the device identity on the mTLS path.
    """
    csr = make_csr(common_name="i-am-the-admin-device")
    cert = issue_device_certificate(ca, csr, DEVICE_ID, now=NOW)

    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(common_names) == 1
    assert common_names[0].value == DEVICE_ID
    assert "i-am-the-admin-device" not in cert.subject.rfc4514_string()


def test_csr_extensions_are_not_copied(ca: CertificateAuthority) -> None:
    """Extension smuggling: a CSR asking for CA:TRUE must not get it.

    Copying requested extensions is a well-known CA vulnerability. A device
    certificate with CA:TRUE could sign certificates for every other device.
    """
    csr = make_csr(
        extensions=(
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
        )
    )
    # The request really did ask, so the test is meaningful.
    assert "basicConstraints" in requested_extensions(csr)

    cert = issue_device_certificate(ca, csr, DEVICE_ID, now=NOW)

    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is False
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_cert_sign is False
    assert usage.crl_sign is False
    assert usage.digital_signature is True


def test_issued_certificate_is_client_auth_only(ca: CertificateAuthority) -> None:
    """It must not be usable to impersonate the server to other agents."""
    csr = make_csr()
    cert = issue_device_certificate(ca, csr, DEVICE_ID, now=NOW)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert ExtendedKeyUsageOID.SERVER_AUTH not in list(eku)


def test_issued_certificate_carries_the_csr_public_key(ca: CertificateAuthority) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = issue_device_certificate(ca, make_csr(key), DEVICE_ID, now=NOW)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()


def test_certificate_lifetime_is_thirty_days_backdated_for_skew(
    ca: CertificateAuthority,
) -> None:
    """Backdating by the skew tolerance stops a device with a fast clock from
    rejecting the certificate it has just been issued.
    """
    cert = issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW)
    assert cert.not_valid_before_utc == NOW - dt.timedelta(seconds=CLOCK_SKEW_TOLERANCE_SECONDS)
    assert cert.not_valid_after_utc == NOW + dt.timedelta(days=DEVICE_CERT_VALIDITY_DAYS)
    assert DEVICE_CERT_VALIDITY_DAYS == 30


def test_renewal_is_due_at_half_life(ca: CertificateAuthority) -> None:
    """The brief says renew at 50%. For a 30-day cert that is day 15."""
    cert = issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW)
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert renewal_due_at(cert) == cert.not_valid_before_utc + lifetime / 2
    assert abs((renewal_due_at(cert) - NOW).days - 15) <= 1


def test_serial_numbers_are_random_and_large(ca: CertificateAuthority) -> None:
    serials = {
        issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW).serial_number for _ in range(5)
    }
    assert len(serials) == 5
    assert all(serial.bit_length() > 32 for serial in serials)


def test_issued_certificate_verifies_against_the_ca(ca: CertificateAuthority) -> None:
    cert = issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW)
    ca_public = ca.certificate.public_key()
    assert isinstance(ca_public, ec.EllipticCurvePublicKey)
    # Raises InvalidSignature if the chain is broken.
    ca_public.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
    )
    assert cert.issuer == ca.certificate.subject


def test_authority_key_identifier_points_at_the_ca(ca: CertificateAuthority) -> None:
    cert = issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW)
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    ca_ski = ca.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert aki.key_identifier == ca_ski.key_identifier


# --------------------------------------------------------------------------- #
# What the CA refuses
# --------------------------------------------------------------------------- #


def test_csr_with_an_invalid_signature_is_rejected(ca: CertificateAuthority) -> None:
    """Without this check, anyone could get a certificate for a key they do not
    hold by pasting someone else's public key into a CSR.
    """
    filler = "a" * 24
    csr = make_csr(common_name=filler)
    der = csr.public_bytes(serialization.Encoding.DER)
    assert filler.encode() in der
    # Same length, so the DER stays structurally valid while the signature
    # no longer covers the contents.
    mutated = der.replace(filler.encode(), b"b" + filler.encode()[1:], 1)
    tampered = x509.load_der_x509_csr(mutated)

    assert tampered.is_signature_valid is False
    with pytest.raises(CsrRejectedError, match="signature is invalid"):
        verify_csr(tampered)
    with pytest.raises(CsrRejectedError):
        issue_device_certificate(ca, tampered, DEVICE_ID, now=NOW)


def test_rsa_key_below_the_minimum_is_rejected(ca: CertificateAuthority) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(CsrRejectedError, match="below"):
        verify_csr(make_csr(weak))


def test_unlisted_ec_curve_is_rejected() -> None:
    """P-521 is not weak, it is simply not on the list. An allowlist that
    silently accepts anything plausible is not an allowlist.
    """
    key = ec.generate_private_key(ec.SECP521R1())
    with pytest.raises(CsrRejectedError, match="not permitted"):
        verify_csr(make_csr(key))


@pytest.mark.parametrize(
    "key_factory",
    [
        lambda: ec.generate_private_key(ec.SECP256R1()),
        lambda: ec.generate_private_key(ec.SECP384R1()),
        ed25519.Ed25519PrivateKey.generate,
    ],
    ids=["p256", "p384", "ed25519"],
)
def test_permitted_key_types_are_accepted(key_factory: object) -> None:
    verify_csr(make_csr(key_factory()))  # type: ignore[operator]


def test_unparseable_csr_is_rejected() -> None:
    garbage = b"-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----"
    with pytest.raises(CsrRejectedError, match="could not parse"):
        load_csr_pem(garbage)


# --------------------------------------------------------------------------- #
# Fingerprints and key files
# --------------------------------------------------------------------------- #


def test_fingerprint_is_sha256_not_sha1(ca: CertificateAuthority) -> None:
    """nginx's $ssl_client_fingerprint is SHA-1, which is why the app computes
    its own. A 64-hex-char digest is the observable difference.
    """
    cert = issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW)
    fingerprint = certificate_fingerprint(cert)
    assert fingerprint.startswith("sha256:")
    assert len(fingerprint) == len("sha256:") + 64
    assert fingerprint == "sha256:" + cert.fingerprint(hashes.SHA256()).hex()


def test_fingerprints_differ_between_certificates(ca: CertificateAuthority) -> None:
    first = issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW)
    second = issue_device_certificate(ca, make_csr(), DEVICE_ID, now=NOW)
    assert certificate_fingerprint(first) != certificate_fingerprint(second)


def test_saved_ca_key_is_mode_0600(tmp_path: Path, ca: CertificateAuthority) -> None:
    """Created with restrictive permissions rather than chmod'ed afterwards,
    because a chmod leaves a window where the file is readable.
    """
    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca.crt"
    save_ca(ca, key_path, cert_path)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_round_trip_through_disk(tmp_path: Path, ca: CertificateAuthority) -> None:
    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca.crt"
    save_ca(ca, key_path, cert_path)
    loaded = load_ca(key_path, cert_path)
    assert loaded.certificate.fingerprint(hashes.SHA256()) == ca.certificate.fingerprint(
        hashes.SHA256()
    )
    # The reloaded key must still be able to issue.
    cert = issue_device_certificate(loaded, make_csr(), DEVICE_ID, now=NOW)
    assert cert.issuer == ca.certificate.subject


def test_group_or_world_readable_key_is_refused(tmp_path: Path, ca: CertificateAuthority) -> None:
    """A world-readable CA key is the worst failure available here, so it fails
    loudly at load time rather than being spotted in a later review.
    """
    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca.crt"
    save_ca(ca, key_path, cert_path)
    key_path.chmod(0o644)

    with pytest.raises(KeyFilePermissionError, match="group or others"):
        assert_key_file_private(key_path)
    with pytest.raises(KeyFilePermissionError):
        load_ca(key_path, cert_path)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_private_modes_are_accepted(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"x")
    path.chmod(mode)
    assert_key_file_private(path)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o666, 0o700 | 0o010])
def test_non_private_modes_are_refused(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"x")
    path.chmod(mode)
    with pytest.raises(KeyFilePermissionError):
        assert_key_file_private(path)
