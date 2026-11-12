"""Device mTLS header tests.

The header-spoofing test is the one that matters. `X-Client-Cert` is as
powerful as the client certificate itself, so anyone who can set it on a
request the application believes can impersonate any device in the fleet.
"""

from __future__ import annotations

import datetime as dt
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ubuntuguard.constants import CLOCK_SKEW_TOLERANCE_SECONDS
from ubuntuguard.security.device_auth import (
    MAX_CERT_HEADER_BYTES,
    DeviceAuthError,
    extract_client_certificate,
    is_trusted_proxy,
)
from ubuntuguard.services.ca import (
    CertificateAuthority,
    certificate_fingerprint,
    generate_ca,
    issue_device_certificate,
)

NOW = dt.datetime(2026, 10, 29, 12, 0, 0, tzinfo=dt.UTC)
DEVICE_ID = "9a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d"
TRUSTED = frozenset({"127.0.0.1", "::1"})


@pytest.fixture(scope="module")
def authority() -> CertificateAuthority:
    return generate_ca(now=NOW)


def make_cert(authority: CertificateAuthority, *, now: dt.datetime = NOW) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ignored")]))
        .sign(key, hashes.SHA256())
    )
    return issue_device_certificate(authority, csr, DEVICE_ID, now=now)


def headers_for(certificate: x509.Certificate, **overrides: str) -> dict[str, str]:
    """Build the headers nginx would set, with the PEM percent-encoded."""
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    base = {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert": quote(pem),
        "X-Client-DN": f"CN={DEVICE_ID}",
        "X-Client-Serial": format(certificate.serial_number, "X"),
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


def test_valid_certificate_yields_identity(authority: CertificateAuthority) -> None:
    certificate = make_cert(authority)
    result = extract_client_certificate(
        headers_for(certificate),
        client_ip="127.0.0.1",
        trusted_proxy_ips=TRUSTED,
        now=NOW,
    )
    assert result.subject_common_name == DEVICE_ID
    assert result.fingerprint == certificate_fingerprint(certificate)
    assert result.fingerprint.startswith("sha256:")
    assert result.serial_number == certificate.serial_number


def test_header_names_are_case_insensitive(authority: CertificateAuthority) -> None:
    """HTTP header names are case-insensitive, and proxies vary."""
    certificate = make_cert(authority)
    lowered = {key.lower(): value for key, value in headers_for(certificate).items()}
    result = extract_client_certificate(
        lowered, client_ip="127.0.0.1", trusted_proxy_ips=TRUSTED, now=NOW
    )
    assert result.subject_common_name == DEVICE_ID


def test_fingerprint_matches_the_value_stored_at_enrollment(
    authority: CertificateAuthority,
) -> None:
    """Enrollment stores `certificate_fingerprint`; auth recomputes it from the
    forwarded header. The two must agree or no device could ever authenticate.
    """
    certificate = make_cert(authority)
    stored = certificate_fingerprint(certificate)
    presented = extract_client_certificate(
        headers_for(certificate), client_ip="127.0.0.1", trusted_proxy_ips=TRUSTED, now=NOW
    )
    assert presented.fingerprint == stored


# --------------------------------------------------------------------------- #
# Header spoofing
# --------------------------------------------------------------------------- #


def test_perfectly_valid_headers_from_an_untrusted_peer_are_refused(
    authority: CertificateAuthority,
) -> None:
    """The central test for this module.

    The certificate is genuine and the headers are exactly what nginx would
    send. The only thing wrong is that the request did not come from nginx.
    Refusing outright, rather than ignoring the headers, means a
    misconfiguration fails loudly instead of quietly authenticating strangers.
    """
    certificate = make_cert(authority)
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers_for(certificate),
            client_ip="203.0.113.7",
            trusted_proxy_ips=TRUSTED,
            now=NOW,
        )
    assert caught.value.code == "untrusted_proxy"


def test_missing_client_ip_is_treated_as_untrusted(authority: CertificateAuthority) -> None:
    """A request with no peer address must fail closed."""
    certificate = make_cert(authority)
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers_for(certificate), client_ip=None, trusted_proxy_ips=TRUSTED, now=NOW
        )
    assert caught.value.code == "untrusted_proxy"


def test_empty_trusted_set_refuses_everything(authority: CertificateAuthority) -> None:
    certificate = make_cert(authority)
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers_for(certificate),
            client_ip="127.0.0.1",
            trusted_proxy_ips=frozenset(),
            now=NOW,
        )
    assert caught.value.code == "untrusted_proxy"


@pytest.mark.parametrize(
    ("ip", "trusted"),
    [("127.0.0.1", True), ("::1", True), ("10.0.0.5", False), (None, False), ("", False)],
)
def test_is_trusted_proxy(ip: str | None, trusted: bool) -> None:
    assert is_trusted_proxy(ip, TRUSTED) is trusted


# --------------------------------------------------------------------------- #
# What the proxy reports
# --------------------------------------------------------------------------- #


def test_absent_verify_header_is_refused(authority: CertificateAuthority) -> None:
    certificate = make_cert(authority)
    headers = headers_for(certificate)
    del headers["X-Client-Verify"]
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers, client_ip="127.0.0.1", trusted_proxy_ips=TRUSTED, now=NOW
        )
    assert caught.value.code == "client_cert_missing"


@pytest.mark.parametrize("verify", ["NONE", "FAILED:certificate has expired", "", "   "])
def test_unverified_certificate_is_refused(authority: CertificateAuthority, verify: str) -> None:
    """nginx reports NONE or FAILED:<reason> when the chain does not check out."""
    certificate = make_cert(authority)
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers_for(certificate, **{"X-Client-Verify": verify}),
            client_ip="127.0.0.1",
            trusted_proxy_ips=TRUSTED,
            now=NOW,
        )
    assert caught.value.code in {"client_cert_not_verified", "client_cert_missing"}


def test_verify_success_without_a_certificate_is_refused(
    authority: CertificateAuthority,
) -> None:
    """A proxy claiming success but forwarding nothing is a misconfiguration."""
    certificate = make_cert(authority)
    headers = headers_for(certificate)
    headers["X-Client-Cert"] = ""
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers, client_ip="127.0.0.1", trusted_proxy_ips=TRUSTED, now=NOW
        )
    assert caught.value.code == "client_cert_missing"


# --------------------------------------------------------------------------- #
# Malformed and expired input
# --------------------------------------------------------------------------- #


def test_garbage_certificate_is_refused() -> None:
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            {"X-Client-Verify": "SUCCESS", "X-Client-Cert": quote("not a certificate")},
            client_ip="127.0.0.1",
            trusted_proxy_ips=TRUSTED,
            now=NOW,
        )
    assert caught.value.code == "client_cert_malformed"


def test_oversized_certificate_header_is_refused() -> None:
    """Bounded so a huge header cannot be turned into parser work."""
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            {"X-Client-Verify": "SUCCESS", "X-Client-Cert": "A" * (MAX_CERT_HEADER_BYTES + 1)},
            client_ip="127.0.0.1",
            trusted_proxy_ips=TRUSTED,
            now=NOW,
        )
    assert caught.value.code == "client_cert_malformed"


def test_expired_certificate_is_refused(authority: CertificateAuthority) -> None:
    """A second, independent expiry check, so the guarantee does not rest only
    on the proxy's configuration.
    """
    certificate = make_cert(authority)
    well_past = certificate.not_valid_after_utc + dt.timedelta(days=1)
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers_for(certificate),
            client_ip="127.0.0.1",
            trusted_proxy_ips=TRUSTED,
            now=well_past,
        )
    assert caught.value.code == "client_cert_expired"


def test_expiry_within_the_skew_tolerance_is_accepted(
    authority: CertificateAuthority,
) -> None:
    """Just-expired is tolerated to the documented skew, and no further."""
    certificate = make_cert(authority)
    inside = certificate.not_valid_after_utc + dt.timedelta(
        seconds=CLOCK_SKEW_TOLERANCE_SECONDS - 5
    )
    result = extract_client_certificate(
        headers_for(certificate), client_ip="127.0.0.1", trusted_proxy_ips=TRUSTED, now=inside
    )
    assert result.subject_common_name == DEVICE_ID

    outside = certificate.not_valid_after_utc + dt.timedelta(
        seconds=CLOCK_SKEW_TOLERANCE_SECONDS + 5
    )
    with pytest.raises(DeviceAuthError):
        extract_client_certificate(
            headers_for(certificate),
            client_ip="127.0.0.1",
            trusted_proxy_ips=TRUSTED,
            now=outside,
        )


def test_not_yet_valid_certificate_is_refused(authority: CertificateAuthority) -> None:
    certificate = make_cert(authority)
    long_before = certificate.not_valid_before_utc - dt.timedelta(days=1)
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers_for(certificate),
            client_ip="127.0.0.1",
            trusted_proxy_ips=TRUSTED,
            now=long_before,
        )
    assert caught.value.code == "client_cert_not_yet_valid"


def test_certificate_without_a_common_name_is_refused(
    authority: CertificateAuthority,
) -> None:
    """Identity comes from the common name, so a certificate lacking one is
    unusable even if it chains correctly.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UbuntuGuard")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(authority.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(minutes=5))
        .not_valid_after(NOW + dt.timedelta(days=30))
        .sign(authority.private_key, hashes.SHA256())
    )
    with pytest.raises(DeviceAuthError) as caught:
        extract_client_certificate(
            headers_for(certificate), client_ip="127.0.0.1", trusted_proxy_ips=TRUSTED, now=NOW
        )
    assert caught.value.code == "client_cert_subject_invalid"
