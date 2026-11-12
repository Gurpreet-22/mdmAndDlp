"""Creating a device identity: the keypair, the CSR, and installing the result.

Three properties carry the weight here, and each has more than one test because
each has more than one way to go wrong.

**The private key never leaves the machine.** Asserted negatively, against the
artefacts that do leave: the CSR must not contain private material.

**The keypair is stable across retries.** This is what makes the server's
enrollment idempotency cache usable, and it is the difference between a network
blip and a wasted single-use token.

**A certificate is verified before it is written.** A response that fails any
check must leave the agent exactly as it was, still able to retry.
"""

from __future__ import annotations

import datetime as dt
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tls_harness import issue_leaf, make_authority
from ubuntuguard_agent.config import AgentPaths
from ubuntuguard_agent.errors import IdentityError, InsecureFileError
from ubuntuguard_agent.identity import (
    CSR_PLACEHOLDER_COMMON_NAME,
    build_csr,
    ensure_device_keypair,
    ensure_runtime_paths,
    generate_device_key,
    install_certificate,
    is_enrolled,
    load_identity,
    load_private_key,
    public_keys_match,
    write_private_key,
)

PEM = serialization.Encoding.PEM
DEVICE_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def paths(tmp_path: Path) -> AgentPaths:
    agent_paths = AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
    ensure_runtime_paths(agent_paths)
    return agent_paths


def _issue_for(
    public_key: ec.EllipticCurvePublicKey,
    *,
    device_id: str = DEVICE_ID,
    authority: object | None = None,
    valid_for: dt.timedelta = dt.timedelta(days=30),
) -> tuple[object, bytes, bytes]:
    """Issue a certificate for `public_key` the way the server's CA would."""
    certificate_authority = authority or make_authority("UbuntuGuard Test Device CA")
    _, certificate = issue_leaf(
        certificate_authority,  # type: ignore[arg-type]
        common_name=device_id,
        client_auth=True,
        public_key=public_key,
        valid_for=valid_for,
    )
    return (
        certificate_authority,
        certificate.public_bytes(PEM),
        certificate_authority.pem,  # type: ignore[attr-defined]
    )


# --------------------------------------------------------------------------- #
# Keypair generation and persistence
# --------------------------------------------------------------------------- #


def test_the_generated_key_is_the_curve_the_server_accepts() -> None:
    """P-256 is in `services/ca.ALLOWED_EC_CURVES`; a wrong curve is a 400."""
    key = generate_device_key()
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp256r1"


def test_the_key_file_is_written_at_0600(paths: AgentPaths) -> None:
    write_private_key(paths.private_key_path, generate_device_key())
    mode = stat.S_IMODE(paths.private_key_path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {mode:04o}"


def test_the_key_file_is_never_wider_than_0600_even_with_a_permissive_umask(
    paths: AgentPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mode is set at creation, not chmod'ed afterwards.

    A chmod after the fact leaves a window in which the key exists at the
    umask's mode. Under umask 0 that window is world-readable, which is the
    whole reason `_atomic_write` uses `os.open` with an explicit mode.
    """
    import os

    previous = os.umask(0)
    try:
        write_private_key(paths.private_key_path, generate_device_key())
    finally:
        os.umask(previous)
    assert stat.S_IMODE(paths.private_key_path.stat().st_mode) == 0o600


def test_loading_a_group_readable_key_is_refused(paths: AgentPaths) -> None:
    """Mirrors the server refusing a group-readable CA key.

    Refused rather than repaired: a key the rest of the machine could read may
    already have been copied, and silently tightening the mode hides that from
    whoever has to decide about re-enrolling.
    """
    write_private_key(paths.private_key_path, generate_device_key())
    paths.private_key_path.chmod(0o640)
    with pytest.raises(InsecureFileError) as raised:
        load_private_key(paths.private_key_path)
    assert "group or others" in str(raised.value)


def test_a_key_of_the_wrong_type_is_refused(paths: AgentPaths) -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    paths.private_key_path.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths.private_key_path.chmod(0o600)
    with pytest.raises(IdentityError) as raised:
        load_private_key(paths.private_key_path)
    assert "EC keys" in str(raised.value)


# --------------------------------------------------------------------------- #
# CSR contents
# --------------------------------------------------------------------------- #


def test_the_csr_carries_the_public_key_and_no_private_material() -> None:
    """The CSR is the only key-derived thing that is transmitted."""
    key = generate_device_key()
    csr_pem = build_csr(key).public_bytes(PEM)

    assert b"BEGIN CERTIFICATE REQUEST" in csr_pem
    assert b"PRIVATE KEY" not in csr_pem

    parsed = x509.load_pem_x509_csr(csr_pem)
    assert public_keys_match(parsed.public_key(), key.public_key())


def test_the_csr_signature_is_valid() -> None:
    """`services/ca.verify_csr` checks this first; it proves key possession."""
    csr = build_csr(generate_device_key())
    assert csr.is_signature_valid


def test_the_csr_requests_no_extensions() -> None:
    """The server ignores CSR extensions but RECORDS which were requested.

    Requesting none keeps the `csr_requested_extensions` audit field empty, so
    a non-empty value for a device this agent enrolled means the request was
    not built here.
    """
    csr = build_csr(generate_device_key())
    assert list(csr.extensions) == []


def test_the_csr_subject_is_a_placeholder_the_server_discards() -> None:
    """Named as such rather than carrying a hostname that looks meaningful."""
    csr = build_csr(generate_device_key())
    names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [attribute.value for attribute in names] == [CSR_PLACEHOLDER_COMMON_NAME]


# --------------------------------------------------------------------------- #
# Idempotency: the property that makes a retry survivable
# --------------------------------------------------------------------------- #


def test_the_keypair_is_generated_once_and_reused(paths: AgentPaths) -> None:
    """The server caches on the CSR public key, so it must not change."""
    first = ensure_device_keypair(paths)
    assert first.created is True

    second = ensure_device_keypair(paths)
    assert second.created is False
    assert second.csr_pem == first.csr_pem
    assert public_keys_match(second.private_key.public_key(), first.private_key.public_key())


def test_the_csr_is_byte_identical_across_calls(paths: AgentPaths) -> None:
    """Stored rather than rebuilt.

    ECDSA signatures are randomised, so rebuilding the CSR would produce
    different bytes for the same key on every call. The public key - which is
    what the server keys its cache on - would still match, so this is belt and
    braces; it also means there is no question to answer about whether a
    rebuild is deterministic.
    """
    first = ensure_device_keypair(paths).csr_pem
    assert ensure_device_keypair(paths).csr_pem == first
    assert ensure_device_keypair(paths).csr_pem == first


def test_a_key_without_a_csr_rebuilds_the_csr_and_keeps_the_key(
    paths: AgentPaths,
) -> None:
    """The key is the irreplaceable half; the CSR is derived."""
    original = ensure_device_keypair(paths)
    paths.csr_path.unlink()

    rebuilt = ensure_device_keypair(paths)
    assert rebuilt.created is False
    assert public_keys_match(rebuilt.private_key.public_key(), original.private_key.public_key())
    assert paths.csr_path.exists()


def test_a_csr_without_a_key_discards_the_csr(paths: AgentPaths) -> None:
    """A CSR whose key is gone can never be completed, so keeping it misleads."""
    first = ensure_device_keypair(paths)
    paths.private_key_path.unlink()

    replacement = ensure_device_keypair(paths)
    assert replacement.created is True
    assert replacement.csr_pem != first.csr_pem


def test_a_csr_that_does_not_match_the_key_is_refused(paths: AgentPaths) -> None:
    """Should be impossible, so it means tampering or a bug. Stop, do not guess."""
    ensure_device_keypair(paths)
    paths.csr_path.write_bytes(build_csr(generate_device_key()).public_bytes(PEM))

    with pytest.raises(IdentityError) as raised:
        ensure_device_keypair(paths)
    assert "different key" in str(raised.value)


# --------------------------------------------------------------------------- #
# Installing the issued certificate
# --------------------------------------------------------------------------- #


def test_a_valid_certificate_is_installed(paths: AgentPaths) -> None:
    keypair = ensure_device_keypair(paths)
    _, certificate_pem, ca_pem = _issue_for(keypair.private_key.public_key())

    summary = install_certificate(
        paths,
        certificate_pem=certificate_pem,
        ca_chain_pem=ca_pem,
        expected_device_id=DEVICE_ID,
        private_key=keypair.private_key,
    )

    assert summary.device_id == DEVICE_ID
    assert is_enrolled(paths)
    assert paths.certificate_path.read_bytes() == certificate_pem
    assert paths.ca_chain_path.read_bytes() == ca_pem
    # Public material, inside a 0700 directory.
    assert stat.S_IMODE(paths.certificate_path.stat().st_mode) == 0o644


def test_the_renewal_point_is_half_life(paths: AgentPaths) -> None:
    """Computed locally, so the decision still works offline."""
    keypair = ensure_device_keypair(paths)
    _, certificate_pem, ca_pem = _issue_for(
        keypair.private_key.public_key(), valid_for=dt.timedelta(days=30)
    )
    summary = install_certificate(
        paths,
        certificate_pem=certificate_pem,
        ca_chain_pem=ca_pem,
        expected_device_id=DEVICE_ID,
        private_key=keypair.private_key,
    )
    lifetime = summary.not_after - summary.not_before
    midpoint = summary.not_before + lifetime / 2
    assert abs((summary.renew_after - midpoint).total_seconds()) < 1


def test_a_certificate_for_another_key_is_refused_and_nothing_is_written(
    paths: AgentPaths,
) -> None:
    """The check that proves the certificate is usable at all.

    Without it this installs cleanly and then fails every TLS handshake with an
    error that points at nginx.
    """
    keypair = ensure_device_keypair(paths)
    stranger = generate_device_key()
    _, certificate_pem, ca_pem = _issue_for(stranger.public_key())

    with pytest.raises(IdentityError) as raised:
        install_certificate(
            paths,
            certificate_pem=certificate_pem,
            ca_chain_pem=ca_pem,
            expected_device_id=DEVICE_ID,
            private_key=keypair.private_key,
        )

    assert "different public key" in str(raised.value)
    assert not paths.certificate_path.exists()
    assert not is_enrolled(paths)


def test_a_certificate_naming_another_device_is_refused(paths: AgentPaths) -> None:
    """`deps.py` rejects this on every request as device_identity_mismatch."""
    keypair = ensure_device_keypair(paths)
    _, certificate_pem, ca_pem = _issue_for(
        keypair.private_key.public_key(), device_id="99999999-8888-7777-6666-555555555555"
    )

    with pytest.raises(IdentityError) as raised:
        install_certificate(
            paths,
            certificate_pem=certificate_pem,
            ca_chain_pem=ca_pem,
            expected_device_id=DEVICE_ID,
            private_key=keypair.private_key,
        )

    assert "device_identity_mismatch" in str(raised.value)
    assert not paths.certificate_path.exists()


def test_a_certificate_not_signed_by_the_returned_ca_is_refused(
    paths: AgentPaths,
) -> None:
    """Catches a half-completed CA rotation before it costs a heartbeat loop."""
    keypair = ensure_device_keypair(paths)
    _, certificate_pem, _ = _issue_for(keypair.private_key.public_key())
    unrelated = make_authority("Some Other CA")

    with pytest.raises(IdentityError) as raised:
        install_certificate(
            paths,
            certificate_pem=certificate_pem,
            ca_chain_pem=unrelated.pem,
            expected_device_id=DEVICE_ID,
            private_key=keypair.private_key,
        )

    assert "issuer" in str(raised.value) or "not signed" in str(raised.value)
    assert not paths.certificate_path.exists()


def test_an_unparseable_certificate_is_refused(paths: AgentPaths) -> None:
    keypair = ensure_device_keypair(paths)
    with pytest.raises(IdentityError) as raised:
        install_certificate(
            paths,
            certificate_pem=b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
            ca_chain_pem=make_authority("CA").pem,
            expected_device_id=DEVICE_ID,
            private_key=keypair.private_key,
        )
    assert "will not parse" in str(raised.value)
    assert not paths.certificate_path.exists()


# --------------------------------------------------------------------------- #
# Loading an identity back
# --------------------------------------------------------------------------- #


def test_load_identity_returns_a_consistent_pair(paths: AgentPaths) -> None:
    keypair = ensure_device_keypair(paths)
    _, certificate_pem, ca_pem = _issue_for(keypair.private_key.public_key())
    install_certificate(
        paths,
        certificate_pem=certificate_pem,
        ca_chain_pem=ca_pem,
        expected_device_id=DEVICE_ID,
        private_key=keypair.private_key,
    )

    key, summary = load_identity(paths)
    assert summary.device_id == DEVICE_ID
    assert public_keys_match(key.public_key(), keypair.private_key.public_key())


def test_load_identity_refuses_a_mismatched_pair(paths: AgentPaths) -> None:
    """Re-checked on load, because root can edit the two files independently."""
    keypair = ensure_device_keypair(paths)
    _, certificate_pem, ca_pem = _issue_for(keypair.private_key.public_key())
    install_certificate(
        paths,
        certificate_pem=certificate_pem,
        ca_chain_pem=ca_pem,
        expected_device_id=DEVICE_ID,
        private_key=keypair.private_key,
    )

    # Someone replaces the key but not the certificate.
    write_private_key(paths.private_key_path, generate_device_key())

    with pytest.raises(IdentityError) as raised:
        load_identity(paths)
    assert "not a pair" in str(raised.value)


def test_load_identity_on_an_unenrolled_device_says_what_to_do(
    paths: AgentPaths,
) -> None:
    with pytest.raises(IdentityError) as raised:
        load_identity(paths)
    assert "enroll" in str(raised.value)
