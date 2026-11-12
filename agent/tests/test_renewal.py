"""Agent certificate renewal, over a real TLS connection on loopback.

One rule carries this module: **the working identity is never given up before
the replacement is in hand.** So most of these tests interrupt a renewal and
then assert the agent can still authenticate, or can finish what it started.

The crash-recovery tests are the ones worth reading. A renewal replaces two
files, which cannot be one atomic operation, so a crash between them leaves a
key and a certificate that do not match - an identity the agent cannot use and
cannot explain. Staging under `.new` paths and reconciling what is on disk is
what turns that from a broken device into a restart.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tls_harness import (
    Authority,
    CannedResponse,
    issue_leaf,
    make_authority,
    tls_server,
    write_key,
    write_pem,
)
from ubuntuguard_agent.config import AgentConfig, AgentPaths, AgentSettings
from ubuntuguard_agent.errors import IdentityError, RenewalError, TlsVerificationError
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.identity import (
    complete_pending_renewal,
    ensure_device_keypair,
    ensure_keypair,
    ensure_runtime_paths,
    install_certificate,
    is_enrolled,
    load_identity,
    public_keys_match,
    read_certificate,
)
from ubuntuguard_agent.renewal import RENEW_PATH, renew, renewal_due
from ubuntuguard_agent.service import CertificateRenewalTask

PEM = serialization.Encoding.PEM
DEVICE_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def server_tls(tmp_path: Path) -> dict[str, Path]:
    authority = make_authority("Harness Server CA")
    key, certificate = issue_leaf(
        authority, common_name="localhost", hostnames=("localhost",), server_auth=True
    )
    assert key is not None
    return {
        "ca": write_pem(tmp_path / "server-ca.pem", authority.pem),
        "certificate": write_pem(tmp_path / "server.crt", certificate.public_bytes(PEM)),
        "key": write_key(tmp_path / "server.key", key),
    }


@pytest.fixture
def device_ca() -> Authority:
    """One CA for the whole test, so a renewal keeps the same issuer."""
    return make_authority("UbuntuGuard Test Device CA")


def config_for(tmp_path: Path, server_tls: dict[str, Path], **overrides: object) -> AgentConfig:
    base: dict[str, object] = {
        "server_url": "https://localhost:1",
        "server_ca_bundle": server_tls["ca"],
        "paths": AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run"),
        "settings": AgentSettings(),
        "release_build": True,
        "config_path": None,
    }
    base.update(overrides)
    return AgentConfig(**base)  # type: ignore[arg-type]


def certificate_for(
    authority: Authority,
    public_key: ec.EllipticCurvePublicKey,
    *,
    device_id: str = DEVICE_ID,
    not_before: dt.datetime | None = None,
    valid_for: dt.timedelta = dt.timedelta(days=30),
) -> bytes:
    _, certificate = issue_leaf(
        authority,
        common_name=device_id,
        client_auth=True,
        public_key=public_key,
        not_before=not_before,
        valid_for=valid_for,
    )
    return certificate.public_bytes(PEM)


def enrol_locally(
    config: AgentConfig,
    authority: Authority,
    *,
    age: dt.timedelta = dt.timedelta(days=0),
) -> ec.EllipticCurvePrivateKey:
    """Install a complete identity without a server.

    `age` backdates the certificate so `renewal_due` can be exercised without
    waiting fifteen days.
    """
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    not_before = dt.datetime.now(dt.timezone.utc) - age - dt.timedelta(minutes=5)
    install_certificate(
        config.paths,
        certificate_pem=certificate_for(
            authority, keypair.private_key.public_key(), not_before=not_before
        ),
        ca_chain_pem=authority.pem,
        expected_device_id=DEVICE_ID,
        private_key=keypair.private_key,
    )
    return keypair.private_key


def renewal_response(
    authority: Authority, public_key: ec.EllipticCurvePublicKey, **overrides: object
) -> bytes:
    certificate_pem = certificate_for(authority, public_key)
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    document: dict[str, object] = {
        "device_id": DEVICE_ID,
        "client_certificate_pem": certificate_pem.decode(),
        "ca_chain_pem": authority.pem.decode(),
        "certificate_not_after": not_after.isoformat(),
        "certificate_renew_after": (not_before + (not_after - not_before) / 2).isoformat(),
        "reused": False,
    }
    document.update(overrides)
    return json.dumps(document).encode()


# --------------------------------------------------------------------------- #
# When renewal is due
# --------------------------------------------------------------------------- #


def test_renewal_is_not_due_on_a_fresh_certificate(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    summary = read_certificate(config.paths)
    assert summary is not None
    assert renewal_due(summary) is False


def test_renewal_is_due_past_half_life(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Computed locally from the certificate, so the decision works offline."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    summary = read_certificate(config.paths)
    assert summary is not None
    assert renewal_due(summary) is True


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


def test_renewal_replaces_both_halves_of_the_identity(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    config = config_for(tmp_path, server_tls)
    old_key = enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    old_certificate = config.paths.certificate_path.read_bytes()

    # The server issues against whatever the agent stages, so the response has
    # to be built after the staged keypair exists.
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(device_ca, staged.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=200, body=body)],
    ) as (base_url, recorded):
        result = renew(
            config,
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _s: None,
        )

    assert result.device_id == DEVICE_ID
    assert result.reused is False
    assert recorded[0].path == "/" + RENEW_PATH

    # The key AND the certificate changed, and they are a pair.
    new_key, summary = load_identity(config.paths)
    assert not public_keys_match(new_key.public_key(), old_key.public_key())
    assert config.paths.certificate_path.read_bytes() != old_certificate
    assert summary.device_id == DEVICE_ID
    assert is_enrolled(config.paths)


def test_the_renewal_csr_is_sent_and_carries_a_new_key(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """The server refuses a CSR reusing the current key, so this must not."""
    config = config_for(tmp_path, server_tls)
    old_key = enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(device_ca, staged.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=200, body=body)],
    ) as (base_url, recorded):
        renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    sent = recorded[0].json()
    assert set(sent) == {"csr_pem"}
    csr = x509.load_pem_x509_csr(sent["csr_pem"].encode())
    assert csr.is_signature_valid
    assert not public_keys_match(csr.public_key(), old_key.public_key())
    # And nothing private went out.
    assert b"PRIVATE KEY" not in recorded[0].body


def test_the_staged_files_are_cleaned_up_after_a_successful_swap(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(device_ca, staged.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=200, body=body)],
    ) as (base_url, _recorded):
        renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    assert not config.paths.pending_private_key_path.exists()
    assert not config.paths.pending_certificate_path.exists()
    assert not config.paths.pending_csr_path.exists()


def test_the_renewed_key_keeps_its_permissions(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """A rotation that widened the key's mode would be a quiet regression."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(device_ca, staged.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=200, body=body)],
    ) as (base_url, _recorded):
        renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    assert stat.S_IMODE(config.paths.private_key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.paths.certificate_path.stat().st_mode) == 0o644


def test_the_replacement_certificate_authenticates(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """A real mTLS handshake with the renewed material.

    The point of the whole exercise: after rotating, the device can still talk
    to a listener that requires a certificate from the device CA.
    """
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(device_ca, staged.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=200, body=body)],
    ) as (base_url, _recorded):
        renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    device_ca_path = write_pem(tmp_path / "device-ca.pem", device_ca.pem)
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        client_ca=device_ca_path,
        responses=[CannedResponse(status=200, body=b'{"heartbeat_seconds":60}')],
    ) as (base_url, recorded):
        client = ServerClient(
            base_url,
            ca_bundle=server_tls["ca"],
            client_certificate=config.paths.certificate_path,
            client_key=config.paths.private_key_path,
        )
        response = client.post_json("api/v1/devices/me/heartbeat", {"agent_version": "0.1.0"})

    assert response.status == 200
    peer = recorded[0].peer_certificate
    assert peer is not None
    subjects = {attribute[0][1] for attribute in peer.get("subject", ()) if attribute}
    assert DEVICE_ID in subjects


# --------------------------------------------------------------------------- #
# Retry and recovery
# --------------------------------------------------------------------------- #


def test_a_retry_sends_the_identical_csr(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """The server keys renewal idempotency on the CSR's public key.

    A rebuilt CSR on retry would collect a second certificate rather than the
    one already issued.
    """
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(device_ca, staged.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[
            CannedResponse(status=503, body=b'{"code":"service_unavailable"}'),
            CannedResponse(status=200, body=body),
        ],
    ) as (base_url, recorded):
        result = renew(
            config,
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _s: None,
        )

    assert result.attempts == 2
    assert recorded[0].body == recorded[1].body, "the retry changed the CSR"


def test_a_failed_renewal_leaves_the_old_identity_working(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """The rule this module exists for.

    After a failure the device must still be able to authenticate with what it
    had. Anything else turns a transient network problem into a re-enrollment.
    """
    config = config_for(tmp_path, server_tls)
    old_key = enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    old_certificate = config.paths.certificate_path.read_bytes()

    client = ServerClient("https://localhost:9", ca_bundle=server_tls["ca"], timeout_seconds=1.0)
    with pytest.raises(RenewalError) as raised:
        renew(config, client=client, max_attempts=2, sleep=lambda _s: None)

    assert "untouched and still valid" in str(raised.value)
    key, summary = load_identity(config.paths)
    assert public_keys_match(key.public_key(), old_key.public_key())
    assert config.paths.certificate_path.read_bytes() == old_certificate
    assert summary.device_id == DEVICE_ID


def test_the_staged_keypair_survives_a_failure_for_the_next_attempt(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Persisted before the POST, so the retry presents the same public key."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))

    client = ServerClient("https://localhost:9", ca_bundle=server_tls["ca"], timeout_seconds=1.0)
    with pytest.raises(RenewalError):
        renew(config, client=client, max_attempts=1, sleep=lambda _s: None)

    assert config.paths.pending_private_key_path.exists()
    first_csr = config.paths.pending_csr_path.read_bytes()

    # A second run reuses it rather than generating another.
    reused = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    assert reused.created is False
    assert reused.csr_pem == first_csr


def test_a_reused_response_is_reported_as_such(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """The server returning `reused: true` is the lost-response recovery."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(device_ca, staged.private_key.public_key(), reused=True)

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=200, body=body)],
    ) as (base_url, _recorded):
        result = renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    assert result.reused is True
    assert is_enrolled(config.paths)


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (401, "device_not_active", "revoked"),
        (400, "csr_key_reused", "agent bug"),
        (400, "csr_invalid", "agent bug"),
        (422, "validation_failed", "schemas.py"),
    ],
)
def test_terminal_refusals_are_not_retried(
    tmp_path: Path,
    server_tls: dict[str, Path],
    device_ca: Authority,
    status: int,
    code: str,
    expected: str,
) -> None:
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    body = json.dumps({"code": code}).encode()

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=status, body=body)],
        ) as (base_url, recorded),
        pytest.raises(RenewalError) as raised,
    ):
        renew(
            config,
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _s: None,
        )

    assert len(recorded) == 1, f"a {status} was retried"
    assert expected in str(raised.value)
    # And the working identity is intact.
    assert is_enrolled(config.paths)


def test_a_tls_failure_is_never_retried(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    wrong_ca = write_pem(tmp_path / "wrong-ca.pem", make_authority("Other CA").pem)

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
        ) as (base_url, recorded),
        pytest.raises(TlsVerificationError),
    ):
        renew(
            config,
            client=ServerClient(base_url, ca_bundle=wrong_ca),
            sleep=lambda _s: None,
        )

    assert recorded == []


def test_a_response_naming_another_device_is_refused(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    config = config_for(tmp_path, server_tls)
    old_certificate = config.paths.certificate_path
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    before = old_certificate.read_bytes()

    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    body = renewal_response(
        device_ca, staged.private_key.public_key(), device_id="99999999-0000-0000-0000-000000000000"
    )

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=200, body=body)],
        ) as (base_url, _recorded),
        pytest.raises(RenewalError) as raised,
    ):
        renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    assert "names device" in str(raised.value)
    assert config.paths.certificate_path.read_bytes() == before


def test_a_certificate_for_the_wrong_key_is_refused_and_nothing_swaps(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Verified against the STAGED key before anything is swapped."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    before = config.paths.certificate_path.read_bytes()
    ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)

    stranger = ec.generate_private_key(ec.SECP256R1())
    body = renewal_response(device_ca, stranger.public_key())

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=200, body=body)],
        ) as (base_url, _recorded),
        pytest.raises(IdentityError) as raised,
    ):
        renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    assert "different public key" in str(raised.value)
    assert config.paths.certificate_path.read_bytes() == before
    assert not config.paths.pending_certificate_path.exists()


def test_a_certificate_from_another_ca_is_refused(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Catches a half-completed CA rotation before it costs a heartbeat loop."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    before = config.paths.certificate_path.read_bytes()
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)

    other = make_authority("Some Other CA")
    body = renewal_response(other, staged.private_key.public_key())
    # The response claims our CA issued it.
    document = json.loads(body)
    document["ca_chain_pem"] = device_ca.pem.decode()

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=200, body=json.dumps(document).encode())],
        ) as (base_url, _recorded),
        pytest.raises(IdentityError),
    ):
        renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    assert config.paths.certificate_path.read_bytes() == before


def test_renewing_an_unenrolled_device_is_refused(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    with pytest.raises(IdentityError) as raised:
        renew(config, client=ServerClient("https://localhost:9", ca_bundle=server_tls["ca"]))
    assert "not enrolled" in str(raised.value)


# --------------------------------------------------------------------------- #
# Crash recovery: the states a half-finished swap leaves behind
# --------------------------------------------------------------------------- #


def test_nothing_staged_is_a_no_op(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    assert complete_pending_renewal(config.paths) is None


def test_a_fully_staged_renewal_is_completed(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Crashed before the swap. Everything needed is on disk, so finish it."""
    config = config_for(tmp_path, server_tls)
    old_key = enrol_locally(config, device_ca)
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    write_pem(
        config.paths.pending_certificate_path,
        certificate_for(device_ca, staged.private_key.public_key()),
    )

    summary = complete_pending_renewal(config.paths)
    assert summary is not None
    assert summary.device_id == DEVICE_ID

    key, _ = load_identity(config.paths)
    assert public_keys_match(key.public_key(), staged.private_key.public_key())
    assert not public_keys_match(key.public_key(), old_key.public_key())
    assert not config.paths.pending_private_key_path.exists()


def test_a_half_swapped_renewal_is_completed(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Crashed BETWEEN replacing the certificate and replacing the key.

    This is the state that would otherwise be a mismatched pair with no
    explanation. It is identified rather than guessed: the installed
    certificate pairs with the pending key, which can only happen this way.
    """
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    new_certificate = certificate_for(device_ca, staged.private_key.public_key())

    # Simulate the crash: certificate moved, key not.
    write_pem(config.paths.certificate_path, new_certificate)
    assert not public_keys_match(
        x509.load_pem_x509_certificate(config.paths.certificate_path.read_bytes()).public_key(),
        ensure_keypair(
            config.paths.private_key_path, config.paths.csr_path
        ).private_key.public_key(),
    )

    summary = complete_pending_renewal(config.paths)
    assert summary is not None

    # Now consistent again, and `load_identity` no longer raises.
    key, _ = load_identity(config.paths)
    assert public_keys_match(key.public_key(), staged.private_key.public_key())
    assert not config.paths.pending_private_key_path.exists()


def test_a_staged_certificate_with_no_staged_key_is_discarded(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Unusable, so it goes. Keeping it would produce a confusing failure."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    stranger = ec.generate_private_key(ec.SECP256R1())
    write_pem(
        config.paths.pending_certificate_path, certificate_for(device_ca, stranger.public_key())
    )

    assert complete_pending_renewal(config.paths) is None
    assert not config.paths.pending_certificate_path.exists()
    # And the working identity is untouched.
    assert is_enrolled(config.paths)


def test_a_staged_key_with_no_certificate_is_kept(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """A renewal that got no response. Keeping it is what makes the retry work."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)

    assert complete_pending_renewal(config.paths) is None
    assert config.paths.pending_private_key_path.exists()
    assert config.paths.pending_csr_path.exists()


def test_a_staged_certificate_that_does_not_match_the_staged_key_is_discarded(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """The certificate is the replaceable half, so it goes and the key stays."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    stranger = ec.generate_private_key(ec.SECP256R1())
    write_pem(
        config.paths.pending_certificate_path, certificate_for(device_ca, stranger.public_key())
    )

    assert complete_pending_renewal(config.paths) is None
    assert not config.paths.pending_certificate_path.exists()
    assert config.paths.pending_private_key_path.exists()


def test_renew_completes_an_interrupted_attempt_instead_of_starting_a_new_one(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Recovery happens before anything is sent, so no request is made."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    write_pem(
        config.paths.pending_certificate_path,
        certificate_for(device_ca, staged.private_key.public_key()),
    )

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=500, body=b"{}")],
    ) as (base_url, recorded):
        result = renew(config, client=ServerClient(base_url, ca_bundle=server_tls["ca"]))

    assert result.recovered is True
    assert result.attempts == 0
    assert recorded == [], "a request was sent when recovery was all that was needed"


# --------------------------------------------------------------------------- #
# The scheduled task
# --------------------------------------------------------------------------- #


def test_the_task_does_nothing_when_renewal_is_not_due(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    calls: list[object] = []

    task = CertificateRenewalTask(
        config,
        logger=logging.getLogger("test"),
        renew_fn=lambda *a, **k: calls.append(a) or None,  # type: ignore[arg-type,return-value]
    )
    task()
    assert calls == []


def test_the_task_renews_when_due_and_resets_the_heartbeat(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """The heartbeat caches an SSLContext holding the old certificate.

    Without the reset it would keep presenting a superseded certificate and
    every heartbeat would fail on a device whose files are perfectly correct.
    """
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca, age=dt.timedelta(days=16))
    calls: list[object] = []
    resets: list[int] = []

    task = CertificateRenewalTask(
        config,
        logger=logging.getLogger("test"),
        on_renewed=lambda: resets.append(1),
        renew_fn=lambda *a, **k: calls.append(a) or None,  # type: ignore[arg-type,return-value]
    )
    task()
    assert len(calls) == 1
    assert resets == [1]


def test_the_task_skips_an_unenrolled_device(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    calls: list[object] = []

    task = CertificateRenewalTask(
        config,
        logger=logging.getLogger("test"),
        renew_fn=lambda *a, **k: calls.append(a) or None,  # type: ignore[arg-type,return-value]
    )
    task()
    assert calls == []


def test_the_task_does_not_attempt_renewal_on_an_expired_certificate(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Past renewal: the server refuses an expired certificate outright.

    Attempting it would only produce a 401 the agent cannot act on.
    """
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    install_certificate(
        config.paths,
        certificate_pem=certificate_for(
            device_ca,
            keypair.private_key.public_key(),
            not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60),
        ),
        ca_chain_pem=device_ca.pem,
        expected_device_id=DEVICE_ID,
        private_key=keypair.private_key,
    )
    calls: list[object] = []

    task = CertificateRenewalTask(
        config,
        logger=logging.getLogger("test"),
        renew_fn=lambda *a, **k: calls.append(a) or None,  # type: ignore[arg-type,return-value]
    )
    task()
    assert calls == []


def test_the_task_recovers_an_interrupted_renewal_at_startup(
    tmp_path: Path, server_tls: dict[str, Path], device_ca: Authority
) -> None:
    """Registered with first_run_immediately, so this happens on service start."""
    config = config_for(tmp_path, server_tls)
    enrol_locally(config, device_ca)
    staged = ensure_keypair(config.paths.pending_private_key_path, config.paths.pending_csr_path)
    write_pem(
        config.paths.pending_certificate_path,
        certificate_for(device_ca, staged.private_key.public_key()),
    )
    resets: list[int] = []
    calls: list[object] = []

    task = CertificateRenewalTask(
        config,
        logger=logging.getLogger("test"),
        on_renewed=lambda: resets.append(1),
        renew_fn=lambda *a, **k: calls.append(a) or None,  # type: ignore[arg-type,return-value]
    )
    task()

    assert resets == [1], "the heartbeat client was not reset after recovery"
    assert calls == [], "a renewal was attempted when recovery was all that was needed"
    key, _ = load_identity(config.paths)
    assert public_keys_match(key.public_key(), staged.private_key.public_key())
