"""Policy signing tests.

The first test is the important one: the server must reproduce the committed
cross-language vector byte for byte. When the Go agent arrives in Phase 4 it
runs against the same file, and that is what will catch the two implementations
disagreeing - before a fleet of agents starts rejecting every policy.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ubuntuguard.constants import MAX_POLICY_PAYLOAD_BYTES
from ubuntuguard.services.ca import KeyFilePermissionError
from ubuntuguard.services.policy_signing import (
    MalformedEnvelopeError,
    PayloadHashMismatchError,
    PayloadTooLargeError,
    PolicySigner,
    SignatureVerificationError,
    UnknownKeyIdError,
    build_signing_input,
    format_rfc3339,
    key_id_for,
    serialize_payload,
    verify_envelope,
)

ISSUED = dt.datetime(2026, 10, 29, 10, 0, 0, tzinfo=dt.UTC)


def signer_from_vector(vectors: dict[str, Any]) -> PolicySigner:
    derivation = vectors["key_derivation"]["derivation_string"]
    seed = hashlib.sha256(derivation.encode("ascii")).digest()
    return PolicySigner.from_seed(seed)


def trusted(signer: PolicySigner) -> dict[str, Any]:
    return {signer.key_id: signer.public_key}


# --------------------------------------------------------------------------- #
# The cross-language vector
# --------------------------------------------------------------------------- #


def test_key_derives_from_the_documented_string(policy_vectors: dict[str, Any]) -> None:
    """No key bytes are committed; the vector is reproducible from a string."""
    signer = signer_from_vector(policy_vectors)
    expected = policy_vectors["key_derivation"]
    assert signer.key_id == expected["expected_key_id"]
    assert (
        base64.b64encode(signer.public_key.public_bytes_raw()).decode()
        == expected["expected_public_key_b64"]
    )


def test_server_reproduces_the_committed_envelope_exactly(
    policy_vectors: dict[str, Any],
) -> None:
    """Every field, including the signature, must match the committed vector."""
    signer = signer_from_vector(policy_vectors)
    expected = policy_vectors["positive"]["envelope"]
    payload = base64.b64decode(expected["payload_b64"], validate=True)

    produced = signer.sign_envelope(
        policy_id=expected["policy_id"],
        policy_version=expected["policy_version"],
        policy_type=expected["policy_type"],
        scope_kind=expected["scope"]["kind"],
        scope_id=expected["scope"]["id"],
        issued_at=dt.datetime.fromisoformat(expected["issued_at"]),
        expires_at=None,
        payload=payload,
    )

    assert produced == expected


def test_signing_input_matches_the_committed_digest(policy_vectors: dict[str, Any]) -> None:
    """Pinned separately so a drift in SIG_INPUT is diagnosable.

    If only the signature comparison failed, the cause could be the key, the
    field order, or the encoding. This narrows it to the input construction.
    """
    positive = policy_vectors["positive"]
    envelope = positive["envelope"]
    payload = base64.b64decode(envelope["payload_b64"], validate=True)

    signing_input = build_signing_input(
        policy_id=envelope["policy_id"],
        policy_version=envelope["policy_version"],
        policy_type=envelope["policy_type"],
        scope_kind=envelope["scope"]["kind"],
        scope_id=envelope["scope"]["id"],
        issued_at=envelope["issued_at"],
        expires_at=envelope["expires_at"],
        key_id=envelope["signature"]["key_id"],
        payload=payload,
    )

    assert len(payload) == positive["expected_payload_len"]
    assert len(signing_input) == positive["expected_sig_input_len"]
    assert hashlib.sha256(signing_input).hexdigest() == positive["expected_sig_input_sha256"]


def test_positive_vector_verifies(policy_vectors: dict[str, Any]) -> None:
    signer = signer_from_vector(policy_vectors)
    envelope = policy_vectors["positive"]["envelope"]
    payload = verify_envelope(envelope, trusted(signer))
    assert hashlib.sha256(payload).hexdigest() == envelope["payload_sha256"]


def test_every_negative_vector_is_rejected(policy_vectors: dict[str, Any]) -> None:
    """These are the three replay attacks the signing input is built to stop:
    a bit-flipped payload, a version bumped without re-signing, and a policy
    re-scoped to a different device.
    """
    signer = signer_from_vector(policy_vectors)
    negatives = policy_vectors["negative"]
    assert len(negatives) == 3

    for case in negatives:
        with pytest.raises(SignatureVerificationError):
            verify_envelope(case["envelope"], trusted(signer))


# --------------------------------------------------------------------------- #
# Verification behaviour
# --------------------------------------------------------------------------- #


def test_verify_returns_raw_bytes_so_parsing_cannot_come_first(
    policy_vectors: dict[str, Any],
) -> None:
    """ "Verify before you parse" is structural here, not a comment.

    The caller gets bytes, so there is nothing to inspect until verification
    has already succeeded.
    """
    signer = signer_from_vector(policy_vectors)
    result = verify_envelope(policy_vectors["positive"]["envelope"], trusted(signer))
    assert isinstance(result, bytes)


def test_unknown_key_id_is_rejected(policy_vectors: dict[str, Any]) -> None:
    envelope = policy_vectors["positive"]["envelope"]
    with pytest.raises(UnknownKeyIdError):
        verify_envelope(envelope, {})


def test_signature_from_another_key_is_rejected() -> None:
    """A valid signature by an untrusted key must not pass.

    The attacker here signs a perfectly well-formed envelope with their own
    key and registers nothing; only the pinned trust set stops them.
    """
    attacker = PolicySigner.from_seed(b"\x01" * 32)
    victim = PolicySigner.from_seed(b"\x02" * 32)
    payload = serialize_payload({"schema": "ubuntuguard.usb_control.v1"})
    envelope = attacker.sign_envelope(
        policy_id="3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        policy_version=1,
        policy_type="usb_control",
        scope_kind="device",
        scope_id="9a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d",
        issued_at=ISSUED,
        payload=payload,
    )
    # Trusting only the victim's key, the attacker's key_id is unknown.
    with pytest.raises(UnknownKeyIdError):
        verify_envelope(envelope, trusted(victim))

    # And relabelling it with the victim's key_id fails the signature check,
    # because key_id is itself inside the signing input.
    envelope["signature"]["key_id"] = victim.key_id
    with pytest.raises(SignatureVerificationError):
        verify_envelope(envelope, trusted(victim))


def test_advisory_hash_mismatch_fails_closed(policy_vectors: dict[str, Any]) -> None:
    signer = signer_from_vector(policy_vectors)
    envelope = dict(policy_vectors["positive"]["envelope"])
    envelope["payload_sha256"] = "0" * 64
    with pytest.raises(PayloadHashMismatchError):
        verify_envelope(envelope, trusted(signer))


def test_tampering_with_issued_at_is_rejected(policy_vectors: dict[str, Any]) -> None:
    """Timestamps are inside the signature, so they cannot be shifted."""
    signer = signer_from_vector(policy_vectors)
    envelope = dict(policy_vectors["positive"]["envelope"])
    envelope["issued_at"] = "2026-11-29T10:00:00Z"
    with pytest.raises(SignatureVerificationError):
        verify_envelope(envelope, trusted(signer))


def test_expires_at_is_covered_by_the_signature() -> None:
    """Otherwise an expiring policy could be made permanent in transit."""
    signer = PolicySigner.from_seed(b"\x03" * 32)
    payload = serialize_payload({"schema": "ubuntuguard.usb_control.v1"})
    envelope = signer.sign_envelope(
        policy_id="3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        policy_version=1,
        policy_type="usb_control",
        scope_kind="device",
        scope_id="d",
        issued_at=ISSUED,
        expires_at=ISSUED + dt.timedelta(hours=1),
        payload=payload,
    )
    assert verify_envelope(envelope, trusted(signer)) == payload

    envelope["expires_at"] = "2099-01-01T00:00:00Z"
    with pytest.raises(SignatureVerificationError):
        verify_envelope(envelope, trusted(signer))


def test_removing_expires_at_is_rejected() -> None:
    """Null and a timestamp must not be interchangeable."""
    signer = PolicySigner.from_seed(b"\x04" * 32)
    payload = serialize_payload({"schema": "ubuntuguard.usb_control.v1"})
    envelope = signer.sign_envelope(
        policy_id="3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        policy_version=1,
        policy_type="usb_control",
        scope_kind="device",
        scope_id="d",
        issued_at=ISSUED,
        expires_at=ISSUED + dt.timedelta(hours=1),
        payload=payload,
    )
    envelope["expires_at"] = None
    with pytest.raises(SignatureVerificationError):
        verify_envelope(envelope, trusted(signer))


@pytest.mark.parametrize("missing", ["payload_b64", "signature", "scope"])
def test_missing_fields_are_rejected(policy_vectors: dict[str, Any], missing: str) -> None:
    signer = signer_from_vector(policy_vectors)
    envelope = dict(policy_vectors["positive"]["envelope"])
    del envelope[missing]
    with pytest.raises(MalformedEnvelopeError):
        verify_envelope(envelope, trusted(signer))


def test_unsupported_algorithm_is_rejected(policy_vectors: dict[str, Any]) -> None:
    """Algorithm confusion fails before any crypto runs."""
    signer = signer_from_vector(policy_vectors)
    envelope = dict(policy_vectors["positive"]["envelope"])
    envelope["signature"] = dict(envelope["signature"], alg="none")
    with pytest.raises(MalformedEnvelopeError, match="unsupported signature algorithm"):
        verify_envelope(envelope, trusted(signer))


def test_invalid_base64_is_rejected(policy_vectors: dict[str, Any]) -> None:
    signer = signer_from_vector(policy_vectors)
    envelope = dict(policy_vectors["positive"]["envelope"])
    envelope["payload_b64"] = "not base64!!"
    with pytest.raises(MalformedEnvelopeError, match="base64"):
        verify_envelope(envelope, trusted(signer))


def test_oversized_payload_is_refused_at_signing_time() -> None:
    signer = PolicySigner.from_seed(b"\x05" * 32)
    with pytest.raises(PayloadTooLargeError):
        signer.sign_envelope(
            policy_id="3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            policy_version=1,
            policy_type="usb_control",
            scope_kind="device",
            scope_id="d",
            issued_at=ISSUED,
            payload=b"x" * (MAX_POLICY_PAYLOAD_BYTES + 1),
        )


def test_oversized_payload_is_refused_at_verification_time() -> None:
    """Bounded before decoding, so a huge envelope is cheap to reject."""
    envelope = {
        "payload_b64": "A" * (MAX_POLICY_PAYLOAD_BYTES * 2),
        "payload_sha256": "0" * 64,
        "policy_id": "x",
        "policy_version": 1,
        "policy_type": "usb_control",
        "scope": {"kind": "device", "id": "d"},
        "issued_at": "2026-10-29T10:00:00Z",
        "expires_at": None,
        "signature": {"alg": "ed25519", "key_id": "ed25519:0000000000000000", "value_b64": "A"},
    }
    with pytest.raises(PayloadTooLargeError):
        verify_envelope(envelope, {})


def test_serialize_payload_enforces_the_size_cap() -> None:
    with pytest.raises(PayloadTooLargeError):
        serialize_payload({"filler": "x" * (MAX_POLICY_PAYLOAD_BYTES + 100)})


def test_serialize_payload_is_stable() -> None:
    """Key order must not depend on dict insertion order."""
    assert serialize_payload({"b": 1, "a": 2}) == serialize_payload({"a": 2, "b": 1})


# --------------------------------------------------------------------------- #
# Timestamps and key loading
# --------------------------------------------------------------------------- #


def test_envelope_timestamps_use_whole_seconds() -> None:
    """Fewer moving parts in the format means fewer ways for Go to disagree."""
    assert format_rfc3339(ISSUED) == "2026-10-29T10:00:00Z"
    assert format_rfc3339(ISSUED.replace(microsecond=123456)) == "2026-10-29T10:00:00Z"


def test_envelope_timestamps_normalise_to_utc() -> None:
    tz = dt.timezone(dt.timedelta(hours=-7))
    assert format_rfc3339(ISSUED.astimezone(tz)) == "2026-10-29T10:00:00Z"


def test_naive_envelope_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        format_rfc3339(dt.datetime(2026, 10, 29, 10, 0, 0))  # noqa: DTZ001


def test_key_id_is_derived_from_the_public_key() -> None:
    key = Ed25519PrivateKey.generate()
    expected = "ed25519:" + hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest()[:16]
    assert key_id_for(key.public_key()) == expected


def _write_key(path: Path, key: object, mode: int) -> None:
    pem = key.private_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    path.chmod(mode)


def test_signing_key_loads_from_a_private_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.key"
    key = Ed25519PrivateKey.generate()
    _write_key(path, key, 0o600)
    signer = PolicySigner.from_file(path)
    assert signer.key_id == key_id_for(key.public_key())


def test_world_readable_signing_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "policy.key"
    _write_key(path, Ed25519PrivateKey.generate(), 0o644)
    with pytest.raises(KeyFilePermissionError):
        PolicySigner.from_file(path)


def test_non_ed25519_signing_key_is_refused(tmp_path: Path) -> None:
    """The policy key is deliberately a different algorithm from the CA key, so
    pointing this at the CA key by mistake fails loudly.
    """
    path = tmp_path / "wrong.key"
    _write_key(path, ec.generate_private_key(ec.SECP256R1()), 0o600)
    with pytest.raises(TypeError, match="must be Ed25519"):
        PolicySigner.from_file(path)
