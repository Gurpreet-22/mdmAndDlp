"""Conformance against the committed policy signing vector.

This is the most important test in the Phase 1 suite. The repository's whole
policy-signing design rests on the agent and the server producing byte-identical
signing input, and `testdata/policy_vectors.json` is the only artefact that will
catch a disagreement before a fleet of agents rejects every policy.

The vector is checked in layers, deliberately, because a single
"signature did not verify" assertion is almost useless for diagnosis:

  1. the key derives to the expected public key and key_id
  2. the signing input has the expected LENGTH
  3. the signing input has the expected SHA-256
  4. only then, the signature verifies

A length mismatch at step 2 means a field is missing or the length prefix is
wrong. A digest mismatch at step 3 with a correct length means a field is in the
wrong order or encoded differently. Both are encoding bugs, and they report as
encoding bugs rather than as mysterious crypto failures.

Then the three negative vectors, each of which is a real attack:
a flipped payload bit, a version bumped without re-signing, and a scope swapped
to another device. The last two are the reason the envelope metadata is inside
the signature rather than merely alongside it.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ubuntuguard_agent.constants import MAX_POLICY_PAYLOAD_BYTES, POLICY_ENVELOPE_DOMAIN
from ubuntuguard_agent.core.envelope import (
    build_signing_input,
    key_id_for,
    load_public_key_b64,
    verify_envelope,
)
from ubuntuguard_agent.errors import (
    MalformedEnvelopeError,
    PayloadHashMismatchError,
    PayloadTooLargeError,
    ReasonCode,
    SignatureVerificationError,
    UnknownKeyIdError,
)

# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #


@pytest.fixture
def vector_private_key(policy_vectors: dict[str, Any]) -> Ed25519PrivateKey:
    """Derive the test key from the documented string.

    No key bytes are committed anywhere (decision D11). The vector states the
    derivation - seed = SHA-256 of an ASCII string - so any implementation in
    any language can reproduce it without a secret in the repository.
    """
    derivation = policy_vectors["key_derivation"]
    seed = hashlib.sha256(derivation["derivation_string"].encode("ascii")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


@pytest.fixture
def vector_public_key(vector_private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return vector_private_key.public_key()


def test_key_derivation_reproduces_the_committed_public_key(
    policy_vectors: dict[str, Any], vector_public_key: Ed25519PublicKey
) -> None:
    raw = vector_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    assert (
        base64.b64encode(raw).decode("ascii")
        == (policy_vectors["key_derivation"]["expected_public_key_b64"])
    )


def test_key_id_matches_the_committed_value(
    policy_vectors: dict[str, Any], vector_public_key: Ed25519PublicKey
) -> None:
    """`key_id` is how an envelope names the key that signed it.

    Derived the same way on both sides - "ed25519:" plus the first 16 hex chars
    of SHA-256 over the raw public key - so a mismatch here would make every
    policy unverifiable with `unknown_key_id`, not merely mislabelled.
    """
    assert key_id_for(vector_public_key) == (policy_vectors["key_derivation"]["expected_key_id"])


# --------------------------------------------------------------------------- #
# The signing input, before any signature is involved
# --------------------------------------------------------------------------- #


def _signing_input_from(envelope: dict[str, Any]) -> bytes:
    return build_signing_input(
        policy_id=envelope["policy_id"],
        policy_version=envelope["policy_version"],
        policy_type=envelope["policy_type"],
        scope_kind=envelope["scope"]["kind"],
        scope_id=envelope["scope"]["id"],
        issued_at=envelope["issued_at"],
        expires_at=envelope.get("expires_at"),
        key_id=envelope["signature"]["key_id"],
        payload=base64.b64decode(envelope["payload_b64"]),
    )


def test_payload_decodes_to_the_committed_length(policy_vectors: dict[str, Any]) -> None:
    positive = policy_vectors["positive"]
    payload = base64.b64decode(positive["envelope"]["payload_b64"])
    assert len(payload) == positive["expected_payload_len"]


def test_signing_input_has_the_committed_length(policy_vectors: dict[str, Any]) -> None:
    """Layer 2. A mismatch means a missing field or a wrong length prefix."""
    positive = policy_vectors["positive"]
    signing_input = _signing_input_from(positive["envelope"])
    assert len(signing_input) == positive["expected_sig_input_len"]


def test_signing_input_has_the_committed_digest(policy_vectors: dict[str, Any]) -> None:
    """Layer 3. Correct length but wrong digest means wrong order or encoding."""
    positive = policy_vectors["positive"]
    signing_input = _signing_input_from(positive["envelope"])
    assert hashlib.sha256(signing_input).hexdigest() == (positive["expected_sig_input_sha256"])


def test_signing_input_starts_with_the_domain_separator(
    policy_vectors: dict[str, Any],
) -> None:
    """Domain separation keeps a policy signature from being valid elsewhere.

    Without it, a signature over an audit-chain input could in principle be
    replayed as a policy signature. The separator is ASCII with no terminator,
    which is why the first length-prefixed field follows it immediately.
    """
    signing_input = _signing_input_from(policy_vectors["positive"]["envelope"])
    assert signing_input.startswith(POLICY_ENVELOPE_DOMAIN)
    assert POLICY_ENVELOPE_DOMAIN == b"ubuntuguard/policy-envelope/v1"


def test_null_expires_at_encodes_as_the_empty_string() -> None:
    """The deliberate, load-bearing deviation from `lp_opt_str`.

    The server's own comment calls this out: a null `expires_at` is encoded as
    the empty string rather than with a presence byte, because that is what the
    committed vector implements. If someone "fixes" either side to use
    `lp_opt_str`, this test fails and says why, instead of the change surfacing
    as every policy failing to verify in production.
    """
    common = {
        "policy_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "policy_version": 7,
        "policy_type": "usb_control",
        "scope_kind": "device",
        "scope_id": "9a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d",
        "issued_at": "2026-10-29T10:00:00Z",
        "key_id": "ed25519:591a43e375a40af2",
        "payload": b"{}",
    }
    assert build_signing_input(expires_at=None, **common) == build_signing_input(
        expires_at="", **common
    )


# --------------------------------------------------------------------------- #
# The positive vector
# --------------------------------------------------------------------------- #


def test_committed_signature_matches_a_fresh_signature(
    policy_vectors: dict[str, Any], vector_private_key: Ed25519PrivateKey
) -> None:
    """Sign the input ourselves and compare against the committed signature.

    Ed25519 is deterministic (RFC 8032), so the same key over the same message
    always produces the same 64 bytes. That makes this a stronger check than
    verification alone: it proves we built the identical message, not merely a
    message the signature happens to satisfy.
    """
    positive = policy_vectors["positive"]
    signature = vector_private_key.sign(_signing_input_from(positive["envelope"]))
    assert base64.b64encode(signature).decode("ascii") == (positive["expected_signature_b64"])


def test_positive_vector_verifies(
    policy_vectors: dict[str, Any], vector_public_key: Ed25519PublicKey
) -> None:
    positive = policy_vectors["positive"]
    envelope = positive["envelope"]
    assert positive["must_verify"] is True

    payload = verify_envelope(envelope, {key_id_for(vector_public_key): vector_public_key})

    assert payload == base64.b64decode(envelope["payload_b64"])
    assert hashlib.sha256(payload).hexdigest() == envelope["payload_sha256"]


def test_verify_returns_bytes_and_does_not_parse(
    policy_vectors: dict[str, Any], vector_public_key: Ed25519PublicKey
) -> None:
    """ "Verify before you parse" is structural, not a convention.

    `verify_envelope` returns raw bytes rather than a decoded object, so a
    caller has nothing to inspect until verification has succeeded. A refactor
    that made it return a dict would quietly move JSON parsing in front of the
    signature check, which is the ordering the whole design exists to prevent.
    """
    payload = verify_envelope(
        policy_vectors["positive"]["envelope"],
        {key_id_for(vector_public_key): vector_public_key},
    )
    assert isinstance(payload, bytes)


# --------------------------------------------------------------------------- #
# The negative vectors
# --------------------------------------------------------------------------- #


def test_every_committed_negative_vector_is_rejected(
    policy_vectors: dict[str, Any], vector_public_key: Ed25519PublicKey
) -> None:
    """All three negatives, each with the reason code the vector specifies.

    Iterating the committed list rather than hardcoding three cases matters: a
    negative vector added to the file in future is picked up automatically
    instead of being silently untested.
    """
    trusted = {key_id_for(vector_public_key): vector_public_key}
    negatives = policy_vectors["negative"]
    assert len(negatives) >= 3, "the vector should carry at least three negatives"

    for case in negatives:
        assert case["must_verify"] is False
        with pytest.raises(SignatureVerificationError) as raised:
            verify_envelope(case["envelope"], trusted)
        assert raised.value.reason_code == case["expected_reason_code"], (
            f"{case['name']}: {case['why']}"
        )


def test_payload_bit_flip_is_caught_by_the_signature_not_only_the_hash(
    policy_vectors: dict[str, Any], vector_public_key: Ed25519PublicKey
) -> None:
    """The flipped-payload vector updates `payload_sha256` to match.

    That is what makes it a real test. If the advisory hash still held the old
    value, the cheap `hash_mismatch` check would catch it and the signature
    check would never run - and a hash the attacker controls proves nothing. The
    vector keeps the hash consistent, so only the signature can reject it.
    """
    case = next(c for c in policy_vectors["negative"] if c["name"] == "payload_bit_flipped")
    envelope = case["envelope"]

    payload = base64.b64decode(envelope["payload_b64"])
    assert hashlib.sha256(payload).hexdigest() == envelope["payload_sha256"]

    with pytest.raises(SignatureVerificationError):
        verify_envelope(envelope, {key_id_for(vector_public_key): vector_public_key})


# --------------------------------------------------------------------------- #
# Everything else verify_envelope has to refuse
# --------------------------------------------------------------------------- #


@pytest.fixture
def good_envelope(policy_vectors: dict[str, Any]) -> dict[str, Any]:
    import copy

    return copy.deepcopy(policy_vectors["positive"]["envelope"])


@pytest.fixture
def trusted(vector_public_key: Ed25519PublicKey) -> dict[str, Ed25519PublicKey]:
    return {key_id_for(vector_public_key): vector_public_key}


def test_unknown_key_id_is_refused_with_no_fallback(good_envelope: dict[str, Any]) -> None:
    """An unpinned key is refused, never fetched.

    The pinned set comes from the enrollment response over a channel the agent
    had already authenticated. Looking a key up anywhere else in order to
    validate a document is how a signature check becomes decoration.
    """
    with pytest.raises(UnknownKeyIdError) as raised:
        verify_envelope(good_envelope, {})
    assert raised.value.reason_code == ReasonCode.UNKNOWN_KEY_ID


def test_wrong_key_does_not_verify(good_envelope: dict[str, Any]) -> None:
    """A different key under the *expected* key_id still fails.

    Covers the case where the key_id lookup succeeds but the key is not the one
    that signed, which an attacker who can edit pinned state would attempt.
    """
    other = Ed25519PrivateKey.generate().public_key()
    key_id = good_envelope["signature"]["key_id"]
    with pytest.raises(SignatureVerificationError):
        verify_envelope(good_envelope, {key_id: other})


def test_hash_mismatch_fails_closed(
    good_envelope: dict[str, Any], trusted: dict[str, Ed25519PublicKey]
) -> None:
    good_envelope["payload_sha256"] = "0" * 64
    with pytest.raises(PayloadHashMismatchError) as raised:
        verify_envelope(good_envelope, trusted)
    assert raised.value.reason_code == ReasonCode.HASH_MISMATCH


def test_oversized_payload_is_rejected_before_decoding(
    trusted: dict[str, Ed25519PublicKey],
) -> None:
    """Bounded before the work, not after.

    The length of the base64 is checked before it is decoded, so an envelope
    claiming a megabyte of payload costs a string comparison rather than a
    megabyte of allocation.
    """
    envelope = {
        "policy_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "policy_version": 1,
        "policy_type": "usb_control",
        "scope": {"kind": "device", "id": "x"},
        "issued_at": "2026-10-29T10:00:00Z",
        "expires_at": None,
        "payload_b64": "A" * (MAX_POLICY_PAYLOAD_BYTES * 2),
        "payload_sha256": "0" * 64,
        "signature": {"alg": "ed25519", "key_id": "ed25519:0000000000000000", "value_b64": "x"},
    }
    with pytest.raises(PayloadTooLargeError) as raised:
        verify_envelope(envelope, trusted)
    assert raised.value.reason_code == ReasonCode.PAYLOAD_TOO_LARGE


def test_non_ed25519_algorithm_is_refused_by_name(
    good_envelope: dict[str, Any], trusted: dict[str, Ed25519PublicKey]
) -> None:
    """Algorithm confusion is refused, not ignored.

    This is the `envelope.bad_key_id` negative case in the schema manifest
    (threat T2) expressed in code: an envelope naming another algorithm must
    fail rather than have the field disregarded.
    """
    good_envelope["signature"]["alg"] = "rsa-pss"
    with pytest.raises(MalformedEnvelopeError):
        verify_envelope(good_envelope, trusted)


def test_signature_of_the_wrong_length_is_refused(
    good_envelope: dict[str, Any], trusted: dict[str, Ed25519PublicKey]
) -> None:
    """A truncated signature: the `envelope.signature_truncated` negative."""
    raw = base64.b64decode(good_envelope["signature"]["value_b64"])
    good_envelope["signature"]["value_b64"] = base64.b64encode(raw[:32]).decode("ascii")
    with pytest.raises(MalformedEnvelopeError):
        verify_envelope(good_envelope, trusted)


def test_invalid_base64_is_refused(
    good_envelope: dict[str, Any], trusted: dict[str, Ed25519PublicKey]
) -> None:
    good_envelope["payload_b64"] = "not valid base64!!"
    with pytest.raises(MalformedEnvelopeError):
        verify_envelope(good_envelope, trusted)


@pytest.mark.parametrize(
    "field", ["payload_b64", "signature", "scope", "policy_id", "policy_version", "policy_type"]
)
def test_missing_required_field_is_refused(
    good_envelope: dict[str, Any], trusted: dict[str, Ed25519PublicKey], field: str
) -> None:
    del good_envelope[field]
    with pytest.raises(MalformedEnvelopeError):
        verify_envelope(good_envelope, trusted)


def test_malformed_envelope_shapes_are_refused(
    trusted: dict[str, Ed25519PublicKey],
) -> None:
    """A server response is untrusted input, including its shape.

    `signature` arriving as a string rather than an object must raise the
    agent's own error type, not a TypeError from somewhere deeper.
    """
    with pytest.raises(MalformedEnvelopeError):
        verify_envelope({"payload_b64": "AA==", "signature": "nope", "scope": {}}, trusted)


def test_boolean_policy_version_is_refused(
    good_envelope: dict[str, Any], trusted: dict[str, Ed25519PublicKey]
) -> None:
    """`True` is an int in Python, and must not be accepted as version 1.

    JSON `true` reaching an integer field is a structural error. Without the
    explicit bool check it would encode as 1 and verify against a policy signed
    for version 1, which is a real, if narrow, confusion.
    """
    good_envelope["policy_version"] = True
    with pytest.raises(MalformedEnvelopeError):
        verify_envelope(good_envelope, trusted)


def test_load_public_key_b64_round_trips(
    policy_vectors: dict[str, Any], vector_public_key: Ed25519PublicKey
) -> None:
    """The enrollment response hands over keys as base64; this is that path."""
    loaded = load_public_key_b64(policy_vectors["key_derivation"]["expected_public_key_b64"])
    assert key_id_for(loaded) == key_id_for(vector_public_key)


@pytest.mark.parametrize("bad", ["", "!!!!", "AAAA", "short"])
def test_load_public_key_b64_refuses_rubbish(bad: str) -> None:
    with pytest.raises(MalformedEnvelopeError):
        load_public_key_b64(bad)
