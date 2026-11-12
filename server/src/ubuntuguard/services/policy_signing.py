"""Ed25519 signing and verification for policy envelopes.

This is the server half of the contract in docs/02-policy-and-signing.md. The Go
agent implements the other half, and testdata/policy_vectors.json is the fixed
vector both halves must reproduce - that file is the only thing that will catch
the two implementations disagreeing before a fleet of agents rejects every
policy.

The rule that shapes everything here: the payload is serialized once, and from
then on it is an opaque byte string. It is signed as bytes, transmitted
base64-encoded, and verified as bytes before anything parses it. Python's
`json.dumps` and Go's `encoding/json` do not agree on key order or escaping, so
signing a re-serialized object would be a verification failure waiting to
happen.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ubuntuguard.canonical import lp, lp_str, lp_u64
from ubuntuguard.constants import MAX_POLICY_PAYLOAD_BYTES, POLICY_ENVELOPE_DOMAIN
from ubuntuguard.services.ca import assert_key_file_private

ENVELOPE_VERSION = 1


class PolicyVerificationError(Exception):
    """Base class. Each subclass maps to a reason_code the agent reports back."""

    reason_code = "unknown"


class SignatureVerificationError(PolicyVerificationError):
    reason_code = "signature_invalid"


class UnknownKeyIdError(PolicyVerificationError):
    reason_code = "unknown_key_id"


class PayloadTooLargeError(PolicyVerificationError):
    reason_code = "payload_too_large"


class PayloadHashMismatchError(PolicyVerificationError):
    reason_code = "hash_mismatch"


class MalformedEnvelopeError(PolicyVerificationError):
    reason_code = "schema_invalid"


def format_rfc3339(moment: dt.datetime) -> str:
    """Render a timestamp for an envelope: UTC, whole seconds, trailing Z.

    Whole seconds, not microseconds, because this exact string goes into the
    signing input and has to be reproduced byte for byte by the Go agent.
    Fewer moving parts in the format means fewer ways for the two to disagree.
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError("envelope timestamps must be timezone-aware")
    return moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """`ed25519:` plus the first 16 hex chars of SHA-256 over the raw public key."""
    raw = public_key.public_bytes_raw()
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def build_signing_input(
    *,
    policy_id: str,
    policy_version: int,
    policy_type: str,
    scope_kind: str,
    scope_id: str,
    issued_at: str,
    expires_at: str | None,
    key_id: str,
    payload: bytes,
) -> bytes:
    """Build SIG_INPUT exactly as docs/02-policy-and-signing.md specifies.

    The metadata is inside the signature, not merely alongside it. Signing the
    payload alone would let an attacker take a validly signed payload and
    replay it under a higher version, a different policy type, or another
    device's scope - which is what the three negative vectors in
    testdata/policy_vectors.json are.

    Note `expires_at` uses the empty string for null, rather than the
    presence-byte encoding in `canonical.lp_opt_str`. That is deliberate and
    load-bearing: it is what the committed vector and the Go agent implement,
    and it is unambiguous here because a real RFC 3339 timestamp is never "".
    Do not "fix" this to lp_opt_str without regenerating the vector and updating
    the agent in the same change.
    """
    return b"".join(
        (
            POLICY_ENVELOPE_DOMAIN,
            lp_str(policy_id),
            lp_u64(policy_version),
            lp_str(policy_type),
            lp_str(scope_kind),
            lp_str(scope_id),
            lp_str(issued_at),
            lp_str(expires_at or ""),
            lp_str(key_id),
            lp(payload),
        )
    )


def serialize_payload(payload: Mapping[str, Any]) -> bytes:
    """Serialize a policy payload ONCE. The result is the authoritative bytes.

    Compact separators and sorted keys make the output stable for a given input,
    which keeps the committed test vector reproducible. That stability is a
    convenience for testing, not a security property: security comes from
    signing whatever bytes this produced, never from re-deriving them.
    """
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode(
        "utf-8"
    )
    if len(data) > MAX_POLICY_PAYLOAD_BYTES:
        raise PayloadTooLargeError(
            f"payload of {len(data)} bytes exceeds the {MAX_POLICY_PAYLOAD_BYTES} byte limit"
        )
    return data


class PolicySigner:
    """Holds the Ed25519 policy signing key and produces envelopes."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._key_id = key_id_for(private_key.public_key())

    @classmethod
    def from_file(cls, path: Path) -> PolicySigner:
        """Load a PEM PKCS#8 Ed25519 key, refusing a file others can read."""
        assert_key_file_private(path)
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(
                f"policy signing key must be Ed25519, got {type(key).__name__}. "
                "The policy key is deliberately separate from the TLS and CA keys."
            )
        return cls(key)

    @classmethod
    def from_seed(cls, seed: bytes) -> PolicySigner:
        """Build from a 32-byte seed. For tests and reproducible vectors only."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign_envelope(
        self,
        *,
        policy_id: str,
        policy_version: int,
        policy_type: str,
        scope_kind: str,
        scope_id: str,
        issued_at: dt.datetime,
        payload: bytes,
        expires_at: dt.datetime | None = None,
    ) -> dict[str, Any]:
        """Produce a signed envelope around already-serialized payload bytes.

        Takes bytes, not a dict, so there is no opportunity to re-serialize
        between signing and sending. Use `serialize_payload` once, upstream.
        """
        if len(payload) > MAX_POLICY_PAYLOAD_BYTES:
            raise PayloadTooLargeError(
                f"payload of {len(payload)} bytes exceeds the {MAX_POLICY_PAYLOAD_BYTES} byte limit"
            )

        issued = format_rfc3339(issued_at)
        expires = format_rfc3339(expires_at) if expires_at is not None else None

        signature = self._private_key.sign(
            build_signing_input(
                policy_id=policy_id,
                policy_version=policy_version,
                policy_type=policy_type,
                scope_kind=scope_kind,
                scope_id=scope_id,
                issued_at=issued,
                expires_at=expires,
                key_id=self._key_id,
                payload=payload,
            )
        )

        return {
            "envelope_version": ENVELOPE_VERSION,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_type": policy_type,
            "scope": {"kind": scope_kind, "id": scope_id},
            "issued_at": issued,
            "expires_at": expires,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "signature": {
                "alg": "ed25519",
                "key_id": self._key_id,
                "value_b64": base64.b64encode(signature).decode("ascii"),
            },
        }


def verify_envelope(
    envelope: Mapping[str, Any],
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> bytes:
    """Verify an envelope and return the payload bytes. Does NOT parse them.

    Returning raw bytes is the point: it makes "verify before you parse"
    structural rather than a comment. A caller cannot accidentally inspect the
    payload first, because it has nothing to inspect until this returns.

    Mirrors what the agent must do, and is what the server uses to test its own
    output and to re-verify a stored policy.
    """
    try:
        payload_b64 = envelope["payload_b64"]
        signature_block = envelope["signature"]
        key_id = signature_block["key_id"]
        signature_b64 = signature_block["value_b64"]
        scope = envelope["scope"]
    except (KeyError, TypeError) as exc:
        raise MalformedEnvelopeError(f"envelope is missing required fields: {exc}") from exc

    if signature_block.get("alg") != "ed25519":
        raise MalformedEnvelopeError(
            f"unsupported signature algorithm: {signature_block.get('alg')!r}"
        )

    # Bound the work before decoding, so an oversized envelope is cheap to reject.
    if len(payload_b64) > (MAX_POLICY_PAYLOAD_BYTES * 4) // 3 + 4:
        raise PayloadTooLargeError("payload_b64 is longer than the maximum payload permits")

    try:
        payload = base64.b64decode(payload_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedEnvelopeError(f"invalid base64 in envelope: {exc}") from exc

    if len(payload) > MAX_POLICY_PAYLOAD_BYTES:
        raise PayloadTooLargeError(f"payload of {len(payload)} bytes exceeds the limit")

    # Advisory check. Cheap, and it fails closed on a corrupted transfer, but the
    # signature below is the only thing that establishes authenticity.
    if hashlib.sha256(payload).hexdigest() != envelope.get("payload_sha256"):
        raise PayloadHashMismatchError("payload_sha256 does not match the decoded payload")

    public_key = trusted_keys.get(key_id)
    if public_key is None:
        raise UnknownKeyIdError(f"key_id {key_id!r} is not in the trusted set")

    signing_input = build_signing_input(
        policy_id=envelope["policy_id"],
        policy_version=envelope["policy_version"],
        policy_type=envelope["policy_type"],
        scope_kind=scope["kind"],
        scope_id=scope["id"],
        # The strings as they arrived, never reformatted: reformatting would
        # verify a different message from the one that was signed.
        issued_at=envelope["issued_at"],
        expires_at=envelope.get("expires_at"),
        key_id=key_id,
        payload=payload,
    )

    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise SignatureVerificationError("Ed25519 signature verification failed") from exc

    return payload
