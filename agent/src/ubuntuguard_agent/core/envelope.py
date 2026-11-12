"""Ed25519 policy envelope verification. The agent half of the contract.

The server half is `server/src/ubuntuguard/services/policy_signing.py` and the
normative specification is docs/02-policy-and-signing.md. This module must agree
with both byte for byte, and `testdata/policy_vectors.json` is the only thing
that will catch a disagreement before a fleet of agents rejects every policy.

One rule shapes everything here, from the server's module header: the payload is
serialized once by the server and from then on is an opaque byte string. It is
signed as bytes, transmitted base64-encoded, and **verified as bytes before
anything parses it**. `verify_envelope` therefore returns `bytes` and never a
parsed object - that makes "verify before you parse" structural rather than a
comment in a docstring, because a caller has nothing to inspect until
verification has succeeded.

Three details will silently break verification if they drift, and all three are
load-bearing rather than incidental:

1. A null `expires_at` is encoded as the **empty string**, not with the
   presence-byte scheme in `canonical.lp_opt_str`. This is what the committed
   vector and the server implement. It is unambiguous because a real RFC 3339
   timestamp is never "".
2. Timestamps are used **exactly as they arrived** on the wire. Reformatting
   them - even into an equivalent representation - verifies a different message
   from the one that was signed.
3. `payload_sha256` is **advisory** and deliberately outside the signing input,
   so there is exactly one authority for authenticity. It is still recomputed
   and still fails closed, because a corrupted transfer should be cheap to
   reject, but the signature is the only thing that establishes authenticity.

Scope and version admission - is this policy for this device, and is it newer
than what we have - is deliberately NOT here. That is a separate decision made
after verification, and it arrives with the policy manager in Phase 6.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ubuntuguard_agent.constants import MAX_POLICY_PAYLOAD_BYTES, POLICY_ENVELOPE_DOMAIN
from ubuntuguard_agent.core.canonical import lp, lp_str, lp_u64
from ubuntuguard_agent.errors import (
    MalformedEnvelopeError,
    PayloadHashMismatchError,
    PayloadTooLargeError,
    SignatureVerificationError,
    UnknownKeyIdError,
)

#: Ed25519 signatures are 64 bytes, which is 88 characters of base64 with two
#: pad characters. The envelope schema pins the same length.
_SIGNATURE_BYTES = 64

#: Ceiling on the encoded payload before any decoding happens, so an oversized
#: envelope is rejected without allocating the decoded form. Matches the
#: server's bound exactly.
_MAX_PAYLOAD_B64_CHARS = (MAX_POLICY_PAYLOAD_BYTES * 4) // 3 + 4


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """`ed25519:` plus the first 16 hex chars of SHA-256 over the raw key.

    Uses the explicit `public_bytes(Raw, Raw)` form rather than
    `public_bytes_raw()`, which only exists from cryptography 41. The explicit
    form has been available for far longer and produces identical bytes, so the
    agent keeps working against an older library than the one it pins.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
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

        SIG_INPUT = DS
                 || LP(policy_id)   || LP_U64(policy_version)
                 || LP(policy_type) || LP(scope.kind) || LP(scope.id)
                 || LP(issued_at)   || LP(expires_at or "")
                 || LP(key_id)      || LP(payload_bytes)

    The metadata is inside the signature, not merely alongside it. Signing the
    payload alone would let an attacker take a validly signed payload and replay
    it under a higher version, a different policy type, or another device's
    scope - which is precisely what the three negative vectors in
    testdata/policy_vectors.json are.
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
            # Empty string for null. See point 1 in the module docstring: do not
            # "fix" this to lp_opt_str without regenerating the vector and
            # changing the server in the same commit.
            lp_str(expires_at or ""),
            lp_str(key_id),
            lp(payload),
        )
    )


def _require(envelope: Mapping[str, Any], field: str) -> Any:
    try:
        return envelope[field]
    except (KeyError, TypeError) as exc:
        raise MalformedEnvelopeError(f"envelope is missing required field {field!r}") from exc


def verify_envelope(
    envelope: Mapping[str, Any],
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> bytes:
    """Verify an envelope and return the payload bytes. Does NOT parse them.

    `trusted_keys` maps `key_id` to public key and comes from the
    `policy_public_keys` the server returned at enrollment, pinned in local
    state. There is no fallback: a `key_id` outside this mapping raises
    `UnknownKeyIdError` rather than being looked up anywhere else, because
    fetching a key to validate a document is how a signature check becomes
    decoration.

    Order of operations matches the server's `verify_envelope`, and the order is
    itself a defence: everything cheap and bounded happens before any
    cryptography, so a hostile envelope costs little to refuse.
    """
    payload_b64 = _require(envelope, "payload_b64")
    signature_block = _require(envelope, "signature")
    scope = _require(envelope, "scope")

    if not isinstance(signature_block, Mapping):
        raise MalformedEnvelopeError("envelope signature must be an object")
    if not isinstance(scope, Mapping):
        raise MalformedEnvelopeError("envelope scope must be an object")

    key_id = _require(signature_block, "key_id")
    signature_b64 = _require(signature_block, "value_b64")

    algorithm = signature_block.get("alg")
    if algorithm != "ed25519":
        # Refused by name rather than ignored. An envelope naming another
        # algorithm is an algorithm-confusion attempt, and the schema pins
        # `alg` to a const for the same reason.
        raise MalformedEnvelopeError(f"unsupported signature algorithm: {algorithm!r}")

    if not isinstance(payload_b64, str) or not isinstance(signature_b64, str):
        raise MalformedEnvelopeError("payload_b64 and signature.value_b64 must be strings")

    # Bound the work before decoding, so an oversized envelope is cheap.
    if len(payload_b64) > _MAX_PAYLOAD_B64_CHARS:
        raise PayloadTooLargeError("payload_b64 is longer than the maximum payload permits")

    try:
        payload = base64.b64decode(payload_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedEnvelopeError(f"invalid base64 in envelope: {exc}") from exc

    if len(payload) > MAX_POLICY_PAYLOAD_BYTES:
        raise PayloadTooLargeError(
            f"payload of {len(payload)} bytes exceeds the {MAX_POLICY_PAYLOAD_BYTES} byte limit"
        )

    if len(signature) != _SIGNATURE_BYTES:
        raise MalformedEnvelopeError(
            f"an Ed25519 signature is {_SIGNATURE_BYTES} bytes, got {len(signature)}"
        )

    # Advisory check. Cheap, fails closed on a corrupted transfer, and carries
    # no authority: the signature below is the only thing that authenticates.
    if hashlib.sha256(payload).hexdigest() != envelope.get("payload_sha256"):
        raise PayloadHashMismatchError("payload_sha256 does not match the decoded payload")

    public_key = trusted_keys.get(key_id)
    if public_key is None:
        raise UnknownKeyIdError(f"key_id {key_id!r} is not in the trusted set")

    policy_version = _require(envelope, "policy_version")
    if isinstance(policy_version, bool) or not isinstance(policy_version, int):
        raise MalformedEnvelopeError("policy_version must be an integer")

    signing_input = build_signing_input(
        policy_id=_require(envelope, "policy_id"),
        policy_version=policy_version,
        policy_type=_require(envelope, "policy_type"),
        scope_kind=_require(scope, "kind"),
        scope_id=_require(scope, "id"),
        # As they arrived, never reformatted. See point 2 in the module
        # docstring.
        issued_at=_require(envelope, "issued_at"),
        expires_at=envelope.get("expires_at"),
        key_id=key_id,
        payload=payload,
    )

    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise SignatureVerificationError("Ed25519 signature verification failed") from exc

    return payload


def load_public_key_b64(public_key_b64: str) -> Ed25519PublicKey:
    """Build a public key from the base64 the enrollment response carries.

    Raises `MalformedEnvelopeError` rather than letting a cryptography error
    escape, so a malformed `policy_public_keys` entry from the server is handled
    on the same path as every other malformed server response.
    """
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedEnvelopeError(f"policy public key is not valid base64: {exc}") from exc
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise MalformedEnvelopeError(
            f"policy public key is not a valid Ed25519 key: {exc}"
        ) from exc
