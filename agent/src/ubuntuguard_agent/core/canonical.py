"""Unambiguous byte encoding for anything hashed or signed.

A byte-for-byte port of `server/src/ubuntuguard/canonical.py`. The server's
module header explains why the encoding exists, and it applies verbatim here:
plain concatenation is not injective, so the field pairs ("ab", "c") and
("a", "bc") produce the identical byte string. An attacker who controls two
adjacent fields can move the boundary and keep the signature valid, which is a
forgery primitive rather than a style question. Length-prefixing removes the
ambiguity.

This file and the server's must agree exactly. `testdata/policy_vectors.json`
is how we find out if they do not: `tests/test_envelope_conformance.py` rebuilds
the committed signing input and checks both its length and its SHA-256 before
it checks any signature, so an encoding bug here is reported as an encoding bug
rather than as a mysterious verification failure.
"""

from __future__ import annotations

#: Width of the length prefix. 8 bytes big-endian, matching the server and the
#: `length_prefix` field of the committed vector ("uint64 big-endian length ||
#: bytes").
LENGTH_PREFIX_BYTES = 8

#: Longest field we will length-prefix. Values this large mean a bug or an
#: attempt to exhaust memory.
MAX_FIELD_BYTES = 16 * 1024 * 1024


def lp(value: bytes) -> bytes:
    """Length-prefix a byte string: uint64 big-endian length, then the bytes."""
    if len(value) > MAX_FIELD_BYTES:
        raise ValueError(f"field of {len(value)} bytes exceeds the {MAX_FIELD_BYTES} byte limit")
    return len(value).to_bytes(LENGTH_PREFIX_BYTES, "big") + value


def lp_str(value: str) -> bytes:
    """Length-prefix a string as UTF-8."""
    return lp(value.encode("utf-8"))


def lp_opt_str(value: str | None) -> bytes:
    """Length-prefix an optional string, keeping None distinct from "".

    Present for parity with the server module, and **not** used by the policy
    envelope. See `core/envelope.build_signing_input` for why: the envelope
    encodes a null `expires_at` as the empty string, which is what the committed
    vector implements. Reaching for this function there would silently produce a
    different signing input and fail every verification.
    """
    if value is None:
        return lp(b"")
    return lp(b"\x01" + value.encode("utf-8"))


def lp_u64(value: int) -> bytes:
    """Length-prefix an unsigned 64-bit integer, encoded big-endian.

    The integer becomes 8 fixed bytes and is THEN length-prefixed, so the
    encoding of 7 differs from the encoding of the string "7". Mixing those up
    is how a version number becomes forgeable.
    """
    if value < 0:
        raise ValueError(f"expected an unsigned integer, got {value}")
    if value > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"value {value} does not fit in a uint64")
    return lp(value.to_bytes(8, "big"))
