"""Unambiguous byte encoding for anything that gets hashed or signed.

Both the policy envelope signature and the audit hash chain build their input by
concatenating several fields. Plain concatenation is not injective: the field
pairs ("ab", "c") and ("a", "bc") produce the identical byte string, so an
attacker who controls two adjacent fields can move a boundary and keep the
signature or chain hash valid. That is a forgery primitive, not a style issue.

Length-prefixing every field removes the ambiguity. These three helpers are the
single implementation, shared so the two call sites cannot drift apart, and the
Go agent must reproduce them byte for byte - testdata/policy_vectors.json is how
we find out if it does not.
"""

from __future__ import annotations

#: Width of the length prefix. 8 bytes big-endian, matching the Go agent's
#: binary.BigEndian.PutUint64 and the spec in docs/02-policy-and-signing.md.
LENGTH_PREFIX_BYTES = 8

#: Longest field we will length-prefix. Values this large mean a bug or an
#: attempt to exhaust memory, and 2^64 lengths are not something to encode
#: faithfully just because the format allows it.
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

    Encoding None as an empty field would make a missing actor hash identically
    to an actor whose id is the empty string. The presence byte keeps the two
    apart: None becomes a zero-length field, and a present value becomes
    0x01 followed by its UTF-8 bytes.
    """
    if value is None:
        return lp(b"")
    return lp(b"\x01" + value.encode("utf-8"))


def lp_u64(value: int) -> bytes:
    """Length-prefix an unsigned 64-bit integer, encoded big-endian.

    The integer is encoded as 8 fixed bytes and THEN length-prefixed, so the
    encoding of 7 is distinct from the encoding of the string "7". Mixing those
    up is how a version number becomes forgeable.
    """
    if value < 0:
        raise ValueError(f"expected an unsigned integer, got {value}")
    if value > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"value {value} does not fit in a uint64")
    return lp(value.to_bytes(8, "big"))
