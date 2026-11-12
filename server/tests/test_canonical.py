"""Tests for the length-prefixed encoding.

The first test is the reason this module exists at all.
"""

from __future__ import annotations

import pytest

from ubuntuguard.canonical import MAX_FIELD_BYTES, lp, lp_opt_str, lp_str, lp_u64


def test_length_prefixing_is_injective_where_concatenation_is_not() -> None:
    """The ("ab","c") vs ("a","bc") collision must not survive prefixing.

    Plain concatenation maps both field pairs to b"abc". An attacker who
    controls two adjacent signed fields could therefore move the boundary
    between them and keep the signature valid. Length prefixes are what stop
    that, so this is the single most important property in the module.
    """
    naive_left = b"ab" + b"c"
    naive_right = b"a" + b"bc"
    assert naive_left == naive_right, "precondition: plain concatenation collides"

    prefixed_left = lp(b"ab") + lp(b"c")
    prefixed_right = lp(b"a") + lp(b"bc")
    assert prefixed_left != prefixed_right


def test_prefix_is_eight_bytes_big_endian() -> None:
    assert lp(b"") == bytes(8)
    assert lp(b"A") == b"\x00\x00\x00\x00\x00\x00\x00\x01A"
    assert lp(b"A" * 258)[:8] == (258).to_bytes(8, "big")


def test_lp_str_encodes_utf8() -> None:
    assert lp_str("é") == lp("é".encode())
    # Two characters, three bytes: the prefix must count BYTES, not characters,
    # or a multi-byte string would desynchronise the decoder.
    assert lp_str("aé")[:8] == (3).to_bytes(8, "big")


def test_lp_u64_distinguishes_a_number_from_its_text() -> None:
    """Version 7 must not encode the same way as the string "7"."""
    assert lp_u64(7) != lp_str("7")
    assert lp_u64(7) == lp((7).to_bytes(8, "big"))


@pytest.mark.parametrize("bad", [-1, 2**64])
def test_lp_u64_rejects_out_of_range(bad: int) -> None:
    with pytest.raises(ValueError, match="unsigned|uint64"):
        lp_u64(bad)


def test_lp_opt_str_keeps_none_distinct_from_empty_string() -> None:
    """None and "" must not hash identically.

    Otherwise an audit row with no actor is indistinguishable from one whose
    actor id happens to be the empty string.
    """
    assert lp_opt_str(None) != lp_opt_str("")
    assert lp_opt_str(None) == lp(b"")
    assert lp_opt_str("") == lp(b"\x01")
    assert lp_opt_str("x") == lp(b"\x01x")


def test_lp_rejects_absurdly_large_fields() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        lp(b"\x00" * (MAX_FIELD_BYTES + 1))
