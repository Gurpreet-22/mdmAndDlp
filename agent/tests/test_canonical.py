"""The length-prefix encoding, asserted against exact bytes.

These tests spell out the expected byte strings rather than comparing the
implementation against itself. That is the only form of this test worth having:
checking `lp(x)` against a reimplementation of `lp` would pass just as happily
if both were wrong, and the entire point of the encoding is that it matches a
specification the server also implements.
"""

from __future__ import annotations

import pytest

from ubuntuguard_agent.core.canonical import (
    LENGTH_PREFIX_BYTES,
    MAX_FIELD_BYTES,
    lp,
    lp_opt_str,
    lp_str,
    lp_u64,
)


def test_prefix_is_eight_bytes_big_endian() -> None:
    assert LENGTH_PREFIX_BYTES == 8
    assert lp(b"abc") == b"\x00\x00\x00\x00\x00\x00\x00\x03abc"


def test_empty_field_is_a_bare_prefix() -> None:
    assert lp(b"") == b"\x00" * 8


def test_lp_str_encodes_utf8_byte_length_not_character_count() -> None:
    """A multi-byte character must contribute its byte length.

    Prefixing the character count instead would make the agent and the server
    disagree the first time a hostname or a label contained a non-ASCII
    character, and only for those documents - the worst kind of bug to find.
    """
    assert lp_str("é") == b"\x00\x00\x00\x00\x00\x00\x00\x02" + "é".encode()


def test_encoding_is_injective() -> None:
    """The property the whole scheme exists for.

    Plain concatenation maps ("ab", "c") and ("a", "bc") to the same bytes, so
    an attacker controlling two adjacent fields can move the boundary and keep a
    signature valid. Length prefixes make those two inputs distinct.
    """
    assert lp_str("ab") + lp_str("c") != lp_str("a") + lp_str("bc")


def test_lp_u64_is_distinct_from_the_string_form() -> None:
    """Version 7 must not encode like the string "7".

    The integer becomes 8 fixed bytes and is then length-prefixed, so a
    `policy_version` cannot be confused with a textual field. Conflating them is
    how a version number becomes forgeable.
    """
    assert lp_u64(7) == b"\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x07"
    assert lp_u64(7) != lp_str("7")


def test_lp_u64_always_occupies_eight_value_bytes() -> None:
    assert len(lp_u64(0)) == 16
    assert len(lp_u64(2**64 - 1)) == 16


@pytest.mark.parametrize("value", [-1, 2**64])
def test_lp_u64_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValueError):
        lp_u64(value)


def test_oversized_field_is_refused() -> None:
    """A bound on parser work, not a theoretical limit.

    Faithfully encoding a 2^64 length just because the format permits it would
    make a hostile document into an allocation of that size.
    """
    with pytest.raises(ValueError):
        lp(b"x" * (MAX_FIELD_BYTES + 1))


def test_lp_opt_str_keeps_none_distinct_from_empty() -> None:
    """Present for parity with the server, and NOT used by the envelope.

    The policy envelope encodes a null `expires_at` as the empty string. This
    function's behaviour is asserted so that the difference between the two is
    documented in the suite rather than only in a comment - reaching for this
    in `build_signing_input` would silently produce a different signing input.
    """
    assert lp_opt_str(None) != lp_opt_str("")
    assert lp_opt_str(None) == lp(b"")
    assert lp_opt_str("a") == lp(b"\x01a")
