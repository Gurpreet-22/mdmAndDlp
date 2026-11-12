"""Opaque token tests."""

from __future__ import annotations

import base64
import hashlib

from ubuntuguard.constants import ENROLLMENT_TOKEN_BYTES, SESSION_TOKEN_BYTES
from ubuntuguard.security.tokens import (
    fingerprint_public_key,
    generate_enrollment_token,
    generate_session_token,
    hash_token,
)


def _decoded_length(plaintext: str) -> int:
    padding = "=" * (-len(plaintext) % 4)
    return len(base64.urlsafe_b64decode(plaintext + padding))


def test_session_token_carries_256_bits_of_entropy() -> None:
    token = generate_session_token()
    assert _decoded_length(token.plaintext) == SESSION_TOKEN_BYTES == 32


def test_enrollment_token_is_32_random_bytes() -> None:
    """The brief specifies 32 random bytes for enrollment tokens."""
    token = generate_enrollment_token()
    assert _decoded_length(token.plaintext) == ENROLLMENT_TOKEN_BYTES == 32


def test_token_is_url_safe_and_unpadded() -> None:
    plaintext = generate_session_token().plaintext
    assert "=" not in plaintext
    assert "+" not in plaintext
    assert "/" not in plaintext


def test_tokens_are_unique_across_many_draws() -> None:
    """A collision here would mean the CSPRNG is not being used correctly."""
    seen = {generate_session_token().plaintext for _ in range(1000)}
    assert len(seen) == 1000


def test_stored_hash_matches_sha256_of_the_plaintext() -> None:
    token = generate_session_token()
    assert token.token_hash == hashlib.sha256(token.plaintext.encode()).hexdigest()
    assert len(token.token_hash) == 64


def test_plaintext_is_never_equal_to_the_stored_hash() -> None:
    """Guards against a refactor that accidentally stores the token itself."""
    token = generate_session_token()
    assert token.plaintext != token.token_hash


def test_repr_redacts_the_plaintext() -> None:
    """A token in a traceback or log line has to be treated as compromised, so
    the container refuses to print it.
    """
    token = generate_session_token()
    rendered = repr(token)
    assert token.plaintext not in rendered
    assert "<redacted>" in rendered


def test_hash_token_is_stable() -> None:
    assert hash_token("abc") == hash_token("abc")
    assert hash_token("abc") != hash_token("abd")


def test_public_key_fingerprint_format() -> None:
    fingerprint = fingerprint_public_key(b"some-der-bytes")
    assert fingerprint.startswith("sha256:")
    assert len(fingerprint) == len("sha256:") + 64
    assert fingerprint == "sha256:" + hashlib.sha256(b"some-der-bytes").hexdigest()


def test_public_key_fingerprint_differs_per_key() -> None:
    assert fingerprint_public_key(b"key-a") != fingerprint_public_key(b"key-b")
