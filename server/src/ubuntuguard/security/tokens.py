"""Opaque bearer and enrollment tokens.

Why SHA-256 here and Argon2id for passwords
-------------------------------------------
A password is low-entropy and guessable, so it needs a deliberately slow KDF to
make guessing expensive. These tokens are 32 bytes from the OS CSPRNG - 256 bits
with no structure to guess. There is nothing for an attacker to brute force, so a
slow hash would buy no security while adding ~50 ms to every authenticated
request. SHA-256 over a 256-bit random value is the right tool.

Why opaque tokens and not JWT
-----------------------------
Revocation. A signed JWT is valid until it expires, so "revoke this admin now"
becomes "revoke them in up to 15 minutes" unless a denylist is bolted on - at
which point the stateless advantage is gone and the lookup is back. Opaque
tokens are revoked by deleting a row. It also removes signing-key management and
the entire algorithm-confusion bug class. At 10-50 devices the lookup cost is
irrelevant.

Only the HASH is ever stored. A stolen database backup yields no usable token.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import NamedTuple

from ubuntuguard.constants import ENROLLMENT_TOKEN_BYTES, SESSION_TOKEN_BYTES


class IssuedToken(NamedTuple):
    """A freshly minted token.

    `plaintext` is returned to the caller exactly once and never persisted.
    `token_hash` is what goes in the database.
    """

    plaintext: str
    token_hash: str

    def __repr__(self) -> str:
        # Keeps the plaintext out of tracebacks, logs and debugger output. A
        # token that reaches a log file has to be treated as compromised.
        return f"IssuedToken(plaintext=<redacted>, token_hash={self.token_hash[:8]}...)"


def _encode(raw: bytes) -> str:
    """URL-safe base64 without padding: safe in headers, URLs and JSON alike."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def hash_token(plaintext: str) -> str:
    """Hash a token for storage or lookup. Lowercase hex SHA-256."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def generate_session_token() -> IssuedToken:
    """Mint an access or refresh token."""
    raw = secrets.token_bytes(SESSION_TOKEN_BYTES)
    plaintext = _encode(raw)
    return IssuedToken(plaintext=plaintext, token_hash=hash_token(plaintext))


def generate_enrollment_token() -> IssuedToken:
    """Mint a one-time enrollment token (32 random bytes, stored hashed)."""
    raw = secrets.token_bytes(ENROLLMENT_TOKEN_BYTES)
    plaintext = _encode(raw)
    return IssuedToken(plaintext=plaintext, token_hash=hash_token(plaintext))


def fingerprint_public_key(public_key_der: bytes) -> str:
    """`sha256:<hex>` fingerprint of a DER-encoded public key.

    Used to bind an enrollment retry to the same keypair, and to pin a device's
    certificate to the identity it enrolled with.
    """
    return "sha256:" + hashlib.sha256(public_key_der).hexdigest()
