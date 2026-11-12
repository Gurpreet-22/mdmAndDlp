"""Argon2id password hashing for admin accounts.

Only admin passwords go through this. Device identity is a client certificate and
session tokens are high-entropy random values, both of which need something
different - see `tokens.py` for why a fast hash is correct there.
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from ubuntuguard.constants import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LENGTH,
    ARGON2_TIME_COST,
)

#: Minimum admin password length. Length beats composition rules, which mostly
#: produce "Password1!" and a sticky note.
MIN_PASSWORD_LENGTH = 12

#: Upper bound, and it is a real control rather than tidiness: Argon2 hashes
#: whatever it is given, so an unbounded password field lets anyone turn one
#: login request into hundreds of megabytes of hashing work.
MAX_PASSWORD_BYTES = 1024

_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LENGTH,
    salt_len=ARGON2_SALT_LENGTH,
    type=Type.ID,  # Argon2id, explicitly - not Argon2i or Argon2d
)

#: A real hash of a value nobody knows, used to spend the same CPU time when the
#: account does not exist. See `verify_dummy`.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


class PasswordPolicyError(ValueError):
    """Raised when a proposed password is unusable. Never raised on login."""


def validate_password(password: str) -> None:
    """Check a NEW password against policy. Raises `PasswordPolicyError`.

    Only for setting or changing a password. Login never calls this: telling a
    caller that their input failed policy would reveal that the stored password
    does not look like that, and would turn login into a policy oracle.
    """
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.strip() == "":
        raise PasswordPolicyError("password must not be only whitespace")


def hash_password(password: str) -> str:
    """Hash a new password. Returns the PHC string, which embeds the parameters."""
    validate_password(password)
    return _hasher.hash(password)


def unusable_password_hash() -> str:
    """A real Argon2id hash of a random value that is immediately discarded.

    For accounts that have no password: the no-authentication placeholder now,
    and Microsoft SSO later, where the credential lives in Entra ID and never
    here.

    The point is what happens when the bypass is switched OFF. Storing a hash of
    a known or empty string would leave every auto-created account reachable
    with a guessable password the moment real authentication is enabled. Hashing
    32 random bytes nobody kept means `verify_password` can only ever return
    False, so these accounts become unreachable rather than open.
    """
    return _hasher.hash(secrets.token_urlsafe(32))


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password. Returns False for every failure mode, never raises.

    An over-long input is rejected before hashing, so the DoS bound in
    `MAX_PASSWORD_BYTES` holds on the login path too. A malformed stored hash
    also returns False: that is a data-integrity problem for the operator to
    find in the logs, not a reason to hand the caller a 500 that distinguishes
    this account from any other.
    """
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_dummy() -> bool:
    """Burn the same CPU time as a real verification. Always returns False.

    Call this when the account does not exist. Without it, a missing account
    answers in microseconds while a wrong password takes ~50 ms, and that gap
    is a reliable account-enumeration oracle no matter how carefully the error
    messages are worded.
    """
    try:
        return _hasher.verify(_DUMMY_HASH, "not the dummy password")
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Whether a stored hash used weaker parameters than the current settings.

    Call after a SUCCESSFUL verification - that is the only moment the plaintext
    is available to re-hash with. Lets Argon2 parameters be raised over time
    without a forced password reset.
    """
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, VerificationError):
        # Unparseable means it certainly does not match current parameters.
        return True
