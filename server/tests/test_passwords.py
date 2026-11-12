"""Argon2id password hashing tests."""

from __future__ import annotations

import time

import pytest
from argon2 import PasswordHasher, Type

from ubuntuguard.constants import (
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
)
from ubuntuguard.security.passwords import (
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    needs_rehash,
    validate_password,
    verify_dummy,
    verify_password,
)

GOOD_PASSWORD = "correct horse battery staple"


def test_hash_is_argon2id_with_the_configured_parameters() -> None:
    """The PHC string records the algorithm and parameters, so assert on them.

    The brief mandates Argon2id specifically, not Argon2i or Argon2d.
    """
    encoded = hash_password(GOOD_PASSWORD)
    assert encoded.startswith("$argon2id$")
    assert f"m={ARGON2_MEMORY_COST_KIB}" in encoded
    assert f"t={ARGON2_TIME_COST}" in encoded
    assert f"p={ARGON2_PARALLELISM}" in encoded


def test_hash_does_not_contain_the_password() -> None:
    assert GOOD_PASSWORD not in hash_password(GOOD_PASSWORD)


def test_verify_accepts_the_right_password_and_rejects_others() -> None:
    encoded = hash_password(GOOD_PASSWORD)
    assert verify_password(encoded, GOOD_PASSWORD) is True
    assert verify_password(encoded, GOOD_PASSWORD + "!") is False
    assert verify_password(encoded, "") is False


def test_same_password_hashes_differently_each_time() -> None:
    """Distinct random salts, so identical passwords are not detectable.

    Without this, the hash column would reveal which admins share a password.
    """
    assert hash_password(GOOD_PASSWORD) != hash_password(GOOD_PASSWORD)


def test_verify_returns_false_for_a_malformed_stored_hash() -> None:
    """A corrupt row must not raise and produce a distinguishable 500."""
    assert verify_password("not-a-phc-string", GOOD_PASSWORD) is False
    assert verify_password("", GOOD_PASSWORD) is False


def test_over_long_password_is_rejected_before_hashing() -> None:
    """The DoS bound has to hold on the login path, not just on registration.

    Argon2 hashes whatever it is handed, so an unbounded password field turns
    one unauthenticated request into unbounded server work.
    """
    encoded = hash_password(GOOD_PASSWORD)
    huge = "a" * (MAX_PASSWORD_BYTES + 1)

    started = time.perf_counter()
    assert verify_password(encoded, huge) is False
    elapsed = time.perf_counter() - started

    # Rejected on length, so it must not have paid for a hash at all.
    assert elapsed < 0.005, f"over-long password appears to have been hashed ({elapsed:.4f}s)"


@pytest.mark.parametrize(
    "bad",
    [
        "short",
        "a" * (MIN_PASSWORD_LENGTH - 1),
        " " * (MIN_PASSWORD_LENGTH + 2),
        "a" * (MAX_PASSWORD_BYTES + 1),
    ],
)
def test_validate_password_rejects_bad_passwords(bad: str) -> None:
    with pytest.raises(PasswordPolicyError):
        validate_password(bad)


def test_validate_password_accepts_a_long_passphrase() -> None:
    validate_password("a reasonably long passphrase")


def test_verify_dummy_spends_real_time_and_always_fails() -> None:
    """Equalises timing when the account does not exist.

    Without this, a missing account answers in microseconds while a wrong
    password takes tens of milliseconds, and that difference is a reliable
    account-enumeration oracle regardless of how carefully the error bodies are
    worded.
    """
    started = time.perf_counter()
    assert verify_dummy() is False
    elapsed = time.perf_counter() - started
    assert elapsed > 0.005, f"verify_dummy returned too fast to be hashing ({elapsed:.4f}s)"


def test_dummy_verification_time_is_comparable_to_a_real_failure() -> None:
    """Loose bound only. A tight assertion here would be flaky on shared CPU.

    Within a factor of five is enough to show the two paths are in the same
    order of magnitude rather than microseconds versus milliseconds.
    """
    encoded = hash_password(GOOD_PASSWORD)

    started = time.perf_counter()
    verify_password(encoded, "definitely wrong")
    real = time.perf_counter() - started

    started = time.perf_counter()
    verify_dummy()
    dummy = time.perf_counter() - started

    ratio = max(real, dummy) / max(min(real, dummy), 1e-9)
    assert ratio < 5.0, f"timing gap too wide: real={real:.4f}s dummy={dummy:.4f}s"


def test_needs_rehash_detects_weaker_parameters() -> None:
    """Lets Argon2 parameters be raised later without a forced password reset."""
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1, type=Type.ID)
    old_hash = weak.hash(GOOD_PASSWORD)
    assert needs_rehash(old_hash) is True
    assert needs_rehash(hash_password(GOOD_PASSWORD)) is False


def test_needs_rehash_treats_garbage_as_needing_rehash() -> None:
    assert needs_rehash("garbage") is True
