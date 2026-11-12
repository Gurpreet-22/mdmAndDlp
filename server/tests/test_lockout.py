"""Login lockout boundary tests.

The brief says "lockout after 5 failures in 10 min". Both numbers are boundaries,
and boundaries are where this kind of logic goes wrong, so each is tested from
both sides.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ubuntuguard.constants import (
    LOGIN_FAILURE_WINDOW_SECONDS,
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_MAX_FAILURES,
)
from ubuntuguard.security.lockout import LockoutDecision, evaluate, lock_until

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)


def failures(count: int, *, seconds_ago: int = 10) -> list[datetime]:
    return [NOW - timedelta(seconds=seconds_ago) for _ in range(count)]


def test_brief_constants_are_as_specified() -> None:
    assert LOGIN_MAX_FAILURES == 5
    assert LOGIN_FAILURE_WINDOW_SECONDS == 600


def test_four_failures_does_not_lock() -> None:
    decision = evaluate(recent_failures=failures(4), now=NOW)
    assert decision == LockoutDecision(locked=False, failures_in_window=4, retry_after_seconds=None)


def test_fifth_failure_locks() -> None:
    decision = evaluate(recent_failures=failures(5), now=NOW)
    assert decision.locked is True
    assert decision.failures_in_window == 5
    assert decision.retry_after_seconds == LOGIN_LOCKOUT_SECONDS


def test_failures_older_than_the_window_are_ignored() -> None:
    """Otherwise the window never expires and five typos lock an account forever."""
    old = failures(5, seconds_ago=LOGIN_FAILURE_WINDOW_SECONDS + 1)
    decision = evaluate(recent_failures=old, now=NOW)
    assert decision.locked is False
    assert decision.failures_in_window == 0


def test_failure_exactly_at_the_window_edge_still_counts() -> None:
    """Inclusive lower bound, asserted so the choice is deliberate."""
    edge = failures(5, seconds_ago=LOGIN_FAILURE_WINDOW_SECONDS)
    decision = evaluate(recent_failures=edge, now=NOW)
    assert decision.locked is True
    assert decision.failures_in_window == 5


def test_one_second_past_the_window_does_not_count() -> None:
    mixed = failures(4) + failures(1, seconds_ago=LOGIN_FAILURE_WINDOW_SECONDS + 1)
    decision = evaluate(recent_failures=mixed, now=NOW)
    assert decision.locked is False
    assert decision.failures_in_window == 4


def test_an_active_lock_wins_regardless_of_failure_count() -> None:
    decision = evaluate(
        recent_failures=[],
        now=NOW,
        locked_until=NOW + timedelta(seconds=120),
    )
    assert decision.locked is True
    assert decision.retry_after_seconds == 120


def test_an_expired_lock_is_ignored() -> None:
    decision = evaluate(
        recent_failures=failures(1),
        now=NOW,
        locked_until=NOW - timedelta(seconds=1),
    )
    assert decision.locked is False


def test_retry_after_never_advertises_zero_seconds() -> None:
    """A sub-second remainder truncates to 0, which would say "retry now" while
    the account is still locked.
    """
    decision = evaluate(
        recent_failures=[],
        now=NOW,
        locked_until=NOW + timedelta(milliseconds=400),
    )
    assert decision.locked is True
    assert decision.retry_after_seconds == 1


def test_lock_until_adds_the_lockout_period() -> None:
    assert lock_until(NOW) == NOW + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)


def test_naive_datetimes_are_rejected() -> None:
    """Two naive datetimes from different sources compare silently and wrongly,
    so they are refused at the boundary rather than trusted.
    """
    naive = datetime(2026, 10, 29, 12, 0, 0)  # noqa: DTZ001 - deliberately naive
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate(recent_failures=[], now=naive)
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate(recent_failures=[naive], now=NOW)
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate(recent_failures=[], now=NOW, locked_until=naive)


def test_non_utc_timezones_are_handled() -> None:
    """A caller in another zone must not get a different answer."""
    tz = __import__("datetime").timezone(timedelta(hours=5, minutes=30))
    now_ist = NOW.astimezone(tz)
    decision = evaluate(recent_failures=failures(5), now=now_ist)
    assert decision.locked is True


def test_max_failures_must_be_sane() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        evaluate(recent_failures=[], now=NOW, max_failures=0)
