"""Login lockout decision logic.

Deliberately a pure function over timestamps, with no database and no clock of
its own. Lockout is easy to get wrong at the boundaries - off-by-one on the
failure count, a window that never expires, a naive datetime compared against an
aware one - and all of those are cheap to test only if the decision is separable
from storage.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ubuntuguard.constants import (
    LOGIN_FAILURE_WINDOW_SECONDS,
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_MAX_FAILURES,
)


@dataclass(frozen=True, slots=True)
class LockoutDecision:
    """Outcome of evaluating an account's recent failures."""

    locked: bool
    failures_in_window: int
    retry_after_seconds: int | None

    def __post_init__(self) -> None:
        if self.locked and self.retry_after_seconds is None:
            raise ValueError("a locked decision must carry retry_after_seconds")


def _require_aware(moment: datetime, label: str) -> datetime:
    """Reject naive datetimes.

    A naive datetime compared against an aware one raises in Python, and worse,
    two naive datetimes from different sources compare silently and wrongly. The
    cheapest fix is to refuse them at the boundary.
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{label} must be timezone-aware")
    return moment.astimezone(UTC)


def evaluate(
    *,
    recent_failures: Sequence[datetime],
    now: datetime,
    locked_until: datetime | None = None,
    max_failures: int = LOGIN_MAX_FAILURES,
    window_seconds: int = LOGIN_FAILURE_WINDOW_SECONDS,
    lockout_seconds: int = LOGIN_LOCKOUT_SECONDS,
) -> LockoutDecision:
    """Decide whether a login attempt should be refused before checking the password.

    `recent_failures` may contain timestamps older than the window; they are
    filtered here so the caller can hand over whatever it has stored.

    An existing `locked_until` in the future wins outright. Otherwise a failure
    count at or above `max_failures` inside the window locks the account.
    """
    now = _require_aware(now, "now")
    if max_failures < 1:
        raise ValueError("max_failures must be at least 1")

    if locked_until is not None:
        locked_until = _require_aware(locked_until, "locked_until")
        if locked_until > now:
            remaining = int((locked_until - now).total_seconds())
            # A sub-second remainder truncates to 0, which would advertise "retry
            # now" while the account is still locked. Floor it at 1.
            return LockoutDecision(
                locked=True,
                failures_in_window=len(recent_failures),
                retry_after_seconds=max(1, remaining),
            )

    window_start = now - timedelta(seconds=window_seconds)
    # Inclusive lower bound: a failure exactly at the window edge still counts.
    in_window = sum(1 for at in recent_failures if _require_aware(at, "failure") >= window_start)

    if in_window >= max_failures:
        return LockoutDecision(
            locked=True, failures_in_window=in_window, retry_after_seconds=lockout_seconds
        )
    return LockoutDecision(locked=False, failures_in_window=in_window, retry_after_seconds=None)


def lock_until(now: datetime, lockout_seconds: int = LOGIN_LOCKOUT_SECONDS) -> datetime:
    """The timestamp to store when locking an account."""
    return _require_aware(now, "now") + timedelta(seconds=lockout_seconds)
