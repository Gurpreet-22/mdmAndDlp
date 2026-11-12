"""Server-side online/offline computation.

Liveness is computed by the server from the last heartbeat it actually received,
never self-reported by the agent. A device that claims to be healthy is making a
claim; a heartbeat timestamp is evidence.

Pure functions, so the boundary cases are cheap to test - and the boundary is
where this matters, because "offline" drives alerting and a threshold that is
one beat out produces either false alarms or a fleet that looks fine while it
is not reporting.
"""

from __future__ import annotations

import datetime as dt

from ubuntuguard.constants import (
    HEARTBEAT_SECONDS,
    OFFLINE_GRACE_SECONDS,
    OFFLINE_MISSED_BEATS,
)


def offline_threshold_seconds(heartbeat_seconds: int = HEARTBEAT_SECONDS.default) -> int:
    """How long silence is tolerated before a device counts as offline.

    Three missed beats plus a 60 second grace period. The grace absorbs jitter
    and a slow network without widening the window by a whole interval; at the
    60 second default this is 240 seconds.
    """
    return OFFLINE_MISSED_BEATS * heartbeat_seconds + OFFLINE_GRACE_SECONDS


def is_online(
    last_heartbeat_at: dt.datetime | None,
    *,
    now: dt.datetime | None = None,
    heartbeat_seconds: int = HEARTBEAT_SECONDS.default,
) -> bool:
    """Whether a device counts as online.

    A device that has never checked in is offline, not unknown: treating silence
    as "probably fine" is how an unenrolled or broken agent stays invisible.
    """
    if last_heartbeat_at is None:
        return False
    now = now or dt.datetime.now(dt.UTC)
    if last_heartbeat_at.tzinfo is None:
        raise ValueError("last_heartbeat_at must be timezone-aware")
    elapsed = (now - last_heartbeat_at).total_seconds()
    # A timestamp in the future means a skewed agent clock. It still counts as
    # online, because we did receive the beat; the skew is reported separately
    # rather than being punished here.
    return elapsed <= offline_threshold_seconds(heartbeat_seconds)
