"""Timing primitives: jitter, backoff and clock-jump detection.

Pure logic with injected clocks and an injected random source, so every
behaviour below is asserted rather than observed. The alternative - sleeping in
a test and timing it - is slow and flaky, and the properties that matter here
are exactly the ones a timing test is bad at showing: that a delay never
collapses to zero, and that a ceiling actually holds.

Three things live here, each addressing a specific requirement.

Jitter spreads a fleet out. Fifty laptops that all enrolled from the same image
would otherwise heartbeat in lockstep, which turns a routine interval into a
thundering herd against one FastAPI process.

Backoff keeps a server outage from becoming a self-inflicted denial of service,
and is where "avoid excessive requests to the server" is actually implemented.

Clock-jump detection exists because a laptop's wall clock is not trustworthy:
it suspends, it resumes, it gets corrected by NTP, and a user can set it
deliberately (threat T16). Scheduling therefore runs on the monotonic clock,
and the wall clock is only ever compared against it to notice that it moved.
"""

from __future__ import annotations

import dataclasses
import random
import time
from collections.abc import Callable

try:  # pragma: no cover - the fallback is exercised only on Python 3.7
    from typing import Protocol
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol  # type: ignore[assignment]

from ubuntuguard_agent.constants import CLOCK_JUMP_THRESHOLD_SECONDS

#: A source of monotonic time, injectable for tests.
MonotonicClock = Callable[[], float]

#: A source of wall-clock time in epoch seconds, injectable for tests.
WallClock = Callable[[], float]


class RandomSource(Protocol):
    """Just the one method these primitives need.

    A Protocol rather than `random.Random`, so a test double does not have to
    subclass it. Subclassing is a real trap here: `random.Random.__new__`
    forwards its argument to the C seeder, so a double whose constructor takes
    anything unhashable fails before its body runs. The `random` module itself
    satisfies this, which is what makes it usable as the default.
    """

    def uniform(self, a: float, b: float) -> float: ...


def jittered_interval(
    base_seconds: float,
    jitter_pct: int,
    *,
    rng: RandomSource | None = None,
) -> float:
    """Spread `base_seconds` by +/- `jitter_pct`, never below zero.

    Symmetric around the base so the long-run average interval is still the
    base. An asymmetric spread would quietly change the effective heartbeat
    rate away from what the policy asked for.
    """
    if base_seconds < 0:
        raise ValueError(f"base_seconds must not be negative, got {base_seconds}")
    if not 0 <= jitter_pct <= 100:
        raise ValueError(f"jitter_pct must be between 0 and 100, got {jitter_pct}")
    if jitter_pct == 0:
        return float(base_seconds)

    generator = rng if rng is not None else random
    spread = base_seconds * (jitter_pct / 100.0)
    return max(0.0, generator.uniform(base_seconds - spread, base_seconds + spread))


class Backoff:
    """Exponential backoff with jitter and a floor, bounded by a ceiling.

    The delay for attempt n is drawn uniformly from

        [initial, min(maximum, initial * 2**n)]

    Textbook "full jitter" draws from [0, ceiling] instead. The floor at
    `initial` is a deliberate change: drawing from zero lets a run of unlucky
    draws produce a burst of near-immediate retries, which is the hot loop this
    class exists to prevent. Keeping the floor costs a little decorrelation and
    guarantees a minimum spacing between attempts.

    At attempt 0 the range collapses to exactly `initial`, so the first retry is
    predictable, which is what you want when reading a log.
    """

    def __init__(
        self,
        initial_seconds: float,
        max_seconds: float,
        *,
        rng: RandomSource | None = None,
    ) -> None:
        if initial_seconds <= 0:
            raise ValueError(f"initial_seconds must be positive, got {initial_seconds}")
        if max_seconds < initial_seconds:
            raise ValueError(
                f"max_seconds ({max_seconds}) must not be below initial_seconds ({initial_seconds})"
            )
        self._initial = float(initial_seconds)
        self._max = float(max_seconds)
        self._rng = rng if rng is not None else random
        self._attempt = 0

    @property
    def attempt(self) -> int:
        """How many delays have been handed out since the last reset."""
        return self._attempt

    def ceiling(self) -> float:
        """The upper end of the range the next delay will be drawn from."""
        # Capped exponent before the shift: 2**1000 is an arithmetic answer to
        # a question nobody asked, and min() would discard it anyway.
        exponent = min(self._attempt, 32)
        return min(self._max, self._initial * float(2**exponent))

    def next_delay(self) -> float:
        """Draw the next delay and advance the attempt counter."""
        delay = self._rng.uniform(self._initial, self.ceiling())
        self._attempt += 1
        return delay

    def peek(self) -> float:
        """The ceiling that `next_delay` would use, without advancing."""
        return self.ceiling()

    def reset(self) -> None:
        """Back to attempt zero. Called after a success."""
        self._attempt = 0


@dataclasses.dataclass(frozen=True)
class ClockJump:
    """A detected disagreement between the wall clock and elapsed real time."""

    wall_delta_seconds: float
    monotonic_delta_seconds: float

    @property
    def drift_seconds(self) -> float:
        """How far the wall clock moved beyond what actually elapsed."""
        return self.wall_delta_seconds - self.monotonic_delta_seconds

    @property
    def direction(self) -> str:
        return "forward" if self.drift_seconds > 0 else "backward"


class ClockWatch:
    """Notices the wall clock stepping relative to the monotonic clock.

    Sampled from the service loop. A suspend/resume cycle, an NTP correction or
    a user setting the date all show up as the two clocks disagreeing about how
    much time passed. The agent reports that as `clock_jump_detected` rather
    than silently rescheduling, because a device whose clock moved is a device
    whose timestamps need explaining.
    """

    def __init__(
        self,
        *,
        monotonic: MonotonicClock | None = None,
        wall: WallClock | None = None,
        threshold_seconds: float = CLOCK_JUMP_THRESHOLD_SECONDS,
    ) -> None:
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._wall = wall if wall is not None else time.time
        self._threshold = threshold_seconds
        self._last_monotonic = self._monotonic()
        self._last_wall = self._wall()

    def sample(self) -> ClockJump | None:
        """Take a reading. Returns a `ClockJump` when the threshold is crossed."""
        now_monotonic = self._monotonic()
        now_wall = self._wall()

        monotonic_delta = now_monotonic - self._last_monotonic
        wall_delta = now_wall - self._last_wall

        self._last_monotonic = now_monotonic
        self._last_wall = now_wall

        if abs(wall_delta - monotonic_delta) > self._threshold:
            return ClockJump(
                wall_delta_seconds=wall_delta,
                monotonic_delta_seconds=monotonic_delta,
            )
        return None
