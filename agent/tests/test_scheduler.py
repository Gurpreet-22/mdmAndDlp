"""Jitter, backoff and clock-jump detection.

Every clock and the random source are injected, so these tests assert
properties rather than timing them. That is not only about speed: the two
properties that matter most here - that a delay never collapses towards zero,
and that the ceiling actually holds - are exactly the ones a wall-clock test is
bad at demonstrating.
"""

from __future__ import annotations

import random

import pytest

from ubuntuguard_agent.constants import CLOCK_JUMP_THRESHOLD_SECONDS
from ubuntuguard_agent.core.scheduler import Backoff, ClockWatch, jittered_interval


class FakeRandom:
    """Returns a scripted position within whatever range it is handed.

    Positions rather than absolute values, so a test can say "the low end" or
    "the midpoint" and stay correct when the range under test changes.

    Deliberately not a subclass of `random.Random`. `Random.__new__` forwards
    its first argument to the C seeder, so a subclass whose constructor takes a
    list fails with "unhashable type" before its body ever runs. The scheduler
    types its `rng` parameter as a Protocol with one method, which is all it
    uses, so a plain object is enough.
    """

    def __init__(self, positions: list[float]) -> None:
        self._positions = list(positions)

    def uniform(self, a: float, b: float) -> float:
        position = self._positions.pop(0) if self._positions else 0.5
        return a + (b - a) * position


# --------------------------------------------------------------------------- #
# Jitter
# --------------------------------------------------------------------------- #


def test_zero_jitter_returns_the_base_exactly() -> None:
    assert jittered_interval(60, 0) == 60.0


def test_jitter_stays_within_the_requested_spread() -> None:
    rng = random.Random(1234)
    for _ in range(2000):
        value = jittered_interval(60, 10, rng=rng)
        assert 54.0 <= value <= 66.0


def test_jitter_is_symmetric_about_the_base() -> None:
    """Symmetry keeps the long-run average equal to the configured interval.

    An asymmetric spread would quietly change the effective heartbeat rate away
    from what the policy asked for, which would show up as a fleet checking in
    more or less often than the dashboard claims.
    """
    assert jittered_interval(100, 50, rng=FakeRandom([0.0])) == 50.0
    assert jittered_interval(100, 50, rng=FakeRandom([1.0])) == 150.0
    assert jittered_interval(100, 50, rng=FakeRandom([0.5])) == 100.0


def test_jitter_never_returns_a_negative_interval() -> None:
    assert jittered_interval(1, 100, rng=FakeRandom([0.0])) == 0.0


@pytest.mark.parametrize(("base", "pct"), [(-1, 10), (60, -1), (60, 101)])
def test_jitter_rejects_nonsense_arguments(base: float, pct: int) -> None:
    with pytest.raises(ValueError):
        jittered_interval(base, pct)


# --------------------------------------------------------------------------- #
# Backoff
# --------------------------------------------------------------------------- #


def test_the_first_delay_is_exactly_the_initial_value() -> None:
    """At attempt 0 the range collapses, so the first retry is predictable.

    Worth having: the first retry interval is the one an operator reads off a
    log while deciding whether the agent is stuck.
    """
    backoff = Backoff(5, 900, rng=FakeRandom([0.0]))
    assert backoff.next_delay() == 5.0


def test_the_ceiling_doubles_per_attempt() -> None:
    backoff = Backoff(5, 900)
    ceilings = []
    for _ in range(6):
        ceilings.append(backoff.ceiling())
        backoff.next_delay()
    assert ceilings == [5.0, 10.0, 20.0, 40.0, 80.0, 160.0]


def test_the_ceiling_is_capped_at_the_maximum() -> None:
    backoff = Backoff(5, 900)
    for _ in range(40):
        backoff.next_delay()
    assert backoff.ceiling() == 900.0


def test_no_delay_ever_falls_below_the_initial_value() -> None:
    """The deliberate departure from textbook full jitter.

    Full jitter draws from [0, ceiling], which lets a run of unlucky draws
    produce a burst of near-immediate retries. That is the hot loop this class
    exists to prevent, and it is the opposite of "avoid excessive requests to
    the server". The floor costs a little decorrelation and guarantees spacing.
    """
    backoff = Backoff(5, 900, rng=random.Random(99))
    for _ in range(500):
        assert backoff.next_delay() >= 5.0


def test_every_delay_respects_the_ceiling() -> None:
    backoff = Backoff(1, 30, rng=random.Random(7))
    for _ in range(500):
        assert backoff.next_delay() <= 30.0


def test_delays_grow_on_average_as_attempts_accumulate() -> None:
    """The point of backing off at all."""
    early = Backoff(5, 3600, rng=random.Random(3))
    first = [early.next_delay() for _ in range(3)]

    late = Backoff(5, 3600, rng=random.Random(3))
    for _ in range(10):
        late.next_delay()
    later = [late.next_delay() for _ in range(3)]

    assert sum(later) / 3 > sum(first) / 3


def test_reset_returns_to_the_initial_delay() -> None:
    """Called after a success, so one recovered request clears the penalty."""
    backoff = Backoff(5, 900, rng=FakeRandom([1.0, 1.0, 1.0, 0.0]))
    for _ in range(3):
        backoff.next_delay()
    assert backoff.attempt == 3

    backoff.reset()
    assert backoff.attempt == 0
    assert backoff.next_delay() == 5.0


def test_a_huge_attempt_count_does_not_overflow() -> None:
    """2**1000 is an arithmetic answer to a question nobody asked."""
    backoff = Backoff(5, 900)
    for _ in range(200):
        backoff.next_delay()
    assert backoff.ceiling() == 900.0


@pytest.mark.parametrize(("initial", "maximum"), [(0, 900), (-1, 900), (60, 30)])
def test_backoff_rejects_an_impossible_range(initial: float, maximum: float) -> None:
    with pytest.raises(ValueError):
        Backoff(initial, maximum)


def test_the_default_bounds_produce_a_usable_schedule() -> None:
    """The shipped defaults, exercised rather than assumed.

    5 s to 900 s reaches the ceiling in eight attempts, which is a few minutes
    of outage before the agent settles at fifteen-minute retries.
    """
    backoff = Backoff(5, 900)
    attempts = 0
    while backoff.ceiling() < 900.0:
        backoff.next_delay()
        attempts += 1
    assert attempts == 8


# --------------------------------------------------------------------------- #
# Clock jumps
# --------------------------------------------------------------------------- #


class FakeClocks:
    """Independently advanceable monotonic and wall clocks."""

    def __init__(self) -> None:
        self.monotonic_value = 1000.0
        self.wall_value = 1_700_000_000.0

    def monotonic(self) -> float:
        return self.monotonic_value

    def wall(self) -> float:
        return self.wall_value

    def advance(self, monotonic: float, wall: float) -> None:
        self.monotonic_value += monotonic
        self.wall_value += wall


def test_clocks_advancing_together_is_not_a_jump() -> None:
    clocks = FakeClocks()
    watch = ClockWatch(monotonic=clocks.monotonic, wall=clocks.wall)
    clocks.advance(monotonic=60.0, wall=60.0)
    assert watch.sample() is None


def test_small_drift_is_tolerated() -> None:
    """Normal NTP correction must not be reported as a jump.

    The threshold sits well above routine correction and well below the 300 s
    skew tolerance, so this is noise rather than signal.
    """
    clocks = FakeClocks()
    watch = ClockWatch(monotonic=clocks.monotonic, wall=clocks.wall)
    clocks.advance(monotonic=60.0, wall=61.0)
    assert watch.sample() is None


def test_a_forward_jump_is_detected() -> None:
    """What a suspend/resume cycle looks like: wall time moved, elapsed did not."""
    clocks = FakeClocks()
    watch = ClockWatch(monotonic=clocks.monotonic, wall=clocks.wall)
    clocks.advance(monotonic=60.0, wall=3_660.0)

    jump = watch.sample()
    assert jump is not None
    assert jump.direction == "forward"
    assert jump.drift_seconds == pytest.approx(3_600.0)


def test_a_backward_jump_is_detected() -> None:
    """A user setting the clock back, which is threat T16.

    Scheduling runs on the monotonic clock so this cannot shorten an interval,
    but it is reported because a device whose clock moved is a device whose
    timestamps need explaining.
    """
    clocks = FakeClocks()
    watch = ClockWatch(monotonic=clocks.monotonic, wall=clocks.wall)
    clocks.advance(monotonic=60.0, wall=-3_540.0)

    jump = watch.sample()
    assert jump is not None
    assert jump.direction == "backward"


def test_sampling_rebases_so_one_jump_is_reported_once() -> None:
    """Otherwise a single suspend would be reported on every later sample."""
    clocks = FakeClocks()
    watch = ClockWatch(monotonic=clocks.monotonic, wall=clocks.wall)

    clocks.advance(monotonic=60.0, wall=3_660.0)
    assert watch.sample() is not None

    clocks.advance(monotonic=60.0, wall=60.0)
    assert watch.sample() is None


def test_the_threshold_is_the_documented_constant() -> None:
    clocks = FakeClocks()
    watch = ClockWatch(monotonic=clocks.monotonic, wall=clocks.wall)
    clocks.advance(monotonic=0.0, wall=CLOCK_JUMP_THRESHOLD_SECONDS + 0.5)
    assert watch.sample() is not None
