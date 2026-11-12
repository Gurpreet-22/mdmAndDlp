"""The service loop: scheduling, error isolation and graceful shutdown.

Driven with a fake monotonic clock and `run_once`, so the loop's behaviour is
asserted without any sleeping. The two requirements under test are the ones a
service gets judged on:

  - a failing task must not kill the agent, because a dead agent enforces
    nothing and reports nothing, and the server will only show the device as
    offline without saying why;
  - shutdown must run every hook, in order, even when one of them raises.
"""

from __future__ import annotations

import logging
import threading

import pytest

from ubuntuguard_agent.constants import MAX_IDLE_WAIT_SECONDS, MIN_LOOP_WAIT_SECONDS
from ubuntuguard_agent.core.runtime import Runtime
from ubuntuguard_agent.core.scheduler import Backoff
from ubuntuguard_agent.errors import AgentError, ReasonCode


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def quiet_logger() -> logging.Logger:
    """A logger with a null handler, so test output stays readable."""
    logger = logging.getLogger("ubuntuguard_agent.test.runtime")
    logger.handlers = [logging.NullHandler()]
    logger.propagate = False
    return logger


def make_runtime(clock: FakeClock, logger: logging.Logger) -> Runtime:
    return Runtime(stop_event=threading.Event(), logger=logger, monotonic=clock)


# --------------------------------------------------------------------------- #
# Scheduling
# --------------------------------------------------------------------------- #


def test_a_task_runs_immediately_by_default(quiet_logger: logging.Logger) -> None:
    """A laptop that has just booted is when the server most wants to hear.

    Waiting one full interval before the first check-in would make a reboot look
    like a minute of silence.
    """
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    calls: list[int] = []

    runtime.register(
        "t", interval=lambda: 60.0, action=lambda: calls.append(1), backoff=Backoff(5, 900)
    )
    runtime.run_once()
    assert calls == [1]


def test_first_run_can_be_deferred(quiet_logger: logging.Logger) -> None:
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    calls: list[int] = []

    runtime.register(
        "t",
        interval=lambda: 60.0,
        action=lambda: calls.append(1),
        backoff=Backoff(5, 900),
        first_run_immediately=False,
    )
    runtime.run_once()
    assert calls == []

    clock.advance(60.0)
    runtime.run_once()
    assert calls == [1]


def test_a_task_does_not_run_again_until_its_interval_elapses(
    quiet_logger: logging.Logger,
) -> None:
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    calls: list[int] = []

    runtime.register(
        "t", interval=lambda: 60.0, action=lambda: calls.append(1), backoff=Backoff(5, 900)
    )
    runtime.run_once()
    clock.advance(30.0)
    runtime.run_once()
    assert len(calls) == 1

    clock.advance(31.0)
    runtime.run_once()
    assert len(calls) == 2


def test_a_changed_interval_takes_effect_at_the_next_scheduling(
    quiet_logger: logging.Logger,
) -> None:
    """A signed agent_settings policy applies without a service restart.

    Note the precise semantics, which are worth pinning because they are easy
    to misread: the interval is re-read when a task is *rescheduled*, i.e. after
    it next runs. A shortened interval does not retroactively pull in a run that
    is already scheduled. So a policy cutting the heartbeat from 900 s to 30 s
    is honoured from the next completed run, not immediately.

    That is acceptable here and documented on `PeriodicTask.interval`. Phase 6
    applies settings as part of a policy, and if it needs the change to land
    sooner it should reschedule the affected tasks explicitly rather than have
    the loop guess.
    """
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    interval = [60.0]
    calls: list[int] = []

    runtime.register(
        "t",
        interval=lambda: interval[0],
        action=lambda: calls.append(1),
        backoff=Backoff(5, 900),
    )
    runtime.run_once()
    assert len(calls) == 1

    # The new interval is not yet in play: the run above already booked the
    # next one 60 s out.
    interval[0] = 10.0
    clock.advance(11.0)
    runtime.run_once()
    assert len(calls) == 1

    # Serve out the old interval; that run reschedules using the new one.
    clock.advance(50.0)
    runtime.run_once()
    assert len(calls) == 2

    clock.advance(11.0)
    runtime.run_once()
    assert len(calls) == 3


def test_the_reported_wait_is_clamped_at_both_ends(quiet_logger: logging.Logger) -> None:
    """A floor stops a CPU spin; a ceiling keeps shutdown responsive.

    Without the floor, an interval of zero returns a wait of zero and the loop
    becomes a busy wait. Without the ceiling, a task due in an hour would make
    the loop blind to the stop flag for an hour.
    """
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)

    runtime.register("fast", interval=lambda: 0.0, action=lambda: None, backoff=Backoff(5, 900))
    assert runtime.run_once() == MIN_LOOP_WAIT_SECONDS

    slow = make_runtime(FakeClock(), quiet_logger)
    slow.register("slow", interval=lambda: 3600.0, action=lambda: None, backoff=Backoff(5, 900))
    assert slow.run_once() == MAX_IDLE_WAIT_SECONDS


def test_an_idle_runtime_waits_rather_than_spinning(quiet_logger: logging.Logger) -> None:
    """Phase 1 with no server configured registers almost nothing."""
    runtime = make_runtime(FakeClock(), quiet_logger)
    assert runtime.run_once() == MAX_IDLE_WAIT_SECONDS


def test_tasks_are_independent(quiet_logger: logging.Logger) -> None:
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    fast: list[int] = []
    slow: list[int] = []

    runtime.register(
        "fast", interval=lambda: 10.0, action=lambda: fast.append(1), backoff=Backoff(5, 900)
    )
    runtime.register(
        "slow", interval=lambda: 100.0, action=lambda: slow.append(1), backoff=Backoff(5, 900)
    )

    for _ in range(5):
        runtime.run_once()
        clock.advance(10.0)

    assert len(fast) > len(slow)


# --------------------------------------------------------------------------- #
# Error isolation
# --------------------------------------------------------------------------- #


def test_an_agent_error_does_not_stop_the_loop(quiet_logger: logging.Logger) -> None:
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)

    def failing() -> None:
        raise AgentError("deliberate")

    task = runtime.register("t", interval=lambda: 60.0, action=failing, backoff=Backoff(5, 900))
    runtime.run_once()

    assert runtime.stopping is False
    assert task.consecutive_failures == 1
    assert task.runs == 0


def test_an_unexpected_exception_does_not_stop_the_loop(
    quiet_logger: logging.Logger,
) -> None:
    """The catch-all, and why it is deliberate.

    A bug in one task must not take the process down. The alternative is an
    agent that stops enforcing and stops reporting because of a TypeError in a
    code path nobody exercised.
    """
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)

    def buggy() -> None:
        raise TypeError("a genuine bug")

    task = runtime.register("t", interval=lambda: 60.0, action=buggy, backoff=Backoff(5, 900))
    runtime.run_once()

    assert runtime.stopping is False
    assert task.consecutive_failures == 1


def test_a_failure_reschedules_on_backoff_not_the_normal_interval(
    quiet_logger: logging.Logger,
) -> None:
    """A failing task retries sooner than its interval, but on a rising curve."""
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)

    def failing() -> None:
        raise AgentError("down")

    task = runtime.register("t", interval=lambda: 600.0, action=failing, backoff=Backoff(5, 900))
    runtime.run_once()
    first_due = task.next_due

    assert first_due < clock.value + 600.0
    assert first_due >= clock.value + 5.0


def test_a_success_clears_the_backoff(quiet_logger: logging.Logger) -> None:
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    should_fail = [True]

    def flaky() -> None:
        if should_fail[0]:
            raise AgentError("temporary")

    task = runtime.register("t", interval=lambda: 60.0, action=flaky, backoff=Backoff(5, 900))

    for _ in range(3):
        runtime.run_once()
        clock.advance(100.0)
    assert task.consecutive_failures == 3

    should_fail[0] = False
    runtime.run_once()
    assert task.consecutive_failures == 0
    assert task.backoff.attempt == 0


def test_one_failing_task_does_not_prevent_another_from_running(
    quiet_logger: logging.Logger,
) -> None:
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    healthy: list[int] = []

    runtime.register(
        "broken",
        interval=lambda: 60.0,
        action=lambda: (_ for _ in ()).throw(AgentError("broken")),
        backoff=Backoff(5, 900),
    )
    runtime.register(
        "healthy",
        interval=lambda: 60.0,
        action=lambda: healthy.append(1),
        backoff=Backoff(5, 900),
    )

    runtime.run_once()
    assert healthy == [1]


def test_the_reason_code_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """The code is what the dashboard groups failures on.

    A log line with only prose is a line nobody can aggregate.
    """
    logger = logging.getLogger("ubuntuguard_agent.test.reason")
    logger.propagate = True
    runtime = Runtime(stop_event=threading.Event(), logger=logger, monotonic=FakeClock())

    class SpecificError(AgentError):
        reason_code = ReasonCode.VERIFY_FAILED

    runtime.register(
        "t",
        interval=lambda: 60.0,
        action=lambda: (_ for _ in ()).throw(SpecificError("nope")),
        backoff=Backoff(5, 900),
    )

    with caplog.at_level(logging.WARNING, logger=logger.name):
        runtime.run_once()

    assert any(
        getattr(record, "reason_code", None) == ReasonCode.VERIFY_FAILED
        for record in caplog.records
    )


# --------------------------------------------------------------------------- #
# Shutdown
# --------------------------------------------------------------------------- #


def test_request_stop_ends_the_loop(quiet_logger: logging.Logger) -> None:
    clock = FakeClock()
    runtime = make_runtime(clock, quiet_logger)
    runtime.register("t", interval=lambda: 0.01, action=lambda: None, backoff=Backoff(1, 2))

    runtime.request_stop("test")
    assert runtime.run() == 0
    assert runtime.stop_reason == "test"


def test_shutdown_hooks_run_in_reverse_order(quiet_logger: logging.Logger) -> None:
    """Teardown should unwind setup, so the last thing opened closes first."""
    runtime = make_runtime(FakeClock(), quiet_logger)
    order: list[str] = []

    runtime.on_shutdown("first", lambda: order.append("first"))
    runtime.on_shutdown("second", lambda: order.append("second"))
    runtime.shutdown()

    assert order == ["second", "first"]


def test_a_failing_hook_does_not_block_the_others(quiet_logger: logging.Logger) -> None:
    """Shutdown is the worst time to stop halfway through."""
    runtime = make_runtime(FakeClock(), quiet_logger)
    order: list[str] = []

    runtime.on_shutdown("ok", lambda: order.append("ok"))
    runtime.on_shutdown("broken", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    runtime.shutdown()

    assert order == ["ok"]


def test_shutdown_is_idempotent(quiet_logger: logging.Logger) -> None:
    """`run` calls it in a finally block, and a caller may call it too."""
    runtime = make_runtime(FakeClock(), quiet_logger)
    calls: list[int] = []
    runtime.on_shutdown("once", lambda: calls.append(1))

    runtime.shutdown()
    runtime.shutdown()
    assert calls == [1]


def test_run_always_shuts_down_even_when_a_task_is_failing(
    quiet_logger: logging.Logger,
) -> None:
    runtime = make_runtime(FakeClock(), quiet_logger)
    stopped: list[int] = []

    runtime.register(
        "broken",
        interval=lambda: 60.0,
        action=lambda: (_ for _ in ()).throw(AgentError("x")),
        backoff=Backoff(5, 900),
    )
    runtime.on_shutdown("record", lambda: stopped.append(1))
    runtime.request_stop("test")
    runtime.run()

    assert stopped == [1]


def test_the_stop_flag_is_honoured_between_tasks(quiet_logger: logging.Logger) -> None:
    """A SIGTERM during a batch of due tasks takes effect at the next boundary.

    It does not interrupt a task mid-flight: a half-applied policy is worse than
    a slightly delayed shutdown.
    """
    runtime = make_runtime(FakeClock(), quiet_logger)
    second: list[int] = []

    runtime.register(
        "stopper",
        interval=lambda: 60.0,
        action=lambda: runtime.request_stop("from_task"),
        backoff=Backoff(5, 900),
    )
    runtime.register(
        "later", interval=lambda: 60.0, action=lambda: second.append(1), backoff=Backoff(5, 900)
    )

    runtime.run_once()
    assert second == []


def test_a_shared_stop_event_can_stop_the_runtime(quiet_logger: logging.Logger) -> None:
    """This is the seam the signal handler uses.

    The handler only sets the event, which is all that is safe to do inside one.
    """
    event = threading.Event()
    runtime = Runtime(stop_event=event, logger=quiet_logger, monotonic=FakeClock())
    event.set()
    assert runtime.run() == 0
