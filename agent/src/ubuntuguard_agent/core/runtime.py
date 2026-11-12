"""The service loop: periodic tasks, error isolation and graceful shutdown.

Pure loop logic. The stop flag, the clock and every task are passed in, so the
whole lifecycle can be driven by a test with a fake clock and no sleeping. The
signal handlers that set the stop flag live in `service.py`, because installing
a signal handler is an operating-system call and this package does not make
them (feature D1).

Two behaviours here are requirements rather than conveniences.

**A failing task must not kill the agent.** An agent that exits because one
heartbeat raised is an agent that stops enforcing and stops reporting, and the
server will show the device as offline without saying why. So every task runs
inside a guard, a failure is logged with its reason code, and the task is
rescheduled on its own backoff while every other task carries on. The process
exits only on a deliberate stop or on something it cannot be expected to handle.

**Shutdown must be bounded and ordered.** On SIGTERM the loop stops accepting
new work, runs the registered shutdown callbacks in reverse registration order
so teardown unwinds setup, and guards each one - a callback that raises must not
prevent the rest from running. systemd's `TimeoutStopSec` is the hard ceiling;
if the agent is still going when it expires, systemd sends SIGKILL, so nothing
here may block indefinitely.
"""

from __future__ import annotations

import dataclasses
import logging
import threading
import time
from collections.abc import Callable

from ubuntuguard_agent.constants import MAX_IDLE_WAIT_SECONDS, MIN_LOOP_WAIT_SECONDS
from ubuntuguard_agent.core.scheduler import Backoff, MonotonicClock
from ubuntuguard_agent.errors import AgentError, ReasonCode


@dataclasses.dataclass
class PeriodicTask:
    """One unit of recurring work.

    `interval` is a callable rather than a number so a signed `agent_settings`
    policy that changes the heartbeat interval takes effect without the task
    being torn down and rebuilt. It is also where jitter is applied, which keeps
    this class unaware of it.

    The timing is worth being precise about: the callable is consulted when a
    task is *rescheduled*, which is after it runs. A shortened interval
    therefore applies from the next completed run and does not pull in a run
    that is already booked. For a heartbeat going from 900 s to 30 s that means
    one more long wait before the new cadence starts. If Phase 6 needs a
    settings change to land sooner than that, it should reschedule the affected
    tasks explicitly rather than have the loop infer it.
    """

    name: str
    interval: Callable[[], float]
    action: Callable[[], None]
    backoff: Backoff
    next_due: float = 0.0
    consecutive_failures: int = 0
    runs: int = 0

    def schedule_after_success(self, now: float) -> None:
        self.backoff.reset()
        self.consecutive_failures = 0
        self.next_due = now + max(0.0, self.interval())

    def schedule_after_failure(self, now: float) -> float:
        self.consecutive_failures += 1
        delay = self.backoff.next_delay()
        self.next_due = now + delay
        return delay


class Runtime:
    """Runs registered tasks until the stop flag is set.

    Single-threaded on purpose. At one heartbeat a minute, one inventory an
    hour and one policy poll every five minutes, there is no work here that
    needs concurrency, and a single thread removes every question about what
    two tasks touching the same SQLite file do to each other.
    """

    def __init__(
        self,
        *,
        stop_event: threading.Event | None = None,
        logger: logging.Logger | None = None,
        monotonic: MonotonicClock | None = None,
    ) -> None:
        self._stop = stop_event if stop_event is not None else threading.Event()
        self._log = logger if logger is not None else logging.getLogger("ubuntuguard_agent.runtime")
        self._monotonic: MonotonicClock = monotonic if monotonic is not None else time.monotonic
        self._tasks: list[PeriodicTask] = []
        self._shutdown_hooks: list[tuple[str, Callable[[], None]]] = []
        self._stop_reason: str = "unknown"

    # --- registration ----------------------------------------------------- #

    def register(
        self,
        name: str,
        *,
        interval: Callable[[], float],
        action: Callable[[], None],
        backoff: Backoff,
        first_run_immediately: bool = True,
    ) -> PeriodicTask:
        """Add a periodic task.

        `first_run_immediately` defaults to True because the useful behaviour at
        start-up is to check in now, not after one full interval. A laptop that
        has just booted is exactly when the server most wants to hear from it.
        """
        task = PeriodicTask(
            name=name,
            interval=interval,
            action=action,
            backoff=backoff,
            next_due=self._monotonic() if first_run_immediately else self._monotonic() + interval(),
        )
        self._tasks.append(task)
        return task

    def on_shutdown(self, name: str, callback: Callable[[], None]) -> None:
        """Register teardown. Runs in reverse order, each one guarded."""
        self._shutdown_hooks.append((name, callback))

    @property
    def tasks(self) -> tuple[PeriodicTask, ...]:
        return tuple(self._tasks)

    @property
    def stop_reason(self) -> str:
        return self._stop_reason

    # --- control ---------------------------------------------------------- #

    def request_stop(self, reason: str = "requested") -> None:
        """Ask the loop to finish. Safe to call from a signal handler.

        Only `Event.set()` and an attribute assignment happen here, both of
        which are safe in a handler. Anything else - logging in particular -
        can deadlock if the signal arrives while the logging lock is held.
        """
        self._stop_reason = reason
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # --- the loop --------------------------------------------------------- #

    def run_once(self) -> float:
        """Run everything due, then return how long to wait before looking again.

        Split out from `run` so a test can step the loop with a fake clock
        instead of sleeping. The returned wait is clamped at both ends: a floor
        so a zero or negative interval cannot spin the CPU, and a ceiling so the
        stop flag is noticed promptly even when nothing is due for an hour.
        """
        now = self._monotonic()

        for task in self._tasks:
            if self._stop.is_set():
                break
            if task.next_due > now:
                continue
            self._run_task(task, now)

        if not self._tasks:
            return MAX_IDLE_WAIT_SECONDS

        soonest = min(task.next_due for task in self._tasks)
        wait = soonest - self._monotonic()
        return max(MIN_LOOP_WAIT_SECONDS, min(MAX_IDLE_WAIT_SECONDS, wait))

    def _run_task(self, task: PeriodicTask, now: float) -> None:
        try:
            task.action()
        except AgentError as exc:
            # A failure the agent anticipated: it carries a reason code, which
            # is what the server and the dashboard group on.
            delay = task.schedule_after_failure(now)
            self._log.warning(
                "task failed",
                extra={
                    "task": task.name,
                    "reason_code": exc.reason_code,
                    "error": str(exc),
                    "consecutive_failures": task.consecutive_failures,
                    "retry_in_seconds": round(delay, 2),
                },
            )
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all, see below
            # Anything unanticipated. Caught rather than allowed to propagate
            # because the alternative is a dead agent, which is a worse outcome
            # than a degraded one: a stopped agent enforces nothing and reports
            # nothing. Logged with the traceback and an `unknown` reason code so
            # it is visibly a bug rather than a handled condition.
            #
            # BaseException is deliberately NOT caught: KeyboardInterrupt and
            # SystemExit mean someone wants this process gone.
            delay = task.schedule_after_failure(now)
            self._log.error(
                "task raised an unexpected exception",
                exc_info=True,
                extra={
                    "task": task.name,
                    "reason_code": ReasonCode.UNKNOWN,
                    "error_type": type(exc).__name__,
                    "consecutive_failures": task.consecutive_failures,
                    "retry_in_seconds": round(delay, 2),
                },
            )
        else:
            task.runs += 1
            task.schedule_after_success(now)

    def run(self) -> int:
        """Loop until stopped, then shut down. Returns a process exit code."""
        self._log.info("service loop started", extra={"tasks": [t.name for t in self._tasks]})
        try:
            while not self._stop.is_set():
                wait = self.run_once()
                if self._stop.is_set():
                    break
                # Waiting on the event rather than sleeping is what makes
                # shutdown immediate: a SIGTERM during a 60-second wait returns
                # at once instead of serving out the remainder.
                self._stop.wait(wait)
        except KeyboardInterrupt:
            self._stop_reason = "interrupted"
        finally:
            self.shutdown()
        return 0

    def shutdown(self) -> None:
        """Run the shutdown hooks in reverse order. Never raises."""
        self._log.info("shutting down", extra={"reason": self._stop_reason})
        for name, callback in reversed(self._shutdown_hooks):
            try:
                callback()
            except Exception:  # noqa: BLE001 - one bad hook must not block the rest
                self._log.error("shutdown hook failed", exc_info=True, extra={"hook": name})
        self._shutdown_hooks.clear()
        self._log.info("stopped", extra={"reason": self._stop_reason})
