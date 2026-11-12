"""Service wiring: signals, task registration and the start-up banner.

This is the OS-facing glue that `core/runtime.py` deliberately does not contain.
Installing a signal handler is a system call, and keeping it out of the core is
what lets the loop be driven by a test with a fake clock.

Two tasks are registered.

`identity_check` reads local state only and never contacts a server. It is
what surfaces an expiring or corrupt certificate, and it runs whether or not
the device is enrolled.

`heartbeat` is the authenticated one. It is skipped - not failed - when there
is no server configured or no identity yet, because both are normal states for
a freshly installed agent and treating them as errors would produce a backoff
loop reporting a condition the operator already knows about.

The heartbeat requires genuine mutual TLS, which requires the nginx
configuration in `deploy/nginx/`. Without it the device plane is reachable only
by setting the forwarded identity headers directly, which is impersonation
rather than authentication - so `status` continues to report
`mtls_verified: false` until an operator has that configuration in place, and
nothing in this build claims otherwise on its behalf.
"""

from __future__ import annotations

import datetime as dt
import logging
import signal
import threading
from collections.abc import Callable

from ubuntuguard_agent import __version__
from ubuntuguard_agent.config import AgentConfig
from ubuntuguard_agent.core.runtime import Runtime
from ubuntuguard_agent.core.scheduler import Backoff, ClockWatch, jittered_interval
from ubuntuguard_agent.errors import AgentError
from ubuntuguard_agent.heartbeat import (
    build_device_client,
    build_heartbeat_payload,
    send_heartbeat,
)
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.identity import (
    complete_pending_renewal,
    ensure_runtime_paths,
    is_enrolled,
    read_certificate,
)
from ubuntuguard_agent.logging_setup import get_logger
from ubuntuguard_agent.osadapter import OsAdapter, detect_adapter
from ubuntuguard_agent.renewal import RenewalResult, renew, renewal_due

#: Signals that mean "stop cleanly". SIGTERM is what systemd sends on `stop`
#: and `restart`; SIGINT is Ctrl-C when run in a terminal.
_STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)


def log_startup_banner(
    config: AgentConfig,
    adapter: OsAdapter,
    *,
    logger: logging.Logger,
) -> None:
    """One structured line describing what this agent is and what it can see.

    Deliberately includes the things that are easy to get wrong and expensive to
    diagnose later: whether this is a release build, whether the host is a
    tested platform, and whether a server is even configured.
    """
    facts = adapter.host_facts()
    logger.info(
        "ubuntuguard agent starting",
        extra={
            "agent_version": __version__,
            "release_build": config.release_build,
            "adapter": adapter.name,
            "platform_supported": adapter.is_supported(),
            "release_validated": adapter.is_validated_release(),
            "os": facts.os.short,
            "kernel": facts.kernel,
            "arch": facts.arch,
            "hostname": facts.hostname,
            "server_configured": config.is_configured,
            "config_path": str(config.config_path) if config.config_path else None,
            "state_dir": str(config.paths.state_dir),
        },
    )

    if not config.release_build:
        logger.warning(
            "development build: environment overrides are active and this device "
            "is reported with release_build=false",
            extra={"release_build": False},
        )

    if config.plaintext_http_permitted:
        # Loud, and on every start. This is the one condition under which the
        # agent will use plaintext HTTP, and it should never be quiet about it.
        logger.warning(
            "plaintext HTTP is permitted to a loopback address in this development "
            "build; no release build will ever do this",
            extra={"server_url": config.server_url},
        )

    if not adapter.is_supported():
        logger.warning(
            "no OS adapter implements this host; fact collection is UNVALIDATED here",
            extra={"os": facts.os.short, "supported_ids": "ubuntu"},
        )

    if not adapter.is_validated_release():
        # On every start, deliberately. The agent has not been exercised on any
        # target release yet, and that is a fact an operator reading the journal
        # should meet rather than have to look up.
        logger.warning(
            "the agent has not been validated on this release; UNVALIDATED",
            extra={"os": facts.os.short},
        )

    if not config.is_configured:
        logger.warning(
            "no server_url is configured; the agent will idle. Set server_url in "
            "the configuration file and restart",
            extra={"config_path": str(config.config_path) if config.config_path else None},
        )


def _identity_check(config: AgentConfig, *, logger: logging.Logger) -> None:
    """Report local identity state. Reads files only; never contacts a server.

    Raises `AgentError` on a corrupt certificate so the runtime logs it with a
    reason code and retries on backoff, rather than treating a damaged identity
    as an absent one.
    """
    if not is_enrolled(config.paths):
        logger.info(
            "device is not enrolled; no certificate or private key is installed",
            extra={"enrolled": False, "pki_dir": str(config.paths.pki_dir)},
        )
        return

    try:
        summary = read_certificate(config.paths)
    except ValueError as exc:
        raise AgentError(f"installed certificate could not be parsed: {exc}") from exc

    if summary is None:
        logger.warning(
            "a private key is installed but no certificate; enrollment did not complete",
            extra={"enrolled": False},
        )
        return

    now = dt.datetime.now(dt.timezone.utc)
    days_left = round(summary.seconds_remaining(now=now) / 86400, 1)

    # No certificate fingerprint or serial in the log line: they identify the
    # device to anyone who reads it, and nothing here needs them.
    context = {
        "enrolled": True,
        "device_id": summary.device_id,
        "not_after": summary.not_after.isoformat(),
        "days_remaining": days_left,
    }

    if summary.is_expired(now=now):
        logger.error(
            "device certificate has expired; the agent cannot authenticate until "
            "it is renewed or the device is re-enrolled",
            extra=context,
        )
    elif summary.renewal_due(now=now):
        # Phase 5. Logged as actionable rather than attempted, because there is
        # no renewal endpoint on the server yet.
        logger.warning(
            "device certificate is past half-life and renewal is due; renewal "
            "arrives in Phase 5 and requires a server-side endpoint that does "
            "not exist yet",
            extra=context,
        )
    else:
        logger.debug("device certificate is valid", extra=context)


class HeartbeatTask:
    """The periodic heartbeat, with the mutable bits the scheduler needs.

    A class rather than a closure because three things have to survive between
    runs: the client, the interval the server last suggested, and the jitter
    with it. A closure over mutable locals would do the same job less legibly,
    and a test needs to be able to reach in and assert the interval changed.

    The client is built **lazily, on the first run that could use it**, not at
    registration. A freshly installed agent has no identity, and an operator
    may enrol it while the service is running; building the client up front
    would mean the service had to be restarted after enrollment to notice.
    """

    def __init__(
        self,
        config: AgentConfig,
        adapter: OsAdapter,
        *,
        logger: logging.Logger,
        client_factory: Callable[[AgentConfig], ServerClient] = build_device_client,
    ) -> None:
        self._config = config
        self._adapter = adapter
        self._log = logger
        self._client_factory = client_factory
        self._client: ServerClient | None = None
        self._interval_seconds = config.settings.heartbeat_seconds
        self._jitter_pct = config.settings.heartbeat_jitter_pct
        self._skip_logged = False

    @property
    def interval_seconds(self) -> int:
        return self._interval_seconds

    def reset(self) -> None:
        """Drop the cached client so the next run rebuilds it.

        Called after a certificate renewal. An `ssl.SSLContext` loads the
        client certificate once, at construction, and holds it for the life of
        the process - so a renewed certificate on disk would be ignored until a
        restart, and the heartbeat would keep presenting a certificate the
        server has superseded. The symptom would be every heartbeat failing
        with `client_cert_superseded` on a device whose files are perfectly
        correct.
        """
        self._client = None

    def interval(self) -> float:
        """The next delay, jittered.

        Jitter spreads a fleet out. Fifty laptops imaged from one template
        would otherwise heartbeat in lockstep, turning a routine interval into
        a thundering herd against one FastAPI process.
        """
        return jittered_interval(self._interval_seconds, self._jitter_pct)

    def _skip(self, reason: str) -> None:
        """Log a skip once, then stay quiet about it.

        An unenrolled laptop would otherwise write the same line every minute
        forever, which is how a journal becomes unreadable and a real warning
        becomes invisible.
        """
        if not self._skip_logged:
            self._log.info("heartbeat skipped", extra={"reason": reason, "repeat_suppressed": True})
            self._skip_logged = True

    def __call__(self) -> None:
        if not self._config.is_configured:
            self._skip("no server_url is configured")
            return
        if not is_enrolled(self._config.paths):
            self._skip("this device is not enrolled")
            return

        self._skip_logged = False

        if self._client is None:
            self._client = self._client_factory(self._config)

        payload = build_heartbeat_payload(self._adapter)
        try:
            hints = send_heartbeat(self._client, payload, logger=self._log)
        except AgentError:
            # Discarded so the next attempt rebuilds it. The identity on disk
            # may have changed - a re-enrollment, or a certificate replaced by
            # hand - and a cached TLS context holds the old one for the life of
            # the process. Rebuilding costs one handshake on a path that is
            # already failing.
            self._client = None
            raise

        if hints.heartbeat_seconds != self._interval_seconds:
            self._log.info(
                "heartbeat interval updated by the server",
                extra={
                    "from_seconds": self._interval_seconds,
                    "to_seconds": hints.heartbeat_seconds,
                },
            )
        self._interval_seconds = hints.heartbeat_seconds
        self._jitter_pct = hints.heartbeat_jitter_pct

        self._log.debug(
            "heartbeat acknowledged",
            extra={
                "server_time": hints.server_time,
                "available_policies": len(hints.available_policies),
            },
        )


class CertificateRenewalTask:
    """Renews the device certificate when it reaches half-life.

    Runs on the heartbeat cadence, which sounds wasteful and is not: the common
    case is reading one small file and comparing two timestamps, and the
    alternative - a second configurable interval - would be a tunable whose
    only job is to decide how late a renewal may be. A certificate reaching its
    midpoint while the agent waits out a longer timer is the failure this task
    exists to prevent.

    It is also what recovers an interrupted renewal, which is why it runs
    immediately at start-up rather than after one interval: a crash during the
    swap leaves staged material that nothing else would look at.
    """

    def __init__(
        self,
        config: AgentConfig,
        *,
        logger: logging.Logger,
        on_renewed: Callable[[], None] | None = None,
        renew_fn: Callable[..., RenewalResult] = renew,
    ) -> None:
        self._config = config
        self._log = logger
        self._on_renewed = on_renewed
        self._renew = renew_fn
        self._skip_logged = False

    def interval(self) -> float:
        return jittered_interval(
            self._config.settings.heartbeat_seconds,
            self._config.settings.heartbeat_jitter_pct,
        )

    def _skip(self, reason: str) -> None:
        if not self._skip_logged:
            self._log.info(
                "certificate renewal skipped",
                extra={"reason": reason, "repeat_suppressed": True},
            )
            self._skip_logged = True

    def __call__(self) -> None:
        paths = self._config.paths

        # Recovery first, and before the enrolled check: a half-swapped
        # identity can look unenrolled, and discarding it on that basis would
        # throw away a certificate the server has already issued.
        recovered = complete_pending_renewal(paths)
        if recovered is not None:
            self._log.info(
                "completed an interrupted certificate renewal",
                extra={
                    "device_id": recovered.device_id,
                    "not_after": recovered.not_after.isoformat(),
                },
            )
            if self._on_renewed is not None:
                self._on_renewed()
            return

        if not self._config.is_configured:
            self._skip("no server_url is configured")
            return
        if not is_enrolled(paths):
            self._skip("this device is not enrolled")
            return

        self._skip_logged = False

        try:
            summary = read_certificate(paths)
        except ValueError as exc:
            raise AgentError(f"installed certificate could not be parsed: {exc}") from exc
        if summary is None:
            return

        now = dt.datetime.now(dt.timezone.utc)
        if summary.is_expired(now=now):
            # Past renewal. The server will refuse an expired certificate at
            # the independent validity check in device_auth, so attempting a
            # renewal would only produce a 401 the operator cannot act on from
            # the agent's side.
            self._log.error(
                "the device certificate has expired; renewal is no longer possible "
                "and this device must be re-enrolled",
                extra={"not_after": summary.not_after.isoformat(), "enrolled": True},
            )
            return
        if not renewal_due(summary, now=now):
            self._log.debug(
                "certificate renewal is not yet due",
                extra={"renew_after": summary.renew_after.isoformat()},
            )
            return

        # The result is logged inside `renew`; nothing here needs it. A failure
        # raises, which the runtime catches and reschedules on backoff - the
        # right behaviour, because the old certificate is still valid and there
        # are days of runway left.
        self._renew(self._config, logger=self._log)
        if self._on_renewed is not None:
            # The heartbeat holds an SSLContext built from the old certificate.
            self._on_renewed()


def build_runtime(
    config: AgentConfig,
    *,
    logger: logging.Logger | None = None,
    stop_event: threading.Event | None = None,
    adapter: OsAdapter | None = None,
) -> Runtime:
    """Assemble the runtime and register its tasks.

    Returned rather than run, so a test can inspect the registered tasks and
    step the loop without a process lifecycle around it.
    """
    log = logger if logger is not None else get_logger("service")
    runtime = Runtime(stop_event=stop_event, logger=log)
    os_adapter = adapter if adapter is not None else detect_adapter()

    settings = config.settings
    clock_watch = ClockWatch()

    def identity_interval() -> float:
        # Re-read from settings on every scheduling decision so a signed
        # agent_settings policy changes the cadence without a restart.
        return jittered_interval(
            config.settings.heartbeat_seconds, config.settings.heartbeat_jitter_pct
        )

    def identity_action() -> None:
        jump = clock_watch.sample()
        if jump is not None:
            # The `clock_jump_detected` event type exists in
            # schemas/event.agent.v1 and will be queued here from Phase 7; for
            # now it is logged, because there is no event queue to put it in.
            log.warning(
                "wall clock stepped relative to elapsed time",
                extra={
                    "event_type": "clock_jump_detected",
                    "direction": jump.direction,
                    "drift_seconds": round(jump.drift_seconds, 2),
                },
            )
        _identity_check(config, logger=log)

    runtime.register(
        "identity_check",
        interval=identity_interval,
        action=identity_action,
        backoff=Backoff(settings.backoff_initial_seconds, settings.backoff_max_seconds),
    )

    heartbeat = HeartbeatTask(config, os_adapter, logger=log)
    runtime.register(
        "heartbeat",
        interval=heartbeat.interval,
        action=heartbeat,
        backoff=Backoff(settings.backoff_initial_seconds, settings.backoff_max_seconds),
    )

    # Registered AFTER the heartbeat so that within one loop pass the heartbeat
    # runs first. On the pass where a renewal happens, the heartbeat has
    # already used the old certificate - which is still valid - and the next
    # pass uses the new one through the rebuilt client. Renewing first would
    # mean the heartbeat in the same pass ran against a client that
    # `on_renewed` had just discarded, which works but makes the ordering
    # load-bearing in a way nothing documents.
    renewal_task = CertificateRenewalTask(config, logger=log, on_renewed=heartbeat.reset)
    runtime.register(
        "certificate_renewal",
        interval=renewal_task.interval,
        action=renewal_task,
        backoff=Backoff(settings.backoff_initial_seconds, settings.backoff_max_seconds),
    )

    runtime.on_shutdown(
        "log_stop",
        lambda: log.info("agent stopped", extra={"event_type": "agent_stopped"}),
    )
    return runtime


def install_signal_handlers(runtime: Runtime, *, logger: logging.Logger | None = None) -> None:
    """Route SIGTERM and SIGINT to a clean stop.

    The handler does the minimum: set a flag. It deliberately does not log,
    because a signal arriving while the logging lock is held can deadlock the
    process, and a service that hangs on SIGTERM is worse than one that exits
    without a farewell line. The loop logs the reason once it wakes up.

    `signal.signal` only works on the main thread, which is where the CLI calls
    this. A ValueError is caught and reported rather than propagated so that
    embedding the runtime in a worker thread degrades to "no signal handling"
    instead of failing to start.
    """
    log = logger if logger is not None else get_logger("service")

    def handler(signum: int, _frame: object) -> None:
        runtime.request_stop(f"signal:{signal.Signals(signum).name}")

    for sig in _STOP_SIGNALS:
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError) as exc:
            log.warning(
                "could not install signal handler",
                extra={"signal": sig.name, "error": str(exc)},
            )


def run_service(
    config: AgentConfig,
    *,
    adapter: OsAdapter | None = None,
    logger: logging.Logger | None = None,
) -> int:
    """Start the agent and run until signalled. Returns a process exit code."""
    log = logger if logger is not None else get_logger("service")
    os_adapter = adapter if adapter is not None else detect_adapter()

    log_startup_banner(config, os_adapter, logger=log)

    try:
        ensure_runtime_paths(config.paths)
    except OSError as exc:
        # Not recoverable and not worth looping over: without a state directory
        # the agent cannot persist an identity, so it exits and lets systemd's
        # Restart=on-failure decide what happens next.
        log.error(
            "could not prepare the state directory",
            extra={"state_dir": str(config.paths.state_dir), "error": str(exc)},
        )
        return 1

    # The adapter is passed in rather than re-detected, so the banner and the
    # heartbeat report facts from the same object. Two independently detected
    # adapters would be equivalent today, and a single source removes the
    # question entirely.
    runtime = build_runtime(config, logger=log, adapter=os_adapter)
    install_signal_handlers(runtime, logger=log)
    return runtime.run()
