"""Security invariants and tunable bounds. The agent-side authority.

This mirrors `server/src/ubuntuguard/constants.py`. It is a deliberate copy
rather than an import: the agent is a separate program installed on a laptop
and cannot depend on the server package being present. Two independent copies
can drift, so `tests/test_constants_match_schema.py` asserts every bound here
still matches the committed JSON Schema the server validates against. That test
is the drift detector; without it this file is a latent disagreement.

The same split as the server applies.

INVARIANTS are not configurable by anyone - not by agent.yaml, not by a signed
policy, not by an environment variable. They are what the threat model rests on.

BOUNDS are the hard range for values that ARE configurable. Note the deliberate
asymmetry with the server, from docs/02-policy-and-signing.md section 5: the
server REJECTS an out-of-range value at policy-creation time so an admin is told
immediately, and the agent CLAMPS instead, because an agent must never brick
itself over a value from a newer server. The clamp emits a `settings_clamped`
event so it is never silent.

Nothing in this module reads the environment or the filesystem.
"""

from __future__ import annotations

from typing import Final, NamedTuple

# --------------------------------------------------------------------------- #
# Invariants - fixed in code, never configurable
# --------------------------------------------------------------------------- #

#: Tolerance for wall-clock disagreement with the server. Widening this extends
#: the window for replaying a time-bound artefact, so it is not tunable.
CLOCK_SKEW_TOLERANCE_SECONDS: Final[int] = 300

#: Device certificates live 30 days and renewal starts at 50% of life (day 15).
#: Renewing later would leave no room to recover from a failed renewal.
DEVICE_CERT_VALIDITY_DAYS: Final[int] = 30
CERT_RENEW_AT_PCT: Final[int] = 50

#: Hard cap on a policy payload. Bounds agent memory and parser work.
MAX_POLICY_PAYLOAD_BYTES: Final[int] = 64 * 1024

#: A USB exception is an admin deliberately unblocking a device, so it expires.
USB_EXCEPTION_MAX_SECONDS: Final[int] = 24 * 60 * 60

#: Domain separator for policy envelope signatures. Must match the server's
#: POLICY_ENVELOPE_DOMAIN and testdata/policy_vectors.json byte for byte.
POLICY_ENVELOPE_DOMAIN: Final[bytes] = b"ubuntuguard/policy-envelope/v1"

#: Envelope format version this build understands.
ENVELOPE_VERSION: Final[int] = 1

#: Transport is HTTPS, always. There is no plaintext fallback in a release
#: build; see config.py for the three conditions under which a development
#: build will talk to a loopback address over HTTP.
REQUIRED_URL_SCHEME: Final[str] = "https"


class Bound(NamedTuple):
    """An inclusive range with a default, shared by the server and the agent."""

    default: int
    minimum: int
    maximum: int

    def clamp(self, value: int) -> int:
        """Agent-side behaviour: pull a value into range rather than failing."""
        return max(self.minimum, min(self.maximum, value))

    def contains(self, value: int) -> bool:
        """Server-side behaviour: decide whether to reject."""
        return self.minimum <= value <= self.maximum


# --------------------------------------------------------------------------- #
# Bounds - for values a signed agent_settings policy may change
# --------------------------------------------------------------------------- #

HEARTBEAT_SECONDS = Bound(default=60, minimum=30, maximum=900)
HEARTBEAT_JITTER_PCT = Bound(default=10, minimum=0, maximum=50)
BACKOFF_INITIAL_SECONDS = Bound(default=5, minimum=1, maximum=60)
BACKOFF_MAX_SECONDS = Bound(default=900, minimum=60, maximum=3600)
INVENTORY_INTERVAL_SECONDS = Bound(default=3600, minimum=300, maximum=86400)
POLICY_POLL_SECONDS = Bound(default=300, minimum=60, maximum=3600)
EVENT_BATCH_MAX = Bound(default=100, minimum=1, maximum=500)
EVENT_QUEUE_MAX_EVENTS = Bound(default=10_000, minimum=100, maximum=10_000)
EVENT_QUEUE_MAX_AGE_DAYS = Bound(default=7, minimum=1, maximum=7)

#: Keyed by the field name used in the agent_settings policy payload.
AGENT_SETTING_BOUNDS: Final[dict[str, Bound]] = {
    "heartbeat_seconds": HEARTBEAT_SECONDS,
    "heartbeat_jitter_pct": HEARTBEAT_JITTER_PCT,
    "backoff_initial_seconds": BACKOFF_INITIAL_SECONDS,
    "backoff_max_seconds": BACKOFF_MAX_SECONDS,
    "inventory_interval_seconds": INVENTORY_INTERVAL_SECONDS,
    "policy_poll_seconds": POLICY_POLL_SECONDS,
    "event_batch_max": EVENT_BATCH_MAX,
    "event_queue_max_events": EVENT_QUEUE_MAX_EVENTS,
    "event_queue_max_age_days": EVENT_QUEUE_MAX_AGE_DAYS,
}

#: Non-numeric agent settings. `Bound` models an integer range, so an enumerated
#: setting needs its own declaration rather than being left out - leaving it out
#: is how the schema and the constants drift apart.
LOG_LEVELS: Final[tuple[str, ...]] = ("error", "warn", "info", "debug")
LOG_LEVEL_DEFAULT: Final[str] = "info"

#: Enumerated so the schema-drift test can account for every property in the
#: JSON Schema rather than silently ignoring the ones it does not model.
NON_NUMERIC_AGENT_SETTINGS: Final[frozenset[str]] = frozenset({"log_level"})

#: The `schema` const every agent_settings payload must carry.
AGENT_SETTINGS_SCHEMA_ID: Final[str] = "ubuntuguard.agent_settings.v1"

# --------------------------------------------------------------------------- #
# Agent-local operational constants (not part of the server contract)
# --------------------------------------------------------------------------- #

#: Longest the service loop will block before re-checking the stop flag. Keeps
#: shutdown responsive when no task is due for a long time.
MAX_IDLE_WAIT_SECONDS: Final[float] = 5.0

#: Floor on the loop wait, so a misconfigured interval cannot spin the CPU.
MIN_LOOP_WAIT_SECONDS: Final[float] = 0.05

#: A wall-clock step larger than this between two consecutive samples, relative
#: to the monotonic clock, is reported as `clock_jump_detected`. Well above
#: normal NTP correction and well below the 300 s skew tolerance.
CLOCK_JUMP_THRESHOLD_SECONDS: Final[float] = 5.0

#: Seconds the service gets to shut down cleanly. Mirrors TimeoutStopSec in the
#: systemd unit; if the two disagree, systemd wins and sends SIGKILL.
SHUTDOWN_GRACE_SECONDS: Final[float] = 30.0
