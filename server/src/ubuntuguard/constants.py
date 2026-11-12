"""Security invariants and bounds.

Two kinds of value live here, and the distinction matters.

INVARIANTS are not configurable by anyone - not by an environment variable, not
by a signed policy, not by an admin. They are the things the threat model relies
on. If one of these became tunable, a misconfiguration or a compromised server
could turn a security control off without anybody signing anything.

BOUNDS are the hard min/max for values that ARE configurable. The server rejects
an out-of-range value at policy-creation time so an admin gets told immediately;
the agent clamps instead, because an agent must never brick itself over a value
from a newer server. See docs/02-policy-and-signing.md section 5.

Nothing in this module reads the environment. That is the point.
"""

from __future__ import annotations

from typing import Final, NamedTuple

# --------------------------------------------------------------------------- #
# Invariants - fixed in code, never configurable
# --------------------------------------------------------------------------- #

#: Tolerance for wall-clock disagreement between agent and server. Widening this
#: would extend the window for replaying a time-bound artefact, so it is fixed.
CLOCK_SKEW_TOLERANCE_SECONDS: Final[int] = 300

#: Device certificates live 30 days and are renewed at 50% of life (day 15).
#: Renewing later would leave no room to recover from a failed renewal.
DEVICE_CERT_VALIDITY_DAYS: Final[int] = 30
CERT_RENEW_AT_PCT: Final[int] = 50

#: How long a SUPERSEDED device certificate may still be used, and for the
#: renewal endpoint only.
#:
#: This window exists to solve one specific failure, and it is the same failure
#: the enrollment idempotency cache exists for: the server commits a renewal and
#: the response is lost in transit. Without a window the agent is holding a
#: certificate the server has just superseded, cannot authenticate, therefore
#: cannot retry the renewal, and is locked out until an operator issues a new
#: enrollment token. A renewal that bricks a laptop whenever a packet drops is
#: not a renewal.
#:
#: Why it is narrow in three separate ways rather than one:
#:
#:   1. Time: one hour. The agent retries on a backoff capped at 900 s
#:      (BACKOFF_MAX_SECONDS), so an hour covers several attempts with room to
#:      spare, and is negligible against a 30-day certificate.
#:   2. Scope: `POST /devices/me/certificate:renew` and nothing else. A
#:      superseded certificate cannot heartbeat. It can only be used to collect
#:      the replacement it was superseded by, which is the single operation it
#:      is needed for. Enforced by `get_device_principal` being the strict
#:      dependency and the renewal route opting in explicitly.
#:   3. Effect: the retry is idempotent. Presenting the same CSR public key
#:      returns the certificate already issued rather than issuing another, so
#:      the window cannot be used to accumulate certificates.
#:
#: Revocation still takes precedence: a revoked device is refused regardless,
#: because the device's own status is checked before the certificate's.
CERT_SUPERSEDE_GRACE_SECONDS: Final[int] = 3600

#: Hard cap on a policy payload. Bounds agent memory and parser work. A real USB
#: policy with a 256-entry allowlist is comfortably under 8 KiB.
MAX_POLICY_PAYLOAD_BYTES: Final[int] = 64 * 1024

#: A USB exception is an admin deliberately unblocking a device, so it expires.
USB_EXCEPTION_MAX_SECONDS: Final[int] = 24 * 60 * 60

#: Enrollment tokens: 32 random bytes, single use, 24 h default life.
ENROLLMENT_TOKEN_BYTES: Final[int] = 32
ENROLLMENT_TOKEN_DEFAULT_TTL_SECONDS: Final[int] = 24 * 60 * 60

#: Window in which an interrupted enrollment may be retried and get back the
#: identical response, keyed by (token hash, CSR public key).
ENROLLMENT_IDEMPOTENCY_SECONDS: Final[int] = 60

#: Session tokens: 32 random bytes is 256 bits, so there is nothing to brute
#: force and a fast hash (SHA-256) is the correct choice for storing them.
#: Argon2id is for low-entropy human passwords only.
SESSION_TOKEN_BYTES: Final[int] = 32

#: Domain separator for the audit hash chain. Changing it breaks every existing
#: chain, which is why it is versioned.
AUDIT_CHAIN_DOMAIN: Final[bytes] = b"ubuntuguard/audit-chain/v1"

#: Domain separator for policy envelope signatures. Must match the Go agent and
#: testdata/policy_vectors.json exactly.
POLICY_ENVELOPE_DOMAIN: Final[bytes] = b"ubuntuguard/policy-envelope/v1"

#: Argon2id parameters. Follows the OWASP guidance of m=19456 KiB, t=2, p=1,
#: which targets roughly 50 ms on server hardware. Raising these later is safe:
#: `needs_rehash` detects old hashes and upgrades them on next successful login.
ARGON2_MEMORY_COST_KIB: Final[int] = 19_456
ARGON2_TIME_COST: Final[int] = 2
ARGON2_PARALLELISM: Final[int] = 1
ARGON2_HASH_LENGTH: Final[int] = 32
ARGON2_SALT_LENGTH: Final[int] = 16

#: Headers nginx sets from the verified client certificate. The application must
#: treat these as trustworthy ONLY when they arrive from the trusted upstream,
#: and nginx must overwrite all of them unconditionally on every request so a
#: client cannot inject its own.
#:
#: Note what is NOT here: nginx's $ssl_client_fingerprint. That variable is
#: SHA-1, and pinning a device identity to a SHA-1 digest is not a hash choice
#: worth defending. Instead nginx forwards the whole certificate via
#: $ssl_client_escaped_cert and the application computes SHA-256 itself, which
#: also means the app can re-derive anything else it needs from the certificate
#: rather than trusting the proxy to summarise it.
CLIENT_CERT_VERIFY_HEADER: Final[str] = "x-client-verify"
CLIENT_CERT_PEM_HEADER: Final[str] = "x-client-cert"
CLIENT_CERT_DN_HEADER: Final[str] = "x-client-dn"
CLIENT_CERT_SERIAL_HEADER: Final[str] = "x-client-serial"


# --------------------------------------------------------------------------- #
# Bounds - for values that are configurable
# --------------------------------------------------------------------------- #


class Bound(NamedTuple):
    """An inclusive range with a default, used by both the server and the agent."""

    default: int
    minimum: int
    maximum: int

    def clamp(self, value: int) -> int:
        """Agent-side behaviour: pull a value into range rather than failing."""
        return max(self.minimum, min(self.maximum, value))

    def contains(self, value: int) -> bool:
        """Server-side behaviour: decide whether to reject."""
        return self.minimum <= value <= self.maximum


#: Agent tunables. These mirror schemas/policy.agent_settings.v1.schema.json and
#: the table in docs/02-policy-and-signing.md; test_bounds_match_schema asserts
#: the three stay in step, so the schema cannot drift away from the code.
HEARTBEAT_SECONDS = Bound(default=60, minimum=30, maximum=900)
HEARTBEAT_JITTER_PCT = Bound(default=10, minimum=0, maximum=50)
BACKOFF_INITIAL_SECONDS = Bound(default=5, minimum=1, maximum=60)
BACKOFF_MAX_SECONDS = Bound(default=900, minimum=60, maximum=3600)
INVENTORY_INTERVAL_SECONDS = Bound(default=3600, minimum=300, maximum=86400)
POLICY_POLL_SECONDS = Bound(default=300, minimum=60, maximum=3600)
EVENT_BATCH_MAX = Bound(default=100, minimum=1, maximum=500)
EVENT_QUEUE_MAX_EVENTS = Bound(default=10_000, minimum=100, maximum=10_000)
EVENT_QUEUE_MAX_AGE_DAYS = Bound(default=7, minimum=1, maximum=7)

#: Non-numeric agent settings. `Bound` models an integer range, so an
#: enumerated setting needs its own declaration rather than being left out -
#: leaving it out is how the schema and the constants drift apart.
LOG_LEVELS: Final[tuple[str, ...]] = ("error", "warn", "info", "debug")
LOG_LEVEL_DEFAULT: Final[str] = "info"

#: Settings that exist but are not integer ranges. Enumerated so the
#: schema-drift test can account for every property in the JSON Schema.
NON_NUMERIC_AGENT_SETTINGS: Final[frozenset[str]] = frozenset({"log_level"})

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

#: Admin login hardening. Brief: lock out after 5 failures in 10 minutes.
LOGIN_MAX_FAILURES: Final[int] = 5
LOGIN_FAILURE_WINDOW_SECONDS: Final[int] = 600
LOGIN_LOCKOUT_SECONDS: Final[int] = 900

#: Admin session lifetimes. Brief: 15 min access, 8 h rotating refresh.
ACCESS_TOKEN_TTL_SECONDS: Final[int] = 15 * 60
REFRESH_TOKEN_TTL_SECONDS: Final[int] = 8 * 60 * 60

#: Device liveness. offline when now - last_heartbeat > 3 beats + 60 s.
OFFLINE_MISSED_BEATS: Final[int] = 3
OFFLINE_GRACE_SECONDS: Final[int] = 60

#: Pagination.
PAGE_SIZE = Bound(default=50, minimum=1, maximum=200)
