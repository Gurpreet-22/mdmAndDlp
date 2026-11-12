"""Typed errors and the closed reason-code vocabulary.

Every failure the agent reports to the server carries a `reason_code` drawn
from a closed set. That set is defined once, here, and is the same vocabulary
as the `reason_code` enum in `schemas/event.agent.v1.schema.json` and the
`reason_code` column on the policy-status API. One vocabulary end to end means
the dashboard can group failures without parsing free text.

`tests/test_reason_codes_match_schema.py` asserts this module and the committed
schema still agree, because a reason code the server has never heard of is a
report that silently does nothing.

The exception hierarchy mirrors `PolicyVerificationError` and its subclasses in
`server/src/ubuntuguard/services/policy_signing.py`, so a failure means the same
thing on both sides of the wire.
"""

from __future__ import annotations

from typing import Final


class ReasonCode:
    """The closed vocabulary. String constants, not an Enum.

    Not an Enum because these values are serialized into JSON documents that a
    JSON Schema validates against a list of strings, and plain constants remove
    one `.value` from every call site without losing anything.
    """

    # Signature and envelope verification
    SIGNATURE_INVALID: Final[str] = "signature_invalid"
    UNKNOWN_KEY_ID: Final[str] = "unknown_key_id"
    PAYLOAD_TOO_LARGE: Final[str] = "payload_too_large"
    HASH_MISMATCH: Final[str] = "hash_mismatch"

    # Admission: is this policy for us, and is it new enough
    SCOPE_MISMATCH: Final[str] = "scope_mismatch"
    VERSION_NOT_NEWER: Final[str] = "version_not_newer"
    ENVELOPE_EXPIRED: Final[str] = "envelope_expired"
    CLOCK_SKEW_EXCEEDED: Final[str] = "clock_skew_exceeded"

    # Parsing and semantic validation
    SCHEMA_INVALID: Final[str] = "schema_invalid"
    UNKNOWN_FIELD: Final[str] = "unknown_field"
    INVARIANT_VIOLATION: Final[str] = "invariant_violation"
    CAPABILITY_MISSING: Final[str] = "capability_missing"

    # Apply, verify and rollback lifecycle
    SNAPSHOT_FAILED: Final[str] = "snapshot_failed"
    ENFORCE_FAILED: Final[str] = "enforce_failed"
    ENFORCER_UNAVAILABLE: Final[str] = "enforcer_unavailable"
    ENFORCER_REJECTED: Final[str] = "enforcer_rejected"
    VERIFY_FAILED: Final[str] = "verify_failed"
    VERIFY_DRIFT: Final[str] = "verify_drift"
    ROLLBACK_FAILED: Final[str] = "rollback_failed"

    # Operational
    VALUE_CLAMPED: Final[str] = "value_clamped"
    QUEUE_FULL: Final[str] = "queue_full"
    UNKNOWN: Final[str] = "unknown"


#: Every code above. Compared against the committed schema by the drift test.
ALL_REASON_CODES: Final[frozenset[str]] = frozenset(
    value
    for name, value in vars(ReasonCode).items()
    if not name.startswith("_") and isinstance(value, str)
)


class AgentError(Exception):
    """Base for every error the agent raises deliberately.

    `reason_code` is what gets reported. The exception message is for the local
    operator log and must never carry a token, key or certificate private
    material - the logging redaction filter is a safety net, not a licence.
    """

    reason_code: str = ReasonCode.UNKNOWN


class ConfigError(AgentError):
    """Configuration is missing, malformed or refuses a security invariant."""

    reason_code = ReasonCode.SCHEMA_INVALID


class InsecureFileError(AgentError):
    """A file that must be private is readable by group or others.

    Mirrors the server's `KeyFilePermissionError`: a private key the rest of the
    machine can read is a failure to stop on, not to note and continue past.
    """

    reason_code = ReasonCode.INVARIANT_VIOLATION


class IdentityError(AgentError):
    """The local device identity is absent, unusable or self-inconsistent.

    Raised when the certificate on disk does not match the private key beside
    it, when a stored CSR does not match its key, or when an issued
    certificate fails to verify against the CA chain it arrived with. Every one
    of those means the agent cannot prove who it is, so the only safe
    behaviour is to stop and say which check failed.
    """

    reason_code = ReasonCode.INVARIANT_VIOLATION


# --------------------------------------------------------------------------- #
# Transport and enrollment
# --------------------------------------------------------------------------- #
#
# A note on the reason codes below, because they are the honest answer rather
# than the tidy one.
#
# `ReasonCode` is a CLOSED vocabulary, shared byte for byte with the
# `reason_code` enum in `schemas/event.agent.v1.schema.json` and asserted in
# both directions by `tests/test_schema_agreement.py`. It was designed for
# POLICY outcomes - verification, admission, apply, rollback - and it contains
# no code for "the server was unreachable" or "the token was rejected",
# because when it was written the agent made no network requests.
#
# So these exceptions carry `UNKNOWN`. That is deliberately not a silent
# choice:
#
#   - Adding `network_unreachable` and `enrollment_rejected` to the enum would
#     be the better long-term answer, but it changes a committed schema that
#     the server validates against and that `tools/validate_phase0.py` gates.
#     That is a contract change, and it belongs in a change that is about the
#     contract.
#   - Nothing is lost today, because there is no event queue until Phase 7.
#     These codes reach the local journal only, via `Runtime._run_task`, and
#     the exception type and message carry the real detail.
#
# When the event queue lands, revisit this: a fleet-wide dashboard that groups
# every connectivity failure under "unknown" is not useful, and that is the
# point at which the enum should grow.


class TransportError(AgentError):
    """The request could not be completed: DNS, TCP, TLS or a timeout.

    Distinct from `HttpStatusError` because the two mean opposite things for a
    retry. A transport failure is usually transient and the right response is
    backoff; an HTTP status is the server's considered answer and may well be
    permanent.
    """

    reason_code = ReasonCode.UNKNOWN


class TlsVerificationError(TransportError):
    """The server's TLS certificate did not verify against the configured CA.

    Separated from a plain transport failure because it must never be retried
    into submission or worked around. It means either a misconfigured
    `server_ca_bundle` or an interception attempt, and the agent cannot tell
    which, so it treats both as fatal for the request.
    """

    reason_code = ReasonCode.INVARIANT_VIOLATION


class HttpStatusError(TransportError):
    """A non-2xx response. `status` and `code` come from the problem document."""

    reason_code = ReasonCode.UNKNOWN

    def __init__(self, message: str, *, status: int, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code

    @property
    def retryable(self) -> bool:
        """Whether retrying could plausibly succeed.

        429 and 5xx are the server saying "not now". 4xx otherwise is the
        server saying "not like this", and retrying an invalid enrollment token
        until the backoff ceiling is reached only delays telling the operator
        they need a new one.
        """
        return self.status == 429 or 500 <= self.status < 600


class EnrollmentError(AgentError):
    """Enrollment could not be completed. Terminal unless stated otherwise."""

    reason_code = ReasonCode.UNKNOWN


class RenewalError(AgentError):
    """Certificate renewal could not be completed.

    Distinct from `EnrollmentError` because the recovery is different and the
    stakes are different. A failed enrollment leaves a device unmanaged; a
    failed renewal leaves a device that is managed now and will stop being
    managed when its certificate expires. The agent therefore keeps retrying a
    renewal on its ordinary schedule rather than treating a failure as
    terminal, and it never discards a working identity to attempt one.
    """

    reason_code = ReasonCode.UNKNOWN


class PolicyVerificationError(AgentError):
    """Base for envelope verification failures."""


class SignatureVerificationError(PolicyVerificationError):
    reason_code = ReasonCode.SIGNATURE_INVALID


class UnknownKeyIdError(PolicyVerificationError):
    reason_code = ReasonCode.UNKNOWN_KEY_ID


class PayloadTooLargeError(PolicyVerificationError):
    reason_code = ReasonCode.PAYLOAD_TOO_LARGE


class PayloadHashMismatchError(PolicyVerificationError):
    reason_code = ReasonCode.HASH_MISMATCH


class MalformedEnvelopeError(PolicyVerificationError):
    reason_code = ReasonCode.SCHEMA_INVALID


#: Note there is no exception for a clamped setting. A clamp is not a failure
#: and must not be raised - the agent applies the clamped value and carries the
#: record in `config.ClampRecord`, which the caller turns into a
#: `settings_clamped` event. `ReasonCode.VALUE_CLAMPED` is the code that event
#: uses.
