"""Database-backed append-only audit log.

Every write goes through `append`. That is not a convention but a requirement of
the design: the sequence number is part of the hashed content, so it has to be
chosen before the row is written, and two writers choosing it independently
would produce two rows claiming the same predecessor.

Two details that are easy to get wrong and are therefore deliberate:

**Serialisation.** Appends take a transaction-scoped advisory lock. Without it,
two concurrent appends both read the same "last row" and both chain to it,
leaving a fork that verification reports as corruption when nothing malicious
happened.

**No sequence gaps.** `seq` is computed as `max(seq) + 1` under that lock rather
than drawn from the BIGSERIAL sequence. `nextval` is not transactional: a rolled
back insert burns the number permanently, and a gap is exactly what
`verify_chain` reports as a deleted row. The column keeps its BIGSERIAL default
for safety, but this service never relies on it.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ubuntuguard.constants import PAGE_SIZE
from ubuntuguard.models import AuditLog
from ubuntuguard.services.audit_chain import (
    GENESIS_PREV_HASH,
    AuditEntry,
    ChainedAuditEntry,
    ChainVerification,
    compute_entry_hash,
    verify_chain,
)

#: Arbitrary but fixed 64-bit key for pg_advisory_xact_lock. Only this service
#: uses it, so it cannot contend with anything else.
AUDIT_LOCK_KEY = 0x5542_4E54_4755_4152

#: Actions worth recording. A closed vocabulary so the dashboard can group them
#: without parsing free text, and so a typo becomes an error rather than a row
#: nobody will ever find again.
ACTIONS = frozenset(
    {
        "login_succeeded",
        "login_failed",
        "logout",
        "token_refreshed",
        "token_reuse_detected",
        "user_created",
        "user_role_changed",
        "user_disabled",
        # Operator set a password on an existing account, via the CLI. Records
        # that the credential changed; never the credential itself.
        "user_password_set",
        # Every live session for an account was revoked without disabling it.
        # Separate from `user_disabled` because the two have different
        # consequences and an operator needs to tell them apart in the log.
        "user_sessions_revoked",
        "enrollment_token_created",
        "enrollment_token_revoked",
        "device_registered",
        "device_enrolled",
        "device_enrollment_failed",
        "device_revoked",
        # A device-plane request that failed authentication: a revoked device
        # still calling in, a certificate this CA did not sign, or a request
        # that reached the backend without coming through the trusted proxy.
        # Rate-limited to one row per device+reason per hour, see api/deps.py.
        "unauthorized_device_communication",
        "clone_suspected",
        "certificate_issued",
        # --- certificate rotation ------------------------------------------ #
        # Three actions rather than one, because an auditor reading this log
        # has three different questions and they need different answers.
        #
        # `certificate_renewed` is the rotation itself. Its detail records how
        # many previous certificates it superseded, which should always be 1 -
        # anything else means a renewal was interrupted and is worth noticing.
        #
        # `certificate_renewal_retried` is a device asking again with a CSR the
        # server had already issued against, so the existing certificate was
        # returned rather than a second one. Not a failure; it means a response
        # was lost in transit, and a device doing this repeatedly has a network
        # problem worth seeing.
        #
        # `certificate_renewal_failed` is a refusal. Separate from
        # `device_enrollment_failed` because the device is already enrolled and
        # already trusted here - a device failing to renew will drop off the
        # control plane when its certificate expires, which is an operational
        # event rather than a rejected stranger.
        "certificate_renewed",
        "certificate_renewal_retried",
        "certificate_renewal_failed",
        "policy_created",
        "policy_assigned",
        "usb_exception_created",
        "usb_exception_revoked",
        "incident_status_changed",
        "audit_exported",
    }
)


class UnknownAuditActionError(ValueError):
    """Raised for an action outside `ACTIONS`."""


def serialise_detail(detail: dict[str, Any] | None) -> bytes:
    """Serialise the detail blob ONCE; these exact bytes are what gets hashed."""
    return json.dumps(
        detail or {}, separators=(",", ":"), sort_keys=True, ensure_ascii=False, default=str
    ).encode("utf-8")


def append(
    session: Session,
    *,
    action: str,
    actor_id: str | None = None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
    occurred_at: dt.datetime | None = None,
) -> ChainedAuditEntry:
    """Append one entry, chained to the current head.

    Must run inside the caller's transaction so the audit row and the change it
    describes commit or roll back together. An audited action that succeeded
    while its audit row was lost is worse than no audit log, because the gap is
    invisible.
    """
    if action not in ACTIONS:
        raise UnknownAuditActionError(
            f"{action!r} is not a known audit action; add it to ACTIONS deliberately"
        )

    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": AUDIT_LOCK_KEY})

    head = session.execute(
        select(AuditLog.seq, AuditLog.entry_hash).order_by(AuditLog.seq.desc()).limit(1)
    ).first()
    next_seq = 1 if head is None else head.seq + 1
    prev_hash = GENESIS_PREV_HASH if head is None else head.entry_hash

    entry = AuditEntry(
        seq=next_seq,
        occurred_at=occurred_at or dt.datetime.now(dt.UTC),
        action=action,
        actor_id=actor_id,
        actor_role=actor_role,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id,
        detail_json=serialise_detail(detail),
    )
    entry_hash = compute_entry_hash(prev_hash, entry)

    session.add(
        AuditLog(
            seq=entry.seq,
            occurred_at=entry.occurred_at,
            action=entry.action,
            actor_id=entry.actor_id,
            actor_role=entry.actor_role,
            target_type=entry.target_type,
            target_id=entry.target_id,
            request_id=entry.request_id,
            detail_json=entry.detail_json,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
    )
    session.flush()
    return ChainedAuditEntry(entry=entry, prev_hash=prev_hash, entry_hash=entry_hash)


def _to_chained(row: AuditLog) -> ChainedAuditEntry:
    return ChainedAuditEntry(
        entry=AuditEntry(
            seq=row.seq,
            occurred_at=row.occurred_at,
            action=row.action,
            actor_id=row.actor_id,
            actor_role=row.actor_role,
            target_type=row.target_type,
            target_id=row.target_id,
            request_id=row.request_id,
            detail_json=row.detail_json,
        ),
        prev_hash=row.prev_hash,
        entry_hash=row.entry_hash,
    )


def read_page(
    session: Session, *, after_seq: int | None = None, limit: int = PAGE_SIZE.default
) -> list[AuditLog]:
    """Read a page in ascending sequence order.

    Ascending, not descending: the chain can only be verified in the order it
    was written, so paging forward keeps a page independently checkable.
    """
    statement = select(AuditLog).order_by(AuditLog.seq)
    if after_seq is not None:
        statement = statement.where(AuditLog.seq > after_seq)
    return list(session.scalars(statement.limit(limit)))


def verify(
    session: Session, *, start_seq: int | None = None, limit: int | None = None
) -> ChainVerification:
    """Recompute the chain and report the first break.

    `start_seq` verifies a slice, for a log too large to walk in one request.
    A slice starting mid-log cannot be expected to chain to genesis, which is
    why `expect_genesis` is derived rather than assumed.
    """
    statement = select(AuditLog).order_by(AuditLog.seq)
    if start_seq is not None:
        statement = statement.where(AuditLog.seq >= start_seq)
    if limit is not None:
        statement = statement.limit(limit)

    rows = [_to_chained(row) for row in session.scalars(statement)]
    return verify_chain(rows, expect_genesis=(start_seq is None or start_seq <= 1))


def head_seq(session: Session) -> int:
    """Current highest sequence number, or 0 for an empty log."""
    value = session.execute(select(AuditLog.seq).order_by(AuditLog.seq.desc()).limit(1)).scalar()
    return int(value or 0)
