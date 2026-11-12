"""Hash-chained audit log.

Each row's hash covers the previous row's hash, so altering or removing any row
invalidates every row after it. Combined with a database role that holds only
SELECT and INSERT on `audit_logs`, that gives two independent barriers: the role
stops an edit through the application, and the chain makes an edit made around
the application detectable.

Neither barrier stops someone with full database superuser access from rewriting
the table and recomputing every hash. Detecting that needs the chain head
anchored somewhere outside the database - an external notary, or simply writing
the head hash to append-only storage. Out of scope for the prototype, and
recorded in the known-limitations page rather than glossed over.

Byte-exactness applies here for the same reason it applies to policy signing:
`detail` is hashed as the exact bytes stored, never as a re-serialized object,
because Python's dict ordering is not a stable part of the on-disk format.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from ubuntuguard.canonical import lp, lp_opt_str, lp_str, lp_u64
from ubuntuguard.constants import AUDIT_CHAIN_DOMAIN

#: The first row's predecessor. 32 zero bytes, matching the SHA-256 digest width.
GENESIS_PREV_HASH: bytes = bytes(32)

HASH_BYTES = 32


def format_timestamp(moment: datetime) -> str:
    """Render a timestamp deterministically for hashing.

    Always UTC, always six digits of microseconds, always a literal Z. Any
    variation here - a dropped trailing zero, a +00:00 offset instead of Z -
    produces a different hash for the same instant and breaks verification on
    read-back. PostgreSQL `timestamptz` stores microsecond resolution, so this
    round-trips exactly.
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One audited action.

    `detail_json` is the exact byte string persisted in the database. The caller
    serializes it once; nothing downstream re-serializes it.
    """

    seq: int
    occurred_at: datetime
    action: str
    actor_id: str | None = None
    actor_role: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    request_id: str | None = None
    detail_json: bytes = b"{}"

    def __post_init__(self) -> None:
        if self.seq < 1:
            raise ValueError("audit seq starts at 1")
        if not self.action:
            raise ValueError("audit action must not be empty")


@dataclass(frozen=True, slots=True)
class ChainedAuditEntry:
    """An entry together with the chain hashes stored alongside it."""

    entry: AuditEntry
    prev_hash: bytes
    entry_hash: bytes


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Result of walking a chain."""

    ok: bool
    checked: int
    broken_at_seq: int | None = None
    reason: str | None = None


def compute_entry_hash(prev_hash: bytes, entry: AuditEntry) -> bytes:
    """SHA-256 over the domain separator, the previous hash and every field."""
    if len(prev_hash) != HASH_BYTES:
        raise ValueError(f"prev_hash must be {HASH_BYTES} bytes, got {len(prev_hash)}")

    payload = b"".join(
        (
            AUDIT_CHAIN_DOMAIN,
            lp(prev_hash),
            lp_u64(entry.seq),
            lp_str(format_timestamp(entry.occurred_at)),
            lp_str(entry.action),
            lp_opt_str(entry.actor_id),
            lp_opt_str(entry.actor_role),
            lp_opt_str(entry.target_type),
            lp_opt_str(entry.target_id),
            lp_opt_str(entry.request_id),
            lp(entry.detail_json),
        )
    )
    return hashlib.sha256(payload).digest()


def chain(entry: AuditEntry, prev_hash: bytes = GENESIS_PREV_HASH) -> ChainedAuditEntry:
    """Attach chain hashes to an entry, ready to insert."""
    return ChainedAuditEntry(
        entry=entry,
        prev_hash=prev_hash,
        entry_hash=compute_entry_hash(prev_hash, entry),
    )


def verify_chain(
    rows: Sequence[ChainedAuditEntry],
    *,
    expect_genesis: bool = True,
) -> ChainVerification:
    """Walk a contiguous run of rows ordered by `seq` and report the first break.

    Detects four distinct kinds of damage:

    - a modified field, because the recomputed hash stops matching;
    - a deleted row, because `seq` skips a value;
    - a reordered row, because `seq` is no longer ascending;
    - a re-parented row, because `prev_hash` stops matching its predecessor.

    `expect_genesis` is for verifying a page from the middle of the log, where
    the first row legitimately has a non-genesis predecessor.
    """
    if not rows:
        return ChainVerification(ok=True, checked=0)

    first = rows[0]
    if expect_genesis and first.entry.seq == 1 and first.prev_hash != GENESIS_PREV_HASH:
        return ChainVerification(
            ok=False,
            checked=0,
            broken_at_seq=first.entry.seq,
            reason="first entry does not chain to the genesis hash",
        )

    previous: ChainedAuditEntry | None = None
    for index, row in enumerate(rows):
        if previous is not None:
            expected_seq = previous.entry.seq + 1
            if row.entry.seq != expected_seq:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    broken_at_seq=row.entry.seq,
                    reason=(
                        f"sequence jumped from {previous.entry.seq} to {row.entry.seq}; "
                        "a row was deleted or reordered"
                    ),
                )
            if row.prev_hash != previous.entry_hash:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    broken_at_seq=row.entry.seq,
                    reason="prev_hash does not match the preceding entry_hash",
                )

        recomputed = compute_entry_hash(row.prev_hash, row.entry)
        if recomputed != row.entry_hash:
            return ChainVerification(
                ok=False,
                checked=index,
                broken_at_seq=row.entry.seq,
                reason="entry_hash does not match the entry contents; the row was altered",
            )
        previous = row

    return ChainVerification(ok=True, checked=len(rows))
