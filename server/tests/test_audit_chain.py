"""Audit hash chain tests.

The requirement is that tampering is DETECTABLE, so these tests are mostly about
damaging a chain in different ways and checking each one is caught, with the
right sequence number reported.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime, timedelta

import pytest

from ubuntuguard.services.audit_chain import (
    GENESIS_PREV_HASH,
    AuditEntry,
    ChainedAuditEntry,
    chain,
    compute_entry_hash,
    format_timestamp,
    verify_chain,
)

BASE = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)

ACTIONS = [
    ("login_success", "user", "u-1"),
    ("enrollment_token_created", "enrollment_token", "t-1"),
    ("device_enrolled", "device", "d-1"),
    ("policy_created", "policy", "p-1"),
    ("device_revoked", "device", "d-1"),
]


def build_chain(count: int = 5) -> list[ChainedAuditEntry]:
    rows: list[ChainedAuditEntry] = []
    prev = GENESIS_PREV_HASH
    for index in range(count):
        action, target_type, target_id = ACTIONS[index % len(ACTIONS)]
        entry = AuditEntry(
            seq=index + 1,
            occurred_at=BASE + timedelta(seconds=index),
            action=action,
            actor_id="u-1",
            actor_role="it_admin",
            target_type=target_type,
            target_id=target_id,
            request_id=f"req-{index}",
            detail_json=json.dumps({"i": index}, separators=(",", ":")).encode(),
        )
        row = chain(entry, prev)
        rows.append(row)
        prev = row.entry_hash
    return rows


def test_a_well_formed_chain_verifies() -> None:
    result = verify_chain(build_chain())
    assert result.ok is True
    assert result.checked == 5
    assert result.broken_at_seq is None


def test_empty_chain_verifies() -> None:
    assert verify_chain([]).ok is True


def test_first_entry_chains_to_genesis() -> None:
    rows = build_chain(1)
    assert rows[0].prev_hash == GENESIS_PREV_HASH
    assert len(GENESIS_PREV_HASH) == 32


def test_a_forged_genesis_is_detected() -> None:
    rows = build_chain(3)
    rows[0] = dataclasses.replace(rows[0], prev_hash=b"\x01" * 32)
    result = verify_chain(rows)
    assert result.ok is False
    assert result.broken_at_seq == 1
    assert "genesis" in (result.reason or "")


def test_modifying_a_field_is_detected() -> None:
    """The core requirement: an edited row stops matching its stored hash."""
    rows = build_chain(5)
    tampered_entry = dataclasses.replace(rows[2].entry, action="login_failure")
    rows[2] = dataclasses.replace(rows[2], entry=tampered_entry)

    result = verify_chain(rows)
    assert result.ok is False
    assert result.broken_at_seq == 3
    assert "altered" in (result.reason or "")


def test_modifying_the_detail_blob_is_detected() -> None:
    """Hashing the exact stored bytes means detail is covered too."""
    rows = build_chain(4)
    tampered_entry = dataclasses.replace(rows[1].entry, detail_json=b'{"i":999}')
    rows[1] = dataclasses.replace(rows[1], entry=tampered_entry)

    result = verify_chain(rows)
    assert result.ok is False
    assert result.broken_at_seq == 2


def test_deleting_a_row_is_detected() -> None:
    """Deletion is the attack an append-only log exists to stop, and it shows up
    as a gap in `seq` rather than as a hash mismatch.
    """
    rows = build_chain(5)
    del rows[2]
    result = verify_chain(rows)
    assert result.ok is False
    assert result.broken_at_seq == 4
    assert "deleted or reordered" in (result.reason or "")


def test_reordering_rows_is_detected() -> None:
    rows = build_chain(5)
    rows[1], rows[2] = rows[2], rows[1]
    result = verify_chain(rows)
    assert result.ok is False


def test_re_parenting_a_row_is_detected() -> None:
    """A row whose hash is self-consistent but points at the wrong predecessor.

    This is what a careful attacker produces: they recompute the hash so the row
    verifies on its own, and the chain link is the only thing that catches them.
    """
    rows = build_chain(4)
    wrong_parent = b"\x02" * 32
    fixed_entry = rows[2].entry
    rows[2] = ChainedAuditEntry(
        entry=fixed_entry,
        prev_hash=wrong_parent,
        entry_hash=compute_entry_hash(wrong_parent, fixed_entry),
    )
    result = verify_chain(rows)
    assert result.ok is False
    assert result.broken_at_seq == 3
    assert "prev_hash" in (result.reason or "")


def test_verifying_a_mid_log_page_does_not_require_genesis() -> None:
    """The dashboard pages the audit log, so verification must work on a slice."""
    rows = build_chain(6)
    page = rows[2:]
    assert verify_chain(page, expect_genesis=False).ok is True


def test_hash_is_deterministic() -> None:
    first = build_chain(3)
    second = build_chain(3)
    assert [r.entry_hash for r in first] == [r.entry_hash for r in second]


def test_hash_changes_when_any_field_changes() -> None:
    entry = build_chain(1)[0].entry
    baseline = compute_entry_hash(GENESIS_PREV_HASH, entry)
    for field, value in [
        ("seq", 2),
        ("action", "other"),
        ("actor_id", "u-2"),
        ("actor_role", "auditor"),
        ("target_type", "policy"),
        ("target_id", "x"),
        ("request_id", "other"),
        ("detail_json", b"{}"),
        ("occurred_at", BASE + timedelta(seconds=1)),
    ]:
        changed = dataclasses.replace(entry, **{field: value})
        assert compute_entry_hash(GENESIS_PREV_HASH, changed) != baseline, (
            f"changing {field} did not change the hash"
        )


def test_none_and_empty_actor_hash_differently() -> None:
    """Relies on the presence-byte encoding in canonical.lp_opt_str."""
    entry = build_chain(1)[0].entry
    with_none = dataclasses.replace(entry, actor_id=None)
    with_empty = dataclasses.replace(entry, actor_id="")
    assert compute_entry_hash(GENESIS_PREV_HASH, with_none) != compute_entry_hash(
        GENESIS_PREV_HASH, with_empty
    )


def test_timestamp_format_is_fixed_width() -> None:
    """Six microsecond digits and a literal Z, always.

    A variable-width timestamp would hash differently after a database
    round-trip and break verification on read-back.
    """
    assert format_timestamp(BASE) == "2026-10-29T12:00:00.000000Z"
    assert format_timestamp(BASE.replace(microsecond=5)) == "2026-10-29T12:00:00.000005Z"


def test_timestamp_normalises_to_utc() -> None:
    tz = __import__("datetime").timezone(timedelta(hours=5, minutes=30))
    assert format_timestamp(BASE.astimezone(tz)) == format_timestamp(BASE)


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        format_timestamp(datetime(2026, 10, 29, 12, 0, 0))  # noqa: DTZ001


def test_prev_hash_must_be_32_bytes() -> None:
    entry = build_chain(1)[0].entry
    with pytest.raises(ValueError, match="32 bytes"):
        compute_entry_hash(b"short", entry)


def test_entry_rejects_invalid_construction() -> None:
    with pytest.raises(ValueError, match="seq starts at 1"):
        AuditEntry(seq=0, occurred_at=BASE, action="x")
    with pytest.raises(ValueError, match="must not be empty"):
        AuditEntry(seq=1, occurred_at=BASE, action="")
