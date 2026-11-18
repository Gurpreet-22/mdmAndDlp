"""Tests for the usb_control policy pipeline: repositories, building, signing.

In-memory SQLite, like `test_employee_and_assignment.py`, so these run with no
database configured. The route-level behaviour that needs a real HTTP round
trip and a real database lives in `test_api_integration.py`.

The emphasis is on the properties the feature's safety rests on rather than on
coverage of each function:

  - a policy that could lock a user out of their own machine is refused before
    it is signed, so it never acquires a version number
  - versions never go backwards or repeat, because the agent's downgrade
    rejection depends on it
  - the signed bytes are the stored bytes are the sent bytes
  - scope resolution is deterministic and device-specific beats fleet
  - a status report is evidence, not a claim
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ubuntuguard import repositories
from ubuntuguard.models import Base, Device, User
from ubuntuguard.services import policy as svc
from ubuntuguard.services.policy_signing import (
    PayloadHashMismatchError,
    PolicySigner,
    verify_envelope,
)

UTC = dt.UTC


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as active:
        yield active


@pytest.fixture
def actor(session: Session) -> User:
    user = User(
        email="admin@example.com",
        password_hash="x",
        role="super_admin",
        is_active=True,
    )
    session.add(user)
    session.flush()
    return user


@pytest.fixture
def device(session: Session) -> Device:
    # `enrolled_at` is required for any status other than `pending`, by the
    # enrolled_at_matches_status check constraint: the model refuses an active
    # device that never enrolled.
    row = Device(
        hostname="laptop-1",
        status="active",
        enrolled_at=dt.datetime(2026, 1, 1, tzinfo=UTC),
    )
    session.add(row)
    session.flush()
    return row


@pytest.fixture
def signer(tmp_path) -> PolicySigner:
    from ubuntuguard.services.keys import generate_policy_signing_key

    path = tmp_path / "policy-signing.key"
    generate_policy_signing_key(path)
    return PolicySigner.from_file(path)


# --------------------------------------------------------------------------- #
# Building the payload: the refusals that matter
# --------------------------------------------------------------------------- #


def _usb_control_schema() -> dict:
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "schemas" / "policy.usb_control.v1.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_built_payload_agrees_with_the_published_schema() -> None:
    """Checked against the schema file itself, with the standard library.

    `jsonschema` is deliberately not a server dependency -- schema validation
    lives in the separate tools venv that `make verify` uses -- so rather than
    add one, this reads the schema and asserts the parts that matter: the exact
    required key set, no extra keys where the schema forbids them, and every
    value inside the published enums.

    The point is that what this service generates must satisfy the contract
    the agent and the dashboard were both written against. Our own validators
    agreeing with themselves would prove nothing.
    """
    schema = _usb_control_schema()
    required = set(schema["required"])
    allowed = set(schema["properties"])
    mode_enum = set(schema["properties"]["mode"]["enum"])
    protected_enum = set(schema["properties"]["protected_classes"]["items"]["enum"])
    allow_enum = set(schema["properties"]["always_allow_classes"]["items"]["enum"])
    reporting_required = set(schema["properties"]["reporting"]["required"])

    assert schema["additionalProperties"] is False

    for mode in sorted(mode_enum):
        payload = svc.build_usb_control_payload(mode=mode)

        assert required <= set(payload), f"{mode}: missing {required - set(payload)}"
        assert set(payload) <= allowed, f"{mode}: extra {set(payload) - allowed}"
        assert payload["schema"] == schema["properties"]["schema"]["const"]
        assert payload["mode"] in mode_enum
        assert set(payload["protected_classes"]) <= protected_enum
        assert set(payload["always_allow_classes"]) <= allow_enum
        assert set(payload["reporting"]) == reporting_required

        # Bounds the schema states, which our defaults must respect.
        assert 1 <= len(payload["protected_classes"]) <= 4
        assert 2 <= len(payload["always_allow_classes"]) <= 16

    # And the enums our own code offers must not drift from the published ones.
    assert set(svc.PROTECTED_CLASS_NAMES) == protected_enum
    assert set(svc.ALWAYS_ALLOW_CLASS_NAMES) == allow_enum


def test_a_built_allowlist_entry_matches_the_schema_shape() -> None:
    """The nested shapes the schema pins, since a wrong one is only discovered
    on the endpoint otherwise."""
    schema = _usb_control_schema()
    defs = schema["$defs"]
    entry_required = set(defs["allowlistEntry"]["required"])
    match_required = set(defs["deviceMatch"]["required"])

    entry = {
        "entry_id": str(uuid.uuid4()),
        "match": {
            "vendor_id": "0781",
            "product_id": "5583",
            "serial": "SN1",
            "serial_match": "exact",
        },
        "label": "Finance stick",
        "added_by": "admin",
        "added_at": "2026-01-01T00:00:00Z",
    }
    payload = svc.build_usb_control_payload(mode="allowlist_enforce", allowlist=[entry])
    built = payload["allowlist"][0]
    assert entry_required <= set(built)
    assert set(built) <= set(defs["allowlistEntry"]["properties"])
    assert match_required <= set(built["match"])
    assert set(built["match"]) <= set(defs["deviceMatch"]["properties"])


def test_always_allow_must_contain_hid_and_hub() -> None:
    """The lockout guard.

    Checked here as well as in the schema and again on the endpoint. Three
    places is not redundancy worth removing: this one stops the policy being
    created, so it never reaches a laptop at all.
    """
    with pytest.raises(svc.PolicyError) as caught:
        svc.build_usb_control_payload(
            mode="block_all_storage", always_allow_classes=["audio", "video"]
        )
    assert "hid" in str(caught.value)
    assert "lock the user out" in str(caught.value)


def test_the_two_class_vocabularies_are_disjoint() -> None:
    """Which is why a class can never be both protected and always-allowed.

    `build_usb_control_payload` does check for an overlap, and that check is
    currently unreachable: no name appears in both enums, so a name from the
    wrong list is refused as unknown before the overlap test runs. It is kept
    as defence against a future edit that adds a name to both lists, and this
    test records that the guarantee presently comes from the vocabularies
    rather than from the check.
    """
    assert not set(svc.PROTECTED_CLASS_NAMES) & set(svc.ALWAYS_ALLOW_CLASS_NAMES)


def test_a_protected_class_name_is_refused_in_the_always_allow_list() -> None:
    with pytest.raises(svc.PolicyError) as caught:
        svc.build_usb_control_payload(
            mode="block_all_storage",
            protected_classes=["mass_storage"],
            always_allow_classes=["hid", "hub", "mass_storage"],
        )
    assert "mass_storage" in str(caught.value)


def test_unknown_class_names_are_refused_not_dropped() -> None:
    """Silently dropping a class would enforce less than the dashboard claims."""
    with pytest.raises(svc.PolicyError):
        svc.build_usb_control_payload(
            mode="block_all_storage", protected_classes=["mass_storage", "nonsense"]
        )
    with pytest.raises(svc.PolicyError):
        svc.build_usb_control_payload(
            mode="block_all_storage", always_allow_classes=["hid", "hub", "nonsense"]
        )


def test_image_class_is_not_protected_by_default() -> None:
    """Blocking class 06 stops phone charging, so it is opt-in."""
    payload = svc.build_usb_control_payload(mode="block_all_storage")
    assert payload["protected_classes"] == ["mass_storage"]
    assert "image" not in payload["protected_classes"]


def test_an_exception_may_not_outlast_the_maximum() -> None:
    """A grant nobody revisits is indistinguishable from a permanent hole."""
    created = dt.datetime(2026, 1, 1, tzinfo=UTC)
    too_long = {
        "exception_id": str(uuid.uuid4()),
        "match": {"vendor_id": "0781", "product_id": "5583", "serial_match": "any"},
        "reason": "a long enough justification",
        "created_by": "admin",
        "created_at": created.isoformat(),
        "expires_at": (created + dt.timedelta(hours=48)).isoformat(),
    }
    with pytest.raises(svc.PolicyError) as caught:
        svc.build_usb_control_payload(mode="block_all_storage", exceptions=[too_long])
    assert "maximum" in str(caught.value)


def test_an_exception_must_expire_after_it_starts() -> None:
    created = dt.datetime(2026, 1, 1, tzinfo=UTC)
    backwards = {
        "exception_id": str(uuid.uuid4()),
        "match": {"vendor_id": "0781", "product_id": "5583", "serial_match": "any"},
        "reason": "a long enough justification",
        "created_by": "admin",
        "created_at": created.isoformat(),
        "expires_at": (created - dt.timedelta(hours=1)).isoformat(),
    }
    with pytest.raises(svc.PolicyError):
        svc.build_usb_control_payload(mode="block_all_storage", exceptions=[backwards])


# --------------------------------------------------------------------------- #
# Versioning
# --------------------------------------------------------------------------- #


def test_versions_start_at_one_and_increase(session: Session, actor, signer) -> None:
    for expected in (1, 2, 3):
        row, _ = svc.issue_policy(
            session,
            signer=signer,
            policy_type="usb_control",
            payload=svc.build_usb_control_payload(mode="monitor_only"),
            scope_kind="fleet",
            scope_id="fleet",
            created_by=actor.id,
        )
        assert row.version == expected


def test_versions_are_per_scope(session: Session, actor, signer) -> None:
    """Two devices each start at 1; a shared counter would be confusing and
    would make one device's history depend on another's."""
    first, _ = svc.issue_policy(
        session,
        signer=signer,
        policy_type="usb_control",
        payload=svc.build_usb_control_payload(mode="monitor_only"),
        scope_kind="device",
        scope_id="device-a",
        created_by=actor.id,
    )
    second, _ = svc.issue_policy(
        session,
        signer=signer,
        policy_type="usb_control",
        payload=svc.build_usb_control_payload(mode="monitor_only"),
        scope_kind="device",
        scope_id="device-b",
        created_by=actor.id,
    )
    assert first.version == second.version == 1


def test_next_version_uses_max_not_count(session: Session, actor, signer) -> None:
    """A reused version is one the agent refuses as a downgrade.

    Counting rows would reissue a number if one were ever removed; taking the
    maximum does not.
    """
    for _ in range(3):
        svc.issue_policy(
            session,
            signer=signer,
            policy_type="usb_control",
            payload=svc.build_usb_control_payload(mode="monitor_only"),
            scope_kind="fleet",
            scope_id="fleet",
            created_by=actor.id,
        )

    # Selected by version rather than by list order: all three were created in
    # one transaction, so their created_at values are identical and the
    # newest-first ordering between them is not defined.
    from ubuntuguard.models import Policy

    oldest = session.query(Policy).filter(Policy.version == 1).one()
    session.delete(oldest)
    session.flush()

    assert (
        repositories.next_policy_version(
            session, policy_type="usb_control", scope_kind="fleet", scope_id="fleet"
        )
        == 4
    )


# --------------------------------------------------------------------------- #
# Signing: the bytes must not change anywhere along the way
# --------------------------------------------------------------------------- #


def test_stored_bytes_are_the_signed_bytes(session: Session, actor, signer) -> None:
    payload = svc.build_usb_control_payload(mode="block_all_storage")
    row, envelope = svc.issue_policy(
        session,
        signer=signer,
        policy_type="usb_control",
        payload=payload,
        scope_kind="fleet",
        scope_id="fleet",
        created_by=actor.id,
    )
    assert base64.b64decode(envelope["payload_b64"]) == row.payload
    assert envelope["payload_sha256"] == row.payload_sha256
    assert envelope["signature"]["value_b64"] == row.signature_b64


def test_rebuilt_envelope_still_verifies(session: Session, actor, signer) -> None:
    """`envelope_for` reassembles from the row rather than re-signing.

    Re-signing would produce a new `issued_at`, which the agent would read as a
    new policy on every poll. Reassembly has to leave the signature intact.
    """
    row, original = svc.issue_policy(
        session,
        signer=signer,
        policy_type="usb_control",
        payload=svc.build_usb_control_payload(mode="allowlist_enforce"),
        scope_kind="device",
        scope_id="device-a",
        created_by=actor.id,
    )
    rebuilt = svc.envelope_for(row)
    assert rebuilt == original

    trusted = {signer.key_id: signer.public_key}
    assert verify_envelope(rebuilt, trusted) == row.payload


def test_a_tampered_payload_fails_verification(session: Session, actor, signer) -> None:
    row, _ = svc.issue_policy(
        session,
        signer=signer,
        policy_type="usb_control",
        payload=svc.build_usb_control_payload(mode="block_all_storage"),
        scope_kind="fleet",
        scope_id="fleet",
        created_by=actor.id,
    )
    envelope = svc.envelope_for(row)
    forged = dict(envelope)
    swapped = svc.build_usb_control_payload(mode="monitor_only")
    forged["payload_b64"] = base64.b64encode(
        json.dumps(swapped, separators=(",", ":"), sort_keys=True).encode()
    ).decode()

    # Named rather than a blind `Exception`: the point of the test is that the
    # payload hash in the signed envelope is what binds the signature to the
    # bytes, so swapping the payload must fail on the hash and not merely fail
    # somehow. A blind assertion would also pass on a typo in the call.
    with pytest.raises(PayloadHashMismatchError):
        verify_envelope(forged, {signer.key_id: signer.public_key})


# --------------------------------------------------------------------------- #
# Scope resolution
# --------------------------------------------------------------------------- #


def _issue(session, signer, actor, *, mode, scope_kind, scope_id):
    row, _ = svc.issue_policy(
        session,
        signer=signer,
        policy_type="usb_control",
        payload=svc.build_usb_control_payload(mode=mode),
        scope_kind=scope_kind,
        scope_id=scope_id,
        created_by=actor.id,
    )
    return row


def test_no_policy_resolves_to_none(session: Session, device) -> None:
    assert (
        repositories.effective_policy_for_device(
            session, device_id=device.id, policy_type="usb_control"
        )
        is None
    )


def test_fleet_policy_applies_without_assignment(session: Session, device, actor, signer) -> None:
    fleet = _issue(
        session, signer, actor, mode="monitor_only", scope_kind="fleet", scope_id="fleet"
    )
    found = repositories.effective_policy_for_device(
        session, device_id=device.id, policy_type="usb_control"
    )
    assert found is not None
    assert found.id == fleet.id


def test_device_assignment_beats_fleet(session: Session, device, actor, signer) -> None:
    _issue(session, signer, actor, mode="monitor_only", scope_kind="fleet", scope_id="fleet")
    specific = _issue(
        session,
        signer,
        actor,
        mode="block_all_storage",
        scope_kind="device",
        scope_id=str(device.id),
    )
    repositories.assign_policy(
        session, policy_id=specific.id, device_id=device.id, assigned_by=actor.id
    )
    found = repositories.effective_policy_for_device(
        session, device_id=device.id, policy_type="usb_control"
    )
    assert found is not None
    assert found.id == specific.id


def test_highest_version_wins_within_a_scope(session: Session, device, actor, signer) -> None:
    for mode in ("monitor_only", "allowlist_enforce", "block_all_storage"):
        row = _issue(
            session,
            signer,
            actor,
            mode=mode,
            scope_kind="device",
            scope_id=str(device.id),
        )
        repositories.unassign_policies_of_type(
            session, device_id=device.id, policy_type="usb_control"
        )
        repositories.assign_policy(
            session, policy_id=row.id, device_id=device.id, assigned_by=actor.id
        )

    found = repositories.effective_policy_for_device(
        session, device_id=device.id, policy_type="usb_control"
    )
    assert found is not None
    assert found.version == 3
    assert svc.decoded_payload(found)["mode"] == "block_all_storage"


def test_unassigning_retires_rather_than_deletes(session: Session, device, actor, signer) -> None:
    """What a laptop was under, and when, is what an auditor asks."""
    row = _issue(
        session,
        signer,
        actor,
        mode="monitor_only",
        scope_kind="device",
        scope_id=str(device.id),
    )
    repositories.assign_policy(session, policy_id=row.id, device_id=device.id, assigned_by=actor.id)
    retired = repositories.unassign_policies_of_type(
        session, device_id=device.id, policy_type="usb_control"
    )
    assert retired == 1

    from ubuntuguard.models import PolicyAssignment

    rows = session.query(PolicyAssignment).all()
    assert len(rows) == 1
    assert rows[0].unassigned_at is not None

    assert (
        repositories.effective_policy_for_device(
            session, device_id=device.id, policy_type="usb_control"
        )
        is None
    )


def test_reassigning_the_same_policy_revives_one_row(
    session: Session, device, actor, signer
) -> None:
    """policy_assignments is unique on (policy, device), so a naive insert
    would fail on the retry a flaky network produces."""
    row = _issue(
        session,
        signer,
        actor,
        mode="monitor_only",
        scope_kind="device",
        scope_id=str(device.id),
    )
    first = repositories.assign_policy(
        session, policy_id=row.id, device_id=device.id, assigned_by=actor.id
    )
    repositories.unassign_policies_of_type(session, device_id=device.id, policy_type="usb_control")
    second = repositories.assign_policy(
        session, policy_id=row.id, device_id=device.id, assigned_by=actor.id
    )
    assert first.id == second.id
    assert second.unassigned_at is None


# --------------------------------------------------------------------------- #
# What the heartbeat advertises
# --------------------------------------------------------------------------- #


def test_advertised_entry_carries_no_policy_content(
    session: Session, device, actor, signer
) -> None:
    """The heartbeat says what exists; it never pushes the thing itself.

    If a payload or a rule ever appeared in this structure, a heartbeat
    response would become a way to push content at a laptop, which is the one
    property this design does not have.
    """
    row = _issue(
        session,
        signer,
        actor,
        mode="block_all_storage",
        scope_kind="device",
        scope_id=str(device.id),
    )
    repositories.assign_policy(session, policy_id=row.id, device_id=device.id, assigned_by=actor.id)
    advertised = repositories.available_policies_for_device(session, device_id=device.id)
    assert advertised == [
        {
            "policy_type": "usb_control",
            "policy_id": str(row.id),
            "policy_version": row.version,
        }
    ]
    blob = json.dumps(advertised)
    for leak in ("payload", "allow ", "block ", "with-interface", "mass_storage"):
        assert leak not in blob


def test_nothing_is_advertised_without_a_policy(session: Session, device) -> None:
    assert repositories.available_policies_for_device(session, device_id=device.id) == []


# --------------------------------------------------------------------------- #
# Status reporting
# --------------------------------------------------------------------------- #


def test_status_is_recorded_with_the_readback(session: Session, device, actor, signer) -> None:
    row = _issue(
        session, signer, actor, mode="block_all_storage", scope_kind="fleet", scope_id="fleet"
    )
    readback = {
        "loaded_rules": ["block with-interface one-of { 08:*:* }"],
        "enforcement_bypassable_without_root": False,
    }
    stored = repositories.record_policy_status(
        session,
        device_id=device.id,
        policy_id=row.id,
        status="applied",
        verified_state=readback,
    )
    assert stored.status == "applied"
    assert stored.verified_state == readback


def test_a_later_report_replaces_the_earlier_one(session: Session, device, actor, signer) -> None:
    """One row per (device, policy): the latest report is the one that matters,
    and the audit log carries the history worth keeping."""
    row = _issue(
        session, signer, actor, mode="block_all_storage", scope_kind="fleet", scope_id="fleet"
    )
    repositories.record_policy_status(
        session,
        device_id=device.id,
        policy_id=row.id,
        status="failed",
        reason_code="enforce_failed",
    )
    repositories.record_policy_status(
        session, device_id=device.id, policy_id=row.id, status="applied"
    )

    statuses = repositories.policy_statuses_for_device(session, device_id=device.id)
    assert len(statuses) == 1
    assert statuses[0].status == "applied"
    assert statuses[0].reason_code is None


def test_long_reason_and_detail_are_truncated_to_the_column(
    session: Session, device, actor, signer
) -> None:
    row = _issue(session, signer, actor, mode="monitor_only", scope_kind="fleet", scope_id="fleet")
    stored = repositories.record_policy_status(
        session,
        device_id=device.id,
        policy_id=row.id,
        status="failed",
        reason_code="x" * 200,
        detail="y" * 2000,
    )
    assert stored.reason_code is not None
    assert len(stored.reason_code) <= 48
    assert stored.detail is not None
    assert len(stored.detail) <= 512


def test_summarise_describes_the_policy(session: Session, actor, signer) -> None:
    entry = {
        "entry_id": str(uuid.uuid4()),
        "match": {
            "vendor_id": "0781",
            "product_id": "5583",
            "serial": "SN1",
            "serial_match": "exact",
        },
        "label": "Finance stick",
        "added_by": "admin",
        "added_at": "2026-01-01T00:00:00Z",
    }
    row, _ = svc.issue_policy(
        session,
        signer=signer,
        policy_type="usb_control",
        payload=svc.build_usb_control_payload(mode="allowlist_enforce", allowlist=[entry]),
        scope_kind="fleet",
        scope_id="fleet",
        created_by=actor.id,
    )
    text = svc.summarise(row)
    assert "allowlist_enforce" in text
    assert "v1" in text
    assert "1 allowed device" in text
