"""Tests for employee management, device assignments, and offline device alerts."""

import datetime as dt
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ubuntuguard import repositories
from ubuntuguard.models import Base, Device, Employee, Incident, User


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    sm = sessionmaker(bind=engine)
    with sm() as s:
        yield s


def test_employee_crud(session: Session) -> None:
    # 1. Create employee
    emp = repositories.create_employee(
        session,
        full_name="Alice Smith",
        email="alice@company.com",
        department="Engineering",
        job_title="Security Lead",
        phone="+1234567890",
    )
    session.commit()
    assert emp.id is not None
    assert emp.full_name == "Alice Smith"
    assert emp.email == "alice@company.com"
    assert emp.department == "Engineering"

    # 2. Get by email & ID
    found = repositories.get_employee(session, emp.id)
    assert found is not None
    assert found.email == "alice@company.com"

    by_email = repositories.get_employee_by_email(session, "ALICE@company.com")
    assert by_email is not None
    assert by_email.id == emp.id

    # 3. List & Search
    employees = repositories.list_employees(session, search="alice")
    assert len(employees) == 1
    assert employees[0][0].id == emp.id

    # 4. Update
    repositories.update_employee(
        session,
        employee=emp,
        job_title="Head of Security",
        status="suspended",
    )
    session.commit()
    updated = repositories.get_employee(session, emp.id)
    assert updated.job_title == "Head of Security"
    assert updated.status == "suspended"

    # 5. Delete
    repositories.delete_employee(session, emp)
    session.commit()
    assert repositories.get_employee(session, emp.id) is None


def test_device_assignment_and_unassign(session: Session) -> None:
    # Setup device & employee
    emp = repositories.create_employee(
        session,
        full_name="Bob Jones",
        email="bob@company.com",
        department="Product",
    )
    dev = repositories.create_device(
        session,
        display_name="Bob's Laptop",
        platform="linux",
        status="active",
        enrolled_at=dt.datetime.now(dt.UTC),
    )
    session.commit()

    # Assign device
    assignment = repositories.assign_device(
        session,
        device=dev,
        assigned_to_name="Bob Jones",
        assigned_to_email="bob@company.com",
        department="Product",
        employee_id=emp.id,
        notes="Initial deployment",
    )
    session.commit()

    assert dev.assigned_to_name == "Bob Jones"
    assert dev.department == "Product"
    assert dev.assigned_to_id == emp.id
    assert assignment.unassigned_at is None

    # Check history
    history = repositories.list_device_assignments(session, dev.id)
    assert len(history) == 1
    assert history[0].assigned_to_name == "Bob Jones"

    # Reassign to Charlie
    repositories.assign_device(
        session,
        device=dev,
        assigned_to_name="Charlie Brown",
        assigned_to_email="charlie@company.com",
        department="Design",
        notes="Transferred to Charlie",
    )
    session.commit()

    assert dev.assigned_to_name == "Charlie Brown"
    assert dev.department == "Design"
    history = repositories.list_device_assignments(session, dev.id)
    assert len(history) == 2
    # Old assignment was closed
    assert history[1].unassigned_at is not None
    # New assignment is active
    assert history[0].assigned_to_name == "Charlie Brown"
    assert history[0].unassigned_at is None

    # Unassign device
    repositories.unassign_device(session, device=dev)
    session.commit()

    assert dev.assigned_to_name is None
    assert dev.assigned_to_email is None
    assert dev.department is None
    assert dev.assigned_to_id is None

    history = repositories.list_device_assignments(session, dev.id)
    assert len(history) == 2
    assert history[0].unassigned_at is not None


def test_offline_devices_check_and_resolve(session: Session) -> None:
    now = dt.datetime.now(dt.UTC)
    old_time = now - dt.timedelta(hours=2)

    # Device with old heartbeat
    stale_dev = repositories.create_device(
        session,
        display_name="Offline Laptop",
        platform="linux",
        status="active",
        enrolled_at=old_time,
        last_heartbeat_at=old_time,
    )
    # Device with recent heartbeat
    fresh_dev = repositories.create_device(
        session,
        display_name="Active Laptop",
        platform="linux",
        status="active",
        enrolled_at=now,
        last_heartbeat_at=now,
    )
    session.commit()

    # Run offline check with 15-minute threshold (900 seconds)
    checked, flagged, new_incidents, device_ids = repositories.check_offline_devices(
        session,
        threshold_seconds=900,
    )
    session.commit()

    assert checked == 2
    assert flagged == 1
    assert new_incidents == 1
    assert device_ids == [stale_dev.id]

    # Verify incident was opened
    incident = session.query(Incident).filter(Incident.device_id == stale_dev.id).first()
    assert incident is not None
    assert incident.kind == "device_offline"
    assert incident.status == "open"
    assert "Offline Laptop" in incident.summary

    # Running check again should not duplicate the open incident
    checked2, flagged2, new_incidents2, _ = repositories.check_offline_devices(
        session,
        threshold_seconds=900,
    )
    assert new_incidents2 == 0

    # Auto-resolve on heartbeat
    repositories.resolve_offline_incidents_for_device(session, stale_dev.id)
    session.commit()

    session.refresh(incident)
    assert incident.status == "resolved"
    assert "[Auto-resolved]" in incident.note
