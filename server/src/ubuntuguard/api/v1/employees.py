"""Employee management routes.

Endpoints for managing employee records, their department assignments, and
correlating employee profiles with managed hardware devices.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ubuntuguard import problems
from ubuntuguard.api.deps import (
    Principal,
    get_directory,
    get_principal,
    get_session,
    require_capability,
)
from ubuntuguard.models import Employee
from ubuntuguard.schemas import (
    DirectorySearchResponse,
    DirectoryUserResponse,
    EmployeeCreateRequest,
    EmployeeResponse,
    EmployeeUpdateRequest,
    OffboardingFlagResponse,
    OffboardingReviewResponse,
)
from ubuntuguard.security.rbac import Capability
from ubuntuguard.services import audit
from ubuntuguard.services.directory import (
    DirectoryError,
    DirectoryNotConfiguredError,
    EntraDirectory,
)
from ubuntuguard import repositories

router = APIRouter(prefix="/employees", tags=["employees"])

#: Enough to cover the whole directory in one call. `search` is paged for the
#: picker's benefit; the offboarding review needs every address at once to
#: answer "is this owner still here", and a tenant large enough to exceed this
#: would want a different design anyway.
_DIRECTORY_FETCH_ALL = 10_000


def _employee_response(emp: Employee, device_count: int = 0) -> EmployeeResponse:
    return EmployeeResponse(
        id=emp.id,
        full_name=emp.full_name,
        email=emp.email,
        department=emp.department,
        job_title=emp.job_title,
        phone=emp.phone,
        status=emp.status,
        assigned_device_count=device_count,
        created_at=emp.created_at,
        updated_at=emp.updated_at,
    )


@router.get("", response_model=list[EmployeeResponse])
def list_employees(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.DEVICE_READ)),
    q: Annotated[str | None, Query(description="Search by name, email, or department")] = None,
    department: Annotated[str | None, Query(description="Filter by department")] = None,
    status: Annotated[str | None, Query(description="Filter by status")] = None,
) -> list[EmployeeResponse]:
    """List employee records with optional filtering."""
    rows = repositories.list_employees(
        session,
        search=q,
        department=department,
        status=status,
    )
    return [_employee_response(emp, count) for emp, count in rows]


@router.post("", response_model=EmployeeResponse, status_code=201)
def create_employee(
    body: EmployeeCreateRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
) -> EmployeeResponse:
    """Create a new employee profile."""
    existing = repositories.get_employee_by_email(session, body.email)
    if existing:
        raise problems.conflict("email_already_exists", "An employee with that email already exists.")

    employee = repositories.create_employee(
        session,
        full_name=body.full_name,
        email=body.email,
        department=body.department,
        job_title=body.job_title,
        phone=body.phone,
    )
    audit.append(
        session,
        action="employee_created",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="employee",
        target_id=str(employee.id),
        request_id=getattr(request.state, "request_id", None),
        detail={"full_name": employee.full_name, "email": employee.email, "department": employee.department},
    )
    session.commit()
    return _employee_response(employee, 0)


#: Declared BEFORE /{employee_id} on purpose. FastAPI matches routes in
#: declaration order, so with the parameterised route first, a request for
#: /employees/directory would try to parse "directory" as a UUID and answer 422.
@router.get("/directory", response_model=DirectorySearchResponse)
def search_directory(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
    directory: EntraDirectory = Depends(get_directory),
    q: Annotated[str | None, Query(description="Search by name, email, or department")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    include_inactive: Annotated[
        bool,
        Query(
            description=(
                "Include people who appear to have left. Off by default; on when an "
                "administrator needs somebody the licence heuristic does not cover."
            )
        ),
    ] = False,
) -> DirectorySearchResponse:
    """Look up employees in Microsoft Entra ID.

    Read-only, and it writes nothing: a directory entry becomes an `employees`
    row only when a device is actually assigned. Gated on
    ENROLLMENT_TOKEN_MANAGE rather than DEVICE_READ because this exposes the
    company's whole staff list, which is more than a read-only device viewer
    needs.

    Only people who appear to still work here are returned by default. In this
    tenant that means holding a paid licence, which is the one offboarding step
    that actually happens - see `_ACTIVE_SIGNAL` in services/directory.py for
    the measurements and the limits. `include_inactive` brings the rest back,
    because a proxy this imperfect must not be the only way to find somebody.

    Returns 200 with `configured: false` when no Entra credentials are set,
    rather than an error. That is a supported deployment, and the dashboard
    falls back to typing a name and address by hand.
    """
    if not directory.configured:
        return DirectorySearchResponse(configured=False, users=[])

    try:
        # One more than asked for, purely to detect truncation. The extra is
        # dropped below, so the caller still gets exactly `limit`.
        found = directory.search(q, limit=limit + 1, include_inactive=include_inactive)
    except DirectoryNotConfiguredError:
        return DirectorySearchResponse(configured=False, users=[])
    except DirectoryError as exc:
        # The directory is configured but unreachable or refusing us: an expired
        # secret, missing admin consent, no network. 502, because the failure is
        # upstream, and the message names the fix.
        raise problems.ProblemError(
            "directory_unavailable",
            status=502,
            title="Could not read the employee directory",
            detail=str(exc),
        ) from exc

    truncated = len(found) > limit
    page = found[:limit]

    # Match the page against our own table in one query rather than one per
    # row, so the picker can hand back an employee_id and avoid creating a
    # duplicate record for somebody already known.
    known = {
        employee.email: employee.id
        for employee in repositories.find_employees_by_emails(
            session, [user.email for user in page]
        )
    }

    return DirectorySearchResponse(
        configured=True,
        truncated=truncated,
        users=[
            DirectoryUserResponse(
                external_id=user.external_id,
                full_name=user.full_name,
                email=user.email,
                department=user.department,
                job_title=user.job_title,
                employee_id=known.get(user.email),
                active=user.active,
            )
            for user in page
        ],
    )


@router.get("/offboarding-review", response_model=OffboardingReviewResponse)
def offboarding_review(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.DEVICE_READ)),
    directory: EntraDirectory = Depends(get_directory),
) -> OffboardingReviewResponse:
    """Working devices still assigned to somebody who appears to have left.

    The other half of reading the directory. Filtering the picker stops a new
    laptop going to a leaver; this catches the ones already out there, which is
    the case that actually costs something. Such a device looks perfectly
    healthy - it heartbeats, its certificate is valid - so nothing else in the
    dashboard would ever mention it.

    Read-only on purpose. It does not revoke, unassign or raise an incident,
    because the signal is a licence rather than a leave date and acting on a
    guess would shut off a working laptop belonging to somebody who is still
    here. An administrator sees the list and decides.

    Gated on DEVICE_READ rather than ENROLLMENT_TOKEN_MANAGE: this is about
    devices an operator is already entitled to see, and it reveals no directory
    entry that is not already recorded as a device owner.
    """
    if not directory.configured:
        return OffboardingReviewResponse(configured=False, checked=0, flagged=[])

    devices = repositories.list_assigned_devices(session)

    try:
        # The whole directory, including inactive people, because the question
        # here is "what does Entra say about this address" rather than "who may
        # I assign a laptop to".
        everyone = {
            user.email: user
            for user in directory.search(limit=_DIRECTORY_FETCH_ALL, include_inactive=True)
        }
    except DirectoryNotConfiguredError:
        return OffboardingReviewResponse(configured=False, checked=0, flagged=[])
    except DirectoryError as exc:
        raise problems.ProblemError(
            "directory_unavailable",
            status=502,
            title="Could not read the employee directory",
            detail=str(exc),
        ) from exc

    flagged: list[OffboardingFlagResponse] = []
    for device in devices:
        email = (device.assigned_to_email or "").strip().lower()
        if not email:
            continue
        entry = everyone.get(email)
        if entry is None:
            # Not in the directory at all. Either typed in by hand - which is
            # legitimate and common for a contractor - or the account has been
            # deleted outright, which is a strong leaver signal. Reported with a
            # distinct reason rather than lumped in, because the two need
            # different responses.
            reason: Literal["no_licence", "not_in_directory"] = "not_in_directory"
        elif not entry.active:
            reason = "no_licence"
        else:
            continue

        flagged.append(
            OffboardingFlagResponse(
                device_id=device.id,
                hostname=device.hostname,
                status=device.status,
                assigned_to_name=device.assigned_to_name,
                assigned_to_email=email,
                last_heartbeat_at=device.last_heartbeat_at,
                reason=reason,
            )
        )

    return OffboardingReviewResponse(configured=True, checked=len(devices), flagged=flagged)


@router.get("/{employee_id}", response_model=EmployeeResponse)
def get_employee(
    employee_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.DEVICE_READ)),
) -> EmployeeResponse:
    """Get single employee profile."""
    emp = repositories.get_employee(session, employee_id)
    if emp is None:
        raise problems.not_found("employee")
    # Count assigned devices
    rows = repositories.list_employees(session, search=emp.email, limit=1)
    count = rows[0][1] if rows else 0
    return _employee_response(emp, count)


@router.patch("/{employee_id}", response_model=EmployeeResponse)
def update_employee(
    employee_id: uuid.UUID,
    body: EmployeeUpdateRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
) -> EmployeeResponse:
    """Update employee details."""
    emp = repositories.get_employee(session, employee_id)
    if emp is None:
        raise problems.not_found("employee")

    if body.email and body.email.strip().lower() != emp.email:
        conflict = repositories.get_employee_by_email(session, body.email)
        if conflict:
            raise problems.conflict("email_already_exists", "An employee with that email already exists.")

    emp = repositories.update_employee(
        session,
        employee=emp,
        full_name=body.full_name,
        email=body.email,
        department=body.department,
        job_title=body.job_title,
        phone=body.phone,
        status=body.status,
    )
    audit.append(
        session,
        action="employee_updated",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="employee",
        target_id=str(emp.id),
        request_id=getattr(request.state, "request_id", None),
        detail={"full_name": emp.full_name, "email": emp.email, "status": emp.status},
    )
    session.commit()

    rows = repositories.list_employees(session, search=emp.email, limit=1)
    count = rows[0][1] if rows else 0
    return _employee_response(emp, count)


@router.delete("/{employee_id}", status_code=204)
def delete_employee(
    employee_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
) -> None:
    """Delete an employee profile."""
    emp = repositories.get_employee(session, employee_id)
    if emp is None:
        raise problems.not_found("employee")

    audit.append(
        session,
        action="employee_deleted",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="employee",
        target_id=str(emp.id),
        request_id=getattr(request.state, "request_id", None),
        detail={"full_name": emp.full_name, "email": emp.email},
    )
    repositories.delete_employee(session, emp)
    session.commit()
