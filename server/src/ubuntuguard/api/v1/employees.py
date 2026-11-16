"""Employee management routes.

Endpoints for managing employee records, their department assignments, and
correlating employee profiles with managed hardware devices.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ubuntuguard import problems
from ubuntuguard.api.deps import Principal, get_principal, get_session, require_capability
from ubuntuguard.models import Employee
from ubuntuguard.schemas import (
    EmployeeCreateRequest,
    EmployeeResponse,
    EmployeeUpdateRequest,
)
from ubuntuguard.security.rbac import Capability
from ubuntuguard.services import audit
from ubuntuguard import repositories

router = APIRouter(prefix="/employees", tags=["employees"])


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

