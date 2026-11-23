"""Enrollment: admin-side token management, and the device-side exchange.

`POST /enroll` is the only route that is neither bearer-authenticated nor
mTLS-authenticated, because a device has no identity until it completes this
call. The one-time token is the whole of its authentication, which is why the
token is 32 random bytes, stored hashed, single use, and short lived.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.api.deps import Principal, get_keys, get_session, require_capability
from ubuntuguard.constants import PAGE_SIZE
from ubuntuguard.models import Employee, EnrollmentToken
from ubuntuguard.schemas import (
    CreateEnrollmentTokenRequest,
    CreateEnrollmentTokenResponse,
    EnrollmentTokenResponse,
    EnrollRequest,
    EnrollResponse,
    TokenEmployeeSummary,
)
from ubuntuguard.security.rbac import Capability
from ubuntuguard.security.tokens import generate_enrollment_token
from ubuntuguard.services import audit, enrollment
from ubuntuguard.services.keys import KeyBundle

admin_router = APIRouter(prefix="/enrollment-tokens", tags=["enrollment"])
device_router = APIRouter(tags=["enrollment"])


def _status(row: EnrollmentToken, now: dt.datetime) -> str:
    """Derive a status rather than storing one, so it cannot go stale."""
    if row.revoked_at is not None:
        return "revoked"
    if row.consumed_at is not None:
        return "consumed"
    if row.expires_at <= now:
        return "expired"
    return "active"


@admin_router.post("", response_model=CreateEnrollmentTokenResponse, status_code=201)
def create_token(
    body: CreateEnrollmentTokenRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
) -> CreateEnrollmentTokenResponse:
    """Mint a one-time enrollment token, optionally for a named employee.

    The plaintext is returned exactly once and is never stored. If it is lost,
    issue another one; there is no recovery path, by design.

    Naming an employee is what makes the device arrive assigned. The admin
    issuing the token knows whose laptop it is; recording it here means nobody
    has to remember a second form afterwards, which is why assignment used to
    be empty on devices that were otherwise working fine.
    """
    now = dt.datetime.now(dt.UTC)
    employee = _resolve_employee(session, body, principal, request)

    token = generate_enrollment_token()
    expires_at = now + dt.timedelta(seconds=body.ttl_seconds)

    row = repositories.create_enrollment_token(
        session,
        token_hash=token.token_hash,
        created_by=uuid.UUID(principal.user_id),
        expires_at=expires_at,
        label=body.label,
        employee_id=employee.id if employee is not None else None,
    )
    audit.append(
        session,
        action="enrollment_token_created",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="enrollment_token",
        target_id=str(row.id),
        request_id=getattr(request.state, "request_id", None),
        # The hash is not recorded either: the audit log is widely readable, and
        # a hash plus a captured plaintext would confirm which token was which.
        detail={
            "label": body.label,
            "expires_at": expires_at,
            "ttl_seconds": body.ttl_seconds,
            # Who it was for belongs in the trail: this is the record of which
            # administrator authorised which person to enrol a device.
            "employee_id": str(employee.id) if employee is not None else None,
            "employee_email": employee.email if employee is not None else None,
        },
    )
    session.commit()
    return CreateEnrollmentTokenResponse(
        id=row.id,
        enrollment_token=token.plaintext,
        expires_at=expires_at,
        label=row.label,
        employee=_employee_summary(employee),
    )


def _employee_summary(employee: Employee | None) -> TokenEmployeeSummary | None:
    if employee is None:
        return None
    return TokenEmployeeSummary(
        id=employee.id,
        full_name=employee.full_name,
        email=employee.email,
        department=employee.department,
    )


def _resolve_employee(
    session: Session,
    body: CreateEnrollmentTokenRequest,
    principal: Principal,
    request: Request,
) -> Employee | None:
    """Turn whatever the request said about the employee into a row, or None.

    Three inputs, by design (see `CreateEnrollmentTokenRequest`): an id for
    somebody already known, a name and address which is matched by address
    before creating anything, or nothing at all for a spare machine.

    Matching on address before creating is the part that matters. Without it,
    minting a second token for the same person would silently produce a second
    employee row, and their two laptops would appear to belong to two different
    people.
    """
    if body.employee_id is not None:
        employee = repositories.get_employee(session, body.employee_id)
        if employee is None:
            # 404 rather than creating one: an id that resolves to nothing means
            # the caller is working from a stale list, and inventing a nameless
            # employee to satisfy the request would hide that.
            raise problems.not_found("employee")
        return employee

    if body.employee_email is None or body.employee_name is None:
        # The request validator already refuses one without the other, so this
        # is unreachable via HTTP. Checked rather than asserted because `assert`
        # is stripped under `python -O`, which would turn a future direct caller
        # passing a half-filled request into an employee row with no name.
        return None

    existing = repositories.get_employee_by_email(session, body.employee_email)
    if existing is not None:
        # Deliberately does not overwrite the stored name from the request. The
        # employee record is the system of record; a token request is not the
        # place to rename somebody, and a directory display name that differs by
        # punctuation should not rewrite a name an admin corrected by hand.
        return existing

    employee = repositories.create_employee(
        session,
        full_name=body.employee_name,
        email=body.employee_email,
        department=body.department,
    )
    audit.append(
        session,
        action="employee_created",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="employee",
        target_id=str(employee.id),
        request_id=getattr(request.state, "request_id", None),
        detail={
            "full_name": employee.full_name,
            "email": employee.email,
            "department": employee.department,
            # Distinguishes this from a record created on the Employees page,
            # so the trail shows the row appeared as a side effect of issuing a
            # token rather than by a deliberate "add employee" action.
            "created_via": "enrollment_token",
        },
    )
    return employee


@admin_router.get("", response_model=list[EnrollmentTokenResponse])
def list_tokens(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
    limit: int = Query(PAGE_SIZE.default, ge=PAGE_SIZE.minimum, le=PAGE_SIZE.maximum),
) -> list[EnrollmentTokenResponse]:
    """Metadata only. Neither the token nor its hash is ever returned."""
    now = dt.datetime.now(dt.UTC)
    rows = list(repositories.list_enrollment_tokens(session, limit=limit))

    # Employees fetched in one query for the whole page rather than per row, so
    # listing 50 tokens is two statements instead of fifty-one.
    employees = {
        employee.id: employee
        for employee in repositories.find_employees_by_ids(
            session, [row.employee_id for row in rows if row.employee_id is not None]
        )
    }

    return [
        EnrollmentTokenResponse(
            id=row.id,
            label=row.label,
            created_at=row.created_at,
            expires_at=row.expires_at,
            consumed_at=row.consumed_at,
            revoked_at=row.revoked_at,
            consumed_by_device_id=row.consumed_by_device_id,
            status=_status(row, now),  # type: ignore[arg-type]
            employee=_employee_summary(
                employees.get(row.employee_id) if row.employee_id is not None else None
            ),
        )
        for row in rows
    ]


@admin_router.post("/{token_id}:revoke", status_code=204)
def revoke_token(
    token_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
) -> None:
    """Invalidate an unused token.

    Returns 409 for a token that is already consumed or revoked, rather than
    pretending to succeed: an operator revoking a token needs to know whether
    they were in time.
    """
    row = repositories.find_enrollment_token_by_id(session, token_id)
    if row is None:
        raise problems.not_found("enrollment token")

    if not repositories.revoke_enrollment_token(session, token_id):
        raise problems.conflict(
            "enrollment_token_not_revocable",
            "That token has already been used or revoked.",
        )

    audit.append(
        session,
        action="enrollment_token_revoked",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="enrollment_token",
        target_id=str(token_id),
        request_id=getattr(request.state, "request_id", None),
        detail={"label": row.label},
    )
    session.commit()


@device_router.post(
    "/enroll",
    response_model=EnrollResponse,
    status_code=201,
    responses={
        401: {"description": "Enrollment token invalid or already used"},
        400: {"description": "Certificate request rejected"},
    },
)
def enroll_device(
    body: EnrollRequest,
    request: Request,
    session: Session = Depends(get_session),
    keys: KeyBundle = Depends(get_keys),
) -> EnrollResponse:
    """Exchange a one-time token and a CSR for a device identity.

    Unauthenticated by necessity: the device has no identity yet. Retrying with
    the same token and the same keypair within 60 seconds returns the identical
    response, so a network failure after the server committed is recoverable.
    The same token with a different keypair is refused.
    """
    return enrollment.enroll(
        session,
        keys=keys,
        request=body,
        request_id=getattr(request.state, "request_id", None),
    )
