"""Admin user management. `super_admin` only.

Creating accounts and changing roles is the capability that can grant every
other capability, so it is the one cell in the matrix held by a single role.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.api.deps import Principal, get_session, require_capability
from ubuntuguard.constants import PAGE_SIZE
from ubuntuguard.schemas import MAX_EMAIL_LENGTH, CreateUserRequest, UserResponse
from ubuntuguard.security import passwords
from ubuntuguard.security.rbac import Capability
from ubuntuguard.services import audit

router = APIRouter(prefix="/users", tags=["users"])


@router.post("", response_model=UserResponse, status_code=201)
def create_user(
    body: CreateUserRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_USERS)),
) -> UserResponse:
    """Create an admin account.

    The password is validated against policy here, which is safe: this is a
    privileged route where telling the caller their proposed password is too
    short reveals nothing. Login never does the same check, because there it
    would turn the endpoint into a policy oracle.
    """
    try:
        password_hash = passwords.hash_password(body.password)
    except passwords.PasswordPolicyError as exc:
        raise problems.validation_failed(
            [problems.FieldError(field="password", message=str(exc))]
        ) from exc

    try:
        user = repositories.create_user(
            session, email=body.email, password_hash=password_hash, role=body.role
        )
        session.flush()
    except IntegrityError as exc:
        raise problems.conflict("user_already_exists", "That email is already registered.") from exc

    audit.append(
        session,
        action="user_created",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="user",
        target_id=str(user.id),
        request_id=getattr(request.state, "request_id", None),
        # The email is recorded; the password and its hash never are.
        detail={"email": user.email, "role": user.role},
    )

    session.commit()
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.get("", response_model=list[UserResponse])
def list_users(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_USERS)),
    q: str | None = Query(
        None, max_length=MAX_EMAIL_LENGTH, description="Substring of the address"
    ),
    limit: int = Query(PAGE_SIZE.default, ge=PAGE_SIZE.minimum, le=PAGE_SIZE.maximum),
) -> list[UserResponse]:
    """List accounts, newest first.

    `q` is here because the page limit alone makes this route misleading once a
    deployment has more accounts than one page: without a way to ask for a
    specific address, an account that exists reads as an account that does not.
    """
    return [
        UserResponse(
            id=row.id,
            email=row.email,
            role=row.role,
            is_active=row.is_active,
            created_at=row.created_at,
            last_login_at=row.last_login_at,
        )
        for row in repositories.list_users(session, limit=limit, search=q)
    ]


@router.post("/{user_id}:disable", status_code=204)
def disable_user(
    user_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_USERS)),
) -> None:
    """Deactivate an account and revoke its sessions.

    Deactivation rather than deletion, so the audit trail keeps pointing at a
    real row. Revoking the sessions is the part that matters operationally:
    without it the account keeps working until its access token expires.
    """
    user = repositories.get_user(session, user_id)
    if user is None:
        raise problems.not_found("user")
    if principal.user_id == str(user_id):
        # Locking yourself out of the only super_admin account is a support
        # call, not a security feature.
        raise problems.conflict("cannot_disable_self", "You cannot disable your own account.")

    revoked = repositories.disable_user(session, user)
    audit.append(
        session,
        action="user_disabled",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="user",
        target_id=str(user_id),
        request_id=getattr(request.state, "request_id", None),
        detail={"email": user.email, "sessions_revoked": revoked},
    )
    session.commit()
