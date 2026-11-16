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
from ubuntuguard.schemas import (
    MAX_EMAIL_LENGTH,
    ChangeRoleRequest,
    CreateUserRequest,
    ResetPasswordRequest,
    UserResponse,
)
from ubuntuguard.security import passwords
from ubuntuguard.security.rbac import Capability
from ubuntuguard.services import audit
from ubuntuguard.services import users as users_service

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
        must_change_password=user.must_change_password,
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
            must_change_password=row.must_change_password,
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

    The self-check and the last-super_admin check both live in
    `services/users.disable`, because the second one has to hold a row lock
    across the decision and the write. See `repositories.lock_active_super_admins`
    for why a plain count is not enough.
    """
    user = users_service.get_target(session, user_id)
    revoked = users_service.disable(session, actor_id=principal.user_id, user=user)

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


@router.post("/{user_id}:enable", status_code=204)
def enable_user(
    user_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_USERS)),
) -> None:
    """Reactivate a disabled account, preserving its identity and history.

    The counterpart that did not exist. Until this route, `:disable` was
    one-way through the API and there was no CLI equivalent either, so a
    disabled account was unreachable without database access - and two
    super_admins disabling each other was an unrecoverable lockout.

    The account comes back with its address, role, id and audit trail intact,
    and with its existing password: this is not a credential operation. Any
    standing lockout is cleared, because an account that was locked and then
    disabled would otherwise return still refusing the correct password with no
    route to clear it. See `repositories.enable_user`.

    No sessions are issued. `:disable` revoked them all and the user signs in
    again.
    """
    user = users_service.get_target(session, user_id)
    users_service.enable(session, user=user)

    audit.append(
        session,
        action="user_enabled",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="user",
        target_id=str(user_id),
        request_id=getattr(request.state, "request_id", None),
        detail={"email": user.email, "role": user.role},
    )
    session.commit()


@router.post("/{user_id}:role", status_code=204)
def change_user_role(
    user_id: uuid.UUID,
    body: ChangeRoleRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_USERS)),
) -> None:
    """Change an account's role.

    Sessions are revoked, and that is not optional. A `Principal` carries the
    role it was resolved with, so a demoted user's live access token would keep
    the capabilities of the role they no longer hold until it expired - up to
    fifteen minutes of an ex-super_admin still able to create accounts.
    Revoking forces them to re-authenticate and be resolved afresh.

    Refused for your own account, and for the last active super_admin. Both
    guards are in `services/users.change_role`; the second holds a row lock
    across the check and the write.
    """
    user = users_service.get_target(session, user_id)
    previous = users_service.change_role(
        session, actor_id=principal.user_id, user=user, role=body.role
    )
    revoked = repositories.revoke_all_sessions(session, user)

    audit.append(
        session,
        action="user_role_changed",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="user",
        target_id=str(user_id),
        request_id=getattr(request.state, "request_id", None),
        # Old and new, so the audit log answers "what were they before" without
        # replaying every earlier entry.
        detail={
            "email": user.email,
            "from_role": previous,
            "to_role": body.role,
            "sessions_revoked": revoked,
        },
    )
    session.commit()


@router.post("/{user_id}:reset-password", status_code=204)
def reset_user_password(
    user_id: uuid.UUID,
    body: ResetPasswordRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_USERS)),
) -> None:
    """Set a temporary password on another account.

    Returns 204 with no body. The administrator supplied the password, so
    returning it would put a live credential in a response for no gain; the
    plaintext exists in this process only long enough to be hashed, and is
    never logged, audited or stored.

    Three effects, all required and all in `services/users.reset_password`:
    the hash is replaced, `must_change_password` is set so the temporary value
    buys nothing but the ability to replace it, and every session the user
    holds is revoked so the reset is immediately visible to them.

    **This route is an account-takeover primitive and was deliberately absent
    until now.** `cli.py:cmd_set_password` carried that reasoning and now
    points here instead. What makes it acceptable: `manage_users` belongs to
    `super_admin` alone, which can already create and disable accounts, so it
    is already total authority over the admin plane. What genuinely changes is
    that one super_admin can take over another's identity without shell access.
    The controls on that are the audit row below, the forced change, and the
    victim being signed out everywhere. See agent/SECURITY-FINDINGS.md item 11.
    """
    user = users_service.get_target(session, user_id)

    try:
        password_hash = passwords.hash_password(body.password)
    except passwords.PasswordPolicyError as exc:
        raise problems.validation_failed(
            [problems.FieldError(field="password", message=str(exc))]
        ) from exc

    revoked = users_service.reset_password(session, user=user, password_hash=password_hash)

    audit.append(
        session,
        action="user_password_reset",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="user",
        target_id=str(user_id),
        request_id=getattr(request.state, "request_id", None),
        # The email and the consequences, never the password or its hash.
        detail={
            "email": user.email,
            "sessions_revoked": revoked,
            "must_change_password": True,
        },
    )
    session.commit()
