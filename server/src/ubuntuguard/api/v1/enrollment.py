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
from ubuntuguard.models import EnrollmentToken
from ubuntuguard.schemas import (
    CreateEnrollmentTokenRequest,
    CreateEnrollmentTokenResponse,
    EnrollmentTokenResponse,
    EnrollRequest,
    EnrollResponse,
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
    """Mint a one-time enrollment token.

    The plaintext is returned exactly once and is never stored. If it is lost,
    issue another one; there is no recovery path, by design.
    """
    now = dt.datetime.now(dt.UTC)
    token = generate_enrollment_token()
    expires_at = now + dt.timedelta(seconds=body.ttl_seconds)

    row = repositories.create_enrollment_token(
        session,
        token_hash=token.token_hash,
        created_by=uuid.UUID(principal.user_id),
        expires_at=expires_at,
        label=body.label,
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
        detail={"label": body.label, "expires_at": expires_at, "ttl_seconds": body.ttl_seconds},
    )
    session.commit()
    return CreateEnrollmentTokenResponse(
        id=row.id,
        enrollment_token=token.plaintext,
        expires_at=expires_at,
        label=row.label,
    )


@admin_router.get("", response_model=list[EnrollmentTokenResponse])
def list_tokens(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
    limit: int = Query(PAGE_SIZE.default, ge=PAGE_SIZE.minimum, le=PAGE_SIZE.maximum),
) -> list[EnrollmentTokenResponse]:
    """Metadata only. Neither the token nor its hash is ever returned."""
    now = dt.datetime.now(dt.UTC)
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
        )
        for row in repositories.list_enrollment_tokens(session, limit=limit)
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
