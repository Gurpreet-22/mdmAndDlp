"""Policy routes: administrators author them, devices pull them.

Two planes in one module, as in `devices.py`, and they never share
authentication. The admin routes take a bearer token and an RBAC capability.
The device routes take an mTLS client certificate and no bearer token at all.

The split between them is the structural reason a compromised server cannot run
code on a laptop:

An administrator creates a *version*. Nothing is pushed. The heartbeat later
advertises that a version exists, and the device decides whether it wants it and
pulls it over its own authenticated request. A response on this API can
therefore only ever offer declarative, signed state -- there is no route that
tells a device to do something.

The device plane is deliberately under `/devices/me/`, which is the nginx
location that verifies the client certificate and overwrites the identity
headers. A device route anywhere else would not receive them, and
`device_auth.py` would refuse it. Identity comes from the certificate on every
one of these requests, never from a field in the body, so a device cannot act
on another's behalf.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Path, Query, Request
from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.api.deps import (
    DevicePrincipal,
    Principal,
    get_device_principal,
    get_keys,
    get_session,
    require_capability,
)
from ubuntuguard.constants import PAGE_SIZE
from ubuntuguard.models import POLICY_TYPES
from ubuntuguard.schemas import (
    DevicePolicyStatusResponse,
    DeviceUsbPolicyView,
    PolicyDetail,
    PolicyEnvelopeResponse,
    PolicySummary,
    ReportPolicyStatusRequest,
    SetUsbPolicyRequest,
)
from ubuntuguard.security.rbac import Capability
from ubuntuguard.services import audit
from ubuntuguard.services import policy as policy_service
from ubuntuguard.services.keys import KeyBundle

admin_router = APIRouter(prefix="/policies", tags=["policies"])
device_router = APIRouter(prefix="/devices/me", tags=["device-plane"])


# --------------------------------------------------------------------------- #
# Shaping
# --------------------------------------------------------------------------- #


def _summary(row: Any) -> PolicySummary:
    return PolicySummary(
        policy_id=row.id,
        policy_type=row.policy_type,
        version=row.version,
        scope_kind=row.scope_kind,
        scope_id=row.scope_id,
        signing_key_id=row.signing_key_id,
        payload_sha256=row.payload_sha256,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        summary=policy_service.summarise(row),
        created_at=row.created_at,
    )


def _detail(row: Any) -> PolicyDetail:
    return PolicyDetail(
        **_summary(row).model_dump(),
        payload=policy_service.decoded_payload(row),
    )


def _status_response(row: Any, policy: Any) -> DevicePolicyStatusResponse:
    return DevicePolicyStatusResponse(
        policy_id=row.policy_id,
        policy_type=policy.policy_type,
        policy_version=policy.version,
        status=row.status,
        reason_code=row.reason_code,
        detail=row.detail,
        reported_at=row.reported_at,
        verified_state=row.verified_state,
    )


# --------------------------------------------------------------------------- #
# Admin plane
# --------------------------------------------------------------------------- #


@admin_router.post("/usb-control", response_model=PolicyDetail, status_code=201)
def set_usb_policy(
    body: SetUsbPolicyRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.POLICY_WRITE)),
    keys: KeyBundle = Depends(get_keys),
) -> PolicyDetail:
    """Create a new `usb_control` version and put a scope under it.

    Always a new version; there is no edit. Assigning it also retires the
    device's previous assignment of the same type, so a laptop is never under
    two versions at once.

    The policy is signed before it is stored, and what is stored is the exact
    bytes that were signed.
    """
    now = dt.datetime.now(dt.UTC)

    if body.scope_kind == "device":
        if body.device_id is None:
            raise problems.validation_failed(
                [
                    problems.FieldError(
                        field="device_id",
                        message="required when scope_kind is 'device'",
                    )
                ]
            )
        device = repositories.get_device(session, body.device_id)
        if device is None:
            raise problems.not_found("device")
        scope_id = str(device.id)
    else:
        scope_id = "fleet"

    actor = principal.email or str(principal.user_id)

    allowlist = [
        {
            "entry_id": str(uuid.uuid4()),
            "match": entry.match.model_dump(),
            "label": entry.label,
            "added_by": actor[:120],
            "added_at": policy_service.format_timestamp(now),
        }
        for entry in body.allowlist
    ]
    exceptions = [
        {
            "exception_id": str(uuid.uuid4()),
            "match": grant.match.model_dump(),
            "reason": grant.reason,
            "created_by": actor[:120],
            "created_at": policy_service.format_timestamp(now),
            "expires_at": policy_service.format_timestamp(
                now + dt.timedelta(hours=grant.expires_in_hours)
            ),
        }
        for grant in body.exceptions
    ]

    try:
        payload = policy_service.build_usb_control_payload(
            mode=body.mode,
            protected_classes=body.protected_classes,
            always_allow_classes=body.always_allow_classes,
            allowlist=allowlist,
            exceptions=exceptions,
            apply_to_present_devices=body.apply_to_present_devices,
        )
    except policy_service.PolicyError as err:
        # Refused before anything is signed or stored, so a policy that would
        # lock a user out never acquires a version number.
        raise problems.validation_failed(
            [problems.FieldError(field="mode", message=str(err))]
        ) from err

    row, _envelope = policy_service.issue_policy(
        session,
        signer=keys.signer,
        policy_type=policy_service.POLICY_TYPE_USB_CONTROL,
        payload=payload,
        scope_kind=body.scope_kind,
        scope_id=scope_id,
        created_by=uuid.UUID(principal.user_id),
        issued_at=now,
    )

    if body.scope_kind == "device" and body.device_id is not None:
        repositories.unassign_policies_of_type(
            session,
            device_id=body.device_id,
            policy_type=policy_service.POLICY_TYPE_USB_CONTROL,
        )
        repositories.assign_policy(
            session,
            policy_id=row.id,
            device_id=body.device_id,
            assigned_by=uuid.UUID(principal.user_id),
        )

    audit.append(
        session,
        action="policy_created",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="policy",
        target_id=str(row.id),
        request_id=getattr(request.state, "request_id", None),
        detail={
            "policy_type": row.policy_type,
            "version": row.version,
            "scope_kind": row.scope_kind,
            "scope_id": row.scope_id,
            "mode": body.mode,
            "allowlist_count": len(allowlist),
            "exception_count": len(exceptions),
            "payload_sha256": row.payload_sha256,
            "signing_key_id": row.signing_key_id,
        },
    )

    # get_session deliberately does not commit: its teardown runs after the
    # response has already gone to the client, so committing there let a
    # client act on a write that had not landed. The writer commits.
    detail = _detail(row)
    session.commit()
    return detail


@admin_router.get("", response_model=list[PolicySummary])
def list_policies(
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.POLICY_READ)),
    policy_type: str | None = Query(default=None),
    limit: int = Query(default=PAGE_SIZE, ge=1, le=200),
) -> list[PolicySummary]:
    """Policy versions, newest first."""
    rows = repositories.list_policies(session, policy_type=policy_type, limit=limit)
    return [_summary(row) for row in rows]


@admin_router.get("/device/{device_id}", response_model=DeviceUsbPolicyView)
def device_usb_policy(
    request: Request,
    device_id: uuid.UUID = Path(),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.POLICY_READ)),
) -> DeviceUsbPolicyView:
    """The USB policy in force for one device, and what it reported back.

    Both halves matter to the dashboard. The policy alone says what was asked
    for; the status says what the laptop actually did about it, which is the
    difference between a dashboard and a wish.
    """
    device = repositories.get_device(session, device_id)
    if device is None:
        raise problems.not_found("device")

    policy = repositories.effective_policy_for_device(
        session,
        device_id=device_id,
        policy_type=policy_service.POLICY_TYPE_USB_CONTROL,
    )
    if policy is None:
        return DeviceUsbPolicyView(policy=None, status=None)

    status_row = repositories.get_policy_status(session, device_id=device_id, policy_id=policy.id)
    return DeviceUsbPolicyView(
        policy=_detail(policy),
        status=_status_response(status_row, policy) if status_row else None,
    )


# --------------------------------------------------------------------------- #
# Device plane
# --------------------------------------------------------------------------- #


@device_router.get("/policies/{policy_type}", response_model=PolicyEnvelopeResponse)
def fetch_policy(
    request: Request,
    policy_type: str = Path(),
    session: Session = Depends(get_session),
    principal: DevicePrincipal = Depends(get_device_principal),
) -> PolicyEnvelopeResponse:
    """Hand this device the signed policy it is under.

    The device identifies itself with its client certificate; there is no
    device id in the path. That is what stops one laptop pulling another's
    policy, and it is why the route is `/devices/me/...` rather than
    `/devices/{id}/...`.

    The envelope is reassembled from the stored columns rather than re-signed,
    so repeated requests return byte-identical bytes and the agent does not see
    a new `issued_at` on every poll.
    """
    if policy_type not in POLICY_TYPES:
        raise problems.not_found("policy")

    policy = repositories.effective_policy_for_device(
        session, device_id=uuid.UUID(principal.device_id), policy_type=policy_type
    )
    if policy is None:
        raise problems.not_found("policy")

    return PolicyEnvelopeResponse(**policy_service.envelope_for(policy))


@device_router.post("/policy-status", status_code=204)
def report_policy_status(
    body: ReportPolicyStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: DevicePrincipal = Depends(get_device_principal),
) -> None:
    """Record what this device did with a policy.

    A device may only report on a policy it is actually under. Without that
    check, any enrolled laptop could write a status row against any policy id
    it guessed, and a dashboard showing `applied` for a machine that never had
    the policy is worse than showing nothing.

    `verified_state` is stored as sent: it is the agent's readback from the
    operating system, and summarising it here would discard the evidence.
    """
    policy = repositories.get_policy(session, body.policy_id)
    if policy is None:
        raise problems.not_found("policy")

    in_force = repositories.effective_policy_for_device(
        session, device_id=uuid.UUID(principal.device_id), policy_type=policy.policy_type
    )
    if in_force is None or in_force.id != policy.id:
        raise problems.conflict("policy_not_assigned", "this device is not under that policy")

    repositories.record_policy_status(
        session,
        device_id=uuid.UUID(principal.device_id),
        policy_id=policy.id,
        status=body.status,
        reason_code=body.reason_code,
        detail=body.detail,
        verified_state=body.verified_state,
    )

    # Written against the device, not an administrator: nobody logged in to
    # cause this, and attributing it to a user would be a lie in the audit log.
    audit.append(
        session,
        action="policy_status_reported",
        actor_id=None,
        actor_role="device",
        target_type="policy",
        target_id=str(policy.id),
        request_id=getattr(request.state, "request_id", None),
        detail={
            "device_id": str(principal.device_id),
            "status": body.status,
            "reason_code": body.reason_code,
            "policy_version": policy.version,
        },
    )
    session.commit()
