"""Device routes: admin inventory and revocation, plus the device heartbeat.

Two planes in one module because they concern the same resource, but they never
share authentication. The admin routes take a bearer token; the heartbeat takes
an mTLS client certificate and no bearer token at all.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.api.deps import (
    DevicePrincipal,
    Principal,
    get_device_principal,
    get_keys,
    get_renewing_device_principal,
    get_session,
    require_capability,
)
from ubuntuguard.constants import HEARTBEAT_JITTER_PCT, HEARTBEAT_SECONDS, PAGE_SIZE
from ubuntuguard.liveness import is_online
from ubuntuguard.models import Device
from ubuntuguard.schemas import (
    CertificateRenewRequest,
    CertificateRenewResponse,
    DeviceCounts,
    DeviceDetail,
    DeviceSummary,
    HeartbeatRequest,
    HeartbeatResponse,
    RegisterDeviceRequest,
    RegisterDeviceResponse,
    RevokeDeviceRequest,
)
from ubuntuguard.security.rbac import Capability
from ubuntuguard.security.tokens import generate_enrollment_token
from ubuntuguard.services import audit, renewal
from ubuntuguard.services.ca import renewal_due_at
from ubuntuguard.services.keys import KeyBundle

admin_router = APIRouter(prefix="/devices", tags=["devices"])
device_router = APIRouter(prefix="/devices/me", tags=["device-plane"])


def _summary(device: Device, now: dt.datetime) -> DeviceSummary:
    return DeviceSummary(
        id=device.id,
        hostname=device.hostname,
        status=device.status,
        online=is_online(device.last_heartbeat_at, now=now),
        # Derived from the timestamp rather than stored separately, so the two
        # cannot drift into disagreeing about whether a device ever enrolled.
        enrolled=device.enrolled_at is not None,
        last_heartbeat_at=device.last_heartbeat_at,
        agent_version=device.agent_version,
        os_id=device.os_id,
        os_version_id=device.os_version_id,
        kernel=device.kernel,
        enrolled_at=device.enrolled_at,
        registered_at=device.registered_at,
        clone_suspected=device.clone_suspected,
        release_build=device.release_build,
        display_name=device.display_name,
        manufacturer=device.manufacturer,
        model=device.model,
        assigned_to_name=device.assigned_to_name,
        assigned_to_email=device.assigned_to_email,
        platform=device.platform,
        asset_tag=device.asset_tag,
        primary_adapter_ip=device.primary_adapter_ip,
    )


def _detail(device: Device, now: dt.datetime) -> DeviceDetail:
    return DeviceDetail(
        **_summary(device, now).model_dump(),
        arch=device.arch,
        cert_fingerprint=device.cert_fingerprint,
        cert_not_after=device.cert_not_after,
        last_inventory_at=device.last_inventory_at,
        revoked_at=device.revoked_at,
        revoke_reason=device.revoke_reason,
        virtualization=device.virtualization,
    )


@admin_router.get("", response_model=list[DeviceSummary])
def list_devices(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.DEVICE_READ)),
    q: str | None = Query(
        None, max_length=253, description="Matches label, hostname, assignee or asset tag"
    ),
    status: str | None = Query(None, pattern="^(pending|active|revoked)$"),
    os_version_id: str | None = Query(None, max_length=32),
    agent_version: str | None = Query(None, max_length=64),
    platform: str | None = Query(None, pattern="^(linux|macos|windows)$"),
    enrolled: bool | None = Query(
        None, description="True for enrolled devices only, false for those awaiting enrollment"
    ),
    limit: int = Query(PAGE_SIZE.default, ge=PAGE_SIZE.minimum, le=PAGE_SIZE.maximum),
) -> list[DeviceSummary]:
    """List devices, enrolled and not. `online` is computed here, never self-reported."""
    now = dt.datetime.now(dt.UTC)
    rows = repositories.list_devices(
        session,
        limit=limit,
        search=q,
        status=status,
        os_version_id=os_version_id,
        agent_version=agent_version,
        platform=platform,
        enrolled=enrolled,
    )
    return [_summary(row, now) for row in rows]


@admin_router.get(":counts", response_model=DeviceCounts)
def device_counts(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.DEVICE_READ)),
) -> DeviceCounts:
    """Fleet totals, counted in the database rather than over one page.

    Separate from the list so the headline numbers stay true when the list is
    filtered or truncated. A dashboard deriving "unenrolled" from the rows it
    happened to fetch reports a smaller number than the truth, which is the
    direction that matters here.

    `devices:counts`, not `devices/counts`, matching `audit-logs:verify`
    elsewhere. The colon form is a SIBLING of the collection rather than a child
    of it, so `/devices/{device_id}` can never capture it. The path form was
    tried first and worked only because it happened to be declared above the
    `{device_id}` route: reorder those two and `counts` gets parsed as a device
    id, failing with "invalid character: found 'o' at 1". Correct-by-ordering is
    not correct enough when the fix is this cheap.
    """
    return DeviceCounts(**repositories.count_devices_by_state(session))


@admin_router.post("", response_model=RegisterDeviceResponse, status_code=201)
def register_device(
    body: RegisterDeviceRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.ENROLLMENT_TOKEN_MANAGE)),
) -> RegisterDeviceResponse:
    """Register an employee laptop before it has been enrolled.

    Creates the record an administrator can see and track while the laptop is
    still in a box, and optionally mints the single-use enrollment token the
    agent will present. Nothing here touches the device: registering it grants
    no access and proves no identity. The device becomes `active` only when the
    agent completes enrollment with a keypair it generated itself.

    Guarded by ENROLLMENT_TOKEN_MANAGE rather than a new capability, because the
    operation issues an enrollment credential and that is the privilege that
    matters. The RBAC matrix in docs/01-api-contract.md is awaiting sign-off, so
    it is deliberately not altered here.
    """
    now = dt.datetime.now(dt.UTC)
    device = repositories.register_device(
        session,
        display_name=body.display_name,
        platform=body.platform,
        registered_by=uuid.UUID(principal.user_id) if principal.user_id else None,
        manufacturer=body.manufacturer,
        model=body.model,
        assigned_to_name=body.assigned_to_name,
        assigned_to_email=body.assigned_to_email,
        asset_tag=body.asset_tag,
        now=now,
    )

    secret: str | None = None
    token_id: uuid.UUID | None = None
    expires_at: dt.datetime | None = None
    if body.issue_enrollment_token:
        minted = generate_enrollment_token()
        secret = minted.plaintext
        expires_at = now + dt.timedelta(seconds=body.token_ttl_seconds)
        token = repositories.create_enrollment_token(
            session,
            token_hash=minted.token_hash,
            created_by=uuid.UUID(principal.user_id),
            expires_at=expires_at,
            label=body.display_name,
            pre_registered_device_id=device.id,
        )
        token_id = token.id
        audit.append(
            session,
            action="enrollment_token_created",
            actor_id=principal.user_id,
            actor_role=principal.role.value,
            target_type="enrollment_token",
            target_id=str(token.id),
            request_id=getattr(request.state, "request_id", None),
            detail={
                "label": body.display_name,
                "expires_at": expires_at,
                "pre_registered_device_id": str(device.id),
            },
        )

    audit.append(
        session,
        action="device_registered",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="device",
        target_id=str(device.id),
        request_id=getattr(request.state, "request_id", None),
        detail={
            "display_name": body.display_name,
            "platform": body.platform,
            "manufacturer": body.manufacturer,
            "model": body.model,
            "assigned_to_email": body.assigned_to_email,
            "asset_tag": body.asset_tag,
            "enrollment_token_issued": secret is not None,
        },
    )
    session.commit()

    return RegisterDeviceResponse(
        device=_detail(device, now),
        enrollment_token=secret,
        enrollment_token_id=token_id,
        enrollment_token_expires_at=expires_at,
    )


@admin_router.get("/{device_id}", response_model=DeviceDetail)
def get_device(
    device_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.DEVICE_READ)),
) -> DeviceDetail:
    device = repositories.get_device(session, device_id)
    if device is None:
        raise problems.not_found("device")
    return _detail(device, dt.datetime.now(dt.UTC))


@admin_router.post("/{device_id}:revoke", status_code=204)
def revoke_device(
    device_id: uuid.UUID,
    body: RevokeDeviceRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.DEVICE_REVOKE)),
) -> None:
    """Revoke a device's identity.

    Takes effect on the device's very next request, because every device-plane
    call re-reads the device's status. It does NOT make the laptop stop
    enforcing: an offline or cut-off device keeps its last verified policy by
    design. Removing enforcement needs a new signed policy or an uninstall.
    """
    device = repositories.get_device(session, device_id)
    if device is None:
        raise problems.not_found("device")
    if device.status == "revoked":
        raise problems.conflict("device_already_revoked", "That device is already revoked.")

    repositories.revoke_device(session, device=device, reason=body.reason)
    audit.append(
        session,
        action="device_revoked",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="device",
        target_id=str(device_id),
        request_id=getattr(request.state, "request_id", None),
        detail={"hostname": device.hostname, "reason": body.reason},
    )
    session.commit()


@device_router.post("/certificate:renew", response_model=CertificateRenewResponse)
def renew_certificate(
    body: CertificateRenewRequest,
    request: Request,
    session: Session = Depends(get_session),
    device: DevicePrincipal = Depends(get_renewing_device_principal),
    keys: KeyBundle = Depends(get_keys),
) -> CertificateRenewResponse:
    """Rotate this device's client certificate.

    Authenticated by the certificate being replaced. There is no token and no
    device identifier in the body: the identity comes entirely from the mTLS
    connection, so a device cannot renew on another's behalf.

    `get_renewing_device_principal` rather than `get_device_principal`, and this
    is the only route in the system that makes that choice. It tolerates a
    certificate a previous renewal already superseded, within
    `CERT_SUPERSEDE_GRACE_SECONDS`, because the agent holding one is an agent
    whose renewal response was lost in transit and whose only credential is the
    certificate it still has. Everything else is unchanged: the proxy must be
    trusted, nginx must have verified the chain, the certificate's own validity
    window is re-checked, the device must be active, and the subject must match.

    A revoked device cannot renew. `status != 'active'` is checked by the
    resolver before anything about the certificate, so revocation outranks every
    other consideration here.

    `:renew` as a colon suffix rather than `/renew`, matching `audit-logs:verify`
    and `devices:counts`. It is an action on `certificate`, not a sub-resource
    of it, and the colon form cannot be captured by a path parameter.
    """
    row = repositories.get_device(session, uuid.UUID(device.device_id))
    if row is None:  # pragma: no cover - the resolver already found this device
        raise problems.device_not_authenticated("device_not_active")

    return renewal.renew(
        session,
        keys=keys,
        device=row,
        presented_certificate=device.certificate.certificate,
        request=body,
        request_id=getattr(request.state, "request_id", None),
    )


@device_router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(
    body: HeartbeatRequest,
    session: Session = Depends(get_session),
    device: DevicePrincipal = Depends(get_device_principal),
) -> HeartbeatResponse:
    """Record liveness and return scheduling hints.

    The response carries no commands. There is no field here that tells the
    agent to run anything; it learns which policy versions exist and pulls them
    itself. That is the structural reason a compromised server cannot execute
    code on a laptop.
    """
    row = repositories.get_device(session, uuid.UUID(device.device_id))
    if row is None:
        raise problems.device_not_authenticated("device_not_active")

    repositories.touch_heartbeat(
        session,
        device=row,
        agent_version=body.agent_version,
        primary_adapter_ip=body.primary_adapter_ip,
    )

    renew_after: dt.datetime | None = None
    certificate = device.certificate.certificate if device.certificate else None
    if certificate is not None:
        renew_after = renewal_due_at(certificate)

    session.commit()
    return HeartbeatResponse(
        server_time=dt.datetime.now(dt.UTC),
        heartbeat_seconds=HEARTBEAT_SECONDS.default,
        heartbeat_jitter_pct=HEARTBEAT_JITTER_PCT.default,
        certificate_renew_after=renew_after,
        # Populated once the policy engine lands in Phase 4.
        available_policies=[],
    )
