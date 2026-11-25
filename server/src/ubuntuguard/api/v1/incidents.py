"""Incidents: the alerts the server raises about devices.

Why this module exists at all. The offline sweep has been writing
`device_offline` incidents since it was built, the `incidents` table carries a
full triage lifecycle - status, severity, note, assignee, closed_at - and
`Capability.INCIDENT_READ` and `INCIDENT_UPDATE` have been sitting in the RBAC
matrix unused. There was no route. So the dashboard's offline check would
report "3 new alert(s) raised" and there was nowhere to go and see them.

Read and update only. Incidents are raised by the server from things it
observed; there is no POST, because an alert an administrator typed in by hand
is a note, not an observation, and the `note` field is where that belongs.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.api.deps import Principal, get_session, require_capability
from ubuntuguard.constants import PAGE_SIZE
from ubuntuguard.models import Incident
from ubuntuguard.schemas import (
    IncidentCountsResponse,
    IncidentKind,
    IncidentResponse,
    IncidentStatus,
    IncidentUpdateRequest,
)
from ubuntuguard.security.rbac import Capability
from ubuntuguard.services import audit

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _response(incident: Incident, hostname: str | None) -> IncidentResponse:
    return IncidentResponse(
        id=incident.id,
        device_id=incident.device_id,
        device_hostname=hostname,
        kind=incident.kind,  # type: ignore[arg-type]
        status=incident.status,  # type: ignore[arg-type]
        severity=incident.severity,
        summary=incident.summary,
        note=incident.note,
        opened_at=incident.opened_at,
        updated_at=incident.updated_at,
        closed_at=incident.closed_at,
        assigned_to=incident.assigned_to,
    )


def _hostnames(session: Session, incidents: list[Incident]) -> dict[uuid.UUID, str | None]:
    """Hostnames for a page of incidents in one query rather than one each."""
    ids = [i.device_id for i in incidents if i.device_id is not None]
    if not ids:
        return {}
    return {device.id: device.hostname for device in repositories.find_devices_by_ids(session, ids)}


#: Declared before /{incident_id} so "counts" is not parsed as a UUID.
@router.get(":counts", response_model=IncidentCountsResponse)
def incident_counts(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.INCIDENT_READ)),
) -> IncidentCountsResponse:
    """How many alerts still need attention.

    Separate from the list so the navigation badge costs one `COUNT(*)` rather
    than fetching rows it will not display.
    """
    return IncidentCountsResponse(open=repositories.count_open_incidents(session))


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.INCIDENT_READ)),
    status: Annotated[IncidentStatus | None, Query(description="Exact status.")] = None,
    kind: Annotated[IncidentKind | None, Query(description="Exact kind.")] = None,
    device_id: Annotated[uuid.UUID | None, Query(description="One device's alerts.")] = None,
    open_only: Annotated[
        bool,
        Query(description="Only incidents nobody has closed: open, acknowledged or investigating."),
    ] = False,
    limit: int = Query(PAGE_SIZE.default, ge=PAGE_SIZE.minimum, le=PAGE_SIZE.maximum),
) -> list[IncidentResponse]:
    """Alerts, newest first."""
    rows = list(
        repositories.list_incidents(
            session,
            status=status,
            kind=kind,
            device_id=device_id,
            open_only=open_only,
            limit=limit,
        )
    )
    hostnames = _hostnames(session, rows)
    return [_response(row, hostnames.get(row.device_id) if row.device_id else None) for row in rows]


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.INCIDENT_READ)),
) -> IncidentResponse:
    row = repositories.get_incident(session, incident_id)
    if row is None:
        raise problems.not_found("incident")
    hostnames = _hostnames(session, [row])
    return _response(row, hostnames.get(row.device_id) if row.device_id else None)


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdateRequest,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.INCIDENT_UPDATE)),
) -> IncidentResponse:
    """Acknowledge, investigate, resolve or dismiss an alert.

    Audited. Closing an alert is an administrator deciding that something the
    server flagged about a laptop does not matter, and the previous status is
    recorded alongside the new one so the trail shows what the decision
    actually changed.
    """
    row = repositories.get_incident(session, incident_id)
    if row is None:
        raise problems.not_found("incident")

    previous_status = row.status
    row = repositories.update_incident(
        session,
        incident=row,
        status=body.status,
        note=body.note,
        assigned_to=uuid.UUID(principal.user_id) if body.assign_to_me else None,
    )

    # Two actions, chosen by what actually changed. Recording a note-only
    # update as a status change would be false in the one log that has to be
    # exact about who decided what.
    status_changed = body.status is not None and body.status != previous_status
    audit.append(
        session,
        action="incident_status_changed" if status_changed else "incident_annotated",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="incident",
        target_id=str(row.id),
        request_id=getattr(request.state, "request_id", None),
        detail={
            "kind": row.kind,
            "device_id": str(row.device_id) if row.device_id else None,
            # Both ends, so the entry says what changed rather than only where
            # it ended up. "resolved" alone does not tell you whether anybody
            # had looked at it first.
            "status_from": previous_status,
            "status_to": row.status,
            "note_added": bool(body.note),
            "assigned_to_self": body.assign_to_me,
        },
    )
    session.commit()

    hostnames = _hostnames(session, [row])
    return _response(row, hostnames.get(row.device_id) if row.device_id else None)
