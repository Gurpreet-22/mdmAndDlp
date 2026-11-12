"""Audit log routes: read, verify, export.

Export is separated from read because it is the action an insider would use to
extract the record of what they did, so it carries its own capability and is
itself audited. By the signed-off matrix only `super_admin` and `auditor` hold
it; `it_admin` deliberately does not.
"""

from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ubuntuguard.api.deps import Principal, get_session, require_capability
from ubuntuguard.constants import PAGE_SIZE
from ubuntuguard.schemas import AuditEntryResponse, ChainVerificationResponse
from ubuntuguard.security.rbac import Capability
from ubuntuguard.services import audit

router = APIRouter(prefix="/audit-logs", tags=["audit"])

#: Bound on an export. A request for the whole log should be paged rather than
#: streamed in one response that could exhaust memory on either end.
MAX_EXPORT_ROWS = 10_000


def _to_response(row: object) -> AuditEntryResponse:
    return AuditEntryResponse(
        seq=row.seq,  # type: ignore[attr-defined]
        occurred_at=row.occurred_at,  # type: ignore[attr-defined]
        action=row.action,  # type: ignore[attr-defined]
        actor_id=row.actor_id,  # type: ignore[attr-defined]
        actor_role=row.actor_role,  # type: ignore[attr-defined]
        target_type=row.target_type,  # type: ignore[attr-defined]
        target_id=row.target_id,  # type: ignore[attr-defined]
        request_id=row.request_id,  # type: ignore[attr-defined]
        detail=json.loads(row.detail_json or b"{}"),  # type: ignore[attr-defined]
        entry_hash=row.entry_hash.hex(),  # type: ignore[attr-defined]
    )


@router.get("", response_model=list[AuditEntryResponse])
def list_entries(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.AUDIT_READ)),
    after_seq: int | None = Query(None, ge=0, description="Cursor: return entries after this seq"),
    limit: int = Query(PAGE_SIZE.default, ge=PAGE_SIZE.minimum, le=PAGE_SIZE.maximum),
) -> list[AuditEntryResponse]:
    """Read a page in ascending sequence order.

    Ascending so a page remains independently verifiable: the chain can only be
    recomputed in the order it was written.
    """
    return [_to_response(row) for row in audit.read_page(session, after_seq=after_seq, limit=limit)]


@router.get(":verify", response_model=ChainVerificationResponse)
def verify_chain(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.AUDIT_VERIFY)),
    start_seq: int | None = Query(None, ge=1),
    limit: int | None = Query(None, ge=1, le=100_000),
) -> ChainVerificationResponse:
    """Recompute the hash chain and report the first break.

    Detects an edited row, a deleted row, a reordered row and a re-parented
    row, and reports the sequence number where the chain stops holding.
    """
    result = audit.verify(session, start_seq=start_seq, limit=limit)
    return ChainVerificationResponse(
        ok=result.ok,
        checked=result.checked,
        broken_at_seq=result.broken_at_seq,
        reason=result.reason,
    )


@router.post(":export")
def export_entries(
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.AUDIT_EXPORT)),
    after_seq: int | None = Query(None, ge=0),
    limit: int = Query(1000, ge=1, le=MAX_EXPORT_ROWS),
) -> StreamingResponse:
    """Export entries as CSV. The export is itself an audited action."""
    rows = audit.read_page(session, after_seq=after_seq, limit=limit)

    audit.append(
        session,
        action="audit_exported",
        actor_id=principal.user_id,
        actor_role=principal.role.value,
        target_type="audit_log",
        target_id=None,
        request_id=getattr(request.state, "request_id", None),
        detail={
            "rows": len(rows),
            "after_seq": after_seq,
            "first_seq": rows[0].seq if rows else None,
            "last_seq": rows[-1].seq if rows else None,
        },
    )

    # The export row must be durable before the file leaves the server.
    session.commit()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "seq",
            "occurred_at",
            "action",
            "actor_id",
            "actor_role",
            "target_type",
            "target_id",
            "request_id",
            "detail",
            "entry_hash",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.seq,
                row.occurred_at.isoformat(),
                row.action,
                row.actor_id or "",
                row.actor_role or "",
                row.target_type or "",
                row.target_id or "",
                row.request_id or "",
                (row.detail_json or b"{}").decode("utf-8"),
                # Included so an exported file can be verified independently of
                # the database it came from.
                row.entry_hash.hex(),
            ]
        )

    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ubuntuguard-audit.csv"'},
    )
