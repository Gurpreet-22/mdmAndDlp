"""Data access.

Plain functions over a `Session` rather than a repository class hierarchy: at
this size the indirection would cost more than it explains. The routers hold no
SQL, which is the property that actually matters.

Two queries here carry security weight and are written the way they are on
purpose:

`consume_enrollment_token` is a single UPDATE with a `WHERE consumed_at IS NULL`
guard and a RETURNING clause. A read-then-write would let two concurrent
enrollments both pass the check and both succeed.

`resolve_access_token` re-checks the user's active flag and the token's revoked
and expiry columns on every request. That per-request check is what makes
revocation take effect immediately instead of whenever a cache expires.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence
from typing import Any, cast

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from ubuntuguard.constants import (
    ACCESS_TOKEN_TTL_SECONDS,
    REFRESH_TOKEN_TTL_SECONDS,
)
from ubuntuguard.models import (
    AuthToken,
    Device,
    EnrollmentAttempt,
    EnrollmentToken,
    Incident,
    IssuedCertificate,
    LoginAttempt,
    User,
)
from ubuntuguard.security.tokens import IssuedToken, generate_session_token

# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #


def get_user_by_email(session: Session, email: str) -> User | None:
    """Look up by lowercased email.

    Stored and compared lowercase so Alice@ and alice@ cannot become two
    accounts with different privileges; a CHECK constraint enforces it too.
    """
    return session.scalars(select(User).where(User.email == email.strip().lower())).first()


def get_user(session: Session, user_id: uuid.UUID) -> User | None:
    return session.get(User, user_id)


def create_user(session: Session, *, email: str, password_hash: str, role: str) -> User:
    user = User(email=email.strip().lower(), password_hash=password_hash, role=role)
    session.add(user)
    session.flush()
    return user


def list_users(session: Session, *, limit: int, search: str | None = None) -> Sequence[User]:
    """List admin accounts, newest first, optionally narrowed by address.

    Newest first for the same reason the device list is: oldest-first with a
    page limit buries the rows an administrator has just created, which is
    precisely the set they are looking at the page to check. On a deployment
    carrying a few thousand rows it hid every real account behind test data,
    including the caller's own.

    `search` is a substring of the address, not a regex. Length is bounded at
    the route, and the value is bound as a parameter rather than interpolated,
    so a `%` in the input widens the match and cannot do anything else.

    The secondary sort on `email` matters more than it looks: accounts created
    by a script share a timestamp, and without a tiebreaker their relative
    order is whatever the database happens to return, which makes both paging
    and tests non-deterministic.

    A `search` that is blank or only whitespace means "no search" rather than
    "match nothing". An address cannot contain whitespace - `normalise_email`
    refuses it - so the alternative is a filter that is guaranteed to return an
    empty list, which reads as "there are no accounts".
    """
    term = search.strip() if search else ""
    statement = select(User).order_by(User.created_at.desc(), User.email)
    if term:
        statement = statement.where(User.email.ilike(f"%{term}%"))
    return list(session.scalars(statement.limit(limit)))


def list_all_users(
    session: Session,
    *,
    pattern: str | None = None,
    include_inactive: bool = True,
) -> Sequence[User]:
    """Every account, unpaginated, for the CLI.

    Separate from `list_users` and deliberately unbounded, because the two
    answer different questions. `list_users` serves `GET /users`, where a page
    limit is correct: it is a request from a browser and an unbounded response
    is a denial-of-service vector.

    This one serves `list-admins`, where the operator is on the server with the
    database password and is asking "who exists". A capped answer there is
    actively misleading - it was exactly what hid two accounts behind a few
    thousand test rows during a cleanup - so the question is answered in full
    and the caller narrows it with `pattern` if it is long.
    """
    statement = select(User).order_by(User.created_at)
    if pattern:
        statement = statement.where(User.email.ilike(f"%{pattern}%"))
    if not include_inactive:
        statement = statement.where(User.is_active)
    return list(session.scalars(statement))


def revoke_all_sessions(session: Session, user: User) -> int:
    """Revoke every live token a user holds, across ALL families.

    Returns the number of rows revoked. Deliberately does NOT touch
    `is_active`: revoking sessions and disabling an account are different
    operations with different consequences, and conflating them is a trap.
    `POST /users/{id}:disable` is one-way through the API - there is no enable
    route - so "log this person out" must not be reachable only via a call that
    locks the account permanently.

    All families, not one: `revoke_family` handles logout and refresh-reuse
    detection, where exactly one session is at fault. After a credential
    change every existing session is suspect, including ones whose refresh
    token an attacker may already hold.

    Runs in the caller's transaction, so a password change and its session
    revocation commit or roll back together.
    """
    result = cast(
        "CursorResult[Any]",
        session.execute(
            update(AuthToken)
            .where(AuthToken.user_id == user.id, AuthToken.revoked_at.is_(None))
            .values(revoked_at=dt.datetime.now(dt.UTC))
        ),
    )
    session.flush()
    return int(result.rowcount or 0)


def disable_user(session: Session, user: User) -> int:
    """Deactivate an account and revoke every session it holds.

    Returns the number of tokens revoked. Without the revocation the account
    keeps working until its access token expires, which is up to 15 minutes of
    a disabled user still making changes.
    """
    user.is_active = False
    user.updated_at = dt.datetime.now(dt.UTC)
    # Shares one statement with revoke_all_sessions rather than repeating it:
    # two copies of "which tokens count as live" would eventually disagree.
    return revoke_all_sessions(session, user)


def record_login_attempt(
    session: Session,
    *,
    email: str,
    succeeded: bool,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Record every attempt, including ones against accounts that do not exist.

    Those are precisely the attempts worth seeing: a run of failures against
    unknown addresses is someone working through a list.
    """
    session.add(
        LoginAttempt(
            email=email.strip().lower()[:320],
            succeeded=succeeded,
            attempted_at=dt.datetime.now(dt.UTC),
            source_ip=source_ip,
            user_agent=(user_agent or None) and user_agent[:256],
        )
    )


def recent_failed_attempts(
    session: Session, *, email: str, since: dt.datetime
) -> list[dt.datetime]:
    rows = session.execute(
        select(LoginAttempt.attempted_at)
        .where(
            LoginAttempt.email == email.strip().lower(),
            LoginAttempt.succeeded.is_(False),
            LoginAttempt.attempted_at >= since,
        )
        .order_by(LoginAttempt.attempted_at)
    ).all()
    return [row.attempted_at for row in rows]


def set_user_lock(session: Session, user: User, locked_until: dt.datetime | None) -> None:
    user.locked_until = locked_until
    user.updated_at = dt.datetime.now(dt.UTC)
    session.flush()


def touch_last_login(session: Session, user: User) -> None:
    user.last_login_at = dt.datetime.now(dt.UTC)
    user.locked_until = None
    session.flush()


def update_password_hash(session: Session, user: User, password_hash: str) -> None:
    user.password_hash = password_hash
    user.updated_at = dt.datetime.now(dt.UTC)
    session.flush()


# --------------------------------------------------------------------------- #
# Session tokens
# --------------------------------------------------------------------------- #


def issue_token_pair(
    session: Session, *, user_id: uuid.UUID, family_id: uuid.UUID | None = None
) -> tuple[IssuedToken, IssuedToken, uuid.UUID]:
    """Mint an access and a refresh token in one family.

    `family_id` groups a login session across refresh rotations. Presenting an
    already-used refresh token revokes the entire family, which is the standard
    way to detect a stolen refresh token: either the attacker or the legitimate
    client will replay one, and the session dies either way.
    """
    family = family_id or uuid.uuid4()
    now = dt.datetime.now(dt.UTC)

    access = generate_session_token()
    refresh = generate_session_token()

    session.add(
        AuthToken(
            user_id=user_id,
            family_id=family,
            kind="access",
            token_hash=access.token_hash,
            issued_at=now,
            expires_at=now + dt.timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
        )
    )
    session.add(
        AuthToken(
            user_id=user_id,
            family_id=family,
            kind="refresh",
            token_hash=refresh.token_hash,
            issued_at=now,
            expires_at=now + dt.timedelta(seconds=REFRESH_TOKEN_TTL_SECONDS),
        )
    )
    session.flush()
    return access, refresh, family


def find_token(session: Session, *, token_hash: str, kind: str) -> AuthToken | None:
    return session.scalars(
        select(AuthToken).where(AuthToken.token_hash == token_hash, AuthToken.kind == kind)
    ).first()


def mark_refresh_used(session: Session, token: AuthToken) -> None:
    token.used_at = dt.datetime.now(dt.UTC)
    session.flush()


def revoke_family(session: Session, family_id: uuid.UUID) -> int:
    """Revoke every token in a family. Used by logout and by reuse detection."""
    now = dt.datetime.now(dt.UTC)
    result = cast(
        "CursorResult[Any]",
        session.execute(
            update(AuthToken)
            .where(AuthToken.family_id == family_id, AuthToken.revoked_at.is_(None))
            .values(revoked_at=now)
        ),
    )
    session.flush()
    return int(result.rowcount or 0)


# --------------------------------------------------------------------------- #
# Enrollment tokens
# --------------------------------------------------------------------------- #


def create_enrollment_token(
    session: Session,
    *,
    token_hash: str,
    created_by: uuid.UUID,
    expires_at: dt.datetime,
    label: str | None,
    pre_registered_device_id: uuid.UUID | None = None,
) -> EnrollmentToken:
    row = EnrollmentToken(
        token_hash=token_hash,
        created_by=created_by,
        expires_at=expires_at,
        label=label,
        pre_registered_device_id=pre_registered_device_id,
    )
    session.add(row)
    session.flush()
    return row


def find_enrollment_token(session: Session, token_hash: str) -> EnrollmentToken | None:
    return session.scalars(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash)
    ).first()


def consume_enrollment_token(
    session: Session, *, token_hash: str, now: dt.datetime
) -> uuid.UUID | None:
    """Atomically consume an unused, unexpired, unrevoked token.

    One statement. The `consumed_at IS NULL` guard and the RETURNING clause are
    what make "exactly one of two simultaneous callers succeeds" true at the
    database level rather than hopefully true in application code.
    """
    result = session.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.token_hash == token_hash,
            EnrollmentToken.consumed_at.is_(None),
            EnrollmentToken.revoked_at.is_(None),
            EnrollmentToken.expires_at > now,
        )
        .values(consumed_at=now)
        .returning(EnrollmentToken.id)
    )
    row = result.first()
    session.flush()
    return row[0] if row else None


def attach_token_to_device(session: Session, *, token_id: uuid.UUID, device_id: uuid.UUID) -> None:
    session.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.id == token_id)
        .values(consumed_by_device_id=device_id)
    )
    session.flush()


def find_enrollment_token_by_id(session: Session, token_id: uuid.UUID) -> EnrollmentToken | None:
    return session.get(EnrollmentToken, token_id)


def revoke_enrollment_token(session: Session, token_id: uuid.UUID) -> bool:
    result = cast(
        "CursorResult[Any]",
        session.execute(
            update(EnrollmentToken)
            .where(
                EnrollmentToken.id == token_id,
                EnrollmentToken.revoked_at.is_(None),
                EnrollmentToken.consumed_at.is_(None),
            )
            .values(revoked_at=dt.datetime.now(dt.UTC))
        ),
    )
    session.flush()
    return bool(result.rowcount)


def list_enrollment_tokens(session: Session, *, limit: int) -> Sequence[EnrollmentToken]:
    return list(
        session.scalars(
            select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc()).limit(limit)
        )
    )


# --------------------------------------------------------------------------- #
# Enrollment idempotency
# --------------------------------------------------------------------------- #


def find_enrollment_attempt(
    session: Session, *, token_hash: str, csr_fingerprint: str, not_before: dt.datetime
) -> EnrollmentAttempt | None:
    """Find a cached response for an interrupted enrollment.

    Keyed by token AND CSR public key. A retry with the same keypair is
    idempotent; the same token with a different keypair is refused, because the
    token is spent. That distinction is what makes retries safe without making
    the token reusable.
    """
    return session.scalars(
        select(EnrollmentAttempt).where(
            EnrollmentAttempt.token_hash == token_hash,
            EnrollmentAttempt.csr_public_key_fingerprint == csr_fingerprint,
            EnrollmentAttempt.created_at >= not_before,
        )
    ).first()


def record_enrollment_attempt(
    session: Session,
    *,
    token_hash: str,
    csr_fingerprint: str,
    device_id: uuid.UUID,
    response: dict[str, object],
) -> EnrollmentAttempt:
    row = EnrollmentAttempt(
        token_hash=token_hash,
        csr_public_key_fingerprint=csr_fingerprint,
        device_id=device_id,
        response_json=response,
    )
    session.add(row)
    session.flush()
    return row


# --------------------------------------------------------------------------- #
# Devices
# --------------------------------------------------------------------------- #


def create_device(session: Session, **fields: object) -> Device:
    device = Device(**fields)
    session.add(device)
    session.flush()
    return device


def register_device(
    session: Session,
    *,
    display_name: str,
    platform: str,
    registered_by: uuid.UUID | None,
    manufacturer: str | None = None,
    model: str | None = None,
    assigned_to_name: str | None = None,
    assigned_to_email: str | None = None,
    asset_tag: str | None = None,
    now: dt.datetime | None = None,
) -> Device:
    """Create a device record for a laptop that has not been enrolled yet.

    `status='pending'` and `enrolled_at=None` together mean unenrolled, and the
    `enrolled_at_matches_status` CHECK constraint keeps those two in step. No
    hostname, OS or fingerprint is set: those are facts only the device can
    report, and inventing them here would make the fleet list a guess.
    """
    device = Device(
        status="pending",
        hostname=None,
        enrolled_at=None,
        display_name=display_name,
        platform=platform,
        manufacturer=manufacturer,
        model=model,
        assigned_to_name=assigned_to_name,
        assigned_to_email=assigned_to_email,
        asset_tag=asset_tag,
        registered_by=registered_by,
        registered_at=now or dt.datetime.now(dt.UTC),
    )
    session.add(device)
    session.flush()
    return device


def claim_pending_device(
    session: Session,
    *,
    device: Device,
    hostname: str,
    agent_version: str | None,
    release_build: bool | None,
    os_id: str | None,
    os_version_id: str | None,
    kernel: str | None,
    arch: str | None,
    machine_id_hash: str | None,
    dmi_product_uuid_hash: str | None,
    virtualization: str | None,
    primary_adapter_ip: str | None,
    clone_suspected: bool,
    clone_of_device_id: uuid.UUID | None,
    enrolled_at: dt.datetime,
) -> Device:
    """Fill in a registered device's row at enrollment.

    This is what stops "an admin added the laptop" and "the laptop arrived"
    producing two rows for one machine. The administrator's own fields
    (display_name, assignee, asset tag) are deliberately NOT touched: the device
    does not get to rename itself or reassign who it belongs to.
    """
    device.status = "active"
    device.hostname = hostname
    device.agent_version = agent_version
    device.release_build = release_build
    device.os_id = os_id
    device.os_version_id = os_version_id
    device.kernel = kernel
    device.arch = arch
    device.machine_id_hash = machine_id_hash
    device.dmi_product_uuid_hash = dmi_product_uuid_hash
    device.virtualization = virtualization
    if primary_adapter_ip is not None:
        device.primary_adapter_ip = primary_adapter_ip
    device.clone_suspected = clone_suspected
    device.clone_of_device_id = clone_of_device_id
    device.enrolled_at = enrolled_at
    session.flush()
    return device


def get_device(session: Session, device_id: uuid.UUID) -> Device | None:
    return session.get(Device, device_id)


def find_device_by_fingerprint(session: Session, fingerprint: str) -> Device | None:
    """Look up the device whose CURRENT certificate has this fingerprint.

    `devices.cert_fingerprint` holds only the newest certificate, so this
    answers "is this the device's current certificate" and nothing else. It is
    not the authentication lookup - see `find_device_by_certificate`, which is,
    and which has to consider the predecessor a renewal just superseded.
    """
    return session.scalars(select(Device).where(Device.cert_fingerprint == fingerprint)).first()


def find_device_by_certificate(
    session: Session, fingerprint: str
) -> tuple[Device, IssuedCertificate] | None:
    """The authentication lookup: fingerprint -> (device, certificate record).

    Goes through `issued_certificates` rather than `devices.cert_fingerprint`,
    and that difference is the whole of certificate rotation. `devices` holds
    one fingerprint, so a lookup against it means a certificate stops
    authenticating the instant a renewal is committed - including for the agent
    that has not yet received the replacement. `issued_certificates` holds every
    certificate ever issued, each with its own `revoked_at` and `superseded_at`,
    which lets the caller decide what a superseded certificate may still do.

    Returns the row whatever its state. **Deciding is the caller's job**, in
    `DbDeviceResolver`, so the policy lives in one readable place rather than
    being half-expressed in a WHERE clause here. The caller must check, in this
    order: the device is active, the certificate is not revoked, and the
    certificate is either current or superseded within the grace window.
    """
    row = session.execute(
        select(IssuedCertificate, Device)
        .join(Device, Device.id == IssuedCertificate.device_id)
        .where(IssuedCertificate.fingerprint == fingerprint)
    ).first()
    if row is None:
        return None
    certificate, device = row
    return device, certificate


def find_live_certificates(session: Session, device_id: uuid.UUID) -> Sequence[IssuedCertificate]:
    """Every certificate for a device that is neither revoked nor superseded.

    After a renewal this is exactly one row. More than one means a renewal is
    in flight or something went wrong, and either way the caller wants to see
    all of them rather than a `.first()` that hides it.
    """
    return list(
        session.scalars(
            select(IssuedCertificate)
            .where(
                IssuedCertificate.device_id == device_id,
                IssuedCertificate.revoked_at.is_(None),
                IssuedCertificate.superseded_at.is_(None),
            )
            .order_by(IssuedCertificate.not_before)
        )
    )


def supersede_other_certificates(
    session: Session,
    *,
    device_id: uuid.UUID,
    keep_fingerprint: str,
    now: dt.datetime,
) -> int:
    """Mark every other live certificate for this device as superseded.

    One UPDATE with a `superseded_at IS NULL` guard, so two concurrent renewals
    cannot both believe they superseded the same row, and re-running it is a
    no-op rather than a timestamp that creeps forward. Returns how many rows
    were actually superseded, which the caller audits.

    `keep_fingerprint` is excluded rather than the statement being scoped to
    "older than" something: ordering certificates by time would depend on the
    clock, and excluding the one just issued is exactly the intent.
    """
    result = cast(
        "CursorResult[Any]",
        session.execute(
            update(IssuedCertificate)
            .where(
                IssuedCertificate.device_id == device_id,
                IssuedCertificate.fingerprint != keep_fingerprint,
                IssuedCertificate.superseded_at.is_(None),
            )
            .values(superseded_at=now)
        ),
    )
    session.flush()
    return int(result.rowcount or 0)


def find_clone_candidates(
    session: Session, *, machine_id_hash: str | None, dmi_product_uuid_hash: str | None
) -> Sequence[Device]:
    """Existing devices sharing a hardware fingerprint.

    Advisory. A reimaged laptop and a cloned VM are indistinguishable here, so
    the caller records a distinct device and raises an incident for a human.
    """
    clauses = []
    if machine_id_hash:
        clauses.append(Device.machine_id_hash == machine_id_hash)
    if dmi_product_uuid_hash:
        clauses.append(Device.dmi_product_uuid_hash == dmi_product_uuid_hash)
    if not clauses:
        return []

    return list(
        session.scalars(
            select(Device)
            .where(or_(*clauses), Device.status != "revoked")
            .order_by(Device.enrolled_at)
        )
    )


def list_devices(
    session: Session,
    *,
    limit: int,
    search: str | None = None,
    status: str | None = None,
    os_version_id: str | None = None,
    agent_version: str | None = None,
    platform: str | None = None,
    enrolled: bool | None = None,
) -> Sequence[Device]:
    """List devices, newest record first.

    Ordered by `registered_at` rather than `enrolled_at`, because `enrolled_at`
    is NULL for every unenrolled device and sorting on it would bury exactly the
    rows an administrator has just created and is waiting on.
    """
    statement = select(Device).order_by(Device.registered_at.desc())
    if search:
        # Matches what an operator would actually type: the label they chose,
        # the hostname the agent reported, or the person it belongs to.
        pattern = f"%{search}%"
        statement = statement.where(
            or_(
                Device.display_name.ilike(pattern),
                Device.hostname.ilike(pattern),
                Device.assigned_to_name.ilike(pattern),
                Device.assigned_to_email.ilike(pattern),
                Device.asset_tag.ilike(pattern),
            )
        )
    if status:
        statement = statement.where(Device.status == status)
    if os_version_id:
        statement = statement.where(Device.os_version_id == os_version_id)
    if agent_version:
        statement = statement.where(Device.agent_version == agent_version)
    if platform:
        statement = statement.where(Device.platform == platform)
    if enrolled is not None:
        statement = statement.where(
            Device.enrolled_at.is_not(None) if enrolled else Device.enrolled_at.is_(None)
        )
    return list(session.scalars(statement.limit(limit)))


def count_devices_by_state(session: Session) -> dict[str, int]:
    """Fleet totals, counted in the database rather than over a truncated page.

    The dashboard previously derived its own counts from the rows it had just
    fetched, which silently became wrong as soon as the fleet exceeded the page
    limit. Counting here keeps "12 unenrolled" true regardless of paging.
    """
    row = session.execute(
        select(
            func.count().label("total"),
            func.count(case((Device.enrolled_at.is_not(None), 1))).label("enrolled"),
            func.count(case((Device.enrolled_at.is_(None), 1))).label("unenrolled"),
            func.count(case((Device.status == "revoked", 1))).label("revoked"),
            func.count(case((Device.clone_suspected, 1))).label("clone_suspected"),
        )
    ).one()
    return {
        "total": int(row.total),
        "enrolled": int(row.enrolled),
        "unenrolled": int(row.unenrolled),
        "revoked": int(row.revoked),
        "clone_suspected": int(row.clone_suspected),
    }


def revoke_device(session: Session, *, device: Device, reason: str) -> None:
    device.status = "revoked"
    device.revoked_at = dt.datetime.now(dt.UTC)
    device.revoke_reason = reason[:500]
    session.flush()


def touch_heartbeat(
    session: Session,
    *,
    device: Device,
    agent_version: str | None,
    primary_adapter_ip: str | None = None,
) -> None:
    device.last_heartbeat_at = dt.datetime.now(dt.UTC)
    if agent_version:
        device.agent_version = agent_version[:64]
    if primary_adapter_ip:
        device.primary_adapter_ip = primary_adapter_ip[:45]
    session.flush()


def record_issued_certificate(
    session: Session,
    *,
    device_id: uuid.UUID,
    fingerprint: str,
    serial_number: str,
    not_before: dt.datetime,
    not_after: dt.datetime,
    pem: str,
) -> IssuedCertificate:
    row = IssuedCertificate(
        device_id=device_id,
        fingerprint=fingerprint,
        serial_number=serial_number,
        not_before=not_before,
        not_after=not_after,
        pem=pem,
    )
    session.add(row)
    session.flush()
    return row


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #


def create_incident(
    session: Session,
    *,
    kind: str,
    summary: str,
    device_id: uuid.UUID | None = None,
    severity: str = "medium",
    note: str | None = None,
) -> Incident:
    now = dt.datetime.now(dt.UTC)
    row = Incident(
        device_id=device_id,
        kind=kind,
        summary=summary[:256],
        severity=severity,
        opened_at=now,
        updated_at=now,
        note=note,
    )
    session.add(row)
    session.flush()
    return row
