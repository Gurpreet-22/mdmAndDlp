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

from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from ubuntuguard.constants import (
    ACCESS_TOKEN_TTL_SECONDS,
    REFRESH_TOKEN_TTL_SECONDS,
)
from ubuntuguard.liveness import offline_threshold_seconds
from ubuntuguard.models import (
    POLICY_TYPES,
    AuthToken,
    Device,
    DeviceAssignment,
    DevicePolicyStatus,
    Employee,
    EnrollmentAttempt,
    EnrollmentToken,
    Incident,
    IssuedCertificate,
    LoginAttempt,
    Policy,
    PolicyAssignment,
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


def enable_user(session: Session, user: User) -> None:
    """Reactivate a disabled account, and clear any standing lockout.

    `locked_until` is cleared deliberately. An account can be both locked (five
    failed passwords) and disabled, and in that order: somebody fails to sign
    in, an administrator disables the account while investigating, and then
    re-enables it. Restoring only `is_active` would hand back an account that
    still refuses the correct password until the lockout expires, with no route
    to clear it - `set_user_lock` is not reachable from any HTTP route, and
    `touch_last_login` only clears it on a *successful* login, which is exactly
    what the lock is preventing. So re-enabling clears it and the user can sign
    in again with their existing password.

    No session work: `disable_user` already revoked everything this account
    held, and enabling must not mint anything. The user signs in again.

    The password is untouched, so account history - the address, the role, the
    audit trail pointing at this id - survives intact. That is the difference
    between this and deleting and recreating the account.
    """
    user.is_active = True
    user.locked_until = None
    user.updated_at = dt.datetime.now(dt.UTC)
    session.flush()


def set_user_role(session: Session, user: User, role: str) -> None:
    """Change a role. The caller is responsible for the last-super_admin guard.

    Deliberately dumb: the guard lives in `services/users.py`, where it can
    take the lock in the same transaction as the write. A check inside this
    function would be a check without a lock, which is the race in F4.
    """
    user.role = role
    user.updated_at = dt.datetime.now(dt.UTC)
    session.flush()


def set_must_change_password(session: Session, user: User, value: bool) -> None:
    user.must_change_password = value
    user.updated_at = dt.datetime.now(dt.UTC)
    session.flush()


def lock_active_super_admins(session: Session, *, exclude_user_id: uuid.UUID) -> int:
    """Count the OTHER active super_admins, holding a row lock on each.

    This is the last-super_admin protection, and the lock is the whole point of
    it. A plain `COUNT(*)` is not sufficient and the reason is specific:
    PostgreSQL defaults to READ COMMITTED, so two concurrent transactions each
    disabling a different super_admin both count the other as still active,
    neither sees the other's uncommitted write, and both commit. Two admins
    become zero, and because `enable_user` is itself guarded by
    `manage_users` - which nobody now holds - that state is unrecoverable
    without database access.

    `with_for_update()` closes it. The first transaction to reach here takes a
    row lock on every other active super_admin; the second blocks on that lock
    until the first commits, and only then takes its count - which now reflects
    the committed change and refuses the operation.

    **Every active super_admin is locked, including the target, and the ORDER
    BY is not cosmetic.** Both details were added after a concurrency test
    deadlocked, and the mechanism is worth stating because it is easy to
    reintroduce.

    The first attempt locked only the OTHER super_admins - `id != exclude` -
    which seemed tidier and is wrong. With two super_admins A and B and two
    transactions disabling one each: T1 locks B, T2 locks A, then T1 tries to
    UPDATE A and T2 tries to UPDATE B. Each holds what the other needs.
    PostgreSQL detects the cycle and aborts one with `deadlock detected`, so no
    lockout occurs - the data stays safe - but the caller gets an unhandled
    `OperationalError` and the client a 500, where it should have had a clean
    409 explaining that the last super_admin cannot be removed.

    Locking the whole set in primary-key order removes the cycle: both
    transactions want the same rows in the same sequence, so the second simply
    waits for the first to commit and then sees the committed state and
    refuses. The target is in that set whenever the guard applies, because
    `_refuse_last_super_admin` only calls this for an account that is currently
    an active super_admin - so the row about to be written is locked up front
    rather than acquired later, which is the other half of why the cycle is
    gone.

    The exclusion therefore happens in Python, on the locked set, rather than
    in the WHERE clause. `exclude_user_id` still means "do not count the
    account being acted on": the caller is asking how many super_admins would
    remain if this one were removed, and zero means refuse.

    `select(User.id)` rather than whole entities: the rows are wanted for the
    lock and the count, never for their attributes.
    """
    locked = (
        session.execute(
            select(User.id)
            .where(User.role == "super_admin", User.is_active)
            # Deterministic lock acquisition order. Without it two callers can
            # take the same rows in different orders and deadlock.
            .order_by(User.id)
            .with_for_update()
        )
        .scalars()
        .all()
    )
    return sum(1 for user_id in locked if user_id != exclude_user_id)


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
    employee_id: uuid.UUID | None = None,
) -> EnrollmentToken:
    row = EnrollmentToken(
        token_hash=token_hash,
        created_by=created_by,
        expires_at=expires_at,
        label=label,
        pre_registered_device_id=pre_registered_device_id,
        employee_id=employee_id,
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
    department: str | None = None,
    assigned_to_id: uuid.UUID | None = None,
    asset_tag: str | None = None,
    now: dt.datetime | None = None,
) -> Device:
    """Create a device record for a laptop that has not been enrolled yet.

    `status='pending'` and `enrolled_at=None` together mean unenrolled, and the
    `enrolled_at_matches_status` CHECK constraint keeps those two in step. No
    hostname, OS or fingerprint is set: those are facts only the device can
    report, and inventing them here would make the fleet list a guess.
    """
    assigned_time = now or dt.datetime.now(dt.UTC)
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
        department=department,
        assigned_to_id=assigned_to_id,
        asset_tag=asset_tag,
        registered_by=registered_by,
        registered_at=assigned_time,
    )
    session.add(device)
    session.flush()

    if assigned_to_name:
        assignment = DeviceAssignment(
            device_id=device.id,
            employee_id=assigned_to_id,
            assigned_to_name=assigned_to_name,
            assigned_to_email=assigned_to_email,
            department=department,
            assigned_at=assigned_time,
            assigned_by=registered_by,
        )
        session.add(assignment)
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
    cpu_model: str | None = None,
    cpu_cores: int | None = None,
    total_ram_bytes: int | None = None,
    disk_total_bytes: int | None = None,
    disk_free_bytes: int | None = None,
    manufacturer: str | None = None,
    model: str | None = None,
) -> Device:
    """Fill in a registered device's row at enrollment.

    This is what stops "an admin added the laptop" and "the laptop arrived"
    producing two rows for one machine. The administrator's own fields
    (display_name, assignee, asset tag, manufacturer, model) are deliberately
    NOT touched: the device does not get to rename itself, restate its own make
    or reassign who it belongs to. The make and model it reports land in
    `reported_manufacturer` and `reported_model` instead, where they can be
    compared with the asset record rather than overwriting it.
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
    if cpu_model is not None:
        device.cpu_model = cpu_model[:128]
    if cpu_cores is not None:
        device.cpu_cores = cpu_cores
    if total_ram_bytes is not None:
        device.total_ram_bytes = total_ram_bytes
    if disk_total_bytes is not None:
        device.disk_total_bytes = disk_total_bytes
    if disk_free_bytes is not None:
        device.disk_free_bytes = disk_free_bytes
    if manufacturer is not None:
        device.reported_manufacturer = manufacturer[:64]
    if model is not None:
        device.reported_model = model[:120]
    # Enrollment is the first time inventory arrives, so it counts.
    device.last_inventory_at = enrolled_at
    # The platform follows from the OS the device reported, so leaving it blank
    # on a self-enrolled laptop was only ever a gap. Never overwritten: an
    # administrator who chose one has said something the device cannot improve on.
    if device.platform is None:
        device.platform = platform_for_os(os_id)
    session.flush()
    return device


def platform_for_os(os_id: str | None) -> str | None:
    """Map a reported os-release ID onto one of the known platforms.

    Returns None for anything unrecognised rather than guessing, because the
    column has a CHECK constraint and a wrong guess would fail the enrollment
    of a laptop that was otherwise fine.
    """
    if os_id is None:
        return None
    lowered = os_id.strip().lower()
    if lowered in {"ubuntu", "debian", "linuxmint", "pop", "fedora", "rhel", "centos", "arch"}:
        return "linux"
    if lowered in {"macos", "darwin"}:
        return "macos"
    if lowered in {"windows"}:
        return "windows"
    return None


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
    cpu_model: str | None = None,
    cpu_cores: int | None = None,
    total_ram_bytes: int | None = None,
    disk_total_bytes: int | None = None,
    disk_free_bytes: int | None = None,
    manufacturer: str | None = None,
    model: str | None = None,
) -> None:
    now = dt.datetime.now(dt.UTC)
    device.last_heartbeat_at = now
    if agent_version:
        device.agent_version = agent_version[:64]
    if primary_adapter_ip:
        device.primary_adapter_ip = primary_adapter_ip[:45]

    # Inventory is optional on a heartbeat: an older agent, or one that could
    # not read /proc, sends none of it. Tracked so `last_inventory_at` means
    # "when inventory last actually arrived" rather than "when this device last
    # said hello", which are different questions and the dashboard asks the
    # first one.
    # A heartbeat means the agent is running, so any record of its removal is
    # stale. Cleared here rather than needing an administrator to tidy up after
    # a reinstall, and cleared on the FIRST beat so coverage is right
    # immediately rather than after the next sweep.
    if device.agent_removed_at is not None:
        device.agent_removed_at = None
        device.agent_removed_reason = None

    reported_inventory = False
    if cpu_model is not None:
        device.cpu_model = cpu_model[:128]
        reported_inventory = True
    if cpu_cores is not None:
        device.cpu_cores = cpu_cores
        reported_inventory = True
    if total_ram_bytes is not None:
        device.total_ram_bytes = total_ram_bytes
        reported_inventory = True
    if disk_total_bytes is not None:
        device.disk_total_bytes = disk_total_bytes
        reported_inventory = True
    if disk_free_bytes is not None:
        device.disk_free_bytes = disk_free_bytes
        reported_inventory = True
    if manufacturer is not None:
        device.reported_manufacturer = manufacturer[:64]
        reported_inventory = True
    if model is not None:
        device.reported_model = model[:120]
        reported_inventory = True

    if reported_inventory:
        device.last_inventory_at = now
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


# --------------------------------------------------------------------------- #
# Employees & Device Assignments
# --------------------------------------------------------------------------- #


def create_employee(
    session: Session,
    *,
    full_name: str,
    email: str,
    department: str | None = None,
    job_title: str | None = None,
    phone: str | None = None,
    status: str = "active",
) -> Employee:
    now = dt.datetime.now(dt.UTC)
    employee = Employee(
        full_name=full_name,
        email=email.strip().lower(),
        department=department,
        job_title=job_title,
        phone=phone,
        status=status,
        created_at=now,
        updated_at=now,
    )
    session.add(employee)
    session.flush()
    return employee


def get_employee(session: Session, employee_id: uuid.UUID) -> Employee | None:
    return session.get(Employee, employee_id)


def get_employee_by_email(session: Session, email: str) -> Employee | None:
    return session.scalar(select(Employee).where(Employee.email == email.strip().lower()))


def list_assigned_devices(session: Session) -> Sequence[Device]:
    """Every device that has an owner's address recorded, revoked ones excluded.

    For checking assignments against the employee directory. Revoked devices are
    left out because they already hold no valid identity - the laptop a leaver
    kept is only a problem while it still works, and listing the ones already
    shut off would bury the ones that are not.
    """
    return list(
        session.scalars(
            select(Device)
            .where(
                Device.assigned_to_email.is_not(None),
                Device.status != "revoked",
            )
            .order_by(Device.assigned_to_email, Device.hostname)
        ).all()
    )


def mark_agent_removed(session: Session, *, device: Device, reason: str | None) -> Device:
    """Record that this device's agent was uninstalled.

    The device's identity is deliberately left alone. It is not revoked, and
    `status` stays `active`: the laptop is still a company asset and the
    certificate is still one we issued. What changed is that nothing is
    enforcing on it, which is a coverage fact rather than a trust decision.
    Conflating the two would mean an uninstall quietly became a revocation,
    and a reinstall would then need a new token.
    """
    device.agent_removed_at = dt.datetime.now(dt.UTC)
    device.agent_removed_reason = reason[:200] if reason else None
    session.flush()
    return device


def count_fleet_coverage(session: Session) -> dict[str, int]:
    """How much of the estate is actually protected.

    Four mutually exclusive buckets, counted in the database so the answer does
    not depend on how many rows the dashboard happened to fetch:

    - `protected`    enrolled, not revoked, agent still present
    - `agent_removed` enrolled, but the agent was uninstalled
    - `never_enrolled` a company laptop that has never run the agent
    - `revoked`      identity withdrawn

    `protected` is the only one of the four that means a laptop is being
    enforced on, and it is deliberately the narrowest: a device counts as
    protected only if nothing has told us otherwise.
    """
    row = session.execute(
        select(
            func.count().label("total"),
            func.count(
                case(
                    (
                        and_(
                            Device.enrolled_at.is_not(None),
                            Device.status != "revoked",
                            Device.agent_removed_at.is_(None),
                        ),
                        1,
                    )
                )
            ).label("protected"),
            func.count(
                case(
                    (
                        and_(
                            Device.agent_removed_at.is_not(None),
                            Device.status != "revoked",
                        ),
                        1,
                    )
                )
            ).label("agent_removed"),
            func.count(
                case((and_(Device.enrolled_at.is_(None), Device.status != "revoked"), 1))
            ).label("never_enrolled"),
            func.count(case((Device.status == "revoked", 1))).label("revoked"),
        ).select_from(Device)
    ).one()
    return {
        "total": row.total,
        "protected": row.protected,
        "agent_removed": row.agent_removed,
        "never_enrolled": row.never_enrolled,
        "revoked": row.revoked,
    }


def devices_assigned_to_employee(session: Session, employee_id: uuid.UUID) -> Sequence[Device]:
    """Devices currently assigned to this employee.

    Current, not historical: a closed assignment interval is a record of the
    past and is no reason to stop anything. Used to refuse deleting somebody
    who still holds hardware.
    """
    return list(
        session.scalars(
            select(Device).where(Device.assigned_to_id == employee_id).order_by(Device.hostname)
        ).all()
    )


def find_devices_by_ids(session: Session, ids: Sequence[uuid.UUID]) -> Sequence[Device]:
    """Every device in `ids`. One statement, for labelling a page of rows."""
    wanted = set(ids)
    if not wanted:
        return []
    return list(session.scalars(select(Device).where(Device.id.in_(wanted))).all())


def find_employees_by_ids(session: Session, ids: Sequence[uuid.UUID]) -> Sequence[Employee]:
    """Every employee in `ids`. One statement, for annotating a page of rows."""
    wanted = set(ids)
    if not wanted:
        return []
    return list(session.scalars(select(Employee).where(Employee.id.in_(wanted))).all())


def find_employees_by_emails(session: Session, emails: Sequence[str]) -> Sequence[Employee]:
    """Every employee whose address is in `emails`.

    One statement instead of a lookup per address, because the directory picker
    needs to annotate a whole page of results with "already an employee" and
    doing that row by row is 25 round trips for one screen.
    """
    wanted = {email.strip().lower() for email in emails if email and email.strip()}
    if not wanted:
        # IN () is a syntax error in some dialects and an always-false in
        # others. Not asking is unambiguous.
        return []
    return list(session.scalars(select(Employee).where(Employee.email.in_(wanted))).all())


def list_employees(
    session: Session,
    *,
    search: str | None = None,
    department: str | None = None,
    status: str | None = None,
    limit: int = 200,
) -> Sequence[tuple[Employee, int]]:
    stmt = (
        select(
            Employee,
            func.count(Device.id).label("assigned_device_count"),
        )
        .outerjoin(Device, Device.assigned_to_id == Employee.id)
        .group_by(Employee.id)
        .order_by(Employee.full_name)
    )
    if search:
        pattern = f"%{search.strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Employee.full_name).like(pattern),
                func.lower(Employee.email).like(pattern),
                func.lower(Employee.department).like(pattern),
            )
        )
    if department:
        stmt = stmt.where(Employee.department == department)
    if status:
        stmt = stmt.where(Employee.status == status)

    return list(session.execute(stmt.limit(limit)).all())


def update_employee(
    session: Session,
    *,
    employee: Employee,
    full_name: str | None = None,
    email: str | None = None,
    department: str | None = None,
    job_title: str | None = None,
    phone: str | None = None,
    status: str | None = None,
) -> Employee:
    if full_name is not None:
        employee.full_name = full_name
    if email is not None:
        employee.email = email.strip().lower()
    if department is not None:
        employee.department = department
    if job_title is not None:
        employee.job_title = job_title
    if phone is not None:
        employee.phone = phone
    if status is not None:
        employee.status = status
    employee.updated_at = dt.datetime.now(dt.UTC)
    session.flush()
    return employee


def delete_employee(session: Session, employee: Employee) -> None:
    session.delete(employee)
    session.flush()


def assign_device(
    session: Session,
    *,
    device: Device,
    assigned_to_name: str,
    assigned_to_email: str | None = None,
    department: str | None = None,
    employee_id: uuid.UUID | None = None,
    assigned_by: uuid.UUID | None = None,
    notes: str | None = None,
) -> DeviceAssignment:
    now = dt.datetime.now(dt.UTC)

    # 1. Close any currently active assignment for this device
    active_assignments = session.scalars(
        select(DeviceAssignment).where(
            DeviceAssignment.device_id == device.id,
            DeviceAssignment.unassigned_at.is_(None),
        )
    ).all()
    for active in active_assignments:
        active.unassigned_at = now
        active.unassigned_by = assigned_by

    # 2. Update device record
    device.assigned_to_name = assigned_to_name
    device.assigned_to_email = assigned_to_email.strip().lower() if assigned_to_email else None
    device.department = department
    device.assigned_to_id = employee_id

    # 3. Create new assignment row
    assignment = DeviceAssignment(
        device_id=device.id,
        employee_id=employee_id,
        assigned_to_name=assigned_to_name,
        assigned_to_email=assigned_to_email.strip().lower() if assigned_to_email else None,
        department=department,
        notes=notes,
        assigned_at=now,
        assigned_by=assigned_by,
    )
    session.add(assignment)
    session.flush()
    return assignment


def unassign_device(
    session: Session,
    *,
    device: Device,
    unassigned_by: uuid.UUID | None = None,
) -> None:
    now = dt.datetime.now(dt.UTC)

    # 1. Close any active assignment
    active_assignments = session.scalars(
        select(DeviceAssignment).where(
            DeviceAssignment.device_id == device.id,
            DeviceAssignment.unassigned_at.is_(None),
        )
    ).all()
    for active in active_assignments:
        active.unassigned_at = now
        active.unassigned_by = unassigned_by

    # 2. Clear assignment fields on device
    device.assigned_to_name = None
    device.assigned_to_email = None
    device.department = None
    device.assigned_to_id = None
    session.flush()


def list_device_assignments(
    session: Session,
    device_id: uuid.UUID,
) -> Sequence[DeviceAssignment]:
    return list(
        session.scalars(
            select(DeviceAssignment)
            .where(DeviceAssignment.device_id == device_id)
            .order_by(DeviceAssignment.assigned_at.desc())
        )
    )


def check_offline_devices(
    session: Session,
    *,
    threshold_seconds: int | None = None,
) -> tuple[int, int, int, list[uuid.UUID]]:
    """Scan active enrolled devices and raise incidents for ones missing heartbeats.

    `threshold_seconds` defaults to the same value `liveness.is_online` uses, so
    the fleet list and the alerting agree about how long is too long. They were
    independent constants - 240 seconds on the list, 900 here - which meant a
    device displayed as offline for eleven minutes before anything was raised.
    Deriving one from the other is what stops them drifting apart again.
    """
    if threshold_seconds is None:
        threshold_seconds = offline_threshold_seconds()
    now = dt.datetime.now(dt.UTC)
    cutoff = now - dt.timedelta(seconds=threshold_seconds)

    # Find active enrolled devices
    devices = list(
        session.scalars(
            select(Device).where(
                Device.status == "active",
                Device.enrolled_at.is_not(None),
            )
        )
    )

    checked = len(devices)
    flagged: list[uuid.UUID] = []
    new_incidents = 0

    for dev in devices:
        last_seen = dev.last_heartbeat_at or dev.enrolled_at
        if last_seen is not None:
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=dt.UTC)
            if last_seen < cutoff:
                flagged.append(dev.id)

                # Check if there's already an open incident for this device
                existing = session.scalar(
                    select(Incident).where(
                        Incident.device_id == dev.id,
                        Incident.kind == "device_offline",
                        Incident.status.in_(OPEN_INCIDENT_STATUSES),
                    )
                )
                if not existing:
                    diff_minutes = max(1, int((now - last_seen).total_seconds() / 60))
                    dev_name = dev.display_name or dev.hostname or str(dev.id)[:8]
                    create_incident(
                        session,
                        kind="device_offline",
                        device_id=dev.id,
                        severity="medium",
                        summary=f"Device '{dev_name}' has not checked in for {diff_minutes} minutes.",
                        note=f"Last seen at {last_seen.isoformat()}. Threshold was {threshold_seconds}s.",
                    )
                    new_incidents += 1

    return checked, len(flagged), new_incidents, flagged


#: Statuses that mean somebody still has to look at this. Shared by the
#: offline sweep's duplicate check, the auto-resolve on reconnect and the
#: dashboard's open count, so "still needs attention" means one thing.
OPEN_INCIDENT_STATUSES: Sequence[str] = ("open", "acknowledged", "investigating")


def list_incidents(
    session: Session,
    *,
    status: str | None = None,
    kind: str | None = None,
    device_id: uuid.UUID | None = None,
    open_only: bool = False,
    limit: int = 100,
) -> Sequence[Incident]:
    """Incidents, newest first.

    Newest first because an operator opening an alert list wants what just
    happened, not what happened when the fleet was first enrolled. The audit
    log is the opposite by design - it is a chain and reads forwards.
    """
    stmt = select(Incident).order_by(Incident.opened_at.desc())
    if open_only:
        stmt = stmt.where(Incident.status.in_(OPEN_INCIDENT_STATUSES))
    if status:
        stmt = stmt.where(Incident.status == status)
    if kind:
        stmt = stmt.where(Incident.kind == kind)
    if device_id is not None:
        stmt = stmt.where(Incident.device_id == device_id)
    return list(session.scalars(stmt.limit(limit)).all())


def get_incident(session: Session, incident_id: uuid.UUID) -> Incident | None:
    return session.get(Incident, incident_id)


def count_open_incidents(session: Session) -> int:
    """How many incidents still need a human. Counted in the database.

    Same reasoning as the fleet counts: deriving this from a fetched page goes
    quietly wrong the moment there are more incidents than the page holds.
    """
    return int(
        session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(OPEN_INCIDENT_STATUSES))
        )
        or 0
    )


def update_incident(
    session: Session,
    *,
    incident: Incident,
    status: str | None = None,
    note: str | None = None,
    assigned_to: uuid.UUID | None = None,
) -> Incident:
    """Change an incident's status, appending rather than replacing its note.

    Appending matters. The note already carries whatever raised the alert - how
    long a device had been silent, or the automatic resolution when it came
    back - and overwriting it would destroy the history of the thing being
    triaged in the act of triaging it.

    `closed_at` is set when the status becomes terminal and cleared if an
    incident is reopened, so "closed" and "has a closing time" cannot disagree.
    """
    now = dt.datetime.now(dt.UTC)
    if status is not None:
        incident.status = status
        if status in ("resolved", "false_positive"):
            incident.closed_at = now
        else:
            # Reopened. Leaving a stale closed_at behind would make a live
            # incident look finished to anything reading that column.
            incident.closed_at = None
    if note:
        stamp = f"[{now.isoformat(timespec='seconds')}] {note}"
        incident.note = f"{incident.note}\n{stamp}" if incident.note else stamp
    if assigned_to is not None:
        incident.assigned_to = assigned_to
    incident.updated_at = now
    session.flush()
    return incident


def resolve_offline_incidents_for_device(
    session: Session,
    device_id: uuid.UUID,
) -> None:
    now = dt.datetime.now(dt.UTC)
    open_incidents = session.scalars(
        select(Incident).where(
            Incident.device_id == device_id,
            Incident.kind == "device_offline",
            Incident.status.in_(OPEN_INCIDENT_STATUSES),
        )
    ).all()
    for inc in open_incidents:
        inc.status = "resolved"
        inc.closed_at = now
        inc.updated_at = now
        inc.note = (inc.note or "") + f"\n[Auto-resolved] Device reconnected at {now.isoformat()}."
    if open_incidents:
        session.flush()


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
#
# Policies are immutable. Nothing here updates `policies`; a change is always a
# new row with a higher version, which is what makes the agent's downgrade
# rejection meaningful and leaves a history nobody can quietly rewrite.
#
# Two reads carry the weight in this section:
#
# `next_policy_version` takes the version from a MAX over the existing rows
# rather than counting them. Counting would reuse a number if a row were ever
# removed, and a reused version is one the agent would refuse as a downgrade.
#
# `effective_policy_for_device` is where scope is resolved. A device-scoped
# policy beats a fleet-scoped one, and within a scope the highest version wins.
# The precedence is explicit in the query rather than left to insertion order,
# because "which policy is this laptop actually under" is the question the
# whole feature answers.


def next_policy_version(
    session: Session,
    *,
    policy_type: str,
    scope_kind: str,
    scope_id: str,
) -> int:
    """The next version for a policy type and scope. Starts at 1."""
    current = session.scalar(
        select(func.max(Policy.version)).where(
            Policy.policy_type == policy_type,
            Policy.scope_kind == scope_kind,
            Policy.scope_id == scope_id,
        )
    )
    return int(current or 0) + 1


def create_policy(
    session: Session,
    *,
    policy_id: uuid.UUID,
    policy_type: str,
    version: int,
    scope_kind: str,
    scope_id: str,
    payload: bytes,
    payload_sha256: str,
    signature_b64: str,
    signing_key_id: str,
    issued_at: dt.datetime,
    issued_at_text: str,
    expires_at: dt.datetime | None,
    expires_at_text: str | None,
    created_by: uuid.UUID,
) -> Policy:
    """Store an already-signed policy.

    `policy_id` is supplied rather than generated here because it is part of
    the signing input: the signature covers the id, so the row must carry the
    same one the envelope was signed with.

    `payload` is the exact bytes that were signed. They are never re-serialized
    on the way in or out.
    """
    row = Policy(
        id=policy_id,
        policy_type=policy_type,
        version=version,
        scope_kind=scope_kind,
        scope_id=scope_id,
        payload=payload,
        payload_sha256=payload_sha256,
        signature_b64=signature_b64,
        signing_key_id=signing_key_id,
        issued_at=issued_at,
        issued_at_text=issued_at_text,
        expires_at=expires_at,
        expires_at_text=expires_at_text,
        created_by=created_by,
    )
    session.add(row)
    session.flush()
    return row


def get_policy(session: Session, policy_id: uuid.UUID) -> Policy | None:
    return session.get(Policy, policy_id)


def list_policies(
    session: Session,
    *,
    policy_type: str | None = None,
    scope_kind: str | None = None,
    scope_id: str | None = None,
    limit: int = 100,
) -> Sequence[Policy]:
    query = select(Policy)
    if policy_type is not None:
        query = query.where(Policy.policy_type == policy_type)
    if scope_kind is not None:
        query = query.where(Policy.scope_kind == scope_kind)
    if scope_id is not None:
        query = query.where(Policy.scope_id == scope_id)
    query = query.order_by(Policy.created_at.desc()).limit(limit)
    return session.scalars(query).all()


def assign_policy(
    session: Session,
    *,
    policy_id: uuid.UUID,
    device_id: uuid.UUID,
    assigned_by: uuid.UUID,
) -> PolicyAssignment:
    """Attach a policy to one device, retiring any live assignment of the
    same policy to it.

    Re-assigning the same policy is treated as reviving the existing row
    rather than inserting a second one, because `policy_assignments` is unique
    on (policy_id, device_id) and a plain insert would fail on the retry a
    flaky network produces.
    """
    existing = session.scalar(
        select(PolicyAssignment).where(
            PolicyAssignment.policy_id == policy_id,
            PolicyAssignment.device_id == device_id,
        )
    )
    now = dt.datetime.now(dt.UTC)
    if existing is not None:
        existing.unassigned_at = None
        existing.assigned_at = now
        existing.assigned_by = assigned_by
        session.flush()
        return existing

    row = PolicyAssignment(
        policy_id=policy_id,
        device_id=device_id,
        assigned_at=now,
        assigned_by=assigned_by,
    )
    session.add(row)
    session.flush()
    return row


def unassign_policies_of_type(
    session: Session,
    *,
    device_id: uuid.UUID,
    policy_type: str,
) -> int:
    """Retire this device's live assignments for one policy type.

    Called before assigning a replacement, so a device is never under two
    versions of the same policy type at once. Returns how many were retired.

    Marks `unassigned_at` rather than deleting: the history of what a laptop
    was under, and when, is the part an auditor asks about.
    """
    live = session.scalars(
        select(PolicyAssignment)
        .join(Policy, Policy.id == PolicyAssignment.policy_id)
        .where(
            PolicyAssignment.device_id == device_id,
            PolicyAssignment.unassigned_at.is_(None),
            Policy.policy_type == policy_type,
        )
    ).all()
    now = dt.datetime.now(dt.UTC)
    for row in live:
        row.unassigned_at = now
    if live:
        session.flush()
    return len(live)


def effective_policy_for_device(
    session: Session,
    *,
    device_id: uuid.UUID,
    policy_type: str,
) -> Policy | None:
    """The policy this device is actually under, or None.

    Device-scoped assignment first, fleet-scoped as the fallback. Within
    either, the highest version wins. A group scope is accepted by the schema
    but not resolved here, because nothing creates one yet; when something
    does, it belongs between the two.
    """
    assigned = session.scalar(
        select(Policy)
        .join(PolicyAssignment, PolicyAssignment.policy_id == Policy.id)
        .where(
            PolicyAssignment.device_id == device_id,
            PolicyAssignment.unassigned_at.is_(None),
            Policy.policy_type == policy_type,
        )
        .order_by(Policy.version.desc())
        .limit(1)
    )
    if assigned is not None:
        return assigned

    return session.scalar(
        select(Policy)
        .where(
            Policy.policy_type == policy_type,
            Policy.scope_kind == "fleet",
        )
        .order_by(Policy.version.desc())
        .limit(1)
    )


def available_policies_for_device(
    session: Session,
    *,
    device_id: uuid.UUID,
) -> list[dict[str, int | str]]:
    """What the heartbeat advertises: one entry per policy type in force.

    Deliberately only identifiers and a version, never the policy itself. The
    heartbeat says what exists; the agent decides whether it needs it and pulls
    it over a separate authenticated request. That split is why a heartbeat
    response cannot be used to push anything at a laptop.
    """
    out: list[dict[str, int | str]] = []
    for policy_type in POLICY_TYPES:
        policy = effective_policy_for_device(session, device_id=device_id, policy_type=policy_type)
        if policy is not None:
            out.append(
                {
                    "policy_type": policy.policy_type,
                    "policy_id": str(policy.id),
                    "policy_version": policy.version,
                }
            )
    return out


# --------------------------------------------------------------------------- #
# What devices report back about applying a policy
# --------------------------------------------------------------------------- #


def record_policy_status(
    session: Session,
    *,
    device_id: uuid.UUID,
    policy_id: uuid.UUID,
    status: str,
    reason_code: str | None = None,
    detail: str | None = None,
    verified_state: dict[str, Any] | None = None,
) -> DevicePolicyStatus:
    """Record, or replace, what a device reports for one policy.

    One row per (device, policy): the table is unique on that pair, and the
    latest report is the one that matters. The previous report for the same
    pair is of no interest once superseded -- the audit log carries the history
    that is worth keeping.

    `verified_state` is what the agent read back from the operating system, not
    what it intended to do. A status of `applied` without it is a claim; with
    it, it is evidence.
    """
    row = session.scalar(
        select(DevicePolicyStatus).where(
            DevicePolicyStatus.device_id == device_id,
            DevicePolicyStatus.policy_id == policy_id,
        )
    )
    now = dt.datetime.now(dt.UTC)
    if row is None:
        row = DevicePolicyStatus(device_id=device_id, policy_id=policy_id, status=status)
        session.add(row)
    row.status = status
    row.reason_code = reason_code[:48] if reason_code else None
    row.detail = detail[:512] if detail else None
    row.verified_state = verified_state
    row.reported_at = now
    session.flush()
    return row


def get_policy_status(
    session: Session,
    *,
    device_id: uuid.UUID,
    policy_id: uuid.UUID,
) -> DevicePolicyStatus | None:
    return session.scalar(
        select(DevicePolicyStatus).where(
            DevicePolicyStatus.device_id == device_id,
            DevicePolicyStatus.policy_id == policy_id,
        )
    )


def policy_statuses_for_device(
    session: Session,
    *,
    device_id: uuid.UUID,
) -> Sequence[DevicePolicyStatus]:
    return session.scalars(
        select(DevicePolicyStatus)
        .where(DevicePolicyStatus.device_id == device_id)
        .order_by(DevicePolicyStatus.reported_at.desc())
    ).all()
