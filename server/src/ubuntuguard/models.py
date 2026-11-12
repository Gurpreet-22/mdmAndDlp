"""SQLAlchemy 2 data model.

Decisions worth knowing before reading
--------------------------------------
**Named constraints.** The metadata carries a naming convention, so every
index, unique, check and foreign key gets a deterministic name. Without it,
PostgreSQL invents names and an Alembic `downgrade` cannot reliably drop a
constraint it never named. The brief asks for migrations tested in both
directions, which is only achievable if downgrades can find what to remove.

**Enumerated values are VARCHAR plus a CHECK, not PostgreSQL ENUM types.**
Adding a value to a native enum needs `ALTER TYPE`, which in older PostgreSQL
could not run in a transaction and still makes downgrades awkward. A CHECK
constraint gives the same validation with an ordinary, reversible migration.

**Exact bytes where bytes are signed or hashed.** `policies.payload` and
`audit_logs.detail_json` are BYTEA, not JSONB. Both are covered by a signature
or a hash chain, and JSONB normalises whitespace and key order on the way in,
which would silently invalidate every signature. Where we query the content we
store JSONB; where we verify it we store bytes.

**Policy timestamps are stored twice.** `issued_at` as `timestamptz` for
querying, and `issued_at_text` as the exact string that went into the signing
input. Re-deriving the string from the timestamp would work today, but one
change to the formatter would break verification for every stored policy.

**`events.event_id` is the primary key.** The agent generates it, so
at-least-once delivery becomes exactly-once storage through an ordinary
`ON CONFLICT DO NOTHING` rather than application-level deduplication.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# --------------------------------------------------------------------------- #
# Enumerated values, mirrored into CHECK constraints
# --------------------------------------------------------------------------- #

ROLES = ("super_admin", "it_admin", "security_analyst", "auditor")
DEVICE_STATUSES = ("pending", "active", "revoked")
#: Target platforms. Only `linux` has an agent; the other two exist so the
#: server can record what a device IS without pretending it can manage it. See
#: docs/04-feature-list.md section 3: platform neutrality is kept in the shape
#: of the code, but only Ubuntu will be implemented.
DEVICE_PLATFORMS = ("linux", "macos", "windows")
POLICY_TYPES = ("usb_control", "agent_settings")
POLICY_SCOPE_KINDS = ("device", "group", "fleet")
POLICY_STATUSES = ("pending", "applied", "failed", "unsupported", "rolled_back")
INCIDENT_STATUSES = ("open", "acknowledged", "investigating", "resolved", "false_positive")
INCIDENT_KINDS = (
    "usb_blocked",
    "clone_suspected",
    "policy_rollback_failed",
    "enforcer_unavailable",
    "capability_lost",
    "audit_chain_broken",
)
TOKEN_KINDS = ("access", "refresh")
EVENT_KINDS = ("usb", "agent")
SERIAL_MATCH_MODES = ("exact", "any")

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _in_list(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({rendered})"


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def timestamp(**kwargs: object) -> Mapped[dt.datetime]:
    """A timezone-aware timestamp. Naive timestamps are never stored."""
    return mapped_column(DateTime(timezone=True), **kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Admin identity
# --------------------------------------------------------------------------- #


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(_in_list("role", ROLES), name="role_valid"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    # Stored lowercase and compared lowercase, so Alice@ and alice@ cannot
    # become two accounts with different privileges.
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    locked_until: Mapped[dt.datetime | None] = timestamp(nullable=True)
    created_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    updated_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    last_login_at: Mapped[dt.datetime | None] = timestamp(nullable=True)


class LoginAttempt(Base):
    """Every login attempt, success or failure.

    A counter column on `users` would be cheaper, but it cannot answer "five
    failures in the last ten minutes" - the rolling window the brief specifies.
    Rows are also what make a brute-force attempt visible after the fact.
    """

    __tablename__ = "login_attempts"
    __table_args__ = (Index("ix_login_attempts_email_at", "email", "attempted_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Not a foreign key: attempts against a non-existent account must be
    # recorded too, and that is exactly when there is no user row to point at.
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attempted_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)


class AuthToken(Base):
    """Opaque access and refresh tokens, stored only as hashes.

    Access and refresh share one table so that revoking a family revokes both
    in a single statement. `family_id` groups a login session across refresh
    rotations: presenting an already-used refresh token revokes the whole
    family, which is the standard detection for a stolen refresh token.
    """

    __tablename__ = "auth_tokens"
    __table_args__ = (
        CheckConstraint(_in_list("kind", TOKEN_KINDS), name="kind_valid"),
        Index("ix_auth_tokens_family_id", "family_id"),
        Index("ix_auth_tokens_user_id_kind", "user_id", "kind"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    family_id: Mapped[uuid.UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # SHA-256 hex. The plaintext is never stored, so a database backup yields
    # no usable token.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    issued_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    expires_at: Mapped[dt.datetime] = timestamp(nullable=False)
    used_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    revoked_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("auth_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )


# --------------------------------------------------------------------------- #
# Devices and enrollment
# --------------------------------------------------------------------------- #


class Device(Base):
    """A laptop, from the moment an administrator registers it.

    A row exists in one of two ways, and the difference is the whole point of
    tracking "unenrolled":

    **Registered.** An administrator adds the device in the dashboard before it
    has ever been touched. `status` is `pending`, `enrolled_at` is NULL, and the
    administrator-supplied fields (`display_name`, `manufacturer`,
    `assigned_to_*`) are the only thing known about it.

    **Enrolled.** The agent presents a valid enrollment token and a CSR. If that
    token was issued for a registered device, enrollment CLAIMS that row rather
    than creating a second one, filling in the facts only the device can know -
    hostname, OS, kernel, architecture, hardware fingerprint - and setting
    `status` to `active` with `enrolled_at` set.

    So `enrolled_at IS NULL` is the precise definition of unenrolled, and it is
    the server's own record of an event it witnessed, never a device's claim.
    """

    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(_in_list("status", DEVICE_STATUSES), name="status_valid"),
        CheckConstraint(
            _in_list("platform", DEVICE_PLATFORMS) + " OR platform IS NULL",
            name="platform_valid",
        ),
        # An enrolled device has been seen; a pending one has not. Stated as a
        # constraint so no code path can produce "enrolled but never enrolled_at"
        # or a pending row claiming an enrollment timestamp.
        CheckConstraint(
            "(status = 'pending' AND enrolled_at IS NULL) "
            "OR (status <> 'pending' AND enrolled_at IS NOT NULL)",
            name="enrolled_at_matches_status",
        ),
        Index("ix_devices_hostname", "hostname"),
        Index("ix_devices_last_heartbeat_at", "last_heartbeat_at"),
        Index("ix_devices_machine_id_hash", "machine_id_hash"),
        Index("ix_devices_status", "status"),
        Index("ix_devices_assigned_to_email", "assigned_to_email"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    # Nullable because a registered device has not reported its hostname yet.
    # Only the device itself can know this, so the server refuses to guess.
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # --- Administrator-supplied, known before the device is ever seen ------ #
    #: Human label, e.g. "Ethan's laptop". Shown in the fleet list.
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    #: The employee the laptop is issued to. Plain contact detail, deliberately
    #: not a foreign key: employees are not administrators and have no account.
    assigned_to_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    assigned_to_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(16), nullable=True)
    asset_tag: Mapped[str | None] = mapped_column(String(64), nullable=True)

    registered_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    registered_by: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Certificate pin. Checked on every device request, which is what binds a
    # connection to this row.
    cert_fingerprint: Mapped[str | None] = mapped_column(String(71), nullable=True, unique=True)
    cert_not_after: Mapped[dt.datetime | None] = timestamp(nullable=True)

    #: NULL until the agent completes enrollment. This is what "unenrolled"
    #: means, and it is a fact the server observed rather than one reported.
    enrolled_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    last_heartbeat_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    last_inventory_at: Mapped[dt.datetime | None] = timestamp(nullable=True)

    #: Last address the agent reported. Informational only: it is self-reported,
    #: trivially spoofable, and never used for authentication or authorisation.
    primary_adapter_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    release_build: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    os_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    os_version_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kernel: Mapped[str | None] = mapped_column(String(128), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Hashed on the agent; raw values never leave the device.
    machine_id_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dmi_product_uuid_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    virtualization: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # A fingerprint collision does not block enrollment. The new device is
    # created as distinct and flagged, because a reimaged laptop and a cloned
    # VM look identical here and only a human can tell them apart.
    clone_suspected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    clone_of_device_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )

    revoked_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    #: Set when the token was minted for an already-registered device. On
    #: enrollment that device's row is CLAIMED instead of a new one being
    #: created, which is what stops "add a device" and "the device arrives"
    #: producing two rows for one laptop.
    #:
    #: Distinct from `consumed_by_device_id`: this one is the INTENT, recorded
    #: when the token is issued, and the other is the OUTCOME, recorded when it
    #: is spent. For a pre-registered device they end up equal, and a mismatch
    #: would be a bug worth seeing in the data rather than hiding behind one
    #: reused column.
    pre_registered_device_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    expires_at: Mapped[dt.datetime] = timestamp(nullable=False)
    # Single use is enforced by one statement:
    #   UPDATE enrollment_tokens SET consumed_at = now()
    #    WHERE id = :id AND consumed_at IS NULL RETURNING id
    # Two concurrent callers therefore produce exactly one RETURNING row.
    consumed_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    consumed_by_device_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[dt.datetime | None] = timestamp(nullable=True)


class EnrollmentAttempt(Base):
    """Idempotency cache so an interrupted enrollment can be retried.

    Keyed by token hash AND the CSR's public key. A retry with the same keypair
    gets the identical response; the same token with a DIFFERENT keypair is
    refused, because the token is spent. That distinction is what makes retries
    safe without making the token reusable.
    """

    __tablename__ = "enrollment_attempts"
    __table_args__ = (
        UniqueConstraint("token_hash", "csr_public_key_fingerprint", name="token_hash_csr"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    csr_public_key_fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=True
    )
    response_json: Mapped[dict[str, Any]] = mapped_column(postgresql.JSONB, nullable=False)
    created_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())


class IssuedCertificate(Base):
    """Every certificate the internal CA has issued, including superseded ones.

    Kept after renewal so an old fingerprint seen in a log can still be
    attributed to a device.
    """

    __tablename__ = "issued_certificates"
    __table_args__ = (Index("ix_issued_certificates_device_id", "device_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    device_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(71), nullable=False, unique=True)
    serial_number: Mapped[str] = mapped_column(String(64), nullable=False)
    not_before: Mapped[dt.datetime] = timestamp(nullable=False)
    not_after: Mapped[dt.datetime] = timestamp(nullable=False)
    pem: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    superseded_at: Mapped[dt.datetime | None] = timestamp(nullable=True)


class DeviceInventory(Base):
    """Latest inventory per device, replaced wholesale on each report.

    JSONB rather than a wide table: the adapter-specific section is explicitly
    opaque to the server, and columns for Ubuntu facts would make the server
    Ubuntu-specific.
    """

    __tablename__ = "device_inventory"

    device_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        primary_key=True,
    )
    collected_at: Mapped[dt.datetime] = timestamp(nullable=False)
    received_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    payload: Mapped[dict[str, Any]] = mapped_column(postgresql.JSONB, nullable=False)


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #


class Policy(Base):
    """An immutable, signed policy version.

    Never updated. A change is a new row with a higher `version`, which is what
    makes the agent's downgrade rejection meaningful and leaves an unambiguous
    history. The application role should hold INSERT and SELECT here, not
    UPDATE or DELETE.
    """

    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint(_in_list("policy_type", POLICY_TYPES), name="policy_type_valid"),
        CheckConstraint(_in_list("scope_kind", POLICY_SCOPE_KINDS), name="scope_kind_valid"),
        CheckConstraint("version >= 1", name="version_positive"),
        UniqueConstraint(
            "policy_type", "scope_kind", "scope_id", "version", name="type_scope_version"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    policy_type: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    scope_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # BYTEA, not JSONB. These are the exact bytes covered by the signature;
    # JSONB would re-encode them and invalidate every signature.
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_b64: Mapped[str] = mapped_column(String(88), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(32), nullable=False)

    # Timestamps twice over: queryable, and byte-exact for the signing input.
    issued_at: Mapped[dt.datetime] = timestamp(nullable=False)
    issued_at_text: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    expires_at_text: Mapped[str | None] = mapped_column(String(32), nullable=True)

    created_by: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())


class PolicyAssignment(Base):
    __tablename__ = "policy_assignments"
    __table_args__ = (
        UniqueConstraint("policy_id", "device_id", name="policy_device"),
        Index("ix_policy_assignments_device_id", "device_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    policy_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    assigned_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    assigned_by: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    unassigned_at: Mapped[dt.datetime | None] = timestamp(nullable=True)


class DevicePolicyStatus(Base):
    """What a device reports about applying a policy.

    `verified_state` holds what the agent read back from the operating system,
    not what it intended. A row saying `applied` without it would be a claim;
    with it, it is evidence.
    """

    __tablename__ = "device_policy_status"
    __table_args__ = (
        CheckConstraint(_in_list("status", POLICY_STATUSES), name="status_valid"),
        UniqueConstraint("device_id", "policy_id", name="device_policy"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    device_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reported_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    verified_state: Mapped[dict[str, Any] | None] = mapped_column(postgresql.JSONB, nullable=True)


# --------------------------------------------------------------------------- #
# Telemetry
# --------------------------------------------------------------------------- #


class Event(Base):
    """A device-reported event.

    The agent-generated `event_id` is the primary key, so re-delivery collides
    and `ON CONFLICT DO NOTHING` turns at-least-once transport into
    exactly-once storage with no application-level bookkeeping.
    """

    __tablename__ = "events"
    __table_args__ = (
        CheckConstraint(_in_list("kind", EVENT_KINDS), name="kind_valid"),
        Index("ix_events_device_id_occurred_at", "device_id", "occurred_at"),
        Index("ix_events_occurred_at", "occurred_at"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(postgresql.UUID(as_uuid=True), primary_key=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    # Agent wall clock, kept as reported. Server receipt time is separate, so a
    # device with a skewed clock is visible rather than silently corrected.
    occurred_at: Mapped[dt.datetime] = timestamp(nullable=False)
    received_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    payload: Mapped[dict[str, Any]] = mapped_column(postgresql.JSONB, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(_in_list("status", INCIDENT_STATUSES), name="status_valid"),
        CheckConstraint(_in_list("kind", INCIDENT_KINDS), name="kind_valid"),
        Index("ix_incidents_status_opened_at", "status", "opened_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open", server_default="open"
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", server_default="medium"
    )
    summary: Mapped[str] = mapped_column(String(256), nullable=False)
    opened_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    updated_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    closed_at: Mapped[dt.datetime | None] = timestamp(nullable=True)
    note: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class UsbException(Base):
    """A time-bound admin grant permitting one USB device.

    The 24 hour ceiling is checked in the application and again by the agent.
    A CHECK constraint cannot express it, because `now()` is not immutable and
    so cannot appear in one.
    """

    __tablename__ = "usb_exceptions"
    __table_args__ = (
        CheckConstraint(_in_list("serial_match", SERIAL_MATCH_MODES), name="serial_match_valid"),
        CheckConstraint("length(reason) >= 8", name="reason_substantive"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_usb_exceptions_device_id_expires_at", "device_id", "expires_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    device_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    vendor_id: Mapped[str] = mapped_column(String(4), nullable=False)
    product_id: Mapped[str] = mapped_column(String(4), nullable=False)
    serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    serial_match: Mapped[str] = mapped_column(String(8), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[dt.datetime] = timestamp(nullable=False, server_default=func.now())
    expires_at: Mapped[dt.datetime] = timestamp(nullable=False)
    revoked_at: Mapped[dt.datetime | None] = timestamp(nullable=True)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


class AuditLog(Base):
    """Append-only, hash-chained audit log.

    Two independent barriers protect this table. The application database role
    holds only SELECT and INSERT, so an UPDATE or DELETE through the app is
    refused by PostgreSQL. And each row's hash covers the previous row's hash,
    so a change made around the application is detectable afterwards.

    `detail_json` is BYTEA because the hash covers the exact stored bytes.
    JSONB would reorder keys on the way in and break the chain on read-back.

    What this does NOT stop: a database superuser rewriting the table and
    recomputing every hash. Detecting that needs the chain head anchored
    outside the database. Out of scope for the prototype, and recorded in the
    known-limitations page rather than glossed over.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_occurred_at", "occurred_at"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_actor_id", "actor_id"),
        Index("ix_audit_logs_target_type_target_id", "target_type", "target_id"),
    )

    # BIGSERIAL. The chain depends on a gapless sequence, so a deletion shows
    # up as a missing number even before any hash is recomputed.
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[dt.datetime] = timestamp(nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    # Not a foreign key: a user row may be deleted, and the audit record of
    # what they did must survive them.
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)


#: Every table, for the DDL tests and for Alembic's autogenerate target.
ALL_TABLES = tuple(Base.metadata.sorted_tables)
