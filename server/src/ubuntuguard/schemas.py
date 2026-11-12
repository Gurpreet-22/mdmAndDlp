"""Pydantic request and response models.

`extra="forbid"` on every request model. Silently dropping an unknown field
hides protocol drift and lets a client believe it sent something that was
ignored, which is how a policy field quietly stops being applied.

Response models never carry a secret. The one exception is deliberate and
one-shot: the plaintext of a freshly created enrollment token, which is the only
moment it exists outside the agent that will consume it.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints

from ubuntuguard.constants import (
    ENROLLMENT_TOKEN_DEFAULT_TTL_SECONDS,
)
from ubuntuguard.security.passwords import MAX_PASSWORD_BYTES, MIN_PASSWORD_LENGTH

Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=120)]

#: Longest address we accept. RFC 5321's limit on a forward path.
MAX_EMAIL_LENGTH = 320


def normalise_email(value: str) -> str:
    """Structural check and lowercasing for an admin login identifier.

    Deliberately NOT full RFC validation. `pydantic[email]` was tried and
    removed: email-validator rejects RFC 2606 reserved domains, so
    `admin@example.invalid` fails and `admin@company.internal` or
    `admin@localhost` would too. An MDM deployed inside a company is exactly
    where those addresses turn up, and refusing a legitimate one is a worse bug
    than accepting an odd-looking one.

    What is enforced is what actually matters here: a bounded length so the
    column and the index behave, exactly one @ with both halves present, no
    whitespace, and lowercasing so Alice@ and alice@ cannot become two accounts
    with different privileges. The database has a CHECK constraint for that last
    one as well.
    """
    if not isinstance(value, str):
        raise ValueError("email must be a string")
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("email must not be empty")
    if len(cleaned.encode("utf-8")) > MAX_EMAIL_LENGTH:
        raise ValueError(f"email must be at most {MAX_EMAIL_LENGTH} bytes")
    if any(character.isspace() for character in cleaned):
        raise ValueError("email must not contain whitespace")
    if cleaned.count("@") != 1:
        raise ValueError("email must contain exactly one @")
    local, _, domain = cleaned.partition("@")
    if not local or not domain:
        raise ValueError("email must have text on both sides of the @")
    if ".." in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("email domain is malformed")
    return cleaned


AdminEmail = Annotated[str, BeforeValidator(normalise_email)]


def normalise_ip_address(value: str) -> str:
    """Accept only a real IPv4 or IPv6 address, returned in canonical form.

    Validated rather than stored as free text for one reason: this value is
    self-reported by the agent and rendered straight into the dashboard. An
    unvalidated string there is somewhere an attacker controls that an operator
    reads, so it is bounded to a shape that cannot carry anything else.

    It is still only informational. Nothing authenticates or authorises on it.
    """
    if not isinstance(value, str):
        raise ValueError("ip address must be a string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("not a valid IPv4 or IPv6 address") from exc


IpAddressText = Annotated[str, BeforeValidator(normalise_ip_address)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


class LoginRequest(StrictModel):
    email: AdminEmail
    # Bounded here as well as in the hasher: an unbounded password field turns
    # one unauthenticated request into unbounded Argon2 work.
    password: Annotated[str, StringConstraints(min_length=1, max_length=MAX_PASSWORD_BYTES)]


class TokenResponse(BaseModel):
    """The access token. The refresh token goes out as an httpOnly cookie.

    Keeping the refresh token out of the body means JavaScript in the dashboard
    never touches it, so an XSS bug cannot read it.
    """

    access_token: str
    # noqa S105: "bearer" is the HTTP auth scheme name, not a credential.
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int = Field(description="Seconds until the access token expires.")


class MeResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    role: str
    capabilities: list[str] = Field(
        description=(
            "What this role may do. The dashboard uses it to hide controls; the "
            "server enforces every call regardless, because a hidden button is "
            "not a security boundary."
        )
    )


class CreateUserRequest(StrictModel):
    email: AdminEmail
    password: Annotated[
        str, StringConstraints(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_BYTES)
    ]
    role: Literal["super_admin", "it_admin", "security_analyst", "auditor"]


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    is_active: bool
    created_at: dt.datetime
    last_login_at: dt.datetime | None


class AuthModeResponse(BaseModel):
    """How the server authenticates, so the login page can warn accordingly."""

    any_login: bool = Field(
        description=(
            "True when the server accepts any email and password and creates the "
            "account on first sight. A development placeholder for SSO."
        )
    )


# --------------------------------------------------------------------------- #
# Enrollment tokens (admin side)
# --------------------------------------------------------------------------- #


class CreateEnrollmentTokenRequest(StrictModel):
    label: ShortText | None = Field(
        default=None, description="Operator note, e.g. the laptop this is for."
    )
    ttl_seconds: int = Field(
        default=ENROLLMENT_TOKEN_DEFAULT_TTL_SECONDS,
        ge=60,
        le=ENROLLMENT_TOKEN_DEFAULT_TTL_SECONDS,
        description="Lifetime, capped at 24 hours.",
    )


class CreateEnrollmentTokenResponse(BaseModel):
    id: uuid.UUID
    enrollment_token: str = Field(
        description=(
            "RETURNED EXACTLY ONCE. Only the hash is stored, so this cannot be "
            "recovered afterwards; issue a new token instead."
        )
    )
    expires_at: dt.datetime
    label: str | None


class EnrollmentTokenResponse(BaseModel):
    """Metadata only. Neither the token nor its hash is ever listed."""

    id: uuid.UUID
    label: str | None
    created_at: dt.datetime
    expires_at: dt.datetime
    consumed_at: dt.datetime | None
    revoked_at: dt.datetime | None
    consumed_by_device_id: uuid.UUID | None
    status: Literal["active", "consumed", "expired", "revoked"]


# --------------------------------------------------------------------------- #
# Device enrollment (device side, no bearer token)
# --------------------------------------------------------------------------- #


class HardwareFingerprint(StrictModel):
    """Hashed on the agent. Raw identifiers never leave the device.

    Advisory only: a collision does not block enrollment. A reimaged laptop and
    a cloned VM look identical here, and only a human can tell them apart, so
    the server records a distinct device and raises an alert.
    """

    machine_id_hash: Hex64 | None = None
    dmi_product_uuid_hash: Hex64 | None = None
    mac_hashes: list[Hex64] = Field(default_factory=list, max_length=32)
    virtualization: Annotated[str, StringConstraints(max_length=32)] | None = None


class OsInfo(StrictModel):
    id: Annotated[str, StringConstraints(max_length=32)]
    version_id: Annotated[str, StringConstraints(max_length=32)]
    kernel: Annotated[str, StringConstraints(max_length=128)]
    pretty_name: Annotated[str, StringConstraints(max_length=128)] | None = None


class EnrollRequest(StrictModel):
    enrollment_token: Annotated[str, StringConstraints(min_length=20, max_length=128)]
    csr_pem: Annotated[str, StringConstraints(min_length=64, max_length=8192)]
    hostname: Annotated[str, StringConstraints(min_length=1, max_length=253)]
    agent_version: Annotated[str, StringConstraints(max_length=64)]
    arch: Annotated[str, StringConstraints(max_length=32)]
    os: OsInfo
    hardware_fingerprint: HardwareFingerprint = Field(default_factory=HardwareFingerprint)
    release_build: bool = True
    primary_adapter_ip: IpAddressText | None = Field(
        default=None,
        description=(
            "Address of the agent's primary adapter. Informational inventory "
            "only; the server never uses it to identify or authorise a device."
        ),
    )


class PolicyPublicKey(BaseModel):
    key_id: str
    alg: Literal["ed25519"]
    public_key_b64: str


class EnrollResponse(BaseModel):
    device_id: uuid.UUID
    client_certificate_pem: str
    ca_chain_pem: str
    certificate_not_after: dt.datetime
    certificate_renew_after: dt.datetime = Field(
        description="When to start renewing: 50 % through the certificate's life."
    )
    policy_public_keys: list[PolicyPublicKey] = Field(
        description="Pinned by the agent. Policy signatures are checked against these."
    )
    clone_suspected: bool = Field(
        description=(
            "True when this device's hardware fingerprint matches an existing "
            "one. Enrollment still succeeds as a distinct device, and an "
            "incident is raised for a human to judge."
        )
    )


# --------------------------------------------------------------------------- #
# Devices (admin side)
# --------------------------------------------------------------------------- #


class DeviceSummary(BaseModel):
    id: uuid.UUID
    hostname: str | None = Field(
        description="NULL until the agent enrolls: only the device can report it."
    )
    status: str
    online: bool = Field(
        description=(
            "Computed by the server from last_heartbeat_at, never self-reported. "
            "Shown alongside last_heartbeat_at so 'online' is never a bare claim."
        )
    )
    enrolled: bool = Field(
        description=(
            "Whether the agent has completed enrollment. Derived from "
            "enrolled_at, so it cannot disagree with it."
        )
    )
    last_heartbeat_at: dt.datetime | None
    agent_version: str | None
    os_id: str | None
    os_version_id: str | None
    kernel: str | None
    enrolled_at: dt.datetime | None = Field(description="NULL means registered but never enrolled.")
    registered_at: dt.datetime
    clone_suspected: bool
    release_build: bool | None

    # Administrator-supplied, available before the device is ever seen.
    display_name: str | None
    manufacturer: str | None
    model: str | None
    assigned_to_name: str | None
    assigned_to_email: str | None
    platform: str | None
    asset_tag: str | None
    primary_adapter_ip: str | None = Field(
        description=(
            "Last address the agent reported. Self-reported and trivially "
            "spoofable, so it is informational only and is never used for "
            "authentication or authorisation."
        )
    )


class DeviceDetail(DeviceSummary):
    arch: str | None
    cert_fingerprint: str | None
    cert_not_after: dt.datetime | None
    last_inventory_at: dt.datetime | None
    revoked_at: dt.datetime | None
    revoke_reason: str | None
    virtualization: str | None


class RegisterDeviceRequest(StrictModel):
    """Add a device before it exists on the network.

    Everything here is an administrator's assertion about a laptop, which is why
    none of it overlaps with what the agent reports at enrollment. The server
    keeps the two apart: an admin may name a device, but only the device can
    report its hostname, OS and hardware fingerprint.
    """

    display_name: Annotated[str, StringConstraints(min_length=1, max_length=120)] = Field(
        description='Human label for the fleet list, e.g. "Ethan\'s laptop".'
    )
    platform: Literal["linux", "macos", "windows"] = Field(
        default="linux",
        description=(
            "Only `linux` has an agent. The others may be recorded so the "
            "inventory is honest about what exists, but nothing will manage them."
        ),
    )
    manufacturer: Annotated[str, StringConstraints(max_length=64)] | None = None
    model: Annotated[str, StringConstraints(max_length=120)] | None = None
    assigned_to_name: Annotated[str, StringConstraints(max_length=120)] | None = None
    #: Reuses the admin login normaliser: bounded, lowercased, and deliberately
    #: permissive about internal domains like `company.internal`, which is
    #: exactly what turns up in a corporate fleet. Send null rather than "" for
    #: "not recorded" - a blank-but-present address is rejected.
    assigned_to_email: AdminEmail | None = None
    asset_tag: Annotated[str, StringConstraints(max_length=64)] | None = None
    issue_enrollment_token: bool = Field(
        default=True,
        description=(
            "Mint a single-use enrollment token bound to this device. Returned "
            "exactly once in the response."
        ),
    )
    token_ttl_seconds: int = Field(
        default=ENROLLMENT_TOKEN_DEFAULT_TTL_SECONDS,
        ge=60,
        le=ENROLLMENT_TOKEN_DEFAULT_TTL_SECONDS,
        description="Lifetime of that token, capped at 24 hours.",
    )


class DeviceCounts(BaseModel):
    """Fleet totals, counted across every row rather than over one page.

    `enrolled + unenrolled == total` always. `revoked` and `clone_suspected`
    overlap with those two and are reported separately rather than carved out
    of them, because a revoked device is still an enrolled one.
    """

    total: int
    enrolled: int
    unenrolled: int
    revoked: int
    clone_suspected: int


class RegisterDeviceResponse(BaseModel):
    device: DeviceDetail
    enrollment_token: str | None = Field(
        default=None,
        description=(
            "RETURNED EXACTLY ONCE, and only when issue_enrollment_token was "
            "true. Only the hash is stored, so it cannot be recovered; issue a "
            "replacement instead."
        ),
    )
    enrollment_token_id: uuid.UUID | None = None
    enrollment_token_expires_at: dt.datetime | None = None


class RevokeDeviceRequest(StrictModel):
    reason: Annotated[str, StringConstraints(min_length=8, max_length=500)] = Field(
        description="Required. Appears in the audit log, so 'test' is refused."
    )


class CertificateRenewRequest(StrictModel):
    """Rotate this device's client certificate.

    Authenticated by the certificate being replaced, so there is no token and
    no device identifier in the body: both come from the mTLS connection. A
    `device_id` field here would be a field the server had to ignore, and a
    field a client might believe was honoured.
    """

    csr_pem: Annotated[str, StringConstraints(min_length=64, max_length=8192)] = Field(
        description=(
            "A certificate request for a NEW keypair. The public key must differ "
            "from the current certificate's: renewal exists partly to bound how "
            "long one private key is exposed, and reusing the key forfeits that."
        )
    )


class CertificateRenewResponse(BaseModel):
    """The replacement certificate.

    Deliberately NOT a copy of `EnrollResponse`. It omits `policy_public_keys`,
    because those were pinned at enrollment and re-sending them would create a
    key-rotation path that bypasses the signed `key_rotation` record; and it
    omits `clone_suspected`, because the hardware fingerprint is not re-examined
    during a renewal.
    """

    device_id: uuid.UUID
    client_certificate_pem: str
    ca_chain_pem: str
    certificate_not_after: dt.datetime
    certificate_renew_after: dt.datetime = Field(
        description="When to start renewing again: 50 % through the new certificate's life."
    )
    reused: bool = Field(
        default=False,
        description=(
            "True when this request presented a CSR the server had already "
            "issued against, so the existing certificate was returned rather "
            "than a second one issued. The recovery path for a renewal whose "
            "response was lost in transit."
        ),
    )


class HeartbeatRequest(StrictModel):
    agent_version: Annotated[str, StringConstraints(max_length=64)]
    uptime_seconds: int = Field(ge=0)
    applied_policy_versions: dict[str, int] = Field(
        default_factory=dict, description="policy_type -> version currently enforced."
    )
    primary_adapter_ip: IpAddressText | None = Field(
        default=None,
        description="Refreshes the recorded address when the device moves network.",
    )


class HeartbeatResponse(BaseModel):
    """Scheduling hints and version numbers. Never a command.

    Nothing in this response tells the agent to *do* anything. It pulls
    declarative, signed state and decides locally, which is the structural
    reason a compromised server cannot run code on a laptop.
    """

    server_time: dt.datetime
    heartbeat_seconds: int
    heartbeat_jitter_pct: int
    certificate_renew_after: dt.datetime | None
    available_policies: list[dict[str, int | str]] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


class AuditEntryResponse(BaseModel):
    seq: int
    occurred_at: dt.datetime
    action: str
    actor_id: str | None
    actor_role: str | None
    target_type: str | None
    target_id: str | None
    request_id: str | None
    detail: dict[str, object]
    entry_hash: str


class ChainVerificationResponse(BaseModel):
    ok: bool
    checked: int
    broken_at_seq: int | None
    reason: str | None
