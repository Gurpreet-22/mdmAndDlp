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
from typing import Annotated, Any, Literal

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
    must_change_password: bool = Field(
        description=(
            "True when this account must set a new password before doing anything "
            "else. The dashboard uses it to show the change-password screen; the "
            "server already refuses every capability-guarded route, so this is "
            "how the UI learns why, not what enforces it."
        )
    )


#: The four roles, as a type. Declared once so `CreateUserRequest` and
#: `ChangeRoleRequest` cannot drift apart, and so adding a role is one edit.
AdminRoleName = Literal["super_admin", "it_admin", "security_analyst", "auditor"]

#: A new password, bounded at both ends. The minimum is enforced here as well
#: as in `passwords.validate_password` - here so the caller gets a 422 naming
#: the field, there because that is the single policy every path goes through.
NewPassword = Annotated[
    str, StringConstraints(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_BYTES)
]


class CreateUserRequest(StrictModel):
    email: AdminEmail
    password: NewPassword
    role: AdminRoleName


class ChangeRoleRequest(StrictModel):
    """Body of `POST /users/{id}:role`. The target comes from the path."""

    role: AdminRoleName


class ResetPasswordRequest(StrictModel):
    """Body of `POST /users/{id}:reset-password`.

    The administrator supplies the temporary password, matching how
    `CreateUserRequest` works, so the response needs to carry no credential at
    all - the caller already has the value they just sent.
    """

    password: NewPassword


class ChangePasswordRequest(StrictModel):
    """Body of `POST /auth/password`.

    `current_password` is bounded by `MAX_PASSWORD_BYTES` but has no minimum:
    it is an existing credential being verified, not a new one being set, and
    applying new-password policy to it would refuse a legitimate change for an
    account whose password predates the current rules.
    """

    current_password: Annotated[str, StringConstraints(min_length=1, max_length=MAX_PASSWORD_BYTES)]
    new_password: NewPassword


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    is_active: bool
    must_change_password: bool = Field(
        description=(
            "True when an administrator has reset this account's password. Until "
            "the user sets a new one, every capability-guarded route refuses them."
        )
    )
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


class InstallerInfoResponse(BaseModel):
    """Metadata for the employee-facing agent installer. Public.

    Served unauthenticated, because the enrollment page is reached by an
    employee who has no credential and is not an administrator. Nothing here is
    sensitive: the digest, size and version describe a file that is itself
    published, and the server URL is the one the caller is already talking to.

    Note that `target_os_versions` and `validated_os_versions` are two separate
    claims and must stay that way. The first says which releases the agent is
    written for; the second says which it has actually been exercised on, and
    it is empty. Collapsing them into one "supported" list is exactly the
    overstatement the brief forbids, and the enrollment page renders the
    difference.
    """

    agent_version: str
    filename: str
    sha256: Hex64 = Field(
        description="SHA-256 of the installer, recomputed from the file on every request."
    )
    size_bytes: int
    built_at: dt.datetime
    server_url: str = Field(
        description="The API URL baked into the installer, so an employee can confirm it."
    )
    minimum_python: str
    supported_os_id: str
    supported_arch: list[str]
    target_os_versions: list[str] = Field(
        description="Releases the agent is written for. NOT a statement that it was tested."
    )
    validated_os_versions: list[str] = Field(
        description=(
            "Releases the agent has actually been run on. Empty until that work is "
            "done and the evidence committed."
        )
    )


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
    cpu_model: str | None = Field(default=None, max_length=128)
    cpu_cores: int | None = Field(default=None, ge=1)
    total_ram_bytes: int | None = Field(default=None, ge=0)
    disk_total_bytes: int | None = Field(default=None, ge=0)
    disk_free_bytes: int | None = Field(default=None, ge=0)


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
    department: str | None = None
    assigned_to_id: uuid.UUID | None = None
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
    cpu_model: str | None = None
    cpu_cores: int | None = None
    total_ram_bytes: int | None = None
    disk_total_bytes: int | None = None
    disk_free_bytes: int | None = None


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
    department: Annotated[str, StringConstraints(max_length=120)] | None = None
    assigned_to_id: uuid.UUID | None = None
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
    cpu_model: str | None = Field(default=None, max_length=128)
    cpu_cores: int | None = Field(default=None, ge=1)
    total_ram_bytes: int | None = Field(default=None, ge=0)
    disk_total_bytes: int | None = Field(default=None, ge=0)
    disk_free_bytes: int | None = Field(default=None, ge=0)


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


# --------------------------------------------------------------------------- #
# Employee & Device Assignment
# --------------------------------------------------------------------------- #


class EmployeeCreateRequest(StrictModel):
    full_name: Annotated[str, StringConstraints(min_length=1, max_length=120)]
    email: AdminEmail
    department: Annotated[str, StringConstraints(max_length=120)] | None = None
    job_title: Annotated[str, StringConstraints(max_length=120)] | None = None
    phone: Annotated[str, StringConstraints(max_length=32)] | None = None


class EmployeeUpdateRequest(StrictModel):
    full_name: Annotated[str, StringConstraints(min_length=1, max_length=120)] | None = None
    email: AdminEmail | None = None
    department: Annotated[str, StringConstraints(max_length=120)] | None = None
    job_title: Annotated[str, StringConstraints(max_length=120)] | None = None
    phone: Annotated[str, StringConstraints(max_length=32)] | None = None
    status: Literal["active", "suspended", "offboarded"] | None = None


class EmployeeResponse(BaseModel):
    id: uuid.UUID
    full_name: str
    email: str
    department: str | None
    job_title: str | None
    phone: str | None
    status: str
    assigned_device_count: int = 0
    created_at: dt.datetime
    updated_at: dt.datetime


class AssignDeviceRequest(StrictModel):
    employee_id: uuid.UUID | None = None
    assigned_to_name: Annotated[str, StringConstraints(min_length=1, max_length=120)]
    assigned_to_email: AdminEmail | None = None
    department: Annotated[str, StringConstraints(max_length=120)] | None = None
    notes: Annotated[str, StringConstraints(max_length=500)] | None = None


class DeviceAssignmentResponse(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    employee_id: uuid.UUID | None
    assigned_to_name: str
    assigned_to_email: str | None
    department: str | None
    notes: str | None
    assigned_at: dt.datetime
    unassigned_at: dt.datetime | None
    assigned_by: uuid.UUID | None
    unassigned_by: uuid.UUID | None


# --------------------------------------------------------------------------- #
# Device Offline Alerts
# --------------------------------------------------------------------------- #


class CheckOfflineDevicesRequest(StrictModel):
    threshold_seconds: int = Field(default=900, ge=60, le=86400 * 30)


class CheckOfflineDevicesResponse(BaseModel):
    checked_count: int
    flagged_offline_count: int
    new_incidents_created: int
    device_ids: list[uuid.UUID]


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
#
# The request models here are `StrictModel`, so an unknown field is a 422
# rather than something silently dropped. That matters more for policy than
# anywhere else in this API: a request carrying `raw_usbguard_rule` or
# `post_apply_command` is an attempt to turn declarative policy into remote
# execution, and it should be refused loudly at the edge rather than ignored
# and reported as success.


class UsbDeviceMatch(StrictModel):
    """One device matcher: a model, or a specific physical unit.

    Mirrors `deviceMatch` in `schemas/policy.usb_control.v1.schema.json`. The
    four-hex-digit constraint is not cosmetic -- these values are interpolated
    into a USBGuard rule on the endpoint, and the pattern is what keeps them
    incapable of carrying rule syntax.
    """

    vendor_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{4}$")] = Field(
        description="Lowercase 4-digit hex vendor id, as usbguard reports it."
    )
    product_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{4}$")] = Field(
        description="Lowercase 4-digit hex product id."
    )
    serial: Annotated[str, StringConstraints(max_length=128)] | None = Field(
        default=None,
        description="Serial as usbguard reports it, or null for devices with none.",
    )
    serial_match: Literal["exact", "any"] = Field(
        default="exact",
        description=(
            "`exact` pins one physical stick and requires a serial. `any` "
            "matches every unit of that model, which is weaker and the "
            "dashboard should label it so."
        ),
    )


class UsbAllowlistEntryRequest(StrictModel):
    """A device an administrator is approving."""

    match: UsbDeviceMatch
    label: Annotated[str, StringConstraints(min_length=1, max_length=120)] = Field(
        description='What this device is, e.g. "Finance SanDisk".'
    )


class UsbExceptionRequest(StrictModel):
    """A time-bound grant for one device.

    `reason` has a floor because a justification nobody has to write is a
    justification that says "test". The expiry bound is checked in
    `services.policy`, since a duration limit is not expressible in a field
    constraint.
    """

    match: UsbDeviceMatch
    reason: Annotated[str, StringConstraints(min_length=8, max_length=500)]
    expires_in_hours: int = Field(
        default=8, ge=1, le=24, description="Capped at 24 hours by USB_EXCEPTION_MAX_SECONDS."
    )


class SetUsbPolicyRequest(StrictModel):
    """Create a new `usb_control` policy version and apply it to a scope.

    There is no "edit": every change is a new immutable version. That is what
    makes the agent's downgrade rejection meaningful, and it means the history
    of what a laptop was under cannot be quietly rewritten.
    """

    mode: Literal["monitor_only", "allowlist_enforce", "block_all_storage"] = Field(
        description=(
            "`monitor_only` blocks nothing and is the safe first step on a new "
            "fleet. `allowlist_enforce` blocks the protected classes except "
            "approved devices. `block_all_storage` ignores the allowlist, "
            "though unexpired exceptions still apply."
        )
    )
    scope_kind: Literal["device", "fleet"] = Field(
        default="device",
        description=(
            "`group` exists in the schema but nothing resolves it yet, so it is "
            "not offered here rather than accepted and ignored."
        ),
    )
    device_id: uuid.UUID | None = Field(
        default=None, description="Required when scope_kind is `device`."
    )
    protected_classes: list[Literal["mass_storage", "image"]] | None = Field(
        default=None,
        description=(
            "Defaults to mass_storage only. `image` is USB class 06, which is "
            "what a phone presents in MTP mode; enabling it blocks phones."
        ),
    )
    always_allow_classes: (
        list[
            Literal[
                "hid",
                "hub",
                "audio",
                "video",
                "printer",
                "network",
                "smartcard",
                "wireless",
                "billboard",
                "cdc",
                "physical",
                "vendor_specific",
            ]
        ]
        | None
    ) = Field(
        default=None,
        description="Must include hid and hub, or the user loses their keyboard.",
    )
    allowlist: list[UsbAllowlistEntryRequest] = Field(default_factory=list, max_length=256)
    exceptions: list[UsbExceptionRequest] = Field(default_factory=list, max_length=64)
    apply_to_present_devices: bool = Field(
        default=True,
        description=(
            "Whether the endpoint re-judges devices already plugged in. False "
            "leaves a connected stick alone until it is unplugged."
        ),
    )


class PolicySummary(BaseModel):
    """A policy version, without its payload."""

    policy_id: uuid.UUID
    policy_type: str
    version: int
    scope_kind: str
    scope_id: str
    signing_key_id: str
    payload_sha256: str
    issued_at: dt.datetime
    expires_at: dt.datetime | None
    summary: str = Field(description="One-line description for a list view.")
    created_at: dt.datetime


class PolicyDetail(PolicySummary):
    """A policy version with its payload decoded, for display only.

    `payload` here is parsed JSON for the dashboard to render. The
    authoritative form is the stored bytes the signature covers; this is never
    used to re-sign or re-send.
    """

    payload: dict[str, Any]


class DevicePolicyStatusResponse(BaseModel):
    """What a device reported about applying a policy.

    `verified_state` is what the agent read back from the operating system, not
    what it set out to do. Without it, `applied` is a claim.
    """

    policy_id: uuid.UUID
    policy_type: str
    policy_version: int
    status: Literal["pending", "applied", "failed", "unsupported", "rolled_back"]
    reason_code: str | None
    detail: str | None
    reported_at: dt.datetime
    verified_state: dict[str, Any] | None


class DeviceUsbPolicyView(BaseModel):
    """Everything the device page needs for its USB card."""

    policy: PolicyDetail | None = Field(
        default=None, description="The policy in force, or null if none is assigned."
    )
    status: DevicePolicyStatusResponse | None = Field(
        default=None, description="The device's last report, or null if it has not reported."
    )


class ReportPolicyStatusRequest(StrictModel):
    """A device reporting the outcome of applying a policy.

    Deliberately narrow. A device may report what happened to a policy it was
    given; it cannot create, modify or assign one, and nothing here is trusted
    as a statement about any other device -- the identity comes from the mTLS
    certificate, never from the body.
    """

    policy_id: uuid.UUID
    status: Literal["applied", "failed", "unsupported", "rolled_back"]
    reason_code: Annotated[str, StringConstraints(max_length=48)] | None = None
    detail: Annotated[str, StringConstraints(max_length=512)] | None = None
    verified_state: dict[str, Any] | None = Field(
        default=None,
        description=(
            "What the agent read back from the OS: the rules usbguard actually "
            "loaded, the daemon parameters, and whether enforcement is "
            "bypassable without root."
        ),
    )


class PolicyEnvelopeResponse(BaseModel):
    """The signed envelope, exactly as it was signed.

    Not a `StrictModel` and not reshaped: this is passed through from the
    stored columns so the bytes the device verifies are the bytes that were
    signed.
    """

    envelope_version: int
    policy_id: str
    policy_version: int
    policy_type: str
    scope: dict[str, str]
    issued_at: str
    expires_at: str | None
    payload_b64: str
    payload_sha256: str
    signature: dict[str, str]
