"""Server-side role-based access control.

Design choice worth stating: the matrix is a FULLY ENUMERATED table of explicit
True/False, not a set of granted capabilities per role.

With "role -> set of allowed capabilities", adding a new capability silently
denies it to everyone. Default-deny is safe, but it is also silent: nobody is
forced to decide what each role should do with the new capability, and the
omission looks identical to a deliberate denial.

With a fully enumerated table, adding a capability without deciding all four
cells raises at import time. `_validate_matrix()` runs on import, so an
incomplete matrix cannot even start the process, let alone reach production.

The matrix below is the one signed off in docs/01-api-contract.md section 5.
tests/test_rbac.py restates it independently and asserts every cell, including
every denial, so the table has a second source of truth.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class Role(StrEnum):
    """Admin roles. Devices are not users and have no role."""

    SUPER_ADMIN = "super_admin"
    IT_ADMIN = "it_admin"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"


@unique
class Capability(StrEnum):
    """What an admin may do. Routes map onto these, never onto roles directly.

    Checking a capability rather than a role means adding a role later touches
    one table instead of every endpoint.
    """

    MANAGE_USERS = "manage_users"
    DEVICE_READ = "device_read"
    DEVICE_REVOKE = "device_revoke"
    # noqa S105: this is a capability name, not a credential. The rule fires on
    # the word "token". Suppressed here rather than disabled globally, because
    # S105 is worth keeping for the code that handles actual tokens.
    ENROLLMENT_TOKEN_MANAGE = "enrollment_token_manage"  # noqa: S105
    POLICY_READ = "policy_read"
    POLICY_WRITE = "policy_write"
    EVENT_READ = "event_read"
    INCIDENT_READ = "incident_read"
    INCIDENT_UPDATE = "incident_update"
    USB_EXCEPTION_MANAGE = "usb_exception_manage"
    AUDIT_READ = "audit_read"
    AUDIT_VERIFY = "audit_verify"
    AUDIT_EXPORT = "audit_export"


class PermissionDeniedError(Exception):
    """Raised when a role lacks a capability.

    Carries the capability for the audit log, never for the HTTP response: the
    client is told only that it was forbidden, so probing cannot map the matrix.
    """

    def __init__(self, role: Role, capability: Capability) -> None:
        super().__init__(f"role {role.value} lacks capability {capability.value}")
        self.role = role
        self.capability = capability


_T = True
_F = False

# Every cell is explicit. Read the columns as the four roles.
_MATRIX: dict[Role, dict[Capability, bool]] = {
    Role.SUPER_ADMIN: {
        Capability.MANAGE_USERS: _T,
        Capability.DEVICE_READ: _T,
        Capability.DEVICE_REVOKE: _T,
        Capability.ENROLLMENT_TOKEN_MANAGE: _T,
        Capability.POLICY_READ: _T,
        Capability.POLICY_WRITE: _T,
        Capability.EVENT_READ: _T,
        Capability.INCIDENT_READ: _T,
        Capability.INCIDENT_UPDATE: _T,
        Capability.USB_EXCEPTION_MANAGE: _T,
        Capability.AUDIT_READ: _T,
        Capability.AUDIT_VERIFY: _T,
        Capability.AUDIT_EXPORT: _T,
    },
    Role.IT_ADMIN: {
        Capability.MANAGE_USERS: _F,
        Capability.DEVICE_READ: _T,
        Capability.DEVICE_REVOKE: _T,
        Capability.ENROLLMENT_TOKEN_MANAGE: _T,
        Capability.POLICY_READ: _T,
        Capability.POLICY_WRITE: _T,
        Capability.EVENT_READ: _T,
        Capability.INCIDENT_READ: _T,
        Capability.INCIDENT_UPDATE: _T,
        Capability.USB_EXCEPTION_MANAGE: _T,
        Capability.AUDIT_READ: _T,
        Capability.AUDIT_VERIFY: _T,
        # Separation of duties: the role that configures the fleet does not get
        # to extract the record of what it did. Confirmed with the product owner.
        Capability.AUDIT_EXPORT: _F,
    },
    Role.SECURITY_ANALYST: {
        Capability.MANAGE_USERS: _F,
        Capability.DEVICE_READ: _T,
        Capability.DEVICE_REVOKE: _F,
        Capability.ENROLLMENT_TOKEN_MANAGE: _F,
        Capability.POLICY_READ: _T,
        Capability.POLICY_WRITE: _F,
        Capability.EVENT_READ: _T,
        Capability.INCIDENT_READ: _T,
        Capability.INCIDENT_UPDATE: _T,
        # An exception UNBLOCKS a USB device, so this is the analyst's sharpest
        # tool. Granted because they triage incidents, and bounded elsewhere:
        # max 24 h, reason required, and every grant is audited.
        Capability.USB_EXCEPTION_MANAGE: _T,
        Capability.AUDIT_READ: _T,
        Capability.AUDIT_VERIFY: _T,
        Capability.AUDIT_EXPORT: _F,
    },
    Role.AUDITOR: {
        Capability.MANAGE_USERS: _F,
        Capability.DEVICE_READ: _T,
        Capability.DEVICE_REVOKE: _F,
        Capability.ENROLLMENT_TOKEN_MANAGE: _F,
        Capability.POLICY_READ: _T,
        Capability.POLICY_WRITE: _F,
        Capability.EVENT_READ: _T,
        Capability.INCIDENT_READ: _T,
        Capability.INCIDENT_UPDATE: _F,
        Capability.USB_EXCEPTION_MANAGE: _F,
        Capability.AUDIT_READ: _T,
        Capability.AUDIT_VERIFY: _T,
        # Read-only, plus export. The only role besides super_admin that can.
        Capability.AUDIT_EXPORT: _T,
    },
}

#: Capabilities that change state. Used to assert that `auditor` stays read-only
#: as a derived property, so a future edit cannot quietly give it write access.
WRITE_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.MANAGE_USERS,
        Capability.DEVICE_REVOKE,
        Capability.ENROLLMENT_TOKEN_MANAGE,
        Capability.POLICY_WRITE,
        Capability.INCIDENT_UPDATE,
        Capability.USB_EXCEPTION_MANAGE,
    }
)


def _validate_matrix() -> None:
    """Fail at import if any (role, capability) cell is missing or mistyped.

    This is the mechanism that makes "someone must decide every cell" real
    rather than aspirational.
    """
    missing_roles = set(Role) - set(_MATRIX)
    if missing_roles:
        raise RuntimeError(
            "RBAC matrix is incomplete, no row for role(s): "
            + ", ".join(sorted(r.value for r in missing_roles))
        )

    for role, row in _MATRIX.items():
        missing = set(Capability) - set(row)
        if missing:
            raise RuntimeError(
                f"RBAC matrix is incomplete for role {role.value}, undecided "
                "capability(ies): " + ", ".join(sorted(c.value for c in missing))
            )
        extra = set(row) - set(Capability)
        if extra:
            raise RuntimeError(f"RBAC matrix for role {role.value} has unknown entries: {extra}")
        for capability, allowed in row.items():
            if not isinstance(allowed, bool):
                raise RuntimeError(
                    f"RBAC cell ({role.value}, {capability.value}) must be a bool, "
                    f"got {type(allowed).__name__}"
                )


_validate_matrix()


def can(role: Role, capability: Capability) -> bool:
    """Return whether `role` holds `capability`.

    Unknown roles raise rather than returning False: a role we do not recognise
    is a bug or tampering, and silently denying would hide it.
    """
    try:
        row = _MATRIX[role]
    except KeyError as exc:
        raise ValueError(f"unknown role: {role!r}") from exc
    try:
        return row[capability]
    except KeyError as exc:
        raise ValueError(f"unknown capability: {capability!r}") from exc


def require(role: Role, capability: Capability) -> None:
    """Raise `PermissionDeniedError` unless `role` holds `capability`."""
    if not can(role, capability):
        raise PermissionDeniedError(role, capability)


def capabilities_for(role: Role) -> frozenset[Capability]:
    """Capabilities granted to `role`. For `GET /auth/me`, so the dashboard can
    hide controls the user cannot use - while the server still enforces every
    call, because a hidden button is not a security boundary.
    """
    return frozenset(cap for cap, allowed in _MATRIX[role].items() if allowed)
