"""The role matrix test.

This file restates the signed-off matrix from docs/01-api-contract.md section 5
INDEPENDENTLY of the implementation, as plain strings, and asserts every single
cell. That redundancy is the whole point: if someone edits the table in
`rbac.py`, this test disagrees with them. A test that imported the matrix it is
checking would pass no matter what the matrix said.

Denials are asserted as explicitly as grants. "security_analyst cannot revoke a
device" is a requirement, not an absence of one, so it gets a test.
"""

from __future__ import annotations

import pytest

from ubuntuguard.security.rbac import (
    WRITE_CAPABILITIES,
    Capability,
    PermissionDeniedError,
    Role,
    can,
    capabilities_for,
    require,
)

# Rows are roles, columns are capabilities. Transcribed by hand from the API
# contract, deliberately not imported from the implementation.
EXPECTED: dict[str, dict[str, bool]] = {
    "super_admin": {
        "manage_users": True,
        "device_read": True,
        "device_revoke": True,
        "enrollment_token_manage": True,
        "policy_read": True,
        "policy_write": True,
        "event_read": True,
        "incident_read": True,
        "incident_update": True,
        "usb_exception_manage": True,
        "audit_read": True,
        "audit_verify": True,
        "audit_export": True,
    },
    "it_admin": {
        "manage_users": False,
        "device_read": True,
        "device_revoke": True,
        "enrollment_token_manage": True,
        "policy_read": True,
        "policy_write": True,
        "event_read": True,
        "incident_read": True,
        "incident_update": True,
        "usb_exception_manage": True,
        "audit_read": True,
        "audit_verify": True,
        "audit_export": False,
    },
    "security_analyst": {
        "manage_users": False,
        "device_read": True,
        "device_revoke": False,
        "enrollment_token_manage": False,
        "policy_read": True,
        "policy_write": False,
        "event_read": True,
        "incident_read": True,
        "incident_update": True,
        "usb_exception_manage": True,
        "audit_read": True,
        "audit_verify": True,
        "audit_export": False,
    },
    "auditor": {
        "manage_users": False,
        "device_read": True,
        "device_revoke": False,
        "enrollment_token_manage": False,
        "policy_read": True,
        "policy_write": False,
        "event_read": True,
        "incident_read": True,
        "incident_update": False,
        "usb_exception_manage": False,
        "audit_read": True,
        "audit_verify": True,
        "audit_export": True,
    },
}

ALL_CELLS = [
    (role, capability, allowed)
    for role, row in EXPECTED.items()
    for capability, allowed in row.items()
]


@pytest.mark.parametrize(("role", "capability", "allowed"), ALL_CELLS)
def test_every_matrix_cell(role: str, capability: str, allowed: bool) -> None:
    assert can(Role(role), Capability(capability)) is allowed


def test_expected_table_covers_every_role_and_capability() -> None:
    """Guard against this test silently going out of date.

    If a capability is added to the enum but not to EXPECTED above, the
    parametrised test would simply never exercise it and would keep passing.
    This assertion is what makes that impossible.
    """
    assert set(EXPECTED) == {role.value for role in Role}
    for role, row in EXPECTED.items():
        assert set(row) == {cap.value for cap in Capability}, f"EXPECTED[{role}] is out of date"


def test_matrix_has_52_cells() -> None:
    """4 roles times 13 capabilities. Catches an accidental enum deletion."""
    assert len(Role) == 4
    assert len(Capability) == 13
    assert len(ALL_CELLS) == 52


def test_require_raises_for_a_denied_capability() -> None:
    with pytest.raises(PermissionDeniedError) as caught:
        require(Role.AUDITOR, Capability.POLICY_WRITE)
    # The exception carries the detail for the audit log...
    assert caught.value.role is Role.AUDITOR
    assert caught.value.capability is Capability.POLICY_WRITE


def test_require_passes_for_a_granted_capability() -> None:
    require(Role.AUDITOR, Capability.AUDIT_EXPORT)  # must not raise


def test_auditor_holds_no_write_capability() -> None:
    """Derived property, so a future edit cannot quietly make auditor a writer."""
    granted = capabilities_for(Role.AUDITOR)
    assert not (granted & WRITE_CAPABILITIES), (
        "auditor must stay read-only; offending capabilities: "
        f"{sorted(c.value for c in granted & WRITE_CAPABILITIES)}"
    )


def test_only_super_admin_and_auditor_can_export_audit() -> None:
    """The separation-of-duties rule, asserted directly.

    it_admin configures the fleet, so it does not also get to extract the
    record of what it did.
    """
    exporters = {role for role in Role if can(role, Capability.AUDIT_EXPORT)}
    assert exporters == {Role.SUPER_ADMIN, Role.AUDITOR}


def test_only_super_admin_manages_users() -> None:
    managers = {role for role in Role if can(role, Capability.MANAGE_USERS)}
    assert managers == {Role.SUPER_ADMIN}


def test_every_role_can_read_devices_and_audit() -> None:
    """Visibility is universal; mutation is not."""
    for role in Role:
        assert can(role, Capability.DEVICE_READ)
        assert can(role, Capability.AUDIT_READ)
        assert can(role, Capability.AUDIT_VERIFY)


def test_unknown_role_raises_rather_than_denying() -> None:
    """A role we do not recognise is a bug or tampering.

    Returning False would hide it behind an ordinary-looking 403.
    """
    with pytest.raises(ValueError, match="unknown role"):
        can("root", Capability.DEVICE_READ)  # type: ignore[arg-type]


def test_unknown_capability_raises() -> None:
    with pytest.raises(ValueError, match="unknown capability"):
        can(Role.SUPER_ADMIN, "delete_everything")  # type: ignore[arg-type]


def test_capabilities_for_matches_the_matrix() -> None:
    for role in Role:
        expected = {Capability(c) for c, allowed in EXPECTED[role.value].items() if allowed}
        assert capabilities_for(role) == expected
