"""Drift detectors against the committed JSON Schemas.

The agent carries its own copy of the settings bounds and the reason-code
vocabulary, because it is a separate program installed on a laptop and cannot
import the server package. Two independent copies of the same values will drift,
and the failure mode is quiet: an agent clamping to a bound the server does not
share, or reporting a reason code the server has never heard of and that the
dashboard therefore cannot group.

These tests make the drift loud. They mirror the server's own
`test_bounds_match_schema.py`, which asserts the same thing from the other side,
so the schema sits between two implementations that both have to agree with it.
"""

from __future__ import annotations

from typing import Any

import pytest

from ubuntuguard_agent import constants
from ubuntuguard_agent.errors import ALL_REASON_CODES


def _properties(schema: dict[str, Any]) -> dict[str, Any]:
    return schema["properties"]


# --------------------------------------------------------------------------- #
# policy.agent_settings.v1
# --------------------------------------------------------------------------- #


def test_every_numeric_bound_matches_the_schema(agent_settings_schema: dict[str, Any]) -> None:
    properties = _properties(agent_settings_schema)
    for name, bound in constants.AGENT_SETTING_BOUNDS.items():
        assert name in properties, f"{name} is not a property of the schema"
        spec = properties[name]
        assert spec["minimum"] == bound.minimum, f"{name} minimum"
        assert spec["maximum"] == bound.maximum, f"{name} maximum"
        assert spec["default"] == bound.default, f"{name} default"


def test_every_schema_property_is_accounted_for(agent_settings_schema: dict[str, Any]) -> None:
    """No property may be silently unmodelled.

    Without this, a setting added to the schema would be accepted by the agent's
    strict structural check (because the schema is the server's contract) while
    having no bound to clamp against. This is the test that forces the agent to
    be updated in the same change.
    """
    modelled = (
        set(constants.AGENT_SETTING_BOUNDS) | constants.NON_NUMERIC_AGENT_SETTINGS | {"schema"}
    )
    unmodelled = sorted(set(_properties(agent_settings_schema)) - modelled)
    assert not unmodelled, f"schema properties with no agent-side model: {unmodelled}"


def test_log_level_enum_matches(agent_settings_schema: dict[str, Any]) -> None:
    spec = _properties(agent_settings_schema)["log_level"]
    assert tuple(spec["enum"]) == constants.LOG_LEVELS
    assert spec["default"] == constants.LOG_LEVEL_DEFAULT


def test_schema_const_matches(agent_settings_schema: dict[str, Any]) -> None:
    assert _properties(agent_settings_schema)["schema"]["const"] == (
        constants.AGENT_SETTINGS_SCHEMA_ID
    )


def test_schema_forbids_unknown_properties(agent_settings_schema: dict[str, Any]) -> None:
    """The agent's strict structural check mirrors a real schema guarantee."""
    assert agent_settings_schema["additionalProperties"] is False


# --------------------------------------------------------------------------- #
# event.agent.v1 reason codes
# --------------------------------------------------------------------------- #


def test_every_agent_reason_code_exists_in_the_schema(
    agent_event_schema: dict[str, Any],
) -> None:
    """A code the server does not recognise is a report that does nothing."""
    permitted = {
        value
        for value in _properties(agent_event_schema)["reason_code"]["enum"]
        if value is not None
    }
    unknown = sorted(ALL_REASON_CODES - permitted)
    assert not unknown, f"reason codes absent from the committed schema: {unknown}"


def test_every_schema_reason_code_is_defined_by_the_agent(
    agent_event_schema: dict[str, Any],
) -> None:
    """And the converse: a code the agent cannot produce is dead vocabulary.

    Not a security problem, but it means the dashboard has a grouping that will
    never appear, so the mismatch is worth knowing about.
    """
    permitted = {
        value
        for value in _properties(agent_event_schema)["reason_code"]["enum"]
        if value is not None
    }
    missing = sorted(permitted - ALL_REASON_CODES)
    assert not missing, f"schema reason codes the agent does not define: {missing}"


# --------------------------------------------------------------------------- #
# Invariants that must not quietly change
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("CLOCK_SKEW_TOLERANCE_SECONDS", 300),
        ("DEVICE_CERT_VALIDITY_DAYS", 30),
        ("CERT_RENEW_AT_PCT", 50),
        ("MAX_POLICY_PAYLOAD_BYTES", 64 * 1024),
        ("USB_EXCEPTION_MAX_SECONDS", 24 * 60 * 60),
        ("ENVELOPE_VERSION", 1),
    ],
)
def test_invariant_values_match_the_server(name: str, expected: int) -> None:
    """Pinned to literals on purpose.

    These are the numbers the threat model rests on and they appear in the
    server's constants, the documentation and the schemas. Asserting the literal
    means changing one requires changing this test, which is a prompt to go and
    change the other three places too.
    """
    assert getattr(constants, name) == expected


def test_policy_envelope_domain_is_byte_exact() -> None:
    """A different separator makes every signature in the fleet invalid."""
    assert constants.POLICY_ENVELOPE_DOMAIN == b"ubuntuguard/policy-envelope/v1"


def test_bound_clamp_and_contains_agree_at_the_edges() -> None:
    for name, bound in constants.AGENT_SETTING_BOUNDS.items():
        assert bound.clamp(bound.minimum - 1) == bound.minimum, name
        assert bound.clamp(bound.maximum + 1) == bound.maximum, name
        assert bound.clamp(bound.default) == bound.default, name
        assert bound.contains(bound.default), name
        assert not bound.contains(bound.minimum - 1), name
        assert not bound.contains(bound.maximum + 1), name
