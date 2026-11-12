"""Keeps the Python constants and the JSON Schema from drifting apart.

The agent tunable bounds exist in three places: these constants, the JSON
Schema the server validates admin input against, and (from Phase 2) the Go
constants the agent clamps with. Three copies of the same numbers will diverge
unless something fails when they do.

This test covers the first two. The Go side gets the same treatment in Phase 2.
"""

from __future__ import annotations

from typing import Any

import pytest

from ubuntuguard.constants import (
    AGENT_SETTING_BOUNDS,
    LOG_LEVEL_DEFAULT,
    LOG_LEVELS,
    NON_NUMERIC_AGENT_SETTINGS,
    Bound,
)


def test_schema_and_constants_cover_the_same_settings(
    agent_settings_schema: dict[str, Any],
) -> None:
    """Neither side may carry a setting the other does not know about.

    Every property in the schema must be accounted for as either an integer
    bound or an explicitly declared non-numeric setting. Simply omitting an
    enumerated setting such as log_level is how the two copies drift apart,
    which is what this caught on first run.
    """
    schema_settings = set(agent_settings_schema["properties"]) - {"schema"}
    known = set(AGENT_SETTING_BOUNDS) | set(NON_NUMERIC_AGENT_SETTINGS)
    assert schema_settings == known, (
        "schema and constants disagree about which settings exist; "
        f"only in schema: {sorted(schema_settings - known)}, "
        f"only in constants: {sorted(known - schema_settings)}"
    )


def test_numeric_and_non_numeric_settings_do_not_overlap() -> None:
    assert not (set(AGENT_SETTING_BOUNDS) & set(NON_NUMERIC_AGENT_SETTINGS))


def test_log_level_enum_and_default_match_the_schema(
    agent_settings_schema: dict[str, Any],
) -> None:
    prop = agent_settings_schema["properties"]["log_level"]
    assert tuple(prop["enum"]) == LOG_LEVELS
    assert prop["default"] == LOG_LEVEL_DEFAULT
    assert LOG_LEVEL_DEFAULT in LOG_LEVELS


@pytest.mark.parametrize("name", sorted(AGENT_SETTING_BOUNDS))
def test_each_bound_matches_the_schema(name: str, agent_settings_schema: dict[str, Any]) -> None:
    bound = AGENT_SETTING_BOUNDS[name]
    prop = agent_settings_schema["properties"][name]
    assert prop["minimum"] == bound.minimum, f"{name} minimum"
    assert prop["maximum"] == bound.maximum, f"{name} maximum"
    assert prop["default"] == bound.default, f"{name} default"


@pytest.mark.parametrize("name", sorted(AGENT_SETTING_BOUNDS))
def test_every_default_is_inside_its_own_bounds(name: str) -> None:
    """A default outside its own range would be clamped on every single apply."""
    bound = AGENT_SETTING_BOUNDS[name]
    assert bound.contains(bound.default)
    assert bound.minimum <= bound.maximum


def test_brief_specified_values_are_what_the_brief_says() -> None:
    """Spot-check the numbers the brief states explicitly."""
    heartbeat = AGENT_SETTING_BOUNDS["heartbeat_seconds"]
    assert (heartbeat.default, heartbeat.minimum, heartbeat.maximum) == (60, 30, 900)

    backoff_initial = AGENT_SETTING_BOUNDS["backoff_initial_seconds"]
    backoff_max = AGENT_SETTING_BOUNDS["backoff_max_seconds"]
    assert backoff_initial.default == 5
    assert backoff_max.default == 900  # 15 minutes

    queue = AGENT_SETTING_BOUNDS["event_queue_max_events"]
    age = AGENT_SETTING_BOUNDS["event_queue_max_age_days"]
    assert queue.maximum == 10_000
    assert age.maximum == 7


def test_clamp_pulls_values_into_range() -> None:
    """Agent-side behaviour: never fail, always clamp."""
    bound = Bound(default=60, minimum=30, maximum=900)
    assert bound.clamp(5) == 30
    assert bound.clamp(10_000) == 900
    assert bound.clamp(120) == 120
    assert bound.clamp(30) == 30
    assert bound.clamp(900) == 900


def test_contains_is_inclusive() -> None:
    """Server-side behaviour: the endpoints are legal values, not rejections."""
    bound = Bound(default=60, minimum=30, maximum=900)
    assert bound.contains(30) is True
    assert bound.contains(900) is True
    assert bound.contains(29) is False
    assert bound.contains(901) is False


def test_schema_has_no_security_invariant_as_a_tunable(
    agent_settings_schema: dict[str, Any],
) -> None:
    """Clock skew tolerance and the certificate renewal threshold must not be
    settable by policy. If either appears here, a signed policy could weaken a
    control the threat model depends on.
    """
    forbidden = {
        "clock_skew_tolerance_seconds",
        "cert_renew_at_pct",
        "signature_required",
        "tls_required",
        "verify_signature",
        "allow_http",
    }
    present = forbidden & set(agent_settings_schema["properties"])
    assert not present, f"security invariants must not be tunable: {sorted(present)}"
