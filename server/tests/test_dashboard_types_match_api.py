"""Keep the dashboard's hand-written types in step with the API.

The dashboard originally generated its TypeScript types from FastAPI's OpenAPI
document, which meant a renamed field broke the dashboard build immediately. The
generator was removed on request, so the types are now hand-written - and
nothing stops them drifting. A renamed Pydantic field would leave the dashboard
compiling happily while reading `undefined` at runtime, which is the worst kind
of failure: silent, and only visible to a user.

This test recovers most of that safety. It parses
`dashboard/src/api/types.ts` and compares every interface against the schema
FastAPI derives from the Pydantic models.

It is weaker than generation, honestly: it checks that field NAMES and
optionality line up, not that the TypeScript types match the JSON types. A
`number` where the server sends a string would pass here. That is the cost of
hand-writing them.

When you change a server model and this fails, update the interface in
types.ts - the failure message names the exact fields.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from ubuntuguard.config import Settings
from ubuntuguard.main import create_app

TYPES_FILE = Path(__file__).resolve().parents[2] / "dashboard" / "src" / "api" / "types.ts"

#: TypeScript interface -> OpenAPI component schema name.
#: Interfaces absent from this map are not checked; add one when you add a
#: response model that the dashboard consumes.
INTERFACE_TO_SCHEMA = {
    "Problem": "Problem",
    "FieldError": "FieldError",
    "TokenResponse": "TokenResponse",
    "AuthModeResponse": "AuthModeResponse",
    "MeResponse": "MeResponse",
    "UserResponse": "UserResponse",
    "CreateUserRequest": "CreateUserRequest",
    "DeviceSummary": "DeviceSummary",
    "DeviceDetail": "DeviceDetail",
    "DeviceCounts": "DeviceCounts",
    "RegisterDeviceRequest": "RegisterDeviceRequest",
    "RegisterDeviceResponse": "RegisterDeviceResponse",
    "EnrollmentTokenResponse": "EnrollmentTokenResponse",
    "CreateEnrollmentTokenResponse": "CreateEnrollmentTokenResponse",
    "AuditEntryResponse": "AuditEntryResponse",
    "ChainVerificationResponse": "ChainVerificationResponse",
}


class Interface:
    """A parsed TypeScript interface."""

    def __init__(self, name: str, extends: str | None, fields: dict[str, bool]) -> None:
        self.name = name
        self.extends = extends
        #: field name -> declared optional with `?`
        self.fields = fields


def strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def parse_interfaces(source: str) -> dict[str, Interface]:
    """Extract interfaces and their field names from a TypeScript file.

    A regex rather than a real parser, which is fine for the deliberately plain
    interfaces in types.ts: no generics, no nested object literals, no mapped
    types. If that stops being true, this test will fail loudly rather than
    quietly pass, which is the right direction to fail in.
    """
    cleaned = strip_comments(source)
    interfaces: dict[str, Interface] = {}

    pattern = re.compile(
        r"export\s+interface\s+(?P<name>\w+)"
        r"(?:\s+extends\s+(?P<extends>\w+))?\s*\{(?P<body>[^{}]*)\}",
        re.DOTALL,
    )
    for match in pattern.finditer(cleaned):
        fields: dict[str, bool] = {}
        for line in match.group("body").splitlines():
            field = re.match(r"\s*(?P<key>\w+)(?P<optional>\?)?\s*:", line)
            if field:
                fields[field.group("key")] = field.group("optional") is not None
        interfaces[match.group("name")] = Interface(
            match.group("name"), match.group("extends"), fields
        )
    return interfaces


def resolved_fields(name: str, interfaces: dict[str, Interface]) -> dict[str, bool]:
    """Fields including those inherited via `extends`.

    Pydantic flattens inheritance in the OpenAPI schema, so the comparison has
    to flatten the TypeScript side too.
    """
    interface = interfaces[name]
    fields = dict(interface.fields)
    if interface.extends and interface.extends in interfaces:
        fields = {**resolved_fields(interface.extends, interfaces), **fields}
    return fields


@pytest.fixture(scope="module")
def openapi() -> dict[str, Any]:
    return create_app(Settings(_env_file=None)).openapi()  # type: ignore[call-arg]


@pytest.fixture(scope="module")
def interfaces() -> dict[str, Interface]:
    if not TYPES_FILE.exists():
        pytest.skip(f"{TYPES_FILE} is missing; is the dashboard checked out?")
    parsed = parse_interfaces(TYPES_FILE.read_text(encoding="utf-8"))
    if not parsed:
        pytest.fail(f"no interfaces parsed from {TYPES_FILE}; has the file format changed?")
    return parsed


def test_every_mapped_interface_exists_on_both_sides(
    interfaces: dict[str, Interface], openapi: dict[str, Any]
) -> None:
    schemas = openapi["components"]["schemas"]
    for interface_name, schema_name in INTERFACE_TO_SCHEMA.items():
        assert interface_name in interfaces, f"types.ts has no interface {interface_name}"
        assert schema_name in schemas, (
            f"the API has no schema {schema_name}; remove it from INTERFACE_TO_SCHEMA "
            "if the endpoint was dropped"
        )


@pytest.mark.parametrize(("interface_name", "schema_name"), sorted(INTERFACE_TO_SCHEMA.items()))
def test_field_names_match(
    interface_name: str,
    schema_name: str,
    interfaces: dict[str, Interface],
    openapi: dict[str, Any],
) -> None:
    """The dashboard must know about exactly the fields the API sends."""
    schema = openapi["components"]["schemas"][schema_name]
    api_fields = set(schema.get("properties", {}))
    ts_fields = set(resolved_fields(interface_name, interfaces))

    missing_in_ts = api_fields - ts_fields
    extra_in_ts = ts_fields - api_fields

    assert not missing_in_ts, (
        f"{interface_name} in dashboard/src/api/types.ts is missing field(s) the API "
        f"sends: {sorted(missing_in_ts)}"
    )
    assert not extra_in_ts, (
        f"{interface_name} in dashboard/src/api/types.ts declares field(s) the API does "
        f"not send: {sorted(extra_in_ts)}. Renamed on the server?"
    )


@pytest.mark.parametrize(("interface_name", "schema_name"), sorted(INTERFACE_TO_SCHEMA.items()))
def test_required_fields_are_not_optional_in_typescript(
    interface_name: str,
    schema_name: str,
    interfaces: dict[str, Interface],
    openapi: dict[str, Any],
) -> None:
    """A field the API always sends should not be `?` in TypeScript.

    Marking a guaranteed field optional forces pointless null checks through the
    UI and hides a genuinely missing value behind the same shrug.
    """
    schema = openapi["components"]["schemas"][schema_name]
    required = set(schema.get("required", []))
    ts_fields = resolved_fields(interface_name, interfaces)

    wrongly_optional = sorted(name for name in required if ts_fields.get(name, False) is True)
    assert not wrongly_optional, (
        f"{interface_name}: the API always sends {wrongly_optional}, so they should not "
        "be declared optional with `?`"
    )


def test_device_list_query_matches_the_route_parameters(
    interfaces: dict[str, Interface], openapi: dict[str, Any]
) -> None:
    """DeviceListQuery is route parameters, not a component schema."""
    assert "DeviceListQuery" in interfaces, "types.ts has no DeviceListQuery interface"

    operation = openapi["paths"]["/api/v1/devices"]["get"]
    api_params = {
        parameter["name"]
        for parameter in operation.get("parameters", [])
        if parameter.get("in") == "query"
    }
    ts_params = set(resolved_fields("DeviceListQuery", interfaces))

    assert ts_params == api_params, (
        "DeviceListQuery does not match GET /api/v1/devices query parameters.\n"
        f"  only in types.ts: {sorted(ts_params - api_params)}\n"
        f"  only in the API : {sorted(api_params - ts_params)}"
    )


def test_problem_carries_the_fields_the_dashboard_branches_on(
    interfaces: dict[str, Interface],
) -> None:
    """ErrorBanner reads these directly, so their absence would be a blank error."""
    problem = resolved_fields("Problem", interfaces)
    for field in ("code", "title", "status", "detail", "fields", "request_id"):
        assert field in problem, f"Problem is missing {field}, which the dashboard renders"
