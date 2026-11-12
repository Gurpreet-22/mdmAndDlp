"""Data model tests that need no database.

SQLAlchemy can compile DDL for a specific dialect without connecting, so the
column types, constraints and indexes are all checkable here. What this does
NOT check is that the DDL actually executes, or that an Alembic migration
reproduces it - both of those need PostgreSQL and are staged in
`test_postgres_integration.py`.

The second half of the file is a set of drift guards: the enumerated values in
the model have to agree with the JSON Schemas and with the RBAC enum, because
the same vocabulary is written down in several places.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Table
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from ubuntuguard.models import (
    DEVICE_STATUSES,
    POLICY_SCOPE_KINDS,
    POLICY_STATUSES,
    POLICY_TYPES,
    ROLES,
    SERIAL_MATCH_MODES,
    Base,
)
from ubuntuguard.security.rbac import Role

TABLES: dict[str, Table] = {table.name: table for table in Base.metadata.sorted_tables}


def ddl(table_name: str) -> str:
    return str(CreateTable(TABLES[table_name]).compile(dialect=postgresql.dialect()))


# --------------------------------------------------------------------------- #
# Shape of the schema
# --------------------------------------------------------------------------- #


def test_expected_tables_exist() -> None:
    assert set(TABLES) == {
        "users",
        "login_attempts",
        "auth_tokens",
        "devices",
        "enrollment_tokens",
        "enrollment_attempts",
        "issued_certificates",
        "device_inventory",
        "policies",
        "policy_assignments",
        "device_policy_status",
        "events",
        "incidents",
        "usb_exceptions",
        "audit_logs",
    }


@pytest.mark.parametrize("name", sorted(TABLES))
def test_every_table_has_a_primary_key(name: str) -> None:
    assert TABLES[name].primary_key.columns, f"{name} has no primary key"


@pytest.mark.parametrize("name", sorted(TABLES))
def test_no_timestamp_is_stored_without_a_timezone(name: str) -> None:
    """A naive timestamp column invites comparing a UTC value against a local
    one, which fails silently rather than loudly.
    """
    rendered = ddl(name)
    assert "TIMESTAMP WITHOUT TIME ZONE" not in rendered
    if "TIMESTAMP" in rendered:
        assert "TIMESTAMP WITH TIME ZONE" in rendered


@pytest.mark.parametrize("name", sorted(TABLES))
def test_every_constraint_is_named(name: str) -> None:
    """Unnamed constraints get server-generated names, and an Alembic
    downgrade cannot reliably drop what it never named. The brief asks for
    migrations tested in both directions, so this is a prerequisite.
    """
    for constraint in TABLES[name].constraints:
        assert constraint.name is not None, f"{name} has an unnamed constraint"
    for index in TABLES[name].indexes:
        assert index.name is not None, f"{name} has an unnamed index"


@pytest.mark.parametrize("name", sorted(TABLES))
def test_no_native_enum_types(name: str) -> None:
    """Enumerated values are VARCHAR plus CHECK.

    Native PostgreSQL enums need ALTER TYPE to extend, which makes a reversible
    migration awkward for no validation benefit over a CHECK constraint.
    """
    assert "CREATE TYPE" not in ddl(name)
    for column in TABLES[name].columns:
        assert not isinstance(column.type, postgresql.ENUM), f"{name}.{column.name} is an ENUM"


# --------------------------------------------------------------------------- #
# Byte-exactness where things are signed or hashed
# --------------------------------------------------------------------------- #


def test_policy_payload_is_bytea_not_jsonb() -> None:
    """JSONB normalises key order and whitespace on the way in, which would
    invalidate the signature over those exact bytes.
    """
    rendered = ddl("policies")
    assert "payload BYTEA" in rendered
    assert "payload JSONB" not in rendered


def test_audit_detail_and_hashes_are_bytea() -> None:
    rendered = ddl("audit_logs")
    assert "detail_json BYTEA" in rendered
    assert "prev_hash BYTEA" in rendered
    assert "entry_hash BYTEA" in rendered


def test_audit_sequence_is_a_gapless_bigserial() -> None:
    """The chain relies on `seq` so a deletion shows as a missing number."""
    rendered = ddl("audit_logs")
    assert "seq BIGSERIAL" in rendered
    assert "PRIMARY KEY (seq)" in rendered


def test_policy_timestamps_are_stored_as_text_as_well() -> None:
    """The exact signed string is kept, so a change to the formatter cannot
    invalidate verification for every already-stored policy.
    """
    columns = set(TABLES["policies"].columns.keys())
    assert {"issued_at", "issued_at_text", "expires_at", "expires_at_text"} <= columns


def test_queryable_payloads_use_jsonb() -> None:
    """Where we filter rather than verify, JSONB is the right choice."""
    for table, column in [
        ("device_inventory", "payload"),
        ("events", "payload"),
        ("device_policy_status", "verified_state"),
        ("enrollment_attempts", "response_json"),
    ]:
        assert f"{column} JSONB" in ddl(table), f"{table}.{column} should be JSONB"


# --------------------------------------------------------------------------- #
# Uniqueness that enforces a product requirement
# --------------------------------------------------------------------------- #


def test_event_id_is_the_primary_key() -> None:
    """Agent-generated ids as the primary key turn at-least-once delivery into
    exactly-once storage via ON CONFLICT DO NOTHING.
    """
    assert [column.name for column in TABLES["events"].primary_key.columns] == ["event_id"]


def test_policy_versions_are_unique_per_scope() -> None:
    """Two version 7s for the same scope would make the agent's downgrade
    rejection meaningless.
    """
    assert "uq_policies_policy_type_version_scope_kind_scope_id" in ddl(
        "policies"
    ) or "UNIQUE (policy_type, scope_kind, scope_id, version)" in ddl("policies")


def test_enrollment_token_hash_is_unique() -> None:
    assert "UNIQUE (token_hash)" in ddl("enrollment_tokens")


def test_enrollment_idempotency_key_is_unique() -> None:
    """Keyed by token AND CSR public key: a retry with the same keypair is
    idempotent, the same token with another keypair is refused.
    """
    assert "UNIQUE (token_hash, csr_public_key_fingerprint)" in ddl("enrollment_attempts")


def test_device_certificate_fingerprint_is_unique() -> None:
    """One certificate cannot be shared by two devices."""
    assert "UNIQUE (cert_fingerprint)" in ddl("devices")


def test_auth_token_hash_is_unique() -> None:
    assert "UNIQUE (token_hash)" in ddl("auth_tokens")


def test_token_plaintext_is_never_stored() -> None:
    """Only hashes. A column named for the token itself would be a red flag."""
    for table in ("auth_tokens", "enrollment_tokens"):
        columns = set(TABLES[table].columns.keys())
        assert "token" not in columns
        assert "token_hash" in columns
        assert TABLES[table].columns["token_hash"].type.length == 64  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# CHECK constraints
# --------------------------------------------------------------------------- #


def test_role_and_status_values_are_constrained() -> None:
    assert "ck_users_role_valid" in ddl("users")
    assert "ck_devices_status_valid" in ddl("devices")
    assert "ck_policies_policy_type_valid" in ddl("policies")
    assert "ck_device_policy_status_status_valid" in ddl("device_policy_status")
    assert "ck_incidents_status_valid" in ddl("incidents")


def test_email_is_forced_lowercase_by_the_database() -> None:
    """Otherwise Alice@ and alice@ become two accounts with different rights."""
    assert "ck_users_email_lowercase" in ddl("users")


def test_usb_exception_requires_a_substantive_reason_and_future_expiry() -> None:
    rendered = ddl("usb_exceptions")
    assert "ck_usb_exceptions_reason_substantive" in rendered
    assert "ck_usb_exceptions_expiry_after_creation" in rendered


def test_policy_version_must_be_positive() -> None:
    assert "ck_policies_version_positive" in ddl("policies")


# --------------------------------------------------------------------------- #
# Drift guards against the JSON Schemas and the RBAC enum
# --------------------------------------------------------------------------- #

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_schema(name: str) -> dict[str, Any]:
    return json.loads((REPO_ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_model_roles_match_the_rbac_enum() -> None:
    assert set(ROLES) == {role.value for role in Role}


def test_policy_types_match_the_envelope_schema() -> None:
    schema = load_schema("policy.envelope.v1.schema.json")
    assert set(POLICY_TYPES) == set(schema["properties"]["policy_type"]["enum"])


def test_scope_kinds_match_the_envelope_schema() -> None:
    schema = load_schema("policy.envelope.v1.schema.json")
    assert set(POLICY_SCOPE_KINDS) == set(
        schema["properties"]["scope"]["properties"]["kind"]["enum"]
    )


def test_policy_statuses_match_the_inventory_schema() -> None:
    schema = load_schema("inventory.v1.schema.json")
    statuses = schema["properties"]["applied_policies"]["items"]["properties"]["status"]["enum"]
    assert set(POLICY_STATUSES) == set(statuses)


def test_serial_match_modes_match_the_usb_policy_schema() -> None:
    schema = load_schema("policy.usb_control.v1.schema.json")
    modes = schema["$defs"]["deviceMatch"]["properties"]["serial_match"]["enum"]
    assert set(SERIAL_MATCH_MODES) == set(modes)


def test_device_statuses_are_the_documented_three() -> None:
    assert set(DEVICE_STATUSES) == {"pending", "active", "revoked"}
