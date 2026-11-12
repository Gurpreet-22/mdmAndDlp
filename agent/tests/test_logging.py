"""Structured logging, and the redaction that the brief makes mandatory.

"Avoid logging enrollment tokens, private keys or certificates' private
material" is a requirement, so these are not decorative tests. Each one feeds a
real secret through a real log call and asserts it is absent from the output.

The emphasis is on the paths that leak in practice. Nobody writes
`logger.info(token)`. What happens is that a token ends up inside an exception
message, or inside a dict passed as `extra=`, or in a traceback - places the
author never considered - which is why redaction runs over the fully serialized
line rather than over the message.
"""

from __future__ import annotations

import io
import json
import logging
from typing import Any

import pytest

from ubuntuguard_agent.logging_setup import (
    MIN_SECRET_LENGTH,
    REDACTED,
    JsonFormatter,
    SecretRegistry,
    configure_logging,
    get_logger,
    is_sensitive_field,
    normalise_level,
    redact,
)

TOKEN = "bDNtRkp2NXhRMnBXc1k3ejhBdEdjSGJLZVVuTXFSdFY"  # noqa: S105 - a fixture
PRIVATE_KEY_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIHRlc3Qga2V5IG1hdGVyaWFsIHRoYXQgbXVzdCBuZXZl\n"
    "ciBiZSBsb2dnZWQgYW55d2hlcmUgYXQgYWxs\n"
    "-----END PRIVATE KEY-----"
)


@pytest.fixture
def captured() -> Any:
    """A logger writing JSON into a StringIO, plus a reader for the lines."""
    stream = io.StringIO()
    registry = SecretRegistry()
    logger = configure_logging("debug", stream=stream, registry=registry)

    def lines() -> list[dict[str, Any]]:
        stream.seek(0)
        return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]

    yield logger, registry, lines

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


# --------------------------------------------------------------------------- #
# Format
# --------------------------------------------------------------------------- #


def test_each_record_is_one_line_of_json(captured: Any) -> None:
    """Single-line matters for a log collector: one record, one line.

    A multi-line record is either truncated or split into unparseable fragments
    by most shippers.
    """
    logger, _, lines = captured
    logger.info("hello")
    logger.info("again")
    assert len(lines()) == 2


def test_embedded_newlines_do_not_break_the_line(captured: Any) -> None:
    logger, _, lines = captured
    logger.info("first\nsecond\nthird")
    entries = lines()
    assert len(entries) == 1
    assert entries[0]["msg"] == "first\nsecond\nthird"


def test_timestamp_is_utc_with_a_trailing_z(captured: Any) -> None:
    """UTC everywhere, so a laptop's timezone never has to be reconciled."""
    logger, _, lines = captured
    logger.info("x")
    assert lines()[0]["ts"].endswith("Z")


def test_structured_extras_become_fields(captured: Any) -> None:
    logger, _, lines = captured
    logger.info("enrolled", extra={"device_id": "abc", "days_remaining": 14.5})
    entry = lines()[0]
    assert entry["device_id"] == "abc"
    assert entry["days_remaining"] == 14.5


def test_level_names_are_lowercase(captured: Any) -> None:
    """Matches the agent's own vocabulary from policy.agent_settings.v1."""
    logger, _, lines = captured
    logger.warning("careful")
    assert lines()[0]["level"] == "warning"


def test_an_unserializable_extra_does_not_lose_the_line(captured: Any) -> None:
    """A logging handler that raises discards the record.

    `default=str` means an unexpected object degrades to its repr rather than
    taking the whole line - and the line you lose is always the one explaining
    the failure.
    """

    class Awkward:
        def __repr__(self) -> str:
            return "<awkward>"

    logger, _, lines = captured
    logger.info("odd", extra={"thing": Awkward()})
    assert lines()[0]["thing"] == "<awkward>"


def test_the_agent_logger_does_not_propagate() -> None:
    """Propagation would copy every record into a handler we do not control.

    The root logger may be configured by something else entirely, and that
    handler has no redaction.
    """
    stream = io.StringIO()
    logger = configure_logging("info", stream=stream)
    try:
        assert logger.propagate is False
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()


def test_configure_logging_is_idempotent() -> None:
    """Called twice, one handler. Otherwise every line would be duplicated."""
    stream = io.StringIO()
    configure_logging("info", stream=stream)
    logger = configure_logging("info", stream=stream)
    try:
        assert len(logger.handlers) == 1
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()


# --------------------------------------------------------------------------- #
# Redaction: registered values
# --------------------------------------------------------------------------- #


def test_a_registered_token_never_reaches_the_output(captured: Any) -> None:
    logger, registry, lines = captured
    registry.register(TOKEN)
    logger.info("enrolling with token %s", TOKEN)

    rendered = json.dumps(lines())
    assert TOKEN not in rendered
    assert REDACTED in rendered


def test_a_registered_token_is_scrubbed_from_an_exception_message(captured: Any) -> None:
    """The path that actually leaks.

    An HTTP library that puts the request body into an exception, or a parser
    that echoes its input, puts the token somewhere the author never looked.
    Redacting the serialized line covers it; redacting only the message would
    not.
    """
    logger, registry, lines = captured
    registry.register(TOKEN)
    try:
        raise ValueError(f"server rejected enrollment_token={TOKEN}")
    except ValueError:
        logger.error("enrollment failed", exc_info=True)

    rendered = json.dumps(lines())
    assert TOKEN not in rendered
    assert "enrollment failed" in rendered


def test_a_registered_token_is_scrubbed_from_a_structured_extra(captured: Any) -> None:
    logger, registry, lines = captured
    registry.register(TOKEN)
    logger.info("request", extra={"body": {"enrollment_token": TOKEN, "hostname": "laptop-1"}})

    rendered = json.dumps(lines())
    assert TOKEN not in rendered
    # Redaction must not cost the surrounding context.
    assert "laptop-1" in rendered


def test_longest_secret_is_replaced_first() -> None:
    """One secret containing another must not corrupt the longer one.

    Replacing the shorter first would rewrite the longer into a form the second
    pass no longer matches, leaving part of it in the log.
    """
    registry = SecretRegistry()
    registry.register("abcdefghij")
    registry.register("abcdefghijklmnop")
    scrubbed = registry.scrub("value=abcdefghijklmnop")
    assert "abcdefghij" not in scrubbed
    assert scrubbed == f"value={REDACTED}"


@pytest.mark.parametrize("value", ["", None, "short"])
def test_short_or_empty_values_are_not_registered(value: Any) -> None:
    """A guard against destroying the log.

    Registering a two-character string would scrub that substring out of every
    later line. Ignored rather than raising, because the caller is holding a
    credential it must not inspect, and an exception would put the value into a
    traceback.
    """
    registry = SecretRegistry()
    registry.register(value)
    assert len(registry) == 0
    assert MIN_SECRET_LENGTH == 8


# --------------------------------------------------------------------------- #
# Redaction: private key material
# --------------------------------------------------------------------------- #


def test_a_pem_private_key_is_redacted_without_being_registered(captured: Any) -> None:
    """The safety net for key material nobody remembered to register."""
    logger, _, lines = captured
    logger.error("could not load key", extra={"content": PRIVATE_KEY_PEM})

    rendered = json.dumps(lines())
    assert "BEGIN PRIVATE KEY" not in rendered
    assert "MC4CAQAwBQYDK2Vw" not in rendered


@pytest.mark.parametrize(
    "armour", ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]
)
def test_every_pem_private_key_armour_variant_is_matched(armour: str) -> None:
    """OpenSSL emits several; matching only one would miss the others."""
    pem = f"-----BEGIN {armour}-----\nc2VjcmV0\n-----END {armour}-----"
    assert redact(f"key: {pem}", SecretRegistry()) == f"key: {REDACTED}"


def test_a_pem_key_is_redacted_after_json_escaping() -> None:
    """The form it is actually in once serialized.

    `json.dumps` turns the newlines into a literal backslash-n, so a pattern
    written only for real newlines would stop matching at exactly the point it
    needs to work.
    """
    escaped = PRIVATE_KEY_PEM.replace("\n", "\\n")
    assert "BEGIN PRIVATE KEY" not in redact(escaped, SecretRegistry())


def test_a_certificate_is_not_redacted() -> None:
    """A certificate is public material and is useful in a log.

    Over-redaction has a cost: it removes the context an operator needs. Only
    private material goes.
    """
    pem = "-----BEGIN CERTIFICATE-----\nc29tZSBjZXJ0\n-----END CERTIFICATE-----"
    assert redact(pem, SecretRegistry()) == pem


# --------------------------------------------------------------------------- #
# Redaction: field names
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [
        "enrollment_token",
        "enrollmentToken",
        "token",
        "password",
        "device_private_key",
        "secret",
        "seed",
        "signature",
        "value_b64",
    ],
)
def test_sensitive_field_names_are_recognised(name: str) -> None:
    assert is_sensitive_field(name)


@pytest.mark.parametrize("name", ["device_id", "hostname", "key_id", "days_remaining", "os"])
def test_ordinary_field_names_are_not_redacted(name: str) -> None:
    """`key_id` in particular: it names a key, it is not key material.

    Redacting it would remove the one field that explains an `unknown_key_id`
    failure.
    """
    assert not is_sensitive_field(name)


def test_a_sensitive_field_is_redacted_by_name_even_when_unregistered(
    captured: Any,
) -> None:
    """Covers the value the code never had a chance to register."""
    logger, _, lines = captured
    logger.info("request", extra={"enrollment_token": "a-value-nobody-registered"})
    entry = lines()[0]
    assert entry["enrollment_token"] == REDACTED


# --------------------------------------------------------------------------- #
# Levels
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        ("error", "error"),
        ("warn", "warn"),
        ("info", "info"),
        ("debug", "debug"),
        ("DEBUG", "debug"),
        ("  info  ", "info"),
    ],
)
def test_known_levels_normalise(requested: str, expected: str) -> None:
    assert normalise_level(requested) == expected


@pytest.mark.parametrize("requested", ["trace", "verbose", "WARNING", "", None])
def test_unknown_levels_clamp_to_the_default(requested: Any) -> None:
    """Same reasoning as the numeric clamp: never brick on a newer server."""
    assert normalise_level(requested) == "info"


def test_warn_maps_to_the_stdlib_warning_level() -> None:
    """The policy spelling is "warn"; the stdlib's is WARNING."""
    stream = io.StringIO()
    logger = configure_logging("warn", stream=stream)
    try:
        assert logger.level == logging.WARNING
        logger.info("should not appear")
        logger.warning("should appear")
        assert "should not appear" not in stream.getvalue()
        assert "should appear" in stream.getvalue()
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()


def test_get_logger_returns_a_child_of_the_agent_logger() -> None:
    assert get_logger("runtime").name == "ubuntuguard_agent.runtime"
    assert get_logger().name == "ubuntuguard_agent"


def test_formatter_can_be_used_directly() -> None:
    """Keeps the formatter usable without the global configuration.

    The unit under test is a function of a record, which is what lets these
    tests assert on redaction rather than on handler wiring.
    """
    registry = SecretRegistry()
    registry.register(TOKEN)
    formatter = JsonFormatter(registry=registry)
    record = logging.LogRecord(
        name="ubuntuguard_agent.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="token is %s",
        args=(TOKEN,),
        exc_info=None,
    )
    rendered = formatter.format(record)
    assert TOKEN not in rendered
    assert json.loads(rendered)["msg"] == f"token is {REDACTED}"
