"""Enrollment, end to end over a real TLS connection on loopback.

The tests that matter most here are about what happens when things go wrong,
because enrollment spends a single-use credential and the cost of getting a
failure path wrong is an operator minting another token for a laptop that
already enrolled.

Specifically:

  - a retry must present the identical body, or it misses the server's
    idempotency cache and is told its token is spent;
  - a refusal must not be retried into the backoff ceiling;
  - the token must never appear in a log line or on disk;
  - nothing may be written until the response has been verified.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import logging
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from tls_harness import (
    CannedResponse,
    issue_leaf,
    make_authority,
    tls_server,
    write_key,
    write_pem,
)
from ubuntuguard_agent.config import AgentConfig, AgentPaths, AgentSettings
from ubuntuguard_agent.enrollment import (
    MAX_TOKEN_LENGTH,
    MIN_TOKEN_LENGTH,
    build_enroll_payload,
    enroll,
    read_token_from_file,
    read_token_from_stdin,
)
from ubuntuguard_agent.errors import EnrollmentError, TlsVerificationError
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.identity import ensure_device_keypair, ensure_runtime_paths, is_enrolled
from ubuntuguard_agent.logging_setup import SECRETS, JsonFormatter
from ubuntuguard_agent.osadapter.base import HostFacts, OsRelease

PEM = serialization.Encoding.PEM
DEVICE_ID = "11111111-2222-3333-4444-555555555555"
TOKEN = "T" * 43  # the shape of a base64url-encoded 32-byte token


class FakeAdapter:
    """An adapter with every field populated, so mapping bugs are visible."""

    name = "fake"

    def __init__(self, **overrides: object) -> None:
        defaults: dict[str, object] = {
            "hostname": "test-laptop",
            "os": OsRelease(id="ubuntu", version_id="24.04", pretty_name="Ubuntu 24.04.1 LTS"),
            "kernel": "6.8.0-45-generic",
            "arch": "x86_64",
            "uptime_seconds": 1234,
            "boot_id": "4f8a9c1e-2b3d-4e5f-8a9b-0c1d2e3f4a5b",
            "machine_id_hash": "a" * 64,
            "dmi_product_uuid_hash": None,
            "mac_hashes": ("b" * 64, "c" * 64),
            "virtualization": None,
            "primary_adapter_ip": "10.0.0.5",
        }
        defaults.update(overrides)
        self._facts = HostFacts(**defaults)  # type: ignore[arg-type]

    def host_facts(self) -> HostFacts:
        return self._facts

    def is_supported(self) -> bool:
        return True

    def is_validated_release(self) -> bool:
        return False


@pytest.fixture
def server_tls(tmp_path: Path) -> dict[str, Path]:
    authority = make_authority("Harness Server CA")
    key, certificate = issue_leaf(
        authority,
        common_name="localhost",
        hostnames=("localhost",),
        server_auth=True,
    )
    assert key is not None
    return {
        "ca": write_pem(tmp_path / "server-ca.pem", authority.pem),
        "certificate": write_pem(tmp_path / "server.crt", certificate.public_bytes(PEM)),
        "key": write_key(tmp_path / "server.key", key),
    }


def config_for(tmp_path: Path, server_tls: dict[str, Path], **overrides: object) -> AgentConfig:
    base: dict[str, object] = {
        "server_url": "https://localhost:1",  # replaced per test with the real port
        "server_ca_bundle": server_tls["ca"],
        "paths": AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run"),
        "settings": AgentSettings(),
        "release_build": True,
        "config_path": None,
    }
    base.update(overrides)
    return AgentConfig(**base)  # type: ignore[arg-type]


def enrollment_response(public_key: object, *, clone_suspected: bool = False) -> bytes:
    """A `201` body with a certificate genuinely issued for `public_key`."""
    authority = make_authority("UbuntuGuard Test Device CA")
    _, certificate = issue_leaf(
        authority,
        common_name=DEVICE_ID,
        client_auth=True,
        public_key=public_key,  # type: ignore[arg-type]
        valid_for=dt.timedelta(days=30),
    )
    not_after = certificate.not_valid_after_utc
    not_before = certificate.not_valid_before_utc
    return json.dumps(
        {
            "device_id": DEVICE_ID,
            "client_certificate_pem": certificate.public_bytes(PEM).decode(),
            "ca_chain_pem": authority.pem.decode(),
            "certificate_not_after": not_after.isoformat(),
            "certificate_renew_after": (not_before + (not_after - not_before) / 2).isoformat(),
            "policy_public_keys": [
                {"key_id": "policy-1", "alg": "ed25519", "public_key_b64": "AAAA"}
            ],
            "clone_suspected": clone_suspected,
        }
    ).encode()


# --------------------------------------------------------------------------- #
# Reading the token
# --------------------------------------------------------------------------- #


def test_a_token_file_must_not_be_readable_by_others(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text(TOKEN, encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(EnrollmentError) as raised:
        read_token_from_file(path)
    message = str(raised.value)
    assert "readable by group or others" in message
    assert "revoke the token" in message
    # The message explains the problem without quoting the credential.
    assert TOKEN not in message


def test_a_token_file_at_0600_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "token"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(descriptor, TOKEN.encode())
    os.close(descriptor)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    assert read_token_from_file(path) == TOKEN


def test_reading_a_token_registers_it_for_redaction_immediately(tmp_path: Path) -> None:
    """Registered before anything could log it, which is the whole mechanism."""
    path = tmp_path / "token"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(descriptor, TOKEN.encode())
    os.close(descriptor)

    assert len(SECRETS) == 0
    read_token_from_file(path)
    assert len(SECRETS) == 1
    assert SECRETS.scrub(f"token is {TOKEN}") == "token is ***REDACTED***"


def test_a_token_from_stdin_is_accepted_and_stripped() -> None:
    assert read_token_from_stdin(io.StringIO(f"  {TOKEN}\n")) == TOKEN


def test_a_truncated_token_names_the_length_but_not_the_value() -> None:
    short = "x" * (MIN_TOKEN_LENGTH - 1)
    with pytest.raises(EnrollmentError) as raised:
        read_token_from_stdin(io.StringIO(short))
    message = str(raised.value)
    assert str(len(short)) in message
    assert short not in message


def test_an_overlong_token_is_refused() -> None:
    with pytest.raises(EnrollmentError):
        read_token_from_stdin(io.StringIO("x" * (MAX_TOKEN_LENGTH + 1)))


def test_a_token_with_internal_whitespace_is_refused() -> None:
    with pytest.raises(EnrollmentError) as raised:
        read_token_from_stdin(io.StringIO("AAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBB"))
    assert "whitespace" in str(raised.value)


def test_an_empty_token_is_refused() -> None:
    with pytest.raises(EnrollmentError) as raised:
        read_token_from_stdin(io.StringIO("   \n"))
    assert "empty" in str(raised.value)


# --------------------------------------------------------------------------- #
# The request body: it must match the server's model exactly
# --------------------------------------------------------------------------- #


def test_the_payload_matches_the_servers_enroll_request(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """Field-for-field against `schemas.EnrollRequest`.

    The fields NOT present are as important as the ones that are: an earlier
    draft of the API document specified `public_key_fingerprint` and nested
    `hostname` under `hardware_fingerprint`, and because the model forbids
    extra fields, sending either is a 422.
    """
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)

    payload = build_enroll_payload(config, FakeAdapter(), token=TOKEN, csr_pem=keypair.csr_pem)

    assert set(payload) == {
        "enrollment_token",
        "csr_pem",
        "hostname",
        "agent_version",
        "arch",
        "os",
        "hardware_fingerprint",
        "release_build",
        "primary_adapter_ip",
    }
    assert "public_key_fingerprint" not in payload
    assert set(payload["os"]) == {"id", "version_id", "kernel", "pretty_name"}
    assert "hostname" not in payload["hardware_fingerprint"]
    assert payload["hardware_fingerprint"] == {
        "machine_id_hash": "a" * 64,
        "mac_hashes": ["b" * 64, "c" * 64],
    }
    assert payload["csr_pem"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert "PRIVATE KEY" not in payload["csr_pem"]


def test_unknown_optional_fields_are_omitted_rather_than_null(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """Omission keeps "not collected" distinguishable from "collected as empty"."""
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)

    payload = build_enroll_payload(
        config,
        FakeAdapter(
            machine_id_hash=None,
            mac_hashes=(),
            primary_adapter_ip=None,
            dmi_product_uuid_hash=None,
            virtualization=None,
        ),
        token=TOKEN,
        csr_pem=keypair.csr_pem,
    )

    assert payload["hardware_fingerprint"] == {}
    assert "primary_adapter_ip" not in payload


def test_a_development_build_reports_release_build_false(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """The dashboard flags such a device; the agent does not hide it."""
    config = config_for(tmp_path, server_tls, release_build=False)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    payload = build_enroll_payload(config, FakeAdapter(), token=TOKEN, csr_pem=keypair.csr_pem)
    assert payload["release_build"] is False


def test_a_host_with_no_hostname_is_refused_rather_than_given_a_placeholder(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """`EnrollRequest.hostname` has min_length=1, so "" is a 422.

    A substituted placeholder would put three laptops called "unknown-host" in
    the fleet list, which is worse than stopping with an explanation.
    """
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)

    with pytest.raises(EnrollmentError) as raised:
        build_enroll_payload(config, FakeAdapter(hostname=""), token=TOKEN, csr_pem=keypair.csr_pem)
    assert "hostnamectl" in str(raised.value)


# --------------------------------------------------------------------------- #
# Success
# --------------------------------------------------------------------------- #


def test_enrollment_succeeds_and_installs_the_identity(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=body)],
    ) as (base_url, recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        result = enroll(config, token=TOKEN, adapter=FakeAdapter(), client=client)

    assert result.device_id == DEVICE_ID
    assert result.attempts == 1
    assert result.reused_keypair is True  # the fixture generated it above
    assert is_enrolled(config.paths)

    sent = recorded[0].json()
    assert sent["enrollment_token"] == TOKEN
    assert sent["hostname"] == "test-laptop"
    assert recorded[0].path == "/api/v1/enroll"


def test_the_policy_keys_are_pinned_to_disk(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    """The trust anchor for every future policy arrives once, at enrollment."""
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=body)],
    ) as (base_url, _recorded):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
        )

    pinned = json.loads(config.paths.policy_keys_path.read_text())
    assert pinned["keys"] == [{"key_id": "policy-1", "alg": "ed25519", "public_key_b64": "AAAA"}]


def test_a_clone_warning_does_not_fail_enrollment(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """A reimaged laptop and a cloned VM are indistinguishable from here."""
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key(), clone_suspected=True)

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=body)],
    ) as (base_url, _recorded):
        result = enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
        )

    assert result.clone_suspected is True
    assert is_enrolled(config.paths)


def test_re_enrolling_an_enrolled_device_is_refused(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """Otherwise one laptop acquires two device records."""
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=body)],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        enroll(config, token=TOKEN, adapter=FakeAdapter(), client=client)

        with pytest.raises(EnrollmentError) as raised:
            enroll(config, token=TOKEN, adapter=FakeAdapter(), client=client)

    assert "already has an identity" in str(raised.value)


# --------------------------------------------------------------------------- #
# Retries: the same keypair, the same bytes
# --------------------------------------------------------------------------- #


def test_a_retry_sends_a_byte_identical_body(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    """THE test for the idempotency contract.

    The server caches its response against `(token_hash,
    csr_public_key_fingerprint)`. If a retry changed the CSR, it would miss the
    cache and be told a token that actually worked had been spent.
    """
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[
            CannedResponse(status=503, body=b'{"code":"service_unavailable"}'),
            CannedResponse(status=201, body=body),
        ],
    ) as (base_url, recorded):
        result = enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _seconds: None,
        )

    assert result.attempts == 2
    assert len(recorded) == 2
    assert recorded[0].body == recorded[1].body, "the retry changed the request body"
    assert is_enrolled(config.paths)


def test_a_failed_attempt_leaves_the_keypair_in_place_for_the_next_one(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """Persisted before the first POST, so a later run reuses it."""
    config = config_for(tmp_path, server_tls)

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=401, body=b'{"code":"enrollment_token_invalid"}')],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(EnrollmentError):
            enroll(config, token=TOKEN, adapter=FakeAdapter(), client=client)

    assert config.paths.private_key_path.exists()
    assert config.paths.csr_path.exists()
    assert not config.paths.certificate_path.exists()
    assert not is_enrolled(config.paths)

    # A second run with a new token reuses the keypair rather than generating one.
    first_csr = config.paths.csr_path.read_bytes()
    assert ensure_device_keypair(config.paths).csr_pem == first_csr


def test_an_invalid_token_is_not_retried(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    """An invalid token does not become valid; backing off only delays the news."""
    config = config_for(tmp_path, server_tls)

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=401, body=b'{"code":"enrollment_token_invalid"}')],
        ) as (base_url, recorded),
        pytest.raises(EnrollmentError) as raised,
    ):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _seconds: None,
        )

    assert len(recorded) == 1, "a 401 was retried"
    message = str(raised.value)
    assert "single-use" in message
    assert "dashboard" in message
    assert TOKEN not in message


def test_a_rejected_csr_is_not_retried_and_says_it_is_an_agent_bug(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    config = config_for(tmp_path, server_tls)

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=400, body=b'{"code":"csr_invalid"}')],
        ) as (base_url, recorded),
        pytest.raises(EnrollmentError) as raised,
    ):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _seconds: None,
        )

    assert len(recorded) == 1
    assert "agent bug" in str(raised.value)


def test_a_contract_mismatch_points_at_both_sides(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    config = config_for(tmp_path, server_tls)

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=422, body=b'{"code":"validation_failed"}')],
        ) as (base_url, _recorded),
        pytest.raises(EnrollmentError) as raised,
    ):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _seconds: None,
        )

    assert "schemas.py" in str(raised.value)


def test_a_rate_limited_request_is_retried(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    """nginx `limit_req` returns 429; the server is saying "not now"."""
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[
            CannedResponse(status=429, body=b'{"code":"rate_limited"}'),
            CannedResponse(status=201, body=body),
        ],
    ) as (base_url, recorded):
        result = enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _seconds: None,
        )

    assert result.attempts == 2
    assert len(recorded) == 2


def test_an_unreachable_server_exhausts_its_attempts_then_reports(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """Network interruption with no recovery."""
    config = config_for(tmp_path, server_tls)
    delays: list[float] = []

    client = ServerClient("https://localhost:9", ca_bundle=server_tls["ca"], timeout_seconds=1.0)
    with pytest.raises(EnrollmentError) as raised:
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=client,
            max_attempts=3,
            sleep=delays.append,
        )

    assert "after 3 attempts" in str(raised.value)
    assert len(delays) == 2, "backoff was not applied between attempts"
    assert all(delay > 0 for delay in delays)


def test_a_tls_failure_is_never_retried(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    """Retrying would repeatedly offer the token to whatever is answering."""
    config = config_for(tmp_path, server_tls)
    wrong_ca = write_pem(tmp_path / "wrong-ca.pem", make_authority("Other CA").pem)

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
        ) as (base_url, recorded),
        pytest.raises(TlsVerificationError),
    ):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=wrong_ca),
            sleep=lambda _seconds: None,
        )

    assert recorded == [], "the token reached a server whose certificate did not verify"


# --------------------------------------------------------------------------- #
# Malformed success responses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"device_id": ""}, "device_id"),
        ({"client_certificate_pem": None}, "client_certificate_pem"),
        ({"ca_chain_pem": None}, "ca_chain_pem"),
        ({"policy_public_keys": []}, "no policy signing keys"),
        ({"policy_public_keys": [{"key_id": "k", "alg": "rsa", "public_key_b64": "x"}]}, "ed25519"),
        ({"policy_public_keys": "not-a-list"}, "policy_public_keys"),
    ],
)
def test_a_malformed_response_is_refused_and_nothing_is_written(
    tmp_path: Path, server_tls: dict[str, Path], mutation: dict[str, object], expected: str
) -> None:
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)

    document = json.loads(enrollment_response(keypair.private_key.public_key()))
    document.update(mutation)

    with (
        tls_server(
            server_certificate=server_tls["certificate"],
            server_key=server_tls["key"],
            responses=[CannedResponse(status=201, body=json.dumps(document).encode())],
        ) as (base_url, _recorded),
        pytest.raises(EnrollmentError) as raised,
    ):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
            sleep=lambda _seconds: None,
        )

    assert expected in str(raised.value)
    assert not is_enrolled(config.paths)


# --------------------------------------------------------------------------- #
# Secret handling
# --------------------------------------------------------------------------- #


def test_the_token_never_appears_in_a_log_line(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    """Captured at the formatter, which is where a line actually becomes text.

    Asserting on captured output rather than on `redact()` in isolation: the
    unit test for redaction already exists, and what this adds is that the
    enrollment path is actually wired through a handler that applies it.
    """
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("test_enrollment_redaction")
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    SECRETS.register(TOKEN)
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=body)],
    ) as (base_url, _recorded):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"], logger=logger),
            logger=logger,
        )

    output = stream.getvalue()
    assert output, "nothing was logged, so this test proves nothing"
    assert TOKEN not in output
    assert "PRIVATE KEY" not in output


def test_the_token_is_never_written_to_disk_by_enrollment(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """Every file under the state directory is checked, not just the ones expected."""
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=body)],
    ) as (base_url, _recorded):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
        )

    written = [path for path in config.paths.state_dir.rglob("*") if path.is_file()]
    assert written, "enrollment wrote nothing, so this test proves nothing"
    for path in written:
        assert TOKEN.encode() not in path.read_bytes(), f"the token reached {path}"


def test_the_private_key_is_never_in_the_request_body(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    config = config_for(tmp_path, server_tls)
    ensure_runtime_paths(config.paths)
    keypair = ensure_device_keypair(config.paths)
    body = enrollment_response(keypair.private_key.public_key())

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=body)],
    ) as (base_url, recorded):
        enroll(
            config,
            token=TOKEN,
            adapter=FakeAdapter(),
            client=ServerClient(base_url, ca_bundle=server_tls["ca"]),
        )

    sent = recorded[0].body
    assert b"PRIVATE KEY" not in sent
    # And specifically not this key: the private scalar, in both the raw and
    # the PEM-encoded forms it could plausibly leak as.
    private_numbers = keypair.private_key.private_numbers().private_value
    assert private_numbers.to_bytes(32, "big") not in sent
    assert (
        keypair.private_key.private_bytes(
            encoding=PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        not in sent
    )
