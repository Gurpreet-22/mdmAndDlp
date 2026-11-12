"""The heartbeat: payload, clamping, and the scheduled task around it.

The clamping tests are the security-relevant ones. `HeartbeatResponse` is not
signed, so a compromised or impersonated server can put any number in
`heartbeat_seconds`. Clamping is what makes accepting an unsigned hint
acceptable at all: the worst that can be done to the fleet's cadence is move it
inside a window the agent already decided was safe.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
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
from ubuntuguard_agent import constants
from ubuntuguard_agent.config import AgentConfig, AgentPaths, AgentSettings
from ubuntuguard_agent.errors import HttpStatusError, TransportError
from ubuntuguard_agent.heartbeat import (
    HEARTBEAT_PATH,
    build_heartbeat_payload,
    send_heartbeat,
)
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.identity import ensure_runtime_paths
from ubuntuguard_agent.osadapter.base import HostFacts, OsRelease
from ubuntuguard_agent.service import HeartbeatTask

PEM = serialization.Encoding.PEM


class FakeAdapter:
    name = "fake"

    def __init__(self, **overrides: object) -> None:
        defaults: dict[str, object] = {
            "hostname": "test-laptop",
            "os": OsRelease(id="ubuntu", version_id="24.04"),
            "kernel": "6.8.0-45-generic",
            "arch": "x86_64",
            "uptime_seconds": 4242,
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
        authority, common_name="localhost", hostnames=("localhost",), server_auth=True
    )
    assert key is not None
    return {
        "ca": write_pem(tmp_path / "server-ca.pem", authority.pem),
        "certificate": write_pem(tmp_path / "server.crt", certificate.public_bytes(PEM)),
        "key": write_key(tmp_path / "server.key", key),
    }


def heartbeat_response(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "server_time": "2026-11-05T12:00:00Z",
        "heartbeat_seconds": 60,
        "heartbeat_jitter_pct": 10,
        "certificate_renew_after": "2026-11-20T12:00:00Z",
        "available_policies": [],
    }
    document.update(overrides)
    return json.dumps(document).encode()


def config_for(tmp_path: Path, **overrides: object) -> AgentConfig:
    base: dict[str, object] = {
        "server_url": "https://localhost:1",
        "server_ca_bundle": None,
        "paths": AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run"),
        "settings": AgentSettings(),
        "release_build": True,
        "config_path": None,
    }
    base.update(overrides)
    return AgentConfig(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The request body
# --------------------------------------------------------------------------- #


def test_the_payload_matches_the_servers_heartbeat_request() -> None:
    payload = build_heartbeat_payload(FakeAdapter())
    assert set(payload) == {
        "agent_version",
        "uptime_seconds",
        "applied_policy_versions",
        "primary_adapter_ip",
    }
    assert payload["uptime_seconds"] == 4242
    assert payload["applied_policy_versions"] == {}


def test_nothing_in_the_payload_claims_liveness() -> None:
    """Online is computed server-side from the heartbeat it received.

    There is deliberately no field here by which an agent could assert it is
    online, which is why `DeviceSummary.online` can be trusted at all.
    """
    payload = build_heartbeat_payload(FakeAdapter())
    assert "online" not in payload
    assert "last_heartbeat_at" not in payload
    assert "status" not in payload


def test_an_unreadable_uptime_reports_zero_rather_than_null() -> None:
    """The server requires an integer and has no null for this field."""
    payload = build_heartbeat_payload(FakeAdapter(uptime_seconds=None))
    assert payload["uptime_seconds"] == 0


def test_applied_policy_versions_is_copied_not_aliased() -> None:
    """A caller's dict must not be mutable through the payload."""
    source = {"usb_control": 3}
    payload = build_heartbeat_payload(FakeAdapter(), applied_policy_versions=source)
    source["usb_control"] = 99
    assert payload["applied_policy_versions"] == {"usb_control": 3}


# --------------------------------------------------------------------------- #
# Clamping an unsigned response
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (1, constants.HEARTBEAT_SECONDS.minimum),
        (0, constants.HEARTBEAT_SECONDS.minimum),
        (-60, constants.HEARTBEAT_SECONDS.minimum),
        (10_000_000, constants.HEARTBEAT_SECONDS.maximum),
        (60, 60),
    ],
)
def test_the_heartbeat_interval_is_clamped(
    server_tls: dict[str, Path], requested: int, expected: int
) -> None:
    """A server cannot make the fleet flood, and cannot make it go quiet."""
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=heartbeat_response(heartbeat_seconds=requested))],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        hints = send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))

    assert hints.heartbeat_seconds == expected


def test_a_clamp_is_recorded_so_it_is_never_silent(server_tls: dict[str, Path]) -> None:
    """An operator who sets 5 and sees 30 needs something to explain it."""
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=heartbeat_response(heartbeat_seconds=5))],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        hints = send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))

    assert hints.clamped == (("heartbeat_seconds", 5, constants.HEARTBEAT_SECONDS.minimum),)


def test_the_jitter_percentage_is_clamped(server_tls: dict[str, Path]) -> None:
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=heartbeat_response(heartbeat_jitter_pct=400))],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        hints = send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))

    assert hints.heartbeat_jitter_pct == constants.HEARTBEAT_JITTER_PCT.maximum


@pytest.mark.parametrize("value", ["sixty", None, True, 1.5, [], {}])
def test_a_non_integer_interval_falls_back_to_the_default(
    server_tls: dict[str, Path], value: object
) -> None:
    """`True` is an int in Python, and `heartbeat_seconds: true` is not a value.

    Replaced with the default rather than clamped: clamping a structural error
    would turn `true` into 30 seconds and look deliberate.
    """
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=heartbeat_response(heartbeat_seconds=value))],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        hints = send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))

    assert hints.heartbeat_seconds == constants.HEARTBEAT_SECONDS.default
    assert hints.clamped == ()


def test_a_missing_field_falls_back_to_the_default(server_tls: dict[str, Path]) -> None:
    body = json.dumps({"server_time": "2026-11-05T12:00:00Z"}).encode()
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=body)],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        hints = send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))

    assert hints.heartbeat_seconds == constants.HEARTBEAT_SECONDS.default
    assert hints.certificate_renew_after is None


# --------------------------------------------------------------------------- #
# Success and failure
# --------------------------------------------------------------------------- #


def test_a_heartbeat_succeeds_and_reaches_the_right_path(
    server_tls: dict[str, Path],
) -> None:
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=heartbeat_response())],
    ) as (base_url, recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        hints = send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))

    assert recorded[0].path == "/" + HEARTBEAT_PATH
    assert hints.server_time == "2026-11-05T12:00:00Z"
    assert hints.certificate_renew_after == dt.datetime(2026, 11, 20, 12, 0, tzinfo=dt.timezone.utc)


def test_a_revoked_device_is_refused_on_its_next_heartbeat(
    server_tls: dict[str, Path],
) -> None:
    """Revocation is enforced per request, not by a CRL."""
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=401, body=b'{"code":"device_not_active"}')],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(HttpStatusError) as raised:
            send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))

    assert raised.value.status == 401
    assert raised.value.code == "device_not_active"
    # Not retried by the caller: a revoked device does not become active.
    assert raised.value.retryable is False


def test_a_non_json_heartbeat_response_is_a_transport_error(
    server_tls: dict[str, Path],
) -> None:
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=b"<html>502</html>", content_type="text/html")],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(TransportError):
            send_heartbeat(client, build_heartbeat_payload(FakeAdapter()))


# --------------------------------------------------------------------------- #
# The scheduled task
# --------------------------------------------------------------------------- #


def test_the_task_skips_when_no_server_is_configured(tmp_path: Path) -> None:
    """A skip, not a failure: no backoff and no repeated warning."""
    built = []
    task = HeartbeatTask(
        config_for(tmp_path, server_url=None),
        FakeAdapter(),
        logger=logging.getLogger("test"),
        client_factory=lambda config: built.append(config) or None,  # type: ignore[arg-type,return-value]
    )
    task()
    assert built == [], "a client was built for an unconfigured agent"


def test_the_task_skips_when_the_device_is_not_enrolled(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    built = []
    task = HeartbeatTask(
        config,
        FakeAdapter(),
        logger=logging.getLogger("test"),
        client_factory=lambda cfg: built.append(cfg) or None,  # type: ignore[arg-type,return-value]
    )
    task()
    assert built == [], "a client was built without an identity"


def test_the_task_adopts_the_servers_interval(tmp_path: Path, server_tls: dict[str, Path]) -> None:
    """And through the clamp, so an absurd value cannot take effect."""
    config = config_for(tmp_path, server_ca_bundle=server_tls["ca"])
    ensure_runtime_paths(config.paths)
    # Both halves present, so `is_enrolled` is satisfied without a real
    # identity: this test is about the scheduling, and the client is injected.
    config.paths.private_key_path.write_bytes(b"placeholder")
    config.paths.certificate_path.write_bytes(b"placeholder")

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=heartbeat_response(heartbeat_seconds=900))],
    ) as (base_url, recorded):
        task = HeartbeatTask(
            config,
            FakeAdapter(),
            logger=logging.getLogger("test"),
            client_factory=lambda _config: ServerClient(base_url, ca_bundle=server_tls["ca"]),
        )
        assert task.interval_seconds == constants.HEARTBEAT_SECONDS.default
        task()

    assert len(recorded) == 1
    assert task.interval_seconds == 900
    # Jittered, so bounded rather than exact.
    assert 0 < task.interval() <= 900 * 1.5


def test_the_task_discards_its_client_after_a_failure(
    tmp_path: Path, server_tls: dict[str, Path]
) -> None:
    """So the next attempt picks up an identity that changed on disk.

    A cached TLS context holds the certificate it was built with for the life
    of the process, which would otherwise outlive a re-enrollment.
    """
    config = config_for(tmp_path, server_ca_bundle=server_tls["ca"])
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_bytes(b"placeholder")
    config.paths.certificate_path.write_bytes(b"placeholder")

    builds = 0

    def factory(_config: AgentConfig) -> ServerClient:
        nonlocal builds
        builds += 1
        return ServerClient("https://localhost:9", ca_bundle=server_tls["ca"], timeout_seconds=1.0)

    task = HeartbeatTask(
        config,
        FakeAdapter(),
        logger=logging.getLogger("test"),
        client_factory=factory,
    )

    for _ in range(2):
        with pytest.raises(TransportError):
            task()

    assert builds == 2, "the failed client was reused"
