"""The HTTP client, tested against a real TLS server on loopback.

The refusals are the point of this module. A client that talks to the right
server is easy; what has to be proven is that it refuses the wrong one, refuses
to be redirected, refuses an unbounded response and refuses plaintext. Each of
those is a one-line edit away from being silently removed, so each has a test
that fails when it is.
"""

from __future__ import annotations

import datetime as dt
import json
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
from ubuntuguard_agent.errors import (
    ConfigError,
    HttpStatusError,
    TlsVerificationError,
    TransportError,
)
from ubuntuguard_agent.http import MAX_RESPONSE_BYTES, ServerClient

PEM = serialization.Encoding.PEM


@pytest.fixture
def server_tls(tmp_path: Path) -> dict[str, Path]:
    """A correctly issued listener certificate, plus the CA that signed it."""
    authority = make_authority("Harness Server CA")
    key, certificate = issue_leaf(
        authority,
        common_name="localhost",
        hostnames=("localhost",),
        ip_addresses=("127.0.0.1",),
        server_auth=True,
    )
    assert key is not None
    return {
        "ca": write_pem(tmp_path / "server-ca.pem", authority.pem),
        "certificate": write_pem(tmp_path / "server.crt", certificate.public_bytes(PEM)),
        "key": write_key(tmp_path / "server.key", key),
    }


# --------------------------------------------------------------------------- #
# The happy path, so the refusals below cannot pass by nothing working
# --------------------------------------------------------------------------- #


def test_a_verified_request_succeeds_and_sends_the_body(server_tls: dict[str, Path]) -> None:
    payload = {"hello": "world", "n": 1}
    response_body = json.dumps({"ok": True}).encode()

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=201, body=response_body)],
    ) as (base_url, recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        response = client.post_json("api/v1/enroll", payload)

    assert response.status == 201
    assert response.json() == {"ok": True}
    assert len(recorded) == 1
    assert recorded[0].path == "/api/v1/enroll"
    assert recorded[0].json() == payload
    assert recorded[0].headers["content-type"] == "application/json"
    assert recorded[0].headers["user-agent"].startswith("ubuntuguard-agent/")


# --------------------------------------------------------------------------- #
# Server TLS certificate verification
# --------------------------------------------------------------------------- #


def test_a_certificate_from_the_wrong_ca_is_refused(
    server_tls: dict[str, Path], tmp_path: Path
) -> None:
    """The single most important test in this file.

    An agent that accepted this would send a single-use enrollment token to
    whatever answered on the configured address.
    """
    other = make_authority("Some Other CA")
    wrong_ca = write_pem(tmp_path / "wrong-ca.pem", other.pem)

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
    ) as (base_url, recorded):
        client = ServerClient(base_url, ca_bundle=wrong_ca)
        with pytest.raises(TlsVerificationError) as raised:
            client.post_json("api/v1/enroll", {"token": "x"})

    assert "did not verify" in str(raised.value)
    # Nothing was sent. The handshake failed before any application data, so
    # the token never left the machine.
    assert recorded == []


def test_a_certificate_for_the_wrong_hostname_is_refused(tmp_path: Path) -> None:
    """check_hostname stays on. A valid certificate for another name is not ours."""
    authority = make_authority("Harness Server CA")
    key, certificate = issue_leaf(
        authority,
        common_name="not-localhost",
        hostnames=("not-localhost.invalid",),
        server_auth=True,
    )
    assert key is not None

    certificate_path = write_pem(tmp_path / "wrong-host.crt", certificate.public_bytes(PEM))
    key_path = write_key(tmp_path / "wrong-host.key", key)
    ca_path = write_pem(tmp_path / "ca.pem", authority.pem)

    with tls_server(server_certificate=certificate_path, server_key=key_path) as (
        base_url,
        recorded,
    ):
        client = ServerClient(base_url, ca_bundle=ca_path)
        with pytest.raises(TlsVerificationError):
            client.post_json("api/v1/enroll", {"token": "x"})

    assert recorded == []


def test_an_expired_server_certificate_is_refused(tmp_path: Path) -> None:
    authority = make_authority("Harness Server CA")
    key, certificate = issue_leaf(
        authority,
        common_name="localhost",
        hostnames=("localhost",),
        server_auth=True,
        not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10),
        valid_for=dt.timedelta(days=5),
    )
    assert key is not None

    with tls_server(
        server_certificate=write_pem(tmp_path / "expired.crt", certificate.public_bytes(PEM)),
        server_key=write_key(tmp_path / "expired.key", key),
    ) as (base_url, recorded):
        client = ServerClient(base_url, ca_bundle=write_pem(tmp_path / "ca.pem", authority.pem))
        with pytest.raises(TlsVerificationError):
            client.post_json("api/v1/enroll", {"token": "x"})

    assert recorded == []


def test_the_system_trust_store_is_never_a_fallback(tmp_path: Path) -> None:
    """No CA bundle is a configuration error, not a quiet widening of trust.

    `ssl.create_default_context()` with no arguments loads around 150 public
    CAs. For an internal API that would mean accepting a certificate from any
    of them, so the absence of a bundle must fail rather than default.
    """
    with pytest.raises(ConfigError) as raised:
        ServerClient("https://localhost:9", ca_bundle=None)
    assert "system trust store" in str(raised.value)


def test_a_missing_ca_bundle_names_the_path(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as raised:
        ServerClient("https://localhost:9", ca_bundle=tmp_path / "absent.pem")
    assert "absent.pem" in str(raised.value)


# --------------------------------------------------------------------------- #
# Client certificates: the device plane
# --------------------------------------------------------------------------- #


def test_the_client_certificate_is_presented_when_the_server_requires_one(
    server_tls: dict[str, Path], tmp_path: Path
) -> None:
    """Mutual TLS end to end, against a listener configured like nginx's 8444."""
    device_ca = make_authority("Harness Device CA")
    device_key, device_certificate = issue_leaf(
        device_ca, common_name="11111111-2222-3333-4444-555555555555", client_auth=True
    )
    assert device_key is not None

    certificate_path = write_pem(tmp_path / "device.crt", device_certificate.public_bytes(PEM))
    key_path = write_key(tmp_path / "device.key", device_key)
    device_ca_path = write_pem(tmp_path / "device-ca.pem", device_ca.pem)

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        client_ca=device_ca_path,
    ) as (base_url, recorded):
        client = ServerClient(
            base_url,
            ca_bundle=server_tls["ca"],
            client_certificate=certificate_path,
            client_key=key_path,
        )
        response = client.post_json("api/v1/devices/me/heartbeat", {"agent_version": "0.1.0"})

    assert response.status == 200
    # The server saw the certificate, and it is the one with our device id in
    # the subject - which is what the application re-derives identity from.
    peer = recorded[0].peer_certificate
    assert peer is not None
    subject_values = {attribute[0][1] for attribute in peer.get("subject", ()) if attribute}
    assert "11111111-2222-3333-4444-555555555555" in subject_values


def test_without_a_client_certificate_a_mutual_tls_listener_refuses(
    server_tls: dict[str, Path], tmp_path: Path
) -> None:
    """The nginx `ssl_verify_client on` behaviour: refused at the handshake.

    This is why `POST /enroll` cannot be served from the device listener, and
    the reason the dev configuration uses two ports.
    """
    device_ca = make_authority("Harness Device CA")
    device_ca_path = write_pem(tmp_path / "device-ca.pem", device_ca.pem)

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        client_ca=device_ca_path,
    ) as (base_url, recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(TransportError):
            client.post_json("api/v1/devices/me/heartbeat", {"agent_version": "0.1.0"})

    assert recorded == []


def test_a_client_certificate_from_the_wrong_ca_is_refused(
    server_tls: dict[str, Path], tmp_path: Path
) -> None:
    """A self-signed certificate naming a real device id does not authenticate."""
    real_ca = make_authority("Harness Device CA")
    forged_ca = make_authority("Attacker CA")
    forged_key, forged_certificate = issue_leaf(
        forged_ca, common_name="11111111-2222-3333-4444-555555555555", client_auth=True
    )
    assert forged_key is not None

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        client_ca=write_pem(tmp_path / "real-device-ca.pem", real_ca.pem),
    ) as (base_url, recorded):
        client = ServerClient(
            base_url,
            ca_bundle=server_tls["ca"],
            client_certificate=write_pem(
                tmp_path / "forged.crt", forged_certificate.public_bytes(PEM)
            ),
            client_key=write_key(tmp_path / "forged.key", forged_key),
        )
        with pytest.raises(TransportError):
            client.post_json("api/v1/devices/me/heartbeat", {"agent_version": "0.1.0"})

    assert recorded == []


def test_incomplete_client_certificate_material_is_a_configuration_error(
    server_tls: dict[str, Path], tmp_path: Path
) -> None:
    with pytest.raises(ConfigError) as raised:
        ServerClient(
            "https://localhost:9",
            ca_bundle=server_tls["ca"],
            client_certificate=tmp_path / "absent.crt",
            client_key=tmp_path / "absent.key",
        )
    assert "incomplete" in str(raised.value)


# --------------------------------------------------------------------------- #
# Refusals that are not about certificates
# --------------------------------------------------------------------------- #


def test_plaintext_http_is_refused_without_an_explicit_opt_in() -> None:
    with pytest.raises(ConfigError) as raised:
        ServerClient("http://127.0.0.1:9", ca_bundle=None)
    assert "HTTPS is required" in str(raised.value)


def test_plaintext_http_is_allowed_only_when_permitted() -> None:
    """Constructing succeeds; `config.py` is what decides whether it may."""
    client = ServerClient("http://127.0.0.1:9", ca_bundle=None, plaintext_permitted=True)
    assert client.base_url.startswith("http://")


def test_an_unsupported_scheme_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        ServerClient("ftp://example.invalid", ca_bundle=None)
    assert "scheme" in str(raised.value)


def test_a_redirect_is_refused_rather_than_followed(server_tls: dict[str, Path]) -> None:
    """Following one would let the server move the token to a host of its choosing."""
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[
            CannedResponse(status=302, body=b"", location="https://attacker.invalid/enroll")
        ],
    ) as (base_url, recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(HttpStatusError) as raised:
            client.post_json("api/v1/enroll", {"enrollment_token": "x" * 40})

    assert raised.value.status == 302
    assert "refuses to follow" in str(raised.value)
    # Exactly one request. The redirect was not acted on.
    assert len(recorded) == 1


def test_an_absolute_path_cannot_escape_the_base_url(server_tls: dict[str, Path]) -> None:
    """urljoin with an absolute URL would discard the base entirely."""
    client = ServerClient("https://localhost:9", ca_bundle=server_tls["ca"])
    with pytest.raises(ConfigError) as raised:
        client.post_json("https://attacker.invalid/enroll", {})
    assert "relative" in str(raised.value)


def test_an_oversized_response_is_abandoned(server_tls: dict[str, Path]) -> None:
    """A hostile or broken server must not become the agent's memory problem."""
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=b"A" * (MAX_RESPONSE_BYTES + 1024))],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(TransportError) as raised:
            client.post_json("api/v1/enroll", {})

    assert "exceeded" in str(raised.value)


def test_a_slow_drip_response_hits_the_total_deadline(server_tls: dict[str, Path]) -> None:
    """A per-recv socket timeout never expires against a trickle; the deadline does."""
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=b"0123456789", chunk_delay_seconds=0.05)],
    ) as (base_url, _recorded):
        client = ServerClient(
            base_url,
            ca_bundle=server_tls["ca"],
            total_timeout_seconds=0.01,
        )
        with pytest.raises(TransportError) as raised:
            client.post_json("api/v1/enroll", {})

    assert "still sending" in str(raised.value)


def test_an_unreachable_server_is_a_transport_error_not_a_tls_error(
    server_tls: dict[str, Path],
) -> None:
    """Port 9 (discard) refuses immediately on loopback."""
    client = ServerClient("https://localhost:9", ca_bundle=server_tls["ca"], timeout_seconds=1.0)
    with pytest.raises(TransportError) as raised:
        client.post_json("api/v1/enroll", {})
    # Specifically NOT a TlsVerificationError: the distinction drives whether
    # the caller retries.
    assert not isinstance(raised.value, TlsVerificationError)


# --------------------------------------------------------------------------- #
# HTTP status handling
# --------------------------------------------------------------------------- #


def test_a_problem_document_code_is_extracted(server_tls: dict[str, Path]) -> None:
    problem = json.dumps(
        {
            "code": "enrollment_token_invalid",
            "title": "Enrollment token invalid or already used",
            "status": 401,
        }
    ).encode()

    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=401, body=problem)],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(HttpStatusError) as raised:
            client.post_json("api/v1/enroll", {})

    assert raised.value.status == 401
    assert raised.value.code == "enrollment_token_invalid"
    assert raised.value.retryable is False


@pytest.mark.parametrize(
    ("status", "retryable"),
    [(400, False), (401, False), (422, False), (429, True), (500, True), (503, True)],
)
def test_which_statuses_are_worth_retrying(
    server_tls: dict[str, Path], status: int, retryable: bool
) -> None:
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(status=status, body=b"{}")],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        with pytest.raises(HttpStatusError) as raised:
            client.post_json("api/v1/enroll", {})

    assert raised.value.retryable is retryable


def test_a_non_json_body_reports_the_length_and_not_the_content(
    server_tls: dict[str, Path],
) -> None:
    """A proxy error page must not be pasted into a log line."""
    page = b"<html><body>502 Bad Gateway from some-internal-proxy</body></html>"
    with tls_server(
        server_certificate=server_tls["certificate"],
        server_key=server_tls["key"],
        responses=[CannedResponse(body=page, content_type="text/html")],
    ) as (base_url, _recorded):
        client = ServerClient(base_url, ca_bundle=server_tls["ca"])
        response = client.post_json("api/v1/enroll", {})
        with pytest.raises(TransportError) as raised:
            response.json()

    message = str(raised.value)
    assert str(len(page)) in message
    assert "some-internal-proxy" not in message
