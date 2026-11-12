"""The heartbeat: the agent's only authenticated request in this build.

Two things the heartbeat is, and one it is not.

It **is** how the server learns a device is alive. Liveness is computed
server-side from the timestamp of the last heartbeat it received
(`server/src/ubuntuguard/liveness.py`) and is never self-reported, so there is
no field here by which an agent could claim to be online.

It **is** how the agent learns its check-in cadence and when to renew.

It is **not** a command channel. `HeartbeatResponse` carries timestamps,
integers and a list of available policy versions, and there is no field
anywhere in it that holds a command, a script, a path or a package name. That
is structural rather than conventional: it is the reason a compromised server
cannot run code on a laptop.

Because the response is **not signed**, everything in it is treated as a hint
and bounded before use. See `_clamped`.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
from typing import Any

from ubuntuguard_agent import __version__, constants
from ubuntuguard_agent.config import AgentConfig
from ubuntuguard_agent.errors import ConfigError, TransportError
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.identity import load_identity
from ubuntuguard_agent.logging_setup import get_logger
from ubuntuguard_agent.osadapter import OsAdapter

HEARTBEAT_PATH = "api/v1/devices/me/heartbeat"


@dataclasses.dataclass(frozen=True)
class HeartbeatHints:
    """What the server suggested, already clamped into range."""

    heartbeat_seconds: int
    heartbeat_jitter_pct: int
    server_time: str | None = None
    certificate_renew_after: dt.datetime | None = None
    available_policies: tuple[dict[str, Any], ...] = ()
    #: Settings the server asked for that were outside the agent's bounds, as
    #: `(name, requested, applied)`. Reported so a clamp is never silent.
    clamped: tuple[tuple[str, int, int], ...] = ()


def _clamped(
    name: str, value: object, bound: constants.Bound
) -> tuple[int, tuple[str, int, int] | None]:
    """Coerce one hint into range, reporting whether it had to move.

    Clamped rather than rejected, which is decision D5 and is easy to get
    backwards. The server REJECTS an out-of-range value when an admin creates a
    policy, so the admin is told immediately. The agent CLAMPS, because an
    agent that refused to check in over a number from a newer server would have
    taken itself off the control plane to defend a bound it could simply have
    applied.

    It also matters that this response is unsigned. Clamping is what makes
    accepting an unsigned hint acceptable at all: the worst a compromised
    server can do to the cadence is move it within a window the agent already
    considered safe. It cannot stop the agent checking in, and it cannot turn
    the fleet into a flood.

    A non-integer is replaced with the default rather than clamped. `True` is
    an `int` in Python and `heartbeat_seconds: true` is a structural error, not
    a value to pull into range.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return bound.default, None
    applied = bound.clamp(value)
    return applied, None if applied == value else (name, value, applied)


def _parse_timestamp(value: object) -> dt.datetime | None:
    """Parse an RFC 3339 timestamp, tolerating a trailing Z.

    `fromisoformat` only learned to accept `Z` in 3.11 and the agent targets
    3.10, so the substitution is not optional.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_device_client(config: AgentConfig) -> ServerClient:
    """A client that presents this device's certificate on every request.

    Built from the device plane's base URL, which in production is the same
    host as enrollment and in development is a second port - see
    `config.ENV_DEVICE_URL`.

    `load_identity` is called for its checks, not for the key: it refuses an
    identity whose certificate and private key are not a pair, which otherwise
    surfaces as an unexplained TLS handshake failure that looks like an nginx
    problem. The TLS layer loads the files itself from the paths below.
    """
    base_url = config.device_base_url
    if not base_url:
        raise ConfigError("no server_url is configured; the device plane has no address")

    load_identity(config.paths)

    return ServerClient(
        base_url,
        ca_bundle=config.server_ca_bundle,
        client_certificate=config.paths.certificate_path,
        client_key=config.paths.private_key_path,
        plaintext_permitted=config.plaintext_http_permitted,
    )


def build_heartbeat_payload(
    adapter: OsAdapter,
    *,
    applied_policy_versions: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Assemble the `HeartbeatRequest` body.

    `applied_policy_versions` is always empty in this build: nothing applies a
    policy until Phase 6. It is a parameter rather than a hardcoded `{}` so the
    shape is already right when that lands, and so a test can assert the field
    is sent rather than dropped.
    """
    facts = adapter.host_facts()
    payload: dict[str, Any] = {
        "agent_version": __version__,
        # The server requires an integer and has no null for this field, so an
        # unreadable /proc/uptime reports 0. On a host where /proc is missing
        # the agent has larger problems than an inaccurate uptime.
        "uptime_seconds": max(0, facts.uptime_seconds or 0),
        "applied_policy_versions": dict(applied_policy_versions or {}),
    }
    if facts.primary_adapter_ip:
        payload["primary_adapter_ip"] = facts.primary_adapter_ip
    return payload


def send_heartbeat(
    client: ServerClient,
    payload: dict[str, Any],
    *,
    logger: logging.Logger | None = None,
) -> HeartbeatHints:
    """Send one heartbeat and return the clamped hints from the response."""
    log = logger if logger is not None else get_logger("heartbeat")

    response = client.post_json(HEARTBEAT_PATH, payload)
    document = response.json()
    if not isinstance(document, dict):
        raise TransportError("the heartbeat response was not a JSON object")

    seconds, seconds_clamp = _clamped(
        "heartbeat_seconds", document.get("heartbeat_seconds"), constants.HEARTBEAT_SECONDS
    )
    jitter, jitter_clamp = _clamped(
        "heartbeat_jitter_pct",
        document.get("heartbeat_jitter_pct"),
        constants.HEARTBEAT_JITTER_PCT,
    )
    clamps = tuple(record for record in (seconds_clamp, jitter_clamp) if record is not None)

    for name, requested, applied in clamps:
        # Never silent. An operator who set 5 seconds, sees 30, and has nothing
        # to explain it is the debugging trap this exists to avoid.
        log.warning(
            "clamped a scheduling hint from the server into range",
            extra={
                "event_type": "settings_clamped",
                "setting": name,
                "requested": requested,
                "applied": applied,
            },
        )

    policies = document.get("available_policies")
    available = (
        tuple(entry for entry in policies if isinstance(entry, dict))
        if isinstance(policies, list)
        else ()
    )

    server_time = document.get("server_time")
    return HeartbeatHints(
        heartbeat_seconds=seconds,
        heartbeat_jitter_pct=jitter,
        server_time=server_time if isinstance(server_time, str) else None,
        certificate_renew_after=_parse_timestamp(document.get("certificate_renew_after")),
        available_policies=available,
        clamped=clamps,
    )
