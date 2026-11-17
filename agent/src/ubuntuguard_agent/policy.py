"""Pulling a signed policy and handing it to the enforcer.

This is the last link in the chain the whole product rests on: a decision made
in the dashboard arrives here and becomes a rule the kernel enforces. The
sequence is fixed and the order is the point.

    heartbeat advertises versions
        -> is any of them newer than what we applied?
        -> pull the envelope over our own authenticated request
        -> verify the signature against keys pinned at enrollment
        -> parse the payload into typed intent
        -> hand it to the enforcer, which applies and reads back from the OS
        -> report what actually happened

Several properties are deliberate rather than incidental:

**Nothing is pushed.** The heartbeat only says which versions exist. The agent
decides whether it wants one and fetches it itself. There is no server
response anywhere in this flow that causes the agent to act on content the
server chose.

**Verify before parse.** `verify_envelope` runs on the raw envelope and
returns the payload bytes; only then is anything decoded. Parsing first would
mean a forged policy's contents had already been through our JSON decoder and
our validator before anyone checked who sent it.

**Downgrades are refused.** A version lower than the one already applied is
rejected. Without that, an attacker who can replay an old signed response --
and a signature stays valid forever -- could reinstate a permissive policy
that was legitimately signed last week.

**The applied version is recorded only after the enforcer confirms.** If it is
written before, a failed apply leaves the agent believing it is current and it
never retries.

**Reporting is best-effort and never changes what was applied.** A laptop that
cannot reach the server still enforces; it just has not told anyone yet. The
alternative -- treating a failed report as a failed apply -- would mean a
network problem silently disabling enforcement.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ubuntuguard_agent.config import AgentConfig
from ubuntuguard_agent.core.envelope import load_public_key_b64, verify_envelope
from ubuntuguard_agent.enforcer.client import EnforcerClient
from ubuntuguard_agent.enrollment import read_policy_keys
from ubuntuguard_agent.errors import (
    AgentError,
    PolicyVerificationError,
    TransportError,
)
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.logging_setup import get_logger

POLICY_TYPE_USB_CONTROL = "usb_control"

#: Device-plane paths. Under /devices/me/ because that is the nginx location
#: which verifies the client certificate; the subject is the caller's own
#: certificate, never a path parameter.
POLICY_PATH = "/api/v1/devices/me/policies/{policy_type}"
STATUS_PATH = "/api/v1/devices/me/policy-status"

#: Where the agent remembers what it has applied. Not authoritative about the
#: machine -- the OS is -- but it is what stops a re-apply on every heartbeat
#: and what makes a downgrade detectable.
APPLIED_STATE_FILENAME = "applied-policies.json"


class PolicySyncError(AgentError):
    """A policy could not be fetched, decoded or trusted.

    Rooted in `AgentError` like every other failure in this package, and named
    apart from `PolicyVerificationError`, which is specifically a signature or
    envelope failure. This one also covers a malformed response and a refused
    downgrade.
    """


@dataclasses.dataclass(frozen=True)
class AppliedRecord:
    """What this device last applied for one policy type."""

    policy_id: str
    policy_version: int
    status: str
    applied_at: str


def applied_state_path(config: AgentConfig) -> Path:
    return config.paths.state_dir / APPLIED_STATE_FILENAME


def read_applied_state(path: Path) -> dict[str, AppliedRecord]:
    """What has been applied, by policy type.

    A missing or unreadable file reads as "nothing applied" rather than
    raising. The consequence is a re-apply, which the enforcer makes
    idempotent; the alternative is an agent that refuses to work because of a
    bookkeeping file, which is the worse failure.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(document, dict):
        return {}

    out: dict[str, AppliedRecord] = {}
    for policy_type, entry in document.items():
        if not isinstance(entry, dict):
            continue
        try:
            out[str(policy_type)] = AppliedRecord(
                policy_id=str(entry["policy_id"]),
                policy_version=int(entry["policy_version"]),
                status=str(entry.get("status", "applied")),
                applied_at=str(entry.get("applied_at", "")),
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def write_applied_state(path: Path, state: dict[str, AppliedRecord]) -> None:
    document = {policy_type: dataclasses.asdict(record) for policy_type, record in state.items()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o640)


def trusted_keys(config: AgentConfig) -> dict[str, Ed25519PublicKey]:
    """The policy signing keys pinned at enrollment, by key id."""
    keys = read_policy_keys(config.paths.policy_keys_path)
    return {key.key_id: load_public_key_b64(key.public_key_b64) for key in keys}


def needs_update(advertised: dict[str, Any], applied: dict[str, AppliedRecord]) -> bool:
    """Whether an advertised policy is worth fetching.

    False when the same version has already been applied successfully. True
    when it is newer, when the id changed at the same version -- which means a
    different policy, so the version alone is not enough -- or when the last
    attempt did not end in `applied`, so a retry is due.
    """
    policy_type = str(advertised.get("policy_type", ""))
    record = applied.get(policy_type)
    if record is None:
        return True

    try:
        version = int(advertised.get("policy_version", 0))
    except (TypeError, ValueError):
        return False

    if version > record.policy_version:
        return True
    if str(advertised.get("policy_id", "")) != record.policy_id:
        return True
    return record.status != "applied"


def fetch_envelope(client: ServerClient, policy_type: str) -> dict[str, Any]:
    """Pull the signed envelope for one policy type."""
    response = client.get_json(POLICY_PATH.format(policy_type=policy_type))
    document = response.json()
    if not isinstance(document, dict):
        raise PolicySyncError("the policy response was not a JSON object")
    return document


def verify_and_parse(
    envelope: dict[str, Any],
    keys: dict[str, Ed25519PublicKey],
    *,
    applied: AppliedRecord | None,
) -> tuple[dict[str, Any], int, str]:
    """Verify the envelope, refuse a downgrade, and return the payload.

    Returns (payload, version, policy_id). The signature is checked before the
    payload is decoded, and the version is checked before the payload is used.
    """
    payload_bytes = verify_envelope(envelope, keys)

    try:
        version = int(envelope["policy_version"])
        policy_id = str(envelope["policy_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicySyncError(f"the envelope has no usable version or id: {exc}") from exc

    if applied is not None and version < applied.policy_version:
        # A signature does not expire, so an old signed response stays
        # verifiable forever. Refusing a lower version is what stops one being
        # replayed to reinstate a policy that was permissive last week.
        raise PolicySyncError(
            f"refusing policy version {version}: a later version "
            f"({applied.policy_version}) has already been applied, and a "
            f"signed response from the past stays verifiable"
        )

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        raise PolicySyncError(f"the policy payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PolicySyncError("the policy payload is not a JSON object")
    return payload, version, policy_id


def build_enforcer_client(config: AgentConfig) -> EnforcerClient:
    """A client for the root enforcer, over its Unix socket.

    This agent does **not** apply the policy itself, and the distinction is
    the privilege split the threat model is built on. Writing
    /etc/usbguard/rules.conf and restarting the daemon needs root; this
    process runs as the unprivileged `ubuntuguard` user. If it applied policy
    directly it would have to run as root, and a compromise of the component
    that talks to the network would be a compromise of root.

    So it asks. `enforcerd` holds the privilege, accepts four typed
    operations and nothing else, and checks with SO_PEERCRED that the caller
    is this user before reading the request.
    """
    return EnforcerClient(socket_path=str(config.paths.enforcer_socket_path))


def apply_usb_control(
    client: EnforcerClient,
    payload: dict[str, Any],
    *,
    policy_version: int,
) -> dict[str, Any]:
    """Ask the root enforcer to apply the policy; return its response.

    The enforcer re-validates the whole payload itself. That is not redundant
    with the server's validation or with this agent's: it is the process that
    would actually deauthorise the keyboard of the person holding the laptop,
    and it takes nobody's word for the policy being safe.
    """
    return client.set_policy(payload, policy_version=policy_version)


def report_status(
    client: ServerClient,
    *,
    policy_id: str,
    status: str,
    reason_code: str | None,
    detail: str | None,
    verified_state: dict[str, Any] | None,
    logger: logging.Logger,
) -> bool:
    """Tell the server what happened. Best-effort by design.

    A failure here is logged and swallowed. The policy is already applied or
    already refused on this machine, and nothing about the report changes
    that. Raising would make a network problem look like an enforcement
    problem, and worse, could unwind an apply that actually succeeded.
    """
    body: dict[str, Any] = {
        "policy_id": policy_id,
        "status": status,
        "reason_code": reason_code,
        "detail": (detail or "")[:512] or None,
        "verified_state": verified_state,
    }
    try:
        client.post_json(STATUS_PATH, body)
    except (TransportError, Exception) as exc:  # noqa: BLE001 - see docstring
        logger.warning(
            "could not report policy status",
            extra={"policy_id": policy_id, "status": status, "error": str(exc)},
        )
        return False
    return True


def _trimmed_state(response: dict[str, Any]) -> dict[str, Any] | None:
    """The readback worth sending, without the bulk.

    `loaded_rules` and the daemon parameters are the evidence an operator
    needs. The full device list is not: it changes every time someone plugs
    anything in, it is reported through the event channel already, and sending
    it here would put device serials in a second place for no gain.
    """
    state = response.get("state")
    if not isinstance(state, dict):
        return None
    keep = (
        "rules_fingerprint",
        "loaded_rule_count",
        "loaded_rules",
        "daemon_params",
        "daemon_active",
        "daemon_conf_readable",
        "ipc_exposure",
        "enforcement_bypassable_without_root",
    )
    trimmed = {key: state[key] for key in keep if key in state}
    for key in ("foreign_rules", "ipc_exposure"):
        if key in response:
            trimmed[key] = response[key]
    return trimmed or None


def sync_policies(
    config: AgentConfig,
    client: ServerClient,
    advertised: Sequence[dict[str, Any]],
    *,
    logger: logging.Logger | None = None,
    enforcer: EnforcerClient | None = None,
) -> list[str]:
    """Apply any advertised policy this device does not already have.

    Returns a short description of each action taken, for the caller to log.
    Never raises for one policy's sake: a failure is recorded, reported and
    moved past, because an `agent_settings` problem must not stop a
    `usb_control` policy being applied.
    """
    log = logger or get_logger(__name__)
    actions: list[str] = []

    if not advertised:
        return actions

    state_path = applied_state_path(config)
    applied = read_applied_state(state_path)

    pending = [item for item in advertised if needs_update(item, applied)]
    if not pending:
        return actions

    try:
        keys = trusted_keys(config)
    except Exception as exc:  # noqa: BLE001 - reported, not fatal to the loop
        log.error("cannot load pinned policy keys", extra={"error": str(exc)})
        return [f"policy keys unavailable: {exc}"]

    for item in pending:
        policy_type = str(item.get("policy_type", ""))
        if policy_type != POLICY_TYPE_USB_CONTROL:
            # agent_settings lands with the settings engine. Skipped by name
            # rather than attempted, so an unknown type is visible in the log
            # instead of producing a confusing enforcer error.
            log.info("skipping policy type with no handler", extra={"policy_type": policy_type})
            continue

        try:
            envelope = fetch_envelope(client, policy_type)
            payload, version, policy_id = verify_and_parse(
                envelope, keys, applied=applied.get(policy_type)
            )
        except (PolicyVerificationError, PolicySyncError, TransportError) as exc:
            log.error(
                "refused a policy before applying it",
                extra={"policy_type": policy_type, "error": str(exc)},
            )
            actions.append(f"{policy_type}: refused ({exc})")
            continue

        active = enforcer or build_enforcer_client(config)
        response = apply_usb_control(active, payload, policy_version=version)
        status = str(response.get("status", "failed"))
        reason = response.get("reason_code")
        detail = response.get("message")

        # Written only after the enforcer has reported, and only as what it
        # reported. Recording `applied` optimistically would leave a failed
        # host believing it was current and never retrying.
        applied[policy_type] = AppliedRecord(
            policy_id=policy_id,
            policy_version=version,
            status=status,
            applied_at=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        )
        try:
            write_applied_state(state_path, applied)
        except OSError as exc:
            # Not fatal: the policy is applied. The cost is a re-apply next
            # heartbeat, which is idempotent.
            log.warning("could not record applied policy", extra={"error": str(exc)})

        log.info(
            "policy applied" if status == "applied" else "policy not applied",
            extra={
                "policy_type": policy_type,
                "policy_version": version,
                "status": status,
                "reason_code": reason,
            },
        )
        actions.append(f"{policy_type} v{version}: {status}")

        report_status(
            client,
            policy_id=policy_id,
            status=status if status != "ok" else "applied",
            reason_code=str(reason) if reason else None,
            detail=str(detail) if detail else None,
            verified_state=_trimmed_state(response),
            logger=log,
        )

    return actions
