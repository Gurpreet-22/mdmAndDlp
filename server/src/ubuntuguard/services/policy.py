"""Building and signing `usb_control` policies.

This is the layer between an administrator's intent -- "block storage on this
laptop, except these two sticks" -- and the signed bytes a device will accept.
It exists separately from the router because the ordering below is
security-relevant and should not be buried in request handling.

The order is: build the payload, serialize it **once**, sign those exact bytes,
then store the same bytes. Nothing re-serializes in between. A payload that is
re-encoded after signing is a payload whose signature no longer covers what the
device receives, and that failure is silent until a device rejects it.

Two defences are applied here rather than left to the schema:

`always_allow_classes` must contain `hid` and `hub`. The JSON Schema requires
it too, and the endpoint enforcer re-checks it a third time. Three places is
not redundancy worth removing: this one stops a bad policy being *created*, so
it never reaches a laptop at all, and the endpoint one stops a policy from any
other source removing the keyboard of the person holding the machine.

Exceptions are bounded to `USB_EXCEPTION_MAX_SECONDS`. JSON Schema cannot
express "expires_at minus created_at is at most 24 hours", so it is checked
here on creation and again on the endpoint before being honoured.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.orm import Session

from ubuntuguard import repositories
from ubuntuguard.constants import USB_EXCEPTION_MAX_SECONDS
from ubuntuguard.models import Policy
from ubuntuguard.services.policy_signing import (
    ENVELOPE_VERSION,
    PolicySigner,
    format_rfc3339,
    serialize_payload,
)

USB_CONTROL_SCHEMA_ID = "ubuntuguard.usb_control.v1"
POLICY_TYPE_USB_CONTROL = "usb_control"

#: Classes that may be enforced against. Mirrors the schema's enum.
PROTECTED_CLASS_NAMES = ("mass_storage", "image")

#: Classes that may be exempted. Mirrors the schema's enum.
ALWAYS_ALLOW_CLASS_NAMES = (
    "hid",
    "hub",
    "audio",
    "video",
    "printer",
    "network",
    "smartcard",
    "wireless",
    "billboard",
    "cdc",
    "physical",
    "vendor_specific",
)

#: Removing either locks the user out of their own machine: `hid` is the
#: keyboard and mouse, `hub` is everything behind a dock.
REQUIRED_ALWAYS_ALLOW = ("hid", "hub")

#: What a new deployment should get before anyone has built an allowlist.
#: `image` is deliberately absent from the protected set: a phone in MTP mode
#: presents class 06, and blocking it by default breaks phone charging for
#: everyone on day one. It is available, off by default, as the schema says.
DEFAULT_PROTECTED_CLASSES = ("mass_storage",)
DEFAULT_ALWAYS_ALLOW_CLASSES = (
    "hid",
    "hub",
    "audio",
    "video",
    "cdc",
    "network",
    "smartcard",
    "vendor_specific",
)


class PolicyError(Exception):
    """A policy cannot be built as asked. The message is operator-facing."""


def _validate_classes(
    protected: Sequence[str], always_allow: Sequence[str]
) -> None:
    unknown_protected = [c for c in protected if c not in PROTECTED_CLASS_NAMES]
    if unknown_protected:
        raise PolicyError(
            f"unknown protected class(es): {', '.join(unknown_protected)}; "
            f"known: {', '.join(PROTECTED_CLASS_NAMES)}"
        )
    if not protected:
        raise PolicyError("protected_classes must name at least one class")

    unknown_allow = [c for c in always_allow if c not in ALWAYS_ALLOW_CLASS_NAMES]
    if unknown_allow:
        raise PolicyError(
            f"unknown always-allow class(es): {', '.join(unknown_allow)}; "
            f"known: {', '.join(ALWAYS_ALLOW_CLASS_NAMES)}"
        )

    missing = [c for c in REQUIRED_ALWAYS_ALLOW if c not in always_allow]
    if missing:
        raise PolicyError(
            f"always_allow_classes must include {', '.join(missing)}: without "
            f"them a policy can deauthorise the keyboard and lock the user out "
            f"of their own machine"
        )

    overlap = sorted(set(protected) & set(always_allow))
    if overlap:
        raise PolicyError(
            f"class(es) {', '.join(overlap)} appear in both protected_classes "
            f"and always_allow_classes; the intent is ambiguous"
        )


def _validate_exceptions(exceptions: Sequence[dict[str, Any]]) -> None:
    for index, exc in enumerate(exceptions):
        created = exc.get("created_at")
        expires = exc.get("expires_at")
        if not isinstance(created, str) or not isinstance(expires, str):
            raise PolicyError(f"exceptions[{index}]: created_at and expires_at are required")
        try:
            created_dt = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
            expires_dt = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError as err:
            raise PolicyError(f"exceptions[{index}]: {err}") from err
        if expires_dt <= created_dt:
            raise PolicyError(f"exceptions[{index}]: expires_at must be after created_at")
        span = (expires_dt - created_dt).total_seconds()
        if span > USB_EXCEPTION_MAX_SECONDS:
            raise PolicyError(
                f"exceptions[{index}]: spans {span / 3600:.1f} h, over the "
                f"{USB_EXCEPTION_MAX_SECONDS // 3600} h maximum. An exception "
                f"nobody revisits is indistinguishable from a permanent hole"
            )


def build_usb_control_payload(
    *,
    mode: str,
    protected_classes: Sequence[str] | None = None,
    always_allow_classes: Sequence[str] | None = None,
    allowlist: Sequence[dict[str, Any]] | None = None,
    exceptions: Sequence[dict[str, Any]] | None = None,
    report_allowed: bool = True,
    report_blocked: bool = True,
    report_present_at_start: bool = True,
    apply_to_present_devices: bool = True,
) -> dict[str, Any]:
    """Assemble a payload conforming to `policy.usb_control.v1`.

    Key order is irrelevant: `serialize_payload` sorts keys, and the signature
    covers its output rather than this dict.
    """
    protected = tuple(protected_classes or DEFAULT_PROTECTED_CLASSES)
    always = tuple(always_allow_classes or DEFAULT_ALWAYS_ALLOW_CLASSES)
    _validate_classes(protected, always)

    entries = [dict(e) for e in (allowlist or ())]
    grants = [dict(e) for e in (exceptions or ())]
    _validate_exceptions(grants)

    return {
        "schema": USB_CONTROL_SCHEMA_ID,
        "mode": mode,
        "protected_classes": list(protected),
        "always_allow_classes": list(always),
        "allowlist": entries,
        "exceptions": grants,
        "reporting": {
            "report_allowed": report_allowed,
            "report_blocked": report_blocked,
            "report_present_at_start": report_present_at_start,
        },
        "enforcement": {"apply_to_present_devices": apply_to_present_devices},
    }


def issue_policy(
    session: Session,
    *,
    signer: PolicySigner,
    policy_type: str,
    payload: dict[str, Any],
    scope_kind: str,
    scope_id: str,
    created_by: uuid.UUID,
    issued_at: dt.datetime | None = None,
    expires_at: dt.datetime | None = None,
) -> tuple[Policy, dict[str, Any]]:
    """Version, sign and store a policy. Returns the row and the envelope.

    The id is minted here because the signature covers it: the envelope and the
    stored row must carry the same one, so it cannot be left to the database
    default.
    """
    issued_at = issued_at or dt.datetime.now(dt.UTC)
    policy_id = uuid.uuid4()

    version = repositories.next_policy_version(
        session, policy_type=policy_type, scope_kind=scope_kind, scope_id=scope_id
    )

    # Serialized once. These bytes are what gets signed, stored and sent.
    payload_bytes = serialize_payload(payload)

    envelope = signer.sign_envelope(
        policy_id=str(policy_id),
        policy_version=version,
        policy_type=policy_type,
        scope_kind=scope_kind,
        scope_id=scope_id,
        issued_at=issued_at,
        payload=payload_bytes,
        expires_at=expires_at,
    )

    row = repositories.create_policy(
        session,
        policy_id=policy_id,
        policy_type=policy_type,
        version=version,
        scope_kind=scope_kind,
        scope_id=scope_id,
        payload=payload_bytes,
        payload_sha256=envelope["payload_sha256"],
        signature_b64=envelope["signature"]["value_b64"],
        signing_key_id=envelope["signature"]["key_id"],
        issued_at=issued_at,
        issued_at_text=envelope["issued_at"],
        expires_at=expires_at,
        expires_at_text=envelope["expires_at"],
        created_by=created_by,
    )
    return row, envelope


def envelope_for(policy: Policy) -> dict[str, Any]:
    """Rebuild the envelope for a stored policy.

    Reassembled from the stored columns rather than re-signed: the signature
    and the payload bytes both come straight out of the row, so what a device
    receives on a later request is byte-identical to what was signed. Re-signing
    here would produce a different `issued_at` and a policy the agent would
    treat as new on every poll.
    """
    return {
        "envelope_version": ENVELOPE_VERSION,
        "policy_id": str(policy.id),
        "policy_version": policy.version,
        "policy_type": policy.policy_type,
        "scope": {"kind": policy.scope_kind, "id": policy.scope_id},
        "issued_at": policy.issued_at_text,
        "expires_at": policy.expires_at_text,
        "payload_b64": base64.b64encode(policy.payload).decode("ascii"),
        "payload_sha256": policy.payload_sha256,
        "signature": {
            "alg": "ed25519",
            "key_id": policy.signing_key_id,
            "value_b64": policy.signature_b64,
        },
    }


def decoded_payload(policy: Policy) -> dict[str, Any]:
    """The payload as a dict, for display in the dashboard only.

    Never used to re-sign or re-send. The authoritative form is always
    `policy.payload`, the bytes the signature covers.
    """
    parsed: dict[str, Any] = json.loads(policy.payload.decode("utf-8"))
    return parsed


def summarise(policy: Policy) -> str:
    """A one-line description, for audit detail and the dashboard."""
    payload = decoded_payload(policy)
    mode = payload.get("mode", "?")
    allowlist = payload.get("allowlist") or []
    exceptions = payload.get("exceptions") or []
    parts = [f"mode={mode}", f"v{policy.version}"]
    if allowlist:
        parts.append(f"{len(allowlist)} allowed device(s)")
    if exceptions:
        parts.append(f"{len(exceptions)} exception(s)")
    return ", ".join(parts)


def format_timestamp(value: dt.datetime) -> str:
    """RFC 3339, matching what goes into the signing input."""
    return format_rfc3339(value)
