#!/usr/bin/env python3
"""Generate the cross-language policy signing test vector.

Why this exists
---------------
docs/02-policy-and-signing.md specifies SIG_INPUT in prose. Prose does not stop a
Python signer and a Go verifier from disagreeing about, say, whether the length
prefix is big-endian. This script emits a fixed vector that BOTH test suites run,
so the first time the two implementations disagree, a test fails instead of a
fleet of agents silently rejecting every policy.

No key material is committed
----------------------------
The Ed25519 signing key is derived deterministically from a documented ASCII
string, so the vector is reproducible in any language without a private key ever
appearing in the repository. This key is for tests only and has no authority over
any real device.

Usage:  .venv-tools/bin/python tools/make_policy_vectors.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / "schemas" / "examples"
TESTDATA = REPO / "testdata"

# The one and only source of the test key. Documented, reproducible, not a secret.
TEST_KEY_DERIVATION = "ubuntuguard/test-vector/policy-signing/v1"

DOMAIN_SEPARATOR = b"ubuntuguard/policy-envelope/v1"


def test_signing_key() -> Ed25519PrivateKey:
    """Derive the test-only signing key from a documented string.

    seed = SHA-256(TEST_KEY_DERIVATION ascii)  ->  32 bytes  ->  Ed25519 seed
    """
    seed = hashlib.sha256(TEST_KEY_DERIVATION.encode("ascii")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def lp(value: bytes) -> bytes:
    """Length-prefix: uint64 big-endian length, then the bytes.

    Without this, ("ab", "c") and ("a", "bc") hash identically, which is a
    forgery primitive rather than a style preference.
    """
    return struct.pack(">Q", len(value)) + value


def sig_input(
    *,
    policy_id: str,
    policy_version: int,
    policy_type: str,
    scope_kind: str,
    scope_id: str,
    issued_at: str,
    expires_at: str | None,
    key_id: str,
    payload: bytes,
) -> bytes:
    """Build SIG_INPUT exactly as docs/02-policy-and-signing.md specifies."""
    return (
        DOMAIN_SEPARATOR
        + lp(policy_id.encode("utf-8"))
        + lp(struct.pack(">Q", policy_version))
        + lp(policy_type.encode("utf-8"))
        + lp(scope_kind.encode("utf-8"))
        + lp(scope_id.encode("utf-8"))
        + lp(issued_at.encode("utf-8"))
        + lp((expires_at or "").encode("utf-8"))
        + lp(key_id.encode("utf-8"))
        + lp(payload)
    )


def key_id_for(public_key_bytes: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_key_bytes).hexdigest()[:16]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_envelope(
    payload_obj: dict,
    *,
    policy_id: str,
    policy_version: int,
    policy_type: str,
    scope_kind: str,
    scope_id: str,
    issued_at: str,
    expires_at: str | None,
) -> tuple[dict, dict]:
    """Serialize the payload ONCE, then treat it as opaque bytes forever after."""
    sk = test_signing_key()
    pk_bytes = sk.public_key().public_bytes_raw()
    kid = key_id_for(pk_bytes)

    # This single serialization is the authoritative byte string. Nothing
    # downstream re-serializes it; that is the entire point of payload_b64.
    payload_bytes = json.dumps(
        payload_obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True
    ).encode("utf-8")

    si = sig_input(
        policy_id=policy_id,
        policy_version=policy_version,
        policy_type=policy_type,
        scope_kind=scope_kind,
        scope_id=scope_id,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=kid,
        payload=payload_bytes,
    )
    signature = sk.sign(si)

    envelope = {
        "envelope_version": 1,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_type": policy_type,
        "scope": {"kind": scope_kind, "id": scope_id},
        "issued_at": issued_at,
        "expires_at": expires_at,
        "payload_b64": b64(payload_bytes),
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "signature": {"alg": "ed25519", "key_id": kid, "value_b64": b64(signature)},
    }

    debug = {
        "public_key_b64": b64(pk_bytes),
        "key_id": kid,
        "payload_len": len(payload_bytes),
        "sig_input_len": len(si),
        "sig_input_sha256": hashlib.sha256(si).hexdigest(),
        "signature_b64": b64(signature),
    }
    return envelope, debug


def main() -> None:
    policy_id = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    device_id = "9a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d"
    issued_at = "2026-10-29T10:00:00Z"

    payload = {
        "schema": "ubuntuguard.usb_control.v1",
        "mode": "allowlist_enforce",
        "protected_classes": ["mass_storage"],
        "always_allow_classes": ["hid", "hub", "audio", "video", "billboard", "network"],
        "allowlist": [
            {
                "entry_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "match": {
                    "vendor_id": "0781",
                    "product_id": "5583",
                    "serial": "4C530001120523117082",
                    "serial_match": "exact",
                },
                "label": "Finance team SanDisk Ultra Fit",
                "added_by": "it-admin",
                "added_at": "2026-10-20T09:15:00Z",
            }
        ],
        "exceptions": [],
        "reporting": {
            "report_allowed": True,
            "report_blocked": True,
            "report_present_at_start": True,
        },
    }

    envelope, debug = build_envelope(
        payload,
        policy_id=policy_id,
        policy_version=7,
        policy_type="usb_control",
        scope_kind="device",
        scope_id=device_id,
        issued_at=issued_at,
        expires_at=None,
    )

    EXAMPLES.joinpath("valid").mkdir(parents=True, exist_ok=True)
    EXAMPLES.joinpath("invalid").mkdir(parents=True, exist_ok=True)
    TESTDATA.mkdir(parents=True, exist_ok=True)

    # The signed envelope, as a schema example.
    _write_json(EXAMPLES / "valid" / "policy.envelope.usb_control.json", envelope)
    # The payload on its own, as a usb_control schema example.
    _write_json(EXAMPLES / "valid" / "policy.usb_control.allowlist.json", payload)

    # --- Negative vectors: these MUST fail signature verification ---------
    tampered_payload = dict(envelope)
    raw = base64.b64decode(envelope["payload_b64"])
    flipped = bytearray(raw)
    flipped[0] ^= 0x01  # flip one bit of the first byte
    tampered_payload = {
        **envelope,
        "payload_b64": b64(bytes(flipped)),
        "payload_sha256": hashlib.sha256(bytes(flipped)).hexdigest(),
    }

    bumped_version = {**envelope, "policy_version": 8}

    rescoped = {
        **envelope,
        "scope": {"kind": "device", "id": "00000000-0000-4000-8000-000000000000"},
    }

    vector = {
        "_comment": (
            "Cross-language policy signing vector. Both the Python server tests and "
            "the Go agent tests must reproduce signature_b64 from the derivation "
            "string and the envelope fields. Regenerate with "
            "tools/make_policy_vectors.py."
        ),
        "key_derivation": {
            "note": "No key bytes are committed. Recompute in any language.",
            "algorithm": "ed25519",
            "seed": "SHA-256(ascii(derivation_string))",
            "derivation_string": TEST_KEY_DERIVATION,
            "expected_public_key_b64": debug["public_key_b64"],
            "expected_key_id": debug["key_id"],
        },
        "sig_input_spec": {
            "domain_separator": DOMAIN_SEPARATOR.decode("ascii"),
            "length_prefix": "uint64 big-endian length || bytes",
            "field_order": [
                "policy_id",
                "policy_version (uint64 big-endian)",
                "policy_type",
                "scope.kind",
                "scope.id",
                "issued_at",
                "expires_at (empty string when null)",
                "key_id",
                "payload_bytes",
            ],
            "signature_algorithm": "pure Ed25519 (RFC 8032), not Ed25519ph",
        },
        "positive": {
            "envelope": envelope,
            "expected_payload_len": debug["payload_len"],
            "expected_sig_input_len": debug["sig_input_len"],
            "expected_sig_input_sha256": debug["sig_input_sha256"],
            "expected_signature_b64": debug["signature_b64"],
            "must_verify": True,
        },
        "negative": [
            {
                "name": "payload_bit_flipped",
                "why": "one bit of the payload changed; signature must not verify",
                "expected_reason_code": "signature_invalid",
                "envelope": tampered_payload,
                "must_verify": False,
            },
            {
                "name": "version_bumped_without_resigning",
                "why": "policy_version is inside SIG_INPUT, so replaying a payload "
                "under a higher version must fail",
                "expected_reason_code": "signature_invalid",
                "envelope": bumped_version,
                "must_verify": False,
            },
            {
                "name": "scope_swapped_to_another_device",
                "why": "scope is inside SIG_INPUT, so a policy signed for device A "
                "must not verify for device B",
                "expected_reason_code": "signature_invalid",
                "envelope": rescoped,
                "must_verify": False,
            },
        ],
    }
    _write_json(TESTDATA / "policy_vectors.json", vector)

    print(f"key_id            : {debug['key_id']}")
    print(f"public_key_b64    : {debug['public_key_b64']}")
    print(f"payload bytes     : {debug['payload_len']}")
    print(f"sig_input bytes   : {debug['sig_input_len']}")
    print(f"sig_input sha256  : {debug['sig_input_sha256']}")
    print(f"signature_b64     : {debug['signature_b64']}")
    print()
    print("wrote schemas/examples/valid/policy.envelope.usb_control.json")
    print("wrote schemas/examples/valid/policy.usb_control.allowlist.json")
    print("wrote testdata/policy_vectors.json")


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
