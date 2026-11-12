"""Key material loading.

Four separate pieces of key material, never the same file and never in the
repository: the policy signing key (Ed25519), the internal CA key (EC P-256),
the TLS server key (nginx's business), and the database credentials (environment).

Loaded once at startup and held in memory. Reading them per request would mean
a filesystem error surfacing as an authentication failure, and would make the
permission check a per-request cost for no benefit.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ubuntuguard.config import Settings
from ubuntuguard.services.ca import CertificateAuthority, generate_ca, load_ca, save_ca
from ubuntuguard.services.policy_signing import PolicySigner, key_id_for


@dataclass(frozen=True, slots=True)
class KeyBundle:
    """Everything the server needs to sign policies and issue certificates."""

    ca: CertificateAuthority
    signer: PolicySigner

    def policy_public_keys_payload(self) -> list[dict[str, str]]:
        return [
            {
                "key_id": self.signer.key_id,
                "alg": "ed25519",
                "public_key_b64": base64.b64encode(
                    self.signer.public_key.public_bytes_raw()
                ).decode("ascii"),
            }
        ]


def generate_policy_signing_key(path: Path) -> str:
    """Create an Ed25519 signing key at mode 0600. Returns its key_id.

    Opened with `os.open(..., 0o600)` rather than written and then chmod'ed: a
    chmod leaves a window in which the private key exists and is readable.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, pem)
    finally:
        os.close(descriptor)
    return key_id_for(key.public_key())


def ensure_keys(settings: Settings, *, create_missing: bool = False) -> KeyBundle:
    """Load the CA and the policy signing key, optionally creating them.

    `create_missing` is for `ubuntuguard init-keys` and local development only.
    A production start loads what is there and fails if anything is absent,
    because silently generating a fresh CA would orphan every enrolled device
    and silently generating a signing key would invalidate every policy.
    """
    ca_key_path = settings.ca_key_path or Path("var/ca.key")
    ca_cert_path = settings.ca_cert_path or Path("var/ca.crt")
    signing_key_path = settings.policy_signing_key_path or Path("var/policy-signing.key")

    if create_missing and not ca_key_path.exists():
        save_ca(generate_ca(), ca_key_path, ca_cert_path)
    if create_missing and not signing_key_path.exists():
        generate_policy_signing_key(signing_key_path)

    missing = [
        str(path) for path in (ca_key_path, ca_cert_path, signing_key_path) if not path.exists()
    ]
    if missing:
        raise RuntimeError(
            "missing key material: " + ", ".join(missing) + ". Generate it with: "
            "python -m ubuntuguard.cli init-keys"
        )

    return KeyBundle(
        ca=load_ca(ca_key_path, ca_cert_path),
        signer=PolicySigner.from_file(signing_key_path),
    )
