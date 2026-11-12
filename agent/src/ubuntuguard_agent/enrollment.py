"""Enrollment: exchanging a one-time token and a CSR for a device identity.

This is the agent's entire trust bootstrap, so the order of operations below is
load-bearing rather than stylistic. Read `docs/01-api-contract.md` §4.1 for the
wire contract; this module's job is the local half.

The sequence, and why each step is where it is:

  1. Read the token from a file or stdin, and register it with the log
     redaction registry **before anything can be logged**. Never from argv -
     see `read_token_from_file`.
  2. Create the state and pki directories at their required modes.
  3. Generate the keypair and CSR, and **persist both before the first POST**.
     This is the step that makes a retry survivable; `ensure_device_keypair`
     explains why at length.
  4. Collect host facts and build the request.
  5. POST, retrying transport failures on backoff with the identical body.
  6. Verify the issued certificate against the keypair and the returned CA,
     then install it.
  7. Pin the policy public keys.

What this module never does: send the private key, log the token, log a
certificate, take the token from the command line, or write anything to disk
before the response has been verified.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import stat
import sys
import time
from pathlib import Path
from typing import Any

from ubuntuguard_agent import __version__
from ubuntuguard_agent.config import AgentConfig
from ubuntuguard_agent.core.scheduler import Backoff
from ubuntuguard_agent.errors import (
    ConfigError,
    EnrollmentError,
    HttpStatusError,
    TlsVerificationError,
    TransportError,
)
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.identity import (
    CertificateSummary,
    ensure_device_keypair,
    ensure_runtime_paths,
    install_certificate,
    is_enrolled,
)
from ubuntuguard_agent.logging_setup import SECRETS, get_logger
from ubuntuguard_agent.osadapter import OsAdapter, detect_adapter

#: The enroll path. Relative, so `ServerClient` resolves it against the base
#: URL and an absolute value can never redirect the request elsewhere.
ENROLL_PATH = "api/v1/enroll"

#: Bounds from `server/src/ubuntuguard/schemas.py:EnrollRequest`. Checked
#: locally so a mistyped token produces a message naming the problem instead of
#: a 422 the operator has to decode.
MIN_TOKEN_LENGTH = 20
MAX_TOKEN_LENGTH = 128

#: How many times to send the request before giving up.
#:
#: Four, with the backoff below, spans roughly a minute - comfortably inside
#: the server's 60-second idempotency window for the first few attempts, so a
#: retry that succeeds gets the original certificate back rather than a second
#: one. Beyond that window the token is spent and no amount of retrying helps,
#: which is why this is small rather than generous.
DEFAULT_MAX_ATTEMPTS = 4

#: Seconds. Deliberately tighter than the service loop's backoff: an operator
#: is watching this command run.
RETRY_INITIAL_SECONDS = 2.0
RETRY_MAX_SECONDS = 20.0


@dataclasses.dataclass(frozen=True)
class PolicyPublicKey:
    """A pinned Ed25519 policy-signing key from the enrollment response."""

    key_id: str
    alg: str
    public_key_b64: str


@dataclasses.dataclass(frozen=True)
class EnrollmentResult:
    device_id: str
    certificate: CertificateSummary
    clone_suspected: bool
    policy_public_keys: tuple[PolicyPublicKey, ...]
    #: False when this enrollment generated a fresh keypair, True when it
    #: reused one already on disk. A reused keypair after a failed attempt is
    #: the mechanism that makes the server's idempotency cache work, so it is
    #: reported rather than inferred.
    reused_keypair: bool
    attempts: int


# --------------------------------------------------------------------------- #
# Reading the token
# --------------------------------------------------------------------------- #


def _accept_token(value: str) -> str:
    """Validate and register a token. The only way a token enters this module.

    Registered with `SECRETS` **before** any validation failure can raise,
    because a validation message could otherwise end up in a traceback that a
    caller logs. Registration is idempotent and `SecretRegistry.register`
    ignores anything shorter than 8 characters, so a truncated token that is
    too short to register is also too short to be a credential.
    """
    token = value.strip()
    SECRETS.register(token)

    if not token:
        raise EnrollmentError("the enrollment token is empty")
    if len(token) < MIN_TOKEN_LENGTH or len(token) > MAX_TOKEN_LENGTH:
        # The length is named, the value is not. A length is not a secret and
        # it is the single most useful thing for diagnosing a copy-paste error.
        raise EnrollmentError(
            f"the enrollment token is {len(token)} characters; the server accepts "
            f"{MIN_TOKEN_LENGTH} to {MAX_TOKEN_LENGTH}. Was it truncated on the "
            "way out of the dashboard?"
        )
    if any(character.isspace() for character in token):
        raise EnrollmentError(
            "the enrollment token contains whitespace. If it was pasted from a "
            "terminal it may have been wrapped across lines."
        )
    return token


def read_token_from_file(path: Path) -> str:
    """Read a token from a file, refusing one other users can read.

    **Why a file and not an argument.** `/proc/<pid>/cmdline` is world-readable
    on Linux, so anything in argv is visible to every user on the machine for
    as long as the process lives, and to anything sampling `ps` afterwards. A
    single-use enrollment token in argv is a credential published to the whole
    system. The `enroll` subcommand therefore has no `--token` option at all -
    not one that warns, not one that is deprecated. An option that rejects the
    value still means the operator typed it, and by then `ps` has already seen
    it.

    The permission check is the same rule the private key gets
    (`identity.assert_private_file`) and raises rather than fixing the mode: a
    token any local user could read may already have been read, and quietly
    tightening the permissions would hide that from the person deciding whether
    to revoke it.
    """
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise EnrollmentError(f"could not read the token file {path}: {exc}") from exc

    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise EnrollmentError(
            f"{path} is readable by group or others (mode {stat.S_IMODE(mode):04o}). "
            "An enrollment token is a single-use credential; store it at 0600:\n"
            f"    chmod 600 {path}\n"
            "If another user could already read it, revoke the token in the "
            "dashboard and issue a new one."
        )

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EnrollmentError(f"could not read the token file {path}: {exc}") from exc
    return _accept_token(raw)


def read_token_from_stdin(stream: Any = None) -> str:
    """Read a token from standard input.

    The other safe channel, and the one that composes:

        pass show ubuntuguard/token | ubuntuguard-agent enroll --token-stdin

    A pipe is not visible in `ps` and leaves nothing on disk.
    """
    source = stream if stream is not None else sys.stdin
    try:
        raw = source.read()
    except OSError as exc:
        raise EnrollmentError(f"could not read the token from stdin: {exc}") from exc
    if not isinstance(raw, str):  # pragma: no cover - stdin is text mode
        raw = str(raw)
    return _accept_token(raw)


# --------------------------------------------------------------------------- #
# Building the request
# --------------------------------------------------------------------------- #


def build_enroll_payload(
    config: AgentConfig,
    adapter: OsAdapter,
    *,
    token: str,
    csr_pem: bytes,
) -> dict[str, Any]:
    """Assemble the `EnrollRequest` body.

    Transcribed from `server/src/ubuntuguard/schemas.py:EnrollRequest`, not
    from the design document - an earlier draft of `docs/01-api-contract.md`
    described a `public_key_fingerprint` field and nested `hostname` inside
    `hardware_fingerprint`, and because every request model sets
    `extra="forbid"`, sending either would be a 422 rather than a warning. The
    document has since been corrected; `tools/demo_api.py:enroll_payload` is
    the other reference, and it is one that has actually been run against the
    server.

    Optional fields are OMITTED when unknown rather than sent as null. Both are
    accepted, and omission is the one that keeps "we did not collect this" and
    "we collected this and it was empty" distinguishable on the wire.
    """
    facts = adapter.host_facts()

    if not facts.hostname:
        # `EnrollRequest.hostname` has min_length=1, so an empty string is a
        # 422. Refused here with an explanation rather than substituted with a
        # placeholder: a fleet list containing three laptops called
        # "unknown-host" is worse than an enrollment that stopped and said why.
        raise EnrollmentError(
            "this host has no hostname, and the server requires one at enrollment. "
            "Set one with `hostnamectl set-hostname <name>` and try again."
        )

    operating_system: dict[str, Any] = {
        "id": facts.os.id,
        "version_id": facts.os.version_id,
        "kernel": facts.kernel,
    }
    if facts.os.pretty_name:
        operating_system["pretty_name"] = facts.os.pretty_name

    fingerprint: dict[str, Any] = {}
    if facts.machine_id_hash:
        fingerprint["machine_id_hash"] = facts.machine_id_hash
    if facts.dmi_product_uuid_hash:
        fingerprint["dmi_product_uuid_hash"] = facts.dmi_product_uuid_hash
    if facts.mac_hashes:
        fingerprint["mac_hashes"] = list(facts.mac_hashes)
    if facts.virtualization:
        fingerprint["virtualization"] = facts.virtualization

    payload: dict[str, Any] = {
        "enrollment_token": token,
        "csr_pem": csr_pem.decode("ascii"),
        "hostname": facts.hostname,
        "agent_version": __version__,
        "arch": facts.arch,
        "os": operating_system,
        "hardware_fingerprint": fingerprint,
        # Reported honestly. False means the dev-only environment overrides are
        # active, and the dashboard flags such a device because its effective
        # settings may not match policy.
        "release_build": config.release_build,
    }
    if facts.primary_adapter_ip:
        payload["primary_adapter_ip"] = facts.primary_adapter_ip
    return payload


# --------------------------------------------------------------------------- #
# Reading the response
# --------------------------------------------------------------------------- #


def _require_string(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise EnrollmentError(
            f"the enrollment response is missing a usable {key!r}; got {type(value).__name__}"
        )
    return value


def _parse_policy_keys(document: dict[str, Any]) -> tuple[PolicyPublicKey, ...]:
    """Read the pinned policy keys, rejecting anything malformed.

    Strict rather than lenient. These are the trust anchor for every policy the
    agent will ever verify, so a response with a half-formed key entry is one
    to refuse at enrollment, when an operator is watching, instead of
    discovering in Phase 6 when a policy silently fails to verify.
    """
    raw = document.get("policy_public_keys")
    if not isinstance(raw, list):
        raise EnrollmentError("the enrollment response has no policy_public_keys list")

    keys: list[PolicyPublicKey] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise EnrollmentError("a policy_public_keys entry is not an object")
        key_id = entry.get("key_id")
        alg = entry.get("alg")
        material = entry.get("public_key_b64")
        if not (
            isinstance(key_id, str)
            and key_id
            and isinstance(alg, str)
            and isinstance(material, str)
            and material
        ):
            raise EnrollmentError("a policy_public_keys entry is missing a field")
        if alg != "ed25519":
            # The envelope verifier only implements Ed25519
            # (`core/envelope.py`), so a key it cannot use is a key it must not
            # record as trusted.
            raise EnrollmentError(
                f"policy key {key_id!r} uses algorithm {alg!r}; this build verifies only ed25519"
            )
        keys.append(PolicyPublicKey(key_id=key_id, alg=alg, public_key_b64=material))

    if not keys:
        raise EnrollmentError(
            "the enrollment response contained no policy signing keys, so no policy "
            "could ever be verified. Has the server run `ubuntuguard.cli init-keys`?"
        )
    return tuple(keys)


def write_policy_keys(path: Path, keys: tuple[PolicyPublicKey, ...]) -> None:
    """Persist the pinned policy keys as JSON, sorted by key id.

    Sorted so the file is byte-stable across re-enrollments with the same key
    set, which makes a genuine change visible in a diff rather than lost in
    reordering.
    """
    document = {
        "pinned_at_enrollment": True,
        "keys": [dataclasses.asdict(key) for key in sorted(keys, key=lambda item: item.key_id)],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o644)


# --------------------------------------------------------------------------- #
# The sequence
# --------------------------------------------------------------------------- #


def _post_with_retries(
    client: ServerClient,
    payload: dict[str, Any],
    *,
    max_attempts: int,
    logger: logging.Logger,
    sleep: Any = time.sleep,
) -> tuple[dict[str, Any], int]:
    """POST the enrollment request, retrying only what retrying can fix.

    **The body is identical on every attempt.** That is the whole point: the
    server caches its response against `(token_hash, csr_public_key_fingerprint)`
    for 60 seconds, so a retry after a response was lost in transit returns the
    original certificate. Rebuilding the payload between attempts would risk a
    different CSR and turn a recoverable network blip into a spent token.

    What is retried, and what is not:

    - `TransportError` - connection refused, DNS failure, timeout. Retried:
      a laptop that just woke up is the normal case.
    - `TlsVerificationError` - NOT retried. It means the CA bundle is wrong or
      something is intercepting the connection, and neither improves by asking
      again. Retrying would also mean repeatedly offering the token to whatever
      is answering.
    - `429` and `5xx` - retried. The server is saying "not now".
    - Any other `4xx` - NOT retried. An invalid token does not become valid,
      and backing off for a minute before telling the operator that wastes the
      only thing they are waiting for.
    """
    backoff = Backoff(RETRY_INITIAL_SECONDS, RETRY_MAX_SECONDS)
    last: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = client.post_json(ENROLL_PATH, payload)
        except TlsVerificationError:
            raise
        except HttpStatusError as exc:
            if not exc.retryable or attempt == max_attempts:
                raise _enrollment_error_for(exc) from exc
            last = exc
        except TransportError as exc:
            if attempt == max_attempts:
                raise EnrollmentError(
                    f"could not reach the server after {attempt} attempts: {exc}"
                ) from exc
            last = exc
        else:
            document = response.json()
            if not isinstance(document, dict):
                raise EnrollmentError(
                    "the enrollment response was not a JSON object; is this the UbuntuGuard API?"
                )
            return document, attempt

        delay = backoff.next_delay()
        logger.warning(
            "enrollment attempt failed; retrying",
            extra={
                "attempt": attempt,
                "of": max_attempts,
                "retry_in_seconds": round(delay, 1),
                "error": str(last),
            },
        )
        sleep(delay)

    # Unreachable: the loop either returns or raises on the final attempt.
    raise EnrollmentError(f"enrollment failed after {max_attempts} attempts: {last}")


def _enrollment_error_for(exc: HttpStatusError) -> EnrollmentError:
    """Turn a refusal into something an operator can act on.

    The server deliberately returns a vague `detail` on authentication paths -
    distinguishing "unknown token" from "already consumed" would tell an
    attacker which tokens once existed - so the advice here comes from the
    stable `code`, not from the server's prose.
    """
    if exc.status == 401:
        return EnrollmentError(
            "the server rejected the enrollment token. It is single-use and short "
            "lived, so it has most likely expired, been revoked, or already been "
            "spent - including by an earlier run of this command that got further "
            "than it appeared to.\n"
            "  Check the device list in the dashboard first: if this laptop is "
            "already there as active, it enrolled and no further action is needed.\n"
            "  Otherwise issue a new token. Note that the existing keypair in "
            "pki/ will be reused, which is correct."
        )
    if exc.status == 400:
        return EnrollmentError(
            f"the server rejected the certificate request ({exc.code or 'csr_invalid'}). "
            "This is an agent bug rather than an operator error; the CSR is in "
            "pki/device.csr and is worth attaching to a report."
        )
    if exc.status == 422:
        return EnrollmentError(
            "the server rejected the shape of the enrollment request. The agent and "
            "server contracts have drifted - compare `build_enroll_payload` against "
            "`EnrollRequest` in the server's schemas.py."
        )
    return EnrollmentError(f"enrollment failed: {exc}")


def build_enrollment_client(config: AgentConfig) -> ServerClient:
    """A client for the enrollment plane, which never presents a certificate.

    No client certificate is configured here even when one exists on disk.
    `POST /enroll` is served by a listener that does not request one, and an
    already-enrolled device re-enrolling is a deliberate operator act with a
    fresh token, not something to authenticate with the identity being
    replaced.
    """
    base_url = config.enroll_base_url
    if not base_url:
        raise ConfigError(
            "no server_url is configured. Set it in /etc/ubuntuguard/agent.yaml:\n"
            "    server_url: https://ubuntuguard.example.internal"
        )
    return ServerClient(
        base_url,
        ca_bundle=config.server_ca_bundle,
        plaintext_permitted=config.plaintext_http_permitted,
    )


def enroll(
    config: AgentConfig,
    *,
    token: str,
    adapter: OsAdapter | None = None,
    client: ServerClient | None = None,
    logger: logging.Logger | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    sleep: Any = time.sleep,
) -> EnrollmentResult:
    """Enrol this device. Idempotent in the keypair, not in the token.

    Safe to re-run after a failure: the keypair and CSR persist, so the next
    attempt presents the same public key and lands on the server's idempotency
    cache if it is still inside the 60-second window. Not safe to re-run with
    the same token after that window - the token is spent - which is why the
    401 message says to check the dashboard before minting another.
    """
    log = logger if logger is not None else get_logger("enrollment")
    os_adapter = adapter if adapter is not None else detect_adapter()

    # Registered again even though the CLI already did it. This function is
    # callable directly, and the cost of registering twice is nothing next to
    # the cost of a path where it was not registered at all.
    SECRETS.register(token)

    if is_enrolled(config.paths):
        raise EnrollmentError(
            f"this device already has an identity in {config.paths.pki_dir}. "
            "Re-enrolling would create a second device record for one laptop. "
            "Revoke the existing device in the dashboard and remove "
            f"{config.paths.private_key_path} and {config.paths.certificate_path} "
            "first, if that is really what you want."
        )

    ensure_runtime_paths(config.paths)

    # Step 3: the key exists on disk before any request is made.
    keypair = ensure_device_keypair(config.paths)
    log.info(
        "device keypair ready",
        extra={
            "generated": keypair.created,
            "key_path": str(config.paths.private_key_path),
            "curve": "secp256r1",
        },
    )

    payload = build_enroll_payload(config, os_adapter, token=token, csr_pem=keypair.csr_pem)
    server = client if client is not None else build_enrollment_client(config)

    log.info(
        "requesting enrollment",
        extra={"server": server.base_url, "hostname": payload["hostname"]},
    )
    document, attempts = _post_with_retries(
        server, payload, max_attempts=max_attempts, logger=log, sleep=sleep
    )

    device_id = _require_string(document, "device_id")
    certificate_pem = _require_string(document, "client_certificate_pem")
    ca_chain_pem = _require_string(document, "ca_chain_pem")
    policy_keys = _parse_policy_keys(document)
    clone_suspected = bool(document.get("clone_suspected", False))

    # Step 6: every check runs before anything is written.
    summary = install_certificate(
        config.paths,
        certificate_pem=certificate_pem.encode("ascii"),
        ca_chain_pem=ca_chain_pem.encode("ascii"),
        expected_device_id=device_id,
        private_key=keypair.private_key,
    )
    write_policy_keys(config.paths.policy_keys_path, policy_keys)

    if clone_suspected:
        # Enrollment succeeded as a distinct device; the server raised an
        # incident for a human. Warned rather than failed, because a reimaged
        # laptop and a cloned VM are indistinguishable from here and refusing
        # would break the legitimate case.
        log.warning(
            "the server flagged this device as a possible clone of an existing one; "
            "an incident was raised for review",
            extra={"device_id": device_id, "clone_suspected": True},
        )

    log.info(
        "enrolled",
        extra={
            "device_id": device_id,
            "not_after": summary.not_after.isoformat(),
            "renew_after": summary.renew_after.isoformat(),
            "policy_keys_pinned": len(policy_keys),
            "attempts": attempts,
        },
    )
    return EnrollmentResult(
        device_id=device_id,
        certificate=summary,
        clone_suspected=clone_suspected,
        policy_public_keys=policy_keys,
        reused_keypair=not keypair.created,
        attempts=attempts,
    )
