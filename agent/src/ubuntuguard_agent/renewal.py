"""Certificate renewal: replacing an identity without ever being without one.

Device certificates live 30 days and the agent starts renewing at half-life
(`CERT_RENEW_AT_PCT`), computed locally from the certificate rather than taken
from the server's `certificate_renew_after`, so the decision works offline.
Renewing at the midpoint leaves the whole second half as the window to recover
from a failure, instead of discovering the problem on the last day.

The one rule this module exists to enforce: **the working identity is never
given up before the replacement is in hand.** Every step below is ordered
around that.

  1. Finish or discard any interrupted previous attempt.
  2. Load the current identity. It stays in place throughout.
  3. Generate a NEW keypair and CSR at the `.new` paths, and persist them
     before sending anything - the server's renewal idempotency is keyed on the
     CSR's public key, so a retry must present the same one.
  4. POST, authenticated with the CURRENT certificate, retrying transport
     failures with a byte-identical body.
  5. Verify the replacement against the new key and stage it.
  6. Swap. Only now does the old identity stop being the identity.

If anything fails before step 6, the old certificate is still installed and
still works. The server has superseded it, but it keeps accepting it for the
renewal endpoint alone during `CERT_SUPERSEDE_GRACE_SECONDS`, which is what
makes step 4 safely retryable.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import time
from typing import Any

from ubuntuguard_agent.config import AgentConfig
from ubuntuguard_agent.core.scheduler import Backoff
from ubuntuguard_agent.errors import (
    ConfigError,
    HttpStatusError,
    RenewalError,
    TlsVerificationError,
    TransportError,
)
from ubuntuguard_agent.http import ServerClient
from ubuntuguard_agent.identity import (
    CertificateSummary,
    complete_pending_renewal,
    ensure_keypair,
    ensure_runtime_paths,
    load_identity,
    stage_renewed_certificate,
)
from ubuntuguard_agent.logging_setup import get_logger

#: Relative, so `ServerClient` resolves it against the device-plane base URL.
RENEW_PATH = "api/v1/devices/me/certificate:renew"

#: Attempts per renewal run.
#:
#: Three, not the four enrollment uses. A renewal that fails is retried again
#: on the next scheduler tick, and there are days of runway left - renewal
#: starts at the certificate's midpoint. Hammering inside one run buys nothing
#: and lengthens the window in which the agent holds a superseded certificate.
DEFAULT_MAX_ATTEMPTS = 3

RETRY_INITIAL_SECONDS = 2.0
RETRY_MAX_SECONDS = 15.0


@dataclasses.dataclass(frozen=True)
class RenewalResult:
    device_id: str
    certificate: CertificateSummary
    #: True when the server returned a certificate it had already issued
    #: against this CSR - the recovery path for a lost response.
    reused: bool
    attempts: int
    #: True when a previous interrupted attempt was completed instead of a new
    #: renewal being performed.
    recovered: bool = False


def renewal_due(summary: CertificateSummary, *, now: dt.datetime | None = None) -> bool:
    """Whether renewal should start. Computed locally; works offline."""
    return summary.renewal_due(now=now)


def build_renewal_client(config: AgentConfig) -> ServerClient:
    """A device-plane client presenting the certificate about to be replaced.

    The current certificate, deliberately - the one being retired is the
    credential that authorises its own replacement, which is what makes
    renewal need no token and no operator.
    """
    base_url = config.device_base_url
    if not base_url:
        raise ConfigError("no server_url is configured; the device plane has no address")
    return ServerClient(
        base_url,
        ca_bundle=config.server_ca_bundle,
        client_certificate=config.paths.certificate_path,
        client_key=config.paths.private_key_path,
        plaintext_permitted=config.plaintext_http_permitted,
    )


def _post_with_retries(
    client: ServerClient,
    payload: dict[str, Any],
    *,
    max_attempts: int,
    logger: logging.Logger,
    sleep: Any = time.sleep,
) -> tuple[dict[str, Any], int]:
    """POST the renewal, retrying only what retrying can fix.

    The body is identical on every attempt, for the same reason as enrollment:
    the server keys its idempotency on the CSR's public key, so a retry with a
    rebuilt CSR would collect a second certificate instead of the one already
    issued.

    `401` is **not** retried, and that distinction matters here. Three things
    produce it - the device was revoked, the certificate expired, or the grace
    window elapsed - and none improves by asking again. All three need an
    operator, and two of them mean this device is finished until it is
    re-enrolled.
    """
    backoff = Backoff(RETRY_INITIAL_SECONDS, RETRY_MAX_SECONDS)
    last: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = client.post_json(RENEW_PATH, payload)
        except TlsVerificationError:
            raise
        except HttpStatusError as exc:
            if not exc.retryable or attempt == max_attempts:
                raise _renewal_error_for(exc) from exc
            last = exc
        except TransportError as exc:
            if attempt == max_attempts:
                raise RenewalError(
                    f"could not reach the server after {attempt} attempts: {exc}. "
                    "The existing certificate is untouched and still valid; renewal "
                    "will be attempted again on the next cycle."
                ) from exc
            last = exc
        else:
            document = response.json()
            if not isinstance(document, dict):
                raise RenewalError("the renewal response was not a JSON object")
            return document, attempt

        delay = backoff.next_delay()
        logger.warning(
            "renewal attempt failed; retrying",
            extra={
                "attempt": attempt,
                "of": max_attempts,
                "retry_in_seconds": round(delay, 1),
                "error": str(last),
            },
        )
        sleep(delay)

    raise RenewalError(f"renewal failed after {max_attempts} attempts: {last}")


def _renewal_error_for(exc: HttpStatusError) -> RenewalError:
    """Turn a refusal into something an operator can act on."""
    if exc.status == 401:
        return RenewalError(
            "the server refused this device's certificate for renewal "
            f"({exc.code or 'device_not_authenticated'}). Three things cause this "
            "and they need different responses:\n"
            "  - the device was revoked in the dashboard: this is expected, and "
            "the laptop should be re-enrolled or left alone deliberately;\n"
            "  - the certificate has expired: too late to renew, re-enrol;\n"
            "  - a previous renewal superseded this certificate more than an "
            "hour ago: the replacement was issued and lost. Re-enrolment is the "
            "recovery.\n"
            "`ubuntuguard-agent status` shows which, from the certificate's dates."
        )
    if exc.status == 400 and exc.code == "csr_key_reused":
        return RenewalError(
            "the server rejected the renewal CSR because it reuses the current "
            "public key. This is an agent bug: renewal must generate a new "
            "keypair. Remove pki/device.key.new and pki/device.csr.new to force "
            "a fresh one."
        )
    if exc.status == 400:
        return RenewalError(
            f"the server rejected the renewal CSR ({exc.code or 'csr_invalid'}). "
            "This is an agent bug rather than an operator error; the request is "
            "in pki/device.csr.new."
        )
    if exc.status == 422:
        return RenewalError(
            "the server rejected the shape of the renewal request. The agent and "
            "server contracts have drifted - compare this module against "
            "`CertificateRenewRequest` in the server's schemas.py."
        )
    return RenewalError(f"renewal failed: {exc}")


def _require_string(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise RenewalError(
            f"the renewal response is missing a usable {key!r}; got {type(value).__name__}"
        )
    return value


def renew(
    config: AgentConfig,
    *,
    client: ServerClient | None = None,
    logger: logging.Logger | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    sleep: Any = time.sleep,
) -> RenewalResult:
    """Renew this device's certificate. Never leaves it without one."""
    log = logger if logger is not None else get_logger("renewal")
    paths = config.paths
    ensure_runtime_paths(paths)

    # Step 1. An interrupted attempt is finished before a new one starts, so a
    # crash during the swap costs a restart rather than accumulating staged
    # material that nobody ever completes.
    recovered = complete_pending_renewal(paths)
    if recovered is not None:
        log.info(
            "completed an interrupted certificate renewal found on disk",
            extra={
                "device_id": recovered.device_id,
                "not_after": recovered.not_after.isoformat(),
            },
        )
        return RenewalResult(
            device_id=recovered.device_id,
            certificate=recovered,
            reused=True,
            attempts=0,
            recovered=True,
        )

    # Step 2. The current identity, which stays in place throughout.
    _current_key, current = load_identity(paths)

    # Step 3. The replacement keypair, persisted BEFORE anything is sent.
    # Reused across retries, which is what lands a retry on the server's
    # idempotency check instead of collecting a second certificate.
    pending = ensure_keypair(paths.pending_private_key_path, paths.pending_csr_path)
    log.info(
        "renewal keypair ready",
        extra={
            "generated": pending.created,
            "key_path": str(paths.pending_private_key_path),
            "replacing_not_after": current.not_after.isoformat(),
        },
    )

    payload = {"csr_pem": pending.csr_pem.decode("ascii")}
    server = client if client is not None else build_renewal_client(config)

    # Step 4.
    document, attempts = _post_with_retries(
        server, payload, max_attempts=max_attempts, logger=log, sleep=sleep
    )

    device_id = _require_string(document, "device_id")
    if device_id != current.device_id:
        # The server named a different device. Nothing is staged and nothing is
        # swapped; the current identity is untouched.
        raise RenewalError(
            f"the renewal response names device {device_id} but this device is "
            f"{current.device_id}; refusing to install it"
        )

    certificate_pem = _require_string(document, "client_certificate_pem")
    ca_chain_pem = _require_string(document, "ca_chain_pem")
    reused = bool(document.get("reused", False))

    # Step 5. Verified against the NEW key, then staged. After this the swap
    # can always be completed.
    staged = stage_renewed_certificate(
        paths,
        certificate_pem=certificate_pem.encode("ascii"),
        ca_chain_pem=ca_chain_pem.encode("ascii"),
        expected_device_id=device_id,
    )

    # Step 6.
    summary = complete_pending_renewal(paths)
    if summary is None:  # pragma: no cover - staging just created this state
        raise RenewalError(
            "the replacement certificate was staged but the swap did not complete; "
            f"inspect {paths.pki_dir}"
        )

    log.info(
        "certificate renewed",
        extra={
            "device_id": summary.device_id,
            "previous_not_after": current.not_after.isoformat(),
            "not_after": summary.not_after.isoformat(),
            "renew_after": summary.renew_after.isoformat(),
            "server_reused_existing": reused,
            "attempts": attempts,
        },
    )
    assert staged.device_id == summary.device_id  # noqa: S101 - invariant, not validation
    return RenewalResult(
        device_id=summary.device_id,
        certificate=summary,
        reused=reused,
        attempts=attempts,
    )
