"""Device enrollment.

The flow, and why each step is where it is:

1. Parse the CSR **and apply the key policy** before touching the token. A
   malformed or weak request should not burn a single-use token, and it should
   be refused with a reason code rather than crashing - see step 1 for the bug
   that made the second half of that sentence necessary.
2. Check the idempotency cache. A network failure after the server committed but
   before the agent received the response is the common case, and the agent
   must be able to retry without being told its token is spent.
3. Consume the token **atomically**. One UPDATE with a `consumed_at IS NULL`
   guard, so two simultaneous callers produce exactly one success.
4. If the consume lost, look in the cache again: a retry with the same keypair
   gets the original response. A different keypair gets a 401, because the
   token really is spent.
5. Create the device, issue the certificate, cache the response, audit.

The server allocates the device UUID and puts it in the certificate's common
name. Nothing from the CSR's subject or extensions is carried over, so a client
cannot choose its own identity.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.constants import ENROLLMENT_IDEMPOTENCY_SECONDS
from ubuntuguard.schemas import EnrollRequest, EnrollResponse
from ubuntuguard.security.tokens import fingerprint_public_key, hash_token
from ubuntuguard.services import audit
from ubuntuguard.services.ca import (
    CsrRejectedError,
    certificate_fingerprint,
    issue_device_certificate,
    load_csr_pem,
    renewal_due_at,
    requested_extensions,
    verify_csr,
)
from ubuntuguard.services.keys import KeyBundle


def enroll(
    session: Session,
    *,
    keys: KeyBundle,
    request: EnrollRequest,
    request_id: str | None = None,
    now: dt.datetime | None = None,
) -> EnrollResponse:
    now = now or dt.datetime.now(dt.UTC)
    token_hash = hash_token(request.enrollment_token)

    # --- 1. The CSR, before anything is consumed -------------------------- #
    # `verify_csr` is called HERE rather than being left to
    # `issue_device_certificate` at step 5, which also calls it. That is not
    # redundancy - it is what makes a weak or unsupported key a 400 with a
    # reason code and an audit row.
    #
    # The bug this fixes: `load_csr_pem` only raises for a CSR that will not
    # parse. The signature check and the key policy (EC curve, RSA >= 3072)
    # live in `verify_csr`, which was first reached from
    # `issue_device_certificate` far below and outside any handler. So an
    # RSA-2048 CSR raised an uncaught `CsrRejectedError`, the global handler
    # returned `500 internal_error`, and no `device_enrollment_failed` row was
    # written. The key was still refused and nothing leaked - but a 500 tells
    # an operator the server is broken when in fact their request was bad, and
    # the absent audit row means a fleet-wide attempt to enrol weak keys left
    # no trace.
    #
    # Moving the check here also means the token is still intact when it fails:
    # step 3 has not run, so a rejected CSR does not burn a single-use token.
    try:
        csr = load_csr_pem(request.csr_pem.encode("utf-8"))
        verify_csr(csr)
        public_key = csr.public_key()
    except CsrRejectedError as exc:
        _audit_failure(session, token_hash, request_id, f"csr rejected: {exc}")
        session.commit()
        raise problems.ProblemError(
            "csr_invalid",
            status=400,
            title="Certificate request rejected",
            detail="The certificate signing request could not be accepted.",
            audit_detail=str(exc),
        ) from exc

    csr_fingerprint = fingerprint_public_key(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # --- 2. Idempotent retry ---------------------------------------------- #
    cutoff = now - dt.timedelta(seconds=ENROLLMENT_IDEMPOTENCY_SECONDS)
    cached = repositories.find_enrollment_attempt(
        session, token_hash=token_hash, csr_fingerprint=csr_fingerprint, not_before=cutoff
    )
    if cached is not None:
        return EnrollResponse.model_validate(cached.response_json)

    # --- 3. Atomic consume ------------------------------------------------- #
    token_id = repositories.consume_enrollment_token(session, token_hash=token_hash, now=now)
    if token_id is None:
        # --- 4. Lost the race, or a genuinely invalid token --------------- #
        cached = repositories.find_enrollment_attempt(
            session, token_hash=token_hash, csr_fingerprint=csr_fingerprint, not_before=cutoff
        )
        if cached is not None:
            return EnrollResponse.model_validate(cached.response_json)

        existing = repositories.find_enrollment_token(session, token_hash)
        reason = "unknown token"
        if existing is not None:
            if existing.revoked_at is not None:
                reason = "token revoked"
            elif existing.consumed_at is not None:
                reason = "token already consumed by a different keypair"
            elif existing.expires_at <= now:
                reason = "token expired"
        _audit_failure(session, token_hash, request_id, reason)
        session.commit()
        raise problems.ProblemError(
            "enrollment_token_invalid",
            status=401,
            title="Enrollment token invalid or already used",
            detail="Enrollment failed.",
            audit_detail=reason,
        )

    # --- 5. Create the device, or claim the one an admin registered --------- #
    fingerprint = request.hardware_fingerprint
    clones = repositories.find_clone_candidates(
        session,
        machine_id_hash=fingerprint.machine_id_hash,
        dmi_product_uuid_hash=fingerprint.dmi_product_uuid_hash,
    )
    clone_suspected = bool(clones)

    # A token minted by "Add device" carries the row it was issued for. Claiming
    # that row rather than inserting a new one is what stops one laptop
    # appearing twice: once as the admin's registration and once as the
    # enrollment. Re-read here rather than carried from step 3, because the
    # atomic consume deliberately returns only the id it won.
    token = repositories.find_enrollment_token_by_id(session, token_id)
    pre_registered = (
        repositories.get_device(session, token.pre_registered_device_id)
        if token is not None and token.pre_registered_device_id is not None
        else None
    )

    if pre_registered is not None and pre_registered.status == "pending":
        device = repositories.claim_pending_device(
            session,
            device=pre_registered,
            hostname=request.hostname,
            agent_version=request.agent_version,
            release_build=request.release_build,
            os_id=request.os.id,
            os_version_id=request.os.version_id,
            kernel=request.os.kernel,
            arch=request.arch,
            machine_id_hash=fingerprint.machine_id_hash,
            dmi_product_uuid_hash=fingerprint.dmi_product_uuid_hash,
            virtualization=fingerprint.virtualization,
            primary_adapter_ip=request.primary_adapter_ip,
            clone_suspected=clone_suspected,
            clone_of_device_id=clones[0].id if clones else None,
            enrolled_at=now,
        )
    else:
        # No pre-registration, or the row is already enrolled or revoked. Either
        # way this enrollment gets its own identity: silently re-activating a
        # revoked device would turn a spent token into a way back in.
        device = repositories.create_device(
            session,
            status="active",
            hostname=request.hostname,
            agent_version=request.agent_version,
            release_build=request.release_build,
            os_id=request.os.id,
            os_version_id=request.os.version_id,
            kernel=request.os.kernel,
            arch=request.arch,
            machine_id_hash=fingerprint.machine_id_hash,
            dmi_product_uuid_hash=fingerprint.dmi_product_uuid_hash,
            virtualization=fingerprint.virtualization,
            primary_adapter_ip=request.primary_adapter_ip,
            clone_suspected=clone_suspected,
            clone_of_device_id=clones[0].id if clones else None,
            enrolled_at=now,
        )

    certificate = issue_device_certificate(keys.ca, csr, str(device.id), now=now)
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    device.cert_fingerprint = certificate_fingerprint(certificate)
    device.cert_not_after = certificate.not_valid_after_utc
    session.flush()

    repositories.record_issued_certificate(
        session,
        device_id=device.id,
        fingerprint=device.cert_fingerprint,
        serial_number=format(certificate.serial_number, "x"),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        pem=certificate_pem,
    )
    repositories.attach_token_to_device(session, token_id=token_id, device_id=device.id)

    response = EnrollResponse(
        device_id=device.id,
        client_certificate_pem=certificate_pem,
        ca_chain_pem=keys.ca.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        certificate_not_after=certificate.not_valid_after_utc,
        certificate_renew_after=renewal_due_at(certificate),
        policy_public_keys=keys.policy_public_keys_payload(),  # type: ignore[arg-type]
        clone_suspected=clone_suspected,
    )

    repositories.record_enrollment_attempt(
        session,
        token_hash=token_hash,
        csr_fingerprint=csr_fingerprint,
        device_id=device.id,
        response=_jsonable(response),
    )

    # Extensions the CSR asked for are all ignored when issuing, but they are
    # worth recording. Some tooling adds basicConstraints by default, so this is
    # not necessarily an attack - it is, however, the kind of thing you want in
    # the log if a device later turns out to be hostile.
    requested = requested_extensions(csr)

    audit.append(
        session,
        action="device_enrolled",
        target_type="device",
        target_id=str(device.id),
        request_id=request_id,
        detail={
            "hostname": device.hostname,
            "os": f"{request.os.id} {request.os.version_id}",
            "kernel": request.os.kernel,
            "agent_version": request.agent_version,
            "release_build": request.release_build,
            "certificate_fingerprint": device.cert_fingerprint,
            "clone_suspected": clone_suspected,
            "csr_requested_extensions": requested,
            # Whether this filled in a record an administrator had already
            # created, or arrived with a token not tied to one. Worth having in
            # the log: the second case means someone enrolled a laptop nobody
            # had registered.
            "claimed_pre_registration": pre_registered is not None
            and device.id == pre_registered.id,
        },
    )
    audit.append(
        session,
        action="certificate_issued",
        target_type="device",
        target_id=str(device.id),
        request_id=request_id,
        detail={
            "serial": format(certificate.serial_number, "x"),
            "not_after": certificate.not_valid_after_utc,
        },
    )

    if clone_suspected:
        # Enrollment still succeeded, as a distinct device. A reimaged laptop
        # and a cloned VM are indistinguishable from here, so this is raised for
        # a human to judge rather than enforced automatically.
        repositories.create_incident(
            session,
            kind="clone_suspected",
            summary=f"{device.hostname} shares a hardware fingerprint with an existing device",
            device_id=device.id,
            severity="high",
            note=(
                "Enrolled as a distinct device. Matching device(s): "
                + ", ".join(str(candidate.id) for candidate in clones[:5])
            ),
        )
        audit.append(
            session,
            action="clone_suspected",
            target_type="device",
            target_id=str(device.id),
            request_id=request_id,
            detail={"matches": [str(candidate.id) for candidate in clones[:5]]},
        )

    # Committed before returning: the agent will present its new certificate
    # immediately, and the device resolver reads from a separate session.
    session.commit()
    return response


def _jsonable(response: EnrollResponse) -> dict[str, Any]:
    """JSON-safe form for the idempotency cache, which is a JSONB column."""
    return response.model_dump(mode="json")


def _audit_failure(session: Session, token_hash: str, request_id: str | None, reason: str) -> None:
    audit.append(
        session,
        action="device_enrollment_failed",
        target_type="enrollment_token",
        # A prefix only. The full hash would let anyone who can read the audit
        # log correlate failures to a specific outstanding token.
        target_id=token_hash[:12],
        request_id=request_id,
        detail={"reason": reason},
    )
