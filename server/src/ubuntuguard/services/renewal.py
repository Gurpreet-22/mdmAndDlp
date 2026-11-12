"""Device certificate renewal.

Device certificates live 30 days and the agent starts renewing at half-life, so
this is the endpoint that keeps a fleet from falling off the control plane a
month after it was enrolled.

The flow, and why each step is where it is:

1. Parse and verify the CSR **before** anything is written. A malformed request
   must not leave a half-rotated device behind.
2. Refuse a CSR that reuses the current public key. Renewal exists partly to
   bound how long one private key is exposed, and reusing it forfeits that
   while also making step 3 ambiguous.
3. Check for an already-issued certificate against this exact public key. This
   is the idempotent retry: the server committed, the response was lost, and
   the agent is asking again with the same CSR. It gets the same certificate
   rather than a second one.
4. Issue, insert, supersede the predecessor and repoint the device - all in one
   transaction, so there is no instant at which the device has two live
   certificates or none.

What this deliberately does not do: re-examine the hardware fingerprint, touch
the policy signing keys, or accept any identity claim from the body. The device
is established entirely by the mTLS connection, so there is nothing in the
request that could name a different one.
"""

from __future__ import annotations

import datetime as dt
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.models import Device
from ubuntuguard.schemas import CertificateRenewRequest, CertificateRenewResponse
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


def _public_key_der(key: object) -> bytes | None:
    """SubjectPublicKeyInfo DER, or None for something that is not a key."""
    public_bytes = getattr(key, "public_bytes", None)
    if public_bytes is None:
        return None
    encoded = public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return encoded if isinstance(encoded, bytes) else None


def renew(
    session: Session,
    *,
    keys: KeyBundle,
    device: Device,
    presented_certificate: x509.Certificate,
    request: CertificateRenewRequest,
    request_id: str | None = None,
    now: dt.datetime | None = None,
) -> CertificateRenewResponse:
    now = now or dt.datetime.now(dt.UTC)

    # --- 1. The CSR, before anything is written ---------------------------- #
    # `verify_csr` is called HERE rather than being left to
    # `issue_device_certificate`, which also calls it. That is not redundancy:
    # it is what turns a weak or unsupported key into a 400 with a reason code
    # instead of an uncaught `CsrRejectedError` and a 500. The signature check
    # and the key-size policy both live in `verify_csr`, so both have to be
    # inside this try block to be reported rather than crashed on.
    try:
        csr = load_csr_pem(request.csr_pem.encode("utf-8"))
        verify_csr(csr)
        public_key = csr.public_key()
    except CsrRejectedError as exc:
        _audit_failure(session, device.id, request_id, f"csr rejected: {exc}")
        session.commit()
        raise problems.ProblemError(
            "csr_invalid",
            status=400,
            title="Certificate request rejected",
            detail="The certificate signing request could not be accepted.",
            audit_detail=str(exc),
        ) from exc

    csr_key_der = _public_key_der(public_key)
    if csr_key_der is None:  # pragma: no cover - load_csr_pem returns a real key
        raise problems.ProblemError(
            "csr_invalid",
            status=400,
            title="Certificate request rejected",
            detail="The certificate signing request could not be accepted.",
        )

    # --- 2. The key must actually be new ---------------------------------- #
    # Checked against the certificate the client is authenticating WITH, not
    # against the device's current pin, because during the grace window those
    # can differ - and the question being asked is "is this a different key
    # from the one you are holding".
    if csr_key_der == _public_key_der(presented_certificate.public_key()):
        _audit_failure(session, device.id, request_id, "csr reuses the current public key")
        session.commit()
        raise problems.ProblemError(
            "csr_key_reused",
            status=400,
            title="Certificate request rejected",
            detail=(
                "The certificate request must use a new keypair. Renewing onto the "
                "same key does not limit how long that key is exposed, which is "
                "half the reason certificates are rotated."
            ),
            audit_detail="renewal CSR presented the public key it already holds",
        )

    # --- 3. Idempotent retry ----------------------------------------------- #
    # Keyed on the CSR's public key, mirroring enrollment. No cache table is
    # needed: the issued certificate IS the record, and there are never more
    # than a handful of live rows per device to compare against.
    for existing in repositories.find_live_certificates(session, device.id):
        stored = x509.load_pem_x509_certificate(existing.pem.encode("ascii"))
        if _public_key_der(stored.public_key()) != csr_key_der:
            continue
        # Already issued against this key. Hand back the same certificate.
        audit.append(
            session,
            action="certificate_renewal_retried",
            target_type="device",
            target_id=str(device.id),
            request_id=request_id,
            detail={"serial": existing.serial_number, "fingerprint": existing.fingerprint},
        )
        session.commit()
        return CertificateRenewResponse(
            device_id=device.id,
            client_certificate_pem=existing.pem,
            ca_chain_pem=_ca_chain_pem(keys),
            certificate_not_after=existing.not_after,
            certificate_renew_after=renewal_due_at(stored),
            reused=True,
        )

    # --- 4. Issue, record, supersede, repoint - one transaction ------------ #
    # `issue_device_certificate` is reused unchanged, which is the point: the
    # subject still comes from the device UUID the server allocated, CSR
    # extensions are still ignored, and the key policy still applies. Renewal
    # introduces no second path to a certificate.
    certificate = issue_device_certificate(keys.ca, csr, str(device.id), now=now)
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    fingerprint = certificate_fingerprint(certificate)

    repositories.record_issued_certificate(
        session,
        device_id=device.id,
        fingerprint=fingerprint,
        serial_number=format(certificate.serial_number, "x"),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        pem=certificate_pem,
    )

    # The predecessor is superseded in the SAME transaction as the insert. If
    # this were two commits there would be a window with two live certificates,
    # or - worse, if ordered the other way - one with none, during which the
    # device could not authenticate at all.
    superseded = repositories.supersede_other_certificates(
        session, device_id=device.id, keep_fingerprint=fingerprint, now=now
    )

    device.cert_fingerprint = fingerprint
    device.cert_not_after = certificate.not_valid_after_utc
    session.flush()

    audit.append(
        session,
        action="certificate_renewed",
        target_type="device",
        target_id=str(device.id),
        request_id=request_id,
        detail={
            "hostname": device.hostname,
            "serial": format(certificate.serial_number, "x"),
            "fingerprint": fingerprint,
            "not_after": certificate.not_valid_after_utc,
            "superseded_certificates": superseded,
            # Worth recording for the same reason enrollment records it: some
            # tooling adds extensions by default, so this is not necessarily an
            # attack, but it is what you want in the log if a device later
            # turns out to be hostile.
            "csr_requested_extensions": requested_extensions(csr),
            # True when the client authenticated with a certificate a previous
            # renewal had already superseded - i.e. it never received that
            # response. Not an error, and worth being able to count.
            "recovered_from_lost_response": certificate_fingerprint(presented_certificate)
            != fingerprint
            and superseded == 0,
        },
    )

    # Committed before returning: the agent will present the new certificate
    # immediately, and the device resolver reads from a separate session.
    session.commit()

    return CertificateRenewResponse(
        device_id=device.id,
        client_certificate_pem=certificate_pem,
        ca_chain_pem=_ca_chain_pem(keys),
        certificate_not_after=certificate.not_valid_after_utc,
        certificate_renew_after=renewal_due_at(certificate),
        reused=False,
    )


def _ca_chain_pem(keys: KeyBundle) -> str:
    return keys.ca.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _audit_failure(
    session: Session, device_id: uuid.UUID, request_id: str | None, reason: str
) -> None:
    audit.append(
        session,
        action="certificate_renewal_failed",
        target_type="device",
        target_id=str(device_id),
        request_id=request_id,
        detail={"reason": reason},
    )
