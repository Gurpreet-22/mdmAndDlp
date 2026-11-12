"""Database-backed implementations of the auth resolver protocols.

Each resolver re-checks state on EVERY request rather than caching. That is
what makes revocation immediate: there is no window during which a revoked
device or a disabled admin keeps working because a cache has not expired yet.
The cost is one indexed lookup per request, which at 10-50 devices is nothing.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session, sessionmaker

from ubuntuguard.api.deps import Principal, ResolvedDevice
from ubuntuguard.constants import CERT_SUPERSEDE_GRACE_SECONDS
from ubuntuguard.repositories import find_device_by_certificate, find_token, get_user
from ubuntuguard.security.rbac import Role


class DbTokenResolver:
    """Resolves an access token hash to an admin principal."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def resolve_access_token(self, token_hash: str) -> Principal | None:
        now = dt.datetime.now(dt.UTC)
        with self._factory() as session:
            token = find_token(session, token_hash=token_hash, kind="access")
            # One return value for every failure mode. Distinguishing expired
            # from revoked from unknown would tell a caller which tokens once
            # existed.
            if token is None or token.revoked_at is not None or token.expires_at <= now:
                return None

            user = get_user(session, token.user_id)
            if user is None or not user.is_active:
                return None

            try:
                role = Role(user.role)
            except ValueError:
                # A role string the code does not recognise means tampering or a
                # bad migration. Refusing is safer than guessing.
                return None

            return Principal(user_id=str(user.id), email=user.email, role=role)


class DbDeviceResolver:
    """Resolves a client certificate fingerprint to a device.

    The order of the checks below is the policy, so it is worth reading as a
    sequence rather than a set.

    **1. The certificate must have been issued by us.** The lookup is against
    `issued_certificates`, which holds every certificate this CA has ever
    issued. A certificate nginx verified but that is not in that table cannot
    identify a device.

    **2. The device must be active.** Checked before anything about the
    certificate, because revocation outranks every other consideration: a
    revoked laptop is refused whether its certificate is current, superseded or
    pristine. This is also what makes revocation immediate - it is re-read here
    on every single request rather than cached.

    **3. The certificate must not be revoked.** A per-certificate revocation,
    separate from the device's. Nothing writes it yet; it is enforced now so
    that whatever does later cannot find the enforcement missing.

    **4. A superseded certificate is accepted only briefly, and the caller is
    told.** `superseded_at` is set by a renewal. Past
    `CERT_SUPERSEDE_GRACE_SECONDS` the certificate is dead here. Inside that
    window it resolves, but the returned `ResolvedDevice` carries the timestamp
    so `get_device_principal` can refuse it for everything except the renewal
    endpoint. That split is the point: the grace exists so an agent whose
    renewal response was lost can collect the replacement, and for nothing else.

    Note what this does NOT check: the certificate's validity window. That is
    `security/device_auth.py`, which re-derives it from the certificate itself
    rather than trusting these columns, so an expired certificate is refused
    even if the row here says it is live.
    """

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def resolve_device(self, fingerprint: str) -> ResolvedDevice | None:
        now = dt.datetime.now(dt.UTC)
        with self._factory() as session:
            found = find_device_by_certificate(session, fingerprint)
            if found is None:
                return None
            device, certificate = found

            if device.status != "active":
                return None
            if certificate.revoked_at is not None:
                return None

            superseded_at = certificate.superseded_at
            if superseded_at is not None:
                age = (now - superseded_at).total_seconds()
                if age > CERT_SUPERSEDE_GRACE_SECONDS:
                    return None

            return ResolvedDevice(
                device_id=str(device.id),
                certificate_superseded_at=superseded_at,
            )
