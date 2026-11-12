"""Request dependencies: who is calling, and may they do this.

RBAC is enforced here, on the server, for every route that declares a
capability. The dashboard also hides controls a user cannot use, but that is
cosmetic - a hidden button is not a security boundary.

Token resolution sits behind a Protocol rather than reaching for a database
session directly. That keeps the authorisation wiring testable without
PostgreSQL, and it means the route layer never grows SQL of its own.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Protocol

from fastapi import Depends, Request
from sqlalchemy.orm import Session, sessionmaker

from ubuntuguard import problems
from ubuntuguard.security.device_auth import (
    ClientCertificate,
    DeviceAuthError,
    extract_client_certificate,
)
from ubuntuguard.security.rbac import Capability, Role, can


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated admin."""

    user_id: str
    email: str
    role: Role

    def __repr__(self) -> str:
        # No token material is held here, but keep the habit: identity objects
        # end up in log lines and exception context.
        return f"Principal(user_id={self.user_id}, role={self.role.value})"


@dataclass(frozen=True, slots=True)
class ResolvedDevice:
    """What the device resolver found, before policy is applied to it.

    `certificate_superseded_at` is the whole reason this is a dataclass rather
    than the bare device id it used to be. A renewal supersedes the certificate
    it replaces, and the agent presenting that certificate may be retrying
    because the response never arrived - so the resolver cannot simply refuse
    it, and the route cannot simply accept it. Carrying the timestamp lets the
    renewal endpoint allow it and every other endpoint refuse it.
    """

    device_id: str
    certificate_superseded_at: dt.datetime | None = None


@dataclass(frozen=True, slots=True)
class DevicePrincipal:
    """An authenticated device, established by mTLS."""

    device_id: str
    certificate: ClientCertificate
    #: Set when the presented certificate has been superseded by a renewal and
    #: is inside the grace window. None for a current certificate. Only the
    #: renewal endpoint ever sees this as non-None; see
    #: `get_renewing_device_principal`.
    certificate_superseded_at: dt.datetime | None = None

    @property
    def certificate_is_current(self) -> bool:
        return self.certificate_superseded_at is None


class TokenResolver(Protocol):
    """Resolves a presented access token to a principal, or returns None.

    The implementation is responsible for the checks that make opaque tokens
    worthwhile: the token exists, is not expired, is not revoked, and its user
    is still active. Returning None for all of those keeps the failure
    indistinguishable to the caller.
    """

    def resolve_access_token(self, token_hash: str) -> Principal | None: ...


class DeviceResolver(Protocol):
    """Resolves a client certificate fingerprint to a device.

    Returns a `ResolvedDevice` rather than a full principal so the resolver
    never has to invent a certificate: the dependency already parsed the real
    one and pairs the two itself.

    Must verify that the device is `active` on every request. That per-request
    check is what makes revocation take effect immediately, rather than waiting
    for a CRL to propagate. Must also refuse a certificate that is revoked, or
    superseded for longer than the grace window, and must report a superseded
    certificate's timestamp rather than silently accepting it.
    """

    def resolve_device(self, fingerprint: str) -> ResolvedDevice | None: ...


class _UnconfiguredResolver:
    """Stand-in used before the database is wired up.

    Returns 503 rather than 401, because "the server cannot check" and "your
    credentials are wrong" are different problems and conflating them sends
    operators hunting in the wrong place.
    """

    def resolve_access_token(self, token_hash: str) -> Principal | None:
        raise problems.service_unavailable(
            "Authentication is not available: the server has no database configured."
        )

    def resolve_device(self, fingerprint: str) -> ResolvedDevice | None:
        raise problems.service_unavailable(
            "Device authentication is not available: the server has no database configured."
        )


UNCONFIGURED_RESOLVER = _UnconfiguredResolver()


def get_session(request: Request) -> Iterator[Session]:
    """Per-request database session. **This teardown does not commit.**

    THE RULE: whichever function performs a write calls `session.commit()`
    before it returns or raises.

    An earlier version committed here, in the dependency teardown, and that was
    a bug rather than a style choice. FastAPI runs the teardown of a `yield`
    dependency AFTER the response has gone to the client, so a client that
    logged in and immediately used its new access token could be told 401: the
    token row had not been committed yet. It reproduced roughly once in twelve
    attempts, which is exactly the kind of failure that reaches production and
    then cannot be reproduced on demand.

    The rollback below is a safety net for a handler that wrote something and
    then raised an unexpected exception. It is not the normal path: a handled
    `ProblemError` must still persist what it wrote, because a failed login has
    already recorded the attempt and an audit row, and refresh-token reuse has
    already revoked the family. Those services commit before raising.
    """
    factory: sessionmaker[Session] | None = getattr(request.app.state, "session_factory", None)
    if factory is None:
        raise problems.service_unavailable("The server has no database configured; see /readyz.")

    session = factory()
    try:
        yield session
    finally:
        # Discards anything the writer did not commit. Committing here would
        # reintroduce the race described above.
        session.rollback()
        session.close()


def get_keys(request: Request) -> object:
    """The loaded CA and policy signing key."""
    keys = getattr(request.app.state, "keys", None)
    if keys is None:
        raise problems.service_unavailable(
            "Key material is not loaded; generate it with: python -m ubuntuguard.cli init-keys"
        )
    return keys


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise problems.not_authenticated()
    return value.strip()


def get_principal(request: Request) -> Principal:
    """Resolve the bearer token to an admin principal."""
    from ubuntuguard.security.tokens import hash_token

    token = _bearer_token(request)
    # `or` rather than a getattr default: create_app sets the attribute to None
    # before the repositories exist, so a plain default would never be used.
    resolver: TokenResolver = (
        getattr(request.app.state, "token_resolver", None) or UNCONFIGURED_RESOLVER
    )
    principal = resolver.resolve_access_token(hash_token(token))
    if principal is None:
        # Expired, revoked, unknown, or a disabled user. One response for all
        # four: distinguishing them tells an attacker which tokens once existed.
        raise problems.not_authenticated()
    request.state.principal = principal
    return principal


def require_capability(capability: Capability) -> Callable[[Principal], Principal]:
    """Build a dependency enforcing one capability.

    Routes declare the capability they need, never the roles. Adding a role
    later touches the matrix in `rbac.py` and nothing else.
    """

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not can(principal.role, capability):
            raise problems.forbidden(
                audit_detail=(
                    f"role {principal.role.value} lacks {capability.value} "
                    f"(user {principal.user_id})"
                )
            )
        return principal

    return dependency


def _authenticate_device(request: Request, *, allow_superseded: bool) -> DevicePrincipal:
    """Shared body of the two device dependencies.

    `allow_superseded` is the only difference between them, and it is a
    parameter rather than a post-hoc check in the route so that every other
    check runs identically on both paths. A route cannot accidentally get a
    weaker version of the subject or proxy checks by choosing the wrong
    dependency; the only thing it can choose is whether a superseded
    certificate is acceptable.
    """
    settings = request.app.state.settings
    try:
        certificate = extract_client_certificate(
            request.headers,
            client_ip=request.client.host if request.client else None,
            trusted_proxy_ips=settings.trusted_proxy_ips,
        )
    except DeviceAuthError as exc:
        raise problems.device_not_authenticated(exc.code, audit_detail=str(exc)) from exc

    resolver: DeviceResolver = (
        getattr(request.app.state, "device_resolver", None) or UNCONFIGURED_RESOLVER
    )
    resolved = resolver.resolve_device(certificate.fingerprint)
    if resolved is None:
        raise problems.device_not_authenticated(
            "device_not_active",
            audit_detail=(
                f"certificate {certificate.fingerprint[:23]}... is unknown, revoked, "
                "superseded beyond the grace window, or the device is not active"
            ),
        )

    # The certificate's subject must agree with the device the fingerprint
    # resolved to. Disagreement means the pin and the subject have drifted
    # apart, which should never happen and is worth failing loudly over.
    if certificate.subject_common_name != resolved.device_id:
        raise problems.device_not_authenticated(
            "device_identity_mismatch",
            audit_detail=(
                f"certificate subject {certificate.subject_common_name} does not "
                f"match device {resolved.device_id}"
            ),
        )

    if resolved.certificate_superseded_at is not None and not allow_superseded:
        # Inside the grace window, so the resolver let it through, but this
        # route is not the renewal endpoint. A superseded certificate exists
        # only to collect the replacement it was superseded by.
        raise problems.device_not_authenticated(
            "client_cert_superseded",
            audit_detail=(
                f"device {resolved.device_id} presented a certificate superseded at "
                f"{resolved.certificate_superseded_at.isoformat()}; only "
                "certificate:renew accepts one"
            ),
        )

    device = DevicePrincipal(
        device_id=resolved.device_id,
        certificate=certificate,
        certificate_superseded_at=resolved.certificate_superseded_at,
    )
    request.state.device = device
    return device


def get_device_principal(request: Request) -> DevicePrincipal:
    """Resolve the mTLS client certificate to a device principal.

    **The strict dependency, and the default for every device route.** A
    certificate that has been superseded by a renewal is refused here, even
    inside the grace window.

    It is the strict one deliberately: a device route added later that reaches
    for the obvious name gets the tightest behaviour without having to know
    this distinction exists. Opting into the looser one is an explicit act, and
    exactly one route does it.
    """
    return _authenticate_device(request, allow_superseded=False)


def get_renewing_device_principal(request: Request) -> DevicePrincipal:
    """As above, but tolerates a certificate superseded within the grace window.

    **Used by `POST /devices/me/certificate:renew` and nothing else.**

    The case it exists for: the server committed a renewal, superseded the old
    certificate, and the response was lost in transit. The agent still holds the
    superseded certificate and has no other credential. Without this it could
    not retry, and a dropped packet would cost a re-enrollment.

    Everything else still applies - trusted proxy, nginx verification, the
    certificate's own validity window, the device being active, the subject
    matching - and the retry is idempotent, so this cannot be used to
    accumulate certificates. See `constants.CERT_SUPERSEDE_GRACE_SECONDS`.
    """
    return _authenticate_device(request, allow_superseded=True)
