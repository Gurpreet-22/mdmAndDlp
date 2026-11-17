"""Every admin route enforces a capability, and the forced-change gate.

Two things are checked here, and the first is structural.

**Route coverage.** `require_capability` carries both the RBAC check and the
forced-password-change check. That is efficient - one dependency covers
eighteen routes - and it is fragile in exactly one way: a new route written
with `Depends(get_principal)` instead gets neither check, compiles, works, and
is invisible in review. So this test walks the assembled router, resolves each
route's full dependency tree, and fails if any route is authenticated-but-
uncapable unless it appears on an explicit allowlist below.

The allowlist is the point. Adding a route to it is a deliberate line in a diff
with this docstring above it, rather than an omission nobody notices.

**The gate itself.** `require_capability` is a closure, so the returned
dependency can be called directly with a `Principal`. That tests the ordering
and the refusal without FastAPI, a database or a token.

No database is needed by anything in this file.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from ubuntuguard import problems
from ubuntuguard.api.deps import Principal, get_principal, require_capability
from ubuntuguard.config import Settings
from ubuntuguard.main import create_app
from ubuntuguard.security.rbac import Capability, Role

#: Qualified name of the closure `require_capability` returns. Matched rather
#: than imported because the function is built per capability, so there is no
#: single object to compare against.
CAPABILITY_DEPENDENCY = "require_capability.<locals>.dependency"

#: Routes that legitimately require no capability, each with the reason.
#:
#: Every entry here is a route that either has no admin principal at all, or
#: must stay reachable for an account that owes a password change. Nothing else
#: belongs in this set.
CAPABILITY_EXEMPT: dict[str, str] = {
    # --- No admin principal: unauthenticated or cookie-only ---------------- #
    "GET /healthz": "unauthenticated liveness; carries no version or build detail",
    "GET /readyz": "unauthenticated readiness; reports dependency state only",
    "POST /api/v1/auth/login": "establishes the session; nobody is authenticated yet",
    "POST /api/v1/auth/refresh": "authenticated by the refresh cookie, not a bearer token",
    "POST /api/v1/auth/logout": "must succeed even with no valid token",
    "GET /api/v1/auth/mode": "read by the login page before anyone has signed in",
    # --- Device plane: mTLS or a one-time token, never a capability -------- #
    "POST /api/v1/enroll": "a device has no identity until this call completes",
    "POST /api/v1/devices/me/heartbeat": "authenticated by the mTLS client certificate",
    "POST /api/v1/devices/me/certificate:renew": "authenticated by the certificate it replaces",
    "GET /api/v1/devices/me/policies/{policy_type}": (
        "authenticated by the mTLS client certificate; the subject is the "
        "caller's own certificate rather than a path parameter, which is what "
        "stops one device pulling another's policy"
    ),
    "POST /api/v1/devices/me/policy-status": (
        "authenticated by the mTLS client certificate; a device may report "
        "only on the policy it is actually under, checked in the handler"
    ),
    # --- Public: an enrolling employee has no account ---------------------- #
    "GET /api/v1/installer": "public installer metadata; carries no secret",
    "GET /api/v1/installer/download": "public installer download; carries no secret",
    # --- Must remain reachable DURING a forced password change ------------- #
    # These two are why the gate lives in `require_capability` rather than in
    # `get_principal`. Gating there would make the forced-change state
    # inescapable: the user could neither discover why they were refused nor do
    # anything about it.
    "GET /api/v1/auth/me": "how the dashboard learns a password change is required",
    "POST /api/v1/auth/password": "the only way out of a forced password change",
}


@pytest.fixture(scope="module")
def app() -> Any:
    return create_app(Settings(_env_file=None))  # type: ignore[call-arg]


def _dependency_names(dependant: Dependant) -> list[str]:
    """Qualified names of every callable in a route's dependency tree.

    Recursive because `require_capability`'s dependency itself depends on
    `get_principal`, and a future route may nest further. A flat inspection of
    the top level would miss anything one layer down.
    """
    names: list[str] = []
    for sub in dependant.dependencies:
        if sub.call is not None:
            names.append(getattr(sub.call, "__qualname__", repr(sub.call)))
        names.extend(_dependency_names(sub))
    return names


def _walk(obj: Any, prefix: str = "") -> list[tuple[str, APIRoute]]:
    """Collect every `APIRoute` with its full path, descending into sub-routers.

    FastAPI 0.162 includes routers lazily: `app.routes` holds `_IncludedRouter`
    wrappers rather than the flattened `APIRoute` list older versions produced.
    A non-recursive inspection of `app.routes` therefore finds only `/healthz`
    and `/readyz` and every assertion below passes vacuously, which is the
    worst possible failure for a test whose job is to catch an unguarded route.
    `test_the_traversal_finds_every_route_in_the_openapi_document` exists to
    make that impossible.

    Only `include_context.prefix` is accumulated. A router's OWN prefix - the
    `/users` in `APIRouter(prefix="/users")` - is already baked into
    `route.path`, because `add_api_route` applies it at decoration time.
    Adding it again here would produce `/api/v1/users/users`.
    """
    if isinstance(obj, APIRoute):
        return [(prefix + obj.path, obj)]
    if type(obj).__name__ == "_IncludedRouter":
        inner_prefix = prefix + (obj.include_context.prefix or "")
        collected: list[tuple[str, APIRoute]] = []
        for child in obj.original_router.routes:
            collected.extend(_walk(child, inner_prefix))
        return collected
    return []


def _routes(app: Any) -> list[tuple[str, APIRoute]]:
    """Every API route as ("METHOD /path", route), excluding HEAD and OPTIONS."""
    found: list[tuple[str, APIRoute]] = []
    for route in app.routes:
        for path, api_route in _walk(route):
            for method in sorted(api_route.methods or set()):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                found.append((f"{method} {path}", api_route))
    return found


# --------------------------------------------------------------------------- #
# Structural: no route escapes the checks by accident
# --------------------------------------------------------------------------- #


def test_every_route_either_enforces_a_capability_or_is_exempt(app: Any) -> None:
    """The check that makes the single-point enforcement safe.

    A route added with `Depends(get_principal)` and no capability would pass
    RBAC *and* the forced-password-change gate, silently. This is what turns
    that into a failing test.
    """
    offenders: list[str] = []
    for label, route in _routes(app):
        names = _dependency_names(route.dependant)
        if CAPABILITY_DEPENDENCY in names:
            continue
        if label in CAPABILITY_EXEMPT:
            continue
        offenders.append(label)

    assert not offenders, (
        "these routes neither enforce a capability nor appear in "
        "CAPABILITY_EXEMPT, so they bypass both the RBAC matrix and the "
        f"forced-password-change gate: {offenders}.\n"
        "Add require_capability(...) to them, or add them to CAPABILITY_EXEMPT "
        "with the reason."
    )


def test_the_traversal_finds_every_route_in_the_openapi_document(app: Any) -> None:
    """Guards the guard.

    Every assertion in this file is of the form "no route does X". If `_walk`
    ever stopped finding routes - a FastAPI change to how routers are
    included, which is exactly what happened at 0.162 - all of them would pass
    while checking almost nothing.

    So the traversal is cross-checked against the OpenAPI document, which
    FastAPI builds by its own independent route resolution. The two must agree
    on every path. `/healthz` and `/readyz` are the only exceptions, because
    they are registered with `include_in_schema=False` and so are deliberately
    absent from the document.
    """
    documented = set(app.openapi()["paths"])
    traversed = {label.split(" ", 1)[1] for label, _ in _routes(app)}

    assert documented - traversed == set(), (
        f"the traversal missed routes that FastAPI documents: {sorted(documented - traversed)}"
    )
    assert traversed - documented == {"/healthz", "/readyz"}, (
        "unexpected undocumented routes: "
        f"{sorted(traversed - documented - {'/healthz', '/readyz'})}"
    )
    # A floor, so a traversal that collapsed to a handful cannot pass.
    assert len(traversed) >= 25, f"only {len(traversed)} routes found; the traversal is broken"


def test_the_exempt_list_has_no_stale_entries(app: Any) -> None:
    """An exemption for a route that no longer exists is a lie in a security list.

    It also hides the real risk: if a path is renamed, its exemption silently
    stops matching and the test would start demanding a capability on the new
    name - which is correct - while the old entry sits there implying coverage
    of something.
    """
    live = {label for label, _ in _routes(app)}
    stale = sorted(set(CAPABILITY_EXEMPT) - live)
    assert not stale, f"CAPABILITY_EXEMPT names routes that do not exist: {stale}"


def test_no_exempt_route_enforces_a_capability(app: Any) -> None:
    """A route doing both is a contradiction worth catching.

    If an exempt route grows a capability dependency, the exemption is wrong
    and should be deleted rather than left as a second, contradictory statement
    about the same route.
    """
    confused = [
        label
        for label, route in _routes(app)
        if label in CAPABILITY_EXEMPT
        and CAPABILITY_DEPENDENCY in _dependency_names(route.dependant)
    ]
    assert not confused, (
        f"these routes enforce a capability but are also listed exempt: {confused}. "
        "Remove them from CAPABILITY_EXEMPT."
    )


def test_the_two_forced_change_escape_hatches_are_the_only_authenticated_exemptions(
    app: Any,
) -> None:
    """Exactly two routes may be authenticated without a capability.

    `/auth/me` and `/auth/password`. Any third would be a route an account
    owing a password change could reach, which is the restriction this whole
    mechanism exists to impose. Detected by looking for `get_principal` in the
    tree of an exempt route.
    """
    authenticated_exemptions = sorted(
        label
        for label, route in _routes(app)
        if label in CAPABILITY_EXEMPT
        and get_principal.__qualname__ in _dependency_names(route.dependant)
    )
    assert authenticated_exemptions == [
        "GET /api/v1/auth/me",
        "POST /api/v1/auth/password",
    ], (
        "the set of routes reachable by an account owing a password change has "
        f"changed: {authenticated_exemptions}"
    )


def test_the_user_management_routes_are_all_capability_guarded(app: Any) -> None:
    """Named explicitly, so the new routes cannot regress into the exempt list."""
    expected = {
        "POST /api/v1/users",
        "GET /api/v1/users",
        "POST /api/v1/users/{user_id}:disable",
        "POST /api/v1/users/{user_id}:enable",
        "POST /api/v1/users/{user_id}:role",
        "POST /api/v1/users/{user_id}:reset-password",
    }
    by_label = dict(_routes(app))
    for label in sorted(expected):
        assert label in by_label, f"{label} is not registered"
        assert CAPABILITY_DEPENDENCY in _dependency_names(by_label[label].dependant), (
            f"{label} does not enforce a capability"
        )


# --------------------------------------------------------------------------- #
# The gate itself, called directly
# --------------------------------------------------------------------------- #


def _principal(role: Role, *, must_change: bool) -> Principal:
    return Principal(
        user_id="11111111-2222-3333-4444-555555555555",
        email="someone@example.invalid",
        role=role,
        must_change_password=must_change,
    )


def test_a_capable_principal_passes_when_no_change_is_owed() -> None:
    dependency = require_capability(Capability.DEVICE_READ)
    principal = _principal(Role.IT_ADMIN, must_change=False)
    assert dependency(principal) is principal


def test_a_capable_principal_is_refused_while_a_change_is_owed() -> None:
    """The enforcement, in one assertion.

    An `it_admin` holds `device_read`, so RBAC would allow this. The forced
    change is what refuses it, with a distinct code the dashboard can route on.
    """
    dependency = require_capability(Capability.DEVICE_READ)
    with pytest.raises(problems.ProblemError) as raised:
        dependency(_principal(Role.IT_ADMIN, must_change=True))

    assert raised.value.code == "password_change_required"
    assert raised.value.status == 403


def test_the_capability_check_runs_before_the_forced_change_check() -> None:
    """Ordering, and it is a disclosure control rather than a preference.

    An `auditor` owing a password change asks for `device_revoke`, which the
    auditor role does not hold. They must get `forbidden`, not
    `password_change_required` - otherwise the forced-change state becomes an
    oracle for probing which capabilities a role holds, answering "you would
    be allowed if only you changed your password".
    """
    dependency = require_capability(Capability.DEVICE_REVOKE)
    with pytest.raises(problems.ProblemError) as raised:
        dependency(_principal(Role.AUDITOR, must_change=True))

    assert raised.value.code == "forbidden"
    assert raised.value.status == 403


@pytest.mark.parametrize("role", list(Role))
def test_no_role_can_act_while_owing_a_password_change(role: Role) -> None:
    """Every role, over every capability it actually holds.

    Parametrised across the whole matrix rather than spot-checked, so a role
    added later is covered the moment it appears in `Role`.
    """
    from ubuntuguard.security.rbac import capabilities_for

    held = capabilities_for(role)
    assert held, f"{role.value} holds no capabilities; the matrix is wrong"

    for capability in sorted(held, key=lambda item: item.value):
        dependency = require_capability(capability)
        with pytest.raises(problems.ProblemError) as raised:
            dependency(_principal(role, must_change=True))
        assert raised.value.code == "password_change_required", (
            f"{role.value} was not stopped on {capability.value}"
        )


def test_the_refusal_names_no_credential() -> None:
    """The detail reaches a browser, so it must carry nothing sensitive."""
    dependency = require_capability(Capability.DEVICE_READ)
    with pytest.raises(problems.ProblemError) as raised:
        dependency(_principal(Role.IT_ADMIN, must_change=True))

    rendered = f"{raised.value.title} {raised.value.detail}"
    assert "password" in rendered.lower(), "the message does not say what is wrong"
    for leak in ("hash", "argon2", "$", "token"):
        assert leak not in rendered.lower(), f"the refusal detail mentions {leak!r}"


# --------------------------------------------------------------------------- #
# The detection mechanism, proved against a deliberately broken app
# --------------------------------------------------------------------------- #


def test_the_coverage_check_actually_catches_an_unguarded_route() -> None:
    """Proves the mechanism, rather than trusting that it works.

    Builds a throwaway app with one route that is authenticated but carries no
    capability - the exact mistake this file exists to catch - and requires the
    traversal to find it. Without this, a bug in `_walk` or in the dependency
    inspection would make every assertion above pass silently.

    The equivalent of the parser self-tests in `test_nginx_config.py`: a test
    whose only job is to fail if the detector cannot detect.
    """
    from fastapi import APIRouter, Depends, FastAPI

    rogue = APIRouter()

    @rogue.get("/secret-fleet-data")
    def _rogue(principal: Principal = Depends(get_principal)) -> dict[str, str]:
        return {"data": "should have required a capability"}

    broken = FastAPI()
    broken.include_router(rogue, prefix="/api/v1")

    labels = [label for label, _ in _routes(broken)]
    assert "GET /api/v1/secret-fleet-data" in labels, (
        "the traversal did not even find the rogue route, so the coverage test "
        "above is not checking what it claims to"
    )

    unguarded = [
        label
        for label, route in _routes(broken)
        if CAPABILITY_DEPENDENCY not in _dependency_names(route.dependant)
    ]
    assert "GET /api/v1/secret-fleet-data" in unguarded, (
        "an authenticated route with no capability was not reported as unguarded"
    )


def test_the_coverage_check_accepts_a_properly_guarded_route() -> None:
    """The other half: a correctly guarded route must not be reported.

    Otherwise the test above could pass by reporting everything, and the real
    coverage test would be unsatisfiable.
    """
    from fastapi import APIRouter, Depends, FastAPI

    proper = APIRouter()

    @proper.get("/fleet-data")
    def _proper(
        principal: Principal = Depends(require_capability(Capability.DEVICE_READ)),
    ) -> dict[str, str]:
        return {"data": "guarded"}

    fine = FastAPI()
    fine.include_router(proper, prefix="/api/v1")

    unguarded = [
        label
        for label, route in _routes(fine)
        if CAPABILITY_DEPENDENCY not in _dependency_names(route.dependant)
    ]
    assert unguarded == [], f"a guarded route was wrongly reported: {unguarded}"


def test_a_principal_defaults_to_owing_nothing() -> None:
    """Constructing a Principal without the flag must not lock the caller out.

    Several existing tests and the unconfigured resolver build principals
    positionally. A default of True would have turned every one of those into a
    403 and made this change look like a widespread regression.
    """
    principal = Principal(user_id="x", email="y@example.invalid", role=Role.SUPER_ADMIN)
    assert principal.must_change_password is False
