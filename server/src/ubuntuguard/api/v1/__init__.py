"""Version 1 router assembly.

The two authentication planes are mounted side by side but never mix: admin
routes require a bearer token, device routes require an mTLS client
certificate, and no route accepts both.
"""

from __future__ import annotations

from fastapi import APIRouter

from ubuntuguard import problems
from ubuntuguard.api.v1 import (
    audit_log,
    auth,
    devices,
    employees,
    enrollment,
    incidents,
    installer,
    policies,
    users,
)


def build_router() -> APIRouter:
    # Every route can return a problem document, so the model is declared once
    # here. That also puts `Problem` into the OpenAPI components, which is what
    # gives the generated TypeScript client a typed error to work with.
    router = APIRouter(responses=problems.ERROR_RESPONSES)

    # --- Public: no credential of any kind ------------------------------- #
    # The agent installer and its metadata. An employee reaching the enrollment
    # page has no UbuntuGuard credential and is not an administrator, and the
    # artifact holds no secret - see installer.py for why that is safe and for
    # what still gates enrollment.
    router.include_router(installer.router)

    # --- Admin plane: bearer token, capability-checked ------------------- #
    router.include_router(auth.router)
    router.include_router(users.router)
    router.include_router(employees.router)
    router.include_router(enrollment.admin_router)
    router.include_router(devices.admin_router)
    router.include_router(policies.admin_router)
    # The alerts the server raises about devices. Read and update only; see the
    # module docstring for why there is no POST.
    router.include_router(incidents.router)
    router.include_router(audit_log.router)

    # --- Device plane --------------------------------------------------- #
    # /enroll is unauthenticated by necessity: a device has no identity until
    # it completes this call, and the one-time token is its whole credential.
    router.include_router(enrollment.device_router)
    # Everything else on this plane requires the mTLS client certificate.
    router.include_router(devices.device_router)
    # Policy pull and status reporting. Under /devices/me/ because that is the
    # nginx location which verifies the client certificate and overwrites the
    # identity headers; a device route outside it would not receive them.
    router.include_router(policies.device_router)

    return router
