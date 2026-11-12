"""Version 1 router assembly.

The two authentication planes are mounted side by side but never mix: admin
routes require a bearer token, device routes require an mTLS client
certificate, and no route accepts both.
"""

from __future__ import annotations

from fastapi import APIRouter

from ubuntuguard import problems
from ubuntuguard.api.v1 import audit_log, auth, devices, enrollment, users


def build_router() -> APIRouter:
    # Every route can return a problem document, so the model is declared once
    # here. That also puts `Problem` into the OpenAPI components, which is what
    # gives the generated TypeScript client a typed error to work with.
    router = APIRouter(responses=problems.ERROR_RESPONSES)

    # --- Admin plane: bearer token, capability-checked ------------------- #
    router.include_router(auth.router)
    router.include_router(users.router)
    router.include_router(enrollment.admin_router)
    router.include_router(devices.admin_router)
    router.include_router(audit_log.router)

    # --- Device plane --------------------------------------------------- #
    # /enroll is unauthenticated by necessity: a device has no identity until
    # it completes this call, and the one-time token is its whole credential.
    router.include_router(enrollment.device_router)
    # Everything else on this plane requires the mTLS client certificate.
    router.include_router(devices.device_router)

    return router
