"""Employee-facing agent installer: metadata and download.

Two routes, both unauthenticated, and that is the whole design question here so
it is answered first.

**Why unauthenticated.** An employee arriving at the enrollment page has no
UbuntuGuard credential and is not an administrator. Gating the download would
mean issuing them one, which is a second thing for an administrator to hand
over and a second credential to manage, in exchange for protecting a file that
holds no secret.

**Why that is safe.** The artifact contains no private key, no certificate and
no enrollment token - `agent/tests/test_installer_build.py` asserts the absence
of all three from the built bytes rather than from the file list. What it does
carry is the API's own URL and, where the server uses an internal CA, that CA's
public certificate. Both are already disclosed by any TLS handshake with this
server.

**What still gates enrollment.** Downloading and installing the agent grants
nothing. The device gets an identity only by presenting a single-use,
time-limited token an administrator minted, and that path is untouched by this
module. An employee with the installer and no token has a service that idles.

Rate limiting is nginx's job (`deploy/nginx/`), alongside `/enroll` and
`/auth/login`, for the same reason: it bounds the work before it reaches Python.

The digest is recomputed from the file on every request rather than read from
the manifest. A manifest that disagreed with the file it describes would have
the server publishing a digest employees are told to compare against, for bytes
it is not serving - which is worse than publishing none, because it would
train them to ignore a real mismatch.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse

from ubuntuguard import problems
from ubuntuguard.api.deps import get_settings
from ubuntuguard.config import Settings
from ubuntuguard.schemas import DebPackageInfoResponse, InstallerInfoResponse

router = APIRouter(prefix="/installer", tags=["installer"])

#: The manifest the builder writes beside the artifact.
MANIFEST_FILENAME = "installer-manifest.json"

#: Schema the builder stamps into the manifest. Refused rather than guessed if
#: it does not match: reading fields that may have moved is how a server starts
#: publishing a digest for the wrong file.
MANIFEST_SCHEMA = "ubuntuguard.installer.v1"

#: The `.deb`'s manifest and schema, written by build_deb.py into the same
#: directory. A separate manifest rather than a second section of one file, so
#: that publishing either artifact is independent: a server with only the
#: script answers 503 on the `.deb` routes and keeps serving the script.
DEB_MANIFEST_FILENAME = "deb-manifest.json"
DEB_MANIFEST_SCHEMA = "ubuntuguard.deb.v1"

#: Served as a download rather than rendered. A shell script with a text content
#: type is something a browser may display, and an employee reading 150 KB of
#: base64 in a tab is not the intended experience.
INSTALLER_MEDIA_TYPE = "application/x-shellscript"

#: The media type dpkg, apt and GNOME Software recognise. Getting this wrong is
#: not cosmetic: a `.deb` served as `application/octet-stream` is saved as an
#: unknown file, and double-clicking it does nothing - which is the entire
#: feature.
DEB_MEDIA_TYPE = "application/vnd.debian.binary-package"

#: Upper bound on the artifact, as a sanity check before it is hashed on a
#: request. The real one is ~160 KB; 32 MB is loose enough for a future build
#: that vendors wheels and tight enough that a misconfigured `installer_dir`
#: pointing at something enormous is refused rather than read.
MAX_INSTALLER_BYTES = 32 * 1024 * 1024


def _unavailable(detail: str) -> problems.ProblemError:
    """503 rather than 404.

    The distinction is worth the keystrokes: 404 says "no such endpoint", which
    sends an administrator looking at their routing. These failures are all
    "this server has no installer published", which is a deployment state and is
    fixed by building one.
    """
    return problems.service_unavailable(detail)


def _resolve_installer_dir(settings: Settings) -> Path:
    if settings.installer_dir is None:
        raise _unavailable(
            "No agent installer is published on this server. Build one with "
            "agent/packaging/build_installer.py and set UBUNTUGUARD_INSTALLER_DIR."
        )
    directory = settings.installer_dir
    if not directory.is_dir():
        raise _unavailable("The configured installer directory does not exist on this server.")
    return directory


def _read_manifest(
    directory: Path,
    filename: str = MANIFEST_FILENAME,
    schema: str = MANIFEST_SCHEMA,
) -> dict[str, Any]:
    """Read and validate one of the two manifests.

    Parameterised rather than duplicated for the `.deb`, so there is one
    description of what a trustworthy manifest looks like. The defaults keep
    the script installer's call sites unchanged.
    """
    path = directory / filename
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise _unavailable(
            "The agent installer manifest could not be read on this server."
        ) from exc

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _unavailable(
            "The agent installer manifest on this server is not valid JSON."
        ) from exc

    if not isinstance(manifest, dict):
        raise _unavailable("The agent installer manifest on this server is malformed.")
    if manifest.get("schema") != schema:
        raise _unavailable(
            "The agent installer manifest on this server has an unrecognised schema."
        )
    return manifest


def _resolve_artifact(directory: Path, manifest: dict[str, Any]) -> Path:
    """Locate the artifact, refusing anything that escapes the directory.

    The filename comes from the manifest, which is a file an administrator
    placed - not from the request, which is the control that matters most here:
    there is no parameter anywhere in this module that a caller can steer, so
    there is no path-traversal surface to get wrong.

    The containment check below is therefore defence in depth against a
    mistaken or hostile manifest rather than against a client. `resolve()`
    collapses `..` and follows symlinks, so a manifest naming `../../../../etc/
    shadow`, or a symlink in the installer directory pointing at a private key,
    is refused rather than served.
    """
    filename = manifest.get("filename")
    if not isinstance(filename, str) or not filename:
        raise _unavailable("The agent installer manifest does not name a file.")

    candidate = (directory / filename).resolve()
    root = directory.resolve()
    if root != candidate.parent:
        raise _unavailable(
            "The agent installer manifest names a file outside the installer directory."
        )
    if not candidate.is_file():
        raise _unavailable("The agent installer named by the manifest is missing.")

    size = candidate.stat().st_size
    if size == 0:
        raise _unavailable("The published agent installer is empty.")
    if size > MAX_INSTALLER_BYTES:
        raise _unavailable("The published agent installer is implausibly large.")
    return candidate


def _digest(path: Path) -> tuple[str, int]:
    """SHA-256 and size of the bytes that will actually be served."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _built_at(manifest: dict[str, Any]) -> dt.datetime:
    raw = manifest.get("built_at")
    if not isinstance(raw, str):
        raise _unavailable("The agent installer manifest has no build timestamp.")
    try:
        return dt.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise _unavailable(
            "The agent installer manifest has an unparseable build timestamp."
        ) from exc


def _string_list(manifest: dict[str, Any], key: str) -> list[str]:
    value = manifest.get(key)
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        raise _unavailable(f"The agent installer manifest field {key!r} is malformed.")
    return list(value)


def _string(manifest: dict[str, Any], key: str) -> str:
    value = manifest.get(key)
    if not isinstance(value, str) or not value:
        raise _unavailable(f"The agent installer manifest field {key!r} is missing.")
    return value


def _int(manifest: dict[str, Any], key: str) -> int:
    value = manifest.get(key)
    # `bool` is a subclass of `int`, and a manifest with `true` where a size
    # belongs is malformed rather than a size of one.
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _unavailable(f"The agent installer manifest field {key!r} is malformed.")
    return value


@router.get("", response_model=InstallerInfoResponse)
def installer_info(
    settings: Settings = Depends(get_settings),
) -> InstallerInfoResponse:
    """What the enrollment page needs to describe the download.

    Unauthenticated: see the module docstring. Nothing here is a secret, and
    the page that renders it is reached by someone with no credential.
    """
    directory = _resolve_installer_dir(settings)
    manifest = _read_manifest(directory)
    artifact = _resolve_artifact(directory, manifest)

    # Recomputed, not trusted. See the module docstring.
    sha256, size = _digest(artifact)

    return InstallerInfoResponse(
        agent_version=_string(manifest, "agent_version"),
        filename=artifact.name,
        sha256=sha256,
        size_bytes=size,
        built_at=_built_at(manifest),
        server_url=_string(manifest, "server_url"),
        minimum_python=_string(manifest, "minimum_python"),
        supported_os_id=_string(manifest, "supported_os_id"),
        supported_arch=_string_list(manifest, "supported_arch"),
        target_os_versions=_string_list(manifest, "target_os_versions"),
        validated_os_versions=_string_list(manifest, "validated_os_versions"),
    )


@router.get(
    "/download",
    response_class=FileResponse,
    responses={
        200: {
            "content": {INSTALLER_MEDIA_TYPE: {}},
            "description": "The agent installer shell script.",
        },
        503: {"description": "No installer is published on this server"},
    },
)
def installer_download(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    """Serve the installer.

    `Content-Disposition: attachment` so a browser saves it rather than
    rendering it, and because the installer must be run from a file - the agent
    is embedded in it, and a pipe cannot be read twice.

    The digest is sent in a header as well so a client that scripts the
    download has it without a second request. It is recomputed here rather than
    taken from the manifest, for the same reason as above.
    """
    directory = _resolve_installer_dir(settings)
    manifest = _read_manifest(directory)
    artifact = _resolve_artifact(directory, manifest)
    sha256, _ = _digest(artifact)

    return FileResponse(
        path=artifact,
        media_type=INSTALLER_MEDIA_TYPE,
        filename=artifact.name,
        headers={
            # Not a standard header, and named so it cannot be mistaken for
            # one. `Digest`/`Repr-Digest` are specified and carry base64 with a
            # `sha-256=:...:` wrapper; publishing a bare hex value under one of
            # those names would be wrong in a way a generic client could act on.
            "X-UbuntuGuard-SHA256": sha256,
            # The one thing a cache must not do with this is serve a stale
            # build after an upgrade, which is why the global Cache-Control
            # from SecurityHeadersMiddleware (no-store) is left in place.
        },
    )


# --------------------------------------------------------------------------- #
# The `.deb`
# --------------------------------------------------------------------------- #
# A second artifact, published from the same directory and reached by the same
# unauthenticated employee. Everything the module docstring says about why the
# script's routes need no credential applies unchanged: the package carries no
# private key, no certificate and no enrollment token, and
# `agent/tests/test_deb_build.py` asserts their absence from the built bytes.
#
# Why a `.deb` exists at all, given that `docs/04-feature-list.md` recorded the
# employee artifact as a script: the documented objection was that `postinst`
# must not enrol and a package opened from a browser gives the employee no
# terminal in which to type a token, so they would install successfully and
# then be stuck. That is correct about the terminal. It is wrong only in
# concluding that the prompt must be a terminal - the package ships a desktop
# application which prompts in a window after the install. `postinst` still
# does not enrol.


def _deb_artifact(directory: Path, manifest: dict[str, Any]) -> Path:
    """Locate the `.deb`, with the same containment rules as the script.

    `_resolve_artifact` is reused rather than reimplemented, so the refusal to
    serve a file outside the installer directory is one piece of code and not
    two that can disagree.
    """
    return _resolve_artifact(directory, manifest)


def _refuse_a_package_that_claims_to_enrol(manifest: dict[str, Any]) -> bool:
    """Read `enrols_on_install`, and refuse anything but false.

    The field exists so that this property is checked rather than described. A
    package whose manifest claimed it enrolled on install would either be
    lying, in which case the page would mislead every employee who read it, or
    telling the truth, in which case a downloadable artifact is enrolling
    laptops without a token and must not be served at all. Both are deployment
    faults worth a 503.
    """
    value = manifest.get("enrols_on_install")
    if value is not False:
        raise _unavailable(
            "The published package's manifest does not state that installation "
            "leaves the laptop un-enrolled. Refusing to serve it: enrollment "
            "must consume a single-use token issued to a person."
        )
    return False


@router.get("/deb", response_model=DebPackageInfoResponse)
def deb_info(
    settings: Settings = Depends(get_settings),
) -> DebPackageInfoResponse:
    """What the enrollment page needs to offer the double-click download.

    503 when no `.deb` is published, independently of the script: a server that
    has only built the script keeps serving it, and the page can offer one
    artifact without the other.
    """
    directory = _resolve_installer_dir(settings)
    manifest = _read_manifest(directory, DEB_MANIFEST_FILENAME, DEB_MANIFEST_SCHEMA)
    artifact = _deb_artifact(directory, manifest)

    # Recomputed, not trusted. See the module docstring.
    sha256, size = _digest(artifact)

    return DebPackageInfoResponse(
        package=_string(manifest, "package"),
        agent_version=_string(manifest, "agent_version"),
        deb_version=_string(manifest, "deb_version"),
        architecture=_string(manifest, "architecture"),
        filename=artifact.name,
        sha256=sha256,
        size_bytes=size,
        installed_size_kib=_int(manifest, "installed_size_kib"),
        built_at=_built_at(manifest),
        server_url=_string(manifest, "server_url"),
        depends=_string_list(manifest, "depends"),
        bundled_wheels=_string_list(manifest, "bundled_wheels"),
        target_pythons=_string_list(manifest, "target_pythons"),
        enrols_on_install=_refuse_a_package_that_claims_to_enrol(manifest),
    )


@router.get(
    "/deb/download",
    response_class=FileResponse,
    responses={
        200: {
            "content": {DEB_MEDIA_TYPE: {}},
            "description": "The agent Debian package.",
        },
        503: {"description": "No package is published on this server"},
    },
)
def deb_download(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    """Serve the `.deb`.

    The media type is the one dpkg, apt and GNOME Software recognise, which is
    load-bearing rather than cosmetic: served as `application/octet-stream` the
    file is saved as an unknown blob and double-clicking it does nothing, which
    is the one thing this artifact exists to do.

    `Content-Disposition: attachment` for the same reason as the script - the
    file must land on disk to be installed - and the global no-store
    `Cache-Control` is left in place so that an upgrade cannot be masked by a
    cached copy of the previous build.
    """
    directory = _resolve_installer_dir(settings)
    manifest = _read_manifest(directory, DEB_MANIFEST_FILENAME, DEB_MANIFEST_SCHEMA)
    _refuse_a_package_that_claims_to_enrol(manifest)
    artifact = _deb_artifact(directory, manifest)
    sha256, _ = _digest(artifact)

    return FileResponse(
        path=artifact,
        media_type=DEB_MEDIA_TYPE,
        filename=artifact.name,
        headers={"X-UbuntuGuard-SHA256": sha256},
    )
