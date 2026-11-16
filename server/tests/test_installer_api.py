"""The public installer routes.

These are the only two routes in the system that require no credential of any
kind, so what they expose and what they refuse both matter more than usual.
The tests below are grouped by the claim they defend:

- the routes are genuinely public, and the artifact genuinely holds no secret;
- downloading grants nothing - enrollment still needs an administrator's
  single-use token;
- the published digest describes the bytes actually served;
- a missing or malformed deployment reports itself rather than crashing, and a
  manifest cannot be used to read a file outside the installer directory;
- the compatibility claim stays honest.

No database is needed. The installer routes do not touch one, which is itself
worth asserting: a public endpoint that opened a database connection would be
an unauthenticated path to the connection pool.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ubuntuguard.config import Settings
from ubuntuguard.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = REPO_ROOT / "agent" / "packaging" / "build_installer.py"

INFO_PATH = "/api/v1/installer"
DOWNLOAD_PATH = "/api/v1/installer/download"


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    """The agent's installer builder, imported by path.

    The server does not depend on the agent and must not: they are separate
    distributions with separate virtualenvs. This import exists only so the
    tests can produce a REAL artifact to serve, rather than a fixture that
    could drift from what the builder actually emits.
    """
    if not BUILDER_PATH.exists():
        pytest.skip(f"{BUILDER_PATH} is missing; is the agent checked out?")
    spec = importlib.util.spec_from_file_location("ug_build_installer_srv", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def published(builder: ModuleType, tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("installer")
    publish(builder, directory)
    return directory


def publish(builder: ModuleType, directory: Path) -> None:
    """Build a real installer into `directory`.

    A helper rather than an inline call at each site: several tests then break
    the result on purpose, and the setup line is noise in every one of them.
    """
    assert (
        builder.main(["--server-url", "https://mdm.example.com", "--output-dir", str(directory)])
        == 0
    )


def client_for(installer_dir: Path | None) -> TestClient:
    settings = Settings(_env_file=None, installer_dir=installer_dir)  # type: ignore[call-arg]
    return TestClient(create_app(settings))


@pytest.fixture
def client(published: Path) -> Any:
    with client_for(published) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# Public, and safe to be
# --------------------------------------------------------------------------- #


def test_the_metadata_route_needs_no_credential(client: TestClient) -> None:
    """An employee reaching the enrollment page has none to offer."""
    response = client.get(INFO_PATH)
    assert response.status_code == 200
    assert "authorization" not in {key.lower() for key in response.request.headers}


def test_the_download_route_needs_no_credential(client: TestClient) -> None:
    response = client.get(DOWNLOAD_PATH)
    assert response.status_code == 200
    assert response.content


def test_a_bearer_token_is_neither_required_nor_consulted(client: TestClient) -> None:
    """A nonsense token must not change the outcome either way.

    If these routes ever acquired an auth dependency, a garbage token would
    start producing 401 and this would fail - which is the point. A public
    route that quietly became authenticated would break the enrollment page for
    every employee.
    """
    anonymous = client.get(INFO_PATH)
    with_garbage = client.get(INFO_PATH, headers={"Authorization": "Bearer not-a-real-token"})
    assert anonymous.status_code == with_garbage.status_code == 200
    assert anonymous.json() == with_garbage.json()


def test_the_served_installer_contains_no_private_key(client: TestClient) -> None:
    """Asserted on the bytes the server actually hands out.

    `agent/tests/test_installer_build.py` asserts this of the build; this
    asserts it of the download, because the two could differ if the published
    directory contained something other than a freshly built artifact.
    """
    body = client.get(DOWNLOAD_PATH).content
    assert not re.search(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", body)


def test_the_served_installer_contains_no_enrollment_token(client: TestClient) -> None:
    """An installer carrying a shared credential would turn one leaked download
    into unlimited enrollments."""
    body = client.get(DOWNLOAD_PATH).content.decode("utf-8", errors="replace")
    header = body.split("__UBUNTUGUARD_PAYLOAD__")[0]
    suspicious = [
        run
        for run in re.findall(r"[A-Za-z0-9_-]{40,}", header)
        if sum(character.isalnum() for character in run) >= 30
        and not re.fullmatch(r"[0-9a-f]{64}", run)
    ]
    assert not suspicious, f"credential-shaped strings in the served installer: {suspicious}"


def test_downloading_grants_no_access_to_anything(client: TestClient) -> None:
    """The installer is not a credential, and this proves the obvious directly.

    Having fetched it, the same client still cannot read the device list, mint a
    token, or reach any admin route. Enrollment still requires an
    administrator's single-use token, which is the control that was never
    weakened here.
    """
    assert client.get(DOWNLOAD_PATH).status_code == 200

    # Refused, every one. The exact code is 503 rather than 401 on this
    # fixture, because these settings configure no database and `get_session`
    # reports that before authentication is reached. Either way the request
    # carries no credential and gets no data, which is what is being asserted
    # here; `test_rbac.py` and `test_api_integration.py` cover which refusal
    # each route gives when a database is present.
    for path in ("/api/v1/devices", "/api/v1/enrollment-tokens", "/api/v1/users"):
        response = client.get(path)
        assert response.status_code >= 400, f"{path} was reachable after a download"
        assert response.status_code in {401, 503}, f"{path} -> {response.status_code}"

    minted = client.post("/api/v1/enrollment-tokens", json={"ttl_seconds": 3600})
    assert minted.status_code >= 400
    assert "enrollment_token" not in minted.text

    # The contrast is the point: the installer routes work without a database,
    # and the admin plane does not work without a credential.
    assert client.get(INFO_PATH).status_code == 200


def test_the_installer_routes_do_not_touch_the_database(published: Path) -> None:
    """A public endpoint that opened a connection would be an unauthenticated
    path to the pool.

    These settings configure no database at all, so any attempt would surface
    as the 503 `get_session` raises. Both routes return 200.
    """
    with client_for(published) as client:
        assert client.get(INFO_PATH).status_code == 200
        assert client.get(DOWNLOAD_PATH).status_code == 200


# --------------------------------------------------------------------------- #
# The digest describes what is served
# --------------------------------------------------------------------------- #


def test_the_published_digest_is_the_digest_of_the_served_bytes(client: TestClient) -> None:
    """The employee is told to compare these, so they must agree.

    Recomputed by the server on every request rather than read from the
    manifest. A manifest that disagreed with its file would have the server
    publishing a digest for bytes it is not serving, which is worse than
    publishing none: it trains people to ignore a real mismatch.
    """
    info = client.get(INFO_PATH).json()
    body = client.get(DOWNLOAD_PATH).content

    assert hashlib.sha256(body).hexdigest() == info["sha256"]
    assert len(body) == info["size_bytes"]


def test_a_manifest_digest_that_disagrees_with_the_file_is_ignored(
    builder: ModuleType, tmp_path: Path
) -> None:
    """The server's own computation wins.

    Staged by rewriting the manifest's digest to a plausible but wrong value.
    The response must carry the real one.
    """
    publish(builder, tmp_path)

    manifest_path = tmp_path / builder.MANIFEST_FILENAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sha256"] = "0" * 64
    manifest["size_bytes"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with client_for(tmp_path) as client:
        info = client.get(INFO_PATH).json()
        body = client.get(DOWNLOAD_PATH).content

    assert info["sha256"] != "0" * 64
    assert info["sha256"] == hashlib.sha256(body).hexdigest()
    assert info["size_bytes"] == len(body)


def test_the_download_carries_the_digest_in_a_header(client: TestClient) -> None:
    """So a scripted download does not need a second request.

    Deliberately under a vendor name rather than `Digest` or `Repr-Digest`:
    those are specified to carry base64 with a `sha-256=:…:` wrapper, and a
    bare hex value under one of those names would be wrong in a way a generic
    client could act on.
    """
    response = client.get(DOWNLOAD_PATH)
    digest = response.headers["X-UbuntuGuard-SHA256"]
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert digest == hashlib.sha256(response.content).hexdigest()


def test_the_download_is_served_as_an_attachment(client: TestClient) -> None:
    """The installer must be run from a file: the agent is embedded in it and a
    pipe cannot be read twice. A browser rendering 150 KB of base64 in a tab is
    also not the intended experience."""
    response = client.get(DOWNLOAD_PATH)
    assert response.headers["content-type"].startswith("application/x-shellscript")
    assert "attachment" in response.headers["content-disposition"]
    assert "ubuntuguard-agent-installer.sh" in response.headers["content-disposition"]


def test_the_download_is_not_cached(client: TestClient) -> None:
    """An upgrade must not be defeated by a stale cached build."""
    assert "no-store" in client.get(DOWNLOAD_PATH).headers.get("cache-control", "")


# --------------------------------------------------------------------------- #
# Deployment states, reported rather than crashed on
# --------------------------------------------------------------------------- #


def test_an_unpublished_installer_reports_itself_and_says_how_to_fix_it() -> None:
    """503 rather than 404.

    404 reads as "no such endpoint" and sends an administrator to look at their
    routing. This is a deployment state and is fixed by building an installer,
    so the message names the builder and the setting.
    """
    with client_for(None) as client:
        for path in (INFO_PATH, DOWNLOAD_PATH):
            response = client.get(path)
            assert response.status_code == 503, path
            body = response.json()
            assert body["code"] == "service_unavailable"
            assert "build_installer.py" in body["detail"]
            assert "UBUNTUGUARD_INSTALLER_DIR" in body["detail"]


def test_a_missing_installer_directory_is_reported(tmp_path: Path) -> None:
    with client_for(tmp_path / "does-not-exist") as client:
        assert client.get(INFO_PATH).status_code == 503


def test_a_missing_manifest_is_reported(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        response = client.get(INFO_PATH)
        assert response.status_code == 503
        assert "manifest" in response.json()["detail"].lower()


def test_an_unparseable_manifest_is_reported(tmp_path: Path) -> None:
    (tmp_path / "installer-manifest.json").write_text("{not json", encoding="utf-8")
    with client_for(tmp_path) as client:
        response = client.get(INFO_PATH)
        assert response.status_code == 503
        assert "json" in response.json()["detail"].lower()


def test_a_manifest_with_an_unknown_schema_is_refused(tmp_path: Path) -> None:
    """Refused rather than read optimistically.

    Reading fields that may have moved is how a server starts publishing a
    digest for the wrong file.
    """
    (tmp_path / "installer-manifest.json").write_text(
        json.dumps({"schema": "ubuntuguard.installer.v99", "filename": "x"}), encoding="utf-8"
    )
    with client_for(tmp_path) as client:
        response = client.get(INFO_PATH)
        assert response.status_code == 503
        assert "schema" in response.json()["detail"].lower()


def test_a_manifest_naming_a_missing_file_is_reported(builder: ModuleType, tmp_path: Path) -> None:
    publish(builder, tmp_path)
    (tmp_path / builder.INSTALLER_FILENAME).unlink()

    with client_for(tmp_path) as client:
        response = client.get(INFO_PATH)
        assert response.status_code == 503
        assert "missing" in response.json()["detail"].lower()


def test_an_empty_installer_is_refused(builder: ModuleType, tmp_path: Path) -> None:
    """A truncated deploy must not be served as a valid download."""
    publish(builder, tmp_path)
    (tmp_path / builder.INSTALLER_FILENAME).write_text("", encoding="utf-8")

    with client_for(tmp_path) as client:
        assert client.get(INFO_PATH).status_code == 503


# --------------------------------------------------------------------------- #
# Path handling
# --------------------------------------------------------------------------- #


def test_no_filename_is_ever_taken_from_the_request(client: TestClient) -> None:
    """The control that matters most: there is no parameter to steer.

    The filename comes from a manifest an administrator placed. These are the
    shapes a traversal attempt would take, and all of them must miss the route
    entirely rather than be sanitised - a 404 or 405 here means there is no
    such endpoint to attack.
    """
    for attempt in (
        "/api/v1/installer/download/../../../../etc/passwd",
        "/api/v1/installer/../../../etc/passwd",
        "/api/v1/installer/download/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ):
        response = client.get(attempt)
        assert response.status_code in {404, 405}, f"{attempt} -> {response.status_code}"
        assert b"root:" not in response.content


@pytest.mark.parametrize(
    "filename",
    [
        "../../../../etc/passwd",
        "/etc/passwd",
        "subdir/installer.sh",
        "..",
    ],
)
def test_a_manifest_cannot_name_a_file_outside_the_directory(
    builder: ModuleType, tmp_path: Path, filename: str
) -> None:
    """Defence in depth against a mistaken or hostile manifest.

    No client can reach this, because no request supplies a filename. But a
    manifest is a file on disk, and one naming `../../../../etc/shadow` must be
    refused rather than served.
    """
    publish(builder, tmp_path)

    manifest_path = tmp_path / builder.MANIFEST_FILENAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["filename"] = filename
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with client_for(tmp_path) as client:
        for path in (INFO_PATH, DOWNLOAD_PATH):
            response = client.get(path)
            assert response.status_code == 503, f"{filename} via {path}"
            assert b"root:" not in response.content


def test_a_symlink_out_of_the_directory_is_refused(builder: ModuleType, tmp_path: Path) -> None:
    """`resolve()` follows symlinks, so a link planted in the installer
    directory cannot be used to serve a key from elsewhere."""
    published = tmp_path / "published"
    published.mkdir()
    publish(builder, published)

    secret = tmp_path / "ca.key"
    secret.write_text("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")

    (published / builder.INSTALLER_FILENAME).unlink()
    (published / builder.INSTALLER_FILENAME).symlink_to(secret)

    with client_for(published) as client:
        response = client.get(DOWNLOAD_PATH)
        assert response.status_code == 503
        assert b"PRIVATE KEY" not in response.content


# --------------------------------------------------------------------------- #
# Honesty of the compatibility claim
# --------------------------------------------------------------------------- #


def test_target_and_validated_releases_are_reported_separately(client: TestClient) -> None:
    """Two different claims, and they must not be collapsed into one.

    The agent makes the same distinction in `osadapter.ubuntu`
    (`is_supported` vs `is_validated_release`). Reporting a single "supported"
    list would be the compatibility claim the brief forbids, so the enrollment
    page is given both and renders the difference.
    """
    info = client.get(INFO_PATH).json()
    assert info["target_os_versions"] == ["22.04", "24.04"]
    assert info["validated_os_versions"] == [], (
        "a release may appear here only once the agent has actually been run on it"
    )
    assert info["supported_os_id"] == "ubuntu"


def test_the_metadata_names_the_server_the_installer_points_at(client: TestClient) -> None:
    """So an employee can confirm they downloaded their own company's agent."""
    info = client.get(INFO_PATH).json()
    assert info["server_url"] == "https://mdm.example.com"


def test_the_metadata_names_the_python_floor(client: TestClient) -> None:
    info = client.get(INFO_PATH).json()
    assert info["minimum_python"] == "3.10"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_installer_dir_is_a_recognised_setting() -> None:
    """The typo check in `_reject_unknown_prefixed_env_vars` works by field
    name, so a new setting must actually be declared or the variable that sets
    it stops the server from booting."""
    assert "installer_dir" in Settings.model_fields


def test_installer_dir_defaults_to_unset() -> None:
    """Publishing nothing is the default. A server that served an installer
    nobody built would be serving whatever happened to be in a directory."""
    assert Settings(_env_file=None).installer_dir is None  # type: ignore[call-arg]


def test_a_production_configuration_does_not_require_an_installer() -> None:
    """Deliberately not in the production-required list.

    A deployment may reasonably distribute the agent by other means - an
    internal apt repository, or configuration management - and refusing to
    start without a published installer would force the download route on
    someone who does not want it.
    """
    with pytest.raises(ValueError) as raised:
        Settings(_env_file=None, environment="prod")  # type: ignore[call-arg]
    assert "installer_dir" not in str(raised.value)
