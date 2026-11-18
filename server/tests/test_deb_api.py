"""The public `.deb` routes.

A second pair of unauthenticated routes beside the script installer's, so they
carry the same burden of proof: they are genuinely public, the artifact
genuinely holds no secret, downloading it grants nothing, and the published
digest describes the bytes actually served.

Two claims are specific to this artifact:

**Installing it does not enrol.** This is the property that made a `.deb`
viable at all. The manifest states it, the server refuses to serve a package
whose manifest says otherwise, and the page renders it. A package that enrolled
on install would be handing out device identities to anyone who could reach the
download.

**It is served as a Debian package.** The media type is load-bearing rather
than cosmetic: served as `application/octet-stream` the file is saved as an
unknown blob and double-clicking it does nothing, which is the single thing
this artifact exists to do.

The packages built here use `--no-vendor`, so no wheels are downloaded and
these tests need no network. The bundled-wheel path is covered in
`agent/tests/test_deb_build.py` and was exercised by hand against Python 3.10
through 3.13.

No database is needed. These routes do not touch one, which is worth asserting:
a public endpoint that opened a database connection would be an unauthenticated
path to the connection pool.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ubuntuguard.config import Settings
from ubuntuguard.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_PACKAGING = REPO_ROOT / "agent" / "packaging"
BUILDER_PATH = AGENT_PACKAGING / "build_deb.py"

INFO_PATH = "/api/v1/installer/deb"
DOWNLOAD_PATH = "/api/v1/installer/deb/download"

DEB_MEDIA_TYPE = "application/vnd.debian.binary-package"

SAMPLE_TOKEN = "T" * 43


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    """The agent's `.deb` builder, imported by path.

    The server does not depend on the agent and must not: they are separate
    distributions with separate virtualenvs. This import exists only so the
    tests can serve a REAL package rather than a fixture that could drift from
    what the builder actually emits.

    `packaging/` goes on `sys.path` because `build_deb` imports the shared URL
    validator and CA reader from `build_installer`.
    """
    if not BUILDER_PATH.exists():
        pytest.skip(f"{BUILDER_PATH} is missing; is the agent checked out?")
    if str(AGENT_PACKAGING) not in sys.path:
        sys.path.insert(0, str(AGENT_PACKAGING))
    spec = importlib.util.spec_from_file_location("ug_build_deb_srv", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def publish(builder: ModuleType, directory: Path) -> None:
    """Build a real package into `directory`.

    `--no-vendor` so the build touches no network. The routes care about the
    manifest and the bytes, not about what is inside the data archive.
    """
    assert (
        builder.main(
            [
                "--server-url",
                "https://mdm.example.com",
                "--output-dir",
                str(directory),
                "--no-vendor",
            ]
        )
        == 0
    )


@pytest.fixture(scope="module")
def published(builder: ModuleType, tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("deb")
    publish(builder, directory)
    return directory


def client_for(installer_dir: Path | None) -> TestClient:
    settings = Settings(_env_file=None, installer_dir=installer_dir)  # type: ignore[call-arg]
    return TestClient(create_app(settings))


@pytest.fixture
def client(published: Path) -> Any:
    with client_for(published) as test_client:
        yield test_client


def _manifest_path(builder: ModuleType, directory: Path) -> Path:
    return directory / builder.MANIFEST_FILENAME


# --------------------------------------------------------------------------- #
# Public, and safe to be
# --------------------------------------------------------------------------- #


def test_the_metadata_route_needs_no_credential(client: TestClient) -> None:
    """An employee reaching the enrollment page has none to offer."""
    response = client.get(INFO_PATH)
    assert response.status_code == 200
    assert response.json()["package"] == "ubuntuguard-agent"


def test_the_download_route_needs_no_credential(client: TestClient) -> None:
    response = client.get(DOWNLOAD_PATH)
    assert response.status_code == 200
    assert response.content.startswith(b"!<arch>\n")


def test_the_served_package_contains_no_private_key(client: TestClient) -> None:
    """The single worst outcome available on a public download.

    Checked against the served bytes, not the builder's file list, because an
    allowlist is only as good as the next edit to it.
    """
    body = client.get(DOWNLOAD_PATH).content
    assert b"-----BEGIN PRIVATE KEY-----" not in body
    assert b"-----BEGIN RSA PRIVATE KEY-----" not in body
    assert b"-----BEGIN EC PRIVATE KEY-----" not in body


def test_the_served_package_contains_no_enrollment_token(client: TestClient) -> None:
    body = client.get(DOWNLOAD_PATH).content
    assert SAMPLE_TOKEN.encode() not in body


def test_the_deb_routes_do_not_touch_the_database(published: Path) -> None:
    """A public endpoint that opened a connection would be an unauthenticated
    path to the pool. Asserted by configuring a database that cannot be
    reached: if either route needed one, these calls would fail."""
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        installer_dir=published,
        database_url="postgresql+psycopg://nobody@127.0.0.1:1/nothing",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get(INFO_PATH).status_code == 200
        assert client.get(DOWNLOAD_PATH).status_code == 200


# --------------------------------------------------------------------------- #
# Installing it does not enrol
# --------------------------------------------------------------------------- #


def test_the_metadata_states_that_installing_does_not_enrol(client: TestClient) -> None:
    """The property the whole design turns on, carried as a field so the page
    renders a fact rather than a sentence someone wrote once."""
    assert client.get(INFO_PATH).json()["enrols_on_install"] is False


def test_a_package_claiming_to_enrol_on_install_is_refused(
    builder: ModuleType, tmp_path: Path
) -> None:
    """Either the manifest is lying, in which case the page would mislead every
    employee who read it, or it is telling the truth, in which case a
    downloadable artifact is enrolling laptops with no token. Both are
    deployment faults, and neither should be served."""
    publish(builder, tmp_path)
    path = _manifest_path(builder, tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["enrols_on_install"] = True
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with client_for(tmp_path) as client:
        for route in (INFO_PATH, DOWNLOAD_PATH):
            response = client.get(route)
            assert response.status_code == 503, route
            assert "enrol" in response.json()["detail"].lower()


def test_a_manifest_missing_the_enrolment_claim_is_refused(
    builder: ModuleType, tmp_path: Path
) -> None:
    """Absent is not the same as false. A manifest from a build that did not
    make the claim at all must not be read as making it."""
    publish(builder, tmp_path)
    path = _manifest_path(builder, tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    del manifest["enrols_on_install"]
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with client_for(tmp_path) as client:
        assert client.get(INFO_PATH).status_code == 503


def test_downloading_grants_no_access_to_anything(client: TestClient) -> None:
    """The package is not a credential, and this proves the obvious directly.

    Having fetched it, the same client still cannot read the device list or
    mint a token. Enrollment still requires an administrator's single-use
    token, which is the control nothing here weakens.
    """
    assert client.get(DOWNLOAD_PATH).status_code == 200
    # The exact code is 503 rather than 401 on this fixture, because these
    # settings configure no database and `get_session` reports that before
    # authentication is reached. Either way the request carries no credential
    # and gets no data, which is what is being asserted; `test_rbac.py` covers
    # which refusal each route gives when a database is present.
    for path in ("/api/v1/devices", "/api/v1/enrollment-tokens", "/api/v1/users"):
        response = client.get(path)
        assert response.status_code >= 400, f"{path} was reachable after a download"
        assert response.status_code in {401, 503}, f"{path} -> {response.status_code}"

    minted = client.post("/api/v1/enrollment-tokens", json={"ttl_seconds": 3600})
    assert minted.status_code >= 400
    assert "enrollment_token" not in minted.text

    # The contrast is the point: the package routes work without a database,
    # and the admin plane does not work without a credential.
    assert client.get(INFO_PATH).status_code == 200


# --------------------------------------------------------------------------- #
# The digest describes the bytes served
# --------------------------------------------------------------------------- #


def test_the_published_digest_is_the_digest_of_the_served_bytes(client: TestClient) -> None:
    body = client.get(DOWNLOAD_PATH).content
    assert client.get(INFO_PATH).json()["sha256"] == hashlib.sha256(body).hexdigest()


def test_a_manifest_digest_that_disagrees_with_the_file_is_ignored(
    builder: ModuleType, tmp_path: Path
) -> None:
    """The server recomputes rather than trusts.

    A manifest that disagreed with its file would have the server publishing a
    digest employees are told to compare against, for bytes it is not serving.
    """
    publish(builder, tmp_path)
    path = _manifest_path(builder, tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["sha256"] = "0" * 64
    manifest["size_bytes"] = 1
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with client_for(tmp_path) as client:
        body = client.get(DOWNLOAD_PATH).content
        reported = client.get(INFO_PATH).json()
        assert reported["sha256"] == hashlib.sha256(body).hexdigest()
        assert reported["sha256"] != "0" * 64
        assert reported["size_bytes"] == len(body)


def test_the_download_carries_the_digest_in_a_header(client: TestClient) -> None:
    response = client.get(DOWNLOAD_PATH)
    assert response.headers["X-UbuntuGuard-SHA256"] == hashlib.sha256(response.content).hexdigest()


# --------------------------------------------------------------------------- #
# It is served as a Debian package
# --------------------------------------------------------------------------- #


def test_the_download_has_the_media_type_dpkg_recognises(client: TestClient) -> None:
    """Served as octet-stream, the file is saved as an unknown blob and
    double-clicking it does nothing -- which is the one thing it exists for."""
    assert client.get(DOWNLOAD_PATH).headers["content-type"] == DEB_MEDIA_TYPE


def test_the_download_is_served_as_an_attachment_named_as_a_deb(
    client: TestClient,
) -> None:
    disposition = client.get(DOWNLOAD_PATH).headers["content-disposition"]
    assert "attachment" in disposition
    assert ".deb" in disposition


def test_the_download_is_not_cached(client: TestClient) -> None:
    """A cached copy of the previous build would mask an upgrade."""
    assert "no-store" in client.get(DOWNLOAD_PATH).headers["cache-control"]


def test_the_metadata_reports_the_dependencies_apt_will_resolve(
    client: TestClient,
) -> None:
    """usbguard arriving automatically is the behaviour the package exists to
    provide, and the page says so rather than leaving the employee to find
    out."""
    depends = client.get(INFO_PATH).json()["depends"]
    assert any("usbguard" in entry for entry in depends)


def test_the_metadata_reports_the_architecture_and_version(client: TestClient) -> None:
    body = client.get(INFO_PATH).json()
    assert body["architecture"] == "amd64"
    # The Debian version is the agent version plus a packaging revision, so a
    # packaging-only fix can supersede an installed package.
    assert body["deb_version"].startswith(body["agent_version"])
    assert body["filename"].endswith("_amd64.deb")


# --------------------------------------------------------------------------- #
# A missing or malformed deployment reports itself
# --------------------------------------------------------------------------- #


def test_an_unpublished_package_reports_itself(tmp_path: Path) -> None:
    """503 and not 404: this is a deployment state, not a routing mistake.

    The directory exists and holds the script's manifest but no package, which
    is the state of a server that has built one artifact and not the other.
    """
    (tmp_path / "installer-manifest.json").write_text("{}", encoding="utf-8")
    with client_for(tmp_path) as client:
        assert client.get(INFO_PATH).status_code == 503


def test_the_script_keeps_working_when_no_package_is_published(tmp_path: Path) -> None:
    """The two artifacts are published independently.

    A server that has only the script must keep serving it rather than having
    both routes fail together, which is why the `.deb` has its own manifest.
    """
    import importlib.util as iu

    installer_builder_path = AGENT_PACKAGING / "build_installer.py"
    spec = iu.spec_from_file_location("ug_bi_only", installer_builder_path)
    assert spec is not None and spec.loader is not None
    module = iu.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    assert (
        module.main(["--server-url", "https://mdm.example.com", "--output-dir", str(tmp_path)]) == 0
    )

    with client_for(tmp_path) as client:
        assert client.get("/api/v1/installer").status_code == 200
        assert client.get(INFO_PATH).status_code == 503


def test_an_unconfigured_installer_directory_is_reported() -> None:
    with client_for(None) as client:
        response = client.get(INFO_PATH)
        assert response.status_code == 503
        assert "installer" in response.json()["detail"].lower()


def test_a_manifest_with_an_unknown_schema_is_refused(tmp_path: Path) -> None:
    """Refused rather than read field by field: a schema this server does not
    know may have moved the fields it is about to publish."""
    (tmp_path / "deb-manifest.json").write_text(
        json.dumps({"schema": "ubuntuguard.deb.v99", "filename": "x"}), encoding="utf-8"
    )
    with client_for(tmp_path) as client:
        assert client.get(INFO_PATH).status_code == 503


def test_an_unparseable_manifest_is_reported(tmp_path: Path) -> None:
    (tmp_path / "deb-manifest.json").write_text("{not json", encoding="utf-8")
    with client_for(tmp_path) as client:
        assert client.get(INFO_PATH).status_code == 503


def test_a_manifest_naming_a_missing_file_is_reported(builder: ModuleType, tmp_path: Path) -> None:
    publish(builder, tmp_path)
    manifest = json.loads(_manifest_path(builder, tmp_path).read_text(encoding="utf-8"))
    (tmp_path / str(manifest["filename"])).unlink()
    with client_for(tmp_path) as client:
        assert client.get(INFO_PATH).status_code == 503


def test_a_manifest_cannot_name_a_file_outside_the_directory(
    builder: ModuleType, tmp_path: Path
) -> None:
    """Defence in depth against a mistaken or hostile manifest.

    No caller can steer the filename -- it comes from a file an administrator
    placed -- but a manifest naming `../../../../etc/shadow` must still be
    refused rather than served.
    """
    publish(builder, tmp_path)
    path = _manifest_path(builder, tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["filename"] = "../../../../etc/passwd"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with client_for(tmp_path) as client:
        for route in (INFO_PATH, DOWNLOAD_PATH):
            assert client.get(route).status_code == 503, route


def test_a_malformed_installed_size_is_reported(builder: ModuleType, tmp_path: Path) -> None:
    """`true` where a size belongs is malformed, not a size of one."""
    publish(builder, tmp_path)
    path = _manifest_path(builder, tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["installed_size_kib"] = True
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with client_for(tmp_path) as client:
        assert client.get(INFO_PATH).status_code == 503
