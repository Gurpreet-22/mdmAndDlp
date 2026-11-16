"""The employee installer builder, checked as an artefact.

The installer is the one file in this repository that is handed to people who
are not administrators, so what it contains matters more than usual. These
tests assert three classes of property:

**It contains no secret.** A private key, a device certificate or an enrollment
token in a published artifact would be a fleet-wide compromise. Asserted
against the built bytes rather than against the file list, because an allowlist
is only as good as the next edit to it.

**It is deterministic.** The digest is published on a web page for employees to
compare against, so two builds of one tree must produce one digest. A digest
that drifted on every rebuild would train everyone to ignore it, which is worse
than publishing none.

**It refuses bad build inputs.** The two that matter are a plaintext server URL
and a `--server-ca` that is actually a private key. Both produce an artifact
that looks fine and is not.

Nothing here needs root, a network or a server.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

AGENT_DIR = Path(__file__).resolve().parents[1]
BUILDER_PATH = AGENT_DIR / "packaging" / "build_installer.py"
TEMPLATE_PATH = AGENT_DIR / "packaging" / "installer-template.sh"

#: A token of the shape the server mints, used to prove none appears in the
#: artifact. 43 characters is base64url of 32 bytes.
SAMPLE_TOKEN = "T" * 43


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    """Import the builder by path.

    It lives in `packaging/` rather than in the package, because it is a build
    tool and has no business being installed onto an employee laptop. So it is
    loaded by path instead of imported by name.
    """
    spec = importlib.util.spec_from_file_location("ug_build_installer", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def built(builder: ModuleType) -> tuple[str, dict[str, object]]:
    artifact, manifest = builder.assemble(
        agent_dir=AGENT_DIR,
        server_url="https://mdm.example.com",
        server_ca_pem=None,
        agent_version="9.9.9",
        built_at="2026-01-01T00:00:00+00:00",
        admin_contact="it-help@example.com",
    )
    return artifact, manifest


def _payload_bytes(artifact: str) -> bytes:
    """Recover the embedded tar.gz the way the installer itself does."""
    marker = f"{'__UBUNTUGUARD_PAYLOAD__'}\n"
    _, _, encoded = artifact.partition(marker)
    assert encoded, "the artifact has no payload section"
    return base64.decodebytes(encoded.encode("ascii"))


def _payload_names(artifact: str) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(_payload_bytes(artifact))) as archive:
        return set(archive.getnames())


# --------------------------------------------------------------------------- #
# Nothing secret is published
# --------------------------------------------------------------------------- #


def test_the_artifact_contains_no_private_key(built: tuple[str, dict[str, object]]) -> None:
    """The single worst outcome available here.

    Checked over the DECODED payload as well as the script text, because a key
    inside the tar would not be visible in the base64.
    """
    artifact, _ = built
    payload = _payload_bytes(artifact)

    pattern = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
    assert not pattern.search(artifact.encode("utf-8")), "the installer text contains a private key"
    assert not pattern.search(payload), "the installer payload contains a private key"


def test_the_artifact_contains_no_certificate_when_no_ca_is_given(
    built: tuple[str, dict[str, object]],
) -> None:
    artifact, _ = built
    assert b"-----BEGIN CERTIFICATE-----" not in _payload_bytes(artifact)


def test_the_artifact_carries_no_enrollment_token(
    builder: ModuleType, built: tuple[str, dict[str, object]]
) -> None:
    """There is no code path that could put one here, and that is the point.

    An installer carrying a shared credential would turn one leaked download
    into unlimited enrollments. The build takes no token argument at all, so
    this asserts the absence of anything token-shaped rather than the absence
    of one specific value.
    """
    artifact, _ = built
    assert SAMPLE_TOKEN not in artifact

    # Nothing token-shaped outside the payload section. A server-minted token
    # is base64url of 32 random bytes - 43 dense alphanumeric characters - so
    # the test looks for that shape rather than for a known value.
    #
    # Density is what makes this usable: a bare `{40,}` run of the base64url
    # character class also matches the comment separators in this script, which
    # are forty-odd dashes and carry no information at all. Requiring 30
    # alphanumerics excludes those while still catching a real credential.
    header = artifact.split("__UBUNTUGUARD_PAYLOAD__")[0]
    suspicious = [
        run
        for run in re.findall(r"[A-Za-z0-9_-]{40,}", header)
        if sum(character.isalnum() for character in run) >= 30
        and not re.fullmatch(r"[0-9a-f]{64}", run)  # the payload digest, which is expected
    ]
    assert not suspicious, f"credential-shaped strings in the installer header: {suspicious}"


def test_the_payload_is_exactly_the_allowlisted_file_set(
    built: tuple[str, dict[str, object]],
) -> None:
    """An explicit set, so adding a file to the payload is a reviewed change.

    This is what stops `var/`, a `.env`, a test fixture or a stray PEM being
    swept in by a future glob.
    """
    artifact, _ = built
    names = _payload_names(artifact)

    assert "pyproject.toml" in names
    assert "README.md" in names
    assert "packaging/install.sh" in names
    assert "packaging/uninstall.sh" in names
    assert "packaging/systemd/ubuntuguard-agent.service" in names
    assert "packaging/etc/agent.yaml.example" in names
    assert "src/ubuntuguard_agent/cli.py" in names
    assert "src/ubuntuguard_agent/enrollment.py" in names

    # The build tooling itself has no business on an endpoint.
    assert "packaging/build_installer.py" not in names
    assert "packaging/installer-template.sh" not in names

    # Nothing from the test suite, and nothing compiled.
    assert not [name for name in names if name.startswith("tests/")]
    assert not [name for name in names if "__pycache__" in name]
    assert not [name for name in names if name.endswith((".pyc", ".pem", ".key", ".crt"))]


def test_every_payload_member_is_a_regular_file_under_a_relative_path(
    built: tuple[str, dict[str, object]],
) -> None:
    """No absolute paths, no `..`, no symlinks, no devices.

    `tar -xzf` without `-P` already refuses an absolute path, and the payload
    is digest-pinned, so this is defence in depth. It costs nothing and the
    failure it guards against is an extraction that writes outside its
    directory.
    """
    artifact, _ = built
    with tarfile.open(fileobj=io.BytesIO(_payload_bytes(artifact))) as archive:
        for member in archive.getmembers():
            assert member.isfile(), f"{member.name} is not a regular file"
            assert not member.name.startswith("/"), f"{member.name} is absolute"
            assert ".." not in Path(member.name).parts, f"{member.name} escapes the tree"


# --------------------------------------------------------------------------- #
# Determinism and integrity
# --------------------------------------------------------------------------- #


def test_two_builds_of_one_tree_are_byte_identical(builder: ModuleType) -> None:
    """Same source, same URL, same bytes, same published digest.

    The build timestamp is deliberately NOT in the artifact for this reason;
    it lives in the manifest. A test that passed only because two builds landed
    in the same second would be worthless, so the timestamps here differ by a
    year.
    """
    first, first_manifest = builder.assemble(
        agent_dir=AGENT_DIR,
        server_url="https://mdm.example.com",
        server_ca_pem=None,
        agent_version="9.9.9",
        built_at="2026-01-01T00:00:00+00:00",
        admin_contact="it-help@example.com",
    )
    second, second_manifest = builder.assemble(
        agent_dir=AGENT_DIR,
        server_url="https://mdm.example.com",
        server_ca_pem=None,
        agent_version="9.9.9",
        built_at="2027-06-30T12:34:56+00:00",
        admin_contact="it-help@example.com",
    )
    assert first == second
    assert first_manifest["sha256"] == second_manifest["sha256"]
    assert first_manifest["built_at"] != second_manifest["built_at"]


def test_the_manifest_digest_is_the_digest_of_the_artifact(
    built: tuple[str, dict[str, object]],
) -> None:
    """The server publishes this value, so it must describe the served bytes."""
    artifact, manifest = built
    assert manifest["sha256"] == hashlib.sha256(artifact.encode("utf-8")).hexdigest()
    assert manifest["size_bytes"] == len(artifact.encode("utf-8"))


def test_the_embedded_digest_is_the_digest_of_the_embedded_payload(
    built: tuple[str, dict[str, object]],
) -> None:
    """What the installer checks before it extracts anything."""
    artifact, manifest = built
    assert manifest["payload_sha256"] == hashlib.sha256(_payload_bytes(artifact)).hexdigest()
    assert f'PAYLOAD_SHA256="{manifest["payload_sha256"]}"' in artifact


def test_a_single_altered_payload_byte_is_detected(
    tmp_path: Path, built: tuple[str, dict[str, object]]
) -> None:
    """The integrity check, exercised by running the real script.

    Not a unit test of sha256 - this runs the installer's own verification
    stage against a tampered copy and requires it to refuse. Flipping one
    character of the base64 is the smallest possible corruption.
    """
    artifact, _ = built
    header, marker, encoded = artifact.partition("__UBUNTUGUARD_PAYLOAD__\n")

    # Change one base64 character to a different valid one, so the payload
    # still decodes but hashes differently.
    index = len(encoded) // 2
    original = encoded[index]
    replacement = "A" if original != "A" else "B"
    tampered = encoded[:index] + replacement + encoded[index + 1 :]

    script = tmp_path / "installer.sh"
    script.write_text(header + marker + tampered, encoding="utf-8")
    script.chmod(0o755)

    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(script), "--dry-run"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=120,
    )
    combined = result.stdout + result.stderr
    assert result.returncode != 0, "a tampered installer was accepted"
    assert "integrity check" in combined.lower() or "could not be decoded" in combined
    # It must refuse BEFORE unpacking anything, so no install stage runs.
    assert "installing the agent" not in combined


def test_the_digest_sidecar_is_in_sha256sum_format(tmp_path: Path, builder: ModuleType) -> None:
    """So an employee can verify with `sha256sum -c` and transcribe nothing."""
    assert (
        builder.main(["--server-url", "https://mdm.example.com", "--output-dir", str(tmp_path)])
        == 0
    )

    sidecar = tmp_path / f"{builder.INSTALLER_FILENAME}.sha256"
    content = sidecar.read_text(encoding="utf-8")
    assert re.fullmatch(rf"[0-9a-f]{{64}}  {re.escape(builder.INSTALLER_FILENAME)}\n", content), (
        f"unexpected sidecar format: {content!r}"
    )

    verified = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["sha256sum", "-c", sidecar.name],  # noqa: S607
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        timeout=60,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr


# --------------------------------------------------------------------------- #
# Build inputs that must be refused
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "http://mdm.example.com",
        "http://10.0.0.5:8000",
        "ftp://mdm.example.com",
        "mdm.example.com",
        "",
    ],
)
def test_a_non_https_server_url_is_refused(builder: ModuleType, url: str) -> None:
    """Threat T1 and feature D4: there is no plaintext fallback.

    Baking a URL the agent would then refuse to load produces an installer that
    fails *after* creating an account and a virtualenv, so this is caught at
    build time.
    """
    with pytest.raises(builder.BuildError):
        builder.validate_server_url(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]"])
def test_loopback_http_is_permitted_only_with_the_explicit_flag(
    builder: ModuleType, url: str
) -> None:
    """The development escape hatch, needing both conditions at once."""
    with pytest.raises(builder.BuildError):
        builder.validate_server_url(url)
    assert builder.validate_server_url(url, allow_loopback_http=True) == url


def test_the_loopback_flag_still_refuses_a_remote_plaintext_url(builder: ModuleType) -> None:
    """The flag is not a general "allow http" switch.

    This is the assertion that makes the escape hatch safe to keep in the tree:
    no combination of arguments bakes a plaintext URL for another machine into
    an artifact handed to employees.
    """
    with pytest.raises(builder.BuildError):
        builder.validate_server_url("http://mdm.example.com", allow_loopback_http=True)


def test_the_builders_url_rule_agrees_with_the_agents(builder: ModuleType) -> None:
    """Two implementations of one invariant, pinned to each other.

    `config._validate_server_url` is what the agent applies at load time and is
    the authority. The builder cannot import it - it must run without the
    agent's dependencies installed - so this test compares them over a table
    instead of leaving the agreement to inspection.
    """
    from ubuntuguard_agent.config import _validate_server_url
    from ubuntuguard_agent.errors import ConfigError

    cases = [
        "https://mdm.example.com",
        "https://mdm.example.com:8443",
        "http://mdm.example.com",
        "http://127.0.0.1:8000",
        "http://localhost",
        "ftp://mdm.example.com",
        "not-a-url",
    ]

    for url in cases:
        # Strict mode on both sides: no dev flags anywhere.
        try:
            _validate_server_url(url, dev_mode=False, allow_plaintext=False)
            agent_accepts = True
        except ConfigError:
            agent_accepts = False

        try:
            builder.validate_server_url(url)
            builder_accepts = True
        except builder.BuildError:
            builder_accepts = False

        assert agent_accepts == builder_accepts, (
            f"{url!r}: the agent {'accepts' if agent_accepts else 'refuses'} it but the "
            f"builder {'accepts' if builder_accepts else 'refuses'} it"
        )


def test_a_server_ca_containing_a_private_key_is_refused(
    builder: ModuleType, tmp_path: Path
) -> None:
    """Passing `ca.key` where `ca.crt` was meant.

    A plausible slip with the worst possible outcome: the internal CA's private
    key published to every employee, and from there anyone can mint a device
    certificate. Refused rather than filtered, so the mistake is visible.
    """
    path = tmp_path / "ca.key"
    path.write_text(
        "-----BEGIN PRIVATE KEY-----\nMIIBOgIBAAJBAKj3\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    with pytest.raises(builder.BuildError) as raised:
        builder.read_server_ca(path)
    assert "PRIVATE KEY" in str(raised.value)


def test_a_server_ca_with_no_certificate_is_refused(builder: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("this is not a certificate\n", encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.read_server_ca(path)


def test_an_unparseable_certificate_is_refused(builder: ModuleType, tmp_path: Path) -> None:
    """PEM armour alone is not a certificate."""
    path = tmp_path / "broken.crt"
    path.write_text(
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    with pytest.raises(builder.BuildError):
        builder.read_server_ca(path)


def test_a_real_certificate_is_accepted_and_embedded(builder: ModuleType, tmp_path: Path) -> None:
    """The CA certificate is public material and belongs in the installer.

    It is what lets the agent verify an internal server, and it is already
    disclosed by every TLS handshake with that server.
    """
    from cryptography.hazmat.primitives import serialization

    from tls_harness import make_authority

    authority = make_authority("UbuntuGuard Test Server CA")
    pem = authority.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    path = tmp_path / "ca.crt"
    path.write_text(pem, encoding="utf-8")

    assert builder.read_server_ca(path) == pem

    artifact, _ = builder.assemble(
        agent_dir=AGENT_DIR,
        server_url="https://mdm.example.com",
        server_ca_pem=pem,
        agent_version="9.9.9",
        built_at="2026-01-01T00:00:00+00:00",
        admin_contact="it-help@example.com",
    )
    encoded = base64.b64encode(pem.encode()).decode()
    assert f'SERVER_CA_PEM_B64="{encoded}"' in artifact
    # Base64-encoded so a PEM's newlines cannot terminate the assignment.
    assert "-----BEGIN CERTIFICATE-----\n" not in artifact.split("__UBUNTUGUARD_PAYLOAD__")[0]


# --------------------------------------------------------------------------- #
# Template and manifest contracts
# --------------------------------------------------------------------------- #


def test_no_placeholder_survives_into_the_artifact(built: tuple[str, dict[str, object]]) -> None:
    """A renamed placeholder would write the literal `@SERVER_URL@` into
    agent.yaml, and the agent would reject that only after installing."""
    artifact, _ = built
    header = artifact.split("__UBUNTUGUARD_PAYLOAD__")[0]
    assert not re.findall(r"@[A-Z0-9_]+@", header)


def test_a_template_with_an_unknown_placeholder_fails_the_build(builder: ModuleType) -> None:
    with pytest.raises(builder.BuildError) as raised:
        builder.render_template(
            'X="@WHO_KNOWS@"',
            agent_version="1",
            server_url="https://x",
            server_ca_pem=None,
            payload_sha256="0" * 64,
            admin_contact="a",
        )
    assert "@WHO_KNOWS@" in str(raised.value)


def test_the_committed_template_does_not_contain_the_literal_payload_marker(
    builder: ModuleType,
) -> None:
    """The script finds the payload by grepping its own text for the marker.

    A second occurrence would make it read the wrong offset and extract
    nothing, so the template references `@PAYLOAD_MARKER@` instead.
    """
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    assert builder.PAYLOAD_MARKER not in template


def test_a_template_containing_the_literal_marker_fails_the_build(
    builder: ModuleType, tmp_path: Path
) -> None:
    """The guard, exercised against a crafted template.

    `assemble` reads the template from the agent directory, so the case is
    staged by giving it a directory whose template is the bad one. Everything
    else is symlinked in, so this exercises the real code path rather than a
    reimplementation of it.
    """
    staged = tmp_path / "agent"
    (staged / "packaging").mkdir(parents=True)
    for name in ("src", "pyproject.toml", "README.md"):
        (staged / name).symlink_to(AGENT_DIR / name)
    for name in ("install.sh", "uninstall.sh", "systemd", "etc"):
        (staged / "packaging" / name).symlink_to(AGENT_DIR / "packaging" / name)

    (staged / "packaging" / "installer-template.sh").write_text(
        f"#!/bin/bash\n# {builder.PAYLOAD_MARKER}\n", encoding="utf-8"
    )

    with pytest.raises(builder.BuildError) as raised:
        builder.assemble(
            agent_dir=staged,
            server_url="https://mdm.example.com",
            server_ca_pem=None,
            agent_version="9.9.9",
            built_at="2026-01-01T00:00:00+00:00",
            admin_contact="a",
        )
    assert "payload marker" in str(raised.value)


def test_the_manifest_declares_the_platform_facts_honestly(
    built: tuple[str, dict[str, object]],
) -> None:
    """Target and validated are separate fields, and validated is empty.

    The brief forbids claiming 22.04 or 24.04 compatibility before it has been
    tested. The installer is written FOR those releases and has been validated
    on none, which is two different statements - so they are two fields, and
    they travel together to the enrollment page.
    """
    _, manifest = built
    assert manifest["schema"] == "ubuntuguard.installer.v1"
    assert manifest["supported_os_id"] == "ubuntu"
    assert manifest["target_os_versions"] == ["22.04", "24.04"]
    assert manifest["validated_os_versions"] == [], (
        "a release may be added here only once the agent has actually been run "
        "on it and the evidence committed"
    )
    assert manifest["minimum_python"] == "3.10"


def test_the_manifest_is_json_serialisable_as_written(tmp_path: Path, builder: ModuleType) -> None:
    """The server reads this file, so it must parse."""
    assert (
        builder.main(["--server-url", "https://mdm.example.com", "--output-dir", str(tmp_path)])
        == 0
    )
    parsed = json.loads((tmp_path / builder.MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert parsed["filename"] == builder.INSTALLER_FILENAME


def test_the_installer_is_written_executable(tmp_path: Path, builder: ModuleType) -> None:
    """An employee should not have to chmod a download before running it."""
    assert (
        builder.main(["--server-url", "https://mdm.example.com", "--output-dir", str(tmp_path)])
        == 0
    )
    mode = (tmp_path / builder.INSTALLER_FILENAME).stat().st_mode
    assert mode & 0o111, "the installer is not executable"


def test_the_agent_version_is_read_from_the_package(builder: ModuleType) -> None:
    from ubuntuguard_agent import __version__

    assert builder._agent_version(AGENT_DIR) == __version__


def test_a_build_failure_is_a_message_not_a_traceback(
    builder: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = builder.main(
        ["--server-url", "http://mdm.example.com", "--output-dir", str(tmp_path)]
    )
    assert exit_code == 1
    assert "must use https" in capsys.readouterr().err
    assert not list(tmp_path.iterdir()), "a failed build left files behind"
