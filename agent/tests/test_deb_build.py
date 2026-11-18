"""The double-clickable `.deb`, checked as an artefact.

The `.deb` is the second artifact handed to people who are not administrators,
so the same three classes of property the script installer is held to apply
here, plus two that are specific to packaging:

**It contains no secret.** A private key, a device certificate or an enrollment
token in a published package would be a fleet-wide compromise. Asserted
against the built bytes, not against the file list, because an allowlist is
only as good as the next edit to it.

**It is deterministic.** Two builds of one tree must produce one digest, for
the same reason the script installer must: the digest is published for
employees to compare against, and one that drifts on every rebuild trains
everyone to ignore it.

**It refuses bad build inputs.** A plaintext server URL and a `--server-ca`
that is actually a private key both produce an artifact that looks fine and is
not. Both checks are shared with `build_installer.py`, and the tests here
assert they are actually wired up rather than merely available.

**It does not enrol.** This is feature D11's constraint and the whole reason
the employee artifact was a script for so long. `postinst` must contain no
enrollment, and the capability must live in the desktop application instead.

**Its internal references agree.** A `.deb` is several files that name each
other: the polkit action names the helper's absolute path, the desktop entry
names the launcher's, and `conffiles` names paths in the data archive. Each
one is a string in a different file and a rename breaks it silently, so they
are compared to the paths actually shipped.

Nothing here needs root, a network, a server, or `dpkg`. The one test that
uses `dpkg-deb` skips when it is absent.

What these tests deliberately do NOT cover: whether `apt install` succeeds on
a real Ubuntu laptop, and whether the offline wheelhouse satisfies pip for
every target Python. Both need either root or a network, and the second was
verified by hand against Python 3.10, 3.11, 3.12 and 3.13; see
`docs/04-feature-list.md`.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

AGENT_DIR = Path(__file__).resolve().parents[1]
PACKAGING_DIR = AGENT_DIR / "packaging"
BUILDER_PATH = PACKAGING_DIR / "build_deb.py"
DEBIAN_DIR = PACKAGING_DIR / "debian"

#: A token of the shape the server mints, used to prove none appears in the
#: artifact. 43 characters is base64url of 32 bytes.
SAMPLE_TOKEN = "T" * 43

#: A syntactically real private key header. The builder's CA reader refuses
#: anything containing this, and the artifact must never contain it either.
PRIVATE_KEY_PATTERN = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")

#: Wheel filenames that satisfy `check_wheelhouse`. Fabricated rather than
#: downloaded: these tests must not touch the network, and nothing here reads
#: a wheel's contents.
FAKE_WHEEL_NAMES = (
    "pip-26.3-py3-none-any.whl",
    "hatchling-1.33.0-py3-none-any.whl",
    "tomli-2.5.0-py3-none-any.whl",
    "tomlkit-0.15.2-py3-none-any.whl",
    "trove_classifiers-2026.9.21.13-py3-none-any.whl",
    "packaging-26.3-py3-none-any.whl",
    "pathspec-1.1.1-py3-none-any.whl",
    "pluggy-1.7.0-py3-none-any.whl",
    "typing_extensions-4.15.0-py3-none-any.whl",
    "cryptography-50.0.2-cp39-abi3-manylinux_2_28_x86_64.whl",
    "pyyaml-6.0.3-cp310-cp310-manylinux_2_28_x86_64.whl",
    "cffi-2.1.1-cp310-cp310-manylinux_2_17_x86_64.whl",
)


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    """Import the builder by path.

    It lives in `packaging/` rather than in the package, because it is a build
    tool and has no business being installed onto an employee laptop. So it is
    loaded by path instead of imported by name.

    `packaging/` goes on `sys.path` first because `build_deb` imports the URL
    validator and the CA reader from `build_installer` rather than carrying its
    own copies.
    """
    if str(PACKAGING_DIR) not in sys.path:
        sys.path.insert(0, str(PACKAGING_DIR))
    spec = importlib.util.spec_from_file_location("ug_build_deb", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fake_wheels(tmp_path_factory: pytest.TempPathFactory) -> list[Path]:
    directory = tmp_path_factory.mktemp("wheelhouse")
    wheels = []
    for name in FAKE_WHEEL_NAMES:
        path = directory / name
        # Distinct contents per wheel, so the md5sums test is meaningful.
        path.write_bytes(f"not a real wheel: {name}".encode())
        wheels.append(path)
    return sorted(wheels)


def _build(
    builder: ModuleType,
    wheels: list[Path],
    **overrides: object,
) -> tuple[bytes, dict[str, object]]:
    arguments: dict[str, object] = {
        "agent_dir": AGENT_DIR,
        "server_url": "https://mdm.example.com",
        "server_ca_pem": None,
        "agent_version": "9.9.9",
        "arch": "amd64",
        "deb_version": "9.9.9-1",
        "admin_contact": "it-help@example.com",
        "wheels": wheels,
    }
    arguments.update(overrides)
    result = builder.assemble(**arguments)
    assert isinstance(result, tuple)
    return result


@pytest.fixture(scope="module")
def built(builder: ModuleType, fake_wheels: list[Path]) -> tuple[bytes, dict[str, object]]:
    return _build(builder, fake_wheels)


# --------------------------------------------------------------------------- #
# Reading the artifact back
# --------------------------------------------------------------------------- #


def _ar_members(artifact: bytes) -> list[tuple[str, bytes]]:
    """Parse the `ar` container the way `dpkg` does.

    Written out rather than shelled to `ar`, so the structural tests run on a
    machine with no binutils and so a malformed header is a parse failure here
    rather than a confusing message from another tool.
    """
    assert artifact.startswith(b"!<arch>\n"), "not an ar archive"
    offset = 8
    members = []
    while offset < len(artifact):
        header = artifact[offset : offset + 60]
        assert len(header) == 60, "truncated ar header"
        assert header[58:60] == b"`\n", "bad ar header magic"
        name = header[0:16].decode("ascii").strip()
        size = int(header[48:58].decode("ascii").strip())
        start = offset + 60
        members.append((name, artifact[start : start + size]))
        offset = start + size + (size % 2)
    return members


def _member(artifact: bytes, name: str) -> bytes:
    for member_name, data in _ar_members(artifact):
        if member_name == name:
            return data
    raise AssertionError(f"{name} is not in the archive")


def _tar_entries(gzipped: bytes) -> dict[str, tarfile.TarInfo]:
    raw = gzip.decompress(gzipped)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        return {info.name.lstrip("./"): info for info in archive.getmembers()}


def _tar_file(gzipped: bytes, name: str) -> bytes:
    raw = gzip.decompress(gzipped)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        extracted = archive.extractfile(f"./{name}")
        assert extracted is not None, f"{name} is not a regular file in the archive"
        return extracted.read()


def _expand_shell_variables(script: str) -> str:
    """Resolve the top-level `NAME="value"` assignments in a shell script.

    The maintainer scripts build every path from variables -- `${STATE_DIR}`,
    `${WHEEL_DIR}`, `${SERVICE_NAME}.service` -- so asserting against literal
    paths tests the wrong thing: it passes only while the script happens to
    spell them out, and fails when it is refactored to be clearer. Expanding
    first means these tests assert what the script will actually do.

    Deliberately simple: one pass over `NAME="value"` at the start of a line,
    then repeated substitution so that a variable defined in terms of another
    resolves too. It is not a shell parser and does not need to be.

    Double quotes are then dropped, so that `rm -rf "${STATE_DIR}"` and
    `rm -rf ${STATE_DIR}` read the same way here. The scripts quote every path
    -- they should, the paths are expanded variables -- and these tests are
    about which command runs against which path, not about quoting style.
    """
    assignments = dict(re.findall(r'^([A-Z_][A-Z0-9_]*)="([^"]*)"', script, re.M))
    expanded = script
    for _ in range(len(assignments) + 1):
        before = expanded
        for name, value in assignments.items():
            expanded = expanded.replace(f"${{{name}}}", value)
        if expanded == before:
            break
    return expanded.replace('"', "")


def _data(artifact: bytes) -> bytes:
    return _member(artifact, "data.tar.gz")


def _control(artifact: bytes) -> bytes:
    return _member(artifact, "control.tar.gz")


# --------------------------------------------------------------------------- #
# Nothing secret is published
# --------------------------------------------------------------------------- #


def test_the_package_contains_no_private_key(built: tuple[bytes, dict[str, object]]) -> None:
    """The single worst outcome available here.

    Checked over the decompressed data archive as well as the raw bytes,
    because a key inside the gzip would not be visible in the compressed form.
    """
    artifact, _ = built
    assert not PRIVATE_KEY_PATTERN.search(artifact)
    assert not PRIVATE_KEY_PATTERN.search(gzip.decompress(_data(artifact)))
    assert not PRIVATE_KEY_PATTERN.search(gzip.decompress(_control(artifact)))


def test_the_package_contains_no_enrollment_token(
    builder: ModuleType, fake_wheels: list[Path]
) -> None:
    """There is no build input that could put a token in, and no code to read one.

    The assertion is still worth making: it is the property an employee's
    download rests on, and a future `--token` convenience flag would break it
    in a way nothing else here would catch.
    """
    artifact, _ = _build(builder, fake_wheels)
    assert SAMPLE_TOKEN.encode() not in gzip.decompress(_data(artifact))
    assert SAMPLE_TOKEN.encode() not in gzip.decompress(_control(artifact))


def test_no_key_shaped_files_are_shipped(built: tuple[bytes, dict[str, object]]) -> None:
    artifact, _ = built
    names = _tar_entries(_data(artifact)).keys()
    offenders = [
        name
        for name in names
        if name.endswith((".key", ".csr")) or name.endswith(("device.crt", "device.key"))
    ]
    assert offenders == []


# --------------------------------------------------------------------------- #
# It does not enrol -- feature D11's constraint
# --------------------------------------------------------------------------- #


def test_postinst_does_not_enrol(built: tuple[bytes, dict[str, object]]) -> None:
    """The constraint that kept the employee artifact a script for so long.

    Enrollment consumes a single-use token and creates an auditable identity,
    so it must not be a side effect of unpacking a package.

    What counts as enrolling is worth being precise about: the claim is that
    postinst never invokes the AGENT's enroll subcommand and never handles a
    token. It does launch the enrollment *dialog*, which is not the same
    thing -- the dialog asks a person for a token postinst neither has nor can
    obtain, and a person who closes it leaves the laptop un-enrolled. An
    assertion on the bare word "enroll" would forbid that, and would have
    forbidden shipping the applications-menu entry too.

    Comment lines are stripped first, because the script explains at length
    why it does not enrol and the word appears throughout that explanation.
    """
    artifact, _ = built
    postinst = _tar_file(_control(artifact), "postinst").decode()
    code = [
        line for line in postinst.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    forbidden = (
        r"ubuntuguard-agent\s+enroll",
        r"--token-stdin",
        r"--token-prompt",
        r"--token\b",
        r"enroll\s+--token",
    )
    offenders = [line for line in code if any(re.search(p, line) for p in forbidden)]
    assert offenders == [], f"postinst appears to enrol: {offenders}"


def test_the_manifest_states_that_it_does_not_enrol(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """Carried to the server and the enrollment page as a fact, not a comment."""
    _, manifest = built
    assert manifest["enrols_on_install"] is False


def test_the_enrollment_capability_is_in_the_desktop_application(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """Not enrolling in postinst is only half the design.

    The other half is that enrollment is still reachable without a terminal,
    which is what makes a `.deb` usable for self-service at all. If the
    launcher stopped invoking the privileged helper this would still install
    cleanly and leave every employee stuck.
    """
    artifact, _ = built
    launcher = _tar_file(_data(artifact), builder.LAUNCHER_PATH).decode()
    assert "pkexec" in launcher
    assert builder.HELPER_PATH in launcher

    helper = _tar_file(_data(artifact), builder.HELPER_PATH).decode()
    assert "--token-stdin" in helper, "the helper must hand the token to the agent on stdin"


def test_the_prompt_comes_to_the_employee_rather_than_waiting_in_a_menu(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """Installing must not enrol, but it must not hide the next step either.

    The package ships a login reminder and postinst copies it into
    /etc/xdg/autostart when the laptop has no identity, so the prompt appears
    on its own. Without this the employee has to know to go looking through the
    applications menu, which is the difference between an install that finishes
    itself and one that silently does nothing.
    """
    artifact, _ = built
    shipped = _tar_entries(_data(artifact))
    assert builder.AUTOSTART_TEMPLATE_PATH in shipped

    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    assert f"/{builder.AUTOSTART_INSTALLED_PATH}" in postinst


def test_the_reminder_is_not_shipped_into_autostart_directly(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """dpkg must not own the reminder.

    If it did, dpkg would restore it on every upgrade and a laptop that had
    already enrolled would start being asked for a token again. The copy is
    postinst's to make and the enrollment helper's to delete, which is what
    lets the file's presence mean "still needs enrolling".
    """
    artifact, _ = built
    shipped = _tar_entries(_data(artifact))
    assert builder.AUTOSTART_INSTALLED_PATH not in shipped

    conffiles = _tar_file(_control(artifact), "conffiles").decode().split()
    assert f"/{builder.AUTOSTART_INSTALLED_PATH}" not in conffiles


def test_enrolling_stops_the_reminder(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """Otherwise the prompt would reappear at every login forever.

    Removed by the privileged helper rather than the launcher, because the
    launcher is unprivileged and must not acquire root for a reminder.
    """
    artifact, _ = built
    helper = _expand_shell_variables(_tar_file(_data(artifact), builder.HELPER_PATH).decode())
    assert f"rm -f /{builder.AUTOSTART_INSTALLED_PATH}" in helper

    # The launcher does delete things -- its own mktemp scratch files, through
    # a trap -- so the claim is specifically that it does not touch the
    # reminder, which lives under /etc and needs root.
    launcher = _expand_shell_variables(_tar_file(_data(artifact), builder.LAUNCHER_PATH).decode())
    removals = [
        line
        for line in launcher.splitlines()
        if "rm " in line and builder.AUTOSTART_INSTALLED_PATH in line
    ]
    assert removals == [], f"the unprivileged launcher must not delete it: {removals}"


def test_postinst_seeds_a_usbguard_baseline_so_the_install_cannot_lock_usb_out(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """Otherwise this package breaks the laptop it was installed to protect.

    `Depends: usbguard` means apt installs and starts usbguard before this
    package is configured. usbguard's shipped defaults are
    ImplicitPolicyTarget=block, PresentDevicePolicy=apply-policy and
    RuleFile=/etc/usbguard/rules.conf -- and the usbguard package ships no
    rules.conf. An empty ruleset with an implicit block, applied to devices
    already present, deauthorizes every USB device on the machine: an external
    keyboard and mouse, a USB webcam, an internal bluetooth or fingerprint
    reader on a USB bus.

    So postinst seeds a baseline allowing what is plugged in, which is
    usbguard's own documented bootstrap, before anything has been enrolled or
    given a policy.
    """
    artifact, _ = built
    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    assert "usbguard generate-policy" in postinst
    assert "/etc/usbguard/rules.conf" in postinst


def test_the_baseline_never_overwrites_an_existing_ruleset(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """An administrator's rules are theirs. Seeding is for the empty case only,
    and clobbering a considered ruleset would be a policy change made by an
    installer."""
    artifact, _ = built
    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    seed = postinst.partition("seed_usbguard_baseline()")[2]
    assert seed, "postinst has no baseline function"
    # -s is "exists and is non-empty", which is the correct test: a zero-byte
    # rules.conf is the lockout, not a decision.
    assert "-s /etc/usbguard/rules.conf" in seed


def test_an_empty_generated_policy_is_never_written(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """Writing an empty ruleset would BE the lockout.

    If usbguard cannot enumerate anything, the safe action is to write nothing
    and say so, not to install a file that blocks every device.
    """
    artifact, _ = built
    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    seed = postinst.partition("seed_usbguard_baseline()")[2]
    assert "-z ${generated}" in seed or '-z "${generated}"' in seed.replace("\\", "")


def test_postinst_does_not_edit_another_packages_conffile(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """usbguard-daemon.conf belongs to the usbguard package.

    Editing it would provoke dpkg conffile prompts on their upgrades and would
    silently change a security setting an administrator may have chosen.
    rules.conf is shipped by nobody, so creating that one is ours to do.
    """
    artifact, _ = built
    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    writes = [
        line
        for line in postinst.splitlines()
        if "usbguard-daemon.conf" in line and not line.lstrip().startswith("#")
    ]
    assert writes == [], f"postinst touches usbguard's conffile: {writes}"


def test_an_already_enrolled_laptop_is_not_prompted(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """The normal case on an upgrade.

    Asking an enrolled laptop for an enrollment token is a dialog whose only
    correct answer is to close it, so postinst checks for an existing identity
    before arranging any prompt.
    """
    artifact, _ = built
    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    assert "already_enrolled" in postinst
    assert "/var/lib/ubuntuguard/pki/device.key" in postinst


def test_removal_takes_the_reminder_away(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """dpkg will not do it: the file is not dpkg-owned.

    Left behind, it would ask the employee at every login to enrol a laptop
    whose agent has been removed.
    """
    artifact, _ = built
    postrm = _expand_shell_variables(_tar_file(_control(artifact), "postrm").decode())
    for branch in ("    remove)", "    purge)"):
        section = postrm.partition(branch)[2].partition(";;")[0]
        assert section, f"postrm has no {branch.strip()} branch"
        assert f"rm -f /{builder.AUTOSTART_INSTALLED_PATH}" in section, branch


def test_the_unprompted_prompt_explains_itself_before_asking_for_a_secret(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """A secret field that appears on its own teaches the wrong reflex.

    A password-shaped box asking for a long code, with no explanation and no
    way out, is indistinguishable from a phishing dialog. On the autostart
    path the launcher explains what it is and offers Later, and only someone
    who agrees is shown an entry field.
    """
    artifact, _ = built
    launcher = _tar_file(_data(artifact), builder.LAUNCHER_PATH).decode()
    assert "--autostart" in launcher
    assert "--question" in launcher, "the autostart path must ask before it prompts"
    assert "Later" in launcher

    autostart = _tar_file(_data(artifact), builder.AUTOSTART_TEMPLATE_PATH).decode()
    assert "--autostart" in autostart, "the reminder must use the self-explaining path"
    assert f"Exec=/{builder.LAUNCHER_PATH} --autostart" in autostart


def test_postinst_does_not_block_dpkg_on_a_dialog(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """A GUI left as dpkg's child would keep apt waiting on an unanswered
    dialog, and GNOME Software would sit at 99% until the employee answered.

    The immediate prompt is handed to the user's own systemd instance, which
    detaches it from dpkg's process tree.
    """
    artifact, _ = built
    postinst = _tar_file(_control(artifact), "postinst").decode()
    launches = [
        line
        for line in postinst.splitlines()
        if "ubuntuguard-enroll" in line and not line.lstrip().startswith("#")
    ]
    assert launches, "postinst never tries to show the prompt"
    assert "systemd-run" in postinst
    # Every attempt is tolerant of failure: the login reminder is the reliable
    # route, and a desktop that cannot be reached is not an install failure.
    assert "|| true" in postinst


def test_the_helper_never_takes_the_token_as_an_argument(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """Anything in a command line is readable by every user through /proc.

    The agent itself has no `--token` option for this reason, and the property
    has to survive the privilege boundary too. The helper is asserted to refuse
    arguments outright rather than merely to ignore them.
    """
    artifact, _ = built
    helper = _tar_file(_data(artifact), builder.HELPER_PATH).decode()
    assert "--token " not in helper
    assert "takes no arguments" in helper


# --------------------------------------------------------------------------- #
# Internal references agree
# --------------------------------------------------------------------------- #


def test_the_polkit_action_names_the_helper_that_is_shipped(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """Two strings in two files that must match, and nothing else checks them.

    pkexec resolves the action by the annotated absolute path. If the helper
    moved and the policy did not, pkexec falls back to a generic "run as the
    super user" prompt, which still works and silently loses the explanation
    the employee is being asked to approve.
    """
    artifact, _ = built
    policy = _tar_file(_data(artifact), builder.POLICY_PATH).decode()
    assert f"/{builder.HELPER_PATH}" in policy


def test_the_desktop_entry_launches_the_launcher_that_is_shipped(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    artifact, _ = built
    desktop = _tar_file(_data(artifact), builder.DESKTOP_PATH).decode()
    assert f"Exec=/{builder.LAUNCHER_PATH}" in desktop
    # Terminal=false is the whole point: this is the artifact for employees who
    # have no terminal to type a token into.
    assert "Terminal=false" in desktop


def test_conffiles_names_only_files_that_are_shipped(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """dpkg refuses to install a package whose conffiles list a missing file.

    server-ca.pem is absent when the server uses a publicly trusted
    certificate, which is the configuration this fixture builds, so the list
    must be shorter in that case rather than fixed.
    """
    artifact, _ = built
    conffiles = _tar_file(_control(artifact), "conffiles").decode().split()
    shipped = _tar_entries(_data(artifact))
    for path in conffiles:
        assert path.lstrip("/") in shipped, f"conffiles names {path}, which is not in the package"


def test_the_server_ca_is_a_conffile_when_one_is_embedded(
    builder: ModuleType, fake_wheels: list[Path]
) -> None:
    certificate = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
    artifact, manifest = _build(builder, fake_wheels, server_ca_pem=certificate)
    conffiles = _tar_file(_control(artifact), "conffiles").decode().split()
    assert f"/{builder.SERVER_CA_PATH}" in conffiles
    assert manifest["server_ca"] == "embedded"
    # And the agent is pointed at it rather than at the system trust store.
    agent_yaml = _tar_file(_data(artifact), builder.AGENT_YAML_PATH).decode()
    assert f"server_ca_bundle: /{builder.SERVER_CA_PATH}" in agent_yaml


def test_without_a_ca_the_agent_uses_the_system_trust_store(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    artifact, _ = built
    agent_yaml = _tar_file(_data(artifact), builder.AGENT_YAML_PATH).decode()
    assert f"server_ca_bundle: {builder.SYSTEM_CA_BUNDLE}" in agent_yaml
    assert not _tar_entries(_data(artifact)).get(builder.SERVER_CA_PATH)


def test_agent_yaml_has_only_the_two_permitted_keys(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """The agent refuses to start with a third key, so a helpful addition here
    would be a laptop that installs and then never runs."""
    artifact, _ = built
    agent_yaml = _tar_file(_data(artifact), builder.AGENT_YAML_PATH).decode()
    keys = [
        line.split(":", 1)[0]
        for line in agent_yaml.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert keys == ["server_url", "server_ca_bundle"]


# --------------------------------------------------------------------------- #
# The install path
# --------------------------------------------------------------------------- #


def test_postinst_runs_install_sh_with_bash(built: tuple[bytes, dict[str, object]]) -> None:
    """A regression test for a bug this package shipped with once.

    `install.sh` has a bash shebang and uses `[[`, and on Ubuntu `/bin/sh` is
    dash. Invoking it with `sh` failed on the first conditional and then died
    claiming `pyproject.toml` was missing, which is a misleading error with
    nothing to do with the real cause.
    """
    artifact, _ = built
    postinst = _tar_file(_control(artifact), "postinst").decode()
    invocations = [
        line.strip()
        for line in postinst.splitlines()
        if "install.sh" in line and not line.lstrip().startswith("#")
    ]
    assert invocations, "postinst does not run install.sh at all"
    assert any(line.startswith("bash ") for line in invocations), invocations
    assert not any(re.match(r"^sh\s", line) for line in invocations), invocations


def test_every_unit_install_sh_installs_is_in_the_package(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """Both units, including the root enforcer.

    `install.sh` installs two units. A package carrying only one would install
    the agent and then fail partway through postinst, leaving dpkg with a
    half-configured package. The builder refuses at build time; this asserts
    the result.
    """
    artifact, _ = built
    shipped = _tar_entries(_data(artifact))
    for unit in builder.REQUIRED_UNITS:
        assert f"{builder.SOURCE_SUBDIR}/{unit}" in shipped


def test_a_missing_unit_fails_the_build(
    builder: ModuleType, fake_wheels: list[Path], tmp_path: Path
) -> None:
    """The build-time half of the test above, exercised by breaking the tree.

    A copy of the agent directory minus the enforcer unit, which is the
    specific omission that produced a broken install before the payload
    allowlist was corrected.
    """
    staged = tmp_path / "agent"
    shutil.copytree(
        AGENT_DIR,
        staged,
        ignore=shutil.ignore_patterns(
            ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", "var", ".git"
        ),
    )
    (staged / "packaging" / "systemd" / "ubuntuguard-enforcerd.service").unlink()

    # Caught by the shared payload allowlist, which resolves every named file
    # and refuses a missing one before the `.deb` layout is considered at all.
    with pytest.raises(builder.BuildError, match="ubuntuguard-enforcerd.service is missing"):
        _build(builder, fake_wheels, agent_dir=staged)


def test_dropping_a_unit_from_the_allowlist_fails_the_build(
    builder: ModuleType, fake_wheels: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure the test above does NOT cover, and the one worth guarding.

    A unit file that is deleted from the tree is caught by the payload
    allowlist. A unit that still exists but is quietly dropped from the
    allowlist is not: the build would succeed and produce a package that
    installs the agent and then dies partway through postinst on a file the
    archive does not contain. That is what happened once already, and it is
    what `REQUIRED_UNITS` exists to catch.
    """
    import build_installer

    monkeypatch.setattr(
        build_installer,
        "PAYLOAD_FILES",
        tuple(
            name
            for name in build_installer.PAYLOAD_FILES
            if "ubuntuguard-enforcerd.service" not in name
        ),
    )
    with pytest.raises(builder.BuildError, match="install.sh installs it"):
        _build(builder, fake_wheels)


def test_the_privileged_helper_is_executable_and_root_only(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """pkexec refuses a helper that anyone but root can write to.

    So 0755 root:root is a requirement rather than a convention, and a 0644
    helper would produce an enrollment application that fails at the moment the
    employee uses it.
    """
    artifact, _ = built
    entries = _tar_entries(_data(artifact))
    helper = entries[builder.HELPER_PATH]
    assert helper.mode == 0o755
    assert helper.uid == 0 and helper.gid == 0
    assert helper.uname == "root" and helper.gname == "root"

    launcher = entries[builder.LAUNCHER_PATH]
    assert launcher.mode == 0o755


def test_install_sh_is_shipped_executable(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    artifact, _ = built
    entries = _tar_entries(_data(artifact))
    assert entries[f"{builder.SOURCE_SUBDIR}/packaging/install.sh"].mode == 0o755


def test_the_maintainer_scripts_are_executable(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """dpkg will not run a maintainer script it cannot execute."""
    artifact, _ = built
    entries = _tar_entries(_control(artifact))
    for script in ("postinst", "prerm", "postrm"):
        assert entries[script].mode == 0o755, script


# --------------------------------------------------------------------------- #
# Removal -- "purge removes keys" is D11's wording
# --------------------------------------------------------------------------- #


def test_purge_removes_the_key_material(built: tuple[bytes, dict[str, object]]) -> None:
    artifact, _ = built
    postrm = _expand_shell_variables(_tar_file(_control(artifact), "postrm").decode())
    purge_section = postrm.partition("purge)")[2].partition(";;")[0]
    assert purge_section, "postrm has no purge branch"
    assert "rm -rf /var/lib/ubuntuguard" in purge_section
    assert "rm -rf /etc/ubuntuguard" in purge_section


def test_plain_removal_keeps_the_key_material(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """The safe default, and the reason the remove/purge split is worth having.

    Deleting a private key cannot be undone, and re-enrolling a laptop creates
    a second device row for one machine. `remove` must therefore leave
    /var/lib/ubuntuguard alone.
    """
    artifact, _ = built
    postrm = _expand_shell_variables(_tar_file(_control(artifact), "postrm").decode())
    remove_section = postrm.partition("    remove)")[2].partition(";;")[0]
    assert remove_section, "postrm has no remove branch"
    deletions = [
        line
        for line in remove_section.splitlines()
        if line.lstrip().startswith("rm ") and "/var/lib/ubuntuguard" in line
    ]
    assert deletions == [], f"remove deletes state: {deletions}"


def test_removal_takes_away_both_units(built: tuple[bytes, dict[str, object]]) -> None:
    """Including the enforcer's.

    `uninstall.sh` still removes only the agent's unit -- it predates the root
    enforcer -- so postrm does not delegate to it, and this asserts postrm got
    the part uninstall.sh is missing.
    """
    artifact, _ = built
    postrm = _expand_shell_variables(_tar_file(_control(artifact), "postrm").decode())
    assert "rm -f /etc/systemd/system/ubuntuguard-agent.service" in postrm
    assert "rm -f /etc/systemd/system/ubuntuguard-enforcerd.service" in postrm


def test_prerm_stops_the_services_on_removal_but_not_on_upgrade(
    built: tuple[bytes, dict[str, object]],
) -> None:
    artifact, _ = built
    prerm = _tar_file(_control(artifact), "prerm").decode()
    remove_section = prerm.partition("remove|deconfigure)")[2].partition(";;")[0]
    assert "systemctl stop" in remove_section
    upgrade_section = prerm.partition("upgrade|failed-upgrade)")[2].partition(";;")[0]
    assert "systemctl stop" not in upgrade_section


# --------------------------------------------------------------------------- #
# Package metadata
# --------------------------------------------------------------------------- #


def test_control_declares_usbguard_as_a_dependency(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """The dependency that makes "it installs what it needs" true.

    usbguard is what the root enforcer drives, so apt pulling it in is the
    behaviour the package exists to provide.
    """
    artifact, _ = built
    control = _tar_file(_control(artifact), "control").decode()
    depends = next(
        line.partition(":")[2] for line in control.splitlines() if line.startswith("Depends:")
    )
    assert "usbguard" in depends
    # ensurepip lives in python3-venv on Debian and Ubuntu, and install.sh
    # checks for it explicitly because its absence is the most common failure.
    assert "python3-venv" in depends
    # The enrollment application is built from these two.
    assert "zenity" in depends
    assert "polkit" in depends


def test_control_has_the_fields_dpkg_requires(
    built: tuple[bytes, dict[str, object]],
) -> None:
    artifact, _ = built
    control = _tar_file(_control(artifact), "control").decode()
    fields = {
        line.partition(":")[0] for line in control.splitlines() if line and not line.startswith(" ")
    }
    for required in ("Package", "Version", "Architecture", "Maintainer", "Description"):
        assert required in fields


def test_the_architecture_is_concrete_and_not_all(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """The vendored wheels carry compiled extensions, so the package really is
    architecture specific. Declaring `all` would let apt install it on armhf
    and then fail in postinst, leaving a half-configured package."""
    artifact, manifest = built
    control = _tar_file(_control(artifact), "control").decode()
    assert "Architecture: amd64" in control
    assert manifest["architecture"] == "amd64"


def test_debian_binary_says_two_point_zero(built: tuple[bytes, dict[str, object]]) -> None:
    artifact, _ = built
    assert _member(artifact, "debian-binary") == b"2.0\n"


def test_the_members_are_in_the_order_dpkg_expects(
    built: tuple[bytes, dict[str, object]],
) -> None:
    """dpkg reads them as a stream, so the order is part of the format."""
    artifact, _ = built
    assert [name for name, _ in _ar_members(artifact)] == [
        "debian-binary",
        "control.tar.gz",
        "data.tar.gz",
    ]


def test_md5sums_covers_every_shipped_file(built: tuple[bytes, dict[str, object]]) -> None:
    """`dpkg --verify` reads this, so a stale entry reports phantom corruption."""
    artifact, _ = built
    listed = {}
    for line in _tar_file(_control(artifact), "md5sums").decode().splitlines():
        digest, _, name = line.partition("  ")
        listed[name] = digest

    raw = gzip.decompress(_data(artifact))
    shipped = 0
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for info in archive.getmembers():
            if not info.isfile():
                continue
            shipped += 1
            name = info.name.lstrip("./")
            assert name in listed, f"{name} is shipped but absent from md5sums"
            extracted = archive.extractfile(info)
            assert extracted is not None
            # md5 because that is the digest dpkg's format specifies and reads.
            # Not a security property: integrity of the download is the
            # published sha256, and this file exists so `dpkg --verify` can
            # detect local tampering after installation.
            digest = hashlib.md5(extracted.read()).hexdigest()  # noqa: S324 - dpkg's format
            assert listed[name] == digest, name

    # No stale entries either: one would report phantom corruption for a file
    # the package does not contain.
    assert len(listed) == shipped


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_two_builds_of_one_tree_are_byte_identical(
    builder: ModuleType, fake_wheels: list[Path]
) -> None:
    """The digest is published for employees to compare against.

    gzip is the easiest thing to get wrong here: it stores its own timestamp in
    a header that `tarfile`'s determinism does not reach, so a build that
    forgot `mtime=0` would differ every second while looking correct.
    """
    first, first_manifest = _build(builder, fake_wheels)
    second, second_manifest = _build(builder, fake_wheels)
    assert first == second
    assert first_manifest["sha256"] == second_manifest["sha256"]
    assert hashlib.sha256(first).hexdigest() == first_manifest["sha256"]


def test_no_member_carries_a_build_host_timestamp_or_identity(
    built: tuple[bytes, dict[str, object]],
) -> None:
    artifact, _ = built
    for gzipped in (_data(artifact), _control(artifact)):
        for info in _tar_entries(gzipped).values():
            assert info.mtime == 0, info.name
            assert info.uid == 0 and info.gid == 0, info.name
            assert info.uname == "root" and info.gname == "root", info.name


# --------------------------------------------------------------------------- #
# Bad build inputs are refused
# --------------------------------------------------------------------------- #


def test_a_plaintext_server_url_is_refused(builder: ModuleType) -> None:
    """Shared with the script installer, and asserted here to prove it is wired.

    A baked http:// URL would produce a package whose agent refuses to load its
    own configuration, after the install had already happened.
    """
    with pytest.raises(builder.BuildError, match="https"):
        builder.validate_server_url("http://mdm.example.com")


def test_a_loopback_http_url_is_allowed_only_with_the_flag(builder: ModuleType) -> None:
    assert builder.validate_server_url("http://127.0.0.1:8000", allow_loopback_http=True)
    with pytest.raises(builder.BuildError):
        builder.validate_server_url("http://127.0.0.1:8000")


def test_a_private_key_passed_as_the_server_ca_is_refused(
    builder: ModuleType, tmp_path: Path
) -> None:
    """Handing the builder `ca.key` instead of `ca.crt` is a plausible slip with
    a serious outcome: the internal CA's private key published to every
    employee who downloads the package."""
    bad = tmp_path / "ca.key"
    bad.write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    with pytest.raises(builder.BuildError, match="PRIVATE KEY"):
        builder.read_server_ca(bad)


def test_an_unknown_architecture_is_refused(builder: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(builder.BuildError, match="unknown --arch"):
        builder.download_wheels(tmp_path, arch="s390x", uv="uv", cache_dir=tmp_path)


def test_an_unsubstituted_placeholder_fails_the_build(builder: ModuleType) -> None:
    """A renamed placeholder would otherwise ship a launcher that tells the
    employee to contact `@ADMIN_CONTACT@`."""
    with pytest.raises(builder.BuildError, match="unsubstituted"):
        builder.render("contact @ADMIN_CONTACT@", {}, origin="test")


# --------------------------------------------------------------------------- #
# The wheelhouse
# --------------------------------------------------------------------------- #


def test_a_wheelhouse_missing_the_build_backend_is_refused(
    builder: ModuleType, tmp_path: Path
) -> None:
    """install.sh installs the agent from a source DIRECTORY, so pip builds a
    wheel from it and needs hatchling. Without it the install fails with "No
    matching distribution found for hatchling" on the employee's laptop."""
    wheels = [tmp_path / name for name in FAKE_WHEEL_NAMES if not name.startswith("hatchling-")]
    for wheel in wheels:
        wheel.write_bytes(b"x")
    with pytest.raises(builder.BuildError, match="hatchling"):
        builder.check_wheelhouse(wheels)


def test_a_wheelhouse_missing_pip_is_refused(builder: ModuleType, tmp_path: Path) -> None:
    """install.sh runs `pip install --upgrade pip`, which with PIP_NO_INDEX set
    and no local pip wheel fails and aborts the install."""
    wheels = [tmp_path / name for name in FAKE_WHEEL_NAMES if not name.startswith("pip-")]
    for wheel in wheels:
        wheel.write_bytes(b"x")
    with pytest.raises(builder.BuildError, match="pip"):
        builder.check_wheelhouse(wheels)


@pytest.mark.parametrize("missing", ["tomli-", "typing_extensions-"])
def test_the_marker_gated_wheels_are_required(
    builder: ModuleType, tmp_path: Path, missing: str
) -> None:
    """These two are the ones a resolution bug drops silently.

    `pip download --python-version 3.10` constrains which wheel TAGS are
    acceptable but does not evaluate environment markers against that version;
    markers resolve against the interpreter running pip. On a build host newer
    than 3.11 that omits hatchling's `tomli` and cryptography's
    `typing-extensions`, producing a wheelhouse that installs on the build host
    and fails on Ubuntu 22.04 -- the oldest supported release, and the one
    least likely to be the one anybody tested.

    The builder avoids this by resolving under a real interpreter per target
    version. This test guards the backstop.
    """
    wheels = [tmp_path / name for name in FAKE_WHEEL_NAMES if not name.startswith(missing)]
    for wheel in wheels:
        wheel.write_bytes(b"x")
    with pytest.raises(builder.BuildError):
        builder.check_wheelhouse(wheels)


def test_a_complete_wheelhouse_is_accepted(builder: ModuleType, fake_wheels: list[Path]) -> None:
    builder.check_wheelhouse(fake_wheels)


def test_the_wheels_are_shipped_where_postinst_looks_for_them(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """postinst points pip at a directory by absolute path, and a moved
    wheelhouse would silently fall back to needing the network."""
    artifact, _ = built
    shipped = _tar_entries(_data(artifact))
    for name in FAKE_WHEEL_NAMES:
        assert f"{builder.WHEEL_SUBDIR}/{name}" in shipped

    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    assert f"/{builder.WHEEL_SUBDIR}" in postinst
    assert "PIP_NO_INDEX" in postinst
    assert "PIP_FIND_LINKS" in postinst


def test_postinst_installs_from_the_source_tree_that_is_shipped(
    built: tuple[bytes, dict[str, object]], builder: ModuleType
) -> None:
    """postinst names the source directory by absolute path, so moving the tree
    inside the package without updating postinst would install nothing."""
    artifact, _ = built
    postinst = _expand_shell_variables(_tar_file(_control(artifact), "postinst").decode())
    assert f"/{builder.SOURCE_SUBDIR}" in postinst
    shipped = _tar_entries(_data(artifact))
    assert f"{builder.SOURCE_SUBDIR}/pyproject.toml" in shipped


def test_a_build_with_no_wheelhouse_still_produces_a_package(
    builder: ModuleType,
) -> None:
    """`--no-vendor` is a supported configuration for sites whose laptops can
    reach PyPI, and postinst handles the absent directory rather than failing."""
    artifact, manifest = _build(builder, [])
    assert manifest["bundled_wheels"] == []
    shipped = _tar_entries(_data(artifact))
    assert not any(name.startswith(builder.WHEEL_SUBDIR) for name in shipped)


# --------------------------------------------------------------------------- #
# dpkg's own opinion
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="dpkg-deb is not installed")
def test_dpkg_deb_can_read_the_package(
    built: tuple[bytes, dict[str, object]], tmp_path: Path
) -> None:
    """The archive is assembled by hand, so the authority on whether it is a
    valid `.deb` is dpkg and not this test file."""
    artifact, manifest = built
    path = tmp_path / str(manifest["filename"])
    path.write_bytes(artifact)

    info = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["dpkg-deb", "--info", str(path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    assert "ubuntuguard-agent" in info.stdout

    contents = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["dpkg-deb", "--contents", str(path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    assert "./usr/bin/ubuntuguard-enroll" in contents.stdout
