"""The employee installer script, exercised rather than read.

This file runs the real installer. Two techniques, because the script has two
kinds of logic worth testing and one technique cannot reach both:

**Sourced.** The script guards `main "$@"` on being executed rather than
sourced, so the decision functions - `check_platform_supported`,
`check_dependencies`, `os_release_value` - can be called directly with the
globals set to whatever case is under test. That is how "an unsupported OS is
refused" is tested without an unsupported machine, and without an environment
variable that changes the behaviour of a real install. A test hook that
production honours is a liability; this one cannot be reached by any
invocation.

**Executed under `--dry-run`.** Every mutating action goes through the `run`
wrapper, so a dry run prints the complete plan and changes nothing. That is
what proves the stages are wired together in the right order, that enrollment
drops privilege, and that no token appears in any planned command.

What is NOT covered here, and cannot be: a real install. It needs root, it
writes to /opt and /etc, it creates a system account, and it fetches two
packages from the network. The dry run exercises every line of the decision and
sequencing logic; the privileged actions themselves are an operator step.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

AGENT_DIR = Path(__file__).resolve().parents[1]
BUILDER_PATH = AGENT_DIR / "packaging" / "build_installer.py"

SERVER_URL = "https://mdm.test.example"
ADMIN_CONTACT = "it-help@test.example"


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ug_build_installer_script", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def installer(builder: ModuleType, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A real built installer, which is what an employee would download."""
    output = tmp_path_factory.mktemp("installer")
    assert (
        builder.main(
            [
                "--server-url",
                SERVER_URL,
                "--admin-contact",
                ADMIN_CONTACT,
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    return output / builder.INSTALLER_FILENAME


@pytest.fixture(scope="module")
def manifest(builder: ModuleType, installer: Path) -> dict[str, object]:
    path = installer.parent / builder.MANIFEST_FILENAME
    parsed: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    return parsed


def run_sourced(installer: Path, snippet: str) -> subprocess.CompletedProcess[str]:
    """Source the installer, then run `snippet` against its functions.

    `set +u` is NOT applied: the script sets `-u` itself and the snippets below
    must work under it, exactly as the real code paths do.
    """
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", "-c", f'source "{installer}"\n{snippet}\n'],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=120,
    )


def run_dry(installer: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(installer), "--dry-run", *args],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=180,
    )


def planned_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith("[dry-run]")]


# --------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------- #


def test_the_installer_is_valid_bash(installer: Path) -> None:
    """A syntax error would only appear on an employee's laptop otherwise."""
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", "-n", str(installer)],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_the_installer_fails_fast(installer: Path) -> None:
    """`set -euo pipefail`: the difference between stopping and continuing with
    a half-finished install."""
    assert "set -euo pipefail" in installer.read_text(encoding="utf-8")


def test_tracing_is_never_enabled(installer: Path) -> None:
    """`set -x` would echo the enrollment token when it is piped to the agent.

    The token is read into a shell variable and written to a pipe with
    `printf`, both of which xtrace would print to stderr.
    """
    text = installer.read_text(encoding="utf-8")
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        assert "set -x" not in code, f"xtrace enabled: {line!r}"
        assert "set -o xtrace" not in code, f"xtrace enabled: {line!r}"


def test_help_works_and_mentions_the_token(installer: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(installer), "--help"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "enrollment token" in result.stdout
    assert "--dry-run" in result.stdout


def test_an_unknown_option_is_refused(installer: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(installer), "--take-over-the-laptop"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "unknown option" in result.stderr


# --------------------------------------------------------------------------- #
# Operating system and architecture detection
# --------------------------------------------------------------------------- #


def test_os_release_is_parsed_and_quotes_are_stripped(installer: Path, tmp_path: Path) -> None:
    """Parsed as data, not sourced. A quoted value is the normal case."""
    release = tmp_path / "os-release"
    release.write_text(
        'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n',
        encoding="utf-8",
    )
    result = run_sourced(
        installer,
        f'os_release_value VERSION_ID "{release}"; os_release_value ID "{release}"',
    )
    assert result.stdout.split() == ["24.04", "ubuntu"]


def test_os_release_is_not_executed(installer: Path, tmp_path: Path) -> None:
    """`. /etc/os-release` is the common idiom and it runs the file.

    The file is root-owned so this is defence in depth, but reading a file to
    learn its contents should not be able to run anything, and a parser is two
    lines.
    """
    release = tmp_path / "os-release"
    marker = tmp_path / "executed"
    release.write_text(f'ID=ubuntu\nVERSION_ID="24.04"\ntouch "{marker}"\n', encoding="utf-8")

    result = run_sourced(installer, f'os_release_value ID "{release}"')
    assert result.stdout.strip() == "ubuntu"
    assert not marker.exists(), "os-release was executed rather than parsed"


@pytest.mark.parametrize("os_id", ["fedora", "debian", "arch", "rhel", ""])
def test_an_unsupported_operating_system_is_refused(installer: Path, os_id: str) -> None:
    """Ubuntu only, for now, and the refusal names what was found.

    There is one OS adapter and it reads Ubuntu's interfaces, so installing on
    anything else produces a service that runs and reports nothing useful. The
    detected value is in the message because "unsupported OS" with no detail
    sends an employee to their administrator with nothing to say.
    """
    result = run_sourced(
        installer,
        f'OS_ID="{os_id}"; OS_VERSION_ID="1"; OS_PRETTY="Something Else"; ARCH="x86_64"; '
        "check_platform_supported",
    )
    assert result.returncode != 0, f"os-release ID {os_id!r} was accepted"
    combined = result.stdout + result.stderr
    assert "ubuntu" in combined.lower()
    if os_id:
        assert os_id in combined, "the refusal does not name the detected OS"
    assert ADMIN_CONTACT in combined, "the refusal does not say who to contact"


@pytest.mark.parametrize("arch", ["armv7l", "i686", "riscv64", "ppc64le", "s390x"])
def test_an_unsupported_architecture_is_refused(installer: Path, arch: str) -> None:
    result = run_sourced(
        installer,
        f'OS_ID="ubuntu"; OS_VERSION_ID="24.04"; OS_PRETTY="Ubuntu"; ARCH="{arch}"; '
        "check_platform_supported",
    )
    assert result.returncode != 0, f"architecture {arch!r} was accepted"
    combined = result.stdout + result.stderr
    assert arch in combined
    assert "x86_64" in combined and "aarch64" in combined


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_the_supported_architectures_are_accepted(installer: Path, arch: str) -> None:
    """So the refusal test above cannot pass by refusing everything."""
    result = run_sourced(
        installer,
        f'OS_ID="ubuntu"; OS_VERSION_ID="24.04"; OS_PRETTY="Ubuntu"; ARCH="{arch}"; '
        "check_platform_supported",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_an_unvalidated_release_warns_but_does_not_refuse(installer: Path) -> None:
    """The distinction the brief insists on, and it cuts both ways.

    The agent is written FOR 22.04 and 24.04 and has been validated on neither,
    so every release warns today. Refusing would make the installer useless;
    staying silent would be the compatibility claim the brief forbids. So it
    warns, on every release, until `VALIDATED_OS_VERSIONS` is filled in from
    evidence.
    """
    result = run_sourced(
        installer,
        'OS_ID="ubuntu"; OS_VERSION_ID="24.04"; OS_PRETTY="Ubuntu 24.04"; ARCH="x86_64"; '
        "check_platform_supported",
    )
    assert result.returncode == 0
    assert "not yet been tested" in result.stderr
    assert "24.04" in result.stderr


def test_the_validated_release_list_is_still_empty(manifest: dict[str, object]) -> None:
    """A release may be added only once the agent has been run on it.

    Asserted here as well as in the build tests because this is the claim an
    employee reads on the enrollment page, and it must not be softened by
    editing one list.
    """
    assert manifest["validated_os_versions"] == []


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #


def _stub_path(directory: Path, *, names: tuple[str, ...], python_minor: int = 12) -> str:
    """A PATH containing just enough stubs to satisfy `check_dependencies`.

    Used to test the dependency logic on a machine whose real python3 may be
    missing ensurepip - which is the development host's actual state, and the
    reason the ensurepip check exists.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        stub = directory / name
        if name == "python3":
            stub.write_text(
                "#!/bin/sh\n"
                'case "$*" in\n'
                f"  *version_info\\[0\\]*) echo 3 ;;\n"
                f"  *version_info\\[1\\]*) echo {python_minor} ;;\n"
                "  *) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
        else:
            stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
    return str(directory)


REQUIRED_TOOLS = ("python3", "systemctl", "runuser", "sha256sum", "base64", "tar", "install")


def test_all_dependencies_present_passes(installer: Path, tmp_path: Path) -> None:
    path = _stub_path(tmp_path / "bin", names=REQUIRED_TOOLS)
    result = run_sourced(installer, f'PATH="{path}"; DRY_RUN=0; check_dependencies')
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("absent", REQUIRED_TOOLS)
def test_each_missing_dependency_is_reported_and_stops_a_real_install(
    installer: Path, tmp_path: Path, absent: str
) -> None:
    """One parametrised case per tool, so a dropped check cannot hide.

    `runuser` is the interesting one: without it enrollment cannot drop to the
    service account, and the install would otherwise get as far as prompting
    for a token before failing.
    """
    names = tuple(name for name in REQUIRED_TOOLS if name != absent)
    path = _stub_path(tmp_path / "bin", names=names)
    result = run_sourced(installer, f'PATH="{path}"; DRY_RUN=0; check_dependencies')

    assert result.returncode != 0, f"a missing {absent} was accepted"
    combined = result.stdout + result.stderr
    assert absent in combined, f"the failure does not name {absent}"


def test_an_old_python_is_refused_and_names_the_version(installer: Path, tmp_path: Path) -> None:
    """3.10 is the floor, so one build covers 22.04 and 24.04."""
    path = _stub_path(tmp_path / "bin", names=REQUIRED_TOOLS, python_minor=9)
    result = run_sourced(installer, f'PATH="{path}"; DRY_RUN=0; check_dependencies')
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "3.10" in combined
    assert "3.9" in combined, "the failure does not name the version that was found"


def test_a_missing_dependency_names_the_apt_package(installer: Path) -> None:
    """An employee needs a command to run, not a module name to look up.

    python3-venv is the case that matters: it provides both `venv` and
    `ensurepip`, and its absence is the single most common cause of a failed
    install of this shape.
    """
    text = installer.read_text(encoding="utf-8")
    assert "apt-get install -y python3-venv" in text
    assert "apt-get install -y python3" in text


def test_a_missing_dependency_is_reported_but_continues_under_dry_run(
    installer: Path, tmp_path: Path
) -> None:
    """A dry run should show the whole plan even on a machine that cannot install.

    This is what makes the script reviewable on a developer box, several of
    which - including this one - lack ensurepip.
    """
    path = _stub_path(tmp_path / "bin", names=("systemctl",))
    result = run_sourced(installer, f'PATH="{path}"; DRY_RUN=1; check_dependencies')
    assert result.returncode == 0
    assert "would STOP here" in result.stderr


# --------------------------------------------------------------------------- #
# Privileges
# --------------------------------------------------------------------------- #


def test_a_dry_run_needs_no_privileges_and_says_so(installer: Path) -> None:
    result = run_dry(installer)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--dry-run needs no privileges" in result.stdout


def test_a_dry_run_plans_no_destructive_action(installer: Path) -> None:
    """Every mutating action goes through the `run` wrapper or an explicit
    dry-run branch, so nothing is executed.

    Asserted by checking the real filesystem is untouched, which is stronger
    than reading the source: a direct call that bypassed the wrapper would
    create something here.
    """
    before = {
        path: path.exists()
        for path in (
            Path("/etc/ubuntuguard"),
            Path("/opt/ubuntuguard"),
            Path("/var/lib/ubuntuguard"),
            Path("/etc/systemd/system/ubuntuguard-agent.service"),
        )
    }
    result = run_dry(installer)
    assert result.returncode == 0
    for path, existed in before.items():
        assert path.exists() == existed, f"--dry-run changed {path}"


def test_privileges_are_requested_only_after_the_platform_checks(installer: Path) -> None:
    """Ordering, and it is a courtesy that matters.

    An employee on an unsupported machine should be told so, not asked for a
    password first and told afterwards. Asserted on the order the stages appear
    in a dry run.
    """
    result = run_dry(installer)
    output = result.stdout
    detected = output.index("detected")
    privileges = output.index("needs no privileges")
    assert detected < privileges, "privileges are requested before the platform is checked"


def test_the_sudo_re_exec_replays_the_original_arguments(installer: Path) -> None:
    """`main` shifts its way through `$@`, so a naive `exec sudo -- "$0" "$@"`
    re-executes with no arguments and silently loses `--no-enroll`."""
    text = installer.read_text(encoding="utf-8")
    assert "_ORIGINAL_ARGS=(" in text
    assert '_ORIGINAL_ARGS[@]+"${_ORIGINAL_ARGS[@]}"' in text


def test_token_from_stdin_refuses_to_escalate(installer: Path) -> None:
    """sudo may read its password prompt from the same stdin as the token.

    That would consume a single-use credential into sudo's authentication path
    and then fail to authenticate. An unattended install is run by something
    that can already be root, so this is refused rather than worked around.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(installer), "--token-stdin"],  # noqa: S607
        capture_output=True,
        text=True,
        input="",
        timeout=180,
    )
    assert result.returncode != 0
    assert "must be run as root" in result.stderr


# --------------------------------------------------------------------------- #
# Stage sequencing
# --------------------------------------------------------------------------- #


def test_the_payload_is_verified_before_it_is_extracted(installer: Path) -> None:
    """A digest checked after unpacking checks a directory that already exists."""
    result = run_dry(installer)
    output = result.stdout
    assert "integrity check passed" in output
    assert output.index("integrity check passed") < output.index("installing the agent")


def test_the_existing_install_script_is_called_with_the_extracted_source(
    installer: Path,
) -> None:
    """The tested install path is reused rather than reimplemented.

    `install.sh` creates the account, the root-owned virtualenv, the 0700 pki
    directory and the unit, and enables it. None of that is duplicated here.
    """
    result = run_dry(installer)
    planned = "\n".join(planned_lines(result.stdout))
    # Evidence that install.sh itself ran: these are its own planned actions.
    assert "groupadd --system ubuntuguard" in planned
    assert "useradd --system" in planned
    assert "install -d -m 0700 -o ubuntuguard -g ubuntuguard /var/lib/ubuntuguard/pki" in planned
    assert "systemctl enable ubuntuguard-agent.service" in planned


def test_the_installer_configures_the_agent_with_the_baked_in_server(installer: Path) -> None:
    """The employee never edits a config file; that was the point."""
    result = run_dry(installer)
    output = result.stdout
    assert "/etc/ubuntuguard/agent.yaml" in output
    assert SERVER_URL in output


def test_the_configuration_written_carries_only_the_two_permitted_keys(
    installer: Path,
) -> None:
    """A third key makes `load_config` raise and the agent refuse to start.

    Checked against the loader's own allowlist, so adding a key on either side
    fails here rather than on a laptop.
    """
    from ubuntuguard_agent.config import ALLOWED_CONFIG_KEYS

    text = installer.read_text(encoding="utf-8")
    heredoc = text.split('cat > "${WORKDIR}/agent.yaml" <<YAML', 1)
    assert len(heredoc) == 2, "the agent.yaml heredoc could not be located"
    body = heredoc[1].split("YAML", 1)[0]

    written = {match.group(1) for match in re.finditer(r"^([a-z_]+):", body, re.MULTILINE)}
    assert written == set(ALLOWED_CONFIG_KEYS), (
        f"the installer writes {sorted(written)} but the agent permits "
        f"{sorted(ALLOWED_CONFIG_KEYS)}"
    )


def test_the_service_is_started_after_enrollment_not_before(installer: Path) -> None:
    """Starting an unenrolled agent produces a skip line and nothing else."""
    result = run_dry(installer)
    planned = "\n".join(planned_lines(result.stdout))
    assert "enroll --token-stdin" in planned
    assert "systemctl start ubuntuguard-agent" in planned
    assert planned.index("enroll --token-stdin") < planned.index("systemctl start")


def test_no_enroll_skips_enrollment_but_still_installs(installer: Path) -> None:
    result = run_dry(installer, "--no-enroll")
    assert result.returncode == 0
    planned = planned_lines(result.stdout)
    joined = "\n".join(planned)

    assert "groupadd --system ubuntuguard" in joined
    assert "skipping enrollment" in result.stdout

    # No enrolling ACTION is planned. Asserted on the command rather than on
    # the word, because the confirmation stage legitimately plans to report
    # "enrollment status" and a bare substring check would trip on it.
    assert not [line for line in planned if "ubuntuguard-agent enroll" in line]
    assert not [line for line in planned if "runuser" in line]


# --------------------------------------------------------------------------- #
# Enrollment: privilege and token handling
# --------------------------------------------------------------------------- #


def test_enrollment_drops_to_the_agent_service_account(installer: Path) -> None:
    """The ownership fix, asserted on the planned command.

    `identity.py` never chowns - it creates the private key at 0600 owned by
    whoever is running - and the unit runs `User=ubuntuguard`. So enrolling as
    root writes a root-owned device.key into the service account's own pki
    directory, and the agent cannot then read the one file its identity rests
    on. Enrollment needs to write one directory and make one HTTPS request; it
    has never needed root.
    """
    result = run_dry(installer)
    planned = "\n".join(planned_lines(result.stdout))
    assert re.search(
        r"runuser -u ubuntuguard -- \S*ubuntuguard-agent enroll --token-stdin", planned
    ), f"enrollment is not run as the service account:\n{planned}"


def test_no_planned_command_carries_a_token_value(installer: Path) -> None:
    """/proc/<pid>/cmdline is world-readable, so argv is published.

    The dry run prints every command the installer would execute. None of them
    may carry the credential - the two safe channels are a pipe and a 0600
    file, and this installer uses the pipe.
    """
    result = run_dry(installer)
    for line in planned_lines(result.stdout):
        # No option anywhere may carry a value that could be the credential.
        assert "--token=" not in line, f"a token value is in argv: {line!r}"
        assert not re.search(r"--token(?!-)\s*\S", line), f"a token value is in argv: {line!r}"
        # The only token-bearing flag that may appear is the one that reads a
        # pipe. --token-file would mean a credential was written to disk.
        assert "--token-file" not in line, f"the token was written to a file: {line!r}"

    # And the channel that IS used is the pipe.
    assert [line for line in planned_lines(result.stdout) if "--token-stdin" in line]


def test_the_token_is_never_written_to_a_file(installer: Path) -> None:
    """`shred` does not reliably erase anything on overlayfs or tmpfs.

    The obvious interactive design is to read the token in shell and write it
    to a 0600 file for `--token-file`. That leaves a live single-use credential
    on a filesystem with no dependable way to remove it, so the installer pipes
    instead. Asserted on the source, because the absence of a write cannot be
    observed in a dry run.
    """
    code = "\n".join(
        line.split("#", 1)[0] for line in installer.read_text(encoding="utf-8").splitlines()
    )

    # Nothing token-shaped is ever redirected to a path.
    assert not re.search(r">\s*\S*[Tt]oken\S*", code), "a token is written to a path"
    # The installer never uses the file channel, which would require a write.
    assert "--token-file" not in code, "the installer uses the on-disk token channel"
    # And it has nothing to erase, which is the point: `shred` cannot reliably
    # erase anything on the overlayfs and tmpfs mounts a laptop actually has,
    # so a design that needs it is a design that leaves the credential behind.
    assert "shred" not in code, "the installer shreds something, so it wrote a secret to disk"


def test_the_token_variable_is_cleared_after_use(installer: Path) -> None:
    text = installer.read_text(encoding="utf-8")
    assert '_ENROLLMENT_INPUT=""' in text


def test_the_prompt_does_not_echo(installer: Path) -> None:
    """`read -rs`. Without `-s` the token appears on screen and in scrollback."""
    text = installer.read_text(encoding="utf-8")
    assert re.search(r"read -rs -p", text), "the token prompt echoes what is typed"


def test_the_prompt_is_the_wording_the_agent_uses(installer: Path) -> None:
    """One wording, whichever channel enrollment came through.

    The agent's `--token-prompt` and this installer ask the same question, so
    an employee following written instructions sees what they were told to
    expect.
    """
    from ubuntuguard_agent.enrollment import ENROLLMENT_PROMPT

    assert ENROLLMENT_PROMPT.strip() in installer.read_text(encoding="utf-8")


def test_the_token_is_read_by_the_privileged_process_not_the_agent(installer: Path) -> None:
    """Why the installer does not use the agent's own `--token-prompt`.

    Enrollment runs as `ubuntuguard`, and a process that has dropped privilege
    may not be able to reopen the controlling terminal: the pty is mode 0600
    and owned by the employee. `getpass` would fall back to reading stdin WITH
    ECHO. The agent refuses that fallback rather than leaking, which would
    leave the installer dead at its final step - so the privileged process
    reads the terminal and passes the value over a pipe.

    This test pins the reasoning to the code so the two cannot be "simplified"
    apart.
    """
    text = installer.read_text(encoding="utf-8")
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())

    # The privileged process reads the terminal, into its own variable.
    assert re.search(r"read -rs -p .*_ENROLLMENT_INPUT", code), (
        "the installer does not read the token itself"
    )
    # And hands it to the agent on a pipe, not as an argument or a file.
    assert "printf '%s' \"${_ENROLLMENT_INPUT}\"" in code, (
        "the token is not written to the agent's standard input"
    )
    assert "| runuser -u" in code, "the token is not piped to a privilege-dropped agent"

    # Every enrolling command the installer EXECUTES drops privilege, and
    # every privilege-dropped command reads the pipe rather than the terminal.
    executed = [line for line in code.splitlines() if "runuser -u" in line]
    assert executed, "no privilege-dropped command found in the installer"
    for line in executed:
        if "enroll" not in line:
            continue
        assert "--token-stdin" in line, f"a dropped-privilege enroll reads a terminal: {line!r}"
        assert "--token-prompt" not in line, (
            f"a dropped-privilege enroll uses --token-prompt, which may be unable to "
            f"open the employee's terminal and would fall back to echoing: {line!r}"
        )

    # `--token-prompt` does appear, but only as recovery advice for an
    # administrator running the CLI under sudo, where the terminal is theirs.
    advice = [line for line in code.splitlines() if "--token-prompt" in line]
    assert advice, "no recovery path offers the interactive prompt"
    for line in advice:
        assert "sudo" in line, f"--token-prompt suggested without sudo: {line!r}"


# --------------------------------------------------------------------------- #
# Failure handling and the confirmation block
# --------------------------------------------------------------------------- #


def test_a_failure_tells_the_employee_who_to_contact(installer: Path) -> None:
    """An employee cannot debug this and should not be asked to."""
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(installer), "--not-an-option"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert ADMIN_CONTACT in result.stderr
    assert "Nothing was enrolled" in result.stderr


def test_a_refused_token_explains_the_likely_causes_and_the_recovery(installer: Path) -> None:
    """Invalid, expired and already-used are deliberately indistinguishable.

    The server returns one vague `detail` on authentication paths, because
    distinguishing "unknown token" from "already consumed" would tell an
    attacker which tokens once existed. So the installer names the three
    plausible causes and the recovery rather than inventing a specific
    diagnosis.
    """
    text = installer.read_text(encoding="utf-8")
    assert "single use" in text
    assert "expired" in text
    assert "already been used" in text
    assert "enroll --token-prompt" in text, "no recovery command for a fresh token"


def test_the_confirmation_reports_every_required_fact(installer: Path) -> None:
    """Hostname, enrollment status, service status, heartbeat, and who to contact.

    Asserted on the confirmation block itself rather than on the whole file, so
    a label that exists only in a comment somewhere else cannot satisfy it.
    """
    result = run_dry(installer)
    assert "report hostname, enrollment status, service status and heartbeat" in result.stdout

    text = installer.read_text(encoding="utf-8")
    block = text.split("stage_confirm()", 1)
    assert len(block) == 2, "the confirmation stage could not be located"
    body = block[1].split("\n# ---", 1)[0]

    for label in (
        "device hostname",
        "operating system",
        "agent version",
        "server ",
        "enrollment ",
        "device identity",
        "agent service",
        "first heartbeat",
    ):
        assert label in body, f"the confirmation block does not report {label!r}"

    assert "${ADMIN_CONTACT}" in body, "the confirmation block does not say who to contact"
    assert "${HOSTNAME_NOW}" in body, "the hostname is labelled but not interpolated"


def test_the_success_message_is_the_one_specified(installer: Path) -> None:
    text = installer.read_text(encoding="utf-8")
    assert "UbuntuGuard has been successfully installed and enrolled." in text


def test_the_installer_never_claims_a_heartbeat_was_delivered(installer: Path) -> None:
    """The constraint that matters most in the confirmation block.

    An active unit means the process is running, not that it reached the
    server. And a SUCCESSFUL heartbeat is logged at debug while the default
    level is info (`service.py:HeartbeatTask`), so there is no journal line to
    find either. Only a FAILURE is observable: `runtime.py` logs "task failed"
    at warning, and a skip logs "heartbeat skipped" at info.

    So the installer reports the absence of a failure, labels it as such, and
    points at the dashboard for the authoritative answer. This test fails if
    that is ever softened into a claim.
    """
    text = installer.read_text(encoding="utf-8")

    assert "not proof of delivery" in text, "the heartbeat report overstates what was checked"
    assert "authoritative" in text, "the confirmation does not point anywhere authoritative"

    # The observation is derived from the journal, not from the unit's state.
    assert "journalctl" in text
    assert '"task":"heartbeat"' in text
    assert "heartbeat skipped" in text

    # No phrasing that asserts delivery.
    for forbidden in (
        "heartbeat sent",
        "heartbeat delivered",
        "heartbeat successful",
        "heartbeat succeeded",
        "successfully checked in",
    ):
        assert forbidden not in text.lower(), f"the installer claims {forbidden!r}"


def test_the_confirmation_states_the_key_never_left_the_machine(installer: Path) -> None:
    """The one security property an employee has a right to be told plainly."""
    text = installer.read_text(encoding="utf-8")
    assert "has not" in text and "left it" in text
    assert "device.key" in text


def test_re_running_the_installer_does_not_ask_for_a_second_token(installer: Path) -> None:
    """An upgrade must not prompt for a token it would then have to refuse.

    `enroll` refuses an already-enrolled device, because re-enrolling creates a
    second device row for one laptop. So the installer makes the same check
    `identity.is_enrolled` makes and skips the prompt.
    """
    text = installer.read_text(encoding="utf-8")
    assert "already_enrolled()" in text
    assert "device.key" in text and "device.crt" in text
    assert "not re-enrolling" in text


def test_the_extraction_directory_is_cleaned_up(installer: Path) -> None:
    text = installer.read_text(encoding="utf-8")
    assert "trap cleanup EXIT" in text


def test_a_piped_installer_is_refused_with_the_fix(installer: Path) -> None:
    """`curl | bash` cannot work: the agent is embedded in the file.

    Refused with the remedy rather than with a confusing error from `tail`
    reading a nonexistent path.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash"],  # noqa: S607
        input=installer.read_text(encoding="utf-8"),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode != 0
    assert "saved to a file" in result.stderr
    # Refused before anything was attempted, not partway through.
    assert "integrity check" not in result.stdout
    assert "groupadd" not in result.stdout
