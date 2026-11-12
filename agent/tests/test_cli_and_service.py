"""The CLI and the service lifecycle.

Exit codes get as much attention as output here, because these commands are
driven by systemd and by shell scripts. `status` returning 1 for a degraded but
perfectly normal state - installed, not yet enrolled - is deliberate, and worth
a test so nobody "fixes" it into always returning 0.

The signal test is the one that matters most for the service: SIGTERM is what
systemd sends on `stop` and `restart`, and an agent that ignores it gets
SIGKILLed thirty seconds later with whatever it was doing left half-finished.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from helpers import issue_certificate
from ubuntuguard_agent import __version__
from ubuntuguard_agent.cli import collect_status, main, run_selftest
from ubuntuguard_agent.config import (
    ENV_ALLOW_PLAINTEXT,
    ENV_DEV_MODE,
    ENV_SERVER_URL,
    ENV_STATE_DIR,
    AgentConfig,
    AgentPaths,
    AgentSettings,
    load_config,
)
from ubuntuguard_agent.identity import ensure_runtime_paths
from ubuntuguard_agent.service import build_runtime, install_signal_handlers, log_startup_banner

AGENT_ROOT = Path(__file__).resolve().parents[1]


def config_for(tmp_path: Path, *, server_url: str = "https://ug.example.internal") -> AgentConfig:
    return AgentConfig(
        server_url=server_url,
        server_ca_bundle=None,
        paths=AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run"),
        settings=AgentSettings(),
        release_build=True,
        config_path=None,
    )


# --------------------------------------------------------------------------- #
# Argument parsing and exit codes
# --------------------------------------------------------------------------- #


def test_version_prints_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_no_subcommand_is_a_usage_error() -> None:
    """argparse exits 2 for usage, which is the conventional code."""
    with pytest.raises(SystemExit) as raised:
        main([])
    assert raised.value.code == 2


def test_an_unknown_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit):
        main(["enroll"])


def _subcommands() -> set[str]:
    from ubuntuguard_agent.cli import build_parser

    actions = [
        action
        for action in build_parser()._actions  # noqa: SLF001 - argparse has no public accessor
        if hasattr(action, "choices") and action.choices
    ]
    return set(actions[-1].choices) if actions else set()


def test_the_expected_subcommands_exist() -> None:
    """An exact set. A command appearing here unreviewed is a capability nobody asked for."""
    assert _subcommands() == {"run", "enroll", "status", "selftest", "version"}


def test_enroll_has_no_option_that_takes_a_token_on_the_command_line() -> None:
    """The absence of `--token` IS the control, so the suite enforces the absence.

    /proc/<pid>/cmdline is world-readable on Linux, so a single-use enrollment
    token passed as an argument is published to every user on the machine and
    to anything sampling `ps`. An option that accepted one and then warned
    would be worse than none at all: by the time the warning prints, the value
    has already been exposed.

    This test exists because the mistake is an easy and well-meaning one -
    somebody adds `--token` for convenience during debugging and it survives
    review. Asserting on the parser rather than on documentation is what makes
    that fail loudly.
    """
    from ubuntuguard_agent.cli import build_parser

    parser = build_parser()
    subparsers = next(
        action
        for action in parser._actions  # noqa: SLF001 - argparse has no public accessor
        if hasattr(action, "choices") and action.choices
    )
    enroll_parser = subparsers.choices["enroll"]

    option_strings = {
        option
        for action in enroll_parser._actions  # noqa: SLF001 - as above
        for option in action.option_strings
    }
    assert "--token" not in option_strings
    assert "-t" not in option_strings
    # The two safe channels are both present, so this test cannot pass by the
    # enroll command having no token input at all.
    assert "--token-file" in option_strings
    assert "--token-stdin" in option_strings

    # Every option that mentions a token must be one of the two safe ones.
    token_options = {option for option in option_strings if "token" in option}
    assert token_options == {"--token-file", "--token-stdin"}


def test_enroll_requires_a_token_source() -> None:
    """Neither flag is a usage error, not a run that does something surprising."""
    with pytest.raises(SystemExit) as raised:
        main(["enroll"])
    assert raised.value.code == 2  # argparse usage error


def test_a_configuration_error_is_reported_on_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Plain text, not a JSON log line.

    At this point logging may not be configured and the reader is a person who
    just typed a command.
    """
    bad = tmp_path / "agent.yaml"
    bad.write_text("server_url: http://evil.example\n", encoding="utf-8")

    assert main(["status", "--config", str(bad)]) == 1
    captured = capsys.readouterr()
    assert "configuration error" in captured.err
    assert captured.out == ""


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #


def test_status_reports_degraded_when_not_enrolled(tmp_path: Path) -> None:
    """Installed but not enrolled is normal, and still not healthy.

    A monitoring script has to be able to tell "managed" from "installed",
    which is why this is an exit code and not only a line of text.
    """
    report, healthy = collect_status(config_for(tmp_path))
    assert healthy is False
    assert report["enrolled"] is False
    assert any("not enrolled" in note for note in report["notes"])


def test_status_reports_degraded_with_no_server(tmp_path: Path) -> None:
    report, healthy = collect_status(config_for(tmp_path, server_url=None))
    assert healthy is False
    assert report["server_configured"] is False


def test_status_never_claims_mtls_is_verified(tmp_path: Path) -> None:
    """The finding from the inspection report, enforced in code.

    The device plane's identity model depends on an nginx configuration that
    does not exist in this repository. Until it does, nothing in this build may
    report device authentication as verified, so the field is present and false
    rather than absent.
    """
    report, _ = collect_status(config_for(tmp_path))
    assert report["mtls_verified"] is False


def test_status_includes_certificate_detail_when_enrolled(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    device_id = str(uuid.uuid4())
    config.paths.private_key_path.write_text("key")
    config.paths.certificate_path.write_bytes(issue_certificate(device_id=device_id))

    report, healthy = collect_status(config)
    assert healthy is True
    assert report["certificate"]["device_id"] == device_id
    assert report["certificate"]["expired"] is False
    assert report["certificate"]["renewal_due"] is False


def test_status_is_degraded_when_the_certificate_has_expired(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_text("key")
    config.paths.certificate_path.write_bytes(
        issue_certificate(
            not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60), valid_days=30
        )
    )

    report, healthy = collect_status(config)
    assert healthy is False
    assert report["certificate"]["expired"] is True


def test_status_is_degraded_when_the_certificate_is_corrupt(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_text("key")
    config.paths.certificate_path.write_bytes(b"garbage")

    report, healthy = collect_status(config)
    assert healthy is False
    assert any("unreadable" in note for note in report["notes"])


def test_status_json_is_parseable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_DEV_MODE, "1")
    monkeypatch.setenv(ENV_STATE_DIR, str(tmp_path / "state"))

    exit_code = main(["status", "--config", str(tmp_path / "absent.yaml"), "--json"])
    payload: dict[str, Any] = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["agent_version"] == __version__
    assert payload["mtls_verified"] is False
    assert "host" in payload


def test_status_text_output_mentions_the_mtls_caveat(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["status", "--config", str(tmp_path / "absent.yaml")])
    out = capsys.readouterr().out
    assert "mTLS verified" in out
    # Still reported as unverified now that the agent does present a client
    # certificate, because the agent cannot check from here whether the proxy
    # it reached actually enforces `ssl_verify_client on`. The caveat must
    # survive, and it must point somewhere an operator can act on.
    assert "no" in out
    assert "deploy/nginx" in out


def test_status_does_not_leak_private_material(tmp_path: Path) -> None:
    """The report is printed and copied into tickets.

    The certificate fingerprint is included because it is public and useful; the
    private key is never read by this path at all.
    """
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_text("-----BEGIN PRIVATE KEY-----\nsecret\n")
    config.paths.certificate_path.write_bytes(issue_certificate())

    report, _ = collect_status(config)
    assert "PRIVATE KEY" not in json.dumps(report)
    assert "secret" not in json.dumps(report)


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #


def test_selftest_is_read_only(tmp_path: Path) -> None:
    """A selftest that created what it checks for would always pass.

    That is the kind of test that tells you nothing on the one occasion it
    matters, so this asserts the state directory is still absent afterwards.
    """
    config = config_for(tmp_path)
    run_selftest(config)
    assert not config.paths.state_dir.exists()


def test_selftest_fails_on_a_fresh_install(tmp_path: Path) -> None:
    results = run_selftest(config_for(tmp_path))
    assert any(not result.passed for result in results)

    names = {result.name for result in results}
    assert "server CA bundle" in names
    assert "private key" in names


def test_selftest_flags_an_insecure_private_key(tmp_path: Path) -> None:
    """The check that makes "restrictive permissions" more than a claim."""
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_text("key")
    config.paths.private_key_path.chmod(0o644)

    results = run_selftest(config)
    permission_checks = [r for r in results if "permissions" in r.name]
    assert permission_checks and not permission_checks[0].passed


def test_selftest_passes_the_key_permission_check_at_0600(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_text("key")
    config.paths.private_key_path.chmod(0o600)

    results = run_selftest(config)
    permission_checks = [r for r in results if "permissions" in r.name]
    assert permission_checks and permission_checks[0].passed


def test_selftest_exit_code_reflects_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_DEV_MODE, "1")
    monkeypatch.setenv(ENV_STATE_DIR, str(tmp_path / "state"))

    assert main(["selftest", "--config", str(tmp_path / "absent.yaml")]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "checks passed" in out


# --------------------------------------------------------------------------- #
# The service
# --------------------------------------------------------------------------- #


def test_the_runtime_registers_the_expected_tasks(tmp_path: Path) -> None:
    """Three tasks, in this order, and the suite names them.

    Asserted as an exact ordered list rather than a membership check, for two
    reasons. A task appearing here that nobody intended is a background job
    nobody reviewed, and on an agent that means unreviewed network traffic from
    every managed laptop. And the order is load-bearing: the heartbeat is
    registered before the renewal so that within one loop pass it runs on the
    certificate that is still current.
    """
    runtime = build_runtime(config_for(tmp_path))
    assert [task.name for task in runtime.tasks] == [
        "identity_check",
        "heartbeat",
        "certificate_renewal",
    ]


def test_every_task_runs_without_a_server_or_an_identity(tmp_path: Path) -> None:
    """Both normal states for a fresh install, and neither is a failure.

    The heartbeat must SKIP rather than fail here. Failing would reschedule it
    on backoff and write a warning a minute about a condition the operator
    created deliberately by installing the agent before enrolling it.
    """
    config = config_for(tmp_path, server_url=None)
    ensure_runtime_paths(config.paths)
    runtime = build_runtime(config)

    runtime.run_once()
    for task in runtime.tasks:
        assert task.runs == 1, f"{task.name} did not complete"
        assert task.consecutive_failures == 0, f"{task.name} reported a failure"


def test_the_identity_task_reports_a_corrupt_certificate_as_a_failure(
    tmp_path: Path,
) -> None:
    """Not swallowed: it reschedules on backoff with a reason code."""
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_text("key")
    config.paths.certificate_path.write_bytes(b"garbage")

    runtime = build_runtime(config)
    runtime.run_once()

    assert runtime.tasks[0].consecutive_failures == 1
    assert runtime.stopping is False


def test_the_startup_banner_warns_about_an_unvalidated_platform(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from ubuntuguard_agent.osadapter import UbuntuAdapter

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text("ID=fedora\nVERSION_ID=41\n", encoding="utf-8")

    logger = logging.getLogger("ubuntuguard_agent.test.banner")
    logger.propagate = True
    with caplog.at_level(logging.WARNING, logger=logger.name):
        log_startup_banner(config_for(tmp_path), UbuntuAdapter(tmp_path), logger=logger)

    assert any("UNVALIDATED" in record.getMessage() for record in caplog.records)


def test_the_startup_banner_warns_loudly_about_plaintext_http(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """On every start, not once. This is the one case plaintext is possible."""
    import logging

    from ubuntuguard_agent.osadapter import detect_adapter

    path = tmp_path / "agent.yaml"
    path.write_text("server_url: http://127.0.0.1:8000\n", encoding="utf-8")
    config = load_config(path, env={ENV_DEV_MODE: "1", ENV_ALLOW_PLAINTEXT: "1"})

    logger = logging.getLogger("ubuntuguard_agent.test.plaintext")
    logger.propagate = True
    with caplog.at_level(logging.WARNING, logger=logger.name):
        log_startup_banner(config, detect_adapter(), logger=logger)

    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "plaintext HTTP" in messages
    assert "release_build=false" in messages


def test_signal_handlers_are_installed_and_stop_the_runtime(tmp_path: Path) -> None:
    """Delivers a real SIGTERM to this process and asserts the flag is set.

    The handler itself only sets an event, which is all that is safe inside a
    signal handler - logging there can deadlock if the signal arrives while the
    logging lock is held.
    """
    runtime = build_runtime(config_for(tmp_path))
    previous = signal.getsignal(signal.SIGTERM)
    try:
        install_signal_handlers(runtime)
        os.kill(os.getpid(), signal.SIGTERM)
        assert runtime.stopping is True
        assert runtime.stop_reason == "signal:SIGTERM"
    finally:
        signal.signal(signal.SIGTERM, previous)


def test_a_sigterm_during_the_loop_ends_it_promptly(tmp_path: Path) -> None:
    """Waiting on an Event rather than sleeping is what makes this immediate.

    With `time.sleep` the loop would serve out the remainder of a 60-second
    interval before noticing, and systemd would be waiting the whole time.
    """
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    runtime = build_runtime(config)

    def stop_shortly() -> None:
        time.sleep(0.2)
        runtime.request_stop("test_thread")

    stopper = threading.Thread(target=stop_shortly, daemon=True)
    started = time.monotonic()
    stopper.start()
    exit_code = runtime.run()
    elapsed = time.monotonic() - started

    assert exit_code == 0
    assert elapsed < 5.0
    assert runtime.stop_reason == "test_thread"


# --------------------------------------------------------------------------- #
# The module entry point, as systemd invokes it
# --------------------------------------------------------------------------- #


def test_python_m_entry_point_responds_to_sigterm(tmp_path: Path) -> None:
    """End to end: the exact ExecStart form, stopped the way systemd stops it.

    A subprocess rather than an in-process call, because this is the only test
    that covers `__main__`, the console entry, signal delivery to a real process
    and a zero exit status all at once - which together are what "graceful
    shutdown" means for a service.
    """
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(AGENT_ROOT / "src"),
            "PYTHONUNBUFFERED": "1",
            ENV_DEV_MODE: "1",
            ENV_STATE_DIR: str(tmp_path / "state"),
            ENV_SERVER_URL: "https://ug.example.internal",
        }
    )

    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "ubuntuguard_agent", "run", "--config", str(tmp_path / "none.yaml")],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(2.0)
        assert process.poll() is None, "the agent exited before it was asked to"

        process.send_signal(signal.SIGTERM)
        stdout, _ = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:  # pragma: no cover
        process.kill()
        pytest.fail("the agent did not exit within 15 s of SIGTERM")

    assert process.returncode == 0, f"non-zero exit; output was:\n{stdout}"

    lines: list[dict[str, Any]] = [
        json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{")
    ]
    messages = [entry["msg"] for entry in lines]

    # Every line is structured JSON, which is what the journal receives.
    assert lines, f"no JSON log lines were produced; output was:\n{stdout}"
    assert any("starting" in message for message in messages)
    assert any("stopped" in message for message in messages)

    # The state directory was created, at the intended mode.
    import stat as stat_module

    pki = tmp_path / "state" / "pki"
    assert pki.is_dir()
    assert stat_module.S_IMODE(pki.stat().st_mode) == 0o700


# --------------------------------------------------------------------------- #
# The two honesty claims, asserted on the reporting surface
# --------------------------------------------------------------------------- #


def test_status_never_claims_the_release_is_validated(tmp_path: Path) -> None:
    """Separate from `platform_supported`, and false everywhere today.

    The adapter can be the correct implementation for a host the agent has
    never been run on. Reporting one field would let a green adapter be read as
    a tested release, which is the claim the brief forbids.
    """
    report, _ = collect_status(config_for(tmp_path))
    assert report["release_validated"] is False
    assert any("not been validated" in note for note in report["notes"])


def test_an_unvalidated_release_is_not_a_health_failure(tmp_path: Path) -> None:
    """Otherwise every device would be degraded until the validation is done.

    It is reported on every status, but health is about whether this agent can
    do its job, and "nobody has tested this release yet" does not change that.
    """
    config = config_for(tmp_path)
    ensure_runtime_paths(config.paths)
    config.paths.private_key_path.write_text("key")
    config.paths.certificate_path.write_bytes(issue_certificate())

    report, healthy = collect_status(config)
    assert report["release_validated"] is False
    assert healthy is True


def test_selftest_reports_adapter_and_validation_separately(tmp_path: Path) -> None:
    results = run_selftest(config_for(tmp_path))
    by_name = {result.name: result for result in results}

    assert by_name["os adapter"].passed is True
    assert by_name["release validated"].passed is False
    assert "not been validated" in by_name["release validated"].detail


def test_status_text_shows_the_release_caveat(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["status", "--config", str(tmp_path / "absent.yaml")])
    out = capsys.readouterr().out
    assert "release tested" in out
    assert "UNVALIDATED" in out


def test_the_startup_banner_warns_about_the_unvalidated_release(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """On every start, because it is true on every start."""
    import logging

    from ubuntuguard_agent.osadapter import detect_adapter

    logger = logging.getLogger("ubuntuguard_agent.test.release")
    logger.propagate = True
    with caplog.at_level(logging.WARNING, logger=logger.name):
        log_startup_banner(config_for(tmp_path), detect_adapter(), logger=logger)

    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "not been validated on this release" in messages
