"""Command-line interface.

Five subcommands, each with a defined exit code, because these are meant to be
driven by systemd and by shell scripts as much as by a person:

    run       start the service loop. 0 on a clean stop, 1 on a fatal error.
    enroll    acquire a device identity. 0 enrolled, 1 refused or unreachable.
    status    report what the agent knows about itself. 0 healthy, 1 degraded.
    selftest  check the installation. 0 all passed, 1 at least one failed.
    version   print the version. Always 0.

`status` returning 1 for "degraded" rather than 0 is deliberate: a monitoring
script should be able to tell "the agent is installed and healthy" from "the
agent is installed and has no identity" without parsing text. Both are normal
states, but only one of them means the device is actually managed.

`enroll` is a separate command rather than something `run` does on its own
start-up. That is feature D11 and it is a deliberate constraint: enrollment
spends a single-use token and creates an auditable identity, so it is an
operator action with a person behind it, not a side effect of a service
starting. It also means a laptop that is reimaged does not silently acquire a
second device record because systemd brought the agent up.

**There is no `--token` option, and its absence is a security control.**
See `enrollment.read_token_from_file` for why. An option that accepted a token
and then warned about it would be worse than none: by the time the warning is
printed, `/proc/<pid>/cmdline` has already published the value to every user
on the machine.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ubuntuguard_agent import __version__
from ubuntuguard_agent.config import AgentConfig, load_config
from ubuntuguard_agent.enrollment import enroll, read_token_from_file, read_token_from_stdin
from ubuntuguard_agent.errors import AgentError, ConfigError, InsecureFileError
from ubuntuguard_agent.identity import (
    PRIVATE_FILE_MODE,
    assert_private_file,
    is_enrolled,
    read_certificate,
)
from ubuntuguard_agent.logging_setup import configure_logging, get_logger
from ubuntuguard_agent.osadapter import detect_adapter
from ubuntuguard_agent.service import run_service

EXIT_OK = 0
EXIT_ERROR = 1

PROGRAM = "ubuntuguard-agent"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="UbuntuGuard endpoint agent.",
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--config",
            type=Path,
            default=None,
            metavar="PATH",
            help="Configuration file (default: /etc/ubuntuguard/agent.yaml)",
        )

    run_parser = subparsers.add_parser("run", help="Run the agent service loop")
    add_common(run_parser)
    run_parser.add_argument(
        "--log-level",
        choices=("error", "warn", "info", "debug"),
        default=None,
        help="Override the log level for this invocation only",
    )

    enroll_parser = subparsers.add_parser(
        "enroll",
        help="Acquire a device identity using a one-time enrollment token",
        description=(
            "Generate a device keypair, exchange a one-time token and a CSR for a "
            "client certificate, and install it. The private key is generated on "
            "this machine and never transmitted.\n\n"
            "The token must come from a file or from standard input. There is "
            "deliberately no option to pass it as an argument: anything in a "
            "command line is readable by every user on the machine via "
            "/proc/<pid>/cmdline and visible in ps."
        ),
    )
    add_common(enroll_parser)
    # required=True, so `enroll` with neither flag prints the usage rather than
    # doing something surprising. Mutually exclusive, because a run that was
    # given two sources would have to pick one, and the operator would not know
    # which.
    token_source = enroll_parser.add_mutually_exclusive_group(required=True)
    token_source.add_argument(
        "--token-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Read the token from this file. Must be mode 0600 or tighter.",
    )
    token_source.add_argument(
        "--token-stdin",
        action="store_true",
        help="Read the token from standard input, e.g. from a password manager.",
    )
    enroll_parser.add_argument(
        "--log-level",
        choices=("error", "warn", "info", "debug"),
        default=None,
        help="Override the log level for this invocation only",
    )

    status_parser = subparsers.add_parser("status", help="Report agent and identity status")
    add_common(status_parser)
    status_parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON instead of text"
    )

    selftest_parser = subparsers.add_parser(
        "selftest", help="Check configuration, paths and file permissions"
    )
    add_common(selftest_parser)

    subparsers.add_parser("version", help="Print the agent version")
    return parser


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #


def collect_status(config: AgentConfig) -> tuple[dict[str, Any], bool]:
    """Gather status. Returns the report and whether the agent is healthy.

    Healthy means: a server is configured, an identity exists, and the
    certificate is present, parseable and unexpired. Anything else is degraded,
    including the perfectly normal "freshly installed, not yet enrolled".
    """
    adapter = detect_adapter()
    facts = adapter.host_facts()

    report: dict[str, Any] = {
        "agent_version": __version__,
        "release_build": config.release_build,
        "config_path": str(config.config_path) if config.config_path else None,
        "server_url": config.server_url,
        "server_configured": config.is_configured,
        "plaintext_http_permitted": config.plaintext_http_permitted,
        "adapter": adapter.name,
        # Two separate claims, reported separately. The first says the adapter
        # is the right implementation for this host; the second says the agent
        # has actually been exercised on this release. The second is currently
        # false everywhere, and will stay false until it has been.
        "platform_supported": adapter.is_supported(),
        "release_validated": adapter.is_validated_release(),
        "host": {
            "hostname": facts.hostname,
            "os": facts.os.short,
            "pretty_name": facts.os.pretty_name,
            "kernel": facts.kernel,
            "arch": facts.arch,
            "uptime_seconds": facts.uptime_seconds,
        },
        "state_dir": str(config.paths.state_dir),
        "enrolled": is_enrolled(config.paths),
        "certificate": None,
        # Stated in every status report rather than left to documentation.
        #
        # Still False, and the nuance matters. The agent now presents its
        # client certificate on every device-plane request, and a configuration
        # that terminates mTLS correctly exists in deploy/nginx/. What the
        # agent cannot do is verify from here that the server it reached is
        # actually enforcing `ssl_verify_client on` rather than accepting
        # forwarded headers from anyone. Reporting True would be reporting
        # something this process has no way to check, so it reports the
        # configuration it can see and leaves the claim to whoever deployed the
        # proxy.
        "mtls_verified": False,
        "notes": [],
    }

    healthy = config.is_configured
    notes: list[str] = []

    if not config.is_configured:
        notes.append("no server_url configured; the agent can only idle")

    if not adapter.is_supported():
        notes.append(
            f"host os-release ID is {facts.os.id!r}; Ubuntu is the only "
            "implemented platform, so collection here is UNVALIDATED"
        )

    if not adapter.is_validated_release():
        # Not a health failure: the agent runs, and saying otherwise would make
        # every device degraded until the validation work is done. It is stated
        # on every report because "we have not tested this" is something an
        # operator should have to see rather than go looking for.
        notes.append(
            f"the agent has not been validated on {facts.os.short or 'this release'}; "
            "no enforcement or compatibility claim here is proven"
        )

    if not config.release_build:
        notes.append("development build: environment overrides are active")

    try:
        summary = read_certificate(config.paths)
    except ValueError as exc:
        notes.append(f"certificate present but unreadable: {exc}")
        healthy = False
        summary = None

    if summary is None:
        if report["enrolled"]:
            notes.append(
                "private key present but no certificate; enrollment did not complete. "
                "Re-run `ubuntuguard-agent enroll` with a new token: the existing "
                "keypair will be reused, which is correct"
            )
            healthy = False
        else:
            notes.append(
                "not enrolled; run `ubuntuguard-agent enroll --token-file <path>` "
                "with a token from the dashboard"
            )
            healthy = False
    else:
        now = dt.datetime.now(dt.timezone.utc)
        report["certificate"] = {
            "device_id": summary.device_id,
            "not_before": summary.not_before.isoformat(),
            "not_after": summary.not_after.isoformat(),
            "renew_after": summary.renew_after.isoformat(),
            "fingerprint": summary.fingerprint,
            "days_remaining": round(summary.seconds_remaining(now=now) / 86400, 1),
            "expired": summary.is_expired(now=now),
            "renewal_due": summary.renewal_due(now=now),
        }
        if summary.is_expired(now=now):
            notes.append("certificate has expired")
            healthy = False
        elif summary.renewal_due(now=now):
            notes.append("certificate renewal is due; renewal arrives in Phase 5")

    report["notes"] = notes
    report["healthy"] = healthy
    return report, healthy


def _render_status_text(report: dict[str, Any]) -> str:
    lines = [
        f"agent            {report['agent_version']}"
        f"{'' if report['release_build'] else '  (development build)'}",
        f"health           {'healthy' if report['healthy'] else 'degraded'}",
        f"config           {report['config_path'] or 'not found'}",
        f"server           {report['server_url'] or 'not configured'}",
        f"adapter          {report['adapter']}"
        f"{'' if report['platform_supported'] else '  (no adapter for this OS)'}",
        f"release tested   {'yes' if report['release_validated'] else 'no  (UNVALIDATED)'}",
        f"host             {report['host']['hostname']}  {report['host']['os']}"
        f"  {report['host']['kernel']}  {report['host']['arch']}",
        f"state            {report['state_dir']}",
        f"enrolled         {'yes' if report['enrolled'] else 'no'}",
    ]
    certificate = report.get("certificate")
    if certificate:
        lines += [
            f"device id        {certificate['device_id']}",
            f"certificate      expires {certificate['not_after']}"
            f"  ({certificate['days_remaining']} days)",
            f"renewal due      {'yes' if certificate['renewal_due'] else 'no'}"
            f"  (at {certificate['renew_after']})",
        ]
    lines.append(
        "mTLS verified    no  (the agent cannot confirm the proxy enforces it; "
        "see deploy/nginx/README.md)"
    )
    for note in report["notes"]:
        lines.append(f"  - {note}")
    return "\n".join(lines)


def command_status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    report, healthy = collect_status(config)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_status_text(report))
    return EXIT_OK if healthy else EXIT_ERROR


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str


def run_selftest(config: AgentConfig) -> list[CheckResult]:
    """Check an installation without changing it.

    Read-only on purpose. A selftest that created the directories it was
    checking for would always pass, which is the kind of test that tells you
    nothing on the one occasion it matters.
    """
    results: list[CheckResult] = []
    paths = config.paths

    results.append(
        CheckResult(
            "configuration file",
            config.config_path is not None,
            str(config.config_path) if config.config_path else "not found (using defaults)",
        )
    )
    results.append(
        CheckResult(
            "server_url",
            config.is_configured,
            config.server_url or "not configured",
        )
    )

    if config.server_ca_bundle is None:
        results.append(
            CheckResult(
                "server CA bundle",
                False,
                "not configured; the agent cannot validate the server's TLS certificate",
            )
        )
    else:
        exists = config.server_ca_bundle.exists()
        results.append(
            CheckResult(
                "server CA bundle",
                exists,
                f"{config.server_ca_bundle}{'' if exists else ' (missing)'}",
            )
        )

    for label, directory in (
        ("state directory", paths.state_dir),
        ("pki directory", paths.pki_dir),
    ):
        results.append(
            CheckResult(
                label,
                directory.is_dir(),
                f"{directory}{'' if directory.is_dir() else ' (missing)'}",
            )
        )

    key_path = paths.private_key_path
    if not key_path.exists():
        results.append(
            CheckResult("private key", False, f"{key_path} (absent; device is not enrolled)")
        )
    else:
        try:
            assert_private_file(key_path)
            results.append(
                CheckResult(
                    "private key permissions", True, f"{key_path} is {PRIVATE_FILE_MODE:04o}"
                )
            )
        except InsecureFileError as exc:
            results.append(CheckResult("private key permissions", False, str(exc)))

    try:
        summary = read_certificate(paths)
    except ValueError as exc:
        results.append(CheckResult("certificate", False, str(exc)))
    else:
        if summary is None:
            results.append(CheckResult("certificate", False, "absent; device is not enrolled"))
        else:
            expired = summary.is_expired()
            results.append(
                CheckResult(
                    "certificate",
                    not expired,
                    f"device {summary.device_id}, expires {summary.not_after.isoformat()}"
                    f"{' (EXPIRED)' if expired else ''}",
                )
            )

    adapter = detect_adapter()
    release = adapter.host_facts().os.short
    results.append(
        CheckResult(
            "os adapter",
            adapter.is_supported(),
            f"{adapter.name} adapter for {release}"
            f"{'' if adapter.is_supported() else ' (no adapter implements this OS)'}",
        )
    )
    # Reported as its own line rather than folded into the adapter check, so a
    # green adapter can never be read as "this release has been tested".
    results.append(
        CheckResult(
            "release validated",
            adapter.is_validated_release(),
            f"{release} is a tested release"
            if adapter.is_validated_release()
            else f"{release} has not been validated; no compatibility claim is proven",
        )
    )
    return results


def command_selftest(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    results = run_selftest(config)
    width = max(len(result.name) for result in results)
    for result in results:
        mark = "PASS" if result.passed else "FAIL"
        print(f"[{mark}] {result.name.ljust(width)}  {result.detail}")
    failed = [result for result in results if not result.passed]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    return EXIT_OK if not failed else EXIT_ERROR


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #


def command_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    level = args.log_level or config.settings.log_level
    configure_logging(level)
    return run_service(config)


# --------------------------------------------------------------------------- #
# enroll
# --------------------------------------------------------------------------- #


def command_enroll(args: argparse.Namespace) -> int:
    """Read the token, enrol, and print what happened.

    Logging is configured BEFORE the token is read, so that the redaction
    filter is installed on the handler by the time any line could carry it.
    The registry itself is process-wide and is populated inside
    `read_token_from_*`, so the ordering here is belt and braces rather than
    the only defence - but the ordering is free and the failure mode is a
    token in a journal.
    """
    config = load_config(args.config)
    configure_logging(args.log_level or config.settings.log_level)

    token = read_token_from_stdin() if args.token_stdin else read_token_from_file(args.token_file)

    result = enroll(config, token=token)

    # Printed to stdout for the operator, separately from the structured log
    # lines. Note what is absent: the token, the certificate and any
    # fingerprint. A device id is not a secret and is what an operator needs to
    # find the laptop in the dashboard.
    print(f"enrolled as device {result.device_id}")
    print(f"  certificate expires  {result.certificate.not_after.isoformat()}")
    print(f"  renewal due          {result.certificate.renew_after.isoformat()}")
    print(f"  policy keys pinned   {len(result.policy_public_keys)}")
    if result.reused_keypair:
        print("  reused the existing keypair in pki/ (an earlier attempt had created it)")
    if result.clone_suspected:
        print(
            "\n  WARNING: the server flagged this device as a possible clone of an\n"
            "  existing one and raised an incident. Enrollment succeeded as a\n"
            "  distinct device. If this laptop was reimaged that is expected; if it\n"
            "  was not, somebody has a copy of a disk image."
        )
    print("\nStart the service to begin heartbeating:\n    systemctl start ubuntuguard-agent")
    return EXIT_OK


# --------------------------------------------------------------------------- #


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"{PROGRAM} {__version__}")
        return EXIT_OK

    handlers = {
        "run": command_run,
        "enroll": command_enroll,
        "status": command_status,
        "selftest": command_selftest,
    }
    handler = handlers.get(args.command)
    if handler is None:  # pragma: no cover - argparse enforces the choices
        # Reachable only if a subcommand is added to the parser and not here.
        raise SystemExit(f"{PROGRAM}: unknown command {args.command!r}")

    try:
        return handler(args)
    except ConfigError as exc:
        # Configuration problems are reported on stderr in plain text, not as a
        # JSON log line. At this point logging may not be configured, and the
        # reader is a person running a command.
        print(f"{PROGRAM}: configuration error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except AgentError as exc:
        print(f"{PROGRAM}: {exc.reason_code}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        get_logger("cli").info("interrupted")
        return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
