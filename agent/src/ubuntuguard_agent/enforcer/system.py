"""OS adapter for enforcerd: capability probing and state readback.

Everything that touches the host lives here, behind injectable seams, so the
operation layer above stays pure and testable. `CommandRunner` and the paths
are constructor arguments rather than module globals precisely because the
interesting cases -- no usbguard, no systemd, unwritable rules.conf, a daemon
that claims success but changed nothing -- are impossible to arrange on a real
machine during a test run.

Two deliberate omissions:

**No package installation.** The older agent in this repo would apt-get
install usbguard when it was missing. That cannot happen here. UbuntuGuard's
threat model keeps package names out of the policy protocol entirely, and a
host without usbguard is a legitimate, reportable outcome -- `unsupported`
with `capability_missing` -- not an error to paper over. A dashboard showing
"unsupported" is honest; one showing green because the agent silently
installed something is not.

**No writing outside the usbguard paths.** The only paths this module writes
are the rules file and the daemon config it was constructed with, both of
which are local constants, never anything derived from a request.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

#: Default locations on Debian/Ubuntu.
DEFAULT_RULES_PATH = "/etc/usbguard/rules.conf"
DEFAULT_DAEMON_CONF = "/etc/usbguard/usbguard-daemon.conf"
DEFAULT_SERVICE = "usbguard.service"

#: rules.conf contains the authorisation policy; it is root-only because a
#: readable copy tells an attacker exactly which device to clone.
RULES_MODE = 0o600

_COMMAND_TIMEOUT = 60


class CommandRunner(Protocol):
    def __call__(self, cmd: list[str]) -> tuple[int, str]: ...


def run_command(cmd: list[str]) -> tuple[int, str]:
    """Run a command, returning (exit code, combined output).

    Always an argument list, never a shell string, and `shell=False` by
    default: there is no shell anywhere in this path, so nothing arriving in a
    request can become a shell metacharacter.

    This is the only place in the agent that runs an external program. The
    rest of it reads `/proc` and `/etc` directly, which is better and is not
    an option here: usbguard is driven through its own command-line tool, and
    the alternative is reimplementing its D-Bus protocol. The commands are
    module-level constants -- `usbguard`, `usbguard-rule-parser`, `systemctl`
    -- with only subcommands and a local rules path appended. No element of
    any command is ever taken from a policy payload.
    """
    try:
        # S603: the argument vector is built from constants in this module,
        # never from request data, and no shell is involved. Suppressed here
        # rather than project-wide so any future subprocess call is flagged.
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=_COMMAND_TIMEOUT, check=False
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]} timed out"
    except PermissionError as exc:
        return 126, str(exc)


# ---------------------------------------------------------------------------
# parsing `usbguard list-devices`
# ---------------------------------------------------------------------------

#: e.g. `7: allow id 03f0:1985 serial "070D..." name "USB Flash Drive" ...`
#:
#: Duplicated from agent.py rather than imported. agent.py is the push-based
#: control plane this integration replaces, so importing from it would couple
#: the new component to a module scheduled for deletion.
_DEVICE_LINE = re.compile(
    r"^\s*(?P<num>\d+):\s+(?P<target>allow|block|reject)\s+id\s+"
    r"(?P<vid>[0-9a-fA-F]{4}):(?P<pid>[0-9a-fA-F]{4})"
)
_QUOTED = {
    "serial": re.compile(r'\bserial\s+"([^"]*)"'),
    "name": re.compile(r'\bname\s+"([^"]*)"'),
    "via_port": re.compile(r'\bvia-port\s+"([^"]*)"'),
    "connect_type": re.compile(r'\bwith-connect-type\s+"([^"]*)"'),
}
_INTERFACE = re.compile(r"\bwith-interface\s+(?:\{\s*([^}]*)\}|(\S+))")

#: Daemon settings worth reporting. Each changes what enforcement means, so a
#: readback that ignored them could call a host compliant while
#: ImplicitPolicyTarget had been flipped to `allow`.
_DAEMON_KEYS = (
    "ImplicitPolicyTarget",
    "PresentDevicePolicy",
    "PresentControllerPolicy",
    "InsertedDevicePolicy",
    "RestoreControllerDeviceState",
    # The two below are not about what the policy means but about who may
    # replace it. See `ipc_exposure`.
    "IPCAllowedUsers",
    "IPCAllowedGroups",
)

#: Settings that hand USBGuard's IPC interface to a non-root principal.
#:
#: These grant *full* IPC access, not read-only: a user covered by them can
#: run `usbguard append-rule 'allow id *:*'` and authorise every device, or
#: `allow-device` on the specific stick the policy blocked. No root required.
#:
#: This is not hypothetical. The earlier agent in this repo wrote
#: `IPCAllowedGroups=plugdev` into the daemon config, and the primary user of
#: an Ubuntu desktop is normally in plugdev -- so the person the policy exists
#: to restrict could switch it off. Verified on a live host: `append-rule`
#: from an unprivileged plugdev account returned a new rule id.
#:
#: Read-only event access, which is what an unprivileged agent legitimately
#: needs, comes from the granular `IPCAccessControlFiles` mechanism instead
#: (`usbguard add-user --devices=listen`), which can grant listening without
#: granting modification.
_IPC_EXPOSURE_KEYS = ("IPCAllowedUsers", "IPCAllowedGroups")


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What this host can actually do, as facts rather than a verdict."""

    usbguard_present: bool
    usbguard_version: str | None
    daemon_unit_present: bool
    daemon_active: bool
    rules_path: str
    rules_writable: bool
    systemd_present: bool
    rule_parser_present: bool

    @property
    def supported(self) -> bool:
        """True when a usb_control policy can be applied and enforced here.

        The daemon need not be running yet -- enforcerd starts it -- but
        usbguard, its unit, systemd and a writable rules file are all
        prerequisites that enforcerd cannot create for itself.
        """
        return (
            self.usbguard_present
            and self.daemon_unit_present
            and self.systemd_present
            and self.rules_writable
        )

    @property
    def missing(self) -> tuple[str, ...]:
        """Which prerequisites are absent, for the `capability_missing` reason."""
        gaps = []
        if not self.usbguard_present:
            gaps.append("usbguard binary")
        if not self.systemd_present:
            gaps.append("systemctl")
        if not self.daemon_unit_present:
            gaps.append(f"{DEFAULT_SERVICE} unit")
        if not self.rules_writable:
            gaps.append(f"writable {self.rules_path}")
        return tuple(gaps)

    def as_dict(self) -> dict:
        return {
            "usbguard_present": self.usbguard_present,
            "usbguard_version": self.usbguard_version,
            "daemon_unit_present": self.daemon_unit_present,
            "daemon_active": self.daemon_active,
            "rules_path": self.rules_path,
            "rules_writable": self.rules_writable,
            "systemd_present": self.systemd_present,
            "rule_parser_present": self.rule_parser_present,
            "supported": self.supported,
            "missing": list(self.missing),
        }


def ipc_exposure(daemon_params: dict) -> tuple[str, ...]:
    """Non-root principals holding full USBGuard IPC access.

    Each entry can rewrite the policy at runtime, so a non-empty result means
    enforcement is advisory for those users however correct the rules are.
    Returned as findings rather than a boolean so the report names who.
    """
    findings: list[str] = []
    for key in _IPC_EXPOSURE_KEYS:
        raw = daemon_params.get(key)
        if not raw:
            continue
        for name in (part.strip() for part in raw.split()):
            if not name:
                continue
            if key == "IPCAllowedUsers" and name == "root":
                continue
            findings.append(f"{key}={name}")
    return tuple(findings)


@dataclass(frozen=True, slots=True)
class UsbState:
    """Observed state, read back from the OS rather than assumed."""

    rules_text: str
    rules_fingerprint: str | None
    loaded_rules: tuple[str, ...]
    devices: tuple[dict, ...]
    daemon_params: dict
    daemon_active: bool
    #: False when the daemon config could not be read at all. Tracked
    #: separately because an unreadable config and a clean one both yield no
    #: findings, and reporting "not bypassable" for the first would be the
    #: same false green this check exists to prevent.
    daemon_conf_readable: bool = True

    @property
    def ipc_exposure(self) -> tuple[str, ...]:
        return ipc_exposure(self.daemon_params)

    def as_dict(self) -> dict:
        exposure = self.ipc_exposure
        return {
            "rules_fingerprint": self.rules_fingerprint,
            "loaded_rule_count": len(self.loaded_rules),
            "loaded_rules": list(self.loaded_rules),
            "devices": [dict(d) for d in self.devices],
            "daemon_params": dict(self.daemon_params),
            "daemon_active": self.daemon_active,
            "daemon_conf_readable": self.daemon_conf_readable,
            # Reported alongside the rules because it decides whether they
            # mean anything. A dashboard showing a correct policy on a host
            # where the user can delete it is showing a false green.
            "ipc_exposure": list(exposure),
            # None, not False, when the config could not be read: unknown is
            # a third answer and collapsing it into "no" loses the warning.
            "enforcement_bypassable_without_root": (
                bool(exposure) if self.daemon_conf_readable else None
            ),
        }


class HostError(Exception):
    """An OS-level operation failed. Carries a machine-readable reason code.

    Named for the host rather than the builtin `SystemError`, which means
    something entirely different and must not be shadowed.
    """

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


@dataclass
class UsbGuardSystem:
    """Capability probing, state readback and rule installation."""

    rules_path: str = DEFAULT_RULES_PATH
    daemon_conf_path: str = DEFAULT_DAEMON_CONF
    service: str = DEFAULT_SERVICE
    runner: CommandRunner = run_command
    which: Callable[[str], str | None] = shutil.which

    # -- capability probing ------------------------------------------------

    def capabilities(self) -> Capabilities:
        usbguard = self.which("usbguard") is not None
        systemd = self.which("systemctl") is not None

        version = None
        if usbguard:
            code, out = self.runner(["usbguard", "--version"])
            if code == 0 and out:
                # "usbguard 1.1.4 compiled with: ..." -- take the token after
                # the name and nothing else; the build flags are noise here.
                parts = out.split()
                if len(parts) >= 2:
                    version = parts[1]

        unit_present = False
        if systemd:
            unit_present = self.runner(["systemctl", "cat", self.service])[0] == 0

        return Capabilities(
            usbguard_present=usbguard,
            usbguard_version=version,
            daemon_unit_present=unit_present,
            daemon_active=self.daemon_active() if systemd else False,
            rules_path=self.rules_path,
            rules_writable=self._rules_writable(),
            systemd_present=systemd,
            rule_parser_present=self.which("usbguard-rule-parser") is not None,
        )

    def _rules_writable(self) -> bool:
        """Can we write the rules file, creating it if absent?

        Testing the parent directory when the file does not yet exist matters
        on a fresh install, where the package has been removed but the
        directory remains, or vice versa.
        """
        path = Path(self.rules_path)
        if path.exists():
            return os.access(path, os.W_OK)
        parent = path.parent
        return parent.is_dir() and os.access(parent, os.W_OK)

    def require_supported(self) -> Capabilities:
        """Return capabilities, or raise with `capability_missing`."""
        caps = self.capabilities()
        if not caps.supported:
            raise HostError(
                "capability_missing",
                "host cannot enforce usb_control policy; missing: "
                + ", ".join(caps.missing),
            )
        return caps

    # -- readback ----------------------------------------------------------

    def daemon_active(self) -> bool:
        code, out = self.runner(["systemctl", "is-active", self.service])
        return code == 0 and out.strip() == "active"

    def read_rules_file(self) -> str:
        try:
            return Path(self.rules_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""
        except PermissionError as exc:
            raise HostError(
                "readback_failed", f"cannot read {self.rules_path}: {exc}"
            ) from exc

    def loaded_rules(self) -> tuple[str, ...]:
        """Rules the daemon has actually loaded.

        Distinct from the file on disk: the file is intent, this is what is
        live. They diverge whenever a write succeeded but the reload did not.
        """
        code, out = self.runner(["usbguard", "list-rules"])
        if code != 0:
            return ()
        rules = []
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # list-rules prefixes an index: "3: allow id 0781:5583"
            rules.append(re.sub(r"^\d+:\s*", "", stripped))
        return tuple(rules)

    def devices(self) -> tuple[dict, ...]:
        """Live devices and the decision usbguard made about each.

        This is the authorisation state the kernel is enforcing, which is the
        only evidence that a policy did what it claimed.
        """
        code, out = self.runner(["usbguard", "list-devices"])
        if code != 0:
            return ()

        found: list[dict] = []
        for line in out.splitlines():
            match = _DEVICE_LINE.match(line)
            if not match:
                continue
            entry: dict = {
                "target": match.group("target"),
                "usb_id": f"{match.group('vid').lower()}:"
                f"{match.group('pid').lower()}",
            }
            for key, pattern in _QUOTED.items():
                hit = pattern.search(line)
                entry[key] = hit.group(1) if hit else ""

            iface = _INTERFACE.search(line)
            interfaces: list[str] = []
            if iface:
                raw = iface.group(1) or iface.group(2) or ""
                interfaces = [tok for tok in raw.split() if tok]
            entry["interfaces"] = interfaces
            entry["classes"] = sorted(
                {tok.split(":")[0].lower() for tok in interfaces if ":" in tok}
            )
            found.append(entry)
        return tuple(found)

    def read_daemon_conf(self) -> tuple[dict, bool]:
        """Return (settings, readable).

        The flag matters: enforcerd runs as root and can read the config, but
        anything else calling this gets PermissionError, and silently
        returning no settings would look identical to a host with nothing
        worrying in it.
        """
        params = self.daemon_params()
        return params, Path(self.daemon_conf_path).is_file() and bool(
            os.access(self.daemon_conf_path, os.R_OK)
        )

    def daemon_params(self) -> dict:
        """The daemon settings that change what enforcement means."""
        params: dict = {}
        try:
            text = Path(self.daemon_conf_path).read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError):
            return params
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            if key in _DAEMON_KEYS:
                params[key] = value.strip()
        return params

    def state(self) -> UsbState:
        """Read everything back from the OS."""
        from . import derive  # local import: avoids a cycle at module load

        rules_text = self.read_rules_file()
        params, readable = self.read_daemon_conf()
        return UsbState(
            rules_text=rules_text,
            rules_fingerprint=derive.extract_fingerprint(rules_text),
            loaded_rules=self.loaded_rules(),
            devices=self.devices(),
            daemon_params=params,
            daemon_active=self.daemon_active(),
            daemon_conf_readable=readable,
        )

    # -- installation ------------------------------------------------------

    def write_rules(self, policy_text: str) -> None:
        """Install rules.conf atomically, root-readable only.

        Written to a temporary file in the same directory and renamed, so a
        concurrent daemon reload never sees a half-written policy. The mode is
        set before the rename for the same reason: there must be no instant at
        which the final path exists and is world-readable.
        """
        path = Path(self.rules_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        except OSError as exc:
            raise HostError(
                "enforce_failed", f"cannot prepare {self.rules_path}: {exc}"
            ) from exc
        tmp_path = Path(tmp)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(policy_text)
            tmp_path.chmod(RULES_MODE)
            tmp_path.replace(path)
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            raise HostError(
                "enforce_failed", f"cannot write {self.rules_path}: {exc}"
            ) from exc

    def validate_rules_file(self) -> None:
        """Ask usbguard's own parser to check the installed file, if present.

        Catching a malformed policy here means the daemon restart below fails
        for a reason we can report, rather than leaving the daemon down with
        no rules loaded -- which, depending on ImplicitPolicyTarget, is either
        a wide-open machine or one with no working keyboard.
        """
        if self.which("usbguard-rule-parser") is None:
            return
        code, out = self.runner(
            ["usbguard-rule-parser", "-f", self.rules_path]
        )
        if code != 0:
            raise HostError(
                "enforce_failed",
                f"usbguard rejected the generated policy: {out[-300:]}",
            )

    def reload_daemon(self) -> None:
        """Enable and restart usbguard so the new rules take effect."""
        self.runner(["systemctl", "enable", self.service])
        code, out = self.runner(["systemctl", "restart", self.service])
        if code != 0:
            raise HostError(
                "enforce_failed", f"could not restart {self.service}: {out[-300:]}"
            )
        if not self.daemon_active():
            raise HostError(
                "enforce_failed",
                f"{self.service} did not stay active after restart",
            )
