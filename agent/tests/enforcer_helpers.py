"""Test helpers shared between the enforcer test modules.

A module rather than conftest fixtures, following the same reasoning as
`helpers.py`: `FakeHost` is configured by setting attributes after
construction, and a fixture returning a half-built object reads worse at every
call site than a plain import.

`FakeHost` is the centrepiece. It stands in for a machine running usbguard and
models the one behaviour that matters -- a daemon restart loads whatever is in
the rules file -- then lets a test switch on the specific ways a real host
misbehaves. A daemon that restarts cleanly and loads nothing, or loads
something other than what was written, is exactly what the verify step exists
to catch, and neither can be produced on demand on real hardware.

Nothing here needs root, a usbguard installation or a running daemon.
"""

from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from ubuntuguard_agent.enforcer import ops, snapshots, system

#: Fixed clock, so every derived policy and snapshot id is reproducible.
NOW = dt.datetime(2026, 10, 29, 10, 0, 0, tzinfo=dt.timezone.utc)

# ---------------------------------------------------------------------------
# the authored contract
# ---------------------------------------------------------------------------

#: agent/tests/enforcer_helpers.py -> agent/ -> repository root.
#: Same derivation as `conftest.REPO_ROOT`.
_REPO_ROOT = Path(__file__).resolve().parents[2]

#: The authored examples, when this package sits in the UbuntuGuard
#: repository. Preferred over the bundled copy, so the contract tests run
#: against the live examples and a drift between the two cannot go unnoticed.
_LIVE_EXAMPLES = _REPO_ROOT / "schemas" / "examples"

#: Byte-identical copies, carried so the suite still runs when the enforcer is
#: developed outside the UbuntuGuard tree.
_BUNDLED_EXAMPLES = Path(__file__).parent / "enforcer_contract"


def contract_root() -> Path:
    return _LIVE_EXAMPLES if _LIVE_EXAMPLES.is_dir() else _BUNDLED_EXAMPLES


def contract_is_live() -> bool:
    """True when reading the authored examples rather than the bundled copy."""
    return _LIVE_EXAMPLES.is_dir()


def load_example(category: str, name: str) -> dict:
    """Load one named example from `valid/` or `invalid/`."""
    path = contract_root() / category / name
    return json.loads(path.read_text(encoding="utf-8"))


def usb_control_examples(category: str) -> list[Path]:
    """Every `usb_control` policy example in `valid/` or `invalid/`.

    Filtered by filename rather than globbed wholesale. The examples directory
    also holds event, inventory, envelope and agent_settings documents, and a
    bare `*.json` would feed those to a usb_control parser that is right to
    reject them.
    """
    prefix = "policy.usb_control." if category == "valid" else "usb_control."
    return sorted(
        path
        for path in contract_root().joinpath(category).glob("*.json")
        if path.name.startswith(prefix)
    )

DAEMON_CONF = """\
# usbguard daemon configuration
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/
"""

#: Two devices: a hub and the HP flash drive this project was tested against.
LIST_DEVICES = """\
0: allow id 1d6b:0002 serial "0000:00:14.0" name "xHCI Host Controller" \
hash "abc" parent-hash "def" via-port "usb1" with-interface { 09:00:00 } \
with-connect-type ""
7: block id 03f0:1985 serial "070D5867E317C137" name "USB Flash Drive" \
hash "ghi" parent-hash "jkl" via-port "1-3" with-interface { 08:06:50 } \
with-connect-type "hotplug"
"""

#: The rule GNOME's `gsd-usb-protection` appends over USBGuard's D-Bus
#: interface, copied verbatim from `usbguard list-rules` on an Ubuntu desktop.
#: It is allow-everything, and it reappears after a daemon restart, so
#: verification has to tolerate it behind the policy while still refusing to
#: let it sit in front.
GNOME_RULE = 'allow id *:* label "GNOME_SETTINGS_DAEMON_RULE"'


def base_payload(**overrides) -> dict:
    """A minimal valid `usb_control` payload, overridable per test."""
    payload = {
        "schema": "ubuntuguard.usb_control.v1",
        "mode": "allowlist_enforce",
        "protected_classes": ["mass_storage"],
        "always_allow_classes": ["hid", "hub"],
        "allowlist": [],
        "exceptions": [],
        "reporting": {
            "report_allowed": True,
            "report_blocked": True,
            "report_present_at_start": True,
        },
    }
    payload.update(overrides)
    return payload


def effective(text: str) -> list[str]:
    """The rule lines of a policy, without comments or blanks."""
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class FakeHost:
    """A fake usbguard host, with switches for the interesting failures."""

    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.loaded: list[str] = []
        self.calls: list[list[str]] = []

        self.has_usbguard = True
        self.has_systemctl = True
        self.has_parser = True
        self.unit_present = True
        self.active = True

        #: restart exits non-zero, every time
        self.restart_fails = False
        #: restart exits non-zero for this many calls, then recovers
        self.restart_fails_times = 0
        #: restart exits 0 but the daemon loads nothing
        self.restart_loads_nothing = False
        #: restart exits 0 but the daemon loads these rules instead
        self.loads_instead: list[str] | None = None
        #: rules another component appends after the daemon loads the file,
        #: the way GNOME's gsd-usb-protection does over D-Bus
        self.appends_after: list[str] = []
        #: the rule parser rejects the file
        self.parser_rejects = False
        #: `systemctl is-active` reports inactive after a restart
        self.dies_after_restart = False

    # -- the seams the system adapter uses ---------------------------------

    def which(self, name: str) -> str | None:
        table = {
            "usbguard": self.has_usbguard,
            "systemctl": self.has_systemctl,
            "usbguard-rule-parser": self.has_parser,
        }
        return f"/usr/bin/{name}" if table.get(name, False) else None

    def runner(self, cmd: list[str]) -> tuple[int, str]:
        self.calls.append(list(cmd))

        if cmd[0] == "usbguard":
            if not self.has_usbguard:
                return 127, "usbguard not found"
            if cmd[1:] == ["--version"]:
                return 0, "usbguard 1.1.4 compiled with:\n  audit: enabled"
            if cmd[1:] == ["list-rules"]:
                return 0, "\n".join(
                    f"{index}: {rule}" for index, rule in enumerate(self.loaded)
                )
            if cmd[1:] == ["list-devices"]:
                return 0, LIST_DEVICES
            return 1, "unknown usbguard subcommand"

        if cmd[0] == "usbguard-rule-parser":
            if not self.has_parser:
                return 127, "not found"
            return (1, "syntax error") if self.parser_rejects else (0, "OK")

        if cmd[0] == "systemctl":
            if not self.has_systemctl:
                return 127, "systemctl not found"
            action = cmd[1]
            if action == "cat":
                return (0, "# unit") if self.unit_present else (1, "not found")
            if action == "is-active":
                return (0, "active") if self.active else (3, "inactive")
            if action == "enable":
                return 0, ""
            if action == "restart":
                if self.restart_fails_times > 0:
                    self.restart_fails_times -= 1
                    return 1, "Job for usbguard.service failed"
                if self.restart_fails:
                    return 1, "Job for usbguard.service failed"
                if self.dies_after_restart:
                    self.active = False
                    return 0, ""
                self.active = True
                if self.restart_loads_nothing:
                    self.loaded = []
                elif self.loads_instead is not None:
                    self.loaded = list(self.loads_instead)
                else:
                    # What a real daemon does: load the file it was given.
                    self.loaded = effective(
                        Path(self.rules_path).read_text(encoding="utf-8")
                    )
                self.loaded += self.appends_after
                return 0, ""
            return 1, f"unknown systemctl action {action}"

        return 127, f"{cmd[0]} not found"


class EnforcerFixture(unittest.TestCase):
    """Builds an Enforcer wired to a FakeHost in a temporary directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

        etc = root / "etc" / "usbguard"
        etc.mkdir(parents=True)
        self.rules_path = etc / "rules.conf"
        self.daemon_conf = etc / "usbguard-daemon.conf"
        self.daemon_conf.write_text(DAEMON_CONF, encoding="utf-8")

        self.host = FakeHost(str(self.rules_path))
        self.system = system.UsbGuardSystem(
            rules_path=str(self.rules_path),
            daemon_conf_path=str(self.daemon_conf),
            runner=self.host.runner,
            which=self.host.which,
        )
        self.store = snapshots.SnapshotStore(
            directory=str(root / "snapshots"), retention=5
        )
        self.enforcer = ops.Enforcer(
            system=self.system, store=self.store, clock=lambda: NOW
        )

    def set_policy(self, payload=None, **kwargs):
        return self.enforcer.handle(
            {
                "op": ops.OP_USB_SET_POLICY,
                "payload": {"policy": payload or base_payload()},
                **kwargs,
            }
        )
