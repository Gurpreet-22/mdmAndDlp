"""The Ubuntu adapter. The one implementation of `OsAdapter` that exists.

Everything is read from the standard Linux interfaces - `/etc/os-release`,
`/proc`, `/etc/machine-id` - and nothing is assumed. In particular the agent
does not hardcode "ubuntu" or a version: it reports what os-release says, so a
device running something untested shows up as what it is.

A note on compatibility, because the brief is explicit about not overstating it:
**this has not been tested on Ubuntu 22.04 or 24.04.** It is written against
interfaces those releases provide and is exercised by the test suite against
synthetic fixtures and against the development machine (Ubuntu 26.04). That is
not the same as running on a target release, and until it does, support for
22.04 and 24.04 is UNVALIDATED.

The filesystem root is injectable. Tests therefore run against a directory tree
they built, rather than mocking `open`, which means the parsing path under test
is the real one.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Callable
from pathlib import Path

from ubuntuguard_agent.osadapter.base import HostFacts, OsRelease
from ubuntuguard_agent.osadapter.facts import (
    detect_virtualization,
    hash_mac,
    is_physical_interface,
    parse_os_release,
    parse_uptime,
    sha256_hex,
)

#: os-release IDs this adapter considers itself a correct choice for. Reported,
#: never enforced: an unrecognised system gets a warning and a running agent,
#: not a refusal.
SUPPORTED_OS_IDS: frozenset[str] = frozenset({"ubuntu"})

#: Releases the agent has actually been exercised on.
#:
#: **Deliberately empty.** Nothing has been validated on a target release yet.
#: "This adapter is the right implementation for this host" and "the agent has
#: been shown to work on this release" are different claims, and conflating them
#: is what the brief forbids - so they are two separate methods, and this set is
#: the one that cannot be filled in from a code review.
#:
#: Add "22.04" and "24.04" here only once the agent has been installed and run
#: on those releases and the evidence committed.
VALIDATED_OS_VERSION_IDS: frozenset[str] = frozenset()

#: Relative to the injected root, so a test can supply all of them.
_OS_RELEASE_PATHS = ("etc/os-release", "usr/lib/os-release")
_UPTIME_PATH = "proc/uptime"
_BOOT_ID_PATH = "proc/sys/kernel/random/boot_id"
_MACHINE_ID_PATHS = ("etc/machine-id", "var/lib/dbus/machine-id")
_DMI_PRODUCT_UUID_PATH = "sys/class/dmi/id/product_uuid"
_DMI_SYS_VENDOR_PATH = "sys/class/dmi/id/sys_vendor"
_DMI_PRODUCT_NAME_PATH = "sys/class/dmi/id/product_name"
_CPUINFO_PATH = "proc/cpuinfo"
_NET_CLASS_DIR = "sys/class/net"

#: Files whose presence identifies a container runtime. Checked before DMI,
#: because a container inside a VM should report the container.
_CONTAINER_MARKERS: tuple[tuple[str, str], ...] = (
    (".dockerenv", "docker"),
    ("run/.containerenv", "podman"),
)

#: Hard cap on how many MAC hashes are reported. The server's
#: `HardwareFingerprint.mac_hashes` has `max_length=32` and rejects more with a
#: 422, so the limit is enforced here rather than discovered at enrollment.
MAX_MAC_HASHES = 32

#: RFC 5737 TEST-NET-1. Used only as a `connect()` target on a UDP socket to
#: make the kernel perform a route lookup; see `primary_adapter_ip`.
_ROUTE_PROBE_ADDRESS = ("192.0.2.1", 9)


def _read_text(path: Path) -> str | None:
    """Read a file, returning None for anything that makes it unreadable.

    Deliberately broad. Every file this adapter reads is optional in at least
    one real situation: `/sys/class/dmi/id/product_uuid` is root-only,
    `/etc/machine-id` may not exist yet on a first boot, and `/proc` entries are
    missing in some container runtimes. An agent that raised on any of those
    would fail to start on the hosts it most needs to report from, so each read
    degrades to None and the caller decides what that means.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


class UbuntuAdapter:
    """Reads host facts from standard Linux interfaces."""

    name = "ubuntu"

    def __init__(
        self,
        root: Path | None = None,
        *,
        hostname_fn: Callable[[], str] | None = None,
        uname_fn: Callable[[], os.uname_result] | None = None,
    ) -> None:
        # `root` exists for tests. `uname` and the hostname cannot be rooted at
        # a directory, so they are injected as callables instead - same goal,
        # and it keeps the production path free of test-only branching.
        self._root = Path(root) if root is not None else Path("/")
        self._hostname_fn = hostname_fn if hostname_fn is not None else socket.gethostname
        self._uname_fn = uname_fn if uname_fn is not None else os.uname

    # --- individual facts -------------------------------------------------- #

    def os_release(self) -> OsRelease:
        """Parse os-release, falling back to the `/usr/lib` copy.

        Both locations are specified: `/etc/os-release` is conventionally a
        symlink to the `/usr/lib` file, and on a system where /etc has been
        reset only the latter exists.
        """
        for relative in _OS_RELEASE_PATHS:
            text = _read_text(self._root / relative)
            if text is None:
                continue
            values = parse_os_release(text)
            if values.get("ID"):
                return OsRelease(
                    id=values.get("ID", ""),
                    version_id=values.get("VERSION_ID", ""),
                    pretty_name=values.get("PRETTY_NAME") or None,
                )
        # Reported as empty rather than guessed. "unknown" would be a value the
        # server could not distinguish from a real os-release ID.
        return OsRelease(id="", version_id="", pretty_name=None)

    def uptime_seconds(self) -> int | None:
        text = _read_text(self._root / _UPTIME_PATH)
        return None if text is None else parse_uptime(text)

    def boot_id(self) -> str | None:
        """Changes every boot, so the server can tell a reboot from a restart."""
        text = _read_text(self._root / _BOOT_ID_PATH)
        if text is None:
            return None
        value = text.strip()
        return value or None

    def machine_id_hash(self) -> str | None:
        """SHA-256 of the machine-id. The raw value is never transmitted."""
        for relative in _MACHINE_ID_PATHS:
            text = _read_text(self._root / relative)
            if text is None:
                continue
            value = text.strip()
            if value:
                return sha256_hex(value)
        return None

    def dmi_product_uuid_hash(self) -> str | None:
        """SHA-256 of the DMI product UUID, or None - usually None.

        `/sys/class/dmi/id/product_uuid` is mode 0400 root-only on every
        mainstream distribution, deliberately: the raw value is a stable,
        unique hardware identifier and exposing it to every local user is a
        privacy problem. The agent runs unprivileged, so this returns None in
        normal operation and the read failure is not logged as an error.

        It is collected at all because the field exists in the enrollment
        schema and because a root-run `selftest` can populate it, which makes
        the difference visible rather than theoretical. The raw UUID is never
        transmitted - only this hash, which is all the server needs to answer
        "are these two enrollments the same hardware".
        """
        text = _read_text(self._root / _DMI_PRODUCT_UUID_PATH)
        if text is None:
            return None
        value = text.strip()
        # Some firmware reports an all-zero or all-F placeholder. Hashing it
        # would give every such machine an identical digest, which the server
        # would read as a fleet of clones.
        if not value or set(value) <= {"0", "-"} or value.lower().strip("-f") == "":
            return None
        return sha256_hex(value.lower())

    def mac_hashes(self) -> tuple[str, ...]:
        """Hashed MACs of the physical interfaces, sorted and capped.

        Sorted so the list is stable across reboots: `/sys/class/net` is
        returned in directory order, which is not guaranteed, and an unstable
        ordering would make two inventory reports from one machine look
        different for no reason.
        """
        net_dir = self._root / _NET_CLASS_DIR
        try:
            names = sorted(entry.name for entry in net_dir.iterdir())
        except OSError:
            return ()

        hashes: set[str] = set()
        for name in names:
            if not is_physical_interface(name):
                continue
            text = _read_text(net_dir / name / "address")
            if text is None:
                continue
            digest = hash_mac(text)
            if digest is not None:
                hashes.add(digest)
        # Sorted after de-duplication: a bonded interface and its members can
        # report the same address, and the server has no use for it twice.
        return tuple(sorted(hashes))[:MAX_MAC_HASHES]

    def virtualization(self) -> str | None:
        """Hypervisor or container runtime, if detectable. Advisory only."""
        container_marker: str | None = None
        for relative, label in _CONTAINER_MARKERS:
            if (self._root / relative).exists():
                container_marker = label
                break

        return detect_virtualization(
            sys_vendor=_read_text(self._root / _DMI_SYS_VENDOR_PATH),
            product_name=_read_text(self._root / _DMI_PRODUCT_NAME_PATH),
            cpuinfo=_read_text(self._root / _CPUINFO_PATH),
            container_marker=container_marker,
        )

    def primary_adapter_ip(self) -> str | None:
        """The local address the kernel would use to reach the outside world.

        Implemented with a `connect()` on an unconnected UDP socket. **No
        packet is sent.** UDP `connect` only records the destination and asks
        the routing table for a source address, which `getsockname` then
        reports - so this is a route lookup with no network traffic and no
        privileges. The destination is RFC 5737 TEST-NET-1, reserved for
        documentation, so even a future change that did send something could
        not reach a real host.

        The alternatives are worse. Parsing `/proc/net/route` gives the
        interface but not its address, and getting from there to an address
        means `/proc/net/fib_trie`, whose format is undocumented and has
        changed. `socket.gethostbyname(gethostname())` returns 127.0.1.1 on a
        default Ubuntu install because of how `/etc/hosts` is written.

        Returns None when there is no route - a laptop with the lid closed and
        no network - which is a normal state and not an error.
        """
        if self._root != Path("/"):
            # A test supplying a synthetic root is testing file parsing, not
            # the host's routing table. Returning None keeps `host_facts()`
            # deterministic under `fake_root` instead of leaking the developer
            # machine's real address into an assertion.
            return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.settimeout(0.5)
                probe.connect(_ROUTE_PROBE_ADDRESS)
                address = probe.getsockname()[0]
        except OSError:
            return None
        if not isinstance(address, str) or not address or address.startswith("127."):
            # A loopback source address means there is no route out. Reporting
            # it would put 127.0.0.1 in the dashboard for every offline laptop.
            return None
        return address

    def kernel(self) -> str:
        return self._uname_fn().release

    def arch(self) -> str:
        return self._uname_fn().machine

    def hostname(self) -> str:
        try:
            return self._hostname_fn()
        except OSError:
            return ""

    # --- the interface ----------------------------------------------------- #

    def host_facts(self) -> HostFacts:
        return HostFacts(
            hostname=self.hostname(),
            os=self.os_release(),
            kernel=self.kernel(),
            arch=self.arch(),
            uptime_seconds=self.uptime_seconds(),
            boot_id=self.boot_id(),
            machine_id_hash=self.machine_id_hash(),
            dmi_product_uuid_hash=self.dmi_product_uuid_hash(),
            mac_hashes=self.mac_hashes(),
            virtualization=self.virtualization(),
            primary_adapter_ip=self.primary_adapter_ip(),
        )

    def is_supported(self) -> bool:
        """Whether this adapter is the right implementation for this host.

        An os-release ID check only. It says nothing about whether the agent has
        been *tested* on the running release - see `is_validated_release`.
        """
        return self.os_release().id in SUPPORTED_OS_IDS

    def is_validated_release(self) -> bool:
        """Whether the agent has been exercised on this exact release.

        Currently False everywhere, because `VALIDATED_OS_VERSION_IDS` is empty
        and will stay empty until the agent has actually been run on a target
        release. Reported in `status` and `selftest` so the distinction reaches
        an operator rather than living only in a document.
        """
        return self.os_release().version_id in VALIDATED_OS_VERSION_IDS


def detect_adapter(root: Path | None = None) -> UbuntuAdapter:
    """Return the adapter for this host.

    There is one implementation, so this always returns `UbuntuAdapter`. It
    exists as a seam: when a second adapter is added, this is the single place
    that chooses, and no caller changes. Callers interested in whether the host
    is actually a target release ask `is_supported()` - which is reported, not
    enforced, so development on a non-target release works.
    """
    return UbuntuAdapter(root)
