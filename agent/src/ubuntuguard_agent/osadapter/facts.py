"""Pure parsers for the Linux interfaces the Ubuntu adapter reads.

Separated from the adapter so each parser is testable against a string rather
than against a machine. That is what lets the suite cover the cases that
actually break collectors - a quoted value, a comment, a blank file, a
truncated `/proc/uptime` - without needing a host in that state.

Nothing here opens a file or decides where a file lives.
"""

from __future__ import annotations

import hashlib
import re

#: A KEY=VALUE line in os-release. The spec allows single or double quotes and
#: permits comments and blank lines, all of which turn up in the wild.
_OS_RELEASE_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")

#: Lowercase 64-char hex, the shape both inventory.v1 and the enrollment schema
#: pin every hash field to.
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release content into a plain mapping.

    Tolerant by design: an unparseable line is skipped rather than raising. A
    single odd line in `/etc/os-release` must not stop the agent from reporting
    the fields it did understand.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _OS_RELEASE_LINE.match(stripped)
        if match is None:
            continue
        key, raw = match.group(1), match.group(2)
        values[key] = _unquote(raw)
    return values


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def parse_uptime(text: str) -> int | None:
    """Seconds of uptime from `/proc/uptime`, or None if unparseable.

    The file is two floats separated by a space. Returns whole seconds because
    `inventory.v1` types `uptime_seconds` as an integer with a minimum of 0.
    """
    first = text.strip().split(" ", 1)[0] if text.strip() else ""
    if not first:
        return None
    try:
        seconds = float(first)
    except ValueError:
        return None
    if seconds < 0:
        return None
    return int(seconds)


def sha256_hex(value: str) -> str:
    """Lowercase hex SHA-256 of a string, encoded UTF-8.

    Used for `machine_id_hash`. The raw machine-id is a stable host identifier
    and is treated as something not to transmit: the server only ever needs to
    know whether two enrollments carry the *same* one, which a hash answers.
    `hexdigest()` is lowercase, matching the schema pattern exactly - uppercase
    hex would be rejected with a 422.
    """
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def normalise_mac(value: str) -> str | None:
    """Lowercase colon-separated MAC, or None if it is not one.

    Phase 4 needs this for `network_interfaces[].mac`, whose schema pattern is
    `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`. It lives here now because the parser is
    pure and the test is cheap; the collector that calls it arrives with
    inventory.
    """
    candidate = value.strip().lower()
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", candidate):
        return candidate
    return None


#: Loopback and the interface names of things that are not a physical NIC.
#: Matched as prefixes, because the kernel appends an index.
#:
#: Why exclude them: a MAC hash is used by the server to notice two enrollments
#: that might be the same laptop
#: (`repositories.find_clone_candidates`). Docker's `docker0` bridge has a
#: randomly generated MAC that changes when the daemon is reinstalled, and a
#: `veth` pair gets a fresh one per container, so including them adds hashes
#: that never match anything and crowd out the ones that would. The 32-entry
#: cap in the enrollment schema makes that crowding real on a developer laptop
#: running containers.
VIRTUAL_INTERFACE_PREFIXES: tuple[str, ...] = (
    "lo",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "tun",
    "tap",
    "wg",
    "zt",
    "tailscale",
)

#: A MAC that carries no information. Some drivers report one before the link
#: is up, and hashing it would produce an identical hash on every machine that
#: happens to have the same placeholder - a guaranteed false clone match.
_EMPTY_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})

#: Substrings in DMI identifiers that name a hypervisor, and what to report.
#: Lowercased comparison. Ordered, because "Microsoft Corporation" appears on
#: both Hyper-V guests and physical Surface hardware, so the more specific
#: product match has to be consulted first - see `detect_virtualization`.
_DMI_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("vmware", "vmware"),
    ("virtualbox", "oracle"),
    ("innotek", "oracle"),
    ("qemu", "qemu"),
    ("bochs", "qemu"),
    ("kvm", "kvm"),
    ("xen", "xen"),
    ("bhyve", "bhyve"),
    ("parallels", "parallels"),
    ("amazon ec2", "amazon"),
    ("google compute engine", "google"),
    ("hyper-v", "microsoft"),
    ("virtual machine", "microsoft"),
    ("alibaba", "alibaba"),
    ("openstack", "openstack"),
)

#: Longest value the server accepts for `virtualization`
#: (`schemas.HardwareFingerprint`). Enforced here so a surprising DMI string
#: cannot turn into a 422 at enrollment.
MAX_VIRTUALIZATION_LENGTH = 32


def is_physical_interface(name: str) -> bool:
    """Whether `name` looks like a real network interface worth fingerprinting."""
    lowered = name.strip().lower()
    if not lowered:
        return False
    return not lowered.startswith(VIRTUAL_INTERFACE_PREFIXES)


def hash_mac(value: str) -> str | None:
    """Normalise then hash a MAC, or None if it is not a usable address.

    Normalised BEFORE hashing, because the hash is only useful if two machines
    reporting the same hardware produce the same digest. `AA:BB:...` and
    `aa:bb:...` are the same address and must not become two different hashes,
    which is the kind of bug that makes clone detection quietly never fire.
    """
    normalised = normalise_mac(value)
    if normalised is None or normalised in _EMPTY_MACS:
        return None
    return sha256_hex(normalised)


def detect_virtualization(
    *,
    sys_vendor: str | None = None,
    product_name: str | None = None,
    cpuinfo: str | None = None,
    container_marker: str | None = None,
) -> str | None:
    """Best-effort guess at the hypervisor, from world-readable files only.

    **A heuristic, and labelled as one.** `systemd-detect-virt` is more
    accurate and is deliberately not used: it is a subprocess, the agent makes
    none, and shelling out from the component that parses untrusted server
    responses is the habit the architecture is built to avoid. The server
    treats this field as advisory inventory and never authorises on it, so a
    wrong or absent answer costs nothing beyond a less useful dashboard
    column.

    Order of evidence, most specific first:

    1. A container marker, because a container inside a VM should report the
       container - it is the more immediate truth about what the agent is
       running in, and it is the one that explains surprising inventory.
    2. DMI product name, then vendor. Product is consulted first because
       "Microsoft Corporation" is the vendor of both a Hyper-V guest and a
       physical Surface, whereas the product name says "Virtual Machine" only
       on the guest.
    3. The `hypervisor` CPU flag. Present on most guests and absent on metal,
       but it names nothing, so it is the fallback that reports "unknown"
       rather than a vendor.

    Returns None for what looks like physical hardware. None means "no
    evidence of virtualization", not "definitely physical".
    """
    if container_marker:
        return container_marker[:MAX_VIRTUALIZATION_LENGTH]

    for haystack in (product_name, sys_vendor):
        if not haystack:
            continue
        lowered = haystack.strip().lower()
        for needle, label in _DMI_SIGNATURES:
            if needle in lowered:
                return label

    if cpuinfo and "hypervisor" in _cpu_flags(cpuinfo):
        return "unknown"

    return None


def _cpu_flags(cpuinfo: str) -> frozenset[str]:
    """The union of every `flags:` line in /proc/cpuinfo.

    Union across cores rather than the first core's line: they are identical
    in practice, but a parser that depends on "the first one" fails oddly on a
    heterogeneous machine, and a set union costs nothing.
    """
    flags: set[str] = set()
    for line in cpuinfo.splitlines():
        key, separator, value = line.partition(":")
        if not separator or key.strip().lower() not in {"flags", "features"}:
            continue
        flags.update(value.strip().lower().split())
    return frozenset(flags)
