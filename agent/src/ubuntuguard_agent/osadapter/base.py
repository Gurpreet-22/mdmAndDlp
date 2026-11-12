"""The fixed adapter interface, and the value types that cross it.

The interface is deliberately narrow and returns plain frozen dataclasses. The
core never receives a live file handle, a subprocess or an OS-specific object,
which is what keeps the core testable without an operating system underneath it.

Every field here is DISCOVERED at runtime, never hardcoded. That is a stated
requirement of `schemas/inventory.v1.schema.json`, and it matters for a concrete
reason: an agent that assumes "ubuntu" and "24.04" reports those values
correctly right up until it is installed on something else, at which point it
reports them incorrectly and nothing fails loudly.

Phase 1 collects only what the service loop and `status` need. The full
inventory surface - hardware vendor, product UUID hash, network interfaces,
capabilities - arrives in Phase 4 and extends this interface rather than
replacing it.
"""

from __future__ import annotations

import dataclasses

try:  # pragma: no cover - the fallback is exercised only on Python 3.7
    from typing import Protocol, runtime_checkable
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol, runtime_checkable  # type: ignore[assignment]


@dataclasses.dataclass(frozen=True)
class OsRelease:
    """Parsed `/etc/os-release`. The fields `inventory.v1` names, no more."""

    id: str
    version_id: str
    pretty_name: str | None = None

    @property
    def short(self) -> str:
        """e.g. "ubuntu 24.04". For logs and the enrollment audit entry."""
        return f"{self.id} {self.version_id}".strip()


@dataclasses.dataclass(frozen=True)
class HostFacts:
    """What the agent knows about the machine it is running on.

    Several fields are optional, and that is a correctness decision rather than
    laziness. `/etc/machine-id` can be absent on a freshly imaged system,
    `/sys/class/dmi/id/product_uuid` is root-only on most hosts, and
    `/proc/sys/kernel/random/boot_id` is unavailable in some containers. An
    agent that refused to start without them would fail on exactly the machines
    it most needs to report from, so each one degrades to None and the server's
    schema already permits that.
    """

    hostname: str
    os: OsRelease
    kernel: str
    arch: str
    uptime_seconds: int | None = None
    boot_id: str | None = None
    #: SHA-256 of /etc/machine-id, hashed here. The raw value never leaves the
    #: device - `inventory.v1` and the enrollment schema both accept only the
    #: hash, and both pin it to lowercase 64-character hex.
    machine_id_hash: str | None = None

    #: SHA-256 of /sys/class/dmi/id/product_uuid.
    #:
    #: **Expect this to be None on a managed laptop, and that is not a bug.**
    #: The file is mode 0400 owned by root, and the agent runs as the
    #: unprivileged `ubuntuguard` user with an empty CapabilityBoundingSet. It
    #: is populated when the agent is run by root - a `selftest` under sudo, or
    #: a development run - and absent otherwise.
    #:
    #: The consequence is worth stating rather than discovering: the server's
    #: clone detection (`repositories.find_clone_candidates`) matches on this
    #: OR machine_id_hash, so in production it effectively matches on
    #: machine_id_hash alone. A reimaged laptop gets a new machine-id and will
    #: not be recognised as the same hardware. That is a known weakness of the
    #: signal, not a claim being made for it.
    dmi_product_uuid_hash: str | None = None

    #: SHA-256 of each physical interface's MAC, sorted, virtual interfaces
    #: excluded. A tuple because `HostFacts` is frozen and a mutable default
    #: shared between instances is a classic way to leak state between devices
    #: in a test suite.
    mac_hashes: tuple[str, ...] = ()

    #: Hypervisor or container runtime, if there is evidence of one. A
    #: heuristic from world-readable DMI and /proc - see
    #: `facts.detect_virtualization`. Advisory inventory; nothing authorises on
    #: it.
    virtualization: str | None = None

    #: Address of the interface carrying the default route.
    #:
    #: Self-reported and trivially spoofable, which the server says explicitly
    #: in `schemas.DeviceSummary`: it is informational only and is never used
    #: to identify or authorise a device. Collected because an operator looking
    #: at a fleet list wants to know which office a laptop checked in from.
    primary_adapter_ip: str | None = None


@runtime_checkable
class OsAdapter(Protocol):
    """What the core may ask of the operating system.

    A Protocol rather than an abstract base class: the core depends on the
    shape, not on an inheritance relationship, and a test double does not have
    to import anything to satisfy it.
    """

    #: Opaque label reported as `adapter.name` in inventory. The server stores
    #: and displays it and never interprets it (decision D9).
    name: str

    def host_facts(self) -> HostFacts:
        """Collect the host facts. Must not raise for a missing optional file.

        Every optional field degrades to None or an empty tuple. An adapter
        that raised because `/sys/class/dmi/id/product_uuid` was unreadable
        would fail on every correctly hardened host, which is the opposite of
        the intent.
        """
        ...

    def is_supported(self) -> bool:
        """Whether this adapter is the right implementation for this host.

        False does not stop the agent. It makes the mismatch visible in the log
        and in `status`, because the agent running somewhere untested is
        information an operator needs, not a reason to refuse to start.
        """
        ...

    def is_validated_release(self) -> bool:
        """Whether the agent has actually been exercised on this release.

        A separate question from `is_supported`, and separate on purpose. The
        adapter can be the correct implementation for a host nobody has ever
        run the agent on. Collapsing the two into one method is how "we read the
        right files" becomes a claim that "this release works".
        """
        ...
