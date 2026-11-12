"""The hardware-fingerprint fields added for enrollment.

Every one of these is optional on the wire, and the tests are mostly about the
degraded cases, because on a correctly hardened host the degraded case IS the
normal one: `/sys/class/dmi/id/product_uuid` is root-only, so the agent's own
systemd unit guarantees it cannot be read.

The parsers are tested against strings and the collectors against a synthetic
filesystem root, so none of this depends on what the developer's machine
happens to be.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ubuntuguard_agent.osadapter.facts import (
    MAX_VIRTUALIZATION_LENGTH,
    detect_virtualization,
    hash_mac,
    is_physical_interface,
)
from ubuntuguard_agent.osadapter.ubuntu import MAX_MAC_HASHES, UbuntuAdapter


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# MAC hashing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name", ["lo", "docker0", "br-1a2b3c", "veth0abc", "virbr0", "tun0", "wg0", "tailscale0"]
)
def test_virtual_interfaces_are_excluded(name: str) -> None:
    """Their MACs are randomly generated and change, so they never match.

    Including them would also crowd out the real ones against the server's
    32-entry limit on a developer laptop running containers.
    """
    assert is_physical_interface(name) is False


@pytest.mark.parametrize("name", ["eth0", "enp3s0", "wlp2s0", "eno1", "wlan0"])
def test_real_interfaces_are_included(name: str) -> None:
    assert is_physical_interface(name) is True


def test_a_mac_is_lowercased_before_hashing() -> None:
    """Otherwise one machine produces two different hashes for one address.

    That is a bug with no symptom: clone detection simply never fires.
    """
    assert hash_mac("AA:BB:CC:DD:EE:FF") == hash_mac("aa:bb:cc:dd:ee:ff")
    assert hash_mac("aa:bb:cc:dd:ee:ff") == _sha256("aa:bb:cc:dd:ee:ff")


def test_the_hash_matches_the_schema_pattern() -> None:
    """`Hex64` is `^[0-9a-f]{64}$`; uppercase would be a 422."""
    digest = hash_mac("aa:bb:cc:dd:ee:ff")
    assert digest is not None
    assert len(digest) == 64
    assert digest == digest.lower()


@pytest.mark.parametrize(
    "value", ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "", "not-a-mac", "aa:bb:cc"]
)
def test_placeholder_and_malformed_macs_are_dropped(value: str) -> None:
    """An all-zero MAC hashed on two machines is a guaranteed false clone match."""
    assert hash_mac(value) is None


# --------------------------------------------------------------------------- #
# Virtualization detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("vendor", "product", "expected"),
    [
        ("VMware, Inc.", "VMware Virtual Platform", "vmware"),
        ("innotek GmbH", "VirtualBox", "oracle"),
        ("QEMU", "Standard PC (Q35 + ICH9, 2009)", "qemu"),
        ("Xen", "HVM domU", "xen"),
        ("Amazon EC2", "t3.micro", "amazon"),
        ("Google", "Google Compute Engine", "google"),
        ("Microsoft Corporation", "Virtual Machine", "microsoft"),
        ("LENOVO", "20XW00ABUK", None),
        ("Acer", "Aspire A515-54", None),
    ],
)
def test_dmi_identifiers_are_mapped(vendor: str, product: str, expected: str | None) -> None:
    assert detect_virtualization(sys_vendor=vendor, product_name=product) == expected


def test_the_product_name_wins_over_the_vendor() -> None:
    """ "Microsoft Corporation" is the vendor of a Hyper-V guest AND a Surface.

    Only the product name distinguishes them, so it is consulted first.
    """
    assert (
        detect_virtualization(sys_vendor="Microsoft Corporation", product_name="Surface Laptop 5")
        is None
    )
    assert (
        detect_virtualization(sys_vendor="Microsoft Corporation", product_name="Virtual Machine")
        == "microsoft"
    )


def test_a_container_marker_beats_dmi() -> None:
    """A container inside a VM reports the container: the more immediate truth."""
    assert (
        detect_virtualization(
            sys_vendor="VMware, Inc.", product_name="VMware7,1", container_marker="docker"
        )
        == "docker"
    )


def test_the_hypervisor_cpu_flag_is_the_unnamed_fallback() -> None:
    """Present on most guests, but it names nothing, so it reports "unknown"."""
    cpuinfo = "processor\t: 0\nflags\t\t: fpu vme de pse hypervisor lm\n"
    assert detect_virtualization(cpuinfo=cpuinfo) == "unknown"


def test_physical_hardware_reports_none() -> None:
    """None means "no evidence", which is not the same as "definitely physical"."""
    cpuinfo = "processor\t: 0\nflags\t\t: fpu vme de pse tsc msr lm\n"
    assert detect_virtualization(sys_vendor="Acer", product_name="Aspire", cpuinfo=cpuinfo) is None


def test_a_long_container_label_is_truncated_to_the_servers_limit() -> None:
    label = "x" * 200
    result = detect_virtualization(container_marker=label)
    assert result is not None
    assert len(result) == MAX_VIRTUALIZATION_LENGTH


def test_no_evidence_at_all_reports_none() -> None:
    assert detect_virtualization() is None


# --------------------------------------------------------------------------- #
# Collection against a synthetic root
# --------------------------------------------------------------------------- #


def test_the_dmi_uuid_is_absent_when_unreadable(fake_root: Path) -> None:
    """The normal case on a managed laptop, and not an error.

    The agent runs as an unprivileged user and the file is mode 0400 root. This
    is the exact behaviour decision 3 of the Phase 2 approval locks in: collect
    it when available, never weaken the hardening to get it.
    """
    adapter = UbuntuAdapter(fake_root)
    assert adapter.dmi_product_uuid_hash() is None
    assert adapter.host_facts().dmi_product_uuid_hash is None


def test_the_dmi_uuid_is_hashed_when_readable(fake_root: Path) -> None:
    """Exercised with a readable file, which is the root-run case."""
    dmi = fake_root / "sys" / "class" / "dmi" / "id"
    dmi.mkdir(parents=True)
    (dmi / "product_uuid").write_text("4C4C4544-0033-4810-8057-B4C04F4D3732\n")

    adapter = UbuntuAdapter(fake_root)
    digest = adapter.dmi_product_uuid_hash()
    # Lowercased before hashing, so firmware that reports uppercase and
    # firmware that reports lowercase agree.
    assert digest == _sha256("4c4c4544-0033-4810-8057-b4c04f4d3732")
    # And the raw value is nowhere in the result.
    assert "4C4C4544" not in (digest or "")


@pytest.mark.parametrize("placeholder", ["00000000-0000-0000-0000-000000000000", "", "---"])
def test_a_placeholder_dmi_uuid_is_dropped(fake_root: Path, placeholder: str) -> None:
    """Hashing it would make every such machine look like a clone of the others."""
    dmi = fake_root / "sys" / "class" / "dmi" / "id"
    dmi.mkdir(parents=True)
    (dmi / "product_uuid").write_text(placeholder)
    assert UbuntuAdapter(fake_root).dmi_product_uuid_hash() is None


def test_mac_hashes_are_collected_sorted_and_deduplicated(fake_root: Path) -> None:
    net = fake_root / "sys" / "class" / "net"
    for name, address in (
        ("eth0", "aa:bb:cc:dd:ee:01"),
        ("wlan0", "aa:bb:cc:dd:ee:02"),
        # A bond member reporting the same address as its master.
        ("bond0", "aa:bb:cc:dd:ee:01"),
        # Excluded: loopback, Docker, and a veth pair.
        ("lo", "00:00:00:00:00:00"),
        ("docker0", "02:42:1a:2b:3c:4d"),
        ("veth1234", "02:42:aa:bb:cc:dd"),
    ):
        (net / name).mkdir(parents=True)
        (net / name / "address").write_text(address + "\n")

    hashes = UbuntuAdapter(fake_root).mac_hashes()
    assert hashes == tuple(sorted({_sha256("aa:bb:cc:dd:ee:01"), _sha256("aa:bb:cc:dd:ee:02")}))


def test_mac_hashes_are_capped_at_the_servers_limit(fake_root: Path) -> None:
    """More than 32 is a 422 from `HardwareFingerprint`, so it is capped here."""
    net = fake_root / "sys" / "class" / "net"
    for index in range(MAX_MAC_HASHES + 10):
        name = f"eth{index}"
        (net / name).mkdir(parents=True)
        (net / name / "address").write_text(f"aa:bb:cc:dd:{index // 256:02x}:{index % 256:02x}\n")

    assert len(UbuntuAdapter(fake_root).mac_hashes()) == MAX_MAC_HASHES


def test_a_missing_network_directory_yields_no_hashes(fake_root: Path) -> None:
    assert UbuntuAdapter(fake_root).mac_hashes() == ()


def test_host_facts_is_deterministic_under_a_synthetic_root(fake_root: Path) -> None:
    """The route probe is skipped when a root is injected.

    Without that, `host_facts()` under `fake_root` would reach the developer
    machine's real routing table and leak its address into an assertion.
    """
    facts = UbuntuAdapter(fake_root).host_facts()
    assert facts.primary_adapter_ip is None
    assert facts.mac_hashes == ()
    assert facts.virtualization is None


def test_collection_never_raises_on_an_empty_root(tmp_path: Path) -> None:
    """Every field is optional, so an empty filesystem degrades rather than fails."""
    facts = UbuntuAdapter(tmp_path).host_facts()
    assert facts.os.id == ""
    assert facts.machine_id_hash is None
    assert facts.dmi_product_uuid_hash is None
    assert facts.mac_hashes == ()
    assert facts.uptime_seconds is None
