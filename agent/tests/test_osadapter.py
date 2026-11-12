"""The Ubuntu adapter and its parsers.

The filesystem root is injected, so these run against a directory tree the test
built rather than against mocked `open` calls. That matters: the code path under
test is the real one, including the fallbacks.

The emphasis is on degradation. Every file this adapter reads is absent in some
real situation - `/etc/machine-id` on a first boot, `/proc` entries in some
container runtimes, `product_uuid` without root - and an agent that raised on
any of them would fail to start on exactly the hosts it most needs to report
from.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ubuntuguard_agent.osadapter import (
    SUPPORTED_OS_IDS,
    VALIDATED_OS_VERSION_IDS,
    UbuntuAdapter,
    detect_adapter,
)
from ubuntuguard_agent.osadapter.base import HostFacts, OsAdapter
from ubuntuguard_agent.osadapter.facts import (
    normalise_mac,
    parse_os_release,
    parse_uptime,
    sha256_hex,
)

FAKE_UNAME = os.uname_result(("Linux", "laptop-1", "6.8.0-45-generic", "#45 SMP", "x86_64"))


def adapter_for(root: Path) -> UbuntuAdapter:
    return UbuntuAdapter(root, hostname_fn=lambda: "laptop-1", uname_fn=lambda: FAKE_UNAME)


# --------------------------------------------------------------------------- #
# os-release parsing
# --------------------------------------------------------------------------- #


def test_quoted_and_unquoted_values_both_parse() -> None:
    parsed = parse_os_release("ID=ubuntu\nVERSION_ID=\"24.04\"\nNAME='Ubuntu'\n")
    assert parsed["ID"] == "ubuntu"
    assert parsed["VERSION_ID"] == "24.04"
    assert parsed["NAME"] == "Ubuntu"


def test_comments_and_blank_lines_are_skipped() -> None:
    parsed = parse_os_release("# a comment\n\nID=ubuntu\n\n")
    assert parsed == {"ID": "ubuntu"}


def test_an_unparseable_line_is_skipped_not_fatal() -> None:
    """One odd line must not cost the fields that did parse.

    os-release is written by the distribution and read by everything; being
    strict here would be a self-inflicted outage.
    """
    parsed = parse_os_release("ID=ubuntu\nthis is not a key=value pair at all\nVERSION_ID=24.04\n")
    assert parsed["ID"] == "ubuntu"
    assert parsed["VERSION_ID"] == "24.04"


def test_an_empty_file_parses_to_nothing() -> None:
    assert parse_os_release("") == {}


# --------------------------------------------------------------------------- #
# uptime parsing
# --------------------------------------------------------------------------- #


def test_uptime_takes_the_first_float_as_whole_seconds() -> None:
    """`inventory.v1` types uptime_seconds as an integer with minimum 0."""
    assert parse_uptime("987654.32 1234567.89\n") == 987654


@pytest.mark.parametrize("text", ["", "   ", "not-a-number", "-5.0"])
def test_unparseable_uptime_is_none(text: str) -> None:
    assert parse_uptime(text) is None


def test_uptime_without_the_second_field_still_parses() -> None:
    assert parse_uptime("123.45") == 123


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #


def test_machine_id_hash_is_lowercase_64_hex() -> None:
    """Uppercase hex would be rejected by the server with a 422.

    Both the enrollment schema and inventory.v1 pin every hash field to
    `^[0-9a-f]{64}$`, so the case is part of the contract, not cosmetic.
    """
    digest = sha256_hex("9e107d9d372bb6826bd81d3542a419d6")
    assert len(digest) == 64
    assert digest == digest.lower()
    assert all(character in "0123456789abcdef" for character in digest)


def test_hashing_ignores_surrounding_whitespace() -> None:
    """The file has a trailing newline; the hash must not depend on it."""
    assert sha256_hex("abc\n") == sha256_hex("abc")


def test_the_raw_machine_id_is_never_the_output() -> None:
    raw = "9e107d9d372bb6826bd81d3542a419d6"
    assert raw not in sha256_hex(raw)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("not-a-mac", None),
        ("aa-bb-cc-dd-ee-ff", None),
        ("", None),
    ],
)
def test_mac_normalisation_matches_the_schema_pattern(value: str, expected: object) -> None:
    assert normalise_mac(value) == expected


# --------------------------------------------------------------------------- #
# The adapter against a complete tree
# --------------------------------------------------------------------------- #


def test_all_facts_are_collected(fake_root: Path) -> None:
    facts = adapter_for(fake_root).host_facts()

    assert isinstance(facts, HostFacts)
    assert facts.hostname == "laptop-1"
    assert facts.os.id == "ubuntu"
    assert facts.os.version_id == "24.04"
    assert facts.os.pretty_name == "Ubuntu 24.04.1 LTS"
    assert facts.kernel == "6.8.0-45-generic"
    assert facts.arch == "x86_64"
    assert facts.uptime_seconds == 987654
    assert facts.boot_id == "4f8a9c1e-2b3d-4e5f-8a9b-0c1d2e3f4a5b"
    assert facts.machine_id_hash == sha256_hex("9e107d9d372bb6826bd81d3542a419d6")


def test_os_short_form_is_what_the_audit_entry_records(fake_root: Path) -> None:
    assert adapter_for(fake_root).os_release().short == "ubuntu 24.04"


def test_the_adapter_satisfies_the_protocol(fake_root: Path) -> None:
    """The core depends on the shape, not on an inheritance relationship."""
    assert isinstance(adapter_for(fake_root), OsAdapter)


def test_nothing_is_hardcoded(tmp_path: Path) -> None:
    """Discovered, never assumed.

    An agent that assumed "ubuntu 24.04" would report those values correctly
    right up until it was installed on something else, at which point it would
    report them incorrectly and nothing would fail loudly.
    """
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text(
        'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n', encoding="utf-8"
    )
    release = adapter_for(tmp_path).os_release()
    assert release.id == "debian"
    assert release.version_id == "12"


# --------------------------------------------------------------------------- #
# Degradation
# --------------------------------------------------------------------------- #


def test_an_empty_root_does_not_raise(tmp_path: Path) -> None:
    """The strongest form of the degradation requirement.

    Nothing present at all, and `host_facts()` still returns.
    """
    facts = adapter_for(tmp_path).host_facts()
    assert facts.os.id == ""
    assert facts.uptime_seconds is None
    assert facts.boot_id is None
    assert facts.machine_id_hash is None
    # The facts that come from uname are always available.
    assert facts.kernel == "6.8.0-45-generic"


def test_a_missing_machine_id_is_none_not_an_error(fake_root: Path) -> None:
    """Absent on a freshly imaged system, which is a normal state."""
    (fake_root / "etc" / "machine-id").unlink()
    assert adapter_for(fake_root).machine_id_hash() is None


def test_the_dbus_machine_id_is_used_as_a_fallback(fake_root: Path) -> None:
    (fake_root / "etc" / "machine-id").unlink()
    (fake_root / "var" / "lib" / "dbus").mkdir(parents=True)
    (fake_root / "var" / "lib" / "dbus" / "machine-id").write_text("fallback-id\n")
    assert adapter_for(fake_root).machine_id_hash() == sha256_hex("fallback-id")


def test_an_empty_machine_id_file_is_none(fake_root: Path) -> None:
    """An empty file must not hash to the digest of the empty string.

    That would be a stable, identical value across every affected host, which
    the server's clone detection would read as one machine enrolling repeatedly.
    """
    (fake_root / "etc" / "machine-id").write_text("\n", encoding="utf-8")
    assert adapter_for(fake_root).machine_id_hash() is None


def test_os_release_falls_back_to_the_usr_lib_copy(tmp_path: Path) -> None:
    """Both locations are specified; only the second exists on some systems."""
    (tmp_path / "usr" / "lib").mkdir(parents=True)
    (tmp_path / "usr" / "lib" / "os-release").write_text(
        'ID=ubuntu\nVERSION_ID="22.04"\n', encoding="utf-8"
    )
    assert adapter_for(tmp_path).os_release().version_id == "22.04"


def test_an_os_release_without_an_id_is_treated_as_absent(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text("VERSION_ID=99\n", encoding="utf-8")
    assert adapter_for(tmp_path).os_release().id == ""


def test_undecodable_bytes_do_not_raise(fake_root: Path) -> None:
    """`errors="replace"` rather than a crash on a corrupt file."""
    (fake_root / "etc" / "os-release").write_bytes(b"ID=ubuntu\n\xff\xfe invalid \n")
    assert adapter_for(fake_root).os_release().id == "ubuntu"


def test_a_hostname_failure_degrades_to_empty() -> None:
    def broken() -> str:
        raise OSError("no hostname")

    adapter = UbuntuAdapter(Path("/"), hostname_fn=broken, uname_fn=lambda: FAKE_UNAME)
    assert adapter.hostname() == ""


# --------------------------------------------------------------------------- #
# Platform support, which is reported and never enforced
# --------------------------------------------------------------------------- #


def test_ubuntu_is_reported_as_supported(fake_root: Path) -> None:
    assert adapter_for(fake_root).is_supported() is True
    assert {"ubuntu"} == SUPPORTED_OS_IDS


def test_no_release_is_reported_as_validated_yet(fake_root: Path) -> None:
    """The brief's rule, encoded rather than documented.

    `is_supported` says the adapter is the right implementation. This says the
    agent has been exercised on the running release, and it is false
    everywhere - including on an ordinary 24.04 host. It stays false until
    someone installs the agent on a target release and commits the evidence,
    which is not something achievable from a code review.
    """
    assert frozenset() == VALIDATED_OS_VERSION_IDS
    assert adapter_for(fake_root).is_validated_release() is False


def test_support_and_validation_are_independent_questions(fake_root: Path) -> None:
    """A supported adapter on an unvalidated release is today's normal case."""
    adapter = adapter_for(fake_root)
    assert adapter.os_release().version_id == "24.04"
    assert adapter.is_supported() is True
    assert adapter.is_validated_release() is False


def test_the_validation_mechanism_works_once_a_release_is_listed(
    fake_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proves the mechanism, without claiming any release passes.

    Patching rather than editing the real set is the point: the committed set
    stays empty, and this shows that adding an entry is all it will take once
    the validation has actually happened.
    """
    monkeypatch.setattr(
        "ubuntuguard_agent.osadapter.ubuntu.VALIDATED_OS_VERSION_IDS", frozenset({"24.04"})
    )
    assert adapter_for(fake_root).is_validated_release() is True


def test_another_distribution_is_reported_as_unsupported(tmp_path: Path) -> None:
    """Reported, not refused.

    Refusing to start would make development on a non-target release
    impossible, and the honest outcome is a running agent that says plainly it
    is on an untested platform.
    """
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text("ID=fedora\nVERSION_ID=41\n", encoding="utf-8")
    adapter = adapter_for(tmp_path)
    assert adapter.is_supported() is False
    assert adapter.host_facts().os.id == "fedora"


def test_detect_adapter_returns_the_ubuntu_adapter() -> None:
    """One implementation today; this is the seam for a second one."""
    assert isinstance(detect_adapter(), UbuntuAdapter)


def test_the_real_host_can_be_read_without_raising() -> None:
    """Runs against the actual machine, whatever it is.

    Deliberately asserts almost nothing about the values - the development box
    is Ubuntu 26.04, and the targets are 22.04 and 24.04. What it does prove is
    that the collection path works against a real /proc and /etc rather than
    only against a fixture. Support for the target releases remains
    UNVALIDATED until it is exercised there.
    """
    facts = detect_adapter().host_facts()
    assert isinstance(facts.kernel, str) and facts.kernel
    assert isinstance(facts.arch, str) and facts.arch
