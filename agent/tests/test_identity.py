"""Local identity: directory modes, the permission guarantee, and cert parsing.

The permission tests are the point of this module. The server refuses to load a
CA key that is group- or world-readable, and the agent must hold itself to the
same standard for the device key - "store sensitive files with restrictive
permissions" is in the brief, and the only way that claim means anything is if
something fails when it is untrue.

Certificates here are generated in-process with `cryptography`, matching what
the server's CA issues: EC P-256, a UUID common name, 30-day validity. No key
material is committed, which is the same discipline decision D11 applies to the
policy signing vector.
"""

from __future__ import annotations

import datetime as dt
import os
import stat
import uuid
from pathlib import Path

import pytest

from helpers import UTC, issue_certificate
from ubuntuguard_agent.config import AgentPaths
from ubuntuguard_agent.constants import CERT_RENEW_AT_PCT
from ubuntuguard_agent.errors import InsecureFileError, ReasonCode
from ubuntuguard_agent.identity import (
    PKI_DIR_MODE,
    PRIVATE_FILE_MODE,
    STATE_DIR_MODE,
    assert_private_file,
    ensure_runtime_paths,
    is_enrolled,
    read_certificate,
    summarise_certificate,
)

# --------------------------------------------------------------------------- #
# Permissions
# --------------------------------------------------------------------------- #


def test_a_private_file_at_0600_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "device.key"
    path.write_text("not a real key")
    path.chmod(PRIVATE_FILE_MODE)
    assert_private_file(path)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o777])
def test_a_file_others_can_read_is_refused(tmp_path: Path, mode: int) -> None:
    """Group-readable counts. Mirrors the server's own check.

    "Readable by the ubuntuguard group" sounds harmless until someone adds a
    user to that group for an unrelated reason.
    """
    path = tmp_path / "device.key"
    path.write_text("not a real key")
    path.chmod(mode)

    with pytest.raises(InsecureFileError) as raised:
        assert_private_file(path)
    assert raised.value.reason_code == ReasonCode.INVARIANT_VIOLATION
    assert f"{mode:04o}" in str(raised.value)


def test_the_check_raises_rather_than_repairing(tmp_path: Path) -> None:
    """Deliberately does not chmod the file.

    A key that has been world-readable may already have been copied. Silently
    tightening the mode would hide that from whoever has to decide whether to
    re-enrol the device.
    """
    path = tmp_path / "device.key"
    path.write_text("x")
    path.chmod(0o644)

    with pytest.raises(InsecureFileError):
        assert_private_file(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_a_missing_file_is_an_insecure_file_error(tmp_path: Path) -> None:
    with pytest.raises(InsecureFileError):
        assert_private_file(tmp_path / "absent.key")


# --------------------------------------------------------------------------- #
# Directory creation
# --------------------------------------------------------------------------- #


def test_directories_are_created_at_the_intended_modes(tmp_path: Path) -> None:
    paths = AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
    ensure_runtime_paths(paths)

    assert stat.S_IMODE(paths.state_dir.stat().st_mode) == STATE_DIR_MODE
    assert stat.S_IMODE(paths.pki_dir.stat().st_mode) == PKI_DIR_MODE


def test_the_pki_directory_is_not_even_listable_by_others(tmp_path: Path) -> None:
    paths = AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
    ensure_runtime_paths(paths)

    mode = paths.pki_dir.stat().st_mode
    assert not mode & (stat.S_IRWXG | stat.S_IRWXO)


def test_the_mode_survives_a_permissive_umask(tmp_path: Path) -> None:
    """The reason the mode is set explicitly after mkdir.

    `mkdir(mode=...)` is masked by the process umask, so on a host with the
    usual 022 a 0700 request becomes 0755. Most hosts are that host.
    """
    paths = AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
    previous = os.umask(0o000)
    try:
        ensure_runtime_paths(paths)
    finally:
        os.umask(previous)

    assert stat.S_IMODE(paths.pki_dir.stat().st_mode) == PKI_DIR_MODE


def test_creation_is_idempotent(tmp_path: Path) -> None:
    """Called on every service start, so it must not fail on the second one."""
    paths = AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
    ensure_runtime_paths(paths)
    ensure_runtime_paths(paths)
    assert paths.pki_dir.is_dir()


# --------------------------------------------------------------------------- #
# Certificate parsing
# --------------------------------------------------------------------------- #


def test_the_device_id_comes_from_the_subject_common_name() -> None:
    """The server allocates it; the agent never chooses it.

    The CA discards the CSR subject entirely and sets the CN to the device UUID
    it allocated, so this field is the server's answer, not our request.
    """
    device_id = str(uuid.uuid4())
    summary = summarise_certificate(issue_certificate(device_id=device_id))
    assert summary.device_id == device_id


def test_the_fingerprint_is_sha256_over_the_der() -> None:
    """Must match what the server stored, and what it recomputes per request.

    SHA-256 rather than SHA-1 deliberately: nginx's $ssl_client_fingerprint is
    SHA-1, which is why the proxy forwards the whole certificate and both sides
    compute this themselves.
    """
    summary = summarise_certificate(issue_certificate())
    assert summary.fingerprint.startswith("sha256:")
    assert len(summary.fingerprint) == len("sha256:") + 64


def test_renewal_is_due_at_half_life() -> None:
    """50% of lifetime, computed locally so the decision works offline.

    Renewing at half-life leaves the whole second half as the window to recover
    from a failed renewal, rather than discovering the problem on the last day.
    """
    not_before = dt.datetime.now(UTC) - dt.timedelta(days=1)
    summary = summarise_certificate(issue_certificate(not_before=not_before, valid_days=30))

    lifetime = summary.not_after - summary.not_before
    assert summary.renew_after == summary.not_before + lifetime * (CERT_RENEW_AT_PCT / 100)
    assert (summary.renew_after - summary.not_before).days == 15


def test_a_fresh_certificate_is_neither_expired_nor_due() -> None:
    summary = summarise_certificate(issue_certificate())
    assert summary.is_expired() is False
    assert summary.renewal_due() is False
    assert summary.seconds_remaining() > 0


def test_renewal_becomes_due_past_half_life() -> None:
    not_before = dt.datetime.now(UTC) - dt.timedelta(days=20)
    summary = summarise_certificate(issue_certificate(not_before=not_before, valid_days=30))
    assert summary.renewal_due() is True
    assert summary.is_expired() is False


def test_an_expired_certificate_is_detected() -> None:
    not_before = dt.datetime.now(UTC) - dt.timedelta(days=60)
    summary = summarise_certificate(issue_certificate(not_before=not_before, valid_days=30))
    assert summary.is_expired() is True
    assert summary.seconds_remaining() < 0


def test_the_clock_can_be_injected() -> None:
    """So expiry logic is asserted rather than waited for."""
    not_before = dt.datetime.now(UTC)
    summary = summarise_certificate(issue_certificate(not_before=not_before, valid_days=30))
    future = not_before + dt.timedelta(days=31)
    assert summary.is_expired(now=future) is True


def test_a_certificate_without_exactly_one_common_name_is_refused() -> None:
    """Mirrors the server's device-auth check.

    Two CNs is ambiguous about which identity is being claimed, and ambiguity in
    an identity field is not something to resolve by picking the first.
    """
    with pytest.raises(ValueError):
        summarise_certificate(issue_certificate(common_names=2))


def test_unparseable_pem_raises() -> None:
    with pytest.raises(ValueError):
        summarise_certificate(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----")


# --------------------------------------------------------------------------- #
# Reading from disk
# --------------------------------------------------------------------------- #


def test_no_certificate_means_not_enrolled(agent_paths: AgentPaths) -> None:
    """A normal state for a fresh install, not an error."""
    ensure_runtime_paths(agent_paths)
    assert read_certificate(agent_paths) is None
    assert is_enrolled(agent_paths) is False


def test_an_installed_certificate_is_read(agent_paths: AgentPaths) -> None:
    ensure_runtime_paths(agent_paths)
    device_id = str(uuid.uuid4())
    agent_paths.certificate_path.write_bytes(issue_certificate(device_id=device_id))

    summary = read_certificate(agent_paths)
    assert summary is not None
    assert summary.device_id == device_id


def test_a_corrupt_certificate_raises_rather_than_reading_as_absent(
    agent_paths: AgentPaths,
) -> None:
    """The distinction that stops a laptop appearing twice.

    Treating a damaged identity as "not enrolled" would send the agent off to
    enrol again, and the server would create a second device row for one
    machine. A corrupt identity is an error for a human to look at.
    """
    ensure_runtime_paths(agent_paths)
    agent_paths.certificate_path.write_bytes(b"this is not a certificate")

    with pytest.raises(ValueError):
        read_certificate(agent_paths)


def test_enrollment_requires_both_halves(agent_paths: AgentPaths) -> None:
    """Either one alone is a broken install, not an identity.

    A key with no certificate never completed enrollment; a certificate with no
    key cannot be used in a TLS handshake.
    """
    ensure_runtime_paths(agent_paths)

    agent_paths.private_key_path.write_text("key")
    assert is_enrolled(agent_paths) is False

    agent_paths.certificate_path.write_bytes(issue_certificate())
    assert is_enrolled(agent_paths) is True

    agent_paths.private_key_path.unlink()
    assert is_enrolled(agent_paths) is False
