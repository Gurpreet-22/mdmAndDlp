"""`deploy/nginx/make_dev_tls.py`: what it replaces, and what it reports.

Why these exist. The script has one decision that can break a whole fleet at
once: whether it REUSES the existing dev server CA or replaces it. Replacing it
invalidates the `server_ca_bundle` every enrolled agent is pinned to, so every
device fails its next request simultaneously. `--dry-run` is the control that
lets an operator check which of the two is about to happen.

That control was inverted. The branch read

    if reuse and not arguments.dry_run:
        log("reusing the existing dev server CA ...")
    else:
        log("generating the dev server CA (EC P-256)")

so a dry run of an invocation that would reuse fell into the `else` and
announced that it was generating - the alarming answer, and the wrong one. An
operator who believed it would either abandon a safe change or, worse, learn to
ignore what the dry run says.

`test_a_real_run_leaves_the_existing_ca_byte_identical` is the one that matters
most: it checks the actual guarantee rather than the message about it.

Nothing here needs root. The script permits a non-root run when the output
directory is under /tmp or /home, which is where `tmp_path` lives.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def script(repo_root: Path) -> ModuleType:
    """Load the script by path. It is a tool, not an installed package."""
    path = repo_root / "deploy" / "nginx" / "make_dev_tls.py"
    if not path.is_file():
        pytest.fail(f"{path} is missing; the nginx configuration cannot be generated")
    spec = importlib.util.spec_from_file_location("make_dev_tls_under_test", path)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def device_ca(script: ModuleType, tmp_path: Path) -> Path:
    """A stand-in for the internal device CA certificate the script copies.

    Only the certificate is ever read, so a self-signed one is enough; the real
    device CA's private key stays in server/var and this script never touches
    it.
    """
    _, certificate = script.generate_server_ca()
    path = tmp_path / "device-ca-source.crt"
    script.write_certificate(path, certificate, dry_run=False)
    return path


def run(
    script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *arguments: str,
) -> str:
    """Invoke `main()` with argv and return everything THIS call printed.

    The discard matters: the fixtures that seed a CA print their own "wrote
    .../server-ca.key" lines, and without draining first those would be
    attributed to the invocation under test - which is how an assertion about
    what the dry run claims it would write ends up reading the setup's output.
    """
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["make_dev_tls.py", *arguments])
    exit_code = script.main()
    assert exit_code == 0, f"main() returned {exit_code}"
    captured = capsys.readouterr()
    return captured.out + captured.err


def seed_existing_ca(script: ModuleType, out: Path) -> bytes:
    """Create a server CA in `out`, as a previous run would have left it.

    Returns the certificate bytes, so a later assertion can prove they are
    unchanged.
    """
    out.mkdir(parents=True, exist_ok=True)
    key, certificate = script.generate_server_ca()
    script.write_private_key(out / "server-ca.key", key, dry_run=False)
    script.write_certificate(out / "server-ca.crt", certificate, dry_run=False)
    return (out / "server-ca.crt").read_bytes()


# --------------------------------------------------------------------------- #
# The guarantee itself
# --------------------------------------------------------------------------- #


def test_a_real_run_leaves_the_existing_ca_byte_identical(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Adding a name must not replace the CA that enrolled agents are pinned to.

    This is the property an operator is relying on when they add a LAN address
    to the listener certificate while devices are already enrolled.
    """
    out = tmp_path / "dev-tls"
    before = seed_existing_ca(script, out)

    output = run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--ip",
        "10.0.0.7",
    )

    assert (out / "server-ca.crt").read_bytes() == before, "the server CA was replaced"
    assert "reusing the existing dev server CA" in output
    # The leaf certificate IS expected to change: that is the point of the run.
    assert (out / "server.crt").is_file()


def test_force_does_replace_the_ca(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`--force` is the documented way to replace it, and must actually do so."""
    out = tmp_path / "dev-tls"
    before = seed_existing_ca(script, out)

    output = run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--force",
    )

    assert (out / "server-ca.crt").read_bytes() != before
    assert "generating the dev server CA" in output


# --------------------------------------------------------------------------- #
# What the dry run reports
# --------------------------------------------------------------------------- #


def test_dry_run_reports_reuse_when_a_ca_exists(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The regression. A dry run of a reusing invocation must say so."""
    out = tmp_path / "dev-tls"
    seed_existing_ca(script, out)

    output = run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--ip",
        "10.0.0.7",
        "--dry-run",
    )

    assert "would reuse the existing dev server CA" in output
    assert "generating the dev server CA" not in output, (
        "the dry run announced a CA replacement that the real run would not perform"
    )


def test_dry_run_does_not_claim_it_would_write_the_ca_when_reusing(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Nor may it list the CA files among what it would write.

    Only the "would write" lines are examined. The closing summary names
    `server-ca.crt` as the bundle the agent trusts, which is information the
    operator needs and not a claim that the file is about to change.
    """
    out = tmp_path / "dev-tls"
    seed_existing_ca(script, out)

    output = run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--dry-run",
    )

    would_write = [line for line in output.splitlines() if "would write" in line]
    assert would_write, "a dry run should still report the files it would write"
    assert not [line for line in would_write if "server-ca" in line], (
        f"the dry run claims it would rewrite the CA it is reusing: {would_write}"
    )
    # The leaf is replaced either way, so it SHOULD be listed.
    assert [line for line in would_write if "server.key" in line]
    assert [line for line in would_write if "server.crt" in line]


def test_dry_run_reports_generating_on_a_clean_directory(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With no CA present a dry run must not claim it would reuse one."""
    output = run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(tmp_path / "fresh"),
        "--device-ca",
        str(device_ca),
        "--dry-run",
    )

    assert "generating the dev server CA" in output
    assert "would reuse" not in output


def test_dry_run_reports_generating_with_force(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "dev-tls"
    seed_existing_ca(script, out)

    output = run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--force",
        "--dry-run",
    )

    assert "generating the dev server CA" in output
    assert "would reuse" not in output


def test_dry_run_changes_nothing_on_disk(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A dry run that writes is not a dry run."""
    out = tmp_path / "dev-tls"
    seed_existing_ca(script, out)
    before = {path.name: path.read_bytes() for path in sorted(out.iterdir())}

    run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--ip",
        "10.0.0.7",
        "--dry-run",
    )

    after = {path.name: path.read_bytes() for path in sorted(out.iterdir())}
    assert after == before


# --------------------------------------------------------------------------- #
# Subject alternative names
# --------------------------------------------------------------------------- #


def test_extra_names_are_added_to_the_defaults(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Adding a LAN address must not remove loopback.

    Every test, demo and local agent on the server's own machine reaches it as
    `localhost`, so a run that replaced the defaults instead of extending them
    would fix the remote laptop and break everything already working.
    """
    out = tmp_path / "dev-tls"

    run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--ip",
        "10.0.0.7",
        "--hostname",
        "ug.example.internal",
    )

    from cryptography import x509

    certificate = x509.load_pem_x509_certificate((out / "server.crt").read_bytes())
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {str(entry) for entry in san.get_values_for_type(x509.DNSName)}
    addresses = {str(entry) for entry in san.get_values_for_type(x509.IPAddress)}

    assert "localhost" in names
    assert "ug.example.internal" in names
    assert {"127.0.0.1", "::1"} <= addresses
    assert "10.0.0.7" in addresses


def test_an_invalid_ip_is_refused(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo in --ip must stop the run rather than produce a useless cert."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "make_dev_tls.py",
            "--dir",
            str(tmp_path / "dev-tls"),
            "--device-ca",
            str(device_ca),
            "--ip",
            "10.197.21.248.9",
            "--dry-run",
        ],
    )

    with pytest.raises(SystemExit) as raised:
        script.main()

    assert raised.value.code != 0


# --------------------------------------------------------------------------- #
# Strict X.509 verification
# --------------------------------------------------------------------------- #


def test_leaf_carries_an_authority_key_identifier(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """RFC 5280 4.2.1.1 requires it on anything that is not a self-signed CA.

    It was absent, and the consequence was not cosmetic: see the handshake test
    below. Asserted against the CA's own subject key identifier rather than
    merely "an extension is present", because an AKID holding the wrong bytes
    fails verification in exactly the same way as a missing one.
    """
    from cryptography import x509

    out = tmp_path / "dev-tls"
    run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--ip",
        "10.0.0.7",
    )

    authority = x509.load_pem_x509_certificate((out / "server-ca.crt").read_bytes())
    leaf = x509.load_pem_x509_certificate((out / "server.crt").read_bytes())

    akid = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    ca_skid = authority.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert akid.key_identifier == ca_skid.digest, (
        "the leaf's authority key identifier does not match the issuing CA"
    )


def test_leaf_verifies_under_strict_x509(
    script: ModuleType,
    tmp_path: Path,
    device_ca: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A real handshake with `VERIFY_X509_STRICT`, which is the agent's default.

    Since Python 3.13 `ssl.create_default_context()` sets this flag, so an
    agent on 3.13 or newer applies it whether or not anyone chose to. The flag
    is set explicitly here so the test asserts the same behaviour on older
    interpreters instead of silently passing on them.

    This is the test that would have caught the original defect. The extension
    assertion above checks the certificate; this checks that a verifier
    accepts it, and the two fail for different reasons. OpenSSL's own defaults
    accept the malformed chain, so curl, `openssl s_client` and nginx all
    reported success while the agent refused to connect - which is why the
    symptom read as a misconfigured CA bundle.
    """
    import socket
    import ssl
    import threading

    out = tmp_path / "dev-tls"
    run(
        script,
        monkeypatch,
        capsys,
        "--dir",
        str(out),
        "--device-ca",
        str(device_ca),
        "--hostname",
        "localhost",
    )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(out / "server.crt", out / "server.key")

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def accept_once() -> None:
        try:
            raw, _ = listener.accept()
            with server_context.wrap_socket(raw, server_side=True) as tls:
                tls.recv(16)
                tls.sendall(b"ok")
        except OSError:
            # The client's verification failure is the assertion; the server
            # side seeing a torn-down handshake is how that arrives here.
            pass

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    try:
        client_context = ssl.create_default_context(cafile=str(out / "server-ca.crt"))
        client_context.verify_flags |= ssl.VERIFY_X509_STRICT
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
            client_context.wrap_socket(raw, server_hostname="localhost") as tls,
        ):
            tls.sendall(b"hello")
            assert tls.recv(16) == b"ok"
            assert tls.getpeercert() is not None
    finally:
        listener.close()
        thread.join(timeout=5)
