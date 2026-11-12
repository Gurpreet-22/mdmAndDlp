#!/usr/bin/env python3
"""Generate the development TLS material the nginx configuration needs.

Creates three things under /etc/ubuntuguard/dev-tls:

  server-ca.crt   a throwaway CA for the SERVER's own TLS certificate. This is
                  what the agent trusts as `server_ca_bundle`.
  server.crt/.key the listener certificate for localhost, 127.0.0.1 and ::1.
  device-ca.crt   a COPY of the internal device CA, which nginx uses as
                  `ssl_client_certificate` to verify device certificates.

Two CAs, two jobs, and keeping them apart is the point. The server CA proves to
the agent that it is talking to the right server. The device CA proves to nginx
that a connecting client is an enrolled device. Using one for both would mean
anything the agent trusts as a server could also authenticate as a device.

The device CA is COPIED rather than symlinked so nginx reads a root-owned path
under /etc, and so a repository checkout moving or being deleted cannot
silently break TLS. The repository remains the source of truth: re-run this
script after `python -m ubuntuguard.cli init-keys`, or every device certificate
nginx sees will fail to verify against a CA that no longer signs them.

Nothing here touches the device CA's PRIVATE key, which stays in server/var at
mode 0600 and is never read by this script or by nginx.

Usage:
    sudo deploy/nginx/make_dev_tls.py
    sudo deploy/nginx/make_dev_tls.py --dry-run
    sudo deploy/nginx/make_dev_tls.py --device-ca server/var/ca.crt
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import shutil
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - a setup error, not a code path
    sys.exit(
        "cryptography is not importable with this interpreter.\n"
        "Run the script with one of the project virtualenvs, e.g.:\n"
        "    sudo server/.venv/bin/python deploy/nginx/make_dev_tls.py"
    )

#: Where nginx reads from. Root-owned, outside the repository.
TLS_DIR = Path("/etc/ubuntuguard/dev-tls")

#: Short on purpose. Development material should expire rather than quietly
#: become a long-lived trusted CA on somebody's laptop.
CA_VALID_DAYS = 365
SERVER_VALID_DAYS = 365

#: Names the listener certificate is valid for, by default.
#:
#: Loopback only, because that is what the committed dev nginx config listens
#: on. Enrolling a laptop OTHER than this one needs a name that laptop can
#: reach, which is what `--hostname` and `--ip` are for: the agent verifies the
#: hostname and has no option to skip it, so a certificate without a matching
#: SAN is refused with `TlsVerificationError` rather than warned about.
DEFAULT_HOSTNAMES = ("localhost",)
DEFAULT_IP_ADDRESSES = ("127.0.0.1", "::1")

UTC = dt.timezone.utc


def log(message: str) -> None:
    print(f"[dev-tls] {message}")


def die(message: str) -> None:
    sys.exit(f"[dev-tls] ERROR: {message}")


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UbuntuGuard Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def generate_server_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A self-signed CA for the listener certificate only."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    subject = _name("UbuntuGuard Dev Server CA")
    public_key = key.public_key()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_VALID_DAYS))
        # path_length=0: may sign the listener certificate and nothing else.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def generate_server_certificate(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_certificate: x509.Certificate,
    *,
    hostnames: tuple[str, ...] = DEFAULT_HOSTNAMES,
    ip_addresses: tuple[str, ...] = DEFAULT_IP_ADDRESSES,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """The listener certificate, with SANs for every address the agent may use.

    Subject alternative names, not just a common name: every TLS stack written
    this decade ignores CN for hostname matching, Python's included. A
    certificate with only a CN would fail verification with
    `check_hostname=True`, which the agent requires and does not relax.

    The common name is the first hostname, which is cosmetic - it is what
    `openssl x509 -subject` shows a human - while the SAN list is what is
    actually checked.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    public_key = key.public_key()

    alternative_names: list[x509.GeneralName] = [x509.DNSName(host) for host in hostnames]
    alternative_names += [x509.IPAddress(ipaddress.ip_address(address)) for address in ip_addresses]
    if not alternative_names:
        raise SystemExit("at least one --hostname or --ip is required")

    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(hostnames[0] if hostnames else ip_addresses[0]))
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=SERVER_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # SERVER_AUTH only. This certificate cannot be presented as a client
        # certificate to the device listener.
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        # Required, not decorative. RFC 5280 4.2.1.1 says every certificate
        # except a self-signed CA must carry an authority key identifier, and
        # since Python 3.13 `ssl.create_default_context()` enables
        # VERIFY_X509_STRICT, which enforces it. Without this extension an
        # agent on 3.13 or newer refuses the handshake with "Missing Authority
        # Key Identifier" while OpenSSL's own defaults - curl, `openssl
        # s_client`, nginx - accept the same chain, so the failure looks like a
        # wrong CA bundle rather than a malformed certificate.
        .add_extension(_authority_key_identifier(ca_certificate), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, certificate


def _authority_key_identifier(ca_certificate: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    """Derive the issuer's key identifier, preferring the CA's own SKID.

    Taken from the CA's subject key identifier when it has one, so the bytes
    match exactly what a verifier reads off the issuer rather than being
    recomputed and hoped to agree. A CA generated before this script wrote a
    SKID has none, so the key digest is the fallback.
    """
    try:
        subject_key_id = ca_certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_certificate.public_key()  # type: ignore[arg-type]
        )
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key_id.value)


def write_private_key(path: Path, key: ec.EllipticCurvePrivateKey, *, dry_run: bool) -> None:
    """Write a private key at 0600, created restrictively rather than chmod'ed.

    `os.open` with the mode is not a style preference: creating the file and
    then calling chmod leaves a window in which the key exists and is
    world-readable, and that window is enough.
    """
    if dry_run:
        log(f"[dry-run] would write {path} (0600)")
        return
    data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    log(f"wrote {path} (0600)")


def write_certificate(path: Path, certificate: x509.Certificate, *, dry_run: bool) -> None:
    if dry_run:
        log(f"[dry-run] would write {path} (0644)")
        return
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)
    log(f"wrote {path} (0644)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--device-ca",
        type=Path,
        default=None,
        help="The internal device CA certificate (default: <repo>/server/var/ca.crt)",
    )
    parser.add_argument("--dir", type=Path, default=TLS_DIR, help=f"Output directory ({TLS_DIR})")
    parser.add_argument(
        "--hostname",
        action="append",
        default=None,
        metavar="NAME",
        help=(
            "Extra DNS name for the listener certificate; repeatable. Needed to "
            "enrol a laptop other than this one, because the agent verifies the "
            "hostname and cannot be told not to. Defaults to localhost."
        ),
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=None,
        metavar="ADDRESS",
        help=(
            "Extra IP address for the listener certificate; repeatable. Use when "
            "agents reach the server by address rather than by name. Defaults to "
            "127.0.0.1 and ::1."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions, change nothing")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate the server CA even if one already exists",
    )
    arguments = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    device_ca = arguments.device_ca or repo_root / "server" / "var" / "ca.crt"
    out = arguments.dir

    if not arguments.dry_run and os.geteuid() != 0 and not str(out).startswith(("/tmp", "/home")):
        die(f"must run as root to write {out}. Try: sudo {sys.argv[0]}")

    if not device_ca.exists():
        die(
            f"the internal device CA is missing at {device_ca}.\n"
            "  Generate it first:  cd server && .venv/bin/python -m ubuntuguard.cli init-keys\n"
            "  or point at it:     --device-ca <path>"
        )

    # Extra names are ADDED to the defaults rather than replacing them, so a
    # run with --ip for a LAN address does not silently stop working for
    # localhost - which is what every test and demo on this machine uses.
    hostnames = tuple(dict.fromkeys(DEFAULT_HOSTNAMES + tuple(arguments.hostname or ())))
    ip_addresses = tuple(dict.fromkeys(DEFAULT_IP_ADDRESSES + tuple(arguments.ip or ())))
    for address in ip_addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            die(f"--ip {address!r} is not a valid IP address")

    log(f"output directory  {out}")
    log(f"device CA source  {device_ca}")
    log(f"certificate names {', '.join(hostnames + ip_addresses)}")

    if arguments.dry_run:
        log(f"[dry-run] would create {out} (0755)")
    else:
        out.mkdir(parents=True, exist_ok=True)
        out.chmod(0o755)

    server_ca_cert_path = out / "server-ca.crt"
    server_ca_key_path = out / "server-ca.key"
    server_cert_path = out / "server.crt"
    server_key_path = out / "server.key"
    device_ca_path = out / "device-ca.crt"

    reuse = server_ca_cert_path.exists() and server_ca_key_path.exists() and not arguments.force
    if reuse and arguments.dry_run:
        # Reported from `reuse` alone, because whether this invocation REPLACES
        # the server CA is the one thing the dry run exists to answer:
        # replacing it invalidates the `server_ca_bundle` every enrolled agent
        # is pinned to, and they all fail at once. Deciding the message with
        # `and not dry_run` instead told the operator a reusing run would
        # generate - the alarming answer, and the wrong one.
        #
        # A throwaway CA is still generated below, in memory and never written,
        # because the listener certificate has to be signed by something and
        # the real CA key is root-owned at 0600, which a non-root dry run
        # cannot read. Nothing about it is reported or persisted.
        log("would reuse the existing dev server CA (pass --force to replace it)")
        ca_key, ca_certificate = generate_server_ca()
    elif reuse:
        log("reusing the existing dev server CA (pass --force to replace it)")
        ca_key_obj = serialization.load_pem_private_key(
            server_ca_key_path.read_bytes(), password=None
        )
        if not isinstance(ca_key_obj, ec.EllipticCurvePrivateKey):
            die(f"{server_ca_key_path} is not an EC private key; pass --force to regenerate")
        ca_key = ca_key_obj
        ca_certificate = x509.load_pem_x509_certificate(server_ca_cert_path.read_bytes())
    else:
        log("generating the dev server CA (EC P-256)")
        ca_key, ca_certificate = generate_server_ca()
        write_private_key(server_ca_key_path, ca_key, dry_run=arguments.dry_run)
        write_certificate(server_ca_cert_path, ca_certificate, dry_run=arguments.dry_run)

    log("generating the listener certificate")
    server_key, server_certificate = generate_server_certificate(
        ca_key, ca_certificate, hostnames=hostnames, ip_addresses=ip_addresses
    )
    write_private_key(server_key_path, server_key, dry_run=arguments.dry_run)
    write_certificate(server_cert_path, server_certificate, dry_run=arguments.dry_run)

    if arguments.dry_run:
        log(f"[dry-run] would copy {device_ca} -> {device_ca_path} (0644)")
    else:
        shutil.copyfile(device_ca, device_ca_path)
        device_ca_path.chmod(0o644)
        log(f"copied the device CA to {device_ca_path} (0644)")

    print(
        f"""
[dev-tls] done.

nginx reads:
    ssl_certificate         {server_cert_path}
    ssl_certificate_key     {server_key_path}
    ssl_client_certificate  {device_ca_path}    <- the DEVICE CA, not the server CA

The agent trusts:
    server_ca_bundle        {server_ca_cert_path}

Put this in /etc/ubuntuguard/agent.yaml (production), or export it for a
development run:

    export UG_AGENT_DEV=1
    export UG_AGENT_SERVER_URL=https://localhost:8443
    export UG_AGENT_DEVICE_URL=https://localhost:8444
    export UG_AGENT_SERVER_CA_BUNDLE={server_ca_cert_path}

Re-run this script after `ubuntuguard.cli init-keys`, or nginx will be
verifying device certificates against a CA that no longer signs them.
"""
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
