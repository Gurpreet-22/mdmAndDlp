#!/usr/bin/env python3
"""Verify the device plane's mutual TLS end to end, and report evidence.

Every check here needs a real TLS handshake, which is the whole point: a mocked
HTTP layer has no TLS in it and cannot fail "the listener refuses a connection
with no client certificate".

Two ways to run it, and the difference matters when quoting the results.

    # Against a real nginx, using deploy/nginx/ubuntuguard-dev.conf.
    # This is what verifies the committed configuration.
    tools/verify_mtls.py --email <admin-email> --password '<password>' \\
        --enroll-url https://localhost:8443 \\
        --device-url https://localhost:8444 \\
        --ca /etc/ubuntuguard/dev-tls/server-ca.crt

    # Against the reference terminator in tools/mtls_reference_proxy.py,
    # started in-process. Use when nginx is unavailable. This verifies the
    # CONTRACT - the server's header trust, the agent's certificate handling,
    # the device plane - and says NOTHING about the nginx configuration.
    tools/verify_mtls.py --email <admin-email> --password '<password>' \\
        --reference-proxy

Needs: the API on 127.0.0.1:8000, the database running, and dev TLS material
from deploy/nginx/make_dev_tls.py.

Exits non-zero if any check fails. A check that cannot be run is reported as
SKIP and does not count as a pass.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TLS_DIR = Path("/etc/ubuntuguard/dev-tls")

_passed = 0
_failed = 0
_skipped = 0


def check(name: str, ok: bool, evidence: str = "") -> bool:
    global _passed, _failed
    if ok:
        _passed += 1
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        _failed += 1
        print(f"  \033[31mFAIL\033[0m {name}")
    if evidence:
        print(f"       {evidence}")
    return ok


def skip(name: str, why: str) -> None:
    global _skipped
    _skipped += 1
    print(f"  \033[33mSKIP\033[0m {name}")
    print(f"       {why}")


def section(title: str) -> None:
    print(f"\n\033[1m{title}\033[0m")


# --------------------------------------------------------------------------- #
# HTTP helpers. Standard library only, like the agent.
# --------------------------------------------------------------------------- #


def tls_context(ca: Path, certificate: Path | None = None, key: Path | None = None):
    context = ssl.create_default_context(cafile=str(ca))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if certificate is not None and key is not None:
        context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
    return context


def request(
    url: str,
    *,
    context: ssl.SSLContext | None = None,
    method: str = "POST",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    """Returns (status, parsed-body-or-text). Never raises for an HTTP status."""
    data = json.dumps(payload).encode() if payload is not None else None
    merged = {"Content-Type": "application/json", "Accept": "application/json"}
    merged.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=merged)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context) if context else urllib.request.HTTPHandler(),
        urllib.request.ProxyHandler({}),
    )
    try:
        with opener.open(req, timeout=20) as response:
            body = response.read()
            try:
                return response.status, json.loads(body or b"{}")
            except ValueError:
                return response.status, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body or b"{}")
        except ValueError:
            return exc.code, body.decode("utf-8", "replace")


def plain_request(
    base: str, path: str, *, method: str = "POST", payload: Any = None, token: str | None = None
) -> tuple[int, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return request(base + path, method=method, payload=payload, headers=headers)


# --------------------------------------------------------------------------- #
# Certificate helpers
# --------------------------------------------------------------------------- #


def write_identity(directory: Path, name: str, certificate_pem: str, key: Any) -> tuple[Path, Path]:
    import os

    from cryptography.hazmat.primitives import serialization

    directory.mkdir(parents=True, exist_ok=True)
    certificate_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    certificate_path.write_text(certificate_pem, encoding="utf-8")
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(
            descriptor,
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
    finally:
        os.close(descriptor)
    return certificate_path, key_path


def make_csr(key: Any = None, common_name: str = "unenrolled") -> tuple[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii"), key


def enrol(admin_base: str, token_source: Any, workdir: Path, label: str) -> dict[str, Any]:
    """Mint a token, enrol a device, write its identity to disk."""
    status, minted = token_source()
    if status != 201:
        raise SystemExit(f"could not mint an enrollment token: {status} {minted}")
    token = minted["enrollment_token"]

    csr, key = make_csr()
    status, payload = request(
        admin_base + "/api/v1/enroll",
        context=ENROLL_CONTEXT,
        payload={
            "enrollment_token": token,
            "csr_pem": csr,
            "hostname": f"verify-{label}-{uuid.uuid4().hex[:6]}",
            "agent_version": "0.1.0",
            "arch": "x86_64",
            "os": {"id": "ubuntu", "version_id": "24.04", "kernel": "6.8.0-45-generic"},
            "hardware_fingerprint": {},
            "release_build": True,
        },
    )
    if status != 201:
        raise SystemExit(f"enrollment failed: {status} {payload}")

    certificate_path, key_path = write_identity(
        workdir, label, payload["client_certificate_pem"], key
    )
    return {
        "device_id": payload["device_id"],
        "certificate_pem": payload["client_certificate_pem"],
        "certificate_path": certificate_path,
        "key_path": key_path,
        "key": key,
    }


ENROLL_CONTEXT: ssl.SSLContext | None = None

#: Devices enrolled by this run, registered as soon as each exists so that the
#: `finally` in `main` can revoke them however the run ends.
_scratch_devices: list[tuple[dict[str, Any], str]] = []

#: The admin access token, shared with the cleanup path. A dict rather than a
#: module-level string so `run_checks` can populate it without a `global`.
_admin_access: dict[str, str] = {}


def revoke_scratch_devices(api: str, access: str | None) -> None:
    """Revoke everything this run enrolled. Safe to call more than once.

    Runs from a `finally`, so it must not raise: a cleanup failure should be
    reported and then get out of the way of whatever actually went wrong. A
    409 here means the device was already revoked, which is a success.
    """
    if not _scratch_devices:
        return
    section("Cleanup")
    if access is None:
        print("  \033[31mno admin session; cannot revoke:\033[0m")
        for device, label in _scratch_devices:
            print(f"    device {label} {device['device_id']} is STILL ACTIVE")
        return

    for device, label in list(_scratch_devices):
        try:
            status, _ = plain_request(
                api,
                f"/api/v1/devices/{device['device_id']}:revoke",
                payload={"reason": "mTLS verification run, revoking the scratch device"},
                token=access,
            )
        except Exception as exc:  # noqa: BLE001 - cleanup must not mask the real failure
            print(f"  \033[31mcould not revoke device {label}: {exc}\033[0m")
            continue
        outcome = "revoked" if status == 204 else ("already revoked" if status == 409 else "FAILED")
        colour = "\033[32m" if status in (204, 409) else "\033[31m"
        print(f"  {colour}{outcome}\033[0m device {label} ({device['device_id']}): HTTP {status}")
    _scratch_devices.clear()


# --------------------------------------------------------------------------- #


def main() -> int:  # noqa: C901 - a linear script of checks reads better whole
    global ENROLL_CONTEXT

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="an admin account")
    parser.add_argument("--password", required=True)
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="the backend, for admin calls")
    parser.add_argument("--enroll-url", default=None, help="TLS enrollment listener")
    parser.add_argument("--device-url", default=None, help="TLS device listener")
    parser.add_argument("--ca", type=Path, default=DEFAULT_TLS_DIR / "server-ca.crt")
    parser.add_argument(
        "--reference-proxy",
        action="store_true",
        help="Start tools/mtls_reference_proxy.py in-process instead of using nginx",
    )
    parser.add_argument("--tls-dir", type=Path, default=DEFAULT_TLS_DIR)
    parser.add_argument("--workdir", type=Path, default=Path("/tmp/ug-verify-mtls"))
    arguments = parser.parse_args()

    print("\033[1mUbuntuGuard device-plane mTLS verification\033[0m")

    # --- the terminator ---------------------------------------------------- #
    import contextlib

    stack = contextlib.ExitStack()
    if arguments.reference_proxy:
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        from mtls_reference_proxy import run_both_planes

        for required in ("server.crt", "server.key", "device-ca.crt"):
            if not (arguments.tls_dir / required).exists():
                raise SystemExit(
                    f"{arguments.tls_dir / required} is missing. Generate it:\n"
                    "  sudo server/.venv/bin/python deploy/nginx/make_dev_tls.py"
                )
        enroll_url, device_url = stack.enter_context(
            run_both_planes(
                server_certificate=arguments.tls_dir / "server.crt",
                server_key=arguments.tls_dir / "server.key",
                device_ca=arguments.tls_dir / "device-ca.crt",
            )
        )
        print("terminator: tools/mtls_reference_proxy.py (in-process)")
        print(
            "\033[33mNOTE: this verifies the mTLS CONTRACT, not "
            "deploy/nginx/ubuntuguard-dev.conf.\033[0m"
        )
    else:
        enroll_url = arguments.enroll_url
        device_url = arguments.device_url
        if not enroll_url or not device_url:
            raise SystemExit(
                "pass --enroll-url and --device-url for an external proxy, "
                "or --reference-proxy to start the built-in one"
            )
        print(f"terminator: external (nginx) {enroll_url} / {device_url}")

    with stack:
        # The cleanup runs however `run_checks` ends - a failed assertion, an
        # unexpected exception, or Ctrl-C. `_admin_access` is set as soon as the
        # admin session exists, so cleanup can authenticate even if the failure
        # happened immediately afterwards.
        try:
            return run_checks(arguments, enroll_url, device_url)
        finally:
            revoke_scratch_devices(arguments.api, _admin_access.get("token"))
            print(f"  identities written to {arguments.workdir} - delete it when done")


def run_checks(arguments: Any, enroll_url: str, device_url: str) -> int:  # noqa: C901, PLR0915
    global ENROLL_CONTEXT

    if not arguments.ca.exists():
        raise SystemExit(f"--ca {arguments.ca} does not exist")
    ENROLL_CONTEXT = tls_context(arguments.ca)
    workdir = arguments.workdir
    workdir.mkdir(parents=True, exist_ok=True)

    # --- admin session, over plain HTTP to the backend --------------------- #
    status, body = plain_request(
        arguments.api,
        "/api/v1/auth/login",
        payload={"email": arguments.email, "password": arguments.password},
    )
    if status != 200:
        raise SystemExit(f"admin login failed: {status} {body}")
    access = body["access_token"]
    # Published before any device exists, so the cleanup path always has a
    # credential by the time there is anything to clean up.
    _admin_access["token"] = access

    def mint() -> tuple[int, Any]:
        return plain_request(
            arguments.api, "/api/v1/enrollment-tokens", payload={}, token=access
        )

    # ======================================================================= #
    section("1. Enrollment listener: works WITHOUT a client certificate")
    # ======================================================================= #
    device_a = enrol(enroll_url, mint, workdir, "device-a")
    check(
        "POST /api/v1/enroll over TLS with no client certificate",
        bool(device_a["device_id"]),
        f"device {device_a['device_id']}",
    )

    device_b = enrol(enroll_url, mint, workdir, "device-b")
    check(
        "a second device enrols, for the impersonation test below",
        device_b["device_id"] != device_a["device_id"],
        f"device {device_b['device_id']}",
    )

    # Registered for cleanup the moment they exist, and cleaned up in a
    # `finally` below.
    #
    # This was a real bug, not a precaution. The first run of this script
    # aborted at check 2 - a handshake refusal arriving as an OSError that the
    # top-level handler swallowed - and because cleanup was the last statement
    # in the happy path, two enrolled devices were left `active` in the
    # database with valid certificates. A verification tool that leaves live
    # device identities behind when it fails is worse than one that does not
    # run, because nobody goes looking.
    _scratch_devices.extend(((device_a, "A"), (device_b, "B")))

    # ======================================================================= #
    section("2. Device listener: refuses a MISSING client certificate")
    # ======================================================================= #
    # A listener with `ssl_verify_client on` aborts the HANDSHAKE rather than
    # answering, so the refusal arrives as a connection error, not an HTTP
    # status. Both shapes count as a refusal and the evidence line says which
    # was seen - a reset here is the stronger result, because it means nothing
    # downstream was ever reachable.
    try:
        status, body = request(
            device_url + "/api/v1/devices/me/heartbeat",
            context=tls_context(arguments.ca),
            payload={"agent_version": "0.1.0", "uptime_seconds": 1},
        )
        outcome = f"HTTP {status}"
        refused = status != 200
    except (ssl.SSLError, urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        outcome = f"connection refused at the handshake: {type(reason).__name__}: {reason}"
        refused = True
    check("no client certificate is refused", refused, outcome)

    # ======================================================================= #
    section("3. Device listener: refuses an INVALID client certificate")
    # ======================================================================= #
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    forged_key = ec.generate_private_key(ec.SECP256R1())
    forged = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_a["device_id"])]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Attacker CA")]))
        .public_key(forged_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30))
        .sign(forged_key, hashes.SHA256())
    )
    forged_cert_path, forged_key_path = write_identity(
        workdir,
        "forged",
        forged.public_bytes(serialization.Encoding.PEM).decode(),
        forged_key,
    )
    try:
        status, body = request(
            device_url + "/api/v1/devices/me/heartbeat",
            context=tls_context(arguments.ca, forged_cert_path, forged_key_path),
            payload={"agent_version": "0.1.0", "uptime_seconds": 1},
        )
        outcome = f"HTTP {status}"
        refused = status != 200
    except (ssl.SSLError, urllib.error.URLError, OSError) as exc:
        outcome = f"handshake refused: {type(exc).__name__}"
        refused = True
    check(
        "a certificate from an unknown CA, naming a real device, is refused",
        refused,
        outcome + " (the CN was a genuine device id)",
    )

    # ======================================================================= #
    section("4. Device listener: ACCEPTS the enrolled certificate")
    # ======================================================================= #
    context_a = tls_context(arguments.ca, device_a["certificate_path"], device_a["key_path"])
    status, body = request(
        device_url + "/api/v1/devices/me/heartbeat",
        context=context_a,
        payload={"agent_version": "0.1.0", "uptime_seconds": 120},
    )
    heartbeat_ok = check(
        "heartbeat over mutual TLS succeeds",
        status == 200,
        f"HTTP {status}; fields: {sorted(body) if isinstance(body, dict) else body}",
    )

    # ======================================================================= #
    section("5. The backend records the CORRECT device identity")
    # ======================================================================= #
    status, detail = plain_request(
        arguments.api, f"/api/v1/devices/{device_a['device_id']}", method="GET", token=access
    )
    check(
        "the heartbeat was attributed to device A",
        status == 200 and detail.get("online") is True,
        f"online={detail.get('online')} last_heartbeat_at={detail.get('last_heartbeat_at')}",
    )
    status, detail_b = plain_request(
        arguments.api, f"/api/v1/devices/{device_b['device_id']}", method="GET", token=access
    )
    check(
        "device B was NOT credited with device A's heartbeat",
        detail_b.get("last_heartbeat_at") is None,
        f"device B last_heartbeat_at={detail_b.get('last_heartbeat_at')}",
    )

    # ======================================================================= #
    section("6. Forged X-Client-* headers cannot impersonate a device")
    # ======================================================================= #
    # The strongest form of this test: a genuine, verified connection as device
    # A, carrying headers that claim to be device B. The proxy must overwrite
    # them, so the backend must see A.
    status, body = request(
        device_url + "/api/v1/devices/me/heartbeat",
        context=context_a,
        payload={"agent_version": "9.9.9-forged", "uptime_seconds": 7},
        headers={
            "X-Client-Verify": "SUCCESS",
            "X-Client-Cert": quote(device_b["certificate_pem"], safe=""),
            "X-Client-DN": f"CN={device_b['device_id']}",
            "X-Client-Serial": "DEADBEEF",
        },
    )
    _, detail_b = plain_request(
        arguments.api, f"/api/v1/devices/{device_b['device_id']}", method="GET", token=access
    )
    _, detail_a = plain_request(
        arguments.api, f"/api/v1/devices/{device_a['device_id']}", method="GET", token=access
    )
    check(
        "device B's forged certificate header was overwritten by the proxy",
        detail_b.get("last_heartbeat_at") is None,
        f"device B still has last_heartbeat_at={detail_b.get('last_heartbeat_at')}",
    )
    check(
        "the request was attributed to device A, whose certificate TLS verified",
        status == 200 and detail_a.get("agent_version") == "9.9.9-forged",
        f"device A agent_version={detail_a.get('agent_version')} (proves A handled it)",
    )

    # And through the enrollment listener, where there is no client certificate
    # at all, forged headers must not reach the device plane either.
    status, body = request(
        enroll_url + "/api/v1/devices/me/heartbeat",
        context=tls_context(arguments.ca),
        payload={"agent_version": "0.1.0", "uptime_seconds": 1},
        headers={
            "X-Client-Verify": "SUCCESS",
            "X-Client-Cert": quote(device_a["certificate_pem"], safe=""),
        },
    )
    check(
        "forged headers on the enrollment listener do not reach the device plane",
        status != 200,
        f"HTTP {status} (421 misdirected, or 401 with the proxy's NONE)",
    )

    # ======================================================================= #
    section("7. Certificate renewal over mutual TLS")
    # ======================================================================= #
    renewal_csr, renewal_key = make_csr()
    status, renewed = request(
        device_url + "/api/v1/devices/me/certificate:renew",
        context=context_a,
        payload={"csr_pem": renewal_csr},
    )
    renewal_ok = check(
        "renewal authenticated by the certificate being replaced",
        status == 200,
        f"HTTP {status}"
        + (
            f"; new not_after={renewed.get('certificate_not_after')}"
            if isinstance(renewed, dict)
            else ""
        ),
    )

    if renewal_ok:
        new_cert_path, new_key_path = write_identity(
            workdir, "device-a-renewed", renewed["client_certificate_pem"], renewal_key
        )
        context_renewed = tls_context(arguments.ca, new_cert_path, new_key_path)

        status, body = request(
            device_url + "/api/v1/devices/me/heartbeat",
            context=context_renewed,
            payload={"agent_version": "0.2.0-renewed", "uptime_seconds": 300},
        )
        check(
            "the REPLACEMENT certificate completes a heartbeat",
            status == 200,
            f"HTTP {status}",
        )

        status, body = request(
            device_url + "/api/v1/devices/me/heartbeat",
            context=context_a,
            payload={"agent_version": "0.1.0", "uptime_seconds": 1},
        )
        check(
            "the OLD certificate can no longer heartbeat",
            status == 401
            and isinstance(body, dict)
            and body.get("code") == "client_cert_superseded",
            f"HTTP {status} code={body.get('code') if isinstance(body, dict) else body}",
        )

        status, again = request(
            device_url + "/api/v1/devices/me/certificate:renew",
            context=context_a,
            payload={"csr_pem": renewal_csr},
        )
        check(
            "the OLD certificate CAN still retry the renewal, idempotently",
            status == 200
            and isinstance(again, dict)
            and again.get("reused") is True
            and again["client_certificate_pem"] == renewed["client_certificate_pem"],
            f"HTTP {status} reused={again.get('reused') if isinstance(again, dict) else again}",
        )

        status, detail = plain_request(
            arguments.api, f"/api/v1/devices/{device_a['device_id']}", method="GET", token=access
        )
        import hashlib

        new_der = x509.load_pem_x509_certificate(
            renewed["client_certificate_pem"].encode()
        ).public_bytes(serialization.Encoding.DER)
        expected = "sha256:" + hashlib.sha256(new_der).hexdigest()
        check(
            "the backend's certificate pin now names the replacement",
            detail.get("cert_fingerprint") == expected,
            f"cert_fingerprint={detail.get('cert_fingerprint')}",
        )
    else:
        skip("replacement-certificate checks", "renewal itself failed")

    # ======================================================================= #
    section("8. Revocation takes effect on the next request")
    # ======================================================================= #
    status, _ = plain_request(
        arguments.api,
        f"/api/v1/devices/{device_b['device_id']}:revoke",
        payload={"reason": "mTLS verification run, revoking the scratch device"},
        token=access,
    )
    if status == 204:
        context_b = tls_context(arguments.ca, device_b["certificate_path"], device_b["key_path"])
        status, body = request(
            device_url + "/api/v1/devices/me/heartbeat",
            context=context_b,
            payload={"agent_version": "0.1.0", "uptime_seconds": 1},
        )
        check(
            "a revoked device is refused despite a perfectly valid certificate",
            status == 401,
            f"HTTP {status} code={body.get('code') if isinstance(body, dict) else body}",
        )
        csr, _ = make_csr()
        status, body = request(
            device_url + "/api/v1/devices/me/certificate:renew",
            context=context_b,
            payload={"csr_pem": csr},
        )
        check(
            "a revoked device cannot renew its certificate",
            status == 401,
            f"HTTP {status} code={body.get('code') if isinstance(body, dict) else body}",
        )
    else:
        skip("revocation checks", f"could not revoke device B: HTTP {status}")

    # ======================================================================= #
    print(f"\n\033[1m{_passed} passed, {_failed} failed, {_skipped} skipped\033[0m")
    if _failed:
        print(
            "\n\033[31mmTLS is NOT verified.\033[0m Do not describe it as verified "
            "while any check above fails."
        )
        return 1
    print("\n\033[32mEvery check passed.\033[0m")
    if arguments.reference_proxy:
        print(
            "This verified the mTLS CONTRACT against the reference terminator.\n"
            "deploy/nginx/ubuntuguard-dev.conf is a separate artefact and remains\n"
            "UNEXERCISED until this script is run with --enroll-url/--device-url\n"
            "against a running nginx."
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except urllib.error.URLError as exc:
        # Deliberately narrow, and only for the admin calls that must work for
        # the script to run at all. An earlier version caught OSError here,
        # which swallowed the connection reset that IS the expected result of
        # check 2 and reported a passing refusal as a fatal error.
        sys.exit(
            f"\ncould not reach the API: {exc.reason}\n"
            "Is it running on 127.0.0.1:8000, with the database up?"
        )
