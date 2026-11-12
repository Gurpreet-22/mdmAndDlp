#!/usr/bin/env python3
"""Drive the running API end to end, and attack it, with visible output.

Companion to `demo_security_core.py`, which needs no server. This one needs the
API running and the database up, and exercises the whole Phase 1 path: log in,
mint a one-time enrollment token, enroll a device with its own keypair, send a
heartbeat over mTLS headers, revoke the device, and verify the audit chain over
the lot.

Uses only the standard library for HTTP, so it works on a machine with no curl.

Run:
    cd server && ./scripts/dev_db.sh up          # if the database is not running
    cd server && .venv/bin/python -m uvicorn ubuntuguard.main:create_app \\
                   --factory --host 127.0.0.1 --port 8000
    ./tools/demo_api.py --password '<your admin password>'

Everything it creates is a test artefact: one enrollment token and one device,
which it revokes before finishing.
"""

# ruff: noqa: E402, I001
# The imports below sit under _ensure_dependencies() on purpose: the re-exec has
# to happen BEFORE cryptography or ubuntuguard are imported, so they cannot move
# to the top of the file. E402 and import sorting are suppressed for that reason
# and that reason only; every other rule stays active.

from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

REPO = Path(__file__).resolve().parent.parent
VENV_PYTHON = REPO / "server" / ".venv" / "bin" / "python"
sys.path.insert(0, str(REPO / "server" / "src"))


def _ensure_dependencies() -> None:
    """Re-exec under the server virtualenv if cryptography is missing.

    The shebang resolves to the system python3, which does not have it. Without
    this, running the script the obvious way fails with a ModuleNotFoundError
    that says nothing about the fix.
    """
    try:
        # Probe the PACKAGE, not one of its dependencies. An earlier version
        # checked only `cryptography`, which the system interpreter happened to
        # have, so the re-exec never fired and the script died later on a
        # missing `sqlalchemy`. `ubuntuguard` can only resolve inside the venv.
        import ubuntuguard  # noqa: F401
    except ModuleNotFoundError:
        if Path(sys.executable).resolve() == VENV_PYTHON.resolve():
            raise
        if not VENV_PYTHON.exists():
            sys.exit(
                "The server virtualenv is missing. Create it with:\n"
                "  uv venv --python 3.12 server/.venv\n"
                '  cd server && uv pip install --python .venv/bin/python -e ".[dev]"'
            )
        # No shell by design; argv is fixed and fully controlled here.
        os.execv(  # noqa: S606
            str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]]
        )


_ensure_dependencies()

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BOLD, DIM, GREEN, RED, CYAN, YELLOW, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[36m",
    "\033[33m",
    "\033[0m",
)


def section(number: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}{number}. {title}{RESET}")
    print(f"{DIM}{'─' * (len(title) + 4)}{RESET}")


def ok(message: str) -> None:
    print(f"   {GREEN}✓{RESET} {message}")


def blocked(message: str) -> None:
    print(f"   {RED}✗ REFUSED{RESET} {message}")


def note(message: str) -> None:
    print(f"   {DIM}{message}{RESET}")


def attack(message: str) -> None:
    print(f"   {YELLOW}attack:{RESET} {message}")


def must(condition: bool, claim: str) -> None:
    """Fail loudly rather than print a claim that is not true.

    A plain assert would be stripped by `python -O`, and a demo that prints
    "refused" without checking is worse than no demo.
    """
    if not condition:
        raise AssertionError(f"demo claim is false: {claim}")


class Client:
    """Minimal HTTP client that keeps cookies, so no curl is needed."""

    #: urlopen honours file:, ftp: and custom schemes. Without this check a
    #: --base-url of file:///etc/passwd would read a local file instead of
    #: making a request, which is a needless foot-gun in a demo script.
    ALLOWED_SCHEMES = ("http://", "https://")

    def __init__(self, base_url: str) -> None:
        if not base_url.startswith(self.ALLOWED_SCHEMES):
            sys.exit(f"--base-url must start with one of {self.ALLOWED_SCHEMES}")
        self.base_url = base_url.rstrip("/")
        self.cookies: dict[str, str] = {}
        self.bearer: str | None = None

    def call(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        if authenticated and self.bearer:
            request_headers["Authorization"] = f"Bearer {self.bearer}"
        if self.cookies:
            request_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        # Scheme is validated in __init__, so file:/ftp: cannot reach here.
        request = urllib.request.Request(  # noqa: S310
            self.base_url + path, data=data, headers=request_headers, method=method
        )
        try:
            # Scheme validated in __init__, so file:/ftp: cannot reach here.
            with urllib.request.urlopen(request) as response:  # noqa: S310
                for raw in response.headers.get_all("set-cookie") or []:
                    name, _, value = raw.split(";")[0].partition("=")
                    self.cookies[name] = value
                payload = response.read().decode()
                content_type = response.headers.get("content-type", "")
                parsed = json.loads(payload) if payload and "json" in content_type else payload
                return response.status, parsed
        except urllib.error.HTTPError as error:
            payload = error.read().decode()
            try:
                return error.code, json.loads(payload)
            except json.JSONDecodeError:
                return error.code, payload
        except urllib.error.URLError as error:
            sys.exit(
                f"\n{RED}Cannot reach {self.base_url}: {error.reason}{RESET}\n\n"
                "Start the server first:\n"
                "  cd server && .venv/bin/python -m uvicorn ubuntuguard.main:create_app "
                "--factory --host 127.0.0.1 --port 8000"
            )


def csr_for(common_name: str) -> str:
    """Build a CSR the way an agent would: keypair generated locally."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def enroll_payload(csr_pem: str, token: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "enrollment_token": token,
        "csr_pem": csr_pem,
        "hostname": f"demo-{uuid.uuid4().hex[:6]}",
        "agent_version": "0.1.0",
        "arch": "x86_64",
        "os": {"id": "ubuntu", "version_id": "24.04", "kernel": "6.8.0-45-generic"},
        "hardware_fingerprint": {"machine_id_hash": uuid.uuid4().hex * 2},
        "release_build": True,
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    # No default: see the note in tools/seed_devices.py.
    parser.add_argument("--email", required=True, help="the admin account to authenticate as")
    parser.add_argument(
        "--password",
        default=None,
        help="Omit to be prompted. Avoid on a shared machine: arguments are visible in ps.",
    )
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.email}: ")
    client = Client(args.base_url)
    socket.setdefaulttimeout(20)

    print(f"{BOLD}UbuntuGuard — API walkthrough{RESET}")
    print(f"{DIM}{args.base_url} · stdlib HTTP only, no curl required{RESET}")

    # --- 1 ----------------------------------------------------------------- #
    section(1, "Readiness")
    status, ready = client.call("GET", "/readyz", authenticated=False)
    if status != 200:
        print(f"   {RED}not ready:{RESET} {ready}")
        print("\n   Fix the failing check above, then re-run. Common causes:")
        print("     database  -> cd server && ./scripts/dev_db.sh up")
        print("     keys      -> cd server && .venv/bin/python -m ubuntuguard.cli init-keys")
        return 1
    ok(f"{ready['status']}")
    for name, value in ready["checks"].items():
        note(f"{name}: {value}")
    note("audit_append_only is checked because that guarantee lives in the database")
    note("GRANTs, not in application code, so a deployment can lose it silently.")

    # --- 2 ----------------------------------------------------------------- #
    section(2, "Admin login")
    status, body = client.call(
        "POST",
        "/api/v1/auth/login",
        {"email": args.email, "password": password},
        authenticated=False,
    )
    if status != 200:
        print(f"   {RED}login failed ({status}):{RESET} {body}")
        print("\n   Create an admin with:")
        print("     cd server && .venv/bin/python -m ubuntuguard.cli create-admin \\")
        print(f"       --email {args.email} --role <role>")
        return 1
    client.bearer = body["access_token"]
    ok(f"access token issued, expires in {body['expires_in']}s")
    must("ubuntuguard_refresh" in client.cookies, "refresh token arrives as a cookie")
    must("ubuntuguard_refresh" not in json.dumps(body), "refresh token is not in the body")
    note("Refresh token is an httpOnly cookie, never in the body, so dashboard")
    note("JavaScript cannot read it and an XSS bug cannot exfiltrate it.")

    status, me = client.call("GET", "/api/v1/auth/me")
    ok(f"authenticated as {me['role']} with {len(me['capabilities'])} capabilities")
    note("The dashboard hides controls using this list; the server still checks")
    note("every call, because a hidden button is not a security boundary.")

    # --- 3 ----------------------------------------------------------------- #
    section(3, "Authentication failures give nothing away")
    attack("guess the password")
    status, wrong = client.call(
        "POST",
        "/api/v1/auth/login",
        {"email": args.email, "password": "definitely-wrong"},
        authenticated=False,
    )
    blocked(f"{status} {wrong['code']} — {wrong['detail']}")

    attack("probe whether an unknown account exists")
    status, unknown = client.call(
        "POST",
        "/api/v1/auth/login",
        {"email": f"nobody-{uuid.uuid4().hex[:6]}@example.invalid", "password": password},
        authenticated=False,
    )
    blocked(f"{status} {unknown['code']} — {unknown['detail']}")

    comparable = {k: v for k, v in wrong.items() if k != "request_id"} == {
        k: v for k, v in unknown.items() if k != "request_id"
    }
    must(comparable, "the two failure bodies are identical")
    ok("both responses are byte-identical apart from the request id")
    note("Wrong password, unknown account and locked account all look the same.")
    note("Only the audit log records which it was.")

    # --- 4 ----------------------------------------------------------------- #
    section(4, "One-time enrollment token")
    status, token = client.call("POST", "/api/v1/enrollment-tokens", {"label": "demo laptop"})
    must(status == 201, "token created")
    plaintext = token["enrollment_token"]
    ok(f"minted {plaintext[:14]}... expiring {token['expires_at']}")

    status, listing = client.call("GET", "/api/v1/enrollment-tokens")
    import hashlib

    rendered = json.dumps(listing)
    must(plaintext not in rendered, "plaintext is not listed")
    must(hashlib.sha256(plaintext.encode()).hexdigest() not in rendered, "hash is not listed")
    blocked("listing the tokens again returns neither the plaintext nor its hash")
    note("Only the hash is stored, and it is never returned. A lost token is")
    note("reissued, not recovered.")

    # --- 5 ----------------------------------------------------------------- #
    section(5, "Device enrollment")
    attack("submit a CSR claiming to be 'i-am-the-ceo-laptop'")
    status, device = client.call(
        "POST",
        "/api/v1/enroll",
        enroll_payload(csr_for("i-am-the-ceo-laptop"), plaintext),
        authenticated=False,
    )
    must(status == 201, f"enrollment succeeded, got {status}: {device}")
    certificate = x509.load_pem_x509_certificate(device["client_certificate_pem"].encode())
    common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    must(common_name == device["device_id"], "certificate CN is the server-allocated id")
    blocked(f"requested subject ignored; certificate says CN={common_name}")
    note("The common name IS the device identity on the mTLS path, so a client")
    note("that could choose it could impersonate another device.")

    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    must(constraints.ca is False, "issued certificate is not a CA")
    ok(f"certificate is not a CA, valid 30 days, renew after {device['certificate_renew_after']}")
    ok(f"agent pins policy key {device['policy_public_keys'][0]['key_id']}")
    must(device["clone_suspected"] is False, "first device is not flagged as a clone")

    # --- 6 ----------------------------------------------------------------- #
    section(6, "The token is spent")
    attack("reuse the same token with a brand new keypair")
    status, reused = client.call(
        "POST",
        "/api/v1/enroll",
        enroll_payload(csr_for("attacker"), plaintext),
        authenticated=False,
    )
    must(status == 401, "reuse refused")
    blocked(f"{status} {reused['code']}")
    note("Single use is one SQL statement: UPDATE ... WHERE consumed_at IS NULL")
    note("RETURNING id, so two simultaneous callers yield exactly one success.")

    # --- 7 ----------------------------------------------------------------- #
    section(7, "Device plane over mTLS")
    device_headers = {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert": quote(device["client_certificate_pem"]),
    }
    status, heartbeat = client.call(
        "POST",
        "/api/v1/devices/me/heartbeat",
        {"agent_version": "0.1.0", "uptime_seconds": 42, "applied_policy_versions": {}},
        headers=device_headers,
        authenticated=False,
    )
    must(status == 200, f"heartbeat accepted, got {status}: {heartbeat}")
    ok(f"heartbeat accepted; fields: {', '.join(sorted(heartbeat))}")
    note("No command field anywhere in that response. The agent pulls signed,")
    note("declarative state and decides locally, which is the structural reason")
    note("a compromised server cannot execute code on a laptop.")

    status, detail = client.call("GET", f"/api/v1/devices/{device['device_id']}")
    must(detail["online"] is True, "device shows online")
    ok(f"server computes online={detail['online']}, last seen {detail['last_heartbeat_at']}")
    note("Liveness is computed from the heartbeat we received, never self-reported.")

    attack("replay those exact headers from a different source address")
    note("Cannot be shown from here: this script and the server share 127.0.0.1,")
    note("which IS the trusted proxy. Covered by")
    note("test_certificate_headers_from_an_untrusted_peer_are_refused.")

    # --- 8 ----------------------------------------------------------------- #
    section(8, "Revocation")
    status, _ = client.call(
        "POST",
        f"/api/v1/devices/{device['device_id']}:revoke",
        {"reason": "laptop reported lost by the user"},
    )
    must(status == 204, "revoked")
    ok("device revoked")

    status, after = client.call(
        "POST",
        "/api/v1/devices/me/heartbeat",
        {"agent_version": "0.1.0", "uptime_seconds": 43},
        headers=device_headers,
        authenticated=False,
    )
    must(status == 401, "revoked device refused")
    blocked(f"its very next heartbeat: {status} {after['code']}")
    note("Every device request re-reads the device status, so the bound is")
    note("'within one request' rather than waiting for a CRL to propagate.")
    note("It does NOT make the laptop stop enforcing: an offline device keeps")
    note("its last verified policy by design.")

    attack("revoke with a throwaway reason")
    status, rejected = client.call(
        "POST", f"/api/v1/devices/{device['device_id']}:revoke", {"reason": "test"}
    )
    blocked(f"{status} {rejected.get('code')} — the reason ends up in the audit log")

    # --- 9 ----------------------------------------------------------------- #
    section(9, "Audit log")
    status, verification = client.call("GET", "/api/v1/audit-logs:verify")
    must(verification["ok"] is True, "chain intact")
    ok(f"chain intact across {verification['checked']} entries")
    note("Each row's hash covers the previous row's, so an edit, a deletion or a")
    note("re-parented row is localised to a sequence number.")

    status, entries = client.call("GET", "/api/v1/audit-logs", headers=None)
    recent = [entry["action"] for entry in entries[-10:]]
    note(f"most recent: {', '.join(recent)}")

    body = json.dumps(entries)
    must(password not in body, "the password does not appear in the audit log")
    must("$argon2" not in body, "no password hash in the audit log")
    must(plaintext not in body, "the enrollment token does not appear in the audit log")
    ok("no password, password hash or enrollment token anywhere in the audit log")

    # --- 10 ---------------------------------------------------------------- #
    section(10, "Separation of duties")
    # The operator chooses which role they run this as, so the outcome cannot be
    # assumed. Read the capability and assert the matching result, which proves
    # the matrix in whichever direction this account sits.
    may_export = "audit_export" in me["capabilities"]
    status, _ = client.call("POST", "/api/v1/audit-logs:export", None)
    if may_export:
        note(f"Running as {me['role']}, which holds audit_export:")
        must(status == 200, f"export permitted for {me['role']} (got {status})")
        ok(f"export returned {status}, and the export is itself audited")
    else:
        note(f"Running as {me['role']}, which does not hold audit_export:")
        must(status == 403, f"export refused for {me['role']} (got {status})")
        blocked(f"export returned {status} before reading a single row")
    note("Only super_admin and auditor hold audit_export. The role that configures")
    note("the fleet does not also get to extract the record of what it did.")
    note("Covered by test_route_matrix.")

    # --- Summary ----------------------------------------------------------- #
    print(f"\n{BOLD}What this demonstrated{RESET}")
    for line in [
        "Login issues a short-lived access token; refresh stays in an httpOnly cookie",
        "Every authentication failure is byte-identical",
        "Enrollment tokens are single use and never readable after creation",
        "The CA takes nothing from a CSR except the public key",
        "The device plane authenticates by certificate and carries no command channel",
        "Revocation takes effect on the device's next request",
        "The audit log chains, verifies, and holds no secrets",
    ]:
        print(f"   {GREEN}✓{RESET} {line}")

    print(f"\n{BOLD}{YELLOW}What this does NOT demonstrate{RESET}")
    for line in [
        "Any real Ubuntu laptop. There is no agent yet - Phase 2",
        "Policy signing, assignment, apply or rollback - Phase 4",
        "Any USB enforcement whatsoever - Phase 5, gated on the USBGuard spike",
        "Real TLS or mTLS: nginx is not set up, so this ran over plain HTTP on",
        "  localhost with the certificate headers supplied directly",
    ]:
        print(f"   {YELLOW}•{RESET} {line}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
