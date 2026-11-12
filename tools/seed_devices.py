#!/usr/bin/env python3
"""Seed simulated devices so the dashboard has realistic data.

The brief asks the dashboard to stay responsive with 50 simulated devices, and
there is no agent yet, so this stands in for one.

It enrolls through the REAL API: a token is minted, a keypair and CSR are
generated locally per device, and the server issues a genuine certificate. No
rows are inserted behind the API's back, so what the dashboard shows is what a
real fleet would produce - including the audit entries for every enrollment.

The one exception is backdating heartbeats, which is done with SQL because no
API lets a client claim it checked in two hours ago, and nor should one. It is
clearly marked, and nothing in production takes that path.

Usage:
    cd server && .venv/bin/python -m uvicorn ubuntuguard.main:create_app --factory &
    ./tools/seed_devices.py --password '<admin password>'
    ./tools/seed_devices.py --password '...' --count 200     # check it stays responsive
"""

# ruff: noqa: E402, I001, S311
# E402/I001: imports sit under _ensure_dependencies() on purpose - the re-exec
# must happen before cryptography is imported, so they cannot move to the top.
#
# S311: `random` is used only to vary hostnames, kernels, uptimes and which
# devices get backdated, and it is seeded so a fleet is reproducible. Nothing
# security-relevant comes from it: device keypairs come from
# ec.generate_private_key, hardware fingerprints from uuid4, and enrollment
# tokens from the server's own CSPRNG. Suppressed at file level with that said
# out loud, because "we used random for a security value" is the exact mistake
# worth not hiding behind a bare noqa.

from __future__ import annotations

import argparse
import getpass
import json
import os
import random
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
VENV_PYTHON = REPO / "server" / ".venv" / "bin" / "python"
sys.path.insert(0, str(REPO / "server" / "src"))


def _ensure_dependencies() -> None:
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
            sys.exit("The server virtualenv is missing. See README.md.")
        # No shell by design; argv is fixed and fully controlled here.
        os.execv(  # noqa: S606
            str(VENV_PYTHON),
            [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]],
        )


_ensure_dependencies()

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

GREEN, DIM, RED, BOLD, RESET = "\033[32m", "\033[2m", "\033[31m", "\033[1m", "\033[0m"

#: A realistic spread. Both LTS releases the prototype targets, with kernels
#: that actually shipped on them.
FLEET = [
    ("24.04", "6.8.0-45-generic"),
    ("24.04", "6.8.0-51-generic"),
    ("24.04", "6.11.0-9-generic"),
    ("22.04", "5.15.0-119-generic"),
    ("22.04", "5.15.0-125-generic"),
    ("22.04", "6.5.0-45-generic"),
]
AGENT_VERSIONS = ["0.1.0", "0.1.0", "0.1.0", "0.1.1", "0.2.0-dev"]
TEAMS = ["fin", "eng", "sales", "ops", "legal", "hr", "support", "exec"]
HARDWARE = [
    ("LENOVO", "ThinkPad T14 Gen 4"),
    ("LENOVO", "ThinkPad X1 Carbon Gen 11"),
    ("Dell Inc.", "Latitude 7440"),
    ("Dell Inc.", "XPS 13 9340"),
    ("HP", "EliteBook 840 G10"),
    ("Framework", "Laptop 13"),
]


class Api:
    ALLOWED_SCHEMES = ("http://", "https://")

    def __init__(self, base_url: str) -> None:
        if not base_url.startswith(self.ALLOWED_SCHEMES):
            sys.exit(f"--base-url must start with one of {self.ALLOWED_SCHEMES}")
        self.base_url = base_url.rstrip("/")
        self.token: str | None = None

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = json.dumps(body).encode() if body is not None else None
        # Scheme validated in __init__, so file:/ftp: cannot reach here.
        request = urllib.request.Request(  # noqa: S310
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:  # noqa: S310
                payload = response.read().decode()
                parsed = json.loads(payload) if payload.startswith(("{", "[")) else payload
                return response.status, parsed
        except urllib.error.HTTPError as error:
            payload = error.read().decode()
            try:
                return error.code, json.loads(payload)
            except json.JSONDecodeError:
                return error.code, payload
        except urllib.error.URLError as error:
            sys.exit(
                f"{RED}Cannot reach {self.base_url}: {error.reason}{RESET}\n"
                "Start the server: cd server && .venv/bin/python -m uvicorn "
                "ubuntuguard.main:create_app --factory --host 127.0.0.1 --port 8000"
            )

    def login(self, email: str, password: str) -> None:
        status, body = self.call(
            "POST", "/api/v1/auth/login", {"email": email, "password": password}
        )
        if status != 200:
            sys.exit(
                f"{RED}login failed ({status}): {body}{RESET}\n"
                "Create an admin: cd server && .venv/bin/python -m ubuntuguard.cli "
                f"create-admin --email {email} --role <role>"
            )
        self.token = body["access_token"]


def make_csr() -> str:
    """Generate a keypair and CSR the way an agent would: locally."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def sha256_hex() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex


def backdate_heartbeats(rows: list[tuple[str, int]]) -> int:
    """Set last_heartbeat_at into the past so the UI shows a realistic spread.

    SQL on purpose: no API lets a client claim it checked in two hours ago, and
    adding one would be a way to fake liveness. This is a seeding shortcut and
    the only thing in the project that writes device state outside the API.
    """
    if not rows:
        return 0
    from sqlalchemy import text

    from ubuntuguard.config import Settings
    from ubuntuguard.db import create_db_engine, create_session_factory, session_scope

    settings = Settings()
    if settings.database_url is None:
        print(f"{DIM}  no database URL; skipping heartbeat backdating{RESET}")
        return 0

    factory = create_session_factory(create_db_engine(settings))
    with session_scope(factory) as session:
        for device_id, minutes_ago in rows:
            session.execute(
                text(
                    "UPDATE devices SET last_heartbeat_at = now() - (:m || ' minutes')::interval "
                    "WHERE id = :id"
                ),
                {"m": minutes_ago, "id": device_id},
            )
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    # No default. A baked-in address is wrong the moment the operator creates an
    # account under their own name, and it fails as an opaque 401 rather than as
    # "you did not say who you are".
    parser.add_argument("--email", required=True, help="the admin account to authenticate as")
    parser.add_argument("--password", default=None)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--seed", type=int, default=20261029, help="for reproducible fleets")
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.email}: ")
    random.seed(args.seed)
    socket.setdefaulttimeout(30)

    api = Api(args.base_url)
    print(f"{BOLD}Seeding {args.count} simulated devices{RESET}")
    print(f"{DIM}  via the real enrollment API: token, CSR, certificate, audit entry{RESET}")
    api.login(args.email, password)

    started = time.perf_counter()
    enrolled: list[dict[str, Any]] = []
    clone_fingerprint: str | None = None
    failures = 0

    for index in range(args.count):
        os_version, kernel = random.choice(FLEET)
        vendor, product = random.choice(HARDWARE)
        agent_version = random.choice(AGENT_VERSIONS)
        hostname = f"{random.choice(TEAMS)}-laptop-{index + 1:03d}"

        status, token = api.call(
            "POST", "/api/v1/enrollment-tokens", {"label": hostname, "ttl_seconds": 3600}
        )
        if status != 201:
            print(f"{RED}  token failed for {hostname}: {status} {token}{RESET}")
            failures += 1
            continue

        # Every twentieth device reuses a fingerprint, so the clone-detection
        # path and its incident are visible in the UI.
        if index % 20 == 7:
            if clone_fingerprint is None:
                clone_fingerprint = sha256_hex()
            machine_id_hash = clone_fingerprint
        else:
            machine_id_hash = sha256_hex()

        status, device = api.call(
            "POST",
            "/api/v1/enroll",
            {
                "enrollment_token": token["enrollment_token"],
                "csr_pem": make_csr(),
                "hostname": hostname,
                "agent_version": agent_version,
                "arch": "x86_64",
                "os": {
                    "id": "ubuntu",
                    "version_id": os_version,
                    "kernel": kernel,
                    "pretty_name": f"Ubuntu {os_version} LTS",
                },
                "hardware_fingerprint": {
                    "machine_id_hash": machine_id_hash,
                    "dmi_product_uuid_hash": sha256_hex(),
                    "virtualization": "none" if index % 11 else "kvm",
                },
                # A couple of dev builds, so the dashboard's warning badge shows.
                "release_build": agent_version != "0.2.0-dev",
            },
        )
        if status != 201:
            print(f"{RED}  enroll failed for {hostname}: {status} {device}{RESET}")
            failures += 1
            continue

        enrolled.append({**device, "hostname": hostname, "agent_version": agent_version})
        if (index + 1) % 10 == 0:
            print(f"{DIM}  {index + 1}/{args.count}…{RESET}")

    elapsed = time.perf_counter() - started
    print(f"{GREEN}  enrolled {len(enrolled)} devices in {elapsed:.1f}s{RESET}")
    if failures:
        print(f"{RED}  {failures} failed{RESET}")

    # --- Heartbeats, so the fleet is not uniformly "never seen" -------------- #
    from urllib.parse import quote

    online = 0
    backdate: list[tuple[str, int]] = []
    for index, device in enumerate(enrolled):
        bucket = index % 10
        if bucket == 9:
            continue  # never checked in: a freshly imaged laptop

        # Sent directly rather than through `api.call`: the device plane needs
        # the X-Client-* certificate headers and carries no bearer token.
        request = urllib.request.Request(  # noqa: S310
            f"{api.base_url}/api/v1/devices/me/heartbeat",
            data=json.dumps(
                {
                    "agent_version": device["agent_version"],
                    "uptime_seconds": random.randint(60, 900_000),
                }
            ).encode(),
            headers={
                "Content-Type": "application/json",
                "X-Client-Verify": "SUCCESS",
                "X-Client-Cert": quote(device["client_certificate_pem"]),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request) as response:  # noqa: S310
                response.read()
                online += 1
        except urllib.error.HTTPError as error:
            print(f"{RED}  heartbeat failed for {device['hostname']}: {error.code}{RESET}")
            continue

        # Spread the last-seen times: most recent, some stale, a few long gone.
        if bucket in (6, 7):
            backdate.append((device["device_id"], random.randint(8, 240)))
        elif bucket == 8:
            backdate.append((device["device_id"], random.randint(1500, 20000)))

    print(f"{GREEN}  {online} devices sent a heartbeat{RESET}")
    moved = backdate_heartbeats(backdate)
    if moved:
        print(f"{DIM}  backdated {moved} heartbeats so last-seen times vary{RESET}")

    # --- A few revocations, so that state is represented too ---------------- #
    revoked = 0
    for device in enrolled[::17]:
        status, _ = api.call(
            "POST",
            f"/api/v1/devices/{device['device_id']}:revoke",
            {"reason": "seeded example: laptop returned at end of contract"},
        )
        if status == 204:
            revoked += 1
    print(f"{GREEN}  revoked {revoked} devices{RESET}")

    status, verification = api.call("GET", "/api/v1/audit-logs:verify")
    print(f"\n{BOLD}Audit chain:{RESET} {verification}")
    print(f"\nOpen the dashboard: {DIM}http://127.0.0.1:5173{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
