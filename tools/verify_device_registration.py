#!/usr/bin/env python3
"""End-to-end check of device registration and the enrollment claim.

Proves the one property the feature rests on: registering a laptop and then
enrolling it produces ONE device row, not two. Run against a live server.

    ./tools/verify_device_registration.py --base-url http://127.0.0.1:8010 \
        --email <admin-email> --password '...'
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import quote

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "server" / "src"))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"

failures = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global failures
    if condition:
        print(f"  {GREEN}PASS{RESET} {label}")
    else:
        failures += 1
        print(f"  {RED}FAIL{RESET} {label}" + (f" — {detail}" if detail else ""))


class Api:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")
        self.token: str | None = None

    def call(
        self, method: str, path: str, body: object = None, headers: dict[str, str] | None = None
    ) -> tuple[int, object]:
        head = {"Content-Type": "application/json"}
        if self.token:
            head["Authorization"] = f"Bearer {self.token}"
        head.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310
            self.base + path, data=data, headers=head, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:  # noqa: S310
                raw = response.read().decode()
                return response.status, (json.loads(raw) if raw.startswith(("{", "[")) else raw)
        except urllib.error.HTTPError as error:
            raw = error.read().decode()
            try:
                return error.code, json.loads(raw)
            except json.JSONDecodeError:
                return error.code, raw
        except urllib.error.URLError as error:
            sys.exit(f"{RED}cannot reach {self.base}: {error.reason}{RESET}")


def make_csr() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, "agent")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8010")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", default="anything")
    args = parser.parse_args()

    api = Api(args.base_url)
    status, body = api.call(
        "POST", "/api/v1/auth/login", {"email": args.email, "password": args.password}
    )
    if status != 200:
        sys.exit(f"{RED}login failed ({status}): {body}{RESET}")
    api.token = body["access_token"]  # type: ignore[index]

    print(f"\n{BOLD}1. Baseline{RESET}")
    _, before = api.call("GET", "/api/v1/devices:counts")
    print(f"{DIM}  {before}{RESET}")

    print(f"\n{BOLD}2. Register a device (no agent involved){RESET}")
    # Built from the domain of the account running this script, lowercased,
    # with a random local part so repeated runs do not collide. Email-shaped
    # because the server validates the field, but not an address anybody owns.
    _, _, operator_domain = args.email.strip().lower().partition("@")
    assignee_email = f"assignee-{uuid.uuid4().hex[:8]}@{operator_domain}"
    status, registered = api.call(
        "POST",
        "/api/v1/devices",
        {
            "display_name": "Ethan's laptop",
            "platform": "linux",
            "manufacturer": "Lenovo",
            "model": "ThinkPad T14 Gen 4",
            "assigned_to_name": "Ethan Carter",
            # Derived from the operator's own address rather than written here.
            # `assigned_to_email` goes through `normalise_email`, so it has to
            # be email-shaped for the check below to mean anything - but the
            # domain comes from whoever is running the script, so no address is
            # baked into this file.
            "assigned_to_email": assignee_email,
            "asset_tag": "IT-004912",
            "issue_enrollment_token": True,
            "token_ttl_seconds": 3600,
        },
    )
    check("POST /devices returns 201", status == 201, str(registered))
    if status != 201:
        return 1
    device = registered["device"]  # type: ignore[index]
    device_id = device["id"]
    token = registered["enrollment_token"]  # type: ignore[index]

    check("status is 'pending'", device["status"] == "pending", device["status"])
    check("enrolled is false", device["enrolled"] is False)
    check("enrolled_at is null", device["enrolled_at"] is None)
    check("hostname is null before enrollment", device["hostname"] is None)
    check("admin fields are stored", device["display_name"] == "Ethan's laptop")
    check("manufacturer is stored", device["manufacturer"] == "Lenovo")
    check("assignee is stored", device["assigned_to_name"] == "Ethan Carter")
    check("employee email lowercased", device["assigned_to_email"] == assignee_email)
    check("an enrollment token was returned once", isinstance(token, str) and len(token) > 20)

    print(f"\n{BOLD}3. It shows as awaiting enrollment{RESET}")
    _, unenrolled = api.call("GET", "/api/v1/devices", None)
    _, pending_only = api.call("GET", "/api/v1/devices?enrolled=false")
    ids_pending = {row["id"] for row in pending_only}  # type: ignore[union-attr]
    check("appears in ?enrolled=false", device_id in ids_pending)
    _, enrolled_only = api.call("GET", "/api/v1/devices?enrolled=true")
    check(
        "absent from ?enrolled=true",
        device_id not in {row["id"] for row in enrolled_only},  # type: ignore[union-attr]
    )
    _, mid = api.call("GET", "/api/v1/devices:counts")
    check(
        "unenrolled count went up by one",
        mid["unenrolled"] == before["unenrolled"] + 1,  # type: ignore[index]
        f"{before} -> {mid}",
    )
    check("searchable by employee name", any(
        row["id"] == device_id
        for row in api.call("GET", "/api/v1/devices?q=" + quote("Ethan"))[1]  # type: ignore[union-attr]
    ))
    check("searchable by asset tag", any(
        row["id"] == device_id
        for row in api.call("GET", "/api/v1/devices?q=IT-004912")[1]  # type: ignore[union-attr]
    ))

    print(f"\n{BOLD}4. The agent enrolls with that token{RESET}")
    status, enrolled_body = api.call(
        "POST",
        "/api/v1/enroll",
        {
            "enrollment_token": token,
            "csr_pem": make_csr(),
            "hostname": "eng-laptop-ethan",
            "agent_version": "0.1.0",
            "arch": "x86_64",
            "os": {
                "id": "ubuntu",
                "version_id": "24.04",
                "kernel": "6.8.0-45-generic",
                "pretty_name": "Ubuntu 24.04 LTS",
            },
            "primary_adapter_ip": "192.168.1.91",
        },
    )
    check("POST /enroll returns 201", status == 201, str(enrolled_body))
    if status != 201:
        return 1

    check(
        "THE CLAIM: enrollment reused the registered row, no duplicate",
        enrolled_body["device_id"] == device_id,  # type: ignore[index]
        f"registered {device_id}, enrolled {enrolled_body['device_id']}",  # type: ignore[index]
    )

    print(f"\n{BOLD}5. The record is now complete{RESET}")
    _, after_device = api.call("GET", f"/api/v1/devices/{device_id}")
    check("status is 'active'", after_device["status"] == "active", after_device["status"])  # type: ignore[index]
    check("enrolled is true", after_device["enrolled"] is True)  # type: ignore[index]
    check("enrolled_at is set", after_device["enrolled_at"] is not None)  # type: ignore[index]
    check("hostname came from the device", after_device["hostname"] == "eng-laptop-ethan")  # type: ignore[index]
    check("OS came from the device", after_device["os_version_id"] == "24.04")  # type: ignore[index]
    check("adapter IP recorded", after_device["primary_adapter_ip"] == "192.168.1.91")  # type: ignore[index]
    check("certificate issued", after_device["cert_fingerprint"] is not None)  # type: ignore[index]
    check(
        "ADMIN FIELDS SURVIVED: the device cannot rename itself",
        after_device["display_name"] == "Ethan's laptop"  # type: ignore[index]
        and after_device["assigned_to_name"] == "Ethan Carter",  # type: ignore[index]
    )

    _, after = api.call("GET", "/api/v1/devices:counts")
    check(
        "total did NOT grow (one laptop, one row)",
        after["total"] == mid["total"],  # type: ignore[index]
        f"{mid} -> {after}",
    )
    check("enrolled count went up by one", after["enrolled"] == mid["enrolled"] + 1)  # type: ignore[index]
    check("unenrolled count went back down", after["unenrolled"] == before["unenrolled"])  # type: ignore[index]

    print(f"\n{BOLD}6. A bare token still works (backward compatible){RESET}")
    _, bare = api.call("POST", "/api/v1/enrollment-tokens", {"label": "no pre-reg", "ttl_seconds": 3600})
    status, bare_enrolled = api.call(
        "POST",
        "/api/v1/enroll",
        {
            "enrollment_token": bare["enrollment_token"],  # type: ignore[index]
            "csr_pem": make_csr(),
            "hostname": "unregistered-laptop",
            "agent_version": "0.1.0",
            "arch": "x86_64",
            "os": {"id": "ubuntu", "version_id": "22.04", "kernel": "5.15.0-119-generic"},
        },
    )
    check("a token with no pre-registration still enrolls", status == 201, str(bare_enrolled))
    check(
        "and creates its own new row",
        status == 201 and bare_enrolled["device_id"] != device_id,  # type: ignore[index]
    )

    print(f"\n{BOLD}7. Refusals{RESET}")
    status, _ = api.call("POST", "/api/v1/devices", {"display_name": ""})
    check("empty device name refused", status == 422, str(status))
    status, _ = api.call(
        "POST", "/api/v1/devices", {"display_name": "x", "assigned_to_email": "not-an-email"}
    )
    check("malformed employee email refused", status == 422, str(status))
    status, _ = api.call(
        "POST", "/api/v1/devices", {"display_name": "x", "platform": "freebsd"}
    )
    check("unknown platform refused", status == 422, str(status))
    status, _ = api.call(
        "POST", "/api/v1/devices", {"display_name": "x", "unexpected_field": 1}
    )
    check("unknown field refused (extra=forbid)", status == 422, str(status))
    status, reused = api.call(
        "POST",
        "/api/v1/enroll",
        {
            "enrollment_token": token,
            "csr_pem": make_csr(),
            "hostname": "thief",
            "agent_version": "0.1.0",
            "arch": "x86_64",
            "os": {"id": "ubuntu", "version_id": "24.04", "kernel": "6.8.0-45-generic"},
        },
    )
    check("spent token with a NEW keypair is refused", status == 401, str(status))

    print(f"\n{BOLD}8. Audit chain{RESET}")
    _, verification = api.call("GET", "/api/v1/audit-logs:verify")
    check("chain still verifies", verification["ok"] is True, str(verification))  # type: ignore[index]

    # The log pages ASCENDING from seq 1, because a page has to be in write
    # order to stay independently verifiable. So read from near the head rather
    # than from the start, or on a busy log the newest entries fall outside the
    # first page and look absent when they are merely later.
    head = int(verification["checked"])  # type: ignore[index]
    _, entries = api.call("GET", f"/api/v1/audit-logs?after_seq={max(0, head - 60)}&limit=200")
    actions = [row["action"] for row in entries]  # type: ignore[union-attr]
    check("'device_registered' was recorded", "device_registered" in actions)
    claimed = [
        row
        for row in entries  # type: ignore[union-attr]
        if row["action"] == "device_enrolled" and row["target_id"] == device_id
    ]
    check(
        "enrollment recorded that it claimed a pre-registration",
        bool(claimed) and claimed[-1]["detail"].get("claimed_pre_registration") is True,
        str(claimed[-1]["detail"]) if claimed else "no entry",
    )

    print()
    if failures:
        print(f"{RED}{BOLD}{failures} check(s) failed{RESET}\n")
        return 1
    print(f"{GREEN}{BOLD}all checks passed{RESET}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
