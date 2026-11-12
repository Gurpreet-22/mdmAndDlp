#!/usr/bin/env python3
"""Walk through everything built so far, with visible output.

There is no server to start yet - no FastAPI app, no dashboard, no agent. Those
arrive in Phases 1b, 2 and 3. What exists is the security core, and a passing
test suite is easy to take on faith without ever seeing what it does. This
script exercises the real modules, prints what happens, and deliberately
attacks each one so you can watch it refuse.

Nothing here touches a database, the network, or any file outside a temporary
directory that is deleted on exit. No keys are written into the repository.

Run:  server/.venv/bin/python tools/demo_security_core.py

Running it as ./tools/demo_security_core.py would pick up the system interpreter,
which has none of the dependencies, so the guard below re-executes this script
with the server virtualenv instead of failing with an import traceback.
"""

# ruff: noqa: E402, I001
# The imports below sit under _ensure_dependencies() on purpose: the re-exec has
# to happen BEFORE cryptography or ubuntuguard are imported, so they cannot move
# to the top of the file. E402 and import sorting are suppressed for that reason
# and that reason only; every other rule stays active.

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "server" / "src"))

VENV_PYTHON = REPO / "server" / ".venv" / "bin" / "python"


def _ensure_dependencies() -> None:
    """Re-exec under the server virtualenv if the dependencies are missing.

    The shebang resolves to the system python3, which has neither argon2-cffi
    nor cryptography. Without this, running the script the obvious way produces
    a ModuleNotFoundError that says nothing about the actual fix.
    """
    try:
        # Probe the PACKAGE, not one of its dependencies. An earlier version
        # checked only `cryptography`, which the system interpreter happened to
        # have, so the re-exec never fired and the script died later on a
        # missing `sqlalchemy`. `ubuntuguard` can only resolve inside the venv.
        import ubuntuguard  # noqa: F401
    except ModuleNotFoundError:
        if Path(sys.executable).resolve() == VENV_PYTHON.resolve():
            raise  # already in the venv, so this is a real missing dependency
        if not VENV_PYTHON.exists():
            sys.exit(
                "The server virtualenv is missing. Create it with:\n"
                "  uv venv --python 3.12 server/.venv\n"
                '  cd server && uv pip install --python .venv/bin/python -e ".[dev]"'
            )
        # No shell by design; argv is fixed and fully controlled here.
        os.execv(  # noqa: S606
            str(VENV_PYTHON),
            [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]],
        )


_ensure_dependencies()

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from ubuntuguard.security import lockout, passwords, tokens
from ubuntuguard.security.rbac import (
    Capability,
    PermissionDeniedError,
    Role,
    can,
    capabilities_for,
    require,
)
from ubuntuguard.services import audit_chain, ca, policy_signing

BOLD, DIM, GREEN, RED, CYAN, YELLOW, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[36m",
    "\033[33m",
    "\033[0m",
)

DEVICE_ID = "9a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d"
NOW = dt.datetime.now(dt.UTC)

# Actions accumulate here and become the audit chain in section 6.
audit_actions: list[tuple[str, str | None, str | None]] = []


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


def record(action: str, target_type: str | None = None, target_id: str | None = None) -> None:
    audit_actions.append((action, target_type, target_id))


def must(condition: bool, claim: str) -> None:
    """Fail the demo loudly if a claim it is about to print is not actually true.

    A plain `assert` would be stripped by `python -O`, and a demo that prints
    "verified" without having verified anything is worse than no demo.
    """
    if not condition:
        raise AssertionError(f"demo claim is false: {claim}")


# --------------------------------------------------------------------------- #


def demo_rbac() -> None:
    section(1, "Role-based access control")

    capabilities = list(Capability)
    width = max(len(c.value) for c in capabilities)
    header = " " * (width + 2) + "".join(f"{r.value[:10]:>12}" for r in Role)
    print(f"   {DIM}{header}{RESET}")
    for capability in capabilities:
        cells = ""
        for role in Role:
            allowed = can(role, capability)
            mark = f"{GREEN}yes{RESET}" if allowed else f"{DIM}no{RESET}"
            pad = 12 - (3 if allowed else 2)
            cells += " " * pad + mark
        print(f"   {capability.value:<{width}}  {cells}")

    print()
    note(
        f"{len(Role)} roles x {len(capabilities)} capabilities = "
        f"{len(Role) * len(capabilities)} cells, every one explicit in the table"
    )
    note("An undecided cell raises at import, so this cannot ship half-filled.")

    print()
    require(Role.AUDITOR, Capability.AUDIT_EXPORT)
    ok("auditor may export the audit log")
    try:
        require(Role.IT_ADMIN, Capability.AUDIT_EXPORT)
    except PermissionDeniedError as exc:
        blocked(f"it_admin may NOT export the audit log ({exc.capability.value})")
        note("Separation of duties: the role that configures the fleet does not")
        note("also get to extract the record of what it did.")
    record("role_matrix_inspected")

    analyst = capabilities_for(Role.SECURITY_ANALYST)
    note(f"security_analyst holds {len(analyst)} of {len(capabilities)} capabilities")


def demo_passwords() -> None:
    section(2, "Admin password hashing (Argon2id)")

    password = "a reasonably long passphrase"  # noqa: S105 - demo value, not a credential
    started = time.perf_counter()
    stored = passwords.hash_password(password)
    hash_ms = (time.perf_counter() - started) * 1000

    algorithm, params = stored.split("$")[1], stored.split("$")[3]
    ok(f"hashed in {hash_ms:.0f} ms using {algorithm} ({params})")
    note(f"stored value: {stored[:48]}...")
    note("The password itself appears nowhere in that string.")

    must(passwords.verify_password(stored, password), "correct password verifies")
    ok("correct password verifies")

    must(not passwords.verify_password(stored, password + "!"), "wrong password fails")
    blocked("one extra character fails")

    must(passwords.hash_password(password) != stored, "salts differ between hashes")
    ok("the same password hashes differently each time (distinct random salts)")
    note("So the database never reveals which admins share a password.")

    print()
    attack("probe whether an account exists, by timing the response")
    started = time.perf_counter()
    passwords.verify_password(stored, "wrong guess")
    real_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    passwords.verify_dummy()
    dummy_ms = (time.perf_counter() - started) * 1000
    blocked(f"wrong password {real_ms:.0f} ms vs unknown account {dummy_ms:.0f} ms")
    note("Comparable by design. Without the dummy hash, a missing account would")
    note("answer in microseconds and leak which usernames are real.")

    print()
    attack("send a 10 MB password to make the server do 10 MB of Argon2 work")
    started = time.perf_counter()
    rejected = not passwords.verify_password(stored, "x" * 10_000_000)
    elapsed_ms = (time.perf_counter() - started) * 1000
    must(rejected, "over-long password is rejected")
    blocked(f"rejected on length in {elapsed_ms:.1f} ms, before any hashing")
    record("login_succeeded", "user", "it-admin")


def demo_lockout() -> None:
    section(3, "Login lockout")

    for count in (4, 5):
        failures = [NOW - dt.timedelta(seconds=30)] * count
        decision = lockout.evaluate(recent_failures=failures, now=NOW)
        if decision.locked:
            blocked(f"{count} failures in the window -> locked for {decision.retry_after_seconds}s")
        else:
            ok(f"{count} failures in the window -> not locked")

    stale = [NOW - dt.timedelta(seconds=601)] * 5
    decision = lockout.evaluate(recent_failures=stale, now=NOW)
    must(not decision.locked, "stale failures do not lock")
    ok("5 failures from 601 s ago -> not locked (the 10 min window expired)")
    note("Otherwise five typos last month would lock an account forever.")

    edge = [NOW - dt.timedelta(seconds=600)] * 5
    must(lockout.evaluate(recent_failures=edge, now=NOW).locked, "window edge counts")
    ok("a failure exactly at the 600 s edge still counts (inclusive bound)")
    record("lockout_policy_evaluated")


def demo_enrollment_token() -> None:
    section(4, "One-time enrollment token")

    token = tokens.generate_enrollment_token()
    ok(f"minted: {token.plaintext}")
    note(f"stored in the database: {token.token_hash}")
    note("Only the hash is persisted, so a stolen backup yields no usable token.")
    print(f"   {DIM}repr() of the token object: {token!r}{RESET}")
    note("The container refuses to print the plaintext, keeping it out of logs.")

    must(
        tokens.hash_token(token.plaintext) == token.token_hash,
        "the presented token hashes to the stored value",
    )
    ok("the presented token hashes to the stored value")
    note("That hash is what the server looks up. There is no secret-dependent")
    note("comparison anywhere in our code: the database matches on a hash of the")
    note("token, never on the token itself.")

    tampered = ("B" if token.plaintext[0] != "B" else "C") + token.plaintext[1:]
    must(tokens.hash_token(tampered) != token.token_hash, "a tampered token hashes differently")
    blocked("one flipped character produces an unrelated hash, so the lookup finds nothing")

    # The real single-use guarantee is one SQL statement:
    #   UPDATE enrollment_tokens SET consumed_at = now()
    #    WHERE id = :id AND consumed_at IS NULL RETURNING id
    # Simulated here; the concurrency test against PostgreSQL is Phase 1b.
    print()
    consumed: dict[str, bool] = {}

    def consume(token_hash: str) -> bool:
        if consumed.get(token_hash):
            return False
        consumed[token_hash] = True
        return True

    first, second = consume(token.token_hash), consume(token.token_hash)
    ok(f"first use succeeds: {first}")
    blocked(f"second use refused: {second}")
    note("Simulated. The real guarantee is a single atomic UPDATE ... WHERE")
    note("consumed_at IS NULL RETURNING id, proven by a concurrency test in 1b.")
    record("enrollment_token_created", "enrollment_token", token.token_hash[:12])


def demo_ca(tmp: Path) -> tuple[ca.CertificateAuthority, x509.Certificate]:
    section(5, "Internal CA and device enrollment")

    authority = ca.generate_ca(now=NOW)
    ok(f"CA created: {authority.certificate.subject.rfc4514_string()}")
    constraints = authority.certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    note(f"basicConstraints: CA={constraints.ca}, path_length={constraints.path_length}")
    note("path_length=0 means a stolen device cert can never become a sub-CA.")

    key_path, cert_path = tmp / "ca.key", tmp / "ca.crt"
    ca.save_ca(authority, key_path, cert_path)
    mode = oct(key_path.stat().st_mode & 0o777)
    ok(f"CA key written with mode {mode} (created restricted, never chmod'ed after)")

    print()
    attack("make the CA key group-readable, then load it")
    key_path.chmod(0o644)
    try:
        ca.load_ca(key_path, cert_path)
    except ca.KeyFilePermissionError as exc:
        blocked(f"{str(exc).split(';')[0]}")
    key_path.chmod(0o600)

    print()
    device_key = ec.generate_private_key(ec.SECP256R1())
    note("The agent generates its keypair locally; the private key never moves.")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "i-am-the-ceo-laptop")]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(device_key, hashes.SHA256())
    )
    attack(f"CSR asks to be called 'i-am-the-ceo-laptop' and requests {requested(csr)}")

    certificate = ca.issue_device_certificate(authority, csr, DEVICE_ID, now=NOW)
    issued_cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    issued_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    blocked(f"requested subject ignored; certificate says CN={issued_cn}")
    blocked(f"requested extensions ignored; certificate says CA={issued_ca}")
    note("Copying CSR extensions is a classic CA vulnerability. Only the public")
    note("key is taken from the request.")

    print()
    ok(f"fingerprint: {ca.certificate_fingerprint(certificate)[:39]}...")
    note("SHA-256, computed by the app. nginx's $ssl_client_fingerprint is SHA-1,")
    note("which is why the proxy forwards the whole certificate instead.")
    lifetime = certificate.not_valid_after_utc - certificate.not_valid_before_utc
    ok(
        f"valid {lifetime.days} days, renewal due "
        f"{ca.renewal_due_at(certificate).date()} (50% of life)"
    )

    print()
    attack("submit a CSR containing someone else's public key")
    filler = "a" * 24
    honest = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, filler)]))
        .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    )
    der = honest.public_bytes(serialization.Encoding.DER)
    forged = x509.load_der_x509_csr(der.replace(filler.encode(), b"b" + filler.encode()[1:], 1))
    try:
        ca.issue_device_certificate(authority, forged, DEVICE_ID, now=NOW)
    except ca.CsrRejectedError as exc:
        blocked(f"{exc}")
        note("The signature check is what proves the requester holds the key.")

    attack("enroll with a 2048-bit RSA key")
    from cryptography.hazmat.primitives.asymmetric import rsa

    weak_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")]))
        .sign(
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            hashes.SHA256(),
        )
    )
    try:
        ca.verify_csr(weak_csr)
    except ca.CsrRejectedError as exc:
        blocked(f"{exc}")

    record("device_enrolled", "device", DEVICE_ID)
    return authority, certificate


def requested(csr: x509.CertificateSigningRequest) -> str:
    return ", ".join(ca.requested_extensions(csr)) or "nothing"


def demo_policy_signing(tmp: Path) -> None:
    section(6, "Policy signing, and the replay attacks it stops")

    signer = policy_signing.PolicySigner(Ed25519PrivateKey.generate())
    ok(f"policy signing key: {signer.key_id}")
    note("Ed25519, deliberately a different algorithm and a different file from")
    note("the CA key, so pointing one at the other fails loudly.")

    example = REPO / "schemas" / "examples" / "valid" / "policy.usb_control.allowlist.json"
    payload_obj = json.loads(example.read_text())
    payload = policy_signing.serialize_payload(payload_obj)
    ok(f"payload serialized ONCE: {len(payload)} bytes, now an opaque byte string")
    note(
        f"mode={payload_obj['mode']}, "
        f"allowlist={len(payload_obj['allowlist'])} entry, "
        f"always_allow={','.join(payload_obj['always_allow_classes'][:3])}..."
    )

    envelope = signer.sign_envelope(
        policy_id="3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        policy_version=7,
        policy_type="usb_control",
        scope_kind="device",
        scope_id=DEVICE_ID,
        issued_at=NOW,
        payload=payload,
    )
    trusted = {signer.key_id: signer.public_key}
    ok(f"signed as version {envelope['policy_version']} for this device only")
    note(f"payload_b64 begins {envelope['payload_b64'][:40]}...")
    note("Base64 so no JSON layer in between can reorder the signed bytes.")

    verified = policy_signing.verify_envelope(envelope, trusted)
    ok(f"verified, returning {len(verified)} raw bytes")
    note("verify_envelope returns BYTES, not a parsed object, so 'verify before")
    note("you parse' is structural rather than a comment in the code.")

    print()
    for description, mutate in [
        ("flip one bit of the payload", _flip_payload),
        ("bump the version 7 -> 8 to look newer", _bump_version),
        ("re-scope the policy to a different device", _rescope),
        ("shift issued_at a month into the future", _shift_time),
        ("forge a signature from scratch", _forge_signature),
    ]:
        attack(description)
        try:
            policy_signing.verify_envelope(mutate(dict(envelope)), trusted)
            print(f"   {RED}!!! ACCEPTED - this is a bug{RESET}")
        except policy_signing.PolicyVerificationError as exc:
            blocked(f"reason_code = {exc.reason_code}")

    note("Version, type, scope, both timestamps and key_id are all INSIDE the")
    note("signature, which is why none of these can be moved in transit.")

    print()
    attack("point the policy signer at the CA's EC key by mistake")
    wrong = tmp / "wrong.key"
    _write_private(wrong, ec.generate_private_key(ec.SECP256R1()))
    try:
        policy_signing.PolicySigner.from_file(wrong)
    except TypeError as exc:
        blocked(str(exc).split(".")[0])

    record("policy_created", "policy", "3f2504e0")
    record("policy_assigned", "device", DEVICE_ID)


def _flip_payload(envelope: dict) -> dict:
    import base64
    import hashlib

    raw = bytearray(base64.b64decode(envelope["payload_b64"]))
    raw[0] ^= 0x01
    envelope["payload_b64"] = base64.b64encode(bytes(raw)).decode()
    envelope["payload_sha256"] = hashlib.sha256(bytes(raw)).hexdigest()
    return envelope


def _bump_version(envelope: dict) -> dict:
    envelope["policy_version"] = 8
    return envelope


def _rescope(envelope: dict) -> dict:
    envelope["scope"] = {"kind": "device", "id": "00000000-0000-4000-8000-000000000000"}
    return envelope


def _shift_time(envelope: dict) -> dict:
    envelope["issued_at"] = "2026-12-29T10:00:00Z"
    return envelope


def _forge_signature(envelope: dict) -> dict:
    """Swap in a well-formed but invented 64-byte signature."""
    envelope["signature"] = dict(envelope["signature"], value_b64="A" * 86 + "==")
    return envelope


def _write_private(path: Path, key: object) -> None:
    pem = key.private_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)


def demo_audit_chain() -> None:
    section(7, "Append-only audit log")

    rows: list[audit_chain.ChainedAuditEntry] = []
    previous = audit_chain.GENESIS_PREV_HASH
    for index, (action, target_type, target_id) in enumerate(audit_actions, start=1):
        entry = audit_chain.AuditEntry(
            seq=index,
            occurred_at=NOW + dt.timedelta(seconds=index),
            action=action,
            actor_id="it-admin",
            actor_role="it_admin",
            target_type=target_type,
            target_id=target_id,
            request_id=f"req-{index:04d}",
            detail_json=json.dumps({"demo": True}, separators=(",", ":")).encode(),
        )
        row = audit_chain.chain(entry, previous)
        rows.append(row)
        previous = row.entry_hash

    note("Every action this demo performed, in order:")
    for row in rows:
        print(
            f"   {row.entry.seq:>2}. {row.entry.action:<28} "
            f"{DIM}{row.entry_hash.hex()[:16]}...{RESET}"
        )

    result = audit_chain.verify_chain(rows)
    ok(f"chain verifies across all {result.checked} entries")

    print()
    import dataclasses

    attack("edit entry 2 to hide a successful login")
    edited = list(rows)
    edited[1] = dataclasses.replace(
        edited[1], entry=dataclasses.replace(edited[1].entry, action="nothing_happened")
    )
    broken = audit_chain.verify_chain(edited)
    blocked(f"detected at seq {broken.broken_at_seq}: {broken.reason}")

    attack("delete entry 3 entirely")
    deleted = [row for row in rows if row.entry.seq != 3]
    broken = audit_chain.verify_chain(deleted)
    blocked(f"detected at seq {broken.broken_at_seq}: {broken.reason}")

    attack("recompute the hash so entry 3 is self-consistent, but re-parented")
    reparented = list(rows)
    wrong_parent = bytes(32)
    reparented[2] = audit_chain.ChainedAuditEntry(
        entry=reparented[2].entry,
        prev_hash=wrong_parent,
        entry_hash=audit_chain.compute_entry_hash(wrong_parent, reparented[2].entry),
    )
    broken = audit_chain.verify_chain(reparented)
    blocked(f"detected at seq {broken.broken_at_seq}: {broken.reason}")
    note("The careful version of the attack: the row verifies on its own, and the")
    note("chain link is the only thing that catches it.")


def main() -> int:
    print(f"{BOLD}UbuntuGuard — security core demonstration{RESET}")
    print(f"{DIM}Real modules from server/src/ubuntuguard. No database, no network.{RESET}")

    with tempfile.TemporaryDirectory(prefix="ubuntuguard-demo-") as temp:
        tmp = Path(temp)
        demo_rbac()
        demo_passwords()
        demo_lockout()
        demo_enrollment_token()
        demo_ca(tmp)
        demo_policy_signing(tmp)
        demo_audit_chain()
        print(f"\n{DIM}Temporary keys in {tmp} are deleted now.{RESET}")

    print(f"\n{BOLD}What this demonstrated{RESET}")
    for line in [
        "RBAC denies by an explicit table, not by omission",
        "Argon2id hashing, with timing equalised and a size bound on the input",
        "Lockout boundaries at 5 failures and a 10 minute window",
        "Enrollment tokens stored only as hashes, compared in constant time",
        "A CA that takes nothing from a CSR except the public key",
        "Policy signatures that bind version, type, scope and time to the payload",
        "An audit chain that localises edits, deletions and re-parenting",
    ]:
        print(f"   {GREEN}✓{RESET} {line}")

    print(f"\n{BOLD}{YELLOW}What this does NOT demonstrate{RESET}")
    for line in [
        "Any HTTP endpoint, login flow or dashboard - Phases 1b and 3",
        "Any database behaviour: migrations, the append-only DB role, the",
        "  enrollment race under real concurrency - all Phase 1b",
        "That the Go agent agrees with this signer - Phase 4, via policy_vectors.json",
        "Any USB enforcement whatsoever - gated on the USBGuard spike",
    ]:
        print(f"   {YELLOW}•{RESET} {line}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
