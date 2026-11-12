#!/usr/bin/env python3
"""Phase 0 validation gate.

Checks, in order:
  1. every file in schemas/ is a structurally valid JSON Schema draft 2020-12
  2. every example validates (or fails) exactly as schemas/examples/manifest.json says
  3. every example file is referenced by the manifest, so none goes untested
  4. the committed policy signing vector still verifies, and each negative vector
     still fails

Exit code is non-zero on any failure, so this can be wired into `make test`.

Scope note: this proves the SCHEMAS and the signing-input construction are
self-consistent in Python. It does NOT prove the Go agent agrees - that needs the
Go side of testdata/policy_vectors.json, which lands in Phase 4.

Usage:  .venv-tools/bin/python tools/validate_phase0.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_policy_vectors import sig_input, test_signing_key

REPO = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO / "schemas"
EXAMPLE_DIR = SCHEMA_DIR / "examples"
VECTOR_FILE = REPO / "testdata" / "policy_vectors.json"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

failures: list[str] = []
checks = 0


def record(ok: bool, label: str, detail: str = "") -> None:
    global checks
    checks += 1
    if ok:
        print(f"  {GREEN}PASS{RESET} {label}")
    else:
        print(f"  {RED}FAIL{RESET} {label}")
        if detail:
            print(f"       {DIM}{detail}{RESET}")
        failures.append(label)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_registry() -> tuple[Registry, dict[str, dict]]:
    """Register every schema under its $id so cross-file $ref resolves offline."""
    registry = Registry()
    by_filename: dict[str, dict] = {}
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = load_json(path)
        by_filename[path.name] = schema
        registry = registry.with_resource(
            uri=schema["$id"], resource=Resource.from_contents(schema)
        )
    return registry, by_filename


def section(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


def check_schemas_are_valid(by_filename: dict[str, dict]) -> None:
    section("1. Schemas are structurally valid (draft 2020-12)")
    if not by_filename:
        record(False, "found at least one schema", f"no *.schema.json under {SCHEMA_DIR}")
        return
    for name, schema in by_filename.items():
        try:
            Draft202012Validator.check_schema(schema)
            record(True, name)
        except Exception as exc:  # noqa: BLE001 - report whatever the library raises
            record(False, name, str(exc))


def check_examples(registry: Registry, by_filename: dict[str, dict]) -> set[Path]:
    section("2. Examples validate exactly as the manifest says")
    manifest = load_json(EXAMPLE_DIR / "manifest.json")
    schema_map = manifest["schemas"]
    referenced: set[Path] = {(EXAMPLE_DIR / "manifest.json").resolve()}

    fmt = FormatChecker()
    active_formats = sorted(fmt.checkers)

    for case in manifest["cases"]:
        rel = case["file"]
        path = (EXAMPLE_DIR / rel).resolve()
        referenced.add(path)
        label = f"{rel} -> expect {case['expect']}"

        if not path.exists():
            record(False, label, "file does not exist")
            continue

        schema_file = schema_map[case["schema"]]
        validator = Draft202012Validator(
            by_filename[schema_file], registry=registry, format_checker=fmt
        )
        errors = sorted(validator.iter_errors(load_json(path)), key=lambda e: list(e.path))

        if case["expect"] == "valid":
            record(
                not errors,
                label,
                "; ".join(f"{list(e.path)}: {e.message}" for e in errors[:3]),
            )
        else:
            # An "invalid" case must be rejected. We also surface WHY, so a case
            # that starts failing for an unintended reason is visible rather than
            # quietly counted as a pass.
            if errors:
                reason = errors[0].message
                trimmed = reason if len(reason) <= 110 else reason[:107] + "..."
                print(f"  {GREEN}PASS{RESET} {label}")
                print(f"       {DIM}rejected: {trimmed}{RESET}")
                global checks
                checks += 1
            else:
                record(False, label, "document was ACCEPTED but the manifest expects rejection")

    print(f"\n  {DIM}format checkers active: {', '.join(active_formats)}{RESET}")
    if "date-time" not in active_formats:
        print(
            f"  {YELLOW}NOTE{RESET} date-time format is NOT being asserted "
            "(install rfc3339-validator to enable it)."
        )
    return referenced


def check_manifest_coverage(referenced: set[Path]) -> None:
    section("3. No example file is left untested")
    on_disk = {p.resolve() for p in EXAMPLE_DIR.rglob("*.json")}
    orphans = sorted(p.relative_to(EXAMPLE_DIR).as_posix() for p in on_disk - referenced)
    record(
        not orphans,
        "every example is referenced by manifest.json",
        "unreferenced: " + ", ".join(orphans) if orphans else "",
    )


def verify_envelope(envelope: dict) -> bool:
    """Verify an envelope the way the agent must: signature over the exact bytes."""
    payload = base64.b64decode(envelope["payload_b64"], validate=True)
    si = sig_input(
        policy_id=envelope["policy_id"],
        policy_version=envelope["policy_version"],
        policy_type=envelope["policy_type"],
        scope_kind=envelope["scope"]["kind"],
        scope_id=envelope["scope"]["id"],
        issued_at=envelope["issued_at"],
        expires_at=envelope["expires_at"],
        key_id=envelope["signature"]["key_id"],
        payload=payload,
    )
    signature = base64.b64decode(envelope["signature"]["value_b64"], validate=True)
    try:
        test_signing_key().public_key().verify(signature, si)
        return True
    except InvalidSignature:
        return False


def check_policy_vector() -> None:
    section("4. Committed policy signing vector")
    if not VECTOR_FILE.exists():
        record(False, "testdata/policy_vectors.json exists", "run tools/make_policy_vectors.py")
        return

    vector = load_json(VECTOR_FILE)
    pos = vector["positive"]
    env = pos["envelope"]

    # Key derivation is reproducible from the documented string alone.
    pk = test_signing_key().public_key().public_bytes_raw()
    derived_kid = "ed25519:" + hashlib.sha256(pk).hexdigest()[:16]
    record(
        derived_kid == vector["key_derivation"]["expected_key_id"],
        "test key derives to the recorded key_id (no key material committed)",
        f"derived {derived_kid}, recorded {vector['key_derivation']['expected_key_id']}",
    )

    # payload_sha256 is advisory, but it must still agree with the bytes.
    payload = base64.b64decode(env["payload_b64"], validate=True)
    record(
        hashlib.sha256(payload).hexdigest() == env["payload_sha256"],
        "advisory payload_sha256 matches the decoded payload bytes",
    )
    record(
        len(payload) == pos["expected_payload_len"],
        f"payload is {pos['expected_payload_len']} bytes",
        f"got {len(payload)}",
    )

    # SIG_INPUT has not drifted from the committed vector.
    si = sig_input(
        policy_id=env["policy_id"],
        policy_version=env["policy_version"],
        policy_type=env["policy_type"],
        scope_kind=env["scope"]["kind"],
        scope_id=env["scope"]["id"],
        issued_at=env["issued_at"],
        expires_at=env["expires_at"],
        key_id=env["signature"]["key_id"],
        payload=payload,
    )
    record(
        hashlib.sha256(si).hexdigest() == pos["expected_sig_input_sha256"],
        "recomputed SIG_INPUT matches the committed sha256",
        f"got {hashlib.sha256(si).hexdigest()}",
    )
    record(verify_envelope(env), "positive vector verifies")

    for neg in vector["negative"]:
        ok = not verify_envelope(neg["envelope"])
        record(ok, f"negative vector rejected: {neg['name']}", neg["why"])


def main() -> int:
    print("UbuntuGuard Phase 0 validation")
    registry, by_filename = build_registry()
    check_schemas_are_valid(by_filename)
    referenced = check_examples(registry, by_filename)
    check_manifest_coverage(referenced)
    check_policy_vector()

    print()
    if failures:
        print(f"{RED}{len(failures)} of {checks} checks FAILED{RESET}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"{GREEN}all {checks} checks passed{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
