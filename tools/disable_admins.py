#!/usr/bin/env python3
"""Disable administrator accounts through the admin API.

Who to disable comes from the command line. **Nothing is hardcoded** - no
address list, no pattern, no exclusions baked into this file. A tool that
carried somebody's email in its source would be wrong twice over: it would
commit personal data to the repository, and it would only work for the one
person it was written for.

**Disable, not delete, and that is not a soft option.** Three structural
reasons:

  1. `enrollment_tokens.created_by` is `ondelete="RESTRICT"`, so PostgreSQL
     refuses to delete any account that ever minted a token.
  2. `audit_logs.actor_id` is a plain string column, deliberately not a foreign
     key, so the audit trail survives a user row disappearing - but it survives
     as a UUID nobody can resolve to a person. Deleting the row does not clean
     the log, it makes the log unreadable.
  3. The audit log is append-only, enforced by database GRANTs rather than
     application code, so there is no tidy-up available even in principle.

Disabling sets `is_active = false`, revokes every live session in the same
statement, and appends a `user_disabled` entry. `DbTokenResolver` returns None
for an inactive user on the very next request, so the lockout is immediate
rather than waiting for an access token to expire.

The write goes through the API rather than straight to SQL, because the route
is where the RBAC check, the self-disable guard, the session revocation and the
audit append live. A script that went round them would be disabling accounts
with no record of who did it.

Examples:

    # See what would happen. Always worth doing first.
    tools/disable_admins.py --email <admin-email> --password '<password>' \\
        --match '^u[0-9]+@x\\.invalid$' --dry-run

    # Named accounts.
    tools/disable_admins.py --email <admin-email> --password '<password>' \\
        --target <address-to-disable> --target <another-address-to-disable>

    # A pattern, keeping one back.
    tools/disable_admins.py --email <admin-email> --password '<password>' \\
        --match '<regex>' --exclude <address-to-keep>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def call(
    base: str, method: str, path: str, payload: Any = None, token: str | None = None
) -> tuple[int, Any]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        base + path, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read()
            return response.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body or b"{}")
        except ValueError:
            return exc.code, {}


def database_url(env_file: Path) -> str:
    if not env_file.exists():
        raise SystemExit(f"{env_file} is missing; is the database configured?")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("UBUNTUGUARD_DATABASE_URL="):
            return line.partition("=")[2].strip()
    raise SystemExit(f"no UBUNTUGUARD_DATABASE_URL in {env_file}")


def active_accounts(env_file: Path) -> list[dict[str, str]]:
    """Every active account: id, email, role. Read-only.

    Read from the database rather than `GET /users`, and that is a workaround
    for a real limitation rather than a preference: that route takes a `limit`
    capped at 200 and offers no cursor, so on a database with more accounts
    than that there is no way to enumerate them over HTTP. A development
    database with a few thousand throwaway accounts from the test suite hides
    everything else behind the first page.

    Selects id, email and role and nothing else - in particular never
    `password_hash`, so this output is safe to paste into a ticket.
    """
    from sqlalchemy import create_engine, text

    with create_engine(database_url(env_file)).connect() as connection:
        rows = connection.execute(
            text(
                "SELECT id::text, email, role FROM users WHERE is_active ORDER BY created_at"
            )
        ).all()
    return [{"id": row[0], "email": row[1], "role": row[2]} for row in rows]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--email", required=True, help="the super_admin doing the work")
    parser.add_argument("--password", required=True)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=REPO_ROOT / "server" / ".env",
        help="where to read the database URL from, for enumerating accounts",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="EMAIL",
        help="Exact address to disable. Repeatable.",
    )
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        metavar="REGEX",
        help=(
            "Python regex matched against the address with re.search. Repeatable. "
            r"Anchor it: '^u[0-9]+@x\.invalid$' rather than 'u'."
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="EMAIL",
        help=(
            "Never disable this address, even if --match selects it. Repeatable. "
            "The acting account is excluded automatically and does not need this."
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="List what would be disabled, change nothing"
    )
    arguments = parser.parse_args()

    if not arguments.target and not arguments.match:
        # No implicit "disable everything that looks stale". Refusing an empty
        # selection is the difference between a tool and an accident.
        parser.error("nothing selected: pass at least one --target or --match")

    try:
        patterns = [re.compile(pattern) for pattern in arguments.match]
    except re.error as exc:
        parser.error(f"bad --match regex: {exc}")

    base = arguments.api.rstrip("/") + "/api/v1"
    status, body = call(
        base, "POST", "/auth/login", {"email": arguments.email, "password": arguments.password}
    )
    if status != 200:
        return _fail(f"login failed as {arguments.email}: HTTP {status}")
    token = body["access_token"]

    status, me = call(base, "GET", "/auth/me", None, token)
    if status != 200:
        return _fail(f"could not read /auth/me: HTTP {status}")
    if me.get("role") != "super_admin" and "user:manage" not in me.get("capabilities", []):
        return _fail(f"{arguments.email} is {me.get('role')}; disabling accounts needs super_admin")
    print(f"acting as {me['email']} ({me['role']})")

    # The acting account is protected automatically, from /auth/me rather than
    # from a list in this file. The API refuses self-disable with 409 anyway;
    # excluding it here keeps the report honest instead of showing a failure
    # that is actually correct behaviour.
    excluded = {address.strip().lower() for address in arguments.exclude}
    excluded.add(me["email"].strip().lower())

    wanted = {address.strip().lower() for address in arguments.target}
    accounts = active_accounts(arguments.env_file)
    by_email = {account["email"].lower(): account for account in accounts}

    missing = sorted(wanted - set(by_email))
    if missing:
        # Reported, not fatal: an address that is already disabled or never
        # existed is not a reason to abandon the rest of the run.
        print("\nnot active, or no such account (skipped):")
        for address in missing:
            print(f"  {address}")

    targets: list[tuple[dict[str, str], str]] = []
    for account in accounts:
        address = account["email"].lower()
        if address in excluded:
            continue
        if address in wanted:
            targets.append((account, "named with --target"))
            continue
        for pattern in patterns:
            if pattern.search(account["email"]):
                targets.append((account, f"matched {pattern.pattern!r}"))
                break

    print(f"\n{len(targets)} active account(s) selected:")
    for account, reason in targets:
        print(f"  {account['email']:38} {account['role']:16} {reason}")
    if not targets:
        print("  (none)")

    if excluded:
        print("\nexcluded:")
        for address in sorted(excluded):
            note = " (the acting account)" if address == me["email"].lower() else ""
            print(f"  {address}{note}")

    if arguments.dry_run:
        print("\n--dry-run: nothing was changed.")
        return 0
    if not targets:
        return 0

    print()
    failed = 0
    for account, _reason in targets:
        status, _ = call(base, "POST", f"/users/{account['id']}:disable", None, token)
        if status == 204:
            print(f"  disabled  {account['email']}")
        else:
            failed += 1
            print(f"  FAILED    {account['email']}: HTTP {status}")

    # Re-read rather than trusting the status codes. The end state is the point,
    # not the sequence of responses that got there.
    still_active = {account["email"].lower() for account in active_accounts(arguments.env_file)}
    remaining = [
        account["email"] for account, _ in targets if account["email"].lower() in still_active
    ]
    print("\n--- verification ---")
    print(f"  selected        {len(targets)}")
    print(f"  still active    {len(remaining)}")
    for address in remaining:
        print(f"    {address}")
    if remaining:
        print(
            "\n  An account cannot disable itself - the API returns 409\n"
            "  cannot_disable_self, deliberately, because locking yourself out of\n"
            "  the last privileged account is a support call rather than a\n"
            "  security feature. Run this again from a different super_admin."
        )
    return 1 if failed or remaining else 0


def _fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
