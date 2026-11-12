#!/usr/bin/env python3
"""Read-only report on administrator accounts and what they left behind.

Who to inspect comes from the command line. **Nothing is hardcoded** - no
address list and no pattern baked into this file.

Written as a tool rather than an ad-hoc query because "what did that account
actually leave behind" has four parts that are each easy to check
incompletely: the account itself, its live sessions, the devices it registered,
and the enrollment tokens it minted that nobody ever spent. The last one is the
one people forget, and it is the one that matters most: `POST /enroll`
authenticates on the token alone, so an unspent token keeps working after the
account that minted it is disabled.

**Reads only.** No UPDATE, no INSERT, no DELETE, and it never selects
`password_hash`, so the output is safe to paste into a ticket. Disabling an
account is a deliberate act with an audit trail, so it belongs to
`tools/disable_admins.py` and an authenticated super_admin.

Examples:

    # Every active account that is not a test-suite throwaway.
    tools/inspect_admins.py --match '^(?!.*@example\\.invalid$)'

    # Named accounts, active or not.
    tools/inspect_admins.py --email <address> --email <another-address>

    # A pattern.
    tools/inspect_admins.py --match '^u[0-9]+@x\\.invalid$'
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

try:
    from sqlalchemy import create_engine, text
except ImportError:  # pragma: no cover - setup error
    sys.exit(
        "sqlalchemy is not importable. Run with the server virtualenv:\n"
        "  server/.venv/bin/python tools/inspect_admins.py --help"
    )

GREEN, RED, YELLOW, BOLD, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"


def database_url(env_file: Path) -> str:
    if not env_file.exists():
        sys.exit(f"{env_file} is missing; is the database configured?")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("UBUNTUGUARD_DATABASE_URL="):
            return line.partition("=")[2].strip()
    sys.exit(f"no UBUNTUGUARD_DATABASE_URL in {env_file}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--email",
        action="append",
        default=[],
        metavar="ADDRESS",
        help="Exact address to inspect. Repeatable.",
    )
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        metavar="REGEX",
        help="Python regex matched against the address with re.search. Repeatable.",
    )
    parser.add_argument(
        "--active-only", action="store_true", help="Skip accounts that are already disabled"
    )
    parser.add_argument("--env-file", type=Path, default=REPO_ROOT / "server" / ".env")
    arguments = parser.parse_args()

    if not arguments.email and not arguments.match:
        parser.error("nothing selected: pass at least one --email or --match")

    try:
        patterns = [re.compile(pattern) for pattern in arguments.match]
    except re.error as exc:
        parser.error(f"bad --match regex: {exc}")

    wanted = {address.strip().lower() for address in arguments.email}
    engine = create_engine(database_url(arguments.env_file))

    with engine.connect() as connection:
        print(f"{BOLD}Administrator account report{OFF}")
        print(f"database: {engine.url.render_as_string(hide_password=True)}")

        # password_hash is never selected. Nothing here needs it, and a report
        # that printed one is a report nobody could share.
        rows = connection.execute(
            text(
                "SELECT id, email, role, is_active, created_at, updated_at, "
                "       last_login_at, locked_until "
                "FROM users ORDER BY created_at"
            )
        ).mappings().all()

        selected = [
            row
            for row in rows
            if (row["email"].lower() in wanted or any(p.search(row["email"]) for p in patterns))
            and (row["is_active"] or not arguments.active_only)
        ]

        if not selected:
            print("\nno account matched.")
            return 0

        active_count = 0
        outstanding_tokens: list[tuple[str, str, object]] = []

        for row in selected:
            state = f"{RED}ACTIVE{OFF}" if row["is_active"] else f"{GREEN}disabled{OFF}"
            if row["is_active"]:
                active_count += 1
            print(f"\n{BOLD}{row['email']}{OFF}")
            print(f"  id             {row['id']}")
            print(f"  role           {row['role']}")
            print(f"  is_active      {state}")
            print(f"  created_at     {row['created_at']}")
            print(f"  last_login_at  {row['last_login_at']}")
            print(f"  locked_until   {row['locked_until']}")

            live = connection.execute(
                text(
                    "SELECT kind, count(*) AS n FROM auth_tokens "
                    "WHERE user_id = :uid AND revoked_at IS NULL AND expires_at > now() "
                    "GROUP BY kind ORDER BY kind"
                ),
                {"uid": row["id"]},
            ).mappings().all()
            if live:
                summary = ", ".join(f"{item['n']} {item['kind']}" for item in live)
                print(f"  live sessions  {RED}{summary}{OFF}")
            else:
                print("  live sessions  none")

            devices = connection.execute(
                text(
                    "SELECT id, display_name, hostname, status FROM devices "
                    "WHERE registered_by = :uid ORDER BY registered_at"
                ),
                {"uid": row["id"]},
            ).mappings().all()
            print(f"  devices registered: {len(devices)}")
            for device in devices:
                colour = GREEN if device["status"] == "revoked" else RED
                label = device["display_name"] or device["hostname"] or "?"
                print(f"    {device['id']}  {colour}{device['status']}{OFF}  {label!r}")

            tokens = connection.execute(
                text(
                    "SELECT id, label, expires_at, consumed_at, revoked_at "
                    "FROM enrollment_tokens WHERE created_by = :uid ORDER BY created_at"
                ),
                {"uid": row["id"]},
            ).mappings().all()
            # Three states worth distinguishing, because only one of them is a
            # live credential. Consumed or revoked is finished. Unspent but
            # EXPIRED is harmless - `consume_enrollment_token` guards on
            # `expires_at > now()`, so it can never be redeemed. Unspent and
            # unexpired is the one that still enrols a device.
            now = connection.execute(text("SELECT now()")).scalar()
            usable = [
                token
                for token in tokens
                if token["consumed_at"] is None
                and token["revoked_at"] is None
                and token["expires_at"] > now
            ]
            expired = [
                token
                for token in tokens
                if token["consumed_at"] is None
                and token["revoked_at"] is None
                and token["expires_at"] <= now
            ]
            print(f"  enrollment tokens minted: {len(tokens)}")
            for token in usable:
                outstanding_tokens.append((row["email"], str(token["id"]), token["expires_at"]))
                print(f"    {RED}STILL USABLE{OFF} {token['id']}  expires {token['expires_at']}")
            if expired:
                print(f"    {len(expired)} unspent but expired (cannot be redeemed)")
            if tokens and not usable and not expired:
                print("    all consumed or revoked")

        print(f"\n{BOLD}Summary{OFF}")
        print(f"  matched            {len(selected)}")
        print(
            "  still active       "
            + (f"{GREEN}0{OFF}" if active_count == 0 else f"{RED}{active_count}{OFF}")
        )

        if active_count:
            print(
                "\n  Disable them from a DIFFERENT super_admin account:\n"
                "      server/.venv/bin/python tools/disable_admins.py \\\n"
                "          --email <another super_admin> --password '...' \\\n"
                "          --target <address>  [--target ...]\n"
                "\n  The API refuses self-disable with 409 cannot_disable_self,\n"
                "  deliberately: locking yourself out of the last privileged account\n"
                "  is a support call, not a security feature."
            )

        if outstanding_tokens:
            # The part most likely to be missed. Disabling an account does NOT
            # revoke the tokens it minted, and `POST /enroll` authenticates on
            # the token alone - so one of these still enrols a device no matter
            # what happened to the account that created it.
            print(
                f"\n  {RED}{len(outstanding_tokens)} enrollment token(s) are still "
                f"redeemable.{OFF}\n"
                "  Disabling an account does not revoke them, and /enroll\n"
                "  authenticates on the token alone. Revoke each one:\n"
                "      POST /api/v1/enrollment-tokens/<id>:revoke"
            )
            for email, token_id, expires in outstanding_tokens:
                print(f"    {token_id}  minted by {email}  expires {expires}")
        else:
            print(f"  redeemable tokens  {GREEN}0{OFF}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
