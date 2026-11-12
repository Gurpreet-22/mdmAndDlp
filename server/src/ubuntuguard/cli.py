"""Operator CLI: bootstrap keys and the first admin account.

These two actions cannot be done through the API, and deliberately so. Creating
the first `super_admin` over HTTP would need an unauthenticated route that
creates a privileged account, which is a backdoor however carefully it is
guarded. Generating key material over HTTP would mean the private key existed
somewhere other than the server's disk.

`set-password` is here for the same reason: a password-reset HTTP endpoint is an
account-takeover primitive, so changing a credential requires shell access and
the database password rather than a request.

Usage:
    python -m ubuntuguard.cli init-keys
    python -m ubuntuguard.cli list-admins [--match ...] [--capabilities]
    python -m ubuntuguard.cli create-admin --email <address> --role <role>
    python -m ubuntuguard.cli set-password --email <address>
    python -m ubuntuguard.cli revoke-sessions --email <address>
    python -m ubuntuguard.cli show-keys
    python -m ubuntuguard.cli verify-audit
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import string
import sys

from ubuntuguard import repositories as repositories_bridge
from ubuntuguard.config import Settings
from ubuntuguard.db import create_db_engine, create_session_factory, session_scope
from ubuntuguard.security import passwords
from ubuntuguard.security.rbac import Role, capabilities_for
from ubuntuguard.services import audit, keys


def _generated_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def cmd_init_keys(args: argparse.Namespace) -> int:
    settings = Settings()
    bundle = keys.ensure_keys(settings, create_missing=True)
    print(f"CA subject         : {bundle.ca.certificate.subject.rfc4514_string()}")
    print(f"CA not_after       : {bundle.ca.certificate.not_valid_after_utc.isoformat()}")
    print(f"Policy signing key : {bundle.signer.key_id}")
    print()
    print("Key files are mode 0600 and are gitignored. Back them up out of band:")
    print(f"  CA key      : {settings.ca_key_path or 'var/ca.key'}")
    print(f"  CA cert     : {settings.ca_cert_path or 'var/ca.crt'}")
    print(f"  Signing key : {settings.policy_signing_key_path or 'var/policy-signing.key'}")
    print()
    print("Losing the CA key means re-enrolling every device.")
    print("Losing the signing key means every existing policy stops verifying.")
    return 0


def cmd_list_admins(args: argparse.Namespace) -> int:
    """Show which accounts exist, and what each one can do.

    There is deliberately no signup page - a self-service route that creates a
    privileged account is a backdoor however carefully it is guarded - so the
    first `super_admin` is bootstrapped from this CLI. That leaves an operator
    with an obvious question this command answers: who already exists, and with
    what role?

    Without it the only answers were to write SQL by hand, or to sign in to the
    dashboard - which needs an account, which is the thing being asked about.
    `GET /users` is also capped at 200 rows with no cursor, so on a database
    with more accounts than that it cannot show them all either.

    Never selects `password_hash`. The output is meant to be readable over a
    shoulder and pasteable into a ticket.
    """
    settings = Settings()
    engine = create_db_engine(settings)
    factory = create_session_factory(engine)

    with session_scope(factory) as session:
        users = repositories_bridge.list_all_users(
            session, pattern=args.match, include_inactive=not args.active_only
        )

        if users:
            width = max(len(user.email) for user in users)
            print(f"{'EMAIL'.ljust(width)}  {'ROLE':16} {'STATE':9} LAST LOGIN")
            for user in users:
                state = "active" if user.is_active else "disabled"
                if user.is_active and user.locked_until is not None:
                    state = "locked"
                last = (
                    user.last_login_at.isoformat(timespec="seconds")
                    if user.last_login_at
                    else "never"
                )
                print(f"{user.email.ljust(width)}  {user.role:16} {state:9} {last}")

            active = sum(1 for user in users if user.is_active)
            print(f"\n{len(users)} account(s), {active} active")
        else:
            # `--match` is a SUBSTRING, not a regex - it becomes an ILIKE
            # '%...%'. Saying so is cheaper than letting somebody conclude an
            # account is missing when their pattern simply did not match it.
            where = f" matching {args.match!r}" if args.match else ""
            print(f"no account{where}.")
            if args.match:
                print("  (--match is a case-insensitive substring, not a regex)")
            print("\nCreate one with:")
            print("  python -m ubuntuguard.cli create-admin --email <address> --role super_admin")

    # Outside the `if users` block on purpose: this is about what the ROLES
    # mean, which is a question an operator has before they have created
    # anything at all.
    if args.capabilities:
        print()
        for role in Role:
            granted = sorted(capability.value for capability in capabilities_for(role))
            print(f"{role.value}:")
            for capability in granted:
                print(f"  {capability}")
    return 0


def cmd_show_keys(args: argparse.Namespace) -> int:
    settings = Settings()
    try:
        bundle = keys.ensure_keys(settings)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"CA subject         : {bundle.ca.certificate.subject.rfc4514_string()}")
    print(f"Policy signing key : {bundle.signer.key_id}")
    return 0


def cmd_create_admin(args: argparse.Namespace) -> int:
    settings = Settings()
    engine = create_db_engine(settings)
    factory = create_session_factory(engine)

    password = args.password
    generated = False
    if not password:
        if sys.stdin.isatty():
            password = getpass.getpass("Password (leave blank to generate): ") or None
        if not password:
            password = _generated_password()
            generated = True

    try:
        passwords.validate_password(password)
    except passwords.PasswordPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    with session_scope(factory) as session:
        if repositories_bridge.get_user_by_email(session, args.email) is not None:
            print(f"error: {args.email} already exists", file=sys.stderr)
            return 1

        user = repositories_bridge.create_user(
            session,
            email=args.email,
            password_hash=passwords.hash_password(password),
            role=args.role,
        )
        audit.append(
            session,
            action="user_created",
            actor_id="cli",
            actor_role=None,
            target_type="user",
            target_id=str(user.id),
            detail={"email": user.email, "role": user.role, "via": "cli"},
        )

    print(f"created {args.email} with role {args.role}")
    if generated:
        # Printed once, to a terminal, and never stored. The operator is
        # expected to put it straight into a password manager.
        print(f"generated password: {password}")
        print("Store it now; it is not recoverable.")
    return 0


def _terminal_is_usable() -> bool:
    """Whether `getpass` has somewhere to prompt.

    `sys.stdin.isatty()` is the WRONG check here, and getting it wrong costs a
    hang rather than an error. CPython's `getpass.getpass` opens /dev/tty
    directly and reads from THAT, falling back to stdin only if /dev/tty cannot
    be opened. So a process whose stdin is a pipe, but which still has a
    controlling terminal nobody is typing at, blocks forever - while
    `sys.stdin.isatty()` cheerfully reports True because it is describing a
    different file altogether.

    Found by running it: the first version of this command hung twice before
    this check existed. A credential-setting command must fail fast and say
    what to do instead.
    """
    try:
        with open("/dev/tty"):  # noqa: PTH123 - os.open semantics not needed
            return True
    except OSError:
        return False


def _prompt_for_password() -> str | None:
    """Ask twice, without echo. None means refuse, with the reason printed."""
    if not _terminal_is_usable():
        print(
            "error: no password supplied and there is no usable terminal to "
            "prompt at.\n"
            "  --password-stdin   read it from stdin (not visible in the process list)\n"
            "  --generate         have one generated and printed once",
            file=sys.stderr,
        )
        return None
    try:
        first = getpass.getpass("New password: ")
        # Asked twice: a typo here is a lockout, and the whole point of this
        # command is recovering from one.
        if first != getpass.getpass("Confirm password: "):
            print("error: passwords do not match", file=sys.stderr)
            return None
    except (EOFError, OSError) as exc:
        # A terminal that disappears mid-prompt must not fall through to
        # setting an empty or partial password.
        print(f"error: could not read a password: {exc}", file=sys.stderr)
        return None
    return first


def cmd_set_password(args: argparse.Namespace) -> int:
    """Set the password on an account that already exists.

    The counterpart to `create-admin`, which deliberately refuses an email it
    already knows rather than silently overwriting a credential.

    This exists because an account created by the retired no-authentication
    placeholder holds an UNUSABLE hash - Argon2id over 32 random bytes that
    were discarded - so no password can ever verify against it. Without this
    command the only route back in is a second account under a different
    address, leaving the original orphaned in the audit trail as an actor
    nobody can sign in as.

    Operator-only, and deliberately not an HTTP route. A password-reset
    endpoint is an account-takeover primitive; adding one permanently to solve
    a one-off migration would be a bad trade.
    """
    settings = Settings()
    factory = create_session_factory(create_db_engine(settings))

    password = args.password
    generated = False
    if password is None:
        if args.generate:
            password = _generated_password()
            generated = True
        elif args.password_stdin:
            # Explicit, scriptable, and absent from the process list. Read from
            # sys.stdin rather than via getpass, which does not read stdin at
            # all - see _prompt_for_password.
            password = sys.stdin.readline().rstrip("\n")
            if not password:
                print("error: --password-stdin given but stdin was empty", file=sys.stderr)
                return 1
        else:
            password = _prompt_for_password()
            if password is None:
                return 1

    try:
        # The same policy as every other password. A second check here would
        # be a second thing to drift.
        passwords.validate_password(password)
    except passwords.PasswordPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    normalised = args.email.strip().lower()
    with session_scope(factory) as session:
        user = repositories_bridge.get_user_by_email(session, normalised)
        if user is None:
            print(
                f"error: {normalised} does not exist. Create it with: "
                f"create-admin --email {normalised} --role <role>",
                file=sys.stderr,
            )
            return 1
        if not user.is_active:
            # Setting a password must not quietly undo an operator's
            # `POST /users/{id}:disable`.
            print(
                f"error: {normalised} is disabled; setting a password would not "
                "re-enable it. Re-enable the account first.",
                file=sys.stderr,
            )
            return 1

        repositories_bridge.update_password_hash(session, user, passwords.hash_password(password))
        # Revoking is the DEFAULT and has no opt-out. A credential change
        # means every session predating it is suspect: an attacker holding a
        # refresh token issued under the old password would otherwise keep a
        # working session for up to 8 hours after the rotation meant to lock
        # them out. There is no operational case for keeping those alive that
        # outweighs that, so no flag is offered.
        revoked = repositories_bridge.revoke_all_sessions(session, user)
        audit.append(
            session,
            action="user_password_set",
            actor_id="cli",
            actor_role=None,
            target_type="user",
            target_id=str(user.id),
            # Email, role and a count. The password and its hash are never
            # recorded, and the audit log is widely readable.
            detail={
                "email": user.email,
                "role": user.role,
                "via": "cli",
                "sessions_revoked": revoked,
            },
        )

    # One transaction: the hash, the revocation and the audit row commit
    # together or not at all. A password that changed without its sessions
    # being cut, or without a record, is the failure mode this prevents.
    print(f"password set for {normalised} (role {user.role})")
    if generated:
        # Printed once, never stored. Same contract as create-admin.
        print(f"generated password: {password}")
        print("Store it now; it is not recoverable.")
    print(f"revoked {revoked} existing session token(s); the account stays enabled")
    return 0


def cmd_revoke_sessions(args: argparse.Namespace) -> int:
    """Revoke every live session for an account, without disabling it.

    The operation that did not previously exist. `POST /auth/logout` only
    revokes the family presenting the token, and cannot reach a session whose
    access token has already expired. `POST /users/{id}:disable` does revoke
    everything, but also sets `is_active = false` - and there is no enable
    route, so it is one-way through the API and would lock the account out
    permanently.

    This sits between the two: log the person out everywhere, leave the
    account working.
    """
    settings = Settings()
    factory = create_session_factory(create_db_engine(settings))

    normalised = args.email.strip().lower()
    with session_scope(factory) as session:
        user = repositories_bridge.get_user_by_email(session, normalised)
        if user is None:
            print(f"error: {normalised} does not exist", file=sys.stderr)
            return 1

        revoked = repositories_bridge.revoke_all_sessions(session, user)
        if revoked:
            # No row when there was nothing to revoke: an audit log full of
            # "revoked 0 sessions" is noise that makes the real events harder
            # to find.
            audit.append(
                session,
                action="user_sessions_revoked",
                actor_id="cli",
                actor_role=None,
                target_type="user",
                target_id=str(user.id),
                detail={
                    "email": user.email,
                    "role": user.role,
                    "via": "cli",
                    "sessions_revoked": revoked,
                },
            )
        still_active = user.is_active

    print(f"revoked {revoked} session token(s) for {normalised}")
    print(f"account is_active: {still_active} (unchanged)")
    if not revoked:
        print("Nothing was live, so no audit entry was written.")
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    settings = Settings()
    factory = create_session_factory(create_db_engine(settings))
    with session_scope(factory) as session:
        result = audit.verify(session)
        head = audit.head_seq(session)

    print(f"entries      : {head}")
    print(f"verified     : {result.checked}")
    if result.ok:
        print("chain        : intact")
        return 0
    print("chain        : BROKEN")
    print(f"first break  : seq {result.broken_at_seq}")
    print(f"reason       : {result.reason}")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ubuntuguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-keys", help="generate the CA and the policy signing key").set_defaults(
        func=cmd_init_keys
    )
    sub.add_parser("show-keys", help="print key identifiers").set_defaults(func=cmd_show_keys)

    listing = sub.add_parser("list-admins", help="show which admin accounts exist, and their roles")
    listing.add_argument(
        "--match",
        default=None,
        metavar="SUBSTRING",
        help="Only addresses containing this. Case-insensitive.",
    )
    listing.add_argument(
        "--active-only", action="store_true", help="Hide accounts that are disabled"
    )
    listing.add_argument(
        "--capabilities",
        action="store_true",
        help="Also print what each role is permitted to do",
    )
    listing.set_defaults(func=cmd_list_admins)

    create = sub.add_parser("create-admin", help="create an admin account")
    create.add_argument("--email", required=True)
    create.add_argument("--role", required=True, choices=[role.value for role in Role])
    create.add_argument(
        "--password",
        default=None,
        help=(
            "Avoid this on a shared machine: an argument is visible in the "
            "process list. Omit it to be prompted, or to have one generated."
        ),
    )
    create.set_defaults(func=cmd_create_admin)

    setpw = sub.add_parser("set-password", help="set the password on an existing admin account")
    setpw.add_argument("--email", required=True)
    setpw.add_argument(
        "--password",
        default=None,
        help=(
            "Avoid this on a shared machine: an argument is visible in the "
            "process list. Omit it to be prompted, or use --generate."
        ),
    )
    setpw.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from stdin. Scriptable, and not visible in the process list.",
    )
    setpw.add_argument(
        "--generate",
        action="store_true",
        help="Generate a password and print it once. For non-interactive use.",
    )
    setpw.set_defaults(func=cmd_set_password)

    revoke = sub.add_parser(
        "revoke-sessions",
        help="revoke every live session for an account, without disabling it",
    )
    revoke.add_argument("--email", required=True)
    revoke.set_defaults(func=cmd_revoke_sessions)

    sub.add_parser("verify-audit", help="recompute the audit hash chain").set_defaults(
        func=cmd_verify_audit
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
