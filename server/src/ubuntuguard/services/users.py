"""Administrative account changes: enable, role change, password reset.

Why these live in a service rather than in the route
----------------------------------------------------
Every operation here has to take a row lock and then write, in one
transaction, and the lock has to be held across the decision. Putting the
check in the route and the write in a repository would separate them by a
function boundary that is easy to reorder, and the failure mode is silent: the
code still works, concurrent requests still succeed, and the fleet quietly
ends up with no administrator.

So the sequence is stated once, here, and the routes do nothing but
authenticate, call, and audit.

The protection being implemented
--------------------------------
`manage_users` is the one capability held by a single role, and it is the
capability that can grant every other capability. That makes "there is at
least one active super_admin" a liveness property of the whole system rather
than a nicety: lose it and nobody can enrol a device, revoke a laptop, or
restore an account, including the account that would do the restoring.

Three ways to lose it, all closed here:

  - disabling the last active super_admin
  - demoting the last active super_admin
  - doing either to yourself, which is the same mistake with a shorter path

`cannot_disable_self` already existed for the third. The first two did not,
and `POST /users/{id}:disable` was reachable by two super_admins in sequence:
A disables B, B disables A, nobody is left.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.models import User

#: The role whose last active holder must never be removed.
PROTECTED_ROLE = "super_admin"


def _refuse_last_super_admin(session: Session, *, user: User, action: str) -> None:
    """Raise unless at least one other active super_admin would remain.

    Takes the row lock described in `repositories.lock_active_super_admins`,
    inside the caller's transaction, so the count cannot be invalidated by a
    concurrent request between here and the write.

    Only applies when the target IS currently an active super_admin. A
    disabled super_admin is not part of the count, and demoting one cannot
    reduce it.
    """
    if user.role != PROTECTED_ROLE or not user.is_active:
        return

    remaining = repositories.lock_active_super_admins(session, exclude_user_id=user.id)
    if remaining == 0:
        raise problems.conflict(
            f"cannot_{action}_last_super_admin",
            "This is the last active super_admin. Promote another account to "
            "super_admin first, or the system would be left with nobody able to "
            "manage users, devices or enrollment.",
        )


def enable(session: Session, *, user: User) -> None:
    """Reactivate a disabled account.

    No last-super_admin guard: enabling cannot reduce the number of active
    super_admins. Refuses an already-active account rather than succeeding
    silently, because an administrator clicking Enable on an active account has
    misread the table and should be told so.
    """
    if user.is_active:
        raise problems.conflict("user_already_active", "That account is already active.")
    repositories.enable_user(session, user)


def change_role(session: Session, *, actor_id: str | None, user: User, role: str) -> str:
    """Change a role. Returns the PREVIOUS role, for the audit entry.

    Self-change is refused for the same reason self-disable is: the only
    account that can restore a demoted super_admin is another super_admin, and
    an administrator who demotes themselves by accident has no way back. It is
    a support call, not a security control.
    """
    if actor_id is not None and actor_id == str(user.id):
        raise problems.conflict(
            "cannot_change_own_role",
            "You cannot change your own role. Ask another super_admin to do it.",
        )

    previous = user.role
    if previous == role:
        raise problems.conflict("role_unchanged", f"That account already has the {role} role.")

    _refuse_last_super_admin(session, user=user, action="demote")
    repositories.set_user_role(session, user, role)
    return previous


def disable(session: Session, *, actor_id: str | None, user: User) -> int:
    """Deactivate an account and revoke its sessions. Returns tokens revoked.

    The self-check is first and the last-super_admin check second, so the
    clearer message wins when both apply - an administrator disabling their own
    sole super_admin account is told it is their own account, which is the fact
    they can act on.
    """
    if actor_id is not None and actor_id == str(user.id):
        raise problems.conflict("cannot_disable_self", "You cannot disable your own account.")

    _refuse_last_super_admin(session, user=user, action="disable")
    return repositories.disable_user(session, user)


def reset_password(session: Session, *, user: User, password_hash: str) -> int:
    """Install an administrator-chosen password and force a change at next use.

    Returns the number of sessions revoked.

    Three things happen together and all three are required:

    The hash replaces the old one. Only the hash reaches this function - the
    route hashes the plaintext and never passes it on, so there is no path by
    which a password could be logged or audited from here.

    `must_change_password` is set, so the temporary credential buys the user
    exactly one thing: the ability to replace it. Every capability-guarded
    route refuses until they do.

    Every session is revoked. This is what makes the operation visible to its
    subject: a user whose password an administrator reset is signed out
    everywhere, immediately, rather than continuing on an access token for up
    to fifteen minutes. If the reset was not legitimate, being logged out is
    how they find out.

    No last-super_admin guard, and that is correct rather than an omission: a
    reset does not reduce the number of active super_admins. It does let one
    super_admin take over another's account, which is a real widening and is
    recorded in agent/SECURITY-FINDINGS.md rather than left implicit.
    """
    repositories.update_password_hash(session, user, password_hash)
    repositories.set_must_change_password(session, user, True)
    return repositories.revoke_all_sessions(session, user)


def get_target(session: Session, user_id: uuid.UUID) -> User:
    """Fetch the account being acted on, or raise 404."""
    user = repositories.get_user(session, user_id)
    if user is None:
        raise problems.not_found("user")
    return user
