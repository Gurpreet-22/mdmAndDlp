"""Admin authentication.

Every failure path returns the same `invalid_credentials` problem. Wrong
password, unknown account, locked account and disabled account are
indistinguishable to the caller; only the audit log records which it was. The
real reason travels in `audit_detail`, which never reaches the response.

The order of operations matters. Lockout is evaluated BEFORE the password is
checked, and it is keyed on the submitted email rather than on a user row, so an
attacker cannot avoid the lockout by targeting an address that does not exist.
For an unknown address a dummy Argon2 verification runs anyway, so the timing
does not reveal whether the account is real.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from ubuntuguard import problems, repositories
from ubuntuguard.constants import ACCESS_TOKEN_TTL_SECONDS, LOGIN_FAILURE_WINDOW_SECONDS
from ubuntuguard.security import lockout, passwords
from ubuntuguard.security.rbac import Role
from ubuntuguard.security.tokens import IssuedToken, hash_token
from ubuntuguard.services import audit


@dataclass(frozen=True, slots=True)
class LoginResult:
    user_id: uuid.UUID
    email: str
    role: Role
    access: IssuedToken
    refresh: IssuedToken
    family_id: uuid.UUID
    access_expires_in: int = ACCESS_TOKEN_TTL_SECONDS


def login(
    session: Session,
    *,
    email: str,
    password: str,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> LoginResult:
    """Authenticate an admin, or raise `invalid_credentials`."""
    now = dt.datetime.now(dt.UTC)
    normalised = email.strip().lower()

    window_start = now - dt.timedelta(seconds=LOGIN_FAILURE_WINDOW_SECONDS)
    failures = repositories.recent_failed_attempts(session, email=normalised, since=window_start)
    user = repositories.get_user_by_email(session, normalised)

    decision = lockout.evaluate(
        recent_failures=failures,
        now=now,
        locked_until=user.locked_until if user else None,
    )
    if decision.locked:
        # Recorded as a failure too: an attacker hammering a locked account is
        # worth seeing in the log, and it keeps the window from draining while
        # they keep trying.
        repositories.record_login_attempt(
            session, email=normalised, succeeded=False, source_ip=source_ip, user_agent=user_agent
        )
        audit.append(
            session,
            action="login_failed",
            actor_id=normalised,
            target_type="user",
            target_id=str(user.id) if user else None,
            request_id=request_id,
            detail={
                "reason": "locked_out",
                "failures_in_window": decision.failures_in_window,
                "retry_after_seconds": decision.retry_after_seconds,
                "source_ip": source_ip,
            },
        )
        session.commit()
        raise problems.invalid_credentials(
            audit_detail=f"account locked, retry in {decision.retry_after_seconds}s"
        )

    if user is None:
        # Spend the same CPU time as a real verification so the response time
        # does not reveal that the address is unknown.
        passwords.verify_dummy()
        _record_failure(
            session, normalised, None, request_id, source_ip, user_agent, "unknown_user"
        )
        session.commit()
        raise problems.invalid_credentials(audit_detail=f"no such user: {normalised}")

    if not user.is_active:
        passwords.verify_dummy()
        _record_failure(session, normalised, user, request_id, source_ip, user_agent, "disabled")
        session.commit()
        raise problems.invalid_credentials(audit_detail=f"user {user.id} is disabled")

    if not passwords.verify_password(user.password_hash, password):
        _record_failure(
            session, normalised, user, request_id, source_ip, user_agent, "wrong_password"
        )
        # Re-evaluate including this failure, and lock if it crossed the line.
        failures = repositories.recent_failed_attempts(
            session, email=normalised, since=window_start
        )
        if lockout.evaluate(recent_failures=failures, now=now).locked:
            repositories.set_user_lock(session, user, lockout.lock_until(now))
        session.commit()
        raise problems.invalid_credentials(audit_detail=f"wrong password for user {user.id}")

    # Success. Raising Argon2 parameters later needs no password reset: the
    # plaintext is available only here, so this is the one place to re-hash.
    if passwords.needs_rehash(user.password_hash):
        repositories.update_password_hash(session, user, passwords.hash_password(password))

    repositories.record_login_attempt(
        session, email=normalised, succeeded=True, source_ip=source_ip, user_agent=user_agent
    )
    repositories.touch_last_login(session, user)
    access, refresh, family_id = repositories.issue_token_pair(session, user_id=user.id)

    audit.append(
        session,
        action="login_succeeded",
        actor_id=str(user.id),
        actor_role=user.role,
        target_type="user",
        target_id=str(user.id),
        request_id=request_id,
        detail={"email": normalised, "source_ip": source_ip, "family_id": str(family_id)},
    )

    # Committed here, not in the dependency teardown: the client may use this
    # access token on its very next request, and teardown runs after the
    # response has already been sent.
    session.commit()

    return LoginResult(
        user_id=user.id,
        email=user.email,
        role=Role(user.role),
        access=access,
        refresh=refresh,
        family_id=family_id,
    )


def login_without_authentication(
    session: Session,
    *,
    email: str,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> LoginResult:
    """Issue a session for ANY address, creating the account on first sight.

    A placeholder until Microsoft SSO is wired in. The password is not read,
    not compared, and not stored: the caller is whoever they say they are.

    Kept as a SEPARATE function rather than a branch inside `login()` on
    purpose. The real authentication path above is the security-critical one,
    and it should stay readable without a flag threaded through its middle;
    anyone auditing this file should be able to see at a glance which function
    checks a password and which does not.

    Everything downstream of identity is unchanged, which is what makes this
    survivable: the account is a real row, so RBAC still applies, the audit log
    still names an actor, and swapping in SSO means replacing this function
    rather than reworking the session machinery.
    """
    normalised = email.strip().lower()

    user = repositories.get_user_by_email(session, normalised)
    created = user is None
    if user is None:
        user = repositories.create_user(
            session,
            email=normalised,
            # Not derived from the submitted password. See the docstring on
            # `unusable_password_hash`: it is what makes these accounts
            # unreachable rather than open once this flag is turned off.
            password_hash=passwords.unusable_password_hash(),
            role=Role.SUPER_ADMIN.value,
        )
        session.flush()
    elif not user.is_active:
        # A disabled account stays disabled. Otherwise this flag would quietly
        # undo every `POST /users/{id}:disable` an operator had performed.
        _record_failure(session, normalised, user, request_id, source_ip, user_agent, "disabled")
        session.commit()
        raise problems.invalid_credentials(audit_detail=f"user {user.id} is disabled")

    repositories.record_login_attempt(
        session, email=normalised, succeeded=True, source_ip=source_ip, user_agent=user_agent
    )
    repositories.touch_last_login(session, user)
    access, refresh, family_id = repositories.issue_token_pair(session, user_id=user.id)

    audit.append(
        session,
        action="login_succeeded",
        actor_id=str(user.id),
        actor_role=user.role,
        target_type="user",
        target_id=str(user.id),
        request_id=request_id,
        # `via` is the part that matters. Without it the audit log would claim
        # this address proved who it was, which is exactly what did not happen.
        detail={
            "email": normalised,
            "source_ip": source_ip,
            "family_id": str(family_id),
            "via": "no_authentication",
            "account_created": created,
        },
    )
    session.commit()

    return LoginResult(
        user_id=user.id,
        email=user.email,
        role=Role(user.role),
        access=access,
        refresh=refresh,
        family_id=family_id,
    )


def _record_failure(
    session: Session,
    email: str,
    user: object | None,
    request_id: str | None,
    source_ip: str | None,
    user_agent: str | None,
    reason: str,
) -> None:
    repositories.record_login_attempt(
        session, email=email, succeeded=False, source_ip=source_ip, user_agent=user_agent
    )
    audit.append(
        session,
        action="login_failed",
        actor_id=email,
        target_type="user",
        target_id=str(getattr(user, "id", "")) or None,
        request_id=request_id,
        detail={"reason": reason, "source_ip": source_ip},
    )


def refresh_session(
    session: Session, *, refresh_plaintext: str, request_id: str | None = None
) -> LoginResult:
    """Rotate a refresh token, or raise.

    Single use. Presenting an already-used token revokes the WHOLE family,
    because at that point either an attacker has a stolen copy or the
    legitimate client is replaying - and there is no way to tell which, so the
    safe move is to end the session and make the user log in again.
    """
    now = dt.datetime.now(dt.UTC)
    token = repositories.find_token(
        session, token_hash=hash_token(refresh_plaintext), kind="refresh"
    )

    if token is None:
        raise problems.not_authenticated()

    if token.used_at is not None:
        revoked = repositories.revoke_family(session, token.family_id)
        audit.append(
            session,
            action="token_reuse_detected",
            actor_id=str(token.user_id),
            target_type="auth_token_family",
            target_id=str(token.family_id),
            request_id=request_id,
            detail={
                "reason": "refresh token presented twice",
                "tokens_revoked": revoked,
                "first_used_at": token.used_at,
            },
        )
        session.commit()
        raise problems.not_authenticated()

    if token.revoked_at is not None or token.expires_at <= now:
        raise problems.not_authenticated()

    user = repositories.get_user(session, token.user_id)
    if user is None or not user.is_active:
        repositories.revoke_family(session, token.family_id)
        session.commit()
        raise problems.not_authenticated()

    repositories.mark_refresh_used(session, token)
    access, new_refresh, _ = repositories.issue_token_pair(
        session, user_id=user.id, family_id=token.family_id
    )

    audit.append(
        session,
        action="token_refreshed",
        actor_id=str(user.id),
        actor_role=user.role,
        target_type="auth_token_family",
        target_id=str(token.family_id),
        request_id=request_id,
        detail={},
    )

    session.commit()

    return LoginResult(
        user_id=user.id,
        email=user.email,
        role=Role(user.role),
        access=access,
        refresh=new_refresh,
        family_id=token.family_id,
    )


def logout(
    session: Session, *, refresh_plaintext: str | None, request_id: str | None = None
) -> None:
    """Revoke the whole family. Idempotent, and silent about unknown tokens.

    Returns successfully even for a token we have never seen: logging out is not
    a place to tell a caller whether their token was real.
    """
    if not refresh_plaintext:
        return
    token = repositories.find_token(
        session, token_hash=hash_token(refresh_plaintext), kind="refresh"
    )
    if token is None:
        return

    revoked = repositories.revoke_family(session, token.family_id)
    audit.append(
        session,
        action="logout",
        actor_id=str(token.user_id),
        target_type="auth_token_family",
        target_id=str(token.family_id),
        request_id=request_id,
        detail={"tokens_revoked": revoked},
    )
    session.commit()


def change_own_password(
    session: Session,
    *,
    user_id: uuid.UUID,
    current_password: str,
    new_password: str,
    request_id: str | None = None,
) -> LoginResult:
    """Change the signed-in user's own password and re-establish the session.

    Returns a fresh token pair, and that is the design rather than a
    convenience. The sequence is:

      1. Verify the CURRENT password. An access token alone is not sufficient
         authority to replace a credential - a stolen token would otherwise be
         an account takeover, and the fifteen-minute lifetime is what currently
         bounds the damage of one. This is the only check that stops that.
      2. Refuse a new password equal to the old one. Checked by verifying the
         proposed password against the stored hash, which costs one Argon2
         verification and no schema: if it verifies, it is the same password.
         Note this prevents reuse of the CURRENT password only; preventing
         reuse of the previous N would need a password-history table, which
         does not exist and is not invented here.
      3. Validate against policy, via `hash_password`, which calls
         `validate_password`. One policy, one place.
      4. Replace the hash and clear `must_change_password`. This is the only
         route that clears it, so a user put into a forced change can leave
         that state exactly one way: by proving they know the temporary
         password and choosing a new one.
      5. Revoke every session, then issue a new pair.

    Step 5 is worth reading twice. Revoking everything is correct after a
    credential change - any session opened with the old password is suspect,
    including one whose refresh token an attacker already holds - but revoking
    and stopping there would sign the user out of the tab they are using,
    which for a FORCED change means they could never get past the screen
    telling them to change it. So every old session dies and one new one is
    issued, in the same transaction. The caller sets the new refresh cookie.

    The lockout counters are untouched. A password change is not a failed login
    and must not clear a standing lock, or an attacker who learned a password
    could use this route to escape a lockout they had triggered.
    """
    user = repositories.get_user(session, user_id)
    if user is None or not user.is_active:
        # Resolved from a valid access token moments ago, so this is a race
        # with a disable rather than a bad request. Same vague body as every
        # other authentication failure.
        raise problems.invalid_credentials(
            audit_detail=f"user {user_id} is missing or disabled at password change"
        )

    if not passwords.verify_password(user.password_hash, current_password):
        # Recorded as a failed attempt so it feeds the same lockout window as
        # login: without this, this route would be an unthrottled oracle for
        # guessing the current password of an already-compromised session.
        repositories.record_login_attempt(session, email=user.email, succeeded=False)
        audit.append(
            session,
            action="password_change_failed",
            actor_id=str(user.id),
            actor_role=user.role,
            target_type="user",
            target_id=str(user.id),
            request_id=request_id,
            detail={"reason": "wrong_current_password"},
        )
        session.commit()
        raise problems.invalid_credentials(
            audit_detail=f"wrong current password for user {user.id}"
        )

    if passwords.verify_password(user.password_hash, new_password):
        raise problems.conflict(
            "password_unchanged",
            "The new password must be different from the current one.",
        )

    try:
        new_hash = passwords.hash_password(new_password)
    except passwords.PasswordPolicyError as exc:
        raise problems.validation_failed(
            [problems.FieldError(field="new_password", message=str(exc))]
        ) from exc

    was_forced = user.must_change_password
    repositories.update_password_hash(session, user, new_hash)
    repositories.set_must_change_password(session, user, False)
    revoked = repositories.revoke_all_sessions(session, user)

    access, refresh, family_id = repositories.issue_token_pair(session, user_id=user.id)

    audit.append(
        session,
        action="password_changed",
        actor_id=str(user.id),
        actor_role=user.role,
        target_type="user",
        target_id=str(user.id),
        request_id=request_id,
        # No password, no hash, no fingerprint of either. `was_forced` is what
        # closes the loop on an administrator reset: it is the record that the
        # subject of that reset actually took over the account.
        detail={
            "self_service": True,
            "completed_forced_change": was_forced,
            "sessions_revoked": revoked,
        },
    )
    session.commit()

    return LoginResult(
        user_id=user.id,
        email=user.email,
        role=Role(user.role),
        access=access,
        refresh=refresh,
        family_id=family_id,
    )
