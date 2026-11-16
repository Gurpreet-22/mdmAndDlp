"""Last-super_admin protection, including the concurrent case.

Why these run in a throwaway schema
-----------------------------------
The guard only fires when *no other active super_admin would remain*. The
development database holds 1,282 active super_admins, created by
`test_api_integration.create_admin()` and never cleaned up, so the condition
cannot be reached there - and deactivating them, even inside a transaction that
is rolled back, means writing to rows that belong to somebody's real
development data.

So each test gets its own PostgreSQL schema, created with the owner role,
populated by `Base.metadata.create_all`, and dropped afterwards. The live
`users` table is never read and never written. What this buys is a `users`
table with exactly the rows the test puts in it, which is the only way to
express "this is the last one".

It is real PostgreSQL throughout, which matters more here than anywhere else in
the suite: the protection rests on `SELECT … FOR UPDATE` row locks, and those
cannot be exercised against SQLite or a mock. The concurrency test below runs
two genuine connections in two threads against one table.

**Scope of this file, stated plainly.** These are service-layer tests. They
exercise `services.users` and `repositories.lock_active_super_admins` directly,
not HTTP. The HTTP behaviour of these routes is covered in
`test_user_management.py` for every case that does not need a globally unique
super_admin - 404, 403, self-change, already-active, the happy paths. The
last-super_admin refusal itself is **not** covered at the HTTP layer, by
decision, because producing that state over HTTP would mean disabling the
1,282 live accounts.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from ubuntuguard import problems, repositories
from ubuntuguard.models import Base, User
from ubuntuguard.security.passwords import hash_password
from ubuntuguard.services import users as users_service

pytestmark = pytest.mark.postgres

SERVER_DIR = Path(__file__).resolve().parents[1]
PASSWORD = "a reasonably long passphrase"


def _owner_url() -> str:
    """The schema-owner URL, which is the only role that may create a schema.

    Read from server/.env directly rather than through `Settings`, matching
    `test_api_integration`: the autouse `isolate_settings_sources` fixture
    neutralises .env for determinism, and these tests need the real thing.
    """
    env_file = SERVER_DIR / ".env"
    if not env_file.exists():
        pytest.skip("server/.env is missing. Create it with: ./scripts/dev_db.sh up")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("UBUNTUGUARD_MIGRATION_DATABASE_URL="):
            return line.partition("=")[2].strip()
    pytest.skip("no UBUNTUGUARD_MIGRATION_DATABASE_URL in server/.env")


@pytest.fixture
def isolated_schema() -> Iterator[Engine]:
    """A private schema with the full table set and an empty `users`.

    Dropped with CASCADE in a `finally`, so a failing assertion cannot leave a
    schema behind. The name carries a uuid, so two runs - or a leftover from a
    killed run - cannot collide.
    """
    url = _owner_url()
    if "UG_SKIP_SCHEMA_TESTS" in os.environ:  # pragma: no cover - operator escape hatch
        pytest.skip("UG_SKIP_SCHEMA_TESTS is set")

    admin_engine = create_engine(url)
    schema = f"ug_test_{uuid.uuid4().hex[:12]}"
    engine: Engine | None = None
    try:
        try:
            with admin_engine.begin() as connection:
                connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        except Exception as exc:  # noqa: BLE001 - reported as a skip, not a failure
            pytest.skip(f"cannot create a test schema: {exc}")

        engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
        Base.metadata.create_all(engine)
        yield engine
    finally:
        if engine is not None:
            engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()


@pytest.fixture
def session_factory(isolated_schema: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=isolated_schema, expire_on_commit=False)


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as opened:
        yield opened


def make_user(session: Session, role: str, *, active: bool = True) -> User:
    user = repositories.create_user(
        session,
        email=f"{role}-{uuid.uuid4().hex[:8]}@example.invalid",
        password_hash=hash_password(PASSWORD),
        role=role,
    )
    if not active:
        user.is_active = False
    session.commit()
    return user


def active_super_admins(session: Session) -> int:
    return int(
        session.execute(
            text("SELECT count(*) FROM users WHERE role = 'super_admin' AND is_active")
        ).scalar()
        or 0
    )


# --------------------------------------------------------------------------- #
# The schema really is isolated
# --------------------------------------------------------------------------- #


def test_the_test_schema_starts_with_no_accounts(session: Session) -> None:
    """If this fails, every other test in this file is meaningless.

    It would mean the fixture is pointed at the live `users` table, and
    "the last super_admin" assertions would be operating on real data.
    """
    total = int(session.execute(text("SELECT count(*) FROM users")).scalar() or 0)
    assert total == 0, (
        f"the isolated schema already holds {total} accounts; the fixture is not "
        "isolated and these tests must not run"
    )


# --------------------------------------------------------------------------- #
# Disable
# --------------------------------------------------------------------------- #


def test_the_last_active_super_admin_cannot_be_disabled(session: Session) -> None:
    sole = make_user(session, "super_admin")
    actor = make_user(session, "super_admin")
    # The actor is the one doing the disabling, so it is excluded from the
    # count by being a different row - disable it first to make `sole` genuinely
    # the last one.
    repositories.disable_user(session, actor)
    session.commit()
    assert active_super_admins(session) == 1

    with pytest.raises(problems.ProblemError) as raised:
        users_service.disable(session, actor_id=str(actor.id), user=sole)

    assert raised.value.code == "cannot_disable_last_super_admin"
    assert raised.value.status == 409
    session.rollback()
    assert active_super_admins(session) == 1, "the refusal did not leave the account active"


def test_a_super_admin_can_be_disabled_while_another_remains(session: Session) -> None:
    """The guard must not refuse the ordinary case."""
    keeper = make_user(session, "super_admin")
    doomed = make_user(session, "super_admin")
    actor = make_user(session, "super_admin")
    assert active_super_admins(session) == 3

    users_service.disable(session, actor_id=str(actor.id), user=doomed)
    session.commit()

    assert doomed.is_active is False
    assert keeper.is_active is True
    assert active_super_admins(session) == 2


def test_disabling_the_only_account_of_another_role_is_allowed(session: Session) -> None:
    """The protection is specific to super_admin, not to being the last of a role.

    An `it_admin` is replaceable by a super_admin at any time, so there is no
    liveness property to protect.
    """
    actor = make_user(session, "super_admin")
    sole_it_admin = make_user(session, "it_admin")

    users_service.disable(session, actor_id=str(actor.id), user=sole_it_admin)
    session.commit()
    assert sole_it_admin.is_active is False


def test_an_already_disabled_super_admin_does_not_count_towards_the_guard(
    session: Session,
) -> None:
    """Only ACTIVE super_admins keep the system administrable.

    A disabled one cannot sign in, so counting it would let the last usable
    account be disabled on the strength of an unusable one.
    """
    sole = make_user(session, "super_admin")
    make_user(session, "super_admin", active=False)
    actor = make_user(session, "it_admin")
    assert active_super_admins(session) == 1

    with pytest.raises(problems.ProblemError) as raised:
        users_service.disable(session, actor_id=str(actor.id), user=sole)
    assert raised.value.code == "cannot_disable_last_super_admin"


def test_you_cannot_disable_your_own_account(session: Session) -> None:
    """Pre-existing guard, re-asserted here because it moved into the service."""
    actor = make_user(session, "super_admin")
    make_user(session, "super_admin")

    with pytest.raises(problems.ProblemError) as raised:
        users_service.disable(session, actor_id=str(actor.id), user=actor)
    assert raised.value.code == "cannot_disable_self"


def test_the_self_check_is_reported_before_the_last_super_admin_check(
    session: Session,
) -> None:
    """When both apply, the actionable message wins.

    A sole super_admin disabling themselves gets "you cannot disable your own
    account", which names something they can do differently, rather than
    "this is the last super_admin", which they would read as a system state.
    """
    sole = make_user(session, "super_admin")
    assert active_super_admins(session) == 1

    with pytest.raises(problems.ProblemError) as raised:
        users_service.disable(session, actor_id=str(sole.id), user=sole)
    assert raised.value.code == "cannot_disable_self"


# --------------------------------------------------------------------------- #
# Role change
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target_role", ["it_admin", "security_analyst", "auditor"])
def test_the_last_active_super_admin_cannot_be_demoted(session: Session, target_role: str) -> None:
    """Every demotion target, because each one removes `manage_users`."""
    sole = make_user(session, "super_admin")
    actor = make_user(session, "it_admin")
    assert active_super_admins(session) == 1

    with pytest.raises(problems.ProblemError) as raised:
        users_service.change_role(session, actor_id=str(actor.id), user=sole, role=target_role)

    assert raised.value.code == "cannot_demote_last_super_admin"
    assert raised.value.status == 409
    session.rollback()
    assert sole.role == "super_admin", "the refusal did not leave the role unchanged"


def test_a_super_admin_can_be_demoted_while_another_remains(session: Session) -> None:
    keeper = make_user(session, "super_admin")
    demoted = make_user(session, "super_admin")
    actor = make_user(session, "super_admin")

    previous = users_service.change_role(
        session, actor_id=str(actor.id), user=demoted, role="auditor"
    )
    session.commit()

    assert previous == "super_admin"
    assert demoted.role == "auditor"
    assert keeper.role == "super_admin"
    assert active_super_admins(session) == 2


@pytest.mark.parametrize("from_role", ["it_admin", "security_analyst", "auditor"])
def test_promotion_to_super_admin_is_always_allowed(session: Session, from_role: str) -> None:
    """Promotion cannot reduce the count, so no guard applies.

    Also the documented escape from a near-lockout: promote somebody else
    first, then the demotion the guard refused becomes permissible.
    """
    actor = make_user(session, "super_admin")
    candidate = make_user(session, from_role)

    previous = users_service.change_role(
        session, actor_id=str(actor.id), user=candidate, role="super_admin"
    )
    session.commit()

    assert previous == from_role
    assert candidate.role == "super_admin"
    assert active_super_admins(session) == 2


def test_promoting_a_second_admin_unblocks_the_refused_demotion(session: Session) -> None:
    """The recovery path, end to end.

    This is what the refusal message tells an administrator to do, so it is
    worth proving that doing it actually works rather than assuming.
    """
    sole = make_user(session, "super_admin")
    actor = make_user(session, "it_admin")

    with pytest.raises(problems.ProblemError):
        users_service.change_role(session, actor_id=str(actor.id), user=sole, role="auditor")
    session.rollback()

    successor = make_user(session, "it_admin")
    users_service.change_role(session, actor_id=str(actor.id), user=successor, role="super_admin")
    session.commit()

    # Now the original demotion is permitted.
    users_service.change_role(session, actor_id=str(actor.id), user=sole, role="auditor")
    session.commit()
    assert sole.role == "auditor"
    assert active_super_admins(session) == 1


def test_you_cannot_change_your_own_role(session: Session) -> None:
    actor = make_user(session, "super_admin")
    make_user(session, "super_admin")

    with pytest.raises(problems.ProblemError) as raised:
        users_service.change_role(session, actor_id=str(actor.id), user=actor, role="auditor")
    assert raised.value.code == "cannot_change_own_role"
    session.rollback()
    assert actor.role == "super_admin"


def test_the_self_check_precedes_the_last_super_admin_check_on_role_change(
    session: Session,
) -> None:
    sole = make_user(session, "super_admin")
    with pytest.raises(problems.ProblemError) as raised:
        users_service.change_role(session, actor_id=str(sole.id), user=sole, role="auditor")
    assert raised.value.code == "cannot_change_own_role"


def test_setting_the_role_an_account_already_holds_is_refused(session: Session) -> None:
    """A no-op change would otherwise write an audit entry recording nothing."""
    actor = make_user(session, "super_admin")
    target = make_user(session, "it_admin")

    with pytest.raises(problems.ProblemError) as raised:
        users_service.change_role(session, actor_id=str(actor.id), user=target, role="it_admin")
    assert raised.value.code == "role_unchanged"


def test_demoting_an_inactive_super_admin_is_allowed(session: Session) -> None:
    """It is not holding the system up, so removing its role changes nothing."""
    actor = make_user(session, "super_admin")
    dormant = make_user(session, "super_admin", active=False)
    assert active_super_admins(session) == 1

    users_service.change_role(session, actor_id=str(actor.id), user=dormant, role="auditor")
    session.commit()
    assert dormant.role == "auditor"


# --------------------------------------------------------------------------- #
# The lock, and the concurrent case
# --------------------------------------------------------------------------- #


def test_the_guard_counts_only_other_active_super_admins(session: Session) -> None:
    """The repository primitive, on its own.

    Four accounts: the target, another active super_admin, a disabled
    super_admin, and an it_admin. Only the second may be counted.
    """
    target = make_user(session, "super_admin")
    make_user(session, "super_admin")
    make_user(session, "super_admin", active=False)
    make_user(session, "it_admin")

    remaining = repositories.lock_active_super_admins(session, exclude_user_id=target.id)
    assert remaining == 1
    session.rollback()


def test_two_concurrent_disables_cannot_remove_both_super_admins(
    session: Session, session_factory: sessionmaker[Session]
) -> None:
    """The race the row lock exists to prevent. The important test in this file.

    Two super_admins, A and B. Two threads in separate transactions, each
    disabling the other's account at the same moment. With a plain `COUNT(*)`
    under PostgreSQL's default READ COMMITTED isolation, both would count one
    other active super_admin, neither would see the other's uncommitted write,
    both would commit, and the system would be left with zero administrators -
    unrecoverably, since `:enable` itself needs `manage_users`.

    `with_for_update()` serialises them: the second transaction blocks on the
    first's row lock, and when it proceeds it sees the committed change and
    refuses.

    The assertion is therefore not "both succeed" or "both fail" but "exactly
    one succeeded, and an active super_admin remains".
    """
    first = make_user(session, "super_admin")
    second = make_user(session, "super_admin")
    actor = make_user(session, "it_admin")
    assert active_super_admins(session) == 2

    first_id, second_id, actor_id = first.id, second.id, str(actor.id)

    def disable(target_id: uuid.UUID) -> str:
        """One whole transaction, on its own connection.

        `OperationalError` is caught and reported distinctly rather than
        allowed to propagate, because it is the specific regression this test
        found once already: locking only the *other* super_admins makes two
        concurrent callers hold what the other needs, PostgreSQL aborts one
        with `deadlock detected`, and the client gets a 500 instead of a 409.
        Naming it here means a reintroduction reads as "deadlock" rather than
        as an unrelated database error.
        """
        with session_factory() as worker:
            try:
                target = repositories.get_user(worker, target_id)
                assert target is not None
                users_service.disable(worker, actor_id=actor_id, user=target)
                worker.commit()
                return "disabled"
            except problems.ProblemError as exc:
                worker.rollback()
                return exc.code
            except OperationalError as exc:
                worker.rollback()
                return f"database error (lock ordering regression?): {type(exc.orig).__name__}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(disable, [first_id, second_id]))

    assert outcomes == ["cannot_disable_last_super_admin", "disabled"], (
        f"expected exactly one success and one clean 409 refusal, got {outcomes}"
    )

    session.rollback()
    assert active_super_admins(session) == 1, (
        "both concurrent disables took effect; the row lock is not working and the "
        "system would have been left with no administrator"
    )


def test_two_concurrent_demotions_cannot_remove_both_super_admins(
    session: Session, session_factory: sessionmaker[Session]
) -> None:
    """The same race through the role route, which shares the guard."""
    first = make_user(session, "super_admin")
    second = make_user(session, "super_admin")
    actor = make_user(session, "it_admin")
    assert active_super_admins(session) == 2

    actor_id = str(actor.id)

    def demote(target_id: uuid.UUID) -> str:
        with session_factory() as worker:
            try:
                target = repositories.get_user(worker, target_id)
                assert target is not None
                users_service.change_role(worker, actor_id=actor_id, user=target, role="auditor")
                worker.commit()
                return "demoted"
            except problems.ProblemError as exc:
                worker.rollback()
                return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(demote, [first.id, second.id]))

    assert outcomes == ["cannot_demote_last_super_admin", "demoted"], (
        f"expected exactly one success and one refusal, got {outcomes}"
    )

    session.rollback()
    assert active_super_admins(session) == 1


def test_a_concurrent_disable_and_demotion_cannot_remove_both(
    session: Session, session_factory: sessionmaker[Session]
) -> None:
    """Mixed operations contend on the same lock.

    Worth its own case: the two routes take different code paths to the guard,
    and a lock held by only one of them would leave this combination open.
    """
    first = make_user(session, "super_admin")
    second = make_user(session, "super_admin")
    actor = make_user(session, "it_admin")
    actor_id = str(actor.id)

    def disable_first() -> str:
        with session_factory() as worker:
            try:
                target = repositories.get_user(worker, first.id)
                assert target is not None
                users_service.disable(worker, actor_id=actor_id, user=target)
                worker.commit()
                return "ok"
            except problems.ProblemError as exc:
                worker.rollback()
                return exc.code

    def demote_second() -> str:
        with session_factory() as worker:
            try:
                target = repositories.get_user(worker, second.id)
                assert target is not None
                users_service.change_role(worker, actor_id=actor_id, user=target, role="auditor")
                worker.commit()
                return "ok"
            except problems.ProblemError as exc:
                worker.rollback()
                return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(disable_first), pool.submit(demote_second)]
        outcomes = sorted(future.result() for future in futures)

    assert outcomes.count("ok") == 1, f"expected exactly one success, got {outcomes}"
    session.rollback()
    assert active_super_admins(session) == 1


# --------------------------------------------------------------------------- #
# Enable, and what it restores
# --------------------------------------------------------------------------- #


def test_enabling_restores_the_account_and_clears_the_lockout(session: Session) -> None:
    """Both halves, because restoring only `is_active` is the subtle bug.

    An account can be locked by failed logins and then disabled by an
    administrator. Re-enabling without clearing `locked_until` hands back an
    account that still refuses the correct password, with no HTTP route able to
    clear it.
    """
    import datetime as dt

    user = make_user(session, "it_admin")
    repositories.set_user_lock(session, user, dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15))
    repositories.disable_user(session, user)
    session.commit()
    assert user.is_active is False
    assert user.locked_until is not None

    users_service.enable(session, user=user)
    session.commit()

    assert user.is_active is True
    assert user.locked_until is None, "the account came back still locked out"


def test_enabling_preserves_identity_history_and_password(session: Session) -> None:
    """The difference between enabling and recreating.

    The id is what every audit row points at, so an account that came back with
    a new id would orphan its own history.
    """
    user = make_user(session, "security_analyst")
    original_id, original_email = user.id, user.email
    original_hash, original_role = user.password_hash, user.role
    created = user.created_at

    repositories.disable_user(session, user)
    session.commit()
    users_service.enable(session, user=user)
    session.commit()

    assert user.id == original_id
    assert user.email == original_email
    assert user.password_hash == original_hash, "enabling changed the credential"
    assert user.role == original_role
    assert user.created_at == created


def test_enabling_an_active_account_is_refused(session: Session) -> None:
    user = make_user(session, "auditor")
    with pytest.raises(problems.ProblemError) as raised:
        users_service.enable(session, user=user)
    assert raised.value.code == "user_already_active"
    assert raised.value.status == 409


def test_enabling_does_not_issue_a_session(session: Session) -> None:
    """`:disable` revoked everything; enabling must not mint a credential."""
    user = make_user(session, "it_admin")
    repositories.disable_user(session, user)
    session.commit()

    users_service.enable(session, user=user)
    session.commit()

    live = int(
        session.execute(
            text("SELECT count(*) FROM auth_tokens WHERE user_id = :uid AND revoked_at IS NULL"),
            {"uid": user.id},
        ).scalar()
        or 0
    )
    assert live == 0, "enabling issued or un-revoked a session token"


# --------------------------------------------------------------------------- #
# Administrator password reset, at the service layer
# --------------------------------------------------------------------------- #


def test_a_reset_sets_the_flag_and_revokes_every_session(session: Session) -> None:
    user = make_user(session, "it_admin")
    repositories.issue_token_pair(session, user_id=user.id)
    repositories.issue_token_pair(session, user_id=user.id)
    session.commit()

    revoked = users_service.reset_password(
        session, user=user, password_hash=hash_password("a brand new passphrase")
    )
    session.commit()

    # Two pairs, each an access plus a refresh token.
    assert revoked == 4, f"expected 4 tokens revoked, got {revoked}"
    assert user.must_change_password is True
    live = int(
        session.execute(
            text("SELECT count(*) FROM auth_tokens WHERE user_id = :uid AND revoked_at IS NULL"),
            {"uid": user.id},
        ).scalar()
        or 0
    )
    assert live == 0


def test_a_reset_replaces_the_hash_and_keeps_the_account_active(session: Session) -> None:
    user = make_user(session, "auditor")
    original = user.password_hash

    users_service.reset_password(
        session, user=user, password_hash=hash_password("another long passphrase")
    )
    session.commit()

    assert user.password_hash != original
    assert user.is_active is True, "a reset must not disable the account"
    assert user.role == "auditor"


def test_resetting_the_last_super_admins_password_is_allowed(session: Session) -> None:
    """No guard applies: a reset does not reduce the number of super_admins.

    It is also the one thing that keeps a sole super_admin recoverable through
    the API when they have forgotten their password but another administrator
    has not.
    """
    sole = make_user(session, "super_admin")
    assert active_super_admins(session) == 1

    users_service.reset_password(
        session, user=sole, password_hash=hash_password("yet another passphrase")
    )
    session.commit()

    assert sole.must_change_password is True
    assert active_super_admins(session) == 1
