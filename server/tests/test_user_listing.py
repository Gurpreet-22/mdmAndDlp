"""`GET /api/v1/users` ordering and search.

These exist because of a real failure, not a hypothetical one. The route was
capped at one page and ordered oldest-first, and on a deployment carrying a few
thousand accounts the effect was that the Administrators page showed only the
oldest rows: the operator's own account, created minutes earlier, was not in
the list, and neither were the two accounts they had opened the page to
disable. Browsing could not reach them and there was no way to ask for them by
name, so an account that existed read as an account that did not.

`test_a_brand_new_account_is_reachable` is the regression test for that. It
deliberately uses `limit=1`, which makes it independent of how many rows the
database happens to hold: under the old ordering it returns the oldest account
in the table, under the correct one it returns the account just created.

Skipped with an explanation when no database is configured.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ubuntuguard.config import Settings
from ubuntuguard.main import create_app
from ubuntuguard.schemas import MAX_EMAIL_LENGTH
from ubuntuguard.security.rbac import Role

pytestmark = pytest.mark.postgres

SERVER_DIR = Path(__file__).resolve().parents[1]
PASSWORD = "a reasonably long passphrase"


def _env_from_file() -> dict[str, str]:
    env_file = SERVER_DIR / ".env"
    if not env_file.exists():
        pytest.skip("server/.env is missing. Create it with: ./scripts/dev_db.sh up")
    values: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("UBUNTUGUARD_") and "=" in line:
            name, _, value = line.partition("=")
            values[name.removeprefix("UBUNTUGUARD_").lower()] = value.strip()
    return values


@pytest.fixture(scope="module")
def app() -> Iterator[FastAPI]:
    values = _env_from_file()
    if "database_url" not in values:
        pytest.skip("no database URL in server/.env")
    # Real password authentication, for the same reason the integration suite
    # does this: a developer with ALLOW_ANY_LOGIN=1 in their .env would
    # otherwise see `login` behave in a way unrelated to the code under test.
    values["allow_any_login"] = "false"
    try:
        settings = Settings(_env_file=None, **values)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 - configuration problem, report as skip
        pytest.skip(f"could not build settings from server/.env: {exc}")

    application = create_app(settings)
    with TestClient(application):
        pass
    if getattr(application.state, "session_factory", None) is None:
        pytest.skip("database unreachable; is the cluster running?")
    if getattr(application.state, "keys", None) is None:
        pytest.skip("key material missing. Run: python -m ubuntuguard.cli init-keys")
    yield application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, client=("127.0.0.1", 54321)) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _create(app: FastAPI, email: str, role: Role = Role.IT_ADMIN) -> None:
    """Create one account in its own transaction.

    One transaction per account on purpose: `created_at` defaults to
    PostgreSQL's `now()`, which is the transaction start time, so accounts
    created inside a single transaction share a timestamp exactly. Tests that
    assert on ordering need distinct timestamps; the test that asserts the
    tiebreaker works needs identical ones and creates them together.
    """
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import create_user
    from ubuntuguard.security.passwords import hash_password

    with session_scope(app.state.session_factory) as session:
        create_user(session, email=email, password_hash=hash_password(PASSWORD), role=role.value)


def _create_together(app: FastAPI, *emails: str) -> None:
    """Create several accounts in ONE transaction, so `created_at` is equal."""
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import create_user
    from ubuntuguard.security.passwords import hash_password

    with session_scope(app.state.session_factory) as session:
        for email in emails:
            create_user(
                session,
                email=email,
                password_hash=hash_password(PASSWORD),
                role=Role.IT_ADMIN.value,
            )


def _super_admin_headers(app: FastAPI, client: TestClient) -> dict[str, str]:
    email = f"super_admin-{uuid.uuid4().hex[:8]}@example.invalid"
    _create(app, email, Role.SUPER_ADMIN)
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _marker() -> str:
    """A token that appears in no other account's address."""
    return uuid.uuid4().hex[:12]


def _emails(response: object) -> list[str]:
    assert isinstance(response, list)
    return [str(row["email"]) for row in response]


# --------------------------------------------------------------------------- #
# The regression
# --------------------------------------------------------------------------- #


def test_a_brand_new_account_is_reachable(app: FastAPI, client: TestClient) -> None:
    """The newest account is on the first page, whatever the table holds.

    `limit=1` is what makes this independent of the size of the database: the
    response has room for exactly one account, so it can only pass if the
    ordering puts the newest first.
    """
    headers = _super_admin_headers(app, client)
    marker = _marker()
    newest = f"newest-{marker}@example.invalid"
    _create(app, newest)

    response = client.get("/api/v1/users", headers=headers, params={"limit": 1})

    assert response.status_code == 200, response.text
    assert _emails(response.json()) == [newest]


def test_an_account_behind_a_full_page_is_reachable_by_search(
    app: FastAPI, client: TestClient
) -> None:
    """Search reaches an account that paging alone has buried.

    The account is created first, then enough newer accounts to fill the
    requested page, so it is genuinely off the first page by the time it is
    looked for. This is the other half of the fix: ordering alone only helps
    the most recent rows.
    """
    headers = _super_admin_headers(app, client)
    marker = _marker()
    buried = f"buried-{marker}@example.invalid"
    _create(app, buried)
    for index in range(3):
        _create(app, f"newer-{index}-{marker}@example.invalid")

    unsearched = client.get("/api/v1/users", headers=headers, params={"limit": 3})
    assert unsearched.status_code == 200, unsearched.text
    assert buried not in _emails(unsearched.json()), "precondition: should be off the page"

    found = client.get("/api/v1/users", headers=headers, params={"q": f"buried-{marker}"})
    assert found.status_code == 200, found.text
    assert _emails(found.json()) == [buried]


# --------------------------------------------------------------------------- #
# Ordering
# --------------------------------------------------------------------------- #


def test_results_are_newest_first(app: FastAPI, client: TestClient) -> None:
    headers = _super_admin_headers(app, client)
    marker = _marker()
    # Named so that creation order and alphabetical order disagree: if the
    # route fell back to sorting by address this would still fail.
    first = f"c-first-{marker}@example.invalid"
    second = f"b-second-{marker}@example.invalid"
    third = f"a-third-{marker}@example.invalid"
    for email in (first, second, third):
        _create(app, email)

    response = client.get("/api/v1/users", headers=headers, params={"q": marker})

    assert response.status_code == 200, response.text
    assert _emails(response.json()) == [third, second, first]


def test_equal_timestamps_order_deterministically(app: FastAPI, client: TestClient) -> None:
    """Accounts sharing a `created_at` come back in a stable order.

    Scripted account creation produces batches with an identical timestamp.
    Without the secondary sort their relative order is whatever the database
    returns, which makes both paging and these tests non-deterministic.
    """
    headers = _super_admin_headers(app, client)
    marker = _marker()
    together = [
        f"c-{marker}@example.invalid",
        f"a-{marker}@example.invalid",
        f"b-{marker}@example.invalid",
    ]
    _create_together(app, *together)

    first = client.get("/api/v1/users", headers=headers, params={"q": marker})
    second = client.get("/api/v1/users", headers=headers, params={"q": marker})

    assert first.status_code == 200, first.text
    assert _emails(first.json()) == sorted(together)
    assert _emails(first.json()) == _emails(second.json())


# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #


def test_search_matches_any_part_of_the_address(app: FastAPI, client: TestClient) -> None:
    headers = _super_admin_headers(app, client)
    marker = _marker()
    email = f"middle-{marker}-tail@example.invalid"
    _create(app, email)

    for term in (f"middle-{marker}", marker, f"{marker}-tail"):
        response = client.get("/api/v1/users", headers=headers, params={"q": term})
        assert response.status_code == 200, response.text
        assert _emails(response.json()) == [email], f"searching for {term!r}"


def test_search_ignores_case(app: FastAPI, client: TestClient) -> None:
    """Addresses are stored lowercased, so a typed capital must still match."""
    headers = _super_admin_headers(app, client)
    marker = _marker()
    email = f"casing-{marker}@example.invalid"
    _create(app, email)

    response = client.get(
        "/api/v1/users", headers=headers, params={"q": f"CASING-{marker.upper()}"}
    )

    assert response.status_code == 200, response.text
    assert _emails(response.json()) == [email]


def test_search_with_no_match_is_empty_not_everything(app: FastAPI, client: TestClient) -> None:
    """A failed search must not silently degrade into an unfiltered list."""
    headers = _super_admin_headers(app, client)

    response = client.get(
        "/api/v1/users", headers=headers, params={"q": f"no-such-account-{_marker()}"}
    )

    assert response.status_code == 200, response.text
    assert response.json() == []


def test_blank_search_is_treated_as_no_search(app: FastAPI, client: TestClient) -> None:
    """An empty or whitespace `q` lists accounts rather than matching nothing."""
    headers = _super_admin_headers(app, client)
    _create(app, f"blank-{_marker()}@example.invalid")

    for term in ("", "   "):
        response = client.get("/api/v1/users", headers=headers, params={"q": term, "limit": 5})
        assert response.status_code == 200, response.text
        assert _emails(response.json()) != [], f"q={term!r} should not filter everything out"


def test_search_metacharacters_are_data(app: FastAPI, client: TestClient) -> None:
    """A quote or a comment marker in `q` is matched, not executed.

    The value is bound as a parameter, so the worst a `%` can do is widen the
    match. These terms appear in no address, so each must come back empty
    rather than erroring or returning the table.
    """
    headers = _super_admin_headers(app, client)

    for term in ("' OR 1=1 --", '" OR ""="', "'; DROP TABLE users; --", "\\"):
        response = client.get("/api/v1/users", headers=headers, params={"q": term})
        assert response.status_code == 200, f"{term!r}: {response.text}"
        assert response.json() == [], f"{term!r} should match no address"

    # Still a live table afterwards.
    survived = client.get("/api/v1/users", headers=headers, params={"limit": 1})
    assert survived.status_code == 200, survived.text
    assert len(survived.json()) == 1


def test_search_longer_than_an_address_is_rejected(app: FastAPI, client: TestClient) -> None:
    """Bounded at the route, so the pattern cannot be made arbitrarily large."""
    headers = _super_admin_headers(app, client)

    response = client.get(
        "/api/v1/users", headers=headers, params={"q": "x" * (MAX_EMAIL_LENGTH + 1)}
    )

    assert response.status_code == 422, response.text


def test_search_still_requires_manage_users(app: FastAPI, client: TestClient) -> None:
    """The new parameter does not open a way around the capability gate."""
    email = f"it_admin-{uuid.uuid4().hex[:8]}@example.invalid"
    _create(app, email, Role.IT_ADMIN)
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    response = client.get("/api/v1/users", headers=headers, params={"q": "anything"})

    assert response.status_code == 403, response.text


def test_search_is_unauthenticated_nowhere(client: TestClient) -> None:
    """No token, no listing, with or without a search term."""
    assert client.get("/api/v1/users", params={"q": "anything"}).status_code == 401
    assert client.get("/api/v1/users").status_code == 401
