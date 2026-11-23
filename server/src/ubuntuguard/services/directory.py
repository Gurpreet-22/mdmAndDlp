"""Microsoft Entra ID employee lookup, read-only.

Why this exists: an administrator minting an enrollment token already knows
whose laptop it is, and the company already maintains that list in Entra.
Retyping a name and an address into the dashboard produces typos, duplicate
employee rows that differ by a capital letter, and devices that sit unassigned.
Reading the directory removes the typing.

Four things worth knowing about the shape of this module.

It is a directory *lookup*, not sign-in. The app credential here can read user
profiles and nothing else; who may log in to the dashboard is still decided by
`Settings.allow_any_login` and the users table. Confusing the two would turn a
read-only Graph permission into an authentication path.

Nothing is written to the database. A directory entry becomes an `employees`
row only when an administrator actually assigns a device, which keeps our table
a record of who has hardware rather than a stale mirror of all 117 accounts in
the tenant.

The whole member list is fetched and filtered in Python, not through Graph's
`$filter`/`$search`. At this size - roughly a hundred accounts - a cached list
costs one request a few times an hour, while interpolating an admin's search
text into an OData filter expression means escaping quotes correctly forever.
Not building the injection vector is cheaper than defending it.

Failures are reported, never guessed at. An expired client secret, a missing
admin consent and an unconfigured tenant are three different problems with
three different fixes, so they raise three different messages instead of one
empty list that looks like "no employees found".
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
from dataclasses import dataclass

import httpx

from ubuntuguard.config import Settings

logger = logging.getLogger(__name__)

#: Graph's maximum page size for /users. Fewer round trips for a tenant that
#: outgrows a single page.
_PAGE_SIZE = 999

#: Hard ceiling on pages walked, so a pathological nextLink chain cannot hang a
#: request thread indefinitely. 20 pages is ~20k accounts.
_MAX_PAGES = 20

#: Re-fetch the member list this often. Long enough that typing in the picker
#: does not hammer Graph, short enough that a new joiner appears the same
#: morning. Joiners are rare; a stale entry is recoverable by manual entry.
_USER_CACHE_TTL = dt.timedelta(minutes=10)

#: Treat an access token as expired this long before it really is, so a token
#: that is valid when we check cannot expire in flight.
_TOKEN_EXPIRY_MARGIN = dt.timedelta(seconds=60)

_HTTP_TIMEOUT = httpx.Timeout(15.0, connect=10.0)

#: Exactly the profile fields the picker shows. Requesting a narrow $select
#: keeps the payload small and means a future Graph addition cannot quietly
#: start arriving.
_USER_FIELDS = (
    "id",
    "displayName",
    "mail",
    "userPrincipalName",
    "department",
    "jobTitle",
    "accountEnabled",
    "userType",
)

#: Guests are excluded. In this tenant 24 of 117 accounts are guests on
#: gmail.com, amazon.com and partner domains: contractors and external
#: collaborators, not staff holding company laptops. Offering them in an
#: employee picker invites assigning a managed device to somebody outside the
#: company. Disabled accounts are excluded for the same reason - a leaver
#: should not be a valid assignee.
_MEMBER_FILTER = "userType eq 'Member' and accountEnabled eq true"


class DirectoryError(RuntimeError):
    """A directory lookup could not be completed.

    Carries a message meant for an administrator's screen, because every cause
    has a different fix and "lookup failed" sends them nowhere.
    """


class DirectoryNotConfiguredError(DirectoryError):
    """No Entra credentials are set. Not an error: manual entry still works."""


@dataclass(frozen=True, slots=True)
class DirectoryUser:
    """One person as the directory describes them.

    `external_id` is Entra's object id. It is carried so a future sync can
    recognise somebody whose address changed, which an email-keyed match
    cannot.
    """

    external_id: str
    full_name: str
    email: str
    department: str | None
    job_title: str | None

    def matches(self, needle: str) -> bool:
        """Substring match on name, address and department, case-insensitively.

        Substring rather than prefix: an admin searching "sharma" should find
        "Rishav Sharma", and a prefix match would not.
        """
        return (
            needle in self.full_name.lower()
            or needle in self.email.lower()
            or (self.department is not None and needle in self.department.lower())
        )


@dataclass
class _CachedToken:
    value: str
    expires_at: dt.datetime


@dataclass
class _CachedUsers:
    value: tuple[DirectoryUser, ...]
    fetched_at: dt.datetime


class EntraDirectory:
    """Reads employees from one Entra tenant, with both responses cached.

    Safe to share across request threads: a lock guards both caches, so a burst
    of keystrokes in the picker produces one Graph call rather than one per
    request.
    """

    def __init__(self, settings: Settings, *, client: httpx.Client | None = None) -> None:
        self._settings = settings
        # Injectable so tests can drive this against a transport stub. Real
        # callers let it build its own, since the client must outlive a request
        # to keep connections warm.
        self._client = client
        self._lock = threading.Lock()
        self._token: _CachedToken | None = None
        self._users: _CachedUsers | None = None

    # --- Public API -------------------------------------------------------- #

    @property
    def configured(self) -> bool:
        return self._settings.entra_configured

    def search(self, query: str | None = None, *, limit: int = 25) -> list[DirectoryUser]:
        """Employees matching `query`, or the first `limit` of them if it is empty.

        Raises `DirectoryNotConfiguredError` when no credentials are set, so the
        caller can offer manual entry rather than reporting a failure.
        """
        users = self._members()
        needle = (query or "").strip().lower()
        if needle:
            users = tuple(user for user in users if user.matches(needle))
        return list(users[:limit])

    def find_by_email(self, email: str) -> DirectoryUser | None:
        """Exact address match, used to fill in a token's employee details."""
        wanted = email.strip().lower()
        return next((user for user in self._members() if user.email == wanted), None)

    def invalidate(self) -> None:
        """Drop both caches. For an explicit "refresh" action and for tests."""
        with self._lock:
            self._token = None
            self._users = None

    # --- Internals --------------------------------------------------------- #

    def _require_configured(self) -> tuple[str, str, str]:
        settings = self._settings
        if (
            settings.entra_tenant_id is None
            or settings.entra_client_id is None
            or settings.entra_client_secret is None
        ):
            raise DirectoryNotConfiguredError(
                "Microsoft Entra ID is not configured. Set UBUNTUGUARD_ENTRA_TENANT_ID, "
                "UBUNTUGUARD_ENTRA_CLIENT_ID and UBUNTUGUARD_ENTRA_CLIENT_SECRET to enable "
                "employee lookup."
            )
        return (
            settings.entra_tenant_id,
            settings.entra_client_id,
            settings.entra_client_secret.get_secret_value(),
        )

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=_HTTP_TIMEOUT)
        return self._client

    def _access_token(self) -> str:
        """A valid app-only access token, minted on demand and reused until stale."""
        now = dt.datetime.now(dt.UTC)
        with self._lock:
            cached = self._token
            if cached is not None and cached.expires_at - _TOKEN_EXPIRY_MARGIN > now:
                return cached.value

        tenant_id, client_id, client_secret = self._require_configured()
        url = f"{self._settings.entra_authority.rstrip('/')}/{tenant_id}/oauth2/v2.0/token"
        try:
            response = self._http().post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    # .default means "every application permission already
                    # consented to for this app", which is how the client
                    # credentials flow works. Asking for User.Read.All by name
                    # here is rejected.
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
        except httpx.HTTPError as exc:
            raise DirectoryError(f"Could not reach Microsoft Entra ID at {url}: {exc}") from exc

        if response.status_code != 200:
            raise DirectoryError(self._describe_token_failure(response))

        payload = response.json()
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise DirectoryError("Entra ID returned no access token.")
        # Graph tokens last an hour. Default low rather than high if the field
        # is ever missing: a short cache costs a request, a long one serves 401s.
        expires_in = payload.get("expires_in")
        lifetime = int(expires_in) if isinstance(expires_in, (int, str)) else 300

        with self._lock:
            self._token = _CachedToken(value=token, expires_at=now + dt.timedelta(seconds=lifetime))
        return token

    @staticmethod
    def _describe_token_failure(response: httpx.Response) -> str:
        """Turn Entra's error codes into the action that fixes them.

        The raw `error_description` is a wall of text with a correlation id and
        a timestamp. The first line carries the AADSTS code, which is the part
        that identifies the problem.
        """
        try:
            body = response.json()
        except ValueError:
            body = {}
        code = body.get("error", "")
        description = str(body.get("error_description", "")).splitlines()
        first_line = description[0] if description else response.text[:200]
        # Entra appends "Trace ID: ... Correlation ID: ... Timestamp: ..." to the
        # first line. Useful to Microsoft support, noise on an admin's screen,
        # and it pushes the actual sentence out of a truncated message.
        for noise in (" Trace ID:", " Correlation ID:", " Timestamp:"):
            first_line = first_line.split(noise)[0]
        first_line = first_line.strip()

        if "AADSTS7000215" in first_line or code == "invalid_client":
            hint = (
                "The client secret is wrong or has expired. Entra secrets expire, so check "
                "Certificates & secrets and paste the secret Value - not the Secret ID - into "
                "UBUNTUGUARD_ENTRA_CLIENT_SECRET."
            )
        elif "AADSTS700016" in first_line or "AADSTS700038" in first_line:
            # 700016: a well-formed client id that no app in this tenant owns.
            # 700038: not a GUID at all, usually a half-pasted value.
            hint = (
                "That client id is not an application in this tenant. Check "
                "UBUNTUGUARD_ENTRA_CLIENT_ID is the Application (client) ID from the app "
                "registration's Overview, and that it belongs to UBUNTUGUARD_ENTRA_TENANT_ID."
            )
        elif "AADSTS90002" in first_line:
            hint = "That tenant does not exist. Check UBUNTUGUARD_ENTRA_TENANT_ID."
        else:
            hint = first_line

        return f"Entra ID rejected the credentials ({response.status_code}): {hint}"

    def _members(self) -> tuple[DirectoryUser, ...]:
        """The cached member list, re-fetched when it goes stale."""
        now = dt.datetime.now(dt.UTC)
        with self._lock:
            cached = self._users
            if cached is not None and now - cached.fetched_at < _USER_CACHE_TTL:
                return cached.value

        users = self._fetch_members()

        with self._lock:
            self._users = _CachedUsers(value=users, fetched_at=now)
        return users

    def _fetch_members(self) -> tuple[DirectoryUser, ...]:
        token = self._access_token()
        client = self._http()
        url: str | None = f"{self._settings.entra_graph_base_url.rstrip('/')}/users"
        params: dict[str, str] | None = {
            "$select": ",".join(_USER_FIELDS),
            "$filter": _MEMBER_FILTER,
            "$top": str(_PAGE_SIZE),
        }
        headers = {"Authorization": f"Bearer {token}"}

        collected: list[DirectoryUser] = []
        skipped_without_email = 0
        for _ in range(_MAX_PAGES):
            if url is None:
                break
            try:
                response = client.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise DirectoryError(f"Could not reach Microsoft Graph: {exc}") from exc

            if response.status_code != 200:
                raise DirectoryError(self._describe_graph_failure(response))

            body = response.json()
            for entry in body.get("value", []):
                user = _to_directory_user(entry)
                if user is None:
                    skipped_without_email += 1
                    continue
                collected.append(user)
            # The nextLink already carries every query parameter, so re-sending
            # ours would duplicate them and Graph would reject the request.
            url = body.get("@odata.nextLink")
            params = None
        else:
            logger.warning(
                "stopped paging Microsoft Graph at %d pages; the employee list may be incomplete",
                _MAX_PAGES,
            )

        if skipped_without_email:
            # Not an error. Some accounts legitimately have no mailbox; they
            # just cannot be matched to an employee row, which is keyed by email.
            logger.info("skipped %d Entra account(s) with no email address", skipped_without_email)

        collected.sort(key=lambda user: user.full_name.casefold())
        return tuple(collected)

    @staticmethod
    def _describe_graph_failure(response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            body = {}
        error = body.get("error", {}) if isinstance(body.get("error"), dict) else {}
        message = str(error.get("message", response.text[:200]))

        if response.status_code == 403:
            return (
                "Microsoft Graph refused the request (403). The app registration most likely "
                "lacks the User.Read.All application permission, or nobody has clicked "
                "'Grant admin consent' for it. Graph reported: " + message
            )
        if response.status_code == 401:
            return "Microsoft Graph rejected the access token (401). Graph reported: " + message
        return f"Microsoft Graph returned {response.status_code}: {message}"


def _to_directory_user(entry: dict[str, object]) -> DirectoryUser | None:
    """Map one Graph user, or None if it cannot be used as an employee.

    An entry needs an address and a name to be useful: `employees.email` is the
    natural key used to match or create a row, and a picker row with no label
    is unclickable. `mail` is preferred over `userPrincipalName` because a UPN
    can be an `.onmicrosoft.com` address that does not receive mail, but the
    UPN is a reasonable fallback when no mailbox is provisioned.
    """
    raw_email = entry.get("mail") or entry.get("userPrincipalName")
    email = raw_email.strip().lower() if isinstance(raw_email, str) and raw_email.strip() else None
    if email is None:
        return None

    display = entry.get("displayName")
    full_name = display.strip() if isinstance(display, str) and display.strip() else email

    external_id = entry.get("id")
    if not isinstance(external_id, str) or not external_id:
        return None

    def optional(key: str) -> str | None:
        value = entry.get(key)
        return value.strip() if isinstance(value, str) and value.strip() else None

    return DirectoryUser(
        external_id=external_id,
        # employees.full_name and employees.email are String(120)/String(320).
        # Truncating here keeps an unusually long display name from turning
        # into a database error at assignment time.
        full_name=full_name[:120],
        email=email[:320],
        department=(optional("department") or None),
        job_title=(optional("jobTitle") or None),
    )
