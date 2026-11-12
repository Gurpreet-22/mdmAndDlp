"""Live check that `GET /users` orders newest-first and honours `?q=`.

Written as a script rather than a test because it answers a different question:
the tests prove the code is correct, this proves the *running* process has it.
A uvicorn started without `--reload` keeps serving the old module after an edit,
and the symptom - a search box that returns nothing - looks like a code bug.

Takes credentials on the command line; nothing is hardcoded. Prints the account
state the operator needs in order to decide what to disable next.

    python tools/check_user_search.py --email you@example.org --password '...' \
        --find gurpreetdev --find phase2-check
"""

from __future__ import annotations

import argparse
import getpass
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def call(
    base: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    token: str | None = None,
    query: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    url = base + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    context = ssl.create_default_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return error.code, raw.decode("utf-8", "replace")
    except urllib.error.URLError as error:
        print(f"error: cannot reach {url}: {error.reason}", file=sys.stderr)
        raise SystemExit(2) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="an account with manage_users")
    parser.add_argument("--password", help="prompted for if omitted, which keeps it out of history")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--find",
        action="append",
        default=[],
        metavar="SUBSTRING",
        help="Search term to check. Repeatable.",
    )
    arguments = parser.parse_args()

    password = arguments.password or getpass.getpass(f"Password for {arguments.email}: ")
    base = arguments.api.rstrip("/") + "/api/v1"

    status, body = call(base, "POST", "/auth/login", {"email": arguments.email, "password": password})
    if status != 200:
        print(f"login failed as {arguments.email}: HTTP {status} {body}", file=sys.stderr)
        return 1
    token = body["access_token"]

    failures = 0
    stale = False

    # 1. Is the filter actually applied? Checked by behaviour rather than by
    #    reading /openapi.json, which a deployment may not expose. An API that
    #    predates the change ignores an unknown query parameter and returns the
    #    unfiltered page, so a row whose address does not contain the term is
    #    proof the parameter did nothing.
    probe = "zzz-no-account-has-this-substring"
    status, rows = call(base, "GET", "/users", token=token, query={"q": probe})
    if status != 200:
        failures += 1
        print(f"search applied             FAIL HTTP {status}: {rows}")
    elif rows:
        failures += 1
        stale = True
        print(f"search applied             FAIL ignored; got {len(rows)} rows for a term")
        print("                                that matches no address.")
    else:
        print("search applied             OK   unmatched term returns nothing")

    # 2. Newest first, verified against the timestamps rather than assumed.
    status, page = call(base, "GET", "/users", token=token, query={"limit": 25})
    if status != 200:
        failures += 1
        print(f"newest-first order         FAIL HTTP {status}: {page}")
    elif len(page) < 2:
        print(f"newest-first order         ---- only {len(page)} account(s), nothing to order")
    else:
        stamps = [row["created_at"] for row in page]
        if stamps == sorted(stamps, reverse=True):
            print(f"newest-first order         OK   newest is {page[0]['email']}")
        else:
            failures += 1
            stale = True
            print(f"newest-first order         FAIL oldest-first; top is {page[0]['email']}")

    if stale:
        print()
        print("The running API is serving code from before this change.")
        print("Stop uvicorn (Ctrl+C in its terminal) and start it again.")
        print()

    # 3. Each requested term, and what it found.
    for term in arguments.find:
        status, rows = call(base, "GET", "/users", token=token, query={"q": term})
        if status != 200:
            failures += 1
            print(f"search {term!r:28} FAIL HTTP {status}: {rows}")
            continue
        unrelated = [row["email"] for row in rows if term.lower() not in row["email"]]
        if unrelated:
            failures += 1
            print(f"search {term!r:28} FAIL returned {len(unrelated)} unrelated row(s)")
            continue
        if not rows:
            print(f"search {term!r:28} ---- no account matches")
            continue
        print(f"search {term!r:28} OK   {len(rows)} match(es)")
        for row in rows:
            state = "active" if row["is_active"] else "disabled"
            print(f"        {row['email']:42} {row['role']:16} {state}")

    print()
    print("all checks passed" if failures == 0 else f"{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
