# UbuntuGuard

Prototype MDM + DLP platform for company Ubuntu laptops. Three components: a central
API server, an admin dashboard, and an agent that enrolls, reports inventory, applies
signed policies, and enforces the first data-protection control — blocking
unauthorized USB storage.

**Phases 1 and 3 complete: 18 endpoints and a working dashboard, against a live PostgreSQL 18.**

> **Scope discipline.** Monitoring is not prevention. Nothing in this repo claims a
> control works until a test proves it, and anything unproven is labelled
> `UNVALIDATED`. A local root user can bypass the agent: this product offers
> detection and response, not a guarantee.

## Where things are

| Path | What it is | Status |
|---|---|---|
| `docs/00-threat-model.md` | Assets, trust boundaries, adversaries, 18 threats mapped to controls and to the test that will prove each one | design |
| `docs/01-api-contract.md` | Endpoints, the two auth planes, error model, RBAC matrix, online/offline and revocation semantics | **needs your sign-off on the RBAC matrix** |
| `docs/02-policy-and-signing.md` | Envelope format, the normative signing input, key separation, settings bounds, apply/verify/rollback lifecycle | design |
| `docs/03-decisions-and-conflicts.md` | Conflicts with the brief, decisions taken with rationale, open questions | **read this first** |
| `schemas/*.schema.json` | JSON Schema 2020-12 for the envelope, both policy types, inventory and events | validated |
| `schemas/examples/` | Valid and invalid documents, with a manifest tying each rejection to a threat | validated |
| `testdata/policy_vectors.json` | Cross-language Ed25519 signing vector: one positive, three negatives | Python side passes; **Go side lands in Phase 4** |
| `spike/usbguard/` | The USBGuard enforcement spike: guarded script, run order, GO/NO-GO rule, results template | **NOT YET RUN — needs an Ubuntu 22.04/24.04 machine** |
| `tools/validate_phase0.py` | The Phase 0 test gate | 40 checks passing |
| `server/src/ubuntuguard/constants.py` | Security invariants (not configurable) and tunable bounds | 25 tests |
| `server/src/ubuntuguard/canonical.py` | Length-prefixed encoding shared by signing and the audit chain | 8 tests |
| `server/src/ubuntuguard/security/rbac.py` | Fully enumerated role matrix, validated at import | 63 tests |
| `server/src/ubuntuguard/security/passwords.py` | Argon2id, with timing equalisation and a DoS bound | 15 tests |
| `server/src/ubuntuguard/security/tokens.py` | Opaque session and enrollment tokens | 13 tests |
| `server/src/ubuntuguard/security/lockout.py` | Login lockout decision, pure function | 13 tests |
| `server/src/ubuntuguard/services/audit_chain.py` | Hash-chained append-only audit log | 18 tests |
| `server/src/ubuntuguard/services/ca.py` | Internal CA for device certificates | 32 tests |
| `server/src/ubuntuguard/services/policy_signing.py` | Ed25519 envelope signing, checked against the committed vector | 28 tests |

Phase 2 adds `agent/`, Phase 3 `dashboard/`. Still to come before Phase 2: the
admin and device routers, and the enrollment API.

## Run it

Three processes: PostgreSQL, the API, and the dashboard.

```bash
# --- one-time setup ------------------------------------------------------
make setup                           # two Python virtualenvs on CPython 3.12
python3 tools/install_toolchain.py   # Go + Node under ~/.local, no sudo

# Put ~/.local/bin on PATH for interactive shells. Ubuntu's ~/.profile already
# does this, but only for LOGIN shells and only if the directory existed when
# you logged in, so a terminal opened before the install will not see node.
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && . ~/.bashrc

cd dashboard && npm install && cd ..

make bootstrap                       # PostgreSQL on port 55432 + CA + signing key
# You pick the address and the role. Valid roles:
#   super_admin  it_admin  security_analyst  auditor
make admin EMAIL=<your-email> ROLE=<your-role>   # password generated, shown once
```

```bash
# --- terminal 1: the database, if not already running --------------------
cd server && ./scripts/dev_db.sh start
```

```bash
# --- terminal 2: the API -------------------------------------------------
cd server
.venv/bin/python -m uvicorn ubuntuguard.main:create_app --factory --host 127.0.0.1 --port 8000 --no-proxy-headers
```

```bash
# --- terminal 3: the dashboard -------------------------------------------
cd dashboard && npm run dev          # http://127.0.0.1:5173
```

```bash
# --- optional: 50 simulated devices so the UI has something to show ------
./tools/seed_devices.py --email '<your-email>' \
    --password '<your-password>' --count 50
```

Then open **http://127.0.0.1:5173**.

### Signing in

`server/.env` ships with authentication switched off:

```
UBUNTUGUARD_ALLOW_ANY_LOGIN=1
```

Type any email and any password. The account is created the first time its
address is used, gets `super_admin`, and your password is never read, compared
or stored. The login page says so in a banner, `/readyz` reports a warning, and
the server logs one on every startup.

This is a placeholder until Microsoft SSO (Entra ID) is wired in. SSO replaces
only this step: the local `users` row, the RBAC matrix, session tokens and the
audit actor are all still needed, because Entra can say who someone is but not
whether they may revoke a device.

Two things make it safe to leave in the tree:

- **Production cannot start with it on.** A config validator raises, so the
  setting cannot reach a server by someone copying a dev `.env`.
- **Accounts it creates become unreachable, not open.** Their stored hash is
  Argon2id over 32 random bytes that are immediately discarded, so once the flag
  is off no password can ever verify against them.

To get real password authentication back, delete that line from `server/.env`
and restart the API. Then create an account explicitly:

```bash
cd server
.venv/bin/python -m ubuntuguard.cli create-admin --email '<your-email>' --role <role>
```

### If `npm: command not found`

`~/.local/bin` is not on your PATH. Run the `~/.bashrc` line above, or log out
and back in — Ubuntu's `~/.profile` adds that directory, but only at login and
only if it already exists.

Nothing in this project depends on it: `make` resolves `npm` and `go` to
absolute paths, and the launchers in `~/.local/bin` are wrapper scripts that put
the toolchain on PATH themselves, so `$HOME/.local/bin/npm run dev` always
works. Check the toolchain with:

```bash
python3 tools/install_toolchain.py --check
```

That now *runs* each tool and requires output, rather than only checking the
file exists — an earlier version reported a healthy `npm` whose version string
was blank, which is how a broken wrapper went unnoticed.

### Why the dashboard proxies to the API

Vite proxies `/api` to `127.0.0.1:8000` rather than letting the browser call the
API directly. That is not convenience. The refresh token is an httpOnly cookie
with `SameSite=Strict`, so it is only sent on same-origin requests; a page
served from `:5173` calling `:8000` would be cross-origin, the cookie would
never be sent, and session refresh would silently never work. It also matches
the intended deployment, where nginx serves the built assets and the API under
one origin.

### What the UI does

Sign in; browse devices with search and filters on hostname, status, Ubuntu
version and agent version; open a device for its certificate and inventory;
revoke it with a reason; create and revoke enrollment tokens; read and verify
the audit log.

Online is computed by the server from the last heartbeat it received, never
self-reported, and the last-seen timestamp sits beside it so "online" is never a
bare claim. Navigation is filtered by the signed-in role's capabilities, so an
`auditor` sees no Enrollment tab — but that is cosmetic, because the server
checks every request independently.

### Driving the API without a browser

```bash
./tools/demo_api.py --email '<your-email>' \
    --password '<the password make admin printed>'
```

That logs in, mints an enrollment token, enrolls a device with its own keypair,
heartbeats over mTLS headers, revokes the device, and verifies the audit chain -
attacking each step so you can watch the refusals. It uses only the standard
library for HTTP, so **no curl needed** (this machine has none).

If you do have curl, or use wget:

```bash
wget -qO- http://127.0.0.1:8000/readyz
# {"status":"ready","checks":{"database":"ok","keys":"ok","audit_append_only":"ok"}}
```

`/readyz` checks three things, not one: the database is reachable, key material
is loaded, and the connected role still lacks `UPDATE`/`DELETE` on `audit_logs`.
The last two exist because a server with no signing key cannot complete an
enrollment, and because the append-only guarantee lives in the database GRANTs
rather than in application code, so a deployment can lose it with nothing
raising anywhere.

`make` is not installed on this machine yet; every target is one command you can
run by hand, listed by `grep '##' Makefile`.

## The 18 endpoints

| Plane | Endpoints |
|---|---|
| **Admin** (bearer token, capability-checked) | `POST /auth/login` `/auth/refresh` `/auth/logout` · `GET /auth/me` · `GET POST /users` `POST /users/{id}:disable` · `GET POST /enrollment-tokens` `POST /enrollment-tokens/{id}:revoke` · `GET /devices` `/devices/{id}` `POST /devices/{id}:revoke` · `GET /audit-logs` `/audit-logs:verify` `POST /audit-logs:export` |
| **Device** (mTLS client certificate) | `POST /devices/me/heartbeat` |
| **Device** (one-time token; no identity yet) | `POST /enroll` |
| Unauthenticated | `GET /healthz` `/readyz` |

The device plane carries no bearer token and the admin plane carries no client
certificate. They never mix. Nothing in any response holds a command, script or
path, which is the structural reason a compromised server cannot run code on a
laptop.

## Test it

```bash
make test                  # 40 schema checks + 489 server tests
make db-test               # just the database-backed tests
make lint                  # ruff check, ruff format --check, mypy --strict
make demo                  # security core with live attacks, no database needed
make verify-audit          # recompute the audit hash chain from the CLI
make db-test-destructive   # migration up/down. DROPS EVERY TABLE, then repairs
```

By hand:

```bash
.venv-tools/bin/python tools/validate_phase0.py
cd server && .venv/bin/python -m pytest
cd server && .venv/bin/python -m pytest -m postgres -v
./tools/demo_security_core.py
```

Database tests **skip with an explanation** when no cluster is running. The two
migration tests that drop every table need `UG_ALLOW_DESTRUCTIVE_TESTS=1`,
because a plain `pytest` should not wipe your development data — it did once,
which is why the guard exists.

Housekeeping: `make db-status`, `make db-psql`, `make db-stop`, `make db-migrate`
(migrations **and** re-applied grants), `make db-destroy`. Cluster data lives in
`~/.local/share/ubuntuguard/pgdata`, outside the repository. Credentials are
generated into `server/.env` at mode 0600; key material into `server/var/` at
mode 0600. Both are gitignored.

Nothing is installed system-wide. `uv` and CPython 3.12 live under `~/.local` -
see `docs/03-decisions-and-conflicts.md` section C1 for why, and how to undo it.

## What the schema and signing gate covers

It checks that every schema is a valid draft 2020-12 schema, that every example is
accepted or rejected exactly as `schemas/examples/manifest.json` says, that no
example is left untested, and that the committed signing vector still verifies while
all three negative vectors still fail.

Regenerate the signing vector after changing the envelope format:

```bash
.venv-tools/bin/python tools/make_policy_vectors.py
```

## What Phase 0 established

**The signing design is implementable, and tested.** The policy payload is serialized
once and from then on treated as opaque bytes, transmitted base64-encoded inside the
envelope. Python's `json.dumps` and Go's `encoding/json` do not produce identical
bytes for the same object, so signing a re-serialized payload is a latent
verification failure. Signing the exact bytes we transmit removes that class of bug
rather than managing it with a canonicalizer. `SIG_INPUT` binds the envelope metadata
to the payload with length-prefixed fields, so a valid payload cannot be replayed
under a different version, type or device — the three negative vectors are exactly
those attacks, and they fail.

**The schemas enforce the privacy and safety claims, not just document them.** Two
negative cases are worth naming: a `usb_control` payload smuggling
`raw_usbguard_rule`, `post_apply_command` and `rules_path` is rejected, which is what
"no arbitrary command execution from the server" means concretely; and a USB event
carrying `filename`, `bytes_copied`, `mount_point` or `content_hash` is rejected,
which is what "metadata only" means concretely. `always_allow_classes` is required by
schema to contain `hid` and `hub`, so no policy can lock a user out of their own
keyboard.

**USB enforcement is still an open question.** USBGuard remains a candidate. The
spike has a decision rule written down before the experiment, and it has not run.

## Known limitations so far

- A local root user on the laptop can stop the agent and flush USB rules. Detection
  and response, not prevention.
- A compromised server can sign a permissive policy. Limited by signed, versioned,
  audited policies and by a protocol with no command channel, so a compromised server
  still cannot run code on a laptop.
- No content inspection. Reading a file and photographing the screen is out of scope.
- No MFA/SSO, no secrets manager, no HA, no signed apt repo — out of prototype scope.
- The Go agent has not yet been shown to agree with the Python signer. Phase 4.

The full page lands in Phase 6.

