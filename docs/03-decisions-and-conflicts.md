# Decisions, conflicts and open questions

Running record. Anything that conflicts with the brief is raised here rather than
quietly resolved in code.

---

## 1. Conflicts between the brief and this machine

### C1 — Python 3.12 is mandated; this box has only Python 3.14 · **resolved, no deviation**

`/usr/bin/python3` is 3.14.4 and there is no 3.12. There is also no `pip` and no
`ensurepip`, so the system interpreter cannot install anything.

Resolved without sudo: installed `uv` (0.13.6) into `~/.local/bin` from its GitHub
release tarball with a **verified SHA-256** against the published checksum, then
`uv python install 3.12` → **CPython 3.12.16** under `~/.local/share/uv/python/`.
The brief's version is honoured exactly; nothing system-wide was touched.

Reversible with: `rm -rf ~/.local/bin/uv ~/.local/share/uv ~/.cache/uv`.

### C2 — Most of the mandated toolchain is absent, and installing needs your password · **BLOCKING Phase 1**

| Tool | Needed for | Present |
|---|---|---|
| PostgreSQL (`psql`, `initdb`, server) | Phase 1 data model, migrations, RBAC and audit tests | **no** |
| `make` | the Makefile the brief requires | **no** |
| Go toolchain | Phase 2 agent | **no** |
| Node + npm | Phase 3 dashboard | **no** |
| nginx | mTLS check, local dev only | **no** |
| `usbguard` | Phase 0 spike, Phase 5 | **no** |
| `curl`, `pip`, `timeout` | general | **no** |

`sudo` requires interactive authentication, so I cannot install system packages.

**Status: PostgreSQL 18.6 is installed and Phase 1b is unblocked. The rest is still outstanding.**

`psql` 18.6 is present and a system cluster runs on 5432, but `make`, `gcc`, `go`,
`node`, `npm`, `nginx` and `curl` are still missing — so Phase 2 (Go agent) and
Phase 3 (Node dashboard) remain blocked.

One thing worth recording: the server binaries (`initdb`, `pg_ctl`) are **not on
PATH** on Debian and Ubuntu, which is why an earlier check reported them missing.
They live in `/usr/lib/postgresql/18/bin`. Because they are there, `scripts/dev_db.sh`
can run a cluster owned by the invoking user — no sudo, on port 55432, leaving the
system cluster untouched. Creating the two roles needs superuser rights, and rather
than asking for sudo the script creates a cluster in which the current user *is* the
superuser. Reversible with `./scripts/dev_db.sh destroy`.

The original command to run for the remainder:

```bash
sudo apt-get update && sudo apt-get install -y postgresql build-essential golang-go nodejs npm nginx curl
```

Two corrections to the original command, both verified against the 26.04 archive:
`postgresql-contrib` has **no candidate** in 26.04 and would have failed the whole
install — the `postgresql` metapackage pulls `postgresql-18`, which already carries
the contrib extensions. And `usbguard` is deliberately excluded: it is available
(1.1.4) but arming it on a bare-metal daily driver risks the keyboard-lockout case,
so it belongs only on the spike VM.

Versions this will install: PostgreSQL 18.6, Go 1.26, Node 22.22, nginx 1.28,
GCC via build-essential 12.12. One thing to watch: the archive's `npm` is 9.2.0,
older than the npm 10 that normally ships with Node 22. Fine for Vite, but if it
misbehaves in Phase 3 the fix is a user-local `npm install -g npm@latest`.

Until it runs, Phase 1 work is split: the security core (no database) is built and
tested; the data model, migrations and routers are blocked.

### C3 — This box is Ubuntu 26.04; the targets are 22.04 and 24.04 · **accept, with a constraint**

Ubuntu 26.04.1, kernel 7.0.0-30, bare metal (`systemd-detect-virt: none`).

Building here is fine: the agent is a static Go binary (`CGO_ENABLED=0`) and the
server is version-pinned. **Validating here is not fine.** Anything that depends on
OS behaviour — usbguard, systemd unit ordering, `.deb` install/purge, udev — has to
be exercised on 22.04 and 24.04 VMs. I will mark such claims `UNVALIDATED` until
they run there, rather than inferring a pass from 26.04.

### C4 — The USBGuard spike needs hardware I cannot reach · **needs you**

The spike requires root, usbguard, a target Ubuntu release, and a physical USB stick
to insert and remove. The last one cannot be done remotely at all. `spike/usbguard/`
contains a guarded script, a run order, a pre-committed GO/NO-GO rule and a results
template. Until it runs, Phase 5 is blocked and no USB claim is permitted anywhere
in the repo.

### C5 — "No Docker" plus PostgreSQL means a native database · **decision needed**

The brief rules out Docker, so Postgres must run natively. Two routes, both viable:
an apt install (needs your sudo), or a user-local cluster under `$HOME` on a high
port (no sudo, `initdb` + `pg_ctl`, which works fine as a normal user). Folded into
the §4 question.

One caveat either way: the brief requires an app role that **cannot UPDATE or DELETE
`audit_logs`**. Creating and testing that role needs a superuser connection to grant
from. A user-local cluster actually makes this easier, since you own the superuser.

### C6 — nginx for the mTLS check · **no conflict, noted**

Only a sample config plus a local dev setup is in scope, so this is not urgent. For
local dev, nginx can run as an unprivileged user on a high port with its own prefix,
so it does not strictly need sudo either.

---

## 2. Decisions taken in Phase 0

| # | Decision | Why | Reversible? |
|---|---|---|---|
| D1 | Policy payload travels **base64-encoded** inside the envelope; the signature covers the exact decoded bytes | Python and Go do not serialize JSON identically. Signing the bytes we send removes a whole class of verification bug instead of managing it with a canonicalizer | Yes, but it is the core of the signing design |
| D2 | **No JCS / RFC 8785** canonical JSON | Canonicalization would be a second implementation that must match across two languages | Yes |
| D3 | `SIG_INPUT` is a **domain-separated, length-prefixed** concatenation of envelope metadata **and** payload bytes | Signing the payload alone lets an attacker replay it under a different version, type or device. Length prefixes close the `("ab","c")` vs `("a","bc")` ambiguity | Yes, before any agent ships |
| D4 | `payload_sha256` is **advisory**, not part of `SIG_INPUT` | One authority for authenticity. The agent recomputes it and fails closed on mismatch, but security rests only on the signature | Yes |
| D5 | Settings bounds **reject on the server, clamp on the agent** | An admin should be told immediately; an agent must never brick itself on a value from a newer server. The clamp emits `settings_clamped` so it is never silent | Yes |
| D6 | `hid` and `hub` are **required by the JSON Schema** in `always_allow_classes` | Makes "never lock a user out" structurally impossible to misconfigure, not just a convention | Yes |
| D7 | Errors use **RFC 9457 `application/problem+json`** | One typed error model for the generated TypeScript client. Costs a small custom exception handler versus FastAPI's default `{"detail": ...}` | Yes — say the word |
| D8 | Revocation is enforced by a **per-request `device.status` check**, not CRL propagation | Makes the bound "within one request" instead of a cache-expiry race, and is simple enough to test | Yes |
| D9 | Adapter-specific facts live in `inventory.adapter.details` as **flat scalars the server never interprets** | Keeps the server free of Ubuntu-specific logic while still showing Ubuntu facts in the dashboard. A macOS adapter later needs no server change | Yes |
| D10 | `unsupported` is a **first-class policy status** | A host without usbguard must show "unsupported", never a false green | No — this is a correctness requirement |
| D11 | Test signing key is **derived from a documented string**, so no key bytes are committed | Honours "never commit keys" while keeping the cross-language vector reproducible | Yes |
| D12 | Installed `uv` + CPython 3.12 **user-locally** | Only no-sudo route to the mandated Python version | Yes, see C1 |
| D13 | Added `jsonschema`, `cryptography`, `rfc3339-validator` as **Phase 0 test tooling** | `cryptography` is needed by the server anyway. `rfc3339-validator` closes a real hole: without it `jsonschema` silently skips `date-time`, so every timestamp would go unchecked while the run still showed green | Yes |

---

## 3. Questions for you, in the order they block work

1. **Toolchain** (blocks Phase 1) — see §4.
2. **RBAC matrix** (blocks the Phase 1 role-matrix test) — the proposal in
   `01-api-contract.md` §5. Specifically: should `security_analyst` be able to grant
   USB exceptions, and should `it_admin` be able to export the audit log? I split
   export away from `it_admin` on separation-of-duties grounds, which you may
   consider too strict for a 10–50 device prototype.
3. **USBGuard spike scheduling** (blocks Phase 5) — which Ubuntu VMs you have and
   whether you want both 22.04 and 24.04 covered before Phase 5 or just one.
4. **Device grouping** (Phase 4) — Phase 1 assigns policies to explicit device lists;
   tag-based groups can come in Phase 4 unless you want them sooner.
5. **`problem+json`** (D7) — keep it, or use FastAPI's default error shape.

---

## 4. The one blocking question

Phase 1 needs a running PostgreSQL to be worth anything: the brief asks for
migrations tested **up and down**, a role-matrix test, an append-only audit log, and
a DB role that cannot UPDATE or DELETE `audit_logs`. I can write all of that without
a database, but I could not *prove* any of it, and unproven is the one thing the
brief rules out.

Two ways to get there:

**Option A — system packages (you run one command).**

```bash
sudo apt-get update && sudo apt-get install -y \
  postgresql postgresql-contrib build-essential golang-go nodejs npm nginx curl
```

Standard layout, matches what a real deployment looks like, `systemctl` manages the
database. Costs you one sudo prompt, and 26.04's `golang-go`/`nodejs` versions may
need pinning later for the Go and Node phases.

**Option B — user-local toolchain (no sudo, nothing system-wide).**

A `make bootstrap` target that pulls verified tarballs into `./.tool/`: Go and Node
official releases, a PostgreSQL binary distribution with `initdb` into
`./.tool/pgdata` on a high port, and `make` itself. Fully reversible with
`rm -rf .tool`, keeps the repo self-contained, and you own the Postgres superuser,
which makes the least-privilege audit role easier to test. Costs more setup code and
drifts from a production-like layout.

**Which do you want?** I lean Option A for Postgres, Go and Node, because
production-like beats self-contained for a prototype that real IT staff will read,
and Option B's bootstrap code is work that ships nothing. But it is your machine, so
it is your call.
