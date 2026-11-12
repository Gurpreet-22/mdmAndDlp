# What UbuntuGuard is, and what actually works

**Status markers used below, and they are literal:**

| Marker | Meaning |
|---|---|
| **TESTED** | Built, and a test proves it. Test count given. |
| **DESIGNED** | A schema, contract or database table exists. No working code. |
| **NOT STARTED** | Nothing exists. |
| **GATED** | Blocked on the USBGuard spike, which has not run. |
| **OUT OF SCOPE** | Deliberately excluded from the prototype. |

Nothing is marked "built but untested", because that state is not allowed to exist.

---

## 1. MDM or DLP?

Both, and the split matters more than the label.

**The MDM half is the delivery mechanism.** Enroll a laptop, give it a verifiable
identity, collect inventory, hand it signed configuration, revoke it when it is
lost. On its own this is an asset-tracking tool.

**The DLP half is the product.** Exactly one control in this prototype: block
unauthorized USB mass storage. On its own it is unshippable, because without the
MDM half there is no way to deploy, configure or audit it across 50 laptops.

So: an MDM platform carrying a single DLP control. The MDM part is plumbing that
has to be right; the DLP part is the reason anyone buys it.

### Where the work has actually gone

All of it into the MDM half, and specifically into the security foundations that
the DLP control will depend on:

- **The MDM control plane now works end to end.** 21 endpoints. An admin can log
  in, register an employee laptop before it is unboxed, mint an enrollment
  token, watch the device enroll into that same record and heartbeat, revoke it,
  and verify the audit chain over the whole sequence.
- **0% of the DLP control exists.** No USB detection, no enforcement, no events.
  Gated on a hardware spike that has not run.
- **The agent enrols, authenticates and heartbeats.** This entry previously read
  "No agent exists", which was out of date. It generates its own keypair, gets a
  certificate, and checks in over mutual TLS. It does not renew that
  certificate, report inventory, apply a policy or enforce anything.
- **Nothing has run on Ubuntu 22.04 or 24.04.** The agent has been exercised on
  CPython 3.10 and 3.12 and on the development host (Ubuntu 26.04), and nginx is
  not installed there, so the proxy configuration has never been started. Both
  are `UNVALIDATED`.

Said plainly: today this is a working MDM control plane with a client that can
join it and report in, and no DLP. The enforcement that makes it a DLP product
is still missing, and so is certificate renewal — which matters sooner, because
every device enrolled from now expires in 30 days with no recovery path.

---

## 2. Feature list

### A. Admin identity and authorisation — MDM control plane

| # | Feature | Status |
|---|---|---|
| A1 | Argon2id password hashing, with timing equalised against account enumeration and a size bound on the input | **TESTED** (15) |
| A2 | Login lockout: 5 failures in a 10 minute rolling window | **TESTED** (13) |
| A3 | Opaque access (15 min) and refresh (8 h, rotating) tokens, stored only as hashes | **TESTED** (13) |
| A4 | RBAC: 4 roles × 13 capabilities, fully enumerated, incomplete matrix refuses to start | **TESTED** (63) |
| A5 | Hash-chained audit log; detects edits, deletions and re-parenting | **TESTED** (18) |
| A6 | Audit log append-only at the database level, fail-safe across migrations | **TESTED** (11 live DB) |
| A7 | Route-level capability enforcement | **TESTED** (via `test_app.py`) |
| A8 | RFC 9457 errors; all authentication failures render identically | **TESTED** (20) |
| A9 | `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `GET /auth/me` | **TESTED** (12) |
| A10 | User create, list, disable; sessions revoked on disable | **TESTED** (route matrix) |
| A11 | Audit log read, chain verification, CSV export (itself audited) | **TESTED** (6) |

### B. Device lifecycle — MDM

| # | Feature | Status |
|---|---|---|
| B1 | Internal CA; 30-day client certificates, renewal due at 50 % of life | **TESTED** (32) |
| B2 | CSR hardening: signature verified, subject ignored, extensions never copied | **TESTED** |
| B3 | Device identity from nginx mTLS headers, refused from an untrusted peer | **TESTED** (24) |
| B4 | Enrollment tokens: 32 random bytes, stored hashed, single-use under real concurrency | **TESTED** (13 + 1 live DB race) |
| B5 | `POST /api/v1/enroll` endpoint | **TESTED** (9) |
| B6 | Idempotent enrollment retry for 60 s, keyed by token + CSR public key | **TESTED** (2) |
| B7 | Clone detection: distinct device, incident raised, audited | **TESTED** (1) |
| B8 | Heartbeat, and server-computed online/offline (3 missed beats + 60 s) | **TESTED** (2) |
| B9 | Inventory reporting with runtime capability discovery | **DESIGNED** — the endpoint lands with the Phase 2 agent |
| B10 | Revocation effective on the next request | **TESTED** (2) |
| B11 | Certificate renewal endpoint | **NOT STARTED** — Phase 2, when the agent can renew |
| B12 | Device list and detail, with hostname/status/os/agent filters | **TESTED** (3) |
| B13 | Register a device before enrollment: admin adds an employee laptop, it is tracked as `pending` with `enrolled_at` NULL | **TESTED** (40 live checks, see note) |
| B14 | Enrollment CLAIMS the registered row instead of creating a second one, so one laptop is one row | **TESTED** (40 live checks) |
| B15 | Enrollment cannot overwrite administrator-supplied fields — a device cannot rename itself or reassign its owner | **TESTED** (40 live checks) |
| B16 | Enrolled vs unenrolled tracking: `?enrolled=` filter and server-side fleet counts | **TESTED** (40 live checks) |
| B17 | Employee assignment, manufacturer, model, asset tag, and search across all of them | **TESTED** (40 live checks) |
| B18 | Agent install instructions in the dashboard | **PARTIAL** — the dashboard states plainly that no installable agent exists yet, rather than printing a command that cannot work. Real instructions arrive with the Phase 2 package. |

> **Note on B13–B17.** These are proven by `tools/verify_device_registration.py`,
> an end-to-end script that runs 40 assertions against a live server and
> database: registration, the claim, the refusals, the counts, and the audit
> entries. All 40 pass. They do **not** yet have `pytest` coverage, so they are
> not counted in the 538 figure elsewhere in this document. That gap is the next
> thing to close, because a script someone has to remember to run is weaker than
> a test that runs on every commit.

### C. Policy engine

| # | Feature | Status |
|---|---|---|
| C1 | Ed25519 signing over the exact transmitted bytes, verified before parsing | **TESTED** (28) |
| C2 | Signature binds version, type, scope and timestamps, so a valid policy cannot be replayed elsewhere | **TESTED** (3 negative vectors) |
| C3 | Policy JSON Schemas for `usb_control` and `agent_settings` | **TESTED** (40 schema checks) |
| C4 | Immutable policy versions, enforced by grants and a trigger | **TESTED** (11 live DB) |
| C5 | Settings bounds: server rejects out-of-range, agent clamps | **TESTED** (25) |
| C6 | Policy create and assign endpoints | **NOT STARTED** |
| C7 | Agent-side apply → verify real OS state → rollback | **NOT STARTED** |
| C8 | ~~Go~~ and Python agreeing on the signing input | **OBSOLETE AS WRITTEN.** The agent is Python, not Go. `testdata/policy_vectors.json` is verified by both the server's suite and the agent's `test_envelope_conformance.py`, so it still catches a byte-level drift between two independent implementations — but it is no longer a cross-*language* check, and the `json.dumps` vs `encoding/json` divergence that motivated the design is moot. The vector keeps its value as a regression fixture; the claim in this row was retired rather than quietly left to look satisfied |

### D. Agent

This section previously read "Phase 2, nothing exists" and marked every row
`NOT STARTED`. That was already wrong when the Phase 2 audit found it: the
foundation had shipped and nobody updated the table. It is now descriptive.

| # | Feature | Status |
|---|---|---|
| D1 | Platform-neutral core with no OS calls | **TESTED** — `core/` has no filesystem, OS or network access; the whole suite runs with no server, no database and no root |
| D2 | Fixed OS adapter interface; Ubuntu as the only implementation | **TESTED** — a `Protocol` in `osadapter/base.py`, one implementation, pure parsers tested against a synthetic filesystem root |
| D3 | Config precedence: compiled defaults → `/etc/ubuntuguard/agent.yaml` → signed policy → dev-only env | **TESTED** — levels 1, 2 and 4; level 3 lands with the policy engine |
| D4 | mTLS HTTPS client, HTTPS-only with no plaintext fallback compiled in | **TESTED** — `http.py` on `urllib` + `ssl.SSLContext`, exercised against a real TLS server on loopback: wrong CA, wrong hostname, expired certificate and absent client certificate are each refused, and so are redirects, proxies, unbounded responses and plaintext |
| D5 | Local identity: keypair generated on the device, never leaves it | **TESTED** — EC P-256 written at 0600 via `os.open`, asserted to survive a permissive umask; tests assert the private scalar and its PEM appear in no request body |
| D6 | Durable SQLite event queue (WAL), surviving `kill -9` | **NOT STARTED** — Phase 7, with the enforcer |
| D7 | Heartbeat with jitter; backoff with full jitter; monotonic timers | **TESTED** — the primitives, and the heartbeat task that uses them. The server's interval is clamped through `constants.HEARTBEAT_SECONDS` because `HeartbeatResponse` is unsigned |
| D8 | Resume-from-sleep and network-return trigger an immediate check-in | **PARTIAL** — `ClockWatch` detects the clock step a suspend/resume produces and reports it; nothing yet reschedules the heartbeat on that signal, and there is no netlink watch |
| D9 | `agentd` (unprivileged) / `enforcerd` (root) split over a Unix socket with `SO_PEERCRED` | **NOT STARTED** — Phase 7. The socket path is declared in `AgentPaths` so the privilege boundary has an address |
| D10 | Inventory collection discovered at runtime, nothing hardcoded | **PARTIAL** — the enrollment fingerprint is discovered, never assumed: os-release, kernel, arch, hashed machine-id, hashed physical MACs, heuristic virtualization. `dmi_product_uuid_hash` is `null` in production, deliberately — see the note below. Full `inventory.v1` reporting has no endpoint yet |
| D11 | `.deb` package, two systemd units, `postinst` does not enroll, `purge` removes keys | **PARTIAL** — `install.sh` and one hardened systemd unit, asserted by 45 packaging tests. Installing does not enrol, and `enroll` is a separate operator command with no `--token` option. No `.deb`, and the second (root) unit is Phase 7 |

> **Note on D10 and clone detection.** `/sys/class/dmi/id/product_uuid` is mode
> 0400 root-only, and the agent runs as an unprivileged user with an empty
> `CapabilityBoundingSet`. So that field is `null` on a managed laptop and the
> server's clone detection effectively matches on `machine_id_hash` alone. A
> reimaged laptop gets a new machine-id and will **not** be recognised as the
> same hardware. This is a known weakness of the signal, accepted rather than
> fixed: collecting it would mean weakening the systemd hardening, which is a
> worse trade. Reading it is a candidate job for the Phase 7 root enforcer.

### E. USB data-loss prevention — Phase 5, the actual product

| # | Feature | Status |
|---|---|---|
| E0 | **USBGuard spike: does it genuinely block for a standard user?** | **NOT RUN** — everything below depends on it |
| E1 | USB device detection and event source | **GATED** |
| E2 | `monitor_only` mode | **GATED** |
| E3 | `allowlist_enforce` mode | **GATED** |
| E4 | `block_all_storage` mode | **GATED** |
| E5 | Enforcement holds at boot before the network is up | **GATED** |
| E6 | Last verified policy keeps enforcing while offline | **GATED** |
| E7 | Never lock a user out: HID, hub and dock classes always allowed | **DESIGNED** — required by the JSON Schema, so no policy can misconfigure it |
| E8 | Time-bound admin exceptions, max 24 h, reason required, surviving restart | **DESIGNED** (table + schema + constraints) |
| E9 | Event pipeline: batched, at-least-once, deduplicated | **PARTIAL** — dedupe **TESTED** against live PostgreSQL (1,000 events delivered twice, stored once); the pipeline itself does not exist |
| E10 | Incidents with a status workflow | **DESIGNED** (table + constraints) |
| E11 | Privacy: vendor, product, serial, class, time, decision — and nothing else | **TESTED** — the schema rejects `filename`, `bytes_copied`, `mount_point`, `content_hash` |

### F. Dashboard — Phase 3

This section previously read "nothing exists", which was already wrong: the
dashboard was built in Phase 3 and the entry was never updated.

| # | Feature | Status |
|---|---|---|
| F1 | Login, with a banner when authentication is disabled | **BUILT** |
| F2 | Device list with search, enrollment and status filters, server-side counts | **BUILT** |
| F3 | Add device: register an employee laptop, pick a platform, issue its token | **BUILT** |
| F4 | Device detail: assignment, identity, inventory, revocation | **BUILT** |
| F5 | Enrollment token creation and revocation | **BUILT** |
| F6 | Audit log view with chain verification | **BUILT** |
| F7 | Navigation filtered by the signed-in role's capabilities | **BUILT** (cosmetic; the server checks every request) |
| F8 | USB policy creation and assignment, USB events, incident workflow | **NOT STARTED** — Phase 5, gated on the spike |

Marked **BUILT** rather than **TESTED**: `tsc --noEmit && vite build` passes and
`server/tests/test_dashboard_types_match_api.py` holds the API types in step
with the server's schema, but there are no component or browser tests. The
status markers at the top of this document do not have a word for "compiles and
has been used by hand", and inventing one would be the kind of quiet grade
inflation this document exists to prevent.

Types are hand-written, not generated from the OpenAPI document — that was
changed on request, and the drift test above is the mitigation.

### G. Supporting

| # | Feature | Status |
|---|---|---|
| G1 | Local PostgreSQL dev cluster, no sudo, system cluster untouched | **TESTED** in use |
| G2 | Two database roles; deny-by-default grants | **TESTED** (11 live DB) |
| G3 | Alembic migrations, up and down | **TESTED** (42 offline + 2 live) |
| G4 | nginx sample config for the mTLS check | **NOT STARTED** |
| G5 | End-to-end demo script | **PARTIAL** — `tools/demo_security_core.py` covers the security core |
| G6 | Known-limitations page | **PARTIAL** — in the threat model and README; the full page is Phase 6 |

---

## 3. Out of scope, deliberately

Content-aware DLP (file contents, fingerprinting, classification) · exfiltration
by email, cloud upload, printing, screenshot or clipboard · Windows, macOS,
mobile · MFA and SSO · high availability and multi-region · a secrets manager ·
a signed apt repository · SIEM integration · deployment automation.

Platform neutrality is kept in the *shape* of the code so other OSes can be
added later as adapters, but only Ubuntu will exist.

## 4. The limitation to repeat out loud

A local root user on the laptop can stop the agent and flush the USB rules. This
offers **detection and response**, not a guarantee. Defending root from root
needs a hardened boot chain and remote attestation, which is outside the
prototype.

Documentation may say "blocks unauthorized USB mass-storage devices for standard
(non-root) users on Ubuntu *x*", and only once the spike proves it. It may never
say "prevents data theft".
