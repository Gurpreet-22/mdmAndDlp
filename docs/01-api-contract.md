# UbuntuGuard — API Contract (Phase 0)

**Status:** §4.1 (device plane) is **descriptive and verified against the code**. The authoritative contract for every implemented endpoint is the Pydantic model in `server/src/ubuntuguard/schemas.py`, surfaced as FastAPI's OpenAPI document at `/api/v1/openapi.json`. The rest of this file remains the proposed design for endpoints that do not exist yet, and says so per row.

Where this document and the code disagree, the code is right and this document is a bug. Two such bugs were found during the Phase 2 audit and are corrected in §4.1, each marked **CORRECTED** with what the earlier draft claimed, so the change is reviewable rather than silent.

---

## 1. Conventions

| Topic | Decision |
|-------|----------|
| Base path | `/api/v1` — version in the path; breaking changes bump to `/api/v2` |
| Transport | HTTPS only, TLS 1.2+. Plain HTTP is refused, never redirected (a redirect would leak the first request) |
| Encoding | `application/json`, UTF-8. Timestamps are RFC 3339 with explicit `Z` (UTC) |
| IDs | UUIDv4 for devices, policies, incidents, users; opaque to clients |
| Errors | RFC 9457 `application/problem+json` (see §3) |
| Pagination | Cursor-based: `?limit=` (1–200, default 50) `&cursor=` → `{items, next_cursor}`. Stable sort by `(created_at desc, id desc)` |
| Request correlation | Server generates `X-Request-Id` if absent, echoes it, and includes it in every problem response and audit row |
| Clock | Server sends `Date`. Agent tolerates ±300 s skew (fixed constant). Requests whose signed timestamps fall outside are rejected `400 clock_skew_exceeded` |
| Rate limits | Enforced in **nginx**, not in the application: `limit_req` on `/api/v1/enroll` and `/api/v1/auth/login`, returning `429`. `problems.rate_limited` exists in the application for the shape of the response but has no caller, and that is deliberate — connection-level limiting belongs at the proxy, in front of the work it is meant to bound. The application's own defence on `/auth/login` is per-account lockout (5 failures / 10 min), which is a different control: it survives an attacker rotating source addresses, and rate limiting survives an attacker rotating account names. Both are needed |
| Unknown fields | Rejected (`extra="forbid"` in Pydantic, `DisallowUnknownFields` in Go). Silent field-dropping hides protocol drift |

### Two authentication planes

**Device plane** (`/api/v1/devices/me/*`): mTLS client certificate issued by the internal CA at enrollment.
nginx terminates TLS, verifies the chain, and forwards `X-Client-Verify`, `X-Client-Cert` (`$ssl_client_escaped_cert`), `X-Client-DN` and `X-Client-Serial`.
**nginx must unconditionally overwrite all of these on every request** so a client cannot inject them; the app also refuses them from any source other than the trusted upstream. The app then re-checks: the SHA-256 fingerprint it computes from the forwarded certificate matches the one stored at enrollment, the cert is not expired, and `device.status == 'active'`. That DB check on every request is what makes revocation effective (§6).

**Correction to an earlier draft of this document:** it specified an `X-Client-Fingerprint` header. nginx's `$ssl_client_fingerprint` is **SHA-1**, and binding device identity to a SHA-1 digest is not a hash choice worth defending. The proxy now forwards the whole certificate and the application computes SHA-256 itself, which also lets the app re-derive anything else it needs rather than trusting the proxy to summarise it.

**Admin plane** (everything else): `Authorization: Bearer <access_token>`, 15 min lifetime. Refresh token is 8 h, rotating, single-use, httpOnly cookie. RBAC is enforced server-side on every route (§5).

The device plane carries **no bearer token** and the admin plane carries **no client cert**. They never mix.

## 2. Design property: no command channel

Nothing in this API lets the server tell an agent to *do* a thing. The agent **pulls** declarative, signed, schema-validated state and decides locally. There is no field anywhere that holds a command, script, shell string, file path, URL to execute, or package name. Heartbeat responses carry scheduling hints and version numbers only. This is the structural reason a compromised server cannot run code on a laptop (threat T9).

## 3. Error model

```json
{
  "type": "https://ubuntuguard.invalid/problems/enrollment-token-invalid",
  "title": "Enrollment token invalid or already used",
  "status": 401,
  "code": "enrollment_token_invalid",
  "request_id": "01JB...",
  "detail": "Enrollment failed."
}
```

`code` is the stable machine-readable string clients branch on; `title`/`detail` are for humans and are deliberately generic on auth paths. Login failure, unknown user, wrong password, and locked account all return the **same** body and `401` with code `invalid_credentials`; only the audit log distinguishes them.

Validation failures return `422` with a `fields` array. No error ever echoes a token, password, key, or signature value.

## 4. Endpoints

### 4.1 Device plane (mTLS)

> **This section is now descriptive, not proposed.** The two implemented
> endpoints below are transcribed from the Pydantic models in
> `server/src/ubuntuguard/schemas.py`, which is the authoritative contract.
> Where an earlier draft of this document disagreed with the code, the code
> won and this document was corrected — see the two notes marked
> **CORRECTED**. Because every request model sets `extra="forbid"`, sending a
> field this table does not list produces `422`, so the distinction is not
> academic.

| Method | Path | Status | Purpose |
|--------|------|--------|---------|
| `POST` | `/api/v1/enroll` | **IMPLEMENTED** | Exchange one-time token + CSR for identity. **TLS only, no client cert** (none exists yet). Rate limiting is enforced in nginx, not in the application — see `deploy/nginx/` |
| `POST` | `/api/v1/devices/me/heartbeat` | **IMPLEMENTED** | Liveness + scheduling hints. No commands |
| `POST` | `/api/v1/devices/me/certificate:renew` | **IMPLEMENTED** | Rotate the client certificate, authenticated by the certificate being replaced. The agent renews at 50 % of the 30-day life (day 15) |
| `PUT` | `/api/v1/devices/me/inventory` | **NOT IMPLEMENTED** | Full inventory replace, schema `inventory.v1`. The `device_inventory` table exists and is unused |
| `GET` | `/api/v1/devices/me/policies` | **NOT IMPLEMENTED** | Fetch signed policy envelopes with the **exact signed bytes** base64-encoded (see `02-policy-and-signing.md`). Supports `?since_version=` |
| `POST` | `/api/v1/devices/me/policy-status` | **NOT IMPLEMENTED** | `{policy_id, policy_version, status, reason_code, detail, verified_state_summary}`. Statuses: `pending, applied, failed, unsupported, rolled_back` |
| `POST` | `/api/v1/devices/me/events:batch` | **NOT IMPLEMENTED** | At-least-once, max 500. Server dedupes on agent-generated `event_id` |

#### `POST /api/v1/enroll` — unauthenticated, `201`

Request — `EnrollRequest`. Unknown fields rejected.

| Field | Type | Constraint | Required |
|---|---|---|---|
| `enrollment_token` | string | 20–128 characters | yes |
| `csr_pem` | string | 64–8192 characters | yes |
| `hostname` | string | 1–253 characters | yes |
| `agent_version` | string | ≤ 64 | yes |
| `arch` | string | ≤ 32 | yes |
| `os.id` | string | ≤ 32 | yes |
| `os.version_id` | string | ≤ 32 | yes |
| `os.kernel` | string | ≤ 128 | yes |
| `os.pretty_name` | string \| null | ≤ 128 | no |
| `hardware_fingerprint.machine_id_hash` | string \| null | `^[0-9a-f]{64}$` | no |
| `hardware_fingerprint.dmi_product_uuid_hash` | string \| null | `^[0-9a-f]{64}$` | no |
| `hardware_fingerprint.mac_hashes` | array\<string\> | each `^[0-9a-f]{64}$`, ≤ 32 items | no |
| `hardware_fingerprint.virtualization` | string \| null | ≤ 32 | no |
| `release_build` | boolean | default `true` | no |
| `primary_adapter_ip` | string \| null | a real IPv4 or IPv6 address, stored canonicalised | no |

> **CORRECTED.** An earlier draft listed a top-level `public_key_fingerprint`
> and put `hostname` *inside* `hardware_fingerprint`. Neither exists. The
> server derives the CSR public-key fingerprint itself
> (`services/enrollment.py`), because a client-supplied fingerprint of a
> client-supplied key proves nothing and would only be another field to
> validate. `hostname` is top-level and required.

Response `201` — `EnrollResponse`:

```
{ "device_id": "uuid",
  "client_certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "ca_chain_pem": "-----BEGIN CERTIFICATE-----...",
  "certificate_not_after": "2026-12-05T12:00:00Z",
  "certificate_renew_after": "2026-11-20T12:00:00Z",
  "policy_public_keys": [ { "key_id": "...", "alg": "ed25519", "public_key_b64": "..." } ],
  "clone_suspected": false }
```

> **CORRECTED.** An earlier draft showed `settings_version` in this response
> and omitted `certificate_renew_after` and `clone_suspected`. There is no
> `settings_version` anywhere in the implementation.

`certificate_renew_after` is 50 % through the certificate's life. The agent
computes the same value locally from the certificate
(`identity.renewal_due_at`) rather than depending on this field, so the
renewal decision still works offline; the field exists so the two can be
compared.

Errors: `400 csr_invalid` · `401 enrollment_token_invalid` · `422` validation failure with a `fields` array. No error body ever echoes the token.

Hardware fingerprint inputs are **hashed on the agent**, never sent raw. They are advisory: a collision does not block enrollment — the new device is created as a **distinct** device and a `clone_suspected` incident is raised (threat T6). In practice `dmi_product_uuid_hash` is `null` on an enrolled laptop, because `/sys/class/dmi/id/product_uuid` is root-only and the agent runs unprivileged, so clone detection rests on `machine_id_hash` alone and is weaker than this section once implied.

**Idempotent retry (60 s):** the response is cached keyed by `(token_hash, csr_public_key_fingerprint)`. A retry with the *same* token and *same* public key within 60 s returns the identical `201` body. The same token with a *different* public key returns `401 enrollment_token_invalid` — the token was consumed. Two simultaneous uses therefore yield exactly one success.

Because the cache is keyed on the public key, **the agent must persist its private key before the first POST** and reuse it on every retry. An agent that generated a fresh keypair on retry would present a different public key, miss the cache, and be told its token is spent.

#### `POST /api/v1/devices/me/heartbeat` — mTLS, `200`

Request — `HeartbeatRequest`. Unknown fields rejected.

| Field | Type | Constraint | Required |
|---|---|---|---|
| `agent_version` | string | ≤ 64 | yes |
| `uptime_seconds` | integer | ≥ 0 | yes |
| `applied_policy_versions` | object\<string, integer\> | `policy_type → version`, default `{}` | no |
| `primary_adapter_ip` | string \| null | a real IPv4 or IPv6 address | no |

Response `200` — `HeartbeatResponse`:

```
{ "server_time": "2026-11-05T12:00:00Z",
  "heartbeat_seconds": 60,
  "heartbeat_jitter_pct": 10,
  "certificate_renew_after": "2026-11-20T12:00:00Z",
  "available_policies": [] }
```

> **CORRECTED.** An earlier draft listed `jitter_pct` and `settings_version`.
> The field is `heartbeat_jitter_pct`, and there is no `settings_version`.
> `available_policies` is always `[]` until the policy engine exists.

This response is **not signed**. The agent therefore treats `heartbeat_seconds`
and `heartbeat_jitter_pct` as hints and clamps both through the bounds in
`constants.py` before using them, so a compromised server can shift the
check-in cadence only within a range the agent already considered safe. It
cannot stop the agent checking in, and it cannot make it flood.

`401` reason codes, each distinguished in the audit log but never in the response body: `untrusted_proxy`, `client_cert_missing`, `client_cert_not_verified`, `client_cert_malformed`, `client_cert_subject_invalid`, `client_cert_expired`, `client_cert_not_yet_valid`, `device_not_active`, `device_identity_mismatch`, `client_cert_superseded`.

#### `POST /api/v1/devices/me/certificate:renew` — mTLS, `200`

Request — `CertificateRenewRequest`. Unknown fields rejected.

| Field | Type | Constraint | Required |
|---|---|---|---|
| `csr_pem` | string | 64–8192 characters, and its public key **must differ** from the current certificate's | yes |

There is no `device_id` and no token. The identity comes entirely from the mTLS
connection, so a device cannot renew on another's behalf, and a field here
naming a device would be one the server had to ignore.

Response `200` — `CertificateRenewResponse`:

```
{ "device_id": "uuid",
  "client_certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "ca_chain_pem": "-----BEGIN CERTIFICATE-----...",
  "certificate_not_after": "2026-12-05T12:00:00Z",
  "certificate_renew_after": "2026-11-20T12:00:00Z",
  "reused": false }
```

Deliberately **not** a copy of `EnrollResponse`. It omits `policy_public_keys`,
because those were pinned at enrollment and re-sending them would create a
key-rotation path that bypasses the signed `key_rotation` record; and it omits
`clone_suspected`, because renewal never re-examines the hardware fingerprint.

Errors: `400 csr_invalid` · `400 csr_key_reused` · `401` with any device-plane
reason code · `422`.

**Why the new key must be new.** Renewal exists partly to bound how long one
private key is exposed, and renewing onto the same key forfeits that. It also
keeps the idempotency below unambiguous: "a certificate already issued against
this key" would otherwise match the certificate being replaced.

**The rotation is one transaction.** The new certificate is inserted, the
predecessor is marked superseded, and `devices.cert_fingerprint` is repointed,
all together. There is no instant at which a device has two live certificates
or none.

**Supersede semantics, and the one deliberate exception.** A superseded
certificate is refused by the authentication layer — `client_cert_superseded`
on the heartbeat, immediately. The exception is this endpoint, which accepts a
certificate superseded within `CERT_SUPERSEDE_GRACE_SECONDS` (one hour).

That exception exists for exactly one failure, and it is the same one the
enrollment idempotency cache exists for: the server commits the renewal and the
response is lost in transit. The agent is then holding a certificate the server
has just superseded and has no other credential, so without the window it could
not retry and a dropped packet would cost a re-enrollment. The window is narrow
in three independent ways — one hour, this endpoint only, and the retry is
idempotent on the CSR's public key so it returns the certificate already issued
(`reused: true`) rather than a second one.

**Revocation outranks all of it.** `device.status` is checked before anything
about the certificate, so a revoked device cannot renew whatever it presents.

### 4.2 Admin plane (bearer + RBAC)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/auth/login` | Argon2id verify → access + refresh. Lockout: 5 failures / 10 min |
| `POST` | `/api/v1/auth/refresh` | Rotate refresh token (single-use; reuse revokes the family) |
| `POST` | `/api/v1/auth/logout` | Revoke the refresh family |
| `GET`  | `/api/v1/auth/me` | Current user + role |
| `GET`  | `/api/v1/devices` | List; filters `q` (hostname), `os_version`, `kernel`, `agent_version`, `status`, `online`, `last_seen_before/after` |
| `GET`  | `/api/v1/devices/{id}` | Detail: inventory, capabilities, applied policies, recent events |
| `POST` | `/api/v1/devices/{id}:revoke` | Revoke identity (reason required) |
| `POST` | `/api/v1/enrollment-tokens` | Create one-time token; **plaintext returned exactly once** |
| `GET`  | `/api/v1/enrollment-tokens` | List metadata only (never the token or its hash) |
| `POST` | `/api/v1/enrollment-tokens/{id}:revoke` | Invalidate before use |
| `POST` | `/api/v1/policies` | Create an immutable signed version |
| `GET`  | `/api/v1/policies` · `/{id}` | List / detail incl. signature metadata and rollout status |
| `POST` | `/api/v1/policies/{id}:assign` | Assign to devices or a group |
| `GET`  | `/api/v1/usb-events` | Filter by device, decision, vendor, time range |
| `GET`  | `/api/v1/incidents` · `/{id}` | List / detail |
| `PATCH`| `/api/v1/incidents/{id}` | Status: `open → acknowledged → investigating → resolved | false_positive`. Note required on terminal states |
| `POST` | `/api/v1/usb-exceptions` | Time-bound grant. `reason` required, `expires_at` ≤ 24 h — server clamps and rejects beyond |
| `GET`  | `/api/v1/usb-exceptions` · `DELETE /{id}` | List / revoke early |
| `GET`  | `/api/v1/audit-logs` | Paginated, filterable, read-only |
| `GET`  | `/api/v1/audit-logs:verify` | Recompute the hash chain, report first break |
| `POST` | `/api/v1/audit-logs:export` | CSV/JSON export — itself an audited action |
| `GET`  | `/healthz` · `/readyz` | Unauthenticated liveness / readiness. No build or version detail |

Audited actions (hash-chained): login success/failure, logout, role change, user create/disable, token create/revoke, enrollment success/failure, device revoke, policy create/assign, exception create/revoke, incident status change, export.

## 5. RBAC matrix (proposed — needs your sign-off)

| Capability | super_admin | it_admin | security_analyst | auditor |
|---|---|---|---|---|
| Manage users & roles | ✓ | — | — | — |
| Read devices / inventory | ✓ | ✓ | ✓ | ✓ |
| Revoke a device | ✓ | ✓ | — | — |
| Create / revoke enrollment tokens | ✓ | ✓ | — | — |
| Read policies | ✓ | ✓ | ✓ | ✓ |
| Create / assign policies | ✓ | ✓ | — | — |
| Read USB events & incidents | ✓ | ✓ | ✓ | ✓ |
| Change incident status | ✓ | ✓ | ✓ | — |
| Create / revoke USB exceptions | ✓ | ✓ | ✓ | — |
| Read audit log | ✓ | ✓ | ✓ | ✓ |
| Verify audit chain | ✓ | ✓ | ✓ | ✓ |
| Export audit log | ✓ | — | — | ✓ |

`auditor` is read-only plus export. Export is split away from `it_admin` deliberately: the role that configures the fleet should not also be the role that extracts the record of what it did. **Tested by `test_rbac_matrix`, which asserts every (route, role) cell — including the denials.**

## 6. Computed state semantics

**Online/offline** is computed by the **server**, never self-reported:
`offline` when `now - last_heartbeat_at > (3 × effective_heartbeat_seconds) + 60 s`. At the 60 s default that is 240 s. Shown in the UI with the actual `last_seen` timestamp so "online" is never a bare claim.

**Revocation** (≤5 s target) means: the server refuses the device's next request. Mechanism is the per-request `device.status` lookup, not CRL propagation — so the bound is "within one request", and the 5 s figure is the *measured* worst case of revoke→rejection, asserted by `test_revoke_takes_effect_under_5s`. Revocation does **not** make a laptop stop enforcing: an offline or cut-off device keeps its last verified policy by design (threat T11). Removing enforcement requires a new signed policy or uninstalling the package.

**Event delivery** is at-least-once with server-side dedupe on the agent-generated `event_id` (UUIDv7, so it also sorts by time). The agent deletes a queued event only after a `2xx` that lists its ID as `accepted` or `duplicate`.

## 7. Open contract decisions

1. **RBAC matrix above** — particularly whether `security_analyst` may grant USB exceptions, and whether `it_admin` should be able to export the audit log.
2. **Device grouping** — Phase 1 ships policy assignment to explicit device lists; tag-based groups are a Phase 4 addition unless you want them earlier.
3. **problem+json** — chosen over FastAPI's default `{"detail": ...}` for one typed error model in the generated client. Costs a small custom exception handler. Say so if you would rather keep the FastAPI default.
