# UbuntuGuard — Policy Format, Signing and Apply Lifecycle (Phase 0)

**Status:** design. Cross-language test vectors land in Phase 4; until then every claim here is **UNVALIDATED**.

---

## 1. The byte-exactness problem, and how we avoid it

Ed25519 signs bytes. Python's `json.dumps` and Go's `encoding/json` do **not** guarantee the same bytes for the same object: key order, unicode escaping, float formatting and whitespace all differ. Signing a re-serialized object is therefore a latent verification failure, or worse, a canonicalization bug that an attacker can steer.

**Rule: the server signs the exact bytes it transmits, and the agent verifies those exact bytes before parsing them.**

Mechanism: the policy payload is serialized **once**, at creation time, and from then on is treated as an opaque byte string. It is stored as bytes, transmitted **base64-encoded inside the envelope**, and the agent verifies the decoded bytes before `json.Unmarshal` ever sees them. Base64 is what makes this survive every JSON layer in between — nginx, FastAPI, any proxy, the TS client — because no middlebox can "helpfully" reorder keys inside a base64 string.

We deliberately do **not** use JCS/RFC 8785 canonical JSON. Canonicalization is a second implementation that must match across two languages; "sign the bytes you send" removes that class of bug instead of managing it.

## 2. Envelope

```json
{
  "envelope_version": 1,
  "policy_id": "0f0f...-uuid",
  "policy_version": 7,
  "policy_type": "usb_control",
  "scope": { "kind": "device", "id": "uuid-of-device" },
  "issued_at": "2026-10-29T10:00:00Z",
  "expires_at": null,
  "payload_b64": "eyJzY2hlbWEiOiAi...",
  "payload_sha256": "9f86d0818...",
  "signature": { "alg": "ed25519", "key_id": "ed25519:4f3c2b1a09d8e7f6", "value_b64": "MEUCIQ..." }
}
```

`payload_sha256` is **advisory only** — for UI display, logs and dedupe. The agent recomputes it and rejects a mismatch early (fail closed), but security rests entirely on the signature over the payload bytes. It is not in the signing input, so there is exactly one authority.

### Signing input (normative)

Signing only the payload would let an attacker replay a valid payload under a different version, type or device. So the signature binds the metadata to the bytes:

```
SIG_INPUT = DS
          || LP(policy_id)      || LP(uint64_be(policy_version))
          || LP(policy_type)    || LP(scope.kind) || LP(scope.id)
          || LP(issued_at)      || LP(expires_at_or_empty)
          || LP(key_id)         || LP(payload_bytes)

DS     = "ubuntuguard/policy-envelope/v1"   (ASCII, no terminator)
LP(x)  = uint64_be(len(x)) || x             (length-prefixed; prevents
                                             concatenation ambiguity)
signature = Ed25519_sign(sk, SIG_INPUT)     (pure Ed25519 — NOT Ed25519ph)
```

All string fields are UTF-8; timestamps are the exact RFC 3339 strings that appear in the envelope. Length-prefixing matters: with plain concatenation, `("ab","c")` and `("a","bc")` produce identical input, which is a forgery primitive.

Phase 4 ships `testdata/policy_vectors.json` — fixed keypair, fixed envelopes, expected signatures — exercised by **both** the Python and Go test suites. That is the only thing that will prove the two implementations agree.

### Hard limits

| Limit | Value | Why |
|---|---|---|
| `payload_bytes` max | 64 KiB | Bounds agent memory; a legitimate USB policy is well under 8 KiB |
| Allowlist entries max | 256 | Keeps rule generation and readback bounded |
| Active exceptions max | 32 per device | Exceptions are meant to be rare |
| Envelope nesting depth | 8 | Parser DoS guard |

## 3. Keys

Four separate pieces of key material, never the same file, never in the repo:

| Material | Algorithm | Lives | Used for |
|---|---|---|---|
| Policy signing key | Ed25519 | File on the server host, mode `0600`, path from config | Signing envelopes |
| Internal CA key | RSA-3072 or P-256 | File on the server host, mode `0600` | Issuing 30-day device certs |
| TLS server key | per nginx | nginx config dir | Public HTTPS endpoint |
| DB credentials | — | Environment | Least-privilege app role |

`key_id = "ed25519:" + hex(sha256(public_key_bytes))[:16]`.

Agents receive the trusted policy public key(s) **at enrollment, over mTLS-protected HTTPS**, and pin them in local state. Rotation in the prototype: a `key_rotation` record introducing a new public key, itself signed by a currently-trusted key, so trust is never bootstrapped from an unauthenticated channel. Revoking a compromised signing key requires re-enrollment — accepted prototype limitation, documented in Phase 6.

## 4. Policy types

| `policy_type` | Payload schema | Purpose |
|---|---|---|
| `usb_control` | `schemas/policy.usb_control.v1.schema.json` | USB modes, allowlist, exceptions, reporting |
| `agent_settings` | `schemas/policy.agent_settings.v1.schema.json` | Tunables, every one clamped to compiled bounds |

Policies are **data, never scripts.** No payload field holds a command, path, rule string, URL or package name. For USB, the server sends *typed device matchers and a mode*; `enforcerd` generates the usbguard rules itself. The server never transmits rule text, which is what keeps rule injection off the table.

## 5. Settings bounds (precedence and clamping)

Precedence: **(1)** compiled defaults → **(2)** `/etc/ubuntuguard/agent.yaml` (server URL + CA bundle **only**) → **(3)** signed `agent_settings` policy, clamped → **(4)** dev-only env overrides, compiled out of release builds.

| Setting | Default | Min | Max |
|---|---|---|---|
| `heartbeat_seconds` | 60 | 30 | 900 |
| `heartbeat_jitter_pct` | 10 | 0 | 50 |
| `backoff_initial_seconds` | 5 | 1 | 60 |
| `backoff_max_seconds` | 900 | 60 | 3600 |
| `inventory_interval_seconds` | 3600 | 300 | 86400 |
| `event_batch_max` | 100 | 1 | 500 |
| `event_queue_max_events` | 10000 | 100 | 10000 |
| `event_queue_max_age_days` | 7 | 1 | 7 |
| `policy_poll_seconds` | 300 | 60 | 3600 |
| `log_level` | `info` | — | one of `error,warn,info,debug` |

Bounds are enforced in two deliberately different places, and the asymmetry is intentional:

- **Server, at policy creation:** validates against `policy.agent_settings.v1.schema.json` and **rejects** an out-of-range value with `422`. An admin typing `heartbeat_seconds: 5` should be told immediately, not have it silently become 30.
- **Agent, at apply:** validates *structure* strictly (`DisallowUnknownFields`) but treats *ranges* leniently and **clamps** to its compiled constants, emitting a `settings_clamped` event with field, requested and applied values. An agent must never brick itself because a newer server sent a value outside the range this build knows about. A silent clamp would be a debugging trap, hence the event.

The Go constants are the runtime authority. These are **not** tunable at all, being security invariants: clock-skew tolerance (300 s), certificate renewal threshold (50 % of life), signature-before-parse ordering, HTTPS-only.

## 6. Apply lifecycle

```
  fetch → [1] verify → [2] admit → [3] parse → [4] validate
        → [5] snapshot → [6] apply → [7] verify real state → [8] commit
                                   ↘ on failure: rollback → verify → report
```

| Step | What happens | Fails with |
|---|---|---|
| 1 | Size cap, `payload_sha256` recomputed, **Ed25519 signature verified over decoded bytes against a pinned key** | `signature_invalid`, `unknown_key_id`, `payload_too_large`, `hash_mismatch` |
| 2 | Scope is this device; `policy_version > last_applied_version`; `issued_at`/`expires_at` within ±300 s skew | `scope_mismatch`, `version_not_newer`, `envelope_expired`, `clock_skew_exceeded` |
| 3 | Strict JSON decode, `DisallowUnknownFields`, depth cap | `schema_invalid`, `unknown_field` |
| 4 | Semantic checks, clamp settings, **invariant: must not block HID/hub/dock classes**; capability check | `invariant_violation`, `unsupported_capability` |
| 5 | Snapshot the real current state (usbguard rules, daemon params, device targets) to local SQLite | `snapshot_failed` |
| 6 | `enforcerd` applies one fixed typed operation; **enforcerd re-validates the whole request itself** | `enforce_failed`, `enforcer_unavailable`, `enforcer_rejected` |
| 7 | Read the state **back from the OS** and compare against intent. Exit code 0 is not evidence | `verify_failed`, `verify_drift` |
| 8 | Persist as last-known-good, report `applied` | — |

Failure at 5–7 triggers rollback from the snapshot, a readback verification of the rollback, and a report of `rolled_back` with the reason code. If rollback itself fails to verify, the agent reports `failed` with `rollback_failed` and raises an incident — that state is an alert, not something to retry silently.

**Statuses:** `pending`, `applied`, `failed`, `unsupported`, `rolled_back`.
`unsupported` is a first-class outcome, not an error: on a host with no usbguard, a `usb_control` policy reports `unsupported` with `reason_code = capability_missing` and the dashboard shows "unsupported" for that device rather than a false green.

## 7. `enforcerd` operation set (fixed, typed)

| Op | Input | Output |
|---|---|---|
| `OP_CAPABILITIES` | — | usbguard present, version, daemon state, D-Bus availability, writable paths |
| `OP_USB_GET_STATE` | — | normalized current rules, daemon params, per-device targets |
| `OP_USB_SET_POLICY` | `{mode, allowlist[], exceptions[], always_allow_classes[]}` | applied + readback state |
| `OP_USB_ROLLBACK` | `{snapshot_id}` | restored + readback state |

Every op is validated against this closed set by **both** agentd and enforcerd. No op accepts a file path, command, shell string or raw usbguard rule. The socket is `/run/ubuntuguard/enforcer.sock`, mode `0660`, group `ubuntuguard`, with an `SO_PEERCRED` check that the caller's uid is the agentd uid. Rejections are logged with the opcode, never with payload contents.

## 8. Privacy: fields we will never collect

USB events carry **vendor id, product id, product name, serial, interface classes, port, timestamp, decision, policy version** — and nothing else. The schema sets `additionalProperties: false`, and `test_event_schema_forbids_content_fields` asserts that fields named like `filename`, `path`, `content`, `bytes_copied`, `hash` are rejected. We do not collect file names, file contents, keystrokes, screenshots, clipboard or browsing data. Serials are collected because allowlisting requires them; note that many cheap sticks report no serial at all (§ spike).
