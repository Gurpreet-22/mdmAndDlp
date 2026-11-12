# UbuntuGuard — Threat Model (Phase 0)

**Status:** design. Every control below is **UNVALIDATED** until the named test exists and passes.
**Scope:** prototype, 10–50 devices, Ubuntu 22.04 / 24.04 LTS desktop, x86_64.
**Guiding rule:** monitoring is not prevention. We claim prevention only where an enforcement test passes.

---

## 1. Assets (what an attacker wants)

| ID | Asset | Why it matters |
|----|-------|----------------|
| A1 | Policy signing private key (Ed25519) | Signs it, owns every agent's enforcement state |
| A2 | Internal CA private key | Mints device identities, impersonates any laptop |
| A3 | Device private key + client cert | Impersonates one laptop |
| A4 | Enrollment tokens | Joins a rogue device to the fleet |
| A5 | Admin credentials / refresh tokens | Fleet-wide control, data export |
| A6 | Audit log integrity | Hides what an attacker or insider did |
| A7 | USB event + inventory metadata | Device fingerprints; privacy-relevant |
| A8 | Enforcement availability | Turning control *off* is the cheapest attack |

A1, A2 are stored outside the database and outside TLS material. A7 deliberately excludes file names and file contents.

## 2. Trust boundaries

```
 [admin browser] --TLS--> B1 --> [nginx] --> [FastAPI] --B4--> [PostgreSQL]
 [agentd on laptop] --TLS+mTLS--> B2 --> [nginx] --> [FastAPI]
 laptop internals:   user session --B3--> agentd (uid ubuntuguard) --B3--> enforcerd (root) --> usbguard
```

- **B1** untrusted internet → server, bearer-token auth, RBAC on every route.
- **B2** untrusted internet → server, mTLS client cert = device identity; app layer re-checks device status.
- **B3** unprivileged → root on the laptop. Unix socket, `SO_PEERCRED` uid check, fixed typed operations, no shell, no server-supplied paths or commands, enforcerd re-validates every request.
- **B4** app → database. Least-privilege role; **no UPDATE/DELETE on `audit_logs`**.

## 3. Adversaries

**In scope:** `ADV-NET` active network attacker (MITM, replay) · `ADV-USER` standard (non-root) user on a managed laptop — *the primary DLP target* · `ADV-CLONE` attacker with a cloned disk image or VM snapshot · `ADV-ADMIN` compromised low-privilege admin account (auditor/analyst) · `ADV-SERVER` compromised server (blast-radius limit, not prevented).

**Out of scope (prototype):** local root on the laptop (see §5), physical disk removal / cold boot, firmware & BIOS implants, Ubuntu supply chain, DoS/volumetric, content-aware exfiltration (email, cloud upload, screenshots, printing), non-Ubuntu OSes.

## 4. Threats and controls

| ID | Threat | Adversary | Control | Proven by (Phase / test) |
|----|--------|-----------|---------|--------------------------|
| T1 | Intercept or tamper with agent↔server traffic | ADV-NET | HTTPS only, TLS 1.2+, pinned CA bundle, no plaintext fallback compiled in | 1 · `test_tls_required`, `test_http_refused` **UNVALIDATED** |
| T2 | Forge or modify a policy | ADV-NET, ADV-SERVER | Ed25519 signature over **exact transmitted bytes**, verified *before* parsing; key separate from DB/TLS keys | 4 · `test_tampered_payload_rejected` **UNVALIDATED** |
| T3 | Replay an old policy to re-enable USB | ADV-NET, ADV-USER | Monotonic version per scope; downgrade rejected; last-known-good persisted | 4 · `test_downgrade_rejected` **UNVALIDATED** |
| T4 | Steal/replay an enrollment token | ADV-NET, ADV-USER | 32 random bytes, stored hashed, single use, 24 h default, atomic consume | 1 · `test_token_single_use_race` **UNVALIDATED** |
| T5 | Enroll a rogue device | ADV-CLONE | Token + agent-generated keypair + CSR; server-issued cert; no self-asserted identity | 1 · `test_enroll_requires_valid_token` **UNVALIDATED** |
| T6 | Clone a managed laptop image | ADV-CLONE | Keypair generated at enrollment, never in the image; duplicate machine-id/fingerprint ⇒ distinct device + clone alert | 1 · `test_clone_raises_alert` **UNVALIDATED** |
| T7 | Keep using a revoked device | ADV-USER | Device status checked server-side on **every** request ⇒ rejection on next call (≤5 s target) | 1 · `test_revoked_device_rejected` **UNVALIDATED** |
| T8 | Escalate privilege via the agent | ADV-USER | agentd unprivileged; enforcerd root but narrow: fixed typed ops, `SO_PEERCRED`, no shell, no exec of server input | 2 · `test_peercred_rejects_other_uid`, `test_unknown_op_rejected` **UNVALIDATED** |
| T9 | Server pushes arbitrary commands to laptops | ADV-SERVER | Protocol carries **data only** (schema-validated JSON). No command, script or path field exists anywhere in the API | 4 · `test_schema_rejects_unknown_fields` **UNVALIDATED** |
| T10 | Copy company data to a USB stick | ADV-USER | usbguard allowlist enforcement; rules hold at boot before network; last verified policy enforced offline | 5 · spike + `test_usb_block_standard_user` **UNVALIDATED — gated on the USBGuard spike** |
| T11 | Silence the agent (kill / uninstall / block network) | ADV-USER | Unprivileged user cannot stop a systemd unit or edit `/etc/ubuntuguard`; server computes offline after 3 missed beats + 60 s; offline device keeps enforcing | 2,5 · `test_offline_detection`, `test_enforce_while_offline` **UNVALIDATED** |
| T12 | Lose events by crashing the agent | ADV-USER | SQLite WAL durable queue, at-least-once, agent-generated event IDs, server dedupes | 2 · `test_kill9_recovery`, `test_1000_events_exactly_once` **UNVALIDATED** |
| T13 | Read/alter data beyond role | ADV-ADMIN | Server-side RBAC on every admin route; role matrix test; no client-side-only checks | 1 · `test_rbac_matrix` **UNVALIDATED** |
| T14 | Brute-force admin login | ADV-NET | Argon2id, 5 failures / 10 min lockout, generic errors, 15 min access + 8 h rotating refresh | 1 · `test_lockout`, `test_generic_error` **UNVALIDATED** |
| T15 | Rewrite history to hide an action | ADV-ADMIN, ADV-SERVER | Append-only hash-chained audit log; DB role lacks UPDATE/DELETE; chain verification endpoint | 1 · `test_audit_chain_detects_tamper`, `test_db_role_cannot_update_audit` **UNVALIDATED** |
| T16 | Shift the clock to expire/extend things | ADV-USER | Monotonic timers for scheduling; ±5 min skew tolerance (fixed constant, not policy-tunable); exception expiry re-checked from signed absolute time | 2,5 · `test_clock_skew`, `test_exception_expiry_survives_restart` **UNVALIDATED** |
| T17 | Over-collect user data | — | Schema allows only vendor, product, serial, class, time, decision. No file names, no contents, no keystrokes, no screen capture | 5 · `test_event_schema_forbids_content_fields` **UNVALIDATED** |
| T18 | Lock a user out of their own laptop | — | HID, hub, audio/video and USB-C dock classes always allowed; policy that would block input devices is rejected server-side *and* agent-side | 5 · `test_policy_cannot_block_hid` **UNVALIDATED** |

## 5. Accepted risks (prototype)

1. **A local root user can bypass the agent.** Root can stop enforcerd, flush usbguard rules, or unload modules. We offer **detection and response**, not a guarantee. Rationale: defending root-from-root needs a hardened boot chain and remote attestation, outside prototype scope. Mitigation available later: lockdown LSM, measured boot, tamper events.
2. **Server compromise disables enforcement.** An attacker with A1 can sign a permissive policy. Not prevented; limited by: signed-and-versioned policies (every change is attributable), append-only audit, and a protocol with no command channel — so a compromised server still cannot run code on a laptop.
3. **No content inspection.** A user may read a file and type, photograph or paste it elsewhere. Out of scope by design.
4. **No MFA/SSO, no secrets manager, no HA, no signed apt repo.** Explicitly out of prototype scope.
5. **usbguard root bypass and no-serial devices** are documented limitations, to be measured by the Phase 0 spike before the USB feature is built.

## 6. Security invariants fixed in code (never configurable)

HTTPS only · signature verified before parse · policy version must increase · hard min/max bounds clamp every tunable · clock skew tolerance 300 s · enforcerd accepts a fixed operation set only · audit log append-only. Dev-only env overrides are compiled out of release builds.
