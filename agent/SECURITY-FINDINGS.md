# Security findings — agent Phase 1

A standing record, opened during Phase 1. Nothing here has been silently
changed; each item states what was found, what was done, and what is still
outstanding.

Scope note: items 1, 4 and 5 are server-side and were **not** touched. Changing
them requires the approval the development rules reserve for backend,
authentication and configuration changes.

---

## 1. `UBUNTUGUARD_ALLOW_ANY_LOGIN=1` was active in `server/.env`

**Severity:** high in effect, contained in practice. **Status:** CLOSED. Verified
disabled during the Phase 2 audit.

`server/.env` line 25 now reads `# UBUNTUGUARD_ALLOW_ANY_LOGIN=1`, commented
out, with an inline note dating the change to 2026-11-04 "ahead of Phase 2
enrollment". The absent setting is the secure state: `allow_any_login` defaults
to false in `config.py`, so commenting it out restores real Argon2id
authentication rather than leaving an unset variable to be interpreted.

The rest of this entry is kept as the record of what the finding was.

With it set, `POST /api/v1/auth/login` accepted **any** email and **any**
password, created the account on first use, and granted `super_admin`.

What that means for the agent specifically: `super_admin` can mint enrollment
tokens and revoke devices. So anyone who can reach port 8000 can enrol a device
of their choosing or revoke a real one. That is the agent's entire trust
bootstrap reachable without a credential.

Three things contain it, and they are the reason this is a development-box
exposure rather than a product hole:

- A config validator refuses to start in production with the flag set
  (`server/src/ubuntuguard/config.py`, `_enforce_production_requirements`).
- The API binds to `127.0.0.1`.
- Accounts it creates become unreachable rather than open once the flag is off:
  their stored hash is Argon2id over 32 random bytes that are discarded.

**Outstanding, and it is not this flag.** Real password authentication is back,
and SSO still does not exist. Recovering a lost password now needs
`python -m ubuntuguard.cli set-password --email <address>`. The note in
`server/.env` says "Do NOT re-enable", which is the right instruction; nothing
enforces it beyond the production config validator, so a developer could
uncomment it. That is acceptable for a development box on loopback and would
not be in a shared environment.

---

## 2. Device authentication depends on an nginx configuration an operator must install

**Severity:** blocks a security claim. **Status:** PARTIALLY CLOSED in Phase 2.
The configuration now exists; it has not been run on a target release.

The device plane derives identity from the `X-Client-Verify` and `X-Client-Cert`
headers, which nginx is required to set from a terminated mTLS connection and to
**overwrite unconditionally on every request**.

**Done in Phase 2.** `deploy/nginx/` carries two HTTPS listeners (8443
enrollment with no client certificate, 8444 device management with
`ssl_verify_client on`), a shared header snippet that overwrites all four
identity headers on every proxying location, `limit_req` on `/enroll` and
`/auth/login`, and `make_dev_tls.py` to generate the material. The agent
presents its client certificate on every device-plane request.

`server/tests/test_nginx_config.py` parses the configuration — rather than
grepping it — and fails if a location proxies to the API without including the
header snippet, if `ssl_verify_client` is not `on` on the device listener, if
`optional_no_ca` appears anywhere, if `ssl_client_certificate` does not look
like the device CA, or if the upstream is not loopback. That test exists because
nginx's `proxy_set_header` directives are **not** inherited into a location that
defines any of its own, so adding one header silently drops the other three, and
the application keeps working while authenticating whoever asks.

**Outstanding.**

- `nginx -t` and the handshake-level verification commands in
  `deploy/nginx/README.md` have not been run: nginx is not installed on the
  development machine. They are written down and are an operator step.
- Nothing the agent can observe from inside a TLS session proves the proxy is
  enforcing `ssl_verify_client`, so `status` still reports
  `mtls_verified: false`. That is deliberate and should stay until there is
  something real to check.
- A test that a forged header from an untrusted address is refused exists at the
  function level (`test_certificate_headers_from_an_untrusted_peer_are_refused`).
  The end-to-end version, through a running nginx, is the gap.

Consequence: the only way to authenticate as a device today is to set those
headers yourself from a trusted-proxy address, which is impersonation rather
than authentication. Anyone who can reach the app from `127.0.0.1` can present
any device's certificate.

The server side is not at fault — it refuses the headers outright from an
untrusted peer rather than ignoring them, so a misconfiguration fails loudly.
The missing piece is the proxy.

`test_status_never_claims_mtls_is_verified` fails if the reported value is ever
softened.

---

## 3. The agent's environment prefix collided with the server's namespace

**Severity:** availability, development only. **Status:** FIXED in Phase 1.

The agent originally used `UBUNTUGUARD_AGENT_` for its development overrides.
The server's settings loader refuses to start when it sees any `UBUNTUGUARD_*`
variable it does not recognise, and it matches by **prefix**
(`_reject_unknown_prefixed_env_vars`). So `UBUNTUGUARD_AGENT_DEV` reads to the
server as a misspelled server setting, and simply having it exported in a shell
stopped the API from constructing its settings at all.

Found by running the agent CLI and then the server suite in the same shell: 34
server tests errored. Measured, cleanly:

| Environment | Server suite |
|---|---|
| clean | 472 passed |
| `UG_AGENT_*` exported (after the fix) | 472 passed |
| `UBUNTUGUARD_AGENT_DEV=1` exported (the bug) | 438 passed, **34 errors** |

**Fixed** by moving the agent to `UG_AGENT_`, which matches the convention the
repository already uses for `UG_ALLOW_DESTRUCTIVE_TESTS`.
`tests/test_no_env_collision_with_server.py` is the regression guard.

The server's validator was **not** modified. Adding the agent's names to its
allowlist would also have worked and would have been the wrong fix: it widens a
typo check that exists to catch this class of mistake, and it would make the
server's configuration depend on the agent's.

---

## 4. `POST /api/v1/enroll` has no rate limiting

**Severity:** low. **Status:** OPEN, server-side, for Phase 2.5.

`docs/01-api-contract.md` states the endpoint is "Rate-limited per IP". It is
not: `problems.rate_limited` exists with no caller.

Token guessing is not the concern — a token is 32 random bytes. The exposure is
unauthenticated CSR parsing and certificate issuance, which is asymmetric work:
a small request causes key-size validation and signature verification.

**Recommended:** nginx `limit_req` on the enroll location, alongside the Phase
2.5 configuration. Application-level limiting would be the wrong layer.

---

## 5. Certificate renewal does not exist, which is a 30-day fuse

**Severity:** high operationally. **Status:** OPEN, server-side, Phase 5.

Device certificates live 30 days. There is no renewal endpoint. Every enrolled
device therefore drops off the control plane 30 days after enrollment, with no
recovery short of re-enrollment using a new admin-minted token. The fuse is lit
by the first enrollment, so this becomes urgent the moment Phase 2 ships.

**Done in Phase 1:** the agent computes `renew_after` locally at 50 % of
lifetime — so the decision works offline rather than depending on the server's
`certificate_renew_after` field — and reports an expiring or expired
certificate through `status`, `selftest` and a warning on every service cycle.
It does not attempt renewal, and says why.

**Agreed:** renewal moves ahead of inventory in the roadmap.

---

## 6. Compatibility and hardening are unvalidated

**Severity:** not a vulnerability; an unproven claim. **Status:** OPEN by design.

The agent has **not** been run on Ubuntu 22.04 or 24.04. It has been exercised
on CPython 3.10 and 3.12 and on the development host (Ubuntu 26.04). The
systemd unit has been checked with `systemd-analyze verify` and has not been
started on a target release.

`MemoryDenyWriteExecute=yes` and `SystemCallFilter=@system-service` are the two
directives most likely to prevent the service from starting on an untested
release, because some Python extension modules allocate executable memory. The
unit names both in a comment so the first thing to try is written down.

**Encoded rather than documented:** `osadapter.VALIDATED_OS_VERSION_IDS` is an
empty set, and `is_validated_release()` is false everywhere as a result. It is
deliberately separate from `is_supported()`, which only answers whether the
adapter is the right implementation. `status` and `selftest` report the two
independently, so a green adapter can never be read as a tested release. Adding
`"22.04"` and `"24.04"` to that set requires having actually run the agent
there.

---

## Carried forward into later phases

| Item | Status |
|---|---|
| nginx mTLS configuration | **DONE** in Phase 2 (`deploy/nginx/`), with a config-parsing test. `nginx -t` and the handshake checks are an operator step; nginx is not installed on the development machine |
| `limit_req` on `/enroll` | **DONE** in Phase 2. Also on `/auth/login`, which is the other unauthenticated endpoint doing expensive work |
| Enrollment token handling: stdin or a 0600 file, never `argv` (visible in `ps`) | **DONE** in Phase 2. `--token` does not exist, and a test asserts its absence |
| Forged-header refusal, end to end through a running nginx | Open. Covered at the function level only |
| Certificate renewal, without ever discarding a valid identity on failure | **DONE.** `POST /devices/me/certificate:renew`, authenticated by the certificate being replaced. The agent stages a new keypair and CSR before sending anything, verifies the replacement against the staged key, and swaps only once everything is present — so a failure at any point leaves the old identity installed and working. A crash mid-swap is recovered at the next start-up rather than leaving a mismatched pair. See item 7 below for what remains |
| Resume-from-sleep rescheduling the heartbeat | Open. The clock step is detected and reported; nothing acts on it |
| Transport reason codes | Open. `ReasonCode` has no vocabulary for a connectivity failure, so transport errors report `unknown`. Harmless today because there is no event queue; revisit when Phase 7 adds one |
| Policy key rotation; the signed `key_rotation` record is unimplemented | Open |
| Root enforcer: fixed typed operations, `SO_PEERCRED`, no shell, no paths from the server | Phase 7 |
| USBGuard enforcement spike on real hardware; nothing may be claimed before it runs | Phase 7 |

---

## 7. The renewal grace window widens device authentication, deliberately

**Severity:** a trade-off, not a defect. **Status:** ACCEPTED, bounded, tested.

Device authentication now resolves a certificate through
`issued_certificates` rather than the single `devices.cert_fingerprint` pin, so
that a certificate a renewal has just superseded can still be presented for a
short time. That is a genuine widening and is recorded here rather than buried
in a docstring.

**Why it is necessary.** With a hard cutover, the sequence "server commits the
renewal, response lost in transit" leaves the agent holding a certificate the
server has just invalidated, with no other credential. It cannot retry, so it
cannot recover, and a single dropped packet costs a re-enrollment. A renewal
that bricks a laptop whenever the network blinks is not a renewal.

**What the widening actually is.** For at most one hour after a renewal, two
certificates for one device will authenticate. Narrow in three independent
ways:

- **Time.** `CERT_SUPERSEDE_GRACE_SECONDS = 3600`. The agent retries on a
  backoff capped at 900 s, so an hour covers several attempts. Negligible
  against a 30-day certificate.
- **Scope.** The renewal endpoint only. `get_device_principal` is the strict
  dependency and refuses a superseded certificate with
  `client_cert_superseded`; `get_renewing_device_principal` is the loose one
  and exactly one route uses it. A new device route that reaches for the
  obvious name gets the tight behaviour without knowing the distinction exists.
- **Effect.** The retry is idempotent on the CSR's public key, so it returns
  the certificate already issued rather than a second one. The window cannot be
  used to accumulate certificates.

**What has not changed.** Revocation still outranks everything:
`device.status != 'active'` is checked before anything about the certificate, so
a revoked device is refused whatever it presents. The certificate's own
validity window is still re-derived from the certificate in
`security/device_auth.py` rather than trusted from the database, so an expired
certificate is refused even while its row says it is live. Both are tested.

**The alternative that was rejected.** Leaving the predecessor live until the
*next* renewal, 15 days later, would avoid any write in the authentication path
and never brick a device — but it would mean two valid certificates for a
fortnight, and `superseded_at` would stop being something the authentication
layer meaningfully enforced. One hour and an enforced flag is the better trade.

---

## 8. A weak key in an ENROLLMENT CSR returns 500 rather than 400

**Severity:** low; error classification, not a security hole.
**Status:** OPEN, found during renewal work, deliberately not changed.

`services/enrollment.py` wraps `load_csr_pem` in a try block that catches
`CsrRejectedError`, but the key-size and curve policy lives in `verify_csr`,
which enrollment does not call until `issue_device_certificate` does — outside
any handler. So `POST /api/v1/enroll` with an RSA-2048 CSR raises an uncaught
`CsrRejectedError` and the global handler returns `500 internal_error` instead
of `400 csr_invalid`.

Nothing leaks: the generic handler returns a fixed message, and the CSR is
still refused, so no weak key is ever certified. What is wrong is the status
code and the absence of a `device_enrollment_failed` audit row for that case.

Found because renewal had the identical bug and a test caught it there.
Renewal now calls `verify_csr` explicitly inside its try block. **The same
two-line fix applies to enrollment and was not applied**, because enrollment is
a working, tested path and changing it was outside the task that found this:

```python
# services/enrollment.py, in the step-1 try block
csr = load_csr_pem(request.csr_pem.encode("utf-8"))
verify_csr(csr)          # <- add this
public_key = csr.public_key()
```

`tests/test_ca.py` already covers the refusal at the unit level, which is why
the gap survived: no test drives a weak key through the HTTP layer.
