# UbuntuGuard endpoint agent

Python endpoint agent for the UbuntuGuard MDM + DLP control plane. Installed on
managed Ubuntu laptops; enrols with the server, reports inventory, applies
signed policies, and enforces the USB control.

**Phase 2 is complete: the agent enrols, authenticates and heartbeats.**

What exists: configuration, structured logging with tested redaction, the
service lifecycle, the OS adapter boundary, the Ed25519 policy-verification
core checked against the committed signing vector, and — new in Phase 2 — local
keypair generation, CSR generation, enrollment, certificate installation, an
HTTPS client with pinned-CA and client-certificate support, and a heartbeat over
mutual TLS.

Certificate renewal now works too: the agent rotates its keypair and
certificate at half-life, and never gives up a working identity to do it.

What does not exist: inventory reporting, policy application and USB
enforcement.

### How renewal avoids bricking a laptop

Worth reading once, because the ordering is the design rather than an
implementation detail.

A renewal replaces two files, which cannot be one atomic operation. So the new
keypair, CSR and certificate are staged under `pki/*.new` and swapped only once
all three are present and verified. Until that moment the old key and
certificate are untouched and still working, so a failure anywhere costs a
retry rather than an identity. A crash *during* the swap is recovered at the
next start-up: `complete_pending_renewal` reads what is on disk and either
finishes the swap or discards an attempt that never got a response.

The other half is server-side. A renewal supersedes the old certificate
immediately, which would normally mean an agent whose response was lost in
transit is holding a dead credential and cannot ask again. So the server keeps
accepting a superseded certificate for **the renewal endpoint only**, for one
hour, and the retry is idempotent on the CSR's public key — it returns the
certificate already issued rather than a second one. A superseded certificate
cannot heartbeat; that is `client_cert_superseded`.

## Two things this build does not claim

**The agent cannot verify that mTLS is actually enforced.** The server's device
plane takes its identity from `X-Client-Verify` and `X-Client-Cert`, which nginx
sets from a terminated mTLS connection and must overwrite unconditionally on
every request. That configuration now exists, in `deploy/nginx/`, along with a
test that parses it and fails if any proxying location leaves a header
unset — but it is a configuration an operator has to install, and nothing the
agent can see from inside a TLS session tells it whether the proxy on the other
end is enforcing `ssl_verify_client on` or happily accepting forwarded headers
from anyone. So `ubuntuguard-agent status` still reports
`mtls_verified: false`. The agent reports what it can check; the claim that
mTLS is enforced belongs to whoever deployed the proxy and ran the verification
commands in `deploy/nginx/README.md`.

**Ubuntu 22.04 and 24.04 are untested.** The agent targets Python 3.10 so one
build covers both, and it reads only interfaces those releases provide. It has
been exercised on CPython 3.10 and 3.12 and on the development machine
(Ubuntu 26.04). That is not the same as running on a target release. Support for
22.04 and 24.04 is `UNVALIDATED`, and so is the systemd unit's hardening.

## Layout

```
agent/
  src/ubuntuguard_agent/
    cli.py           run / enroll / status / selftest / version
    config.py        four-level precedence, HTTPS invariant, settings clamping
    constants.py     invariants and bounds, mirroring the server's
    enrollment.py    token handling, the enrollment sequence, retry policy
    errors.py        the closed reason-code vocabulary
    heartbeat.py     the one authenticated request, and clamping its response
    http.py          the HTTPS client: pinned CA, client certificate, no redirects
    identity.py      paths, permissions, keypair, CSR, certificate install
    logging_setup.py JSON formatter and the redaction filter
    service.py       signal handling and task registration
    core/            no OS calls, no filesystem, no network
      canonical.py     length-prefix encoding, byte-identical to the server
      envelope.py      Ed25519 envelope verification
      runtime.py       the service loop
      scheduler.py     jitter, backoff, clock-jump detection
    osadapter/       the only package that touches the operating system
      base.py          the fixed adapter interface
      ubuntu.py        the one implementation
      facts.py         pure parsers for /proc, /sys, /etc/os-release
  packaging/
    systemd/ubuntuguard-agent.service
    install.sh  uninstall.sh  etc/agent.yaml.example
  tests/
```

The proxy configuration the device plane depends on lives outside this
directory, in `deploy/nginx/`, because it is a server-side deployment concern
rather than part of the agent package.

The `core/` and `osadapter/` split is features D1 and D2: a platform-neutral
core behind a fixed adapter interface. It is what lets the policy-format tests —
the ones that catch a byte-level disagreement with the server — run with no
laptop, no server and no database. The directory is `osadapter/` rather than
`platform/` to avoid shadowing a standard-library module name.

Two directories named in the design are deliberately absent until they have
something in them: `queue/` (the durable SQLite event queue, Phase 7) and
`enforcer/` (the root component, Phase 7). The enforcer socket path is already
declared in `AgentPaths` so the privilege boundary has an address.

## Dependencies

Runtime: `cryptography` and `PyYAML`. That is all, including now that the agent
makes HTTP requests.

`httpx` was the Phase 1 plan and was rejected when the client was actually
written. `urllib.request` with an explicit `ssl.SSLContext` does everything
needed — a pinned CA, a client certificate, timeouts, no redirects — and httpx
would add six transitive dependencies to software installed on employee
laptops. `tools/demo_api.py` already drives this API from the standard library,
so the pattern is proven against this server rather than assumed.
`pyproject.toml` carries the full reasoning. `psutil` is not here because every field
`schemas/inventory.v1.schema.json` requires is readable from `/proc`, `/sys` and
`/etc/os-release` — it would earn its place only if the CPU, RAM and disk fields
are added. `structlog` is not here because the formatter and redaction filter
are shorter than the integration, and "no secrets in logs" is a requirement, so
the redaction has to be a plain function a test can call directly.
`pyproject.toml` carries the full reasoning.

## Development

```bash
cd agent

# A user-local CPython 3.10 via uv, matching the repository's existing
# toolchain decision (docs/03-decisions-and-conflicts.md C1/D12).
# Nothing is installed system-wide.
uv venv --python 3.10 .venv
uv pip install --python .venv/bin/python -e ".[dev]"

.venv/bin/python -m pytest              # the whole suite, no network, no root
.venv/bin/python -m pytest -q --no-header
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check src tests
.venv/bin/python -m mypy
```

The suite needs no server, no database and no privileges. Tests that would need
otherwise carry a marker (`integration`, `root`, `hardware`, `ubuntu`) and are
skipped by default, so a plain `pytest` can never reach the development
database or a protected account.

### Running it without installing

```bash
export PYTHONPATH=src
export UG_AGENT_DEV=1
export UG_AGENT_STATE_DIR=/tmp/ug-state

.venv/bin/python -m ubuntuguard_agent status
.venv/bin/python -m ubuntuguard_agent selftest
.venv/bin/python -m ubuntuguard_agent run     # Ctrl-C to stop
```

`UG_AGENT_DEV=1` is the gate on the level-4 environment overrides.
Setting it forces `release_build` to false, which is reported to the server and
flagged in the dashboard — a development box shows up as one rather than passing
for a managed laptop.

## Installing on a host

```bash
sudo ./packaging/install.sh          # add --dry-run to see every action first
sudo vi /etc/ubuntuguard/agent.yaml  # server_url and server_ca_bundle
/opt/ubuntuguard/venv/bin/ubuntuguard-agent selftest

# Enrol. The token comes from the dashboard and is single use.
sudo install -m 0600 /dev/null /run/ubuntuguard-token
sudo sh -c "printf '%s' '<token>' > /run/ubuntuguard-token"
sudo /opt/ubuntuguard/venv/bin/ubuntuguard-agent enroll \
    --token-file /run/ubuntuguard-token
sudo shred -u /run/ubuntuguard-token

sudo systemctl start ubuntuguard-agent
journalctl -u ubuntuguard-agent -f
```

**There is no `--token` option, and that is the control rather than an
oversight.** `/proc/<pid>/cmdline` is world-readable on Linux, so a token
passed as an argument is published to every user on the machine and visible to
anything sampling `ps`. An option that accepted one and warned would be worse
than none: by the time the warning printed, the value would already be exposed.
`tests/test_cli_and_service.py` asserts the option does not exist, because the
mistake is an easy and well-meaning one.

To avoid the disk entirely, pipe it in:

```bash
pass show ubuntuguard/token | sudo -E \
    /opt/ubuntuguard/venv/bin/ubuntuguard-agent enroll --token-stdin
```

The installer creates an unprivileged `ubuntuguard` account, a virtualenv under
`/opt/ubuntuguard` owned by root (so the service cannot rewrite its own code),
and `/var/lib/ubuntuguard/pki` at mode 0700. It **enables** the unit, which is
what brings the agent back after a reboot, and does not start it — a freshly
installed agent has no server configured.

It does not enrol the device. Enrollment consumes a single-use token and creates
an auditable identity, so it is an operator action rather than a side effect of
installing a package (feature D11). It also means a reimaged laptop does not
silently acquire a second device record because systemd brought the agent up.

Enrollment is idempotent in the keypair but not in the token. The private key
and CSR are written to `pki/` **before** the first request, so a run that fails
on a network error can be retried and will present the same public key — which
is what lands it on the server's 60-second idempotency cache and returns the
original certificate. Past that window the token is spent; `status` and the
failure message both say to check the dashboard before minting another, because
an enrollment that looked like it failed may well have succeeded.

Removal keeps the identity by default, because deleting a private key is not
reversible and re-enrolling creates a second device row for one laptop:

```bash
sudo ./packaging/uninstall.sh            # service and code only
sudo ./packaging/uninstall.sh --purge    # also the key and state; asks first
```

## Configuration

`/etc/ubuntuguard/agent.yaml` carries exactly two keys, and the shortness is the
point:

```yaml
server_url: https://ubuntuguard.example.internal
server_ca_bundle: /etc/ubuntuguard/server-ca.pem
```

Every tunable — heartbeat interval, backoff, log level, queue sizes — comes from
compiled defaults and may only be changed by a signed `agent_settings` policy,
which is auditable. An operator with root on a laptop cannot widen a heartbeat
interval by editing a file. Any third key is an error that names it, rather than
being silently ignored.

`server_ca_bundle` validates the **server**. It is not the device CA chain from
the enrollment response, which is the issuer of this laptop's own client
certificate and lives at `/var/lib/ubuntuguard/pki/ca-chain.pem`. Two trust
stores, two jobs; conflating them is the easiest mistake in this file.

Precedence, from `docs/02-policy-and-signing.md` section 5:

1. compiled defaults (`constants.py`)
2. `/etc/ubuntuguard/agent.yaml` — server URL and CA bundle only
3. a signed `agent_settings` policy, **clamped** (Phase 6)
4. dev-only environment overrides, gated on `UG_AGENT_DEV=1`

Still two keys. The development nginx configuration splits the two planes
across ports 8443 and 8444, which needs a second URL, and that lives at level 4
as `UG_AGENT_DEVICE_URL` rather than becoming a third key here. Production
splits by hostname on 443, so one `server_url` covers both planes and the
override is never set — see `deploy/nginx/README.md`.

Level 3 clamps rather than rejects, which is decision D5 and is easy to get
backwards: the server rejects an out-of-range setting so an admin is told
immediately, and the agent clamps so it never bricks itself over a value from a
newer server. Every clamp emits a record, because a silent clamp is a debugging
trap — an operator sets 5 seconds, sees 30, and has nothing to explain it.

## Transport security

HTTPS only. There is no plaintext fallback. The single exception needs three
conditions at once: a development build (`UG_AGENT_DEV=1`), an explicit
opt-in (`UG_AGENT_ALLOW_PLAINTEXT_HTTP=1`), **and** a loopback host.
The third is what makes it safe to keep in the tree — even with both flags, the
agent will not send an enrollment token to another machine in clear — and the
agent logs a warning on every start when it is active.

## Where the agent must match the server byte for byte

`core/envelope.py` and `core/canonical.py` reimplement the server's
`services/policy_signing.py` and `canonical.py`. `testdata/policy_vectors.json`
is what proves they agree, and `tests/test_envelope_conformance.py` checks it in
layers — key derivation, then the signing input's length, then its SHA-256, then
the signature — so an encoding bug reports as an encoding bug rather than as a
mysterious verification failure.

Three details will silently break verification if they drift:

- a null `expires_at` encodes as the **empty string**, not with the presence
  byte in `canonical.lp_opt_str`;
- timestamps are used **exactly as they arrived**, never reformatted;
- `payload_sha256` is **advisory** and outside the signing input.

All three are asserted by the suite, so changing one fails a test that says why.
