# nginx: TLS for the API, mutual TLS for the device plane

This directory is what makes device authentication real. Without it the device
plane can only be reached by setting the forwarded identity headers directly,
which is impersonation rather than authentication — and until an operator has
installed this, `ubuntuguard-agent status` will keep reporting
`mtls_verified: no`.

| File | What it is |
|---|---|
| `ubuntuguard-dev.conf` | Two HTTPS listeners for local development: 8443 enrollment, 8444 device management |
| `client-cert-headers.conf` | The four forwarded identity headers. **Read this one.** It is the security boundary |
| `make_dev_tls.py` | Generates the development certificates and copies the device CA into place |

`server/tests/test_nginx_config.py` parses `ubuntuguard-dev.conf` and fails if a
location proxies to the API without overwriting the identity headers, if
`ssl_verify_client` is not `on` on the device listener, or if the client CA
looks like the server's own. Run it with the server suite.

## The two trust stores

Getting these backwards is the most consequential mistake available here, so
they are named distinctly on disk and the test asserts they differ.

| File | Verifies | Consequence of using the wrong one |
|---|---|---|
| `server-ca.crt` | the **server** to the agent. The agent's `server_ca_bundle` | The agent would trust any public CA for an internal API |
| `device-ca.crt` | the **client** to nginx. `ssl_client_certificate` | Any publicly issued certificate would authenticate as a device |

`device-ca.crt` is a copy of whatever `UBUNTUGUARD_CA_CERT_PATH` names, which
is `server/var/ca.crt` by default. It is the certificate whose private key
`services/ca.py` signs device certificates with. Only the certificate is copied;
the private key stays in `server/var` at mode 0600 and nginx never reads it.

**Re-run `make_dev_tls.py` after `ubuntuguard.cli init-keys`.** Regenerating the
CA invalidates every device certificate nginx has been told to trust, and the
symptom is every agent failing with `client_cert_not_verified` at once.

## Why two listeners in development

The device plane has two kinds of request that need opposite TLS settings:

- `POST /api/v1/enroll` has **no** client certificate. The device does not have
  an identity yet; acquiring one is the point of the call. Its only credential
  is the single-use token in the body.
- `POST /api/v1/devices/me/*` **must** have one, verified against the device CA.

One listener cannot do both with `ssl_verify_client on`, because nginx aborts
the handshake when no certificate is presented — which is exactly the state an
enrolling device is in. So development splits them by port.

Two approaches were rejected:

- **`ssl_verify_client optional` with an `if` inside a location.** Works, and
  puts the enforcement in a conditional that is easy to edit wrongly. nginx's
  own documentation describes `if` in a location context as surprising.
- **`ssl_verify_client optional_no_ca`.** Never acceptable. It forwards the
  certificate *without verifying the chain*, so `$ssl_client_verify` stops
  meaning "issued by our CA" while still reporting `SUCCESS`. Every application
  check that trusts `SUCCESS` would then be trusting nothing. A test asserts it
  appears nowhere in this directory.

## Production: one port, split by hostname

The two-port split is a development convenience. In production both planes live
on 443 and nginx chooses the listener by SNI, which is why the agent needs only
one `server_url` and why `UG_AGENT_DEVICE_URL` is a development-only override.

The security properties are identical; what changes is that each `server` block
gets its own name and certificate.

```nginx
# Admin API and dashboard. No client certificate requested.
server {
    listen 443 ssl;
    http2 on;
    server_name ubuntuguard.company.internal;

    ssl_certificate     /etc/ssl/ubuntuguard/api.crt;
    ssl_certificate_key /etc/ssl/ubuntuguard/api.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location = /api/v1/enroll {
        limit_req zone=ug_enroll burst=5 nodelay;
        include /etc/nginx/ubuntuguard/client-cert-headers.conf;
        proxy_pass http://ubuntuguard_api;
    }
    location = /api/v1/auth/login {
        limit_req zone=ug_login burst=10 nodelay;
        include /etc/nginx/ubuntuguard/client-cert-headers.conf;
        proxy_pass http://ubuntuguard_api;
    }
    # Not served here.
    location ^~ /api/v1/devices/me/ { return 421; }

    location / {
        include /etc/nginx/ubuntuguard/client-cert-headers.conf;
        proxy_pass http://ubuntuguard_api;
    }
}

# Device plane. A verified client certificate is mandatory.
server {
    listen 443 ssl;
    http2 on;
    server_name devices.ubuntuguard.company.internal;

    ssl_certificate     /etc/ssl/ubuntuguard/devices.crt;
    ssl_certificate_key /etc/ssl/ubuntuguard/devices.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    ssl_client_certificate /etc/ssl/ubuntuguard/device-ca.crt;
    ssl_verify_client      on;
    ssl_verify_depth       1;

    location = /api/v1/enroll { return 421; }

    location ^~ /api/v1/devices/me/ {
        include /etc/nginx/ubuntuguard/client-cert-headers.conf;
        proxy_pass http://ubuntuguard_api;
    }
    location / { return 404; }
}
```

Two details that are easy to miss with SNI-based splitting:

- The agent's `server_url` must be the **admin** hostname for enrollment and the
  **device** hostname for the device plane. With one `server_url` the agent uses
  it for both, so in production either put both planes on one hostname and split
  by location with `ssl_verify_client optional` plus a location gate, or keep
  two hostnames and set `UG_AGENT_DEVICE_URL`. Two hostnames with the override
  is the configuration this repository tests.
- A client that connects **without** SNI gets the first matching `server` block
  for the address. Make that the admin block, so a missing SNI degrades to "no
  device plane" rather than "device plane without the mTLS settings you
  intended".

## What nginx proves, and what it does not

nginx proves the client holds the private key for a certificate issued by the
internal device CA and currently inside its validity window. That is all.

It does **not** prove the device is still authorised. There is deliberately no
CRL: revocation is enforced by the application on every single request
(`DbDeviceResolver.resolve_device` requires `status == 'active'`), so revoking a
device in the dashboard takes effect on that device's very next call. A CRL
propagates on a timer and would be strictly worse. Adding `ssl_crl` later is
defence in depth; the application check stays the authority.

So a revoked device still completes the TLS handshake and then gets
`401 device_not_active`. That is correct and is what the test for it asserts.

## Run uvicorn with `--no-proxy-headers`

The application decides whether to believe the `X-Client-*` headers by checking
`request.client.host` against `UBUNTUGUARD_TRUSTED_PROXY_IPS`. uvicorn's proxy
header handling makes Starlette rewrite `request.client.host` from
`X-Forwarded-For`, which makes the one value that check relies on come from a
request header.

**It is on by default.** `uvicorn.Config(proxy_headers=...)` defaults to `True`,
so omitting `--proxy-headers` does not disable it; `--no-proxy-headers` is
required. An earlier version of this section said the documented command "has
no such flag, keep it that way", which was wrong for exactly that reason.

The symptom is not subtle once a device is not on loopback. This proxy sets
`X-Forwarded-For $remote_addr`, so with the rewrite active the application sees
the *device's* address rather than nginx's, finds it absent from
`trusted_proxy_ips`, and refuses every device-plane request with
`401 untrusted_proxy`. Devices reaching the server over loopback keep working,
because for them the forwarded address happens to be `127.0.0.1` - so the
failure appears only once the deployment stops being a single laptop.

```bash
.venv/bin/python -m uvicorn ubuntuguard.main:create_app \
    --factory --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Keep the application bound to `127.0.0.1` as well. The two controls are
separate: the binding limits who can connect, and `--no-proxy-headers` keeps
the address of whoever connects from being overridden by what they send.

`server/tests/test_proxy_headers.py` asserts the committed run commands carry
the flag, so this cannot drift back.

## Install it

```bash
# 1. Key material. Needs the device CA to exist already:
#       cd server && .venv/bin/python -m ubuntuguard.cli init-keys
sudo server/.venv/bin/python deploy/nginx/make_dev_tls.py --dry-run   # review first
sudo server/.venv/bin/python deploy/nginx/make_dev_tls.py

# 2. The configuration. The include path is absolute in the config, so the
#    snippet has to land exactly here.
sudo install -d -m 0755 /etc/nginx/ubuntuguard
sudo install -m 0644 deploy/nginx/client-cert-headers.conf \
    /etc/nginx/ubuntuguard/client-cert-headers.conf
sudo install -m 0644 deploy/nginx/ubuntuguard-dev.conf \
    /etc/nginx/conf.d/ubuntuguard-dev.conf

# 3. Check and reload. `nginx -t` is the half the unit tests cannot do.
sudo nginx -t
sudo systemctl reload nginx
```

If nginx is not installed: `sudo apt-get install nginx`.

## Verify it

### The scripted way, which is the one that counts

`tools/verify_mtls.py` runs seventeen handshake-level checks and prints
pass/fail evidence for each. It exits non-zero if any fails, so it is the thing
to point at rather than a claim.

```bash
# Against THIS configuration, through a running nginx. This is what verifies
# the committed config.
server/.venv/bin/python tools/verify_mtls.py \
    --email <admin-email> --password '<password>' \
    --enroll-url https://localhost:8443 \
    --device-url https://localhost:8444 \
    --ca /etc/ubuntuguard/dev-tls/server-ca.crt
```

Needs the API on `127.0.0.1:8000` and the database up. It enrols two scratch
devices, revokes them at the end, and writes their identities under
`/tmp/ug-verify-mtls`.

What it checks: enrollment over TLS with no client certificate; the device
listener refusing a missing certificate and one from an unknown CA; the
enrolled certificate being accepted; the backend attributing the heartbeat to
the right device; **a verified connection as device A carrying device B's
certificate in a forged header being attributed to A, not B**; renewal over
mTLS; the replacement certificate heartbeating; the old certificate being
refused for the heartbeat but still accepted for an idempotent renewal retry;
and a revoked device being refused for both.

If nginx is unavailable, `--reference-proxy` starts the terminator in
`tools/mtls_reference_proxy.py` instead. **That verifies the contract, not this
configuration file.** The script says so in its own output, and so should
anyone quoting the result.

### By hand

Each command below should produce the stated result. A different one means the
configuration is not doing what it claims.

```bash
# The server certificate verifies against the CA the agent will be given.
openssl s_client -connect localhost:8443 \
    -CAfile /etc/ubuntuguard/dev-tls/server-ca.crt </dev/null 2>&1 \
    | grep -E 'Verify return code|Verification'
# expect: Verification: OK

# The device listener REFUSES a connection with no client certificate.
openssl s_client -connect localhost:8444 \
    -CAfile /etc/ubuntuguard/dev-tls/server-ca.crt </dev/null 2>&1 \
    | grep -iE 'alert|certificate required'
# expect: a handshake failure. This is `ssl_verify_client on` working.

# An enrolled device's certificate IS accepted.
openssl s_client -connect localhost:8444 \
    -CAfile /etc/ubuntuguard/dev-tls/server-ca.crt \
    -cert /var/lib/ubuntuguard/pki/device.crt \
    -key /var/lib/ubuntuguard/pki/device.key </dev/null 2>&1 \
    | grep -E 'Verify return code'
# expect: Verify return code: 0 (ok)

# A forged identity header is ignored, because nginx overwrites it.
# The 401 reason in the server log is client_cert_missing, NOT a successful
# authentication - the header the client sent never reached the application.
wget -qO- --header='X-Client-Verify: SUCCESS' \
     --header='X-Client-Cert: anything' \
     --ca-certificate=/etc/ubuntuguard/dev-tls/server-ca.crt \
     --post-data='{"agent_version":"0.1.0","uptime_seconds":1}' \
     --header='Content-Type: application/json' \
     https://localhost:8444/api/v1/devices/me/heartbeat
# expect: refused. Without a client certificate the handshake never completes.

# Rate limiting on enrollment.
for i in $(seq 1 20); do
  wget -qO/dev/null --ca-certificate=/etc/ubuntuguard/dev-tls/server-ca.crt \
       --post-data='{}' --header='Content-Type: application/json' \
       https://localhost:8443/api/v1/enroll 2>&1 | grep -o '429' || true
done
# expect: 429 once the burst is spent
```

## Known limitations

**The agent cannot confirm the proxy enforces mTLS.** Nothing observable from
inside a TLS session tells it whether the far end is running
`ssl_verify_client on` or accepting forwarded headers from anywhere. `status`
therefore reports `mtls_verified: no` even once this configuration is live.
That is deliberate: the agent reports what it can check, and the claim that
mTLS is enforced belongs to whoever deployed the proxy and ran the verification
above.

**This configuration has never been started.** nginx is not installed on the
development machine and could not be installed there, so `ubuntuguard-dev.conf`
has been parsed by `server/tests/test_nginx_config.py` and read by a human, and
that is all. `nginx -t` has not run against it. The mTLS *contract* is verified
— 17/17 checks against the reference terminator — but a typo in this file that
the config test does not cover would still be live. Running
`tools/verify_mtls.py` with `--enroll-url`/`--device-url` against a real nginx
is what closes that gap, and until someone does, treat this file as reviewed
rather than tested.

**There is no CRL.** Deliberate: revocation is enforced per request by the
application, which is immediate, where a CRL propagates on a timer. A revoked
device therefore completes the TLS handshake and is then refused with
`401 device_not_active`. The same applies to a certificate a renewal has
superseded: nginx accepts it, and the application refuses it with
`client_cert_superseded` — except at the renewal endpoint, for one hour, which
`agent/SECURITY-FINDINGS.md` item 7 explains.
