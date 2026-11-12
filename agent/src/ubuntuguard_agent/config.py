"""Configuration, with the precedence order the design specifies.

From docs/02-policy-and-signing.md section 5, four levels, lowest first:

  1. compiled defaults               -> constants.py
  2. /etc/ubuntuguard/agent.yaml     -> server URL and CA bundle ONLY
  3. signed `agent_settings` policy  -> tunables, clamped (Phase 6)
  4. dev-only environment overrides  -> absent from a release build

Level 2 is deliberately tiny. Every tunable lives at level 1 or 3, so an
operator cannot quietly widen a heartbeat interval by editing a file on the
laptop - that takes a signed policy, which is auditable. The file carries the
two things that cannot come from a policy, because they are what the agent needs
in order to *fetch* a policy at all.

Level 4 cannot be "compiled out" of a Python build the way it is in a compiled
language, so it is gated instead: the overrides are read only when
`UG_AGENT_DEV=1`, and setting that flag forces `release_build` to
False. That value is reported at enrollment and in inventory, and
`schemas/inventory.v1.schema.json` describes exactly this case - "False means
dev-only environment overrides are compiled in. The dashboard flags such
devices, because their effective settings may not match policy." So a developer
box is visible as a developer box rather than passing for a managed laptop.

Unknown keys in the YAML file are an error that names the key. That mirrors the
server's `_reject_unknown_prefixed_env_vars` validator and exists for the same
reason: a typo that is silently ignored sends an operator hunting in the wrong
place, because the agent reports "no server configured" while the file plainly
contains a server.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from ubuntuguard_agent import constants
from ubuntuguard_agent.errors import ConfigError
from ubuntuguard_agent.logging_setup import normalise_level

# --------------------------------------------------------------------------- #
# Filesystem layout
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG_PATH = Path("/etc/ubuntuguard/agent.yaml")
DEFAULT_STATE_DIR = Path("/var/lib/ubuntuguard")
DEFAULT_RUN_DIR = Path("/run/ubuntuguard")

#: The only keys agent.yaml may contain.
ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset({"server_url", "server_ca_bundle"})

#: Environment prefix for the dev-only overrides at precedence level 4.
#:
#: `UG_AGENT_` and deliberately NOT `UBUNTUGUARD_AGENT_`, which is the obvious
#: choice and is broken. The server's own settings loader refuses to start if it
#: sees any `UBUNTUGUARD_*` variable it does not recognise - a typo check, and a
#: good one - and it matches by prefix (`server/src/ubuntuguard/config.py`
#: `_reject_unknown_prefixed_env_vars`). So an agent variable named
#: `UBUNTUGUARD_AGENT_DEV` is, to the server, a misspelled server variable, and
#: exporting one in a shell stops the API from starting. That is not a
#: hypothetical: the documented development workflow runs both on one host.
#:
#: `tests/test_no_env_collision_with_server.py` is the regression guard.
ENV_PREFIX = "UG_AGENT_"

#: The gate. Without this, every other override below is ignored.
ENV_DEV_MODE = ENV_PREFIX + "DEV"

ENV_CONFIG_PATH = ENV_PREFIX + "CONFIG"
ENV_SERVER_URL = ENV_PREFIX + "SERVER_URL"
ENV_SERVER_CA_BUNDLE = ENV_PREFIX + "SERVER_CA_BUNDLE"

#: Dev-only: a separate base URL for the mTLS device plane.
#:
#: Why this exists, and why it is dev-only. The device plane needs mutual TLS
#: and `POST /enroll` must work without a client certificate, which one nginx
#: listener cannot provide: `ssl_verify_client on` aborts the handshake when no
#: certificate is presented, and that is exactly the state a device enrolling
#: for the first time is in. Production splits the two by HOSTNAME on port 443,
#: so one `server_url` covers both planes and this override is never set.
#: Development splits them by PORT (8443 enrollment, 8444 device) because
#: issuing two hostnames on a laptop is more ceremony than the problem
#: deserves - see deploy/nginx/README.md.
#:
#: Keeping it at level 4 rather than adding a third key to agent.yaml is
#: deliberate. That file is two keys on purpose, and a production deployment
#: has no reason to carry a second URL whose only job is to paper over a
#: development port split.
ENV_DEVICE_URL = ENV_PREFIX + "DEVICE_URL"
ENV_STATE_DIR = ENV_PREFIX + "STATE_DIR"
ENV_RUN_DIR = ENV_PREFIX + "RUN_DIR"
ENV_LOG_LEVEL = ENV_PREFIX + "LOG_LEVEL"
ENV_ALLOW_PLAINTEXT = ENV_PREFIX + "ALLOW_PLAINTEXT_HTTP"


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def dev_mode_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Whether the level-4 overrides are readable at all."""
    environ = os.environ if env is None else env
    return _is_truthy(environ.get(ENV_DEV_MODE))


# --------------------------------------------------------------------------- #
# Tunables (precedence levels 1 and 3)
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class AgentSettings:
    """The tunables, every one already inside its bound.

    Defaults come from constants.py, so there is one source for the compiled
    default and the range that guards it.
    """

    heartbeat_seconds: int = constants.HEARTBEAT_SECONDS.default
    heartbeat_jitter_pct: int = constants.HEARTBEAT_JITTER_PCT.default
    backoff_initial_seconds: int = constants.BACKOFF_INITIAL_SECONDS.default
    backoff_max_seconds: int = constants.BACKOFF_MAX_SECONDS.default
    inventory_interval_seconds: int = constants.INVENTORY_INTERVAL_SECONDS.default
    policy_poll_seconds: int = constants.POLICY_POLL_SECONDS.default
    event_batch_max: int = constants.EVENT_BATCH_MAX.default
    event_queue_max_events: int = constants.EVENT_QUEUE_MAX_EVENTS.default
    event_queue_max_age_days: int = constants.EVENT_QUEUE_MAX_AGE_DAYS.default
    log_level: str = constants.LOG_LEVEL_DEFAULT


@dataclasses.dataclass(frozen=True)
class ClampRecord:
    """One setting that was pulled into range.

    Becomes the `fields` object of a `settings_clamped` event, which is why the
    shape matches the example in schemas/event.agent.v1.schema.json:
    {"setting": ..., "requested": ..., "applied": ...}.
    """

    setting: str
    requested: Any
    applied: Any

    def as_event_fields(self) -> dict[str, Any]:
        return {"setting": self.setting, "requested": self.requested, "applied": self.applied}


def apply_settings_payload(
    payload: Mapping[str, Any],
    *,
    base: AgentSettings | None = None,
) -> tuple[AgentSettings, list[ClampRecord]]:
    """Fold a verified `agent_settings` payload into the current settings.

    Strict about structure, lenient about ranges. That asymmetry is decision D5
    and it is the whole point of this function:

    - an unknown field raises, because it means this build does not understand
      the policy and guessing is worse than reporting `unknown_field`;
    - an out-of-range value is clamped and recorded, because an agent that
      bricked itself over a number from a newer server would be a worse failure
      than one running at the nearest value it considers safe.

    The caller is expected to emit a `settings_clamped` event for every record
    returned. A silent clamp is a debugging trap - the operator sets 5 seconds,
    sees 30, and has nothing to explain it.

    Does NOT verify the signature. The payload must already have come out of
    `core.envelope.verify_envelope`, which returns bytes precisely so that
    parsing cannot happen before verification.
    """
    current = base if base is not None else AgentSettings()

    if not isinstance(payload, Mapping):
        raise ConfigError("agent_settings payload must be a JSON object")

    schema_id = payload.get("schema")
    if schema_id != constants.AGENT_SETTINGS_SCHEMA_ID:
        raise ConfigError(
            f"agent_settings payload has schema {schema_id!r}, "
            f"expected {constants.AGENT_SETTINGS_SCHEMA_ID!r}"
        )

    known = set(constants.AGENT_SETTING_BOUNDS) | constants.NON_NUMERIC_AGENT_SETTINGS | {"schema"}
    unknown = sorted(set(payload) - known)
    if unknown:
        raise ConfigError("agent_settings payload has unknown field(s): " + ", ".join(unknown))

    values: dict[str, Any] = dataclasses.asdict(current)
    clamped: list[ClampRecord] = []

    for name, bound in constants.AGENT_SETTING_BOUNDS.items():
        if name not in payload:
            continue
        requested = payload[name]
        # bool is a subclass of int, and `heartbeat_seconds: true` is a
        # structural error rather than a value to clamp to 30.
        if isinstance(requested, bool) or not isinstance(requested, int):
            raise ConfigError(f"{name} must be an integer, got {type(requested).__name__}")
        applied = bound.clamp(requested)
        values[name] = applied
        if applied != requested:
            clamped.append(ClampRecord(setting=name, requested=requested, applied=applied))

    if "log_level" in payload:
        requested_level = payload["log_level"]
        if not isinstance(requested_level, str):
            raise ConfigError(f"log_level must be a string, got {type(requested_level).__name__}")
        applied_level = normalise_level(requested_level)
        values["log_level"] = applied_level
        if applied_level != requested_level:
            clamped.append(
                ClampRecord(setting="log_level", requested=requested_level, applied=applied_level)
            )

    return AgentSettings(**values), clamped


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class AgentPaths:
    """Where the agent keeps things, and how private each one is.

    Grouped into one object so the layout is stated once and tests can relocate
    all of it under a temporary directory in a single step.
    """

    state_dir: Path
    run_dir: Path

    @property
    def pki_dir(self) -> Path:
        """Private key, certificate and the device CA chain. Mode 0700."""
        return self.state_dir / "pki"

    @property
    def private_key_path(self) -> Path:
        """The device private key. Mode 0600, and it never leaves this host."""
        return self.pki_dir / "device.key"

    @property
    def certificate_path(self) -> Path:
        """The client certificate the server issued. Public material."""
        return self.pki_dir / "device.crt"

    @property
    def pending_private_key_path(self) -> Path:
        """The NEXT private key, during a renewal. Mode 0600.

        A renewal cannot be a single atomic filesystem operation: the key and
        the certificate are two files, and a crash between replacing them
        leaves a pair that does not match, which is an identity the agent
        cannot use and cannot explain.

        So renewal stages the new material under these three `.new` paths and
        swaps only once all of it is present and verified. That makes the
        window recoverable rather than merely narrow:
        `identity.complete_pending_renewal` inspects what is on disk at
        start-up and either finishes the swap or discards a staging attempt
        that never completed. The old identity keeps working throughout,
        because nothing touches it until the replacement is in hand.
        """
        return self.pki_dir / "device.key.new"

    @property
    def pending_csr_path(self) -> Path:
        """The CSR for `pending_private_key_path`, persisted before it is sent.

        Same reason as `csr_path`: the server's renewal idempotency is keyed on
        the CSR's public key, so a retry has to present the same one or it gets
        a second certificate instead of the one already issued.
        """
        return self.pki_dir / "device.csr.new"

    @property
    def pending_certificate_path(self) -> Path:
        """The replacement certificate, after verification and before the swap.

        Its presence alongside `pending_private_key_path` is the commit point
        of a renewal: once both exist and agree, the swap can always be
        completed, so a crash here costs a restart rather than an identity.
        """
        return self.pki_dir / "device.crt.new"

    @property
    def csr_path(self) -> Path:
        """The certificate signing request, kept after it is sent.

        Persisted rather than rebuilt because the server's enrollment
        idempotency cache is keyed on `(token_hash, csr_public_key_fingerprint)`
        and a retry must present the same public key or be told the token is
        spent. Reusing the stored CSR byte for byte is the strongest form of
        that guarantee: it cannot drift from the private key beside it, and it
        removes any question about whether a rebuilt CSR would serialize
        identically.

        Public material - a CSR contains the public key and a signature over
        it, nothing secret - but it lives in `pki_dir` at 0700 anyway, because
        splitting one keypair's files across two directories with two
        permission stories is how the wrong one ends up readable.
        """
        return self.pki_dir / "device.csr"

    @property
    def ca_chain_path(self) -> Path:
        """The DEVICE CA from enrollment: the issuer of our own certificate.

        Not the CA that validates the server's TLS certificate - that one is
        `AgentConfig.server_ca_bundle` and comes from agent.yaml. Two different
        trust stores, and conflating them is the easiest mistake here.
        """
        return self.pki_dir / "ca-chain.pem"

    @property
    def state_db_path(self) -> Path:
        """SQLite: event queue, applied policy versions, pinned policy keys."""
        return self.state_dir / "state.db"

    @property
    def policy_keys_path(self) -> Path:
        """Ed25519 public keys pinned at enrollment, as JSON.

        A file rather than a row in `state_db_path`, which is where the design
        eventually puts them, because the SQLite layer is Phase 7 and this
        needs somewhere to live now: the keys arrive in the enrollment response
        and throwing them away would mean the only moment the agent learns its
        policy trust anchor is the one moment it does not record it.

        Public key material, so the file is 0644 inside the 0700 `pki_dir`.
        Moving these into `state.db` is a Phase 7 migration and the only reader
        is `core.envelope`, which does not exist as a caller yet.
        """
        return self.pki_dir / "policy-keys.json"

    @property
    def enforcer_socket_path(self) -> Path:
        """Phase 7. Declared now so the privilege boundary has an address."""
        return self.run_dir / "enforcer.sock"


# --------------------------------------------------------------------------- #
# The whole configuration
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class AgentConfig:
    """Everything the agent needs to start, resolved across all four levels."""

    server_url: str | None
    server_ca_bundle: Path | None
    paths: AgentPaths
    settings: AgentSettings
    release_build: bool
    config_path: Path | None
    #: True only in the narrow development case described in `_validate_server_url`.
    plaintext_http_permitted: bool = False
    #: Dev-only override for the mTLS device plane; see `ENV_DEVICE_URL`. None
    #: in every release build, where both planes share one URL.
    device_url_override: str | None = None

    @property
    def is_configured(self) -> bool:
        """Whether a server is known. Without one the agent can only idle."""
        return bool(self.server_url)

    @property
    def enroll_base_url(self) -> str | None:
        """Where `POST /api/v1/enroll` goes. Never carries a client certificate."""
        return self.server_url

    @property
    def device_base_url(self) -> str | None:
        """Where `/api/v1/devices/me/*` goes, over mutual TLS.

        Falls back to `server_url`, which is the production answer: one
        hostname on 443, with nginx choosing the mTLS listener by SNI. The
        override is a development convenience only.
        """
        return self.device_url_override or self.server_url


def _loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _validate_server_url(
    url: str,
    *,
    dev_mode: bool,
    allow_plaintext: bool,
) -> bool:
    """Enforce HTTPS-only. Returns whether plaintext was permitted.

    Threat T1 and feature D4: there is no plaintext fallback. The one exception
    needs all three of these at once, so none of them is enough on its own:

      1. the build is in development mode (`UG_AGENT_DEV=1`),
      2. plaintext is explicitly opted into, and
      3. the host is a loopback address.

    The third condition is what makes this safe to have in the tree. Even with
    both flags set, the agent will not send an enrollment token to another
    machine in clear. The caller logs a warning on every start when this is
    active, and `release_build` is already False, so the device is flagged in
    the dashboard.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ConfigError(
            f"server_url must be an absolute URL such as https://ubuntuguard.example.internal, "
            f"got {url!r}"
        )

    if parsed.scheme == constants.REQUIRED_URL_SCHEME:
        return False

    if parsed.scheme != "http":
        raise ConfigError(f"server_url scheme must be https, got {parsed.scheme!r}")

    if not (dev_mode and allow_plaintext and _loopback_host(parsed.hostname)):
        raise ConfigError(
            "server_url must use https. Plaintext HTTP is permitted only for a "
            "loopback address in a development build, which requires both "
            f"{ENV_DEV_MODE}=1 and {ENV_ALLOW_PLAINTEXT}=1."
        )
    return True


def load_yaml_config(path: Path) -> dict[str, Any]:
    """Read agent.yaml, rejecting anything it should not contain.

    `yaml.safe_load` rather than `yaml.load`: the full loader constructs
    arbitrary Python objects from a document, which would turn a writable config
    file into code execution. The file is root-owned, so this is defence in
    depth rather than the only thing standing in the way.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc

    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ConfigError(f"{path} must contain a YAML mapping, got {type(parsed).__name__}")

    unknown = sorted(set(parsed) - ALLOWED_CONFIG_KEYS)
    if unknown:
        raise ConfigError(
            f"{path} has unknown key(s): {', '.join(unknown)}. "
            f"Recognised keys are {', '.join(sorted(ALLOWED_CONFIG_KEYS))}. "
            "Every tunable comes from a signed agent_settings policy, not from this file."
        )
    return parsed


def _optional_path(value: str | None) -> Path | None:
    if value is None:
        return None
    text = value.strip()
    return Path(text) if text else None


def load_config(
    config_path: Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> AgentConfig:
    """Resolve the configuration across all four precedence levels.

    Does not touch the filesystem beyond reading the YAML file: creating
    directories and checking permissions is `ensure_runtime_paths`, called at
    service start, so that `status` and `selftest` can report on a broken
    installation instead of repairing it as a side effect of looking.
    """
    environ = dict(os.environ if env is None else env)
    dev_mode = dev_mode_enabled(environ)

    # The config path itself is resolvable from the environment even outside dev
    # mode. It selects which file to read, not what the file is allowed to say,
    # and a systemd unit does not inherit a user's environment anyway.
    if config_path is None:
        config_path = _optional_path(environ.get(ENV_CONFIG_PATH)) or DEFAULT_CONFIG_PATH

    # --- level 1: compiled defaults ------------------------------------- #
    settings = AgentSettings()
    state_dir = DEFAULT_STATE_DIR
    run_dir = DEFAULT_RUN_DIR

    # --- level 2: agent.yaml -------------------------------------------- #
    file_values = load_yaml_config(config_path)
    server_url = file_values.get("server_url")
    server_ca_bundle = _optional_path(file_values.get("server_ca_bundle"))

    if server_url is not None and not isinstance(server_url, str):
        raise ConfigError(f"server_url must be a string, got {type(server_url).__name__}")

    # --- level 3: signed policy ----------------------------------------- #
    # Applied by the policy manager in Phase 6 via apply_settings_payload. The
    # level exists in the order now so it cannot be bolted on in the wrong place
    # later: a policy must be able to override the file, and nothing else may.

    # --- level 4: dev-only environment overrides ------------------------ #
    allow_plaintext = False
    device_url: str | None = None
    if dev_mode:
        server_url = environ.get(ENV_SERVER_URL, server_url)
        device_url = environ.get(ENV_DEVICE_URL) or None
        server_ca_bundle = _optional_path(environ.get(ENV_SERVER_CA_BUNDLE)) or server_ca_bundle
        state_dir = _optional_path(environ.get(ENV_STATE_DIR)) or state_dir
        run_dir = _optional_path(environ.get(ENV_RUN_DIR)) or run_dir
        allow_plaintext = _is_truthy(environ.get(ENV_ALLOW_PLAINTEXT))
        if ENV_LOG_LEVEL in environ:
            settings = dataclasses.replace(
                settings, log_level=normalise_level(environ[ENV_LOG_LEVEL])
            )

    plaintext_permitted = False
    if server_url:
        plaintext_permitted = _validate_server_url(
            server_url, dev_mode=dev_mode, allow_plaintext=allow_plaintext
        )

    if device_url:
        # Validated by the same function, so the device plane cannot be the way
        # a plaintext URL gets in. If either URL is plaintext the agent reports
        # plaintext as permitted, because the warning is about the process, not
        # about one endpoint.
        plaintext_permitted = (
            _validate_server_url(device_url, dev_mode=dev_mode, allow_plaintext=allow_plaintext)
            or plaintext_permitted
        )

    if server_ca_bundle is not None and not server_ca_bundle.is_absolute():
        raise ConfigError(f"server_ca_bundle must be an absolute path, got {server_ca_bundle}")

    return AgentConfig(
        server_url=server_url,
        server_ca_bundle=server_ca_bundle,
        paths=AgentPaths(state_dir=state_dir, run_dir=run_dir),
        settings=settings,
        # A development build is never a release build, by definition. This is
        # what surfaces the difference in the dashboard.
        release_build=not dev_mode,
        config_path=config_path if config_path.exists() else None,
        plaintext_http_permitted=plaintext_permitted,
        device_url_override=device_url,
    )
