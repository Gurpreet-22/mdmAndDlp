"""Configuration: precedence, the HTTPS invariant, and clamping.

The clamping tests are the ones to read first. Decision D5 says the server
rejects an out-of-range setting and the agent clamps it, and that asymmetry is
easy to get backwards - a well-meaning change that made the agent raise instead
would brick every laptop in the fleet the first time a newer server sent a value
this build considers out of range.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ubuntuguard_agent import constants
from ubuntuguard_agent.config import (
    ALLOWED_CONFIG_KEYS,
    ENV_ALLOW_PLAINTEXT,
    ENV_DEV_MODE,
    ENV_LOG_LEVEL,
    ENV_SERVER_URL,
    ENV_STATE_DIR,
    AgentPaths,
    AgentSettings,
    apply_settings_payload,
    load_config,
    load_yaml_config,
)
from ubuntuguard_agent.errors import ConfigError, ReasonCode


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "agent.yaml"
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Level 1: compiled defaults
# --------------------------------------------------------------------------- #


def test_defaults_come_from_constants(tmp_path: Path) -> None:
    config = load_config(tmp_path / "absent.yaml", env={})
    assert config.settings == AgentSettings()
    assert config.settings.heartbeat_seconds == constants.HEARTBEAT_SECONDS.default
    assert config.settings.log_level == constants.LOG_LEVEL_DEFAULT


def test_a_missing_config_file_is_not_an_error(tmp_path: Path) -> None:
    """A fresh install has no file yet, and that is a normal state.

    The agent reports "no server configured" and idles. Refusing to start would
    put the service into a restart loop before anyone could configure it.
    """
    config = load_config(tmp_path / "absent.yaml", env={})
    assert config.config_path is None
    assert config.is_configured is False
    assert config.server_url is None


def test_release_build_is_true_without_the_dev_flag(tmp_path: Path) -> None:
    assert load_config(tmp_path / "absent.yaml", env={}).release_build is True


# --------------------------------------------------------------------------- #
# Level 2: agent.yaml
# --------------------------------------------------------------------------- #


def test_file_values_are_read(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        "server_url: https://ug.example.internal\n"
        "server_ca_bundle: /etc/ubuntuguard/server-ca.pem\n",
    )
    config = load_config(path, env={})
    assert config.server_url == "https://ug.example.internal"
    assert config.server_ca_bundle == Path("/etc/ubuntuguard/server-ca.pem")
    assert config.is_configured is True


def test_unknown_key_is_an_error_that_names_it(tmp_path: Path) -> None:
    """A typo must be loud.

    The silent-ignore alternative is genuinely worse than an error: the agent
    reports "no server configured" while the file in front of the operator
    plainly contains a server, and they go looking in the wrong place.
    """
    path = write_config(tmp_path, "server_url: https://ug.invalid\nheartbeat_seconds: 30\n")
    with pytest.raises(ConfigError) as raised:
        load_config(path, env={})
    assert "heartbeat_seconds" in str(raised.value)


def test_tunables_cannot_be_set_from_the_file() -> None:
    """The file is deliberately limited to two keys.

    Everything else comes from a signed policy, which is auditable. An operator
    with root on a laptop editing this file must not be able to widen the
    heartbeat interval or turn the log level down.
    """
    assert {"server_url", "server_ca_bundle"} == ALLOWED_CONFIG_KEYS


def test_malformed_yaml_is_reported_not_crashed(tmp_path: Path) -> None:
    path = write_config(tmp_path, "server_url: [unclosed\n")
    with pytest.raises(ConfigError) as raised:
        load_config(path, env={})
    assert "not valid YAML" in str(raised.value)


def test_a_yaml_scalar_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "just-a-string\n")
    with pytest.raises(ConfigError):
        load_config(path, env={})


def test_an_empty_file_is_treated_as_no_settings(tmp_path: Path) -> None:
    path = write_config(tmp_path, "# only a comment\n")
    assert load_yaml_config(path) == {}


def test_non_string_server_url_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "server_url: 8000\n")
    with pytest.raises(ConfigError):
        load_config(path, env={})


def test_relative_ca_bundle_is_rejected(tmp_path: Path) -> None:
    """A relative path would resolve against the service's working directory.

    Under systemd that is `/`, which is not what anybody writing `./ca.pem`
    intends, and a CA bundle silently resolving somewhere unexpected is a
    validation failure waiting to happen.
    """
    path = write_config(tmp_path, "server_url: https://ug.invalid\nserver_ca_bundle: ca.pem\n")
    with pytest.raises(ConfigError) as raised:
        load_config(path, env={})
    assert "absolute" in str(raised.value)


# --------------------------------------------------------------------------- #
# The HTTPS invariant (threat T1, feature D4)
# --------------------------------------------------------------------------- #


def test_https_is_accepted(tmp_path: Path) -> None:
    path = write_config(tmp_path, "server_url: https://ug.example.internal\n")
    config = load_config(path, env={})
    assert config.plaintext_http_permitted is False


def test_plaintext_http_is_refused_in_a_release_build(tmp_path: Path) -> None:
    path = write_config(tmp_path, "server_url: http://ug.example.internal\n")
    with pytest.raises(ConfigError) as raised:
        load_config(path, env={})
    assert "https" in str(raised.value)


def test_plaintext_http_is_refused_even_for_loopback_without_the_flags(
    tmp_path: Path,
) -> None:
    path = write_config(tmp_path, "server_url: http://127.0.0.1:8000\n")
    with pytest.raises(ConfigError):
        load_config(path, env={})


def test_plaintext_http_needs_dev_mode_and_the_opt_in_and_loopback(
    tmp_path: Path,
) -> None:
    """All three conditions, and the test proves each one is load-bearing."""
    path = write_config(tmp_path, "server_url: http://127.0.0.1:8000\n")

    # dev mode alone is not enough
    with pytest.raises(ConfigError):
        load_config(path, env={ENV_DEV_MODE: "1"})

    # the opt-in alone is not enough
    with pytest.raises(ConfigError):
        load_config(path, env={ENV_ALLOW_PLAINTEXT: "1"})

    # both together, on loopback, are
    config = load_config(path, env={ENV_DEV_MODE: "1", ENV_ALLOW_PLAINTEXT: "1"})
    assert config.plaintext_http_permitted is True
    assert config.release_build is False


def test_plaintext_http_to_a_remote_host_is_refused_even_in_dev(tmp_path: Path) -> None:
    """The condition that makes the escape hatch safe to keep in the tree.

    With both flags set, the agent still will not send an enrollment token to
    another machine in clear. Only loopback.
    """
    path = write_config(tmp_path, "server_url: http://10.0.0.5:8000\n")
    with pytest.raises(ConfigError):
        load_config(path, env={ENV_DEV_MODE: "1", ENV_ALLOW_PLAINTEXT: "1"})


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]"])
def test_loopback_forms_are_all_recognised(tmp_path: Path, host: str) -> None:
    path = write_config(tmp_path, f"server_url: http://{host}:8000\n")
    config = load_config(path, env={ENV_DEV_MODE: "1", ENV_ALLOW_PLAINTEXT: "1"})
    assert config.plaintext_http_permitted is True


@pytest.mark.parametrize("url", ["ftp://ug.invalid", "not-a-url", "://missing-scheme"])
def test_other_schemes_are_refused(tmp_path: Path, url: str) -> None:
    path = write_config(tmp_path, f"server_url: {url}\n")
    with pytest.raises(ConfigError):
        load_config(path, env={})


# --------------------------------------------------------------------------- #
# Level 4: dev-only environment overrides
# --------------------------------------------------------------------------- #


def test_environment_overrides_are_ignored_without_the_dev_flag(tmp_path: Path) -> None:
    """The gate. This is what stands in for "compiled out of a release build".

    Python cannot drop code at build time, so the overrides are gated at runtime
    instead and the gate itself is what the test pins.
    """
    path = write_config(tmp_path, "server_url: https://real.example.internal\n")
    config = load_config(
        path,
        env={ENV_SERVER_URL: "https://attacker.invalid", ENV_STATE_DIR: "/tmp/evil"},
    )
    assert config.server_url == "https://real.example.internal"
    assert config.paths.state_dir == Path("/var/lib/ubuntuguard")


def test_environment_overrides_apply_in_dev_mode(tmp_path: Path) -> None:
    path = write_config(tmp_path, "server_url: https://real.example.internal\n")
    config = load_config(
        path,
        env={
            ENV_DEV_MODE: "1",
            ENV_SERVER_URL: "https://dev.example.internal",
            ENV_STATE_DIR: str(tmp_path / "state"),
            ENV_LOG_LEVEL: "debug",
        },
    )
    assert config.server_url == "https://dev.example.internal"
    assert config.paths.state_dir == tmp_path / "state"
    assert config.settings.log_level == "debug"


def test_dev_mode_forces_release_build_false(tmp_path: Path) -> None:
    """A development box must be visible as one in the dashboard.

    `inventory.v1` documents exactly this: release_build false means the
    device's effective settings may not match policy, so it is flagged rather
    than passing for a managed laptop.
    """
    config = load_config(tmp_path / "absent.yaml", env={ENV_DEV_MODE: "1"})
    assert config.release_build is False


def test_an_unknown_log_level_in_the_environment_clamps(tmp_path: Path) -> None:
    config = load_config(tmp_path / "absent.yaml", env={ENV_DEV_MODE: "1", ENV_LOG_LEVEL: "shout"})
    assert config.settings.log_level == constants.LOG_LEVEL_DEFAULT


# --------------------------------------------------------------------------- #
# Level 3: a signed agent_settings policy
# --------------------------------------------------------------------------- #


def valid_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"schema": constants.AGENT_SETTINGS_SCHEMA_ID}
    payload.update(overrides)
    return payload


def test_in_range_values_are_applied_unchanged() -> None:
    settings, clamped = apply_settings_payload(
        valid_payload(heartbeat_seconds=120, log_level="debug")
    )
    assert settings.heartbeat_seconds == 120
    assert settings.log_level == "debug"
    assert clamped == []


def test_omitted_fields_keep_the_current_value() -> None:
    base = AgentSettings(heartbeat_seconds=300)
    settings, clamped = apply_settings_payload(valid_payload(log_level="warn"), base=base)
    assert settings.heartbeat_seconds == 300
    assert clamped == []


def test_a_value_below_the_minimum_is_clamped_not_rejected() -> None:
    """The core of decision D5, in the direction that matters most.

    An agent that raised here would stop working the moment a newer server sent
    a value outside the range this build knows about. Clamping keeps it running
    at the nearest safe value.
    """
    settings, clamped = apply_settings_payload(valid_payload(heartbeat_seconds=5))
    assert settings.heartbeat_seconds == constants.HEARTBEAT_SECONDS.minimum == 30
    assert len(clamped) == 1
    assert clamped[0].setting == "heartbeat_seconds"
    assert clamped[0].requested == 5
    assert clamped[0].applied == 30


def test_a_value_above_the_maximum_is_clamped() -> None:
    settings, clamped = apply_settings_payload(valid_payload(backoff_max_seconds=999_999))
    assert settings.backoff_max_seconds == constants.BACKOFF_MAX_SECONDS.maximum
    assert clamped[0].requested == 999_999


def test_a_clamp_is_never_silent() -> None:
    """The record is what stops a clamp becoming a debugging trap.

    An operator sets 5 seconds, observes 30, and without this has nothing
    linking the two. The shape matches the `settings_clamped` example in
    schemas/event.agent.v1.schema.json.
    """
    _, clamped = apply_settings_payload(valid_payload(heartbeat_seconds=5))
    assert clamped[0].as_event_fields() == {
        "setting": "heartbeat_seconds",
        "requested": 5,
        "applied": 30,
    }


def test_several_clamps_are_all_recorded() -> None:
    _, clamped = apply_settings_payload(
        valid_payload(heartbeat_seconds=1, heartbeat_jitter_pct=99, event_batch_max=9_999)
    )
    assert {record.setting for record in clamped} == {
        "heartbeat_seconds",
        "heartbeat_jitter_pct",
        "event_batch_max",
    }


def test_every_bound_clamps_from_both_directions() -> None:
    """Covers every setting rather than a representative sample.

    A bound added to constants without a matching schema entry is caught by
    test_schema_agreement; this catches one that is present but not actually
    applied by the fold.
    """
    for name, bound in constants.AGENT_SETTING_BOUNDS.items():
        low, _ = apply_settings_payload(valid_payload(**{name: bound.minimum - 1}))
        high, _ = apply_settings_payload(valid_payload(**{name: bound.maximum + 1}))
        assert getattr(low, name) == bound.minimum, name
        assert getattr(high, name) == bound.maximum, name


def test_unknown_field_is_rejected_structurally() -> None:
    """Structure strict, ranges lenient.

    An unknown field means this build does not understand the policy, and
    guessing is worse than reporting it.
    """
    with pytest.raises(ConfigError) as raised:
        apply_settings_payload(valid_payload(enable_backdoor=True))
    assert "enable_backdoor" in str(raised.value)
    assert raised.value.reason_code == ReasonCode.SCHEMA_INVALID


def test_a_wrong_schema_id_is_rejected() -> None:
    """Prevents a usb_control payload being folded in as settings."""
    with pytest.raises(ConfigError):
        apply_settings_payload({"schema": "ubuntuguard.usb_control.v1"})


def test_a_missing_schema_id_is_rejected() -> None:
    with pytest.raises(ConfigError):
        apply_settings_payload({"heartbeat_seconds": 60})


@pytest.mark.parametrize("bad", ["60", 60.5, None, [60], {"v": 60}])
def test_a_non_integer_setting_is_a_structural_error(bad: Any) -> None:
    with pytest.raises(ConfigError):
        apply_settings_payload(valid_payload(heartbeat_seconds=bad))


def test_boolean_is_not_accepted_as_an_integer() -> None:
    """`True` is an int in Python; `heartbeat_seconds: true` is not a value.

    Without the explicit check it would clamp to 30 and look deliberate.
    """
    with pytest.raises(ConfigError):
        apply_settings_payload(valid_payload(heartbeat_seconds=True))


def test_an_unknown_log_level_clamps_rather_than_raising() -> None:
    settings, clamped = apply_settings_payload(valid_payload(log_level="verbose"))
    assert settings.log_level == constants.LOG_LEVEL_DEFAULT
    assert clamped[0].setting == "log_level"


def test_a_non_string_log_level_is_a_structural_error() -> None:
    with pytest.raises(ConfigError):
        apply_settings_payload(valid_payload(log_level=3))


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def test_path_layout_is_derived_from_the_state_directory(tmp_path: Path) -> None:
    paths = AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
    assert paths.pki_dir == tmp_path / "state" / "pki"
    assert paths.private_key_path == tmp_path / "state" / "pki" / "device.key"
    assert paths.certificate_path == tmp_path / "state" / "pki" / "device.crt"
    assert paths.ca_chain_path == tmp_path / "state" / "pki" / "ca-chain.pem"
    assert paths.state_db_path == tmp_path / "state" / "state.db"
    assert paths.enforcer_socket_path == tmp_path / "run" / "enforcer.sock"


def test_the_device_ca_chain_is_not_the_server_ca_bundle(tmp_path: Path) -> None:
    """Two trust stores with two jobs, and the easiest mistake here.

    `ca_chain_path` holds the issuer of our own client certificate, written by
    enrollment. `server_ca_bundle` validates the server and comes from
    agent.yaml. Using one for the other's job would either fail the handshake or
    trust the wrong issuer.
    """
    path = write_config(
        tmp_path,
        "server_url: https://ug.invalid\nserver_ca_bundle: /etc/ubuntuguard/server-ca.pem\n",
    )
    config = load_config(path, env={})
    assert config.server_ca_bundle != config.paths.ca_chain_path
