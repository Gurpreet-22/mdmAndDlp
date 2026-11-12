"""Settings tests.

Two things matter here: a production configuration that is missing something
must refuse to boot rather than fail on the first request, and nothing
sensitive may be printable.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ubuntuguard.config import Settings


def test_dev_defaults_need_no_environment() -> None:
    """The test suite, --help and OpenAPI generation must work on a bare machine."""
    settings = Settings()
    assert settings.environment == "dev"
    assert settings.database_url is None
    assert settings.is_production is False


def test_database_password_is_not_printable() -> None:
    """A stray repr, log line or exception render must not leak the password."""
    secret = "sup3r-secret-password"
    settings = Settings(database_url=f"postgresql+psycopg://app:{secret}@localhost/ug")

    for rendered in (repr(settings), str(settings), repr(settings.database_url)):
        assert secret not in rendered, f"password leaked into {rendered[:80]}"
    assert "**********" in repr(settings.database_url)

    # Available when deliberately asked for, which is the point of SecretStr.
    assert secret in settings.require_database_url()


def test_model_dump_does_not_leak_the_password() -> None:
    """Settings often end up in a diagnostics endpoint; check that path too."""
    secret = "another-secret"
    settings = Settings(database_url=f"postgresql+psycopg://app:{secret}@localhost/ug")
    assert secret not in str(settings.model_dump())


def test_missing_database_url_explains_how_to_fix_it() -> None:
    with pytest.raises(RuntimeError, match="UBUNTUGUARD_DATABASE_URL"):
        Settings().require_database_url()


def test_production_refuses_to_start_without_key_material() -> None:
    """Failing at startup beats failing when the first policy is signed."""
    with pytest.raises(ValidationError) as caught:
        Settings(environment="prod")
    message = str(caught.value)
    for expected in (
        "UBUNTUGUARD_DATABASE_URL",
        "UBUNTUGUARD_POLICY_SIGNING_KEY_PATH",
        "UBUNTUGUARD_CA_KEY_PATH",
        "UBUNTUGUARD_CA_CERT_PATH",
    ):
        assert expected in message


def _complete_prod_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "environment": "prod",
        "database_url": "postgresql+psycopg://app:pw@localhost/ug",
        "policy_signing_key_path": Path("/etc/ubuntuguard/policy.key"),
        "ca_key_path": Path("/etc/ubuntuguard/ca.key"),
        "ca_cert_path": Path("/etc/ubuntuguard/ca.crt"),
    }
    base.update(overrides)
    return base


def test_complete_production_configuration_is_accepted() -> None:
    settings = Settings(**_complete_prod_kwargs())  # type: ignore[arg-type]
    assert settings.is_production is True


def test_production_refuses_dev_overrides() -> None:
    """Mirrors the agent, where dev overrides are compiled out of release builds."""
    with pytest.raises(ValidationError, match="allow_dev_overrides must be false"):
        Settings(**_complete_prod_kwargs(allow_dev_overrides=True))  # type: ignore[arg-type]


def test_production_refuses_an_empty_trusted_proxy_set() -> None:
    """With no trusted proxy, no device could ever authenticate."""
    with pytest.raises(ValidationError, match="trusted_proxy_ips must not be empty"):
        Settings(**_complete_prod_kwargs(trusted_proxy_ips=frozenset()))  # type: ignore[arg-type]


def test_trusted_proxies_default_to_loopback() -> None:
    """The app is meant to sit behind nginx on the same host."""
    assert Settings().trusted_proxy_ips == frozenset({"127.0.0.1", "::1"})


@pytest.mark.parametrize("bad", [0, 500])
def test_page_size_outside_bounds_is_rejected(bad: int) -> None:
    with pytest.raises(ValidationError):
        Settings(default_page_size=bad)


def test_default_page_size_must_not_exceed_max() -> None:
    with pytest.raises(ValidationError, match="must not exceed max_page_size"):
        Settings(default_page_size=100, max_page_size=50)


def test_unknown_setting_is_an_error_not_a_shrug(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo such as UBUNTUGUARD_DATABSE_URL must not be silently ignored.

    Silently ignoring it would leave the server running with no database and a
    confusing "not configured" message instead of a pointer at the typo.
    """
    monkeypatch.setenv("UBUNTUGUARD_DATABSE_URL", "postgresql://typo")
    with pytest.raises(ValidationError) as caught:
        Settings()
    message = str(caught.value)
    assert "UBUNTUGUARD_DATABSE_URL" in message
    # The error should also point at the name that was meant.
    assert "UBUNTUGUARD_DATABASE_URL" in message


def test_recognised_env_vars_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UBUNTUGUARD_ENVIRONMENT", "dev")
    monkeypatch.setenv("UBUNTUGUARD_DATABASE_URL", "postgresql+psycopg://a:b@localhost/c")
    settings = Settings()
    assert settings.environment == "dev"
    assert settings.database_url is not None


def test_environment_is_a_closed_set() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="staging")  # type: ignore[arg-type]
