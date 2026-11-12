"""Runtime configuration.

Three rules shape this module.

No hardcoded values: everything an operator might need to change is here and
comes from the environment. Everything an operator must NOT change lives in
`constants.py`, which reads no environment at all.

No secrets in logs: anything sensitive is `SecretStr`, so a stray `repr()`,
an exception rendering, or a debug log prints `**********` instead of a
database password. `test_config.py` asserts that.

Fail at startup, not at the first request: a production configuration missing
its signing key should refuse to boot rather than serve traffic and fall over
when the first policy is created.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ubuntuguard.constants import PAGE_SIZE

Environment = Literal["dev", "prod"]

ENV_PREFIX = "UBUNTUGUARD_"

#: Prefixed variables that are not settings. Kept short on purpose; every entry
#: is a hole in the typo check.
ENV_ALLOWLIST: frozenset[str] = frozenset()


class Settings(BaseSettings):
    """Environment-driven settings, prefixed `UBUNTUGUARD_`."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_file=".env",
        env_file_encoding="utf-8",
        # Guards direct construction. It does NOT catch a misspelled environment
        # variable: pydantic-settings only looks up the fields it knows about, so
        # an unknown UBUNTUGUARD_* variable is invisible to it. That case is
        # handled by _reject_unknown_prefixed_env_vars below.
        extra="forbid",
    )

    environment: Environment = "dev"

    # --- Storage ---------------------------------------------------------- #
    database_url: SecretStr | None = Field(
        default=None,
        description=(
            "SQLAlchemy URL for the least-privilege application role, e.g. "
            "postgresql+psycopg://ubuntuguard_app:...@localhost/ubuntuguard. "
            "This role must NOT hold UPDATE or DELETE on audit_logs."
        ),
    )
    migration_database_url: SecretStr | None = Field(
        default=None,
        description=(
            "URL for the schema OWNER role, used only by Alembic. Migrations "
            "need CREATE and ALTER, which is exactly what the runtime role must "
            "not have - running migrations as the app role would hand it the "
            "ability to drop the audit table."
        ),
    )

    # --- Key material (paths only; the keys themselves never come from env) - #
    policy_signing_key_path: Path | None = Field(
        default=None,
        description="PEM PKCS#8 Ed25519 private key, mode 0600. Separate from the CA key.",
    )
    ca_key_path: Path | None = None
    ca_cert_path: Path | None = None

    # --- Proxy trust ------------------------------------------------------- #
    trusted_proxy_ips: frozenset[str] = Field(
        default=frozenset({"127.0.0.1", "::1"}),
        description=(
            "Peers whose X-Client-* headers are believed. The device plane's "
            "identity comes from those headers, so anyone able to set them can "
            "impersonate any device. The app should also bind to localhost and "
            "be reachable only through nginx."
        ),
    )

    # --- HTTP -------------------------------------------------------------- #
    api_prefix: str = "/api/v1"
    default_page_size: int = PAGE_SIZE.default
    max_page_size: int = PAGE_SIZE.maximum

    # --- Dev-only escape hatches ------------------------------------------- #
    allow_dev_overrides: bool = Field(
        default=False,
        description=(
            "Enables dev-only behaviour. Forced off in prod by a validator, "
            "mirroring the agent, where these are compiled out of release builds."
        ),
    )
    allow_any_login: bool = Field(
        default=False,
        description=(
            "Accept ANY email and password at POST /api/v1/auth/login, creating "
            "the account the first time an address is seen. A placeholder until "
            "Microsoft SSO is wired in, so the dashboard is usable before "
            "identity exists. The password is not read at all, and anyone who "
            "can reach the port becomes super_admin, so a validator refuses to "
            "start in prod with it set."
        ),
    )

    @model_validator(mode="after")
    def _reject_unknown_prefixed_env_vars(self) -> Settings:
        """Refuse to start if a UBUNTUGUARD_* variable matches no setting.

        `extra="forbid"` does not cover this. pydantic-settings reads only the
        variables corresponding to declared fields, so `UBUNTUGUARD_DATABSE_URL`
        is simply never looked at - the server starts with no database and
        reports "not configured", sending the operator looking in the wrong
        place entirely. Checking the environment directly turns a typo into an
        error that names the variable.
        """
        known = {f"{ENV_PREFIX}{name.upper()}" for name in type(self).model_fields}
        unknown = sorted(
            name
            for name in os.environ
            if name.startswith(ENV_PREFIX) and name not in known and name not in ENV_ALLOWLIST
        )
        if unknown:
            raise ValueError(
                "unknown environment variable(s): "
                + ", ".join(unknown)
                + ". Check for a typo; recognised names are "
                + ", ".join(sorted(known))
            )
        return self

    @model_validator(mode="after")
    def _enforce_production_requirements(self) -> Settings:
        if self.environment != "prod":
            return self

        missing = [
            name
            for name, value in (
                ("database_url", self.database_url),
                ("policy_signing_key_path", self.policy_signing_key_path),
                ("ca_key_path", self.ca_key_path),
                ("ca_cert_path", self.ca_cert_path),
            )
            if value is None
        ]
        if missing:
            raise ValueError(
                "production configuration is incomplete; set "
                + ", ".join(f"UBUNTUGUARD_{name.upper()}" for name in sorted(missing))
            )

        if self.allow_dev_overrides:
            raise ValueError(
                "allow_dev_overrides must be false in production; it exists only "
                "for local development"
            )
        if self.allow_any_login:
            raise ValueError(
                "allow_any_login must be false in production; it accepts any "
                "password for any address and grants super_admin, which is a "
                "backdoor into every enrolled device rather than a weak default"
            )
        if not self.trusted_proxy_ips:
            raise ValueError(
                "trusted_proxy_ips must not be empty in production, or no device "
                "could ever authenticate"
            )
        return self

    @model_validator(mode="after")
    def _check_page_sizes(self) -> Settings:
        if not PAGE_SIZE.contains(self.default_page_size):
            raise ValueError(
                f"default_page_size {self.default_page_size} is outside "
                f"{PAGE_SIZE.minimum}..{PAGE_SIZE.maximum}"
            )
        if self.max_page_size > PAGE_SIZE.maximum:
            raise ValueError(f"max_page_size must not exceed {PAGE_SIZE.maximum}")
        if self.default_page_size > self.max_page_size:
            raise ValueError("default_page_size must not exceed max_page_size")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "prod"

    def require_database_url(self) -> str:
        """The database URL, or a message that says how to fix its absence."""
        if self.database_url is None:
            raise RuntimeError(
                "UBUNTUGUARD_DATABASE_URL is not set. For local development:\n"
                "  export UBUNTUGUARD_DATABASE_URL="
                "postgresql+psycopg://ubuntuguard_app:devpassword@localhost:5432/ubuntuguard"
            )
        return self.database_url.get_secret_value()
