"""Shared test fixtures.

Note what is absent: any database fixture. Everything in this suite is pure
logic or cryptography, so it runs with no PostgreSQL, no network and no
environment setup. The database-backed tests arrive with the models and carry
the `postgres` marker.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

#: server/tests/conftest.py -> server/ -> repository root
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolate_settings_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep `Settings()` deterministic regardless of the developer's machine.

    `scripts/dev_db.sh` writes server/.env, and pydantic-settings reads it. Once
    that file existed, four tests asserting default behaviour started failing -
    not because the code changed, but because a local file appeared. A test
    suite whose result depends on whether someone has run the database script is
    not telling you about the code.

    Both sources are neutralised: the .env file and any UBUNTUGUARD_* variable
    already in the environment. The database tests are unaffected, because they
    read the .env file directly rather than through Settings.
    """
    from ubuntuguard.config import ENV_PREFIX, Settings

    monkeypatch.setitem(Settings.model_config, "env_file", None)
    for name in list(os.environ):
        if name.startswith(ENV_PREFIX):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def policy_vectors() -> dict[str, Any]:
    """The committed cross-language signing vector."""
    path = REPO_ROOT / "testdata" / "policy_vectors.json"
    if not path.exists():
        pytest.fail(
            f"{path} is missing. Regenerate it with: "
            ".venv-tools/bin/python tools/make_policy_vectors.py"
        )
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def agent_settings_schema() -> dict[str, Any]:
    """The agent_settings JSON Schema, used to check the Go/Python bounds agree."""
    path = REPO_ROOT / "schemas" / "policy.agent_settings.v1.schema.json"
    if not path.exists():
        pytest.fail(f"{path} is missing")
    return json.loads(path.read_text(encoding="utf-8"))
