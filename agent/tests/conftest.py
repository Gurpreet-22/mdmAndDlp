"""Shared fixtures.

Note what is absent: any network fixture, any database fixture, and anything
needing root. Every test in this suite runs on a developer machine with no
server, no PostgreSQL and no privileges. The tests that need otherwise carry a
marker and are skipped by default.

The autouse environment fixture mirrors the server's `isolate_settings_sources`
and exists for the same reason: once `UG_AGENT_*` variables are in a
developer's shell, tests asserting default behaviour start failing for reasons
that have nothing to do with the code. A suite whose result depends on whether
someone exported a variable is not telling you about the code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

#: agent/tests/conftest.py -> agent/ -> repository root
REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every UG_AGENT_* variable for the duration of a test."""
    import os

    from ubuntuguard_agent.config import ENV_PREFIX

    for name in list(os.environ):
        if name.startswith(ENV_PREFIX):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def clean_secret_registry() -> Any:
    """Keep the process-wide secret registry from leaking between tests.

    Without this, a test that registers a secret changes what every later test
    sees in its log output, and the failure surfaces somewhere unrelated.
    """
    from ubuntuguard_agent.logging_setup import SECRETS

    SECRETS.clear()
    yield
    SECRETS.clear()


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def agent_root() -> Path:
    return AGENT_ROOT


def _load_committed_json(relative: str) -> dict[str, Any]:
    path = REPO_ROOT / relative
    if not path.exists():
        pytest.fail(f"{path} is missing; this test exists to compare against it")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def policy_vectors() -> dict[str, Any]:
    """The committed cross-language signing vector.

    The repository generates this with `tools/make_policy_vectors.py` and the
    server's own suite verifies against it. The agent verifying the same file is
    what makes the two implementations provably agree - with a Python-only
    agent it is no longer a cross-*language* check, but it is still the only
    thing that catches a byte-level drift between the two codebases.
    """
    return _load_committed_json("testdata/policy_vectors.json")


@pytest.fixture(scope="session")
def agent_settings_schema() -> dict[str, Any]:
    return _load_committed_json("schemas/policy.agent_settings.v1.schema.json")


@pytest.fixture(scope="session")
def agent_event_schema() -> dict[str, Any]:
    return _load_committed_json("schemas/event.agent.v1.schema.json")


@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    """A synthetic filesystem root for the Ubuntu adapter.

    Populated to look like a plausible 24.04 host. Tests that care about a
    missing or malformed file overwrite or delete what they need, which keeps
    each test's intent visible instead of hidden in a fixture.
    """
    (tmp_path / "etc").mkdir()
    (tmp_path / "proc" / "sys" / "kernel" / "random").mkdir(parents=True)

    (tmp_path / "etc" / "os-release").write_text(
        'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n'
        "NAME=Ubuntu\n"
        'VERSION_ID="24.04"\n'
        'VERSION="24.04.1 LTS (Noble Numbat)"\n'
        "ID=ubuntu\n"
        "ID_LIKE=debian\n"
        "# a comment, which os-release permits\n"
        'HOME_URL="https://www.ubuntu.com/"\n',
        encoding="utf-8",
    )
    (tmp_path / "proc" / "uptime").write_text("987654.32 1234567.89\n", encoding="utf-8")
    (tmp_path / "proc" / "sys" / "kernel" / "random" / "boot_id").write_text(
        "4f8a9c1e-2b3d-4e5f-8a9b-0c1d2e3f4a5b\n", encoding="utf-8"
    )
    (tmp_path / "etc" / "machine-id").write_text(
        "9e107d9d372bb6826bd81d3542a419d6\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def agent_paths(tmp_path: Path) -> Any:
    """`AgentPaths` rooted in a temporary directory."""
    from ubuntuguard_agent.config import AgentPaths

    return AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
