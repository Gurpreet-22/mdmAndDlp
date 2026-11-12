"""The agent's environment namespace must not collide with the server's.

This test exists because the collision happened. The agent originally used
`UBUNTUGUARD_AGENT_` as its prefix, which looks like the obviously correct
choice and breaks the server: `Settings._reject_unknown_prefixed_env_vars` in
`server/src/ubuntuguard/config.py` refuses to start when it sees any
`UBUNTUGUARD_*` variable it does not recognise, and it matches by **prefix**.
So `UBUNTUGUARD_AGENT_DEV` is, from the server's point of view, a misspelled
server setting, and merely having it exported in a shell makes the API fail to
start with a validation error.

It is not a hypothetical. The documented development workflow runs the API and
the agent on one machine, and this was found by exporting the agent's variables
in a shell and watching 34 server tests fall over.

The fix is the agent's own namespace, `UG_AGENT_`, which also matches the
convention the repository already uses for `UG_ALLOW_DESTRUCTIVE_TESTS`.

The server's validator is deliberately left alone. Adding the agent's names to
its allowlist would have worked and would have been the wrong fix: it widens a
typo check that exists to catch exactly this kind of mistake, and it would have
made the server's configuration depend on the agent's.
"""

from __future__ import annotations

import os

from ubuntuguard_agent import config

#: The server's prefix. Hardcoded rather than imported: the agent must not
#: depend on the server package being installed, since on a laptop it is not.
SERVER_ENV_PREFIX = "UBUNTUGUARD_"

#: Every environment variable the agent reads.
AGENT_ENV_NAMES = (
    config.ENV_DEV_MODE,
    config.ENV_CONFIG_PATH,
    config.ENV_SERVER_URL,
    config.ENV_SERVER_CA_BUNDLE,
    config.ENV_STATE_DIR,
    config.ENV_RUN_DIR,
    config.ENV_LOG_LEVEL,
    config.ENV_ALLOW_PLAINTEXT,
)


def test_the_agent_prefix_is_not_within_the_server_namespace() -> None:
    """The actual bug, in one assertion."""
    assert not config.ENV_PREFIX.startswith(SERVER_ENV_PREFIX), (
        f"{config.ENV_PREFIX!r} is inside the server's {SERVER_ENV_PREFIX!r} namespace; "
        "the server refuses to start on any unrecognised variable with that prefix"
    )


def test_no_agent_variable_is_within_the_server_namespace() -> None:
    """Checks every name, not only the prefix constant.

    A variable added later with a hand-written name rather than via `ENV_PREFIX`
    would slip past the test above.
    """
    offenders = [name for name in AGENT_ENV_NAMES if name.startswith(SERVER_ENV_PREFIX)]
    assert not offenders, f"these would break the server if exported: {offenders}"


def test_every_agent_variable_uses_the_agent_prefix() -> None:
    """Keeps the namespace a namespace rather than a loose collection."""
    strays = [name for name in AGENT_ENV_NAMES if not name.startswith(config.ENV_PREFIX)]
    assert not strays, f"variables outside the {config.ENV_PREFIX} namespace: {strays}"


def test_agent_variables_do_not_collide_with_the_repository_convention() -> None:
    """`UG_ALLOW_DESTRUCTIVE_TESTS` already exists and must stay distinct.

    The agent's names all carry `AGENT_`, so they cannot shadow it. Nothing
    prefix-matches on bare `UG_`, so there is no validator to upset either -
    but the names should still be unambiguous to a reader.
    """
    assert "UG_ALLOW_DESTRUCTIVE_TESTS" not in AGENT_ENV_NAMES
    for name in AGENT_ENV_NAMES:
        assert name.startswith("UG_AGENT_")


def test_agent_variables_are_absent_from_this_test_environment() -> None:
    """Guards the isolation fixture itself.

    If `isolate_environment` stopped working, tests asserting default behaviour
    would start passing or failing based on the developer's shell, which is how
    the collision went unnoticed long enough to reach a server test run.
    """
    leaked = sorted(name for name in os.environ if name.startswith(config.ENV_PREFIX))
    assert not leaked, f"the isolation fixture did not clear: {leaked}"
