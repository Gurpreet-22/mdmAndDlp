"""Every documented way of starting the API must disable uvicorn's proxy headers.

Why this is a test and not a note. Device identity on the device plane comes
entirely from the `X-Client-*` headers, and the application only believes them
when `request.client.host` is in `trusted_proxy_ips`
(`security/device_auth.py`). uvicorn's proxy-header handling rewrites
`request.client.host` from `X-Forwarded-For`, which turns the one value that
check depends on into something a request carries.

The trap is the default. `uvicorn.Config(proxy_headers=...)` defaults to
**True**, so a command that simply omits `--proxy-headers` still has the
rewrite active; `--no-proxy-headers` has to be passed. `deploy/nginx/README.md`
previously said the opposite - that the documented command "has no such flag,
keep it that way" - and the commands in the Makefile and README did omit it, so
the advice read as satisfied while the rewrite was on.

It stayed invisible for as long as everything ran on one laptop. This proxy
sets `X-Forwarded-For $remote_addr`, so a device on loopback forwards
`127.0.0.1`, which is in `trusted_proxy_ips` and verifies normally. The first
device on another host forwards its own address, which is not, and every
device-plane request from it fails with `401 untrusted_proxy` - while the same
certificate works from the server's own machine.

What is NOT covered here: the rewrite itself lives in uvicorn's ASGI layer, so
it cannot be exercised through `TestClient`, which speaks to the application
directly. Confirming it takes a real uvicorn process, which these tests do not
start. They check the two things that can be checked cheaply and that actually
drifted: what the committed commands say, and that the underlying trust check
still refuses an address that is not the proxy.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ubuntuguard.security.device_auth import DeviceAuthError, extract_client_certificate

#: What every documented invocation has to carry.
REQUIRED_FLAG = "--no-proxy-headers"

#: Files that tell a human or a tool how to start the API.
DOCUMENTED_LAUNCHERS = ("Makefile", "README.md", "deploy/nginx/README.md")


def _text(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    if not path.is_file():
        pytest.fail(f"{relative} is missing")
    return path.read_text(encoding="utf-8")


def _uvicorn_commands(text: str) -> list[str]:
    """Every uvicorn invocation in a file, with line continuations joined.

    Joined first because these commands are wrapped across lines for width, and
    a naive per-line search would report a flag as absent whenever it happened
    to sit on the continuation.
    """
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    return [line.strip() for line in joined.splitlines() if "uvicorn" in line and "-m" in line]


# --------------------------------------------------------------------------- #
# The documented commands
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("relative", DOCUMENTED_LAUNCHERS)
def test_documented_run_commands_disable_proxy_headers(repo_root: Path, relative: str) -> None:
    commands = _uvicorn_commands(_text(repo_root, relative))
    if not commands:
        pytest.fail(f"{relative} documents no uvicorn command; has it moved?")
    missing = [command for command in commands if REQUIRED_FLAG not in command]
    assert not missing, (
        f"{relative} starts the API without {REQUIRED_FLAG}, which leaves "
        f"request.client.host overridable by X-Forwarded-For: {missing}"
    )


@pytest.mark.parametrize("relative", DOCUMENTED_LAUNCHERS)
def test_nothing_turns_proxy_headers_back_on(repo_root: Path, relative: str) -> None:
    """`--proxy-headers` must appear nowhere, including as a suggestion."""
    for command in _uvicorn_commands(_text(repo_root, relative)):
        assert not re.search(r"(?<!-no)(?<!no)\s--proxy-headers\b", command), (
            f"{relative} enables uvicorn's proxy headers: {command}"
        )


def test_the_reason_is_written_down(repo_root: Path) -> None:
    """The nginx README has to say the setting defaults to on.

    Without that sentence the flag reads as redundant and the next person
    removes it, which is how it came to be missing in the first place.
    """
    text = _text(repo_root, "deploy/nginx/README.md")
    assert REQUIRED_FLAG in text
    assert re.search(r"on by default|defaults to `?True`?", text, re.IGNORECASE), (
        "deploy/nginx/README.md does not record that uvicorn enables proxy "
        "headers by default, which is the only reason the flag is needed"
    )


# --------------------------------------------------------------------------- #
# The control the flag protects
# --------------------------------------------------------------------------- #


def test_headers_are_refused_from_an_address_that_is_not_the_proxy() -> None:
    """The check the rewrite defeats. A device's own address is not the proxy's."""
    with pytest.raises(DeviceAuthError) as raised:
        extract_client_certificate(
            {"X-Client-Verify": "SUCCESS", "X-Client-Cert": "anything"},
            client_ip="10.197.21.245",
            trusted_proxy_ips=frozenset({"127.0.0.1", "::1"}),
        )

    assert raised.value.code == "untrusted_proxy"


def test_the_proxy_check_runs_before_any_header_is_read() -> None:
    """An untrusted peer is refused for being untrusted, not for a bad header.

    Ordering matters for what an operator sees: if the headers were parsed
    first, a forged request would be reported as a certificate problem and the
    proxy misconfiguration behind it would stay hidden.
    """
    with pytest.raises(DeviceAuthError) as raised:
        extract_client_certificate(
            {},  # no headers at all
            client_ip="203.0.113.9",
            trusted_proxy_ips=frozenset({"127.0.0.1"}),
        )

    assert raised.value.code == "untrusted_proxy", (
        f"a request from an untrusted peer should be refused as such, not as {raised.value.code}"
    )


def test_a_missing_client_address_is_not_trusted() -> None:
    """`request.client` can be None. That must not read as 'came from nginx'."""
    with pytest.raises(DeviceAuthError) as raised:
        extract_client_certificate(
            {"X-Client-Verify": "SUCCESS"},
            client_ip=None,
            trusted_proxy_ips=frozenset({"127.0.0.1", "::1"}),
        )

    assert raised.value.code == "untrusted_proxy"
