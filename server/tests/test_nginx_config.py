"""The committed nginx configuration, checked against the application's needs.

Why a test and not a review. `security/device_auth.py` derives a device's
identity from four forwarded headers and believes them when they arrive from a
trusted peer. That trust is only sound if nginx overwrites all four on every
request. nginx will not warn when it does not: the application keeps working,
a caller can set its own `X-Client-Cert`, and the device plane is
authenticating whoever asks.

The specific trap is that nginx's `proxy_set_header` directives are NOT
inherited into a `location` that defines any `proxy_set_header` of its own. So
adding one header to a location silently drops the other three. That is a
one-line change which a reviewer can easily read as harmless, and it is exactly
what the first test below fails on.

This parses the file rather than grepping it, so "the directive exists
somewhere" cannot pass for "the directive applies to this location".

Nothing here runs nginx. `nginx -t` on the real file is the other half and is
documented in deploy/nginx/README.md; it needs nginx installed and so cannot be
a unit test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from ubuntuguard.constants import (
    CLIENT_CERT_DN_HEADER,
    CLIENT_CERT_PEM_HEADER,
    CLIENT_CERT_SERIAL_HEADER,
    CLIENT_CERT_VERIFY_HEADER,
)

#: Where the include snippet is expected to live once installed. The config
#: refers to this absolute path, and README.md tells the operator to copy it
#: there; the test ties the two together so they cannot drift.
INSTALLED_INCLUDE_PATH = "/etc/nginx/ubuntuguard/client-cert-headers.conf"


@dataclass
class Block:
    """One nginx block: its header words plus what it contains."""

    header: str
    directives: list[tuple[str, list[str]]] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return self.header.split()[0] if self.header else ""

    @property
    def argument(self) -> str:
        parts = self.header.split(None, 1)
        return parts[1].strip() if len(parts) > 1 else ""

    def values(self, name: str) -> list[list[str]]:
        """Arguments of every `name` directive directly in this block."""
        return [arguments for directive, arguments in self.directives if directive == name]

    def walk(self) -> list[Block]:
        found = [self]
        for child in self.blocks:
            found.extend(child.walk())
        return found


def parse(text: str) -> Block:
    """A small brace-aware nginx parser. Enough for assertions, not a linter.

    Comments are stripped first, then the text is tokenised on `{`, `}` and
    `;`. nginx's real grammar has quoting and `\\` escapes that this does not
    handle; the committed file deliberately uses neither, and a test helper
    growing a string lexer would be a worse trade than keeping the config
    plain.
    """
    stripped = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    root = Block(header="")
    stack = [root]
    buffer = ""

    for character in stripped:
        if character == "{":
            block = Block(header=" ".join(buffer.split()))
            stack[-1].blocks.append(block)
            stack.append(block)
            buffer = ""
        elif character == "}":
            if buffer.strip():
                raise ValueError(f"unterminated directive before '}}': {buffer.strip()!r}")
            if len(stack) == 1:
                raise ValueError("unbalanced '}' in the configuration")
            stack.pop()
            buffer = ""
        elif character == ";":
            words = buffer.split()
            if words:
                stack[-1].directives.append((words[0], words[1:]))
            buffer = ""
        else:
            buffer += character

    if len(stack) != 1:
        raise ValueError("unbalanced '{' in the configuration")
    return root


@pytest.fixture(scope="module")
def nginx_dir(repo_root: Path) -> Path:
    path = repo_root / "deploy" / "nginx"
    if not path.is_dir():
        pytest.fail(f"{path} is missing; the device plane has no proxy configuration")
    return path


@pytest.fixture(scope="module")
def config(nginx_dir: Path) -> Block:
    return parse((nginx_dir / "ubuntuguard-dev.conf").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def header_snippet(nginx_dir: Path) -> str:
    return (nginx_dir / "client-cert-headers.conf").read_text(encoding="utf-8")


def _servers(config: Block) -> list[Block]:
    return [block for block in config.walk() if block.kind == "server"]


def _listen_ports(server: Block) -> set[int]:
    ports: set[int] = set()
    for arguments in server.values("listen"):
        if not arguments:
            continue
        match = re.search(r":(\d+)$|^(\d+)$", arguments[0])
        if match:
            ports.add(int(match.group(1) or match.group(2)))
    return ports


def _server_on(config: Block, port: int) -> Block:
    for server in _servers(config):
        if port in _listen_ports(server):
            return server
    pytest.fail(f"no server block listens on port {port}")


# --------------------------------------------------------------------------- #
# The header overwrite. The most important assertion in this file.
# --------------------------------------------------------------------------- #


def test_the_snippet_sets_every_header_the_application_reads(header_snippet: str) -> None:
    """All four, by the exact names in `constants.py`.

    Asserted against the constants rather than string literals, so renaming a
    header in the application fails here instead of in production.
    """
    expected = {
        CLIENT_CERT_VERIFY_HEADER: "$ssl_client_verify",
        CLIENT_CERT_PEM_HEADER: "$ssl_client_escaped_cert",
        CLIENT_CERT_DN_HEADER: "$ssl_client_s_dn",
        CLIENT_CERT_SERIAL_HEADER: "$ssl_client_serial",
    }
    snippet = parse(header_snippet)
    assigned = {
        arguments[0].lower(): arguments[1]
        for arguments in snippet.values("proxy_set_header")
        if len(arguments) >= 2
    }

    for header, variable in expected.items():
        assert header in assigned, f"{header} is not overwritten; a client could supply it"
        assert assigned[header] == variable, (
            f"{header} is set from {assigned[header]} rather than {variable}"
        )


def test_the_certificate_header_is_not_the_sha1_fingerprint(header_snippet: str) -> None:
    """`$ssl_client_fingerprint` is SHA-1.

    The whole certificate is forwarded instead and the application computes
    SHA-256 itself. Using the proxy's digest would pin device identity to SHA-1.

    Asserted against the parsed DIRECTIVES, not the file text. The snippet
    names the variable in a comment explaining why it is not used, and a
    substring check over the raw file would fail on the explanation - rejecting
    the documentation of a decision rather than its violation.
    """
    snippet = parse(header_snippet)
    for arguments in snippet.values("proxy_set_header"):
        assert "$ssl_client_fingerprint" not in arguments, (
            "a header is set from nginx's SHA-1 fingerprint variable"
        )


def test_every_proxying_location_includes_the_snippet(config: Block) -> None:
    """The inheritance trap, enforced.

    A location that sets any proxy_set_header of its own loses the ones defined
    above it. So every location that proxies must include the snippet, and this
    test names the one that does not.
    """
    offenders = []
    for block in config.walk():
        if block.kind != "location":
            continue
        if not block.values("proxy_pass"):
            continue
        includes = {arguments[0] for arguments in block.values("include") if arguments}
        if INSTALLED_INCLUDE_PATH not in includes:
            offenders.append(block.argument)

    assert not offenders, (
        "these locations proxy to the API without overwriting the client-identity "
        f"headers, so a caller could supply its own: {offenders}"
    )


def test_the_include_path_is_the_one_the_readme_documents(config: Block, nginx_dir: Path) -> None:
    """Otherwise the config references a file the operator never installed."""
    readme = (nginx_dir / "README.md").read_text(encoding="utf-8")
    assert INSTALLED_INCLUDE_PATH in readme, (
        f"README.md does not tell the operator to install the snippet at {INSTALLED_INCLUDE_PATH}"
    )


def test_the_forwarded_for_header_is_overwritten_too(header_snippet: str) -> None:
    """Not because the application trusts it, but so a client's own is replaced.

    If nginx did not set it, the client's `X-Forwarded-For` would pass through
    untouched - and anyone later enabling uvicorn's `--proxy-headers` would make
    `request.client.host` attacker-controlled, which is the single value the
    trusted-proxy check rests on.
    """
    snippet = parse(header_snippet)
    assigned = {
        arguments[0].lower() for arguments in snippet.values("proxy_set_header") if arguments
    }
    assert "x-forwarded-for" in assigned


def test_the_snippet_warns_against_uvicorn_proxy_headers(header_snippet: str) -> None:
    """The hazard is non-obvious and silent, so it is written where it applies."""
    assert "--proxy-headers" in header_snippet


# --------------------------------------------------------------------------- #
# Mutual TLS on the device listener
# --------------------------------------------------------------------------- #


def test_the_device_listener_requires_a_verified_client_certificate(config: Block) -> None:
    """`on`, not `optional`. nginx aborts the handshake without a certificate."""
    device = _server_on(config, 8444)
    verify = device.values("ssl_verify_client")
    assert verify, "the device listener does not set ssl_verify_client at all"
    assert verify[0] == ["on"], f"expected `ssl_verify_client on`, found {verify[0]}"


def test_optional_no_ca_is_used_nowhere(nginx_dir: Path) -> None:
    """It forwards the certificate WITHOUT verifying the chain.

    `$ssl_client_verify` would still report SUCCESS, so every application check
    that trusts SUCCESS would be trusting an unverified certificate. There is no
    configuration in which this is the right answer here.
    """
    for path in nginx_dir.glob("*.conf"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            assert "optional_no_ca" not in code, f"{path.name} uses optional_no_ca"


def test_the_device_listener_verifies_against_the_device_ca(config: Block) -> None:
    """Not the CA that issued the listener's own certificate.

    Pointing `ssl_client_certificate` at a public bundle would make any
    publicly issued certificate a valid device identity. The two files are
    named distinctly so the mistake is visible in a diff.
    """
    device = _server_on(config, 8444)
    client_ca = device.values("ssl_client_certificate")
    assert client_ca, "the device listener does not configure a client CA"

    client_ca_path = client_ca[0][0]
    server_certificate = device.values("ssl_certificate")[0][0]
    assert client_ca_path != server_certificate
    assert "device" in Path(client_ca_path).name, (
        f"{client_ca_path} does not look like the device CA; if this is the "
        "server's own CA, any certificate it signed would authenticate as a device"
    )


def test_the_verify_depth_matches_the_cas_path_length(config: Block) -> None:
    """The device CA is created with path_length=0, so depth 1 is the truth."""
    device = _server_on(config, 8444)
    depth = device.values("ssl_verify_depth")
    assert depth == [["1"]], f"expected ssl_verify_depth 1, found {depth}"


def test_the_enrollment_listener_requests_no_client_certificate(config: Block) -> None:
    """A device enrolling has no certificate yet; requiring one is a deadlock.

    This is the reason the development configuration uses two ports rather than
    one listener with a conditional.
    """
    enrollment = _server_on(config, 8443)
    assert enrollment.values("ssl_verify_client") == []
    assert enrollment.values("ssl_client_certificate") == []


def test_the_planes_do_not_overlap(config: Block) -> None:
    """Enrollment is not served on the device port, nor the reverse.

    An enrolled device spending tokens for others, and an agent getting a 401
    it reads as a credential problem, are the two failures this prevents.
    """
    enrollment = _server_on(config, 8443)
    device = _server_on(config, 8444)

    def locations(server: Block) -> dict[str, Block]:
        return {block.argument: block for block in server.walk() if block.kind == "location"}

    device_plane_on_enrollment = locations(enrollment)["^~ /api/v1/devices/me/"]
    assert device_plane_on_enrollment.values("return"), (
        "the enrollment listener proxies the device plane"
    )
    assert not device_plane_on_enrollment.values("proxy_pass")

    enroll_on_device_plane = locations(device)["= /api/v1/enroll"]
    assert enroll_on_device_plane.values("return")
    assert not enroll_on_device_plane.values("proxy_pass")


# --------------------------------------------------------------------------- #
# Rate limiting and backend exposure
# --------------------------------------------------------------------------- #


def test_enrollment_is_rate_limited(config: Block) -> None:
    """Closes SECURITY-FINDINGS item 4.

    /enroll is unauthenticated and does asymmetric work: a small request causes
    a CSR parse, a key-size check and a signature verification.
    """
    # `limit_req_zone <key> zone=<name>:<size> rate=<rate>` - the zone name is
    # in the `zone=` argument, which is not necessarily the last one.
    zones = {
        argument.split("=", 1)[1].split(":", 1)[0]
        for arguments in config.values("limit_req_zone")
        for argument in arguments
        if argument.startswith("zone=")
    }
    assert any("enroll" in zone for zone in zones), (
        f"no rate-limit zone for enrollment; found {sorted(zones)}"
    )

    enrollment = _server_on(config, 8443)
    enroll_location = next(
        block
        for block in enrollment.walk()
        if block.kind == "location" and block.argument == "= /api/v1/enroll"
    )
    limits = enroll_location.values("limit_req")
    assert limits, "the enroll location has no limit_req"
    assert any("zone=ug_enroll" in argument for argument in limits[0])


def test_the_login_endpoint_is_rate_limited(config: Block) -> None:
    """The other unauthenticated endpoint that does expensive work (Argon2id).

    Per-account lockout does not help against one attacker spraying many
    account names, which is what this covers.
    """
    enrollment = _server_on(config, 8443)
    login = next(
        (
            block
            for block in enrollment.walk()
            if block.kind == "location" and "auth/login" in block.argument
        ),
        None,
    )
    assert login is not None, "no location for the login endpoint"
    assert login.values("limit_req"), "the login location has no limit_req"


def test_the_backend_is_only_reachable_on_loopback(config: Block) -> None:
    """The application believes the identity headers from a trusted peer.

    `trusted_proxy_ips` defaults to 127.0.0.1 and ::1, so an upstream on any
    other interface would either break authentication or require widening that
    allowlist.
    """
    upstreams = [block for block in config.walk() if block.kind == "upstream"]
    assert upstreams, "no upstream block"
    for upstream in upstreams:
        for arguments in upstream.values("server"):
            assert arguments[0].startswith(("127.0.0.1:", "[::1]:", "localhost:")), (
                f"upstream {arguments[0]} is not loopback"
            )


def test_every_listener_binds_loopback_in_the_development_config(config: Block) -> None:
    """Development only. A dev box must not serve the fleet by accident."""
    for server in _servers(config):
        for arguments in server.values("listen"):
            assert arguments[0].startswith(("127.0.0.1:", "[::1]:")), (
                f"listen {arguments[0]} is not bound to loopback"
            )


def test_only_modern_tls_is_offered(config: Block) -> None:
    """TLS 1.2 is the floor named in docs/01-api-contract.md."""
    for server in _servers(config):
        protocols = server.values("ssl_protocols")
        assert protocols, "a server block does not pin ssl_protocols"
        offered = set(protocols[0])
        assert offered <= {"TLSv1.2", "TLSv1.3"}, f"weak protocols offered: {offered}"


# --------------------------------------------------------------------------- #
# The parser itself, so a false pass is not possible
# --------------------------------------------------------------------------- #


def test_the_parser_finds_nested_locations() -> None:
    root = parse("http { server { listen 443 ssl; location / { proxy_pass http://x; } } }")
    locations = [block for block in root.walk() if block.kind == "location"]
    assert len(locations) == 1
    assert locations[0].values("proxy_pass") == [["http://x"]]


def test_the_parser_strips_comments() -> None:
    root = parse("server { # ssl_verify_client off;\n ssl_verify_client on; }")
    assert root.blocks[0].values("ssl_verify_client") == [["on"]]


def test_the_parser_rejects_unbalanced_braces() -> None:
    with pytest.raises(ValueError, match="unbalanced"):
        parse("server { location / { } ")
