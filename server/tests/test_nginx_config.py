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


def test_the_installer_download_is_rate_limited(config: Block) -> None:
    """The third unauthenticated endpoint, and the only one that returns a file.

    The concern is bandwidth rather than computation: each request hashes and
    returns ~160 KB and needs no credential, so an unlimited route is a cheap
    way to make this server serve traffic for somebody else.
    """
    zones = {
        argument.split("=", 1)[1].split(":", 1)[0]
        for arguments in config.values("limit_req_zone")
        for argument in arguments
        if argument.startswith("zone=")
    }
    assert any("installer" in zone for zone in zones), (
        f"no rate-limit zone for the installer download; found {sorted(zones)}"
    )

    enrollment = _server_on(config, 8443)
    installer = next(
        (
            block
            for block in enrollment.walk()
            if block.kind == "location" and "installer" in block.argument
        ),
        None,
    )
    assert installer is not None, "no location for the installer routes"
    limits = installer.values("limit_req")
    assert limits, "the installer location has no limit_req"
    assert any("zone=ug_installer" in argument for argument in limits[0])


def test_the_installer_is_not_served_on_the_device_plane(config: Block) -> None:
    """A device presenting a certificate has already been installed.

    Every route on the mTLS listener is one more thing sitting behind a device
    certificate, so one that exists for nobody should not be there at all.
    """
    device = _server_on(config, 8444)
    installer = next(
        (
            block
            for block in device.walk()
            if block.kind == "location" and "installer" in block.argument
        ),
        None,
    )
    assert installer is not None, "the installer routes are not addressed on the device listener"
    assert installer.values("return"), "the device listener proxies the installer routes"
    assert not installer.values("proxy_pass")


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


# --------------------------------------------------------------------------- #
# The single-hostname configuration, which is the one an INSTALLED agent can use
# --------------------------------------------------------------------------- #
#
# `ubuntuguard-dev.conf` splits the planes across two ports, and an installed
# agent cannot reach both: a second URL needs `UG_AGENT_DEVICE_URL`, which is a
# dev-only override that forces `release_build` to False, and
# `ALLOWED_CONFIG_KEYS` has no third key to carry one. So that configuration is
# for development only, and this one is what a real deployment uses.
#
# It relies on `ssl_verify_client optional` plus the application's own check
# rather than on nginx aborting the handshake. These tests pin the three things
# that makes sound.


@pytest.fixture(scope="module")
def single_host(nginx_dir: Path) -> Block:
    path = nginx_dir / "ubuntuguard-single-host.conf"
    if not path.is_file():
        pytest.fail(f"{path} is missing; an installed agent has no usable configuration")
    return parse(path.read_text(encoding="utf-8"))


def test_the_single_host_listener_requests_a_client_certificate(single_host: Block) -> None:
    """`optional`, which is the only value that serves both planes.

    `on` would abort the handshake for a device that has no certificate yet,
    which is exactly the state `POST /enroll` exists to resolve. `off` would
    mean no certificate is ever forwarded and the device plane could not
    authenticate anybody.
    """
    servers = [block for block in single_host.walk() if block.kind == "server"]
    assert len(servers) == 1, f"expected exactly one server block, found {len(servers)}"

    verify = servers[0].values("ssl_verify_client")
    assert verify == [["optional"]], f"expected `ssl_verify_client optional`, found {verify}"


def test_the_single_host_listener_verifies_the_chain_against_the_device_ca(
    single_host: Block,
) -> None:
    """This is what makes `optional` safe rather than decorative.

    `optional` validates a presented certificate against this CA, so SUCCESS
    means "issued by the internal device CA" exactly as it does on the
    two-listener config. Point it at a public bundle and any publicly issued
    certificate becomes a valid device identity.
    """
    server = next(block for block in single_host.walk() if block.kind == "server")

    client_ca = server.values("ssl_client_certificate")
    assert client_ca, "the listener forwards certificates without verifying any chain"

    client_ca_path = client_ca[0][0]
    assert client_ca_path != server.values("ssl_certificate")[0][0]
    assert "device" in Path(client_ca_path).name, (
        f"{client_ca_path} does not look like the device CA"
    )
    assert server.values("ssl_verify_depth") == [["1"]]


def test_the_single_host_config_uses_no_conditional(nginx_dir: Path) -> None:
    """The objection README.md raised against `optional`, and why it does not apply.

    The documented concern was that `optional` puts enforcement "in a
    conditional that is easy to edit wrongly", and nginx's `if` in a location
    context is documented as surprising. There is no `if` in this file: the
    enforcement is `device_auth.py` comparing the forwarded verify header
    against SUCCESS, which it already did. If an `if` ever appears here, the
    reasoning in the header comment has stopped being true.
    """
    text = (nginx_dir / "ubuntuguard-single-host.conf").read_text(encoding="utf-8")
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        assert not re.match(r"\s*if\s*\(", code), f"a conditional appeared: {line!r}"


def test_the_single_host_config_serves_both_planes(single_host: Block) -> None:
    """The whole point: one listener an installed agent can use for everything.

    Both locations must PROXY - not `return 421` as the two-port config does
    for whichever plane it is not serving.
    """
    locations = {block.argument: block for block in single_host.walk() if block.kind == "location"}

    enroll = locations.get("= /api/v1/enroll")
    assert enroll is not None, "enrollment is not served"
    assert enroll.values("proxy_pass"), "enrollment is addressed but not proxied"
    assert not enroll.values("return")

    device = locations.get("^~ /api/v1/devices/me/")
    assert device is not None, "the device plane is not served"
    assert device.values("proxy_pass"), "the device plane is addressed but not proxied"
    assert not device.values("return")


def test_every_single_host_location_overwrites_the_identity_headers(
    single_host: Block,
) -> None:
    """The inheritance trap again, and it matters more here.

    On this listener a caller CAN complete a handshake without a certificate,
    so a location that failed to overwrite `X-Client-Verify` would let that
    caller supply `SUCCESS` itself and authenticate as any device whose
    certificate it could guess the fingerprint of.
    """
    offenders = [
        block.argument
        for block in single_host.walk()
        if block.kind == "location"
        and block.values("proxy_pass")
        and INSTALLED_INCLUDE_PATH
        not in {arguments[0] for arguments in block.values("include") if arguments}
    ]
    assert not offenders, (
        "these locations proxy without overwriting the client-identity headers, "
        f"so a caller could supply its own: {offenders}"
    )


def test_the_two_configurations_use_different_ports(config: Block, single_host: Block) -> None:
    """Not so they can coexist - they cannot - but so the failure is legible.

    An operator who installs the single-host config while the dev one is still
    present gets a `limit_req_status is duplicate` error, which names the real
    problem. If they also shared a port they could instead get "address already
    in use", which reads like a stray process rather than two configurations
    answering the same question.
    """

    def ports(block: Block) -> set[int]:
        found: set[int] = set()
        for server in (item for item in block.walk() if item.kind == "server"):
            found |= _listen_ports(server)
        return found

    shared = ports(config) & ports(single_host)
    assert not shared, f"both configurations listen on {sorted(shared)}"


#: Directives that may appear only ONCE in an `http{}` context. Everything in
#: conf.d is included there, so two files each declaring one of these makes
#: nginx refuse to start with "directive is duplicate".
#:
#: `limit_req_zone` is deliberately absent: repeating it is legal and expected,
#: because each occurrence declares a differently-named zone.
HTTP_SINGLETON_DIRECTIVES = (
    "limit_req_status",
    "limit_conn_status",
    "server_tokens",
    "client_max_body_size",
)


def test_no_two_configurations_declare_the_same_http_singleton_directive(
    nginx_dir: Path,
) -> None:
    """The test that was missing, and it cost a failed `nginx -t` to find.

    `limit_req_status 429` is declared at http level by both
    `ubuntuguard-dev.conf` and `ubuntuguard-single-host.conf`. Installing both
    into conf.d therefore produces:

        [emerg] "limit_req_status" directive is duplicate

    The configurations are alternatives and that error is the correct outcome -
    but nothing in this file detected the overlap, so it surfaced as a broken
    reload on someone's machine instead of as a failing test. This asserts the
    overlap is known and documented rather than accidental.

    A third configuration that reintroduced the clash without saying so now
    fails here.
    """
    declared: dict[str, list[str]] = {}
    for path in sorted(nginx_dir.glob("*.conf")):
        parsed = parse(path.read_text(encoding="utf-8"))
        # Top-level only: a directive inside a server{} or location{} block is
        # a different context and may legitimately repeat across files.
        for directive, _ in parsed.directives:
            if directive in HTTP_SINGLETON_DIRECTIVES:
                declared.setdefault(directive, []).append(path.name)

    clashes = {directive: files for directive, files in declared.items() if len(files) > 1}
    for directive, files in clashes.items():
        for name in files:
            text = (nginx_dir / name).read_text(encoding="utf-8")
            assert "INSTALL ONE" in text or "alternatives" in text.lower(), (
                f"{name} declares the http-level singleton {directive!r}, which "
                f"{[other for other in files if other != name]} also declares, but "
                "it does not document that these configurations are mutually "
                "exclusive. Installing both makes nginx refuse to start."
            )


def test_the_single_host_config_rate_limits_and_stays_on_loopback(
    single_host: Block,
) -> None:
    """Same controls as the dev config: the endpoints are identical."""
    zones = {
        argument.split("=", 1)[1].split(":", 1)[0]
        for arguments in single_host.values("limit_req_zone")
        for argument in arguments
        if argument.startswith("zone=")
    }
    assert any("enroll" in zone for zone in zones), f"no enroll rate limit; found {zones}"
    assert any("login" in zone for zone in zones)
    assert any("installer" in zone for zone in zones)

    for upstream in (block for block in single_host.walk() if block.kind == "upstream"):
        for arguments in upstream.values("server"):
            assert arguments[0].startswith(("127.0.0.1:", "[::1]:", "localhost:"))

    server = next(block for block in single_host.walk() if block.kind == "server")
    for arguments in server.values("listen"):
        assert arguments[0].startswith(("127.0.0.1:", "[::1]:")), (
            f"listen {arguments[0]} is not bound to loopback in a development config"
        )
    assert set(server.values("ssl_protocols")[0]) <= {"TLSv1.2", "TLSv1.3"}


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
