"""The HTTP client. Standard library only, and deliberately small.

`urllib.request` over `httpx`, which was the Phase 1 plan. The reasoning, since
`pyproject.toml` asks for one per dependency:

  - This runs on employee laptops. `httpx` brings `httpcore`, `h11`, `certifi`,
    `idna`, `anyio` and `sniffio`, which is six more things to track advisories
    for in exchange for a shorter module.
  - `tools/demo_api.py` already drives this exact API from the standard
    library, so the pattern is proven against this server rather than assumed.
  - Everything the agent needs is one POST with a pinned CA and an optional
    client certificate. There is no connection pooling to gain, no HTTP/2 to
    negotiate, and no async to integrate - the service loop is single-threaded
    on purpose.

What this module refuses to do is as important as what it does, so each refusal
is stated where it is implemented rather than only here: no plaintext, no
system trust store, no redirects, no proxies, no unbounded response.

Nothing in this module logs a request body, a response body, a header value or
a URL query string. The enrollment token travels in a body through
`post_json`, and the only defence that actually holds at three in the morning
is that the code which could log it does not exist.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from ubuntuguard_agent import __version__
from ubuntuguard_agent.errors import (
    ConfigError,
    HttpStatusError,
    TlsVerificationError,
    TransportError,
)
from ubuntuguard_agent.logging_setup import get_logger

#: Socket timeout, in seconds. Bounds the TCP connect, the TLS handshake and
#: each individual recv.
#:
#: Note honestly what this is not: urllib applies ONE socket timeout to every
#: phase and offers no way to set connect and read separately, so a single
#: value covers both. Separating them would mean dropping to raw sockets for no
#: benefit the agent can use. What a per-operation timeout does NOT bound is a
#: server that trickles one byte every nine seconds forever, which is what
#: TOTAL_TIMEOUT_SECONDS below is for.
TIMEOUT_SECONDS = 15.0

#: Wall-clock budget for a whole request, including reading the body. Enforced
#: in the read loop, so a slow-drip response is cut off rather than held open
#: indefinitely by a socket timeout that never individually expires.
TOTAL_TIMEOUT_SECONDS = 45.0

#: Hard cap on a response body.
#:
#: The largest legitimate response the agent receives is an enrollment
#: response carrying two PEM certificates and a short key list - a couple of
#: kilobytes. 256 KiB is generous by two orders of magnitude and still small
#: enough that a hostile or broken server cannot make the agent's memory the
#: problem. Policy envelopes are separately capped at
#: `constants.MAX_POLICY_PAYLOAD_BYTES` (64 KiB), so this does not need to
#: accommodate them.
MAX_RESPONSE_BYTES = 256 * 1024

#: Read granularity. Also how often the total deadline is checked.
_READ_CHUNK_BYTES = 64 * 1024

USER_AGENT = f"ubuntuguard-agent/{__version__}"


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    """A completed response. The body is bytes; nothing here is logged."""

    status: int
    body: bytes

    def json(self) -> Any:
        """Parse the body as JSON, or raise `TransportError`.

        A server that returns 200 with a non-JSON body is broken in a way the
        agent cannot act on, so the failure names the status and the length and
        deliberately not the content - an HTML error page from a misconfigured
        proxy is exactly the kind of thing that ends up in a log and should
        not.
        """
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TransportError(
                f"expected a JSON body, got {len(self.body)} bytes that would not "
                f"parse (HTTP {self.status})"
            ) from exc


def _transport_error(reason: object, *, timeout: float) -> TransportError:
    """Map a pre-response failure onto the right exception type.

    The distinction that matters is TLS verification versus everything else.
    A `TlsVerificationError` must never be retried into submission: it means
    either `server_ca_bundle` names the wrong CA or something is sitting
    between the agent and the server, and the agent cannot tell which, so both
    are treated as fatal for the request rather than as a blip to back off
    from. A connection refused on a laptop that just woke up is the opposite -
    entirely expected, and backoff is exactly right.
    """
    if isinstance(reason, ssl.SSLCertVerificationError):
        detail = reason.verify_message or str(reason.reason)
        return TlsVerificationError(
            f"the server's TLS certificate did not verify against the configured CA "
            f"bundle: {detail}. Either server_ca_bundle names the wrong CA, or this "
            "is not the server it claims to be. Not retried."
        )
    if isinstance(reason, ssl.SSLError):
        return TlsVerificationError(f"TLS failure talking to the server: {reason}")
    if isinstance(reason, TimeoutError):
        return TransportError(f"the server did not respond within {timeout:g}s")
    # str() of a socket or DNS error is a system message. It never contains
    # anything the agent sent, which is why it is safe to put in a log line.
    return TransportError(f"could not reach the server: {reason}")


def _failure_outcome(reason: object) -> str:
    """A short, stable label for the structured log line."""
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "tls_verification_failed"
    if isinstance(reason, ssl.SSLError):
        return "tls_error"
    if isinstance(reason, TimeoutError):
        return "timeout"
    return "unreachable"


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Turns any redirect into an error instead of following it.

    This is a security control, not tidiness. Following a redirect would let a
    server - or anything that can answer as one - move the next request, which
    carries either a single-use enrollment token or a client certificate, to a
    host of its choosing. The agent has exactly one server, configured locally,
    and a response telling it to go somewhere else is a response to refuse.

    Returning None from `redirect_request` makes urllib fall through to
    `HTTPDefaultErrorHandler`, which raises `HTTPError` with the 3xx status.
    The caller turns that into a message naming the refusal.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def build_ssl_context(
    *,
    ca_bundle: Path,
    client_certificate: Path | None = None,
    client_key: Path | None = None,
) -> ssl.SSLContext:
    """A context that verifies the server and optionally presents a client cert.

    `cafile` is required rather than optional, and that is the security
    decision in this function. Calling `create_default_context()` with no
    arguments loads the system trust store, which on Ubuntu is around 150
    public certificate authorities. The UbuntuGuard API is an internal service
    with an internal certificate, so trusting the system store would mean
    accepting a certificate for `ubuntuguard.company.internal` from any public
    CA that could be persuaded to issue one - and leaving the agent no way to
    notice. Pinning to the operator-supplied bundle makes the set of acceptable
    issuers exactly one.

    `check_hostname` and `verify_mode` are the defaults from
    `create_default_context`. They are re-asserted below anyway: they are the
    two values whose quiet removal would turn verified TLS into decoration, and
    an assertion is cheaper than discovering it from a packet capture.
    """
    if not ca_bundle.exists():
        raise ConfigError(
            f"server_ca_bundle {ca_bundle} does not exist. The agent will not fall "
            "back to the system trust store: that would mean accepting a "
            "certificate for the API from any public CA."
        )

    try:
        context = ssl.create_default_context(cafile=str(ca_bundle))
    except (OSError, ssl.SSLError) as exc:
        raise ConfigError(f"could not load server_ca_bundle {ca_bundle}: {exc}") from exc

    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # TLS 1.2 is the floor named in docs/01-api-contract.md. create_default_context
    # already sets this on current Python; stating it means a future interpreter
    # with a laxer default does not silently lower it.
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    if client_certificate is not None:
        if client_key is None:  # pragma: no cover - callers always pass both
            raise ConfigError("a client certificate was given without its private key")
        if not client_certificate.exists() or not client_key.exists():
            raise ConfigError(
                f"client certificate material is incomplete: {client_certificate} "
                f"and {client_key} must both exist"
            )
        try:
            context.load_cert_chain(certfile=str(client_certificate), keyfile=str(client_key))
        except (OSError, ssl.SSLError) as exc:
            # The message names the paths, never the key. An SSLError from
            # load_cert_chain does not contain key material, but this is the one
            # call site where that is worth being sure about.
            raise ConfigError(
                f"could not load the device certificate {client_certificate} with "
                f"its key {client_key}: {type(exc).__name__}"
            ) from exc

    return context


class ServerClient:
    """One client per base URL and per identity. Not thread-safe; not needed.

    Two instances exist in practice: one without a client certificate for
    enrollment, and one with for the device plane. Keeping them separate is
    structural - the enrollment client has no certificate to present, so it
    cannot accidentally authenticate as a device, and the device client is
    built only once an identity exists.
    """

    def __init__(
        self,
        base_url: str,
        *,
        ca_bundle: Path | None,
        client_certificate: Path | None = None,
        client_key: Path | None = None,
        plaintext_permitted: bool = False,
        timeout_seconds: float = TIMEOUT_SECONDS,
        total_timeout_seconds: float = TOTAL_TIMEOUT_SECONDS,
        logger: logging.Logger | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._timeout = timeout_seconds
        self._total_timeout = total_timeout_seconds
        self._log = logger if logger is not None else get_logger("http")

        scheme = urlsplit(self._base_url).scheme
        if scheme == "https":
            if ca_bundle is None:
                raise ConfigError(
                    "server_ca_bundle is not configured. It is required for HTTPS: "
                    "the agent verifies the server against that bundle alone and "
                    "will not fall back to the system trust store."
                )
            context: ssl.SSLContext | None = build_ssl_context(
                ca_bundle=ca_bundle,
                client_certificate=client_certificate,
                client_key=client_key,
            )
        elif scheme == "http":
            # config.py has already established that this is a development
            # build, that plaintext was explicitly opted into, and that the host
            # is loopback. Re-checked rather than assumed, because this class is
            # also constructed directly by tests and by any future caller.
            if not plaintext_permitted:
                raise ConfigError(
                    f"refusing to use plaintext HTTP for {self._base_url!r}; HTTPS is required"
                )
            context = None
        else:
            raise ConfigError(f"unsupported URL scheme {scheme!r} in {self._base_url!r}")

        handlers: list[urllib.request.BaseHandler] = [
            _RefuseRedirects(),
            # An empty ProxyHandler disables proxy use entirely. The default
            # opener reads http_proxy/https_proxy from the environment, and an
            # agent silently routing its traffic through whatever a shell
            # variable named is a surprise nobody configured on purpose. The
            # server is specified in agent.yaml; that is the only place it
            # should come from.
            urllib.request.ProxyHandler({}),
        ]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    @property
    def base_url(self) -> str:
        return self._base_url

    def post_json(self, path: str, payload: dict[str, Any]) -> HttpResponse:
        """POST a JSON body and return the response.

        `path` is relative and must not be absolute: `urljoin` with an absolute
        URL would discard the base entirely, which is how a caller passing a
        server-supplied string would reach a server-chosen host. Nothing does
        that today, and the check means nothing can.
        """
        if "://" in path:
            raise ConfigError(f"path must be relative to the base URL, got {path!r}")

        url = urljoin(self._base_url, path.lstrip("/"))
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                # Explicitly not keep-alive: one request per connection. The
                # agent makes one call a minute, so pooling saves nothing, and
                # a fresh connection means a fresh TLS handshake rather than a
                # resumed session whose client certificate was presented
                # minutes ago.
                "Connection": "close",
            },
        )
        return self._send(request, path=urlsplit(url).path, request_bytes=len(body))

    def _send(
        self, request: urllib.request.Request, *, path: str, request_bytes: int
    ) -> HttpResponse:
        started = time.monotonic()
        deadline = started + self._total_timeout
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = self._read_bounded(response, deadline=deadline)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            # HTTPError is itself a response, so the body is readable and worth
            # reading: it carries the problem document's `code`, which is what
            # the caller branches on. Bounded like any other body.
            try:
                error_body = self._read_bounded(exc, deadline=deadline)
            except TransportError:
                error_body = b""
            finally:
                exc.close()
            raise self._status_error(
                status=int(exc.code), body=error_body, path=path, started=started
            ) from exc
        except urllib.error.URLError as exc:
            # Everything that fails before a response arrives lands here, TLS
            # included, and that is worth spelling out because getting it wrong
            # is silent.
            #
            # `urllib.request.AbstractHTTPHandler.do_open` catches OSError and
            # re-raises it as `URLError(err)`, and `ssl.SSLError` is an OSError
            # subclass. So a certificate that fails to verify does NOT arrive
            # here as `SSLCertVerificationError` - it arrives as a `URLError`
            # whose `.reason` IS that exception. An `except
            # ssl.SSLCertVerificationError` clause next to this one would be
            # unreachable, and the agent would report an interception attempt
            # as "could not reach the server". Hence the dispatch on `.reason`.
            self._log_outcome(path, _failure_outcome(exc.reason), started, request_bytes, 0)
            raise _transport_error(exc.reason, timeout=self._timeout) from exc
        except TimeoutError as exc:
            self._log_outcome(path, "timeout", started, request_bytes, 0)
            raise TransportError(f"the server did not respond within {self._timeout:g}s") from exc
        except ssl.SSLError as exc:
            # Reachable for a TLS failure raised outside do_open's wrapping,
            # such as one during the body read rather than the handshake.
            self._log_outcome(path, _failure_outcome(exc), started, request_bytes, 0)
            raise _transport_error(exc, timeout=self._timeout) from exc
        except OSError as exc:
            self._log_outcome(path, "os_error", started, request_bytes, 0)
            raise TransportError(f"network error talking to the server: {exc}") from exc

        self._log_outcome(path, str(status), started, request_bytes, len(body))
        return HttpResponse(status=status, body=body)

    def _read_bounded(self, stream: Any, *, deadline: float) -> bytes:
        """Read a body, refusing one that is too large or too slow.

        Chunked rather than `read()` in one call, for two reasons that both
        matter against a hostile server. A single `read()` with no argument
        would allocate whatever arrives; a single `read(MAX + 1)` would bound
        the size but not the time, so a server sending one byte per nine
        seconds would hold the connection open indefinitely without ever
        tripping the per-recv socket timeout. Checking the deadline every chunk
        bounds both.
        """
        chunks: list[bytes] = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise TransportError(
                    f"the server was still sending after {self._total_timeout:g}s; "
                    f"abandoned after {total} bytes"
                )
            try:
                chunk = stream.read(_READ_CHUNK_BYTES)
            except TimeoutError as exc:
                raise TransportError(f"timed out reading the response body: {exc}") from exc
            except OSError as exc:
                raise TransportError(f"error reading the response body: {exc}") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise TransportError(
                    f"response body exceeded {MAX_RESPONSE_BYTES} bytes; abandoned. "
                    "Is this the UbuntuGuard API, or a proxy error page?"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _status_error(
        self, *, status: int, body: bytes, path: str, started: float
    ) -> HttpStatusError:
        """Build the error for a non-2xx response, including a 3xx redirect."""
        code: str | None = None
        if body:
            try:
                document = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                document = None
            if isinstance(document, dict):
                raw = document.get("code")
                if isinstance(raw, str):
                    code = raw

        self._log_outcome(path, str(status), started, 0, len(body))

        if 300 <= status < 400:
            return HttpStatusError(
                f"the server returned a {status} redirect, which the agent refuses "
                "to follow: a redirect could move a request carrying an enrollment "
                "token or a client certificate to another host",
                status=status,
                code=code,
            )

        # The problem document's `code` is included because it is a stable
        # machine string the server publishes on purpose. `detail` and `title`
        # are NOT included: they are free text from the server, and this message
        # goes into a log line.
        suffix = f" ({code})" if code else ""
        return HttpStatusError(
            f"the server refused the request with HTTP {status}{suffix}",
            status=status,
            code=code,
        )

    def _log_outcome(
        self, path: str, outcome: str, started: float, request_bytes: int, response_bytes: int
    ) -> None:
        """One structured line per request. Metadata only, never content.

        Path without query string, status, duration and byte counts. No body,
        no headers, no URL parameters. The enrollment token is in a body that
        this function is never given, which is the design: redaction in
        `logging_setup` is the safety net, and not having the value here is the
        actual control.
        """
        self._log.debug(
            "server request",
            extra={
                "path": path,
                "outcome": outcome,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                "request_bytes": request_bytes,
                "response_bytes": response_bytes,
            },
        )
