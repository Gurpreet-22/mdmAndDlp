"""The privilege boundary: a Unix socket that only agentd may speak through.

This is the B3 edge in UbuntuGuard's threat model -- unprivileged agentd to
root enforcerd on the same laptop -- so the rules it enforces matter more than
the code volume suggests. Everything here exists to make one guarantee: the
only thing that crosses into root is one of four named operations carrying
typed data, from a process we have confirmed is agentd.

**Wire format.** Newline-delimited JSON: one compact JSON object per line,
request and response alike. This is the one part of the integration her
documentation does not specify, so it is a proposal rather than a given, but
it is not an arbitrary one. Her agent already encodes HTTP bodies with
`json.dumps(..., separators=(",", ":"))` and already writes newline-delimited
JSON logs, with a comment observing that `json.dumps` escapes control
characters so a record cannot break its own line. That property is exactly
what makes newline framing unambiguous here, so this follows a convention her
code already relies on. Should she prefer length-prefixed framing, only this
module changes: `ops` has no idea a socket exists.

**Peer check.** `SO_PEERCRED` is read from the accepted connection and the
uid compared against the one agentd runs as. The kernel fills those
credentials in, so unlike anything in the payload they cannot be forged by the
caller. File permissions alone would not do: the socket is group-accessible so
agentd can reach it, and that group may have other members.

**Bounded reads.** The caller is unprivileged and may be compromised, so a
request that never ends, or one megabyte of a single line, must not be able to
exhaust root's memory. Reads stop at a byte ceiling and a deadline.

**Sequential handling.** One connection at a time, deliberately. Two
concurrent `OP_USB_SET_POLICY` calls would interleave writes to rules.conf and
daemon restarts, and could leave the host enforcing a mixture of two policies.
There is exactly one legitimate client, so serialising costs nothing and
removes the race entirely.
"""

from __future__ import annotations

import argparse
import contextlib
import grp
import json
import logging
import os
import pwd
import select
import signal
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from . import ops

LOG = logging.getLogger("ubuntuguard.enforcerd")

DEFAULT_SOCKET_PATH = "/run/ubuntuguard/enforcer.sock"

#: Group that may connect. agentd runs as a member.
DEFAULT_GROUP = "ubuntuguard"

#: User agentd runs as; the uid permitted by the peer check.
DEFAULT_PEER_USER = "ubuntuguard"

#: Socket is group read/write, nothing for others.
SOCKET_MODE = 0o660

#: The containing directory gates access even in the instant between bind()
#: and chmod(), so the socket is never reachable with a wider mode.
RUNDIR_MODE = 0o750

#: A usb_control payload with a large allowlist is still only tens of
#: kilobytes. This is generous enough for any real policy and small enough
#: that an unprivileged caller cannot use it to exhaust memory.
MAX_REQUEST_BYTES = 1 << 20  # 1 MiB

#: Guards against a client that connects, sends a partial line and stalls,
#: which would otherwise hold the single-threaded loop forever.
CONNECTION_TIMEOUT_SECONDS = 30

#: Connections are handled one at a time, so the backlog is what absorbs a
#: burst rather than a measure of parallelism. Generous because a queued
#: connection costs almost nothing and a refused one makes agentd report a
#: failure that did not really happen.
LISTEN_BACKLOG = 64


class ServiceError(Exception):
    """The service cannot start or cannot be configured safely."""


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def peer_credentials(conn: socket.socket) -> PeerCredentials:
    """Read the peer's credentials from the kernel.

    `SO_PEERCRED` is recorded by the kernel at connect time. The caller cannot
    influence it, which is what distinguishes this from any identity claim
    that arrives in the payload.
    """
    raw = conn.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def resolve_uid(user: str | int) -> int:
    if isinstance(user, int):
        return user
    if isinstance(user, str) and user.isdigit():
        return int(user)
    try:
        return pwd.getpwnam(str(user)).pw_uid
    except KeyError as exc:
        raise ServiceError(
            f"user {user!r} does not exist, so the peer check could not be "
            f"configured; refusing to start rather than accept any caller"
        ) from exc


def resolve_gid(group: str | int) -> int:
    if isinstance(group, int):
        return group
    if isinstance(group, str) and group.isdigit():
        return int(group)
    try:
        return grp.getgrnam(str(group)).gr_gid
    except KeyError as exc:
        # Failing closed here would leave a root-only socket that agentd
        # cannot reach, and the resulting breakage would be mystifying. Say
        # what is wrong instead.
        raise ServiceError(
            f"group {group!r} does not exist; create it and add the agent "
            f"user to it, or pass --group"
        ) from exc


def encode_response(response: dict) -> bytes:
    """Encode one response as a single newline-terminated line.

    `json.dumps` escapes control characters, so no value inside the response
    can introduce a newline and split the record.
    """
    return (
        json.dumps(response, separators=(",", ":"), default=str) + "\n"
    ).encode("utf-8")


def read_request_line(
    conn: socket.socket, *, max_bytes: int = MAX_REQUEST_BYTES
) -> bytes | None:
    """Read one newline-terminated line, bounded.

    Returns None when the peer closes without sending anything. Raises
    ValueError when the ceiling is reached, which is reported to the caller
    rather than silently truncated -- a truncated policy that happened to
    parse would be far worse than a refusal.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            if not chunks:
                return None
            # A line without its terminator: treat as malformed rather than
            # guessing that the caller meant to finish.
            raise ValueError("peer closed mid-request")
        newline = chunk.find(b"\n")
        if newline != -1:
            chunks.append(chunk[:newline])
            total += newline
            if total > max_bytes:
                raise ValueError("request exceeds the size limit")
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("request exceeds the size limit")


@dataclass
class EnforcerServer:
    enforcer: ops.Enforcer
    socket_path: str = DEFAULT_SOCKET_PATH
    group: str | int = DEFAULT_GROUP
    peer_user: str | int = DEFAULT_PEER_USER
    #: Set only by tests, where the test process is its own peer.
    allow_any_peer: bool = False
    #: Resolved from `peer_user`. Declared rather than assigned on the fly so
    #: a connection served without bind() cannot silently skip the check by
    #: finding the attribute absent.
    peer_uid: int | None = None

    _sock: socket.socket | None = None
    _stopping: bool = False
    #: Wakeup pipe. Closing a listening socket does not reliably interrupt a
    #: thread blocked in accept() on Linux, so shutdown needs something the
    #: loop can actually select on. Without it a SIGTERM leaves enforcerd
    #: blocked until systemd gives up and sends SIGKILL.
    _wake_r: int | None = None
    _wake_w: int | None = None

    def _required_peer_uid(self) -> int:
        if self.peer_uid is None:
            self.peer_uid = resolve_uid(self.peer_user)
        return self.peer_uid

    # -- lifecycle ---------------------------------------------------------

    def bind(self) -> socket.socket:
        """Create the listening socket with its directory and mode in place."""
        path = Path(self.socket_path)
        gid = None if self.allow_any_peer else resolve_gid(self.group)
        if not self.allow_any_peer:
            self._required_peer_uid()

        self._prepare_directory(path, gid)
        self._remove_stale_socket(path)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # The umask applies to bind(), so the mode is set explicitly
        # afterwards. The directory above is already restricted, so the
        # window between the two is not reachable.
        sock.bind(str(path))
        try:
            if gid is not None and os.geteuid() == 0:
                os.chown(path, 0, gid)
            path.chmod(SOCKET_MODE)
        except OSError as exc:
            sock.close()
            path.unlink(missing_ok=True)
            raise ServiceError(
                f"cannot set ownership or mode on {path}: {exc}"
            ) from exc

        sock.listen(LISTEN_BACKLOG)
        self._sock = sock
        if self._wake_r is None:
            self._wake_r, self._wake_w = os.pipe()
            os.set_blocking(self._wake_r, False)
        LOG.info(
            "listening on %s (mode %o, group %s)",
            path,
            SOCKET_MODE,
            self.group if gid is not None else "<any>",
        )
        return sock

    def _prepare_directory(self, path: Path, gid: int | None) -> None:
        directory = path.parent
        try:
            directory.mkdir(parents=True, exist_ok=True)
            if gid is not None:
                # Only root can give a file away, and `main` refuses to run as
                # anyone else, so skipping this off-root is not a weakening --
                # it keeps the path reachable from tests.
                if os.geteuid() == 0:
                    os.chown(directory, 0, gid)
                directory.chmod(RUNDIR_MODE)
        except OSError as exc:
            raise ServiceError(
                f"cannot prepare {directory}: {exc}"
            ) from exc

    def _remove_stale_socket(self, path: Path) -> None:
        """Clear a socket left behind by a previous run.

        Only a socket is removed. If something else occupies the path that is
        a misconfiguration, and deleting it unasked could destroy a file the
        administrator cares about.
        """
        if not path.exists():
            return
        try:
            if not path.is_socket():
                raise ServiceError(
                    f"{path} exists and is not a socket; refusing to remove it"
                )
            path.unlink()
        except OSError as exc:
            raise ServiceError(f"cannot remove stale socket {path}: {exc}") from exc

    def close(self) -> None:
        """Stop serving. Safe to call from a signal handler or another thread.

        Only writes to the wakeup pipe and closes descriptors, so there is
        nothing here that can deadlock against the serving loop.
        """
        self._stopping = True
        if self._wake_w is not None:
            # A closed or full pipe both mean the loop is already going away.
            with contextlib.suppress(OSError):
                os.write(self._wake_w, b"x")
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        Path(self.socket_path).unlink(missing_ok=True)

    def _release_wakeup(self) -> None:
        for attr in ("_wake_r", "_wake_w"):
            fd = getattr(self, attr)
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
                setattr(self, attr, None)

    # -- serving -----------------------------------------------------------

    def serve_forever(self) -> None:
        sock = self._sock or self.bind()
        try:
            while not self._stopping:
                # Wait until there is either a connection or a shutdown
                # request, so accept() is never entered blind.
                try:
                    readable, _, _ = select.select(
                        [sock, self._wake_r], [], []
                    )
                except (OSError, ValueError):
                    if self._stopping:
                        break
                    LOG.exception("select failed")
                    continue

                if self._wake_r in readable or self._stopping:
                    break

                try:
                    conn, _ = sock.accept()
                except OSError:
                    if self._stopping:
                        break
                    LOG.exception("accept failed")
                    continue

                with conn:
                    try:
                        self.serve_connection(conn)
                    except Exception:
                        # One bad client must never take the daemon down: if
                        # enforcerd dies, policy stops being applied and
                        # nothing reports why.
                        LOG.exception("error while serving a connection")
        finally:
            self._release_wakeup()

    def serve_connection(self, conn: socket.socket) -> None:
        conn.settimeout(CONNECTION_TIMEOUT_SECONDS)

        if not self.allow_any_peer:
            expected_uid = self._required_peer_uid()
            creds = peer_credentials(conn)
            if creds.uid != expected_uid:
                # Logged with the uid, never with the payload -- which has not
                # even been read at this point.
                LOG.warning(
                    "rejected connection from uid %d pid %d; only uid %d may "
                    "call enforcerd",
                    creds.uid,
                    creds.pid,
                    expected_uid,
                )
                self._send(
                    conn,
                    {
                        "status": ops.STATUS_FAILED,
                        "reason_code": "peer_rejected",
                        "message": "caller is not the agent user",
                    },
                )
                return

        try:
            line = read_request_line(conn)
        except ValueError as exc:
            LOG.warning("malformed request: %s", exc)
            self._send(
                conn,
                {
                    "status": ops.STATUS_FAILED,
                    "reason_code": "enforcer_rejected",
                    "message": str(exc),
                },
            )
            return
        except TimeoutError:
            LOG.warning("client stalled mid-request")
            return

        if line is None:
            return

        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            # The decode error can quote the input, so it is logged by type
            # only and never echoed back.
            LOG.warning("request was not valid JSON (%s)", type(exc).__name__)
            self._send(
                conn,
                {
                    "status": ops.STATUS_FAILED,
                    "reason_code": "enforcer_rejected",
                    "message": "request was not valid JSON",
                },
            )
            return

        op = request.get("op") if isinstance(request, dict) else None
        LOG.info("handling %s", op if op in ops.OPERATIONS else "<unknown op>")
        response = self.enforcer.handle(request)
        LOG.info(
            "%s -> %s%s",
            op if op in ops.OPERATIONS else "<unknown op>",
            response.get("status"),
            f" ({response['reason_code']})" if response.get("reason_code") else "",
        )
        self._send(conn, response)

    def _send(self, conn: socket.socket, response: dict) -> None:
        try:
            conn.sendall(encode_response(response))
        except OSError as exc:
            LOG.warning("could not send response: %s", exc)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enforcerd",
        description=(
            "Root USB policy enforcer. Accepts a fixed set of typed "
            "operations from the agent over a Unix socket."
        ),
    )
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--group", default=DEFAULT_GROUP)
    parser.add_argument(
        "--peer-user",
        default=DEFAULT_PEER_USER,
        help="only this user may connect (SO_PEERCRED uid check)",
    )
    parser.add_argument(
        "--rules-path", default=None, help="override the usbguard rules path"
    )
    parser.add_argument(
        "--snapshot-dir", default=None, help="override the snapshot store"
    )
    parser.add_argument(
        "--allow-hid-on-authorised",
        action="store_true",
        help=(
            "permit an authorised device to also present a keyboard "
            "interface; off by default because that is the BadUSB shape"
        ),
    )
    parser.add_argument(
        "--verbose", action="store_true", help="log at debug level"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    from . import snapshots, system

    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if os.geteuid() != 0:
        # Said plainly rather than failing later on a permission error that
        # looks like something else.
        LOG.error(
            "enforcerd must run as root: it writes the usbguard rules and "
            "restarts the daemon"
        )
        return 1

    adapter = system.UsbGuardSystem(
        **({"rules_path": args.rules_path} if args.rules_path else {})
    )
    store = snapshots.SnapshotStore(
        **({"directory": args.snapshot_dir} if args.snapshot_dir else {})
    )
    server = EnforcerServer(
        enforcer=ops.Enforcer(
            system=adapter,
            store=store,
            allow_hid_on_authorised=args.allow_hid_on_authorised,
        ),
        socket_path=args.socket,
        group=args.group,
        peer_user=args.peer_user,
    )

    def shutdown(signum, _frame):
        LOG.info("signal %d received, shutting down", signum)
        server.close()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        server.bind()
    except ServiceError as exc:
        LOG.error("%s", exc)
        return 1

    try:
        server.serve_forever()
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
