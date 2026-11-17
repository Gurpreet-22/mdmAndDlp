"""Tests for the enforcerd socket layer.

These run against a real `AF_UNIX` socket in a temporary directory, with a
real server thread, because the things worth testing here are properties of
the socket rather than of our code: that `SO_PEERCRED` reports what we think,
that a bounded read actually stops, that newline framing survives a payload
split across several `recv` calls. A mock socket would confirm only that the
test author and the implementation share an assumption.

The peer check cannot be exercised positively by running as another uid
without root, so it is tested from the other side: a deliberately wrong
expected uid must refuse the test process's own connection.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path

from enforcer_helpers import DAEMON_CONF, NOW, FakeHost, base_payload
from ubuntuguard_agent.enforcer import (
    client,
    intent,
    ops,
    service,
    snapshots,
    system,
)


class ServiceFixture(unittest.TestCase):
    def setUp(self):
        # The service logs rejections and errors at warning level, which is
        # correct in production and only noise here. Several of these tests
        # deliberately trigger it, so left alone it buries real failures.
        service.LOG.disabled = True
        self.addCleanup(setattr, service.LOG, "disabled", False)

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)

        etc = root / "etc"
        etc.mkdir()
        self.rules_path = etc / "rules.conf"
        daemon_conf = etc / "usbguard-daemon.conf"
        daemon_conf.write_text(DAEMON_CONF, encoding="utf-8")

        self.host = FakeHost(str(self.rules_path))
        self.enforcer = ops.Enforcer(
            system=system.UsbGuardSystem(
                rules_path=str(self.rules_path),
                daemon_conf_path=str(daemon_conf),
                runner=self.host.runner,
                which=self.host.which,
            ),
            store=snapshots.SnapshotStore(directory=str(root / "snaps")),
            clock=lambda: NOW,
        )

        self.socket_path = str(root / "enforcer.sock")
        self.server = service.EnforcerServer(
            enforcer=self.enforcer,
            socket_path=self.socket_path,
            allow_any_peer=True,
        )

    def start_server(self) -> None:
        self.server.bind()
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()

        def stop():
            self.server.close()
            thread.join(timeout=5)

        self.addCleanup(stop)

    def request(self, payload, *, raw: bytes | None = None) -> dict:
        """Send one request over a fresh connection and read the response."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(self.socket_path)
            if raw is not None:
                client.sendall(raw)
            else:
                client.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
            chunks = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        data = b"".join(chunks)
        if not data:
            raise AssertionError("server sent no response")
        return json.loads(data.split(b"\n")[0].decode("utf-8"))


# ---------------------------------------------------------------------------
# framing
# ---------------------------------------------------------------------------


class TestFraming(unittest.TestCase):
    def test_response_is_one_newline_terminated_line(self):
        encoded = service.encode_response({"status": "ok"})
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded.count(b"\n"), 1)

    def test_newlines_in_values_cannot_split_a_record(self):
        """The property newline framing depends on.

        json.dumps escapes control characters, so no value can terminate the
        line early. Without this, a device name containing a newline would
        desynchronise the stream.
        """
        encoded = service.encode_response(
            {"status": "ok", "message": "line one\nline two\r\n\u2028"}
        )
        self.assertEqual(encoded.count(b"\n"), 1)
        restored = json.loads(encoded.decode("utf-8"))
        self.assertEqual(restored["message"], "line one\nline two\r\n\u2028")

    def test_response_is_compact(self):
        """Matches the separators her agent already uses for JSON bodies."""
        encoded = service.encode_response({"a": 1, "b": 2})
        self.assertNotIn(b", ", encoded)
        self.assertNotIn(b": ", encoded)

    def test_non_serialisable_values_do_not_raise(self):
        """A response must always be sendable.

        Were encoding able to fail, a successful apply could be followed by a
        crash that leaves the caller believing nothing happened.
        """
        encoded = service.encode_response({"at": dt.datetime.now()})
        json.loads(encoded.decode("utf-8"))


class TestBoundedReads(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def test_reads_a_single_line(self):
        left, right = self.pair()
        right.sendall(b'{"op":"OP_CAPABILITIES"}\n')
        self.assertEqual(service.read_request_line(left), b'{"op":"OP_CAPABILITIES"}')

    def test_reassembles_a_line_split_across_packets(self):
        """A large policy will not arrive in one recv."""
        left, right = self.pair()
        payload = json.dumps({"op": "X", "pad": "y" * 20000}).encode("utf-8")

        def feed():
            for index in range(0, len(payload), 1000):
                right.sendall(payload[index : index + 1000])
            right.sendall(b"\n")

        thread = threading.Thread(target=feed, daemon=True)
        thread.start()
        self.assertEqual(service.read_request_line(left), payload)
        thread.join(timeout=5)

    def test_stops_at_the_byte_ceiling(self):
        """An unprivileged caller must not be able to exhaust root's memory."""
        left, right = self.pair()

        ceiling = 4096 * 8
        # Enough to cross the ceiling, and small enough to fit the socket
        # buffer so the writer does not block once the reader has given up.
        right.sendall(b"z" * (ceiling + 4096))

        with self.assertRaises(ValueError) as caught:
            service.read_request_line(left, max_bytes=ceiling)
        self.assertIn("size limit", str(caught.exception))

    def test_empty_connection_reads_as_none(self):
        left, right = self.pair()
        right.close()
        self.assertIsNone(service.read_request_line(left))

    def test_unterminated_line_is_malformed(self):
        """A partial request must not be guessed at.

        A truncated policy that happened to parse would be worse than a
        refusal, because it would be applied.
        """
        left, right = self.pair()
        right.sendall(b'{"op":"OP_CAPAB')
        right.close()
        with self.assertRaises(ValueError):
            service.read_request_line(left)


# ---------------------------------------------------------------------------
# socket setup
# ---------------------------------------------------------------------------


class TestSocketSetup(ServiceFixture):
    def test_socket_is_created(self):
        self.start_server()
        self.assertTrue(Path(self.socket_path).is_socket())

    def test_socket_is_removed_on_close(self):
        self.start_server()
        self.server.close()
        self.assertFalse(Path(self.socket_path).exists())

    def test_a_stale_socket_is_replaced(self):
        """enforcerd restarting must not be blocked by its own leftovers."""
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(self.socket_path)
        stale.close()
        self.assertTrue(Path(self.socket_path).is_socket())

        self.start_server()
        response = self.request({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_OK)

    def test_a_regular_file_at_the_socket_path_is_not_deleted(self):
        """Removing an unrelated file unasked would be destructive."""
        Path(self.socket_path).write_text("not a socket", encoding="utf-8")
        with self.assertRaises(service.ServiceError) as caught:
            self.server.bind()
        self.assertIn("refusing to remove", str(caught.exception))
        self.assertEqual(Path(self.socket_path).read_text(encoding="utf-8"), "not a socket")

    def test_unknown_group_is_refused_with_a_clear_message(self):
        """A root-only socket agentd cannot reach would be baffling."""
        server = service.EnforcerServer(
            enforcer=self.enforcer,
            socket_path=self.socket_path,
            group="definitely-not-a-real-group",
        )
        with self.assertRaises(service.ServiceError) as caught:
            server.bind()
        self.assertIn("does not exist", str(caught.exception))

    def test_unknown_peer_user_is_refused_rather_than_allowing_anyone(self):
        server = service.EnforcerServer(
            enforcer=self.enforcer,
            socket_path=self.socket_path,
            group=os.getgid(),
            peer_user="definitely-not-a-real-user",
        )
        with self.assertRaises(service.ServiceError) as caught:
            server.bind()
        self.assertIn("refusing to start", str(caught.exception))

    def test_numeric_group_and_user_are_accepted(self):
        """So the unit can be configured without name lookups."""
        self.assertEqual(service.resolve_gid(os.getgid()), os.getgid())
        self.assertEqual(service.resolve_uid(str(os.getuid())), os.getuid())

    def test_shutdown_is_prompt(self):
        """close() must actually interrupt the accept loop.

        Closing a listening socket does not reliably wake a thread blocked in
        accept() on Linux, so without an explicit wakeup a SIGTERM leaves
        enforcerd running until systemd loses patience and sends SIGKILL.
        """
        self.server.bind()
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()

        # Confirm it is actually serving before asking it to stop.
        self.assertEqual(self.request({"op": ops.OP_CAPABILITIES})["status"], ops.STATUS_OK)

        started = time.monotonic()
        self.server.close()
        thread.join(timeout=10)
        elapsed = time.monotonic() - started

        self.assertFalse(thread.is_alive(), "serve_forever did not exit")
        self.assertLess(elapsed, 2.0, f"shutdown took {elapsed:.2f}s")

    def test_close_is_idempotent(self):
        self.start_server()
        self.server.close()
        self.server.close()

    def test_socket_mode_is_group_only(self):
        """Not world-accessible: the socket is a path into root."""
        server = service.EnforcerServer(
            enforcer=self.enforcer,
            socket_path=self.socket_path,
            group=os.getgid(),
            peer_user=os.getuid(),
        )
        server.bind()
        self.addCleanup(server.close)
        mode = stat.S_IMODE(Path(self.socket_path).stat().st_mode)
        self.assertEqual(mode, service.SOCKET_MODE)
        self.assertFalse(mode & stat.S_IRWXO, "socket is reachable by others")


# ---------------------------------------------------------------------------
# the peer check
# ---------------------------------------------------------------------------


class TestPeerCheck(ServiceFixture):
    def test_peercred_reports_this_process(self):
        """Confirms SO_PEERCRED means what the check assumes."""
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        creds = service.peer_credentials(left)
        self.assertEqual(creds.uid, os.getuid())
        self.assertEqual(creds.gid, os.getgid())
        self.assertEqual(creds.pid, os.getpid())

    def test_wrong_uid_is_refused(self):
        """Tested from the other side: expect a uid this process is not.

        Running as a second uid needs root, so the check is verified by
        configuring an expectation the test process cannot satisfy.
        """
        self.server.allow_any_peer = False
        self.server.peer_uid = os.getuid() + 1
        self.server.group = os.getgid()
        self.start_server()

        response = self.request({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "peer_rejected")

    def test_refused_peer_cannot_apply_policy(self):
        """The refusal must happen before the request is even read."""
        self.server.allow_any_peer = False
        self.server.peer_uid = os.getuid() + 1
        self.server.group = os.getgid()
        self.start_server()

        response = self.request(
            {
                "op": ops.OP_USB_SET_POLICY,
                "payload": {"policy": base_payload()},
            }
        )
        self.assertEqual(response["reason_code"], "peer_rejected")
        self.assertFalse(self.rules_path.exists(), "a refused peer changed the policy")

    def test_correct_uid_is_accepted(self):
        self.server.allow_any_peer = False
        self.server.peer_uid = os.getuid()
        self.server.group = os.getgid()
        self.start_server()

        response = self.request({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_OK)


# ---------------------------------------------------------------------------
# end to end over the socket
# ---------------------------------------------------------------------------


class TestOperationsOverTheSocket(ServiceFixture):
    def setUp(self):
        super().setUp()
        self.start_server()

    def test_capabilities(self):
        response = self.request({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_OK)
        self.assertTrue(response["capabilities"]["supported"])

    def test_set_policy_applies_over_the_socket(self):
        response = self.request(
            {
                "op": ops.OP_USB_SET_POLICY,
                "payload": {"policy": base_payload()},
                "policy_version": 3,
            }
        )
        self.assertEqual(response["status"], ops.STATUS_APPLIED)
        self.assertIn(
            "block with-interface one-of { 08:*:* }",
            self.rules_path.read_text(encoding="utf-8"),
        )

    def test_get_state_after_apply(self):
        self.request({"op": ops.OP_USB_SET_POLICY, "payload": {"policy": base_payload()}})
        response = self.request({"op": ops.OP_USB_GET_STATE})
        self.assertEqual(response["status"], ops.STATUS_OK)
        self.assertTrue(response["fingerprint_self_consistent"])

    def test_rollback_over_the_socket(self):
        self.rules_path.write_text("allow id 1111:2222\n", encoding="utf-8")
        applied = self.request({"op": ops.OP_USB_SET_POLICY, "payload": {"policy": base_payload()}})
        response = self.request(
            {
                "op": ops.OP_USB_ROLLBACK,
                "payload": {"snapshot_id": applied["snapshot"]["snapshot_id"]},
            }
        )
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), "allow id 1111:2222\n")

    def test_unknown_op_is_refused_over_the_socket(self):
        response = self.request({"op": "OP_RUN_SHELL"})
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_malformed_json_is_refused(self):
        response = self.request(None, raw=b"{not json\n")
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_malformed_json_response_does_not_echo_the_input(self):
        secret = "s3cret-serial-value"
        response = self.request(None, raw=b'{"op": "X", "secret": "' + secret.encode() + b'" \n')
        self.assertNotIn(secret, json.dumps(response))

    def test_oversized_request_is_refused(self):
        huge = {"op": ops.OP_CAPABILITIES, "payload": {}}
        raw = json.dumps(huge).encode("utf-8")
        raw = raw[:-1] + b',"pad":"' + b"z" * (service.MAX_REQUEST_BYTES + 1024)
        response = self.request(None, raw=raw + b'"}\n')
        self.assertEqual(response["status"], ops.STATUS_FAILED)

    def test_non_utf8_request_is_refused(self):
        response = self.request(None, raw=b"\xff\xfe\x00bad\n")
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_server_survives_a_bad_request_and_serves_the_next(self):
        """One hostile client must not take enforcerd down.

        If it dies, policy stops being applied and nothing reports why.
        """
        self.request(None, raw=b"{not json\n")
        self.request(None, raw=b"\xff\xfe\n")
        self.request({"op": "OP_NONSENSE"})
        response = self.request({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_OK)

    def test_server_survives_a_client_that_disconnects_immediately(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.socket_path)
        response = self.request({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_OK)

    def test_requests_are_handled_sequentially(self):
        """Concurrent applies would interleave writes to rules.conf.

        Twelve clients apply at once; every one must get a complete, valid
        response and the installed file must be exactly one policy.
        """
        results: list[dict] = []
        lock = threading.Lock()

        def apply_once():
            try:
                response = self.request(
                    {
                        "op": ops.OP_USB_SET_POLICY,
                        "payload": {"policy": base_payload()},
                    }
                )
            except Exception as exc:  # noqa: BLE001
                response = {"status": f"client error: {exc}"}
            with lock:
                results.append(response)

        threads = [threading.Thread(target=apply_once) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        self.assertEqual(len(results), 12)
        for response in results:
            self.assertEqual(response["status"], ops.STATUS_APPLIED)

        parsed = intent.parse(base_payload(), now=NOW)
        from ubuntuguard_agent.enforcer import derive

        body = [
            line.strip()
            for line in self.rules_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(body, derive.derive_rules(parsed, now=NOW))


class TestReferenceClient(ServiceFixture):
    """The client is the executable half of the wire spec, so it is tested
    against the real server rather than a stub."""

    def setUp(self):
        super().setUp()
        self.start_server()
        self.client = client.EnforcerClient(socket_path=self.socket_path, timeout=20)

    def test_capabilities_round_trip(self):
        response = self.client.capabilities()
        self.assertEqual(response["status"], ops.STATUS_OK)
        self.assertTrue(response["capabilities"]["supported"])

    def test_set_policy_round_trip(self):
        response = self.client.set_policy(base_payload(), policy_version=4)
        self.assertEqual(response["status"], ops.STATUS_APPLIED)
        self.assertEqual(response["policy_version"], 4)

    def test_get_state_round_trip(self):
        self.client.set_policy(base_payload())
        response = self.client.get_state()
        self.assertEqual(response["status"], ops.STATUS_OK)

    def test_rollback_round_trip(self):
        self.rules_path.write_text("allow id 1111:2222\n", encoding="utf-8")
        applied = self.client.set_policy(base_payload())
        response = self.client.rollback(applied["snapshot"]["snapshot_id"])
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)

    def test_invalid_policy_is_reported_with_problems(self):
        response = self.client.set_policy(base_payload(always_allow_classes=["hub"]))
        self.assertEqual(response["reason_code"], "enforcer_rejected")
        self.assertTrue(response["problems"])


class TestClientWithoutAServer(unittest.TestCase):
    """A missing enforcer must be reported, never mistaken for success.

    "No policy applied because nobody was listening" and "no policy applied
    because this host cannot enforce" are both failures, but only one of them
    describes a healthy machine, so they must not collapse into one outcome.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_absent_socket_reports_enforcer_unavailable(self):
        missing = str(Path(self.tmp.name) / "nope.sock")
        response = client.EnforcerClient(socket_path=missing).capabilities()
        self.assertEqual(response["status"], "failed")
        self.assertEqual(response["reason_code"], "enforcer_unavailable")

    def test_socket_with_nothing_listening_reports_unavailable(self):
        """A stale socket file left by a crashed enforcer."""
        path = str(Path(self.tmp.name) / "stale.sock")
        orphan = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        orphan.bind(path)
        orphan.close()

        response = client.EnforcerClient(socket_path=path).capabilities()
        self.assertEqual(response["reason_code"], "enforcer_unavailable")

    def test_apply_against_a_missing_enforcer_is_not_applied(self):
        missing = str(Path(self.tmp.name) / "nope.sock")
        response = client.EnforcerClient(socket_path=missing).set_policy(base_payload())
        self.assertNotEqual(response["status"], ops.STATUS_APPLIED)
        self.assertEqual(response["reason_code"], "enforcer_unavailable")


if __name__ == "__main__":
    unittest.main()
