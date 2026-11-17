"""Reference client for the enforcerd socket.

Written for two audiences. It is what the unprivileged agent uses to reach
enforcerd, and it is the executable specification of the wire protocol -- the
half of the integration that has to agree between two codebases. Anyone
reimplementing this side can read it instead of inferring the framing from the
server.

Nothing here is privileged. The client runs as the agent user and can do no
more than ask; every decision is made on the other side of the socket.

Errors are returned as response dicts rather than raised, using the reason
codes UbuntuGuard's apply sequence already defines, so a caller can report
them without translating:

  `enforcer_unavailable`  the socket is missing, or refused the connection
  `enforcer_rejected`     enforcerd refused the request
  `enforcer_timeout`      no reply within the deadline

A connection refused because enforcerd is not running is reported, never
inferred as success. That matters: `capability_missing` and "nobody was
listening" both mean no policy was applied, but only one of them is a healthy
machine.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any

from .service import (
    DEFAULT_SOCKET_PATH,
    MAX_REQUEST_BYTES,
    encode_response,
    read_request_line,
)

#: Long enough for an apply, which restarts the usbguard daemon and then reads
#: the device list back. Short enough that agentd's check-in is not held up
#: indefinitely by an enforcer that has wedged.
DEFAULT_TIMEOUT_SECONDS = 60


@dataclass
class EnforcerClient:
    socket_path: str = DEFAULT_SOCKET_PATH
    timeout: float = DEFAULT_TIMEOUT_SECONDS

    def call(self, op: str, payload: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
        """Send one request and return the response.

        A fresh connection per request. enforcerd handles connections
        sequentially, so holding one open would block every other caller, and
        there is no session state to preserve between operations.
        """
        request: dict[str, Any] = {"op": op}
        if payload is not None:
            request["payload"] = payload
        request.update(extra)

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self.timeout)
                conn.connect(self.socket_path)
                conn.sendall(encode_response(request))
                line = read_request_line(conn, max_bytes=MAX_REQUEST_BYTES)
        except TimeoutError:
            return self._error(
                "enforcer_timeout",
                f"no reply from enforcerd within {self.timeout:g}s",
            )
        except FileNotFoundError:
            return self._error(
                "enforcer_unavailable",
                f"no enforcer socket at {self.socket_path}; is ubuntuguard-enforcerd running?",
            )
        except PermissionError:
            return self._error(
                "enforcer_unavailable",
                f"not permitted to connect to {self.socket_path}; the agent "
                f"user must be in the socket's group",
            )
        except (ConnectionError, OSError) as exc:
            return self._error("enforcer_unavailable", f"cannot reach enforcerd: {exc}")
        except ValueError as exc:
            return self._error("enforcer_unavailable", f"malformed reply: {exc}")

        if line is None:
            # Most likely the peer check refused us and closed, or enforcerd
            # died mid-request. Either way no policy was applied.
            return self._error(
                "enforcer_unavailable",
                "enforcerd closed the connection without replying",
            )

        try:
            response = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self._error("enforcer_unavailable", f"reply was not valid JSON: {exc}")
        if not isinstance(response, dict):
            return self._error("enforcer_unavailable", "reply was not an object")
        return response

    @staticmethod
    def _error(reason_code: str, message: str) -> dict[str, Any]:
        return {
            "status": "failed",
            "reason_code": reason_code,
            "message": message,
        }

    # -- the operation set -------------------------------------------------

    def capabilities(self) -> dict[str, Any]:
        from . import ops

        return self.call(ops.OP_CAPABILITIES)

    def get_state(self) -> dict[str, Any]:
        from . import ops

        return self.call(ops.OP_USB_GET_STATE)

    def set_policy(
        self, policy: dict[str, Any], *, policy_version: int | None = None
    ) -> dict[str, Any]:
        from . import ops

        extra = {} if policy_version is None else {"policy_version": policy_version}
        return self.call(ops.OP_USB_SET_POLICY, {"policy": policy}, **extra)

    def rollback(self, snapshot_id: str) -> dict[str, Any]:
        from . import ops

        return self.call(ops.OP_USB_ROLLBACK, {"snapshot_id": snapshot_id})
