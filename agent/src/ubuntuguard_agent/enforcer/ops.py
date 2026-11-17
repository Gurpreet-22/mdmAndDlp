"""The closed operation set enforcerd will execute.

This layer is deliberately transport-free: a request is a dict[str, Any], a response is
a dict, and nothing here knows about sockets, framing or peer credentials.
Two reasons. It makes the privileged logic testable without root or a running
daemon, and it confines the one part of the integration still awaiting
agreement -- the wire framing -- to a separate module, so settling that
question cannot disturb anything below.

The operation set is fixed and closed, per UbuntuGuard's design: four ops, no
op accepting a path, command, shell string or raw USBGuard rule. An
unrecognised op is refused rather than ignored.

`OP_USB_SET_POLICY` implements the documented apply sequence, and step 7 is
the one that matters most:

    snapshot -> apply -> read the state back from the OS -> commit

Exit code 0 is not evidence that a policy took effect. `systemctl restart`
succeeds when the daemon starts, which it will do happily with rules that
authorise nothing we asked for. So the applied rules are compared against the
derived rules as read back out of the daemon, and a mismatch triggers rollback
even though every command reported success.

That comparison is exact string equality, which is only sound because the
conformance tests establish that USBGuard's canonical form of every rule we
derive is byte-identical to what we wrote. Were the daemon reformatting rules,
this check would fail on correct policies.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import derive, snapshots
from .intent import IntentError, parse
from .system import HostError, UsbGuardSystem, UsbState

OP_CAPABILITIES = "OP_CAPABILITIES"
OP_USB_GET_STATE = "OP_USB_GET_STATE"
OP_USB_SET_POLICY = "OP_USB_SET_POLICY"
OP_USB_ROLLBACK = "OP_USB_ROLLBACK"

#: The complete operation set. Anything else is an error.
OPERATIONS = (
    OP_CAPABILITIES,
    OP_USB_GET_STATE,
    OP_USB_SET_POLICY,
    OP_USB_ROLLBACK,
)

STATUS_OK = "ok"
STATUS_APPLIED = "applied"
STATUS_FAILED = "failed"
STATUS_UNSUPPORTED = "unsupported"
STATUS_ROLLED_BACK = "rolled_back"

#: Fields a request may carry. Mirrors the payload-level allowlisting in
#: `intent`: a request growing a `rules_path` or `command` field is refused,
#: not quietly dropped.
_REQUEST_FIELDS = frozenset({"op", "payload", "policy_version", "request_id"})
_SET_POLICY_FIELDS = frozenset({"policy"})
_ROLLBACK_FIELDS = frozenset({"snapshot_id"})


class OpError(Exception):
    """A request cannot be executed. Carries a reason code for reporting."""

    def __init__(
        self, reason_code: str, message: str, *, problems: list[str] | None = None
    ) -> None:
        self.reason_code = reason_code
        self.problems = problems or []
        super().__init__(message)


def _reject_unknown(obj: dict[str, Any], known: frozenset[str], where: str) -> None:
    unknown = set(obj) - known
    if unknown:
        raise OpError(
            "enforcer_rejected",
            f"{where}: unknown field(s) {', '.join(sorted(unknown))}; the "
            f"operation set is closed and accepts no paths, commands or rule "
            f"text",
        )


@dataclass
class Enforcer:
    """Executes the operation set against a host."""

    system: UsbGuardSystem = field(default_factory=UsbGuardSystem)
    store: snapshots.SnapshotStore = field(default_factory=snapshots.SnapshotStore)
    #: Injected so tests are deterministic and so an audit record of a
    #: rejected op can be asserted on.
    clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc)
    allow_hid_on_authorised: bool = False

    # -- dispatch ----------------------------------------------------------

    def handle(self, request: Any) -> dict[str, Any]:
        """Execute one request, returning a response dict.

        Never raises for a bad request: a rejection is a response, because the
        caller needs the reason code in order to report it. Only a programming
        error should propagate.
        """
        try:
            return self._dispatch(request)
        except OpError as exc:
            return self._failure(exc.reason_code, str(exc), problems=exc.problems)
        except (HostError, snapshots.SnapshotError) as exc:
            return self._failure(exc.reason_code, str(exc))

    def _dispatch(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise OpError("enforcer_rejected", "request must be a JSON object")

        op = request.get("op")
        if op not in OPERATIONS:
            # Logged with the opcode only. The payload is never included:
            # UbuntuGuard's design says rejections record the op and not the
            # contents, and a rejected payload is exactly the thing most
            # likely to be hostile.
            raise OpError(
                "enforcer_rejected",
                f"unknown operation {op!r}; known operations are {', '.join(OPERATIONS)}",
            )

        _reject_unknown(request, _REQUEST_FIELDS, "request")
        payload = request.get("payload") or {}
        if not isinstance(payload, dict):
            raise OpError("enforcer_rejected", "'payload' must be an object")

        if op == OP_CAPABILITIES:
            return self.capabilities()
        if op == OP_USB_GET_STATE:
            return self.get_state()
        if op == OP_USB_SET_POLICY:
            _reject_unknown(payload, _SET_POLICY_FIELDS, "payload")
            return self.set_policy(
                payload.get("policy"),
                policy_version=request.get("policy_version"),
            )
        if op == OP_USB_ROLLBACK:
            _reject_unknown(payload, _ROLLBACK_FIELDS, "payload")
            return self.rollback(payload.get("snapshot_id"))

        raise AssertionError(f"unreachable: {op}")  # pragma: no cover

    # -- responses ---------------------------------------------------------

    def _envelope(self, status: str, **extra: Any) -> dict[str, Any]:
        response = {
            "status": status,
            "at": self.clock().replace(microsecond=0).isoformat(),
        }
        response.update(extra)
        return response

    def _failure(
        self, reason_code: str, message: str, *, problems: list[str] | None = None
    ) -> dict[str, Any]:
        response = self._envelope(STATUS_FAILED, reason_code=reason_code, message=message)
        if problems:
            response["problems"] = problems
        return response

    # -- OP_CAPABILITIES ---------------------------------------------------

    def capabilities(self) -> dict[str, Any]:
        caps = self.system.capabilities()
        return self._envelope(
            STATUS_OK,
            capabilities=caps.as_dict(),
            snapshots=len(self.store.ids()),
        )

    # -- OP_USB_GET_STATE --------------------------------------------------

    def get_state(self) -> dict[str, Any]:
        caps = self.system.capabilities()
        if not caps.usbguard_present:
            # Reporting `unsupported` rather than an empty state: a dashboard
            # must not read "no rules loaded" as "policy applied, nothing
            # matched".
            return self._envelope(
                STATUS_UNSUPPORTED,
                reason_code="capability_missing",
                message="usbguard is not installed on this host",
                capabilities=caps.as_dict(),
            )

        state = self.system.state()
        return self._envelope(
            STATUS_OK,
            state=state.as_dict(),
            fingerprint_self_consistent=derive.verify_fingerprint(state.rules_text),
            snapshots=self.store.summaries(),
        )

    # -- OP_USB_SET_POLICY -------------------------------------------------

    def set_policy(self, policy: Any, *, policy_version: Any = None) -> dict[str, Any]:
        if not isinstance(policy, dict):
            raise OpError("enforcer_rejected", "payload.policy must be a usb_control object")
        if policy_version is not None and not isinstance(policy_version, int):
            raise OpError("enforcer_rejected", "'policy_version' must be an integer")

        now = self.clock()

        # [1-4] Validate before anything privileged happens. enforcerd
        # re-validates the whole request itself rather than trusting that
        # agentd did -- agentd is unprivileged and in the threat model's
        # compromisable set.
        try:
            intent = parse(policy, now=now)
        except IntentError as exc:
            raise OpError(
                "enforcer_rejected",
                "usb_control payload rejected by enforcerd",
                problems=exc.problems,
            ) from exc

        # A host that cannot enforce is a reportable outcome, not a failure.
        caps = self.system.capabilities()
        if not caps.supported:
            return self._envelope(
                STATUS_UNSUPPORTED,
                reason_code="capability_missing",
                message="host cannot enforce usb_control policy; missing: "
                + ", ".join(caps.missing),
                capabilities=caps.as_dict(),
            )

        expected = derive.derive_rules(
            intent,
            now=now,
            allow_hid_on_authorised=self.allow_hid_on_authorised,
        )
        policy_text = derive.render_policy(
            intent,
            now=now,
            policy_version=policy_version,
            allow_hid_on_authorised=self.allow_hid_on_authorised,
        )

        # [5] Snapshot the real current state, before touching anything.
        before = self.system.state()
        snapshot = self.store.take(
            rules_text=before.rules_text,
            daemon_params=before.daemon_params,
            rules_fingerprint=before.rules_fingerprint,
            note=f"before policy_version={policy_version}",
            now=now,
        )

        # [6] Apply, then [7] verify. Any failure in either rolls back.
        try:
            self.system.write_rules(policy_text)
            self.system.validate_rules_file()
            self.system.reload_daemon()
            after = self.system.state()
            foreign = self._verify(expected, after)
        except (HostError, OpError) as exc:
            reason = getattr(exc, "reason_code", "enforce_failed")
            return self._rollback_after_failure(snapshot, reason, str(exc))

        # [8] Commit.
        return self._envelope(
            STATUS_APPLIED,
            policy_version=policy_version,
            mode=intent.mode,
            rules_applied=len(expected),
            rules_fingerprint=derive.compute_fingerprint(expected),
            snapshot=snapshot.summary(),
            state=after.as_dict(),
            note=derive.TRAILING_ALLOW_NOTE,
            # Reported rather than hidden: these are rules another component
            # added, inert where they sit but worth an operator seeing. On an
            # Ubuntu desktop this is normally GNOME's one allow-everything
            # rule.
            foreign_rules=foreign,
            # A correct policy on a host where the restricted user can delete
            # it is not enforcement. Surfaced on the apply response, not only
            # in get-state, so it cannot be missed by a caller that applies
            # and never reads back.
            ipc_exposure=list(after.ipc_exposure),
        )

    def _verify(self, expected: list[str], observed: UsbState) -> list[str]:
        """Compare intent against what the OS reports, not against exit codes.

        Checks the rules the *daemon* has loaded, not the file just written.
        Comparing the file against itself would pass even when the daemon
        failed to load it, which is the likeliest way for an apply to look
        successful and change nothing.

        The loaded set is not required to equal the policy, because on a real
        desktop it never does. GNOME's `gsd-usb-protection` appends

            allow id *:* label "GNOME_SETTINGS_DAEMON_RULE"

        over USBGuard's D-Bus interface, and re-adds it after a daemon
        restart. Demanding exact equality would report drift and roll back on
        every single apply on an Ubuntu desktop -- and do it intermittently,
        depending on whether GNOME had got there yet.

        What actually has to hold is an *ordering* property. USBGuard is
        first-match-wins, so the policy means what it says as long as its
        rules are loaded consecutively and in order, with nothing spliced in
        front of them. A foreign rule after the policy is inert: the policy
        ends with a catch-all for everything outside the protected classes and
        blocks everything inside them, so no device reaches a later rule.
        GNOME's rule is allow-everything, which would nullify the policy
        entirely if it came first -- hence the position check rather than
        merely tolerating the extra rule.

        Returns the foreign rules, for reporting.
        """
        loaded = list(observed.loaded_rules)
        if not loaded:
            raise OpError(
                "verify_failed",
                "daemon reports no loaded rules after apply; the policy was "
                "written but is not in effect",
            )

        width = len(expected)
        at = next(
            (
                index
                for index in range(len(loaded) - width + 1)
                if loaded[index : index + width] == expected
            ),
            None,
        )

        if at is None:
            missing = [rule for rule in expected if rule not in loaded]
            detail = (
                f"{len(missing)} expected rule(s) not loaded"
                if missing
                else "the policy's rules are loaded but reordered or split up"
            )
            raise OpError(
                "verify_drift",
                f"state read back from usbguard does not match the policy: {detail}",
            )

        preceding = loaded[:at]
        if preceding:
            # First-match-wins means anything here decides before the policy
            # does, so it can silently override it.
            raise OpError(
                "verify_drift",
                f"{len(preceding)} rule(s) are evaluated before the policy "
                f"and can override it, starting with: {preceding[0][:120]!r}",
            )

        return loaded[at + width :]

    # -- OP_USB_ROLLBACK ---------------------------------------------------

    def rollback(self, snapshot_id: Any) -> dict[str, Any]:
        if not isinstance(snapshot_id, str):
            raise OpError("enforcer_rejected", "'snapshot_id' must be a string")

        # Raises on a malformed or absent id. The rules come from the store,
        # never from the request.
        snapshot = self.store.load(snapshot_id)

        caps = self.system.capabilities()
        if not caps.supported:
            return self._envelope(
                STATUS_UNSUPPORTED,
                reason_code="capability_missing",
                message="host cannot enforce usb_control policy; missing: "
                + ", ".join(caps.missing),
                capabilities=caps.as_dict(),
            )

        self._restore(snapshot)
        after = self.system.state()
        return self._envelope(
            STATUS_ROLLED_BACK,
            reason_code="operator_requested",
            snapshot=snapshot.summary(),
            state=after.as_dict(),
        )

    def _restore(self, snapshot: snapshots.Snapshot) -> None:
        """Reinstall a snapshot's rules and reload.

        An empty rules body is restored as an empty file rather than skipped:
        "there was no policy here before" is a real previous state, and the
        rollback target for the very first apply on a host.
        """
        self.system.write_rules(snapshot.rules_text)
        self.system.reload_daemon()

    def _rollback_after_failure(
        self, snapshot: snapshots.Snapshot, reason_code: str, message: str
    ) -> dict[str, Any]:
        """Undo a failed apply, then verify the undo.

        If the rollback itself cannot be verified the response is `failed`
        with `rollback_failed`, which UbuntuGuard's design treats as an
        incident rather than something to retry quietly -- correctly, because
        the host is now in a state no one chose.
        """
        try:
            self._restore(snapshot)
            restored = self.system.state()
            if restored.rules_text != snapshot.rules_text:
                raise HostError(
                    "rollback_failed",
                    "rules file does not match the snapshot after restore",
                )
        except (HostError, snapshots.SnapshotError) as exc:
            return self._envelope(
                STATUS_FAILED,
                reason_code="rollback_failed",
                message=(
                    f"apply failed ({reason_code}: {message}) and rollback "
                    f"could not be verified: {exc}"
                ),
                snapshot=snapshot.summary(),
                incident=True,
            )

        return self._envelope(
            STATUS_ROLLED_BACK,
            reason_code=reason_code,
            message=message,
            snapshot=snapshot.summary(),
            state=restored.as_dict(),
        )
