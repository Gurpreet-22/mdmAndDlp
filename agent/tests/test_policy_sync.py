"""Tests for pulling, verifying and applying a signed policy.

No network and no root. The server is a fake that returns whatever envelope a
test hands it, and the enforcer is a fake that records what it was asked to do
-- except in `TestOverARealSocket`, which drives the real enforcer daemon over
a real Unix socket so the one boundary that cannot be faked usefully is
actually exercised.

The emphasis is on the refusals. Applying a good policy is the easy path and
one test covers it; the rest are the ways a bad one must not be applied, and
the ways a failure must not be recorded as success.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from enforcer_helpers import DAEMON_CONF, FakeHost
from ubuntuguard_agent import policy as agent_policy
from ubuntuguard_agent.core import envelope as envelope_mod
from ubuntuguard_agent.enforcer import ops, service, snapshots, system
from ubuntuguard_agent.errors import PolicyVerificationError, TransportError

UTC = dt.timezone.utc
ISSUED_AT = "2026-11-17T12:00:00Z"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def usb_payload(mode: str = "block_all_storage") -> dict[str, Any]:
    return {
        "schema": "ubuntuguard.usb_control.v1",
        "mode": mode,
        "protected_classes": ["mass_storage"],
        "always_allow_classes": ["hid", "hub"],
        "allowlist": [],
        "exceptions": [],
        "reporting": {
            "report_allowed": True,
            "report_blocked": True,
            "report_present_at_start": True,
        },
    }


class Signer:
    """Signs envelopes the way the server does, for tests to verify against."""

    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.key_id = envelope_mod.key_id_for(self.key.public_key())

    @property
    def trusted(self) -> dict[str, Any]:
        return {self.key_id: self.key.public_key()}

    def envelope(
        self,
        payload: dict[str, Any],
        *,
        version: int = 1,
        policy_id: str | None = None,
        policy_type: str = "usb_control",
        issued_at: str = ISSUED_AT,
    ) -> dict[str, Any]:
        policy_id = policy_id or str(uuid.uuid4())
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        signature = self.key.sign(
            envelope_mod.build_signing_input(
                policy_id=policy_id,
                policy_version=version,
                policy_type=policy_type,
                scope_kind="device",
                scope_id="device-1",
                issued_at=issued_at,
                expires_at=None,
                key_id=self.key_id,
                payload=body,
            )
        )
        return {
            "envelope_version": 1,
            "policy_id": policy_id,
            "policy_version": version,
            "policy_type": policy_type,
            "scope": {"kind": "device", "id": "device-1"},
            "issued_at": issued_at,
            "expires_at": None,
            "payload_b64": base64.b64encode(body).decode(),
            "payload_sha256": hashlib.sha256(body).hexdigest(),
            "signature": {
                "alg": "ed25519",
                "key_id": self.key_id,
                "value_b64": base64.b64encode(signature).decode(),
            },
        }


@pytest.fixture
def signer() -> Signer:
    return Signer()


class FakeResponse:
    def __init__(self, document: Any) -> None:
        self._document = document

    def json(self) -> Any:
        return self._document


class FakeServer:
    """Stands in for the control plane. Records what the agent reported."""

    def __init__(self, envelope: dict[str, Any] | None = None) -> None:
        self.envelope = envelope
        self.reports: list[dict[str, Any]] = []
        self.fetches: list[str] = []
        self.fail_fetch: Exception | None = None
        self.fail_report: Exception | None = None

    def get_json(self, path: str) -> FakeResponse:
        self.fetches.append(path)
        if self.fail_fetch is not None:
            raise self.fail_fetch
        return FakeResponse(self.envelope)

    def post_json(self, path: str, payload: dict[str, Any]) -> FakeResponse:
        if self.fail_report is not None:
            raise self.fail_report
        self.reports.append(payload)
        return FakeResponse(None)


class FakeEnforcer:
    """Stands in for the root daemon. Returns a canned response."""

    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response or {
            "status": "applied",
            "rules_applied": 3,
            "state": {
                "loaded_rules": ["block with-interface one-of { 08:*:* }"],
                "loaded_rule_count": 1,
                "daemon_active": True,
                "ipc_exposure": [],
                "enforcement_bypassable_without_root": False,
                "devices": [{"usb_id": "0781:5583", "serial": "SECRET-SERIAL"}],
            },
        }
        self.calls: list[dict[str, Any]] = []

    def set_policy(
        self, payload: dict[str, Any], *, policy_version: int | None = None
    ) -> dict[str, Any]:
        self.calls.append({"payload": payload, "policy_version": policy_version})
        return self.response


@pytest.fixture
def config(tmp_path: Path):
    """Same shape as `config_for` in test_heartbeat.py."""
    from ubuntuguard_agent.config import AgentConfig, AgentPaths, AgentSettings

    paths = AgentPaths(state_dir=tmp_path / "state", run_dir=tmp_path / "run")
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    return AgentConfig(
        server_url="https://server.invalid",
        server_ca_bundle=None,
        paths=paths,
        settings=AgentSettings(),
        release_build=True,
        config_path=None,
    )


# --------------------------------------------------------------------------- #
# Deciding whether to fetch at all
# --------------------------------------------------------------------------- #


class TestNeedsUpdate:
    """Re-applying on every heartbeat would restart usbguard once a minute."""

    def record(self, **over: Any) -> agent_policy.AppliedRecord:
        base = {
            "policy_id": "p1",
            "policy_version": 3,
            "status": "applied",
            "applied_at": "2026-11-17T12:00:00+00:00",
        }
        base.update(over)
        return agent_policy.AppliedRecord(**base)  # type: ignore[arg-type]

    def advertised(self, **over: Any) -> dict[str, Any]:
        base = {"policy_type": "usb_control", "policy_id": "p1", "policy_version": 3}
        base.update(over)
        return base

    def test_nothing_applied_yet_means_fetch(self) -> None:
        assert agent_policy.needs_update(self.advertised(), {})

    def test_same_version_already_applied_means_skip(self) -> None:
        applied = {"usb_control": self.record()}
        assert not agent_policy.needs_update(self.advertised(), applied)

    def test_a_newer_version_means_fetch(self) -> None:
        applied = {"usb_control": self.record()}
        assert agent_policy.needs_update(self.advertised(policy_version=4), applied)

    def test_a_different_id_at_the_same_version_means_fetch(self) -> None:
        """Version alone is not identity: two scopes number independently, so
        the same version can be a different policy."""
        applied = {"usb_control": self.record()}
        assert agent_policy.needs_update(self.advertised(policy_id="p2"), applied)

    def test_a_previous_failure_means_retry(self) -> None:
        applied = {"usb_control": self.record(status="failed")}
        assert agent_policy.needs_update(self.advertised(), applied)

    def test_unsupported_is_retried_too(self) -> None:
        """usbguard may have been installed since the last attempt."""
        applied = {"usb_control": self.record(status="unsupported")}
        assert agent_policy.needs_update(self.advertised(), applied)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


class TestVerifyAndParse:
    def test_a_good_envelope_yields_its_payload(self, signer: Signer) -> None:
        envelope = signer.envelope(usb_payload(), version=5)
        payload, version, policy_id = agent_policy.verify_and_parse(
            envelope, signer.trusted, applied=None
        )
        assert payload["mode"] == "block_all_storage"
        assert version == 5
        assert policy_id == envelope["policy_id"]

    def test_an_unknown_signing_key_is_refused(self, signer: Signer) -> None:
        """There is no fetch-on-demand for keys: fetching one to validate a
        document is how a signature check becomes decoration."""
        envelope = signer.envelope(usb_payload())
        with pytest.raises(PolicyVerificationError):
            agent_policy.verify_and_parse(envelope, {}, applied=None)

    def test_a_tampered_payload_is_refused(self, signer: Signer) -> None:
        envelope = signer.envelope(usb_payload())
        swapped = json.dumps(
            usb_payload("monitor_only"), separators=(",", ":"), sort_keys=True
        ).encode()
        envelope["payload_b64"] = base64.b64encode(swapped).decode()
        with pytest.raises(PolicyVerificationError):
            agent_policy.verify_and_parse(envelope, signer.trusted, applied=None)

    def test_a_forged_signature_is_refused(self, signer: Signer) -> None:
        other = Signer()
        envelope = signer.envelope(usb_payload())
        # Another key's signature, presented under the trusted key's id.
        envelope["signature"]["value_b64"] = other.envelope(usb_payload())["signature"]["value_b64"]
        with pytest.raises(PolicyVerificationError):
            agent_policy.verify_and_parse(envelope, signer.trusted, applied=None)

    def test_a_downgrade_is_refused(self, signer: Signer) -> None:
        """A signature does not expire, so an old signed response stays
        verifiable forever and could be replayed to reinstate a permissive
        policy that was legitimate last week."""
        applied = agent_policy.AppliedRecord(
            policy_id="p1", policy_version=9, status="applied", applied_at="x"
        )
        envelope = signer.envelope(usb_payload(), version=4)
        with pytest.raises(agent_policy.PolicySyncError) as caught:
            agent_policy.verify_and_parse(envelope, signer.trusted, applied=applied)
        assert "version 4" in str(caught.value)

    def test_the_same_version_is_allowed_through(self, signer: Signer) -> None:
        """Only a strictly lower version is a downgrade. Re-applying the same
        one is how a previously failed attempt retries."""
        applied = agent_policy.AppliedRecord(
            policy_id="p1", policy_version=4, status="failed", applied_at="x"
        )
        envelope = signer.envelope(usb_payload(), version=4)
        _, version, _ = agent_policy.verify_and_parse(envelope, signer.trusted, applied=applied)
        assert version == 4

    def test_a_payload_that_is_not_json_is_refused(self, signer: Signer) -> None:
        body = b"not json at all"
        signature = signer.key.sign(
            envelope_mod.build_signing_input(
                policy_id="p1",
                policy_version=1,
                policy_type="usb_control",
                scope_kind="device",
                scope_id="device-1",
                issued_at=ISSUED_AT,
                expires_at=None,
                key_id=signer.key_id,
                payload=body,
            )
        )
        envelope = {
            "envelope_version": 1,
            "policy_id": "p1",
            "policy_version": 1,
            "policy_type": "usb_control",
            "scope": {"kind": "device", "id": "device-1"},
            "issued_at": ISSUED_AT,
            "expires_at": None,
            "payload_b64": base64.b64encode(body).decode(),
            "payload_sha256": hashlib.sha256(body).hexdigest(),
            "signature": {
                "alg": "ed25519",
                "key_id": signer.key_id,
                "value_b64": base64.b64encode(signature).decode(),
            },
        }
        with pytest.raises(agent_policy.PolicySyncError):
            agent_policy.verify_and_parse(envelope, signer.trusted, applied=None)


# --------------------------------------------------------------------------- #
# Remembering what was applied
# --------------------------------------------------------------------------- #


class TestAppliedState:
    def test_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "applied.json"
        state = {
            "usb_control": agent_policy.AppliedRecord(
                policy_id="p1", policy_version=2, status="applied", applied_at="t"
            )
        }
        agent_policy.write_applied_state(path, state)
        assert agent_policy.read_applied_state(path) == state

    def test_a_missing_file_reads_as_nothing_applied(self, tmp_path: Path) -> None:
        """The cost is one idempotent re-apply; the alternative is an agent
        that refuses to work because of a bookkeeping file."""
        assert agent_policy.read_applied_state(tmp_path / "absent.json") == {}

    def test_corrupt_content_reads_as_nothing_applied(self, tmp_path: Path) -> None:
        path = tmp_path / "applied.json"
        path.write_text("{ not json", encoding="utf-8")
        assert agent_policy.read_applied_state(path) == {}

    def test_a_malformed_entry_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        path = tmp_path / "applied.json"
        path.write_text(
            json.dumps(
                {
                    "usb_control": {"policy_id": "p1", "policy_version": "not a number"},
                    "agent_settings": {
                        "policy_id": "p2",
                        "policy_version": 1,
                        "status": "applied",
                        "applied_at": "t",
                    },
                }
            ),
            encoding="utf-8",
        )
        state = agent_policy.read_applied_state(path)
        assert "usb_control" not in state
        assert "agent_settings" in state

    def test_the_file_is_not_world_readable(self, tmp_path: Path) -> None:
        import stat

        path = tmp_path / "applied.json"
        agent_policy.write_applied_state(path, {})
        mode = stat.S_IMODE(path.stat().st_mode)
        assert not mode & stat.S_IROTH


# --------------------------------------------------------------------------- #
# The readback that gets reported
# --------------------------------------------------------------------------- #


class TestTrimmedState:
    def test_the_evidence_is_kept(self) -> None:
        enforcer = FakeEnforcer()
        trimmed = agent_policy._trimmed_state(enforcer.response)
        assert trimmed is not None
        assert "loaded_rules" in trimmed
        assert trimmed["enforcement_bypassable_without_root"] is False

    def test_the_device_list_is_not_sent(self) -> None:
        """It changes whenever anything is plugged in, it already goes through
        the event channel, and it carries serials. Sending it here would put
        them in a second place for no gain."""
        trimmed = agent_policy._trimmed_state(FakeEnforcer().response)
        assert trimmed is not None
        assert "devices" not in trimmed
        assert "SECRET-SERIAL" not in json.dumps(trimmed)

    def test_a_response_with_no_state_trims_to_none(self) -> None:
        assert agent_policy._trimmed_state({"status": "failed"}) is None


# --------------------------------------------------------------------------- #
# The whole sync
# --------------------------------------------------------------------------- #


class TestSyncPolicies:
    def advertise(self, envelope: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {
                "policy_type": envelope["policy_type"],
                "policy_id": envelope["policy_id"],
                "policy_version": envelope["policy_version"],
            }
        ]

    def pin(self, config: Any, signer: Signer) -> None:
        from ubuntuguard_agent.enrollment import PolicyPublicKey, write_policy_keys

        public = signer.key.public_key().public_bytes_raw()
        write_policy_keys(
            config.paths.policy_keys_path,
            (
                PolicyPublicKey(
                    key_id=signer.key_id,
                    alg="ed25519",
                    public_key_b64=base64.b64encode(public).decode(),
                ),
            ),
        )

    def test_a_good_policy_is_applied_and_reported(self, config: Any, signer: Signer) -> None:
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), version=2)
        server = FakeServer(envelope)
        enforcer = FakeEnforcer()

        actions = agent_policy.sync_policies(
            config, server, self.advertise(envelope), enforcer=enforcer
        )

        assert actions == ["usb_control v2: applied"]
        assert len(enforcer.calls) == 1
        assert enforcer.calls[0]["policy_version"] == 2
        assert len(server.reports) == 1
        assert server.reports[0]["status"] == "applied"
        assert server.reports[0]["policy_id"] == envelope["policy_id"]

    def test_the_applied_version_is_recorded(self, config: Any, signer: Signer) -> None:
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), version=2)
        agent_policy.sync_policies(
            config,
            FakeServer(envelope),
            self.advertise(envelope),
            enforcer=FakeEnforcer(),
        )
        state = agent_policy.read_applied_state(agent_policy.applied_state_path(config))
        assert state["usb_control"].policy_version == 2
        assert state["usb_control"].status == "applied"

    def test_a_second_sync_does_nothing(self, config: Any, signer: Signer) -> None:
        """Otherwise usbguard would be restarted once a minute, forever."""
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), version=2)
        enforcer = FakeEnforcer()
        advertised = self.advertise(envelope)

        agent_policy.sync_policies(config, FakeServer(envelope), advertised, enforcer=enforcer)
        actions = agent_policy.sync_policies(
            config, FakeServer(envelope), advertised, enforcer=enforcer
        )

        assert actions == []
        assert len(enforcer.calls) == 1

    def test_a_failure_is_recorded_as_a_failure(self, config: Any, signer: Signer) -> None:
        """Recording `applied` optimistically would leave a failed host
        believing it was current, and it would never retry."""
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), version=1)
        enforcer = FakeEnforcer(
            {
                "status": "failed",
                "reason_code": "enforce_failed",
                "message": "usbguard would not restart",
            }
        )
        actions = agent_policy.sync_policies(
            config, FakeServer(envelope), self.advertise(envelope), enforcer=enforcer
        )
        assert actions == ["usb_control v1: failed"]
        state = agent_policy.read_applied_state(agent_policy.applied_state_path(config))
        assert state["usb_control"].status == "failed"

    def test_a_failure_is_retried_on_the_next_sync(self, config: Any, signer: Signer) -> None:
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), version=1)
        advertised = self.advertise(envelope)
        failing = FakeEnforcer({"status": "failed", "reason_code": "enforce_failed"})
        agent_policy.sync_policies(config, FakeServer(envelope), advertised, enforcer=failing)

        recovered = FakeEnforcer()
        actions = agent_policy.sync_policies(
            config, FakeServer(envelope), advertised, enforcer=recovered
        )
        assert actions == ["usb_control v1: applied"]
        assert len(recovered.calls) == 1

    def test_unsupported_is_reported_not_swallowed(self, config: Any, signer: Signer) -> None:
        """A laptop with no usbguard must show as unsupported, not as green."""
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), version=1)
        server = FakeServer(envelope)
        enforcer = FakeEnforcer(
            {
                "status": "unsupported",
                "reason_code": "capability_missing",
                "message": "usbguard is not installed on this host",
            }
        )
        agent_policy.sync_policies(config, server, self.advertise(envelope), enforcer=enforcer)
        assert server.reports[0]["status"] == "unsupported"
        assert server.reports[0]["reason_code"] == "capability_missing"

    def test_a_refused_policy_is_never_handed_to_the_enforcer(
        self, config: Any, signer: Signer
    ) -> None:
        """Verification failure must stop before anything privileged happens."""
        self.pin(config, signer)
        rogue = Signer()
        envelope = rogue.envelope(usb_payload(), version=1)
        enforcer = FakeEnforcer()

        actions = agent_policy.sync_policies(
            config, FakeServer(envelope), self.advertise(envelope), enforcer=enforcer
        )

        assert enforcer.calls == []
        assert len(actions) == 1
        assert "refused" in actions[0]

    def test_a_fetch_failure_does_not_raise(self, config: Any, signer: Signer) -> None:
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload())
        server = FakeServer(envelope)
        server.fail_fetch = TransportError("the network is down")
        enforcer = FakeEnforcer()

        actions = agent_policy.sync_policies(
            config, server, self.advertise(envelope), enforcer=enforcer
        )
        assert enforcer.calls == []
        assert "refused" in actions[0]

    def test_a_report_failure_does_not_undo_the_apply(self, config: Any, signer: Signer) -> None:
        """A laptop that cannot reach the server still enforces. Treating a
        failed report as a failed apply would let a network problem disable
        enforcement."""
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), version=1)
        server = FakeServer(envelope)
        server.fail_report = TransportError("the network is down")
        enforcer = FakeEnforcer()

        actions = agent_policy.sync_policies(
            config, server, self.advertise(envelope), enforcer=enforcer
        )

        assert actions == ["usb_control v1: applied"]
        assert len(enforcer.calls) == 1
        state = agent_policy.read_applied_state(agent_policy.applied_state_path(config))
        assert state["usb_control"].status == "applied"

    def test_missing_pinned_keys_refuses_everything(self, config: Any, signer: Signer) -> None:
        """No keys means no policy can be trusted, and that is reported rather
        than treated as nothing to do."""
        envelope = signer.envelope(usb_payload())
        enforcer = FakeEnforcer()
        actions = agent_policy.sync_policies(
            config, FakeServer(envelope), self.advertise(envelope), enforcer=enforcer
        )
        assert enforcer.calls == []
        assert "policy keys unavailable" in actions[0]

    def test_an_unknown_policy_type_is_skipped(self, config: Any, signer: Signer) -> None:
        self.pin(config, signer)
        envelope = signer.envelope(usb_payload(), policy_type="agent_settings")
        enforcer = FakeEnforcer()
        actions = agent_policy.sync_policies(
            config, FakeServer(envelope), self.advertise(envelope), enforcer=enforcer
        )
        assert enforcer.calls == []
        assert actions == []

    def test_nothing_advertised_is_a_no_op(self, config: Any) -> None:
        enforcer = FakeEnforcer()
        assert agent_policy.sync_policies(config, FakeServer(), [], enforcer=enforcer) == []
        assert enforcer.calls == []


# --------------------------------------------------------------------------- #
# Over the real socket
# --------------------------------------------------------------------------- #


class TestOverARealSocket:
    """The privilege boundary, with a real daemon and a real socket.

    The fake enforcer above proves the agent's logic. This proves the two
    halves actually speak to each other, which is the part a fake cannot tell
    you anything about. usbguard itself is still faked, because a test suite
    must not restart the daemon on the developer's machine.
    """

    def test_a_policy_crosses_the_socket_and_lands_on_disk(
        self, config: Any, signer: Signer, tmp_path: Path
    ) -> None:
        etc = tmp_path / "etc"
        etc.mkdir()
        rules = etc / "rules.conf"
        conf = etc / "usbguard-daemon.conf"
        conf.write_text(DAEMON_CONF, encoding="utf-8")
        host = FakeHost(str(rules))

        socket_path = str(tmp_path / "enforcer.sock")
        server = service.EnforcerServer(
            enforcer=ops.Enforcer(
                system=system.UsbGuardSystem(
                    rules_path=str(rules),
                    daemon_conf_path=str(conf),
                    runner=host.runner,
                    which=host.which,
                ),
                store=snapshots.SnapshotStore(directory=str(tmp_path / "snaps")),
            ),
            socket_path=socket_path,
            allow_any_peer=True,
        )
        server.bind()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            from ubuntuguard_agent.enforcer.client import EnforcerClient

            envelope = signer.envelope(usb_payload(), version=3)
            payload, version, _ = agent_policy.verify_and_parse(
                envelope, signer.trusted, applied=None
            )
            response = agent_policy.apply_usb_control(
                EnforcerClient(socket_path=socket_path, timeout=20),
                payload,
                policy_version=version,
            )
        finally:
            server.close()
            thread.join(timeout=5)

        assert response["status"] == "applied"
        body = [
            line.strip()
            for line in rules.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert "block with-interface one-of { 08:*:* }" in body

    def test_a_missing_enforcer_reports_unavailable(self, tmp_path: Path) -> None:
        """Distinct from `unsupported`. Both mean no policy was applied, but
        only one of them describes a healthy machine."""
        from ubuntuguard_agent.enforcer.client import EnforcerClient

        response = agent_policy.apply_usb_control(
            EnforcerClient(socket_path=str(tmp_path / "absent.sock"), timeout=5),
            usb_payload(),
            policy_version=1,
        )
        assert response["status"] == "failed"
        assert response["reason_code"] == "enforcer_unavailable"
