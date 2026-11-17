"""Tests for the enforcerd USB policy derivation.

The contract tests in `TestAgainstUbuntuGuardFixtures` run against the
`usb_control` example payloads taken verbatim from the UbuntuGuard repository
(`schemas/examples/`), copied into `tests/contract/`. Those are the authored
contract: if a change here stops accepting her valid examples or starts
accepting an invalid one, the integration is broken regardless of what the
rest of this suite says.
"""

from __future__ import annotations

import datetime as dt
import json
import unittest
from pathlib import Path

import enforcer_helpers as helpers
from enforcer_helpers import load_example, usb_control_examples
from ubuntuguard_agent.enforcer import classes, derive, intent

NOW = dt.datetime(2026, 10, 29, 10, 0, 0, tzinfo=dt.timezone.utc)


def load(category: str, name: str) -> dict:
    """Her authored example, from the live schemas dir when available."""
    return load_example(category, name)


def base_payload(**overrides) -> dict:
    payload = {
        "schema": intent.SCHEMA_ID,
        "mode": intent.MODE_ALLOWLIST,
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
    payload.update(overrides)
    return payload


def allowlist_entry(**overrides) -> dict:
    entry = {
        "entry_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "match": {
            "vendor_id": "0781",
            "product_id": "5583",
            "serial": "4C530001120523117082",
            "serial_match": "exact",
        },
        "label": "Finance SanDisk",
        "added_by": "it-admin",
        "added_at": "2026-10-20T09:15:00Z",
    }
    entry.update(overrides)
    return entry


def exception_entry(**overrides) -> dict:
    entry = {
        "exception_id": "b1e4f0a2-7d3c-4e51-9f68-2a0c7d9e4b11",
        "match": {
            "vendor_id": "0951",
            "product_id": "1666",
            "serial": None,
            "serial_match": "any",
        },
        "reason": "Vendor on site delivering signed firmware, ticket SEC-4821",
        "created_by": "security-analyst",
        "created_at": "2026-10-29T08:00:00Z",
        "expires_at": "2026-10-29T16:00:00Z",
    }
    entry.update(overrides)
    return entry


def rules_of(policy_text: str) -> list[str]:
    return [
        ln.strip()
        for ln in policy_text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


# ---------------------------------------------------------------------------
# contract: her fixtures
# ---------------------------------------------------------------------------


class TestBundledExamplesMatchTheAuthoredOnes(unittest.TestCase):
    """The bundled copy must not drift from `schemas/examples/`.

    `enforcer_contract/` carries byte-identical copies so the enforcer suite
    still runs when developed outside this repository. Inside it, that copy is
    a duplicate of the authored examples, and a duplicate nobody compares is a
    duplicate that will eventually disagree -- at which point the contract
    tests would be certifying against a stale snapshot while reporting success.
    """

    def test_every_bundled_example_matches_the_authored_one(self):
        bundled_root = Path(__file__).parent / "enforcer_contract"
        if not helpers.contract_is_live():
            self.skipTest("authored examples not present; nothing to compare")

        bundled = sorted(bundled_root.rglob("*.json"))
        self.assertGreater(len(bundled), 0, "no bundled examples found")

        for copy in bundled:
            relative = copy.relative_to(bundled_root)
            authored = helpers.contract_root() / relative
            with self.subTest(example=str(relative)):
                self.assertTrue(
                    authored.is_file(),
                    f"bundled {relative} has no counterpart in "
                    f"schemas/examples; it was renamed or removed upstream",
                )
                self.assertEqual(
                    copy.read_bytes(),
                    authored.read_bytes(),
                    f"bundled copy of {relative} has drifted from the authored example",
                )


class TestAgainstUbuntuGuardFixtures(unittest.TestCase):
    """The integration contract, verified against the authored examples."""

    def test_her_allowlist_example_is_accepted(self):
        parsed = intent.parse(load("valid", "policy.usb_control.allowlist.json"), now=NOW)
        self.assertEqual(parsed.mode, intent.MODE_ALLOWLIST)
        self.assertEqual(parsed.protected_classes, ("mass_storage",))
        self.assertIn("hid", parsed.always_allow_classes)
        self.assertEqual(len(parsed.allowlist), 1)
        self.assertEqual(parsed.allowlist[0].match.usb_id, "0781:5583")
        self.assertTrue(parsed.allowlist[0].match.is_exact)

    def test_her_block_all_example_is_accepted(self):
        parsed = intent.parse(load("valid", "policy.usb_control.block_all_storage.json"), now=NOW)
        self.assertEqual(parsed.mode, intent.MODE_BLOCK_ALL)
        self.assertEqual(len(parsed.exceptions), 1)
        self.assertFalse(parsed.exceptions[0].match.is_exact)

    def test_her_allowlist_example_derives_usable_rules(self):
        parsed = intent.parse(load("valid", "policy.usb_control.allowlist.json"), now=NOW)
        rules = derive.derive_rules(parsed, now=NOW)
        self.assertIn(
            'allow id 0781:5583 serial "4C530001120523117082" with-interface none-of { 03:*:* }',
            rules,
        )
        self.assertIn("block with-interface one-of { 08:*:* }", rules)

    def test_her_block_all_example_ignores_allowlist_but_honours_exception(self):
        payload = load("valid", "policy.usb_control.block_all_storage.json")
        payload["allowlist"] = [allowlist_entry()]
        parsed = intent.parse(payload, now=NOW)
        rules = derive.derive_rules(parsed, now=NOW)
        joined = "\n".join(rules)
        self.assertNotIn("0781:5583", joined, "allowlist honoured in block_all mode")
        self.assertIn("0951:1666", joined, "unexpired exception was dropped")

    # -- the invalid fixtures ---------------------------------------------

    def test_missing_hid_is_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(load("invalid", "usb_control.always_allow_missing_hid.json"), now=NOW)
        self.assertIn("hid", str(ctx.exception))
        self.assertIn("lock the user out", str(ctx.exception))

    def test_command_injection_attempt_is_rejected(self):
        """Her fixture plants raw_usbguard_rule, post_apply_command, rules_path."""
        payload = load("invalid", "usb_control.command_injection_attempt.json")
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(payload, now=NOW)
        message = str(ctx.exception)
        for smuggled in ("raw_usbguard_rule", "post_apply_command", "rules_path"):
            self.assertIn(smuggled, message, f"{smuggled} not named in rejection")

    def test_exact_serial_without_serial_is_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(load("invalid", "usb_control.exact_serial_without_serial.json"), now=NOW)
        self.assertIn("requires a serial", str(ctx.exception))

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(load("invalid", "usb_control.unknown_mode.json"), now=NOW)
        self.assertIn("mode", str(ctx.exception))

    def test_short_exception_reason_is_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(load("invalid", "usb_control.exception_reason_too_short.json"), now=NOW)
        self.assertIn("reason", str(ctx.exception))

    def test_every_invalid_fixture_is_rejected(self):
        """Guards against a fixture being added that we silently accept."""
        fixtures = usb_control_examples("invalid")
        # Without this, a wrong examples path would make the whole test pass
        # by iterating nothing.
        self.assertGreater(len(fixtures), 0, "no invalid fixtures found")
        for path in fixtures:
            with self.subTest(fixture=path.name), self.assertRaises(intent.IntentError):
                intent.parse(json.loads(path.read_text()), now=NOW)

    def test_every_valid_fixture_is_accepted(self):
        fixtures = usb_control_examples("valid")
        self.assertGreater(len(fixtures), 0, "no valid fixtures found")
        for path in fixtures:
            with self.subTest(fixture=path.name):
                intent.parse(json.loads(path.read_text()), now=NOW)


# ---------------------------------------------------------------------------
# class vocabulary
# ---------------------------------------------------------------------------


class TestClasses(unittest.TestCase):
    def test_mass_storage_is_class_08(self):
        self.assertEqual(classes.protected_codes(["mass_storage"]), ("08",))

    def test_image_is_class_06_the_phone_case(self):
        self.assertEqual(classes.protected_codes(["image"]), ("06",))

    def test_both_protected_classes_together(self):
        self.assertEqual(classes.protected_codes(["mass_storage", "image"]), ("08", "06"))

    def test_hid_and_hub_codes(self):
        self.assertEqual(classes.always_allow_codes(["hid"]), ("03",))
        self.assertEqual(classes.always_allow_codes(["hub"]), ("09",))

    def test_cdc_and_network_both_cover_the_cdc_pair(self):
        self.assertEqual(classes.always_allow_codes(["cdc"]), ("02", "0a"))
        self.assertEqual(classes.always_allow_codes(["network"]), ("02", "0a"))

    def test_duplicate_codes_are_collapsed(self):
        self.assertEqual(classes.always_allow_codes(["cdc", "network"]), ("02", "0a"))

    def test_unknown_class_name_raises_rather_than_guessing(self):
        with self.assertRaises(KeyError):
            classes.protected_codes(["mass_storge"])
        with self.assertRaises(KeyError):
            classes.always_allow_codes(["keyboard"])

    def test_dock_classes_are_expressible(self):
        """USB-C docks need billboard, network, audio, video."""
        codes = classes.always_allow_codes(["hid", "hub", "billboard", "network", "audio", "video"])
        for expected in ("03", "09", "11", "02", "01", "0e"):
            self.assertIn(expected, codes)

    def test_selector_format(self):
        self.assertEqual(classes.selector("08"), "08:*:*")


# ---------------------------------------------------------------------------
# intent validation
# ---------------------------------------------------------------------------


class TestIntentValidation(unittest.TestCase):
    def test_minimal_valid_payload(self):
        parsed = intent.parse(base_payload(), now=NOW)
        self.assertEqual(parsed.mode, intent.MODE_ALLOWLIST)

    def test_wrong_schema_id_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(base_payload(schema="ubuntuguard.usb_control.v2"), now=NOW)
        self.assertIn("schema", str(ctx.exception))

    def test_each_required_field_is_enforced(self):
        for field in (
            "schema",
            "mode",
            "protected_classes",
            "always_allow_classes",
            "allowlist",
            "exceptions",
            "reporting",
        ):
            with self.subTest(field=field):
                payload = base_payload()
                del payload[field]
                with self.assertRaises(intent.IntentError):
                    intent.parse(payload, now=NOW)

    def test_unknown_top_level_field_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(base_payload(rules_path="/etc/usbguard/rules.conf"), now=NOW)
        self.assertIn("rules_path", str(ctx.exception))
        self.assertIn("data only", str(ctx.exception))

    def test_unknown_field_inside_a_matcher_rejected(self):
        entry = allowlist_entry()
        entry["match"]["raw_rule"] = "allow id *:*"
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(base_payload(allowlist=[entry]), now=NOW)
        self.assertIn("raw_rule", str(ctx.exception))

    def test_all_problems_reported_not_just_the_first(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(base_payload(mode="nope", protected_classes=["nonsense"]), now=NOW)
        self.assertGreaterEqual(len(ctx.exception.problems), 2)

    def test_protected_and_always_allow_overlap_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(
                base_payload(
                    protected_classes=["mass_storage"],
                    always_allow_classes=["hid", "hub", "mass_storage"],
                ),
                now=NOW,
            )
        self.assertIn("ambiguous", str(ctx.exception))


class TestDeviceMatchValidation(unittest.TestCase):
    def _reject(self, match_overrides):
        entry = allowlist_entry()
        entry["match"].update(match_overrides)
        with self.assertRaises(intent.IntentError):
            intent.parse(base_payload(allowlist=[entry]), now=NOW)

    def test_vendor_id_must_be_four_lowercase_hex(self):
        for bad in ("078", "07811", "ZZZZ", "0781 ", "0A1B", ""):
            with self.subTest(value=bad):
                self._reject({"vendor_id": bad})

    def test_serial_injection_payloads_rejected(self):
        for bad in (
            'ABC" allow id 1234:5678 #',
            "ABC\\",
            "ABC\nallow id 1:2",
            "ABC DEF",
            "ABC#x",
            'ABC"',
        ):
            with self.subTest(serial=bad):
                self._reject({"serial": bad, "serial_match": "exact"})

    def test_legitimate_serials_accepted(self):
        for good in ("4C530001120523117082", "E0D5-5EA5_74B6.F371", "abc:123"):
            with self.subTest(serial=good):
                entry = allowlist_entry()
                entry["match"].update({"serial": good, "serial_match": "exact"})
                parsed = intent.parse(base_payload(allowlist=[entry]), now=NOW)
                self.assertEqual(parsed.allowlist[0].match.serial, good)

    def test_serial_any_without_serial_is_allowed(self):
        entry = allowlist_entry()
        entry["match"].update({"serial": None, "serial_match": "any"})
        parsed = intent.parse(base_payload(allowlist=[entry]), now=NOW)
        self.assertFalse(parsed.allowlist[0].match.is_exact)


class TestExceptionValidation(unittest.TestCase):
    def test_valid_exception_accepted(self):
        parsed = intent.parse(base_payload(exceptions=[exception_entry()]), now=NOW)
        self.assertEqual(len(parsed.exceptions), 1)

    def test_exception_over_24h_rejected(self):
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(
                base_payload(
                    exceptions=[
                        exception_entry(
                            created_at="2026-10-29T08:00:00Z",
                            expires_at="2026-10-31T08:00:00Z",
                        )
                    ]
                ),
                now=NOW,
            )
        self.assertIn("24 h maximum", str(ctx.exception))

    def test_exception_at_exactly_24h_accepted(self):
        parsed = intent.parse(
            base_payload(
                exceptions=[
                    exception_entry(
                        created_at="2026-10-29T08:00:00Z",
                        expires_at="2026-10-30T08:00:00Z",
                    )
                ]
            ),
            now=NOW,
        )
        self.assertEqual(len(parsed.exceptions), 1)

    def test_expiry_before_creation_rejected(self):
        with self.assertRaises(intent.IntentError):
            intent.parse(
                base_payload(
                    exceptions=[
                        exception_entry(
                            created_at="2026-10-29T12:00:00Z",
                            expires_at="2026-10-29T08:00:00Z",
                        )
                    ]
                ),
                now=NOW,
            )

    def test_naive_timestamp_rejected(self):
        """A timestamp without an offset shifts expiry per timezone."""
        with self.assertRaises(intent.IntentError) as ctx:
            intent.parse(
                base_payload(exceptions=[exception_entry(expires_at="2026-10-29T16:00:00")]),
                now=NOW,
            )
        self.assertIn("UTC offset", str(ctx.exception))

    def test_expired_exception_produces_no_allow_rule(self):
        parsed = intent.parse(base_payload(exceptions=[exception_entry()]), now=NOW)
        later = dt.datetime(2026, 10, 30, 10, 0, tzinfo=dt.timezone.utc)
        self.assertEqual(parsed.effective_matches(later), [])
        self.assertEqual(len(parsed.expired_exceptions(later)), 1)

    def test_active_exception_produces_an_allow_rule(self):
        parsed = intent.parse(base_payload(exceptions=[exception_entry()]), now=NOW)
        self.assertEqual(len(parsed.effective_matches(NOW)), 1)


# ---------------------------------------------------------------------------
# rule derivation
# ---------------------------------------------------------------------------


class TestDerivation(unittest.TestCase):
    def parse(self, **kw):
        return intent.parse(base_payload(**kw), now=NOW)

    def test_rule_order_authorised_before_block(self):
        """USBGuard is first-match-wins; an allow after the block never fires."""
        parsed = self.parse(allowlist=[allowlist_entry()])
        rules = derive.derive_rules(parsed, now=NOW)
        allow_i = next(i for i, r in enumerate(rules) if r.startswith("allow id"))
        block_i = next(i for i, r in enumerate(rules) if r.startswith("block"))
        self.assertLess(allow_i, block_i)

    def test_block_precedes_the_catch_all(self):
        rules = derive.derive_rules(self.parse(), now=NOW)
        block_i = next(i for i, r in enumerate(rules) if r.startswith("block"))
        catch_i = next(
            i for i, r in enumerate(rules) if r.startswith("allow with-interface none-of")
        )
        self.assertLess(block_i, catch_i)

    def test_monitor_mode_emits_no_block_rule(self):
        rules = derive.derive_rules(self.parse(mode=intent.MODE_MONITOR), now=NOW)
        self.assertEqual([r for r in rules if r.startswith(("block", "reject"))], [])

    def test_monitor_and_enforce_differ_by_one_rule(self):
        monitor = derive.derive_rules(self.parse(mode=intent.MODE_MONITOR), now=NOW)
        enforce = derive.derive_rules(self.parse(mode=intent.MODE_BLOCK_ALL), now=NOW)
        self.assertEqual(len(monitor), len(enforce))
        differing = [(a, b) for a, b in zip(monitor, enforce, strict=True) if a != b]
        self.assertEqual(len(differing), 1, differing)

    def test_hid_guard_applied_by_default(self):
        rules = derive.derive_rules(self.parse(allowlist=[allowlist_entry()]), now=NOW)
        device_rule = next(r for r in rules if r.startswith("allow id"))
        self.assertIn("none-of { 03:*:* }", device_rule)

    def test_hid_guard_removable_explicitly(self):
        rules = derive.derive_rules(
            self.parse(allowlist=[allowlist_entry()]),
            now=NOW,
            allow_hid_on_authorised=True,
        )
        device_rule = next(r for r in rules if r.startswith("allow id"))
        self.assertNotIn("none-of { 03:*:* }", device_rule)

    def test_image_class_included_when_protected(self):
        rules = derive.derive_rules(
            self.parse(protected_classes=["mass_storage", "image"]), now=NOW
        )
        block = next(r for r in rules if r.startswith("block"))
        self.assertIn("08:*:*", block)
        self.assertIn("06:*:*", block)

    def test_always_allow_classes_are_emitted(self):
        rules = derive.derive_rules(
            self.parse(always_allow_classes=["hid", "hub", "video"]), now=NOW
        )
        allow = next(r for r in rules if r.startswith("allow with-interface one-of"))
        for code in ("03:*:*", "09:*:*", "0e:*:*"):
            self.assertIn(code, allow)

    def test_model_wide_match_omits_serial(self):
        entry = allowlist_entry()
        entry["match"].update({"serial": None, "serial_match": "any"})
        rules = derive.derive_rules(self.parse(allowlist=[entry]), now=NOW)
        device_rule = next(r for r in rules if r.startswith("allow id"))
        self.assertNotIn("serial", device_rule)

    def test_derivation_is_deterministic(self):
        parsed = self.parse(allowlist=[allowlist_entry()])
        self.assertEqual(
            derive.derive_rules(parsed, now=NOW),
            derive.derive_rules(parsed, now=NOW),
        )

    def test_no_rule_line_contains_a_comment_character(self):
        rules = derive.derive_rules(self.parse(allowlist=[allowlist_entry()]), now=NOW)
        for rule in rules:
            self.assertNotIn("#", rule)

    def test_every_rule_has_balanced_quotes(self):
        rules = derive.derive_rules(self.parse(allowlist=[allowlist_entry()]), now=NOW)
        for rule in rules:
            self.assertEqual(rule.count('"') % 2, 0)

    def test_every_rule_starts_with_a_valid_target(self):
        rules = derive.derive_rules(self.parse(allowlist=[allowlist_entry()]), now=NOW)
        for rule in rules:
            self.assertRegex(rule, r"^(allow|block|reject)\s")


class TestRenderedPolicy(unittest.TestCase):
    def parse(self, **kw):
        return intent.parse(base_payload(**kw), now=NOW)

    def test_header_records_provenance(self):
        text = derive.render_policy(self.parse(), now=NOW, policy_version=7)
        self.assertIn("GENERATED by ubuntuguard enforcerd", text)
        self.assertIn("policy version: 7", text)
        self.assertIn("mode          : allowlist_enforce", text)

    def test_model_wide_entry_carries_a_warning(self):
        entry = allowlist_entry()
        entry["match"].update({"serial": None, "serial_match": "any"})
        text = derive.render_policy(self.parse(allowlist=[entry]), now=NOW)
        self.assertIn("WARNING", text)
        self.assertIn("EVERY 0781:5583", text)

    def test_expired_exception_is_explained_in_the_trailer(self):
        parsed = self.parse(exceptions=[exception_entry()])
        later = dt.datetime(2026, 10, 30, 10, 0, tzinfo=dt.timezone.utc)
        text = derive.render_policy(parsed, now=later)
        self.assertIn("expired exceptions", text)

    def test_fingerprint_present_and_self_consistent(self):
        text = derive.render_policy(self.parse(), now=NOW)
        self.assertEqual(len(derive.extract_fingerprint(text) or ""), 64)
        self.assertTrue(derive.verify_fingerprint(text))

    def test_fingerprint_ignores_generation_time(self):
        parsed = self.parse()
        a = derive.render_policy(parsed, now=NOW)
        b = derive.render_policy(parsed, now=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
        self.assertEqual(derive.extract_fingerprint(a), derive.extract_fingerprint(b))

    def test_tampering_breaks_verification(self):
        text = derive.render_policy(self.parse(), now=NOW)
        tampered = text.replace("block with-interface", "allow with-interface")
        self.assertFalse(derive.verify_fingerprint(tampered))

    def test_monitor_mode_is_labelled_in_the_output(self):
        text = derive.render_policy(self.parse(mode=intent.MODE_MONITOR), now=NOW)
        self.assertIn("MONITOR ONLY", text)

    def test_block_all_mode_states_allowlist_is_ignored(self):
        text = derive.render_policy(self.parse(mode=intent.MODE_BLOCK_ALL), now=NOW)
        self.assertIn("allowlist deliberately ignored", text)


if __name__ == "__main__":
    unittest.main()
