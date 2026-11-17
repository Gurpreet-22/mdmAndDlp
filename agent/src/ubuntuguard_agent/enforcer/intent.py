"""Parsing and validation of the `usb_control` policy payload.

The payload is **data only**: typed device matchers and a mode. It never
carries rule text, shell strings, file paths or commands, and this module is
what makes that true in practice rather than merely documented.

Three defences, in order of how much they matter:

1. **Unknown fields are rejected.** The payload is parsed by allowlisting
   known keys, so a server that adds `raw_usbguard_rule`, `post_apply_command`
   or `rules_path` is refused outright. Ignoring unknown fields would be
   almost as bad as honouring them: the policy would apply while the operator
   believed something else had happened.

2. **Values are constrained to shapes that cannot escape a rule.** Vendor and
   product IDs are four lowercase hex digits. Serials are restricted to a
   character set with no quotes, backslashes or whitespace, so they cannot
   terminate a quoted literal in a generated rule.

3. **Lockout invariants are re-checked here**, not trusted from the schema,
   because this process is the one that would actually remove the user's
   keyboard.

Validation collects every problem rather than stopping at the first, so a
rejection tells the operator everything that is wrong in one response.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any

from . import classes

#: The only payload schema identifier this build understands.
SCHEMA_ID = "ubuntuguard.usb_control.v1"

MODE_MONITOR = "monitor_only"
MODE_ALLOWLIST = "allowlist_enforce"
MODE_BLOCK_ALL = "block_all_storage"
MODES = (MODE_MONITOR, MODE_ALLOWLIST, MODE_BLOCK_ALL)

SERIAL_MATCH_EXACT = "exact"
SERIAL_MATCH_ANY = "any"
SERIAL_MATCH_MODES = (SERIAL_MATCH_EXACT, SERIAL_MATCH_ANY)

#: Mirrors UbuntuGuard's USB_EXCEPTION_MAX_SECONDS. An exception is an admin
#: deliberately unblocking a device, so it expires; a grant nobody revisits is
#: indistinguishable from a permanent hole.
EXCEPTION_MAX_SECONDS = 24 * 60 * 60

#: Minimum justification length, matching the server's CHECK constraint.
#: Short strings exist to discourage "test" and "asdf".
REASON_MIN_LENGTH = 8
REASON_MAX_LENGTH = 500

HEX4_RE = re.compile(r"\A[0-9a-f]{4}\Z")

#: Deliberately narrow. USB serials are machine-generated, so this excludes
#: quotes, backslashes, whitespace and '#' -- every character that could
#: terminate or comment out part of a generated rule.
SERIAL_RE = re.compile(r"\A[A-Za-z0-9._:-]{1,128}\Z")

_PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "protected_classes",
        "always_allow_classes",
        "allowlist",
        "exceptions",
        "reporting",
        "enforcement",
    }
)
_REQUIRED_PAYLOAD_FIELDS = (
    "schema",
    "mode",
    "protected_classes",
    "always_allow_classes",
    "allowlist",
    "exceptions",
    "reporting",
)
_MATCH_FIELDS = frozenset({"vendor_id", "product_id", "serial", "serial_match"})
_ALLOWLIST_FIELDS = frozenset({"entry_id", "match", "label", "added_by", "added_at"})
_EXCEPTION_FIELDS = frozenset(
    {"exception_id", "match", "reason", "created_by", "created_at", "expires_at"}
)
_REPORTING_FIELDS = frozenset({"report_allowed", "report_blocked", "report_present_at_start"})
_ENFORCEMENT_FIELDS = frozenset({"apply_to_present_devices"})


class IntentError(Exception):
    """The payload is not a usable usb_control policy."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        count = len(self.problems)
        detail = "\n".join(f"  - {p}" for p in self.problems)
        super().__init__(
            f"usb_control payload rejected ({count} problem{'s' if count != 1 else ''}):\n{detail}"
        )


@dataclass(frozen=True, slots=True)
class DeviceMatch:
    """One device matcher: a model, or a specific physical unit."""

    vendor_id: str
    product_id: str
    serial_match: str
    serial: str | None = None

    @property
    def usb_id(self) -> str:
        return f"{self.vendor_id}:{self.product_id}"

    @property
    def is_exact(self) -> bool:
        """True when this pins one physical device rather than a whole model."""
        return self.serial_match == SERIAL_MATCH_EXACT and bool(self.serial)


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    entry_id: str
    match: DeviceMatch
    label: str
    added_by: str
    added_at: str


@dataclass(frozen=True, slots=True)
class ExceptionGrant:
    """A time-bound admin grant from the policy's `exceptions` list.

    Named `ExceptionGrant` rather than `Exception` for the obvious reason, and
    rather than `Exception_` because a trailing underscore reads as a mistake
    and this is not an exception class at all -- it is a record of someone
    deliberately unblocking a device until a stated expiry.
    """

    exception_id: str
    match: DeviceMatch
    reason: str
    created_by: str
    created_at: dt.datetime
    expires_at: dt.datetime

    def is_active(self, now: dt.datetime) -> bool:
        return now < self.expires_at


@dataclass(frozen=True, slots=True)
class Reporting:
    report_allowed: bool
    report_blocked: bool
    report_present_at_start: bool


@dataclass(frozen=True, slots=True)
class UsbControlIntent:
    """A validated usb_control policy, ready to derive rules from."""

    mode: str
    protected_classes: tuple[str, ...]
    always_allow_classes: tuple[str, ...]
    allowlist: tuple[AllowlistEntry, ...]
    exceptions: tuple[ExceptionGrant, ...]
    reporting: Reporting
    apply_to_present_devices: bool = True

    @property
    def protected_codes(self) -> tuple[str, ...]:
        return classes.protected_codes(list(self.protected_classes))

    @property
    def always_allow_codes(self) -> tuple[str, ...]:
        return classes.always_allow_codes(list(self.always_allow_classes))

    def effective_matches(self, now: dt.datetime) -> list[tuple[DeviceMatch, str]]:
        """Device matchers that should produce an allow rule, with their origin.

        In `block_all_storage` the allowlist is deliberately ignored -- that is
        the point of the mode -- but unexpired exceptions still apply, so an
        admin can unblock one device without abandoning the posture.
        """
        out: list[tuple[DeviceMatch, str]] = []
        if self.mode == MODE_ALLOWLIST:
            for entry in self.allowlist:
                out.append((entry.match, f"allowlist:{entry.label}"))
        for exc in self.exceptions:
            if exc.is_active(now):
                out.append((exc.match, f"exception:{exc.exception_id}"))
        return out

    def expired_exceptions(self, now: dt.datetime) -> list[ExceptionGrant]:
        return [e for e in self.exceptions if not e.is_active(now)]


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def _reject_unknown(
    obj: dict[str, Any], known: frozenset[str], where: str, problems: list[str]
) -> None:
    unknown = set(obj) - known
    if unknown:
        # The security-relevant case: a server appending a command or path
        # field. Named explicitly so the log makes the attempt obvious.
        problems.append(
            f"{where}: unknown field(s) {', '.join(sorted(unknown))} -- "
            f"the usb_control payload carries data only and must not contain "
            f"rule text, commands or paths"
        )


def _str(obj: dict[str, Any], key: str, where: str, problems: list[str]) -> str | None:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{where}: {key!r} must be a non-empty string")
        return None
    return value


def _parse_datetime(raw: Any, key: str, where: str, problems: list[str]) -> dt.datetime | None:
    if not isinstance(raw, str):
        problems.append(f"{where}: {key!r} must be an RFC 3339 timestamp string")
        return None
    text = raw.strip()
    # Python's fromisoformat accepts "+00:00" but historically not "Z".
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        problems.append(f"{where}: {key!r} is not a valid timestamp: {raw!r}")
        return None
    if parsed.tzinfo is None:
        # A naive timestamp would be interpreted in local time, which on a
        # fleet spread across timezones silently shifts every expiry.
        problems.append(f"{where}: {key!r} must include a UTC offset")
        return None
    return parsed.astimezone(dt.timezone.utc)


def _parse_match(raw: Any, where: str, problems: list[str]) -> DeviceMatch | None:
    if not isinstance(raw, dict):
        problems.append(f"{where}: 'match' must be an object")
        return None
    _reject_unknown(raw, _MATCH_FIELDS, f"{where}.match", problems)

    vendor = raw.get("vendor_id")
    product = raw.get("product_id")
    for name, value in (("vendor_id", vendor), ("product_id", product)):
        if not isinstance(value, str) or not HEX4_RE.match(value):
            problems.append(
                f"{where}.match: {name!r} must be exactly 4 lowercase hex digits (got {value!r})"
            )

    serial_match = raw.get("serial_match")
    if serial_match not in SERIAL_MATCH_MODES:
        problems.append(
            f"{where}.match: 'serial_match' must be one of "
            f"{', '.join(SERIAL_MATCH_MODES)} (got {serial_match!r})"
        )

    serial = raw.get("serial")
    if serial is not None and (not isinstance(serial, str) or not SERIAL_RE.match(serial)):
        problems.append(
            f"{where}.match: 'serial' contains characters that are not "
            f"permitted in a generated rule; must match {SERIAL_RE.pattern}"
        )
        serial = None

    # 'exact' without a serial matches nothing, so it would silently fail to
    # authorise the device the admin thought they had authorised.
    if serial_match == SERIAL_MATCH_EXACT and not serial:
        problems.append(
            f"{where}.match: serial_match 'exact' requires a serial; use "
            f"'any' for devices that report none (weaker: matches every unit "
            f"of that model)"
        )

    if problems:
        return None
    return DeviceMatch(
        vendor_id=vendor,  # type: ignore[arg-type]
        product_id=product,  # type: ignore[arg-type]
        serial_match=serial_match,  # type: ignore[arg-type]
        serial=serial,
    )


def parse(payload: dict[str, Any], *, now: dt.datetime | None = None) -> UsbControlIntent:
    """Validate a usb_control payload and return typed intent.

    Raises IntentError listing every problem found.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    problems: list[str] = []

    if not isinstance(payload, dict):
        raise IntentError(["payload must be a JSON object"])

    _reject_unknown(payload, _PAYLOAD_FIELDS, "payload", problems)

    if payload.get("schema") != SCHEMA_ID:
        problems.append(f"payload: 'schema' must be {SCHEMA_ID!r} (got {payload.get('schema')!r})")

    for name in _REQUIRED_PAYLOAD_FIELDS:
        if name not in payload:
            problems.append(f"payload: missing required field {name!r}")

    mode = payload.get("mode")
    if mode not in MODES:
        problems.append(f"payload: 'mode' must be one of {', '.join(MODES)} (got {mode!r})")

    # -- classes -----------------------------------------------------------
    protected = payload.get("protected_classes")
    if not isinstance(protected, list) or not protected:
        problems.append("payload: 'protected_classes' must be a non-empty array")
        protected = []
    else:
        try:
            classes.protected_codes(protected)
        except KeyError as exc:
            problems.append(f"payload: {exc.args[0]}")

    always = payload.get("always_allow_classes")
    if not isinstance(always, list) or not always:
        problems.append("payload: 'always_allow_classes' must be a non-empty array")
        always = []
    else:
        try:
            classes.always_allow_codes(always)
        except KeyError as exc:
            problems.append(f"payload: {exc.args[0]}")
        missing = classes.REQUIRED_ALWAYS_ALLOW - set(always)
        if missing:
            # The lockout invariant. Re-checked here because this process is
            # the one that would remove the user's keyboard.
            problems.append(
                f"payload: 'always_allow_classes' must include "
                f"{', '.join(sorted(missing))} -- without them a policy can "
                f"deauthorise the keyboard and lock the user out of their own "
                f"machine"
            )

    overlap = set(protected) & set(always)
    if overlap:
        problems.append(
            f"payload: class(es) {', '.join(sorted(overlap))} appear in both "
            f"'protected_classes' and 'always_allow_classes'; the intent is "
            f"ambiguous"
        )

    # -- allowlist ---------------------------------------------------------
    entries: list[AllowlistEntry] = []
    raw_allowlist = payload.get("allowlist")
    if raw_allowlist is None:
        raw_allowlist = []
    if not isinstance(raw_allowlist, list):
        problems.append("payload: 'allowlist' must be an array")
        raw_allowlist = []
    for index, raw in enumerate(raw_allowlist):
        where = f"allowlist[{index}]"
        if not isinstance(raw, dict):
            problems.append(f"{where}: must be an object")
            continue
        _reject_unknown(raw, _ALLOWLIST_FIELDS, where, problems)
        match = _parse_match(raw.get("match"), where, problems)
        entry_id = _str(raw, "entry_id", where, problems)
        label = _str(raw, "label", where, problems)
        added_by = _str(raw, "added_by", where, problems)
        added_at = raw.get("added_at")
        if not isinstance(added_at, str):
            problems.append(f"{where}: 'added_at' must be a timestamp string")
        if match and entry_id and label and added_by and isinstance(added_at, str):
            entries.append(
                AllowlistEntry(
                    entry_id=entry_id,
                    match=match,
                    label=label,
                    added_by=added_by,
                    added_at=added_at,
                )
            )

    # -- exceptions --------------------------------------------------------
    exceptions: list[ExceptionGrant] = []
    raw_exceptions = payload.get("exceptions")
    if raw_exceptions is None:
        raw_exceptions = []
    if not isinstance(raw_exceptions, list):
        problems.append("payload: 'exceptions' must be an array")
        raw_exceptions = []
    for index, raw in enumerate(raw_exceptions):
        where = f"exceptions[{index}]"
        if not isinstance(raw, dict):
            problems.append(f"{where}: must be an object")
            continue
        _reject_unknown(raw, _EXCEPTION_FIELDS, where, problems)
        match = _parse_match(raw.get("match"), where, problems)
        exception_id = _str(raw, "exception_id", where, problems)
        created_by = _str(raw, "created_by", where, problems)

        reason = raw.get("reason")
        if not isinstance(reason, str) or not (
            REASON_MIN_LENGTH <= len(reason) <= REASON_MAX_LENGTH
        ):
            problems.append(
                f"{where}: 'reason' must be {REASON_MIN_LENGTH}-"
                f"{REASON_MAX_LENGTH} characters; a substantive justification "
                f"is required"
            )
            reason = None

        created_at = _parse_datetime(raw.get("created_at"), "created_at", where, problems)
        expires_at = _parse_datetime(raw.get("expires_at"), "expires_at", where, problems)

        if created_at and expires_at:
            if expires_at <= created_at:
                problems.append(f"{where}: 'expires_at' must be after 'created_at'")
            else:
                span = (expires_at - created_at).total_seconds()
                if span > EXCEPTION_MAX_SECONDS:
                    # JSON Schema cannot express this bound, so it is enforced
                    # by the server on create and again here on apply.
                    problems.append(
                        f"{where}: exception spans {span / 3600:.1f} h, "
                        f"exceeding the {EXCEPTION_MAX_SECONDS // 3600} h "
                        f"maximum"
                    )

        if match and exception_id and created_by and reason and created_at and expires_at:
            exceptions.append(
                ExceptionGrant(
                    exception_id=exception_id,
                    match=match,
                    reason=reason,
                    created_by=created_by,
                    created_at=created_at,
                    expires_at=expires_at,
                )
            )

    # -- reporting ---------------------------------------------------------
    reporting = Reporting(True, True, True)
    raw_reporting = payload.get("reporting")
    if not isinstance(raw_reporting, dict):
        problems.append("payload: 'reporting' must be an object")
    else:
        _reject_unknown(raw_reporting, _REPORTING_FIELDS, "reporting", problems)
        flags = {}
        for name in _REPORTING_FIELDS:
            value = raw_reporting.get(name)
            if not isinstance(value, bool):
                problems.append(f"reporting: {name!r} must be true or false")
                flags[name] = True
            else:
                flags[name] = value
        reporting = Reporting(
            report_allowed=flags["report_allowed"],
            report_blocked=flags["report_blocked"],
            report_present_at_start=flags["report_present_at_start"],
        )

    # -- enforcement (optional) -------------------------------------------
    apply_to_present = True
    raw_enforcement = payload.get("enforcement")
    if raw_enforcement is not None:
        if not isinstance(raw_enforcement, dict):
            problems.append("payload: 'enforcement' must be an object")
        else:
            _reject_unknown(raw_enforcement, _ENFORCEMENT_FIELDS, "enforcement", problems)
            value = raw_enforcement.get("apply_to_present_devices", True)
            if not isinstance(value, bool):
                problems.append("enforcement: 'apply_to_present_devices' must be true or false")
            else:
                apply_to_present = value

    if problems:
        raise IntentError(problems)

    return UsbControlIntent(
        mode=mode,  # type: ignore[arg-type]
        protected_classes=tuple(protected),
        always_allow_classes=tuple(always),
        allowlist=tuple(entries),
        exceptions=tuple(exceptions),
        reporting=reporting,
        apply_to_present_devices=apply_to_present,
    )
